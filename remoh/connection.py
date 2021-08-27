import sys
import io
import socket
import signal
import hashlib
import base64

try:
    # http://pycurl.io/docs/latest
    import pycurl

    # Octobre 2019: the Python GnuTLS bindings don't work with Python 3. So we use OpenSSL.
    # https://www.pyopenssl.org/
    # https://pyopenssl.readthedocs.io/
    import OpenSSL

    # http://www.dnspython.org/
    import dns.message
except ImportError as e:
    print("Error: missing module")
    print(e)
    sys.exit(1)

import remoh.utils
import remoh.exceptions

class Connection:

    def __init__(self, server, servername=None, connect_to=None,
                 forceIPv4=False, forceIPv6=False, insecure=False,
                 verbose=False, debug=False, dot=False):

        if dot and not remoh.is_valid_hostname(server):
            raise remoh.ConnectionDOTException("DoT requires a host name or IP address, not \"%s\"" % server)

        if not dot and not remoh.is_valid_url(server):
            raise remoh.ConnectionDOHException("DoH requires a valid HTTPS URL, not \"%s\"" % server)

        if forceIPv4 and forceIPv6:
            raise remoh.ConnectionException("Force IPv4 *or* IPv6 but not both")

        self.dot = dot
        self.server = server
        self.servername = servername
        if self.servername is not None:
            self.check_name_cert = self.servername
        else:
            self.check_name_cert = self.server
        self.verbose = verbose
        self.debug = debug
        self.insecure = insecure
        self.forceIPv4 = forceIPv4
        self.forceIPv6 = forceIPv6
        self.connect_to = connect_to
        self.state = 'CONN_OK'
        self.nbr_finished_queries = 0

    def __str__(self):
        return self.server

    def do_test(self, request):
        # Routine doing one actual test. Returns nothing
        pass


class ConnectionDOT(Connection):

    def __init__(self, server, servername=None, connect_to=None,
                 forceIPv4=False, forceIPv6=False, insecure=False,
                 verbose=False, debug=False,
                 sni=True, key=None, pipelining=False):

        super().__init__(server, servername=servername, connect_to=connect_to,
                forceIPv4=forceIPv4, forceIPv6=forceIPv6, insecure=insecure,
                verbose=verbose, debug=debug, dot=True)

        self.sni = sni
        self.key = key
        self.pipelining = pipelining
        if self.pipelining:
            self.all_requests = [] # Currently, we load everything in memory
                                   # since we want to keep everything,
                                   # anyway. May be in the future, if we don't
                                   # want to keep individual results, we'll use
                                   # an iterator to fill a smaller table.
                                   # all_requests is indexed by its rank in the input file.
            self.pending = {} # pending is indexed by the query ID, and its
                              # maximum size is max_in_flight.

        # establish the connection
        self.connect()

    def connect(self):
        # if connect_to is defined, it means we know the IP address of the
        # server and therefore we can establish a connection with it
        # otherwise we only have a domain name and we should loop on all
        # resolved IPs until a connection can be established
        # getaddrinfo provides a list of resolved IPs, when connect_to is
        # defined this list will have only one element
        # so we can loop on the items until a connection is made
        # the list is converted into a set of tuples to avoid duplicates

        self.success = False

        if self.connect_to is not None: # the server's IP address is known
            addr = self.connect_to
        else:
            addr = self.server # otherwise keep the server name

        family = remoh.get_addrfamily(addr, forceIPv4=self.forceIPv4, forceIPv6=self.forceIPv6)
        addrinfo_list = socket.getaddrinfo(addr, remoh.PORT_DOT, family)
        addrinfo_set = { (addrinfo[4], addrinfo[0]) for addrinfo in addrinfo_list }

        signal.signal(signal.SIGALRM, remoh.exceptions.timeout_connection)

        # contains a set of tuples ('ip address', 'error message')
        errors = set()
        i = 0
        for addrinfo in addrinfo_set:
            # catch the raised exceptions and store them in the error set
            # if that the last element of the loop raises an exception
            # it will also be catched, but in this case we are sure we can not
            # establish a connection therefore we raise an exception containing
            # a string with all the errors
            try:
                self.establish_session(addrinfo[0], addrinfo[1])
            except remoh.ConnectionDOTException as e:
                errors.add((addrinfo[0][0], str(e)))
                if self.verbose and self.connect_to is None:
                    print(e, file=sys.stderr)
                # we tried all the resolved IPs
                if i == (len(addrinfo_set) - 1):
                    if self.verbose and self.connect_to is None:
                        print("No other IP address")
                    # join all the errors into a single string
                    err = ', '.join( "%s: %s" % (e[0], e[1]) for e in errors)
                    raise remoh.ConnectionDOTException(err)
                if self.verbose and self.connect_to is None:
                    print("Could not connect to %s" % addrinfo[0][0])
                    print("Trying another IP address")
            else:
                self.success = True
                break
            i += 1

    def establish_session(self, addr, sock_family):
        """Return True if a TLS session is established."""

        self.hasher = hashlib.sha256()

        # start the timer
        signal.alarm(remoh.TIMEOUT_CONN)

        self.sock = socket.socket(sock_family, socket.SOCK_STREAM)

        if self.verbose:
            print("Connecting to %s ..." % addr[0])

        # With typical DoT servers, we *must* use TLS 1.2 (otherwise,
        # do_handshake fails with "OpenSSL.SSL.SysCallError: (-1, 'Unexpected
        # EOF')" Typical HTTP servers are more lax.
        self.context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
        if self.insecure:
            self.context.set_verify(OpenSSL.SSL.VERIFY_NONE, lambda *x: True)
        else:
            self.context.set_default_verify_paths()
            self.context.set_verify_depth(4) # Seems ignored
            self.context.set_verify(OpenSSL.SSL.VERIFY_PEER | OpenSSL.SSL.VERIFY_FAIL_IF_NO_PEER_CERT | \
                                    OpenSSL.SSL.VERIFY_CLIENT_ONCE,
                                    lambda conn, cert, errno, depth, preverify_ok: preverify_ok)
        self.session = OpenSSL.SSL.Connection(self.context, self.sock)
        if self.sni:
            self.session.set_tlsext_host_name(remoh.canonicalize(self.check_name_cert).encode())

        try:
            self.session.connect((addr))
            self.session.do_handshake()
        except remoh.exceptions.TimeoutConnectionError:
            self.state = 'CONN_TIMEOUT'
            raise remoh.ConnectionDOTException("Timeout")
        except OSError:
            self.state = 'CONN_FAILED'
            raise remoh.ConnectionDOTException("Cannot connect")
        except OpenSSL.SSL.SysCallError as e:
            self.state = e.args[1]
            raise remoh.ConnectionDOTException("OpenSSL error: %s" % e.args[1])
        except OpenSSL.SSL.ZeroReturnError:
            # see #18
            self.state = 'CONN_CLOSED'
            raise remoh.ConnectionDOTException("Error: The SSL connection has been closed (try with --nosni to avoid sending SNI ?)")
        except OpenSSL.SSL.Error as e:
            self.state = 'CONN_ERROR'
            raise remoh.ConnectionDOTException("OpenSSL error: %s" % ', '.join(err[0][2] for err in e.args))

        # RFC 7858, section 4.2 and appendix A
        self.cert = self.session.get_peer_certificate()
        self.publickey = self.cert.get_pubkey()
        if self.debug or self.key is not None:
            self.hasher.update(OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_ASN1,
                                                  self.publickey))
            self.digest = self.hasher.digest()
            key_string = base64.standard_b64encode(self.digest).decode()
        if self.debug:
            print("Certificate #%x for \"%s\", delivered by \"%s\"" % \
                  (self.cert.get_serial_number(),
                   self.cert.get_subject().commonName,
                   self.cert.get_issuer().commonName))
            print("Public key is pin-sha256=\"%s\"" % key_string)
        if not self.insecure:
            if self.key is None:
                valid = remoh.validate_hostname(self.check_name_cert, self.cert)
                if not valid:
                    raise remoh.ConnectionDOTException("Certificate error: \"%s\" is not in the certificate" % (self.check_name_cert))
            else:
                if key_string != self.key:
                    raise remoh.ConnectionDOTException("Key error: expected \"%s\", got \"%s\"" % (self.key, key_string))

        # restore the timer
        signal.alarm(0)
        # and start a new timer when pipelining requests
        if self.pipelining:
            self.sock.settimeout(remoh.TIMEOUT_READ)
        return True

    def end(self):
        self.session.shutdown()
        self.session.close()
        self.state = 'CLOSED'

    def send_data(self, data, dump=False):
        if dump:
            remoh.dump_data(data, 'data sent')
        length = len(data)
        try:
            self.session.send(length.to_bytes(2, byteorder='big') + data)
        except OpenSSL.SSL.SysCallError as e:
            self.state = e.args[1]
            raise remoh.ConnectionDOTException('OpenSSL error : %s' % self.state)
        except OpenSSL.SSL.ZeroReturnError:
            self.state = 'CONN_CLOSED'
            raise remoh.ConnectionDOTException('The SSL connection has been closed')

    def receive_data(self, dump=False):
        try:
            buf = self.session.recv(2)
            self.nbr_finished_queries += 1
        except OpenSSL.SSL.WantReadError:
            return (False, None, None)
        except OpenSSL.SSL.ZeroReturnError:
            self.state = 'CONN_CLOSED'
            raise remoh.ConnectionDOTException('The SSL connection has been closed')
        size = int.from_bytes(buf, byteorder='big')
        data = self.session.recv(size)
        if dump:
            remoh.dump_data(data, 'data recv')
        return (True, data, size)

    def send_and_receive(self, request, dump=False):
        self.send_data(request.data, dump=dump)
        rcode, data, size = self.receive_data(dump=dump)
        request.store_response(rcode, data, size)

    # this function might need to be moved outside
    def do_test(self, request):
        self.send_data(request.data)
        rcode, data, size = self.receive_data()
        request.store_response(rcode, data, size)
        request.check_response(self.debug)

    # should the pipelining methods be part of ConnectionDOT ?
    def pipelining_add_request(self, request):
        self.all_requests.append({'request': request, 'response': None}) # No answer yet

    def pipelining_fill_pending(self, index):
        if index < len(self.all_requests):
            request = self.all_requests[index]['request']
            id = request.message.id
            # TODO check there is no duplicate in IDs
            self.pending[id] = (False, index, request)
            self.send_data(request.data)

    def pipelining_init_pending(self, max_in_flight):
        for i in range(0, max_in_flight):
            if i == len(self.all_requests):
                break
            self.pipelining_fill_pending(i)
        return i

    # this method might need to be moved somewhere else in order to avoid
    # calling dns.message.from_wire()
    def read_result(self, connection, requests, display_results=True):
        rcode, data, size = self.receive_data() # TODO can raise
                                                    # OpenSSL.SSL.ZeroReturnError
                                                    # if the
                                                    # connection was
                                                    # closed
        if not rcode:
            if display_results:
                print("TIMEOUT")
            return None
        # TODO remove call to dns.message (use abstraction instead)
        response = dns.message.from_wire(data)
        id = response.id
        if id not in requests:
            raise remoh.PipeliningException("Received response for ID %s which is unexpected" % id)
        over, rank, request = requests[id]
        self.all_requests[rank]['response'] = (rcode, response, size)
        requests[id] = (True, rank, request)
        if display_results:
            print()
            print(response)
        # TODO a timeout if some responses are lost?
        return id

def create_handle(connection):
    def reset_opt_default(handle):
        opts = {
                pycurl.NOBODY: False,
                pycurl.POST: False,
                pycurl.POSTFIELDS: '',
                pycurl.URL: ''
               }
        for opt, value in opts.items():
            handle.setopt(opt, value)

    def prepare(handle, connection, request):
        if not connection.multistreams:
            handle.reset_opt_default(handle)
        if request.post:
            handle.setopt(pycurl.POST, True)
            handle.setopt(pycurl.POSTFIELDS, request.data)
            handle.setopt(pycurl.URL, connection.server)
        else:
            handle.setopt(pycurl.HTTPGET, True) # automatically sets CURLOPT_NOBODY to 0
            if request.head:
                handle.setopt(pycurl.NOBODY, True)
            dns_req = base64.urlsafe_b64encode(request.data).decode('UTF8').rstrip('=')
            handle.setopt(pycurl.URL, connection.server + ("?dns=%s" % dns_req))
        handle.buffer = io.BytesIO()
        handle.setopt(pycurl.WRITEDATA, handle.buffer)
        handle.request = request

    handle = pycurl.Curl()
    # Does not work if pycurl was not compiled with nghttp2 (recent Debian
    # packages are OK) https://github.com/pycurl/pycurl/issues/477
    handle.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_2)
    if connection.debug:
        handle.setopt(pycurl.VERBOSE, True)
    if connection.insecure:
        handle.setopt(pycurl.SSL_VERIFYPEER, False)
        handle.setopt(pycurl.SSL_VERIFYHOST, False)
    if connection.forceIPv4:
        handle.setopt(pycurl.IPRESOLVE, pycurl.IPRESOLVE_V4)
    if connection.forceIPv6:
        handle.setopt(pycurl.IPRESOLVE, pycurl.IPRESOLVE_V6)
    if connection.connect_to is not None:
        handle.setopt(pycurl.CONNECT_TO, ["::[%s]:%d" % (connection.connect_to, remoh.PORT_DOH),])
    handle.setopt(pycurl.HTTPHEADER,
            ["Accept: application/dns-message", "Content-type: application/dns-message"])
    handle.reset_opt_default = reset_opt_default
    handle.prepare = prepare
    return handle


class ConnectionDOH(Connection):

    def __init__(self, server, servername=None, connect_to=None,
                 forceIPv4=False, forceIPv6=False,
                 insecure=False, verbose=False, debug=False,
                 multistreams=False):

        super().__init__(server, servername=servername, connect_to=connect_to,
                forceIPv4=forceIPv4, forceIPv6=forceIPv6, insecure=insecure,
                verbose=verbose, debug=debug, dot=False)

        self.url = server
        self.multistreams = multistreams

        # temporary tweak to check that the ip family is coherent with
        # user choice on forced IP
        if self.connect_to:
            remoh.check_ip_address(self.connect_to, forceIPv4=self.forceIPv4, forceIPv6=self.forceIPv6)

        if self.multistreams:
            self.multi = self.create_multi()
            self.all_handles = []
            self.finished = { 'http': {} }
        else:
            self.curl_handle = create_handle(self)

    def create_multi(self):
        multi = pycurl.CurlMulti()
        multi.setopt(pycurl.M_MAX_HOST_CONNECTIONS, 1)
        return multi

    def init_multi(self):
        # perform a first query alone
        # to establish the connection and hence avoid starting
        # the transfer of all the other queries simultaneously
        # query the root NS because this should not impact the resover cache
        if self.verbose:
            print("Establishing multistreams connection...")
        request = remoh.RequestDOH('.', qtype='NS')
        request.to_wire()
        self.multistreams_add_request(request)
        self.perform_multi(silent=True, display_results=False, show_time=False)
        self.all_handles = []
        self.finished = { 'http': {} }

    def end(self):
        if not self.multistreams:
            self.curl_handle.close()
        else:
            self.remove_handles()
            self.multi.close()
        self.state = 'CLOSED'

    def remove_handles(self):
        n, handle_success, handle_fail = self.multi.info_read()
        handles = handle_success + handle_fail
        for h in handles:
            h.close()
            self.multi.remove_handle(h)

    def perform_multi(self, silent=False, display_results=True, show_time=False):
        while 1:
            ret, num_handles = self.multi.perform()
            if ret != pycurl.E_CALL_MULTI_PERFORM:
                break
        while num_handles:
            ret = self.multi.select(1.0)
            if ret == -1:
                continue
            while 1:
                ret, num_handles = self.multi.perform()
                n, handle_pass, handle_fail = self.multi.info_read()
                for handle in handle_pass:
                    self.read_result_handle(handle, silent=silent, display_results=display_results, show_time=show_time)
                if ret != pycurl.E_CALL_MULTI_PERFORM:
                    break
        n, handle_pass, handle_fail = self.multi.info_read()
        for handle in handle_pass:
            self.read_result_handle(handle, silent=silent, display_results=display_results, show_time=show_time)

    def send(self, handle):
        handle.buffer = io.BytesIO()
        handle.setopt(pycurl.WRITEDATA, handle.buffer)
        try:
            handle.perform()
        except pycurl.error as e:
            self.state = e.args[1]
            raise remoh.DOHException(e.args[1])

    def receive(self, handle):
        self.nbr_finished_queries += 1
        request = handle.request
        body = handle.buffer.getvalue()
        body_size = len(body)
        http_code = handle.getinfo(pycurl.RESPONSE_CODE)
        handle.time = handle.getinfo(pycurl.TOTAL_TIME)
        handle.pretime = handle.getinfo(pycurl.PRETRANSFER_TIME)
        try:
            content_type = handle.getinfo(pycurl.CONTENT_TYPE)
        except TypeError: # This is the exception we get if there is no Content-Type: (for intance in response to HEAD requests)
            content_type = None
        request.response = body
        request.response_size = body_size
        request.rcode = http_code
        request.ctype = content_type
        handle.buffer.close()

    def send_and_receive(self, handle, dump=False):
        self.send(handle)
        self.receive(handle)

    def read_result_handle(self, handle, silent=False, display_results=True, show_time=False):
        self.receive(handle)
        handle.request.check_response()
        if not silent and show_time:
            self.print_time(handle)
        try:
            self.finished['http'][handle.request.rcode] += 1
        except KeyError:
            self.finished['http'][handle.request.rcode] = 1
        if not silent and display_results:
            print("Return code %s (%.2f ms):" % (handle.request.rcode,
                (handle.time - handle.pretime) * 1000))
            print(f"{handle.request.response}\n")
        handle.close()
        self.multi.remove_handle(handle)

    def read_results(self, display_results=True, show_time=False):
        for handle in self.all_handles:
            self.read_result_handle(handle, display_results=display_results, show_time=show_time)

    def print_time(self, handle):
        print(f'{handle.request.i:3d}', end='   ')
        print(f'({handle.request.rcode})', end='   ')
        print(f'{handle.pretime * 1000:8.3f} ms', end='  ')
        print(f'{handle.time * 1000:8.3f} ms', end='  ')
        print(f'{(handle.time - handle.pretime) * 1000:8.3f} ms')

    def multistreams_add_request(self, request):
        handle = create_handle(self)
        self.all_handles.append(handle)
        handle.prepare(handle, self, request)
        self.multi.add_handle(handle)

    def do_test(self, request):
        handle = self.curl_handle
        handle.prepare(handle, self, request)
        self.send_and_receive(handle)
        request.check_response(self.debug)
