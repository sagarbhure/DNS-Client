#!/usr/bin/env python3

# Remoh is a DoH (DNS-over-HTTPS) and DoT (DNS-over-TLS) client. Its
# main purpose is to test DoH and DoT resolvers. Reference site is
# <https://framagit.org/bortzmeyer/homer/> See author, documentation,
# etc, there, or in the README.md included with the distribution.

import sys
import getopt
import urllib.parse
import time
import socket
import dns

try:
    # http://pycurl.io/docs/latest
    import pycurl

    # Octobre 2019: the Python GnuTLS bindings don't work with Python 3. So we use OpenSSL.
    # https://www.pyopenssl.org/
    # https://pyopenssl.readthedocs.io/
    import OpenSSL
except ImportError as e:
    print("Error: missing module")
    print(e)
    sys.exit(1)

import remoh

# Values that can be changed from the command line
class opts:
    dot = False # DoH by default
    verbose = False
    debug = False
    insecure = False
    post = False
    head = False
    dnssec = False
    edns = True
    no_ecs = True
    sni = True
    rtype = 'AAAA'
    vhostname = None
    tests = 1 # Number of repeated tests
    key = None # SPKI
    ifile = None # Input file
    delay = None
    forceIPv4 = False
    forceIPv6 = False
    connectTo = None
    pipelining = False
    max_in_flight = 20
    multistreams = False
    display_results = True
    show_time = False
    check = False
    mandatory_level = None
    check_additional = True

def error(msg=None, exit=True):
    if msg is None:
        msg = "Unknown error"
    print(msg, file=sys.stderr)

def error_and_exit(msg=None):
    error(msg)
    sys.exit(1)

def usage(msg=None):
    if msg:
        print(msg,file=sys.stderr)
    print("Usage: %s [options] url-or-servername domain-name [DNS type]" % sys.argv[0], file=sys.stderr)
    print("""Options
    -t --dot            Use DoT (by default use DoH)
    -k --insecure       Do not check the certificate
    -4 --v4only         Force IPv4 resolution of url-or-servername
    -6 --v6only         Force IPv6 resolution of url-or-servername
    -v --verbose        Make the program more talkative
    --debug             Make the program even more talkative than -v
    -r --repeat <N>     Perform N times the query. If used with -f, read up to
                        <N> lines of the <file>
    -d --delay <T>      Time to wait in seconds between each synchronous
                        request (only with --repeat)
    -f --file <file>    Read domain names from <file>, one per row with an
                        optional DNS type. Read the first line only, use
                        --repeat N to read up to N lines of the file
    --check             Perform a set of predefined tests
    --mandatory-level <level>
                        Define the <level> of test to perform (only with
                        --check)
                        Available <level> : legal, necessary, nicetohave
    --no-display-results
                        Disable output of DNS response
    --dnssec            Request DNSSEC data (signatures)
    --noedns            Disable EDNS, default is to indicate EDNS support
    --ecs               Send ECS to authoritative servers, default is to
                        refuse it
    -V --vhost <vhost>  Use a specific virtual host
    -h --help           Print this message

  DoH only options:
    -P --post --POST    Use HTTP POST method for all the transfers
    -e --head --HEAD    Use HTTP HEAD method for all the transfers
    --multistreams      Use HTTP/2 streams, needs an input file with -f
    --time              Display the time elapsed for the query (only with
                        --multistreams)

  DoT only options:
    --key <key>         Authenticate a DoT resolver with its public <key> in
                        base64
    --nosni             Do not perform SNI
    --pipelining        Pipeline the requests, needs an input file with -f
    --max-in-flight <M> Maximum number of concurrent requests in parallel (only
                        with --pipelining)

    url-or-servername   The URL or domain name of the DoT/DoH server
    domain-name         The domain name to resolve, not required if -f is
                        provided
    DNS type            The DNS record type to resolve, default AAAA
    """, file=sys.stderr)
    print("See the README.md for more details.", file=sys.stderr)

def get_next_domain(input_file):
    name, rtype = 'framagit.org', 'AAAA'
    line = input_file.readline()
    if line[:-1] == "":
        error("Not enough data in %s for the %i tests" % (opts.ifile, opts.tests))
    if line.find(' ') == -1:
        name = line[:-1]
        rtype = 'AAAA'
    else:
        (name, rtype) = line.split()
    return name, rtype

def print_info(msg, ip=None, prefix=None, msg_type=None, fd=sys.stdout):
    output = ""
    if ip:
        output += '%s: ' % ip
    if prefix:
        output += '%s: ' % prefix
    if msg_type:
        output += '%s: ' % msg_type
    output += '%s' % msg
    print(output, file=fd)

def print_result(connection, request, prefix=None, display_err=True):
    dot = connection.dot
    server = connection.server
    rcode = request.rcode
    msg = request.response
    size = request.response_size
    if (dot and rcode) or (not dot and rcode == 200):
        if not opts.dot and opts.show_time:
            connection.print_time(connection.curl_handle)
        if opts.display_results and (not opts.check or opts.verbose):
            print(msg)
    else:
        if display_err:
            ip = connection.connect_to
            if dot:
                msg_type = 'Error'
            else:
               try:
                   msg = msg.decode()
               except (UnicodeDecodeError, AttributeError):
                   pass # Sometimes, msg can be binary, or Latin-1
               msg_type = 'HTTP error %i' % rcode
            print_info(msg, ip, prefix, msg_type, fd=sys.stderr)


def print_check_result(test_name, ok, verbose=True):
    if verbose:
        print(test_name, end=' : ')
        if ok:
            print('OK')
        else:
            print('KO')

def check_dot_two_requests(connection, opts):
    # not using a DoT connection -> exit the test
    if not connection.dot:
        return True

    r1 = remoh.RequestDOT('framagit.org', qtype=opts.rtype, use_edns=opts.edns, want_dnssec=opts.dnssec, no_ecs=opts.no_ecs)
    r2 = remoh.RequestDOT('afnic.fr', qtype=opts.rtype, use_edns=opts.edns, want_dnssec=opts.dnssec, no_ecs=opts.no_ecs)

    requests = []
    requests.append(('Test 1', r1, remoh.mandatory_levels["legal"]))
    # RFC 7858 section 3.3, SHOULD accept several requests on one connection.
    requests.append(('Test 2', r2, remoh.mandatory_levels["necessary"]))

    return do_check(connection, requests, opts)

def check_doh_methods(connection, opts):
    # not using a DoH connection -> exit the test
    if connection.dot:
        return True

    r1 = remoh.RequestDOH('framagit.org', qtype=opts.rtype, use_edns=opts.edns, want_dnssec=opts.dnssec, no_ecs=opts.no_ecs)
    r2 = remoh.RequestDOH('afnic.fr', qtype=opts.rtype, use_edns=opts.edns, want_dnssec=opts.dnssec, no_ecs=opts.no_ecs)
    r2.post = True
    r3 = remoh.RequestDOH('www.rfc-editor.org', qtype=opts.rtype, use_edns=opts.edns, want_dnssec=opts.dnssec, no_ecs=opts.no_ecs)
    r3.head = True

    requests = []
    requests.append(('Test GET', r1, remoh.mandatory_levels["legal"])) # RFC 8484, section 4.1
    requests.append(('Test POST', r2, remoh.mandatory_levels["legal"])) # RFC 8484, section 4.1
    # HEAD method is not mentioned in RFC 8484 (see section 4.1), so just "nice to have".
    requests.append(('Test HEAD', r3, remoh.mandatory_levels["nicetohave"]))

    return do_check(connection, requests, opts)

def check_doh_header(connection, opts, level=remoh.mandatory_levels["nicetohave"],
        accept="application/dns-message", content_type="application/dns-message"):
    # change the MIME value and see what happens
    # based on the RFC only application/dns-message must be supported, any
    # other MIME type can be also supported, but nothing is said on that

    # not using a DoH connection -> exit the test
    if connection.dot:
        return True

    header = ["Accept: %s" % accept, "Content-type: %s" % content_type]
    test_name = "Test Header MIME: %s " % ", ".join(h for h in header)
    r1 = remoh.RequestDOH('curl.haxx.se', qtype=opts.rtype, use_edns=opts.edns, want_dnssec=opts.dnssec, no_ecs=opts.no_ecs)
    r1.post = True

    requests = []
    requests.append((test_name, r1, level))

    handle = connection.curl_handle
    handle.setopt(pycurl.HTTPHEADER, header)

    ok = do_check(connection, requests, opts)

    default_accept = "application/dns-message"
    default_ct = "application/dns-message"
    default_header = ["Accept: %s" % default_accept, "Content-type: %s" % default_ct]
    handle.setopt(pycurl.HTTPHEADER, default_header)

    return ok

def do_check(connection, requests, opts):
    ok = True
    for request_pack in requests:
        test_name, request, level = request_pack

        # the test level is too small, therefore shouldn't be run
        if level < opts.mandatory_level:
            continue

        request.to_wire()

        if connection.debug:
            print(test_name)
        if connection.dot:
            bundle = request
        else:
            handle = connection.curl_handle
            handle.prepare(handle, connection, request)
            bundle = handle

        try:
            connection.send_and_receive(bundle)
        except (remoh.ConnectionException, remoh.DOHException) as e:
            ok = False
            print_check_result(test_name, ok, verbose=connection.verbose)
            print_info(e, connection.connect_to, fd=sys.stderr)
            continue

        if level >= opts.mandatory_level:
            ok = request.check_response(connection.debug)
            if request.rcode == 415 and 'Test Header MIME' in test_name:
                ok = True
        print_check_result(test_name, ok, verbose=connection.verbose)
        print_result(connection, request, prefix=test_name, display_err=not ok)
        if not ok:
            break
    return ok

def check_truncated_query(connection, opts, level=remoh.mandatory_levels["nicetohave"]):
    # send truncated DNS request to the server and expect a HTTP return code
    # either equal to 200 or in the 400 range
    # in case the server answers with 200, look for a FORMERR error in the DNS
    # response

    # the test level is too small, therefore shouldn't be run
    if level < opts.mandatory_level:
       return True

    ok = True

    test_name = 'Test truncated data'

    if connection.dot:
        request = remoh.RequestDOT('example.com', qtype=opts.rtype, use_edns=opts.edns, want_dnssec=opts.dnssec, no_ecs=opts.no_ecs)
    else:
        request = remoh.RequestDOH('example.com', qtype=opts.rtype, use_edns=opts.edns, want_dnssec=opts.dnssec, no_ecs=opts.no_ecs)
        request.post = True

    request.trunc_data()

    if connection.debug:
        print(test_name)
    if connection.dot:
        bundle = request
    else:
        handle = connection.curl_handle
        handle.prepare(handle, connection, request)
        bundle = handle

    try:
        # 8.8.8.8 replies FORMERR but most DoT servers violently shut down the connection (which is legal)
        connection.send_and_receive(bundle, dump=connection.debug)
    except OpenSSL.SSL.ZeroReturnError: # This is acceptable
        return True
    except dns.exception.FormError as e: # This is also acceptable
        # Some DSN resolvers will echo mangled requests with
        # the RCODE set to FORMERR
        # so response can not be parsed in this case
        print_info(e, connection.connect_to, test_name, 'Info', fd=sys.stderr)
        return True
    except remoh.ConnectionDOTException as e:
        print_info(e, connection.connect_to, test_name, 'Info', fd=sys.stderr)
        return connection.state == 'CONN_CLOSED'
    except remoh.DOHException as e:
        print_info(e, connection.connect_to, test_name, 'Info', fd=sys.stderr)
        return False

    if request.check_response(connection.debug): # FORMERR is expected
        if connection.dot:
            ok = request.rcode == dns.rcode.FORMERR
        else:
            ok = (request.response.rcode() == dns.rcode.FORMERR)
    else:
        if connection.dot:
            ok = False
        else: # only a 400 range HTTP code is acceptable
              # if we send garbage to the server, it seems reasonable that it
              # does not fail, which means we don't accept a 500 range HTTP
              # error code (even so it means the server failed to process the
              # input data)
            ok = (request.rcode >= 400 and request.rcode < 500)

    print_check_result(test_name, ok, verbose=connection.verbose)
    print_result(connection, request, prefix=test_name, display_err=not ok)

    return ok

def run_check(connection):
    ok = True
    if connection.dot:
        ok = check_dot_two_requests(connection, opts)
    else:
        ok = check_doh_methods(connection, opts)
    if not ok and opts.mandatory_level >= remoh.mandatory_levels["nicetohave"]:
        return False

    # TODO we miss the tests of pipelining and out-of-order for DoT and
    # multistreams for DoH

    # Test that different Header values are not breaking anything
    if not connection.dot:
        # The DoH server is right to reject these (Example: 'HTTP
        # error 415: only Content-Type: application/dns-message is
        # supported')
        ok = check_doh_header(connection, opts, level=remoh.mandatory_levels["nocrash"], accept="text/html") and ok
        ok = check_doh_header(connection, opts, level=remoh.mandatory_levels["nocrash"], content_type="text/html") and ok

    # test if a truncated query breaks anything
    ok = check_truncated_query(connection, opts, level=remoh.mandatory_levels["nocrash"]) and ok

    return ok

def resolved_ips(host, port, family, dot=False):
    try:
        addr_list = socket.getaddrinfo(host, port, family)
    except socket.gaierror:
        error_and_exit("Could not resolve \"%s\"" % host)
    ip_set = { addr[4][0] for addr in addr_list }
    return ip_set

def parse_opts(opts):
    name = None
    rtype = opts.rtype

    try:
        optlist, args = getopt.getopt (sys.argv[1:], "hvPkeV:r:f:d:t46",
                                       ["help", "verbose", "debug", "dot",
                                        "head", "HEAD", "post", "POST",
                                        "insecure", "vhost=", "multistreams",
                                        "pipelining", "max-in-flight=", "key=",
                                        "dnssec", "noedns", "ecs", "nosni",
                                        "no-display-results", "time",
                                        "file=", "repeat=", "delay=",
                                        "v4only", "v6only",
                                        "check", "mandatory-level="])
        for option, value in optlist:
            if option == "--help" or option == "-h":
                usage()
                sys.exit(0)
            elif option == "--dot" or option == "-t":
                opts.dot = True
            elif option == "--verbose" or option == "-v":
                opts.verbose = True
            elif option == "--debug":
                opts.debug = True
                opts.verbose = True
            elif option == "--HEAD" or option == "--head" or option == "-e":
                opts.head = True
            elif option == "--POST" or option == "--post" or option == "-P":
                opts.post = True
            elif option == "--vhost" or option == "-V":
                opts.vhostname = value
            elif option == "--insecure" or option == "-k":
                opts.insecure = True
            elif option == "--multistreams":
                opts.multistreams = True
            elif option == "--no-display-results":
                opts.display_results = False
            elif option == "--time":
                opts.show_time = True
            elif option == "--dnssec":
                opts.dnssec = True
            elif option == "--nosni":
                opts.sni = False
            elif option == "--noedns": # Warning: it will mean the
                                       # resolver may send ECS
                                       # information to the
                                       # authoritative name servers.
                opts.edns = False
            elif option == "--ecs":
                opts.no_ecs = False
            elif option == "--repeat" or option == "-r":
                opts.tests = int(value)
                if opts.tests <= 1:
                    error_and_exit("--repeat needs a value > 1")
            elif option == "--delay" or option == "-d":
                opts.delay = float(value)
                if opts.delay <= 0:
                    error_and_exit("--delay needs a value > 0")
            elif option == "--file" or option == "-f":
                opts.ifile = value
            elif option == "--key":
                opts.key = value
            elif option == "-4" or option == "--v4only":
                opts.forceIPv4 = True
            elif option == "-6" or option == "--v6only":
                opts.forceIPv6 = True
            elif option == "--pipelining":
                opts.pipelining = True
            elif option == "--max-in-flight":
                opts.max_in_flight = int(value)
                if opts.max_in_flight <= 0:
                    error_and_exit("--max_in_flight but be > 0")
                if opts.max_in_flight >= 65536:
                    error_and_exit("Because of a limit of the DNS protocol (the size of the query ID) --max_in_flight must be < 65 536")
            elif option == "--check":
                opts.check = True
                opts.display_results = False
            elif option == "--mandatory-level":
                opts.mandatory_level = value
            else:
                error_and_exit("Unknown option %s" % option)
    except (getopt.error, ValueError) as reason:
        error_and_exit(reason)

    if opts.delay is not None and opts.multistreams:
        error_and_exit("--delay makes no sense with multistreams")
    if opts.tests <= 1 and opts.delay is not None:
        error_and_exit("--delay makes no sense if there is no repetition")
    if not opts.dot and opts.pipelining:
        error_and_exit("Pipelining is only accepted for DoT")
    if opts.dot and (opts.post or opts.head):
        error_and_exit("POST or HEAD makes non sense for DoT")
    if opts.post and opts.head:
        error_and_exit("POST or HEAD but not both")
    if opts.pipelining and opts.ifile is None:
        error_and_exit("Pipelining requires an input file")
    if opts.check and opts.multistreams:
        error_and_exit("--check and --multistreams are not compatible")
    if opts.dot and opts.multistreams:
        error_and_exit("Multi-streams makes no sense for DoT")
    if opts.multistreams and opts.ifile is None:
        error_and_exit("Multi-streams requires an input file")
    if opts.show_time and opts.dot:
        error_and_exit("--time cannot be used with --dot")
    if not opts.edns and not opts.no_ecs:
        error_and_exit("ECS requires EDNS")
    if opts.mandatory_level is not None and \
       opts.mandatory_level not in remoh.mandatory_levels.keys():
        error_and_exit("Unknown mandatory level \"%s\"" % opts.mandatory_level)
    if opts.mandatory_level is not None and not opts.check:
        error_and_exit("--mandatory-level only makes sense with --check")
    if opts.mandatory_level is None:
        opts.mandatory_level = "necessary"
    opts.mandatory_level = remoh.mandatory_levels[opts.mandatory_level]
    if opts.ifile is None and (len(args) != 2 and len(args) != 3):
        error_and_exit("Wrong number of arguments")
    if opts.ifile is not None and len(args) != 1:
        error_and_exit("Wrong number of arguments (if --file is used, do not indicate the domain name)")
    url = args[0]
    if opts.ifile is None:
        name = args[1]
        if len(args) == 3:
            opts.rtype = args[2]

    return (url, name)

def run_default(name, connection, opts):
    ok = True
    start = time.time()

    if opts.multistreams:
        connection.init_multi()

    for i in range (0, opts.tests):

        if not opts.pipelining and not opts.multistreams:
            if opts.tests > 1 and (opts.verbose or opts.display_results):
                print("\nTest %i" % i)

        if opts.ifile is not None:
            name, opts.rtype = get_next_domain(input)

        if connection.dot:
            request = remoh.RequestDOT(name, qtype=opts.rtype, use_edns=opts.edns,
                     want_dnssec=opts.dnssec, no_ecs=opts.no_ecs)
        else:
            request = remoh.RequestDOH(name, qtype=opts.rtype, use_edns=opts.edns,
                     want_dnssec=opts.dnssec, no_ecs=opts.no_ecs)

        request.to_wire()
        request.i = i

        if not opts.dot:
            request.head = opts.head
            request.post = opts.post

        if opts.pipelining: # We do pipelining (DoT)
            connection.pipelining_add_request(request)
        elif opts.multistreams: # We do multistreams (DoH)
            connection.multistreams_add_request(request)
        else:
            try:
                connection.do_test(request) # perform the query
            except (OpenSSL.SSL.Error, remoh.ConnectionDOTException, remoh.DOHException) as e:
                ok = False
                error(e)
                break
            ok = request.success
            print_result(connection, request)
            if opts.tests > 1 and i == 0:
                start2 = time.time()
            if opts.delay is not None:
                time.sleep(opts.delay)

    if opts.multistreams:
        connection.perform_multi(opts.show_time, display_results=opts.display_results)
    elif opts.pipelining:
        done = 0
        try:
            current = connection.pipelining_init_pending(opts.max_in_flight)
        except remoh.ConnectionDOTException as e:
            ok = False
            error("%s, %i/%i requests never got a reply" % (e, opts.tests - connection.nbr_finished_queries, opts.tests))
        else:
            while done < opts.tests:
                if time.time() > start + remoh.MAX_DURATION: # if we send thousands of requests
                                                       # MAX_DURATION will be reached
                                                       # need to increase MAX_DURATION based
                                                       # on the number of queries
                                                       # or to define a relation such as
                                                       # f(tests) = MAX_DURATION
                    error("Elapsed time too long, %i/%i requests never got a reply" % (opts.tests-done, opts.tests))
                    ok = False
                    break
                id = connection.read_result(connection, connection.pending, display_results=opts.display_results)
                if id is None: # Probably a timeout
                    time.sleep(remoh.SLEEP_TIMEOUT)
                    continue
                done += 1
                over, rank, request = connection.pending[id]
                if not over:
                    error("Internal error, request %i should be over" % id)
                if current < len(connection.all_requests):
                    try:
                        connection.pipelining_fill_pending(current)
                    except remoh.ConnectionDOTException as e:
                        ok = False
                        error("%s, %i/%i requests never got a reply" % (e, opts.tests - connection.nbr_finished_queries, opts.tests))
                        break
                    current += 1

    stop = time.time()

    n_queries = connection.nbr_finished_queries

    if n_queries > 1 and not opts.pipelining and not opts.multistreams:
        extra = ", %.2f ms/request if we ignore the first one" % ((stop-start2)*1000/(n_queries-1))
    else:
        extra = ""
    if not opts.check or opts.verbose:
        time_tot = stop - start
        if n_queries > 1:
            time_per_request = " (%.2f ms/request%s)" % (time_tot / n_queries * 1000, extra)
        else:
            time_per_request = ""
        print("\nTotal elapsed time: %.2f seconds%s" % (time_tot, time_per_request))

    if opts.multistreams and opts.verbose:
        for rcode, n in conn.finished['http'].items():
            print("HTTP %d : %d %.2f%%" % (rcode, n, n / n_queries * 100))

    return ok

# Main program
url, name = parse_opts(opts)

# retrieve all ips when using --check
# not necessary if connectTo is already defined
if not opts.check or opts.connectTo is not None:
    ip_set = {opts.connectTo, }
else:
    if opts.dot:
        port = remoh.PORT_DOT
        if not remoh.is_valid_hostname(url):
            error_and_exit("DoT requires a host name or IP address, not \"%s\"" % url)
        netloc = url
    else:
        port = remoh.PORT_DOH
        if not remoh.is_valid_url(url):
            error_and_exit("DoH requires a valid HTTPS URL, not \"%s\"" % url)
        try:
            url_parts = urllib.parse.urlparse(url) # A very poor validation, many
            # errors (for instance whitespaces, IPv6 address litterals without
            # brackets...) are ignored.
        except ValueError:
            error_and_exit("The provided url \"%s\" could not be parsed" % url)
        netloc = url_parts.netloc
    if opts.forceIPv4:
        family = socket.AF_INET
    elif opts.forceIPv6:
        family = socket.AF_INET6
    else:
        family = 0
    ip_set = resolved_ips(netloc, port, family, opts.dot)

# print number of IPs found
if opts.verbose and opts.check:
    print("Checking \"%s\" ..." % url)
    print("%d IP found : %s" % (len(ip_set), ', '.join(ip_set)))

ok = True
i = 0 # ip counter
for ip in ip_set:
    i += 1
    if opts.dot and opts.vhostname is not None:
        extracheck = opts.vhostname
    else:
        extracheck = None
    if opts.verbose and opts.check and ip:
        print("(%d/%d) checking IP : %s" % (i, len(ip_set), ip))
    try:
        if opts.dot:
            conn = remoh.ConnectionDOT(url, servername=extracheck, connect_to=ip,
                                 forceIPv4=opts.forceIPv4, forceIPv6=opts.forceIPv6,
                                 insecure=opts.insecure, verbose=opts.verbose, debug=opts.debug,
                                 sni=opts.sni, key=opts.key, pipelining=opts.pipelining)
        else:
            conn = remoh.ConnectionDOH(url, servername=extracheck, connect_to=ip,
                                 forceIPv4=opts.forceIPv4, forceIPv6=opts.forceIPv6,
                                 insecure=opts.insecure, verbose=opts.verbose, debug=opts.debug,
                                 multistreams=opts.multistreams)
    except TimeoutError:
        error("timeout")
        ok = False
        continue
    except ConnectionRefusedError:
        error("Connection to server refused")
        ok = False
        continue
    except ValueError:
        error("\"%s\" not a name or an IP address" % url)
        ok = False
        continue
    except socket.gaierror:
        error("Could not resolve \"%s\"" % url)
        ok = False
        continue
    except remoh.ConnectionDOTException as e:
        print(e, file=sys.stderr)
        err = "Could not connect to \"%s\"" % url
        if opts.connectTo is not None:
            err += " on %s" % opts.connectTo
        elif ip is not None:
            err += " on %s" % ip
        error(err)
        ok = False
        continue
    except (remoh.ConnectionException, remoh.DOHException) as e:
        error(e)
        ok = False
        continue

    if conn.dot and not conn.success:
        ok = False
        continue

    if opts.ifile is not None:
        input = open(opts.ifile)

    if not opts.check:
        ok = run_default(name, conn, opts)
    else:
        ok = run_check(conn) and ok # need to run run_check first

    if opts.ifile is not None:
        input.close()

    if conn.state == 'CONN_OK':
        conn.end()

if ok:
    if opts.check or opts.pipelining:
        print('OK')
    sys.exit(0)
else:
    if opts.check:
        print('KO')
    sys.exit(1)
