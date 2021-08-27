#!/usr/bin/env python3

# Remoh is a DoH (DNS-over-HTTPS) and DoT (DNS-over-TLS) client. Its
# main purpose is to test DoH and DoT resolvers. Reference site is
# <https://framagit.org/bortzmeyer/homer/> See author, documentation,
# etc, there, or in the README.md included with the distribution.
#
# This file can be used to monitor a DoT/DoH server.

import sys
import getopt
import socket
import os.path

try:
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
# "H:n:p:V:t:e:Pih46k:x"
# Options
#   -H <host>   IP address or domain name of the server (necessary). If using
#               DoH, the url will be built as https://<host>/<path>
#   -n <name>   The domain name to resolve (necessary)
#   -V <vhost>  The virtual hostname to use
#   -t <rtype>  The DNS record type to resolve, default AAAA
#   -e <value>  expect (looks for expected string in output)
#   -p <path>   [DoH] URL path of the DoH service
#   -P          [DoH] Use HTTP POST method
#   -h          [DoH] Use HTTP HEAD method
#   -i          Do not check the certificate
#   -x          Do not perform SNI
#   -4          Force IPv4 resolution of url-or-servername
#   -6          Force IPv6 resolution of url-or-servername
#   -k <key>    [DoT] Authenticate a DoT resolver with its public <key> in
#               base64
class opts:
    dot = False # DoH by default
    dnssec = False
    edns = True
    no_ecs = True
    connectTo = None
    # Monitoring plugin only:
    host = None
    vhostname = None
    rtype = 'AAAA'
    expect = None
    path = None
    post = False
    head = False
    insecure = False
    sni = True
    forceIPv4 = False
    forceIPv6 = False
    key = None # SPKI

# For the monitoring plugin
STATE_OK = 0
STATE_WARNING = 1
STATE_CRITICAL = 2
STATE_UNKNOWN = 3
STATE_DEPENDENT = 4

def error(msg=None):
    if msg is None:
        msg = "Unknown error"
    print("%s: %s" % (url, msg))
    sys.exit(STATE_CRITICAL)

def print_result(connection, request, prefix=None, display_err=True):
    dot = connection.dot
    server = connection.server
    rcode = request.rcode
    msg = request.response
    size = request.response_size
    if (dot and rcode) or (not dot and rcode == 200):
        if not request.has_expected_str(opts.expect):
            print("%s Cannot find \"%s\" in response" % (server, opts.expect))
        else:
            if size is not None and size > 0:
                print("%s OK - %s" % (server, "No error for %s/%s, %i bytes received" % (name, opts.rtype, size)))
            else:
                print("%s OK - %s" % (server, "No error"))
    else:
        if not dot:
            print("%s HTTP error - %i: %s" % (server, rcode, msg))
        else:
            print("%s Error - %i: %s" % (server, rcode, msg))

def parse_opts_monitoring(me, opts):
    name = None
    opts.dot = (me == "check_dot")
    rtype = opts.rtype

    try:
        optlist, args = getopt.getopt (sys.argv[1:], "H:n:p:V:t:e:Pih46k:x")
        for option, value in optlist:
            if option == "-H":
                opts.host = value
            elif option == "-V":
                opts.vhostname = value
            elif option == "-n":
                name = value
            elif option == "-t":
                opts.rtype = value
            elif option == "-e":
                opts.expect = value
            elif option == "-p":
                opts.path = value
            elif option == "-P":
                opts.post = True
            elif option == "-h":
                opts.head = True
            elif option == "-i":
                opts.insecure = True
            elif option == "-x":
                opts.sni = False
            elif option == "-4":
                opts.forceIPv4 = True
            elif option == "-6":
                opts.forceIPv6 = True
            elif option == "-k":
                opts.key = value
            else:
                # Should never occur, it is trapped by getopt
                print("Unknown option %s" % option)
                sys.exit(STATE_UNKNOWN)
    except getopt.error as reason:
        print("Option parsing problem %s" % reason)
        sys.exit(STATE_UNKNOWN)

    if len(args) > 0:
        print("Too many arguments (\"%s\")" % args)
        sys.exit(STATE_UNKNOWN)
    if opts.host is None or name is None:
        print("Host (-H) and name to lookup (-n) are necessary")
        sys.exit(STATE_UNKNOWN)
    if opts.post and opts.head:
        print("POST or HEAD but not both")
        sys.exit(STATE_UNKNOWN)
    if opts.dot and (opts.post or opts.head):
        print("POST or HEAD makes no sense for DoT")
        sys.exit(STATE_UNKNOWN)
    if opts.dot and opts.path:
        print("URL path makes no sense for DoT")
        sys.exit(STATE_UNKNOWN)
    if opts.dot:
        url = opts.host
    else:
        if opts.vhostname is None or opts.vhostname == opts.host:
            opts.connectTo = None
            url = "https://%s/" % opts.host
        else:
            opts.connectTo = opts.host
            url = "https://%s/" % opts.vhostname
        if opts.path is not None:
            if opts.path.startswith("/"):
                opts.path = opts.path[1:]
            url += opts.path

    return (url, name)

def run_default(name, connection, opts):
    if connection.dot:
        request = remoh.RequestDOT(name, qtype=opts.rtype, use_edns=opts.edns,
                 want_dnssec=opts.dnssec, no_ecs=opts.no_ecs)
    else:
        request = remoh.RequestDOH(name, qtype=opts.rtype, use_edns=opts.edns,
                 want_dnssec=opts.dnssec, no_ecs=opts.no_ecs)

    request.to_wire()

    if not opts.dot:
        request.head = opts.head
        request.post = opts.post

    try:
        connection.do_test(request)
    except (OpenSSL.SSL.Error, remoh.DOHException) as e:
        error(e)
        return False

    ok = request.success and request.has_expected_str(opts.expect)
    print_result(connection, request)

    return ok

# Main program
if __name__ == '__main__':
    me = os.path.basename(sys.argv[0])

    url, name = parse_opts_monitoring(me, opts)

    # The provided host is indeed a valid IP
    # TODO catch ValueError exception if the host is an url as in :
    # ./check_doh -H https://doh.bortzmeyer.fr -n afnic.fr
    if remoh.is_valid_ip_address(opts.host)[0]:
        opts.connectTo = opts.host

    ok = True
    if opts.dot and opts.vhostname is not None:
        extracheck = opts.vhostname
    else:
        extracheck = None
    try:
        if opts.dot:
            conn = remoh.ConnectionDOT(url, servername=extracheck, connect_to=opts.connectTo,
                                 forceIPv4=opts.forceIPv4, forceIPv6=opts.forceIPv6,
                                 insecure=opts.insecure,
                                 sni=opts.sni, key=opts.key)
        else:
            conn = remoh.ConnectionDOH(url, servername=extracheck, connect_to=opts.connectTo,
                                 forceIPv4=opts.forceIPv4, forceIPv6=opts.forceIPv6,
                                 insecure=opts.insecure)
    except TimeoutError:
        error("timeout")
    except ConnectionRefusedError:
        error("Connection to server refused")
    except ValueError:
        error("\"%s\" not a name or an IP address" % url)
    except socket.gaierror:
        error("Could not resolve \"%s\"" % url)
    except (remoh.ConnectionException, remoh.DOHException) as e:
        error(e)
    if conn.dot and not conn.success:
        ok = False
    else:
        ok = run_default(name, conn, opts)

    conn.end()

    if ok:
        sys.exit(STATE_OK)
    else:
        sys.exit(STATE_CRITICAL)
