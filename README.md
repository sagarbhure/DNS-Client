# Remoh

Remoh (formerly Homer) is a DoH (DNS-over-HTTPS) and DoT (DNS-over-TLS) client.
Its main purpose is to test DoH and DoT resolvers.

With the proliferation of public DoH and DoT resolvers, and the implementation
of clients inside OS or applications such as web browsers, we wanted to have an
easy to use command line client to make DoT and DoH queries. Remoh also aims to
assess if a DoT or DoH resolver is compliant with the RFCs (
[RFC 7858](https://www.rfc-editor.org/rfc/rfc7858) for DoT and
[RFC 8484](https://www.rfc-editor.org/rfc/rfc8484) for DoH).


Remoh is a Python3 script using the [dnspython](http://www.dnspython.org/)
library to generate and parse DNS messages, [netaddr](https://github.com/netaddr/netaddr)
to manipulate IP addresses, [PycURL](http://pycurl.io/) to perform the HTTPs
transfers in DoH and [pyOpenSSL](https://www.pyopenssl.org/en/stable/) to
establish TLS session in DoT.

### Contents

* [Usage](#usage)
* [Options](#options)
  - [Repetition of tests](#repetition-of-tests)
  - [Check option](#check-option)
  - [Multistreams](#multistreams)
  - [Pipelining](#pipelining)
  - [A note on the SNI](#a-note-on-the-sni)
* [Monitoring with Nagios, Icinga, or similar software](#monitoring-with-nagios-icinga-or-similar-software)
* [Installation](#installation)
* [Public servers](#public-servers)
* [License](#license)
* [Authors](#authors)

## Usage

Two mandatory arguments, the URL of the DoH server (or name/address of
the DoT resolver), and a domain name to query. By default, Remoh uses
DoH. Also by defaut, the type of data is AAAA (IP address). You can
add a third argument to use another type, as in the second example
below.

```
% remoh https://doh.powerdns.org/ framagit.org
id 0
opcode QUERY
rcode NOERROR
flags QR RD RA
;QUESTION
framagit.org. IN AAAA
;ANSWER
framagit.org. 10800 IN AAAA 2a01:4f8:200:1302::42
;AUTHORITY
;ADDITIONAL
Total elapsed time: 0.40 seconds (402.28 ms/request)

% remoh --dot 9.9.9.9 cocca.fr A
id 42545
opcode QUERY
rcode NOERROR
flags QR RD RA
;QUESTION
cocca.fr. IN A
;ANSWER
cocca.fr. 43200 IN A 185.17.236.69
;AUTHORITY
;ADDITIONAL

Total elapsed time: 0.07 seconds (66.72 ms/request )
```

When using DoT, Remoh first resolves the domain name of the resolver into a
list of IPv4 and IPv6 addresses (or only one subset when using `-4` or `-6`)
and will loop on each of them until a response is received. Hence if Remoh gets
an answer, this mean that at least one DoT resolver is up and running. To check
all the IPs, use `--check`.

For DoH, `PycURL` is responsible to loop on all resolved IPs in turn until one
sends a response to the query. Use `--check` in order to try all the resolved
IPs.

## Options

Several options are available in order to tune the request.

* `-t, --dot` : use DoT
* `-k, --insecure` : do not check certificate validity
* `-v, --verbose` : output more information
* `--debug` : display even more information, when using DoH, `--debug` will
output all the curl vebose information
* `-4, --v4only` : use Ipv4 only
* `-6, --v6only` : use Ipv6 only
* `--dnssec` : request DNSSEC data (signatures)
* `--noedns` : disable EDNS, default is to indicate EDNS support
* `--ecs` : send ECS to authoritative servers, default is to refuse it
* `-r, --repeat <N>` : perform N times the query. If used with -f, read up to
N lines of the FILE
* `-d, --delay <T>` : time to wait in seconds between each synchronous request
(only with --repeat)
* `-f, --file FILE` : provide an input file with a list of domain name to query
(read the first line only, use --repeat N to read up to N lines of the file)
* `--check` : perform a set of predefined tests
* `--mandatory-level LEVEL` : define the LEVEL of test to perform (only
with --check). Available LEVEL : `legal`, `necessary`, `nicetohave`, `nocrash`
* `--no-display-results` : disable output of DNS response, this can be combined
with `-v` to keep only part of the output
* `-V --vhost <vhost>` : define a specific virtual host

#### DoH only options

* `-P, --post, --POST` : use HTTP POST method for all the transfers
* `-e, --head, --HEAD` : use HTTP HEAD method for all the transfers
* `--multistreams` : use HTTP/2 streams, needs an input file with `-f`
* `--time` : display the time elapsed for the query (only with --multistreams)

#### DoT only options

* `--key KEY` : authenticate a DoT resolver with its public KEY in base64
* `--nosni` : do not send the SNI
* `--pipelining` : pipeline the requests, needs an input file with `-f`
* `--max-in-flight M` : maximum number of simultaneous requests


### Repetition of tests

You can repeat the tests several times, for instance for performance
measurements. This is done with option `--repeat N` where N is the
number of repetitions.

```
% remoh --repeat 3 https://doh.bortzmeyer.fr ça.fr SOA
Test 0
...
Test 1
...
Test 2

Total elapsed time: 0.10 seconds (33.56 ms/request , 7.88 ms/request if we ignore the first one)
```

Remoh reuses the same connection for all requests, both for DoH and
DoT, which explains why the first request is often longer.

Repetition is often combined with the use of an external file `-f FILE`, where
Remoh reads the domain names (and types) to query. Here is a sample
file:

```
truc.fr
chose.fr
machin.fr
trucmachin.fr NS
```

Assuming the file is named `list.txt`, this command will run four
tests, with the above names (and the query type `NS` for the last
one):

```
% remoh --repeat 4 --file list.txt https://doh.42l.fr/dns-query
```

When repeating tests, you can add a delay between tests, with `--delay
T` or `-d T`, where T is the (possibly fractional) number of seconds
to wait.

### Check option

The `--check` option allows to run several defined tests on a DoH/DoT
connection. This can be used to test the compliance of the servers with the
RFCs. DoT is standardized in [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858)
and DoH in [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484).

If all the tests passed, Remoh displays `OK`. Otherwise if at least
on test failed, Remoh outputs `KO`. When a test fails, an error message
is displayed.

```
% remoh --check https://doh.bortzmeyer.fr framagit.org
OK

% remoh --dot --check dnsotls.lab.nic.cl wikipedia.org
Could not connect to "dnsotls.lab.nic.cl" on 200.1.123.46
KO
```

When used with an URL for DoH or a domain name for DoT, Remoh loops
on all the resolved IPs. All the tests are then run for each connection.

Each test is marked with a level of compliance. There are three
levels, "legal" (compliant with the strict requirments of the RFCs),
"necessary" (in a typical setup) and "nicetohave". The default level
is "necessary" but you can change it with option
`--mandatory-check`. For instance, sending a reply when the request
uses the HEAD method is "nicetohave" for a DoH server (the RFC does
not mandate it). The tests are always performed but are not fatal if
the choosen level is lower than the level of the test.

#### List of tests for DoT

| level | test |
| ----- | ---- |
| legal | two queries on the same connection |
| nocrash | truncated query |

#### List of tests for DoH

| level | test |
| ----- | ---- |
| legal | HTTP GET method |
| legal | HTTP POST method |
| nicetohave | HTTP HEAD method |
| nocrash | truncated query |
| nocrash | Accept-header: text/html |
| nocrash | Content-type: text/html |

### Multistreams

When using Remoh with DoH, the option `--multistreams` can be used
to specify that you want to take advantage of the HTTP/2 streams
when sending several requests.

This option requires an input file provided with the `-f, --file` option.
By default only the first line of the file is read. You need to
specify a number of line with `--repeat` to read more lines from
the file.

For example :
```
% remoh --multistreams --file input_file --repeat 5 https://doh.powerdns.org
...
Total elapsed time: 0.11 seconds (22.60 ms/request)
```

When dealing with multistreams, Remoh relies on the multi interface
from PycURL (and libcurl). By default all the queries are attached to
the multi object before performing the transfers. For a better use of
the multi interface, see the branch [homer-perf](-/tree/homer-perf).

As soon as a a response is received, it is displayed with the HTTP
return code and the elapsed time for this specific query. This output
can be suppressed with `--no-display-results`.

It is also possible to focus on the elapsed time only with the use
of the `--time` option combined with `--no-display-results`. This shows
the time spent by each transfer independently. The values should be
regard carefully, as they do not reflect the fact that the queries are
done at the same time. The displayed times are based on
[libcurl time values](https://curl.haxx.se/libcurl/c/curl_easy_getinfo.html#TIMES)
[CURLINFO_TOTAL_TIME](https://curl.haxx.se/libcurl/c/curl_easy_getinfo.html#CURLINFOTOTALTIME)
and [CURLINFO_PRETRANSFER_TIME](https://curl.haxx.se/libcurl/c/curl_easy_getinfo.html#CURLINFOPRETRANSFERTIME)
This option will output for each transfer its number in the outgoing
queue, the value of the HTTP return code, the time elapsed until the
transfer begins, the time until the associated response is received
and the difference between these two first times.

Finally note that when using multistreams, an initial DNS request is
sent to initiate the connection with the server. This request asks for
the root NS.

### Pipelining

It is possible to pipeline multiple DoT queries with the option `--pipelining`.
The queries are created based on the provided input file. Up to `N` lines are
read from the file, with `N` defined by the option `--repeat N`. By default
Remoh sends up to 20 requests in parallel before listening for responses.
This value can be changed with `--max-in-flight`.

After sending the first query, Remoh is configured to stop after 10 seconds
has elapsed. This mean that if more queries need to be sent or received 10
seconds after the beginning of the first transfer, they will all be dropped.
To increase this value, update the variable `MAX_DURATION`.

Remoh will display all the DNS response as they arrive. To suppress
this output, use `--no-display-results`.

If not all the queries got a response in `MAX_DURATION` seconds, Remoh
outputs `KO` instead of `OK`.

```
% remoh --dot --pipelining -f input_file -r 5 dns.switch.ch
...
Total elapsed time: 0.56 seconds (111.67 ms/request)
OK

% remoh --dot --pipelining -f huge_file -r 1000 127.0.0.1
...
Elapsed time too long, 42 requests never got a reply
Total elapsed time: 10.29 seconds (10.29 ms/request)
KO
```

### A note on the SNI

By default, Remoh sends a SNI when establishing the TLS session with DoT. The
SNI value is extracted from the name or address of the DoT resolver. If a
literal IP address is used, the SNI will then be set with the IP address.

If you don't want to send the SNI when dealing with literal IP addresses,
use the option `--nosni`.

## Monitoring with Nagios, Icinga, or similar software

If the program is named `check_doh` or ` check_dot` (either from
copying or symbolic linking), it will behave as a [monitoring
plugin](https://www.monitoring-plugins.org/), suitable to be used from monitoring program like Nagios
or [Icinga](https://icinga.com/). The options are different in that case, and follow the
monitoring plugins conventions:

* -H: host name or address to monitor
* -V: virtual hostname (the certificate check will be based on that)
* -n: domain name to lookup
* -t: DNS type to query
* -p: (DoH) path in the URLx
* -e: a string to expect in the result
* -P: uses the HTTP method POST
* -h: uses the HTTP method HEAD
* -i: insecure (do not check the certificate)
* -k:  authenticated the DoT server with this public key

For Icinga, the following definition enables the plugin:

```
object CheckCommand "doh_monitor" {
  command = [ PluginContribDir + "/check_doh" ]

  arguments = {
      "-H" = "$address6$",
	  "-n" = "$doh_lookup$",
	  "-p" = "$doh_path$",
	  "-e" = "$doh_expect$",
	  "-V" = "$doh_vhost$",
	  "-t" = "$doh_type$",
	  "-P" = "$doh_post$",
	  "-i" = "$doh_insecure$",
	  "-h" = "$doh_head$"	
	  }
}

object CheckCommand "dot_monitor" {
  command = [ PluginContribDir + "/check_dot" ]

  arguments = {
      "-H" = "$address6$",
	  "-n" = "$dot_lookup$",
	  "-p" = "$dot_path$",
	  "-e" = "$dot_expect$",
	  "-V" = "$dot_vhost$",
	  "-t" = "$dot_type$",
	  "-P" = "$dot_post$",
	  "-i" = "$dot_insecure$",
	  "-h" = "$dot_head$",
	  "-k" = "$dot_key$"
	}
}

```

And a possible use is:

```
apply Service "doh" {
  import "generic-service"
  check_command = "doh_monitor"
    assign where (host.address || host.address6) && host.vars.doh
      vars.doh_lookup = "fr.wikipedia.org"

}

apply Service "dot" {
  import "generic-service"
  check_command = "dot_monitor"
    assign where (host.address || host.address6) && host.vars.dot
      vars.dot_lookup = "fr.wikipedia.org"

}

```

```
object Host "myserver" {
...
  vars.dot = true
  vars.dot_vhost = "dot.me.example"

  vars.doh = true
  vars.doh_vhost = "doh.me.example"
  vars.doh_post = true

```

## Installation

You need Python 3, [DNSpython](http://www.dnspython.org/),
[PyOpenSSL](https://www.pyopenssl.org/),
[netaddr](https://github.com/drkjam/netaddr/) and
[PycURL](http://pycurl.io/docs/latest). You can install them with pip
`pip3 install dnspython pyOpenSSL netaddr pycurl`. Then, just run the
script `remoh` (or `remoh.py`).

On Debian, if you prefer regular operating system packages to pip,
`apt install python3 python3-dnspython python3-openssl python3-netaddr
python3-pycurl` will install everything you need.

### Testing

The tests configured in `tests.yaml` require
https://framagit.org/feth/test_exe_matrix. Then, just run
`test_exe_matrix tests.yaml`.

## Public servers

(Managed by non-profit organisations. I may trim this list in the
future, to remove servers that do not validate with DNSSEC.)

### DoH

* `https://doh.powerdns.org/`
* `https://doh.bortzmeyer.fr/` ([Documentation](https://doh.bortzmeyer.fr/about)) 
* `https://doh.42l.fr/dns-query` ([Documentation](https://42l.fr/DoH-service))
* `https://odvr.nic.cz/doh` ([Documentation](https://www.nic.cz/odvr/))
* `https://dns.hostux.net/dns-query`
  ([Documentation](https://dns.hostux.net/))
* `https://ldn-fai.net/dns-query` ([Documentation in french](https://ldn-fai.net/serveur-dns-recursif-ouvert/))
* `https://dns.digitale-gesellschaft.ch/dns-query` ([Documentation in german](https://www.digitale-gesellschaft.ch/dns/))
* `https://doh.ffmuc.net`
  ([Documentation](https://ffmuc.net/wiki/doku.php?id=knb:dohdot_en))
* `https://doh.libredns.gr/dns-query`
  ([Documentation](https://libredns.gr/); Also,
  `https://doh.libredns.gr/ads` is a lying resolver, blocking ads and trackers)
* `https://dns.switch.ch/dns-query` ([Documentation](https://www.switch.ch/security/info/public-dns/))
* `https://nat64.tuxis.nl`
  ([Documentation](https://www.tuxis.nl/blog/public-doh-dot-dns64-nat64-service-20191021/);
  NAT64, and no IPv4 address)

### DoT

* `dot.bortzmeyer.fr` ([Documentation](https://doh.bortzmeyer.fr/about)) 
* `dns.digitale-gesellschaft.ch` ([Documentation in german](https://www.digitale-gesellschaft.ch/dns/))
* `dot.ffmuc.net` ([Documentation](https://ffmuc.net/wiki/doku.php?id=knb:dohdot_en)) 
* `ns0.ldn-fai.net` ([Documentation in french](https://ldn-fai.net/serveur-dns-recursif-ouvert/))
* `dot.libredns.gr` ([Documentation](https://libredns.gr/))
* `dns.switch.ch` ([Documentation](https://www.switch.ch/security/info/public-dns/))
* `nat64.tuxis.net`
  ([Documentation](https://www.tuxis.nl/blog/public-doh-dot-dns64-nat64-service-20191021/);
  NAT64, and no IPv4 address)
* `anycast.censurfridns.dk` ([Documentation](https://blog.uncensoreddns.org/))

## License

GPL. See LICENSE.

## Authors

Stéphane Bortzmeyer <stephane+framagit@bortzmeyer.org> and Alexandre
Pion, at [AFNIC](https://www.afnic.fr/).

## Reference site

https://framagit.org/bortzmeyer/homer/ Use the Gitlab issue tracker to
report bugs or wishes.

## See also

* A [simple DoH client](https://github.com/curl/doh), from the author
  of curl.


