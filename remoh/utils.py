# utils.py

import sys
import re
import socket
import urllib.parse

try:
    # https://github.com/drkjam/netaddr/
    import netaddr
except ImportError as e:
    print("Error: missing module")
    print(e)
    sys.exit(1)

import remoh

# Do not change these
re_host = re.compile(r'^([0-9a-z][0-9a-z-\.]*)|([0-9:]+)|([0-9\.])$')

def dump_data(data, text="data"):
    pref = ' ' * (len(text) - 4)
    print(f'{text}: ', data)
    print(pref, 'hex:', " ".join(format(c, '02x') for c in data))
    print(pref, 'bin:', " ".join(format(c, '08b') for c in data))

def is_valid_hostname(name):
    name = canonicalize(name)
    return re_host.search(name)

def canonicalize(hostname):
    result = hostname.lower()
    # TODO handle properly the case where it fails with UnicodeError
    # (two consecutive dots for instance) to get a custom exception
    result = result.encode('idna').decode()
    if result[len(result)-1] == '.':
        result = result[:-1]
    return result

def is_valid_ip_address(addr):
    """ Return True and the address family if the IP address is valid. """
    try:
        baddr = netaddr.IPAddress(addr)
    except netaddr.core.AddrFormatError:
        return (False, None)
    return (True, baddr.version)

def is_valid_url(url):
  try:
    result = urllib.parse.urlparse(url) # A very poor validation, many
    # errors (for instance whitespaces, IPv6 address litterals without
    # brackets...) are ignored.
    return (result.scheme=="https" and result.netloc != "")
  except ValueError:
    return False

def _get_certificate_san(x509cert):
    san = ""
    ext_count = x509cert.get_extension_count()
    for i in range(0, ext_count):
        ext = x509cert.get_extension(i)
        if "subjectAltName" in str(ext.get_short_name()):
            san = str(ext)
    return san

# Try one possible name. Names must be already canonicalized.
def _match_hostname(hostname, possibleMatch):
    if possibleMatch.startswith("*."): # Wildcard
        base = possibleMatch[1:] # Skip the star
        # RFC 6125 says that we MAY accept left-most labels with
        # wildcards included (foo*bar). We don't do it here.
        try:
            (first, rest) = hostname.split(".", maxsplit=1)
        except ValueError: # One-label name
            rest = hostname
        if rest == base[1:]:
            return True
        if hostname == base[1:]:
            return True
        return False
    else:
        return hostname == possibleMatch

# Try all the names in the certificate
def validate_hostname(hostname, cert):
    # Complete specification is in RFC 6125. It is long and
    # complicated and I'm not sure we do it perfectly.
    (is_addr, family) = is_valid_ip_address(hostname)
    hostname = canonicalize(hostname)
    for alt_name in _get_certificate_san(cert).split(", "):
        if alt_name.startswith("DNS:") and not is_addr:
            (start, base) = alt_name.split("DNS:")
            base = canonicalize(base)
            found = _match_hostname(hostname, base)
            if found:
                return True
        elif alt_name.startswith("IP Address:") and is_addr:
            host_i = netaddr.IPAddress(hostname)
            (start, base) = alt_name.split("IP Address:")
            if base.endswith("\n"):
                base = base[:-1]
            try:
                base_i = netaddr.IPAddress(base)
            except netaddr.core.AddrFormatError:
                continue # Ignore broken IP addresses in certificates. Are we too liberal?
            if host_i == base_i:
                return True
        else:
            pass # Ignore unknown alternative name types. May be
                 # accept URI alternative names for DoH,
    # According to RFC 6125, we MUST NOT try the Common Name before the Subject Alternative Names.
    cn = canonicalize(cert.get_subject().commonName)
    found = _match_hostname(hostname, cn)
    if found:
        return True
    return False

def get_addrfamily(addr, forceIPv4=False, forceIPv6=False):
    """Return the family as a socket object of the address."""

    (is_ip, family) = is_valid_ip_address(addr)

    # thoses checks between the IP family and the command line option
    # might need to land somewhere else
    if forceIPv4 and family == 6:
        raise remoh.FamilyException("You cannot force IPv4 with a litteral IPv6 address (%s)" % addr)
    elif forceIPv6 and family == 4:
        raise remoh.FamilyException("You cannot force IPv6 with a litteral IPv4 address (%s)" % addr)

    if forceIPv4 or family == 4:
        family = socket.AF_INET
    elif forceIPv6 or family == 6:
        family = socket.AF_INET6
    else:
        family = 0

    return family

def check_ip_address(addr, forceIPv4=False, forceIPv6=False):
    return get_addrfamily(addr, forceIPv4=forceIPv4, forceIPv6=forceIPv6)
