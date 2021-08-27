# request.py

try:
    # http://www.dnspython.org/
    import dns.message
except ImportError as e:
    print("Error: missing module")
    print(e)
    sys.exit(1)

import remoh

class Request:
    def __init__(self, qname, qtype='AAAA', use_edns=True, want_dnssec=False, no_ecs=True):
        if no_ecs:
             opt = dns.edns.ECSOption(address='', srclen=0) # Disable ECS (RFC 7871, section 7.1.2)
             options = [opt]
        else:
            options = None
        self.message = dns.message.make_query(qname, dns.rdatatype.from_text(qtype),
                                              use_edns=use_edns, want_dnssec=want_dnssec, options=options)
        self.message.flags |= dns.flags.AD # Ask for validation
        self.success = True # True by default, set to False as soon as an error is encountered
        self.i = 0 # request's number on the connection (default to the first)

    def trunc_data(self):
        self.data = self.message.to_wire()
        half = round(len(self.data) / 2)
        self.data = self.data[:half]

    def to_wire(self):
        self.data = self.message.to_wire()

    def has_expected_str(self, string):
        try:
            return string is None or string in str(self.response)
        except AttributeError:
            return False


class RequestDOT(Request):
    # raising custom exception for each unexpected response might be a good idea
    def check_response(self, debug=False):
        if self.response is None:
            self.success = False
            raise remoh.RequestDOTException("No reply received")
        if not self.rcode:
            self.success = False
            return False
        if self.response.id != self.message.id:
            self.response = "The ID in the answer does not match the one in the query"
            if debug:
                self.response += f'"(query id: {self.message.id}) (response id: {self.response.id})'
            self.success = False
            return False
        return self.success

    def store_response(self, rcode, data, size):
        self.rcode = True
        self.response_size = size
        self.response = dns.message.from_wire(data)


class RequestDOH(Request):
    def __init__(self, qname, qtype='AAAA', use_edns=True, want_dnssec=False, no_ecs=True):
        super().__init__(qname, qtype=qtype, use_edns=use_edns, want_dnssec=want_dnssec, no_ecs=no_ecs)
        self.message.id = 0 # DoH requests that
        self.post = False # TODO pass as argument
        self.head = False # pass as argument

    # raising custom exception for each unexpected response might be a good idea
    def check_response(self, debug=False):
        if self.rcode == 200:
            if self.ctype != "application/dns-message":
                self.response = "Content type of the response (\"%s\") invalid" % self.ctype
                self.success = False
            else:
                if not self.head:
                    try:
                        response = dns.message.from_wire(self.response)
                    except dns.message.TrailingJunk: # Not DNS. Should
                        # not happen for a content type
                        # application/dns-message but who knows?
                        self.response = "ERROR Not proper DNS data, trailing junk"
                        if debug:
                            self.response += " \"%s\"" % response
                        self.success = False
                    except dns.name.BadLabelType: # Not DNS.
                        self.response = "ERROR Not proper DNS data (wrong path in the URL?)"
                        if debug:
                            self.response += " \"%s\"" % response[:100]
                        self.success = False
                    else:
                        self.response = response
                else:
                    if self.response_size == 0:
                        self.response = "HEAD successful"
                    else:
                        data = self.response
                        self.response = "ERROR Body length is not null"
                        if debug:
                            self.response += "\"%s\"" % data[:100]
                        self.success = False
        else:
            self.success = False
            if self.response_size == 0:
                self.response = "[No details]"
            else:
                self.response = self.response
        return self.success
