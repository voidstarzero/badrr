#!/usr/bin/env python3

import collections  # for defaultdict
import io  # for BytesIO
import random  # for choice
import socket  # for UDP packets
import struct  # for DNS message creation/parsing
import sys  # for argv, stderr

# Local package imports
import rrlib.constants as rrparams
from rrlib.utils import eprint


def dns_encode_string(s):
    parts = s.split('.')

    result = io.BytesIO()
    for part in parts:
        result.write(struct.pack('!B', len(part)))
        result.write(part.encode('ascii'))

    return result.getvalue()


# At the moment, the only type we query is A, and the only class we query is IN
class DnsQuestion:
    def __init__(self, qname):
        self.qname = qname

    def __eq__(self, other):
        return self.qname == other.qname

    def to_wire(self):
        return (dns_encode_string(self.qname) +
                struct.pack('!HH', rrparams.TYPE_A, rrparams.CLASS_IN))


class DnsQuery:
    def __init__(self, qid, qname):
        self.qid = qid
        self.question = DnsQuestion(qname)

    def to_wire(self):
        return struct.pack('!HHHHHH',
                           self.qid,
                           0,  # All flags clear: outbound, non-recursive query
                           1,  # One question
                           0,  # No answer records
                           0,  # No authority records
                           0   # No additional records
                           ) + self.question.to_wire()


def dns_error_string(rcode):
    return {
        rrparams.CODE_FORMERR:  'Query rejected due to format error',
        rrparams.CODE_SERVFAIL: 'Query failed due to server error',
        rrparams.CODE_NOTIMP:   'Query rejected (not implemented)',
        rrparams.CODE_REFUSED:  'Query refused by policy',
    }[rcode]


# We only ask IN A questions, so we should only receive IN A answers
class DnsAnswer:
    def __init__(self, rdata):
        self.rdata = rdata

    def __eq__(self, other):
        return self.rdata == other.rdata


def dns_is_subdomain(sub, parent):
    """Determine if sub is a proper subdomain of parent"""

    if parent == '.':
        # The root is everything's parent
        return True

    return sub.endswith('.' + parent)


class DnsResponse:
    def __init__(self, rcode, authority):
        self.error = None
        self.nxdomain = False

        # Any error other than NXDOMAIN is fatal
        if rcode != rrparams.CODE_NOERROR and rcode != rrparams.CODE_NXDOMAIN:
            self.error = dns_error_string(rcode)
            eprint('error: From upstream name server: ', self.error)
        elif rcode == rrparams.CODE_NXDOMAIN:
            self.nxdomain = True

        # Store the authority that generated the response, for checking referrals
        self.authority_zone = authority

        # Create class fields for later completion
        self.question = None
        self.answers = []
        self.referral_zone = None
        self.referrals = []
        self.glues = collections.defaultdict(list)

    def set_question(self, qname, qtype, qclass):
        # We only ever ask IN A questions
        if qtype != rrparams.TYPE_A or qclass != rrparams.CLASS_IN:
            eprint('error: Wrong question type returned (not IN A)')
            self.error = dns_error_string(rrparams.CODE_FORMERR)
            return

        self.question = DnsQuestion(qname)

    def add_answer(self, rname, rtype, rclass, rdata):
        # We only ever ask IN A questions
        if rtype != rrparams.TYPE_A or rclass != rrparams.CLASS_IN:
            eprint('warning: Extra resource record found in answer section (not IN A)')
            return

        # We should also reasonably expect the answer to be to our question
        if rname != self.question.qname:
            eprint('warning: Server included more records than I was asking for')
            return

        eprint('info:     Found answer "', rdata, '"')
        self.answers.append(DnsAnswer(rdata))

    def add_authority(self, rname, rtype, rclass, rdata):
        # We are expecting only IN NS records here
        if rtype not in (rrparams.TYPE_NS, rrparams.TYPE_SOA) or rclass != rrparams.CLASS_IN:
            eprint('warning: Extra resource record found in authority section (not IN NS)')
            return

        # We don't care if someone has packaged us up a spare SOA we didn't ask for
        # but we don't need it, either
        if rtype == rrparams.TYPE_SOA:
            return

        # Make sure we're only being referred to a subdomain of the current authority
        if not dns_is_subdomain(rname, self.authority_zone):
            eprint('warning: A referral to a non-subdomain was present, and is being ignored')
            return

        # The first referral sets the subdomain being referred to, the rest must be the same
        if self.referral_zone is None:
            self.referral_zone = rname
        elif rname != self.referral_zone:
            eprint('error: Inconsistent referrals present in the response, I\'m confused')
            self.error = dns_error_string(rrparams.CODE_FORMERR)
            return

        eprint('info:     Found referral to "', rdata, '" for zone "', rname, '"')
        self.referrals.append(DnsAnswer(rdata))

    def add_additional(self, rname, rtype, rclass, rdata):
        # We are expecting only IN A glue records here
        if rtype not in (rrparams.TYPE_A, rrparams.TYPE_AAAA) or rclass != rrparams.CLASS_IN:
            eprint('warning: Extra resource record found in additional section (not IN A/AAAA)')
            return

        # Flag glue that has no relation to the referrals, and don't use it
        if DnsAnswer(rname) not in self.referrals:
            eprint('warning: Unnecessary glue received, eww sticky')
            return

        # Silently discard IPv6 (we're not using it at the moment)
        if rtype == rrparams.TYPE_AAAA:
            return

        eprint('info:     Found glue "', rdata, '" for "', rname, '"')
        self.glues[rname].append(DnsAnswer(rdata))


def dns_parse_name(buffer, pos):
    """Parses the DNS-encoded name stored at pos in buffer to a string."""

    result = ''
    while True:
        # Deal with the length/pointer component
        length = buffer[pos]
        pos += 1

        # Is it over?
        if length == 0:
            break
        # Else, is it a pointer?
        elif length < 0xc0:
            # No, simple case
            result += buffer[pos:pos + length].decode('ascii') + '.'
            pos += length
        # Egads, DNS name compression!
        else:
            # The pointer is formed from low bytes of length and next byte (big endian)
            pointer = ((length & ~0xc0) << 8)  + buffer[pos]
            pos += 1

            # Finish parsing at the new location
            tail, _ = dns_parse_name(buffer, pointer)
            result += tail
            break

    # Fixup the empty DNS string to signify the root before returning
    if result == '':
        result = '.'
    return result, pos


def ip_address_to_text(ip):
    return "{}.{}.{}.{}".format(ip[0], ip[1], ip[2], ip[3])


def dns_parse_response(response, authority):
    # Parse the header
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', response[:12])
    result = DnsResponse(flags & rrparams.FLAG_BITS_RCODE, authority)

    if qdcount != 1:
        eprint('error: Received other than 1 question in response')
        return None

    # The question begins with the name asked for
    qname, pos = dns_parse_name(response, 12)
    qtype, qclass = struct.unpack('!HH', response[pos:pos + 4])
    result.set_question(qname, qtype, qclass)
    pos += 4

    for i in range(ancount):
        rname, pos = dns_parse_name(response, pos)
        rtype, rclass, rttl, rdlength = struct.unpack('!HHLH', response[pos:pos + 10])
        pos += 10

        rdata = ip_address_to_text(response[pos:pos + 4])
        # Jump forward rdlength, no matter what
        pos += rdlength

        result.add_answer(rname, rtype, rclass, rdata)

    for i in range(nscount):
        rname, pos = dns_parse_name(response, pos)
        rtype, rclass, rttl, rdlength = struct.unpack('!HHLH', response[pos:pos + 10])
        pos += 10

        # RDATA for an authority should be another name
        rdata, _ = dns_parse_name(response, pos)
        # Jump forward rdlength, no matter what
        pos += rdlength

        result.add_authority(rname, rtype, rclass, rdata)

    for i in range(arcount):
        rname, pos = dns_parse_name(response, pos)
        rtype, rclass, rttl, rdlength = struct.unpack('!HHLH', response[pos:pos + 10])
        pos += 10

        # RDATA of an A record is 4 long
        rdata = ip_address_to_text(response[pos:pos + 4])
        # Jump forward rdlength, no matter what
        pos += rdlength

        result.add_additional(rname, rtype, rclass, rdata)

    return result


def dns_send_query(query, target):
    """Take a DNS query in wire format, send it to target, and return the response packet."""
    # Create a "connected" UDP socket to query the name server
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(target)

    sock.send(query)
    return sock.recv(512)  # Limit imposed on non-EDNS responses by RFC1035


def dns_resolve(qname):
    """Perform actual recursive resolution for the address record(s) of the given name."""

    # First, pick a root name server (any will do)
    # For now, we only act over IPv4
    name_server_name, name_server_addr, _ = random.choice(rrparams.ROOT_NAME_SERVERS)
    active_zone = '.'

    while True:
        eprint('info: Querying "', name_server_name,
               '" (', name_server_addr,
               ') for "', qname,
               '" in zone "', active_zone,
               '"')

        qid = random.randrange(65536)
        message = DnsQuery(qid, qname)

        response = dns_send_query(message.to_wire(),
                                  (name_server_addr, rrparams.PORT_DNS_UDP))
        result = dns_parse_response(response, active_zone)

        if result.error:
            eprint('error: ', result.error)
            return None
        elif result.nxdomain:
            eprint('info: Name does not exist')
            return None
        elif len(result.answers) > 0:
            eprint('info: Name resolution completed for "', qname, '"')
            return [answer.rdata for answer in result.answers]

        # Not found but not denied either, we should try again with new auth servers
        name_server_name = random.choice([referral.rdata for referral in result.referrals])
        active_zone = result.referral_zone

        # We need to find out the address of the server we've now been asked to query
        if name_server_name in result.glues:
            name_server_addr = random.choice([glue.rdata for glue in result.glues[name_server_name]])
        else:
            # Glueless delegation requires a separate lookup for the name server address
            eprint('info: Need address for "', name_server_name, '", restarting recursive resolution')

            candidate_addresses = dns_resolve(name_server_name)
            if candidate_addresses is None:
                # We can't go on like this (nowhere to go)!
                eprint('error: Resolution failed because "', name_server_name, '" does not have an address')
                return None

            name_server_addr = random.choice([addr for addr in candidate_addresses])


def dns_qualify(name):
    """Translates a (possibly-relative) name into a fully-qualified domain name."""
    # Special case: an empty name should be qualified to the root
    if len(name) == 0:
        return '.'

    # If it already ends in a dot, nothing more to do
    if name[-1] == '.':
        return name

    # Otherwise, append a dot
    return name + '.'


def cmd_resolve(qname):
    """Resolve the given dns_name by performing recursive DNS queries from the root."""

    # Force the string provided to be fully-qualified, as expected by the resolver routines
    qname = dns_qualify(qname)

    eprint('info: Resolving name "', qname, '"')

    addresses = dns_resolve(qname)

    # The resolver either returns None...
    if addresses is None:
        print(qname, 'does not have an address')
        return False

    # ... or a list with at least one element in it
    for address in addresses:
        print(qname, 'has address', address)
    return True


def cmd_main():
    """Begin execution of the program from the command line."""

    if len(sys.argv) != 2:
        eprint('usage: ', sys.argv[0], ' <domain-name>')
        return 1

    # At the moment, we only know how to resolve addresses, so do that
    cmd_resolve(sys.argv[1])
    return 0


if __name__ == '__main__':
    exit(cmd_main())
