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


class DnsQuestion:
    def __init__(self, qname, qtype, qclass):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    def to_wire(self):
        return dns_encode_string(self.qname) + struct.pack('!HH', self.qtype, self.qclass)


class DnsQueryRequest:
    def __init__(self, qid, qname, qtype, qclass):
        self.qid = qid
        self.question = DnsQuestion(qname, qtype, qclass)

    def to_wire(self):
        return struct.pack('!HHHHHH', self.qid, 0, 1, 0, 0, 0) + self.question.to_wire()


def dns_error_string(rcode):
    return {
        rrparams.CODE_NOERROR: None,
        rrparams.CODE_FORMERR: 'Query rejected due to format error',
        rrparams.CODE_SERVFAIL: 'Query failed due to server error',
        rrparams.CODE_NXDOMAIN: None,
        rrparams.CODE_NOTIMP: 'Query rejected (not implemented)',
        rrparams.CODE_REFUSED: 'Query refused by policy',
    }[rcode]


class DnsRecord:
    def __init__(self, rname, rtype, rclass, rttl, rdata):
        self.rname = rname
        self.rtype = rtype
        self.rclass = rclass
        self.rttl = rttl
        self.rdata = rdata


class DnsQueryResponse:
    def __init__(self, aa, tc, rcode):
        self.aa = aa
        self.tc = tc
        self.nxdomain = rcode == rrparams.CODE_NXDOMAIN
        self.error = dns_error_string(rcode)
        self.question = None
        self.answers = []
        self.authority_zone = None
        self.authorities = []
        self.additionals = collections.defaultdict(list)

    def set_question(self, qname, qtype, qclass):
        self.question = DnsQuestion(qname, qtype, qclass)

    def add_answer(self, rname, rtype, rclass, rttl, rdata):
        self.answers.append(DnsRecord(rname, rtype, rclass, rttl, rdata))

    def add_authority(self, rname, rtype, rclass, rttl, rdata):
        if self.authority_zone is None:
            self.authority_zone = rname
        elif rname != self.authority_zone:
            eprint('error: Inconsistent authorities received in response to query')
            self.error = dns_error_string(rrparams.CODE_FORMERR)
            return

        self.authorities.append(DnsRecord(rname, rtype, rclass, rttl, rdata))

    def add_additional(self, rname, rtype, rclass, rttl, rdata):
        self.additionals[rname].append(DnsRecord(rname, rtype, rclass, rttl, rdata))


def parse_dns_name(buffer, pos):
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
            tail, _ = parse_dns_name(buffer, pointer)
            result += tail
            break

    # Fixup the empty DNS string to signify the root before returning
    if result == '':
        result = '.'
    return result, pos


def ip_address_to_text(ip):
    return "{}.{}.{}.{}".format(ip[0], ip[1], ip[2], ip[3])


def parse_response(response):
    # Parse the header
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', response[:12])
    result = DnsQueryResponse(flags & rrparams.FLAG_BIT_AA,
                              flags & rrparams.FLAG_BIT_TC,
                              flags & rrparams.FLAG_BITS_RCODE)

    if qdcount != 1:
        eprint('error: Received other than 1 question in response')
        return None

    # The question begins with the name asked for
    qname, pos = parse_dns_name(response, 12)
    qtype, qclass = struct.unpack('!HH', response[pos:pos + 4])
    result.set_question(qname, qtype, qclass)
    pos += 4

    for i in range(ancount):
        rname, pos = parse_dns_name(response, pos)
        rtype, rclass, rttl, rdlength = struct.unpack('!HHLH', response[pos:pos + 10])
        pos += 10

        # RDATA for an answer should be 4 long (length of an IPv4 address)
        rdata = ip_address_to_text(response[pos:pos + 4])
        # Jump forward rdlength, no matter what
        pos += rdlength

        eprint('info:     Found answer "', rdata, '"')

        result.add_answer(rname, rtype, rclass, rttl, rdata)

    for i in range(nscount):
        rname, pos = parse_dns_name(response, pos)
        rtype, rclass, rttl, rdlength = struct.unpack('!HHLH', response[pos:pos + 10])
        pos += 10

        # RDATA for an authority should be another name
        rdata, _ = parse_dns_name(response, pos)
        # Jump forward rdlength, no matter what
        pos += rdlength

        eprint('info:     Found referral to "', rdata, '" for zone "', rname, '"')

        result.add_authority(rname, rtype, rclass, rttl, rdata)

    for i in range(arcount):
        rname, pos = parse_dns_name(response, pos)
        rtype, rclass, rttl, rdlength = struct.unpack('!HHLH', response[pos:pos + 10])
        pos += 10

        # We only care about glue A records, nothing else
        if rtype != rrparams.TYPE_A:
            # Skip the RDATA and do the next one instead
            pos += rdlength
            continue

        # RDATA of an A record is 4 long
        rdata = ip_address_to_text(response[pos:pos + 4])
        # Jump forward rdlength, no matter what
        pos += rdlength

        eprint('info:     Found glue "', rdata, '" for "', rname, '"')

        result.add_additional(rname, rtype, rclass, rttl, rdata)

    return result


def send_query(message, target):
    # Create a "connected" UDP socket to query the name server
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(target)

    query = message.to_wire()
    sock.send(query)
    response = sock.recv(512)  # Limit imposed on non-EDNS responses by RFC1035

    result = parse_response(response)

    return result


def dns_resolve(qname):
    """Perform actual recursive resolution for the address record(s) of the given name."""

    # First, pick a root name server (any will do).
    name_server_name, name_server_addr, _ = random.choice(rrparams.ROOT_NAME_SERVERS)
    active_zone = '.'

    while True:
        eprint('info: Querying "', name_server_name,
               '" (', name_server_addr,
               ') for "', qname,
               '" in zone "', active_zone,
               '"')

        qid = random.randrange(65536)
        message = DnsQueryRequest(qid, qname, rrparams.TYPE_A, rrparams.CLASS_IN)

        result = send_query(message, (name_server_addr, rrparams.PORT_DNS_UDP))

        if result.error:
            eprint('error: Query failed due to "', result.error)
            return None
        elif result.nxdomain:
            eprint('info: Name does not exist')
            return None
        elif len(result.answers) > 0:
            eprint('info: Name resolution completed for "', qname, '"')
            return [answer.rdata for answer in result.answers]

        # Not found but not denied either, we should try again with new auth servers
        name_server_name = random.choice([authority.rdata for authority in result.authorities])
        active_zone = result.authority_zone

        # We need to find out the address of the server we've now been asked to query
        if name_server_name in result.additionals:
            name_server_addr = random.choice([additional.rdata for additional in result.additionals[name_server_name]])
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
