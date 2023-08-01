#!/usr/bin/env python3

import io  # for BytesIO
import random  # for choice
import socket  # for UDP packets
import struct  # for DNS message creation/parsing
import sys  # for argv, stderr

DNS_PORT = 53

CLASS_IN = 1  # Internet class
CLASS_CH = 3  # Chaos class
CLASS_HS = 4  # Hesiod class
CLASS_NONE = 254  # None class (special)
CLASS_ANY = 255  # Any class (special)

TYPE_A = 1  # Address record
TYPE_NS = 2  # Authoritative name server
TYPE_SOA = 6  # Start of zone of authority

FLAG_BIT_QR      = 0b1000000000000000  # Query/response bit
FLAG_BITS_OPCODE = 0b0111100000000000  # Query type code bits
FLAG_BIT_AA      = 0b0000010000000000  # Authoritative answer bit
FLAG_BIT_TC      = 0b0000001000000000  # Truncation bit
FLAG_BIT_RD      = 0b0000000100000000  # Recursion desired bit
FLAG_BIT_RA      = 0b0000000010000000  # Recursion available bit
FLAG_BIT_AD      = 0b0000000000100000  # Authentic data bit
FLAG_BIT_CD      = 0b0000000000010000  # Checking disabled bit
FLAG_BITS_RCODE  = 0b0000000000001111  # Response code bits

OP_QUERY = 0  # Query opcode
OP_IQUERY = 1  # Inverse query opcode
OP_STATUS = 2  # Status opcode
OP_NOTIFY = 4  # Notify opcode
OP_UPDATE = 5  # Update opcode

CODE_NOERROR = 0
CODE_FORMERR = 1
CODE_SERVFAIL = 2
CODE_NXDOMAIN = 3
CODE_NOTIMP = 4
CODE_REFUSED = 5

# A list of every root name server IP
ROOT_NS_IPS = [
    '198.41.0.4',      # a.root-servers.net
    '199.9.14.201',    # b.root-servers.net
    '192.33.4.12',     # c.root-servers.net
    '199.7.91.13',     # d.root-servers.net
    '192.203.230.10',  # e.root-servers.net
    '192.5.5.241',     # f.root-servers.net
    '192.112.36.4',    # g.root-servers.net
    '198.97.190.53',   # h.root-servers.net
    '192.36.148.17',   # i.root-servers.net
    '192.58.128.30',   # j.root-servers.net
    '193.0.14.129',    # k.root-servers.net
    '199.7.83.42',     # l.root-servers.net
    '202.12.27.33',    # j.root-servers.net
]


def eprint(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr, sep='')


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
        CODE_NOERROR: None,
        CODE_FORMERR: 'Query rejected due to format error',
        CODE_SERVFAIL: 'Query failed due to server error',
        CODE_NXDOMAIN: None,
        CODE_NOTIMP: 'Query rejected (not implemented)',
        CODE_REFUSED: 'Query refused by policy',
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
        self.nxdomain = rcode == CODE_NXDOMAIN
        self.error = dns_error_string(rcode)
        self.question = None
        self.answers = []
        self.authority_zone = None
        self.authorities = []

    def set_question(self, qname, qtype, qclass):
        self.question = DnsQuestion(qname, qtype, qclass)

    def add_answer(self, rname, rtype, rclass, rttl, rdata):
        self.answers.append(DnsRecord(rname, rtype, rclass, rttl, rdata))

    def add_authority(self, rname, rtype, rclass, rttl, rdata):
        if self.authority_zone is None:
            self.authority_zone = rname
        elif rname != self.authority_zone:
            eprint('error: Inconsistent authorities received in response to query')
            self.error = dns_error_string(CODE_FORMERR)
            return

        self.authorities.append(DnsRecord(rname, rtype, rclass, rttl, rdata))


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
    result = DnsQueryResponse(flags & FLAG_BIT_AA, flags & FLAG_BIT_TC, flags & FLAG_BITS_RCODE)

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


def do_recursive_resolve(qname, qtype, qclass):
    """Perform actual recursive resolution of the given record name, type and class."""

    # First, pick a root name server (any will do).
    name_server = random.choice(ROOT_NS_IPS)
    active_zone = '.'

    while True:
        eprint('info: Querying "', name_server, '" for zone "', active_zone, '"')

        qid = random.randrange(65536)
        message = DnsQueryRequest(qid, qname, qtype, qclass)

        result = send_query(message, (name_server, DNS_PORT))

        if result.error:
            eprint('error: Query failed due to "', result.error)
            return None
        elif result.nxdomain:
            eprint('info: Name does not exist')
            return None
        elif len(result.answers) > 0:
            eprint('info: Name resolution completed')
            return [answer.rdata for answer in result.answers]

        # Not found but not denied either, we should try again with new auth servers
        name_server = random.choice([authority.rdata for authority in result.authorities])
        active_zone = result.authority_zone


def cmd_resolve(dns_name):
    """Resolve the given dns_name by performing recursive DNS queries from the root."""

    # Force the string provided to be fully-qualified
    if dns_name[-1] != '.':
        dns_name += '.'

    eprint('info: Resolving name "', dns_name, '"')

    addresses = do_recursive_resolve(dns_name, TYPE_A, CLASS_IN)

    if addresses is None:
        print(dns_name, ' does not have an address')
        return False

    for address in addresses:
        print(dns_name, 'has address', address)
    return True


def cmd_main():
    """Begin execution of the program from the command line."""

    # Take the only action we can at the moment, recursively resolve the argument
    cmd_resolve(sys.argv[1])


if __name__ == '__main__':
    cmd_main()
