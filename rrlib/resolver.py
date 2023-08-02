import collections  # for defaultdict
import random  # for choice
import socket  # for UDP packets
import struct  # for DNS message creation/parsing

# Local package imports
import rrlib.cache as rrcache
import rrlib.constants as rrparams
from rrlib.parser import ip_address_decode, label_encode_name, label_decode_name, label_strip_left, name_is_subdomain
from rrlib.utils import eprint


ns_cache = rrcache.RecordCache()    # Cache for already looked-up referrals
addr_cache = rrcache.RecordCache()  # Cache for already looked-up A records


# At the moment, the only type we query is A, and the only class we query is IN
class DnsQuestion:
    def __init__(self, qname: str):
        self.qname = qname

    def __eq__(self, other) -> bool:
        return self.qname == other.qname

    def to_wire(self) -> bytes:
        return (label_encode_name(self.qname) +
                struct.pack('!HH', rrparams.TYPE_A, rrparams.CLASS_IN))


class DnsQuery:
    def __init__(self, qid: int, qname: str):
        self.qid = qid
        self.question = DnsQuestion(qname)

    def to_wire(self) -> bytes:
        return struct.pack('!HHHHHH',
                           self.qid,
                           0,  # All flags clear: outbound, non-recursive query
                           1,  # One question
                           0,  # No answer records
                           0,  # No authority records
                           0   # No additional records
                           ) + self.question.to_wire()


# We only ask IN A questions, so we should only receive IN A answers
class DnsAnswer:
    def __init__(self, rdata: str):
        self.rdata = rdata

    def __eq__(self, other) -> bool:
        return self.rdata == other.rdata


class DnsResponse:
    def __init__(self, rcode: int, authority: str):
        self.error = None
        self.nxdomain = False

        # Any error other than NXDOMAIN is fatal
        if rcode != rrparams.CODE_NOERROR and rcode != rrparams.CODE_NXDOMAIN:
            self.error = rrparams.CODE_ERROR_STRING[rcode]
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

    def set_question(self, qname: str, qtype: int, qclass: int) -> None:
        # We only ever ask IN A questions
        if qtype != rrparams.TYPE_A or qclass != rrparams.CLASS_IN:
            eprint('error: Wrong question type returned (not IN A)')
            self.error = rrparams.CODE_ERROR_STRING[rrparams.CODE_FORMERR]
            return

        self.question = DnsQuestion(qname)

    def add_answer(self, rname: str, rtype: int, rclass: int, rdata: str) -> None:
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

        # Also, put the answer in the cache
        addr_cache.add(rname, rdata)

    def add_authority(self, rname: str, rtype: int, rclass: int, rdata: str) -> None:
        # We are expecting only IN NS records here
        if rtype not in (rrparams.TYPE_NS, rrparams.TYPE_SOA) or rclass != rrparams.CLASS_IN:
            eprint('warning: Extra resource record found in authority section (not IN NS/SOA)')
            return

        # We don't care if someone has packaged us up a spare SOA we didn't ask for,
        # but we don't need it, either
        if rtype == rrparams.TYPE_SOA:
            return

        # Make sure we're only being referred to a subdomain of the current authority
        if not name_is_subdomain(rname, self.authority_zone):
            eprint('warning: A referral to a non-subdomain was present, and is being ignored')
            return

        # The first referral sets the subdomain being referred to, the rest must be the same
        if self.referral_zone is None:
            self.referral_zone = rname
        elif rname != self.referral_zone:
            eprint('error: Inconsistent referrals present in the response, I\'m confused')
            self.error = rrparams.CODE_ERROR_STRING[rrparams.CODE_FORMERR]
            return

        eprint('info:     Found referral to "', rdata, '" for zone "', rname, '"')
        self.referrals.append(DnsAnswer(rdata))

        # Also, put the referral in the cache
        ns_cache.add(rname, rdata)

    def add_additional(self, rname: str, rtype: int, rclass: int, rdata: str) -> None:
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

        # Also, put the address in the cache
        addr_cache.add(rname, rdata)


def parse_response(response: bytes, authority: str) -> DnsResponse | None:
    # Parse the header
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', response[:12])

    # Handle truncation early, no point working through the rest of the steps on half a message
    if flags & rrparams.FLAG_BIT_TC:
        eprint('warning: Response truncated, bailing out early')
        return None

    result = DnsResponse(flags & rrparams.FLAG_BITS_RCODE, authority)

    if qdcount != 1:
        eprint('error: Received other than 1 question in response')
        return None

    # The question begins with the name asked for
    qname, pos = label_decode_name(response, 12)
    qtype, qclass = struct.unpack('!HH', response[pos:pos + 4])
    result.set_question(qname, qtype, qclass)
    pos += 4

    for i in range(ancount):
        rname, pos = label_decode_name(response, pos)
        rtype, rclass, rttl, rdlength = struct.unpack('!HHLH', response[pos:pos + 10])
        pos += 10

        rdata = ip_address_decode(response[pos:pos + 4])
        # Jump forward rdlength, no matter what
        pos += rdlength

        result.add_answer(rname, rtype, rclass, rdata)

    for i in range(nscount):
        rname, pos = label_decode_name(response, pos)
        rtype, rclass, rttl, rdlength = struct.unpack('!HHLH', response[pos:pos + 10])
        pos += 10

        # RDATA for an authority should be another name
        rdata, _ = label_decode_name(response, pos)
        # Jump forward rdlength, no matter what
        pos += rdlength

        result.add_authority(rname, rtype, rclass, rdata)

    for i in range(arcount):
        rname, pos = label_decode_name(response, pos)
        rtype, rclass, rttl, rdlength = struct.unpack('!HHLH', response[pos:pos + 10])
        pos += 10

        # RDATA of an A record is 4 long
        rdata = ip_address_decode(response[pos:pos + 4])
        # Jump forward rdlength, no matter what
        pos += rdlength

        result.add_additional(rname, rtype, rclass, rdata)

    return result


def send_query_udp(query: bytes, target: tuple[str, int]) -> bytes | None:
    """Take a DNS query in wire format, send it to target, and return the response packet."""

    # Create a "connected" UDP socket to query the name server
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(target)
    sock.settimeout(4)  # Suggested in DNS documentation

    sock.send(query)

    try:
        message = sock.recv(512)  # Limit imposed on non-EDNS responses by RFC1035
    except TimeoutError:
        message = None

    sock.close()
    return message


def send_query_tcp(query: bytes, target: tuple[str, int]) -> bytes:
    """Take a DNS query in wire format, send it to target, and read the full response."""

    # Create a "connected" TCP socket to communicate with the name server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(target)

    sock.send(struct.pack('!H', len(query)))
    sock.sendall(query)

    # How much data to follow, assuming here the transport won't split individual bytes
    message_len = struct.unpack('!H', sock.recv(2))[0]

    # Initiate the read loop
    response = bytearray()
    response_len = 0
    while response_len < message_len:
        recv_bytes = sock.recv(message_len - response_len)
        recv_len = len(recv_bytes)

        # Only done when no more to read
        if recv_len == 0:
            break

        # Otherwise, append and keep trying
        response += recv_bytes
        response_len = recv_len

    sock.close()
    return bytes(response)


def name_resolve(qname: str) -> list[str] | None:
    """Perform actual recursive resolution for the address record(s) of the given name."""

    # If we already have an answer, finish early
    if addr_cache.contains(qname):
        eprint('info: Address for "', qname, '" found in cache')
        return addr_cache.get(qname)

    # Find the closest ancestor domain that has its name server names cached
    active_zone = qname
    while active_zone != '.':
        eprint('info: Considering if we already know about "', active_zone, '"...')
        if ns_cache.contains(active_zone):
            # If we find a cached set of name servers, pick one
            eprint('info: Name servers for "', active_zone, '" were already cached, trying to start there...')
            name_server_name = random.choice(ns_cache.get(active_zone))

            # Now we need its address
            candidate_addresses = name_resolve(name_server_name)
            if candidate_addresses is not None:
                name_server_addr = random.choice([addr for addr in candidate_addresses])
                break
            else:
                eprint('warning: Couldn\'t look up address for cached name server "', name_server_name,
                       '", falling through')

        # If we either failed to find cached nameservers, or couldn't find a valid address,
        # we fall to the next level
        active_zone = label_strip_left(active_zone)

    else:
        # Otherwise, pick a root name server (any will do)
        # For now, we only act over IPv4
        name_server_name, name_server_addr, _ = random.choice(rrparams.ROOT_NAME_SERVERS)

    while True:
        eprint('info: Querying "', name_server_name,
               '" (', name_server_addr,
               ') for "', qname,
               '" in zone "', active_zone,
               '"')

        # Build our representation of the A query to be sent to the name server
        qid = random.randrange(65536)
        message = DnsQuery(qid, qname).to_wire()

        # First, try over UDP
        response = send_query_udp(message, (name_server_addr, rrparams.PORT_DNS_UDP))

        # Only try to parse things if we got something back
        if response is None:
            result = None
        else:
            result = parse_response(response, active_zone)

        # If failed for some reason (probably because the packet was lost or discarded due to truncation)
        if result is None:
            eprint("info: UDP query failed, retrying with TCP...")

            response = send_query_tcp(message, (name_server_addr, rrparams.PORT_DNS_TCP))
            result = parse_response(response, active_zone)

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

            candidate_addresses = name_resolve(name_server_name)
            if candidate_addresses is None:
                # We can't go on like this (nowhere to go)!
                eprint('error: Resolution failed because "', name_server_name, '" does not have an address')
                return None

            name_server_addr = random.choice([addr for addr in candidate_addresses])


def name_qualify(name: str) -> str:
    """Translates a (possibly-relative) name into a fully-qualified domain name."""
    # Special case: an empty name should be qualified to the root
    if len(name) == 0:
        return '.'

    # If it already ends in a dot, nothing more to do
    if name[-1] == '.':
        return name

    # Otherwise, append a dot
    return name + '.'
