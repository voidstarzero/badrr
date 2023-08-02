# TCP and UDP port numbers relevant for DNS
PORT_DNS_UDP = 53
PORT_DNS_TCP = 53

# DNS classes
CLASS_IN   = 1    # Internet class
CLASS_ANY  = 255  # Any class (special)

# DNS resource record types
TYPE_A     = 1   # Host address
TYPE_NS    = 2   # Authoritative name server
TYPE_CNAME = 5   # Canonical name for an alias
TYPE_SOA   = 6   # Start of zone of authority
TYPE_PTR   = 12  # Domain name pointer
TYPE_HINFO = 13  # Host information
TYPE_MX    = 15  # Mail exchanger
TYPE_TXT   = 16  # Text strings
TYPE_RP    = 17  # Responsible person
TYPE_AAAA  = 28  # IPv6 host address
TYPE_LOC   = 29  # Location information
TYPE_SRV   = 33  # Service selection
TYPE_DNAME = 39  # Domain subtree redirection

# DNS operation codes
OP_QUERY  = 0  # Query opcode
OP_STATUS = 2  # Status opcode

# DNS response codes
CODE_NOERROR  = 0  # No error
CODE_FORMERR  = 1  # Format error
CODE_SERVFAIL = 2  # Server failure
CODE_NXDOMAIN = 3  # Non-existent domain
CODE_NOTIMP   = 4  # Not implemented
CODE_REFUSED  = 5  # Query refused

# DNS header flags
FLAG_BIT_QR      = 0b1000000000000000  # Query/response
FLAG_BITS_OPCODE = 0b0111100000000000  # Opcode
FLAG_BIT_AA      = 0b0000010000000000  # Authoritative answer
FLAG_BIT_TC      = 0b0000001000000000  # Truncated response
FLAG_BIT_RD      = 0b0000000100000000  # Recursion desired
FLAG_BIT_RA      = 0b0000000010000000  # Recursion available
FLAG_BITS_RCODE  = 0b0000000000001111  # Response code

# Global DNS root nameserver information
ROOT_NAME_SERVERS = [
    # Operated by Verisign, Inc.
    ('a.root-servers.net', '198.41.0.4',     '2001:503:ba3e::2:30'),
    # Operated by Information Sciences Institute
    ('b.root-servers.net', '199.9.14.201',   '2001:500:200::b'),
    # Operated by Cogent Communications
    ('c.root-servers.net', '192.33.4.12',    '2001:500:2::c'),
    # Operated by University of Maryland
    ('d.root-servers.net', '199.7.91.13',    '2001:500:2d::d'),
    # Operated by NASA Ames Research Center
    ('e.root-servers.net', '192.203.230.10', '2001:500:a8::e'),
    # Operated by Information Systems Consortium, Inc.
    ('f.root-servers.net', '192.5.5.241',    '2001:500:2f::f'),
    # Operated by Defense Information Systems Agency
    ('g.root-servers.net', '192.112.36.4',   '2001:500:12::d0d'),
    # Operated by U.S. Army DEVCOM Army Research Lab
    ('h.root-servers.net', '198.97.190.53',  '2001:500:1::53'),
    # Operated by Netnod
    ('i.root-servers.net', '192.36.148.17',  '2001:7fe::53'),
    # Operated by Verisign, Inc.
    ('j.root-servers.net', '192.58.128.30',  '2001:503:c27::2:30'),
    # Operated by RIPE NCC
    ('k.root-servers.net', '193.0.14.129',   '2001:7fd::1'),
    # Operated by ICANN
    ('l.root-servers.net', '199.7.83.42',    '2001:500:9f::42'),
    # Operated by WIDE Project
    ('j.root-servers.net', '202.12.27.33',   '2001:dc3::35'),
]

# Protocol size constants
LABEL_LEN_MAX   = 63             # Length of the longest label in a DNS name
NAME_LEN_MAX    = 255            # Length of the longest DNS name
TTL_VALUE_MAX   = (1 << 31) - 1  # Value of the highest acceptable TTL (in seconds)
MSG_LEN_MAX_UDP = 512            # Length of the largest allowable DNS message passed over UDP
