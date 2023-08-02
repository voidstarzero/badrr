import ipaddress  # for switching between strings and binary representation

# Local package imports
import rrlib.constants as rrparams


def ip_address_encode(address: str) -> bytes:
    """Convert a textual IP address to 4 octet format"""

    return ipaddress.ip_address(address).packed


def ip_address_decode(address: bytes) -> str:
    """Convert a 4 octet IP address to textual representation"""

    return ipaddress.ip_address(address).exploded


def label_encode_name(name: str) -> bytes | None:
    """Encode a dot-separated domain name in DNS label format."""

    # The root name '.' needs special treatment, and is represented as NUL
    if name == '.':
        return b'\x00'

    labels = name.split('.')
    result = bytearray()

    for label in labels:
        label_len = len(label)

        # RFC1035 specifies a maximum length for each label
        if label_len > rrparams.LABEL_LEN_MAX:
            return None

        result.append(len(label))
        result += label.encode('ascii')

    # RFC1035 also specifies a maximum length of a whole (encoded) DNS name
    if len(result) > rrparams.NAME_LEN_MAX:
        return None

    return bytes(result)


def _label_decode_name(message: bytes, startpos: int, iter_count: int) -> tuple[bytes, int] | None:
    """Recursive helper method for label_decode_name"""

    # Catch a crazy recursive loop and bail out, such as might occur if the
    # compressed label sequence contained a pointer loop
    # We assume that each iteration should be contributing at least one byte
    # to the final result
    if iter_count >= rrparams.NAME_LEN_MAX:
        return None

    # Because of label pointers, we both don't know how large a name is going
    # to be ahead of time, and we need the entire message to decode a single
    # name
    name = bytearray()
    pos = startpos

    while True:
        # Deal with the length/pointer component
        label_len = message[pos]
        pos += 1

        if label_len == 0:
            # NUL label length signifies the end of parsing
            break

        elif label_len >= 0xc0:
            # Egads, DNS name compression!
            # The pointer to the new position is formed from low bytes of
            # the length and the next byte (big endian)
            newpos = ((label_len & ~0xc0) << 8)  + message[pos]
            pos += 1  # Need to keep this to find the true end of the name in the buffer

            # Finish parsing at the new location
            rest, _ = _label_decode_name(message, newpos, iter_count + 1)

            # If decoding of the rest failed, the whole process must also fail
            if rest is None:
                return None

            name += rest
            break

        elif label_len <= rrparams.LABEL_LEN_MAX:
            # Easy, we just take the label as-is
            name += message[pos:pos + label_len]
            name += b'.'

            pos += label_len

        else:
            # Bad length value
            return None

    # Check the overall length for consistency with the name length max
    # Note that our textual representation is one byte shorter, hence >=
    if len(name) >= rrparams.LABEL_LEN_MAX:
        return None

    # The root is once again a special case here, it is computed by the above
    # incorrectly and needs to be fixed up
    if len(name) == 0:
        return b'.', pos

    return bytes(name), pos


def label_decode_name(message: bytes, startpos: int) -> tuple[str, int] | None:
    """Decode a DNS label string to dot-separated format."""

    # Palm most of the work off onto a recursive helper method
    result = _label_decode_name(message, startpos, 0)

    if result is None:
        return None

    name, pos = result
    return name.decode('ascii'), pos


def label_strip_left(name: str) -> str:
    tail = name.split('.', 1)[1]

    # Root ends up empty, so needs special case
    if tail == '':
        return '.'

    return tail


def name_is_subdomain(name: str, parent: str) -> bool:
    """Determine if name is a proper subdomain of parent"""

    if parent == '.':
        # The root is everything's parent
        return True

    return name.endswith('.' + parent)
