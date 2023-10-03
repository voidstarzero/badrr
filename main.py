#!/usr/bin/env python3

import sys  # for argv

# Local package imports
from rrlib.resolver import name_qualify, name_resolve
from rrlib.utils import eprint


def cmd_resolve(qname: str) -> bool:
    """Resolve the given dns_name by performing recursive DNS queries from the root."""

    # Force the string provided to be fully-qualified, as expected by the resolver routines
    qname = name_qualify(qname)

    eprint('info: Resolving name ', qname)

    addresses = name_resolve(qname)

    # The resolver either returns None...
    if addresses is None:
        print(qname, 'does not have an address')
        return False

    # ... or a list with at least one element in it
    for address in addresses:
        print(qname, 'has address', address)
    return True


def cmd_main() -> int:
    """Begin execution of the program from the command line."""

    if len(sys.argv) != 2:
        eprint('usage: ', sys.argv[0], ' <domain-name>')
        return 1

    # At the moment, we only know how to resolve addresses, so do that
    cmd_resolve(sys.argv[1])
    return 0


if __name__ == '__main__':
    exit(cmd_main())
