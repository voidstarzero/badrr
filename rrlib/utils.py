import sys  # for stderr


def eprint(*args, **kwargs):
    """Print the supplied parameters to stderr."""

    return print(*args, **kwargs, file=sys.stderr, sep='')
