# badrr
A bad recursive DNS resolver

## Usage
```
$ ./badrr example.com
```

## Why?
Why not?

I wanted to learn more about how the low-level details of DNS works, so here is my journey.

## Todo
- Stop relying on the system resolver for *every* name server lookup (process the additional section properly).
- Stop relying on the system resolver for *any* name server lookup (start a separate resolution for glueless delegations).
- Process errors (at all).
- Process errors (correctly).
- Don't crash when a response contains garbage.
- Check various parameters of the response for consistency.
- Cache things (at all).
- Cache things (properly).
