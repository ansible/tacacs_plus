# TACACS+ Python client

[![Build Status](https://travis-ci.org/ansible/tacacs_plus.svg?branch=master)](https://travis-ci.org/ansible/tacacs_plus)

A TACACS+ client that supports authentication and authorization.  At this time,
the client does not support the accounting (session management) features of the
TACACS+ protocol.

Unlike RADIUS, which was designed for similar purposes, the TACACS+ protocol
offers basic packet encryption but, as with most crypto designed back then,
it's [not secure](http://www.openwall.com/articles/TACACS+-Protocol-Security)
and definitely should not be used over untrusted networks.

This package has been successfully used with the free
[tac_plus](http://www.shrubbery.net/tac_plus/) TACACS+ server on a variety of
operating systems.

### Basic Installation and Usage
```
$ pip install tacacs_plus

$ tacacs_plus authenticate username localhost --port 49
$ tacacs_plus authenticate username localhost --port 49 --authen_type=pap
$ tacacs_plus authenticate username localhost --port 49 --authen_type=chap

$ tacas_plus -h
usage: tacacs_plus [-h] [--port PORT] [--authen_type {pap,chap,ascii}]
                   [--timeout TIMEOUT] [--debug]
                   {authenticate} username host

simple tacacs+ auth client

positional arguments:
  {authenticate}
  username
  host

optional arguments:
  -h, --help            show this help message and exit
  --port PORT, -p PORT
  --authen_type {pap,chap,ascii}
  --timeout TIMEOUT
  --debug
```

### Programmatic Usage

```python
#!/usr/bin/env python
from tacacs_plus.client import TACACSClient
from tacacs_plus.flags import TAC_PLUS_AUTHEN_TYPE_ASCII

auth = TACACSClient('host', 49, 'secret', timeout=10).authenticate(
    'username', 'password', TAC_PLUS_AUTHEN_TYPE_ASCII
)
print "PASS!" if auth.valid else "FAIL!"
```
