# TACACS+ Python client

[![Build Status](https://travis-ci.org/ansible/tacacs_plus.svg?branch=master)](https://travis-ci.org/ansible/tacacs_plus)

A TACACS+ client that supports authentication, authorization and
accounting.

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

$ tacacs_plus -h
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
from tacacs_plus.flags import TAC_PLUS_ACCT_FLAG_START, TAC_PLUS_ACCT_FLAG_WATCHDOG, TAC_PLUS_ACCT_FLAG_STOP

cli = TACACSClient('host', 49, 'secret', timeout=10)

# authenticate user and pass
authen = cli.authenticate('username', 'password')
print "PASS!" if authen.valid else "FAIL!"

# authorize user and command
author = cli.authorize('username', arguments=[b"service=shell", b"cmd=show", b"cmdargs=version"])
print "PASS! if author.valid else "FAIL!"

# start accounting session for command
acct = cli.account('username', TAC_PLUS_ACCT_FLAG_START, arguments=[b"service=shell", b"cmd=show", b"cmdargs=version"])
print "PASS! if acct.valid else "FAIL!"

# continue accounting session for another command
acct = cli.account('username', TAC_PLUS_ACCT_FLAG_WATCHDOG, arguments=[b"service=shell", b"cmd=debug", b"cmdargs=aaa"])
print "PASS! if acct.valid else "FAIL!"

# close accounting session
acct = cli.account('username', TAC_PLUS_ACCT_FLAG_STOP, arguments=[b"service=shell", b"cmd=exit"])
print "PASS! if acct.valid else "FAIL!"
```
