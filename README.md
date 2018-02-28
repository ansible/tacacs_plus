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

$ tacacs_client -u myuser -H localhost authenticate
$ tacacs_client -u myuser -H localhost authenticate -t pap
$ tacacs_client -u myuser -H localhost -v authenticate -t chap
status: PASS

$ tacacs_client -u myuser -H localhost authorize -c service=shell cmd=show cmdarg=version
$ tacacs_client -u myuser -H localhost -v authorize -t pap -c service=shell cmd=show cmdarg=version
status: PASS

$ tacacs_client -u myuser -H localhost -v authorize -t pap -c service=junos-exec
status: REPL
av-pairs:
    allow-commands=^acommandregex$
    deny-commands=^anothercommandregex$

$ tacacs_client -u myuser -H localhost account -f start -c service=shell cmd=show cmdarg=version
$ tacacs_client -u myuser -H localhost account -f stop -c service=shell cmd=show cmdarg=version

$ tacacs_client -h
usage: tacacs_client [-h] -u USERNAME -H HOST [-p PORT] [-l PRIV_LVL]
                     [-t {ascii,pap,chap}] [-r REM_ADDR] [-P VIRTUAL_PORT]
                     [--timeout TIMEOUT] [-d] [-v] [-k KEY]
                     {authenticate,authorize,account} ...

        Tacacs+ client with full AAA support:

            * Authentication supports both ascii, pap and chap.
            * Authorization supports AV pairs and single commands.
            * Accounting support AV pairs and single commands.

        NOTE: shared encryption key can be set via environment variable TACACS_PLUS_KEY or via argument.
        NOTE: user password can be setup via environment variable TACACS_PLUS_PWD or via argument.


positional arguments:
  {authenticate,authorize,account}
                        action to perform over the tacacs+ server
    authenticate        authenticate against a tacacs+ server
    authorize           authorize a command against a tacacs+ server
    account             account commands with accounting flags against a tacacs+ server

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        user name
  -H HOST, --host HOST  tacacs+ server address
  -p PORT, --port PORT  tacacs+ server port (default 49)
  -l PRIV_LVL, --priv-lvl PRIV_LVL
                        user privilege level
  -t {ascii,pap,chap}, --authen-type {ascii,pap,chap}
                        authentication type
  -r REM_ADDR, --rem-addr REM_ADDR
                        remote address (logged by tacacs server)
  -P VIRTUAL_PORT, --virtual-port VIRTUAL_PORT
                        console port used in connection (logged by tacacs server)
  --timeout TIMEOUT
  -d, --debug           enable debugging output
  -v, --verbose         print responses
  -6, --v6              use IPv6 addresses
  -k KEY, --key KEY     tacacs+ shared encryption key

$ tacacs_client authenticate -h
usage: tacacs_client authenticate [-h] [-p PASSWORD]

optional arguments:
  -h, --help            show this help message and exit
  -p PASSWORD, --password PASSWORD
                        user password

$ tacacs_client authorize -h
usage: tacacs_client authorize [-h] -c CMDS [CMDS ...]

optional arguments:
  -h, --help            show this help message and exit
  -c CMDS [CMDS ...], --cmds CMDS [CMDS ...]
                        list of cmds to authorize

$ tacacs_client account -h
usage: tacacs_client account [-h] -c CMDS [CMDS ...] -f {start,stop,update}

optional arguments:
  -h, --help            show this help message and exit
  -c CMDS [CMDS ...], --cmds CMDS [CMDS ...]
                        list of cmds to authorize
  -f {start,stop,update}, --flag {start,stop,update}
                        accounting flag
```

### Programmatic Usage

```python
#!/usr/bin/env python
from __future__ import print_function

from tacacs_plus.client import TACACSClient
from tacacs_plus.flags import TAC_PLUS_ACCT_FLAG_START, TAC_PLUS_ACCT_FLAG_WATCHDOG, TAC_PLUS_ACCT_FLAG_STOP
import socket

# For IPv6, use `family=socket.AF_INET6`
cli = TACACSClient('host', 49, 'secret', timeout=10, family=socket.AF_INET)

# authenticate user and pass
authen = cli.authenticate('username', 'password')
print("PASS!" if authen.valid else "FAIL!")

# authorize user and command
author = cli.authorize('username', arguments=[b"service=shell", b"cmd=show", b"cmdargs=version"])
print("PASS!" if author.valid else "FAIL!")

# start accounting session for command
acct = cli.account('username', TAC_PLUS_ACCT_FLAG_START, arguments=[b"service=shell", b"cmd=show", b"cmdargs=version"])
print("PASS!" if acct.valid else "FAIL!")

# continue accounting session for another command
acct = cli.account('username', TAC_PLUS_ACCT_FLAG_WATCHDOG, arguments=[b"service=shell", b"cmd=debug", b"cmdargs=aaa"])
print("PASS!" if acct.valid else "FAIL!")

# close accounting session
acct = cli.account('username', TAC_PLUS_ACCT_FLAG_STOP, arguments=[b"service=shell", b"cmd=exit"])
print("PASS!" if acct.valid else "FAIL!")
```
