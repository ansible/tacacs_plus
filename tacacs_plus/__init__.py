# Copyright (c) 2017 Ansible by Red Hat
# All Rights Reserved.
import sys
import argparse
import getpass
import logging

import six

from .flags import TAC_PLUS_AUTHEN_TYPES
from .client import TACACSClient

logger = logging.getLogger(__name__)


def handle_command_line():
    parser = argparse.ArgumentParser(description='simple tacacs+ auth client')
    parser.add_argument('command', choices=['authenticate'])
    parser.add_argument('username')
    parser.add_argument('host')
    parser.add_argument('--port', '-p', type=int, default=49)
    parser.add_argument('--authen_type', choices=TAC_PLUS_AUTHEN_TYPES,
                        default='ascii')
    parser.add_argument('--timeout', type=int, default=10)
    parser.add_argument('--debug', action='store_true')

    args = parser.parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logger.warn("\033[93mTACACS+ --debug will log raw packet data INCLUDING PASSWORDS; proceed at your own risk!\033[00m")  # noqa

    secret = getpass.getpass('tacacs+ secret: ')
    password = getpass.getpass('password for %s: ' % args.username)

    chap_ppp_id = six.moves.input('chap PPP ID: ') if args.authen_type == 'chap' else None  # noqa
    chap_challenge = six.moves.input('chap challenge: ') if args.authen_type == 'chap' else None  # noqa

    auth = TACACSClient(
        args.host,
        args.port,
        secret,
        timeout=args.timeout
    ).authenticate(args.username, password,
                   authen_type=TAC_PLUS_AUTHEN_TYPES[args.authen_type],
                   chap_ppp_id=chap_ppp_id,
                   chap_challenge=chap_challenge)
    if auth.valid:
        sys.exit(0)
    sys.exit(1)
