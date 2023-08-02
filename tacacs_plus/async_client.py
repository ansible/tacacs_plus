import random
import socket
import logging
import contextlib
from hashlib import md5
import sys
import asyncio


from .flags import (
    TAC_PLUS_MAJOR_VER,
    TAC_PLUS_MINOR_VER,
    TAC_PLUS_PRIV_LVL_MIN,
    TAC_PLUS_AUTHEN_TYPE_CHAP,
    TAC_PLUS_MINOR_VER_ONE,
    TAC_PLUS_AUTHEN_TYPE_PAP,
    TAC_PLUS_AUTHEN,
    TAC_PLUS_AUTHEN_TYPE_ASCII,
    TAC_PLUS_AUTHEN_METH_TACACSPLUS,
    TAC_PLUS_AUTHOR,
    TAC_PLUS_AUTHOR_STATUS_FAIL,
    TAC_PLUS_PRIV_LVL_MAX,
    TAC_PLUS_ACCT,
    TAC_PLUS_VIRTUAL_REM_ADDR,
    TAC_PLUS_VIRTUAL_PORT,
    TAC_PLUS_AUTHEN_STATUS_FAIL,
    TAC_PLUS_CONTINUE_FLAG_ABORT,
)
from .packet import TACACSPacket, TACACSHeader
from .authentication import (
    TACACSAuthenticationStart,
    TACACSAuthenticationContinue,
    TACACSAuthenticationReply,
)
from .authorization import TACACSAuthorizationStart, TACACSAuthorizationReply
from .accounting import TACACSAccountingStart, TACACSAccountingReply

logger = logging.getLogger(__name__)

if sys.version_info < (3, 7):
    raise Exception(
        'Async TACACS client requires Python 3.7+. Current Python version: %s' % sys.version
    )


class TACACSClient(object):
    """
    A TACACS+ authentication client.
    https://datatracker.ietf.org/doc/draft-ietf-opsawg-tacacs

    An open source TACACS+ server daemon is available at
    http://www.shrubbery.net/tac_plus/
    """

    def __init__(
        self,
        host,
        port,
        secret,
        timeout=10,
        session_id=None,
        family=socket.AF_INET,
        version_max=TAC_PLUS_MAJOR_VER,
        version_min=TAC_PLUS_MINOR_VER,
    ):
        """
        :param host:        hostname of the TACACS+ server
        :param port:        port of the TACACS+ server, generally 49
        :param secret:      the secret key used to obfuscate packet bodies; can
                            be None to disable packet body obfuscation
        :param session_id:  a unique 32-bit int representing the session; if
                            left empty, one will be auto-generated
        :param version_max: TACACS+ major version number, 12
        :param version_min: TACACS+ minor version number, 0 or 1
        """
        self.host = host
        self.port = port
        self.secret = secret
        self.timeout = timeout
        self.version_max = version_max
        self.version_min = version_min
        self.family = family

        # session_id is an unsigned 32-bit int; unless it's provided, randomize
        self.session_id = session_id or random.randint(1, 2**32 - 1)

    @property
    def version(self):
        return (self.version_max * 0x10) + self.version_min

    @contextlib.asynccontextmanager
    async def flow_control(self):
        if self.family == socket.AF_INET:
            conn = (self.host, self.port)
        else:
            # For AF_INET6 address family, a four-tuple (host, port,
            # flowinfo, scopeid) is used
            conn = (self.host, self.port, 0, 0)
        sock = socket.socket(self.family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(conn)

        reader, writer = await asyncio.open_connection(sock=sock)
        try:
            yield reader, writer
        finally:
            writer.close()
            await writer.wait_closed()
            sock.close()

    async def send(self, body, req_type, seq_no=1, reader=None, writer=None):
        """
        Send a TACACS+ message body

        :param body:     packed bytes, i.e., struct.pack(...)
        :param req_type: TAC_PLUS_AUTHEN,
                         TAC_PLUS_AUTHOR,
                         TAC_PLUS_ACCT
        :param seq_no:   The sequence number of the current packet.  The
                         first packet in a session MUST have the sequence
                         number 1 and each subsequent packet will increment
                         the sequence number by one.  Thus clients only send
                         packets containing odd sequence numbers, and TACACS+
                         servers only send packets containing even sequence
                         numbers.
        :param reader:   asyncio.StreamReader instance
        :param writer:   asyncio.StreamWriter instance
        :return:         TACACSPacket
        :raises:         socket.timeout, socket.error
        """
        if not reader or not writer:
            raise socket.error('Working outside of context')
        # construct a packet
        header = TACACSHeader(
            self.version,
            req_type,
            self.session_id,
            len(body.packed),
            seq_no=seq_no,
        )
        packet = TACACSPacket(header, body.packed, self.secret)

        debug_message = body.__class__.__name__ + '\n'
        debug_message += 'sent header <%s>' % header + '\n'
        debug_message += 'sent body <%s>' % body
        logger.debug(debug_message)

        writer.write(bytes(packet))
        await writer.drain()

        # TACACS+ header packets are always 12 bytes
        header_bytes = await reader.read(12)
        resp_header = TACACSHeader.unpacked(header_bytes)
        # If the reply header doesn't match, it's likely a non-TACACS+ TCP
        # service answering with data we don't antipicate.  Bail out.
        possible_errors = [
            resp_header.version_max != header.version_max,
            resp_header.type != header.type,
            resp_header.session_id != header.session_id,
        ]
        if any(possible_errors):
            error_message = resp_header.__class__.__name__ + '\n'
            error_message += 'recv header <%s>' % resp_header + '\n'
            error_message += str(resp_header.packed)
            logger.error(error_message)
            raise socket.error

        # read the number of bytes specified in the response header
        body_bytes = b''
        remaining = resp_header.length
        while remaining > 0:
            body_bytes += await reader.read(remaining)
            remaining = resp_header.length - len(body_bytes)
        return TACACSPacket(resp_header, body_bytes, self.secret)

    async def authenticate(
        self,
        username,
        password,
        priv_lvl=TAC_PLUS_PRIV_LVL_MIN,
        authen_type=TAC_PLUS_AUTHEN_TYPE_ASCII,
        chap_ppp_id=None,
        chap_challenge=None,
        rem_addr=TAC_PLUS_VIRTUAL_REM_ADDR,
        port=TAC_PLUS_VIRTUAL_PORT,
    ):
        """
        Authenticate to a TACACS+ server with a username and password.

        :param username:
        :param password:
        :param priv_lvl:
        :param authen_type:    TAC_PLUS_AUTHEN_TYPE_ASCII,
                               TAC_PLUS_AUTHEN_TYPE_PAP,
                               TAC_PLUS_AUTHEN_TYPE_CHAP
        :param chap_ppp_id:    PPP ID when authen_type == 'chap'
        :param chap_challenge: challenge value when authen_type == 'chap'
        :param rem_addr:       AAA request source, default to TAC_PLUS_VIRTUAL_REM_ADDR
        :param port:           AAA port, default to TAC_PLUS_VIRTUAL_PORT
        :return:               TACACSAuthenticationReply
        :raises:               socket.timeout, socket.error
        """
        start_data = b''
        if authen_type in (TAC_PLUS_AUTHEN_TYPE_PAP,
                           TAC_PLUS_AUTHEN_TYPE_CHAP):
            self.version_min = TAC_PLUS_MINOR_VER_ONE

            if authen_type == TAC_PLUS_AUTHEN_TYPE_PAP:
                start_data = password.encode()

            if authen_type == TAC_PLUS_AUTHEN_TYPE_CHAP:
                if not isinstance(chap_ppp_id, str):
                    raise ValueError('chap_ppp_id must be a string')
                if len(chap_ppp_id) != 1:
                    raise ValueError('chap_ppp_id must be a 1-byte string')
                if not isinstance(chap_challenge, str):
                    raise ValueError('chap_challenge must be a string')
                if len(chap_challenge) > 255:
                    raise ValueError('chap_challenge may not be more 255 bytes')

                start_data = chap_ppp_id.encode()
                start_data += chap_challenge.encode()
                data_to_md5 = (chap_ppp_id + password + chap_challenge).encode()
                start_data += md5(data_to_md5).digest()
        async with self.flow_control() as (reader, writer):
            packet = await self.send(
                TACACSAuthenticationStart(
                    username,
                    authen_type,
                    priv_lvl,
                    start_data,
                    rem_addr=rem_addr,
                    port=port,
                ),
                TAC_PLUS_AUTHEN,
                reader=reader,
                writer=writer,
            )
            reply = TACACSAuthenticationReply.unpacked(packet.body)

            debug_message = reply.__class__.__name__ + '\n'
            debug_message += 'recv header <%s>' % packet.header + '\n'
            debug_message += 'recv body <%s>' % reply
            logger.debug(debug_message)

            if authen_type == TAC_PLUS_AUTHEN_TYPE_ASCII and reply.getpass:
                packet = await self.send(
                    TACACSAuthenticationContinue(password),
                    TAC_PLUS_AUTHEN,
                    packet.seq_no + 1,
                    reader,
                    writer,
                )
                reply = TACACSAuthenticationReply.unpacked(packet.body)

                debug_message = reply.__class__.__name__ + '\n'
                debug_message += 'recv header <%s>' % packet.header + '\n'
                debug_message += 'recv body <%s>' % reply
                logger.debug(debug_message)

                if reply.flags == TAC_PLUS_CONTINUE_FLAG_ABORT:
                    reply.status = TAC_PLUS_AUTHEN_STATUS_FAIL

        return reply

    async def authorize(
        self,
        username,
        arguments=None,
        authen_type=TAC_PLUS_AUTHEN_TYPE_ASCII,
        priv_lvl=TAC_PLUS_PRIV_LVL_MIN,
        rem_addr=TAC_PLUS_VIRTUAL_REM_ADDR,
        port=TAC_PLUS_VIRTUAL_PORT,
    ):
        """
        Authorize with a TACACS+ server.

        :param username:
        :param arguments:      The authorization arguments
        :param authen_type:    TAC_PLUS_AUTHEN_TYPE_ASCII,
                               TAC_PLUS_AUTHEN_TYPE_PAP,
                               TAC_PLUS_AUTHEN_TYPE_CHAP
        :param priv_lvl:       Minimal Required priv_lvl.
        :param rem_addr:       AAA request source, default to TAC_PLUS_VIRTUAL_REM_ADDR
        :param port:           AAA port, default to TAC_PLUS_VIRTUAL_PORT
        :return:               TACACSAuthenticationReply
        :raises:               socket.timeout, socket.error
        """
        if arguments is None:
            arguments = []
        async with self.flow_control() as (reader, writer):
            packet = await self.send(
                TACACSAuthorizationStart(
                    username,
                    TAC_PLUS_AUTHEN_METH_TACACSPLUS,
                    priv_lvl,
                    authen_type,
                    arguments,
                    rem_addr=rem_addr,
                    port=port,
                ),
                TAC_PLUS_AUTHOR,
                reader=reader,
                writer=writer,
            )
            reply = TACACSAuthorizationReply.unpacked(packet.body)

            debug_message = reply.__class__.__name__ + '\n'
            debug_message += 'recv header <%s>' % packet.header + '\n'
            debug_message += 'recv body <%s>' % reply
            logger.debug(debug_message)

            reply_arguments = dict(
                [
                    arg.split(b'=', 1)
                    for arg in reply.arguments or []
                    if arg.find(b'=') > -1
                ]
            )
            user_priv_lvl = reply_arguments.get(b'priv-lvl', TAC_PLUS_PRIV_LVL_MAX)
            user_priv_lvl = int(user_priv_lvl)
            if user_priv_lvl < priv_lvl:
                reply.status = TAC_PLUS_AUTHOR_STATUS_FAIL

            return reply

    async def account(
        self,
        username,
        flags,
        arguments=None,
        authen_type=TAC_PLUS_AUTHEN_TYPE_ASCII,
        priv_lvl=TAC_PLUS_PRIV_LVL_MIN,
        rem_addr=TAC_PLUS_VIRTUAL_REM_ADDR,
        port=TAC_PLUS_VIRTUAL_PORT,
    ):
        """
        Account with a TACACS+ server.

        :param username:
        :param flags:          TAC_PLUS_ACCT_FLAG_START,
                               TAC_PLUS_ACCT_FLAG_WATCHDOG,
                               TAC_PLUS_ACCT_FLAG_STOP
        :param arguments:      The authorization arguments
        :param authen_type:    TAC_PLUS_AUTHEN_TYPE_ASCII,
                               TAC_PLUS_AUTHEN_TYPE_PAP,
                               TAC_PLUS_AUTHEN_TYPE_CHAP
        :param priv_lvl:       Minimal Required priv_lvl.
        :param rem_addr:       AAA request source, default to TAC_PLUS_VIRTUAL_REM_ADDR
        :param port:           AAA port, default to TAC_PLUS_VIRTUAL_PORT
        :return:               TACACSAccountingReply
        :raises:               socket.timeout, socket.error
        """
        if arguments is None:
            arguments = []
        async with self.flow_control() as (reader, writer):
            packet = await self.send(
                TACACSAccountingStart(
                    username,
                    flags,
                    TAC_PLUS_AUTHEN_METH_TACACSPLUS,
                    priv_lvl,
                    authen_type,
                    arguments,
                    rem_addr=rem_addr,
                    port=port,
                ),
                TAC_PLUS_ACCT,
                reader=reader,
                writer=writer,
            )
            reply = TACACSAccountingReply.unpacked(packet.body)

            debug_message = reply.__class__.__name__ + '\n'
            debug_message += 'recv header <%s>' % packet.header + '\n'
            debug_message += 'recv body <%s>' % reply
            logger.debug(debug_message)

        return reply
