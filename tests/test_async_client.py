import asyncio
import pytest
from hashlib import md5
import socket
import io
from tacacs_plus.flags import (
    TAC_PLUS_AUTHEN,
    TAC_PLUS_AUTHEN_TYPE_ASCII,
    TAC_PLUS_AUTHEN_TYPE_PAP,
    TAC_PLUS_AUTHEN_TYPE_CHAP,
    TAC_PLUS_PRIV_LVL_MIN,
    TAC_PLUS_PRIV_LVL_MAX,
    TAC_PLUS_AUTHEN_METH_TACACSPLUS,
    TAC_PLUS_ACCT_FLAG_START,
)
from tacacs_plus.packet import TACACSHeader, TACACSPacket
from tacacs_plus.authentication import (
    TACACSAuthenticationStart,
    TACACSAuthenticationContinue,
    TACACSAuthenticationReply,
)
from tacacs_plus.authorization import TACACSAuthorizationStart
from tacacs_plus.accounting import TACACSAccountingStart
from tacacs_plus.async_client import TACACSClient


AUTHENTICATE_HEADER = b'\xc0\x01\x01\x00\x00\x0009\x00\x00\x00'
AUTHENTICATE_HEADER_V12_1 = b'\xc1\x01\x01\x00\x00\x0009\x00\x00\x00'
AUTHENTICATE_HEADER_WRONG = b'\xf0\x01\x01\x00\x00\x0009\x00\x00\x00'
AUTHORIZE_HEADER = b'\xc0\x02\x01\x00\x00\x0009\x00\x00\x00'
ACCOUNT_HEADER = b'\xc0\x03\x01\x00\x00\x0009\x00\x00\x00'


class FakeReader:
    def __init__(self, buff):
        self.buff = buff

    async def read(self, size: int = 0):
        return self.buff.read(size or None)


class FakeWriter:
    def __init__(self, buff: io.BytesIO):
        self.buff = buff

    def write(self, data):
        self.buff.write(data)

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


@pytest.fixture
def patch_connection(monkeypatch, packets):
    async def open_connection(*args, **kwargs):
        return fake_reader, fake_writer

    reader_buff = io.BytesIO(packets)
    reader_buff.seek(0)
    fake_reader = FakeReader(reader_buff)

    writer_buff = io.BytesIO()
    fake_writer = FakeWriter(writer_buff)

    monkeypatch.setattr(asyncio, 'open_connection', open_connection)
    monkeypatch.setattr(socket.socket, 'connect', lambda self, conn: None)
    monkeypatch.setattr(socket.socket, 'close', lambda self: None)

    return writer_buff


# test client send
@pytest.mark.parametrize(
    'packets, state',
    [
        [AUTHENTICATE_HEADER + b'\x06\x01\x00\x00\x00\x00\x00', 'valid'],
        [
            AUTHENTICATE_HEADER + b'\x06\x02\x00\x00\x00\x00\x00',
            'invalid',
        ],
        [
            AUTHENTICATE_HEADER + b'\x10\x05\x01\x00\n\x00\x00Password: ',
            'getpass',
        ],
        [AUTHENTICATE_HEADER + b'\x06\x07\x00\x00\x00\x00\x00', 'error'],
    ],
)
@pytest.mark.asyncio
async def test_client_socket_send(patch_connection, packets, state):
    body = TACACSAuthenticationStart('user123', TAC_PLUS_AUTHEN_TYPE_ASCII)
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    async with client.flow_control() as (reader, writer):
        packet = await client.send(
            body, TAC_PLUS_AUTHEN, reader=reader, writer=writer
        )
    assert isinstance(packet, TACACSPacket)
    reply = TACACSAuthenticationReply.unpacked(packet.body)
    assert getattr(reply, state) is True

    # the first 12 bytes of the packet represent the header
    patch_connection.seek(0)
    sent_header, sent_body = (
        patch_connection.read(12),
        patch_connection.read(),
    )
    body_length = TACACSHeader.unpacked(sent_header).length
    assert len(sent_body) == body_length
    assert body.packed == sent_body


@pytest.mark.parametrize(
    'packets',
    [AUTHENTICATE_HEADER_WRONG + b'\x06\x07\x00\x00\x00\x00\x00'],
)
@pytest.mark.asyncio
async def test_client_socket_send_wrong_headers(patch_connection, packets):
    body = TACACSAuthenticationStart('user123', TAC_PLUS_AUTHEN_TYPE_ASCII)
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    with pytest.raises(socket.error):
        await client.send(
            body,
            TAC_PLUS_AUTHEN,
        )


# test client.authenticate
@pytest.mark.parametrize(
    'packets',
    [
        AUTHENTICATE_HEADER
        + '\x10\x05\x01\x00\n\x00\x00Password: '.encode()
        + AUTHENTICATE_HEADER  # noqa getpass
        + '\x06\x01\x00\x00\x00\x00\x00'.encode()  # auth_valid
    ],
)
@pytest.mark.asyncio
async def test_authenticate_ascii(patch_connection, packets):
    """
    client -> AUTHSTART (username)
              STATUS_GETPASS           <- server
    client -> AUTHCONTINUE (password)
              STATUS_PASS              <- server
    """
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    reply = await client.authenticate(
        'username', 'pass',
    )
    assert reply.valid

    patch_connection.seek(0)
    first_header = TACACSHeader.unpacked(patch_connection.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 0)
    first_body = patch_connection.read(first_header.length)
    assert (
        TACACSAuthenticationStart(
            'username', TAC_PLUS_AUTHEN_TYPE_ASCII
        ).packed
        == first_body
    )

    second_header = TACACSHeader.unpacked(patch_connection.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 0)
    assert second_header.seq_no > first_header.seq_no

    second_body = patch_connection.read()
    assert TACACSAuthenticationContinue('pass').packed == second_body


@pytest.mark.parametrize(
    'packets',
    [
        AUTHENTICATE_HEADER_V12_1 + b'\x06\x01\x00\x00\x00\x00\x00'
    ],  # auth_valid
)
@pytest.mark.asyncio
async def test_authenticate_pap(patch_connection, packets):
    """
    client -> AUTHSTART (user+pass)
              STATUS_PASS              <- server
    """
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    reply = await client.authenticate(
        'username',
        'pass',
        authen_type=TAC_PLUS_AUTHEN_TYPE_PAP,
    )
    assert reply.valid

    patch_connection.seek(0)
    first_header = TACACSHeader.unpacked(patch_connection.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 1)
    first_body = patch_connection.read(first_header.length)
    assert (
        TACACSAuthenticationStart(
            'username', TAC_PLUS_AUTHEN_TYPE_PAP, data='pass'.encode()
        ).packed
        == first_body
    )


@pytest.mark.parametrize(
    'packets',
    [
        AUTHENTICATE_HEADER_V12_1 + b'\x06\x01\x00\x00\x00\x00\x00'
    ],  # auth_valid
)
@pytest.mark.asyncio
async def test_authenticate_chap(patch_connection, packets):
    """
    client -> AUTHSTART user+md5challenge(pass)
              STATUS_PASS                         <- server
    """
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    reply = await client.authenticate(
        'username',
        'pass',
        authen_type=TAC_PLUS_AUTHEN_TYPE_CHAP,
        chap_ppp_id='A',
        chap_challenge='challenge',
    )
    assert reply.valid

    patch_connection.seek(0)
    first_header = TACACSHeader.unpacked(patch_connection.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 1)
    first_body = patch_connection.read(first_header.length)
    assert (
        TACACSAuthenticationStart(
            'username',
            TAC_PLUS_AUTHEN_TYPE_CHAP,
            data=(b'A' + b'challenge' + md5(b'Apasschallenge').digest()),
        ).packed
        == first_body
    )


@pytest.mark.parametrize(
    'packets', [AUTHORIZE_HEADER + b'\x06\x01\x00\x00\x00\x00\x00']
)
@pytest.mark.asyncio
async def test_authorize_ascii(patch_connection, packets):
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    reply = await client.authorize(
        'username',
        arguments=[b'service=shell', b'cmd=show', b'cmdargs=version'],
    )
    assert reply.valid

    patch_connection.seek(0)
    first_header = TACACSHeader.unpacked(patch_connection.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 0)
    first_body = patch_connection.read(first_header.length)
    assert (
        TACACSAuthorizationStart(
            'username',
            TAC_PLUS_AUTHEN_METH_TACACSPLUS,
            TAC_PLUS_PRIV_LVL_MIN,
            TAC_PLUS_AUTHEN_TYPE_ASCII,
            [b'service=shell', b'cmd=show', b'cmdargs=version'],
        ).packed
        == first_body
    )


@pytest.mark.parametrize(
    'packets', [AUTHORIZE_HEADER + b'\x06\x01\x00\x00\x00\x00\x00']
)
@pytest.mark.asyncio
async def test_authorize_pap(patch_connection, packets):
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    reply = await client.authorize(
        'username',
        arguments=[b'service=shell', b'cmd=show', b'cmdargs=version'],
        authen_type=TAC_PLUS_AUTHEN_TYPE_PAP,
    )
    assert reply.valid

    patch_connection.seek(0)
    first_header = TACACSHeader.unpacked(patch_connection.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 0)
    first_body = patch_connection.read(first_header.length)
    assert (
        TACACSAuthorizationStart(
            'username',
            TAC_PLUS_AUTHEN_METH_TACACSPLUS,
            TAC_PLUS_PRIV_LVL_MIN,
            TAC_PLUS_AUTHEN_TYPE_PAP,
            [b'service=shell', b'cmd=show', b'cmdargs=version'],
        ).packed
        == first_body
    )


@pytest.mark.parametrize(
    'packets', [AUTHORIZE_HEADER + b'\x06\x01\x00\x00\x00\x00\x00']
)
@pytest.mark.asyncio
async def test_authorize_chap(patch_connection, packets):
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    reply = await client.authorize(
        'username',
        arguments=[b'service=shell', b'cmd=show', b'cmdargs=version'],
        authen_type=TAC_PLUS_AUTHEN_TYPE_CHAP,
    )
    assert reply.valid

    patch_connection.seek(0)
    first_header = TACACSHeader.unpacked(patch_connection.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 0)
    first_body = patch_connection.read(first_header.length)
    assert (
        TACACSAuthorizationStart(
            'username',
            TAC_PLUS_AUTHEN_METH_TACACSPLUS,
            TAC_PLUS_PRIV_LVL_MIN,
            TAC_PLUS_AUTHEN_TYPE_CHAP,
            [b'service=shell', b'cmd=show', b'cmdargs=version'],
        ).packed
        == first_body
    )


# # test client.account
@pytest.mark.parametrize(
    'packets', [ACCOUNT_HEADER + b'\x06\x00\x00\x00\x00\x01\x00\x00']
)
@pytest.mark.asyncio
async def test_account_start(patch_connection, packets):
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    reply = await client.account(
        'username',
        TAC_PLUS_ACCT_FLAG_START,
        arguments=[b'service=shell', b'cmd=show', b'cmdargs=version'],
    )
    assert reply.valid

    patch_connection.seek(0)
    first_header = TACACSHeader.unpacked(patch_connection.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 0)
    first_body = patch_connection.read(first_header.length)
    assert (
        TACACSAccountingStart(
            'username',
            TAC_PLUS_ACCT_FLAG_START,
            TAC_PLUS_AUTHEN_METH_TACACSPLUS,
            TAC_PLUS_PRIV_LVL_MIN,
            TAC_PLUS_AUTHEN_TYPE_ASCII,
            [b'service=shell', b'cmd=show', b'cmdargs=version'],
        ).packed
        == first_body
    )


@pytest.mark.parametrize(
    'packets',
    [AUTHORIZE_HEADER + b'\x12\x01\x01\x00\x00\x00\x00\x0bpriv-lvl=15'],
)
@pytest.mark.asyncio
async def test_authorize_equal_priv_lvl(patch_connection, packets):
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    reply = await client.authorize(
        'username',
        arguments=[b'service=shell', b'cmd=show', b'cmdargs=version'],
        authen_type=TAC_PLUS_AUTHEN_TYPE_PAP,
        priv_lvl=TAC_PLUS_PRIV_LVL_MAX,
    )
    assert (
        reply.valid
    ), 'the privilege level sent by the server is equal to the requested one (15)'


@pytest.mark.parametrize(
    'packets',
    [AUTHORIZE_HEADER + b'\x11\x01\x01\x00\x00\x00\x00\x0bpriv-lvl=1'],
)
@pytest.mark.asyncio
async def test_authorize_lesser_priv_lvl(patch_connection, packets):
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    reply = await client.authorize(
        'username',
        arguments=[b'service=shell', b'cmd=show', b'cmdargs=version'],
        authen_type=TAC_PLUS_AUTHEN_TYPE_PAP,
        priv_lvl=TAC_PLUS_PRIV_LVL_MAX,
    )
    assert (
        not reply.valid
    ), 'the privilege level sent by the server is less than the requested one (1 < 15)'
