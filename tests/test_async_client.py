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

    async def read(self, size: int = 0):
        return self.buff.read(size or None)


class FakePair:
    def __init__(self, response_packets):
        self.reader = FakeReader(io.BytesIO(response_packets))
        self.writer = FakeWriter(io.BytesIO())


@pytest.fixture(scope='function')
def fake_pair(request):
    packets = request.node.callspec.params.get('packets')
    return FakePair(packets)


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
async def test_client_socket_send(fake_pair, packets, state):
    body = TACACSAuthenticationStart('user123', TAC_PLUS_AUTHEN_TYPE_ASCII)
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    fake_pair.reader.buff.seek(0)
    packet = await client.send(
        body, TAC_PLUS_AUTHEN, reader=fake_pair.reader, writer=fake_pair.writer
    )
    assert isinstance(packet, TACACSPacket)
    reply = TACACSAuthenticationReply.unpacked(packet.body)
    assert getattr(reply, state) is True

    # the first 12 bytes of the packet represent the header
    fake_pair.writer.buff.seek(0)
    sent_header, sent_body = (
        await fake_pair.writer.read(12),
        await fake_pair.writer.read(),
    )
    body_length = TACACSHeader.unpacked(sent_header).length
    assert len(sent_body) == body_length
    assert body.packed == sent_body


@pytest.mark.parametrize(
    'packets',
    [AUTHENTICATE_HEADER_WRONG + b'\x06\x07\x00\x00\x00\x00\x00'],
)
@pytest.mark.asyncio
async def test_client_socket_send_wrong_headers(fake_pair, packets):
    body = TACACSAuthenticationStart('user123', TAC_PLUS_AUTHEN_TYPE_ASCII)
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    with pytest.raises(socket.error):
        await client.send(
            body,
            TAC_PLUS_AUTHEN,
            reader=fake_pair.reader,
            writer=fake_pair.writer,
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
async def test_authenticate_ascii(fake_pair, packets):
    """
    client -> AUTHSTART (username)
              STATUS_GETPASS           <- server
    client -> AUTHCONTINUE (password)
              STATUS_PASS              <- server
    """
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    reply = await client.authenticate(
        'username', 'pass', reader=fake_pair.reader, writer=fake_pair.writer
    )
    assert reply.valid

    fake_pair.writer.buff.seek(0)
    first_header = TACACSHeader.unpacked(await fake_pair.writer.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 0)
    first_body = fake_pair.writer.buff.read(first_header.length)
    assert (
        TACACSAuthenticationStart(
            'username', TAC_PLUS_AUTHEN_TYPE_ASCII
        ).packed
        == first_body
    )

    second_header = TACACSHeader.unpacked(await fake_pair.writer.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 0)
    assert second_header.seq_no > first_header.seq_no

    second_body = await fake_pair.writer.read()
    assert TACACSAuthenticationContinue('pass').packed == second_body


@pytest.mark.parametrize(
    'packets',
    [
        AUTHENTICATE_HEADER_V12_1 + b'\x06\x01\x00\x00\x00\x00\x00'
    ],  # auth_valid
)
@pytest.mark.asyncio
async def test_authenticate_pap(fake_pair, packets):
    """
    client -> AUTHSTART (user+pass)
              STATUS_PASS              <- server
    """
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    reply = await client.authenticate(
        'username',
        'pass',
        authen_type=TAC_PLUS_AUTHEN_TYPE_PAP,
        reader=fake_pair.reader,
        writer=fake_pair.writer,
    )
    assert reply.valid

    fake_pair.writer.buff.seek(0)
    first_header = TACACSHeader.unpacked(await fake_pair.writer.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 1)
    first_body = await fake_pair.writer.read(first_header.length)
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
async def test_authenticate_chap(fake_pair, packets):
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
        reader=fake_pair.reader,
        writer=fake_pair.writer,
    )
    assert reply.valid

    fake_pair.writer.buff.seek(0)
    first_header = TACACSHeader.unpacked(await fake_pair.writer.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 1)
    first_body = await fake_pair.writer.read(first_header.length)
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
async def test_authorize_ascii(fake_pair, packets):
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    reply = await client.authorize(
        'username',
        arguments=[b'service=shell', b'cmd=show', b'cmdargs=version'],
        reader=fake_pair.reader,
        writer=fake_pair.writer,
    )
    assert reply.valid

    fake_pair.writer.buff.seek(0)
    first_header = TACACSHeader.unpacked(await fake_pair.writer.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 0)
    first_body = await fake_pair.writer.read(first_header.length)
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
async def test_authorize_pap(fake_pair, packets):
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    reply = await client.authorize(
        'username',
        arguments=[b'service=shell', b'cmd=show', b'cmdargs=version'],
        authen_type=TAC_PLUS_AUTHEN_TYPE_PAP,
        reader=fake_pair.reader,
        writer=fake_pair.writer,
    )
    assert reply.valid

    fake_pair.writer.buff.seek(0)
    first_header = TACACSHeader.unpacked(await fake_pair.writer.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 0)
    first_body = await fake_pair.writer.read(first_header.length)
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
async def test_authorize_chap(fake_pair, packets):
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    reply = await client.authorize(
        'username',
        arguments=[b'service=shell', b'cmd=show', b'cmdargs=version'],
        authen_type=TAC_PLUS_AUTHEN_TYPE_CHAP,
        reader=fake_pair.reader,
        writer=fake_pair.writer,
    )
    assert reply.valid

    fake_pair.writer.buff.seek(0)
    first_header = TACACSHeader.unpacked(await fake_pair.writer.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 0)
    first_body = await fake_pair.writer.read(first_header.length)
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
async def test_account_start(fake_pair, packets):
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    reply = await client.account(
        'username',
        TAC_PLUS_ACCT_FLAG_START,
        arguments=[b'service=shell', b'cmd=show', b'cmdargs=version'],
        reader=fake_pair.reader,
        writer=fake_pair.writer,
    )
    assert reply.valid

    fake_pair.writer.buff.seek(0)
    first_header = TACACSHeader.unpacked(await fake_pair.writer.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 0)
    first_body = await fake_pair.writer.read(first_header.length)
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
async def test_authorize_equal_priv_lvl(fake_pair, packets):
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    reply = await client.authorize(
        'username',
        arguments=[b'service=shell', b'cmd=show', b'cmdargs=version'],
        authen_type=TAC_PLUS_AUTHEN_TYPE_PAP,
        priv_lvl=TAC_PLUS_PRIV_LVL_MAX,
        reader=fake_pair.reader,
        writer=fake_pair.writer,
    )
    assert (
        reply.valid
    ), 'the privilege level sent by the server is equal to the requested one (15)'


@pytest.mark.parametrize(
    'packets',
    [AUTHORIZE_HEADER + b'\x11\x01\x01\x00\x00\x00\x00\x0bpriv-lvl=1'],
)
@pytest.mark.asyncio
async def test_authorize_lesser_priv_lvl(fake_pair, packets):
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    reply = await client.authorize(
        'username',
        arguments=[b'service=shell', b'cmd=show', b'cmdargs=version'],
        authen_type=TAC_PLUS_AUTHEN_TYPE_PAP,
        priv_lvl=TAC_PLUS_PRIV_LVL_MAX,
        reader=fake_pair.reader,
        writer=fake_pair.writer,
    )
    assert (
        not reply.valid
    ), 'the privilege level sent by the server is less than the requested one (1 < 15)'
