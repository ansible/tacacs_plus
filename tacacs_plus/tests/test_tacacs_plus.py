# Copyright (c) 2017 Ansible by Red Hat
# All Rights Reserved.

from hashlib import md5
import socket
import types
from uuid import uuid4

import pytest
import six

import tacacs_plus

AUTH_HEADER = six.b('\xc0\x01\x01\x00\x00\x0009\x00\x00\x00')
AUTH_HEADER_V12_1 = six.b('\xc1\x01\x01\x00\x00\x0009\x00\x00\x00')


@pytest.fixture
def fake_socket(tmpdir_factory, request):
    packets = request.node.callspec.params.get('packets')

    # write data to the "socket"; this must be an actual file, because
    # select.select()() expects a real file descriptor
    filename = str(tmpdir_factory.mktemp('fake-socket').join(str(uuid4())))
    f = open(filename, 'w')
    request.addfinalizer(f.close)

    sockobj = socket._socket.socket if six.PY3 else socket._socketobject

    class fakesocket(sockobj):
        buff = six.BytesIO()

    def _send(self, data):
        self.buff.write(data)
        return len(data)  # number of bytes sent

    sock = fakesocket()
    sock.f = six.BytesIO(packets)
    # socket.socket overrides these at instantiation time to the underlying
    # C implementation; set them here so that we can mock send() and recv()
    # calls
    sock.send = types.MethodType(_send, sock)
    sock.recv = types.MethodType(
        lambda self, _bytes: self.f.read(_bytes),
        sock
    )
    sock.fileno = types.MethodType(lambda self: f.fileno(), sock)
    return sock


@pytest.fixture
def tacacs_header():
    return tacacs_plus.TACACSHeader(
        192,  # version
        tacacs_plus.TAC_PLUS_AUTHEN,
        12345,  # session_id,
        0,  # body len
        1,  # seq_no
    )


@pytest.mark.parametrize('username', ['username', 'long-very-padded-username'])
def test_packet_body_obfuscation(tacacs_header, username):
    header = tacacs_header
    body = tacacs_plus.TACACSAuthenticationStart(
        username,
        tacacs_plus.TAC_PLUS_AUTHEN_TYPE_ASCII
    ).packed
    secret = '6f188b78-964f-4f3e-aea7-da26b7772495'
    encrypted = tacacs_plus.crypt(header, body, secret)
    assert tacacs_plus.crypt(header, encrypted, secret) == body


def test_packet_seq_no(tacacs_header):
    packet = tacacs_plus.TACACSPacket(tacacs_header, '', None)
    assert packet.seq_no == 1


def test_packet_encrypted(tacacs_header):
    assert tacacs_plus.TACACSPacket(tacacs_header, '', None).encrypted is False
    assert tacacs_plus.TACACSPacket(tacacs_header, '', 'secret').encrypted is True


@pytest.mark.parametrize('secret_key', ('secret', None))
def test_packet_raw(secret_key, tacacs_header):
    header = tacacs_header
    body = tacacs_plus.TACACSAuthenticationStart(
        'user123',
        tacacs_plus.TAC_PLUS_AUTHEN_TYPE_ASCII
    )
    header.length = len(body.packed)
    packet = tacacs_plus.TACACSPacket(header, body.packed, secret_key)
    assert isinstance(packet.header, tacacs_plus.TACACSHeader)

    if secret_key:
        assert bytes(packet) == header.packed + tacacs_plus.crypt(header,
                                                               body.packed,
                                                               secret_key)
    else:
        assert bytes(packet) == header.packed + body.packed


def test_header_pack(tacacs_header):
    packed = tacacs_header.packed
    unpacked = tacacs_plus.TACACSHeader.unpacked(packed)
    assert unpacked.version == 192
    assert unpacked.type == tacacs_plus.TAC_PLUS_AUTHEN
    assert unpacked.session_id == 12345
    assert unpacked.length == 0
    assert unpacked.seq_no == 1
    assert unpacked.flags == 0


def test_auth_start_pack():
    username = 'user123'
    packed = tacacs_plus.TACACSAuthenticationStart(
        username,
        tacacs_plus.TAC_PLUS_AUTHEN_TYPE_ASCII
    ).packed
    assert packed == six.b(
        '\x01'  # tacacs_plus.TAC_PLUS_AUTHEN_LOGIN \
        '\x00'  # tacacs_plus.TAC_PLUS_PRIV_LVL_MIN \
        '\x01'  # tacacs_plus.TAC_PLUS_AUTHEN_TYPE_ASCII \
        '\x01'  # tacacs_plus.TAC_PLUS_AUTHEN_SVC_LOGIN \
        '\x07'  # username len == 7 \
        '\x00'  # port_len \
        '\x00'  # rem_addr_len \
        '\x00'  # data_len \
        'user123'
    )


def test_auth_continue_pack():
    password = 'password'
    packed = tacacs_plus.TACACSAuthenticationContinue(password).packed
    assert packed == six.b(
        '\x00\x08'  # user_msg len (password length) \
        '\x00\x00'  # data_len \
        '\x00'      # flags \
        'password'
    )


@pytest.mark.parametrize('raw, state, human_status', [
    (six.b('\x01\x00\x00\x00\x00\x00'), 'valid', 'PASS'),
    (six.b('\x02\x00\x00\x00\x00\x00'), 'invalid', 'FAIL',),
    (six.b('\x07\x00\x00\x00\x00\x00'), 'error', 'ERROR'),
])
def test_auth_reply_unpack(raw, state, human_status):
    reply = tacacs_plus.TACACSAuthenticationReply.unpacked(raw)
    assert getattr(reply, state) is True
    assert reply.human_status == human_status


def test_auth_reply_unpack_server_msg():
    reply = tacacs_plus.TACACSAuthenticationReply.unpacked(
        six.b('\x05\x01\x00\n\x00\x00Password: ')
    )
    assert reply.getpass is True
    assert reply.server_msg == six.b('Password: ')
    assert reply.human_status == 'GETPASS'


@pytest.mark.parametrize(
    'packets, state',
    [
        [AUTH_HEADER + six.b('\x06\x01\x00\x00\x00\x00\x00'), 'valid'],
        [AUTH_HEADER + six.b('\x06\x02\x00\x00\x00\x00\x00'), 'invalid'],
        [AUTH_HEADER + six.b('\x10\x05\x01\x00\n\x00\x00Password: '), 'getpass'],  # noqa
        [AUTH_HEADER + six.b('\x06\x07\x00\x00\x00\x00\x00'), 'error'],
    ]
)
def test_client_socket_send(fake_socket, packets, state):
    body = tacacs_plus.TACACSAuthenticationStart(
        'user123',
        tacacs_plus.TAC_PLUS_AUTHEN_TYPE_ASCII
    )
    client = tacacs_plus.TACACSClient('127.0.0.1', 49, None, session_id=12345)
    client._sock = fake_socket
    packet = client.send(body, tacacs_plus.TAC_PLUS_AUTHEN)
    assert isinstance(packet, tacacs_plus.TACACSPacket)
    reply = tacacs_plus.TACACSAuthenticationReply.unpacked(packet.body)
    assert getattr(reply, state) is True

    # the first 12 bytes of the packet represent the header
    fake_socket.buff.seek(0)
    sent_header, sent_body = (
        fake_socket.buff.read(12), fake_socket.buff.read()
    )

    body_length = tacacs_plus.TACACSHeader.unpacked(sent_header).length
    assert len(sent_body) == body_length
    assert body.packed == sent_body


@pytest.mark.parametrize(
    'packets',
    [
        AUTH_HEADER + six.b('\x10\x05\x01\x00\n\x00\x00Password: ') +  # noqa getpass
        AUTH_HEADER + six.b('\x06\x01\x00\x00\x00\x00\x00')  # auth_valid
    ]
)
def test_authenticate_ascii(fake_socket, packets):
    """
    client -> AUTHSTART (username)
              STATUS_GETPASS           <- server
    client -> AUTHCONTINUE (password)
              STATUS_PASS              <- server
    """
    client = tacacs_plus.TACACSClient('127.0.0.1', 49, None, session_id=12345)
    client._sock = fake_socket
    reply = client.authenticate('username', 'pass')
    assert reply.valid

    fake_socket.buff.seek(0)
    first_header = tacacs_plus.TACACSHeader.unpacked(fake_socket.buff.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 0)
    first_body = fake_socket.buff.read(first_header.length)
    assert tacacs_plus.TACACSAuthenticationStart(
        'username',
        tacacs_plus.TAC_PLUS_AUTHEN_TYPE_ASCII
    ).packed == first_body

    second_header = tacacs_plus.TACACSHeader.unpacked(fake_socket.buff.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 0)
    assert second_header.seq_no > first_header.seq_no

    second_body = fake_socket.buff.read()
    assert tacacs_plus.TACACSAuthenticationContinue('pass').packed == second_body


@pytest.mark.parametrize(
    'packets',
    [AUTH_HEADER_V12_1 + six.b('\x06\x01\x00\x00\x00\x00\x00')]  # auth_valid
)
def test_authenticate_pap(fake_socket, packets):
    """
    client -> AUTHSTART (user+pass)
              STATUS_PASS              <- server
    """
    client = tacacs_plus.TACACSClient('127.0.0.1', 49, None, session_id=12345)
    client._sock = fake_socket
    reply = client.authenticate('username', 'pass',
                                authen_type=tacacs_plus.TAC_PLUS_AUTHEN_TYPE_PAP)
    assert reply.valid

    fake_socket.buff.seek(0)
    first_header = tacacs_plus.TACACSHeader.unpacked(fake_socket.buff.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 1)
    first_body = fake_socket.buff.read(first_header.length)
    assert tacacs_plus.TACACSAuthenticationStart(
        'username',
        tacacs_plus.TAC_PLUS_AUTHEN_TYPE_PAP,
        data=six.b('pass')
    ).packed == first_body


@pytest.mark.parametrize(
    'packets',
    [AUTH_HEADER_V12_1 + six.b('\x06\x01\x00\x00\x00\x00\x00')]  # auth_valid
)
def test_authenticate_chap(fake_socket, packets):
    """
    client -> AUTHSTART user+md5challenge(pass)
              STATUS_PASS                         <- server
    """
    client = tacacs_plus.TACACSClient('127.0.0.1', 49, None, session_id=12345)
    client._sock = fake_socket
    reply = client.authenticate('username', 'pass',
                                authen_type=tacacs_plus.TAC_PLUS_AUTHEN_TYPE_CHAP,
                                chap_ppp_id='A',
                                chap_challenge='challenge')
    assert reply.valid

    fake_socket.buff.seek(0)
    first_header = tacacs_plus.TACACSHeader.unpacked(fake_socket.buff.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 1)
    first_body = fake_socket.buff.read(first_header.length)
    assert tacacs_plus.TACACSAuthenticationStart(
        'username',
        tacacs_plus.TAC_PLUS_AUTHEN_TYPE_CHAP,
        data=(
            six.b('A') +
            six.b('challenge') +
            md5(six.b('Apasschallenge')).digest()
        )
    ).packed == first_body


def test_authenticate_chap_ppp_id_required():
    client = tacacs_plus.TACACSClient('127.0.0.1', 49, None, session_id=12345)
    with pytest.raises(ValueError):
        client.authenticate('username', 'pass',
                            authen_type=tacacs_plus.TAC_PLUS_AUTHEN_TYPE_CHAP,
                            chap_challenge='challenge')


def test_authenticate_chap_challenge_required():
    client = tacacs_plus.TACACSClient('127.0.0.1', 49, None, session_id=12345)
    with pytest.raises(ValueError):
        client.authenticate('username', 'pass',
                            authen_type=tacacs_plus.TAC_PLUS_AUTHEN_TYPE_CHAP,
                            chap_ppp_id='X')
