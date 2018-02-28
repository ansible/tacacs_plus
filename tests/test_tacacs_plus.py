# Copyright (c) 2017 Ansible by Red Hat
# All Rights Reserved.

from hashlib import md5
import socket
import types
from uuid import uuid4

import pytest
import six

from tacacs_plus.flags import (
    TAC_PLUS_AUTHEN, TAC_PLUS_AUTHEN_TYPE_ASCII,
    TAC_PLUS_AUTHEN_TYPE_PAP, TAC_PLUS_AUTHEN_TYPE_CHAP,
    TAC_PLUS_PRIV_LVL_MIN, TAC_PLUS_PRIV_LVL_MAX,
    TAC_PLUS_AUTHEN_METH_TACACSPLUS,
    TAC_PLUS_ACCT_FLAG_START
)
from tacacs_plus.packet import TACACSHeader, TACACSPacket, crypt
from tacacs_plus.authentication import (
    TACACSAuthenticationStart, TACACSAuthenticationContinue, TACACSAuthenticationReply
)
from tacacs_plus.authorization import TACACSAuthorizationStart, TACACSAuthorizationReply
from tacacs_plus.accounting import TACACSAccountingStart, TACACSAccountingReply
from tacacs_plus.client import TACACSClient

AUTHENTICATE_HEADER = six.b('\xc0\x01\x01\x00\x00\x0009\x00\x00\x00')
AUTHENTICATE_HEADER_V12_1 = six.b('\xc1\x01\x01\x00\x00\x0009\x00\x00\x00')
AUTHENTICATE_HEADER_WRONG = six.b('\xf0\x01\x01\x00\x00\x0009\x00\x00\x00')
AUTHORIZE_HEADER = six.b('\xc0\x02\x01\x00\x00\x0009\x00\x00\x00')
ACCOUNT_HEADER = six.b('\xc0\x03\x01\x00\x00\x0009\x00\x00\x00')


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
    return TACACSHeader(
        192,  # version
        TAC_PLUS_AUTHEN,
        12345,  # session_id,
        0,  # body len
        1,  # seq_no
    )


@pytest.mark.parametrize('username', ['username', 'long-very-padded-username'])
def test_packet_body_obfuscation(tacacs_header, username):
    header = tacacs_header
    body = TACACSAuthenticationStart(
        username,
        TAC_PLUS_AUTHEN_TYPE_ASCII
    ).packed
    secret = '6f188b78-964f-4f3e-aea7-da26b7772495'
    encrypted = crypt(header, body, secret)
    assert crypt(header, encrypted, secret) == body


def test_packet_seq_no(tacacs_header):
    packet = TACACSPacket(tacacs_header, '', None)
    assert packet.seq_no == 1


def test_packet_encrypted(tacacs_header):
    assert TACACSPacket(tacacs_header, '', None).encrypted is False
    assert TACACSPacket(tacacs_header, '', 'secret').encrypted is True


@pytest.mark.parametrize('secret_key', ('secret', None))
def test_packet_raw(secret_key, tacacs_header):
    header = tacacs_header
    body = TACACSAuthenticationStart(
        'user123',
        TAC_PLUS_AUTHEN_TYPE_ASCII
    )
    header.length = len(body.packed)
    packet = TACACSPacket(header, body.packed, secret_key)
    assert isinstance(packet.header, TACACSHeader)

    if secret_key:
        assert bytes(packet) == header.packed + crypt(header, body.packed, secret_key)
    else:
        assert bytes(packet) == header.packed + body.packed


def test_header_pack(tacacs_header):
    packed = tacacs_header.packed
    unpacked = TACACSHeader.unpacked(packed)
    assert unpacked.version == 192
    assert unpacked.type == TAC_PLUS_AUTHEN
    assert unpacked.session_id == 12345
    assert unpacked.length == 0
    assert unpacked.seq_no == 1
    assert unpacked.flags == 0


# test authentication objects
def test_authentication_start_pack():
    username = 'user123'
    packed = TACACSAuthenticationStart(
        username,
        TAC_PLUS_AUTHEN_TYPE_ASCII
    ).packed
    assert packed == six.b(
        '\x01'           # tacacs_plus.flags.TAC_PLUS_AUTHEN_LOGIN \
        '\x00'           # tacacs_plus.flags.TAC_PLUS_PRIV_LVL_MIN \
        '\x01'           # tacacs_plus.flags.TAC_PLUS_AUTHEN_TYPE_ASCII \
        '\x01'           # tacacs_plus.flags.TAC_PLUS_AUTHEN_SVC_LOGIN \
        '\x07'           # username_len == 7 \
        '\x0b'           # port_len == 11 \
        '\x0d'           # rem_addr_len == 13 \
        '\x00'           # data_len == 0 \
        'user123'        # username \
        'python_tty0'    # port \
        'python_device'  # rem_addr
    )


def test_authentication_continue_pack():
    password = 'password'
    packed = TACACSAuthenticationContinue(password).packed
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
def test_authentication_reply_unpack(raw, state, human_status):
    reply = TACACSAuthenticationReply.unpacked(raw)
    assert getattr(reply, state) is True
    assert reply.human_status == human_status


def test_authentication_reply_unpack_server_msg():
    reply = TACACSAuthenticationReply.unpacked(
        six.b('\x05\x01\x00\n\x00\x00Password: ')
    )
    assert reply.getpass is True
    assert reply.server_msg == six.b('Password: ')
    assert reply.human_status == 'GETPASS'


# test authorization objects
def test_authorization_start_pack():
    username = 'user123'
    packed = TACACSAuthorizationStart(
        username, TAC_PLUS_AUTHEN_METH_TACACSPLUS,
        TAC_PLUS_PRIV_LVL_MIN, TAC_PLUS_AUTHEN_TYPE_ASCII,
        [b"service=shell", b"cmd=show", b"cmdargs=version"],
    ).packed
    assert packed == six.b(
        '\x06'              # tacacs_plus.flags.TAC_PLUS_AUTHEN_METH_TACACSPLUS \
        '\x00'              # tacacs_plus.flags.TAC_PLUS_PRIV_LVL_MIN \
        '\x01'              # tacacs_plus.flags.TAC_PLUS_AUTHEN_TYPE_ASCII \
        '\x01'              # tacacs_plus.flags.TAC_PLUS_AUTHEN_SVC_LOGIN \
        '\x07'              # username_len == 7 \
        '\x0b'              # port_len == 11 \
        '\x0d'              # rem_addr_len == 13 \
        '\x03'              # arg_len == 3
        '\x0d'              # arg_1_len == 13 (service=shell) \
        '\x08'              # arg_2_len == 8 (cmd=show) \
        '\x0f'              # arg_3_len == 14 (cmdargs=version) \
        'user123'           # username \
        'python_tty0'       # port \
        'python_device'     # rem_addr \
        'service=shell'     # arg_1 (service=shell) \
        'cmd=show'          # arg_2 (cmd=show) \
        'cmdargs=version'   # arg_3 (cmdargs=version)
    )


@pytest.mark.parametrize('raw, state, human_status', [
    (six.b('\x01\x00\x00\x00\x00\x00'), 'valid', 'PASS'),
    (six.b('\x02\x00\x00\x00\x00\x00'), 'reply', 'REPL'),
    (six.b('\x10\x00\x00\x00\x00\x00'), 'invalid', 'FAIL',),
    (six.b('\x11\x00\x00\x00\x00\x00'), 'error', 'ERROR'),
    (six.b('\x21\x00\x00\x00\x00\x00'), 'follow', 'FOLLOW'),
])
def test_authorization_reply_unpack(raw, state, human_status):
    reply = TACACSAuthorizationReply.unpacked(raw)
    assert getattr(reply, state) is True
    assert reply.human_status == human_status


def test_authorization_reply_unpack_server_msg():
    reply = TACACSAuthorizationReply.unpacked(
        six.b('\x01\x00\x08\x00\x00\x00amessage')
    )
    assert reply.server_msg == six.b('amessage')
    assert 'amessage' in str(reply)


def test_authorization_reply_unpack_data():
    reply = TACACSAuthorizationReply.unpacked(
        six.b('\x01\x00\x00\x00\x08\x00adata')
    )
    assert reply.data == six.b('adata')
    assert 'adata' in str(reply)


def test_authorization_reply_unpack_args():
    reply = TACACSAuthorizationReply.unpacked(
        six.b('\x01\x02\x00\x00\x00\x00\x04\x04arg1arg2')
    )
    assert reply.arg_cnt == 2
    assert reply.arguments == [b'arg1', b'arg2']


# test accounting object
def test_accounting_start_pack():
    username = 'user123'
    packed = TACACSAccountingStart(
        username, TAC_PLUS_ACCT_FLAG_START, TAC_PLUS_AUTHEN_METH_TACACSPLUS,
        TAC_PLUS_PRIV_LVL_MIN, TAC_PLUS_AUTHEN_TYPE_ASCII,
        [b"service=shell", b"cmd=show", b"cmdargs=version"],
    ).packed
    assert packed == six.b(
        '\x02'
        '\x06'              # tacacs_plus.flags.TAC_PLUS_AUTHEN_METH_TACACSPLUS \
        '\x00'              # tacacs_plus.flags.TAC_PLUS_PRIV_LVL_MIN \
        '\x01'              # tacacs_plus.flags.TAC_PLUS_AUTHEN_TYPE_ASCII \
        '\x01'              # tacacs_plus.flags.TAC_PLUS_AUTHEN_SVC_LOGIN \
        '\x07'              # username_len == 7 \
        '\x0b'              # port_len == 11 \
        '\x0d'              # rem_addr_len == 13 \
        '\x03'              # arg_len == 3
        '\x0d'              # arg_1_len == 13 (service=shell) \
        '\x08'              # arg_2_len == 8 (cmd=show) \
        '\x0f'              # arg_3_len == 14 (cmdargs=version) \
        'user123'           # username \
        'python_tty0'       # port \
        'python_device'     # rem_addr \
        'service=shell'     # arg_1 (service=shell) \
        'cmd=show'          # arg_2 (cmd=show) \
        'cmdargs=version'   # arg_3 (cmdargs=version)
    )


@pytest.mark.parametrize('raw, state, human_status', [
    (six.b('\x00\x00\x00\x00\x01\x00\x00'), 'valid', 'SUCCESS'),
    (six.b('\x00\x00\x00\x00\x02\x00\x00'), 'error', 'ERROR'),
    (six.b('\x00\x00\x00\x00\x21\x00\x00'), 'follow', 'FOLLOW'),
])
def test_accounting_reply_unpack(raw, state, human_status):
    reply = TACACSAccountingReply.unpacked(raw)
    assert getattr(reply, state) is True
    assert reply.human_status == human_status


def test_accounting_reply_unpack_server_msg():
    reply = TACACSAccountingReply.unpacked(
        six.b('\x08\x00\x00\x00\x01amessage')
    )
    assert reply.server_msg == six.b('amessage')
    assert 'amessage' in str(reply)


def test_accounting_reply_unpack_data():
    reply = TACACSAccountingReply.unpacked(
        six.b('\x00\x00\x08\x00\x01adata')
    )
    assert reply.data == six.b('adata')
    assert 'adata' in str(reply)


@pytest.mark.parametrize('family', [socket.AF_INET, socket.AF_INET6])
def test_v4_sock(family):
    try:
        client = TACACSClient('127.0.0.1', 49, None, family=family)
        client.sock
    except socket.error:
        pass
    assert client._sock.family == family


# test client send
@pytest.mark.parametrize(
    'packets, state',
    [
        [AUTHENTICATE_HEADER + six.b('\x06\x01\x00\x00\x00\x00\x00'), 'valid'],
        [AUTHENTICATE_HEADER + six.b('\x06\x02\x00\x00\x00\x00\x00'), 'invalid'],
        [AUTHENTICATE_HEADER + six.b('\x10\x05\x01\x00\n\x00\x00Password: '), 'getpass'],  # noqa
        [AUTHENTICATE_HEADER + six.b('\x06\x07\x00\x00\x00\x00\x00'), 'error'],
    ]
)
def test_client_socket_send(fake_socket, packets, state):
    body = TACACSAuthenticationStart(
        'user123',
        TAC_PLUS_AUTHEN_TYPE_ASCII
    )
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    client._sock = fake_socket
    packet = client.send(body, TAC_PLUS_AUTHEN)
    assert isinstance(packet, TACACSPacket)
    reply = TACACSAuthenticationReply.unpacked(packet.body)
    assert getattr(reply, state) is True

    # the first 12 bytes of the packet represent the header
    fake_socket.buff.seek(0)
    sent_header, sent_body = (
        fake_socket.buff.read(12), fake_socket.buff.read()
    )

    body_length = TACACSHeader.unpacked(sent_header).length
    assert len(sent_body) == body_length
    assert body.packed == sent_body


@pytest.mark.parametrize(
    'packets',
    [AUTHENTICATE_HEADER_WRONG + six.b('\x06\x07\x00\x00\x00\x00\x00')]
)
def test_client_socket_send_wrong_headers(fake_socket, packets):
    body = TACACSAuthenticationStart(
        'user123',
        TAC_PLUS_AUTHEN_TYPE_ASCII
    )
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    client._sock = fake_socket
    with pytest.raises(socket.error):
        client.send(body, TAC_PLUS_AUTHEN)


# test client.authenticate
@pytest.mark.parametrize(
    'packets',
    [
        AUTHENTICATE_HEADER + six.b('\x10\x05\x01\x00\n\x00\x00Password: ') +  # noqa getpass
        AUTHENTICATE_HEADER + six.b('\x06\x01\x00\x00\x00\x00\x00')  # auth_valid
    ]
)
def test_authenticate_ascii(fake_socket, packets):
    """
    client -> AUTHSTART (username)
              STATUS_GETPASS           <- server
    client -> AUTHCONTINUE (password)
              STATUS_PASS              <- server
    """
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    client._sock = fake_socket
    reply = client.authenticate('username', 'pass')
    assert reply.valid

    fake_socket.buff.seek(0)
    first_header = TACACSHeader.unpacked(fake_socket.buff.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 0)
    first_body = fake_socket.buff.read(first_header.length)
    assert TACACSAuthenticationStart(
        'username',
        TAC_PLUS_AUTHEN_TYPE_ASCII
    ).packed == first_body

    second_header = TACACSHeader.unpacked(fake_socket.buff.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 0)
    assert second_header.seq_no > first_header.seq_no

    second_body = fake_socket.buff.read()
    assert TACACSAuthenticationContinue('pass').packed == second_body


@pytest.mark.parametrize(
    'packets',
    [AUTHENTICATE_HEADER_V12_1 + six.b('\x06\x01\x00\x00\x00\x00\x00')]  # auth_valid
)
def test_authenticate_pap(fake_socket, packets):
    """
    client -> AUTHSTART (user+pass)
              STATUS_PASS              <- server
    """
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    client._sock = fake_socket
    reply = client.authenticate('username', 'pass',
                                authen_type=TAC_PLUS_AUTHEN_TYPE_PAP)
    assert reply.valid

    fake_socket.buff.seek(0)
    first_header = TACACSHeader.unpacked(fake_socket.buff.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 1)
    first_body = fake_socket.buff.read(first_header.length)
    assert TACACSAuthenticationStart(
        'username',
        TAC_PLUS_AUTHEN_TYPE_PAP,
        data=six.b('pass')
    ).packed == first_body


@pytest.mark.parametrize(
    'packets',
    [AUTHENTICATE_HEADER_V12_1 + six.b('\x06\x01\x00\x00\x00\x00\x00')]  # auth_valid
)
def test_authenticate_chap(fake_socket, packets):
    """
    client -> AUTHSTART user+md5challenge(pass)
              STATUS_PASS                         <- server
    """
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    client._sock = fake_socket
    reply = client.authenticate('username', 'pass',
                                authen_type=TAC_PLUS_AUTHEN_TYPE_CHAP,
                                chap_ppp_id='A',
                                chap_challenge='challenge')
    assert reply.valid

    fake_socket.buff.seek(0)
    first_header = TACACSHeader.unpacked(fake_socket.buff.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 1)
    first_body = fake_socket.buff.read(first_header.length)
    assert TACACSAuthenticationStart(
        'username',
        TAC_PLUS_AUTHEN_TYPE_CHAP,
        data=(
            six.b('A') +
            six.b('challenge') +
            md5(six.b('Apasschallenge')).digest()
        )
    ).packed == first_body


def test_authenticate_chap_ppp_id_required():
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    with pytest.raises(ValueError):
        client.authenticate('username', 'pass',
                            authen_type=TAC_PLUS_AUTHEN_TYPE_CHAP,
                            chap_challenge='challenge')


def test_authenticate_chap_ppp_id_length():
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    with pytest.raises(ValueError) as e:
        client.authenticate('username', 'pass',
                            authen_type=TAC_PLUS_AUTHEN_TYPE_CHAP,
                            chap_ppp_id='AA',
                            chap_challenge='challenge')
    assert 'chap_ppp_id must be a 1-byte string' in str(e)


def test_authenticate_chap_challenge_required():
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    with pytest.raises(ValueError):
        client.authenticate('username', 'pass',
                            authen_type=TAC_PLUS_AUTHEN_TYPE_CHAP,
                            chap_ppp_id='X')


def test_authenticate_chap_challenge_length():
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    with pytest.raises(ValueError) as e:
        client.authenticate('username', 'pass',
                            authen_type=TAC_PLUS_AUTHEN_TYPE_CHAP,
                            chap_ppp_id='A',
                            chap_challenge='X' * 256)
    assert 'chap_challenge may not be more 255 bytes' in str(e)


# test client.authorize
@pytest.mark.parametrize(
    'packets',
    [
        AUTHORIZE_HEADER + six.b('\x06\x01\x00\x00\x00\x00\x00')
    ]
)
def test_authorize_ascii(fake_socket, packets):
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    client._sock = fake_socket
    reply = client.authorize('username', arguments=[b"service=shell", b"cmd=show", b"cmdargs=version"])
    assert reply.valid

    fake_socket.buff.seek(0)
    first_header = TACACSHeader.unpacked(fake_socket.buff.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 0)
    first_body = fake_socket.buff.read(first_header.length)
    assert TACACSAuthorizationStart(
        'username', TAC_PLUS_AUTHEN_METH_TACACSPLUS, TAC_PLUS_PRIV_LVL_MIN,
        TAC_PLUS_AUTHEN_TYPE_ASCII, [b"service=shell", b"cmd=show", b"cmdargs=version"],
    ).packed == first_body


@pytest.mark.parametrize(
    'packets',
    [
        AUTHORIZE_HEADER + six.b('\x06\x01\x00\x00\x00\x00\x00')
    ]
)
def test_authorize_pap(fake_socket, packets):
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    client._sock = fake_socket
    reply = client.authorize('username', arguments=[b"service=shell", b"cmd=show", b"cmdargs=version"],
                             authen_type=TAC_PLUS_AUTHEN_TYPE_PAP)
    assert reply.valid

    fake_socket.buff.seek(0)
    first_header = TACACSHeader.unpacked(fake_socket.buff.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 0)
    first_body = fake_socket.buff.read(first_header.length)
    assert TACACSAuthorizationStart(
        'username', TAC_PLUS_AUTHEN_METH_TACACSPLUS, TAC_PLUS_PRIV_LVL_MIN,
        TAC_PLUS_AUTHEN_TYPE_PAP, [b"service=shell", b"cmd=show", b"cmdargs=version"],
    ).packed == first_body


@pytest.mark.parametrize(
    'packets',
    [
        AUTHORIZE_HEADER + six.b('\x06\x01\x00\x00\x00\x00\x00')
    ]
)
def test_authorize_chap(fake_socket, packets):
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    client._sock = fake_socket
    reply = client.authorize('username', arguments=[b"service=shell", b"cmd=show", b"cmdargs=version"],
                             authen_type=TAC_PLUS_AUTHEN_TYPE_CHAP)
    assert reply.valid

    fake_socket.buff.seek(0)
    first_header = TACACSHeader.unpacked(fake_socket.buff.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 0)
    first_body = fake_socket.buff.read(first_header.length)
    assert TACACSAuthorizationStart(
        'username', TAC_PLUS_AUTHEN_METH_TACACSPLUS, TAC_PLUS_PRIV_LVL_MIN,
        TAC_PLUS_AUTHEN_TYPE_CHAP, [b"service=shell", b"cmd=show", b"cmdargs=version"],
    ).packed == first_body


# test client.account
@pytest.mark.parametrize(
    'packets',
    [
        ACCOUNT_HEADER + six.b('\x06\x00\x00\x00\x00\x01\x00\x00')
    ]
)
def test_account_start(fake_socket, packets):
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    client._sock = fake_socket
    reply = client.account('username', TAC_PLUS_ACCT_FLAG_START,
                           arguments=[b"service=shell", b"cmd=show", b"cmdargs=version"])
    assert reply.valid

    fake_socket.buff.seek(0)
    first_header = TACACSHeader.unpacked(fake_socket.buff.read(12))
    assert (first_header.version_max, first_header.version_min) == (12, 0)
    first_body = fake_socket.buff.read(first_header.length)
    assert TACACSAccountingStart(
        'username', TAC_PLUS_ACCT_FLAG_START, TAC_PLUS_AUTHEN_METH_TACACSPLUS, TAC_PLUS_PRIV_LVL_MIN,
        TAC_PLUS_AUTHEN_TYPE_ASCII, [b"service=shell", b"cmd=show", b"cmdargs=version"],
    ).packed == first_body


@pytest.mark.parametrize(
    'packets',
    [
        AUTHORIZE_HEADER + six.b('\x12\x01\x01\x00\x00\x00\x00\x0bpriv-lvl=15')
    ]
)
def test_authorize_equal_priv_lvl(fake_socket, packets):
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    client._sock = fake_socket
    reply = client.authorize('username', arguments=[b"service=shell", b"cmd=show", b"cmdargs=version"],
                             authen_type=TAC_PLUS_AUTHEN_TYPE_PAP, priv_lvl=TAC_PLUS_PRIV_LVL_MAX)
    assert reply.valid, "the privilege level sent by the server is equal to the requested one (15)"


@pytest.mark.parametrize(
    'packets',
    [
        AUTHORIZE_HEADER + six.b('\x11\x01\x01\x00\x00\x00\x00\x0bpriv-lvl=1')
    ]
)
def test_authorize_lesser_priv_lvl(fake_socket, packets):
    client = TACACSClient('127.0.0.1', 49, None, session_id=12345)
    client._sock = fake_socket
    reply = client.authorize('username', arguments=[b"service=shell", b"cmd=show", b"cmdargs=version"],
                             authen_type=TAC_PLUS_AUTHEN_TYPE_PAP, priv_lvl=TAC_PLUS_PRIV_LVL_MAX)
    assert not reply.valid, "the privilege level sent by the server is less than the requested one (1 < 15)"
