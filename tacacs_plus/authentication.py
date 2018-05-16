import struct

import six

from .flags import (
    TAC_PLUS_PRIV_LVL_MIN, TAC_PLUS_AUTHEN_LOGIN, TAC_PLUS_AUTHEN_SVC_LOGIN,
    TAC_PLUS_AUTHEN_STATUS_PASS, TAC_PLUS_AUTHEN_STATUS_FAIL, TAC_PLUS_AUTHEN_STATUS_ERROR,
    TAC_PLUS_AUTHEN_STATUS_GETPASS, TAC_PLUS_VIRTUAL_PORT, TAC_PLUS_VIRTUAL_REM_ADDR
)


class TACACSAuthenticationStart(object):

    def __init__(self, username, authen_type, priv_lvl=TAC_PLUS_PRIV_LVL_MIN,
                 data=six.b(''), rem_addr=TAC_PLUS_VIRTUAL_REM_ADDR,
                 port=TAC_PLUS_VIRTUAL_PORT):
        self.username = username
        self.action = TAC_PLUS_AUTHEN_LOGIN
        self.priv_lvl = priv_lvl
        self.authen_type = authen_type
        self.service = TAC_PLUS_AUTHEN_SVC_LOGIN
        self.data = data
        self.rem_addr = rem_addr
        self.port = port

    @property
    def packed(self):
        # 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        #
        # +----------------+----------------+----------------+----------------+
        # |    action      |    priv_lvl    |  authen_type   |     service    |
        # +----------------+----------------+----------------+----------------+
        # |    user len    |    port len    |  rem_addr len  |    data len    |
        # +----------------+----------------+----------------+----------------+
        # |    user ...
        # +----------------+----------------+----------------+----------------+
        # |    port ...
        # +----------------+----------------+----------------+----------------+
        # |    rem_addr ...
        # +----------------+----------------+----------------+----------------+
        # |    data...
        # +----------------+----------------+----------------+----------------+

        # B = unsigned char
        # s = char[]
        username = six.b(self.username)
        rem_addr = six.b(self.rem_addr)
        port = six.b(self.port)
        data = self.data
        body = struct.pack(
            'B' * 8,
            self.action,
            self.priv_lvl,
            self.authen_type,
            self.service,
            len(username),
            len(port),
            len(rem_addr),
            len(data),
        )
        for value in (username, port, rem_addr, data):
            body += struct.pack('%ds' % len(value), value)
        return body

    def __str__(self):
        return ', '.join([
            'action: %s' % self.action,
            'authen_type: %s' % self.authen_type,
            'authen_service: %s' % self.service,
            'data: %s' % self.data,
            'data_len: %d' % len(self.data),
            'priv_lvl: %s' % self.priv_lvl,
            'port: %s' % self.port,
            'port_len: %d' % len(self.port),
            'rem_addr: %s' % self.rem_addr,
            'rem_addr_len: %d' % len(self.rem_addr),
            'user: %s' % self.username,
            'user_len: %d' % len(self.username)
        ])


class TACACSAuthenticationContinue(object):
    def __init__(self, password, data=six.b(''), flags=0):
        self.password = password
        self.data = data
        self.flags = flags

    @property
    def packed(self):
        # 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        #
        # +----------------+----------------+----------------+----------------+
        # |          user_msg len           |            data len             |
        # +----------------+----------------+----------------+----------------+
        # |     flags      |  user_msg ...
        # +----------------+----------------+----------------+----------------+
        # |    data ...
        # +----------------+

        # B = unsigned char
        # !H = network-order (big-endian) unsigned short
        # s = char[]
        password = six.b(self.password)
        data = self.data
        return (
            struct.pack('!H', len(password)) +
            struct.pack('!H', len(data)) +
            struct.pack('B', self.flags) +
            struct.pack('%ds' % len(password), password) +
            struct.pack('%ds' % len(data), data)
        )

    def __str__(self):
        return ', '.join([
            'data_len: 0',
            'flags: 0',
            'user_msg: %s' % ('*' * len(self.password)),
            'user_msg_len: %s' % len(self.password)
        ])


class TACACSAuthenticationReply(object):

    def __init__(self, status, flags, server_msg, data):
        self.status = status
        self.flags = flags
        self.server_msg = server_msg
        self.data = data
        self.arguments = []

    @classmethod
    def unpacked(cls, raw):
        # 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        #
        # +----------------+----------------+----------------+----------------+
        # |     status     |      flags     |        server_msg len           |
        # +----------------+----------------+----------------+----------------+
        # |           data len              |        server_msg ...
        # +----------------+----------------+----------------+----------------+
        # |           data ...
        # +----------------+----------------+

        # B = unsigned char
        # !H = network-order (big-endian) unsigned short
        raw = six.BytesIO(raw)
        status, flags = struct.unpack('BB', raw.read(2))
        server_msg_len, data_len = struct.unpack('!HH', raw.read(4))
        server_msg = raw.read(server_msg_len)
        data = raw.read(data_len)
        return cls(status, flags, server_msg, data)

    @property
    def valid(self):
        return self.status == TAC_PLUS_AUTHEN_STATUS_PASS

    @property
    def invalid(self):
        return self.status == TAC_PLUS_AUTHEN_STATUS_FAIL

    @property
    def error(self):
        return self.status == TAC_PLUS_AUTHEN_STATUS_ERROR

    @property
    def getpass(self):
        return self.status == TAC_PLUS_AUTHEN_STATUS_GETPASS

    @property
    def human_status(self):
        return {
            TAC_PLUS_AUTHEN_STATUS_PASS: 'PASS',
            TAC_PLUS_AUTHEN_STATUS_FAIL: 'FAIL',
            TAC_PLUS_AUTHEN_STATUS_GETPASS: 'GETPASS',
            TAC_PLUS_AUTHEN_STATUS_ERROR: 'ERROR'
        }.get(self.status, 'UNKNOWN: %s' % self.status)

    def __str__(self):
        return ', '.join([
            'data: %s' % self.data,
            'data_len: %d' % len(self.data),
            'flags: %s' % self.flags,
            'server_msg: %s' % self.server_msg,
            'server_msg_len: %d' % len(self.server_msg),
            'status: %s' % self.human_status
        ])
