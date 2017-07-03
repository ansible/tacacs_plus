import struct

import six


from .flags import (
    TAC_PLUS_PRIV_LVL_MIN, TAC_PLUS_AUTHEN_LOGIN, TAC_PLUS_AUTHEN_SVC_LOGIN,
    TAC_PLUS_AUTHEN_STATUS_PASS, TAC_PLUS_AUTHEN_STATUS_FAIL, TAC_PLUS_AUTHEN_STATUS_ERROR,
    TAC_PLUS_AUTHEN_STATUS_GETPASS
)


class TACACSAuthenticationStart(object):

    def __init__(self, username, authen_type, priv_lvl=TAC_PLUS_PRIV_LVL_MIN,
                 data=six.b('')):
        self.username = username
        self.action = TAC_PLUS_AUTHEN_LOGIN
        self.priv_lvl = priv_lvl
        self.authen_type = authen_type
        self.service = TAC_PLUS_AUTHEN_SVC_LOGIN
        self.data = data

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
        data = self.data
        port = rem_addr = six.b('')
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
            'priv_lvl: %s' % self.priv_lvl,
            'authen_type: %s' % self.authen_type,
            'service: %s' % self.service,
            'user_len: %d' % len(self.username),
            'port_len: 0',
            'rem_addr_len: 0',
            'data_len: %s' % len(self.data),
            'user: %s' % self.username,
            'data: %s' % self.data
        ])


class TACACSAuthenticationContinue(object):
    def __init__(self, password):
        self.password = password

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
        return (
            struct.pack('!H', len(password)) +
            struct.pack('!H', 0) +
            struct.pack('B', 0) +
            struct.pack('%ds' % len(password), password)
        )

    def __str__(self):
        return ', '.join([
            'user_msg_len: %s' % len(self.password),
            'data_len: 0',
            'flags: 0',
            'user_msg: %s' % self.password
        ])


class TACACSAuthenticationReply(object):

    def __init__(self, status, flags, server_msg, data):
        self.status = status
        self.flags = flags
        self.server_msg = server_msg
        self.data = data

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
            'status: %s' % self.human_status,
            'flags: %s' % self.flags,
            'server_msg: %s' % self.server_msg,
            'data: %s' % self.data
        ])
