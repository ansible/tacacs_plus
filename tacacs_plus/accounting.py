import struct

import six

from .flags import (
    TAC_PLUS_AUTHEN_SVC_LOGIN, TAC_PLUS_ACCT_STATUS_SUCCESS,
    TAC_PLUS_ACCT_STATUS_ERROR, TAC_PLUS_ACCT_STATUS_FOLLOW,
    TAC_PLUS_VIRTUAL_PORT, TAC_PLUS_VIRTUAL_REM_ADDR
)


class TACACSAccountingStart(object):

    def __init__(self, username, flags, authen_method, priv_lvl, authen_type,
                 arguments, rem_addr=TAC_PLUS_VIRTUAL_REM_ADDR,
                 port=TAC_PLUS_VIRTUAL_PORT):
        self.username = username
        self.flags = flags
        self.authen_method = authen_method
        self.priv_lvl = priv_lvl
        self.authen_type = authen_type
        self.service = TAC_PLUS_AUTHEN_SVC_LOGIN
        self.arguments = arguments
        self.rem_addr = rem_addr
        self.port = port

    @property
    def packed(self):
        #  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        # +----------------+----------------+----------------+----------------+
        # |      flags     |  authen_method |    priv_lvl    |  authen_type   |
        # +----------------+----------------+----------------+----------------+
        # | authen_service |    user_len    |    port_len    |  rem_addr_len  |
        # +----------------+----------------+----------------+----------------+
        # |    arg_cnt     |   arg_1_len    |   arg_2_len    |      ...       |
        # +----------------+----------------+----------------+----------------+
        # |   arg_N_len    |    user ...
        # +----------------+----------------+----------------+----------------+
        # |   port ...
        # +----------------+----------------+----------------+----------------+
        # |   rem_addr ...
        # +----------------+----------------+----------------+----------------+
        # |   arg_1 ...
        # +----------------+----------------+----------------+----------------+
        # |   arg_2 ...
        # +----------------+----------------+----------------+----------------+
        # |   ...
        # +----------------+----------------+----------------+----------------+
        # |   arg_N ...
        # +----------------+----------------+----------------+----------------+
        username = six.b(self.username)
        rem_addr = six.b(self.rem_addr)
        port = six.b(self.port)
        arguments = self.arguments
        body = struct.pack(
            'B' * 9,
            self.flags,
            self.authen_method,
            self.priv_lvl,
            self.authen_type,
            self.service,
            len(username),
            len(port),
            len(rem_addr),
            len(arguments),
        )
        for value in arguments:
            body += struct.pack('B', len(value))
        for value in (username, port, rem_addr):
            body += struct.pack('%ds' % len(value), value)
        for value in arguments:
            body += struct.pack('%ds' % len(value), value)
        return body

    def __str__(self):
        args = ', '.join([x.decode('utf-8') for x in self.arguments])
        return ', '.join([
            'args: %s' % args,
            'args_cnt: %d' % len(self.arguments),
            'authen_method: %s' % self.authen_method,
            'authen_type: %s' % self.authen_type,
            'authen_service: %s' % self.service,
            'flags: %s' % self.flags,
            'port_len: %d' % len(self.port),
            'port: %s' % self.port,
            'priv_lvl: %s' % self.priv_lvl,
            'rem_addr_len: %d' % len(self.rem_addr),
            'user: %s' % self.username,
            'user_len: %d' % len(self.username),
        ])


class TACACSAccountingReply(object):
    def __init__(self, status, server_msg, data):
        self.status = status
        self.server_msg = server_msg
        self.data = data
        self.flags = None
        self.arguments = []

    @classmethod
    def unpacked(cls, raw):
        #  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        # +----------------+----------------+----------------+----------------+
        # |         server_msg len          |            data_len             |
        # +----------------+----------------+----------------+----------------+
        # |     status     |         server_msg ...
        # +----------------+----------------+----------------+----------------+
        # |     data ...
        # +----------------+

        # B = unsigned char
        # !H = network-order (big-endian) unsigned short
        raw = six.BytesIO(raw)
        server_msg_len, data_len = struct.unpack('!HH', raw.read(4))
        status = struct.unpack('B', raw.read(1))[0]
        server_msg = raw.read(server_msg_len)
        data = raw.read(data_len) if data_len else b''
        return cls(status, server_msg, data)

    @property
    def valid(self):
        return self.status == TAC_PLUS_ACCT_STATUS_SUCCESS

    @property
    def error(self):
        return self.status == TAC_PLUS_ACCT_STATUS_ERROR

    @property
    def follow(self):
        return self.status == TAC_PLUS_ACCT_STATUS_FOLLOW

    @property
    def human_status(self):
        return {
            TAC_PLUS_ACCT_STATUS_SUCCESS: 'SUCCESS',
            TAC_PLUS_ACCT_STATUS_ERROR: 'ERROR',
            TAC_PLUS_ACCT_STATUS_FOLLOW: 'FOLLOW'
        }.get(self.status, 'UNKNOWN: %s' % self.status)

    def __str__(self):
        return ', '.join([
            'data: %s' % self.data,
            'data_len: %d' % len(self.data),
            'server_msg: %s' % self.server_msg,
            'server_msg_len: %d' % len(self.server_msg),
            'status: %s' % self.human_status,
        ])
