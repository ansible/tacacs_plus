import struct

import six

from .flags import (
    TAC_PLUS_AUTHEN_SVC_LOGIN, TAC_PLUS_AUTHOR_STATUS_PASS_ADD, TAC_PLUS_AUTHOR_STATUS_PASS_REPL,
    TAC_PLUS_AUTHOR_STATUS_FAIL, TAC_PLUS_AUTHOR_STATUS_ERROR, TAC_PLUS_AUTHOR_STATUS_FOLLOW
)


class TACACSAuthorizationStart(object):

    def __init__(self, username, authen_method, priv_lvl, authen_type,
                 arguments):
        self.username = username
        self.authen_method = authen_method
        self.priv_lvl = priv_lvl
        self.authen_type = authen_type
        self.service = TAC_PLUS_AUTHEN_SVC_LOGIN
        self.arguments = arguments

    @property
    def packed(self):
        #  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        # +----------------+----------------+----------------+----------------+
        # |  authen_method |    priv_lvl    |  authen_type   | authen_service |
        # +----------------+----------------+----------------+----------------+
        # |    user len    |    port len    |  rem_addr len  |    arg_cnt     |
        # +----------------+----------------+----------------+----------------+
        # |   arg 1 len    |   arg 2 len    |      ...       |   arg N len    |
        # +----------------+----------------+----------------+----------------+
        # |   user ...
        # +----------------+----------------+----------------+----------------+
        # |   port ...
        # +----------------+----------------+----------------+----------------+
        # |   rem_addr ...
        # +----------------+----------------+----------------+----------------+
        # |   arg 1 ...
        # +----------------+----------------+----------------+----------------+
        # |   arg 2 ...
        # +----------------+----------------+----------------+----------------+
        # |   ...
        # +----------------+----------------+----------------+----------------+
        # |   arg N ...
        # +----------------+----------------+----------------+----------------+

        # B = unsigned char
        # s = char[]
        username = six.b(self.username)
        port = rem_addr = six.b('')
        arguments = self.arguments
        body = struct.pack(
            'B' * 8,
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


class TACACSAuthorizationReply(object):

    def __init__(self, status, arg_cnt, server_msg, data, arguments):
        self.status = status
        self.arg_cnt = arg_cnt
        self.server_msg = server_msg
        self.data = data
        self.arguments = arguments

    @classmethod
    def unpacked(cls, raw):
        #  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        # +----------------+----------------+----------------+----------------+
        # |    status      |     arg_cnt    |         server_msg len          |
        # +----------------+----------------+----------------+----------------+
        # +            data len             |    arg 1 len   |    arg 2 len   |
        # +----------------+----------------+----------------+----------------+
        # |      ...       |   arg N len    |         server_msg ...
        # +----------------+----------------+----------------+----------------+
        # |   data ...
        # +----------------+----------------+----------------+----------------+
        # |   arg 1 ...
        # +----------------+----------------+----------------+----------------+
        # |   arg 2 ...
        # +----------------+----------------+----------------+----------------+
        # |   ...
        # +----------------+----------------+----------------+----------------+
        # |   arg N ...
        # +----------------+----------------+----------------+----------------+

        # B = unsigned char
        # !H = network-order (big-endian) unsigned short
        raw = six.BytesIO(raw)
        status, arg_cnt = struct.unpack('BB', raw.read(2))
        server_msg_len, data_len = struct.unpack('!HH', raw.read(4))
        args_lens = struct.unpack(
            'B' * arg_cnt, raw.read(arg_cnt)
        ) if arg_cnt else []
        server_msg = raw.read(server_msg_len)
        data = raw.read(data_len) if data_len else ''
        arguments = []
        for arg_len in args_lens:
            arg = raw.read(arg_len) if arg_len else ''
            arguments.append(arg)
        return cls(status, arg_cnt, server_msg, data, arguments)

    @property
    def valid(self):
        return self.status == TAC_PLUS_AUTHOR_STATUS_PASS_ADD

    @property
    def invalid(self):
        return self.status == TAC_PLUS_AUTHOR_STATUS_FAIL

    @property
    def error(self):
        return self.status == TAC_PLUS_AUTHOR_STATUS_ERROR

    @property
    def reply(self):
        return self.status == TAC_PLUS_AUTHOR_STATUS_PASS_REPL

    @property
    def follow(self):
        return self.status == TAC_PLUS_AUTHOR_STATUS_FOLLOW

    @property
    def human_status(self):
        return {
            TAC_PLUS_AUTHOR_STATUS_PASS_ADD: 'PASS',
            TAC_PLUS_AUTHOR_STATUS_FAIL: 'FAIL',
            TAC_PLUS_AUTHOR_STATUS_PASS_REPL: 'REPL',
            TAC_PLUS_AUTHOR_STATUS_ERROR: 'ERROR',
            TAC_PLUS_AUTHOR_STATUS_FOLLOW: 'FOLLOW',
        }.get(self.status, 'UNKNOWN: %s' % self.status)

    def __str__(self):
        return ', '.join([
            'status: %s' % self.human_status,
            'server_msg: %s' % self.server_msg,
            'args: %s' % ','.join(self.arguments)
        ])
