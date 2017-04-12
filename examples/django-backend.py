import logging

from django.conf import settings
from django.contrib.auth.models import User
import tacacs_plus

logger = logging.getLogger(__file__)


#
# settings.py
# TACACSPLUS_HOST = 'localhost'
# TACACSPLUS_PORT = 49
# TACACSPLUS_SECRET = 'super-secret'
# TACACSPLUS_SESSION_TIMEOUT = 5
# TACACSPLUS_AUTH_PROTOCOL = 'ascii'
#

class TACACSPlusBackend(object):
    '''
    Custom TACACS+ auth backend for Django
    '''
    def _get_or_set_user(self, username, password):
        user, created = User.objects.get_or_create(
            username=username,
            defaults={'is_superuser': False},
        )
        if created:
            logger.debug("Created TACACS+ user %s" % (username,))
        return user

    def authenticate(self, username, password):
        if not settings.TACACSPLUS_HOST:
            return None
        try:
            auth = tacacs_plus.TACACSClient(
                settings.TACACSPLUS_HOST.encode('utf-8'),
                settings.TACACSPLUS_PORT,
                settings.TACACSPLUS_SECRET.encode('utf-8'),
                timeout=settings.TACACSPLUS_SESSION_TIMEOUT,
            ).authenticate(
                username.encode('utf-8'), password.encode('utf-8'),
                tacacs_plus.TAC_PLUS_AUTHEN_TYPES[settings.TACACSPLUS_AUTH_PROTOCOL],
            )
        except Exception as e:
            logger.exception("TACACS+ Authentication Error: %s" % (e.message,))
            return None
        if auth.valid:
            return self._get_or_set_user(username, password)
        else:
            return None
        return None

    def get_user(self, user_id):
        if not settings.TACACSPLUS_HOST:
            return None
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
