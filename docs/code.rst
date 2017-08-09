API documentation
=================

This is the tacacs_plus API documentation. It contains the documentation extracted from the docstrings of the various classes, methods, and functions in the tacacs_plus package. If you want to know what a certain function/method does, this is the place to look.

.. contents::
    :depth: 2


:mod:`tacacs_plus.client` module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

source: https://github.com/ansible/tacacs_plus/blob/master/tacacs_plus/client.py

.. autoclass:: tacacs_plus.client.TACACSClient
   :members:
   :private-members:
   :undoc-members:


:mod:`tacacs_plus.packet` module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

source: https://github.com/ansible/tacacs_plus/blob/master/tacacs_plus/packet.py

.. autoclass:: tacacs_plus.client.TACACSHeader
   :members:
   :undoc-members:


.. autoclass:: tacacs_plus.client.TACACSPacket
   :members:
   :undoc-members:


:mod:`tacacs_plus.authentication` module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

source: https://github.com/ansible/tacacs_plus/blob/master/tacacs_plus/authentication.py

.. autoclass:: tacacs_plus.authentication.TACACSAuthenticationStart
   :members:
   :undoc-members:


.. autoclass:: tacacs_plus.authentication.TACACSAuthenticationContinue
   :members:
   :undoc-members:


.. autoclass:: tacacs_plus.authentication.TACACSAuthenticationReply
   :members:
   :undoc-members:


:mod:`tacacs_plus.authorization` module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

source: https://github.com/ansible/tacacs_plus/blob/master/tacacs_plus/authorization.py

.. autoclass:: tacacs_plus.authorization.TACACSAuthorizationStart
   :members:
   :undoc-members:


.. autoclass:: tacacs_plus.authorization.TACACSAuthorizationReply
   :members:
   :undoc-members:


:mod:`tacacs_plus.accounting` module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

source: https://github.com/ansible/tacacs_plus/blob/master/tacacs_plus/accounting.py

.. autoclass:: tacacs_plus.accounting.TACACSAccountingStart
   :members:
   :undoc-members:


.. autoclass:: tacacs_plus.accounting.TACACSAccountingReply
   :members:
   :undoc-members:


:mod:`tacacs_plus.flags` module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

source: https://github.com/ansible/tacacs_plus/blob/master/tacacs_plus/flags.py

this module contains all the constant flags used to implement the tacacs+ RFC.
