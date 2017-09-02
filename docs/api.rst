API
===

Account
-------

.. autoclass:: eth_accounts.Account
   :members:


Signing
-------

.. autofunction:: eth_accounts.sign_message
.. autofunction:: eth_accounts.sign_transaction
.. autofunction:: eth_accounts.recover_signer
.. autofunction:: eth_accounts.recover_sender
.. autofunction:: eth_accounts.prepare_ethereum_message


Utils
-----

.. autofunction:: eth_accounts.random_private_key
.. autofunction:: eth_accounts.private_key_to_public_key
.. autofunction:: eth_accounts.private_key_to_address
.. autofunction:: eth_accounts.public_key_to_address


Exceptions
----------

.. autoexception:: eth_accounts.EthereumAccountException
.. autoexception:: eth_accounts.DecryptionError
.. autoexception:: eth_accounts.InvalidKeystore
.. autoexception:: eth_accounts.UnsupportedKeystore
