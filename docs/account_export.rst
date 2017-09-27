Keystore Export
===============

Exporting accounts to keystore files is possible via the :meth:`Account.to_keystore` method:

    >>> with open('keystore.json', 'w') as keystore_file:
    ...     account.to_keystore(keystore_file, b'password')

Instead of writing the keystore to a file, it can also be returned in form of a dictionary:

    >>> d = account.to_keystore_dict(b'password')

Both methods allow extensive customization of the result. Most importantly, the key derivation
function (KDF) can be specified. Currently, PBKDF2 and scrypt are supported:

    >>> pbkdf2_keystore = account.to_keystore_dict(b'password', kdf='pbkdf2')
    >>> scrypt_keystore = account.to_keystore_dict(b'password', kdf='scrypt')

Typically, the KDF have to be parametrized. Sensible defaults are chosen, but those can
individually be overridden if desired:

    >>> pbkdf2_keystore = account.to_keystore_dict(b'password', kdf='pbkdf2',
    ...                                            kdf_params={'salt': '0xff'})

The same applies to the cipher, but here only the canonical ``'aes-128-ctr'`` is supported:

    >>> keystore = account.to_keystore_dict(b'password', cipher='aes-128-ctr',
    ...                                     cipher_params={'iv': '0xff'})

.. warning::

   The security of the keystore depends on both KDF salt and cipher IV being random (which they
   are by default). Don't override those or any other parameters unless you know what you are
   doing.

Exposure of the address can be prevented by setting ``expose_address`` to ``False``:

    >>> keystore = account.to_keystore_dict(b'password', expose_address=False)
    >>> assert account.from_keystore(keystore, b'password').exposed_account is None

Finally, the keystore's ID can be customized. By default (``uuid=True``) a random UUID will be
generated. To use a custom value, pass it as the argument. Setting it to ``False`` or ``None``
will result in no ID appearing in the keystore.

    >>> keystore = account.to_keystore_dict(b'password', uuid=None)
    >>> assert account.from_keystore(keystore, b'password').uuid is None
    >>> keystore = account.to_keystore_dict(b'password', uuid='some-random-id')
    >>> assert account.from_keystore(keystore, b'password').uuid == 'some-random-id'


.. note::

   Importing an account from a keystore file and exporting it again will by default lead to
   keystores with different IDs. If this is not desired, make it explicit:

       >>> keystore = account.to_keystore_dict(b'password', uuid=account.uuid)
