Account Creation
================

Accounts are represented by the :class:`Account` class. They are always based on a private key,
that can either be given explicitly, extracted from a keystore file or generated randomly.
Accordingly, three methods are available to create account objects:

    >>> from eth_accounts import Account
    >>> account = Account.from_private_key('0xff')
    >>> another_account = Account.from_keystore('keystore.json', b'password')
    >>> third_account = Account.new()

After initialization, the private key as well as the inferred public key and address are accessible
via properties:

    >>> account.private_key
    '0x00000000000000000000000000000000000000000000000000000000000000ff'
    >>> account.public_key
    '0x041b38903a43f7f114ed4500b4eac7083fdefece1cf29c63528d563446f972c1804036edc931a60ae889353f77fd53de4a2708b26b6f5da72ad3394119daf408f9'
    >>> account.address
    '0x5044a80bD3eff58302e638018534BbDA8896c48A'

Note that all output is hex encoded and the address EIP55 checksummed.

Accounts that have been imported from keystores, have two additional properties: The address found
in the keystore in plain text (which usually but not necessarily is the same as the actual address)
and an identifier:

    >>> account.exposed_address
    0x5044a80bD3eff58302e638018534BbDA8896c48A
    >>> account.id
    TODO

If those are not available, they fall back to ``None``.
