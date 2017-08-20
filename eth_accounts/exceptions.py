class EthereumAccountException(Exception):
    pass


class DecryptionError(EthereumAccountException, ValueError):
    pass


class InvalidKeystore(EthereumAccountException, ValueError):
    pass


class UnsupportedKeystore(EthereumAccountException, ValueError):
    pass


class MissingAddress(EthereumAccountException, KeyError):
    pass


class AccountLocked(EthereumAccountException, ValueError):
    pass
