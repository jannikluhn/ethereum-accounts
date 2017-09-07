import json
import os

import jsonschema

from .ciphers import (
    ciphers,
    cipher_validators,
)
from .exceptions import (
    InvalidKeystore,
    UnsupportedKeystore,
)
from .kdfs import (
    kdf_validators,
    kdfs,
)


keystore_schema_path = os.path.join(os.path.dirname(__file__), 'schemas/keystore_schema.json')
with open(keystore_schema_path) as f:
    keystore_schema = json.load(f)


def validate_keystore(keystore):
    try:
        jsonschema.validate(keystore, keystore_schema)
    except jsonschema.ValidationError:
        raise InvalidKeystore('Invalid keystore format')
    cipher = keystore['crypto']['cipher']
    if cipher not in ciphers:
        raise UnsupportedKeystore('Keystore unsupported due to unknown cipher "{}"'.format(cipher))
    cipher_validators[cipher](keystore)
    kdf = keystore['crypto']['kdf']
    if kdf not in kdfs:
        raise UnsupportedKeystore('Keystore unsupported due to unknown KDF "{}"'.format(kdf))
    kdf_validators[kdf](keystore)
