import pytest
import copy
import json
import os


testdata_directory = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'testdata')
pbkdf2_keystore_template_path = os.path.join(testdata_directory, 'pbkdf2_keystore_template.json')
scrypt_keystore_template_path = os.path.join(testdata_directory, 'scrypt_keystore_template.json')
with open(pbkdf2_keystore_template_path) as f:
    pbkdf2_keystore_template = json.load(f)
with open(scrypt_keystore_template_path) as f:
    scrypt_keystore_template = json.load(f)


@pytest.fixture
def pbkdf2_keystore():
    return copy.deepcopy(pbkdf2_keystore_template)


@pytest.fixture
def scrypt_keystore():
    return copy.deepcopy(scrypt_keystore_template)


keystore = pbkdf2_keystore
