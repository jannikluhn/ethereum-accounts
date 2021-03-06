# Ethereum Accounts

[![Build Status](https://travis-ci.org/jannikluhn/ethereum-accounts.svg?branch=master)](https://travis-ci.org/jannikluhn/ethereum-accounts)
[![Coverage Status](https://coveralls.io/repos/github/jannikluhn/ethereum-accounts/badge.svg?branch=master)](https://coveralls.io/github/jannikluhn/ethereum-accounts?branch=master)

This is a Python library for working with Ethereum accounts. Its main features are keystore import
and export, as well as message and transaction signing. Seamless integration with
[web3.py](https://github.com/pipermerriam/web3.py) using its middleware API allows sending
transactions even if the RPC node does not manage the user's private keys.

## Installation

```Python
pip install ethereum-accounts
```

## Documentation

Docs are hosted on [Read the Docs](https://ethereum-accounts.readthedocs.io/en/latest/).
