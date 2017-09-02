Ethereum Accounts
=================

`ethereum-accounts` is a Python package for working with Ethereum accounts. Its main features are
keystore import and export, as well as message and transaction signing. Seamless integration with
`web3.py <https://github.com/pipermerriam/web3.py>`_ using its middleware API allows sending
transactions even when the RPC node does not manage the user's private keys.

We'll start with a :doc:`short demo <quickstart>` to give you an overview over the functionality of
the package. After that, I recommed having a quick look at the :doc:`encoding conventions chapter
<encodings>` because encoding parameters in a wrong format tends to be a common source of trouble
(for me, that is). Then, visit other chapters or the automatically generated :doc:`API docs <api>`
according to your needs. Have fun!


.. toctree::
   :maxdepth: 1
   :caption: Contents:

   quickstart
   encodings
   account_creation
   signing
   web3
   account_export
   api



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
