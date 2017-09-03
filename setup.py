#!/usr/bin/env python

from setuptools import setup, find_packages


setup(
    name='ethereum-accounts',
    version='0.1',
    description='Utilities for working with Ethereum accounts',
    author='Jannik Luhn',
    author_email='jannik.luhn@brainbot.com',
    url='https://www.github.com/jannikluhn/ethereum-accounts',

    packages=find_packages(),
    install_requires=[
        'coincurve',
        'ethereum-utils',
        'pycrypto',
        'scrypt',
    ]
)
