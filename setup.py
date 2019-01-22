#!/usr/bin/env python
# -*- coding:utf-8 -*-

import re
from setuptools import setup, find_packages

# Retrieve all metadata from project
with open("__metadata.py") as meta_file:
    metadata = dict(re.findall("__([a-z]+)__\s*=\s*'([^']+)'", meta_file.read()))

# Get required packages from requirements.txt
# Make it compatible with setuptools and pip
with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='uPKI_CLI',
    description='µPKI client',
    long_description=open('README.md').read(),
    author=metadata['author'],
    author_email=metadata['authoremail'],
    version=metadata['version'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Intended Audience :: System Administrators'
      ],
    url='https://github.com/proh4cktive/upki-cli',
    packages=find_packages(),
    license='MIT',
    install_requires=requirements
)