#!/usr/bin/env python
"""Adds authorization module to the API project.

Usage:
    add_auth

Examples:
    add_auth

License:
    MIT License

    Copyright (c) 2021 Michael Ottoson

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
"""

import os
import sys
import argparse
import itertools
from libcst import *
import importlib
import eve_utils
from eve_utils.code_gen import AuthorizationInserter

# TODO: script getting default values (e.g. client keys)
# TODO: provide non Auth0

def wire_up_service():
    with open('eve_service.py', 'r') as source:
        tree = parse_module(source.read())
    
    inserter = AuthorizationInserter()
    new_tree = tree.visit(inserter)
    
    with open('eve_service.py', 'w') as source:
        source.write(new_tree.code)


def add():
    try:
        settings = eve_utils.jump_to_api_folder('src/{project_name}')
    except RuntimeError:
        print('This command must be run in an eve_service API folder structure')
        sys.exit(1)

    if os.path.exists('./auth'):
        print('auth has already been added')
        sys.exit(201)

    eve_utils.copy_skel(settings['project_name'], 'auth')
    eve_utils.install_packages(['eve-negotiable-auth', 'PyJWT', 'cryptography', 'requests'], 'add_auth')
    # eve_negotiable_auth also installs authparser and pyparsing    
    # cryptography also installs cffi, pycparser
    # requests also installs certifi, chardet, idna, urllib3
    wire_up_service()
    
    print('auth modules added')
