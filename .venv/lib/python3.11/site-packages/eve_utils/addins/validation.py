#!/usr/bin/env python
"""Adds custom validation module to the API project.

This also adds two new validation rules
- unique_to_parent
    - the field must be unique amongst other resources with the same parent_ref, but can
      be repeated within other parents
- unique_ignorecase
    - prevents the same value being considered unique when the only difference is case
      e.g. 'station #1' will be considered the same as 'Station #1', the rule will
      prevent whichever is second from being inserted.

Usage:
    add_val

Examples:
    add_val

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
import itertools
from libcst import *
from eve_utils.code_gen import ValidationInserter
import eve_utils


def wire_up_service():
    with open('eve_service.py', 'r') as source:
        tree = parse_module(source.read())
    
    inserter = ValidationInserter()
    new_tree = tree.visit(inserter)
    
    with open('eve_service.py', 'w') as source:
        source.write(new_tree.code)
        
        
def add():
    try:
        settings = eve_utils.jump_to_api_folder('src/{project_name}')
    except RuntimeError:
        print('This command must be run in an eve_service API folder structure')
        sys.exit(1)

    if os.path.exists('./validation'):
        print('validation has already been added')
        sys.exit(301)

    eve_utils.copy_skel(settings['project_name'], 'validation')
    eve_utils.install_packages(['isodate'], 'add_validation')
    wire_up_service()

    print('validation module added')
