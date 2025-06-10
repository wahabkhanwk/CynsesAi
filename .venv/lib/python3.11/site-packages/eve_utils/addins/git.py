#!/usr/bin/env python
"""Adds custom git to the API project.

If you provide a remote path, this will also add the remote to the local repository 
then push the code
Usage:
    add_git [=remote]

Examples:
    add_git
    add_git=http://github.com/myaccount/myrepos.git

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
import platform
from shutil import copyfile
import eve_utils


def add(remote):
    try:
        settings = eve_utils.jump_to_api_folder()
    except RuntimeError:
        print('This command must be run in an eve_service API folder structure')
        sys.exit(1)

    if os.path.isdir('./.git'):
        print('git has already been added')
        sys.exit(101)

    skel = os.path.join(os.path.dirname(eve_utils.__file__), 'skel')
    gitignore_filename = os.path.join(skel, 'git/.gitignore')
    copyfile(gitignore_filename, './.gitignore')
    eve_utils.replace_project_name(settings['project_name'], '.')
    
    
    silent = ' > /dev/null 2> /dev/null'
    if platform.system() == 'Windows':
        silent = ' > nul 2> nul'

    os.system('git init --quiet')
    os.system(f'git add . --all {silent}')
    os.system('git commit -m "Initial commit" --quiet')
    os.system('git branch -M main')
    os.system('git status')
    
    if not remote == 'no remote':
        result = os.system(f'git remote add origin {remote}')
        os.system('git push -u origin main')
    
    
