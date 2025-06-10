#!/usr/bin/env python
"""Adds files to facilitate deploying the API as a serverless function
   in either aws, azure, or google cloud

Usage:
    add_serverless [-h|--help] api_name
      NOTE: Run this in the folder above the API project folder

Examples:
    add_serverless my-api

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
import sys
import click
from subprocess import Popen, PIPE
import eve_utils


def warning():
    print('''
NOTE: this feature is still under development - use at your own risk!

*** DO NOT USE THIS UNLESS YOU KNOW WHAT YOU ARE DOING ***

This script will
- check for node/npm
- install serverless globally
- npm init the api folder
- install serverless plugins
- add  dnspython==2.1.0  to requirements.txt

You can then run the API with
    sls wsgi serve --config serverless-XXX.yml -p 2112

Before you deploy
- configure your credentials
  (e.g. sls config credentials --provider aws --key XXXX --secret YYYY -o)
- ensure your logging.yml makes no reference to the file system
  (e.g. copy logging_no-files.yml to logging.yml)
- modify as required the serverless-*.yml files (esp. connection to MongoDB!)
- test with serverless
  - sls wsgi serve --config serverless-XXX.yml -p 2112
- when you are ready to deploy:
  - sls deploy --config serverless-XXX.yml

- if you only use one cloud provider, copy that serverless-XXX.yml
  to serverless.yml, then you can leave off the --config...

''')
    click.confirm('Do you want to continue?', abort=True)



def run_process(cmd):
    process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE, encoding='utf-8')
    out, err = process.communicate()
    exit_code = process.wait()

    return exit_code, out, err


def is_node_installed():
    exit_code, out, err = run_process('node -v')

    try:
        major_version = int(out[1:].split('.')[0])
    except:
        major_version = 0

    if exit_code:
        print('node.js is not installed.\nPlease install and try again.')
        return False
    elif major_version < 10:
        print('node.js is installed, version must be greater than v10 (yours is {out}).\nPlease upgrade and try again.')
        return False

    # TODO: is any of this even required given a proper installation of node.js?
    exit_code, out, err = run_process('npm -v')

    try:
        major_version = int(out.split('.')[0])
    except:
        major_version = 0

    if exit_code:
        print('npm is not installed.\nPlease install and try again.')
        return False
    elif major_version < 0:
        # UNREACHABLE: is there a minimun npm version required by serverlesss?
        print('npm is installed, version must be greater than XX (yours is {out}).\nPlease upgrade and try again.')
        return False


    return True


def ensure_serverless_is_installed():
    exit_code, out, err = run_process('sls -v')

    if not exit_code:  # TODO: serverless is installed, but should we check version?
        return True

    print('installing serverless framework')
    exit_code, out, err = run_process('npm install -g serverless')

    if exit_code:
        print('Something went wrong installing serverless.')
        return False


def ensure_node_initialized():
    if os.path.exists('./package.json'):
        return True

    print('running npm init')
    exit_code, out, err = run_process('npm init -f')

    if exit_code:
        print('Something went wrong running npm init.')
        return False

    return True


def ensure_serverless_plugins_installed():
    print('Installing serverless plugins')
    exit_code, out, err = run_process('npm install --save-dev serverless-wsgi serverless-python-requirements serverless-domain-manager')

    if exit_code:
        print('Something went wrong installing serverless plugins.')
        return False

    return True


def add():
    warning()

    try:
        settings = eve_utils.jump_to_api_folder('src')
    except RuntimeError:
        print('This command must be run in an eve_service API folder structure')
        sys.exit(1)
        
    if os.path.exists('./serverless.py'):
        print('serverless has already been added')
        sys.exit(601)

        
    eve_utils.copy_skel(settings['project_name'], 'serverless', '.')
    eve_utils.replace_project_name(settings['project_name'], '.')
    
    if not is_node_installed():
        sys.exit(602)

    if not ensure_serverless_is_installed():
        sys.exit(603)

    os.chdir(f"./{settings['project_name']}")
    eve_utils.install_packages(['dnspython'], 'add_serverless')

    if not ensure_node_initialized():
        sys.exit(604)

    if not ensure_serverless_plugins_installed():
        sys.exit(605)
