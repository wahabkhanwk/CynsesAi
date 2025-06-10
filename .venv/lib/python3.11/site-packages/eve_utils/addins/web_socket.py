#!/usr/bin/env python
"""Adds web socket functionality to API

Usage:
    add_web_socket

Examples:
    add_web_socket

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
import argparse
from distutils.dir_util import copy_tree
import eve_utils


def modify_eve_service():
    with open('./eve_service.py', 'r') as f:
        lines = f.readlines()
        
    with open('./eve_service.py', 'w') as f:
        for line in lines:
            if 'from flask_cors import CORS' in line:
                f.write(line)
                f.write('from flask_socketio import SocketIO\n')
                f.write('import web_socket\n')
            elif 'hooks.add_hooks(self._app)' in line:
                f.write(line)
                f.write("        self._socket = SocketIO(self._app, async_mode=None, path='/_ws/socket.io', cors_allowed_origins='*')\n")
                f.write("        web_socket.initialize(self._app, self._socket)\n")
            elif 'self._app.run' in line:
                f.write("            self._socket.run(self._app, host='0.0.0.0', port=SETTINGS.get('ES_API_PORT'), allow_unsafe_werkzeug=True)\n")
            else:
                f.write(line)


def add():
    try:
        settings = eve_utils.jump_to_api_folder('src/{project_name}')
    except RuntimeError:
        print('This command must be run in an eve_service API folder structure')
        sys.exit(1)

    if os.path.exists('./web_socket'):
        print('web_socket has already been added')
        sys.exit(501)

    modify_eve_service()
    eve_utils.copy_skel(settings['project_name'], 'web_socket', '.')
    eve_utils.install_packages(['Flask-SocketIO'], 'add_web_socket')
