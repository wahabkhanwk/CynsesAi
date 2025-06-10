"""Extends requests.Session to add url_base and default headers to requests

Usage:
    Pass url_base and/or headers to constructor

Examples:
    api =  RequestsWithDefaults(url_base='https://example.org/my-api', headers={
        'Content-type': 'application/json',
        'Cache-Control': 'no-cache'
    })
    api.get('/users')  # will call GET request on https://example.org/my-api/users 
                       # with Content-type and Cache-Control headers

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

import requests


def urljoin(base, path):
    return "{0}/{1}".format(base.rstrip("/"), path.lstrip("/"))


class RequestsWithDefaults(requests.Session):
    def __init__(self, url_base=None, headers=None, *args, **kwargs):
        super(RequestsWithDefaults, self).__init__(*args, **kwargs)
        self.url_base = url_base
        self.headers_base = headers

    def request(self, method, url, **kwargs):
        if self.url_base:
            modified_url = urljoin(self.url_base, url)
        else:
            modified_url = url

        if self.headers_base:
            if "headers" not in kwargs:
                kwargs["headers"] = {}
            kwargs["headers"].update(self.headers_base)

        return super(RequestsWithDefaults, self).request(method, modified_url, **kwargs)


requests.Session = RequestsWithDefaults
