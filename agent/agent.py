#!/usr/bin/env python
"""
Very simple HTTP server in python.
Usage:
    ./agent.py [<port>]
Send a GET request::
    curl http://localhost
Send a HEAD request::
    curl -I http://localhost
Send a POST request::
    curl -d "foo=bar&bin=baz" http://localhost
"""
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import json
import cmdhandler
from cmdmacro import DEFAULT_PORT

from agentlog import agentlog

class S(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        self._set_headers()
        self.wfile.write("<html><body><h1>My name is onephone!</h1></body></html>")

    def do_HEAD(self):
        self._set_headers()

    def do_POST(self):
        self._set_headers()
        length = self.headers.getheaders('content-length')
        data = self.rfile.read(int(length[0]))
        result = cmdhandler.mainbody(data)
        agentlog.info(str(result))
        if result == {}:
            agentlog.warning('do_POST result is {}')
        else:
            self.wfile.write(json.dumps(result))

def run(server_class=HTTPServer, handler_class=S, port=int(DEFAULT_PORT)):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    agentlog.info('Starting httpd...')
    httpd.serve_forever()

if __name__ == "__main__":
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()