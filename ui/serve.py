#!/usr/bin/env python3
"""
Simple HTTP server to serve the SAST Scanner UI.
Serves files from the same directory on port 9080.
"""
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os
import sys

PORT = 9080

class SilentHandler(SimpleHTTPRequestHandler):
    """Handler that suppresses noisy log output for static assets."""
    def log_message(self, format, *args):
        # Only log non-200 or HTML requests
        if args and (str(args[1]) != '200' or str(args[0]).endswith('.html') or str(args[0]) == 'GET / '):
            SimpleHTTPRequestHandler.log_message(self, format, *args)

if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    server = HTTPServer(("0.0.0.0", PORT), SilentHandler)
    print(f"SAST Scanner UI server starting on port {PORT}...")
    print(f"Open http://localhost:{PORT}/ in your browser")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()
        sys.exit(0)
