#!/usr/bin/env python3
"""
mock_server.py - A tiny local web server for SAFE testing.

It runs only on YOUR laptop (127.0.0.1) and pretends to be several
websites with different security settings, so you can test the scanner
without touching any real website.

Run it with:        python mock_server.py
Then scan with:     python scanner.py http://127.0.0.1:8000/secure --allow-local

Available test pages
--------------------
/                       list of all pages
/secure                 all security headers set correctly
/insecure               no security headers (and leaks X-Powered-By)
/weak                   headers present but badly configured
/demo                   mixed results + a risky CORS rule (used for the sample report)
/cors-wildcard          Access-Control-Allow-Origin: *
/cors-reflect           copies any Origin back + allows credentials  (CONFIRMED)
/cors-reflect-nocreds   copies any Origin back, no credentials       (WEAK)
/cors-null              trusts the "null" origin + credentials       (CONFIRMED)
/cors-safe              allows only one trusted origin               (PASS)
/redirect               redirects to /secure
/slow                   waits 3 seconds before answering (timeout test)
anything else           404 error page
"""

import argparse
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HOST = "127.0.0.1"          # localhost only: nobody else can reach it
DEFAULT_PORT = 8000
TRUSTED_ORIGIN = "https://trusted.example"

# A complete, correct set of security headers.
SECURE_HEADERS = [
    ("Content-Security-Policy",
     "default-src 'self'; script-src 'self'; frame-ancestors 'none'"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "geolocation=(), camera=(), microphone=()"),
]

# Badly configured headers.
WEAK_HEADERS = [
    ("Content-Security-Policy", "default-src * 'unsafe-inline'"),
    ("Strict-Transport-Security", "max-age=300"),
    ("X-Content-Type-Options", "sniff"),
    ("X-Frame-Options", "ALLOW-FROM https://anywhere.example"),
    ("Referrer-Policy", "unsafe-url"),
]


# --- Functions that decide which CORS headers to send -----------------------
def cors_wildcard(origin):
    return [("Access-Control-Allow-Origin", "*")]


def cors_reflect(origin):
    if not origin:
        return []
    return [("Access-Control-Allow-Origin", origin),
            ("Access-Control-Allow-Credentials", "true"),
            ("Vary", "Origin")]


def cors_reflect_nocreds(origin):
    if not origin:
        return []
    return [("Access-Control-Allow-Origin", origin), ("Vary", "Origin")]


def cors_null(origin):
    if origin == "null":
        return [("Access-Control-Allow-Origin", "null"),
                ("Access-Control-Allow-Credentials", "true")]
    return []


def cors_safe(origin):
    if origin == TRUSTED_ORIGIN:
        return [("Access-Control-Allow-Origin", origin), ("Vary", "Origin")]
    return [("Vary", "Origin")]


# Route table:  path -> (base security headers, CORS function or None)
ROUTES = {
    "/secure": (SECURE_HEADERS, None),
    "/insecure": ([("X-Powered-By", "PHP/5.6.40")], None),
    "/weak": (WEAK_HEADERS, None),
    "/demo": ([("Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline'"),
               ("X-Content-Type-Options", "nosniff")], cors_reflect),
    "/cors-wildcard": (SECURE_HEADERS, cors_wildcard),
    "/cors-reflect": (SECURE_HEADERS, cors_reflect),
    "/cors-reflect-nocreds": (SECURE_HEADERS, cors_reflect_nocreds),
    "/cors-null": (SECURE_HEADERS, cors_null),
    "/cors-safe": (SECURE_HEADERS, cors_safe),
    "/slow": (SECURE_HEADERS, None),
}


def build_headers(path, origin):
    """Return the list of headers this mock page should send."""
    base, cors_function = ROUTES[path]
    headers = list(base)
    if cors_function is not None:
        headers.extend(cors_function(origin))
    return headers


class MockHandler(BaseHTTPRequestHandler):
    """Handles GET, HEAD and OPTIONS requests for the mock pages."""

    def version_string(self):
        return "MockServer"                 # hide Python's version number

    def log_message(self, format, *args):
        if not getattr(self.server, "quiet", False):
            print("[mock-server] %s - %s" % (self.address_string(),
                                             format % args))

    def _handle(self):
        path = urlparse(self.path).path
        origin = self.headers.get("Origin")
        is_options = self.command == "OPTIONS"
        is_head = self.command == "HEAD"

        if path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/secure")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path == "/":
            status = 200
            body = ("<html><body><h1>Mock test server</h1><ul>%s</ul>"
                    "</body></html>" % "".join(
                        '<li><a href="%s">%s</a></li>' % (p, p)
                        for p in list(ROUTES) + ["/redirect"]))
            extra_headers = []
        elif path in ROUTES:
            if path == "/slow":
                time.sleep(3)
            status = 200
            body = "<html><body>Mock page: %s</body></html>" % path
            extra_headers = build_headers(path, origin)
            if is_options:
                # A real server answers a CORS "preflight" like this.
                if any(n == "Access-Control-Allow-Origin"
                       for n, _ in extra_headers):
                    extra_headers.append(("Access-Control-Allow-Methods",
                                          "GET, POST, OPTIONS"))
        else:
            status = 404
            body = "<html><body>404 - page not found</body></html>"
            extra_headers = []

        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for name, value in extra_headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if not is_head and not is_options:
            self.wfile.write(data)

    do_GET = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle


def create_server(port=DEFAULT_PORT, quiet=False):
    """Create (but do not start) the mock server. Use port 0 for any free port."""
    server = ThreadingHTTPServer((HOST, port), MockHandler)
    server.quiet = quiet
    return server


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local mock server for testing the scanner.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help="Port to listen on (default %d)" % DEFAULT_PORT)
    args = parser.parse_args(argv)
    try:
        server = create_server(args.port)
    except OSError as err:
        print("Could not start the server on port %d: %s" % (args.port, err))
        print("Try another port, e.g.  python mock_server.py --port 8001")
        return 1
    print("Mock server running at http://%s:%d/  (press Ctrl+C to stop)"
          % (HOST, args.port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping the server.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
