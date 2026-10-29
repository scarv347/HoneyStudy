"""Serve allowlisted private dashboard/report files; no directory or raw evidence access."""
from http.server import BaseHTTPRequestHandler
from pathlib import Path
import re
import os
import gzip
import json
from urllib.parse import urlsplit
from exports import options, blob, stream, raw_stream
from decoy import Server

class DashboardServer(Server):
    def get_request(self):
        sock,address=super().get_request()
        if getattr(self,'tls_context',None):
            try:sock=self.tls_context.wrap_socket(sock,server_side=True)
            except Exception:sock.close();raise
        return sock,address

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def respond(self, head=False):
        parsed = urlsplit(self.path)
        if parsed.path == '/download' and not head:
            try:
                p = options(parsed.query)
                if p.get('raw') == '1':
                    raw_stream(self)
                    return
                snapshot = blob(p.get('snapshot', ''))
            except (ValueError, KeyError, OSError):
                self.send_error(400, 'Invalid export selection')
                return
            try:
                stream(self, p, snapshot)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        routes={'/':('dashboard.html','text/html; charset=utf-8'), '/dashboard.html':('dashboard.html','text/html; charset=utf-8'), '/research.json':('research.json','application/json'), '/report.html':('report.html','text/html; charset=utf-8'), '/report.md':('report.md','text/markdown; charset=utf-8')}
        routes.update({'/status.json': ('status.json', 'application/json'), '/snapshot.json': ('snapshot.json', 'application/json'), '/world.json': ('world.json', 'application/json')})
        if re.fullmatch(r'/history/[0-9a-f]{64}\.json', self.path):
            routes[self.path] = (self.path[1:], 'application/json')
        if self.path not in routes:
            self.send_error(404)
            return
        try:
            data = (Path(os.environ.get('RX1_PUBLIC_DIR', '/run/rx1-public')) / routes[self.path][0]).read_bytes()
        except FileNotFoundError:
            self.send_error(503)
            return
        compressed = self.path.startswith('/history/') and 'gzip' in self.headers.get('Accept-Encoding', '')
        if compressed:
            cached=(Path(os.environ.get('RX1_PUBLIC_DIR', '/run/rx1-public')) / routes[self.path][0]).with_suffix('.json.gz')
            data = cached.read_bytes() if cached.is_file() else gzip.compress(data, compresslevel=1)
        self.send_response(200)
        if compressed:
            self.send_header('Content-Encoding', 'gzip')
        self.send_header('Vary', 'Accept-Encoding')
        self.send_header('Content-Type', routes[self.path][1])
        self.send_header('Cache-Control', 'private, max-age=31536000, immutable' if self.path.startswith('/history/') else 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        if not head:
            self.wfile.write(data)
        self.close_connection = True

    def do_GET(self): self.respond()
    def do_HEAD(self): self.respond(True)

if __name__ == '__main__':
    server=DashboardServer((os.environ.get('RX1_BIND','127.0.0.1'),int(os.environ.get('RX1_PORT','9090'))),Handler)
    if os.environ.get('RX1_TLS')=='1':
        import ssl
        credentials=Path(os.environ['CREDENTIALS_DIRECTORY'])
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(credentials/'dashboard.crt',credentials/'dashboard.key')
        server.tls_context=context
    server.serve_forever()
