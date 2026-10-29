"""Small HTTP protocol emulators. No PHP, containers, file writes or execution."""
import argparse
import base64
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import json
import threading
import re
import uuid
from urllib.parse import urlsplit, unquote_plus
from personas import respond as simulate, VERSION as SIMULATION_VERSION

class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    request_queue_size = 16
    slots = threading.BoundedSemaphore(16)
    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(4)
        return sock, addr
    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise
    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

class Handler(BaseHTTPRequestHandler):
    server_version = 'nginx'
    sys_version = ''
    def log_message(self, *args):
        pass
    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ValueError, OSError):
            self.close_connection = True
    def respond(self, head=False):
        error = None
        length = 0
        body = b''
        if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) > 1:
            error = 'unsupported-transfer-framing'
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length < 0:
                raise ValueError()
        except ValueError:
            error = 'invalid-content-length'
            length = 0
        if not error:
            try:
                body = self.rfile.read(min(length, 16384))
            except (OSError, TimeoutError):
                error = 'body-read-timeout'
        try:
            path = urlsplit(self.path).path
        except ValueError:
            path = '/[malformed-target]'
        sensitive = any(s in path.lower() for s in ('login', 'auth', 'signin', 'token', 'xmlrpc', '/admin', '/account'))
        sensitive_header = re.compile(r'authorization|cookie|token|api.?key|password|secret|session', re.I)
        headers = {k: v[:500] for k, v in list(self.headers.items())[:64] if not sensitive_header.search(k)}
        # Redact credential-like query fields while preserving untouched raw attack encoding.
        target = self.path[:2048]
        if '?' in target:
            prefix, query = target.split('?', 1)
            fields = query.split('&')
            if len(fields) > 64:
                target = prefix + '?[query_omitted]'
            else:
                private = {'password','passwd','pass','pwd','token','access_token','api_key','key','secret','session','username','user','log','email'}
                fields = [f.split('=', 1)[0] + '=[redacted]' if unquote_plus(f.split('=',1)[0]).lower() in private else f for f in fields]
                target = prefix + '?' + '&'.join(fields)
        request_id = uuid.uuid4().hex
        origins=self.headers.get_all('Origin', [])
        allowed_origins={'https://honeystudy.example.invalid','http://honeystudy.example.invalid'}
        invalid_origin=self.server.persona=='api' and origins and (len(origins)!=1 or origins[0] not in allowed_origins)
        if invalid_origin:
            from personas import Response
            response=Response(403,b'Origin denied','text/plain','api-origin-rejected')
        elif error:
            from personas import Response
            response = Response(400, b'Bad request', 'text/plain', 'transport-rejected')
        else:
            response = simulate(self.server.persona, self.path, self.command, body)
        from breadcrumbs import decorate
        response=decorate(response,self.path,request_id)
        xmlrpc_method = ''
        if path == '/xmlrpc.php':
            match = re.search(br'<methodName>\s*([a-zA-Z0-9_.:-]{1,80})\s*</methodName>', body)
            if match:
                xmlrpc_method = match[1].decode('ascii')
        captured_body=body
        rpc_redacted=False
        if self.server.persona == 'api' and path in ('/mcp','/mcp/'):
            from developer_api import redact_rpc_body
            captured_body,rpc_redacted=redact_rpc_body(body)
        from php_watch import profile as php_profile
        php_capture=php_profile({'path':target,'headers':headers,'body_redacted':sensitive or rpc_redacted,'body_truncated':length>16384},body)
        event = {'php_capture':{'signals':php_capture['signals'],'structure':php_capture['structure']},'time': datetime.now(timezone.utc).isoformat(), 'service': self.server.persona,
                 'ip': self.headers.get('X-Real-IP', self.client_address[0]), 'method': self.command,
                 'path': target, 'headers': headers, 'content_length': length,
                 'body_truncated': length > 16384 or (not error and len(body) < length), 'body_redacted': sensitive or rpc_redacted,
                 'payload_base64': '' if sensitive else base64.b64encode(captured_body).decode(),
                 'simulation_version': SIMULATION_VERSION, 'scenario': response.scenario,
                 'response_status': response.status, 'request_id': request_id,
                 'canary': response.canary, 'xmlrpc_method': xmlrpc_method, 'capture_error': error,
                 **getattr(response, 'details', {})}
        print(json.dumps(event), flush=True)
        self.send_response(response.status)
        self.send_header('Content-Type', response.mime)
        self.send_header('Content-Length', str(len(response.content)))
        self.send_header('Connection', 'close')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Request-ID', request_id)
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        if self.server.persona in ('portal','cms') and 'X-Powered-By' not in response.headers:
            self.send_header('X-Powered-By', 'PHP/8.2.34')
        for name, value in response.headers.items():
            self.send_header(name, value)
        self.end_headers()
        if not head:
            self.wfile.write(response.content)
        self.close_connection = True
    def do_HEAD(self): self.respond(True)
    def do_GET(self): self.respond()
    do_POST = do_GET
    do_PUT = do_GET
    do_PATCH = do_GET
    do_DELETE = do_GET
    do_PROPFIND = do_GET
    do_PROPPATCH = do_GET
    do_MKCOL = do_GET
    do_COPY = do_GET
    do_MOVE = do_GET
    do_LOCK = do_GET
    do_UNLOCK = do_GET
    do_OPTIONS = do_GET
    do_TRACE = do_GET
    do_CONNECT = do_GET

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('persona', choices=['registry', 'cms', 'api'])
    args = parser.parse_args()
    server = Server(('127.0.0.1', {'registry':8081, 'cms':8082, 'api':8083}[args.persona]), Handler)
    server.persona = args.persona
    server.serve_forever()
