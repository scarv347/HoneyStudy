"""Socket-activated, bounded FTP conversation simulator. Never authenticates or transfers."""
import base64
from datetime import datetime,timezone
import json
import os
import socket
import socketserver
import threading
import uuid

class Server(socketserver.ThreadingMixIn,socketserver.TCPServer):
    allow_reuse_address=True
    daemon_threads=True
    request_queue_size=16
    def __init__(self,*args,**kwargs):
        self.slots=threading.BoundedSemaphore(8)
        super().__init__(*args,**kwargs)
    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):request.close();return
        try:super().process_request(request,address)
        except Exception:self.slots.release();raise
    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:self.slots.release()

class Handler(socketserver.StreamRequestHandler):
    timeout=3
    def handle(self):
        commands=[];samples=[];received=0;logins=0;truncated=False
        self.request.settimeout(3)
        try:
            self.wfile.write(b'220 Portal FTP service ready\r\n')
            for _ in range(32):
                line=self.rfile.readline(1025)
                if not line:break
                received+=len(line)
                if len(line)>1024 or not line.endswith(b'\n'):
                    truncated=True;self.wfile.write(b'500 Command too long\r\n');break
                text=line.decode('utf-8','replace').strip()
                command=text.split(None,1)[0].upper()[:16] if text else ''
                commands.append(command)
                # Do not retain usernames, passwords or authentication material.
                if command in ('USER','PASS','ACCT','AUTH','ADAT'):
                    samples.append(command+' [redacted]')
                elif len(samples)<16:samples.append(text[:160])
                if command=='USER':reply=b'331 User name okay, need password\r\n'
                elif command=='PASS':logins+=1;reply=b'530 Login incorrect\r\n'
                elif command=='QUIT':self.wfile.write(b'221 Goodbye\r\n');break
                elif command=='SYST':reply=b'215 UNIX Type: L8\r\n'
                elif command=='FEAT':reply=b'211-Features\r\n UTF8\r\n211 End\r\n'
                elif command in ('NOOP','OPTS','TYPE'):reply=b'200 Command okay\r\n'
                elif command=='PWD':reply=b'257 "/" is current directory\r\n'
                elif command in ('PORT','PASV','EPSV','EPRT'):reply=b'502 Data connections unavailable\r\n'
                elif command in ('LIST','NLST','RETR','STOR','APPE','DELE','CWD','MKD','RMD','SITE'):reply=b'530 Authentication required\r\n'
                else:reply=b'502 Command not implemented\r\n'
                self.wfile.write(reply)
            else:truncated=True
        except (OSError,TimeoutError):pass
        finally:
            event={'time':datetime.now(timezone.utc).isoformat(),'ip':self.client_address[0],'path':'ftp://21/','method':'FTP',
                   'service':'ftp','headers':{},'simulation_version':'rx1-sim-4','scenario':'ftp-login-attempt' if logins else 'ftp-connection',
                   'request_id':uuid.uuid4().hex,'ftp_commands':commands,'ftp_login_attempts':logins,'ftp_bytes_received':received,
                   'body_truncated':truncated,'credentials_redacted':True,'payload_base64':base64.b64encode('\n'.join(samples).encode()).decode()}
            print(json.dumps(event),flush=True)

if __name__=='__main__':
    if int(os.environ.get('LISTEN_PID','0'))!=os.getpid() or os.environ.get('LISTEN_FDS')!='1':
        raise SystemExit('Requires the dedicated systemd socket')
    server=Server(('127.0.0.1',0),Handler,bind_and_activate=False)
    server.socket.close()
    server.socket=socket.socket(fileno=3)
    server.server_address=server.socket.getsockname()
    server.serve_forever()
