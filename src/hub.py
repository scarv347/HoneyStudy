"""Private, authenticated append-only ingestion. No read or remote command API."""
import hashlib
import hmac
import ipaddress
import logging
import json
import os
import re
from pathlib import Path
import shutil
import sqlite3
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from collector import atomic, connect

MAX_BODY = 8 * 1024 * 1024
PHP_SERVICES = {'redis','mysql','telnet','portal','php-honeypot','php-honeypot.service','registry','cms','api','ftp','nginx-edge','rx1-decoy@registry.service','rx1-decoy@cms.service','rx1-decoy@api.service'}

def schema(db):
    db.execute('CREATE TABLE IF NOT EXISTS sensor_delivery (sensor TEXT PRIMARY KEY, received TEXT, newest_event TEXT, lag_seconds REAL)')
    db.execute('CREATE TABLE IF NOT EXISTS sensors (sensor TEXT PRIMARY KEY, seen TEXT, health TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS event_sources (id TEXT PRIMARY KEY, sensor TEXT)')
    db.execute('CREATE INDEX IF NOT EXISTS event_sources_sensor ON event_sources(sensor)')
    db.execute('CREATE TABLE IF NOT EXISTS capture_delivery(sensor TEXT PRIMARY KEY,received TEXT,data TEXT)')

def valid_event(event, sensor):
    if not isinstance(event, dict) or len(json.dumps(event)) > 262144:
        raise ValueError('Invalid event size')
    if not isinstance(event.get('id'),str) or not 1 <= len(event['id']) <= 256:
        raise ValueError('Invalid event ID')
    if sensor=='cowrie-ssh' and not re.fullmatch(r'cowrie:[0-9a-f]{64}',event['id']):
        raise ValueError('Invalid SSH event namespace')
    if sensor=='research' and not re.fullmatch(r'network:[0-9a-f]{64}',event['id']):
        raise ValueError('Invalid network event namespace')
    if sensor=='rx1-php' and event['id'].startswith(('cowrie:','network:')):
        raise ValueError('Wrong event namespace')
    if not isinstance(event.get('time'),str) or len(event['time']) > 64:
        raise ValueError('Invalid timestamp')
    stamp = datetime.fromisoformat(event['time'].replace('Z','+00:00'))
    if stamp.tzinfo is None:
        raise ValueError('Timestamp requires timezone')
    ipaddress.ip_address(event['ip'])
    allowed = {'cowrie'} if sensor == 'cowrie-ssh' else {'network'} if sensor == 'research' else PHP_SERVICES
    if event.get('service') not in allowed:
        raise ValueError('Invalid service')
    if not isinstance(event.get('path'),str) or len(event['path']) > 8192:
        raise ValueError('Invalid event path')
    a = event.get('analysis')
    if not isinstance(a,dict) or a.get('severity') not in ('info','low','medium','high') or not isinstance(a.get('hits'),list) or len(a['hits']) > 64:
        raise ValueError('Invalid assessment')
    for hit in a['hits']:
        if not isinstance(hit,dict) or not isinstance(hit.get('rule'),str) or hit.get('severity') not in ('info','low','medium','high'):
            raise ValueError('Invalid finding')
    return event

def accept(state, sensor, body):
    obj = json.loads(body, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Non-finite number')))
    if not isinstance(obj,dict) or obj.get('version') != 1:
        raise ValueError('Invalid envelope')
    events, proxies = obj.get('events',[]), obj.get('proxies',[])
    if not isinstance(events,list) or not isinstance(proxies,list) or len(events)+len(proxies)>500:
        raise ValueError('Invalid batch')
    events = [valid_event(e,sensor) for e in events]
    if sensor != 'rx1-php' and proxies:
        raise ValueError('Wrong stream')
    for row in proxies:
        if not isinstance(row,dict) or not isinstance(row.get('id'),str) or len(row['id'])>256 or not isinstance(row.get('data'),dict):
            raise ValueError('Invalid proxy observation')
        ipaddress.ip_address(row['ip'])
        datetime.fromisoformat(row['time'].replace('Z','+00:00'))
    capture=obj.get('capture_delivery')
    if capture is not None:
        if sensor!='research':raise ValueError('Wrong capture telemetry source')
        from capture_health import validate
        capture=validate(capture)
    health=obj.get('health',{})
    if not isinstance(health,dict) or len(health)>16 or any(not isinstance(k,str) or len(k)>100 or v not in ('active','inactive','failed','unknown') for k,v in health.items()):
        raise ValueError('Invalid health')
    db=connect(state)
    try:
        db.execute('PRAGMA busy_timeout=10000')
        schema(db)
        for event in events:
            a=event['analysis']
            from index_state import record_clock
            stamp=record_clock(db,event['id'],event['time'])
            db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?)',(event['id'],stamp,event['ip'],event['service'],a['severity'],json.dumps(event)))
            db.execute('INSERT OR IGNORE INTO event_sources VALUES (?,?)',(event['id'],sensor))
        for row in proxies:
            db.execute('INSERT OR IGNORE INTO proxy_observations VALUES (?,?,?,?,?)',(row['id'],row['time'],row['ip'],row.get('upstream_request_id',''),json.dumps(row['data'])))
        if not health:
            previous=db.execute('SELECT health FROM sensors WHERE sensor=?',(sensor,)).fetchone()
            health=json.loads(previous[0]) if previous else {}
        now=datetime.now(timezone.utc).isoformat()
        if capture is not None:db.execute('INSERT OR REPLACE INTO capture_delivery VALUES (?,?,?)',(sensor,now,json.dumps(capture)))
        if events:
            newest=max(datetime.fromisoformat(e['time'].replace('Z','+00:00')) for e in events)
            lag=max(0,(datetime.fromisoformat(now)-newest).total_seconds())
            db.execute('INSERT OR REPLACE INTO sensor_delivery VALUES (?,?,?,?)',(sensor,now,newest.isoformat(),lag))
        db.execute('INSERT OR REPLACE INTO sensors VALUES (?,?,?)',(sensor,now,json.dumps(health)))
        db.commit()
    finally:
        db.close()

class Server(ThreadingMixIn,HTTPServer):
    daemon_threads=True
    slots=threading.BoundedSemaphore(2)
    def get_request(self):
        sock,addr=super().get_request();sock.settimeout(15);return sock,addr
    def process_request(self,request,address):
        if not self.slots.acquire(False):request.close();return
        super().process_request(request,address)
    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:self.slots.release()

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):self.send_error(405)
    def do_POST(self):
        self.close_connection=True
        sensor=None
        supplied=self.headers.get('Authorization','')
        for name,entry in self.server.config['sensors'].items():
            if hmac.compare_digest(supplied,'Bearer '+entry['token']) and self.client_address[0] == entry['ip']:
                sensor=name;break
        if not sensor:self.send_error(403);return
        try:
            length=int(self.headers.get('Content-Length','0'))
            limit=MAX_BODY if self.path.startswith('/v1/archive/') else 2*1024*1024
            if not 0 < length <= limit or self.headers.get('Transfer-Encoding') or self.headers.get('Content-Encoding'):
                self.send_error(413);return
            if shutil.disk_usage(self.server.state).free < 2*1024**3:
                self.send_error(507);return
            body=self.rfile.read(length)
            if len(body)!=length:raise ValueError('Incomplete body')
            if self.path=='/v1/batch':accept(self.server.state,sensor,body)
            elif self.path == '/v1/intelligence':
                if sensor != 'research':raise ValueError('Wrong feed source')
                from threat_intelligence import accept_feed
                accept_feed(self.server.state,body)
            elif self.path.startswith('/v1/archive/'):
                pieces=self.path.split('/')
                if len(pieces)!=5:raise ValueError('Invalid archive route')
                kind,digest=pieces[3:]
                allowed={'cowrie-archive'} if sensor=='cowrie-ssh' else {'network-archive'} if sensor=='research' else {'archive','proxy-archive'}
                if kind not in allowed or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest) or hashlib.sha256(body).hexdigest()!=digest:
                    raise ValueError('Invalid archive')
                folder=self.server.state/kind;folder.mkdir(mode=0o700,exist_ok=True)
                target=folder/(digest+'.jsonl')
                if not target.exists():atomic(target,body)
                descriptor=os.open(folder,os.O_RDONLY|os.O_DIRECTORY)
                try:os.fsync(descriptor)
                finally:os.close(descriptor)
            else:self.send_error(404);return
        except (ValueError,TypeError,KeyError,UnicodeError):self.send_error(400);return
        except (OSError,sqlite3.Error) as error:
            # Record operational failure types without credentials or captured content.
            logging.warning('Ingestion unavailable sensor=%s error=%s sqlite=%s',sensor,type(error).__name__,getattr(error,'sqlite_errorname','none'))
            self.send_error(503);return
        self.send_response(204);self.send_header('Content-Length','0');self.end_headers()

if __name__=='__main__':
    state=Path(os.environ.get('HUB_STATE','/var/lib/honeypot-hub'));state.mkdir(parents=True,exist_ok=True)
    credential=Path(os.environ['CREDENTIALS_DIRECTORY'])/'sensors.json'
    config=json.loads(credential.read_text())
    db=connect(state);schema(db);db.commit();db.close()
    server=Server((os.environ['HUB_BIND'],8991),Handler)
    server.state=state;server.config=config;server.serve_forever()
