"""Checkpoint only after durable acknowledgement; keep source logs on outages."""
import gzip,hashlib,http.client,json,os,sqlite3,time
from pathlib import Path
import subprocess
import stat
import select
from collector import atomic

MAX_RECORD=262144

def post(config,route,body):
    limit=8*1024*1024 if route.startswith('/v1/archive/') else 2*1024*1024
    if len(body)>limit:raise ValueError('Batch exceeds receiver limit')
    if config.get('transport')=='tailscale-nc':
        header=('POST '+route+' HTTP/1.1\r\nHost: collector\r\nAuthorization: Bearer '+config['token']+'\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body))+'\r\nConnection: close\r\n\r\n').encode()
        # Keep stdin open until the acknowledgement arrives: nc may close both
        # directions on stdin EOF, even when the peer has saved the request.
        process=subprocess.Popen(['/usr/bin/tailscale','nc',config['collector'],'8991'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        try:
            os.set_blocking(process.stdin.fileno(),False);os.set_blocking(process.stdout.fileno(),False)
            payload=header+body;offset=0;reply=b'';deadline=time.monotonic()+25
            while b'\r\n\r\n' not in reply:
                remaining=deadline-time.monotonic()
                if remaining<=0:raise TimeoutError('Collector acknowledgement timed out')
                reads,writes,_=select.select([process.stdout],[process.stdin] if offset<len(payload) else [],[],remaining)
                if writes:offset+=os.write(process.stdin.fileno(),payload[offset:offset+65536])
                if reads:
                    chunk=os.read(process.stdout.fileno(),4096)
                    if not chunk:break
                    reply+=chunk
                    if len(reply)>16384:raise RuntimeError('Invalid collector response')
            first=reply.split(b'\r\n',1)[0].split()
            if len(first)<2 or first[1]!=b'204':raise RuntimeError('Private collector did not acknowledge the batch')
        finally:
            if process.poll() is None:process.terminate()
            try:process.communicate(timeout=2)
            except subprocess.TimeoutExpired:process.kill();process.communicate()
        return
    conn=http.client.HTTPConnection(config['collector'],8991,timeout=20)
    try:
        conn.request('POST',route,body,{'Authorization':'Bearer '+config['token'],'Content-Type':'application/json','Connection':'close'})
        response=conn.getresponse();response.read(4096)
        if response.status!=204:raise RuntimeError('Collector did not acknowledge: HTTP '+str(response.status))
    finally:conn.close()

def health(config):
    result={}
    for unit in config['units']:
        p=subprocess.run(['systemctl','is-active',unit],capture_output=True,text=True,timeout=3)
        value=p.stdout.strip();result[unit]=value if value in ('active','inactive','failed') else 'unknown'
    return result

def batch(config,events=(),proxies=(),status=None):
    body=json.dumps({'version':1,'events':events,'proxies':proxies,'health':status or {}}).encode()
    post(config,'/v1/batch',body)

def php(config,state,save,deadline):
    db=sqlite3.connect('file:'+config['database']+'?mode=ro',uri=True,timeout=5)
    try:
        for stream in ('events','proxy_observations'):
            maximum=db.execute('SELECT coalesce(max(rowid),0) FROM '+stream).fetchone()[0]
            if maximum<state.get(stream,0):raise RuntimeError('Source index moved behind its acknowledged checkpoint')
            while time.monotonic()<deadline:
                rows=list(db.execute('SELECT rowid,* FROM '+stream+' WHERE rowid>? ORDER BY rowid LIMIT 50',(state.get(stream,0),)))
                if not rows:break
                while len(rows)>1 and sum(len(r[-1]) for r in rows)>1024*1024:rows=rows[:max(1,len(rows)//2)]
                if stream=='events':
                    payload=[json.loads(r[-1]) for r in rows]
                    batch(config,events=payload)
                else:
                    payload=[{'id':r[1],'time':r[2],'ip':r[3],'upstream_request_id':r[4],'data':json.loads(r[5])} for r in rows]
                    batch(config,proxies=payload)
                state[stream]=rows[-1][0];save()
    finally:db.close()
    sent=set(state.get('archives',[]))
    for kind in ('archive','proxy-archive'):
        archive_root=Path(config.get('archives_root',str(Path(config['database']).parent)))
        for path in sorted((archive_root/kind).glob('*.jsonl')):
            key=kind+'/'+path.name
            if key in sent:continue
            if time.monotonic()>=deadline:return
            if path.is_symlink():continue
            descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(descriptor,'rb') as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):raise RuntimeError('Not a regular archive')
                body=source.read(8*1024*1024+1)
            digest=hashlib.sha256(body).hexdigest()
            if digest+'.jsonl'!=path.name:raise RuntimeError('Source archive checksum mismatch')
            post(config,'/v1/archive/'+kind+'/'+digest,body)
            sent.add(key);state['archives']=sorted(sent);save()

def cowrie(config,state,save,deadline):
    from cowrie_adapter import adapt
    root=Path(config['logs']);positions=state.setdefault('positions',{});sessions=state.setdefault('sessions',{})
    paths=sorted((p for p in root.glob('cowrie.json*') if p.is_file() and not p.is_symlink()),key=lambda p:p.stat().st_mtime_ns)
    for path in paths:
        if time.monotonic()>=deadline:return
        info=path.stat()
        # Renamed/copy-truncated logs replay safely: event IDs hash original lines.
        key=str(info.st_dev)+':'+str(info.st_ino)
        old=positions.get(key,{})
        if old.get('size')==info.st_size and old.get('mtime')==info.st_mtime_ns:continue
        descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(descriptor,'rb') as original:
            if not stat.S_ISREG(os.fstat(original.fileno()).st_mode):raise RuntimeError('Not a regular log')
            source=gzip.GzipFile(fileobj=original) if path.suffix=='.gz' else original
            prefix=hashlib.sha256(source.read(1024)).hexdigest();source.seek(0)
            start=old.get('offset',0) if old.get('prefix')==prefix and info.st_size>=old.get('physical_size',0) else 0
            source.seek(start)
            while time.monotonic()<deadline:
                raw=[];events=[];size=0
                for _ in range(50):
                    position=source.tell();line=source.readline(MAX_RECORD+1)
                    if not line:break
                    if len(line)>MAX_RECORD:raise RuntimeError('Oversized Cowrie record; position retained')
                    if not line.endswith(b'\n'):source.seek(position);break
                    text=line.decode('utf-8');raw.append(line);size+=len(line)
                    try:event=adapt(text,sessions)
                    except (ValueError,KeyError,TypeError):event=None
                    if event:events.append(event)
                    if size>=512*1024:break
                if not raw:break
                data=b''.join(raw)
                post(config,'/v1/archive/cowrie-archive/'+hashlib.sha256(data).hexdigest(),data)
                batch(config,events=events)
                positions[key]={'offset':source.tell(),'prefix':prefix,'physical_size':info.st_size,'size':info.st_size,'mtime':info.st_mtime_ns}
                if len(sessions)>10000:
                    for sid in list(sessions)[:-10000]:sessions.pop(sid)
                save()
            # Mark unchanged file complete only at EOF; an interrupted run must resume.
            if time.monotonic()>=deadline:
                positions.get(key,{}).pop('mtime',None);save();return

def run():
    config=json.loads((Path(os.environ['CREDENTIALS_DIRECTORY'])/'ship.json').read_text())
    directory=Path(os.environ.get('STATE_DIRECTORY','/var/lib/honeypot-ship'));directory.mkdir(parents=True,exist_ok=True)
    path=directory/'checkpoint.json';state=json.loads(path.read_text()) if path.exists() else {}
    def save():atomic(path,json.dumps(state))
    status=health(config);status['log-forwarder.service']='active'
    batch(config,status=status)
    deadline=time.monotonic()+35
    try:
        if config['sensor']=='rx1-php':php(config,state,save,deadline)
        else:cowrie(config,state,save,deadline)
    except Exception:
        status['log-forwarder.service']='failed'
        try:batch(config,status=status)
        except Exception:pass
        raise
    batch(config,status=status)

if __name__=='__main__':
    os.umask(0o077)
    run()
