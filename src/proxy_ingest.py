"""Bounded, restart-safe proxy log archiving with separate observation provenance."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
from analysis import analyze,ip_info

FIELDS=('time','ip','method','path','raw_path','status','request_bytes','response_bytes','duration','tls','cipher','user_agent','request_id','upstream_request_id','upstream_addr','upstream_status','http_version','limit_req_status')

def schema(db):
    db.execute('CREATE TABLE IF NOT EXISTS proxy_positions (file_id TEXT PRIMARY KEY, offset INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS proxy_observations (id TEXT PRIMARY KEY, time TEXT, ip TEXT, upstream_request_id TEXT, data TEXT)')
    db.execute('CREATE INDEX IF NOT EXISTS proxy_by_upstream ON proxy_observations(upstream_request_id)')
    db.execute("CREATE INDEX IF NOT EXISTS event_by_request ON events(json_extract(data,'$.simulation.request_id'))")

def ingest_line(db,line,identifier,provenance=None):
    try:
        raw=json.loads(line)
        if not isinstance(raw,dict) or not ip_info(str(raw.get('ip','')))['valid']:return False
        data={key:raw.get(key) for key in FIELDS if key in raw}
        if isinstance(data.get('raw_path'),str):
            data['raw_path']=data['raw_path'].split('?',1)[0][:2048]
            if not data['raw_path'].startswith('/'):data.pop('raw_path')
        if provenance:data['provenance']=provenance
        db.execute('INSERT OR IGNORE INTO proxy_observations VALUES (?,?,?,?,?)',(identifier,str(raw.get('time','')),str(raw['ip']),str(raw.get('upstream_request_id','')),json.dumps(data)))
        # Only a positively identified request that never attempted an upstream is an additional event.
        # Legacy rows remain separate observations; absence of a matching application row is not proof.
        edge=('request_id' in raw and 'upstream_addr' in raw and raw.get('upstream_addr') in ('','-',None))
        if edge:
            evidence_path=data.get('raw_path') or str(raw.get('path','/'))[:8192]
            if raw.get('status') in (400,413,414,429):data['rejection_reason']={400:'malformed-request',413:'request-too-large',414:'request-target-too-long',429:'rate-limited'}[raw['status']]
            event={'id':'edge:'+identifier,'time':str(raw.get('time','')),'ip':str(raw['ip']),'path':evidence_path,
                   'method':str(raw.get('method',''))[:20],'service':'nginx-edge','headers':{},
                   'simulation':{'scenario':'proxy-only-request','response_status':raw.get('status'),'request_id':raw.get('request_id')},
                   'proxy':data,'intelligence':ip_info(str(raw['ip'])),'self_test':str(raw['ip']) in ('127.0.0.1','::1'),
                   'analysis':analyze({'path':evidence_path,'method':raw.get('method',''),'headers':{'User-Agent':str(raw.get('user_agent',''))}}),
                   'user_agent_claim':str(raw.get('user_agent',''))[:300]}
            db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?)',('edge:'+identifier,event['time'],event['ip'],'nginx-edge',event['analysis']['severity'],json.dumps(event)))
            from index_state import record_clock
            canonical=record_clock(db,'edge:'+identifier,event['time'])
            if canonical!=event['time']:db.execute('UPDATE events SET time=? WHERE id=?',(canonical,'edge:'+identifier))
        return True
    except (ValueError,TypeError,KeyError):return False

def collect_proxy(db,state,logfile,byte_limit=4*1024*1024,line_limit=5000):
    schema(db)
    logfile=Path(logfile)
    folder=state/'proxy-archive';folder.mkdir(mode=0o700,exist_ok=True)
    # Rotation retains uncompressed originals, so inode positions survive rename and restart.
    rotated=[p for p in logfile.parent.glob(logfile.name+'.*') if p.name.rsplit('.',1)[-1].isdigit()]
    files=sorted(rotated,key=lambda p:int(p.name.rsplit('.',1)[-1]),reverse=True)+([logfile] if logfile.exists() else [])
    consumed=0;records=0;malformed=0
    for path in files:
        if consumed>=byte_limit or records>=line_limit:break
        with path.open('rb') as source:
            info=os.fstat(source.fileno());file_id=f'{info.st_dev}:{info.st_ino}'
            row=db.execute('SELECT offset FROM proxy_positions WHERE file_id=?',(file_id,)).fetchone()
            start=row[0] if row else 0
            if info.st_size<start:raise RuntimeError('Proxy log shrank; refusing to silently reset position')
            source.seek(start);lines=[];end=start
            while consumed<byte_limit and records<line_limit:
                position=source.tell();line=source.readline(131073)
                if not line:break
                if len(line)>131072:raise RuntimeError('Oversized proxy record; offset not advanced')
                if not line.endswith(b'\n'):break
                lines.append((position,line));end=source.tell();consumed+=len(line);records+=1
            if not lines:continue
            content=b''.join(line for _,line in lines);digest=hashlib.sha256(content).hexdigest()
            target=folder/(digest+'.jsonl')
            if target.exists():
                if target.read_bytes()!=content:raise RuntimeError('Proxy archive checksum collision')
            else:
                fd,tmp=tempfile.mkstemp(dir=folder,prefix='.proxy-')
                try:
                    os.fchmod(fd,0o600)
                    with os.fdopen(fd,'wb') as out:out.write(content);out.flush();os.fsync(out.fileno())
                    os.replace(tmp,target)
                finally:
                    if os.path.exists(tmp):os.unlink(tmp)
            # Archive first; derived rows and source offset commit in the same transaction.
            for offset,line in lines:
                identifier=hashlib.sha256((file_id+':'+str(offset)+':').encode()+line).hexdigest()
                if not ingest_line(db,line,identifier,{'file_id':file_id,'offset':offset,'batch_sha256':digest,'source_name':path.name}):malformed+=1
            db.execute('INSERT OR REPLACE INTO proxy_positions VALUES (?,?)',(file_id,end))
            db.commit()
    return {'read_records':records,'malformed':malformed}

def enrich(db,events):
    for event in events:
        if event.get('proxy'):continue
        rid=(event.get('simulation') or {}).get('request_id')
        if not rid:continue
        row=db.execute('SELECT data FROM proxy_observations WHERE upstream_request_id=? ORDER BY time DESC LIMIT 1',(rid,)).fetchone()
        if row:event['proxy']=json.loads(row[0])
    return events

def summary(db):
    # Remove TEXT affinity on the outer column so SQLite can seek the JSON expression index.
    return {'observations':db.execute('SELECT count(*) FROM proxy_observations').fetchone()[0],
            'correlated_application_observations':db.execute("SELECT count(*) FROM proxy_observations p WHERE p.upstream_request_id NOT IN ('','-') AND EXISTS (SELECT 1 FROM events e WHERE json_extract(e.data,'$.simulation.request_id')=+p.upstream_request_id)").fetchone()[0],
            'status_counts':{str(status):n for status,n in db.execute("SELECT json_extract(data,'$.status'),count(*) FROM proxy_observations GROUP BY 1")},
            'tls_counts':{str(tls or 'plain HTTP'):n for tls,n in db.execute("SELECT json_extract(data,'$.tls'),count(*) FROM proxy_observations GROUP BY 1")},
            'traffic':dict(zip(('request_bytes','response_bytes','mean_duration_seconds'),db.execute("SELECT coalesce(sum(json_extract(data,'$.request_bytes')),0),coalesce(sum(json_extract(data,'$.response_bytes')),0),avg(json_extract(data,'$.duration')) FROM proxy_observations").fetchone())),
            'scope':'All proxy observations, including self-tests. Legacy observations without request IDs are retained separately and never guessed into application events.'}
