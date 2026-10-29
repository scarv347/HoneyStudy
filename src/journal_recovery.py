"""Bounded full-field journal replay; independent checkpoint, immutable additive evidence."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
from collector import atomic,connect,ingest,UNITS

def recover(state,byte_limit=4*1024*1024,line_limit=5000):
    state=Path(state);folder=state/'archive';folder.mkdir(mode=0o700,exist_ok=True)
    checkpoint=state/'full-journal-recovery-cursor'
    command=['journalctl','--all','--no-pager','-o','json','--output-fields=MESSAGE,__CURSOR,_SYSTEMD_UNIT']
    for unit in UNITS:command += ['-u',unit]
    if checkpoint.exists():command += ['--after-cursor',checkpoint.read_text().strip()]
    proc=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    lines=[];size=0;cursor=None;exhausted=True
    try:
        while len(lines)<line_limit and size<byte_limit:
            line=proc.stdout.readline(131073)
            if not line:break
            if len(line)>131072 or not line.endswith(b'\n'):raise RuntimeError('Oversized/incomplete recovery record; checkpoint unchanged')
            envelope=json.loads(line)
            cursor=envelope['__CURSOR']
            if not isinstance(cursor,str) or not cursor:raise RuntimeError('Invalid journal cursor')
            lines.append(line);size+=len(line)
        else:
            exhausted=False
        if not exhausted:proc.terminate()
        result=proc.wait(timeout=5)
        if exhausted and result!=0:raise RuntimeError('Journal recovery export failed; checkpoint unchanged')
    finally:
        if proc.poll() is None:
            proc.kill();proc.wait(timeout=5)
        proc.stdout.close()
    if not lines:return {'exhausted':exhausted,'source_records':0,'new_events':0}
    raw=b''.join(lines);digest=hashlib.sha256(raw).hexdigest();target=folder/(digest+'.jsonl')
    if target.exists():
        if target.read_bytes()!=raw:raise RuntimeError('Archive hash collision')
    else:
        atomic(target,raw.decode(),0o600)
        owner=folder.stat()
        if os.geteuid()==0:os.chown(target,owner.st_uid,owner.st_gid)
    db=connect(state)
    try:
        before=db.execute('SELECT count(*) FROM events').fetchone()[0]
        with db:malformed=ingest(db,raw.decode())
        after=db.execute('SELECT count(*) FROM events').fetchone()[0]
        atomic(checkpoint,cursor,0o600)
    finally:db.close()
    return {'exhausted':exhausted,'source_records':len(lines),'new_events':after-before,'malformed_records':malformed,'archive_sha256':digest}

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('state',type=Path);args=parser.parse_args()
    batches=[]
    for _ in range(8):
        row=recover(args.state);batches.append(row)
        if row['exhausted']:break
    else:raise SystemExit('Recovery checkpoint saved; more history remains. Rerun to continue.')
    print(json.dumps({'batches':batches,'new_events':sum(row['new_events'] for row in batches)},indent=2))
