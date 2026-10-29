"""Explicit derived-analysis migration. Raw archives, IDs and sensor metadata stay intact."""
import hashlib
import json
from pathlib import Path
from analysis import analyze, VERSION

def reassess(db,state):
    counts={'updated_journal_events':0,'updated_edge_events':0,'high_before':db.execute("SELECT count(*) FROM events WHERE severity='high'").fetchone()[0]}
    def update(identifier,raw,kind):
        row=db.execute('SELECT data FROM events WHERE id=?',(identifier,)).fetchone()
        if not row:return
        data=json.loads(row[0])
        if data.get('analysis',{}).get('rules_version')==VERSION:return
        data['analysis']=analyze(raw)
        db.execute('UPDATE events SET severity=?,data=? WHERE id=?',(data['analysis']['severity'],json.dumps(data),identifier))
        counts[kind]+=1
    with db:
        for path in sorted((Path(state)/'archive').glob('*.jsonl')):
            content=path.read_bytes()
            if hashlib.sha256(content).hexdigest()+'.jsonl'!=path.name:
                raise RuntimeError('Archive hash mismatch: '+path.name)
            for line in content.decode().splitlines():
                try:
                    envelope=json.loads(line)
                    if not isinstance(envelope,dict):continue
                    raw=json.loads(envelope['MESSAGE']) if 'MESSAGE' in envelope else envelope
                    if not isinstance(raw,dict) or 'ip' not in raw or 'path' not in raw:continue
                except (ValueError,TypeError):continue
                identifier=envelope.get('__CURSOR') or hashlib.sha256(line.encode()).hexdigest()
                update(identifier,raw,'updated_journal_events')
        for identifier,value in db.execute("SELECT id,data FROM events WHERE service='nginx-edge'").fetchall():
            event=json.loads(value)
            raw={'path':event.get('path','/'),'method':event.get('method',''),'headers':{'User-Agent':str((event.get('proxy') or {}).get('user_agent',''))}}
            update(identifier,raw,'updated_edge_events')
    counts['high_after']=db.execute("SELECT count(*) FROM events WHERE severity='high'").fetchone()[0]
    counts['rules_version']=VERSION
    return counts

if __name__=='__main__':
    import argparse,sqlite3
    parser=argparse.ArgumentParser();parser.add_argument('state',type=Path);args=parser.parse_args()
    db=sqlite3.connect(args.state/'index.sqlite')
    print(json.dumps(reassess(db,args.state),indent=2))
