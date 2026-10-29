"""Independent lightweight health, even when history publication fails."""
from datetime import datetime,timezone
from pathlib import Path
import json,os,shutil,sqlite3
from collector import atomic

def status(state,now=None):
    now=now or datetime.now(timezone.utc);state=Path(state)
    value={'generated':now.isoformat(),'disk_free_bytes':shutil.disk_usage(state).free,'sensors':[]}
    try:
        snapshot=json.loads((state/'public/snapshot.json').read_text())
        age=max(0,(now-datetime.fromisoformat(snapshot['generated'])).total_seconds())
        value.update(snapshot_generated=snapshot['generated'],snapshot_age_seconds=round(age),publication='current' if age<180 else 'stale')
    except (OSError,ValueError,KeyError,TypeError):value.update(publication='unavailable',snapshot_age_seconds=None)
    try:
        with sqlite3.connect('file:'+str(state/'index.sqlite')+'?mode=ro',uri=True,timeout=2) as db:
            for identifier,seen,raw in db.execute('SELECT sensor,seen,health FROM sensors'):
                try:
                    health=json.loads(raw)
                    if not isinstance(health,dict):raise ValueError('Invalid service health')
                    stamp=datetime.fromisoformat(seen)
                    if stamp.tzinfo is None:raise ValueError('Missing heartbeat timezone')
                    age=max(0,(now-stamp).total_seconds())
                    sensor={'id':identifier,'seen':seen,'health':health,'status':'stale' if age>=180 else 'active' if health and all(v=='active' for v in health.values()) else 'failed'}
                except (ValueError,TypeError,AttributeError):
                    sensor={'id':identifier,'seen':None,'health':{},'status':'unknown'}
                value['sensors'].append(sensor)
            try:
                row=db.execute("SELECT received,data FROM capture_delivery WHERE sensor='research'").fetchone()
                if row:value['capture']={**json.loads(row[1]),'received':row[0]}
            except sqlite3.Error:pass
    except (OSError,sqlite3.Error,ValueError):value['collection']='unavailable'
    value['storage']='critical' if value['disk_free_bytes']<2*1024**3 else 'warning' if value['disk_free_bytes']<5*1024**3 else 'healthy'
    return value

def needs_alert(result):
    return (result.get('publication')!='current' or result.get('storage')!='healthy'
            or result.get('collection')=='unavailable' or not result.get('sensors')
            or any(s.get('status')!='active' for s in result['sensors']))

def main():
    state=Path(os.environ.get('HUB_STATE','/var/lib/honeypot-hub'));result=status(state)
    atomic(state/'public/status.json',json.dumps(result),0o644)
    if needs_alert(result):print(json.dumps({'type':'independent_health_alert',**result}),flush=True)
if __name__=='__main__':main()
