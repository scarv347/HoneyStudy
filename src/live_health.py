"""Current health summaries, with no secrets or local backup filenames."""
from datetime import datetime, timezone
import json
from pathlib import Path

def enrich(db, sensors, state, now=None):
    now=now or datetime.now(timezone.utc)
    for sensor in sensors:
        row=db.execute('SELECT received,newest_event,lag_seconds FROM sensor_delivery WHERE sensor=?',(sensor['id'],)).fetchone()
        sensor['delivery']=dict(zip(('received','newest_event','lag_seconds'),row)) if row else None
        sensor['last_event']=row[1] if row else None
    db.execute('CREATE TABLE IF NOT EXISTS storage_samples (day TEXT PRIMARY KEY, bytes INTEGER)')
    total=sum(p.stat().st_size for name in ('archive','proxy-archive','cowrie-archive','network-archive') for p in (state/name).glob('*.jsonl'))+(state/'index.sqlite').stat().st_size
    day=now.date().isoformat()
    previous=db.execute('SELECT day,bytes FROM storage_samples WHERE day<? ORDER BY day DESC LIMIT 1',(day,)).fetchone()
    db.execute('INSERT OR IGNORE INTO storage_samples VALUES (?,?)',(day,total))
    backup={'status':'unknown','last_success':None,'age_hours':None}
    try:
        raw=json.loads(Path('/var/lib/honeypot-backup-health/status.json').read_text())
        stamp=datetime.fromisoformat(raw['last_success'].replace('Z','+00:00'))
        age=max(0,(now-stamp).total_seconds()/3600)
        backup={'status':'current' if age<36 else 'overdue','last_success':stamp.isoformat(),'age_hours':round(age,1),'bytes':int(raw['bytes']),'sensor_recovery':raw.get('sensor_recovery',{})}
    except (OSError,ValueError,KeyError,TypeError):pass
    capture=None
    try:
        row=db.execute("SELECT received,data FROM capture_delivery WHERE sensor='research'").fetchone()
        if row:capture={**json.loads(row[1]),'received':row[0]}
    except (ValueError,__import__('sqlite3').Error):pass
    db.commit()
    return {'capture':capture,'backup':backup,'stored_evidence_bytes':total,'growth_since_previous_day_bytes':max(0,total-previous[1]) if previous else None,'growth_baseline_day':previous[0] if previous else None}
