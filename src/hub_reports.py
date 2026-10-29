"""Low-priority reports from a private copy; never blocks live publication."""
import fcntl,json,os,time
from pathlib import Path
import collector
from scratch import snapshot,cleanup

def main():
    state=Path(os.environ.get('HUB_STATE','/var/lib/honeypot-hub'))
    started=time.monotonic()
    def phase(name):print(json.dumps({'report_phase':name,'elapsed_seconds':round(time.monotonic()-started,2)}),flush=True)
    phase('start')
    with (state/'reports.lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        import sqlite3
        db=sqlite3.connect('file:'+str(state/'render-source/index.sqlite')+'?mode=ro',uri=True,timeout=10);copy=None
        try:
            copy=snapshot(db,state,'reports');db.close()
            phase('snapshot-complete')
            try:checks=json.loads((state/'public/snapshot.json').read_text()).get('health',{})
            except (OSError,ValueError):checks={}
            collector.research_sections(copy,state,checks,refresh=True)
            phase('research-complete')
            from threat_intelligence import summarize
            collector.atomic(state/'intelligence-summary-cache.json',json.dumps(summarize(copy,state)))
            phase('complete')
        finally:
            db.close()
            if copy is not None:copy.close()
            cleanup(state,'reports')

if __name__=='__main__':main()
