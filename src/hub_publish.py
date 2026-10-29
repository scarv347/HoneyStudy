"""Publish from a coherent database copy so ingestion can continue during rendering."""
import json,os,shutil,sqlite3,tempfile,time
from pathlib import Path
from datetime import datetime,timezone
import collector
from hub import schema

def main():
    state=Path(os.environ.get('HUB_STATE','/var/lib/honeypot-hub'))
    import time
    started=time.monotonic()
    def phase(name):print(json.dumps({'publisher_phase':name,'elapsed_seconds':round(time.monotonic()-started,2)}),flush=True)
    phase('start')
    db=collector.connect(state);schema(db)
    # Imported legacy events need attribution once; live intake records it atomically.
    if not db.execute("SELECT 1 FROM meta WHERE key='event-source-backfill-v1'").fetchone():
        db.execute("INSERT OR IGNORE INTO event_sources SELECT id,'rx1-php' FROM events WHERE service NOT IN ('cowrie','network')")
        db.execute("INSERT INTO meta VALUES ('event-source-backfill-v1','complete')")
        db.commit()
    sensors=[];checks={}
    for sensor,seen,health in db.execute('SELECT sensor,seen,health FROM sensors ORDER BY sensor'):
        age=(datetime.now(timezone.utc)-datetime.fromisoformat(seen)).total_seconds()
        statuses=json.loads(health)
        status='stale' if age>=180 else 'active' if statuses and all(v=='active' for v in statuses.values()) else 'failed'
        checks[sensor+'.service']=status
        sensors.append({'id':sensor,'seen':seen,'status':status,'health':statuses,'events':db.execute('SELECT count(*) FROM event_sources WHERE sensor=?',(sensor,)).fetchone()[0]})
    for sensor in ('rx1-php','cowrie-ssh','research'):
        if not any(s['id']==sensor for s in sensors):
            checks[sensor+'.service']='waiting';sensors.append({'id':sensor,'seen':None,'status':'waiting','events':0,'health':{}})
    disk=shutil.disk_usage(state);checks.update(disk_free_bytes=disk.free,disk_free_percent=round(100*disk.free/disk.total,1),storage_warning=disk.free<5*1024**3)
    from live_health import enrich
    monitoring=enrich(db,sensors,state)
    from threat_intelligence import summarize as intelligence_summary
    from scratch import cleanup
    from render_index import sync
    copy=None
    try:
        phase('index-sync-start')
        db.close();copy=sync(state)
        phase('index-sync-complete')
        # Run historical JSON scans on the private copy, freeing the intake index.
        if os.environ.get('HUB_ASYNC_REPORTS')=='1':
            try:intelligence=json.loads((state/'intelligence-summary-cache.json').read_text())
            except (OSError,ValueError):intelligence={'status':'pending','sources':{}}
        else:intelligence=intelligence_summary(copy,state)
        public=state/'public';public.mkdir(mode=0o755,exist_ok=True);public.chmod(0o755)
        collector.atomic(public/'world.json',Path(__file__).with_name('world.json').read_text(),0o644)
        phase('render-start')
        collector.publish(copy,state,checks,extra={'sensors':sensors,'monitoring':monitoring,'threat_intelligence':intelligence,'scope':'All indexed application and sampled network history; outside traffic by default. Locations are approximate and simulated shell activity does not establish host compromise.'})
        phase('render-complete')
        copy.close()
        # The normal publisher embeds this field in both snapshot and HTML.
        public=state/'public'
        # Retain originals and indexed evidence indefinitely. Only unreferenced render cache expires.
        import re
        gc_stamp=state/'history-gc.timestamp'
        if gc_stamp.exists() and time.time()-gc_stamp.stat().st_mtime<3600:return
        try:
            from render_cache import collect
            print(json.dumps({'render_cache':collect(public)}),flush=True)
            gc_stamp.touch()
        except (OSError,ValueError,KeyError) as error:
            print(json.dumps({'render_cache_maintenance':'deferred','error':type(error).__name__}),flush=True)

    finally:
        try:db.close()
        except sqlite3.Error:pass
        if copy is not None:copy.close()
        cleanup(state,'publish')

if __name__=='__main__':main()
