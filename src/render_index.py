"""Append-only analytical mirror. Short source reads, no full live copy per refresh."""
import json,os,sqlite3
from pathlib import Path
from datetime import datetime,timezone
BATCH=200

def seed(state):
 state=Path(state);folder=state/'render-source';folder.mkdir(mode=0o700,exist_ok=True);target=folder/'index.sqlite'
 if target.exists():return
 stage=folder/'seed.sqlite'
 source=sqlite3.connect('file:'+str(state/'index.sqlite')+'?mode=ro',uri=True,timeout=10);dest=sqlite3.connect(stage)
 try:source.backup(dest)
 finally:dest.close();source.close()
 os.replace(stage,target);target.chmod(0o600)
 db=sqlite3.connect(target)
 try:
  db.execute('CREATE TABLE IF NOT EXISTS render_sync(key TEXT PRIMARY KEY,value TEXT)')
  for table in ['events','proxy_observations']:
   maximum=db.execute('SELECT coalesce(max(rowid),0) FROM '+table).fetchone()[0]
   db.execute('INSERT OR REPLACE INTO render_sync VALUES (?,?)',(table,str(maximum)))
  info=(state/'index.sqlite').stat();db.execute('INSERT OR REPLACE INTO render_sync VALUES (?,?)',('source_identity',json.dumps([info.st_dev,info.st_ino])))
  db.execute('INSERT OR REPLACE INTO render_sync VALUES (?,?)',('generated',datetime.now(timezone.utc).isoformat()));db.commit()
 finally:db.close()

def sync(state):
 from collector import connect
 from hub import schema
 state=Path(state);folder=state/'render-source'
 if not (folder/'index.sqlite').exists():raise RuntimeError('Analytical index must be seeded before live publication')
 source=sqlite3.connect('file:'+str(state/'index.sqlite')+'?mode=ro',uri=True,timeout=2)
 mirror=connect(folder);schema(mirror);mirror.execute('CREATE TABLE IF NOT EXISTS storage_samples(day TEXT PRIMARY KEY,bytes INTEGER)');mirror.commit();mirror.execute('PRAGMA busy_timeout=90000')
 try:
  identity=mirror.execute("SELECT value FROM render_sync WHERE key='source_identity'").fetchone()
  info=(state/'index.sqlite').stat()
  if identity and json.loads(identity[0])!=[info.st_dev,info.st_ino]:raise RuntimeError('Live index identity changed; preserve and re-seed analytical copy')
  if not identity:
   mirror.execute('INSERT INTO render_sync VALUES (?,?)',('source_identity',json.dumps([info.st_dev,info.st_ino])));mirror.commit()
  # Both upper bounds come from the same short read snapshot.
  maxima=source.execute('SELECT (SELECT coalesce(max(rowid),0) FROM events),(SELECT coalesce(max(rowid),0) FROM proxy_observations)').fetchone()
  for table,maximum in zip(['events','proxy_observations'],maxima):
   row=mirror.execute('SELECT value FROM render_sync WHERE key=?',(table,)).fetchone()
   if not row:raise RuntimeError('Missing analytical checkpoint')
   cursor=int(row[0])
   if maximum<cursor:raise RuntimeError('Live index moved behind analytical checkpoint')
   while cursor<maximum:
    rows=source.execute('SELECT rowid,* FROM '+table+' WHERE rowid>? AND rowid<=? ORDER BY rowid LIMIT ?',(cursor,maximum,BATCH)).fetchall()
    if not rows:raise RuntimeError('Unexpected analytical row gap')
    # fetchall completes/releases each source read before writes to the mirror.
    if table=='events':
     mirror.executemany('INSERT OR IGNORE INTO events(rowid,id,time,ip,service,severity,data) VALUES (?,?,?,?,?,?,?)',rows)
     ids=[row[1] for row in rows];placeholders=','.join('?' for _ in ids)
     clocks=source.execute('SELECT id,utc,epoch_us FROM event_clock WHERE id IN ('+placeholders+')',ids).fetchall()
     owners=source.execute('SELECT id,sensor FROM event_sources WHERE id IN ('+placeholders+')',ids).fetchall()
     mirror.executemany('INSERT OR IGNORE INTO event_clock VALUES (?,?,?)',clocks)
     mirror.executemany('INSERT OR IGNORE INTO event_sources VALUES (?,?)',owners)
    else:mirror.executemany('INSERT OR IGNORE INTO proxy_observations(rowid,id,time,ip,upstream_request_id,data) VALUES (?,?,?,?,?,?)',rows)
    cursor=rows[-1][0];mirror.execute('INSERT OR REPLACE INTO render_sync VALUES (?,?)',(table,str(cursor)));mirror.commit()
  for table,marks in [('sensors','?,?,?'),('sensor_delivery','?,?,?,?'),('capture_delivery','?,?,?'),('storage_samples','?,?')]:
   try:rows=source.execute('SELECT * FROM '+table).fetchall()
   except sqlite3.OperationalError:continue
   mirror.executemany('INSERT OR REPLACE INTO '+table+' VALUES ('+marks+')',rows)
  mirror.execute('INSERT OR REPLACE INTO render_sync VALUES (?,?)',('generated',datetime.now(timezone.utc).isoformat()));mirror.commit()
  return mirror
 except BaseException:mirror.close();raise
 finally:source.close()

if __name__=='__main__':seed(Path(os.environ.get('HUB_STATE','/var/lib/honeypot-hub')))
