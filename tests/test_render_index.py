import json,sqlite3,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from collector import connect
from hub import accept
from render_index import seed,sync

def events(n,start=0):return [{'id':'fixture-'+str(i),'time':'2026-10-26T01:00:00Z','ip':'8.8.8.8','service':'portal','path':'/fixture','simulation':{'request_id':'request-'+str(i)},'analysis':{'severity':'info','hits':[]}} for i in range(start,start+n)]
def deliver(state,rows):accept(state,'rx1-php',json.dumps({'version':1,'events':rows,'health':{'service':'active'}}).encode())
class RenderMirror(unittest.TestCase):
 def test_bounded_sync_matches_live_and_does_not_lock_intake(self):
  with tempfile.TemporaryDirectory() as tmp:
   state=Path(tmp);deliver(state,events(1));seed(state);deliver(state,events(450,1));mirror=sync(state)
   live=sqlite3.connect(state/'index.sqlite')
   self.assertEqual(live.execute('select * from events order by rowid').fetchall(),mirror.execute('select * from events order by rowid').fetchall())
   self.assertEqual(mirror.execute('select count(*) from event_clock').fetchone()[0],451)
   mirror.execute('begin');mirror.execute('select count(*) from events').fetchone();deliver(state,events(1,451));self.assertEqual(mirror.execute('select count(*) from events').fetchone()[0],451);mirror.rollback();mirror.close()
   mirror=sync(state);self.assertEqual(mirror.execute('select count(*) from events').fetchone()[0],452);mirror.close();live.close()
 def test_failed_chunk_resumes_without_omitting_or_duplicating_rows(self):
  with tempfile.TemporaryDirectory() as tmp:
   state=Path(tmp);deliver(state,events(1));seed(state);deliver(state,events(450,1));original=connect
   class Interrupted:
    def __init__(self,db):self.db=db;self.chunks=0
    def __getattr__(self,key):return getattr(self.db,key)
    def executemany(self,sql,rows):
     result=self.db.executemany(sql,rows)
     if sql.startswith('INSERT OR IGNORE INTO events('):
      self.chunks+=1
      if self.chunks==2:raise RuntimeError('simulated interruption')
     return result
   with patch('collector.connect',side_effect=lambda folder:Interrupted(original(folder))):
    with self.assertRaises(RuntimeError):sync(state)
   checkpoint=sqlite3.connect(state/'render-source/index.sqlite');self.assertEqual(checkpoint.execute('select count(*) from events').fetchone()[0],201);checkpoint.close()
   mirror=sync(state);self.assertEqual(mirror.execute('select count(*) from events').fetchone()[0],451);self.assertEqual(mirror.execute('select count(distinct id) from events').fetchone()[0],451);mirror.close()
 def test_abrupt_process_exit_recovers_sqlite_journal_and_replays(self):
  import subprocess,sys,os
  with tempfile.TemporaryDirectory() as tmp:
   state=Path(tmp);deliver(state,events(1));seed(state);deliver(state,events(450,1))
   code="""import os,sys
from pathlib import Path
import collector,render_index
original=collector.connect
class Interrupted:
 def __init__(self,db):self.db=db;self.chunks=0
 def __getattr__(self,key):return getattr(self.db,key)
 def executemany(self,sql,rows):
  result=self.db.executemany(sql,rows)
  if sql.startswith('INSERT OR IGNORE INTO events('):
   self.chunks+=1
   if self.chunks==2:os._exit(73)
  return result
collector.connect=lambda path:Interrupted(original(path))
render_index.sync(Path(sys.argv[1]))
"""
   env={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parents[1] / 'src')};result=subprocess.run([sys.executable,'-c',code,str(state)],env=env)
   self.assertEqual(result.returncode,73)
   mirror=sync(state);self.assertEqual(mirror.execute('select count(*) from events').fetchone()[0],451);self.assertEqual(mirror.execute('pragma quick_check').fetchone()[0],'ok');mirror.close()
 def test_late_proxy_and_source_rewind_are_handled_safely(self):
  with tempfile.TemporaryDirectory() as tmp:
   state=Path(tmp);deliver(state,events(1));seed(state)
   accept(state,'rx1-php',json.dumps({'version':1,'proxies':[{'id':'p','time':'2026-10-26T01:00:01Z','ip':'8.8.8.8','upstream_request_id':'request-0','data':{'status':200}}]}).encode())
   mirror=sync(state);self.assertEqual(mirror.execute('select count(*) from proxy_observations').fetchone()[0],1);mirror.close()
   live=sqlite3.connect(state/'index.sqlite');live.execute('delete from events');live.commit();live.close()
   with self.assertRaises(RuntimeError):sync(state)
   mirror=sqlite3.connect(state/'render-source/index.sqlite');self.assertEqual(mirror.execute('select count(*) from events').fetchone()[0],1);mirror.close()
if __name__=='__main__':unittest.main()
