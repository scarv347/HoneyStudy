import json,sqlite3,tempfile,unittest
from pathlib import Path
from datetime import datetime,timezone,timedelta
from unittest.mock import patch
from types import SimpleNamespace
from collector import connect,research_sections
from hub import schema
from hub_status import status,needs_alert
from scratch import cleanup,snapshot

class RuntimeSafety(unittest.TestCase):
 def test_cleanup_is_confined_to_disposable_files(self):
  with tempfile.TemporaryDirectory() as tmp:
   state=Path(tmp);evidence=state/'index.sqlite';evidence.write_bytes(b'preserve')
   root=cleanup(state,'publish');(root/'snapshot.sqlite').write_bytes(b'disposable');(root/'snapshot.sqlite-journal').write_bytes(b'disposable')
   cleanup(state,'publish');self.assertFalse(list(root.iterdir()));self.assertEqual(evidence.read_bytes(),b'preserve')
   (root/'unexpected').write_text('keep')
   with self.assertRaises(RuntimeError):cleanup(state,'publish')
   self.assertTrue((root/'unexpected').exists())
 def test_cleanup_rejects_symlink(self):
  with tempfile.TemporaryDirectory() as tmp:
   state=Path(tmp);target=state/'evidence';target.mkdir();(state/'scratch-publish').symlink_to(target,target_is_directory=True)
   with self.assertRaises(RuntimeError):cleanup(state,'publish')
 def test_scratch_reserve_prevents_new_copy(self):
  with tempfile.TemporaryDirectory() as tmp:
   state=Path(tmp);db=connect(state);db.commit()
   with patch('scratch.shutil.disk_usage',return_value=SimpleNamespace(free=1024)):
    with self.assertRaises(RuntimeError):snapshot(db,state,'publish')
   self.assertFalse(list((state/'scratch-publish').iterdir()));db.close()
 def test_backup_failure_cleans_partial_copy(self):
  with tempfile.TemporaryDirectory() as tmp:
   state=Path(tmp);(state/'index.sqlite').write_bytes(b'fixture')
   with patch('scratch.shutil.disk_usage',return_value=SimpleNamespace(free=10*1024**3)):
    with self.assertRaises(RuntimeError):snapshot(SimpleNamespace(backup=lambda *a,**k:(_ for _ in ()).throw(RuntimeError('failure'))),state,'publish')
   self.assertFalse(list((state/'scratch-publish').iterdir()))
 def test_stale_publication_does_not_hide_current_sensor(self):
  with tempfile.TemporaryDirectory() as tmp:
   state=Path(tmp);db=connect(state);schema(db);now=datetime.now(timezone.utc)
   db.execute('insert into sensors values (?,?,?)',('research',now.isoformat(),json.dumps({'engine.service':'active'})));db.commit();db.close()
   (state/'public').mkdir();(state/'public/snapshot.json').write_text(json.dumps({'generated':(now-timedelta(hours=5)).isoformat()}))
   result=status(state,now);self.assertEqual(result['publication'],'stale');self.assertEqual(result['sensors'][0]['status'],'active')
 def test_sensor_failures_alert_even_when_dashboard_and_disk_are_healthy(self):
  result={'publication':'current','storage':'healthy','sensors':[{'status':'active'}]}
  self.assertFalse(needs_alert(result))
  for state in ('failed','stale','unknown'):
   result['sensors']=[{'status':state}];self.assertTrue(needs_alert(result))
  result['sensors']=[];self.assertTrue(needs_alert(result))
 def test_invalid_sensor_health_does_not_hide_other_sensors(self):
  with tempfile.TemporaryDirectory() as tmp:
   state=Path(tmp);db=connect(state);schema(db);now=datetime.now(timezone.utc)
   for identifier,seen,health in [('bad',now.isoformat(),'[]'),('naive',now.replace(tzinfo=None).isoformat(),'{}'),('good',now.isoformat(),'{'+'"engine":"active"'+'}')]:
    db.execute('insert into sensors values (?,?,?)',(identifier,seen,health))
   db.commit();db.close()
   result=status(state,now);sensors={s['id']:s['status'] for s in result['sensors']}
   self.assertEqual(sensors,{'bad':'unknown','naive':'unknown','good':'active'})
 def test_live_publish_never_builds_slow_report_when_cache_old(self):
  with tempfile.TemporaryDirectory() as tmp:
   state=Path(tmp);db=connect(state)
   (state/'research-sections-cache.json').write_text(json.dumps({'generated':'2020-01-01T00:00:00+00:00','version':'old','sections':{'research_generated':'2020-01-01T00:00:00+00:00'}}))
   with patch.dict('os.environ',{'HUB_ASYNC_REPORTS':'1','HUB_STATE':str(state)}),patch('publication.build',side_effect=AssertionError('slow work on live path')):
    config,sections=research_sections(db,state,{})
   self.assertEqual(sections['research_status']['state'],'stale');db.close()
 def test_live_publish_missing_report_cache_is_explicit(self):
  with tempfile.TemporaryDirectory() as tmp:
   state=Path(tmp);db=connect(state)
   with patch.dict('os.environ',{'HUB_ASYNC_REPORTS':'1','HUB_STATE':str(state)}),patch('publication.build',side_effect=AssertionError('slow work on live path')):
    config,sections=research_sections(db,state,{})
   self.assertEqual(sections['research_status']['state'],'pending');db.close()
 def test_cache_budget_preserves_current_details_and_ignores_captured_fake_urls(self):
  import os,time
  from render_cache import collect
  with tempfile.TemporaryDirectory() as tmp:
   public=Path(tmp);folder=public/'history';folder.mkdir()
   index='a'*64+'.json';detail='b'*64+'.json';old='c'*64+'.json'
   (folder/index).write_text(json.dumps([{'detail':'/history/'+detail,'path':'/history/'+'d'*64+'.json'}]));(folder/detail).write_text('[]');(folder/old).write_text('[]')
   (public/'snapshot.json').write_text(json.dumps({'history':{'outside':['/history/'+index],'excluded':[]}}))
   for path in folder.iterdir():os.utime(path,(time.time()-3600,time.time()-3600))
   result=collect(public,budget=1);self.assertEqual(result['removed_derived_files'],1);self.assertTrue((folder/detail).exists());self.assertTrue((folder/index).exists());self.assertFalse((folder/old).exists())
if __name__=='__main__':unittest.main()
