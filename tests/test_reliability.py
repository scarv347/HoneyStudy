import json,sqlite3,tempfile,unittest
from pathlib import Path
from collector import connect,ingest
from hub import accept
from history import publish_history
from classification import classify
from analysis import analyze
from proxy_ingest import ingest_line
from network_adapter import adapt
from exports import matches,options

class Reliability(unittest.TestCase):
 def test_legacy_offset_migration_retains_original_and_exact_epoch(self):
  with tempfile.TemporaryDirectory() as tmp:
   state=Path(tmp);db=sqlite3.connect(state/'index.sqlite')
   db.execute('CREATE TABLE events(id TEXT PRIMARY KEY,time TEXT,ip TEXT,service TEXT,severity TEXT,data TEXT)')
   raw=json.dumps({'time':'2026-10-25T01:02:03.123456+0000'})
   db.execute('INSERT INTO events VALUES (?,?,?,?,?,?)',('x','2026-10-25T01:02:03.123456+0000','8.8.8.8','network','info',raw));db.commit();db.close()
   db=connect(state)
   stamp,data,valid=db.execute('select time,data,julianday(time) is not null from events').fetchone()
   self.assertEqual(stamp,'2026-10-25T01:02:03.123456+00:00');self.assertEqual(data,raw);self.assertEqual(valid,1)
   self.assertEqual(db.execute('select epoch_us%1000000 from event_clock').fetchone()[0],123456);db.close()
 def test_ingested_network_clock_is_canonical_and_retry_safe(self):
  with tempfile.TemporaryDirectory() as tmp:
   event=adapt({'event_type':'flow','timestamp':'2026-10-25T01:00:00+0000','src_ip':'8.8.8.8','dest_ip':'10.0.0.10'},'a'*64)
   for _ in range(2):accept(Path(tmp),'research',json.dumps({'version':1,'events':[event]}).encode())
   db=connect(Path(tmp));self.assertEqual(db.execute('select count(*) from events').fetchone()[0],1)
   self.assertEqual(db.execute('select time from events').fetchone()[0],'2026-10-25T01:00:00.000000+00:00');db.close()
 def test_diagnostics_do_not_hide_real_network_detections(self):
  for signature,kind,severity in [('SURICATA TCPv4 invalid checksum','capture_diagnostic','info'),('ET SCAN mySQL probe','detection','medium'),('ET DROP Dshield Block Listed Source group 1','reputation','medium')]:
   e=adapt({'event_type':'alert','timestamp':'2026-10-25T01:00:00Z','src_ip':'8.8.8.8','dest_ip':'10.0.0.10','alert':{'signature':signature,'severity':2}},'a'*64)
   result=classify(e);self.assertEqual(result['signal_kind'],kind);self.assertEqual(result['severity'],severity)
   self.assertFalse(result['exploitation_confirmed'])
 def test_php_tag_is_not_execution_but_calls_remain_detected(self):
  import base64
  for body,wanted in [(b'<?php /* documentation */','info'),(b'<?php system("id");','high')]:
   a=analyze({'path':'/upload.php','method':'POST','payload_base64':base64.b64encode(body).decode()})
   e={'path':'/example.php','method':'POST','service':'portal','analysis':a}
   # Exclude the upload-path indicator: this assertion concerns PHP syntax itself.
   e['analysis']=analyze({'path':'/example.php','method':'POST','payload_base64':base64.b64encode(body).decode()})
   self.assertEqual(classify(e)['severity'],wanted)
  legacy={'path':'/x','service':'portal','analysis':{'hits':[{'rule':'PHP execution markers','match':'<?php','severity':'high'}],'payload_preview':'<?php /* comment */'}}
  self.assertEqual(classify(legacy)['severity'],'info')
 def test_rejected_raw_path_retains_traversal_and_redacts_query(self):
  with tempfile.TemporaryDirectory() as tmp:
   db=connect(Path(tmp));raw={'time':'2026-10-25T01:00:00Z','ip':'8.8.8.8','method':'GET','path':'','raw_path':'/%2e%2e/etc/passwd?password=never-store-this','status':400,'request_id':'fixture','upstream_addr':''}
   self.assertTrue(ingest_line(db,json.dumps(raw),'fixture'))
   data=db.execute('select data from events').fetchone()[0];self.assertNotIn('never-store-this',data)
   e=json.loads(data);self.assertIn('Traversal / local file probe',[x['name'] for x in classify(e)['findings']]);self.assertIn('Rejected requests',classify(e)['groups']);db.close()
 def test_history_reuses_closed_pages_and_tracks_late_proxy(self):
  with tempfile.TemporaryDirectory() as tmp:
   state=Path(tmp);public=state/'public';public.mkdir();db=connect(state)
   ingest(db,json.dumps({'time':'2026-10-25T01:00:00Z','ip':'8.8.8.8','path':'/fixture','request_id':'fixture'}))
   config={'operator_networks':[]};first=publish_history(db,public,config);trace=[];db.set_trace_callback(trace.append)
   self.assertEqual(first,publish_history(db,public,config));self.assertFalse(any('FROM events WHERE rowid BETWEEN' in sql for sql in trace))
   db.execute('insert into proxy_observations values (?,?,?,?,?)',('p','2026-10-25T01:00:00Z','8.8.8.8','fixture',json.dumps({'status':400})))
   self.assertNotEqual(first,publish_history(db,public,config));db.close()
 def test_export_diagnostics_is_explicit(self):
  e={'time':'2026-10-25T01:00:00Z','signal_kind':'capture_diagnostic','ip':'8.8.8.8'}
  self.assertFalse(matches(e,options('diagnostics=0'),{}));self.assertTrue(matches(e,options('diagnostics=1'),{}))
  with self.assertRaises(ValueError):options('diagnostics=bogus')
 def test_exact_test_registry_does_not_exclude_other_events_from_same_ip(self):
  from publication import classifier
  cohort=classifier({'operator_networks':[],'verified_tests':{'reviewed-id':'owner audit'}})
  self.assertEqual(cohort('8.8.8.8','reviewed-id'),'operator_test')
  self.assertEqual(cohort('8.8.8.8','copied-user-agent'),'outside_unclassified')
 def test_admin_registry_is_readable_by_publisher_not_shared_directory_group(self):
  from register_test_run import register
  from unittest.mock import patch
  from types import SimpleNamespace
  with tempfile.TemporaryDirectory() as tmp:
   state=Path(tmp)
   with patch('register_test_run.os.geteuid',return_value=0),patch('register_test_run.grp.getgrnam',return_value=SimpleNamespace(gr_gid=987)) as group,patch('register_test_run.os.chown') as owner:
    register(state,['reviewed-id'],'owner audit');group.assert_called_once_with('hub');owner.assert_called_once_with(state/'verified-tests.json',0,987)
 def test_test_registry_applies_to_history_and_research_counts(self):
  from publication import build,observe
  with tempfile.TemporaryDirectory() as tmp:
   state=Path(tmp);public=state/'public';public.mkdir();db=connect(state)
   ingest(db,json.dumps({'time':'2026-10-25T01:00:00Z','ip':'8.8.8.8','path':'/fixture'}))
   identifier=db.execute('select id from events').fetchone()[0]
   config={'operator_networks':[],'verified_tests':{identifier:'owner audit'}}
   manifest=publish_history(db,public,config)
   self.assertEqual(manifest['outside_count'],0);self.assertEqual(manifest['excluded_count'],1)
   observe(db,{},config)
   report=build(db,config,all_time=True);self.assertEqual(report['outside']['events'],0);self.assertEqual(report['cohorts']['operator_test'],1);db.close()

if __name__=='__main__':unittest.main()
