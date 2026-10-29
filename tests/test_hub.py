import hashlib,http.client,json,sqlite3,tempfile,threading,unittest,subprocess,sys
from pathlib import Path
from unittest.mock import patch
import hub,ship
from collector import connect
from cowrie_adapter import adapt
from classification import classify

def event():
 return adapt(json.dumps({'eventid':'cowrie.command.input','timestamp':'2026-10-25T01:00:00Z','session':'a','src_ip':'8.8.8.8','input':'curl http://example.invalid/wp-admin'}),{})

class Ingestion(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.state=Path(self.temp.name)
  self.server=hub.Server(('127.0.0.1',0),hub.Handler);self.server.state=self.state
  self.server.config={'sensors':{'cowrie-ssh':{'token':'test-only','ip':'127.0.0.1'}}}
  self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
 def tearDown(self):
  self.server.shutdown();self.server.server_close();self.temp.cleanup()
 def request(self,path,body,token='test-only',headers=None):
  c=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=3)
  c.request('POST',path,body,{'Authorization':'Bearer '+token,**(headers or {})});r=c.getresponse();status=r.status;r.read();c.close();return status
 def test_replay_and_health(self):
  data={'version':1,'events':[event()],'health':{'cowrie.service':'active'}}
  for _ in range(2):self.assertEqual(self.request('/v1/batch',json.dumps(data)),204)
  self.assertEqual(self.request('/v1/batch',json.dumps({'version':1,'events':[]})),204)
  db=sqlite3.connect(self.state/'index.sqlite')
  self.assertEqual(db.execute('select count(*) from events').fetchone()[0],1)
  self.assertEqual(json.loads(db.execute('select health from sensors').fetchone()[0]),data['health']);db.close()
 def test_intelligence_reader_uses_snapshot_while_intake_continues(self):
  import hub_publish
  db=connect(self.state);db.commit()
  self.assertEqual(db.execute('PRAGMA synchronous').fetchone()[0],2)
  db.close()
  (self.state/'history-gc.timestamp').touch()
  from render_index import seed
  seed(self.state)
  from threat_intelligence import summarize
  def inspect_copy(copy,state):
   # Hold a read snapshot for the full duration of historical analysis.
   copy.execute('BEGIN');self.assertEqual(copy.execute('SELECT count(*) FROM events').fetchone()[0],0)
   data={'version':1,'events':[event()],'health':{'cowrie.service':'active'}}
   self.assertEqual(self.request('/v1/batch',json.dumps(data)),204)
   self.assertEqual(copy.execute('SELECT count(*) FROM events').fetchone()[0],0)
   self.assertNotEqual(copy.execute('PRAGMA database_list').fetchone()[2],str(self.state/'index.sqlite'))
   return summarize(copy,state)
  with patch.dict('os.environ',{'HUB_STATE':str(self.state)}),patch('threat_intelligence.summarize',side_effect=inspect_copy),patch('collector.publish'):
   hub_publish.main()
  # Future publications must not rescan historical provenance under a write lock.
  traced=[];original_connect=hub_publish.collector.connect
  def traced_connect(state):
   connection=original_connect(state);connection.set_trace_callback(traced.append);return connection
  with patch.dict('os.environ',{'HUB_STATE':str(self.state)}),patch('collector.connect',side_effect=traced_connect),patch('collector.publish'):
   hub_publish.main()
  self.assertFalse(any('INSERT OR IGNORE INTO event_sources SELECT' in sql for sql in traced))
  live=sqlite3.connect(self.state/'index.sqlite');backup=sqlite3.connect(self.state/'restore.sqlite')
  live.backup(backup);self.assertEqual(backup.execute('SELECT count(*) FROM events').fetchone()[0],1)
  self.assertEqual(backup.execute('PRAGMA integrity_check').fetchone()[0],'ok')
  backup.close();live.close()
 def test_auth_and_source(self):
  self.assertEqual(self.request('/v1/batch','{}',token='wrong'),403)
  self.server.config['sensors']['cowrie-ssh']['ip']='127.0.0.2'
  self.assertEqual(self.request('/v1/batch','{}'),403)
 def test_reject_invalid_and_wrong_stream(self):
  bad=event();bad['service']='portal'
  self.assertEqual(self.request('/v1/batch',json.dumps({'version':1,'events':[bad]})),400)
  self.assertEqual(self.request('/v1/batch','{"version":1,"events":NaN}'),400)
  self.assertEqual(self.request('/v1/batch','{}',headers={'Content-Length':str(3*1024*1024)}),413)
 def test_archive_hash_and_path(self):
  raw=b'{"original":true}\n';digest=hashlib.sha256(raw).hexdigest()
  for _ in range(2):self.assertEqual(self.request('/v1/archive/cowrie-archive/'+digest,raw),204)
  self.assertEqual((self.state/'cowrie-archive'/(digest+'.jsonl')).read_bytes(),raw)
  self.assertEqual(self.request('/v1/archive/archive/'+digest,raw),400)
  self.assertEqual(self.request('/v1/archive/cowrie-archive/'+'0'*64,raw),400)
 def test_original_archive_preserves_non_utf8_request_bytes(self):
  raw=b'{"captured_header":"raw-'+bytes([255,254])+b'"}\n';digest=hashlib.sha256(raw).hexdigest()
  self.assertEqual(self.request('/v1/archive/cowrie-archive/'+digest,raw),204)
  self.assertEqual((self.state/'cowrie-archive'/(digest+'.jsonl')).read_bytes(),raw)
 def test_ssh_classification(self):
  e=event();c=classify(e)
  self.assertEqual(c['severity'],'high');self.assertEqual(c['targets'],['SSH'])
  self.assertFalse(any('WordPress' in f['name'] for f in c['findings']))
 def test_outage_retains_sender_checkpoint(self):
  db=connect(self.state);e=event();e['id']='source-1';e['service']='portal'
  db.execute('INSERT INTO events VALUES (?,?,?,?,?,?)',(e['id'],e['time'],e['ip'],e['service'],'info',json.dumps(e)));db.commit();db.close()
  state={};config={'database':str(self.state/'index.sqlite')}
  with patch('ship.batch',side_effect=RuntimeError('offline')):
   with self.assertRaises(RuntimeError):ship.php(config,state,lambda:None,float('inf'))
  self.assertNotIn('events',state)
  with patch('ship.batch'):
   ship.php(config,state,lambda:None,float('inf'))
  self.assertEqual(state['events'],1)
 def test_userspace_transport_waits_for_ack_without_stdin_eof(self):
  code="""import sys,time
length=0
while True:
 line=sys.stdin.buffer.readline()
 if line==b'\\r\\n':break
 if line.lower().startswith(b'content-length:'):length=int(line.split(b':')[1])
sys.stdin.buffer.read(length)
sys.stdout.buffer.write(b'HTTP/1.0 204 No Content\\r\\nContent-Length: 0\\r\\n\\r\\n');sys.stdout.buffer.flush()
time.sleep(30)
"""
  original=subprocess.Popen
  with patch('ship.subprocess.Popen',side_effect=lambda *a,**kw:original([sys.executable,'-c',code],**kw)):
   ship.post({'transport':'tailscale-nc','collector':'unused','token':'test-only'},'/v1/batch',b'x'*100000)

if __name__=='__main__':unittest.main()
