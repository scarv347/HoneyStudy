import json,tempfile,unittest
from datetime import datetime,timezone
from pathlib import Path
from threat_intelligence import accept_feed,summarize
from hub import valid_event
from network_adapter import adapt
from collector import connect,ingest
class Expansion(unittest.TestCase):
 def test_cached_matching_and_invalid_feed_preserved(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);db=connect(root)
   ingest(db,json.dumps({'time':datetime.now(timezone.utc).isoformat(),'ip':'8.8.8.8','path':'/','service':'portal','headers':{}}));db.commit()
   feed={'source':'Spamhaus DROP','fetched_at':datetime.now(timezone.utc).isoformat(),'entries':[{'cidr':'8.8.8.0/24','sblid':'SBL123'}]}
   accept_feed(root,json.dumps(feed).encode());before=(root/'threat-feed.json').read_bytes()
   self.assertIn('8.8.8.8',summarize(db,root)['sources'])
   feed['entries'][0]['cidr']='0.0.0.0/0'
   with self.assertRaises(ValueError):accept_feed(root,json.dumps(feed).encode())
   self.assertEqual(before,(root/'threat-feed.json').read_bytes());db.close()
 def test_network_namespace(self):
  e=adapt({'timestamp':datetime.now(timezone.utc).isoformat(),'event_type':'flow','src_ip':'8.8.8.8','dest_ip':'10.0.0.10'},'a'*64);valid_event(e,'research')
  with self.assertRaises(ValueError):valid_event(e,'rx1-php')
  e['service']='redis'
  with self.assertRaises(ValueError):valid_event(e,'research')
 def test_protocol_ingestion(self):
  with tempfile.TemporaryDirectory() as tmp:
   db=connect(Path(tmp));e={'time':datetime.now(timezone.utc).isoformat(),'ip':'8.8.8.8','path':'redis://6379/','service':'redis','method':'REDIS','headers':{},'protocol_commands':['CONFIG SET dir /tmp'],'protocol':{'commands':['CONFIG SET dir /tmp']}}
   self.assertEqual(ingest(db,json.dumps(e)),0)
   stored=json.loads(db.execute('SELECT data FROM events').fetchone()[0]);self.assertEqual(stored['analysis']['severity'],'high');self.assertTrue(stored['protocol']);valid_event(stored,'rx1-php');db.close()
if __name__=='__main__':unittest.main()
