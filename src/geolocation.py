"""Offline MMDB lookups, cached per IP and database release. Never query source IPs."""
import ipaddress,json,sqlite3,os
from pathlib import Path
from datetime import datetime,timezone

def enrich(db,state,root=None):
 root=Path(root or os.environ.get('RX1_GEO_DIR','/var/lib/rx1-geo'))
 paths=[root/'city.mmdb',root/'asn.mmdb']
 if not all(p.exists() for p in paths):return {'status':'unavailable','sources':{},'provider':'DB-IP Lite'}
 import maxminddb
 readers=[maxminddb.open_database(str(p)) for p in paths]
 version='-'.join(str(r.metadata().build_epoch) for r in readers)
 cache=sqlite3.connect(Path(state)/'geo-cache.sqlite')
 cache.execute('CREATE TABLE IF NOT EXISTS locations (ip TEXT, version TEXT, data TEXT, PRIMARY KEY(ip,version))')
 result={};new=0
 try:
  for (ip,) in db.execute('SELECT DISTINCT ip FROM events'):
   try:
    if not ipaddress.ip_address(ip).is_global:continue
   except ValueError:continue
   old=cache.execute('SELECT data FROM locations WHERE ip=? AND version=?',(ip,version)).fetchone()
   if old:record=json.loads(old[0])
   else:
    city=readers[0].get(ip) or {};asn=readers[1].get(ip) or {};loc=city.get('location',{})
    record={'country':city.get('country',{}).get('names',{}).get('en','Unknown'),'country_code':city.get('country',{}).get('iso_code',''),'city':city.get('city',{}).get('names',{}).get('en',''),'latitude':loc.get('latitude'),'longitude':loc.get('longitude'),'accuracy_radius_km':loc.get('accuracy_radius'),'asn':asn.get('autonomous_system_number'),'organization':asn.get('autonomous_system_organization','Unknown'),'lookup_at':datetime.now(timezone.utc).isoformat(),'database_version':version,'provider':'DB-IP Lite','precision':'Approximate network location; accuracy radius unavailable' if not loc.get('accuracy_radius') else 'Approximate network location'}
    cache.execute('INSERT INTO locations VALUES (?,?,?)',(ip,version,json.dumps(record)));new+=1
   result[ip]=record
  cache.commit()
 finally:
  cache.close()
  for r in readers:r.close()
 return {'status':'ready','provider':'DB-IP Lite','database_version':version,'new_lookups':new,'sources':result}
