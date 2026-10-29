"""Bounded streaming exports from immutable published snapshots, no arbitrary paths."""
import os
import csv,gzip,io,json,re,tarfile
from pathlib import Path
from datetime import datetime
from urllib.parse import parse_qs
PUBLIC=Path(os.environ.get('RX1_PUBLIC_DIR', '/run/rx1-public'))
EVIDENCE=PUBLIC/'originals'

def blob(url,root=PUBLIC):
 if not re.fullmatch(r'/history/[0-9a-f]{64}\.json',url):raise ValueError('Invalid snapshot reference')
 return json.loads((root/url.lstrip('/')).read_text())
def options(query):
 p=parse_qs(query,keep_blank_values=True)
 if set(p)-{'snapshot','format','cohort','from','to','severity','category','target','service','q','ip','network','raw','php','diagnostics'} or any(len(v)!=1 for v in p.values()):raise ValueError('Invalid filters')
 p={k:v[0] for k,v in p.items()}
 if p.get('format','jsonl') not in ('jsonl','json','csv'):raise ValueError('Invalid format')
 if p.get('cohort','outside') not in ('outside','all'):raise ValueError('Invalid cohort')
 if p.get('severity','') not in ('','info','low','medium','high'):raise ValueError('Invalid severity')
 if p.get('diagnostics','1') not in ('0','1'):raise ValueError('Invalid diagnostics selection')
 for k in ('from','to'):
  if p.get(k):
   if datetime.fromisoformat(p[k].replace('Z','+00:00')).tzinfo is None:raise ValueError('Timezone required')
 if any(len(v)>1000 for v in p.values()):raise ValueError('Filter too long')
 return p

def matches(e,p,geo):
 if p.get('diagnostics')=='0' and e.get('signal_kind')=='capture_diagnostic':return False
 t=datetime.fromisoformat(e['time'].replace('Z','+00:00'))
 if p.get('from') and t<datetime.fromisoformat(p['from'].replace('Z','+00:00')):return False
 if p.get('to') and t>=datetime.fromisoformat(p['to'].replace('Z','+00:00')):return False
 for key in ('severity','service','ip'):
  if p.get(key) and e.get(key)!=p[key]:return False
 if p.get('category') and p['category'] not in e.get('groups',[]):return False
 if p.get('target') and p['target'] not in e.get('targets',[]):return False
 if p.get('network') and p['network'].lower() not in (str(geo.get(e['ip'],{}).get('asn',''))+' '+geo.get(e['ip'],{}).get('organization','')).lower():return False
 if p.get('php'):
  php=e.get('php') or {};mode=p['php']
  if not php:return False
  if mode=='injection' and not php.get('injection_markers'):return False
  if mode=='anomaly' and not php.get('structural_anomaly'):return False
  if mode=='current' and not any(c['id'].startswith('CVE-2026-') for c in php.get('cve_context',[])):return False
  if mode=='cgi' and 'cgi-argument-pattern' not in php.get('signals',[]):return False
 text=' '.join([e['ip'],e.get('path',''),e.get('method',''),e.get('service',''),*e.get('labels',e.get('rules',[])),*((e.get('php') or {}).get('signals',[]))]).lower()
 return not p.get('q') or p['q'].lower() in text

def rows(snapshot,p,root=PUBLIC):
 geo=snapshot.get('geolocation',{}).get('sources',{});h=snapshot['history']
 for url in h['outside']+(h['excluded'] if p.get('cohort')=='all' else []):
  for e in blob(url,root):
   if matches(e,p,geo):yield e

def csv_safe(v):
 s=str(v if v is not None else '')
 return "'"+s if s.lstrip().startswith(('=','+','-','@','\t','\r')) else s

def stream(handler,p,snapshot,root=PUBLIC):
 fmt=p.get('format','jsonl');handler.send_response(200)
 handler.send_header('Content-Type','application/gzip');handler.send_header('Content-Disposition',f'attachment; filename="rx1-evidence.{fmt}.gz"')
 handler.send_header('Cache-Control','no-store');handler.send_header('X-Content-Type-Options','nosniff');handler.end_headers();handler.close_connection=True
 cache={};geo=snapshot.get('geolocation',{}).get('sources',{})
 with gzip.GzipFile(fileobj=handler.wfile,mode='wb') as out:
  def write(s):out.write(s.encode())
  if fmt=='json':write('{"snapshot":'+json.dumps(snapshot['generated'])+',"filters":'+json.dumps(p)+',"events":[')
  fields=['id','time','ip','service','method','path','severity','categories','targets','labels','country','city','asn','organization']
  def csvrow(values):
   s=io.StringIO();csv.writer(s).writerow([csv_safe(v) for v in values]);write(s.getvalue())
  if fmt=='csv':csvrow(fields)
  first=True
  for e in rows(snapshot,p,root):
   if fmt=='csv':
    v={**e,**geo.get(e['ip'],{}),'categories':'; '.join(e.get('groups',[])),'targets':'; '.join(e.get('targets',[])),'labels':'; '.join(e.get('labels',[]))};csvrow([v.get(f,'') for f in fields]);continue
   if e['detail'] not in cache:
    cache.clear();cache[e['detail']]=blob(e['detail'],root)
   v=dict(cache[e['detail']][e['position']])
   if v['id']!=e['id']:raise ValueError('Snapshot mismatch')
   v['severity']=e['severity'];v['geolocation']=geo.get(e['ip']);v['export_snapshot']=snapshot['generated']
   write(('' if first or fmt=='jsonl' else ',')+json.dumps(v)+ ('\n' if fmt=='jsonl' else ''));first=False
  if fmt=='json':write(']}')

def raw_stream(handler,root=EVIDENCE):
 # Only the two explicitly mounted archive directories; no credentials/database paths.
 files=[]
 for name in ('archive','proxy-archive','cowrie-archive','network-archive'):
  for p in sorted((root/name).glob('*.jsonl')):
   if p.is_file() and not p.is_symlink():files.append((p,name+'/'+p.name))
 if not files:handler.send_error(503,'Original archive is unavailable');return
 handler.send_response(200);handler.send_header('Content-Type','application/gzip');handler.send_header('Content-Disposition','attachment; filename="rx1-original-logs.tar.gz"');handler.send_header('Cache-Control','no-store');handler.end_headers();handler.close_connection=True
 with tarfile.open(fileobj=handler.wfile,mode='w|gz') as tar:
  for p,name in files:tar.add(p,arcname=name,recursive=False)
