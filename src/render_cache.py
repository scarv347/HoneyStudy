"""Bound only derived history; preserve the full currently published reference set."""
import json,re,time
from pathlib import Path

def referenced(public):
 public=Path(public);doc=json.loads((public/'snapshot.json').read_text());keep=set()
 def name(url):
  if not isinstance(url,str) or not re.fullmatch(r'/history/[0-9a-f]{64}\.json',url):raise ValueError('Invalid history reference')
  return url.rsplit('/',1)[1]
 if doc.get('snapshot'):keep.add(name(doc['snapshot']))
 history=doc['history']
 for url in history['outside']+history['excluded']:
  key=name(url);keep.add(key);rows=json.loads((public/'history'/key).read_text())
  if not isinstance(rows,list):raise ValueError('Invalid history index')
  for row in rows:
   if row.get('detail'):keep.add(name(row['detail']))
 return keep

def collect(public,budget=4*1024**3,now=None):
 public=Path(public);now=time.time() if now is None else now;keep=referenced(public)
 paths=list((public/'history').glob('*.json'));total=sum(p.stat().st_size+(p.with_suffix('.json.gz').stat().st_size if p.with_suffix('.json.gz').exists() else 0) for p in paths);removed=0
 for p in sorted(paths,key=lambda p:p.stat().st_mtime):
  age=now-p.stat().st_mtime
  if p.name in keep or age<1200 or (age<86400 and total<=budget):continue
  size=p.stat().st_size;other=p.with_suffix('.json.gz')
  if other.exists():size+=other.stat().st_size;other.unlink()
  p.unlink();removed+=1;total-=size
 return {'removed_derived_files':removed,'remaining_bytes':total,'budget_bytes':budget,'current_reference_files':len(keep)}
