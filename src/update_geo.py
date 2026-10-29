"""Download only fixed DB-IP monthly releases; validate before atomic activation."""
import gzip,json,os,tempfile,urllib.request,shutil
from pathlib import Path
from datetime import datetime,timezone
import maxminddb
ROOT=Path(os.environ.get('RX1_GEO_DIR','/var/lib/rx1-geo'))
def main():
 ROOT.mkdir(exist_ok=True,mode=0o755)
 release=datetime.now(timezone.utc).strftime('%Y-%m')
 if (ROOT/'release.json').exists() and json.loads((ROOT/'release.json').read_text()).get('release')==release:return
 with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
  for kind in ('city','asn'):
   url=f'https://download.db-ip.com/free/dbip-{kind}-lite-{release}.mmdb.gz'
   target=Path(tmp)/(kind+'.mmdb')
   with urllib.request.urlopen(url,timeout=60) as response,gzip.GzipFile(fileobj=response) as compressed,target.open('wb') as out:
    total=0
    while block:=compressed.read(1024*1024):
     total+=len(block)
     if total>400*1024*1024:raise ValueError('Database size limit exceeded')
     out.write(block)
   with maxminddb.open_database(str(target)) as reader:
    if not reader.metadata().node_count:raise ValueError('Empty database')
  for kind in ('city','asn'):
   p=Path(tmp)/(kind+'.mmdb');p.chmod(0o644);os.replace(p,ROOT/p.name)
  p=Path(tmp)/'release.json';p.write_text(json.dumps({'release':release,'updated':datetime.now(timezone.utc).isoformat(),'provider':'DB-IP Lite'}));p.chmod(0o644);os.replace(p,ROOT/p.name)
if __name__=='__main__':main()
