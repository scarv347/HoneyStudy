"""Read-only checksum verification of captured raw journal batches."""
import argparse
import hashlib
import json
from pathlib import Path

parser=argparse.ArgumentParser()
parser.add_argument('state',type=Path)
args=parser.parse_args()
files=sorted((args.state/'archive').glob('*.jsonl'))+sorted((args.state/'proxy-archive').glob('*.jsonl'))
if not files:
    raise SystemExit('No evidence batches found; verification incomplete')
failures=[]
size=0
for path in files:
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(65536),b''):
            digest.update(block)
            size+=len(block)
    if path.name!=digest.hexdigest()+'.jsonl':
        failures.append(path.name)
print(json.dumps({'batches':len(files),'bytes':size,'mismatches':failures}))
raise SystemExit(bool(failures))
