"""Admin-only exact-ID adjudication. No header or future IP traffic is trusted."""
import argparse,json,os,grp
from pathlib import Path
from collector import atomic

def register(state,identifiers,label):
 if not isinstance(identifiers,list) or not 1<=len(identifiers)<=5000 or any(not isinstance(x,str) or not 1<=len(x)<=256 for x in identifiers):raise ValueError('Invalid exact IDs')
 if not isinstance(label,str) or not 1<=len(label)<=100:raise ValueError('Invalid test label')
 target=state/'verified-tests.json'
 current=json.loads(target.read_text()) if target.exists() else {}
 current.update({identifier:label for identifier in identifiers})
 if len(current)>10000:raise ValueError('Review test registry retention')
 atomic(target,json.dumps(current),0o640)
 if os.geteuid()==0:os.chown(target,0,grp.getgrnam('hub').gr_gid)
 return len(identifiers)

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--state',type=Path,default=Path('/var/lib/honeypot-hub'));parser.add_argument('--label',required=True);args=parser.parse_args()
 if os.geteuid()!=0:raise SystemExit('Use authenticated administrator SSH and sudo')
 print('Registered exact observations:',register(args.state,json.load(__import__('sys').stdin),args.label))
