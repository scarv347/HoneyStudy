"""Bounded, attributed packet delivery telemetry from the research peer."""
from datetime import datetime,timezone
import json,re

def validate(value):
 if not isinstance(value,dict) or len(json.dumps(value))>32768:raise ValueError('Invalid capture telemetry')
 result={}
 if not re.fullmatch('[0-9a-f]{32}',str(value.get('epoch',''))):raise ValueError('Invalid capture epoch')
 result['epoch']=value['epoch']
 for key in ['generated','tracking_started']:
  stamp=datetime.fromisoformat(value[key]);
  if stamp.tzinfo is None:raise ValueError('Capture telemetry requires timezone')
  result[key]=stamp.astimezone(timezone.utc).isoformat()
 for key in ['pending_count','pending_bytes','expired_unacknowledged','acknowledged_count','budget_bytes']:
  n=value[key]
  if not isinstance(n,int) or isinstance(n,bool) or not 0<=n<=2**53:raise ValueError('Invalid capture counter')
  result[key]=n
 result['oldest_pending']=None
 if value.get('oldest_pending'):
  stamp=datetime.fromisoformat(value['oldest_pending'])
  if stamp.tzinfo is None:raise ValueError('Capture time requires timezone')
  result['oldest_pending']=stamp.astimezone(timezone.utc).isoformat()
 gaps=value.get('recent_gaps',[])
 if not isinstance(gaps,list) or len(gaps)>20:raise ValueError('Invalid capture gaps')
 result['recent_gaps']=[]
 for gap in gaps:
  if gap.get('reason') not in ['missing-file','disk-budget','disk-reserve','age-limit']:raise ValueError('Invalid gap reason')
  if not isinstance(gap.get('sequence'),int) or gap['sequence']<1 or not re.fullmatch('[0-9a-f]{64}',str(gap.get('sha256',''))):raise ValueError('Invalid gap reference')
  result['recent_gaps'].append({k:gap[k] for k in ['sequence','sha256','created','expired','reason']})
 return result
