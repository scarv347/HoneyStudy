"""IndexNow ownership fixture and aggregate engagement experiment, no outbound requests."""
from datetime import datetime,timezone,timedelta
import json
import os
from pathlib import Path
import re

VERSION='rx1-engagement-1'
HOST='honeystudy.example.invalid'
PUBLIC_PATHS=('/', '/php/', '/docs/', '/info.php', '/upload.php', '/import.php', '/legacy/', '/legacy/phpinfo.php', '/legacy/upload.php', '/legacy/import.php')
_key=None
if os.environ.get('CREDENTIALS_DIRECTORY'):
    path=Path(os.environ['CREDENTIALS_DIRECTORY'])/'indexnow.key'
    if path.exists():
        _key=path.read_text().strip()
        if not re.fullmatch(r'[0-9a-f]{32}',_key):raise RuntimeError('Invalid IndexNow ownership key')

def ownership(path,key=None):
    key=_key if key is None else key
    if key and re.fullmatch(r'[0-9a-f]{32}',key) and path=='/'+key+'.txt':return key.encode('ascii')
    return None

def release():
    path=Path(__file__).with_name('discovery_release.json')
    if not path.exists():return {'deployed_utc':None,'indexnow_status':'not submitted'}
    value=json.loads(path.read_text())
    stamp=value['deployed_utc']
    if datetime.fromisoformat(stamp).utcoffset()!=timedelta(0):raise ValueError('Release time must be UTC')
    status=value.get('indexnow_status','not submitted')
    if status not in ('not submitted','received HTTP 200','received HTTP 202','submission failed'):raise ValueError('Invalid discovery status')
    return {'deployed_utc':stamp,'indexnow_status':status}

def summarize(db,config,now=None,all_time=False):
    from publication import classifier
    db.create_function('engagement_cohort',2,classifier(config),deterministic=True)
    now=(now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    since=(now-timedelta(days=30)).replace(hour=0,minute=0,second=0,microsecond=0).isoformat()
    if all_time:since=''
    current=release();boundary=current['deployed_utc']
    groups={'before':{'observations':0,'passed':0,'delayed':0,'rejected':0,'unavailable':0},'after':{'observations':0,'passed':0,'delayed':0,'rejected':0,'unavailable':0}}
    for time,status in db.execute("SELECT time,json_extract(data,'$.limit_req_status') FROM proxy_observations WHERE time>=? AND time<=? AND engagement_cohort(ip,id)='outside_unclassified'",(since,now.isoformat())):
        row=groups['after' if boundary and time>=boundary else 'before']
        row['observations']+=1
        row[{'PASSED':'passed','DELAYED':'delayed','REJECTED':'rejected'}.get(status,'unavailable')]+=1
    legacy=db.execute("SELECT count(*),count(DISTINCT ip) FROM events WHERE time>=? AND time<=? AND engagement_cohort(ip,id)='outside_unclassified' AND json_extract(data,'$.simulation.scenario') LIKE 'php85-%'",(since,now.isoformat())).fetchone()
    return {'version':VERSION,**current,'steady_requests_per_second_per_ip':5,'burst_slots':40,'immediate_burst_slots':20,'active_request_cap':32,
            'proxy_outside':groups,'legacy85_events':legacy[0],'legacy85_source_ips':legacy[1],
            'scope':('Outside-unclassified HTTP proxy observations, all indexed history. ' if all_time else 'Outside-unclassified HTTP proxy observations in the 31-date query window. ')+'Before/after counts have unequal durations. Search crawling is not attack attribution.'}
