"""Derived, bounded research summaries. IP correlation is observational, not attribution."""
from collections import Counter,defaultdict
from datetime import datetime,timezone,timedelta
import hashlib
import json

LOOPBACK={'127.0.0.1','::1'}

def summarize(events,generated=None):
    by_source=defaultdict(list)
    payloads={}
    paths=Counter()
    scenarios=Counter()
    for event in events:
        if event.get('ip') in LOOPBACK:continue
        by_source[event['ip']].append(event)
        path=str(event.get('path','/')).split('?',1)[0][:200]
        paths[path]+=1
        sim=event.get('simulation') or {}
        if sim.get('scenario'):scenarios[sim['scenario']]+=1
        assessment=event.get('analysis',{})
        digest=assessment.get('payload_sha256')
        if digest and not sim.get('body_redacted'):
            group=payloads.setdefault(digest,{'sha256':digest,'requests':0,'sources':set(),'paths':set()})
            group['requests']+=1;group['sources'].add(event['ip']);group['paths'].add(path)
    sessions=[]
    sources=[]
    for ip,rows in by_source.items():
        rows.sort(key=lambda r:r.get('time',''))
        sources.append({'ip':ip,'requests':len(rows),'distinct_paths':len(set(str(e.get('path','')).split('?',1)[0] for e in rows)),
                        'high_severity':sum(e.get('analysis',{}).get('severity')=='high' for e in rows),'first':rows[0].get('time'),'last':rows[-1].get('time')})
        current=[]
        previous=None
        for event in rows:
            try:
                stamp=datetime.fromisoformat(event.get('time','').replace('Z','+00:00'))
                if stamp.tzinfo is None:stamp=stamp.replace(tzinfo=timezone.utc)
            except ValueError:continue
            if previous and (stamp-previous).total_seconds()>1800:
                if len(current)>=2:sessions.append(session(ip,current))
                current=[]
            current.append(event);previous=stamp
        if len(current)>=2:sessions.append(session(ip,current))
    repeated=[]
    for group in payloads.values():
        if group['requests']<2:continue
        repeated.append({**group,'source_count':len(group['sources']),'sources':sorted(group['sources'])[:20],'paths':sorted(group['paths'])[:10]})
    return {'generated':generated or datetime.now(timezone.utc).isoformat(),'scope':'Newest 5000 non-loopback indexed events within 24 hours; sessions split after 30 minutes of inactivity.',
            'limitations':['Source IPs are not verified identities.','Shared payload hashes indicate matching captured bytes, not common ownership.','Hashes cover captured bytes; payloads may be truncated.','Canary visits do not prove a link was followed or exploitation succeeded.'],
            'requests':sum(paths.values()),'source_count':len(sources),'top_paths':[{'path':p,'requests':n} for p,n in paths.most_common(30)],
            'scenarios':dict(scenarios.most_common(30)),'sources':sorted(sources,key=lambda s:s['requests'],reverse=True)[:100],
            'sessions':sorted(sessions,key=lambda s:s['last'],reverse=True)[:50],
            'repeated_payloads':sorted(repeated,key=lambda g:g['requests'],reverse=True)[:30]}

def session(ip,events):
    stages=[]
    for event in events:
        sim=event.get('simulation') or {}
        value='canary: '+str(sim['canary']) if sim.get('canary') else str(sim.get('scenario') or 'unclassified')
        if value not in stages:stages.append(value)
    first=events[0].get('time','');last=events[-1].get('time','')
    return {'id':hashlib.sha256((ip+first).encode()).hexdigest()[:16],'ip':ip,'first':first,'last':last,'requests':len(events),
            'stages':stages[:20],'path_sequence':[{'time':e.get('time'),'path':str(e.get('path','')).split('?',1)[0][:200],'method':e.get('method')} for e in events[:30]]}

def from_database(db):
    since=(datetime.now(timezone.utc)-timedelta(hours=24)).isoformat()
    # Select only report fields rather than materializing thousands of payload previews.
    query="""SELECT time,ip,json_extract(data,'$.method'),substr(json_extract(data,'$.path'),1,200),
        json_extract(data,'$.analysis.severity'),json_extract(data,'$.analysis.payload_sha256'),
        json_extract(data,'$.simulation.body_redacted'),json_extract(data,'$.simulation.scenario'),json_extract(data,'$.simulation.canary')
        FROM events WHERE time>=? AND ip NOT IN ('127.0.0.1','::1') ORDER BY time DESC LIMIT 5000"""
    rows=[{'time':time,'ip':ip,'method':method,'path':path or '/',
           'analysis':{'severity':severity,'payload_sha256':digest},
           'simulation':{'body_redacted':redacted,'scenario':scenario,'canary':canary}}
          for time,ip,method,path,severity,digest,redacted,scenario,canary in db.execute(query,(since,))]
    return summarize(rows)
