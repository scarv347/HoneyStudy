"""Correlate validated discovery markers to their issuing requests, without identity claims."""
import json

def trails(db):
    rows=db.execute("SELECT time,ip,data FROM events WHERE json_extract(data,'$.simulation.breadcrumb_follow.status')='valid' ORDER BY time DESC LIMIT 100")
    result=[]
    for stamp,ip,raw in rows:
        event=json.loads(raw);follow=event['simulation']['breadcrumb_follow']
        parent=db.execute("SELECT time,ip,json_extract(data,'$.path') FROM events WHERE json_extract(data,'$.simulation.request_id')=? LIMIT 1",(follow['parent_request_id'],)).fetchone()
        result.append({'time':stamp,'source_ip':ip,'marker':follow,'issuer':{'time':parent[0],'ip':parent[1],'path':parent[2]} if parent else None,'different_observed_ip':bool(parent and parent[1]!=ip)})
    return {'items':result,'scope':'Newest 100 validated marker follow-ups, including self-tests. Markers link requests to issued URLs, not to verified people or successful exploitation.'}
