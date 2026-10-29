"""Validated cached feed matching. Reputation never changes event severity."""
import ipaddress,json
from datetime import datetime,timezone
from pathlib import Path
from collector import atomic

SOURCE='Spamhaus DROP'
URL='https://www.spamhaus.org/blocklists/do-not-route-or-peer/'

def validate(raw):
    if raw.get('source')!=SOURCE:raise ValueError('Unknown feed')
    fetched=datetime.fromisoformat(raw['fetched_at'])
    if fetched.tzinfo is None or fetched>datetime.now(timezone.utc):raise ValueError('Invalid feed time')
    entries=raw['entries']
    if not isinstance(entries,list) or not 1<=len(entries)<=20000:raise ValueError('Invalid feed size')
    result=[]
    for row in entries:
        net=ipaddress.ip_network(row['cidr'],strict=True)
        if net.prefixlen<8:raise ValueError('Unexpectedly broad network')
        sid=str(row.get('sblid',''))
        if not sid.startswith('SBL') or not sid[3:].isdigit():raise ValueError('Invalid listing reference')
        result.append({'cidr':str(net),'sblid':sid})
    return {'source':SOURCE,'source_url':URL,'fetched_at':fetched.isoformat(),'entries':result}

def accept_feed(state,body):
    if len(body)>2*1024*1024:raise ValueError('Feed too large')
    value=validate(json.loads(body));atomic(state/'threat-feed.json',json.dumps(value),0o600)

def summarize(db,state):
    try:feed=validate(json.loads((state/'threat-feed.json').read_text()))
    except (OSError,ValueError,KeyError,TypeError):return {'status':'unavailable','source':SOURCE,'source_url':URL,'sources':{}}
    age=max(0,(datetime.now(timezone.utc)-datetime.fromisoformat(feed['fetched_at'])).total_seconds()/3600)
    groups={}
    for row in feed['entries']:
        net=ipaddress.ip_network(row['cidr']);groups.setdefault((net.version,net.prefixlen),{})[int(net.network_address)]=row
    matches={}
    for value,count in db.execute('SELECT ip,count(*) FROM events GROUP BY ip'):
        address=ipaddress.ip_address(value)
        if not address.is_global:continue
        for (version,prefix),rows in sorted(groups.items(),key=lambda x:-x[0][1]):
            if version!=address.version:continue
            shift=address.max_prefixlen-prefix;row=rows.get((int(address)>>shift)<<shift)
            if row:
                matches[value]={'cidr':row['cidr'],'reference':row['sblid'],'events':count};break
    from urllib.parse import urlsplit
    from collections import Counter
    domains=Counter()
    for url,count in db.execute("SELECT j.value,count(*) FROM events e,json_each(json_extract(e.data,'$.analysis.urls')) j GROUP BY j.value"):
        try:
            host=urlsplit(url).hostname
            if host:host=host.rstrip(').,;').encode('idna').decode('ascii')
            if host:domains[host[:253]]+=count
        except (ValueError,TypeError,UnicodeError):pass
    fingerprints=db.execute("SELECT count(DISTINCT json_extract(data,'$.analysis.payload_sha256')) FROM events").fetchone()[0]
    return {'domains':[{'host':h,'events':n} for h,n in domains.most_common(100)],'payload_fingerprints':fingerprints,'status':'current' if age<48 else 'stale','source':SOURCE,'source_url':URL,'fetched_at':feed['fetched_at'],'age_hours':round(age,1),'networks':len(feed['entries']),'sources':matches,'scope':'Current network-range listing, matched locally. Not proof of event-time reputation or attribution. No logs or observed indicators are submitted to this provider.'}
