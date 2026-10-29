"""Inert document journeys and bounded aggregate research queries; no execution or I/O."""
from datetime import datetime,timezone,timedelta
import re
import hashlib

UPLOADS=('/upload.php','/import.php','/legacy/upload.php','/legacy/import.php')

def response(path,method,body=b''):
    from personas import Response,html,data
    legacy=path.startswith('/legacy/')
    prefix='/legacy' if legacy else ''
    headers={'X-Powered-By':'PHP/8.5.11'} if legacy else {}
    if path=='/login.php' and method in ('GET','HEAD'):
        return Response(200,html('<h1>Customer Portal sign in</h1><form method="POST" action="/login.php"><label>Account <input name="username" autocomplete="off"></label><label>Password <input type="password" name="password"></label><button>Sign in</button></form><p><a href="/documents.php">Guest document submission</a> | <a href="/docs/">Integration documentation</a></p>'),scenario='php-login-discovery')
    if path in ('/documents.php','/legacy/documents.php'):
        return Response(200,html('<h1>Document workspace</h1><p>Submit a document for processing or import structured records. Processing results appear in the job queue.</p><ul><li><a href="'+prefix+'/upload.php">Upload document</a></li><li><a href="'+prefix+'/import.php">Import records</a></li><li><a href="'+prefix+'/status.php">Job queue</a></li><li><a href="/login.php">Account sign in</a></li></ul>'),scenario='php-workspace',headers=headers)
    if path in UPLOADS and method in ('GET','HEAD'):
        return Response(200,html('<h1>'+('Import records' if 'import' in path else 'Upload document')+'</h1><p>Documents enter the review queue before processing.</p><form method="POST" enctype="multipart/form-data" action="'+path+'"><input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="document"><label>Document <input type="file" name="document"></label><button>Submit document</button></form><p><a href="'+prefix+'/documents.php">Document workspace</a></p>'),scenario='php-workflow-form',headers=headers)
    if path in UPLOADS and method=='POST':
        # A signed status URL is added by breadcrumbs.decorate; no uploaded data is reflected.
        return data({'document_id':hashlib.sha256(body).hexdigest()[:20],'status':'pending_review','message':'Document queued for review.','status_url':prefix+'/status.php'},202,'php-workflow-submission',headers)
    if path in ('/status.php','/legacy/status.php'):
        return data({'status':'pending_review','result_url':prefix+'/result.php','message':'Processing is awaiting review.'},scenario='php-workflow-status',headers=headers)
    if path in ('/result.php','/legacy/result.php'):
        return data({'status':'review_required','message':'Document processing is unavailable pending review.'},scenario='php-workflow-result',headers=headers)
    return None

def summarize(db,config,now=None,all_time=False):
    from publication import classifier
    db.create_function('journey_cohort',2,classifier(config),deterministic=True)
    now=(now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    since=(now-timedelta(days=30)).replace(hour=0,minute=0,second=0,microsecond=0).isoformat()
    if all_time:since=''
    condition="time>=? AND time<=? AND journey_cohort(ip,json_extract(data,'$.id'))='outside_unclassified'"
    args=(since,now.isoformat())
    php="(json_extract(data,'$.analysis.php_research.php_surface')=1 OR json_array_length(json_extract(data,'$.analysis.php_research.signals'))>0)"
    stage={}
    for name,extra in [('php_observations',php),('submissions',php+" AND json_extract(data,'$.method')='POST'"),('injection_markers',"json_extract(data,'$.analysis.php_research.injection_markers')=1"),('signed_followups',"json_extract(data,'$.simulation.breadcrumb_follow.status')='valid' AND json_extract(data,'$.simulation.breadcrumb_follow.purpose') LIKE 'workflow-%'")]:
        n,ips=db.execute('SELECT count(*),count(DISTINCT ip) FROM events WHERE '+condition+' AND '+extra,args).fetchone()
        stage[name]={'events':n,'source_ips':ips}
    repeats=db.execute('SELECT count(*) FROM (SELECT ip FROM events WHERE '+condition+' AND '+php+' GROUP BY ip HAVING count(*)>1)',args).fetchone()[0]
    hashes=db.execute("SELECT count(DISTINCT json_extract(data,'$.analysis.payload_sha256')) FROM events WHERE "+condition+' AND '+php+" AND json_extract(data,'$.analysis.payload_bytes')>0 AND coalesce(json_extract(data,'$.simulation.body_redacted'),0)=0",args).fetchone()[0]
    # Deduplicate marker replays. A signed URL establishes an issued link, not human identity.
    unique=db.execute("SELECT count(DISTINCT json_extract(data,'$.simulation.breadcrumb_follow.id')) FROM events WHERE "+condition+" AND json_extract(data,'$.simulation.breadcrumb_follow.status')='valid' AND json_extract(data,'$.simulation.breadcrumb_follow.purpose') LIKE 'workflow-%'",args).fetchone()[0]
    # Return only path components, no query parameters; this remains private analyst data.
    path="substr(json_extract(data,'$.path'),1,instr(json_extract(data,'$.path')||'?','?')-1)"
    unmatched=[{'path':p[:240],'events':n,'source_ips':ips} for p,n,ips in db.execute('SELECT '+path+',count(*),count(DISTINCT ip) FROM events WHERE '+condition+" AND json_extract(data,'$.simulation.scenario')='unmatched-probe' AND lower("+path+") LIKE '%.php%' GROUP BY 1 ORDER BY count(*) DESC,1 LIMIT 20",args)]
    patterns=[{'signal':s,'events':n,'first_seen_utc':first,'last_seen_utc':last} for s,n,first,last in db.execute("SELECT j.value,count(*),min(e.time),max(e.time) FROM events e,json_each(e.data,'$.analysis.php_research.signals') j WHERE "+condition+" GROUP BY j.value ORDER BY min(e.time) DESC LIMIT 30",args) if isinstance(s,str) and re.fullmatch('[a-z-]{1,60}',s)]
    # Reconstruct signed PHP workflows only. Request IDs correlate captured
    # events; they do not establish a person or general browser session.
    rows=db.execute("SELECT ip,time,json_extract(data,'$.simulation.request_id'),json_extract(data,'$.simulation.scenario'),"+
        path+",json_extract(data,'$.simulation.breadcrumb_follow.id'),json_extract(data,'$.simulation.breadcrumb_follow.parent_request_id'),"+
        "json_extract(data,'$.simulation.breadcrumb_follow.purpose') FROM events WHERE "+condition+
        " AND json_extract(data,'$.simulation.breadcrumb_follow.status')='valid' AND json_extract(data,'$.simulation.breadcrumb_follow.purpose') LIKE 'workflow-%' ORDER BY time LIMIT 50000",args).fetchall()
    chains={}
    for ip,stamp,rid,scenario,route,marker,parent,purpose in rows:
        if all(isinstance(x,str) and x for x in (rid,parent,purpose)) and re.fullmatch('[0-9a-f]{32}',marker or ''):
            # Keep the first observation of a marker to avoid counting a replay.
            chains.setdefault((parent,purpose,marker),(ip,stamp,rid,scenario,route))
    by_request={v[2]:(k,v) for k,v in chains.items()}
    def journey_step(purpose):
        if purpose in ('workflow-upload','workflow-import','workflow-legacy-upload','workflow-legacy-import','workflow-api-documents','workflow-api-import'):return 'submission'
        if purpose in ('workflow-status','workflow-legacy-status','workflow-api-status'):return 'status check'
        if purpose in ('workflow-result','workflow-legacy-result','workflow-api-result'):return 'result check'
        return 'other'
    sequences={}
    for key,v in chains.items():
        seq=[];seen=set();node=key
        while node not in seen and len(seq)<5:
            seen.add(node);seq.append(journey_step(node[1]))
            previous=node[0]
            prior=by_request.get(previous)
            if not prior:break
            node=prior[0]
        signature=' → '.join(reversed(seq))
        item=sequences.setdefault(signature,{'events':0,'source_ips':set(),'markers':set(),'last_seen_utc':''})
        item['events']+=1;item['source_ips'].add(v[0]);item['markers'].add(key[2]);item['last_seen_utc']=max(item['last_seen_utc'],v[1])
    observed_journeys=[{'sequence':name,'events':item['events'],'source_ips':len(item['source_ips']),'markers':len(item['markers']),'last_seen_utc':item['last_seen_utc']} for name,item in sorted(sequences.items(),key=lambda pair:(-pair[1]['events'],pair[0]))[:12]]
    return {'stages':stage,'repeat_php_source_ips':repeats,'distinct_captured_php_payloads':hashes,'unique_followed_markers':unique,'unmatched_php_paths':unmatched,'observed_signals':patterns,'observed_journeys':observed_journeys,'scope':('All indexed history; ' if all_time else 'Current and previous 30 UTC dates; ')+'outside-unclassified cohort. Stages overlap; signed links can be replayed; request IDs correlate events but do not establish people or sessions. Captured hashes may identify truncated prefixes.'}
