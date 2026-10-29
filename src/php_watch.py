"""Bounded PHP-request observations, never an emulator of memory corruption or execution."""
from collections import Counter
from datetime import datetime,timezone,timedelta
import re
from urllib.parse import unquote

VERSION='rx1-php-watch-1'
CATALOG=[
 {'id':'CVE-2026-109618','title':'PHP request-memory handling','mapping':'Context only; multipart structure cannot establish OOM or exploitation.','source':'https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w'},
 {'id':'CVE-2026-109619','title':'PHP state across requests','mapping':'Context only; upload-progress markers do not establish stale worker state.','source':'https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp'},
 {'id':'CVE-2024-4577-family','title':'Older PHP-CGI argument injection','mapping':'Family-level pattern; does not distinguish all bypasses or prove exploitability.','source':'https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv'},
]
SIGNALS={'php-code-marker','php-execution-function','php-input-wrapper','php-config-directive','cgi-argument-pattern','multipart-upload','upload-progress-field','multipart-many-parts','multipart-many-headers','multipart-deep-field-nesting','multipart-no-declared-length','php-serialized-object'}

def profile(event,payload):
    body=payload[:16384].decode('utf-8','replace')
    path=str(event.get('path',''))[:8192]
    headers=event.get('headers',{})
    headers={str(k).lower():str(v)[:500] for k,v in headers.items()} if isinstance(headers,dict) else {}
    content=path+'\n'+body+'\n'+headers.get('php_value','')+'\n'+headers.get('php_admin_value','')
    normalized=content
    for _ in range(2):normalized=unquote(normalized,encoding='latin-1')
    text=(content+'\n'+normalized).lower()
    signals=[]
    fragments=[]
    patterns=[('php-code-marker',r'<\?(?:php\b|=)'),('php-execution-function',r'\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\('),
              ('php-input-wrapper',r'php://(?:input|filter)'),('php-config-directive',r'\b(?:auto_prepend_file|auto_append_file|allow_url_include|php_value|php_admin_value)\b'),
              ('cgi-argument-pattern',r'(?:%ad|\u00ad|-)d.{0,100}(?:auto_prepend_file|allow_url_include)'),
              ('upload-progress-field',r'php_session_upload_progress|session\.upload_progress'),
              ('php-serialized-object',r'(?:^|[^a-z])o:\d{1,5}:"[^"\r\n]{1,80}":\d{1,5}:')]
    for name,pattern in patterns:
        match=re.search(pattern,text,re.I)
        if match:
            signals.append(name)
            if len(fragments)<6:
                fragments.append({'signal':name,'normalized_text':text[max(0,match.start()-50):match.end()+170][:300]})
    multipart='multipart/form-data' in headers.get('content-type','').lower()
    counts={'captured_multipart_parts':0,'captured_part_header_lines':0,'max_captured_field_nesting':0}
    if multipart:
        signals.append('multipart-upload')
        counts['captured_multipart_parts']=len(re.findall(r'(?im)^content-disposition\s*:',body))
        counts['captured_part_header_lines']=len(re.findall(r'(?m)^[A-Za-z0-9-]{1,80}:',body))
        names=re.findall(r'(?i)\bname="([^"\r\n]{0,256})"',body)
        counts['max_captured_field_nesting']=max((name.count('[') for name in names),default=0)
        if counts['captured_multipart_parts']>=32:signals.append('multipart-many-parts')
        if counts['captured_part_header_lines']>=64:signals.append('multipart-many-headers')
        if counts['max_captured_field_nesting']>=8:signals.append('multipart-deep-field-nesting')
        if 'content-length' not in headers:signals.append('multipart-no-declared-length')
    # Sensors may retain only these fixed labels and numeric counts for credential-redacted bodies.
    captured=event.get('php_capture') or {}
    if isinstance(captured,dict):
        observed=captured.get('signals',[])
        observed=observed if isinstance(observed,list) else []
        for signal in observed[:len(SIGNALS)]:
            if isinstance(signal,str) and signal in SIGNALS and signal not in signals:signals.append(signal)
        for key in counts:
            value=captured.get('structure',{}).get(key) if isinstance(captured.get('structure'),dict) else None
            if isinstance(value,int) and 0<=value<=16384:counts[key]=max(counts[key],value)
    suspicious=any(s in signals for s in ('multipart-many-parts','multipart-many-headers','multipart-deep-field-nesting'))
    injection=any(s in signals for s in ('php-code-marker','php-execution-function','php-input-wrapper','php-config-directive','cgi-argument-pattern'))
    contexts=[]
    if multipart or 'multipart-upload' in signals:
        contexts.append({'id':'CVE-2026-109618','confidence':'context-only'})
    if 'upload-progress-field' in signals:
        contexts.append({'id':'CVE-2026-109619','confidence':'context-only'})
    if 'cgi-argument-pattern' in signals:
        contexts.append({'id':'CVE-2024-4577-family','confidence':'family-pattern'})
    surface=path.split('?',1)[0] in ('/php/','/phpinfo','/pinfo','/legacy/','/_ignition/health-check','/_ignition/execute-solution') or bool(re.search(r'\.php(?:[/?]|$)|/cgi-bin/(?:php|php-cgi)|/php-cgi/',path,re.I))
    return {'version':VERSION,'php_surface':surface,'injection_markers':injection,'structural_anomaly':suspicious,
            'signals':sorted(signals),'evidence_fragments':fragments,'structure':counts,'cve_context':contexts,'capture_truncated':bool(event.get('body_truncated')),
            'body_redacted':bool(event.get('body_redacted')),'exploitation_confirmed':False}

def aggregate(db,config,now=None,all_time=False):
    from publication import classifier
    db.create_function('php_cohort',2,classifier(config),deterministic=True)
    now=(now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    since=(now-timedelta(days=30)).replace(hour=0,minute=0,second=0,microsecond=0).isoformat()
    if all_time:since=''
    condition="time>=? AND time<=? AND php_cohort(ip,id)='outside_unclassified'"
    args=(since,now.isoformat())
    signals=Counter();contexts=Counter();daily={};totals=Counter()
    for day,value in db.execute("SELECT substr(time,1,10),json_extract(data,'$.analysis.php_research') FROM events WHERE "+condition,args):
        if not value:continue
        data=__import__('json').loads(value)
        relevant=data['php_surface'] or bool(data['signals'])
        if not relevant:continue
        totals['php_related_events']+=1
        row=daily.setdefault(day,{'day_utc':day,'php_related_events':0,'injection_marker_events':0,'structural_anomaly_events':0})
        row['php_related_events']+=1
        for key,flag in [('injection_marker_events','injection_markers'),('structural_anomaly_events','structural_anomaly')]:
            if data[flag]:totals[key]+=1;row[key]+=1
        if data['capture_truncated']:totals['truncated_events']+=1
        if data['body_redacted']:totals['redacted_events']+=1
        signals.update(data['signals']);contexts.update(item['id'] for item in data['cve_context'])
    blocked=db.execute("SELECT count(*) FROM events WHERE "+condition+" AND service='nginx-edge' AND json_extract(data,'$.simulation.response_status')=413 AND (lower(json_extract(data,'$.path')) LIKE '%.php%' OR lower(json_extract(data,'$.path')) LIKE '%/cgi-bin/php%')",args).fetchone()[0]
    distinct=db.execute("SELECT count(DISTINCT ip) FROM events WHERE "+condition+" AND (json_extract(data,'$.analysis.php_research.php_surface')=1 OR json_array_length(json_extract(data,'$.analysis.php_research.signals'))>0)",args).fetchone()[0]
    return {'version':VERSION,'scope':('Outside-unclassified cohort, all indexed history; context is not CVE attribution.' if all_time else 'Outside-unclassified cohort, current and previous 30 UTC dates; context is not CVE attribution.'),
            'totals':{key:totals[key] for key in ('php_related_events','injection_marker_events','structural_anomaly_events','truncated_events','redacted_events')},
            'source_ips':distinct,'php_edge_body_limit_rejections':blocked,'signals':dict(signals),'cve_context_events':dict(contexts),
            'daily':list(sorted(daily.values(),key=lambda row:row['day_utc'])),'catalog':CATALOG,
            'limitations':['No PHP interpreter or memory-corruption exploit runs in the simulator.','The new CVEs cannot be confirmed from these HTTP signals.','Multipart counts cover at most the captured 16 KiB prefix; they are lower bounds.','Nginx can reject requests before body capture; rejected bodies are unavailable.','Ordinary file uploads can match CVE context without being attacks.']}
