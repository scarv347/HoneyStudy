"""Versioned, explainable labels over retained evidence; original assessments stay intact."""
import re
from urllib.parse import unquote
VERSION = 'rx1-context-2026.10.25.4'
SSH_COMMAND_RULES = [
 ('SSH host discovery command','low',r'\b(?:uname|whoami|lscpu)\b|/etc/(?:os-release|lsb-release|redhat-release)'),
 ('SSH key persistence indicators','high',r'authorized_keys|(?:ssh-(?:rsa|ed25519)|ecdsa-sha2-)\s+[A-Za-z0-9+/]{30,}'),
 ('SSH file attribute change command','medium',r'\b(?:chattr|lockr)\s+[-+]'),
 ('SSH executable permission change','medium',r'\bchmod\s+(?:\+x|[0-7]?[1357][0-7]{2})\b'),
 ('SSH scheduled persistence indicators','high',r'\bcrontab\b|/etc/cron(?:\.|/)|/etc/rc\.local'),
 ('SSH download command observed','high',r'\b(?:wget|curl|tftp|ftpget)\b|/dev/tcp/'),
 ('SSH download piped to shell','high',r'\b(?:curl|wget)\b[^\n|]{0,1500}\|\s*(?:/bin/)?(?:ba)?sh\b'),
]
# Match request paths independently from bodies and headers to retain evidence context.
PATH_RULES = [
 ('Environment secrets discovery','Reconnaissance','Secrets',r'/\.env(?:[./?_-]|$)'),
 ('Source control discovery','Reconnaissance','Source code',r'/\.(?:git|svn|hg)(?:/|$)'),
 ('Cloud credential discovery','Reconnaissance','Secrets',r'/\.(?:aws|azure|kube)/|/credentials(?:[./?]|$)'),
 ('Backup archive discovery','Reconnaissance','Backups',r'/(?:[^/?]+\.(?:zip|tar|tgz|bak|sql)(?:\?|$)|backup(?:s)?(?:/|$))'),
 ('Debug and configuration discovery','Reconnaissance','Configuration',r'/(?:actuator|console|server-status|_profiler|phpinfo|info\.php|@vite/env|debug|telescope|config\.|api/config)'),
 ('Camera management endpoint probe','Reconnaissance','Network appliance',r'/sdk/weblanguage(?:[/?]|$)'),
 ('WordPress discovery','Reconnaissance','WordPress',r'/wp-|/xmlrpc\.php'),
 ('PHP administration discovery','Reconnaissance','PHP',r'/phpmyadmin|/pma(?:/|$)'),
 ('PHP framework and test tooling discovery','Reconnaissance','PHP framework',r'/(?:vendor/phpunit/phpunit/src/util/php/eval-stdin\.php|phpunit/phpunit/src/util/php/eval-stdin\.php|_ignition(?:/|$)|telescope(?:/|$)|vendor/composer/|composer\.(?:json|lock)(?:\?|$))'),
 ('PHP runtime and FastCGI discovery','Reconnaissance','PHP runtime',r'/(?:php-cgi(?:\.exe)?|cgi-bin/php(?:-cgi)?(?:\.exe)?|fpm-status|status\.php\?full)(?:/|\?|$)'),
 ('PHP CMS administration discovery','Reconnaissance','PHP CMS',r'/(?:wp-admin(?:/|$)|wp-login\.php|xmlrpc\.php|administrator/(?:index\.php)?|user/login(?:/|\?|$))'),
 ('Database administration discovery','Reconnaissance','Database tools',r'/(?:adminer(?:\.php)?|phpmyadmin|pma)(?:/|\?|$)'),
 ('Authentication endpoint discovery','Reconnaissance','Authentication',r'/(?:login|signin|wp-login)(?:\.php|/|\?|$)'),
 ('API and tool endpoint discovery','Reconnaissance','API',r'/(?:mcp|api|v2/_catalog)(?:/|\?|$)'),
 ('Crawler discovery files','Reconnaissance','Site structure',r'/(?:robots\.txt|sitemap\.xml)(?:\?|$)'),
 ('Source map discovery','Reconnaissance','Source code',r'\.js\.map(?:\?|$)'),
]
COMPILED=[(*r[:3],re.compile(r[3],re.I)) for r in PATH_RULES]
def group(name):
 if name.startswith('Capture diagnostic:'):return 'Capture diagnostics'
 if name=='PHP syntax observed':return 'Syntax observations'
 if name.startswith('Portal navigation'):return 'Navigation'
 if name.startswith('Gateway rejected'):return 'Rejected requests'
 if name.startswith(('Network ','Suricata ')):return 'Network activity'
 if name.startswith(('REDIS ','MYSQL ','TELNET ','Redis ')):return 'Service probes'
 if name.startswith('SSH '):
  if any(s in name for s in ('authentication','login')):return 'Authentication'
  if any(s in name for s in ('command','download','upload')):return 'Shell activity'
  if 'forwarding' in name:return 'Forwarding'
  return 'Connection activity'
 if any(s in name.lower() for s in ('breadcrumb','canary','simulated tool')):return 'Decoy engagement'
 if any(s in name.lower() for s in ('reconnaissance','discovery')):return 'Reconnaissance'
 return 'Attack indicators'
def classify(event):
 a=event.get('analysis',{});findings=[];seen=set()
 signal_kind='observation'
 if event.get('service')=='network':
  signature=str((event.get('network') or {}).get('signature',''))
  signal_kind='capture_diagnostic' if re.fullmatch(r'SURICATA (?:TCP|UDP|IP)v[46] invalid checksum',signature) else 'reputation' if signature.startswith('ET DROP ') else 'detection' if (event.get('network') or {}).get('type')=='alert' else 'observation'
 # Reassess retained legacy PHP tag matches without claiming the tag executes.
 hits=[]
 for original in a.get('hits',[]):
  hit=dict(original)
  if hit['rule']=='PHP execution markers' and hit.get('match','').lower()=='<?php':hit.update(rule='PHP syntax observed',severity='info')
  hits.append(hit)
 if any(h['rule']=='PHP syntax observed' for h in hits):
  match=re.search(r'(?:shell_exec|passthru|base64_decode|system|eval)\s*\(|auto_prepend_file|php://(?:input|filter)',a.get('payload_preview',''),re.I)
  if match:hits.append({'rule':'PHP execution markers','severity':'high','match':match.group(0),'layer':'retained body preview'})
 a=dict(a,hits=hits)
 if event.get('service') in ('redis','mysql','telnet') and isinstance(event.get('protocol'),dict):
  from service_signals import enrich
  a=dict(a);a['hits']=[h for h in a.get('hits',[]) if not h['rule'].startswith(('REDIS ','Redis ','MYSQL ','TELNET '))]
  proto=event['protocol'];a=enrich({'service':event['service'],'protocol_commands':proto.get('commands',[]),'protocol_login_attempts':proto.get('login_attempts',0)},a)
 for hit in a.get('hits',[]):
  name=hit['rule']
  if signal_kind=='capture_diagnostic':hit=dict(hit,rule='Capture diagnostic: packet checksum warning',severity='info');name=hit['rule']
  if name in seen:continue
  seen.add(name);g='Reputation matches' if signal_kind=='reputation' else group(name)
  findings.append({'name':name,'group':g,'target':event['service'].upper() if event.get('service') in ('redis','mysql','telnet','network') else 'SSH' if event.get('service')=='cowrie' else 'PHP' if 'PHP' in name else 'Authentication' if 'login' in name.lower() or 'authentication' in name.lower() else 'General','severity':hit.get('severity','info'),'confidence':'medium' if g=='Attack indicators' else 'high','field':hit.get('layer','legacy combined fields'),'evidence':hit.get('match','')[:180],'reason':'Observed in the simulated SSH service; commands do not establish host compromise.' if event.get('service')=='cowrie' else 'Captured indicator; successful exploitation is not established.' if g=='Attack indicators' else 'Observed interaction or requested resource; intent is unverified.'})
 path=str(event.get('path',''))[:8192]
 proxy=event.get('proxy') or {}
 if event.get('service')=='nginx-edge' and isinstance(proxy.get('raw_path'),str):path=proxy['raw_path'][:8192]
 if event.get('service')=='cowrie' and event.get('method')=='cowrie.command.input':
  for name,severity,pattern in SSH_COMMAND_RULES:
   match=re.search(pattern,path,re.I)
   if match and name not in seen:
    seen.add(name)
    findings.append({'name':name,'group':'Shell activity','target':'SSH','severity':severity,'confidence':'high','field':'captured SSH command','evidence':match.group(0)[:180],'reason':'Command text submitted to a simulated shell. The label describes syntax; host execution or persistence is not established.'})
 for _ in range(2):path=unquote(path)
 for name,g,target,pattern in ([] if event.get('service') in ('cowrie','redis','mysql','telnet','network') else COMPILED):
  m=pattern.search(path)
  if m:findings.append({'name':name,'group':g,'target':target,'severity':'medium' if target=='Secrets' else 'low','confidence':'high','field':'request path','evidence':m.group(0)[:180],'reason':'The requested path identifies this resource category; it does not establish access or exploitation.'})
 try:proxy_status=int(proxy.get('status') or 0)
 except (ValueError,TypeError,OverflowError):proxy_status=0
 if event.get('service')=='nginx-edge' and proxy_status>=400:
  findings.append({'name':'Gateway rejected oversized request' if proxy.get('status')==413 else 'Gateway rejected request','group':'Rejected requests','target':'Gateway','severity':'info','confidence':'high','field':'gateway response','evidence':str(proxy.get('status')),'reason':'The edge rejected this request; successful access is not established.'})
 if not findings and event.get('method') in ('GET','HEAD') and path.split('?',1)[0] in ('/','/help.php','/documents.php','/search.php'):
  findings.append({'name':'Portal navigation observed','group':'Navigation','target':'Portal','severity':'info','confidence':'high','field':'request path','evidence':path[:180],'reason':'Navigation to a decoy page; intent is unverified.'})
 if signal_kind=='capture_diagnostic':
  for f in findings:f['reason']='Packet checksum diagnostic; host capture offload or packet damage is possible. This is not an attack determination.'
 # Body evidence can support a stronger confidence than an endpoint name alone.
 body=a.get('payload_preview','')
 for f in findings:
  if f['group']=='Attack indicators' and f['evidence'] and f['evidence'].lower() in body.lower():
   f['field']='captured body preview';f['confidence']='high'
 targets=sorted(set(f['target'] for f in findings))
 if (a.get('php_research') or {}).get('php_surface') and 'PHP' not in targets:targets.append('PHP')
 rank={'info':0,'low':1,'medium':2,'high':3}
 severity=max((f['severity'] for f in findings),key=lambda x:rank[x],default='info')
 return {'severity':severity,'version':VERSION,'signal_kind':signal_kind,'findings':findings,'groups':sorted(set(f['group'] for f in findings)) or ['Unclassified'],'targets':targets,'coverage':'Retained path, original rule matches and captured preview; missing/redacted bodies are not reconstructed.','exploitation_confirmed':False}

def catalog():
 from analysis import RULES
 names={r[0]:group(r[0]) for r in RULES}
 names.update({r[0]:r[1] for r in PATH_RULES})
 for label in ('REDIS service probe','MYSQL service probe','TELNET service probe','REDIS authentication attempt','MYSQL authentication attempt','TELNET authentication attempt','Redis configuration or execution probe','Redis configuration discovery','Redis snapshot command probe','Redis destructive command probe','Network flow observed','Network TLS handshake observed'):
  names[label]=group(label)
 from cowrie_adapter import RULES as SSH_RULES
 names.update({rule[0]:group(rule[0]) for rule in SSH_RULES.values()})
 names['SSH download command observed']='Shell activity'
 names['SSH protocol observation']='Connection activity'
 names.update({r[0]:'Shell activity' for r in SSH_COMMAND_RULES})
 names.update({'Portal navigation observed':'Navigation','PHP syntax observed':'Syntax observations','Capture diagnostic: packet checksum warning':'Capture diagnostics','Gateway rejected request':'Rejected requests','Gateway rejected oversized request':'Rejected requests'})
 for n in ['Upload endpoint discovery','Executable upload filename','Unusual HTTP method','Canary endpoint requested','Decoy authentication attempt','XML-RPC pingback probe','Registry modification attempt','MCP simulated tool invocation','Signed discovery breadcrumb followed','FTP decoy login attempt','PHP multipart structural anomaly']:names[n]=group(n)
 return [{'name':n,'group':g} for n,g in sorted(names.items())]
