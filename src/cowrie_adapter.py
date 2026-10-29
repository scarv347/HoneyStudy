"""Translate observed Cowrie records without running captured commands or URLs."""
import hashlib,ipaddress,json,re
from datetime import datetime,timezone
from analysis import ip_info

RULES={
 'cowrie.session.connect':('SSH connection observed','info'),
 'cowrie.login.failed':('SSH authentication attempt','low'),
 'cowrie.login.success':('SSH simulated login accepted','medium'),
 'cowrie.command.input':('SSH command observed','medium'),
 'cowrie.session.file_download':('SSH simulated file download','high'),
 'cowrie.session.file_upload':('SSH file upload observed','high'),
 'cowrie.direct-tcpip.request':('SSH forwarding request','medium'),
}

def adapt(line,sessions):
    raw=json.loads(line)
    if not isinstance(raw,dict):raise ValueError('Invalid Cowrie record')
    session=str(raw.get('session',''))[:128]
    if raw.get('src_ip'):sessions[session]=str(ipaddress.ip_address(raw['src_ip']))
    ip=raw.get('src_ip') or sessions.get(session)
    if not ip:return None
    ipaddress.ip_address(ip)
    stamp=datetime.fromisoformat(raw['timestamp'].replace('Z','+00:00')).astimezone(timezone.utc).isoformat()
    eventid=str(raw.get('eventid',''))[:100]
    name,severity=RULES.get(eventid,('SSH protocol observation','info'))
    command=str(raw.get('input',''))[:8192]
    if eventid=='cowrie.command.input' and re.search(r'\b(?:wget|curl|tftp|ftpget)\b|/dev/tcp/',command,re.I):
        name,severity='SSH download command observed','high'
    path=command or eventid
    # Never put submitted passwords or SSH key bodies into the searchable dashboard.
    evidence={k:raw[k] for k in ('eventid','session','username','input','url','shasum','filename','duration','duration_ms','version','fingerprint') if k in raw}
    if 'password' in raw:evidence['password_redacted']=True
    return {'id':'cowrie:'+hashlib.sha256(line.encode()).hexdigest(),'time':stamp,'ip':ip,'path':path,'method':eventid,'service':'cowrie',
      'intelligence':ip_info(ip),'analysis':{'rules_version':'cowrie-observed-1','severity':severity,'hits':[{'rule':name,'severity':severity,'match':command[:180] or eventid,'layer':'Cowrie event'}],
        'payload_bytes':0,'payload_sha256':None,'payload_preview':'','urls':[],'exploitation_confirmed':False},
      'simulation':{'scenario':eventid,'credentials_redacted':True},'ssh':evidence,'self_test':ip_info(ip)['scope']=='loopback','user_agent_claim':''}
