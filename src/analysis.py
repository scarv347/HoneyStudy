"""Offline, bounded analysis. Never execute, resolve, fetch, or unpack payloads."""
import base64
import hashlib
import ipaddress
import re
from urllib.parse import unquote

VERSION = 'rx1-2026.10.25.9'
MAX_PAYLOAD = 16384
RULES = [
 ('PHP-CGI argument injection probe', 'high', r'(?:%ad|\u00ad|-)[dD].{0,100}(?:allow_url_include|auto_prepend_file)'),
 ('PowerShell execution markers', 'high', r'\b(?:invoke-expression|downloadstring|frombase64string)\b|\biex\s*[\(\s]'),
 ('PHP syntax observed', 'info', r'<\?php'),
 ('PHP execution markers', 'high', r'(?:shell_exec|passthru|base64_decode|system|eval)\s*\(|auto_prepend_file|php://(?:input|filter)'),
 ('Traversal / local file probe', 'high', r'\.\.[/\\]|/etc/(?:passwd|shadow)|win\.ini'),
 ('Shell command injection markers', 'high', r'(?:;|\||`|\$\().{0,40}\b(?:curl|wget|bash|sh|whoami|id)\b|/bin/(?:ba)?sh'),
 ('SQL injection markers', 'medium', r'union\s+(?:all\s+)?select|\bor\s+[\x27\x22]?1[\x27\x22]?\s*=\s*[\x27\x22]?1|sleep\s*\('),
 ('JNDI lookup probe', 'high', r'\$\{jndi:|\$\{.{0,80}ldap:'),
 ('Script injection markers', 'medium', r'<script\b|onerror\s*=|javascript:'),
 ('Sensitive configuration reconnaissance', 'medium', r'/\.(?:env|git|vscode|ds_store)|/actuator|/config\.(?:json|js)|/(?:agents|claude)\.md|/server-status|/console|/v2/_catalog|/cgi-bin|/login.action|/download/resources/|/telescope/|/@vite/env|/api/config|/js/env.js|/debug/default/view|/trace.axd|/ecp/current/|/___proxy_subdomain_|/meta-inf/'),
 ('CMS / PHP reconnaissance', 'low', r'/wp-|/xmlrpc\.php|/phpmyadmin|/(?:phpinfo|info)\.php'),
 ('Upload attempt', 'medium', r'/upload\.php|multipart/form-data|php_session_upload_progress'),
]
COMPILED = [(name, severity, re.compile(pattern, re.I)) for name, severity, pattern in RULES]
RANK = {'info': 0, 'low': 1, 'medium': 2, 'high': 3}

def analyze(event):
    encoded = str(event.get('payload_base64', ''))
    error = None
    try:
        if len(encoded) > 4 * ((MAX_PAYLOAD + 2) // 3):
            raise ValueError('payload exceeds analysis limit')
        payload = base64.b64decode(encoded, validate=True)
        if len(payload) > MAX_PAYLOAD:
            raise ValueError('payload exceeds analysis limit')
    except (ValueError, TypeError) as exc:
        payload, error = b'', str(exc)
    raw_path = str(event.get('path', ''))[:8192]
    headers = event.get('headers', {})
    if not isinstance(headers, dict):
        headers = {}
    content = raw_path + '\n' + payload.decode('utf-8', 'replace')
    content += '\n' + '\n'.join(str(k)[:100] + ':' + str(v)[:1000] for k, v in list(headers.items())[:64])
    normalized = content
    for _ in range(2):
        normalized = unquote(normalized, encoding='latin-1')
    content = (content + '\n' + normalized).lower()
    from payload_profile import profile
    payload_profile = profile(payload, headers)
    hits = [{'rule': n, 'severity': s, 'match': m.group(0)[:120]} for n, s, p in COMPILED if (m := p.search(content))]
    for layer in payload_profile['decoded_layers']:
        text=layer['preview'].lower()
        for name,severity,pattern in COMPILED:
            if match := pattern.search(text):
                hits.append({'rule':name,'severity':severity,'match':match.group(0)[:120],'layer':'base64-decoded'})
    # Browsing a form and following an issued URL are engagement, not attack evidence.
    if str(event.get('method','')).upper() in ('GET','HEAD') and not payload:
        for hit in hits:
            if hit['rule']=='Upload attempt':
                hit['rule']='Upload endpoint discovery';hit['severity']='info'
    if any(item['executable_extension'] for item in payload_profile['uploads']):
        hits.append({'rule':'Executable upload filename','severity':'medium','match':'Executable extension in a captured multipart filename'})
    if str(event.get('method', '')).upper() in ('PUT', 'PATCH', 'DELETE'):
        hits.append({'rule': 'Unusual HTTP method', 'severity': 'low', 'match': str(event.get('method'))})
    if event.get('simulation_version') in ('rx1-sim-2','rx1-sim-3','rx1-sim-4','rx1-sim-5','rx1-sim-6','rx1-sim-7','rx1-sim-8','rx1-sim-9','rx1-sim-10','rx1-sim-11'):
        if event.get('canary'):
            hits.append({'rule': 'Canary endpoint requested', 'severity': 'medium', 'match': str(event['canary'])[:100]})
        if event.get('scenario') in ('login-attempt', 'cms-login-attempt'):
            hits.append({'rule': 'Decoy authentication attempt', 'severity': 'low', 'match': str(event['scenario'])})
        if event.get('xmlrpc_method') == 'pingback.ping':
            hits.append({'rule': 'XML-RPC pingback probe', 'severity': 'medium', 'match': 'pingback.ping'})
        if event.get('scenario') == 'registry-write-attempt':
            hits.append({'rule': 'Registry modification attempt', 'severity': 'medium', 'match': str(event.get('method', ''))})
    if event.get('rpc_method') == 'tools/call':
        hits.append({'rule':'MCP simulated tool invocation','severity':'medium','match':str(event.get('rpc_tool',''))[:100]})
    if (event.get('breadcrumb_follow') or {}).get('status')=='valid':
        hits.append({'rule':'Signed discovery breadcrumb followed','severity':'info','match':str(event['breadcrumb_follow'].get('purpose',''))})
    if event.get('scenario')=='ftp-login-attempt':
        hits.append({'rule':'FTP decoy login attempt','severity':'low','match':'Authentication always denied; credentials redacted'})
    from php_watch import profile as php_profile
    php_research=php_profile(event,payload)
    if php_research['structural_anomaly']:
        hits.append({'rule':'PHP multipart structural anomaly','severity':'medium','match':'Bounded multipart counts; CVE attribution unconfirmed'})
    hits.sort(key=lambda h: RANK[h['severity']], reverse=True)
    # Indicators are inert strings. No network enrichment or automatic navigation.
    urls = sorted(set(re.findall(r'https?://[^\s<>\x00-\x20\x22\x27]{1,512}', content)))[:32]
    return {'rules_version': VERSION, 'hits': hits, 'severity': hits[0]['severity'] if hits else 'info',
            'payload_bytes': len(payload), 'payload_sha256': hashlib.sha256(payload).hexdigest() if payload else None,
            'payload_error': error, 'php_research': php_research, 'payload_profile': payload_profile, 'payload_preview': payload.decode('utf-8', 'replace')[:2048],
            'urls': urls, 'truncated': bool(event.get('body_truncated')), 'normalization': 'two URL decode passes; no evaluation'}

def ip_info(value):
    try:
        ip = ipaddress.ip_address(value)
        scope = 'global' if ip.is_global else ('loopback' if ip.is_loopback else 'private/reserved')
        return {'valid': True, 'scope': scope, 'version': ip.version,
                'network': str(ipaddress.ip_network(f'{ip}/{24 if ip.version == 4 else 48}', strict=False))}
    except ValueError:
        return {'valid': False, 'scope': 'invalid', 'network': '', 'version': None}
