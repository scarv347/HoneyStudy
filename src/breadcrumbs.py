"""Signed inert discovery links. They grant no access and create no server-side sessions."""
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import time
from urllib.parse import urlsplit,parse_qs

TARGETS={'backup':'/backup/','snapshot':'/backup/customer-portal-20261020.sql','export':'/internal/export.php'}
TARGETS.update({'workflow-status':'/status.php','workflow-result':'/result.php','workflow-legacy-status':'/legacy/status.php','workflow-legacy-result':'/legacy/result.php'})
TARGETS.update({'workflow-upload':'/upload.php','workflow-import':'/import.php','workflow-legacy-upload':'/legacy/upload.php','workflow-legacy-import':'/legacy/import.php'})
TARGETS.update({'workflow-api-documents':'/api/documents.php','workflow-api-import':'/api/import.php','workflow-api-status':'/api/jobs.php','workflow-api-result':'/api/result.php'})
ISSUERS={'/docs/':'backup','/backup/':'snapshot','/backup/customer-portal-20261020.sql':'export'}
_key=None
if os.environ.get('CREDENTIALS_DIRECTORY'):
    path=Path(os.environ['CREDENTIALS_DIRECTORY'])/'breadcrumb.key'
    if path.exists():
        _key=path.read_bytes()
        if len(_key)!=32:raise RuntimeError('Invalid breadcrumb signing-key length')

def issue(parent,purpose,key,now=None):
    if purpose not in TARGETS or not re.fullmatch('[0-9a-f]{32}',parent):raise ValueError('Invalid configured breadcrumb')
    stamp=int(time.time() if now is None else now)
    identifier=secrets.token_hex(16)
    message=f'v1.{stamp:x}.{identifier}.{parent}.{purpose}'
    signature=hmac.new(key,message.encode(),hashlib.sha256).hexdigest()[:32]
    return message+'.'+signature,identifier

def verify(token,path,key,now=None):
    invalid={'status':'invalid'}
    if len(token)>300:return invalid
    parts=token.split('.')
    if len(parts)!=6:return invalid
    version,stamp,identifier,parent,purpose,signature=parts
    if version!='v1' or purpose not in TARGETS or TARGETS[purpose]!=path:return invalid
    if not all(re.fullmatch('[0-9a-f]{32}',v) for v in (identifier,parent,signature)):return invalid
    if not re.fullmatch('[0-9a-f]{1,12}',stamp):return invalid
    expected=hmac.new(key,'.'.join(parts[:-1]).encode(),hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(signature,expected):return invalid
    age=int(time.time() if now is None else now)-int(stamp,16)
    if age < -60 or age>86400:return {'status':'expired'}
    return {'status':'valid','id':identifier,'parent_request_id':parent,'purpose':purpose,'age_seconds':age}

def decorate(response,target,parent,key=None,now=None):
    key=_key if key is None else key
    if key is None:return response
    try:
        parsed=urlsplit(target);query=parse_qs(parsed.query,max_num_fields=64)
    except ValueError:return response
    details=dict(getattr(response,'details',{}))
    refs=query.get('ref',[])
    if refs:details['breadcrumb_follow']=verify(refs[0],parsed.path,key,now) if len(refs)==1 else {'status':'invalid'}
    purpose=ISSUERS.get(parsed.path)
    if response.scenario=='php-workflow-form':
        purpose=next(name for name,destination in TARGETS.items() if name.startswith('workflow-') and destination==parsed.path)
    if response.scenario=='php-workflow-submission':
        purpose='workflow-legacy-status' if parsed.path.startswith('/legacy/') else 'workflow-status'
    elif response.scenario=='php-workflow-status':
        purpose='workflow-legacy-result' if parsed.path.startswith('/legacy/') else 'workflow-result'
    if response.scenario=='php-api-form':
        purpose='workflow-api-documents' if parsed.path=='/api/documents.php' else 'workflow-api-import'
    elif response.scenario=='php-api-submission':purpose='workflow-api-status'
    elif response.scenario=='php-api-status':purpose='workflow-api-result'
    if purpose and response.status in (200,202):
        token,identifier=issue(parent,purpose,key,now)
        destination=TARGETS[purpose]
        response.content=response.content.replace(destination.encode(),(destination+'?ref='+token).encode())
        details['breadcrumb_issued']={'id':identifier,'purpose':purpose,'target':destination,'parent_request_id':parent}
    response.details=details
    return response
