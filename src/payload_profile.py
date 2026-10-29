"""Bounded static file/encoding metadata. No execution, decompression or file writes."""
import base64
import hashlib
import re

LIMIT=16384

def file_kind(data):
    for magic,label in ((b'\x7fELF','ELF executable'),(b'MZ','DOS/PE candidate'),(b'PK\x03\x04','ZIP archive'),(b'\x1f\x8b','gzip stream'),(b'%PDF-','PDF document')):
        if data.startswith(magic):return label
    if b'<?php' in data[:1024].lower():return 'PHP source candidate'
    return 'text or unknown binary'

def profile(payload,headers):
    payload=payload[:LIMIT]
    result={'kind':file_kind(payload),'uploads':[],'decoded_layers':[],'limits':{'captured_bytes':LIMIT,'files':8,'base64_layers':4,'recursive_decode':False,'decompression':False}}
    content_type=next((str(v) for k,v in headers.items() if str(k).lower()=='content-type'),'')
    boundary=re.search(r'boundary=(?:"([^"\r\n]{1,70})"|([^;\s]{1,70}))',content_type,re.I)
    if 'multipart/form-data' in content_type.lower() and boundary:
        token=(boundary[1] or boundary[2]).encode('ascii','ignore')
        if token and b'\r' not in token and b'\n' not in token:
            for part in payload.split(b'--'+token,17)[1:17]:
                head,sep,data=part.partition(b'\r\n\r\n')
                if not sep or len(head)>2048:continue
                match=re.search(br'filename="([^"\r\n]{0,256})"',head,re.I)
                if not match:continue
                name=match[1].decode('utf-8','replace').replace('\\','/').rsplit('/',1)[-1]
                name=''.join(c for c in name if c.isprintable())[:100]
                if data.endswith(b'\r\n'):data=data[:-2]
                result['uploads'].append({'filename':name,'captured_bytes':len(data),'captured_sha256':hashlib.sha256(data).hexdigest(),'kind':file_kind(data),'executable_extension':bool(re.search(r'\.(?:php\d*|phtml|phar|jsp|aspx?|exe|dll|sh|ps1)$',name,re.I))})
                if len(result['uploads'])>=8:break
    patterns=[(re.compile(br'base64_decode\s*\(\s*[\x22\x27]([A-Za-z0-9+/=]{16,8192})[\x22\x27]',re.I),'utf-8','PHP base64_decode literal'),
              (re.compile(br'-(?:enc|encodedcommand)\s+([A-Za-z0-9+/=]{16,8192})(?![A-Za-z0-9+/=])',re.I),'utf-16-le','PowerShell encoded command')]
    for pattern,encoding,source in patterns:
        for match in pattern.finditer(payload):
            if len(result['decoded_layers'])>=4:break
            try:decoded=base64.b64decode(match[1],validate=True)
            except ValueError:continue
            if len(decoded)>LIMIT:continue
            text=decoded.decode(encoding,'replace')
            result['decoded_layers'].append({'source':source,'bytes':len(decoded),'sha256':hashlib.sha256(decoded).hexdigest(),'preview':text[:1024],'kind':file_kind(decoded)})
    return result
