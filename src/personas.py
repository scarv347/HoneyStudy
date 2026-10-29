"""Allowlisted, static decoy responses. No filesystem reads, writes or networking."""
from dataclasses import dataclass, field
import hashlib
import json
import re
from urllib.parse import urlsplit
from portal_legacy import PAGES

VERSION = 'rx1-sim-11'
CANARIES = {
    '/.env': 'configuration-discovery',
    '/.git/config': 'repository-discovery',
    '/backup/customer-portal-20261020.sql': 'backup-followup',
    '/internal/export.php': 'internal-api-followup',
    '/api/v1/diagnostics': 'diagnostic-followup',
}

@dataclass
class Response:
    status: int
    content: bytes
    mime: str = 'text/html; charset=utf-8'
    scenario: str = 'unknown-route'
    headers: dict = field(default_factory=dict)
    canary: str = ''

def html(body, title='Customer Portal'):
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><title>'+title+'</title><body>'+body+'</body></html>').encode()

def data(value, status=200, scenario='api-discovery', headers=None):
    return Response(status, json.dumps(value).encode(), 'application/json', scenario, headers or {})

def portal(path, method, body):
    from portal_content import respond as content_response
    page=content_response(path,method)
    if page is not None:return page
    from webdav_fixture import respond as dav_response
    dav=dav_response(path,method)
    if dav is not None:return dav
    from php_apps import respond as apps_response
    app=apps_response(path,method,body)
    if app is not None:return app
    from php_recon import respond as recon_response
    recon=recon_response(path,method)
    if recon is not None:return recon
    from workflows import response as workflow_response
    workflow=workflow_response(path,method,body)
    if workflow is not None:return workflow
    from discovery import ownership
    proof=ownership(path)
    if proof is not None:
        return Response(200,proof,'text/plain; charset=utf-8','search-ownership-verification')
    if path == '/php/':
        return Response(200,html('<h1>Customer Portal PHP services</h1><a href="/integration.php">PHP document API</a> | <a href="/documents.php">Document workspace</a> | <a href="/login.php">Sign in</a><p>Document management and integration services.</p><ul><li><a href="/upload.php">PHP document upload</a></li><li><a href="/import.php">PHP data import</a></li><li><a href="/info.php">PHP 8.2 runtime diagnostics</a></li><li><a href="/legacy/">Legacy PHP 8.5 integration</a></li></ul>','PHP application services | Customer Portal'),scenario='php-services-discovery')
    if path in ('/legacy/','/legacy/index.php'):
        return Response(200,html('<h1>Legacy integration portal</h1><a href="/legacy/documents.php">Document workspace</a><p>PHP 8.5 document processing.</p><a href="/legacy/upload.php">Upload document</a> | <a href="/legacy/import.php">Import records</a> | <a href="/legacy/phpinfo.php">Runtime diagnostics</a>','Legacy PHP Integration'),scenario='php85-home',headers={'X-Powered-By':'PHP/8.5.11'})
    if path == '/legacy/phpinfo.php':
        return Response(200,html('<h1>PHP Version 8.5.11</h1><table><tr><td>Server API</td><td>Apache 2.0 Handler</td></tr><tr><td>memory_limit</td><td>128M</td></tr><tr><td>session.upload_progress.enabled</td><td>On</td></tr><tr><td>fatal_error_backtraces</td><td>On</td></tr></table>','phpinfo()'),scenario='php85-runtime-discovery',headers={'X-Powered-By':'PHP/8.5.11'})
    if path in ('/legacy/upload.php','/legacy/import.php'):
        if method in ('GET','HEAD'):
            page=html('<h1>Legacy document processing</h1><form method="POST" enctype="multipart/form-data" action="'+path+'"><input name="PHP_SESSION_UPLOAD_PROGRESS" value="document" type="hidden"><input type="file" name="document"><button>Submit document</button></form>')
            return Response(200,page,scenario='php85-upload-discovery',headers={'X-Powered-By':'PHP/8.5.11'})
        return data({'status':'pending_review','document_id':hashlib.sha256(body).hexdigest()[:20]},202,'php85-upload-attempt',{'X-Powered-By':'PHP/8.5.11'})
    if path == '/legacy/upload-progress.php':
        return data({'status':'idle','progress':0},scenario='php85-progress-discovery',headers={'X-Powered-By':'PHP/8.5.11'})
    # Fixed fixtures only. PHP/FastCGI is never installed or invoked.
    if path in ('/info.php','/php-info.php','/test.php','/phpinfo','/pinfo'):
        return Response(200,PAGES['/phpinfo.php'],scenario='php-runtime-discovery')
    if path in ('/cgi-bin/php','/cgi-bin/php-cgi','/cgi-bin/php-cgi.exe','/php-cgi/php-cgi.exe'):
        return Response(500,b'PHP Warning: request initialization failed\n','text/plain','php-cgi-probe')
    if path in ('/fileupload.php','/upload/index.php','/import.php','/api/upload.php'):
        if method in ('GET','HEAD'):
            return Response(200,PAGES['/upload.php'].replace(b'<form ',b'<form action="'+path.encode()+b'" '),scenario='php-upload-discovery')
        ticket=hashlib.sha256(body).hexdigest()[:20]
        return data({'status':'pending_review','document_id':ticket},202,'php-upload-attempt')
    if path == '/upload-progress.php':
        return data({'status':'idle','progress':0},scenario='php-progress-discovery')
    if path == '/php.ini.bak':
        return Response(200,b'; Portal runtime settings snapshot\nmemory_limit=128M\npost_max_size=8M\nupload_max_filesize=2M\nsession.upload_progress.enabled=1\n','text/plain','php-config-discovery')
    if path == '/robots.txt':
        return Response(200,b'User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /internal/\nSitemap: https://honeystudy.example.invalid/sitemap.xml\n','text/plain','discovery')
    if path == '/sitemap.xml':
        return Response(200,b'<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://honeystudy.example.invalid/</loc></url><url><loc>https://honeystudy.example.invalid/help.php</loc></url><url><loc>https://honeystudy.example.invalid/search.php</loc></url><url><loc>https://honeystudy.example.invalid/release-notes.php</loc></url><url><loc>https://honeystudy.example.invalid/integration.php</loc></url><url><loc>https://honeystudy.example.invalid/documents.php</loc></url><url><loc>https://honeystudy.example.invalid/legacy/documents.php</loc></url><url><loc>https://honeystudy.example.invalid/php/</loc></url><url><loc>https://honeystudy.example.invalid/legacy/</loc></url><url><loc>https://honeystudy.example.invalid/legacy/phpinfo.php</loc></url><url><loc>https://honeystudy.example.invalid/legacy/upload.php</loc></url><url><loc>https://honeystudy.example.invalid/legacy/import.php</loc></url><url><loc>https://honeystudy.example.invalid/docs/</loc></url><url><loc>https://honeystudy.example.invalid/blog/</loc></url><url><loc>https://honeystudy.example.invalid/upload.php</loc></url><url><loc>https://honeystudy.example.invalid/import.php</loc></url><url><loc>https://honeystudy.example.invalid/info.php</loc></url></urlset>','application/xml','discovery')
    if path in ('/', '/index.php'):
        extra=b'<section><h2>Document services</h2><p>Submit documents, import records and check review status.</p><a href="/documents.php">Document workspace</a> | <a href="/help.php">Submission help</a> | <a href="/search.php">Find resources</a></section><footer><a href="/php/">PHP application services</a> | <a href="/legacy/">Legacy integration</a> | <a href="/blog/">Company news</a> | <a href="/docs/">API documentation</a></footer><script src="/assets/portal.js"></script>'
        return Response(200,PAGES[path].replace(b'</body>',extra+b'</body>'),scenario='portal-home')
    if path == '/docs/':
        return Response(200,html('<h1>Portal developer resources</h1><p><a href="/help.php">Import guide and sample template</a> | <a href="/release-notes.php">Release notes</a></p><p><a href="/webdav/">Read-only document collection</a></p><p><a href="/integration.php">Document API integration guide</a></p><p>Document API: POST a multipart document to /upload.php or /legacy/upload.php. Follow status_url in the receipt, then result_url for the review outcome. <a href="/documents.php">Document workspace</a></p><p><a href="/php/">PHP services</a> | <a href="/legacy/">Legacy PHP integration</a></p><p>API version 1.4.2</p><ul><li><a href="/upload.php">Document upload</a></li><li><a href="/import.php">Data import</a></li><li><a href="/info.php">Runtime diagnostics</a></li><li><a href="/upload-progress.php">Upload status</a></li><li><a href="/api/openapi.json">OpenAPI schema</a></li><li><a href="/api/v1/status">Service status</a></li><li><a href="/backup/">Database snapshots</a></li><li><a href="/v2/">Container registry</a></li><li><a href="/swagger.json">Integration API schema</a></li></ul>'),scenario='api-discovery')
    if path == '/assets/portal.js':
        return Response(200,b'"use strict";\nconst portalApi="/api/v1";\nconst diagnosticEndpoint="/api/v1/diagnostics";\nconst exportEndpoint="/internal/export.php";\n','application/javascript','client-config-discovery')
    if path == '/api/openapi.json':
        return data({'openapi':'3.0.3','info':{'title':'Customer Portal API','version':'1.4.2'},'paths':{'/api/v1/status':{'get':{'responses':{'200':{'description':'Service status'}}}},'/internal/export.php':{'get':{'responses':{'403':{'description':'Operator access required'}}}},'/api/v1/diagnostics':{'post':{'responses':{'403':{'description':'Operator access required'}}}}}},scenario='api-schema-discovery')
    if path in ('/api/v1/status','/actuator/health'):
        return data({'status':'UP','service':'customer-portal','build':'2026.10.20'},scenario='service-discovery')
    if path in ('/api/v1/diagnostics','/internal/export.php'):
        return data({'error':'operator_access_required','code':'access_denied'},403,'restricted-decoy')
    if path == '/.git/HEAD':
        return Response(200,b'ref: refs/heads/main\n','text/plain','repository-discovery')
    if path == '/.git/config':
        return Response(200,b'[core]\n repositoryformatversion = 0\n bare = false\n[remote "origin"]\n url = https://git.portal.invalid/customer/portal.git\n fetch = +refs/heads/*:refs/remotes/origin/*\n','text/plain','repository-discovery')
    if path == '/.env':
        return Response(200,b'APP_NAME=CustomerPortal\nAPP_ENV=production\nAPP_DEBUG=false\nAPP_URL=https://portal.invalid\nDB_HOST=db.portal.invalid\nDB_DATABASE=customer_portal\nDB_USERNAME=portal_app\nDB_PASSWORD=m6R4nV9qK2s7tP3x\n','text/plain','configuration-discovery')
    if path == '/backup/':
        return Response(200,html('<h1>Index of /backup/</h1><a href="/backup/customer-portal-20261020.sql">customer-portal-20261020.sql</a> 20-Oct-2026 02:10 326'),scenario='backup-discovery')
    if path == '/backup/customer-portal-20261020.sql':
        return Response(200,b'-- Customer Portal schema snapshot\nCREATE TABLE app_settings (setting_key varchar(64), setting_value varchar(255));\nINSERT INTO app_settings VALUES (\'export_endpoint\',\'/internal/export.php\');\nINSERT INTO app_settings VALUES (\'support_email\',\'support@portal.invalid\');\n','text/plain','backup-followup')
    if path in ('/login.php','/account.php','/admin/') and method not in ('GET','HEAD','OPTIONS'):
        return Response(403,html('<h2>Sign in failed</h2><p>Unable to verify account.</p><a href="/login.php">Try again</a>'),scenario='login-attempt')
    if path == '/upload.php' and method not in ('GET','HEAD','OPTIONS'):
        ticket=hashlib.sha256(body).hexdigest()[:20]
        return data({'status':'pending_review','document_id':ticket,'message':'Document pending security review.'},202,'upload-attempt')
    if path in PAGES:
        return Response(200,PAGES[path],'text/plain' if path=='/robots.txt' else 'text/html; charset=utf-8','portal-page')
    return Response(404,html('<h1>Not Found</h1>'),scenario='unmatched-probe')

def cms(path, method, body):
    login=html('<h1>Customer Portal News</h1><h2>Log In</h2><form method="post" action="/wp-login.php"><label>Username <input name="log" autocomplete="off"></label><label>Password <input type="password" name="pwd" autocomplete="off"></label><button>Log In</button></form>','Log In ‹ Customer Portal News')
    if path in ('/wp-login.php','/wp-admin','/wp-admin/'):
        if method in ('GET','HEAD'):
            return Response(200,login,scenario='cms-login-discovery')
        return Response(403,html('<h1>Authentication failed</h1><p>The supplied credentials could not be verified.</p>'),scenario='cms-login-attempt')
    if path in ('/', '/blog/'):
        return Response(200,html('<h1>Customer Portal News</h1><article><h2>Scheduled document maintenance</h2><p>The document service will be unavailable during the weekend maintenance window.</p></article><a href="/wp-login.php">Log in</a> | <a href="/wp-json/">API</a> | <a href="/xmlrpc.php?rsd">Publishing</a>','Customer Portal News'),scenario='cms-home')
    if path in ('/wp-json','/wp-json/'):
        return data({'name':'Customer Portal News','description':'Service updates','namespaces':['wp/v2'],'routes':{'/wp/v2/posts':{'methods':['GET']},'/wp/v2/users':{'methods':['GET']}}},scenario='cms-api-discovery')
    if path == '/wp-json/wp/v2/posts' and method in ('GET','HEAD'):
        return data([{'id':1,'slug':'scheduled-maintenance','title':{'rendered':'Scheduled maintenance'},'content':{'rendered':'Document service maintenance is scheduled this weekend.'},'status':'publish'}],scenario='cms-posts-discovery')
    if path.startswith('/wp-json/'):
        return data({'code':'rest_cannot_access','message':'Authentication required.','data':{'status':401}},401,'cms-api-probe')
    if path == '/xmlrpc.php':
        if method not in ('POST',):
            return Response(405,b'XML-RPC server accepts POST requests only.','text/plain','xmlrpc-discovery',{'Allow':'POST'})
        # Static fault response: never parse XML, expand entities, call methods or follow pingbacks.
        return Response(200,b'<?xml version="1.0"?><methodResponse><fault><value><struct><member><name>faultCode</name><value><int>403</int></value></member><member><name>faultString</name><value><string>Authentication failed.</string></value></member></struct></value></fault></methodResponse>','text/xml','xmlrpc-attempt')
    if path == '/wp-content/plugins/portal-documents/readme.txt':
        return Response(200,b'=== Portal Documents ===\nStable tag: 1.4.2\nCustomer document management integration.\n','text/plain','plugin-discovery')
    return Response(404,html('<h1>Page not found</h1>','Customer Portal News'),scenario='cms-unmatched-probe')

def registry(path, method, body):
    headers={'Docker-Distribution-Api-Version':'registry/2.0'}
    if method not in ('GET','HEAD'):
        return data({'errors':[{'code':'DENIED','message':'requested access to the resource is denied'}]},403,'registry-write-attempt',headers)
    if path in ('/','/v2','/v2/'):
        return data({},scenario='registry-ping',headers=headers)
    if path == '/v2/_catalog':
        return data({'repositories':['customer/portal','customer/document-worker']},scenario='registry-catalog',headers=headers)
    match=re.fullmatch(r'/v2/(customer/(?:portal|document-worker))/tags/list',path)
    if match:
        return data({'name':match[1],'tags':['latest','2026.10.20']},scenario='registry-tags',headers=headers)
    # Keep image content inaccessible: no real layers, manifests or packages to pull.
    return data({'errors':[{'code':'NAME_UNKNOWN','message':'repository or manifest unknown'}]},404,'registry-content-probe',headers)

def respond(persona, target, method='GET', body=b''):
    if method == 'CONNECT':
        return Response(403, b'Proxy access denied', 'text/plain', 'proxy-connect-attempt')
    try:
        path=urlsplit(target).path
    except ValueError:
        return Response(400,b'Bad request','text/plain','malformed-target')
    if persona == 'api':
        from developer_api import respond as api_respond
        return api_respond(path, method, body)
    handler={'portal':portal,'cms':cms,'registry':registry}.get(persona)
    if handler is None:
        raise ValueError('Unknown configured persona')
    response=handler(path,method,body)
    response.canary=CANARIES.get(path,'')
    return response
