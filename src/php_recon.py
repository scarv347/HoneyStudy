"""Exact-route PHP reconnaissance fixtures. Never read files or open requested URLs."""
DIAGNOSTICS=('/assets/info.php','/assets/phpinfo.php','/assets/test.php','/app_dev.php/_profiler/phpinfo')
CONFIGS=('/config.php.bak','/.env.php.bak','/.env.php.backup','/.env.example.php')

def respond(path,method):
    from personas import Response,html
    known=path in DIAGNOSTICS+CONFIGS+('/app_dev.php/_profiler/open','/app_dev.php/_profiler/.env')
    if not known:return None
    if method not in ('GET','HEAD'):
        return Response(405,b'Method not allowed\n','text/plain','php-recon-write-denied',{'Allow':'GET, HEAD'})
    if path in DIAGNOSTICS:
        return Response(200,html('<h1>PHP Version 8.2.34</h1><table><tr><td>Server API</td><td>FPM/FastCGI</td></tr><tr><td>memory_limit</td><td>128M</td></tr><tr><td>session.upload_progress.enabled</td><td>On</td></tr></table><p><a href="/documents.php">Document workspace</a> | <a href="/import.php">Record import</a></p>','PHP runtime diagnostics'),scenario='php-recon-diagnostics')
    if path in CONFIGS:
        return Response(200,b'<?php\nreturn [\n "app" => "CustomerPortal",\n "environment" => "production",\n "database_host" => "db.portal.invalid",\n "document_endpoint" => "/documents.php",\n "import_endpoint" => "/import.php",\n];\n','text/plain; charset=utf-8','php-recon-config-fixture')
    if path=='/app_dev.php/_profiler/.env':
        return Response(200,b'APP_ENV=production\nAPP_DEBUG=0\nDOCUMENT_ENDPOINT=/documents.php\nIMPORT_ENDPOINT=/import.php\n','text/plain; charset=utf-8','php-recon-profiler-fixture')
    return Response(403,b'File viewer disabled in this environment.\n','text/plain; charset=utf-8','php-recon-file-view-denied')
