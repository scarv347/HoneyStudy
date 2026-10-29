"""Finite WebDAV-shaped fixtures. No XML parser, storage, locking or outbound I/O."""
ROOTS=('/webdav/','/dav/')
WRITES=('PUT','POST','PATCH','DELETE','PROPPATCH','MKCOL','COPY','MOVE','LOCK','UNLOCK')

def respond(path,method):
    from personas import Response,html
    root=next((r for r in ROOTS if path.startswith(r)),None)
    if root is None:return None
    if method in WRITES:
        return Response(403,b'Collection is read-only.\n','text/plain; charset=utf-8','webdav-write-probe')
    if method=='OPTIONS':
        return Response(200,b'','text/plain','webdav-discovery',{'DAV':'1','Allow':'OPTIONS, GET, HEAD, PROPFIND'})
    if method=='PROPFIND' and path==root:
        # Ignore XML bodies, Depth and Destination. Never enumerate the host filesystem.
        body=('<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>'+root+'</d:href><d:propstat><d:prop><d:displayname>Portal documents</d:displayname><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response><d:response><d:href>'+root+'info.php</d:href><d:propstat><d:prop><d:displayname>info.php</d:displayname><d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>').encode()
        return Response(207,body,'application/xml; charset=utf-8','webdav-listing-probe',{'DAV':'1'})
    if method in ('GET','HEAD') and path==root:
        return Response(200,html('<h1>Document collection</h1><p>WebDAV collection: read-only access.</p><a href="'+root+'info.php">PHP document service</a> | <a href="/integration.php">Submission API</a> | <a href="/documents.php">Upload workspace</a>'),scenario='webdav-discovery',headers={'DAV':'1'})
    if method in ('GET','HEAD') and path==root+'info.php':
        return Response(200,html('<h1>PHP document service</h1><p>Runtime: PHP 8.2.34. Collection updates require document review.</p><a href="/integration.php">API integration guide</a>'),scenario='webdav-php-discovery')
    return Response(404,b'Not found\n','text/plain','webdav-unmatched-probe')
