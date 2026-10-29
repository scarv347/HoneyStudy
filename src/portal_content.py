"""Fixed public application content. Query parameters never select files or run searches."""
PATHS=('/help.php','/search.php','/download.php','/templates/document-import.csv','/release-notes.php')

def respond(path,method):
    from personas import Response,html
    if path not in PATHS:return None
    if method not in ('GET','HEAD'):
        return Response(405,b'Method not allowed\n','text/plain','portal-content-write-probe',{'Allow':'GET, HEAD'})
    if path=='/templates/document-import.csv':
        return Response(200,b'document_id,title,category\nEXAMPLE-001,Sample invoice,invoice\nEXAMPLE-002,Sample service request,service\n','text/csv; charset=utf-8','portal-template-discovery',{'Content-Disposition':'attachment; filename="document-import.csv"'})
    if path=='/download.php':
        return Response(200,b'Document integration guide\nSubmit files at /upload.php or records at /import.php.\nAPI clients: /integration.php\nProcessing requires review.\n','text/plain; charset=utf-8','portal-download-probe',{'Content-Disposition':'attachment; filename="document-guide.txt"'})
    nav='<nav><a href="/documents.php">Documents</a> | <a href="/search.php">Find resources</a> | <a href="/help.php">Help</a> | <a href="/integration.php">API</a></nav>'
    if path=='/help.php':
        body='<h1>Document service help</h1><h2>Submit a document</h2><p>Use the document workspace to submit a file. The receipt includes a status link; follow it for the review result.</p><a href="/upload.php">Upload a document</a><h2>Import records</h2><p>Use document_id, title and category columns. Download the sample CSV, replace the example rows, and submit it through record import.</p><a href="/templates/document-import.csv">Sample CSV</a> | <a href="/import.php">Import records</a><h2>Integrations</h2><p>API submissions return status_url and result_url links. Legacy clients use the separate PHP integration workspace.</p><a href="/legacy/documents.php">Legacy workspace</a> | <a href="/download.php?id=document-guide">Download guide</a>'
    elif path=='/search.php':
        body='<h1>Find document resources</h1><form action="/search.php" method="GET"><label>Search resources <input name="q" maxlength="200"></label><button>Search</button></form><h2>Featured resources</h2><ul><li><a href="/help.php">Document submission guide</a></li><li><a href="/templates/document-import.csv">Record import template</a></li><li><a href="/download.php?id=document-guide">Integration reference</a></li><li><a href="/release-notes.php">Service release notes</a></li></ul>'
    else:
        body='<h1>Customer Portal 2.4.1</h1><h2>Document integration</h2><p>Document submissions now return receipt and review-status links. Record imports use the document schema available in the sample template.</p><h2>Compatibility</h2><p>Legacy PHP integrations remain available in the legacy workspace. WebDAV collections provide read-only document service information.</p><a href="/legacy/">Legacy integration</a> | <a href="/webdav/">Document collection</a>'
    return Response(200,html(nav+body,'Document services | Customer Portal'),scenario='portal-resource-discovery')
