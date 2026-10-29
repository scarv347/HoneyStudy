"""PHP-shaped API and development-tool fixtures; no parsing, execution or fetching."""
import hashlib
PHPUNIT=('/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php','/phpunit/phpunit/src/Util/PHP/eval-stdin.php')
API=('/api/documents.php','/api/import.php','/api/jobs.php','/api/result.php')
DEBUG=('/_ignition/health-check','/_ignition/execute-solution')

def respond(path,method,body):
    from personas import Response,data,html
    if path not in PHPUNIT+API+DEBUG+('/integration.php',):return None
    if path=='/integration.php':
        if method not in ('GET','HEAD'):return data({'error':'method_not_allowed'},405,'php-api-method-denied',{'Allow':'GET, HEAD'})
        return Response(200,html('<h1>PHP document integration</h1><p>Send a POST request to a document endpoint. Follow status_url in the receipt, then result_url for the review result. Documents remain pending until reviewed.</p><ul><li><a href="/api/documents.php">Document endpoint</a></li><li><a href="/api/import.php">Record import endpoint</a></li><li><a href="/documents.php">Browser document workspace</a></li></ul><p>Supported submission content: application/json or multipart/form-data. Example document: {&quot;title&quot;:&quot;sample&quot;,&quot;content&quot;:&quot;example&quot;}.</p>','PHP document API'),scenario='php-api-docs')
    if path in PHPUNIT:
        # Constant failure, including for valid PHP: stdin is never evaluated.
        return Response(500,b'PHP Fatal error: Test bootstrap unavailable\n','text/plain; charset=utf-8','php-test-runner-probe')
    if path=='/_ignition/health-check':
        return data({'can_execute_commands':False},scenario='php-debug-discovery') if method in ('GET','HEAD') else data({'error':'method_not_allowed'},405,'php-debug-method-denied',{'Allow':'GET, HEAD'})
    if path=='/_ignition/execute-solution':
        return data({'message':'Solution could not be executed.','exception':'RuntimeException'},422,'php-debug-solution-probe')
    if path in ('/api/documents.php','/api/import.php'):
        if method in ('GET','HEAD'):
            return data({'service':'document-processing','method':'POST','submit_url':path,'documentation':'/integration.php','accepted_content_types':['application/json','multipart/form-data']},scenario='php-api-form')
        if method=='POST':
            return data({'status':'pending_review','document_id':hashlib.sha256(body).hexdigest()[:20],'status_url':'/api/jobs.php'},202,'php-api-submission')
    if path=='/api/jobs.php' and method in ('GET','HEAD'):
        return data({'status':'pending_review','result_url':'/api/result.php'},scenario='php-api-status')
    if path=='/api/result.php' and method in ('GET','HEAD'):
        return data({'status':'review_required','message':'Processing requires review.'},scenario='php-api-result')
    return data({'error':'method_not_allowed'},405,'php-api-method-denied',{'Allow':'GET, HEAD'})
