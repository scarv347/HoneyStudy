"""Static developer API simulation; fixed fixtures only, no network or tool execution."""
import json
from dataclasses import dataclass, field

@dataclass
class Reply:
    status: int
    content: bytes
    mime: str = 'application/json'
    scenario: str = 'developer-api-discovery'
    headers: dict = field(default_factory=dict)
    canary: str = ''
    details: dict = field(default_factory=dict)

TOOLS=[{'name':'search_documents','description':'Search the customer portal knowledge base.','inputSchema':{'type':'object','properties':{'query':{'type':'string'}},'required':['query']}},
       {'name':'get_document','description':'Read a published customer portal notice.','inputSchema':{'type':'object','properties':{'id':{'type':'string'}},'required':['id']}}]
NOTICE={'id':'maintenance-notice','title':'Scheduled maintenance','text':'The document service has a scheduled weekend maintenance window.'}

def data(value,status=200,scenario='developer-api-discovery',details=None,headers=None):
    return Reply(status,json.dumps(value).encode(),scenario=scenario,details=details or {},headers=headers or {})

def respond(path,method,body):
    if path in ('/','/api/developer/status'):
        return data({'service':'portal-integrations','status':'ok','mcp':'/mcp','schema':'/swagger.json'})
    if path in ('/swagger.json','/openapi.json'):
        return data({'openapi':'3.0.3','info':{'title':'Portal integrations','version':'1.4.2'},'paths':{'/mcp':{'post':{'responses':{'200':{'description':'JSON-RPC response'}}}},'/developmentserver/metadatauploader':{'post':{'responses':{'202':{'description':'Metadata queued for validation'}}}}}},scenario='developer-schema-discovery')
    if path in ('/developmentserver/metadatauploader','/api/developer/import'):
        if method in ('GET','HEAD'):
            return data({'accepted_types':['application/json','multipart/form-data'],'status':'ready'},scenario='developer-upload-discovery')
        return data({'status':'pending_validation','message':'Metadata submitted for review.'},202,'developer-upload-attempt')
    if path == '/sse':
        # A bounded legacy discovery hint, not a persistent stream or callback channel.
        return Reply(200,b'event: endpoint\ndata: /mcp\n\n','text/event-stream','legacy-stream-discovery')
    if path not in ('/mcp','/mcp/'):
        return data({'error':'not_found'},404,'developer-unmatched-probe')
    if method in ('GET','HEAD'):
        return data({'error':'POST required'},405,'mcp-discovery',headers={'Allow':'POST'})
    if method != 'POST':
        return data({'error':'method_not_allowed'},405,'mcp-method-probe',headers={'Allow':'POST'})
    try:
        request=json.loads(body)
    except (ValueError,UnicodeError,RecursionError):
        return data({'jsonrpc':'2.0','id':None,'error':{'code':-32700,'message':'Parse error'}},400,'mcp-malformed-request')
    if not isinstance(request,dict) or request.get('jsonrpc')!='2.0':
        return data({'jsonrpc':'2.0','id':None,'error':{'code':-32600,'message':'Invalid Request'}},400,'mcp-malformed-request')
    identifier=request.get('id')
    name=request.get('method')
    if not isinstance(name,str) or len(name)>100 or isinstance(identifier,(dict,list,bool,float)) or (isinstance(identifier,str) and len(identifier)>128):
        return data({'jsonrpc':'2.0','id':None,'error':{'code':-32600,'message':'Invalid Request'}},400,'mcp-malformed-request')
    params=request.get('params',{})
    if not isinstance(params,dict):
        return data({'jsonrpc':'2.0','id':identifier,'error':{'code':-32602,'message':'Invalid params'}},400,'mcp-malformed-request')
    details={'rpc_method':name}
    if 'id' not in request:
        if name=='notifications/initialized':
            return Reply(202,b'',scenario='mcp-notification',details=details)
        return Reply(202,b'',scenario='mcp-unhandled-notification',details=details)
    result=None
    error=None
    if name=='initialize':
        client=params.get('clientInfo',{})
        if isinstance(client,dict) and isinstance(client.get('name'),str):
            details['rpc_client']=client['name'][:100]
        # Emulate the explicit legacy revision; no claim of full/current MCP conformance.
        result={'protocolVersion':'2025-06-18','capabilities':{'tools':{'listChanged':False}},'serverInfo':{'name':'portal-integrations','version':'1.4.2'}}
    elif name=='ping':
        result={}
    elif name=='tools/list':
        result={'tools':TOOLS}
    elif name=='tools/call':
        tool=params.get('name')
        details['rpc_tool']=tool[:100] if isinstance(tool,str) else ''
        if tool=='search_documents':
            result={'content':[{'type':'text','text':json.dumps([{'id':NOTICE['id'],'title':NOTICE['title']}])}],'isError':False}
        elif tool=='get_document':
            args=params.get('arguments',{})
            found=isinstance(args,dict) and args.get('id')==NOTICE['id']
            result={'content':[{'type':'text','text':json.dumps(NOTICE) if found else 'Document not found.'}],'isError':not found}
        else:
            error={'code':-32602,'message':'Unknown tool'}
    else:
        error={'code':-32601,'message':'Method not found'}
    response={'jsonrpc':'2.0','id':identifier}
    response['error' if error else 'result']=error if error else result
    return data(response,scenario='mcp-tool-call' if name=='tools/call' else 'mcp-request',details=details)

def redact_rpc_body(body):
    """Remove recognized credential fields from well-formed RPC JSON before journaling."""
    try:value=json.loads(body)
    except (ValueError,UnicodeError):return body,False
    except RecursionError:return b'',True
    private={'authorization','cookie','token','access_token','api_key','apikey','password','passwd','secret','client_secret','private_key'}
    changed=False
    count=0
    def visit(node,depth=0):
        nonlocal changed,count
        count+=1
        if depth>12 or count>512:raise ValueError('redaction work limit')
        if isinstance(node,dict):
            result={}
            for key,val in node.items():
                if key.lower() in private:
                    result[key]='[redacted]';changed=True
                else:result[key]=visit(val,depth+1)
            return result
        if isinstance(node,list):return [visit(item,depth+1) for item in node]
        return node
    try:result=visit(value)
    except ValueError:return b'',True
    return (json.dumps(result).encode() if changed else body),changed
