"""Protocol-specific labels from redacted emulator evidence."""
def enrich(event,assessment):
    service=event.get('service')
    if service not in ('redis','mysql','telnet'):return assessment
    hits=assessment['hits'];commands=event.get('protocol_commands',[])
    def hit(name,severity,evidence):hits.append({'rule':name,'severity':severity,'match':evidence[:180],'layer':'redacted protocol conversation'})
    hit(service.upper()+' service probe','low',service+' conversation observed')
    if event.get('protocol_login_attempts'):hit(service.upper()+' authentication attempt','medium','Credential exchange observed; credentials redacted')
    for command in commands:
        words=command.upper().split();verb=words[0] if words else ''
        if service!='redis':continue
        if verb=='CONFIG' and len(words)>1 and words[1]=='GET':hit('Redis configuration discovery','medium',command)
        elif verb in ('CONFIG','SLAVEOF','REPLICAOF','MODULE','EVAL','EVALSHA','SCRIPT'):hit('Redis configuration or execution probe','high',command)
        elif verb in ('SAVE','BGSAVE'):hit('Redis snapshot command probe','medium',command)
        elif verb in ('FLUSHALL','FLUSHDB'):hit('Redis destructive command probe','high',command)
    rank={'info':0,'low':1,'medium':2,'high':3};assessment['severity']=max((h['severity'] for h in hits),key=lambda v:rank[v],default='info')
    return assessment
