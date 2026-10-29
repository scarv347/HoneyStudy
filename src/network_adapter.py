"""Map offline network observations to bounded dashboard events; never fetch indicators."""
import hashlib,ipaddress,json
from analysis import ip_info

def adapt(row,capture):
    kind=row.get('event_type')
    if kind not in ('alert','flow','tls'):return None
    # Decoder/packet alerts can lack flow addresses. Keep them in the original
    # EVE archive, but do not invent an IP attribution for the dashboard.
    try:
        src=ipaddress.ip_address(row.get('src_ip'));dest=ipaddress.ip_address(row.get('dest_ip'))
    except (ValueError,TypeError):return None
    if src.is_global:ip=str(src)
    elif dest.is_global:ip=str(dest)
    else:return None
    severity='info';name='Network TLS handshake observed' if kind=='tls' else 'Network flow observed';signature=''
    if kind=='alert':
        a=row.get('alert',{});severity={1:'high',2:'medium',3:'low'}.get(a.get('severity'),'medium');signature=str(a.get('signature','Unknown signature'))[:180];name='Suricata alert: '+signature
    # A checksum-only decoder finding is diagnostic, not proof of an attack.
    diagnostic=signature in {f'SURICATA {proto}{version} invalid checksum' for proto in ('TCP','UDP') for version in ('v4','v6')}
    if diagnostic:severity='info';name='Packet checksum diagnostic'
    timestamp=row['timestamp'];ports=[int(row.get('src_port',0)),int(row.get('dest_port',0))]
    stable=[capture,kind,timestamp,str(src),str(dest),ports,row.get('alert',{}).get('signature_id')]
    identifier=hashlib.sha256(json.dumps(stable,sort_keys=True).encode()).hexdigest()
    network={'type':kind,'transport':str(row.get('proto','TCP'))[:16],'application':str(row.get('app_proto','unknown'))[:24],'source_port':ports[0],'destination_port':ports[1],'signature':signature,'capture_sha256':capture,'capture_snaplen':2048}
    if diagnostic:network.update(diagnostic=True,engine_severity=row['alert'].get('severity'),diagnostic_note='Possible capture checksum offload or malformed packet; not an attack verdict')
    if row.get('community_id'):network['community_id']=str(row['community_id'])[:100]
    if kind=='alert':network.update(signature_id=int(row.get('alert',{}).get('signature_id',0)),signature_revision=int(row.get('alert',{}).get('rev',0)),signature_category=str(row.get('alert',{}).get('category',''))[:120])
    if kind=='flow':network.update({k:row.get('flow',{}).get(k) for k in ('pkts_toserver','pkts_toclient','bytes_toserver','bytes_toclient','age','state')})
    if kind=='tls':network.update({k:str(row.get('tls',{}).get(k,''))[:180] for k in ('sni','version')})
    path=f'{network["transport"]} {src}:{ports[0]} → {dest}:{ports[1]}'
    return {'id':'network:'+identifier,'time':timestamp,'ip':ip,'service':'network','method':kind.upper(),'path':path,'network':network,'intelligence':ip_info(ip),'analysis':{'rules_version':'rx1-network-2','severity':severity,'hits':[{'rule':name,'severity':severity,'match':signature or network['application'],'layer':'passive packet sample'}],'payload_preview':'','payload_bytes':0,'payload_sha256':None,'urls':[],'exploitation_confirmed':False},'simulation':{'scenario':'passive-network-observation','credentials_redacted':True},'self_test':False}
