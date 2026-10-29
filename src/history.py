"""Stable row-id pages: only changed pages load event JSON and regenerate files."""
import hashlib,json,sqlite3,gzip,os,tempfile
from pathlib import Path

def write_blob(directory,value):
    raw=json.dumps(value,separators=(',', ':'),ensure_ascii=True).encode()
    name=hashlib.sha256(raw).hexdigest()+'.json';target=directory/name
    if not target.exists():
        from collector import atomic
        atomic(target,raw.decode(),0o644)
    compressed=target.with_suffix('.json.gz')
    if not compressed.exists():
        descriptor,tmp=tempfile.mkstemp(dir=directory,prefix='.gzip-')
        try:
            os.fchmod(descriptor,0o644)
            with os.fdopen(descriptor,'wb') as out:out.write(gzip.compress(raw,compresslevel=1,mtime=0))
            os.replace(tmp,compressed)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    return '/history/'+name

def publish_history(db,public,config):
    from publication import classifier
    cohort=classifier(config);directory=Path(public)/'history';directory.mkdir(mode=0o755,exist_ok=True);directory.chmod(0o755)
    cache=sqlite3.connect(Path(public).parent/'history-cache.sqlite')
    cache.execute('CREATE TABLE IF NOT EXISTS page_cache_v2 (page INTEGER PRIMARY KEY, version TEXT, revision INTEGER, result TEXT)')
    version=hashlib.sha256(Path(__file__).read_bytes()+Path(__file__).with_name('publication.py').read_bytes()+Path(__file__).with_name('classification.py').read_bytes()+json.dumps({k:v for k,v in config.items() if k!='verified_tests'},sort_keys=True).encode()).hexdigest()
    test_pages={};verified=config.get('verified_tests',{});identifiers=list(verified)
    for start in range(0,len(identifiers),200):
        chunk=identifiers[start:start+200]
        for rowid,identifier in db.execute('SELECT rowid,id FROM events WHERE id IN ('+','.join('?' for _ in chunk)+')',chunk):
            test_pages.setdefault((rowid-1)//500,[]).append((identifier,verified[identifier]))
    outside=[];excluded=[];outside_count=excluded_count=0
    def build_page(batch):
        proxy={}
        for row in batch:
            rid=(json.loads(row[-1]).get('simulation') or {}).get('request_id')
            if rid:
                found=db.execute('SELECT data FROM proxy_observations WHERE upstream_request_id=? ORDER BY time DESC LIMIT 1',(rid,)).fetchone()
                if found:proxy[rid]=('',found[0])
        metadata_outside, metadata_excluded, records, rids = [], [], [], set()

        def details():
            if not records:
                return
            url = write_blob(directory, records)
            for position, event in enumerate(records):
                analysis = event['analysis']
                php = analysis.get('php_research')
                item = {k: event[k] for k in ('id', 'time', 'ip', 'service', 'method', 'path')}
                item.update(severity=analysis['severity'], rules=[h['rule'] for h in analysis['hits']],
                            cohort=event['traffic_cohort'], detail=url, position=position)
                c = event['classification']
                item['severity'] = c['severity']
                item['groups'] = c['groups']
                item['targets'] = c['targets']
                item['labels'] = list(dict.fromkeys(f['name'] for f in c['findings']))
                item['findings'] = [{'name': f['name'], 'group': f['group'], 'severity': f['severity']} for f in c['findings']]
                item['signal_kind']=c['signal_kind']
                if event.get('network'):
                    item['network'] = event['network']
                if event.get('protocol'):
                    item['protocol'] = event['protocol']
                if event.get('service') == 'cowrie':
                    item['session'] = str(event.get('ssh', {}).get('session', ''))[:128]
                if php and (php['php_surface'] or php['signals']):
                    item['php'] = {k: php[k] for k in ('php_surface', 'injection_markers', 'structural_anomaly', 'signals', 'cve_context')}
                (metadata_outside if item['cohort'] == 'outside_unclassified' else metadata_excluded).append(item)
            records.clear()

        for _, identifier, stamp, ip, service, severity, raw in batch:
            event = json.loads(raw)
            event.update(id=identifier, time=stamp, ip=ip, service=service)
            event.setdefault('method', '')
            event.setdefault('path', '')
            event['analysis'].setdefault('severity', severity)
            event['traffic_cohort'] = cohort(ip,identifier)
            if identifier in config.get('verified_tests',{}):event['verified_test_run']=config['verified_tests'][identifier]
            from classification import classify
            event['classification'] = classify(event)
            rid = (event.get('simulation') or {}).get('request_id')
            if rid and not event.get('proxy'):
                rids.add(rid)
                if rid in proxy:
                    event['proxy'] = json.loads(proxy[rid][1])
            records.append(event)
            if len(records) == 100:
                details()
        details()
        result = {'outside': write_blob(directory, metadata_outside) if metadata_outside else None,
                  'excluded': write_blob(directory, metadata_excluded) if metadata_excluded else None,
                  'outside_count': len(metadata_outside), 'excluded_count': len(metadata_excluded)}
        return result

    try:
        for page,revision in db.execute('SELECT page,revision FROM event_page_versions ORDER BY page'):
            revision=str(revision)+':'+hashlib.sha256(json.dumps(sorted(test_pages.get(page,[]))).encode()).hexdigest()
            old=cache.execute('SELECT version,revision,result FROM page_cache_v2 WHERE page=?',(page,)).fetchone()
            result=json.loads(old[2]) if old and old[0]==version and old[1]==revision else None
            if result and any(result[key] and not (Path(public)/result[key].lstrip('/')).exists() for key in ('outside','excluded')):result=None
            if result is None:
                batch=list(db.execute('SELECT rowid,id,time,ip,service,severity,data FROM events WHERE rowid BETWEEN ? AND ? ORDER BY rowid',(page*500+1,(page+1)*500)))
                result=build_page(batch)
                cache.execute('INSERT OR REPLACE INTO page_cache_v2 VALUES (?,?,?,?)',(page,version,revision,json.dumps(result)))
            if result['outside']:outside.append(result['outside'])
            if result['excluded']:excluded.append(result['excluded'])
            outside_count+=result['outside_count'];excluded_count+=result['excluded_count']
        cache.commit()
    finally:cache.close()
    return {'outside':outside,'excluded':excluded,'outside_count':outside_count,'excluded_count':excluded_count,'scope':'All indexed history through this snapshot. Detail records load on demand.'}
