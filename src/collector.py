"""Cursor-based immutable journal batches, derived SQLite index, static private UI."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
from analysis import analyze, ip_info, VERSION

UNITS = ('php-honeypot.service', 'rx1-decoy@registry.service', 'rx1-decoy@cms.service', 'rx1-decoy@api.service', 'rx1-ftp.service', 'rx1-protocol@redis.service', 'rx1-protocol@mysql.service', 'rx1-protocol@telnet.service')

def atomic(path, data, mode=0o600):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix='.rx1-')
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb' if isinstance(data,bytes) else 'w') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def connect(state):
    db = sqlite3.connect(state / 'index.sqlite', timeout=10)
    db.execute('PRAGMA synchronous=FULL')
    db.execute('CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, time TEXT, ip TEXT, service TEXT, severity TEXT, data TEXT)')
    db.execute('CREATE INDEX IF NOT EXISTS by_time ON events(time)')
    db.execute('CREATE INDEX IF NOT EXISTS by_ip ON events(ip)')
    db.execute('CREATE INDEX IF NOT EXISTS event_summary_by_ip ON events(ip,time,severity)')
    db.execute('CREATE INDEX IF NOT EXISTS event_summary_by_time ON events(time,ip,severity)')
    db.execute('CREATE INDEX IF NOT EXISTS event_summary_by_severity ON events(severity,time,ip)')
    db.execute('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)')
    from proxy_ingest import schema
    schema(db)
    from index_state import initialize
    initialize(db)
    return db

def ingest(db, raw, origin='journal'):
    malformed = 0
    for line in raw.splitlines():
        try:
            envelope = json.loads(line)
            if not isinstance(envelope, dict):
                malformed += 1
                continue
            event = json.loads(envelope['MESSAGE']) if 'MESSAGE' in envelope else envelope
            if not isinstance(event, dict) or 'ip' not in event or 'path' not in event:
                continue
            if not ip_info(str(event['ip']))['valid']:
                malformed += 1
                continue
            # Journal cursor uniquely identifies captured records, including identical requests.
            identifier = envelope.get('__CURSOR') or hashlib.sha256(line.encode()).hexdigest()
            assessment = analyze(event)
            from service_signals import enrich as protocol_enrich
            assessment = protocol_enrich(event, assessment)
            data = {'id': identifier, 'time': str(event.get('time', '')), 'ip': str(event['ip']),
                    'path': str(event['path'])[:8192], 'method': str(event.get('method', ''))[:20],
                    'service': str(event.get('service', envelope.get('_SYSTEMD_UNIT', origin))),
                    'protocol': event.get('protocol') if isinstance(event.get('protocol'), dict) else None,
                    'intelligence': ip_info(str(event['ip'])), 'analysis': assessment,
                    'self_test': ip_info(str(event['ip']))['scope'] == 'loopback',
                    'simulation': {k: event.get(k) for k in ('simulation_version', 'scenario', 'canary', 'response_status', 'request_id', 'xmlrpc_method', 'capture_error', 'body_redacted', 'content_length', 'rpc_method', 'rpc_tool', 'rpc_client', 'breadcrumb_issued', 'breadcrumb_follow', 'ftp_commands', 'ftp_login_attempts', 'ftp_bytes_received', 'credentials_redacted')},
                    'user_agent_claim': str(event.get('headers', {}).get('User-Agent', ''))[:300] if isinstance(event.get('headers', {}), dict) else ''}
            db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?)',
                       (identifier, data['time'], data['ip'], data['service'], assessment['severity'], json.dumps(data)))
            from index_state import record_clock
            canonical=record_clock(db,identifier,data['time'])
            if canonical!=data['time']:db.execute('UPDATE events SET time=? WHERE id=?',(canonical,identifier))
        except (ValueError, TypeError, KeyError, AttributeError):
            malformed += 1
    return malformed

def health(state):
    import http.client
    checks = {}
    targets = [('php-honeypot.service', 8080, 200), ('rx1-decoy@registry.service', 8081, 200),
               ('rx1-decoy@cms.service', 8082, 200), ('rx1-decoy@api.service', 8083, 200), ('nginx.service', 80, 200),
               ('rx1-dashboard.service', 9090, 200)]
    for unit, port, expected in targets:
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
        try:
            conn.request('HEAD', '/', headers={'User-Agent': 'RX1-local-health/1'})
            status = conn.getresponse().status
            checks[unit] = 'active' if status == expected else f'unhealthy: HTTP {status}'
        except (OSError, http.client.HTTPException) as exc:
            checks[unit] = 'unreachable: ' + str(exc)[:120]
        finally:
            conn.close()
    if os.environ.get('RX1_FTP_HEALTH')=='1':
        import socket
        try:
            with socket.create_connection(('127.0.0.1',21),timeout=2) as sock:
                sock.settimeout(2)
                banner=sock.recv(128)
                sock.sendall(b'QUIT\r\n')
                checks['rx1-ftp.service']='active' if banner.startswith(b'220 ') else 'unhealthy FTP banner'
        except OSError as exc:checks['rx1-ftp.service']='unreachable: '+str(exc)[:120]
    disk = shutil.disk_usage(state)
    checks['disk_free_bytes'] = disk.free
    checks['disk_free_percent'] = round(disk.free / disk.total * 100, 1)
    checks['storage_warning'] = disk.free < 2 * 1024 ** 3
    return checks

def research_sections(db,state,checks,refresh=False):
    from publication import settings,observe,build,markdown,html
    from proxy_ingest import summary
    research_config=settings();observe(db,checks,research_config)
    path=state/'research-sections-cache.json'
    revision=hashlib.sha256(json.dumps(research_config,sort_keys=True).encode())
    for name in ('collector.py','publication.py','research.py','php_watch.py','discovery.py','workflows.py','breadcrumb_report.py','classification.py'):
        revision.update(Path(__file__).with_name(name).read_bytes())
    version=revision.hexdigest();now=datetime.now(timezone.utc)
    if os.environ.get('HUB_ASYNC_REPORTS')=='1' and not refresh:
        try:
            saved=json.loads(path.read_text());sections=saved['sections']
            age=max(0,(now-datetime.fromisoformat(saved['generated'])).total_seconds())
            sections['research_status']={'state':'current' if age<7200 and saved['version']==version else 'stale','age_seconds':round(age),'generated':saved['generated']}
        except (OSError,ValueError,KeyError,TypeError):
            sections={'research_status':{'state':'pending','generated':None}}
        return research_config,sections
    try:
        saved=json.loads(path.read_text())
        age=(now-datetime.fromisoformat(saved['generated'])).total_seconds()
        if saved['version']==version and 0<=age<600:
            return research_config,saved['sections']
    except (OSError,ValueError,KeyError,TypeError):pass
    sections={'research_generated':now.isoformat()}
    public=state/'public'
    publication = build(db, research_config, all_time=True)
    from php_watch import aggregate as php_aggregate
    php_metrics = php_aggregate(db, research_config, all_time=True)
    from discovery import summarize as engagement_summary
    sections['engagement'] = engagement_summary(db,research_config, all_time=True)
    from workflows import summarize as journey_summary
    sections['journeys'] = journey_summary(db,research_config, all_time=True)
    publication['journeys'] = {k:v for k,v in sections['journeys'].items() if k not in ('unmatched_php_paths','observed_signals')}
    publication['engagement'] = sections['engagement']
    publication['php_research'] = php_metrics
    sections['php_research'] = php_metrics
    sections['publication'] = publication
    sections['publication_markdown'] = markdown(publication)
    atomic(public / 'report.md', markdown(publication), 0o644)
    atomic(public / 'report.html', html(publication), 0o644)
    from research import from_database
    report=from_database(db)
    report['publication'] = publication
    report['proxy_telemetry']=summary(db)
    from breadcrumb_report import trails
    report['breadcrumb_trails']=trails(db)
    atomic(public / 'research.json', json.dumps(report, indent=2), 0o644)
    atomic(path,json.dumps({'generated':now.isoformat(),'version':version,'sections':sections}))
    return research_config,sections

def publish(db, state, checks, malformed=0, extra=None):
    public = state / 'public'
    public.mkdir(mode=0o755, exist_ok=True)
    public.chmod(0o755)
    rows = []  # Full details are immutable pages; no redundant newest-events JSON scan.
    from proxy_ingest import enrich,summary
    enrich(db, rows)
    stats = {'requests': db.execute("SELECT count(*) FROM events WHERE ip NOT IN ('127.0.0.1','::1')").fetchone()[0],
             'ips': db.execute("SELECT count(DISTINCT ip) FROM events WHERE ip NOT IN ('127.0.0.1','::1')").fetchone()[0],
             'detections': db.execute("SELECT count(*) FROM events WHERE severity != 'info' AND ip NOT IN ('127.0.0.1','::1')").fetchone()[0],
             'high': db.execute("SELECT count(*) FROM events WHERE severity = 'high' AND ip NOT IN ('127.0.0.1','::1')").fetchone()[0]}
    sources = []
    for ip, count, first, last, highs in db.execute("SELECT ip,count(*),min(time),max(time),sum(severity='high') FROM events WHERE ip NOT IN ('127.0.0.1','::1') GROUP BY ip ORDER BY count(*) DESC LIMIT 100"):
        sources.append({'ip': ip, 'requests': count, 'first': first, 'last': last, 'high': highs, **ip_info(ip)})
    timeline = list(db.execute("SELECT substr(time,1,16),count(*) FROM events WHERE ip NOT IN ('127.0.0.1','::1') GROUP BY substr(time,1,16) ORDER BY substr(time,1,16) DESC LIMIT 60"))[::-1]
    alerts = []
    for unit, status in checks.items():
        if unit.endswith('.service') and status != 'active':
            alerts.append(f'{unit}: {status}')
    if checks.get('storage_warning'):
        alerts.append('Low disk space: archive collection paused below 1 GiB; no evidence is deleted automatically')
    # Only alert on recent traffic, not the whole historical corpus.
    for ip, count in db.execute("SELECT ip,count(*) FROM events WHERE severity='high' AND ip NOT IN ('127.0.0.1','::1') AND time >= ? GROUP BY ip HAVING count(*) >= 5", ((datetime.now(timezone.utc).isoformat()[:14] + '00:00+00:00'),)):
        alerts.append(f'Repeated high severity probes this UTC hour: {ip} ({count})')
    doc = {'generated': datetime.now(timezone.utc).isoformat(), 'rules_version': VERSION,
           'proxy_summary':summary(db), 'stats': stats, 'events': rows, 'sources': sources, 'timeline': timeline, 'health': checks,
           'alerts': alerts, 'malformed_this_run': malformed,
           'scope': 'Summary metrics exclude loopback self-tests; event view limited to newest 2000 captured records. IP identity and exploit success are unverified.'}
    research_config,sections=research_sections(db,state,checks)
    doc.update(sections)
    from history import publish_history
    doc['history'] = publish_history(db, public, research_config)
    # Full details now live in bounded private pages; no duplicate newest-events bundle.
    doc['events'] = []
    # Publish private, read-only copies for the explicitly requested original-log export.
    # Original evidence files and their permissions remain unchanged.
    for archive_name in ('archive', 'proxy-archive', 'cowrie-archive', 'network-archive'):
        destination = public / 'originals' / archive_name
        destination.mkdir(parents=True, exist_ok=True, mode=0o755)
        destination.parent.chmod(0o755)
        destination.chmod(0o755)
        for source in (state / archive_name).glob('*.jsonl'):
            target = destination / source.name
            if source.is_file() and not source.is_symlink() and not target.exists():
                temporary = target.with_suffix('.tmp')
                shutil.copyfile(source, temporary)
                temporary.chmod(0o644)
                os.replace(temporary, target)
    from geolocation import enrich as geo_enrich
    from classification import catalog, VERSION as classification_version
    doc['geolocation'] = geo_enrich(db, state)
    doc['classification_version'] = classification_version
    doc['catalog'] = catalog()
    from history import write_blob
    doc['snapshot'] = write_blob(public / 'history', {'history': doc['history'], 'generated': doc['generated'], 'geolocation': doc['geolocation'], 'classification_version': classification_version})
    doc['scope'] = 'All indexed history; outside traffic by default. Source IPs are not people; findings do not prove exploitation.'
    if extra:doc.update(extra)
    atomic(public / 'snapshot.json', json.dumps(doc), 0o644)
    template = Path(__file__).with_name('dashboard.html').read_text()
    # Base64 prevents hostile evidence from ending a script element.
    import base64
    embedded = base64.b64encode(json.dumps({'bootstrap':True}).encode()).decode()
    atomic(public / 'dashboard.html', template.replace('RX1_DATA_PLACEHOLDER', embedded), 0o644)
    fingerprint = hashlib.sha256(json.dumps(alerts, sort_keys=True).encode()).hexdigest()
    old = db.execute("SELECT value FROM meta WHERE key='alerts'").fetchone()
    if (not old and alerts) or (old and old[0] != fingerprint):
        print(json.dumps({'type': 'monitor_alert' if alerts else 'monitor_recovery', 'alerts': alerts}), flush=True)
    db.execute("INSERT OR REPLACE INTO meta VALUES ('alerts',?)", (fingerprint,))
    db.commit()

def collect(state):
    state.mkdir(mode=0o755, parents=True, exist_ok=True)
    archive = state / 'archive'
    archive.mkdir(mode=0o700, exist_ok=True)
    db = connect(state)
    checks = health(state)
    if checks['disk_free_bytes'] < 1024 ** 3:
        publish(db, state, checks)
        raise RuntimeError('Collection paused: less than 1 GiB free; evidence retained')
    # Recover durable batches before advancing the cursor (safe after interrupted transactions).
    checkpoint = state / 'cursor'
    cursor = checkpoint.read_text().strip() if checkpoint.exists() else ''
    pending = sorted(archive.glob('*.pending'))
    for marker in pending:
        batch = archive / marker.read_text().strip()
        raw = batch.read_text()
        if hashlib.sha256(batch.read_bytes()).hexdigest() + '.jsonl' != batch.name:
            raise RuntimeError('Archive checksum mismatch; checkpoint unchanged')
        ingest(db, raw)
        envelopes = [json.loads(line) for line in raw.splitlines()]
        db.commit()
        if envelopes:
            atomic(checkpoint, envelopes[-1]['__CURSOR'])
            cursor = envelopes[-1]['__CURSOR']
        marker.unlink()
    command = ['journalctl', '--all', '--no-pager', '-o', 'json', '--output-fields=MESSAGE,__CURSOR,_SYSTEMD_UNIT']
    for unit in UNITS:
        command += ['-u', unit]
    # Oldest-first, bounded initial bootstrap avoids silently skipping historical evidence.
    command += ['--after-cursor=' + cursor] if cursor else []
    fd, tmp = tempfile.mkstemp(dir=archive, prefix='.capture-')
    malformed = 0
    try:
        # Drain only 4 MiB or 5000 records per run, without buffering unlimited journal output.
        with os.fdopen(fd, 'wb') as out:
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                size = 0
                lines = 0
                for line in proc.stdout:
                    if len(line) > 262144:
                        raise RuntimeError('Oversized journal record; cursor unchanged')
                    out.write(line)
                    size += len(line)
                    lines += 1
                    if size >= 4 * 1024 * 1024 or lines >= 5000:
                        proc.terminate()
                        break
                _, err = proc.communicate(timeout=10)
                if proc.returncode not in (0, -15):
                    raise RuntimeError('Journal read failed: ' + err.decode('utf-8', 'replace')[:500])
                out.flush()
                os.fsync(out.fileno())
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
        raw_bytes = Path(tmp).read_bytes()
        if raw_bytes:
            digest = hashlib.sha256(raw_bytes).hexdigest()
            name = digest + '.jsonl'
            batch = archive / name
            if batch.exists():
                if batch.read_bytes() != raw_bytes:
                    raise RuntimeError('Archive hash collision')
            else:
                os.rename(tmp, batch)
            atomic(archive / (digest + '.pending'), name)
            raw = raw_bytes.decode('utf-8')
            malformed = ingest(db, raw)
            db.commit()
            last = json.loads(raw.splitlines()[-1])['__CURSOR']
            atomic(checkpoint, last)
            (archive / (digest + '.pending')).unlink()
        from proxy_ingest import collect_proxy
        proxy_log=os.environ.get('RX1_PROXY_LOG')
        if proxy_log:
            proxy_result=collect_proxy(db,state,proxy_log)
            malformed+=proxy_result['malformed']
        if os.environ.get('RX1_CAPTURE_ONLY')!='1':
            publish(db, state, checks, malformed)
        else:
            # Keep the already-private, read-only original-log copies current for forwarding.
            for kind in ('archive','proxy-archive'):
                destination=state/'public'/'originals'/kind
                destination.mkdir(parents=True,exist_ok=True,mode=0o755)
                for source in (state/kind).glob('*.jsonl'):
                    target=destination/source.name
                    if source.is_file() and not source.is_symlink() and not target.exists():
                        temporary=target.with_suffix('.tmp')
                        shutil.copyfile(source,temporary);temporary.chmod(0o644);os.replace(temporary,target)
    finally:
        db.close()
        if os.path.exists(tmp):
            os.unlink(tmp)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--import-log', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if args.import_log:
        args.state.mkdir(parents=True, mode=0o755, exist_ok=True)
        db = connect(args.state)
        bad = ingest(db, args.import_log.read_text(errors='replace'), str(args.import_log))
        db.commit()
        publish(db, args.state, {'mode': 'offline import; no live health checks'}, bad)
    else:
        collect(args.state)
