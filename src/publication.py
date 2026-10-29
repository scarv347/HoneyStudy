"""Aggregate-only publication metrics. Never publish addresses, paths or captured text."""
from datetime import datetime, timezone, timedelta
import hashlib
from functools import lru_cache
import ipaddress
import json
import os
from pathlib import Path
import re

VERSION = 'rx1-research-3'

def settings():
    directory = os.environ.get('CREDENTIALS_DIRECTORY')
    value = json.loads((Path(directory) / 'research.json').read_text()) if directory else {'operator_networks': []}
    networks = value['operator_networks']
    if not isinstance(networks, list) or len(networks) > 32:
        raise ValueError('Invalid operator network configuration')
    result={'operator_networks': [str(ipaddress.ip_network(n, strict=True)) for n in networks]}
    registry=Path(os.environ.get('HUB_STATE','/var/lib/honeypot-hub'))/'verified-tests.json'
    if registry.exists():
        if registry.stat().st_size>2*1024*1024:raise ValueError('Test registry too large')
        tests=json.loads(registry.read_text())
        if not isinstance(tests,dict) or len(tests)>10000 or any(not isinstance(k,str) or not 1<=len(k)<=256 or not isinstance(v,str) or len(v)>100 for k,v in tests.items()):raise ValueError('Invalid test registry')
        result['verified_tests']=tests
    return result

def classifier(config):
    nets = [ipaddress.ip_network(n, strict=True) for n in config['operator_networks']]
    verified=config.get('verified_tests',{})
    @lru_cache(maxsize=8192)
    def address_cohort(value):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return 'invalid'
        if address.is_loopback:
            return 'local_checks'
        if any(address in net for net in nets):
            return 'operator_associated'
        if not address.is_global:
            return 'reserved_private'
        return 'outside_unclassified'
    def classify(value,identifier=None):
        return 'operator_test' if identifier in verified else address_cohort(value)
    return classify

def observe(db, checks, config, now=None):
    stamp = now or datetime.now(timezone.utc)
    db.execute('CREATE TABLE IF NOT EXISTS research_health (minute TEXT PRIMARY KEY, checked INTEGER, healthy INTEGER, revision TEXT)')
    services = [v for k,v in checks.items() if k.endswith('.service')]
    # Revision captures analysis/collector/report source plus classification settings.
    digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode())
    for name in ('analysis.py','collector.py','publication.py','research.py','php_watch.py','personas.py','decoy.py','discovery.py','workflows.py','breadcrumbs.py','php_recon.py','php_apps.py','proxy_ingest.py','webdav_fixture.py','portal_content.py'):
        digest.update(Path(__file__).with_name(name).read_bytes())
    db.execute('INSERT OR IGNORE INTO research_health VALUES (?,?,?,?)',
               (stamp.astimezone(timezone.utc).isoformat()[:16], len(services), services.count('active'), digest.hexdigest()))

def build(db, config, now=None, all_time=False):
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start = (now - timedelta(days=30)).replace(hour=0, minute=0, second=0, microsecond=0)
    if all_time:
        first = db.execute('SELECT min(time) FROM events WHERE time<=?', (now.isoformat(),)).fetchone()[0]
        start = datetime.fromisoformat(first).replace(hour=0, minute=0, second=0, microsecond=0) if first else now
    lower, upper = start.isoformat(), now.isoformat()
    db.create_function('research_cohort', 2, classifier(config), deterministic=True)
    # Filter and aggregate in SQLite; no payload bodies or large event lists in memory.
    window = "time>=? AND time<=?"
    args = (lower, upper)
    cohorts = dict(db.execute('SELECT research_cohort(ip,id),count(*) FROM events WHERE '+window+' GROUP BY research_cohort(ip,id)', args))
    condition = window + " AND research_cohort(ip,id)='outside_unclassified'"
    daily = [{'day_utc':day, 'events':n, 'source_ips':ips, 'http_requests':http, 'ftp_sessions':ftp, 'flagged_events':flagged}
             for day,n,ips,http,ftp,flagged in db.execute("SELECT substr(time,1,10),count(*),count(DISTINCT ip),sum(service NOT IN ('ftp','cowrie','network','redis','mysql','telnet')),sum(service='ftp'),sum(severity!='info') FROM events WHERE "+condition+' GROUP BY substr(time,1,10) ORDER BY 1', args)]
    totals = db.execute('SELECT count(*),count(DISTINCT ip),min(time),max(time) FROM events WHERE '+condition,args).fetchone()
    services = [{'sensor':sensor if sensor in ('portal','ftp','php-honeypot','registry','cms','api','nginx-edge','cowrie','php-honeypot.service','rx1-decoy@registry.service','rx1-decoy@cms.service','rx1-decoy@api.service') else 'other', 'events':n}
                for sensor,n in db.execute('SELECT service,count(*) FROM events WHERE '+condition+' GROUP BY service ORDER BY count(*) DESC',args)]
    aliases = {'php-honeypot.service':'portal','php-honeypot':'portal','rx1-decoy@registry.service':'registry','rx1-decoy@cms.service':'cms','rx1-decoy@api.service':'api'}
    merged = {}
    for item in services:
        name = aliases.get(item['sensor'],item['sensor'])
        merged[name] = merged.get(name,0) + item['events']
    services = [{'sensor':name,'events':n} for name,n in sorted(merged.items(),key=lambda pair:pair[1],reverse=True)]
    digest_expr = "json_extract(data,'$.analysis.payload_sha256')"
    clusters = [{'captured_payload_sha256':digest,'events':n,'source_ips':ips}
                for digest,n,ips in db.execute('SELECT '+digest_expr+',count(*),count(DISTINCT ip) FROM events WHERE '+condition+" AND json_extract(data,'$.analysis.payload_bytes')>0 AND coalesce(json_extract(data,'$.simulation.body_redacted'),0)=0 AND coalesce(json_extract(data,'$.simulation.credentials_redacted'),0)=0 GROUP BY "+digest_expr+' HAVING count(*)>=2 ORDER BY count(*) DESC LIMIT 10', args)
                if isinstance(digest,str) and re.fullmatch('[0-9a-f]{64}',digest)]
    followed = db.execute('SELECT count(*) FROM events WHERE '+condition+" AND json_extract(data,'$.simulation.breadcrumb_follow.status')='valid'",args).fetchone()[0]
    issued = db.execute('SELECT count(*) FROM events WHERE '+condition+" AND json_extract(data,'$.simulation.breadcrumb_issued') IS NOT NULL",args).fetchone()[0]
    health = list(db.execute('SELECT minute,checked,healthy,revision FROM research_health WHERE minute>=? AND minute<=? ORDER BY minute',(lower[:16],upper[:16])))
    gaps = []
    for previous,current in zip(health,health[1:]):
        minutes = (datetime.fromisoformat(current[0])-datetime.fromisoformat(previous[0])).total_seconds()/60
        if minutes>3:
            gaps.append({'from_utc':previous[0], 'to_utc':current[0], 'minutes_between_samples':int(minutes)})
    revisions = []
    for minute,checked,healthy,revision in health:
        if not revisions or revisions[-1]['revision_sha256'] != revision:
            revisions.append({'first_observed_utc':minute, 'revision_sha256':revision})
    checked = sum(r[1] for r in health)
    return {'version':VERSION,'generated_utc':upper,'window_start_utc':lower,'window_end_utc':upper,
            'scope':('All indexed history through this snapshot.' if all_time else 'Current UTC date and previous 30 UTC dates; all indexed events in this window, without a newest-events cap.'),
            'cohorts':cohorts,'operator_networks_configured':len(config['operator_networks']),
            'outside':{'events':totals[0],'source_ips':totals[1],'first_event_utc':totals[2],'last_event_utc':totals[3]},
            'daily':daily,'sensors':services,'repeated_captured_payloads':clusters,
            'discovery':{'events_issuing_links':issued,'valid_follow_events':followed},
            'monitoring':{'samples':len(health),'first_sample_utc':health[0][0] if health else None,
                          'last_sample_utc':health[-1][0] if health else None,
                          'successful_check_percent':round(100*sum(r[2] for r in health)/checked,2) if checked else None,
                          'gaps_over_three_minutes':gaps[:100], 'gap_count':len(gaps),'observed_revisions':revisions[:100]},
            'limitations':['Outside traffic is unclassified; it includes benign scanners and unknown tests.',
                          'Operator-associated addresses can be shared or reassigned; exclusions are configurable and retrospective.',
                          'Source IP counts are not attacker counts. A matched rule does not establish compromise.',
                          'HTTP requests and FTP sessions are different measurement units.',
                          'Payload clusters match captured nonempty bytes; truncation and redaction limit conclusions.',
                          'Signed follow events are not unique visitors or a conversion rate; links can be reused.',
                          'Health percentages describe sampled local responses, not independently measured uptime.',
                          'Monitoring history starts with this release; gaps can reflect restarts, delays or failures.',
                          'One host and a limited observation window are not representative of the entire internet.']}

def markdown(report):
    out = ['# RX1 honeypot research — preliminary observations','',
           f"Query window (UTC): {report['window_start_utc']} to {report['window_end_utc']}",'',
           f"Actual indexed outside observations (UTC): {report['outside']['first_event_utc']} to {report['outside']['last_event_utc']}. The query window is not a claim of continuous operation.",'',
           '## Method', '',
           'An isolated Oracle Cloud honeypot simulates web applications and FTP. Payloads are analyzed as inert text. Raw evidence is preserved separately; this export contains aggregates only. Local, operator-associated and reserved/private sources are excluded from the outside cohort.', '',
           '## Observations', '',
           f"- Outside events: {report['outside']['events']}",
           f"- Unique outside source IPs: {report['outside']['source_ips']}",
           f"- Local check events excluded: {report['cohorts'].get('local_checks',0)}",
           f"- Operator-associated events excluded: {report['cohorts'].get('operator_associated',0)}", '',
           '| UTC date | HTTP requests | FTP sessions | Source IPs | Rule-flagged events |',
           '|---|---:|---:|---:|---:|']
    for row in report['daily']:
        out.append(f"| {row['day_utc']} | {row['http_requests']} | {row['ftp_sessions']} | {row['source_ips']} | {row['flagged_events']} |")
    out += ['', '## Collection quality', '',
            f"Monitor samples: {report['monitoring']['samples']}. Sampled checks successful: {report['monitoring']['successful_check_percent']}%. Gaps exceeding three minutes: {report['monitoring']['gap_count']}.", '',
            '## Limitations', ''] + ['- '+item for item in report['limitations']]
    if report.get('php_research'):
        php=report['php_research']
        out += ['', '## PHP research focus', '', f"PHP-related outside events: {php['totals']['php_related_events']}; injection-marker events: {php['totals']['injection_marker_events']}; multipart structural anomalies: {php['totals']['structural_anomaly_events']}.", '', 'CVE-2026-109618 and CVE-2026-109619 observations are context only, not verified exploitation. Older CGI-family probes are tracked separately. Ordinary uploads can match the context.', '']
    if report.get('journeys'):
        j=report['journeys']
        out += ['', '## PHP engagement', '', f"Distinct captured payload hashes: {j['distinct_captured_php_payloads']}; repeat PHP source IPs: {j['repeat_php_source_ips']}; unique followed workflow markers: {j['unique_followed_markers']}.", j['scope'], '']
    out += ['', '## Analyst review before publication', '',
            'Select and verify two or three findings against preserved evidence. Add defensive lessons and a reviewed architecture diagram. These preliminary counts alone do not establish malicious intent or successful exploitation. No LinkedIn post has been published.', '']
    return '\n'.join(out)

def html(report):
    """Standalone, printable report with no scripts, external assets or raw evidence."""
    from html import escape
    def chart(title, values):
        maximum = max([int(n) for _,n in values] or [1]) or 1
        rows = ''.join('<div class="bar"><span>'+escape(str(label))+'</span><i style="width:'+str(round(100*int(n)/maximum,2))+'%"></i><b>'+str(int(n))+'</b></div>' for label,n in values)
        return '<section><h2>'+escape(title)+'</h2>'+(rows or '<p>No observations yet.</p>')+'</section>'
    charts = chart('Outside events by UTC date',[(d['day_utc'],d['events']) for d in report['daily']])
    charts += chart('Unique outside source IPs by UTC date',[(d['day_utc'],d['source_ips']) for d in report['daily']])
    charts += chart('Outside events by sensor',[(d['sensor'],d['events']) for d in report['sensors']])
    charts += chart('Traffic cohorts — exclusions visible',list(report['cohorts'].items()))
    text = markdown(report)
    formatted = []
    table_open = False
    for line in text.splitlines():
        if line.startswith('|'):
            if not table_open:
                formatted.append('<div class=table><table>');table_open=True
            cells = line.strip('|').split('|')
            if all(set(cell.strip()) <= set('-:') for cell in cells):continue
            formatted.append('<tr>'+''.join('<td>'+escape(cell.strip())+'</td>' for cell in cells)+'</tr>')
            continue
        if table_open:
            formatted.append('</table></div>');table_open=False
        if line.startswith('# '):continue
        if line.startswith('## '):formatted.append('<h2>'+escape(line[3:])+'</h2>')
        elif line.startswith('- '):formatted.append('<p class=item>• '+escape(line[2:])+'</p>')
        elif line:formatted.append('<p>'+escape(line)+'</p>')
    if table_open:formatted.append('</table></div>')
    return '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>RX1 research report</title><style>body{font:16px system-ui,sans-serif;color:#183347;background:#f4f7fa;max-width:1000px;margin:36px auto;padding:0 20px}h1,h2{color:#114e66}section{background:white;border:1px solid #ccdbe4;border-radius:12px;padding:18px;margin:20px 0}.bar{display:grid;grid-template-columns:200px minmax(0,1fr) 70px;gap:12px;align-items:center;margin:9px 0;font-size:13px}.bar i{display:block;min-height:12px;background:#167f99;border-radius:3px}.bar b{text-align:right}p{line-height:1.6}.item{font-size:14px}.table{overflow:auto}table{width:100%;border-collapse:collapse;font-size:13px}td{padding:9px;border-bottom:1px solid #dce6ed}tr:first-child{font-weight:bold}p,td{overflow-wrap:anywhere}@media(max-width:600px){.bar{grid-template-columns:110px minmax(0,1fr) 45px;font-size:11px}}@media print{body{background:white;margin:0}section{break-inside:avoid}}</style><h1>RX1 honeypot research</h1><p>Preliminary, aggregate-only observations. Review findings before publication. Save or print this page to share it.</p>'''+charts+'<section>'+''.join(formatted)+'</section></html>'
