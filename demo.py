"""Start a loopback-only demo using synthetic data and isolated local state."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
SRC = ROOT / 'src'
STATE = ROOT / 'state'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dashboard-port', type=int, default=9090)
    args = parser.parse_args()
    if not 1024 <= args.dashboard_port <= 65535 or args.dashboard_port in (8080, 8081, 8082, 8083):
        parser.error('Choose a dashboard port from 1024–65535, excluding 8080–8083.')
    ports = (8080, 8081, 8082, 8083, args.dashboard_port)
    for port in ports:
        with socket.socket() as check:
            try:
                check.bind(('127.0.0.1', port))
            except OSError:
                raise SystemExit(f'Local port {port} is in use. Stop the conflicting service and retry.')
    os.umask(0o077)
    STATE.mkdir(mode=0o700, exist_ok=True)
    env = {**os.environ, 'PYTHONPATH': str(SRC), 'HUB_STATE': str(STATE),
           'RX1_PUBLIC_DIR': str(STATE / 'public'), 'RX1_BIND': '127.0.0.1', 'RX1_PORT': str(args.dashboard_port)}
    for name in ('CREDENTIALS_DIRECTORY', 'RX1_TLS', 'RX1_PROXY_LOG', 'HUB_ASYNC_REPORTS'):
        env.pop(name, None)
    events = [
        {'time': datetime.now(timezone.utc).isoformat(), 'ip': '8.8.8.8', 'method': 'GET',
         'path': path, 'service': 'portal', 'headers': {'User-Agent': 'HoneyStudy synthetic demo'}}
        for path in ('/', '/docs/', '/wp-login.php')
    ]
    fixture = STATE / 'demo.jsonl'
    fixture.write_text('\n'.join(json.dumps(event) for event in events) + '\n')
    subprocess.run([sys.executable, str(SRC / 'collector.py'), '--state', str(STATE),
                    '--import-log', str(fixture)], env=env, check=True)
    (STATE / 'public' / 'world.json').write_text((SRC / 'world.json').read_text())
    children, logs = [], []
    commands = [('portal', ['portal_app.py']), ('registry', ['decoy.py', 'registry']),
                ('cms', ['decoy.py', 'cms']), ('api', ['decoy.py', 'api']), ('dashboard', ['serve.py'])]
    def stop(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        for name, command_args in commands:
            log = (STATE / f'{name}.log').open('a')
            logs.append(log)
            children.append(subprocess.Popen([sys.executable, '-u', str(SRC / command_args[0]), *command_args[1:]],
                                              cwd=SRC, env=env, stdout=log, stderr=log))
        print(f'HoneyStudy demo: http://127.0.0.1:{args.dashboard_port}', flush=True)
        print('Synthetic dashboard data. Decoys: loopback ports 8080–8083. Ctrl+C to stop.', flush=True)
        while True:
            for child in children:
                if child.poll() is not None:
                    raise RuntimeError('A demo service stopped. See state/*.log for details.')
            try:
                children[0].wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
    except KeyboardInterrupt:
        pass
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        for log in logs:
            log.close()

if __name__ == '__main__':
    main()
