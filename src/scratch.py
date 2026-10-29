"""Lifecycle-managed, bounded publisher/report scratch space. Never touches evidence."""
import os,shutil,sqlite3,sys
from pathlib import Path

KINDS={'publish','reports'}
def cleanup(state,kind):
    if kind not in KINDS:raise ValueError('Unknown scratch role')
    root=Path(state)/('scratch-'+kind)
    if root.is_symlink():raise RuntimeError('Unsafe scratch directory')
    if root.exists():
        for child in root.iterdir():
            if child.is_symlink() or not child.is_file():raise RuntimeError('Unexpected scratch entry')
            if child.name not in ('snapshot.sqlite','snapshot.sqlite-journal','snapshot.sqlite-wal','snapshot.sqlite-shm'):raise RuntimeError('Unexpected scratch file')
            child.unlink()
    else:root.mkdir(mode=0o700)
    return root

def snapshot(db,state,kind):
    root=cleanup(state,kind)
    source=Path(state)/'index.sqlite'
    required=max(2*1024**3,source.stat().st_size+512*1024**2)
    if shutil.disk_usage(state).free<required:raise RuntimeError('Insufficient scratch reserve; evidence retained')
    copy=sqlite3.connect(root/'snapshot.sqlite')
    try:db.backup(copy)
    except BaseException:copy.close();cleanup(state,kind);raise
    return copy

if __name__=='__main__':cleanup(Path(os.environ.get('HUB_STATE','/var/lib/honeypot-hub')),sys.argv[1])
