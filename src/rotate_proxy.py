"""Preservation-only proxy rotation. Originals are renamed, never truncated or deleted."""
import grp
import os
from pathlib import Path
import subprocess
import time

def rotate(log,marker,gid,reopen,threshold=16*1024*1024):
    log=Path(log);marker=Path(marker)
    if log.is_symlink():raise RuntimeError('Refusing symlink log')
    if log.exists() and log.stat().st_size>=threshold:
        marker.write_text('reopen required\n')
        target=log.with_name(log.name+'.'+str(time.time_ns()))
        if target.exists():raise RuntimeError('Rotation target already exists')
        log.rename(target)
    if not log.exists():
        marker.write_text('reopen required\n')
        fd=os.open(log,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
        os.close(fd)
    info=log.stat()
    if info.st_gid!=gid or info.st_uid!=os.getuid():os.chown(log,os.getuid(),gid)
    log.chmod(0o640)
    if marker.exists():
        reopen()
        marker.unlink()

if __name__=='__main__':
    rotate('/var/log/nginx/php-honeypot-details.jsonl','/var/lib/rx1-rotation/pending',grp.getgrnam('systemd-journal').gr_gid,
           lambda:subprocess.run(['/usr/sbin/nginx','-s','reopen'],check=True,timeout=10))
