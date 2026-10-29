"""Derived UTC clocks and page revisions; original archives are never rewritten."""
from datetime import datetime,timezone

def clock(value):
    stamp=datetime.fromisoformat(value.replace('Z','+00:00'))
    if stamp.tzinfo is None:raise ValueError('Timezone required')
    stamp=stamp.astimezone(timezone.utc)
    delta=stamp-datetime(1970,1,1,tzinfo=timezone.utc)
    return stamp.isoformat(timespec='microseconds'),(delta.days*86400+delta.seconds)*1000000+delta.microseconds

def record_clock(db,identifier,value):
    try:canonical,epoch=clock(value)
    except (ValueError,TypeError,AttributeError):return value
    db.execute('INSERT OR IGNORE INTO event_clock VALUES (?,?,?)',(identifier,canonical,epoch))
    return canonical

def initialize(db):
    db.execute('CREATE TABLE IF NOT EXISTS event_clock (id TEXT PRIMARY KEY, utc TEXT NOT NULL, epoch_us INTEGER NOT NULL)')
    db.execute('CREATE INDEX IF NOT EXISTS event_clock_epoch ON event_clock(epoch_us)')
    db.execute('CREATE TABLE IF NOT EXISTS event_page_versions (page INTEGER PRIMARY KEY, revision INTEGER NOT NULL)')
    for operation,reference in [('INSERT','NEW'),('UPDATE','NEW'),('DELETE','OLD')]:
        db.execute(f'''CREATE TRIGGER IF NOT EXISTS render_events_{operation.lower()} AFTER {operation} ON events BEGIN
          INSERT INTO event_page_versions VALUES (({reference}.rowid-1)/500,1)
          ON CONFLICT(page) DO UPDATE SET revision=revision+1;
        END''')
    for operation,reference in [('INSERT','NEW'),('UPDATE','NEW'),('DELETE','OLD')]:
        db.execute(f'''CREATE TRIGGER IF NOT EXISTS render_proxy_{operation.lower()} AFTER {operation} ON proxy_observations BEGIN
          INSERT INTO event_page_versions
          SELECT (rowid-1)/500,1 FROM events WHERE json_extract(data,'$.simulation.request_id')={reference}.upstream_request_id AND {reference}.upstream_request_id NOT IN ('','-')
          GROUP BY (rowid-1)/500
          ON CONFLICT(page) DO UPDATE SET revision=revision+1;
        END''')
    if not db.execute("SELECT 1 FROM meta WHERE key='canonical-index-v1'").fetchone():
        for identifier,value in db.execute('SELECT id,time FROM events').fetchall():
            canonical=record_clock(db,identifier,value)
            if canonical!=value:db.execute('UPDATE events SET time=? WHERE id=?',(canonical,identifier))
        db.execute('INSERT OR IGNORE INTO event_page_versions SELECT (rowid-1)/500,1 FROM events GROUP BY (rowid-1)/500')
        db.execute("INSERT INTO meta VALUES ('canonical-index-v1','complete')")
        db.commit()
