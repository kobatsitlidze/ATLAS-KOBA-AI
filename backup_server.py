"""Consistent verified SQLite snapshot. Does not change source DB."""
import sqlite3,hashlib,json,os
from datetime import datetime,timezone
from pathlib import Path
from contextlib import closing
import atlas
source=atlas.DB;dest=atlas.BACKUP_DIR
if not source.exists():raise SystemExit('Database missing; refusing to create an empty DB')
dest.mkdir(parents=True,exist_ok=True)
target=dest/('atlas_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.sqlite3')
with closing(sqlite3.connect(f'file:{source.as_posix()}?mode=ro',uri=True)) as a,closing(sqlite3.connect(target)) as b:a.backup(b)
with closing(sqlite3.connect(target)) as c:
 if c.execute('pragma integrity_check').fetchone()[0]!='ok':target.unlink();raise SystemExit('INTEGRITY ERROR')
sha=hashlib.sha256(target.read_bytes()).hexdigest()
(target.with_suffix('.sha256')).write_text(sha+'  '+target.name+'\n')
os.chmod(target,0o600)
print('BACKUP OK',target,'SHA256',sha,'\nCOPY THIS ENCRYPTED OFF THE SERVER using a separate backup system.')
