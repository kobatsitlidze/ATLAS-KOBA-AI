"""Manual verified SQLite export; never modifies the live ATLAS database."""
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DATA = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'ATLAS' / 'data'
SOURCE = DATA / 'atlas_data.sqlite3'
DEST = Path.home() / 'Documents' / 'ATLAS_EXPORTS'

def main():
    if not SOURCE.is_file():
        raise SystemExit('ATLAS database not found. No changes made: ' + str(SOURCE))
    DEST.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    target = DEST / ('atlas_backup_' + timestamp + '.sqlite3')
    try:
        with sqlite3.connect(f'file:{SOURCE.as_posix()}?mode=ro', uri=True, timeout=20) as source:
            with sqlite3.connect(target) as output:
                source.backup(output)
        with sqlite3.connect(f'file:{target.as_posix()}?mode=ro', uri=True) as check:
            result = check.execute('PRAGMA integrity_check').fetchone()[0]
            tables = {row[0] for row in check.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if result != 'ok' or not {'hotels', 'daily', 'plans', 'audit'} <= tables:
            raise RuntimeError('Backup integrity or required tables check failed')
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        manifest = {'created_utc': datetime.now(timezone.utc).isoformat(), 'filename': target.name,
                    'bytes': target.stat().st_size, 'sha256': digest,
                    'integrity_check': result, 'tables': sorted(tables),
                    'note': 'PRIVATE hotel data. Do not upload publicly.'}
        (DEST / (target.name + '.json')).write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
        print('BACKUP OK:', target)
        print('SHA256:', digest)
        print('Source database unchanged.')
    except Exception:
        target.unlink(missing_ok=True)
        raise

if __name__ == '__main__':
    main()
