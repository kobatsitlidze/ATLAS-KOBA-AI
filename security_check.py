"""Read-only local security checks for ATLAS 4.8. Never changes user data."""
from pathlib import Path
import os, json, sqlite3, hashlib, sys
DATA=Path(os.environ.get('LOCALAPPDATA',str(Path.home()))) / 'ATLAS' / 'data'
DB=DATA/'atlas_data.sqlite3'; AUTH=DATA/'auth.json'
print('ATLAS & KOBA 4.8 — SECURITY CHECK (READ ONLY)')
issues=[]
if DB.exists():
 try:
  with sqlite3.connect(f'file:{DB.as_posix()}?mode=ro',uri=True) as c:
   integrity=c.execute('PRAGMA integrity_check').fetchone()[0]
  print('DATABASE:', 'OK' if integrity=='ok' else 'FAILED')
  if integrity!='ok':issues.append('database integrity')
 except Exception as e:print('DATABASE ERROR:',type(e).__name__);issues.append('database access')
else:print('DATABASE: NOT FOUND');issues.append('database missing')
if AUTH.exists():
 try:
  obj=json.loads(AUTH.read_text(encoding='utf-8'))
  valid=obj.get('username')=='admin' and ':' in obj.get('password_hash','') and 'password' not in obj
  print('AUTH FILE:', 'OK (password hash present)' if valid else 'CHECK REQUIRED')
  if not valid:issues.append('authentication format')
 except Exception:print('AUTH FILE: INVALID');issues.append('auth file')
else:print('AUTH FILE: NOT FOUND');issues.append('auth missing')
print('LOCAL NETWORK: HTTP ONLY — DO NOT EXPOSE TO INTERNET')
print('SERVER HTTPS: NOT CONFIGURED (requires separate deployment)')
print('RESULT:', 'LOCAL CHECK OK' if not issues else 'REVIEW: '+', '.join(issues))
print('DATABASE UNCHANGED; AUTH UNCHANGED')
sys.exit(0 if not issues else 1)
