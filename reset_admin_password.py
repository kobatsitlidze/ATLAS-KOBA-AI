"""Offline recovery. Stop ATLAS first; run as the OS account owning its data."""
import getpass, os, sys
from pathlib import Path
import atlas
if __name__ == '__main__':
    if os.name != 'nt' and hasattr(os,'geteuid') and os.geteuid() == 0:
        sys.exit('Run as the atlas service user, not root.')
    if not atlas.AUTH_FILE.exists():sys.exit('No existing auth.json; first-time setup must be done locally.')
    if input('Type RESET to replace admin password (sessions clear on restart): ').strip()!='RESET':sys.exit('Cancelled')
    p=getpass.getpass('New admin password (min 16 chars): ')
    q=getpass.getpass('Repeat: ')
    if p!=q or len(p)<16 or len(p)>256:sys.exit('Mismatch or invalid password length')
    atlas.write_auth(p)
    print('Password changed. Restart service to invalidate all active sessions.')
