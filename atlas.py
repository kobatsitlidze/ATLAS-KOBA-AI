import socket
import ipaddress
import csv, io, json, sqlite3, threading, webbrowser, os, sys, tempfile, shutil, time, re, math, secrets, hmac, hashlib, base64
from datetime import date, datetime, timedelta
from decimal import Decimal
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from contextlib import closing
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

ROOT=Path(__file__).resolve().parent
DATA_DIR=Path(os.environ.get('ATLAS_DATA_DIR', str(Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'ATLAS' / 'data')))
BACKUP_DIR=Path(os.environ.get('ATLAS_BACKUP_DIR', str(Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'ATLAS' / 'backups')))
DB=DATA_DIR/'atlas_data.sqlite3'
AUTH_FILE=DATA_DIR/'auth.json'
SESSIONS={}
FAILED={}
AUTH_LOCK=threading.Lock()

def password_hash(password,salt=None):
    salt=salt or secrets.token_bytes(16)
    derived=hashlib.scrypt(password.encode('utf-8'),salt=salt,n=2**14,r=8,p=1,dklen=32)
    return base64.b64encode(salt).decode()+':'+base64.b64encode(derived).decode()

def valid_password(password,stored):
    try:
        salt_b64,digest_b64=stored.split(':',1)
        expected=base64.b64decode(digest_b64,validate=True)
        salt=base64.b64decode(salt_b64,validate=True)
        actual=hashlib.scrypt(password.encode('utf-8'),salt=salt,n=2**14,r=8,p=1,dklen=32)
        return hmac.compare_digest(actual,expected)
    except (ValueError,TypeError):return False

def write_auth(password):
    DATA_DIR.mkdir(parents=True,exist_ok=True)
    payload=json.dumps({'version':1,'username':'admin','password_hash':password_hash(password)})
    fd,path=tempfile.mkstemp(prefix='auth_',dir=DATA_DIR)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f:f.write(payload)
        os.replace(path,AUTH_FILE)
        try:os.chmod(AUTH_FILE,0o600)
        except OSError:pass
    finally:
        if os.path.exists(path):os.unlink(path)

LOGIN_HTML="""<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ATLAS & KOBA 4.9 — Вход</title><style>body{font:16px Arial,sans-serif;background:#0e211c;color:#f6edda;min-height:100vh;display:grid;place-items:center;margin:0}main{box-sizing:border-box;background:#18362d;padding:32px;border-radius:16px;width:min(92vw,410px);border:1px solid #a88b52}h1{font-size:26px}label{display:block;margin-top:16px}input{box-sizing:border-box;width:100%;padding:13px;margin-top:6px;border-radius:8px;border:1px solid #777;font-size:17px}button{width:100%;padding:13px;margin-top:22px;background:#d8b46c;color:#14271e;border:0;border-radius:8px;font-weight:bold;font-size:16px}small{color:#d5cdb8}#msg{color:#ffb7a9;min-height:20px}</style><main><h1>ATLAS &amp; KOBA <span style="color:#d8b46c">4.9</span></h1><p id="heading">Вход в систему</p><form id="f"><label>Логин<input name="username" value="admin" autocomplete="username" required></label><label>Пароль<input name="password" type="password" autocomplete="current-password" minlength="12" required></label><button id="submit">Войти</button></form><p id="msg" role="alert"></p><small>Локальная версия. Не открывайте порт в интернете.</small></main><script>const setup=SETUP_MODE;const heading=document.getElementById('heading');const btn=document.getElementById('submit');if(setup){heading.textContent='Первый запуск: создайте пароль (минимум 12 символов)';btn.textContent='Создать пароль';}document.getElementById('f').onsubmit=async e=>{e.preventDefault();const f=e.target;btn.disabled=true;try{const r=await fetch(setup?'/auth/setup':'/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:f.elements.namedItem('username').value,password:f.elements.namedItem('password').value})});const data=await r.json();if(!r.ok)throw Error(data.error||'Ошибка');location.href='/';}catch(err){document.getElementById('msg').textContent=err.message;}finally{btn.disabled=false;}};</script></html>"""



def verify(path):
    try:
        with closing(sqlite3.connect(f'file:{path.as_posix()}?mode=ro',uri=True)) as c:
            if c.execute('PRAGMA integrity_check').fetchone()[0]!='ok':return False
            tables={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            return {'hotels','daily','plans','audit'}<=tables
    except (sqlite3.Error,OSError):return False

def backup(tag='startup'):
    BACKUP_DIR.mkdir(parents=True,exist_ok=True)
    stamp=datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    dest=BACKUP_DIR/f'atlas_{tag}_{stamp}.sqlite3'
    with closing(sqlite3.connect(DB,timeout=15)) as source, closing(sqlite3.connect(dest)) as target:
        source.backup(target)
    if not verify(dest):
        dest.unlink(missing_ok=True)
        raise RuntimeError('Резервная копия не прошла проверку целостности')
    return dest

def bootstrap():
    DATA_DIR.mkdir(parents=True,exist_ok=True)
    BACKUP_DIR.mkdir(parents=True,exist_ok=True)
    if DB.exists():
        if not verify(DB):raise RuntimeError(f'Рабочая база повреждена: {DB}. Запуск остановлен; резервные копии не затронуты.')
        return 'Обнаружена постоянная база ATLAS'
    # One-time migration: find a previous installation near the new extracted folder.
    candidates=[]
    for parent in [ROOT,ROOT.parent,ROOT.parent.parent]:
        if not parent.exists():continue
        try:
            for folder in parent.iterdir():
                if not folder.is_dir() or folder==DATA_DIR:continue
                if 'atlas' not in folder.name.lower():continue
                for candidate in (folder/'atlas_data.sqlite3',folder/'ATLAS_3_2'/'atlas_data.sqlite3',folder/'ATLAS_3_1'/'atlas_data.sqlite3'):
                    if candidate.is_file() and candidate.resolve()!=DB.resolve() and verify(candidate):
                        candidates.append(candidate)
        except (OSError,PermissionError):pass
    candidates=list(dict.fromkeys(candidates))
    if candidates:
        # Do not silently choose between different databases.
        if len(candidates)>1:
            raise RuntimeError('Найдено несколько баз ATLAS. Для безопасного переноса выберите нужную через IMPORT_DATABASE.bat.\n'+'\n'.join(map(str,candidates)))
        migrate(candidates[0]);return f'История безопасно перенесена из {candidates[0]}'
    raise RuntimeError('База ATLAS не найдена. Запустите IMPORT_DATABASE.bat и выберите atlas_data.sqlite3 из ATLAS 3.2. Новая пустая база НЕ создана.')

def migrate(source):
    if DB.exists():
        raise RuntimeError('Постоянная база уже существует; импорт остановлен во избежание перезаписи')
    if not verify(source):
        raise RuntimeError('Выбранная база не прошла проверку')
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    # Unique temporary filename avoids any stale pending database from earlier attempts.
    import uuid
    tmp = DATA_DIR / f'atlas_import_{uuid.uuid4().hex}.sqlite3'
    try:
        # sqlite3.Connection context managers COMMIT but DO NOT CLOSE connections.
        # Explicit closing is required on Windows before replacing the database file.
        with closing(sqlite3.connect(f'file:{source.as_posix()}?mode=ro', uri=True)) as src:
            with closing(sqlite3.connect(tmp)) as dst:
                src.backup(dst)
        if not verify(tmp):
            raise RuntimeError('Копия не прошла проверку')
        tmp.replace(DB)
        backup('migration')
    finally:
        tmp.unlink(missing_ok=True)


def connect():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;c.execute('PRAGMA foreign_keys=ON');return c

def setup():
 with connect() as c:
  c.executescript('''CREATE TABLE IF NOT EXISTS hotels(id INTEGER PRIMARY KEY,name TEXT NOT NULL UNIQUE,rooms INTEGER NOT NULL CHECK(rooms>0));
  CREATE TABLE IF NOT EXISTS daily(id INTEGER PRIMARY KEY,hotel_id INTEGER NOT NULL REFERENCES hotels(id),day TEXT NOT NULL,available INTEGER NOT NULL CHECK(available>=0),sold INTEGER NOT NULL CHECK(sold>=0 AND sold<=available),revenue REAL NOT NULL CHECK(revenue>=0),source TEXT NOT NULL DEFAULT 'Ручной ввод',updated_at TEXT NOT NULL,UNIQUE(hotel_id,day));
  CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,hotel_id INTEGER,day TEXT,old_data TEXT,new_data TEXT,changed_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS plans(id INTEGER PRIMARY KEY,hotel_id INTEGER NOT NULL REFERENCES hotels(id),start TEXT NOT NULL,end TEXT NOT NULL,target REAL NOT NULL CHECK(target>=0),created_at TEXT NOT NULL);
  INSERT OR IGNORE INTO hotels(name,rooms) VALUES('Magnolia (настройте название)',49);''')

def q(v):return round(v,2)
def summary(rows):
 av=sum(r['available'] for r in rows);sold=sum(r['sold'] for r in rows);rev=sum(r['revenue'] for r in rows)
 return {'available':av,'sold':sold,'revenue':q(rev),'occupancy':q(sold/av*100) if av else None,'adr':q(rev/sold) if sold else None,'revpar':q(rev/av) if av else None,'days_recorded':len(rows)}


# Local multilingual rule-based report parser; no network or AI API.
# Each candidate must be adjacent to its metric label or match a known sentence pattern.
NUMBER = r"(?:\d{1,3}(?:[ \u00a0\u202f,]\d{3})+(?:\.\d{1,2})?|\d+(?:[.,]\d{1,2})?)"

def parse_report_text(message, thresholds):
    if not isinstance(message,str) or not message.strip():
        raise ValueError('Вставьте текст письма')
    if len(message)>30000:
        raise ValueError('Текст слишком длинный (максимум 30000 символов)')
    t=re.sub(r'[\u00a0\u202f]', ' ', message)
    # Pattern order is important: explicit room revenue is preferred to generic turnover.
    def pick(patterns):
        for pat in patterns:
            m=re.search(pat,t,re.I|re.U)
            if not m:continue
            raw=m.group('v').replace(' ','')
            raw=(raw.replace(',','') if re.fullmatch(r'\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?',raw) else raw.replace(',','.'))
            try:
                val=float(raw)
                if math.isfinite(val) and 0<=val<1e12:return val
            except ValueError:pass
        return None
    n=r'(?P<v>'+NUMBER+r')'
    sep=r'(?:\s|[:=]|-|–|—){0,5}'
    # English and Georgian variants include common inflections and word order.
    sold=pick([
        r'(?:продал[аио]?|продано|проданных|реализовано|занято|заселено|გავყიდეთ|გაიყიდა|გაყიდულია|დაიჯავშნა|დაკავებულია|sold|booked|occupied)\s*(?:было|вчера|номеров|номеро.?ночей|ოთახი|ნომერი|rooms?|room nights?|[:=]){0,3}\s*'+n,
        r'(?:продаж[аи]?|გაყიდული\s+ნომრების\s+რაოდენობა|rooms?\s+sold|sold\s+rooms?|occupied\s+rooms?|booked\s+rooms?)'+sep+n,
        n+r'\s*(?:проданных|продано|გაყიდული|გაიყიდა|sold|booked|occupied)\s*(?:номеров|ნომერი|ოთახი|rooms?)?',
        n+r'\s*(?:номеров|номера|ნომერი|ნომრები|ოთახი|ოთახები|rooms?|room nights?)\s*(?:продано|продали|გავყიდეთ|გაიყიდა|sold|booked|occupied)',
        r'(?:we\s+)?(?:sold|booked|occupied|checked\s+in)\s+'+n+r'\s*(?:rooms?|room[- ]nights?)?',
        r'(?:გაყიდულია|დაჯავშნილია|გაიყიდა|დაკავებულია)\s*'+n+r'\s*(?:ნომერი|ნომრები|ოთახი|ოთახები)?',
        n+r'\s*(?:ნომერი|ნომრები|ოთახი|ოთახები)\s*(?:გაიყიდა|გავყიდეთ|დაიჯავშნა|დაკავებულია)',
    ])
    available=pick([
        r'(?:из|всего|доступно|номерной\s+фонд|в\s+наличии|დან|სულ|ხელმისაწვდომია|ხელმისაწვდომი|ჯამში|of|out\s+of|total\s+rooms?|available\s+rooms?|inventory|capacity)\s*(?:номеров|номера|ნომერი|ნომრები|ოთახი|ოთახები|rooms?|[:=]){0,3}\s*'+n,
        n+r'\s*(?:-\s*დან|დამ|დანი|დоступных|доступно|ხელმისაწვდომი|available)\s*(?:номеров|ნომერი|ოთახი|rooms?)?',
        r'(?:номеров|номера|ნომრები|ოთახები|rooms?)\s*(?:всего|доступно|სულ|ხელმისაწვდომია|total|available)'+sep+n,
        n+r'\s*(?:номеров|номера|ნომერი|ნომრები|ოთახი|ოთახები|rooms?)\s*(?:доступно|доступных|ხელმისაწვდომი|available)',
        r'(?:out\s+of|of|from|დან|დან\s+სულ)\s*'+n+r'\s*(?:available\s+)?(?:rooms?|ნომერი|ნომრები|ოთახი|ოთახები)?',
        r'(?:we\s+have|hotel\s+has|სასტუმროში\s+არის|სულ\s+გვაქვს)\s*'+n+r'\s*(?:available\s+)?(?:rooms?|ნომერი|ნომრები|ოთახი|ოთახები)',
    ])
    revenue=pick([
        r'(?:выручка\s+от\s+(?:проживания|номеров)|доход\s+от\s+(?:проживания|номеров)|ნომრებიდან\s+მიღებულმა\s+შემოსავალმა|ოთახებიდან\s+შემოსავალმა|room\s+revenue|rooms?\s+revenue|accommodation\s+revenue)\s*(?:составил[а-я]*|был[ао]?|равн[ао]?|შეადგინა|არის|was|is|amounted\s+to|totaled|totalled|[:=]){0,3}\s*'+n,
        r'(?:общая\s+выручка|выручка|доход|შემოსავალი|ამონაგები|revenue|income|turnover)\s*(?:от\s+проживания|от\s+номеров|სულ|ჯამში|შეადგინა|составил[а-я]*|был[ао]?|равн[ао]?|amounted\s+to|totaled|totalled|was|is|[:=]){0,5}\s*'+n,
        n+r'\s*(?:GEL|лари|ლარი|₾)\s*(?:выручк[аи]|შემოსავალი|revenue)',
        # Georgian inflections: ნომრების შემოსავალმა შეადგინა 5 250 ლარი;
        # ნომრებიდან მიღებულმა შემოსავალმა ...; დღიურმა შემოსავალმა ...
        r'(?:ნომრების|ნომრებიდან|ოთახების|ოთახებიდან|სასტუმროს|საერთო|ჯამურმა|დღიურმა|მთლიანმა)?\s*(?:მიღებულმა\s+)?(?:შემოსავალმა|შემოსავალმა|შემოსავალი|ამონაგებმა|ამონაგები)\s*(?:(?:შეადგინა|შეადგენს|იყო|არის|გახლდათ|მიაღწია|დაფიქსირდა|ჯამში|სულ|დაახლოებით|[:=])\s*){0,4}'+n+r'\s*(?:GEL|ლარი|₾)?',
        r'(?:ნომრების|ნომრებიდან|ოთახების|ოთახებიდან)\s+(?:მიღებული\s+)?(?:შემოსავალი|ამონაგები)\s*(?:იყო|შეადგინა|არის|[:=])?\s*'+n,
        # English: room revenue amounted to 5,250 GEL; we generated 5250 GEL in room revenue.
        r'(?:total\s+)?(?:room|rooms|hotel|accommodation|lodging)?\s*(?:revenue|income|sales|takings|earnings)\s*(?:(?:from\s+(?:rooms?|accommodation|lodging)|amounted\s+to|total(?:ed|led)?|came\s+to|was|were|is|of|reached|generated|[:=])\s*){0,4}'+n+r'\s*(?:GEL|lari|₾)?',
        r'(?:generated|earned|made|brought\s+in|received)\s*'+n+r'\s*(?:GEL|lari|₾)?\s*(?:in|from|of)?\s*(?:room|rooms|accommodation|hotel)?\s*(?:revenue|income|sales)',
        r'(?:выручка|доход)\s*(?:от\s+(?:номеров|проживания))?\s*(?:составила|составил|была|был|[:=])?\s*'+n,
    ])
    adr=pick([
        r'\bADR\b'+sep+r'(?:составил|равен|შეადგინა|was|is)?\s*'+n,
        r'(?:средняя\s+(?:цена|стоимость)\s+номера|საშუალო\s+(?:ფასი|ტარიფი)|average\s+(?:daily\s+)?(?:room\s+)?rate)\s*(?:составила|შეადგინა|was|is|[:=])?\s*'+n,
    ])
    revpar=pick([r'\bRevPAR\b'+sep+r'(?:составил|равен|შეადგინა|was|is)?\s*'+n])
    occupancy=pick([
        r'(?:загрузка|загруженность|დატვირთვა|დაკავებულობა|occupancy)\s*(?:составил[а-я]*|была|равна|შეადგინა|was|is|rate|[:=]){0,2}\s*'+n+r'\s*%',
    ])
    values={'sold':sold,'available':available,'revenue':revenue,'adr_reported':adr,'revpar_reported':revpar,'occupancy_reported':occupancy}
    warnings=[]
    if sold is not None and not sold.is_integer():warnings.append('Проданные номера должны быть целым числом')
    if available is not None and not available.is_integer():warnings.append('Доступные номера должны быть целым числом')
    if sold is not None and available is not None and sold>available:warnings.append('Продано больше номеров, чем доступно — проверьте исходное письмо')
    if occupancy is not None and occupancy>100:warnings.append('Загрузка в письме больше 100% — проверьте данные')
    if revenue is not None and sold is not None and sold>0:values['adr_calculated']=round(revenue/sold,2)
    if revenue is not None and available is not None and available>0:values['revpar_calculated']=round(revenue/available,2)
    if sold is not None and available is not None and available>0 and sold<=available:values['occupancy_calculated']=round(100*sold/available,2)
    for key in ('adr','revpar','occupancy'):
        stated=values.get(key+'_reported');computed=values.get(key+'_calculated')
        if stated is not None and computed is not None and abs(stated-computed)>max(0.5,0.02*computed):
            warnings.append(f'{key.upper()}: в письме {stated:g}, по расчёту {computed:g}; проверьте данные')
    occ=values.get('occupancy_calculated')
    if occ is None:occ=occupancy
    actual_adr=values.get('adr_calculated')
    if actual_adr is None:actual_adr=adr
    low=float(thresholds.get('occupancy_low',50));high=float(thresholds.get('occupancy_good',75));target=float(thresholds.get('adr_target',150))
    if not (0<=low<high<=100 and target>0):raise ValueError('Проверьте пороги: низкая < хорошей загрузки; план ADR > 0')
    evaluation=[]
    if occ is not None:
        evaluation.append('Загрузка: '+('низкая' if occ<low else 'средняя' if occ<high else 'хорошая')+f' ({occ:g}%).')
    if actual_adr is not None:
        gap=round((actual_adr/target-1)*100,1)
        evaluation.append(f'ADR {actual_adr:g} GEL; план {target:g} GEL; отклонение {gap:+g}%.')
        if gap<0:evaluation.append('Рекомендуется проверить тарифы, скидки и долю групповых бронирований.')
    if not evaluation:evaluation.append('Недостаточно показателей для оценки: запросите выручку, проданные и доступные номера.')
    missing=[label for key,label in [('sold','проданные номера'),('available','доступные номера'),('revenue','выручку')] if values.get(key) is None]
    if missing:evaluation.append('Для полного расчёта уточните: '+', '.join(missing)+'.')
    if warnings:evaluation.append('Есть расхождения: сначала уточните исходные цифры.')
    reply='Добрый день!\n\nБлагодарю за предоставленную информацию.\n\n'+'\n'.join(evaluation)+'\n\nПрошу уточнить причины отклонений и предложить корректирующие действия.\n\nС уважением,\nКоба'
    language=thresholds.get('language','ru')
    if language in ('en','ka'):
        local=[]
        for item in evaluation:
            if item.startswith('Загрузка: '):
                state=('low' if occ<low else 'medium' if occ<high else 'good')
                state_text={'en':{'low':'low','medium':'medium','good':'good'},'ka':{'low':'დაბალი','medium':'საშუალო','good':'კარგი'}}[language][state]
                local.append((f'Occupancy: {state_text} ({occ:g}%).' if language=='en' else f'დატვირთულობა: {state_text} ({occ:g}%).'))
            elif item.startswith('ADR ') and actual_adr is not None:
                gap=round((actual_adr/target-1)*100,1)
                local.append((f'ADR {actual_adr:g} GEL; target {target:g} GEL; variance {gap:+g}%.' if language=='en' else f'ADR {actual_adr:g} GEL; გეგმა {target:g} GEL; გადახრა {gap:+g}%.'))
            elif item.startswith('Рекомендуется проверить'):
                local.append('Review room rates, discounts and the share of group bookings.' if language=='en' else 'შეამოწმეთ ნომრების ტარიფები, ფასდაკლებები და ჯგუფური ჯავშნების წილი.')
            elif item.startswith('Недостаточно показателей'):
                local.append('Insufficient information: request revenue, rooms sold and available rooms.' if language=='en' else 'მონაცემები არასაკმარისია: მოითხოვეთ შემოსავალი, გაყიდული და ხელმისაწვდომი ნომრების რაოდენობა.')
            elif item.startswith('Для полного расчёта'):
                labels={'проданные номера':('rooms sold','გაყიდული ნომრები'),'доступные номера':('available rooms','ხელმისაწვდომი ნომრები'),'выручку':('revenue','შემოსავალი')}
                names=[labels[k][0 if language=='en' else 1] for k in [k for key,k in [('sold','проданные номера'),('available','доступные номера'),('revenue','выручку')] if values.get(key) is None]]
                local.append(('For complete calculations, clarify: ' if language=='en' else 'სრული გაანგარიშებისთვის დააზუსტეთ: ')+', '.join(names)+'.')
            elif item.startswith('Есть расхождения'):
                local.append('Discrepancies detected: verify the original figures first.' if language=='en' else 'აღმოჩენილია შეუსაბამობები: ჯერ გადაამოწმეთ საწყისი მონაცემები.')
            else:local.append(item)
        evaluation=local
        if language=='en':
            reply='Good day!\n\nThank you for the report.\n\n'+'\n'.join(evaluation)+'\n\nPlease investigate any deviations and propose corrective actions.\n\nBest regards,\nKoba'
        else:
            reply='გამარჯობა!\n\nგმადლობთ მოწოდებული ანგარიშისთვის.\n\n'+'\n'.join(evaluation)+'\n\nგთხოვთ შეისწავლოთ გადახრების მიზეზები და შემოგვთავაზოთ გამოსასწორებელი ღონისძიებები.\n\nპატივისცემით,\nკობა'
    return {'values':values,'warnings':warnings,'evaluation':evaluation,'draft':reply,'note':'Rule-based preliminary analysis (RU / KA / EN). The message is not sent or saved automatically.' if language=='en' else 'წესებზე დაფუძნებული წინასწარი ანალიზი (RU / KA / EN). წერილი ავტომატურად არ იგზავნება და არ ინახება.' if language=='ka' else 'Предварительный анализ по правилам (RU / KA / EN). Текст не отправляется и не сохраняется автоматически.'}

# ATLAS 4.0: deterministic local text analysis; no Ollama, network, or API required.
def ai_status():
    return {'ready': True, 'model': 'ATLAS Local Rules 4.0', 'installed': [],
            'message': 'Локальный анализ доступен без AI-модели'}

def analyze_ai_email(message, thresholds):
    if not isinstance(message, str) or not message.strip():
        raise ValueError('Вставьте текст письма')
    if len(message) > 12000:
        raise ValueError('Слишком длинное письмо (максимум 12000 символов)')
    return parse_report_text(message, thresholds)

HTML=r'''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ATLAS &amp; KOBA 4.8 SECURITY PREP</title><style>
:root{font-family:Segoe UI,Arial,sans-serif;color:#e8f3ed;background:#071c18}*{box-sizing:border-box}body{margin:0}header{background:#0c2a22;padding:22px max(18px,calc((100vw - 1120px)/2));border-bottom:1px solid #30445f}h1{margin:0;font-size:28px;letter-spacing:2px}small,.muted{color:#a8b7cf}main{max-width:1120px;margin:22px auto;padding:0 16px}.panel{background:#103026;border:1px solid #365447;border-radius:14px;padding:20px;margin-bottom:18px}h2{margin:0 0 15px;font-size:20px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:12px}.kpi{background:#194034;border-radius:10px;padding:15px}.kpi b{font-size:23px;display:block;margin-top:8px;color:#e2c17e}label{display:flex;flex-direction:column;gap:6px;color:#b9c9df;font-size:13px}input,select,button{font:inherit;border-radius:8px;padding:10px;border:1px solid #526682;background:#09251e;color:#fff;min-width:0}button{background:#94743b;border:0;cursor:pointer;font-weight:600}button:hover{background:#b29252}.fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px;align-items:end}.note{background:#15392e;border-left:3px solid #64b4ff;padding:12px;border-radius:5px;margin-top:12px}table{width:100%;border-collapse:collapse;font-size:14px}td,th{padding:9px;border-bottom:1px solid #314561;text-align:left}th{color:#a8c7e9}.scroll{overflow-x:auto}.error{color:#ff9d9d}.success{color:#9ce0b4}.tag{color:#ffd78b}nav{display:flex;gap:9px;flex-wrap:wrap;margin:15px 0}nav a{color:#b7d7ff;text-decoration:none;background:#194034;padding:8px 12px;border-radius:7px}@media(max-width:600px){header{padding:18px}h1{font-size:23px}}
.bartrack{height:12px;border-radius:8px;background:#09251e;overflow:hidden;margin-top:8px}.barfill{height:100%;background:#64b4ff}.warn{color:#ffd78b}.good{color:#9ce0b4}.sub{font-size:12px;color:#a8b7cf;margin-top:5px}
.brand{display:flex;align-items:center;gap:22px;max-width:1120px;margin:auto}.brandlogo{width:118px;height:118px;object-fit:cover;object-position:center;border-radius:18px;border:1px solid #6c5935;box-shadow:0 0 30px #b6924933}.brand h1{font-size:clamp(23px,3vw,34px);background:linear-gradient(95deg,#f5dc9b,#b18a48,#69ba9a);-webkit-background-clip:text;background-clip:text;color:transparent}.brand small{letter-spacing:1.3px;color:#ddc58b}.panel{box-shadow:0 7px 30px #0003}button{background:linear-gradient(120deg,#9a7537,#c59d56);color:#fff}.kpi{border:1px solid #315b48}@media(max-width:600px){.brandlogo{width:76px;height:76px}.brand{gap:12px}}
.language-switch{display:flex;gap:6px;margin-left:auto;align-self:flex-start;flex-wrap:wrap}.langbtn{background:#16382d;border:1px solid #7e6c42;padding:9px;font-size:13px}.langbtn.active{background:#a8813f;outline:2px solid #e1c47e}.langbtn span{font-weight:700}.brand{flex-wrap:wrap}@media(max-width:600px){.language-switch{margin-left:0;width:100%}.langbtn{flex:1}}
/* ATLAS 4.3: responsive mobile layout; no external dependencies */
html{scroll-behavior:smooth;-webkit-text-size-adjust:100%}
body{min-width:0;overflow-x:hidden}
main,section,.panel,.fields,.grid,.brand{min-width:0}
button,input,select,textarea{max-width:100%}
button,a,input,select{touch-action:manipulation}
button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:3px solid #f1ce84;outline-offset:2px}
.scroll{max-width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch}
.scroll table{min-width:650px}
nav a{min-height:44px;display:inline-flex;align-items:center}
@media(max-width:720px){
 header{padding:12px 14px 16px}
 main{margin:12px auto;padding:0 10px}
 .panel{padding:14px;margin-bottom:12px;border-radius:12px}
 .brand{gap:10px}
 .brandlogo{width:54px;height:54px;border-radius:10px}
 .brand h1{font-size:19px;letter-spacing:.3px}
 .brand small{font-size:9px;letter-spacing:0;overflow-wrap:anywhere}
 .language-switch{width:100%;margin:4px 0 0}
 .langbtn{min-height:44px}
 .fields{grid-template-columns:1fr}
 .grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
 .kpi{padding:10px;overflow-wrap:anywhere}
 .kpi b{font-size:20px}
 h2{font-size:18px}
 input,select,textarea{font-size:16px!important;min-height:44px}
 button{min-height:44px}
 .fields>button{width:100%}
 nav{display:flex;flex-wrap:nowrap;overflow-x:auto;scroll-snap-type:x proximity;padding-bottom:8px}
 nav a{flex:0 0 auto;scroll-snap-align:start;white-space:nowrap}
 #revenueChart{overflow-x:auto}
}
@media(max-width:360px){.grid{grid-template-columns:1fr}.brand h1{font-size:17px}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
</style><header><div class="brand"><img class="brandlogo" src="/logo.png" alt="Золотая A с глобусом — ATLAS & KOBA"><div><h1>ATLAS <span style="color:#d8b46c">&amp; KOBA</span> <span style="font-size:14px;color:#9dc8af">4.8 SECURITY PREP</span></h1><small>INTELLIGENT BUSINESS ASSISTANT · Created Together. Built for Business.</small></div><div class="language-switch" role="group" aria-label="Language"><button type="button" class="langbtn" data-lang="ka" onclick="setLanguage('ka')" title="ქართული">🇬🇪 <span>KA</span></button><button type="button" class="langbtn" data-lang="en" onclick="setLanguage('en')" title="English">🇬🇧 <span>EN</span></button><button type="button" class="langbtn" data-lang="ru" onclick="setLanguage('ru')" title="Русский">🇷🇺 <span>RU</span></button></div></div><button type="button" onclick="fetch('/auth/logout',{method:'POST'}).then(()=>location.href='/login')" style="float:right;padding:9px;background:#a8813f;border:0;border-radius:6px;cursor:pointer">Выйти / Logout</button></header><main>
<div class="panel"><div class="fields"><label>Гостиница<select id="hotel"></select></label><label>Название новой гостиницы<input id="newhotel" placeholder="Название"></label><label>Номеров<input id="newrooms" type="number" value="49" min="1"></label><button onclick="addHotel()">Добавить гостиницу</button></div><nav><a href="#email">Анализ писем</a><a href="#daily">История</a><a href="#strategy">Стратегия</a><a href="#plans">План / факт</a><a href="#records">Записи</a><a href="#executive">Панель директора</a><a href="#diagnostics">Проверка дат</a></nav><small>Локальная версия с входом по паролю. Не открывайте порт в интернете.</small></div>
<section class="panel" id="email"><h2>✉ Интеллектуальный анализ письма · RU · ქართული · EN · локально</h2><p class="muted">Вставьте письмо на русском, грузинском или английском. Программа анализирует текст по правилам и проверяет финансовые расчёты. AI-модель не используется. Проверяйте результат перед использованием. Вставьте текст из email. ATLAS извлечёт цифры, проверит формулы, оценит показатели и подготовит черновик ответа. Почта не подключена, отправки нет.</p><div id="aiStatus" class="note">Проверка локального AI...</div><button type="button" onclick="checkAI()">Проверить анализ</button><label>Текст письма<textarea id="emailText" rows="7" placeholder="Господин Коба, вчера продано 40 номеров из 50. Выручка составила 4000 GEL..." style="width:100%;background:#09251e;color:#fff;border:1px solid #526682;border-radius:8px;padding:12px;resize:vertical"></textarea></label><div class="fields" style="margin-top:12px"><label>Низкая загрузка ниже, %<input id="occLow" type="number" value="50" min="0" max="99"></label><label>Хорошая загрузка от, %<input id="occGood" type="number" value="75" min="1" max="100"></label><label>План ADR, GEL<input id="adrTarget" type="number" value="150" min="0.01" step="0.01"></label><button onclick="analyzeEmail()">Анализировать письмо</button></div><div id="emailResult" class="note">Показатели появятся здесь после анализа. Пороги демонстрационные и изменяются вручную.</div><h3>Черновик ответа (не отправляется)</h3><textarea id="emailDraft" rows="8" style="width:100%;background:#09251e;color:#fff;border:1px solid #526682;border-radius:8px;padding:12px;resize:vertical" placeholder="Здесь появится черновик ответа на русском"></textarea><button onclick="navigator.clipboard.writeText($('emailDraft').value).then(()=>alert('Черновик скопирован')).catch(()=>alert('Выделите и скопируйте текст вручную'))">Скопировать черновик</button><p class="muted">Письма не сохраняются в базе. Не вставляйте пароли, банковские данные и персональные сведения гостей.</p></section>
<section class="panel" id="daily"><h2>Ежедневная история и любой период</h2><div class="fields"><label>С даты<input id="from" type="date"></label><label>По дату включительно<input id="to" type="date"></label><button onclick="refresh()">Рассчитать период</button></div><div class="grid" id="kpis" style="margin-top:16px"></div><div id="coverage" class="note"></div><div class="note">Occupancy = продано / доступно × 100%; ADR = выручка номеров / продано; RevPAR = выручка номеров / доступно. Итоги рассчитываются из сумм, не из средних дневных процентов.</div></section>
<section class="panel"><h2>Добавить или исправить день</h2><div class="fields"><label>Дата<input type="date" id="day"></label><label>Доступно номеро-ночей<input type="number" id="available" min="0" value="49"></label><label>Продано номеро-ночей<input type="number" id="sold" min="0" value="0"></label><label>Выручка номеров, GEL<input type="number" id="revenue" min="0" step="0.01" value="0"></label><label>Источник<input id="source" value="Ручной ввод"></label><button onclick="saveDay()">Сохранить день</button></div><div id="saveMsg" class="note">При изменении существующей даты предыдущая версия попадёт в журнал исправлений.</div></section>
<section class="panel" id="strategy"><h2>Financial Navigator · Двусторонний расчёт</h2><p class="muted">Модель выручки от проживания. Изменения здесь не меняют фактические записи и сохранённые планы.</p>
<div class="fields"><label>Режим расчёта<select id="navMode"><option value="goal">От цели к ADR</option><option value="adr">От ADR к выручке</option><option value="revpar">От RevPAR к выручке</option><option value="occupancy">От цели и ADR к загрузке</option></select></label><label>Дней в периоде<input type="number" id="days" value="365" min="1" step="1"></label><label>Загрузка, %<input type="number" id="occ" value="75" min="0" max="100" step="0.1"></label><label>Целевая выручка, GEL<input type="number" id="target" value="2500000" min="0" step="0.01"></label><label>ADR, GEL<input type="number" id="navAdr" value="200" min="0" step="0.01"></label><label>RevPAR, GEL<input type="number" id="navRevpar" value="150" min="0" step="0.01"></label></div>
<div id="strategyOut" class="note" aria-live="polite"></div><h3>Сценарии загрузки</h3><div id="scenarioOut" class="scroll"></div><small>Плановый расчёт: количество номеров × дни. При ремонте или закрытии номеров фактическая доступность может отличаться. Проданные номеро-ночи в модели могут быть дробными, в реальности — целые.</small></section>
<section class="panel" id="plans"><h2>Финансовый план / факт</h2><div class="fields"><label>Плановая выручка за выбранный период, GEL<input type="number" id="planTarget" value="250000" min="0"></label><button onclick="savePlan()">Сохранить версию плана</button><button onclick="loadPlans()">Показать историю планов</button></div><div id="planOut" class="note"></div><div id="planHistory"></div></section>
<section class="panel" id="executive"><h2>Executive Dashboard · План, факт и прогноз</h2><p class="muted">Прогноз строится только по уже сохранённым дням. Пропущенные дни не считаются нулевой выручкой. Выберите период выше и нажмите «Рассчитать период».</p><div class="grid" id="executiveKpis"></div><div id="executiveProgress" class="note"></div><div id="executiveAdvice" class="note"></div><h2 style="margin-top:18px">Динамика дневной выручки</h2><div id="revenueChart" class="scroll"></div></section>
<section class="panel" id="records"><h2>Ежедневные записи выбранного периода</h2><div class="scroll"><table><thead><tr><th>Дата</th><th>Доступно</th><th>Продано</th><th>Выручка</th><th>ADR</th><th>RevPAR</th><th>Источник</th></tr></thead><tbody id="recordsBody"></tbody></table></div><button style="margin-top:12px" onclick="downloadCsv()">Скачать CSV периода</button></section>
<section class="panel"><h2>Защита данных · ATLAS 4.7</h2><p class="muted">База хранится отдельно от папки программы в Windows AppData. При каждом запуске создаётся проверенная резервная копия. Для дополнительной защиты сохраняйте скачанную копию на другой диск.</p><button onclick="location.href='/backup'">Скачать проверенную копию SQLite</button> <button onclick="showProtection()">Проверить защиту</button><div id="protection" class="note">Автоматическая проверка базы при запуске.</div></section>
<section id="diagnostics" class="panel" style="margin-top:18px"><h2>Проверка пропущенных дат · 4.7</h2><p>Показывает точные даты, за которые нет записей. Ничего не изменяет в базе.</p><div class="fields"><label>С даты<input type="date" id="diagStart"></label><label>По дату<input type="date" id="diagEnd"></label><button type="button" onclick="atlasUseReportPeriod()">Период отчёта</button><button type="button" onclick="atlasCurrentMonth()">Текущий месяц</button><button type="button" onclick="atlasMissingDays()">Проверить даты</button></div><pre id="diagResult" style="white-space:pre-wrap;overflow-wrap:anywhere">Выберите период и нажмите «Проверить даты».</pre></section>
<footer class="muted" style="padding-bottom:25px">ATLAS & KOBA 4.8 · Локальный анализ текста по правилам, без Ollama и API. Gmail и XLSX не подключены. Доступ с телефона возможен в локальной сети.</footer></main>
<script>
const $=id=>document.getElementById(id),num=n=>n==null?'нет данных':Number(n).toLocaleString('ru-RU',{maximumFractionDigits:2});let currentRows=[];
async function api(path,body){let r=await fetch(path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});let x=await r.json();if(!r.ok)throw Error(x.error||'Ошибка');return x}
async function checkAI(){try{let x=await api('/api/ai-status');$('aiStatus').textContent=(x.ready?({ru:'Локальный анализ готов',en:'Local analysis ready',ka:'ლოკალური ანალიზი მზადაა'}[currentLanguage]):({ru:'AI недоступен: запустите Ollama и установите модель',en:'AI unavailable: start Ollama and install the model',ka:'AI მიუწვდომელია: გაუშვით Ollama და დააყენეთ მოდელი'}[currentLanguage]))+' · '+x.model;}catch(e){$('aiStatus').textContent=e.message}}
async function analyzeEmail(){try{$('emailResult').textContent=({ru:'ATLAS анализирует письмо...',en:'ATLAS is analyzing the email...',ka:'ATLAS აანალიზებს წერილს...'}[currentLanguage]);let x=await api('/api/analyze-email',{text:$('emailText').value,thresholds:{occupancy_low:+$('occLow').value,occupancy_good:+$('occGood').value,adr_target:+$('adrTarget').value,language:currentLanguage}});let v=x.values;let names={sold:'Продано номеров',available:'Доступно номеров',revenue:'Выручка, GEL',adr_calculated:'ADR расчёт, GEL',revpar_calculated:'RevPAR расчёт, GEL',occupancy_calculated:'Загрузка расчёт, %',adr_reported:'ADR из письма',revpar_reported:'RevPAR из письма',occupancy_reported:'Загрузка из письма, %'};$('emailResult').innerHTML='<div class="grid">'+Object.entries(names).filter(([k])=>v[k]!=null).map(([k,name])=>'<div class="kpi">'+name+'<b>'+num(v[k])+'</b></div>').join('')+'</div><p>'+x.evaluation.map(escapeHtml).join('<br>')+'</p>'+(x.warnings.length?'<p class="error">'+x.warnings.map(escapeHtml).join('<br>')+'</p>':'')+'<small>'+escapeHtml(x.note)+'</small>';$('emailDraft').value=x.draft}catch(e){$('emailResult').textContent='Ошибка анализа: '+e.message}}
function hotelId(){return +$('hotel').value}
async function hotels(){let a=await api('/api/hotels');$('hotel').innerHTML=a.map(x=>`<option value="${x.id}">${escapeHtml(x.name)} (${x.rooms})</option>`).join('');$('hotel').onchange=()=>{let x=a.find(y=>y.id===hotelId());$('available').value=x.rooms;refresh();strategy()};$('available').value=a[0].rooms;refresh();strategy()}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function addHotel(){try{let n=$('newhotel').value.trim();if(!n)throw Error('Введите название');await api('/api/hotels',{name:n,rooms:+$('newrooms').value});await hotels();$('hotel').selectedIndex=$('hotel').options.length-1;$('hotel').dispatchEvent(new Event('change'))}catch(e){alert(e.message)}}
async function saveDay(){try{let data={hotel_id:hotelId(),day:$('day').value,available:+$('available').value,sold:+$('sold').value,revenue:+$('revenue').value,source:$('source').value};await api('/api/daily',data);$('saveMsg').innerHTML='<span class="success">Сохранено. История периода обновлена.</span>';refresh()}catch(e){$('saveMsg').innerHTML='<span class="error">'+escapeHtml(e.message)+'</span>'}}
async function refresh(){if(!hotelId())return;try{let x=await api(`/api/report?hotel_id=${hotelId()}&start=${$('from').value}&end=${$('to').value}`);currentRows=x.rows;let s=x.summary;let vals=[['Выручка, GEL',s.revenue],['Продано номеро-ночей',s.sold],['Доступно',s.available],['Occupancy, %',s.occupancy],['ADR, GEL',s.adr],['RevPAR, GEL',s.revpar]];$('kpis').innerHTML=vals.map(v=>`<div class="kpi">${v[0]}<b>${num(v[1])}</b></div>`).join('');$('coverage').innerHTML=`Заполнено дней: <b>${s.days_recorded}</b> из <b>${x.calendar_days}</b>. Отсутствует: <b>${x.calendar_days-s.days_recorded}</b>. <span class="tag">Пропущенные даты не считаются нулевыми.</span>`;$('recordsBody').innerHTML=x.rows.map(r=>`<tr><td>${r.day}</td><td>${r.available}</td><td>${r.sold}</td><td>${num(r.revenue)}</td><td>${num(r.sold?r.revenue/r.sold:null)}</td><td>${num(r.available?r.revenue/r.available:null)}</td><td>${escapeHtml(r.source)}</td></tr>`).join('');if(!x.rows.length)$('recordsBody').innerHTML='<tr><td colspan="7">Нет записей за этот период</td></tr>';planCalc(s);executive(x)}catch(e){$('coverage').textContent=e.message}}

function executive(x){
 let s=x.summary, target=Number($('planTarget').value), start=$('from').value,end=$('to').value;
 let today=new Date();today.setHours(0,0,0,0);let startD=new Date(start+'T00:00:00'),endD=new Date(end+'T00:00:00');
 let elapsed=Math.max(0,Math.min(x.calendar_days,Math.floor((today-startD)/86400000)+1));
 let future=Math.max(0,x.calendar_days-elapsed);let recordedElapsed=x.rows.filter(r=>r.day<=today.toLocaleDateString('en-CA')).length;
 let complete=elapsed>0&&recordedElapsed===elapsed;
 let avg=recordedElapsed?s.revenue/recordedElapsed:null;
 let forecast=(complete&&future>0)?s.revenue+avg*future:null;
 let gap=target-s.revenue;let remainingDaily=future>0?Math.max(0,gap)/future:null;
 let values=[['Факт, GEL',s.revenue],['План, GEL',target],['Отклонение, GEL',s.revenue-target],['Заполнено дней',s.days_recorded+' / '+x.calendar_days],['Прогноз, GEL',forecast],['Нужно в день, GEL',remainingDaily]];
 $('executiveKpis').innerHTML=values.map(v=>'<div class="kpi">'+v[0]+'<b>'+ (typeof v[1]==='string'?v[1]:num(v[1]))+'</b></div>').join('');
 let percent=target>0?s.revenue/target*100:null;
 $('executiveProgress').innerHTML='Выполнение плана по сохранённому факту: <b>'+(percent===null?'не определено':num(percent)+'%')+'</b><div class="bartrack"><div class="barfill" style="width:'+Math.max(0,Math.min(100,percent||0))+'%"></div></div>';
 let warnings=[];
 if(!s.days_recorded)warnings.push('Нет сохранённых записей за выбранный период.');
 if(x.calendar_days>s.days_recorded)warnings.push('История неполная: отсутствуют '+(x.calendar_days-s.days_recorded)+' дней.');
 if(!complete&&future>0)warnings.push('Прогноз не рассчитывается: есть пропуски среди прошедших дней выбранного периода.');
 if(future===0)warnings.push('Выбранный период уже закончился: прогноз будущих дней не нужен.');
 if(startD>today)warnings.push('Выбран будущий период без исторического факта.');
 if(complete&&future>0&&forecast!==null){warnings.push('Линейный прогноз по среднему доходу сохранённых дней: '+num(forecast)+' GEL. Он не учитывает сезонность, будущие бронирования и изменения спроса.');if(target>0)warnings.push(forecast<target?'При текущем темпе прогноз ниже плана. Проверьте спрос и тарифы.':'При текущем темпе прогноз не ниже плана.');}
 if(remainingDaily!==null&&gap>0)warnings.push('Для достижения цели за оставшиеся '+future+' дней требуется в среднем '+num(remainingDaily)+' GEL в день.');
 $('executiveAdvice').innerHTML='<b>Анализ и рекомендации</b><ul>'+warnings.map(w=>'<li>'+escapeHtml(w)+'</li>').join('')+'</ul><small>Это арифметические подсказки, не AI-анализ и не доказательство причин отклонений.</small>';
 let max=Math.max(1,...x.rows.map(r=>r.revenue));
 $('revenueChart').innerHTML=x.rows.length?'<div style="min-width:360px">'+x.rows.map(r=>'<div style="display:grid;grid-template-columns:105px 1fr 110px;gap:10px;align-items:center;margin:7px 0"><small>'+r.day+'</small><div class="bartrack"><div class="barfill" style="width:'+Math.max(0,Math.min(100,r.revenue/max*100))+'%"></div></div><small>'+num(r.revenue)+' GEL</small></div>').join('')+'</div>':'<p class="muted">Пока нет данных для графика.</p>';
}

function strategy(){
 const h=$('hotel').selectedOptions[0];if(!h)return;
 const rooms=Number(h.textContent.match(/\((\d+)\)$/)?.[1]);
 const d=Number($('days').value),occ=Number($('occ').value),goal=Number($('target').value),enteredAdr=Number($('navAdr').value),enteredRevpar=Number($('navRevpar').value),mode=$('navMode').value;
 const valid=[d,occ,goal,enteredAdr,enteredRevpar,rooms].every(Number.isFinite)&&Number.isInteger(d)&&d>0&&rooms>0&&occ>=0&&occ<=100&&goal>=0&&enteredAdr>=0&&enteredRevpar>=0;
 if(!valid){$('strategyOut').innerHTML='<span class="error">Проверьте числа: дни должны быть целыми и больше нуля, загрузка от 0 до 100%, денежные значения неотрицательные.</span>';$('scenarioOut').textContent='';return}
 const available=rooms*d;let revenue,adr,revpar,actualOcc=occ,warning='';
 if(mode==='goal'){
  revenue=goal;revpar=revenue/available;adr=occ>0?revpar/(occ/100):null;
  if(adr===null&&goal>0)warning='При нулевой загрузке положительная выручка невозможна.';
 }else if(mode==='adr'){
  adr=enteredAdr;revenue=available*(occ/100)*adr;revpar=revenue/available;
 }else if(mode==='revpar'){
  revpar=enteredRevpar;revenue=revpar*available;adr=occ>0?revpar/(occ/100):null;
  if(adr===null&&revpar>0)warning='При нулевой загрузке положительная выручка невозможна.';
 }else{
  revenue=goal;adr=enteredAdr;revpar=revenue/available;
  actualOcc=adr>0?revenue/(available*adr)*100:(revenue===0?0:null);
  if(actualOcc===null)warning='Для положительной цели нужен ADR больше нуля.';
  else if(actualOcc>100)warning='Цель недостижима при указанном ADR: необходимая загрузка превышает 100%.';
 }
 const sold=actualOcc===null?null:available*actualOcc/100;
 const box=(name,value)=>'<div class="kpi">'+name+'<b>'+value+'</b></div>';
 $('strategyOut').innerHTML='<div class="grid">'+box('Выручка, GEL',num(revenue))+box('ADR, GEL',num(adr))+box('RevPAR, GEL',num(revpar))+box('Загрузка, %',num(actualOcc))+box('Продано номеро-ночей',num(sold))+box('Доступно номеро-ночей',num(available))+'</div>'+(warning?'<p class="error">'+warning+'</p>':'');
 const scenarios=[50,60,70,80,90,100];
 let rows=scenarios.map(o=>{
  let a,r,v;
  if(mode==='adr'){a=enteredAdr;r=available*o/100*a;v=r/available;}
  else {r=revenue;v=r/available;a=o>0?v/(o/100):null;}
  return '<tr><td>'+o+'%</td><td>'+num(a)+'</td><td>'+num(v)+'</td><td>'+num(r)+'</td></tr>';
 });
 $('scenarioOut').innerHTML='<table><thead><tr><th>Загрузка</th><th>ADR, GEL</th><th>RevPAR, GEL</th><th>Выручка, GEL</th></tr></thead><tbody>'+rows.join('')+'</tbody></table><small>'+(mode==='adr'?'В сценариях ADR фиксирован.':'В сценариях выручка фиксирована, ADR подбирается под загрузку.')+'</small>';
}
$('navMode').addEventListener('change',()=>{
 const mode=$('navMode').value;
 $('target').parentElement.style.display=(mode==='goal'||mode==='occupancy')?'':'none';
 $('navAdr').parentElement.style.display=(mode==='adr'||mode==='occupancy')?'':'none';
 $('navRevpar').parentElement.style.display=mode==='revpar'?'':'none';
 $('occ').parentElement.style.display=mode==='occupancy'?'none':'';
 strategy();
});
['days','occ','target','navAdr','navRevpar'].forEach(id=>$(id).addEventListener('input',strategy));
$('navMode').dispatchEvent(new Event('change'));
function atlasLocalISO(d){
 const y=d.getFullYear(),m=String(d.getMonth()+1).padStart(2,'0'),day=String(d.getDate()).padStart(2,'0');
 return `${y}-${m}-${day}`;
}
function atlasUseReportPeriod(){
 $('diagStart').value=$('from').value;
 $('diagEnd').value=$('to').value;
 $('diagResult').textContent='Период отчёта выбран. Нажмите «Проверить даты».';
}
function atlasCurrentMonth(){
 const now=new Date();
 $('diagStart').value=atlasLocalISO(new Date(now.getFullYear(),now.getMonth(),1));
 $('diagEnd').value=atlasLocalISO(now);
 $('diagResult').textContent='Текущий месяц выбран. Нажмите «Проверить даты».';
}
async function atlasMissingDays(){
 const el=document.getElementById('diagResult');
 const hotel=document.getElementById('hotel').value;
 const start=document.getElementById('diagStart').value,end=document.getElementById('diagEnd').value;
 if(!hotel||!start||!end){el.textContent='Выберите гостиницу и обе даты.';return;}
 try{
  const q=new URLSearchParams({hotel_id:hotel,start,end});
  const r=await fetch('/api/missing-days?'+q.toString(),{credentials:'same-origin'});
  const x=await r.json();if(!r.ok)throw Error(x.error||'Ошибка');
  el.textContent='Заполнено дней: '+x.recorded+'\nОтсутствует дней: '+x.missing_count+'\n'+(x.missing_dates.join(', ')||'Пропусков нет')+'\nОтсутствие записи не означает нулевую выручку.';
 }catch(e){el.textContent='Ошибка: '+e.message;}
}
function planCalc(s){let t=+$('planTarget').value;let gap=t-s.revenue;$('planOut').innerHTML=`План: <b>${num(t)} GEL</b>; зафиксированный факт: <b>${num(s.revenue)} GEL</b>; разница: <b>${num(gap)} GEL</b>. Выполнение: <b>${t?num(s.revenue/t*100)+'%':'не определено'}</b>.<br><small>Сравнение предварительное, если записи за период неполные. Прогноз доступен в разделе «Панель директора» при полной истории прошедших дней.</small>`}
async function savePlan(){try{await api('/api/plans',{hotel_id:hotelId(),start:$('from').value,end:$('to').value,target:+$('planTarget').value});loadPlans();refresh()}catch(e){alert(e.message)}}
async function loadPlans(){let a=await api('/api/plans?hotel_id='+hotelId());$('planHistory').innerHTML='<div class="scroll"><table><tr><th>Создан</th><th>Период</th><th>План GEL</th></tr>'+a.map(x=>`<tr><td>${x.created_at}</td><td>${x.start} — ${x.end}</td><td>${num(x.target)}</td></tr>`).join('')+'</table></div>'}
async function showProtection(){try{let x=await api('/api/protection');$('protection').textContent='Целостность: '+x.integrity+'; автоматических копий: '+x.backups+'; последняя: '+(x.latest||'нет')+'; папка данных: '+x.data_dir}catch(e){$('protection').textContent=e.message}}
function downloadCsv(){let lines=[['Дата','Доступно','Продано','Выручка','Источник'],...currentRows.map(r=>[r.day,r.available,r.sold,r.revenue,r.source])];let text='\ufeff'+lines.map(r=>r.map(v=>'"'+String(v).replaceAll('"','""')+'"').join(';')).join('\r\n');let a=document.createElement('a');a.href=URL.createObjectURL(new Blob([text],{type:'text/csv;charset=utf-8'}));a.download='atlas_history.csv';a.click();URL.revokeObjectURL(a.href)}
let today=new Date();$('day').value=atlasLocalISO(today);$('to').value=atlasLocalISO(today);$('from').value=atlasLocalISO(new Date(today.getFullYear(),today.getMonth(),1));atlasUseReportPeriod();$('planTarget').addEventListener('change',refresh);hotels();

const translations={"Проверить анализ":{"en": "Check analysis", "ka": "ანალიზის შემოწმება"},"Проверка локального AI...":{"en": "Checking local AI...", "ka": "ლოკალური ანალიზის შემოწმება..."},"Вставьте письмо на русском, грузинском или английском. Программа анализирует текст по правилам и проверяет финансовые расчёты. AI-модель не используется. Проверяйте результат перед использованием. Вставьте текст из email. ATLAS извлечёт цифры, проверит формулы, оценит показатели и подготовит черновик ответа. Почта не подключена, отправки нет.":{"en": "Paste an email in Russian, Georgian or English. A separately installed local AI model reads the email; the app independently calculates KPIs. Check all results. Email is not connected and nothing is sent.", "ka": "ჩასვით წერილი ქართულ, რუსულ ან ინგლისურ ენაზე. ცალკე დაინსტალირებული ლოკალური AI მოდელი კითხულობს წერილს; პროგრამა დამოუკიდებლად ითვლის მაჩვენებლებს. გადაამოწმეთ შედეგები. ელფოსტა არ არის დაკავშირებული და არაფერი იგზავნება."},"Локальный анализ текста по правилам, без Ollama и API. Gmail и XLSX не подключены. Доступ с телефона возможен в локальной сети.":{"en": "Local AI via Ollama (separate installation required). Gmail, mobile access and XLSX are not connected.", "ka": "ლოკალური AI Ollama-ს მეშვეობით (საჭიროა ცალკე ინსტალაცია). Gmail, მობილური წვდომა და XLSX არ არის დაკავშირებული."},"Гостиница": {"en": "Hotel", "ka": "სასტუმრო"}, "Название новой гостиницы": {"en": "New hotel name", "ka": "ახალი სასტუმროს სახელი"}, "Номеров": {"en": "Rooms", "ka": "ნომრები"}, "Добавить гостиницу": {"en": "Add hotel", "ka": "სასტუმროს დამატება"}, "Анализ писем": {"en": "Email analysis", "ka": "წერილების ანალიზი"}, "История": {"en": "History", "ka": "ისტორია"}, "Стратегия": {"en": "Strategy", "ka": "სტრატეგია"}, "План / факт": {"en": "Plan / actual", "ka": "გეგმა / ფაქტი"}, "Записи": {"en": "Records", "ka": "ჩანაწერები"}, "Панель директора": {"en": "Executive dashboard", "ka": "დირექტორის პანელი"}, "Локальная версия с входом по паролю. Не открывайте порт в интернете.": {"en": "This interface runs locally. Do not expose it to the internet: there is no login protection yet.", "ka": "ეს ინტერფეისი ლოკალურად მუშაობს. არ გამოაქვეყნოთ ინტერნეტში: ავტორიზაცია ჯერ არ არის."}, "Интеллектуальный анализ письма": {"en": "Smart email analysis", "ka": "წერილის ინტელექტუალური ანალიზი"}, "Вставьте письмо на русском, грузинском или английском. Программа анализирует текст по правилам и проверяет финансовые расчёты. AI-модель не используется. Проверяйте результат перед использованием. Вставьте текст из email. ATLAS извлечёт цифры, проверит формулы, оценит показатели и подготовит черновик ответа. Почта не подключена, отправки нет.": {"en": "Paste an email in Russian, Georgian or English. Common expressions are supported, but not all free-form text. Check results before use. ATLAS extracts figures, checks formulas, evaluates performance and prepares a draft reply. Email is not connected; nothing is sent.", "ka": "ჩასვით წერილის ტექსტი რუსულ, ქართულ ან ინგლისურ ენაზე. მხარდაჭერილია გავრცელებული ფორმულირებები, მაგრამ არა ყველა თავისუფალი ტექსტი. გამოყენებამდე შეამოწმეთ შედეგი. ATLAS ამოიცნობს რიცხვებს, გადაამოწმებს ფორმულებს, შეაფასებს მაჩვენებლებს და მოამზადებს პასუხის პროექტს. ელფოსტა არ არის დაკავშირებული და არაფერი იგზავნება."}, "Текст письма": {"en": "Email text", "ka": "წერილის ტექსტი"}, "Низкая загрузка ниже, %": {"en": "Low occupancy below, %", "ka": "დაბალი დატვირთულობა, %-ზე ნაკლები"}, "Хорошая загрузка от, %": {"en": "Good occupancy from, %", "ka": "კარგი დატვირთულობა, %-დან"}, "План ADR, GEL": {"en": "ADR target, GEL", "ka": "ADR-ის გეგმა, GEL"}, "Анализировать письмо": {"en": "Analyze email", "ka": "წერილის ანალიზი"}, "Показатели появятся здесь после анализа. Пороги демонстрационные и изменяются вручную.": {"en": "Results will appear here after analysis. Thresholds are examples and can be changed.", "ka": "შედეგები გამოჩნდება ანალიზის შემდეგ. ზღვრები მაგალითებია და მათი შეცვლა შესაძლებელია."}, "Черновик ответа (не отправляется)": {"en": "Reply draft (not sent)", "ka": "პასუხის პროექტი (არ იგზავნება)"}, "Скопировать черновик": {"en": "Copy draft", "ka": "პროექტის კოპირება"}, "Письма не сохраняются в базе. Не вставляйте пароли, банковские данные и персональные сведения гостей.": {"en": "Emails are not saved to the database. Do not paste passwords, banking details or guest personal data.", "ka": "წერილები ბაზაში არ ინახება. არ ჩასვათ პაროლები, საბანკო ან სტუმრების პერსონალური მონაცემები."}, "Ежедневная история и любой период": {"en": "Daily history and date ranges", "ka": "დღიური ისტორია და პერიოდები"}, "С даты": {"en": "From date", "ka": "საწყისი თარიღი"}, "По дату включительно": {"en": "Through date", "ka": "საბოლოო თარიღი"}, "Рассчитать период": {"en": "Calculate period", "ka": "პერიოდის გამოთვლა"}, "Добавить или исправить день": {"en": "Add or edit a day", "ka": "დღის დამატება ან შესწორება"}, "Дата": {"en": "Date", "ka": "თარიღი"}, "Доступно номеро-ночей": {"en": "Available room-nights", "ka": "ხელმისაწვდომი ნომერ-ღამეები"}, "Продано номеро-ночей": {"en": "Sold room-nights", "ka": "გაყიდული ნომერ-ღამეები"}, "Выручка номеров, GEL": {"en": "Room revenue, GEL", "ka": "ნომრების შემოსავალი, GEL"}, "Источник": {"en": "Source", "ka": "წყარო"}, "Сохранить день": {"en": "Save day", "ka": "დღის შენახვა"}, "При изменении существующей даты предыдущая версия попадёт в журнал исправлений.": {"en": "Editing an existing date records the previous version in the audit log.", "ka": "არსებული თარიღის ცვლილებისას წინა ვერსია ინახება ცვლილებების ჟურნალში."}, "Financial Navigator · Двусторонний расчёт": {"en": "Financial Navigator · Two-way calculations", "ka": "ფინანსური ნავიგატორი · ორმხრივი გამოთვლები"}, "Модель выручки от проживания. Изменения здесь не меняют фактические записи и сохранённые планы.": {"en": "Room revenue model. Changes here do not alter actual records or saved plans.", "ka": "ნომრების შემოსავლის მოდელი. აქ ცვლილებები არ ცვლის რეალურ ჩანაწერებს ან შენახულ გეგმებს."}, "Режим расчёта": {"en": "Calculation mode", "ka": "გამოთვლის რეჟიმი"}, "От цели к ADR": {"en": "Target to ADR", "ka": "მიზნიდან ADR-მდე"}, "От ADR к выручке": {"en": "ADR to revenue", "ka": "ADR-დან შემოსავალამდე"}, "От RevPAR к выручке": {"en": "RevPAR to revenue", "ka": "RevPAR-დან შემოსავალამდე"}, "От цели и ADR к загрузке": {"en": "Target and ADR to occupancy", "ka": "მიზნიდან და ADR-დან დატვირთულობამდე"}, "Дней в периоде": {"en": "Days in period", "ka": "დღეები პერიოდში"}, "Загрузка, %": {"en": "Occupancy, %", "ka": "დატვირთულობა, %"}, "Целевая выручка, GEL": {"en": "Target revenue, GEL", "ka": "სამიზნე შემოსავალი, GEL"}, "Сценарии загрузки": {"en": "Occupancy scenarios", "ka": "დატვირთულობის სცენარები"}, "Плановый расчёт: количество номеров × дни. При ремонте или закрытии номеров фактическая доступность может отличаться. Проданные номеро-ночи в модели могут быть дробными, в реальности — целые.": {"en": "Planning model: rooms × days. Availability may differ during renovations or closures. Modeled room-nights can be fractional; actual sales are whole numbers.", "ka": "გეგმის მოდელი: ნომრები × დღეები. რემონტის ან დახურვის დროს ხელმისაწვდომობა შეიძლება განსხვავდებოდეს. მოდელში ნომერ-ღამეები შეიძლება წილადი იყოს, რეალურად კი მთელი რიცხვია."}, "Финансовый план / факт": {"en": "Financial plan / actual", "ka": "ფინანსური გეგმა / ფაქტი"}, "Плановая выручка за выбранный период, GEL": {"en": "Planned revenue for selected period, GEL", "ka": "არჩეული პერიოდის დაგეგმილი შემოსავალი, GEL"}, "Сохранить версию плана": {"en": "Save plan version", "ka": "გეგმის ვერსიის შენახვა"}, "Показать историю планов": {"en": "Show plan history", "ka": "გეგმების ისტორიის ჩვენება"}, "Executive Dashboard · План, факт и прогноз": {"en": "Executive Dashboard · Plan, actual and forecast", "ka": "დირექტორის პანელი · გეგმა, ფაქტი და პროგნოზი"}, "Прогноз строится только по уже сохранённым дням. Пропущенные дни не считаются нулевой выручкой. Выберите период выше и нажмите «Рассчитать период».": {"en": "Forecast uses saved days only. Missing days are not treated as zero revenue. Choose a period above and select Calculate period.", "ka": "პროგნოზი ეფუძნება მხოლოდ შენახულ დღეებს. გამოტოვებული დღეები ნულოვან შემოსავლად არ ითვლება. აირჩიეთ პერიოდი და დააჭირეთ „პერიოდის გამოთვლა“."}, "Динамика дневной выручки": {"en": "Daily revenue trend", "ka": "დღიური შემოსავლის დინამიკა"}, "Ежедневные записи выбранного периода": {"en": "Daily records for selected period", "ka": "არჩეული პერიოდის დღიური ჩანაწერები"}, "Доступно": {"en": "Available", "ka": "ხელმისაწვდომია"}, "Продано": {"en": "Sold", "ka": "გაყიდულია"}, "Выручка": {"en": "Revenue", "ka": "შემოსავალი"}, "Скачать CSV периода": {"en": "Download period CSV", "ka": "პერიოდის CSV-ის ჩამოტვირთვა"}, "Защита данных · ATLAS 4.7": {"en": "Data protection · ATLAS 4.0", "ka": "მონაცემთა დაცვა · ATLAS 4.0"}, "База хранится отдельно от папки программы в Windows AppData. При каждом запуске создаётся проверенная резервная копия. Для дополнительной защиты сохраняйте скачанную копию на другой диск.": {"en": "The database is stored separately from the app in Windows AppData. A verified backup is created at every launch. Save another copy on a separate drive.", "ka": "ბაზა ინახება პროგრამისგან განცალკევებით Windows AppData-ში. ყოველ გაშვებაზე იქმნება შემოწმებული სარეზერვო ასლი. დამატებითი დაცვისთვის შეინახეთ ასლი სხვა დისკზე."}, "Скачать проверенную копию SQLite": {"en": "Download verified SQLite backup", "ka": "შემოწმებული SQLite ასლის ჩამოტვირთვა"}, "Проверить защиту": {"en": "Check protection", "ka": "დაცვის შემოწმება"}, "Автоматическая проверка базы при запуске.": {"en": "Automatic database check at startup.", "ka": "ბაზის ავტომატური შემოწმება გაშვებისას."}, "Локальный анализ текста по правилам, без Ollama и API. Gmail и XLSX не подключены. Доступ с телефона возможен в локальной сети.": {"en": "Rule-based trilingual text analysis (no AI model). Gmail, mobile access and XLSX are not connected yet.", "ka": "წესებზე დაფუძნებული სამენოვანი ტექსტის ანალიზი (AI მოდელის გარეშე). Gmail, მობილური წვდომა და XLSX ჯერ არ არის დაკავშირებული."}, "Продано номеров": {"en": "Rooms sold", "ka": "გაყიდული ნომრები"}, "Доступно номеров": {"en": "Available rooms", "ka": "ხელმისაწვდომი ნომრები"}, "ADR расчёт, GEL": {"en": "Calculated ADR, GEL", "ka": "გამოთვლილი ADR, GEL"}, "RevPAR расчёт, GEL": {"en": "Calculated RevPAR, GEL", "ka": "გამოთვლილი RevPAR, GEL"}, "Загрузка расчёт, %": {"en": "Calculated occupancy, %", "ka": "გამოთვლილი დატვირთულობა, %"}, "ADR из письма": {"en": "ADR from email", "ka": "ADR წერილიდან"}, "RevPAR из письма": {"en": "RevPAR from email", "ka": "RevPAR წერილიდან"}, "Загрузка из письма, %": {"en": "Occupancy from email, %", "ka": "დატვირთულობა წერილიდან, %"}, "Заполнено дней:": {"en": "Days recorded:", "ka": "შევსებული დღეები:"}, "Отсутствует:": {"en": "Missing:", "ka": "აკლია:"}, "Пропущенные даты не считаются нулевыми.": {"en": "Missing dates are not treated as zero.", "ka": "გამოტოვებული თარიღები ნულად არ ითვლება."}, "Нет записей за этот период": {"en": "No records for this period", "ka": "ამ პერიოდის ჩანაწერები არ არის"}, "Сохранено. История периода обновлена.": {"en": "Saved. Period history updated.", "ka": "შენახულია. პერიოდის ისტორია განახლდა."}, "Анализ и рекомендации": {"en": "Analysis and recommendations", "ka": "ანალიზი და რეკომენდაციები"}, "Нет сохранённых записей за выбранный период.": {"en": "No saved records for this period.", "ka": "ამ პერიოდში შენახული ჩანაწერები არ არის."}, "История неполная: отсутствуют": {"en": "History incomplete: missing", "ka": "ისტორია არასრულია: აკლია"}, "Прогноз не рассчитывается: есть пропуски среди прошедших дней выбранного периода.": {"en": "Forecast unavailable: past dates are missing.", "ka": "პროგნოზი მიუწვდომელია: გასულ დღეებში ჩანაწერები აკლია."}, "Выбранный период уже закончился: прогноз будущих дней не нужен.": {"en": "The selected period has ended; no future forecast needed.", "ka": "არჩეული პერიოდი დასრულებულია; მომავალი დღეების პროგნოზი საჭირო არ არის."}, "Выбран будущий период без исторического факта.": {"en": "A future period with no historical actuals was selected.", "ka": "არჩეულია მომავალი პერიოდი ისტორიული ფაქტის გარეშე."}, "При текущем темпе прогноз ниже плана. Проверьте спрос и тарифы.": {"en": "At the current pace, forecast is below target. Check demand and rates.", "ka": "მიმდინარე ტემპით პროგნოზი გეგმაზე დაბალია. შეამოწმეთ მოთხოვნა და ტარიფები."}, "При текущем темпе прогноз не ниже плана.": {"en": "At the current pace, forecast meets or exceeds target.", "ka": "მიმდინარე ტემპით პროგნოზი გეგმაზე დაბალი არ არის."}, "Это арифметические подсказки, не AI-анализ и не доказательство причин отклонений.": {"en": "These are arithmetic hints, not AI analysis or proof of causes.", "ka": "ეს არის არითმეტიკული მინიშნებები და არა AI ანალიზი ან გადახრების მიზეზების მტკიცებულება."}, "Пока нет данных для графика.": {"en": "No chart data yet.", "ka": "გრაფიკის მონაცემები ჯერ არ არის."}, "Выручка, GEL": {"en": "Revenue, GEL", "ka": "შემოსავალი, GEL"}, "Факт, GEL": {"en": "Actual, GEL", "ka": "ფაქტი, GEL"}, "План, GEL": {"en": "Plan, GEL", "ka": "გეგმა, GEL"}, "Отклонение, GEL": {"en": "Variance, GEL", "ka": "გადახრა, GEL"}, "Прогноз, GEL": {"en": "Forecast, GEL", "ka": "პროგნოზი, GEL"}, "Нужно в день, GEL": {"en": "Required per day, GEL", "ka": "საჭიროა დღეში, GEL"}, "Заполнено дней": {"en": "Days recorded", "ka": "შევსებული დღეები"}, "Выполнение плана по сохранённому факту:": {"en": "Plan completion based on recorded actuals:", "ka": "გეგმის შესრულება შენახული ფაქტით:"}, "не определено": {"en": "not defined", "ka": "არ არის განსაზღვრული"}, "нет данных": {"en": "no data", "ka": "მონაცემები არ არის"}, "План:": {"en": "Plan:", "ka": "გეგმა:"}, "зафиксированный факт:": {"en": "recorded actual:", "ka": "შენახული ფაქტი:"}, "разница:": {"en": "difference:", "ka": "სხვაობა:"}, "Выполнение:": {"en": "Completion:", "ka": "შესრულება:"}, "Сравнение предварительное, если записи за период неполные. Прогноз доступен в разделе «Панель директора» при полной истории прошедших дней.": {"en": "Comparison is preliminary if records are incomplete. Forecast requires complete past-day history in the Executive dashboard.", "ka": "შედარება წინასწარია, თუ ჩანაწერები არასრულია. პროგნოზისთვის საჭიროა გასული დღეების სრული ისტორია დირექტორის პანელში."}, "Создан": {"en": "Created", "ka": "შექმნილია"}, "Период": {"en": "Period", "ka": "პერიოდი"}, "План GEL": {"en": "Plan GEL", "ka": "გეგმა GEL"}, "Загрузка": {"en": "Occupancy", "ka": "დატვირთულობა"}, "Сохранить": {"en": "Save", "ka": "შენახვა"}, "Ошибка анализа:": {"en": "Analysis error:", "ka": "ანალიზის შეცდომა:"}, "Целостность:": {"en": "Integrity:", "ka": "მთლიანობა:"}, "автоматических копий:": {"en": "automatic backups:", "ka": "ავტომატური ასლები:"}, "последняя:": {"en": "latest:", "ka": "ბოლო:"}, "папка данных:": {"en": "data folder:", "ka": "მონაცემთა საქაღალდე:"}, "нет": {"en": "none", "ka": "არ არის"}, "Проверьте числа: дни должны быть целыми и больше нуля, загрузка от 0 до 100%, денежные значения неотрицательные.": {"en": "Check numbers: days must be positive integers, occupancy 0–100%, monetary values nonnegative.", "ka": "შეამოწმეთ რიცხვები: დღეები უნდა იყოს დადებითი მთელი, დატვირთულობა 0–100%, თანხები არაუარყოფითი."}, "При нулевой загрузке положительная выручка невозможна.": {"en": "Positive revenue is impossible with zero occupancy.", "ka": "ნულოვანი დატვირთვისას დადებითი შემოსავალი შეუძლებელია."}, "Цель недостижима при указанном ADR: необходимая загрузка превышает 100%.": {"en": "Target is unattainable at this ADR: required occupancy exceeds 100%.", "ka": "მოცემული ADR-ით მიზანი მიუღწეველია: საჭირო დატვირთულობა 100%-ს აღემატება."}, "Для положительной цели нужен ADR больше нуля.": {"en": "A positive target requires ADR above zero.", "ka": "დადებითი მიზნისთვის ADR ნულზე მეტი უნდა იყოს."}, "В сценариях ADR фиксирован.": {"en": "ADR is fixed in scenarios.", "ka": "სცენარებში ADR ფიქსირებულია."}, "В сценариях выручка фиксирована, ADR подбирается под загрузку.": {"en": "Revenue is fixed in scenarios; ADR varies with occupancy.", "ka": "სცენარებში შემოსავალი ფიქსირებულია, ADR დატვირთულობას ერგება."}, "Черновик скопирован": {"en": "Draft copied", "ka": "პროექტი დაკოპირებულია"}, "Выделите и скопируйте текст вручную": {"en": "Select and copy the text manually", "ka": "მონიშნეთ და დააკოპირეთ ტექსტი ხელით"}, "Ручной ввод": {"en": "Manual entry", "ka": "ხელით შეყვანა"}, "Название": {"en": "Name", "ka": "სახელი"}};
let currentLanguage='ru';
const sourceText=new WeakMap();
const renderedText=new WeakMap();
const sortedPhrases=Object.keys(translations).sort((a,b)=>b.length-a.length);
function translateString(original,lang){
 if(lang==='ru')return original;
 let out=original;
 for(const phrase of sortedPhrases){
  if(out.includes(phrase))out=out.split(phrase).join(translations[phrase][lang]);
 }
 return out;
}
let translating=false;
function translatePage(){
 if(translating)return;
 translating=true;
 try{
  document.documentElement.lang=currentLanguage;
  document.title='ATLAS & KOBA 4.0';
  document.querySelectorAll('.langbtn').forEach(b=>{b.classList.toggle('active',b.dataset.lang===currentLanguage);b.setAttribute('aria-pressed',String(b.dataset.lang===currentLanguage));});
  const walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);
  let node;
  while((node=walker.nextNode())){
   if(node.parentElement?.closest('script,style,textarea,input,select#hotel,.brand h1,.brand small'))continue;
   const val=node.nodeValue;
   if(!val.trim())continue;
   let origin=sourceText.get(node);
   if(origin===undefined){origin=val;sourceText.set(node,origin)}
   else if(val!==renderedText.get(node)&&val!==origin){origin=val;sourceText.set(node,origin)}
   const next=translateString(origin,currentLanguage);
   if(val!==next)node.nodeValue=next;
   renderedText.set(node,next);
  }
  document.querySelectorAll('input[placeholder],textarea[placeholder]').forEach(el=>{
   if(!el.dataset.originalPlaceholder)el.dataset.originalPlaceholder=el.placeholder;
   el.placeholder=translateString(el.dataset.originalPlaceholder,currentLanguage);
  });
  document.querySelectorAll('#source').forEach(el=>{
   if(!el.dataset.originalDefault)el.dataset.originalDefault=el.value;
   if(['Ручной ввод','Manual entry','ხელით შეყვანა'].includes(el.value))el.value=translateString(el.dataset.originalDefault,currentLanguage);
  });
 }finally{translating=false}
}
function setLanguage(lang){
 if(!['ru','en','ka'].includes(lang))return;
 currentLanguage=lang;
 try{localStorage.setItem('atlas_interface_language',lang)}catch(e){}
 translatePage();
 // Existing draft must be regenerated with the selected language; do not re-analyze automatically.
 if($('emailDraft').value) $('emailDraft').value='';
}
const observer=new MutationObserver(()=>{if(!translating)translatePage()});
observer.observe(document.body,{subtree:true,childList:true,characterData:true});
try{currentLanguage=localStorage.getItem('atlas_interface_language')||'ru'}catch(e){}
checkAI();
if(!['ru','en','ka'].includes(currentLanguage))currentLanguage='ru';
translatePage();
</script></html>'''

class Handler(BaseHTTPRequestHandler):
 def allowed(self):
  if getattr(self.server,'lan_mode',False):
   try:
    remote=ipaddress.ip_address(self.client_address[0]);local=ipaddress.ip_address(self.server.lan_ip)
    if not (remote.is_loopback or (remote.version==4 and remote.is_private and remote in ipaddress.ip_network(f'{local}/24',strict=False))):return False
   except ValueError:return False
  host=self.headers.get('Host','')
  if host in (f'127.0.0.1:{self.server.server_port}',f'localhost:{self.server.server_port}'):return True
  if getattr(self.server,'private_mode',False) and host==self.server.private_host:return True
  if not getattr(self.server,'lan_mode',False):return False
  return host==f'{self.server.lan_ip}:{self.server.server_port}'
 def authorized(self):
  from http.cookies import SimpleCookie
  try:
   c=SimpleCookie();c.load(self.headers.get('Cookie',''))
   token=c['atlas_session'].value if 'atlas_session' in c else ''
   with AUTH_LOCK:
    created=SESSIONS.get(token)
    if created is None:return False
    if time.time()-created>8*3600:
     SESSIONS.pop(token,None);return False
    return True
  except Exception:return False
 def session_cookie(self,token,expire=False):
  self.send_header('Set-Cookie',f'atlas_session={token}; HttpOnly; SameSite=Strict; Path=/'+('; Secure' if getattr(self.server,'private_mode',False) else '')+('; Max-Age=0' if expire else ''))
 def auth_response(self,code,obj,token=None,expire=False):
  data=json.dumps(obj,ensure_ascii=False).encode('utf-8')
  self.send_response(code)
  self.send_header('Content-Type','application/json; charset=utf-8')
  self.send_header('Content-Length',str(len(data)))
  self.send_header('Cache-Control','no-store')
  self.send_header('X-Content-Type-Options','nosniff')
  self.send_header('X-Frame-Options','DENY')
  if token is not None:self.session_cookie(token,expire)
  self.end_headers();self.wfile.write(data)
 def gate(self,post=False):
  if not self.allowed():self.reply({'error':'Invalid host'},403);return False
  if not self.authorized():self.reply({'error':'Unauthorized'},401);return False
  if post:
   origin=self.headers.get('Origin')
   expected=('https://' if getattr(self.server,'private_mode',False) and self.headers.get('Host')==self.server.private_host else 'http://')+self.headers.get('Host')
   if not origin or origin != expected:
    self.reply({'error':'Invalid origin'},403);return False
  return True

 def send(self,code,data,typ='application/json',filename=None):
  self.send_response(code);self.send_header('Content-Type',typ);self.send_header('Content-Length',str(len(data)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('X-Frame-Options','DENY');self.send_header('Referrer-Policy','no-referrer');
  if filename:self.send_header('Content-Disposition',f'attachment; filename="{filename}"')
  self.end_headers();self.wfile.write(data)
 def reply(self,obj,code=200):self.send(code,json.dumps(obj,ensure_ascii=False).encode('utf-8'))
 def do_GET(self):
  from urllib.parse import parse_qs
  u=urlparse(self.path);p=parse_qs(u.query)
  if not self.allowed():return self.reply({'error':'Invalid host'},403)
  if u.path=='/login':
   if (getattr(self.server,'lan_mode',False) or getattr(self.server,'private_mode',False)) and not AUTH_FILE.exists():return self.reply({'error':'Сначала создайте пароль в локальном режиме'},403)
   return self.send(200,LOGIN_HTML.replace('SETUP_MODE','true' if not AUTH_FILE.exists() else 'false').encode(),'text/html; charset=utf-8')
  if not self.authorized():
   self.send_response(303);self.send_header('Location','/login');self.send_header('Cache-Control','no-store');self.end_headers();return
  if not self.gate():return
  try:
   if u.path=='/':return self.send(200,HTML.encode(),'text/html; charset=utf-8')
   if u.path=='/logo.png':return self.send(200,(ROOT/'logo.png').read_bytes(),'image/png')
   if u.path=='/backup':
    copy=backup('download')
    return self.send(200,copy.read_bytes(),'application/octet-stream','atlas_backup.sqlite3')
   if u.path=='/api/ai-status':return self.reply(ai_status())
   if u.path=='/api/protection':
    copies=sorted(BACKUP_DIR.glob('atlas_*.sqlite3'))
    return self.reply({'integrity':'OK' if verify(DB) else 'ОШИБКА','backups':len(copies),'latest':copies[-1].name if copies else None,'data_dir':str(DATA_DIR)})
   with connect() as c:
    if u.path=='/api/hotels':return self.reply([dict(r) for r in c.execute('SELECT * FROM hotels ORDER BY id')])
    if u.path=='/api/plans':return self.reply([dict(r) for r in c.execute('SELECT * FROM plans WHERE hotel_id=? ORDER BY id DESC',(int(p['hotel_id'][0]),))])
    if u.path=='/api/missing-days':
     h=int(p['hotel_id'][0]);start=date.fromisoformat(p['start'][0]);end=date.fromisoformat(p['end'][0])
     if end<start or (end-start).days>366:raise ValueError('Неверный период (максимум 367 дней)')
     existing={r[0] for r in c.execute('SELECT day FROM daily WHERE hotel_id=? AND day BETWEEN ? AND ?',(h,start.isoformat(),end.isoformat()))}
     missing=[(start+timedelta(days=i)).isoformat() for i in range((end-start).days+1) if (start+timedelta(days=i)).isoformat() not in existing]
     return self.reply({'start':start.isoformat(),'end':end.isoformat(),'recorded':len(existing),'missing_count':len(missing),'missing_dates':missing,'note':'Отсутствие записи не означает нулевую выручку'})
   if u.path=='/api/report':
     h=int(p['hotel_id'][0]);start=date.fromisoformat(p['start'][0]);end=date.fromisoformat(p['end'][0]);
     if end<start or (end-start).days>3652:raise ValueError('Неверный период (максимум 10 лет)')
     rows=[dict(r) for r in c.execute('SELECT day,available,sold,revenue,source FROM daily WHERE hotel_id=? AND day BETWEEN ? AND ? ORDER BY day',(h,start.isoformat(),end.isoformat()))]
     return self.reply({'rows':rows,'summary':summary(rows),'calendar_days':(end-start).days+1})
   self.reply({'error':'Не найдено'},404)
  except Exception as e:self.reply({'error':str(e)},400)
 def do_POST(self):
  if self.path in ('/auth/login','/auth/setup','/auth/logout'):
   if not self.allowed():return self.reply({'error':'Invalid host'},403)
   origin=self.headers.get('Origin')
   expected=('https://' if getattr(self.server,'private_mode',False) and self.headers.get('Host')==self.server.private_host else 'http://')+self.headers.get('Host')
   if not origin or origin!=expected:return self.reply({'error':'Invalid origin'},403)
   if self.path=='/auth/logout':
    from http.cookies import SimpleCookie
    c=SimpleCookie();c.load(self.headers.get('Cookie',''))
    token=c['atlas_session'].value if 'atlas_session' in c else ''
    with AUTH_LOCK:SESSIONS.pop(token,None)
    return self.auth_response(200,{'ok':True},'',True)
   n=int(self.headers.get('Content-Length','0'))
   if n<1 or n>4096:return self.reply({'error':'Invalid request size'},413)
   try:x=json.loads(self.rfile.read(n))
   except (ValueError,UnicodeError):return self.reply({'error':'Invalid JSON'},400)
   user=x.get('username','');password=x.get('password','')
   if not isinstance(password,str) or len(password)>256:return self.reply({'error':'Invalid password'},400)
   with AUTH_LOCK:
    if self.path=='/auth/setup':
     if getattr(self.server,'lan_mode',False) or getattr(self.server,'private_mode',False):return self.reply({'error':'Создавайте пароль только локально'},403)
     if AUTH_FILE.exists():return self.reply({'error':'Already configured'},403)
     if user!='admin' or len(password)<12:return self.reply({'error':'Пароль: минимум 12 символов'},400)
     write_auth(password)
    else:
     now=time.monotonic();recent=[t for t in FAILED.get('local',[]) if now-t<300]
     if len(recent)>=5:return self.reply({'error':'Слишком много попыток. Повторите через 5 минут.'},429)
     if not AUTH_FILE.exists():return self.reply({'error':'Setup required'},409)
     try:stored=json.loads(AUTH_FILE.read_text(encoding='utf-8'))['password_hash']
     except (OSError,ValueError,KeyError):return self.reply({'error':'Ошибка файла авторизации'},500)
     if user!='admin' or not valid_password(password,stored):
      recent.append(now);FAILED['local']=recent
      return self.reply({'error':'Неверный логин или пароль'},401)
     FAILED['local']=[]
    token=secrets.token_urlsafe(32);SESSIONS[token]=time.time()
   return self.auth_response(200,{'ok':True},token)
  if not self.gate(post=True):return
  try:
   n=int(self.headers.get('Content-Length','0'))
   if n>100000:self.reply({'error':'Слишком большой запрос'},413);return
   x=json.loads(self.rfile.read(n));now=datetime.now().isoformat(timespec='seconds')
   with connect() as c:
    if self.path=='/api/analyze-email':return self.reply(analyze_ai_email(x.get('text',''),x.get('thresholds',{})))
    if self.path=='/api/hotels':
     name=str(x['name']).strip();rooms=int(x['rooms']);
     if not name or rooms<=0:raise ValueError('Неверное название или число номеров')
     c.execute('INSERT INTO hotels(name,rooms) VALUES(?,?)',(name,rooms))
    elif self.path=='/api/daily':
     h=int(x['hotel_id']);day=date.fromisoformat(x['day']).isoformat();a=int(x['available']);s=int(x['sold']);r=float(x['revenue']);source=str(x.get('source','Ручной ввод')).strip()[:200]
     if a<0 or s<0 or s>a or not 0<=r<1e14:raise ValueError('Проверьте доступность, продажи и выручку')
     old=c.execute('SELECT available,sold,revenue,source FROM daily WHERE hotel_id=? AND day=?',(h,day)).fetchone()
     new={'available':a,'sold':s,'revenue':r,'source':source}
     if old:c.execute('INSERT INTO audit(hotel_id,day,old_data,new_data,changed_at) VALUES(?,?,?,?,?)',(h,day,json.dumps(dict(old),ensure_ascii=False),json.dumps(new,ensure_ascii=False),now))
     c.execute('INSERT INTO daily(hotel_id,day,available,sold,revenue,source,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(hotel_id,day) DO UPDATE SET available=excluded.available,sold=excluded.sold,revenue=excluded.revenue,source=excluded.source,updated_at=excluded.updated_at',(h,day,a,s,r,source,now))
    elif self.path=='/api/plans':
     start=date.fromisoformat(x['start']);end=date.fromisoformat(x['end']);t=float(x['target']);
     if end<start or not 0<=t<1e14:raise ValueError('Неверный план')
     c.execute('INSERT INTO plans(hotel_id,start,end,target,created_at) VALUES(?,?,?,?,?)',(int(x['hotel_id']),start.isoformat(),end.isoformat(),t,now))
    else:return self.reply({'error':'Не найдено'},404)
   self.reply({'ok':True})
  except Exception as e:self.reply({'error':str(e)},400)
 def log_message(self,*args):pass

if __name__=='__main__':
 try:
  print(bootstrap(),flush=True)
  backup('startup')
  setup()
 except Exception as exc:
  print('ATLAS: ЗАПУСК ОСТАНОВЛЕН. '+str(exc),flush=True)
  input('Нажмите Enter, чтобы закрыть окно...')
  sys.exit(1)
 lan_mode=os.environ.get('ATLAS_LAN_MODE')=='1'
 private_mode=os.environ.get('ATLAS_PRIVATE_MODE')=='1'
 private_host=os.environ.get('ATLAS_PRIVATE_HOST','').strip().lower()
 if private_mode and (lan_mode or not private_host or ':' in private_host or '/' in private_host):
  print('PRIVATE MODE: set ATLAS_PRIVATE_HOST to exact Tailscale HTTPS hostname, without scheme/port.');sys.exit(1)
 if lan_mode and not AUTH_FILE.exists():
  print('Сначала запустите START_ATLAS.bat и создайте пароль.',flush=True)
  input('Нажмите Enter...');sys.exit(1)
 if lan_mode:
  sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
  try:
   sock.connect(('192.0.2.1',80));lan_ip=sock.getsockname()[0]
  except OSError:lan_ip=''
  finally:sock.close()
  if not lan_ip or not ipaddress.ip_address(lan_ip).is_private or ipaddress.ip_address(lan_ip).is_loopback:
   print('Не найден локальный IPv4 Wi-Fi/сети. Запуск остановлен.');input('Нажмите Enter...');sys.exit(1)
 else:lan_ip='127.0.0.1'
 try:server=ThreadingHTTPServer(('0.0.0.0' if lan_mode else '127.0.0.1',8765 if lan_mode or private_mode else 0),Handler)
 except OSError as exc:
  print('Не удалось открыть порт:',exc);input('Нажмите Enter...');sys.exit(1)
 server.lan_mode=lan_mode;server.lan_ip=lan_ip;server.private_mode=private_mode;server.private_host=private_host
 url=f'http://127.0.0.1:{server.server_port}/login'
 print('ATLAS & KOBA 4.9 — вход по паролю',flush=True)
 if lan_mode:
  print('АДРЕС ДЛЯ ТЕЛЕФОНА: http://'+lan_ip+':8765/login',flush=True)
  print('ТОЛЬКО ДОВЕРЕННАЯ ЛОКАЛЬНАЯ СЕТЬ. HTTP без шифрования. НЕ открывайте порт на роутере и НЕ используйте публичный Wi-Fi.',flush=True)
 if not private_mode:threading.Timer(1,lambda:webbrowser.open(url)).start()
 try:server.serve_forever()
 except KeyboardInterrupt:pass
