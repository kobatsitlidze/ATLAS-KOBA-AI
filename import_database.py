from pathlib import Path
from tkinter import Tk, filedialog
from atlas import DB, migrate, verify
if DB.exists():
 print('Постоянная база уже существует. Импорт не выполнен: история защищена.')
else:
 root=Tk();root.withdraw()
 name=filedialog.askopenfilename(title='Выберите atlas_data.sqlite3 из ATLAS 3.2',filetypes=[('SQLite database','*.sqlite3')])
 root.destroy()
 if name:
  try:
   migrate(Path(name))
   print('ГОТОВО. База проверена, перенесена и сохранена резервная копия. Запустите START_ATLAS.bat')
  except Exception as exc:print('ОШИБКА:',exc)
 else:print('Импорт отменён. Данные не изменены.')
