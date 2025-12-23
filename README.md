# LinuxTimeMachine

LinuxTimeMachine — утилита резервного копирования для Linux, работающая по принципам Time Machine из macOS. Проект написан на Python и использует `rsync` для копирования файлов и `mysqldump` для резервирования баз данных MySQL.

## Возможности
- Инкрементальные копии файлов в каталогах с временными метками, что позволяет экономить место и быстро восстанавливаться.
- Поддержка локальных и удалённых (через SSH) источников и хранилищ.
- Автоматическое создание дампов MySQL с последующей проверкой и, при необходимости, удалением после передачи.
- Гибкая система конфигурации: варианты резервного копирования описываются в файлах YAML, JSON или Python, которые располагаются в `~/.config/LinuxTimeMachine/variants`.
- Плагинная архитектура (Yapsy) даёт возможность расширять функциональность.
- Очистка устаревших копий по настраиваемым правилам командой `sweep`.
- Удобный CLI на базе `click`.

## Установка
```bash
git clone https://github.com/yourname/LinuxTimeMachine.git
cd LinuxTimeMachine
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
Также необходимы системные утилиты `rsync` и `mysqldump`.

## Пример конфигурации
Пример файла `~/.config/LinuxTimeMachine/variants/example.py`:

```python
# Файл с описанием вариантов резервного копирования
variants = {
    "site": {  # название варианта
        "description": "Резервное копирование каталога сайта",  # произвольное описание
        "src": {  # источник данных
            "path": "/var/www/site/public_html/modules",  # путь к каталогу на исходной машине
            "host": "user@site.com"  # хост, откуда копировать (оставьте пустым для локального)
        },
        "dest": {  # хранилище резервных копий
            "path": "/backup/site",  # путь, куда сохранять бэкапы
            "host": ""  # хост назначения (пустая строка — локальный каталог)
        },
        "exclude": ["*.log", "*.tar", "*.zip"],  # маски исключаемых файлов
        "min_timedelta": "1 hour",  # минимальный интервал между копиями
        "mysqldump": {  # параметры создания дампа MySQL
            "user": "root",  # пользователь БД
            "password": "secret",  # пароль пользователя
            "sshhost": "user@db.example.com",  # хост, на котором делать дамп
            "folder": "/backup/mysql",  # каталог для хранения дампов
            "filters": ["site_db.*"],  # шаблоны баз/таблиц
            "remove_after_backup": True  # удалить дамп после передачи
        },
        "sweep": {  # политика удаления старых копий
            "1 day": "1 hour",   # в первые сутки — копия каждый час
            "1 week": "1 day",   # затем неделю — копия раз в день
            "1 month": "1 week"  # затем месяц — копия раз в неделю
        }
    }
}
```

## Использование
Список доступных конфигураций:

```bash
python cli.py list
```

Запуск резервного копирования для конкретного варианта:

```bash
python cli.py backup --run site
```

Если нужно запустить резервное копирование, игнорируя ограничение по минимальному
интервалу между бэкапами (`min_timedelta`), добавьте флаг `--skip-frequency-check`:

```bash
python cli.py backup --run site --skip-frequency-check
```

Удаление устаревших копий:

```bash
python cli.py sweep --run site
```

## Подробнее
Подробное описание системы и примеры использования доступны в статье:
[Linux Time Machine на базе Python, rsync и MySQL](https://mihanentalpo.me/2017/03/linux-time-machine-на-базе-python-rsync-mysql/).

