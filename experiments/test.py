from outer import read_custom_py_module

backup = read_custom_py_module("../backup.py")
import shutil
import time
# Этот файл содержит пароли к mysql-серверам. В репозиторий не добавлен из соображений безопасности
import passwords

backup_root = "/home/backuper/backup"
machine_backup_root = backup_root + "/machines/mihanlenovo"
mihanentalpo_me_backup_root = backup_root + "/machines/mihanentalpo.me"
backup_host = "backuper@terrarian"

variants = {
    "home_mihanentalpo": {
        "src": {"path":"/home/mihanentalpo", "host":""},
        "dest": {"path":machine_backup_root + "/home/mihanentalpo", "host":backup_host},
        "exclude": [
            "mihanentalpo/Torrents", "mihanentalpo/Music", "mihanentalpo/.cache",
            "mihanentalpo/.PyCharm40/system/caches", "mihanentalpo/.PyCharm50/system/caches",
            "mihanentalpo/.PyCharm50/system/LocalHistory", "mihanentalpo/.xsession-errors"
            "mihanentalpo/.PyCharm40/system/index", "mihanentalpo/.PyCharm40/system/log",
            "mihanentalpo/.PyCharm50/system/index", "mihanentalpo/.PyCharm50/system/log",
            "mihanentalpo/.thumbnails", "mihanentalpo/Downloads", "mihanentalpo/VirtualBox VMs",
            "mihanentalpo/.PyCharm40/system/index", "mihanentalpo/.TelegramDesktop/log.txt",
            "mihanentalpo/.config/freshwrapper-data/Shockwave Flash",
            "mihanentalpo/.config/transmission/resume", "*.pyc", "*.bak",
            "mihanentalpo/.PyCharm50/system", "mihanentalpo/.config/google-chrome/Default/Local Storage",
            "mihanentalpo/.config/google-chrome/Default/IndexedDB",
            "mihanentalpo/.config/google-chrome/Default/GPUCache", ".parentlock", "cookies.sqlite",
            "downloads.json", "mihanentalpo/.icedove/6xzgf26z.default/logs/irc",
            "mihanentalpo/.kde/share/apps/RecentDocuments",
            "mihanentalpo/.kde/share/apps/dolphin/view_properties/search",
            "mihanentalpo/.netbeans/8.0.2/var/filehistory",
            "mihanentalpo/git/UnrealEngine/Engine/DerivedDataCache"
        ],
    },
    "home_data": {
        "src": {"path":"/home/data", "host":""},
        "dest": {"path":machine_backup_root + "/home/data", "host":backup_host},
        "exclude": ["data/root_fs_pre_reinst.fsa"]
    },
    "home_mihanentalpo_music": {
        "src": {"path":"/home/mihanentalpo/Music", "host":""},
        "dest": {"path":machine_backup_root + "/home/mihanentalpo_Music", "host":backup_host},
        "exclude": []
    },
    "home_mihanentalpo_torrents": {
        "src": {"path":"/home/mihanentalpo/Torrents", "host":""},
        "dest": {"path":machine_backup_root + "/home/mihanentalpo_Torrents", "host":backup_host},
        "exclude": []
    },
    "home_mihanentalpo_downloads": {
        "src": {"path":"/home/mihanentalpo/Downloads", "host":""},
        "dest": {"path":machine_backup_root + "/home/mihanentalpo_Downloads", "host":backup_host},
        "exclude": []
    },
    "home_mihanentalpo_vboxvms": {
        "src": {"path":"/home/mihanentalpo/VirtualBox VMs", "host":""},
        "dest": {"path":machine_backup_root + "/home/mihanentalpo_VirtualBox_VMs", "host":backup_host},
        "exclude": ["Logs", "*.log.*", "*.log"]
    },
    "var_www": {
        "src": {"path":"/home/var/www", "host":""},
        "dest": {"path":machine_backup_root + "/var_www", "host":backup_host},
        "exclude": ["*.tar.gz", "*.zip", "*.sql", "*.tar", "*.log", "*~"]
    },
    "var_lib": {
        "src": {"path":"/home/var/lib", "host":""},
        "dest": {"path":machine_backup_root + "/var_lib", "host":backup_host},
        "exclude": ["*.tar.gz", "*.zip", "*.sql", "*.tar", "*.log", "*~"]
    },
    "local_mysql": {
        "src": {"path":"/home/var/mysql-backup", "host":""},
        "dest": {"path":machine_backup_root + "/mysql_backup", "host":backup_host},
        "mysqldump": {
            "user": passwords.local_mysql['user'], "password": passwords.local_mysql['password'],
            "sshhost" : passwords.local_mysql['sshhost'],
            "folder": "/home/var/mysql-backup",
            "filters": [
                ["include", "*", "*"],
            ],
            "remove_after_backup": False
        }
    },
    "mihanentalpo.me-files": {
        "src": {"path": "/var/www", "host":"mihanentalpo.me"},
        "dest": {"path": "/home/data/mihanentalpo.me/backup/files", "host":""},
        "exclude": [
            "*.log", "*.tar", "*.tar.gz", "*.zip", "*.sql",
            "www/2995575.ru/www/wp-content/cache",
        ]
    },
    "mihanentalpo.me-mysql": {
        "src": {"path": "/home/mihanentalpo/mysql-backup", "host":"mihanentalpo.me"},
        "dest": {"path": "/home/data/mihanentalpo.me/backup/database", "host":""},
        "mysqldump": {
            "user": passwords.mihanentalpo_me_mysql['user'], "password": passwords.mihanentalpo_me_mysql['password'],
            "sshhost" : passwords.mihanentalpo_me_mysql['sshhost'],
            "folder": "/home/mihanentalpo/mysql-backup",
            "filters": [
                ["include", "*", "*"],
            ]
        }
    }
}

pVariants = {}

# Выберем только определённые варианты
for v in ["local_mysql"]: #"home_mihanentalpo", "local_mysql", "home_data"]:
    pVariants[v] = variants[v]

backup.go(pVariants)

