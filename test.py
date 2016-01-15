import backup
import shutil
import time
# Этот файл содержит пароли к mysql-серверам. В репозиторий не добавлен из соображений безопасности
import passwords

rsync = backup.Rsync()

def rsync_callback(data):
    if data['type'] == "progress":
        try:
            speed = data['speed']
            if speed > 1024**3:
                data['speed'] = str(round(speed / (1024**3), 2)) + "GB/s"
            elif speed > 1024**2:
                data['speed'] = str(round(speed / (1024**2), 2)) + "MB/s"
            elif speed > 1024:
                data['speed'] = str(round(speed / (1024), 2)) + "KB/s"
            print("Progress:{progress}%, checked {ir_chk_top} / {ir_chk_bottom}, speed: {speed}".format(**data))
        except Exception as e:
            print(data)
            print(e)
    elif data['type'] == "path":
        print("Last copied file: " + data['path'])
    elif data['type'] == "message":
        print("Message: " + data['message'])
    else:
        print(data)

backup_root = "/home/backuper/backup"
machine_backup_root = "/home/backuper/backup/machines/mihanlenovo"
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
            "mihanentalpo/.config/transmission/resume", "*.pyc"
        ]
    },
    "home_data": {
        "src": {"path":"/home/data", "host":""},
        "dest": {"path":machine_backup_root + "/home/data", "host":backup_host},
        "exclude": []
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
            "user": "", "password": "", "host": "", "folder": "/home/var/mysql-backup",
            "dbs_filter": [
                ["include", "*", "*"],
            ]
        }.update(passwords.local_mysql)
    },
}

summ_time = 0

#variants = {"home_mihanentalpo":variants["home_mihanentalpo"]}

for node in variants:
    print("*****************" + "*" * len(node) + "**")
    print("* Backuping node " + node + " *")
    print("*****************" + "*" * len(node) + "**")
    start_time = time.clock()
    if "mysqldump" in variants[node]:
        mysqldump = variants[node]['mysqldump']
        del variants[node]['mysqldump']

        dbs = backup.Mysql.filter_dbs_and_tbls(
            backup.Mysql.get_dbs_and_tbls(mysqldump['user'], mysqldump['password'], mysqldump['host']),
            mysqldump['dbs_filter']
        )
        backup.Mysql.dump_dbs(mysqldump['user'], mysqldump['password'], mysqldump['host'], dbs, mysqldump['folder'])

    rsync.timemachine(callback=rsync_callback, **variants[node])
    end_time = time.clock()
    dtime = end_time - start_time
    print("Time: " + str(dtime))
    summ_time += dtime

print("Full time:" + str(summ_time))

