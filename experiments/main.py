import backup
import conf

src_root = "/home"
dest_root = "/home/backuper/backup/machines/mihanlenovo/home"

src_host = ""
dest_host = "backuper@terrarian"
main_exclude = conf.exclude_patterns['normal']

folders = [
    {"path": "/mihanentalpo", "exclude": main_exclude +
        [
            "mihanentalpo/Torrents", "mihanentalpo/Music", "mihanentalpo/.cache",
            "mihanentalpo/.PyCharm40/system/caches", "mihanentalpo/.PyCharm50/system/caches",
            "mihanentalpo/.PyCharm40/system/index", "mihanentalpo/.PyCharm40/system/log",
            "mihanentalpo/.PyCharm50/system/index", "mihanentalpo/.PyCharm50/system/log",
            "mihanentalpo/.thumbnails"
        ]
    },
    {
        "path": "/data", "exclude": main_exclude
    }
]

for folder in folders:
    path = folder["path"]
    exclude = folder['exclude']
    backup.check_dest_folder(dest_root + path, dest_host)
    backup.rsync_timemachine(src_root + path, dest_root + path, exclude, src_host, dest_host)