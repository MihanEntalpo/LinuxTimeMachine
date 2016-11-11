import backup
import datetime

src = {"host": "", "path": "/home/mihanentalpo/bin"}
dest = {"host": "", "path": "/home/mihanentalpo/Desktop/tmp/bin-backup"}

backup.go({"single": {
    "src": src, "dest": dest, "min_timedelta": "30 seconds"
}})

dest_path = dest['path']
dest_host = dest['host']

delta = backup.Console.get_lastbackup_timedelta(dest_path, dest_host)

print(delta)

#timedelta = backup.Tools.make_time_delta("10 days 5 weeks 1 hours 1000 seconds 1 milliseconds")
#print(timedelta)
