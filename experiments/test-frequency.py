import backup

src = {"host": "", "path": "/home/mihanentalpo/bin"}
dest = {"host":"", "path":"/home/mihanentalpo/Desktop/tmp/bin-backup"}

#backup.go({"single":{"src":src, "dest":dest}})

dest_path = dest['path']
dest_host = dest['host']

delta = backup.Console.get_lastbackup_timedelta(dest_path, dest_host)

print(delta)

