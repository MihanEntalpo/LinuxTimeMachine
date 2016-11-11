import time
import passwords
from LinuxTimeMachine import backup

mysql = backup.Mysql("root", "123mihan", "mihanentalpo@localhost")

mysql.fill_cached_table_checksums()
hashes = mysql.cached_table_checksums

print(hashes)


