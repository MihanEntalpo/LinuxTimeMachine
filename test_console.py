import backup
import passwords
import json

mysql = backup.Mysql(**passwords.mihanentalpo_me_mysql)
old_info = mysql.get_old_dump_info("/tmp/dump")
print(old_info)

