import backup
import passwords
import json


mysql = backup.Mysql("root", "123root", "")

mysql.remove_dump("/home/var/mysql-backu")


