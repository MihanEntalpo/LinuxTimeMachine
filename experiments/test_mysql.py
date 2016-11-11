from LinuxTimeMachine import backup
import re
# Этот файл содержит пароли к mysql-сервера. В репозиторий не добавлен из соображений безопасности
import passwords

console = backup.Console()

#res = mysql.query(user, password, "USE information_schema; SELECT TABLE_SCHEMA, TABLE_NAME FROM TABLES", host)

db_conf = [
    ["include", "fcrm", "user"],
    ["include", "*", "*"]
    # ["include", "mihanentalpo_me", re.compile(".*")],
    # ["exclude", "mihanentalpo_me", ["wp_comments"]],
    # ["include", "*", ["af_goods"]]
]

mysql = backup.Mysql(**passwords.local_mysql)
#mysql = backup.Mysql(**passwords.local_mysql)

dbs = mysql.get_dbs_and_tbls()

#print(dbs)

#for db in dbs:
#    print(db + ":")
#    print(dbs[db])

filtered_dbs = mysql.filter_dbs_and_tbls(dbs, db_conf)

#print()

for db in filtered_dbs:
    print(db + ":")
    print(filtered_dbs[db])

mysql.dump_dbs(filtered_dbs, "/tmp/dump")

d = None
dd = dir(d)
ddd = dir(d[0])
#print(res)

#dbs = mysql.get_databases(user, password, host)
#print(dbs)

#for db in dbs:
#    print("База данных:" + db)
#    print("Таблицы:")
#    print(mysql.query(user, password, "USE " + db + "; SHOW TABLES;", host))

