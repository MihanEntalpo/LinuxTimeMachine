import backup
import re
# Этот файл содержит пароли к mysql-сервера. В репозиторий не добавлен из соображений безопасности
import passwords

console = backup.Console()

#res = mysql.query(user, password, "USE information_schema; SELECT TABLE_SCHEMA, TABLE_NAME FROM TABLES", host)

db_conf = [
    ["include", "mihanentalpo_me", re.compile(".*")],
    ["exclude", "mihanentalpo_me", ["wp_comments"]],
    ["include", re.compile(".*"), ["af_goods"]]
]


mysql = backup.Mysql(**passwords.mihanentalpo_me_mysql)
#mysql = backup.Mysql(**passwords.local_mysql)


dbs = mysql.get_dbs_and_tbls()

#print(dbs)

#for db in dbs:
#    print(db + ":")
#    print(dbs[db])

filtered_dbs = mysql.filter_dbs_and_tbls(dbs, [["include", "webasyst_newjevi", "blog_post_params"]])

#print()

for db in filtered_dbs:
    print(db + ":")
    print(filtered_dbs[db])

mysql.dump_dbs(dbs, "/tmp/dump")


#print(res)

#dbs = mysql.get_databases(user, password, host)
#print(dbs)

#for db in dbs:
#    print("База данных:" + db)
#    print("Таблицы:")
#    print(mysql.query(user, password, "USE " + db + "; SHOW TABLES;", host))

