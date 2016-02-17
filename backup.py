#!/usr/bin/python3
"""
Здесь находятся библиотечные функции для создания резервных копий
"""
import datetime
import sys
import os
import re
from subprocess import call, Popen, PIPE, check_output
import datetime
import time
import pexpect
import copy
import shlex
import json
import yaml
import types
from io import StringIO

TimeMachineVersion = 1


class Tools:
    @staticmethod
    def getNestedDictValue(dictionary, *keys):
        """
        Функция получает из вложенного dict-а элемент, либо None.
        Например, у нас есть данные о фруктах в виде вложенных dict-ов:
        a = {"fruits": {"apple": {"color":"red", "price":"100"}, "orange": {"color":"orange", "proce":50}}}
        Получить цену яблока:
        apple_price = Tools.getNestedDictValue(a, "fruits", "apple", "price")
        Получить данные об апельсине:
        orange_info = Tools.getNestedDictValue(a, "fruits", "orange")
        А вот такой запрос не вызовет ошибку, а просто вернёт None (так как арбуза у нас нет):
        watermelon_price = Tools.getNestedDictValue(a, "fruits", "watermelon", "price")
        :param dictionary: вложенный словарь dict
        :param keys: массив ключей, последовательно выбираемых из вложенных dict-ов
        :return:
        """
        pointer = dictionary
        for key in keys:
            if key not in pointer:
                return None
            else:
                pointer = pointer[key]
        return pointer


class Conf:
    @staticmethod
    def read_conf_dir(dir_path):
        """
        Считать все конфигурационные файлы из указанной папки.
        Файлы считываются в алфавитном порядке, и если среди файлов будут одинаковые варианты, они будут прочитаны позднее
        :param dir_path: Путь к папке
        :return: dict с объединённой конфигурацией файлов
        """
        if (not os.path.exists(dir_path)):
            print("Configuration folder '{}' doesn't exists".format(dir_path))
        filenames = [file for file in os.listdir(dir_path) if re.search("\.(py3?|ya?ml|json)$", file)]
        files = [dir_path + "/" + file for file in sorted(filenames)]
        if len(files) == 0:
            print("There are no config files in folder '{}'".format(dir_path))
        for file in files:
            return Conf.read_conf_file(file)

    @staticmethod
    def read_conf_files(files):
        """
        Считывает набор файлов
        :param files: массив файлов (list или set)
        :return: dict с объединёнными конфигурациями файлов
        """
        data = {}
        assert isinstance(files, (list, set))
        for file in files:
            file_data = Conf.read_conf_file(file)
            data.update(file_data)
        return data

    @staticmethod
    def read_py_conf_file(file):
        with open(file, "r") as f:
            code = f.read()
        new_module = types.ModuleType("new_temporary_module")
        exec(code, new_module.__dict__)
        if "variants" in new_module.__dict__:
            return new_module.variants
        else:
            pass
            #raise Exception("File {} should contain 'variants' variable, but it's not.".format(file))

    @staticmethod
    def read_conf_file(filename):
        """
        Считывает один конфигурационный файл
        :param filename: имя файла
        :return: dict с настройками из файла
        """
        assert(filename, str)

        regs = {
            "py": ".*\.py3?$",
            "json": ".*\.json$",
            "yaml": ".*\.ya?ml$"
        }

        filetype = None
        for curtype in regs:
            if re.search(regs[curtype], filename):
                filetype = curtype
                break
        if filetype is None:
            raise Exception("Config file {} must have extension .py, .json, .yaml or .yml".format(filename))
        content = ""
        with open(filename, "r") as f:
            content = f.read()

        conf = {}

        if content:
            if filetype == "py":
                conf = Conf.read_py_conf_file(filename)
            elif filetype == "json":
                conf = json.loads(content)
            elif filetype == "yaml":
                conf = yaml.load(StringIO(content))

        return conf



class Console:
    # staticvariable
    _checked_ssh_hosts = {}
    _checked_dest_folders = {}

    @staticmethod
    def rm(path, host=""):
        """
        Удаляет файл на локальном или удалённом хосте. Один файл!
        :param path: str путь к файлу
        :param host: str ssh-хост
        :return:
        """
        cmd = Console.cmd(Console.list2cmdline(["rm", path]), host)
        print("Command: " + cmd)
        Console.call_shell(cmd)

    @staticmethod
    def mv(src, dest, host=""):
        """
        Выполняет команду "mv" на локальном или на удалённом хосте
        :param src: исходное имя
        :param dest: конечное имя
        :param host: пользователь@хост
        """
        cmd = Console.cmd(
            Console.list2cmdline(["mv", src, dest]), host
        )
        Console.call_shell(cmd)

    @staticmethod
    def cmd(cmd, sshhost=""):
        """
        Заворачивает указанную команду в вызов ssh, или просто возвращает её, если sshhost не задан
        :param cmd: команда
        :param sshhost: ssh-хост, в формате user@host.com
        :return:
        """
        if sshhost:
            cmd = "ssh " + sshhost + " " + Console.list2cmdline([cmd])
        return cmd

    @staticmethod
    def call_shell(code):
        """
        Выполнить команду в консоли
        :param code: Команда
        """
        try:
            retcode = call(code, shell=True)
            if retcode < 0:
                print("Child was terminated by signal", -retcode, file=sys.stderr)
            else:
                print("Child returned", retcode, file=sys.stderr)
        except OSError as e:
            print("Execution failed:", e, file=sys.stderr)

    @staticmethod
    def check_dest_folder(dest, dest_host):
        """
        Убедиться в том, что папка назначения существует.
        Пытается создать папку со всеми родительскими папками.
        Кэширует результат выполнения, так что можно вызывать сколько угодно, сработает только первый
        :param dest: Папка
        :param dest_host: SSH-хост, или Пользователь@Хост
        """
        Console.check_ssh_or_throw(dest_host)
        if dest_host in Console._checked_dest_folders:
            if dest in Console._checked_dest_folders[dest_host]:
                return True
        else:
            Console._checked_dest_folders[dest_host] = {}
        cmd = Console.cmd(Console.list2cmdline(["mkdir", "-p", dest]), dest_host)
        print("checking folder by command: " + cmd)
        Console.call_shell(cmd)
        Console._checked_dest_folders[dest_host][dest] = True

    @classmethod
    def write_file(cls, filename, content, sshhost=""):
        """
        Записать файл на локальный или удалённый хост.
        Используется например для записи bash-скриптов на удалённый сервер
        :param filename: str имя файла
        :param content: str контент файла
        :param sshhost: str SSH-хост
        """
        if sshhost:
            cls.check_ssh_or_throw(sshhost)
        cls.check_dest_folder(os.path.dirname(filename), sshhost)
        data = content.encode("UTF-8")
        codes = ""
        for byte in data:
            codes = codes + "\\x" + hex(byte)[2:]
        cmd = Console.cmd("bash -c 'echo -e \"" + codes + "\" > " + cls.list2cmdline([filename]) + " ' ", sshhost)
        print("Writing file " + filename + ((" on ssh:" + sshhost) if sshhost else " locally"))
        #print("Command: " + cmd)
        cls.call_shell_and_return(cmd)

    @classmethod
    def check_ssh_or_throw(cls, host):
        """
        Проверить SSH-хост, и если он не работает - бросить исключение
        :param host: str хост
        :return: Boolean, как правило True
        """
        cssh = cls.check_ssh(host)
        if type(cssh) == Exception:
            raise Exception
        else:
            return cssh

    @classmethod
    def check_ssh(cls, host):
        """
        Проверить ssh-хост на возможность подключиться к нему без пароля
        кэширует результаты в переменной, так что медленным будет только первый вызов,
        остальные будут мгновенными
        :param host: хост для подключения к ssh
        :return: True если удалось подключиться и Exception (именно возвращает, а не кидает его) если нет
        """
        if host == "":
            return True
        if host not in cls._checked_ssh_hosts:
            cmd = "ssh " + host + " " + cls.list2cmdline([cls.list2cmdline(["echo", "testmessage"])])
            p = pexpect.spawn(cmd)
            res = Console.p_expect(p, {
                "ssh_first_connect": "Are you sure you want to continue connecting",
                "ssh_password_required": "s password:",
                "ok": "testmessage",
                "eof": pexpect.EOF
            })
            if res in ["ssh_first_connect", "ssh_password_required"]:
                data = p.before.decode("UTF-8")
                result = Exception("ssh cannot connect automatically, message: " + data)
            elif res == "ok":
                result = True
            elif res == pexpect.EOF:
                data = p.before.decode("UTF-8")
                print(data)
                result = Exception("ssh unknown error: " + data)
            else:
                data = p.before.decode("UTF-8")
                print(data)
                result = Exception("ssh unknown error: " + data)

            cls._checked_ssh_hosts[host] = result

        return cls._checked_ssh_hosts[host]

    @staticmethod
    def call_shell_and_return(code):
        """
        Выполняет код в консоли и возвращает то, что консоль вернула в ответ (stdout)
        :param code: строка, код для запуска в консоли
        :return: строка, текст, возвращённый консолью
        """
        try:
            output = check_output(code, shell=True)
            return output
        except OSError as e:
            print("Execution failed:", e, file=sys.stderr)

    @staticmethod
    def list2cmdline(seq):
        """
        Превратить массив из команды и параметров в строку для запуска в консоли.
        Выполняет экранирование всяких плохих символов
        :param seq: массив из команды и параметров
        :return: строка
        """
        slist = []
        for item in seq:
            slist.append(shlex.quote(item))
        return " ".join(slist)

    @staticmethod
    def p_expect(pexpect_child, variants_dict, ssh=False):
        """
        Обёртка над объектом pexpect, в отличии от него, умеет возвращать
        осмысленные "названия" произошедших событий (pexpect может только номера), а также,
        умеет реагировать на ошибки работы по ssh.
        :param pexpect_child: Объект, полученный при выполнении pexpect.spawn(...)
        :param variants_dict: dict, ключи которого - имена событий, а значения - текстовые строки, которые программа
                              должна вывести, чтобы это послужило сигналом этих событий.
        :param ssh: True/False использовать ли проверку на ошибки подключения по ssh.
                    При такой ошибке кидается исключение
        :return: Возвращает название события
        """
        vd = copy.deepcopy(variants_dict)
        if ssh:
            vd["ssh_first_connect"] = "Are you sure you want to continue connecting"
            vd["ssh_password_required"] = "s password:"
        keys, values = vd.keys(), vd.values()
        res = pexpect_child.expect(list(values))
        dres = list(keys)[res]
        if ssh:
            if dres in ("ssh_first_connect", "ssh_password_required"):
                pexpect_child.sendline("n")
                data = (pexpect_child.before + pexpect_child.after).decode("UTF-8")
                raise Exception("Error non-interactive connecting to ssh: " + data)

        return dres


class Mysql:
    def __init__(self, user, password, sshhost):
        """
        Конструктор класса
        :param user: пользователь
        :param password: пароль
        :param sshhost: ssh-хост, на котором находится mysql-сервер (или с которого к нему можно подключиться)
        """
        self.user = user
        self.password = password
        self.sshhost = sshhost
        self.cached_update_time = None
        self.remove_dbs = ["TABLE_SCHEMA", "information_schema", "mysql", "performance_schema"]
        self.remove_tables = []

    def query(self, query):
        """
        Выполнить запрос в mysql. Выполняется посредством запуска консольного клиента, и передачи ему SQL-запрос
        :param query: SQL-запрос
        :return: текст, возвращённый mysql-клиентом (разумеется, просто строка, никаких "записей, полей" и т.д.
                 парсить этот результат придётся самостоятельно.
        """
        pexvs = {}
        pexvs["mysql_pass"] = "Enter password:"
        pexvs["eof"] = pexpect.EOF

        cmd = Console.cmd(Console.list2cmdline(["mysql", "-u" + self.user, "-p", "-e", query]), self.sshhost)

        p = pexpect.spawn(cmd)
        res = Console.p_expect(p, pexvs, ssh=(self.sshhost != ""))
        if res == "mysql_pass":
            p.sendline(self.password)
            p.read(len(self.password) + 1)
            data = p.read().decode("UTF-8")
            if re.search("ERROR\ [0-9]+.*?at line [0-9]+:", data):
                raise Exception("MysqlError: " + data)
            return data
        elif res == "eof":
            data = p.before.decode("UTF-8")
            raise Exception("Error while calling mysql: " + data)

    def fill_cached_update_time(self):
        """
        Заполнить кэш времени обновлений таблиц баз данных.
        Выполняет запрос, получающий от mysql список баз данных, таблиц, и даты последнего изменения этих таблиц.
        Результат парсится, и заносится в кэш для дальнейшего быстрого доступа
        """
        print("Filling cached update time")
        data = self.query(
                'USE  information_schema; ' +
                'SELECT CONCAT("&", table_schema, "&") as db, ' +
                'CONCAT("&", table_name, "&") as tbl, ' +
                'CONCAT("&", IFNULL(update_time, create_time), "&") as update_date ' +
                'FROM `TABLES`'
        )
        lines = data.split("\r\n")
        line_re = re.compile("&(?P<db>.*?)&.*?&(?P<tbl>.*?)&.*?&(?P<update_date>.*?)&")
        dbs = {}
        for line in lines:
            matches = line_re.search(line)
            if matches:
                d = matches.groupdict()
                if d['db'] not in dbs:
                    dbs[d['db']] = {}
                dbs[d['db']][d['tbl']] = d['update_date']

        self.cached_update_time = dbs

    def get_table_change_date(self, database, table):
        """
        Получить дату изменения таблицы
        возвращает дату изменения из кэша (построенного функцией fill_cached_update_time), а если кэш пуст - вызывает
        эту самую функцию (fill_cached_update_time)
        :param database: имя базы данных
        :param table: имя таблицы
        :return: дата изменения
        """
        if self.cached_update_time is None:
            self.fill_cached_update_time()
        return self.cached_update_time[database][table]

    def call_dump(self, options, cmd_before="", cmd_after=""):
        """
        Запустить скрипт mysql_dump на сервере
        :param options: набор опций, передаваемых в mysqldump (обычные, все кроме -u и -p)
        :param cmd_before: консольная команда, которую нужно выполнить ДО запуска, например, удалить прошлый дамп
        :param cmd_after: консольная команда, которую нужно выполнить ПОСЛЕ запуска, например внести какие-то изменения
                          в файлы дампа
        """
        pexvs = {}
        pexvs["mysqldump_pass"] = "Enter password:"
        pexvs['mysqldump_usage'] = "Usage: mysqldump"
        pexvs["eof"] = pexpect.EOF

        if type(options) not in [str]:
            raise Exception("Options must be a str, but it's:" + type(options).__name__)

        dump_cmd = Console.list2cmdline(["mysqldump", "-u" + self.user, "-p"]) + " " + options

        cmds = []
        if cmd_before:
            cmds.append(cmd_before)
        cmds.append(dump_cmd)
        if cmd_after:
            cmds.append(cmd_after)

        cmd = Console.cmd("/bin/bash -c " + Console.list2cmdline([" && ".join(cmds)]), self.sshhost)

        Console.check_ssh_or_throw(self.sshhost)

        print(cmd)

        p = pexpect.spawn(cmd)

        res = Console.p_expect(p, pexvs, ssh=(self.sshhost != ""))

        if res == "mysqldump_pass":
            p.sendline(self.password)
            p.read(len(self.password) + 1)
            data = p.read().decode("UTF-8")
            print(data)
        elif res == "mysqldump_usage":
            data = (p.before + p.after).decode("UTF-8")
            p.expect(pexpect.EOF)
            data += (p.before).decode("UTF-8")
            raise Exception("Options not are bad, mysqldump returned :\n" + data)
        elif res == "eof":
            data = (p.before).decode("UTF-8")
            raise Exception("Error while calling mysql: " + data)

    def remove_dump(self, root_folder):
        print("Removing dump from: " + root_folder)
        Console.call_shell(
            Console.cmd("find '" + root_folder + "' -type f -name *.sql -exec rm {} \;", self.sshhost)
        )
        Console.call_shell(
            Console.cmd("find '" + root_folder + "' -type d -empty -delete")
        )


    def dump_dbs(self, dbs, root_folder, force_dump_intact=False):
        """
        Выполнить дамп баз данных по таблицам в отдельные файлы.
        Для каждой базы данных создаётся отдельная папка, а в ней, для каждой таблицы
        создаётся файл со структурой и файл с данными.
        Перед началом дампа собирается информация о том, каковы даты изменения таблиц, хранящиеся в уже сделанных ранее
        дампах (если они были), чтобы не перезаписывать те таблицы, которые не изменились.
        При дампе, в каждый файл дописывается дата изменения таблицы, которая как раз и используется для исключения
        лишней работы.
        :param dbs: dict, ключи которого - имена баз данных, а значения - массивы имён таблиц
        :param root_folder: папка, в которую нужно складывать дампы баз данных
        :param force_dump_intact: True/False, нужно ли перезаписывать даже не изменённые файлы таблиц
        :return:
        """
        old_dump_info = self.get_old_dump_info(root_folder)

        def dump_params(filename, tbl, db, save_data, save_structure):
            """
            Замыкание формирует параметры для запуска mysql_dump конкретной базы и конкретной таблицы
            :param filename: имя файла, куда сохранять дамп
            :param tbl: имя таблицы
            :param db: имя базы данных
            :param save_data: сохранять ли данные? boolean
            :param save_structure: сохранять структуру? boolean
            :return:
            """
            table_update_date = self.get_table_change_date(db, tbl)

            base_filename = os.path.basename(filename)

            table_old_update_date = Tools.getNestedDictValue(old_dump_info, db, tbl, base_filename)

            if table_old_update_date == table_update_date and not force_dump_intact:
                return None

            param_array = []

            if not save_data:
                param_array.append("--no-data")

            if not save_structure:
                param_array.append("--no-create-info")

            param_array.append("--add-drop-table"),

            param_array += [db, tbl]
            params = {
                "options":" -r " + Console.list2cmdline([filename]) + " " + Console.list2cmdline(param_array),
                "cmd_after":("echo -e '-- LTMINFO: TMVERSION:#{version}# " +
                                    " DB:#{db}#" +
                                    " TBL:#{tbl}#" +
                                    " TABLEUPDATEDATE:#{date}#' >> {filename}").format(
                                        date=table_update_date,
                                        filename=filename,
                                        version=TimeMachineVersion,
                                        tbl=tbl,
                                        db=db
                )
            }
            return params

        def call_dump(filename, tbl, db, save_data, save_structure):
            """
            Замыкание, вызывающее дамп одной таблицы
            :param filename: имя файла, куда надо сохранить дамп
            :param tbl: название таблицы
            :param db: название базы данных
            :param save_data: сохранять данные? boolean
            :param save_structure: сохранять структуру? boolean
            :return:
            """
            params = dump_params(filename, tbl, db, save_data, save_structure)

            if params is None:
                print("Bypassing table " + tbl + " from database " + db + " (data not changed)")
            else:
                Console.check_dest_folder(folder, self.sshhost)
                self.call_dump(**params)

        Console.check_ssh_or_throw(self.sshhost)

        for db in dbs:
            folder = root_folder + "/" + db

            for tbl in dbs[db]:
                call_dump(folder + "/" + tbl + ".structure.sql", tbl, db, False, True)
                call_dump(folder + "/" + tbl + ".data.sql", tbl, db, True, False)

    def get_old_dump_info(self, folder):
        """
        Получить информацию о старых дампах.
        загружает на удалённый (или локальный, в зависимости от sshhost) сервер bash-скрипт, который сканирует папку
        в поиска SQL-дампов, и пытается прочитать данные о дате изменения. Что прочитал - выводит в ответ.
        После загрузки bash-скрипта, он запускается, считываются отображённые им данные, и заносятся в dict
        :param folder:
        :return: многомерный dict, содержащий информацию о старых дампах
        """
        old_info = {}

        bash_file = folder + "/old_dump_info.sh"

        text = """#!/bin/bash
        FOLDER="%folder%"
        cd $FOLDER
        IFS=$'\\n'
        FILES=`find -name "*.sql"`
        NUM=`echo "$FILES" | wc -l`
        for FILE in $FILES
        do
            INFO=`tail -n2 $FILE | grep -e LTMINFO:`
            if [ -n "$INFO" ]
            then
                echo -n "INFO: $INFO"
                FILENAME=`basename $FILE`
                echo " FILE:#$FILENAME#"
            fi
        done
        IFS=" "
        echo "Done"
        """.replace("%folder%", folder)

        Console.write_file(bash_file, text, self.sshhost)

        cmd = Console.cmd(" bash '" + bash_file + "'", self.sshhost)

        result = Console.call_shell_and_return(cmd).decode("UTF-8").split("\n")
        reg = re.compile("INFO: -- LTMINFO: TMVERSION:#(?P<TMVERSION>[0-9\.]+)#  DB:#(?P<DB>[^#]+)# TBL:#(?P<TBL>[^#]+)# TABLEUPDATEDATE:#(?P<TABLEUPDATEDATE>[^#]+)# FILE:#(?P<FILE>[^#]+)#")
        for line in result:
            matches = reg.search(line)
            if matches:
                d = matches.groupdict()
                db = d['DB']
                tbl = d['TBL']
                update_date = d['TABLEUPDATEDATE']
                file = d['FILE']
                version = d['TMVERSION']
                if int(version) == TimeMachineVersion:
                    if db not in old_info:
                        old_info[db] = {}
                    if tbl not in old_info[db]:
                        old_info[db][tbl] = {}
                    old_info[db][tbl][file] = update_date

        Console.rm(bash_file, self.sshhost)

        return old_info

    def get_dbs_and_tbls(self):
        """
        Получить список баз данных и таблиц.
        Получает базы и таблицы путём запроса к консольному mysql-клиенту
        :return: dict, ключи которого - имена баз, а значения - массивы с именами таблиц каждой базы,
                 например {"first_db": ["table1", "table2", "table3"], "second_db": ["table4", "table5"]}
        """
        Console.check_ssh_or_throw(self.sshhost)
        result_raw = self.query(
                'USE information_schema; SELECT CONCAT("&", TABLE_SCHEMA, "&") as db,' +
                ' CONCAT("&", TABLE_NAME, "&") as tbl FROM TABLES'
        )
        result_lines = result_raw.split("\r\n")
        re_line = re.compile("&(?P<database>.*?)&.*?&(?P<table>.*?)&")

        dbs = {}
        for line in result_lines:
            cmp = re_line.search(line)
            if cmp:
                data_line = cmp.groupdict()
                if data_line['database'] not in self.remove_dbs:
                    if data_line['database'] not in dbs:
                        dbs[data_line['database']] = []
                    if data_line['table'] not in self.remove_tables:
                        dbs[data_line['database']].append(data_line['table'])

        return dbs

    def filter_dbs_and_tbls(self, dbs, filters):
        """
        Отфильтровать базы данных и таблицы по заданным правилам
        :param dbs: dict базы данных и таблицы, со структурой, аналогичной той,
                    которую возвращает функция get_dbs_and_tbls
        :param filters: массив фильтров. Каждый фильтр - это также массив, состоящий из трёх значений - действия,
                        базы и таблицы.
                        Пример:
                        [
                            ["include", "*", "*"] # включить все базы и все таблицы
                            ["exclude", "*", "_log$"] # исключить из всех баз таблицы, заканчивающиеся на _log
                            ["include", "mydb", "important_log"] # добавить таблтицу important_log из базы mydb
                        ]
                        то есть, первый параметр - либо "include" либо "exclude".
                        второй параметр - либо "*", либо регулярное выражение, определяет правило отбора баз данных
                                         ("*" - аналог регулярного выражения ".*"
                        третий параметр - тоже самое, но для выбора таблиц.

                        Изначально не выбрано ничего, фильтры проходятся по очереди, и, в соответствии с их действием,
                        ("include" или "exlude") производится добавление БД и таблиц в результирующий список, либо
                        удаление из него.

        :return: dict баз данных и таблиц, формат аналогичен параметру dbs
        """
        selected_dbs = {}
        for rule in filters:
            if len(rule) != 3:
                raise Exception("filters Rule must be a list with 3 items")

            action, db_raw, tables_raw = rule

            if action not in ["include", "exclude"]:
                raise Exception("first element of filters Rule must be 'include' or 'exclude'")

            assert(type(db_raw).__name__ == "str")

            if (db_raw == "*"):
                db_raw = ".*"
            db = re.compile("^" + db_raw + "$")

            if type(tables_raw).__name__ != "list":
                tables_raw = [tables_raw]

            tables = []
            for table in tables_raw:
                assert(type(table).__name__ == "str")
                if table == "*":
                    table = ".*"
                tables.append(re.compile("^" + table + "$"))

            if action == "include":
                dbs_to_go = dbs
            else:
                dbs_to_go = selected_dbs
            for db_name in dbs_to_go:
                if db.search(db_name):
                    for table_re in tables:
                        for table in dbs[db_name]:
                            if table_re.search(table):
                                if action == "include":
                                    if db_name not in selected_dbs:
                                        selected_dbs[db_name] = []
                                    if table not in selected_dbs[db_name]:
                                        selected_dbs[db_name].append(table)
                                elif action == "exclude":
                                    if table in selected_dbs[db_name]:
                                        selected_dbs[db_name].remove(table)
        return selected_dbs


class Rsync:
    """
    Класс, предназначенный для запуска процесса резервного копирования
    """
    def __init__(self):
        self.line_parsers = [
            {
                "type": "progress",
                "re": "(?P<bytes>[0-9,]+)\ +(?P<progress>[0-9]+)%\ +(?P<speed>[0-9\.]+[MKGTmkgt])B/s\ +" +
                      "(?P<time>(?P<hour>[0-9]+):(?P<minute>[0-9]+):(?P<second>[0-9]+))\ +" +
                      "\(xfr#(?P<xfr_num>[0-9]+), ir-chk=(?P<ir_chk_top>[0-9]+)/(?P<ir_chk_bottom>[0-9]+)\)",
                "parser": lambda res: {
                    "time": int(res['second']) + 60 * int(res['minute']) + 3600 * int(res['hour']),
                    "type": "progress",
                    "bytes": int(res['bytes'].replace(",", "")),
                    "speed": float(res['speed'][0:-1]) * self.multipliers[res['speed'][-1].upper()],
                    "progress": float(res['progress']),
                    "xfr_num": int(res['xfr_num']),
                    "ir_chk_top": int(res['ir_chk_top']),
                    "ir_chk_bottom": int(res['ir_chk_bottom'])
                }
            },
            {
                "type": "info",
                "re": "^(?P<message>sending incremental file list)$",
                "parser": lambda res: {'message': res['message'], 'type': 'info'}
            },
            {
                "type": "info",
                "re": "^(?P<message>created directory) (?P<path>[^\0]+)$",
                "parser": lambda res: {'message': res['message'], 'type': 'info', 'path': res['path']}
            },
            {
                "type": "result_stat",
                "re": ("sent\ +(?P<sent>[0-9,]+)" +
                       "\ +bytes\ +received\ +(?P<received>[0-9,]+)\ +bytes\ +(?P<speed>[0-9,\.]+) bytes/sec"),
                "parser": lambda res: {
                    "type": "result_stat",
                    "sent": int(res['sent'].replace(',', "")),
                    "received": int(res['received'].replace(",", "")),
                    "speed": float(res['speed'].replace(",", ""))
                }
            },
            {
                "type": "error",
                "re": ("(?P<message>IO error encountered -- skipping file deletion)"),
                "parser": lambda res: {
                    "type": "error",
                    "message": res['message']
                }
            },
            {
                "type": "progress_path",
                "re": "(?P<path>[^\0]+)",
                "parser": lambda res: {"path": res['path'], "type": "path"}
            }
        ]

        self.multipliers = {"K": 1024, "M": 1024 * 1024, "G": 1024 * 1024 * 1024}

    @staticmethod
    def default_callback(data):
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

    def get_exists_progress_folders(self, dest, dest_host, tmp_dir="in-progress-"):
        """
        Получает список существующих папок in-progress
        :param dest: путь
        :param dest_host: пользователь@хост
        :param tmp_dir: формат имени папки (с чего она начинается)
        :return:

        """
        Console.check_ssh_or_throw(dest_host)
        cmd = Console.cmd("find '{dest}' -name {tmp_dir}* -maxdepth 1", dest_host)
        cmd = cmd.format(dest=dest, dest_host=dest_host, tmp_dir=tmp_dir)
        try:
            print(cmd)
            res = sorted([re.sub("^" + dest + "/", "", path) for path in
                          Console.call_shell_and_return(cmd).decode("UTF-8").split("\n") if path])
        except Exception as e:
            res = ""
        return res

    def use_exists_progress_folders(self, dest_path, dest_host, cur_dir, tmp_dir="in-progress-"):
        """
        Использовать существующую папку in-progress (продолжить копирование если оно было прервано
        :param dest_path: Пункт назначения
        :param dest_host: Пользователь@Хост
        :param cur_dir: Текущее имя временной папки, например in-progress-2015-12-25_10:30:05"
        :param tmp_dir: Шаблон имён временных папок
        :return:
        """
        Console.check_ssh_or_throw(dest_host)
        folders = self.get_exists_progress_folders(dest_path, dest_host, tmp_dir)
        if len(folders) == 0:
            return False
        else:
            last_folder = folders.pop()
            if len(folders):
                for folder in folders:
                    renamed = "old-" + folder
                    Console.mv(dest_path + "/" + folder, dest_path + "/" + renamed, dest_host)
            Console.mv(dest_path + "/" + last_folder, dest_path + "/" + cur_dir, dest_host)

    def parse_line(self, line, callback):
        """
        Распарсить строку, получаемую из rsync
        :param line: str Строка
        :param callback: Функция, которой будут переданы результирующие данные
        :return:
        """
        uline = line.decode("UTF-8")
        for parser_conf in self.line_parsers:
            matches = re.search(parser_conf['re'], uline)
            if matches is not None:
                if parser_conf["type"] == "progress":
                    pass
                res = parser_conf['parser'](matches.groupdict())
                callback(res)
                return True

        return False

    def go(self, cmd, progress_callback=lambda x: x):
        ps = Popen(cmd + " | tr '\\r' '\\n'", close_fds=True, shell=True, stdout=PIPE, stderr=PIPE)
        line = b""
        delta = 0.001
        while ps.poll() is None:
            line = ps.stdout.readline().strip(b"\n")
            if line:
                if not self.parse_line(line, progress_callback):
                    print("<LINE>" + line.decode("UTF-8") + "</LINE>\n")
            time.sleep(delta)

        line = ps.stdout.readline().strip(b"\n")
        if line:
            if not self.parse_line(line, progress_callback):
                print("<LINE LAST>" + line.decode("UTF-8") + "</LINE>\n")

    def timemachine(self, src, dest, exclude=[], callback=lambda x: x):
        assert isinstance(src, dict)
        assert "path" in src
        assert "host" in src
        assert isinstance(dest, dict)
        assert "path" in dest
        assert "host" in dest

        Console.check_ssh_or_throw(dest['host'])
        Console.check_ssh_or_throw(src['host'])

        exclude_str = " ".join(['--exclude "{}"'.format(item) for item in exclude])

        date = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")

        params = {
            "exclude_str": exclude_str,
            "src_path": src['path'],
            "src_host": src['host'],
            "src_full": (src['host'] + ":" + src['path']) if src['host'] else src['path'],
            "dest_path": dest['path'],
            "dest_host": dest['host'],
            "dest_full": (dest['host'] + ":" + dest['path']) if dest['host'] else dest['path'],
            "date": date,
            "latest_dir": "../Latest",
            "cmd_pre": ("ssh " + dest["host"] + " \"") if dest['host'] else "",
            "cmd_post": " \"" if dest['host'] else "",
            "cur_tmp_dir": "in-progress-" + date
        }

        Console.check_dest_folder(dest['path'], dest['host'])

        self.use_exists_progress_folders(dest['path'], dest['host'], params['cur_tmp_dir'])

        cmds = [
            (
                "rsync -axv --info=progress2 --delete {exclude_str} --link-dest='{latest_dir}' '{src_full}' '{dest_full}/{cur_tmp_dir}'",
                True),
            ("{cmd_pre} mv '{dest_path}/{cur_tmp_dir}' '{dest_path}/{date}' {cmd_post}", False),
            ("{cmd_pre} rm -f '{dest_path}/Latest' {cmd_post}", False),
            ("{cmd_pre} ln -s '{dest_path}/{date}' '{dest_path}/Latest' {cmd_post}", False)
        ]

        for (cmd, is_rsync) in cmds:
            raw_cmd = cmd.format(**params)
            print("Command: " + raw_cmd)
            if (is_rsync):
                self.go(raw_cmd, callback)
            else:
                Console.call_shell(raw_cmd)


def go(variants, rsync_callback=Rsync.default_callback):

    def print_asterisked(text):
        print("**" + "*" * len(text) + "**")
        print("* " + text + " *")
        print("**" + "*" * len(text) + "**")

    assert(type(variants)==dict)
    summ_time = 0
    for variant_name in variants:

        variant = copy.deepcopy(variants[variant_name])

        print_asterisked("Backuping variant `" + variant_name + "`")

        start_time = time.time()

        mysqldump = None

        if "mysqldump" in variant:
            mysqldump = variant['mysqldump']
            assert(type(mysqldump) == dict)
            assert("user" in mysqldump)
            assert("password" in mysqldump)
            assert("sshhost" in mysqldump)
            assert("filters" in mysqldump)
            assert("folder" in mysqldump)
            del variant['mysqldump']

            remove_after_backup = mysqldump.get("remove_after_backup", False)

            mysql = Mysql(mysqldump['user'], mysqldump['password'], mysqldump['sshhost'])

            dbs = mysql.filter_dbs_and_tbls(
                mysql.get_dbs_and_tbls(),
                mysqldump['filters']
            )

            print_asterisked("Dumping mysql dbs for variant `" + variant_name + "`")

            mysql.dump_dbs(dbs, mysqldump['folder'])

            print_asterisked("Dumping mysql dbs for variant `" + variant_name + "` is done!")

        print_asterisked("Rsync is started for variant `" + variant_name + "`")

        rsync = Rsync()

        rsync.timemachine(callback=rsync_callback, **variant)

        end_time = time.time()
        dtime = end_time - start_time
        summ_time += dtime

        print_asterisked("Rsync for variant `" + variant_name + "` is done, time is:" + str(dtime))

        if mysqldump and remove_after_backup:
            print_asterisked("Remove mysql DB dump after rsync")
            mysql.remove_dump(mysqldump["folder"])


    print_asterisked("Backup is done, full time is:" + str(summ_time))
