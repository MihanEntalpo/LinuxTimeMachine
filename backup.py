#!/usr/bin/python3
"""
Здесь находятся библиотечные функции для создания резервных копий
"""
import datetime
import sys
import re
import copy
from subprocess import call, Popen, PIPE, check_output
import datetime
import time
import pexpect
import copy
import shlex

TimeMachineVersion = 1

class Console:
    # staticvariable
    _checked_ssh_hosts = {}

    @staticmethod
    def call_shell(code):
        try:
            retcode = call(code, shell=True)
            if retcode < 0:
                print("Child was terminated by signal", -retcode, file=sys.stderr)
            else:
                print("Child returned", retcode, file=sys.stderr)
        except OSError as e:
            print("Execution failed:", e, file=sys.stderr)

    @classmethod
    def write_file(cls, filename, content, sshhost=""):
        if sshhost:
            cls.check_ssh_or_throw(sshhost)
        data = content.encode("UTF-8")
        codes = ""
        for byte in data:
            codes = codes + "\\x" + hex(byte)[2:]
        cmd = "bash -c 'echo -e \"" + codes + "\" > " + cls.list2cmdline([filename]) + " ' "
        if sshhost:
            cmd = "ssh " + sshhost + " " + cls.list2cmdline([cmd])
        print("Writing file " + filename + (" on ssh:" + sshhost) if sshhost else " locally")
        print("Command: " + cmd)
        cls.call_shell_and_return(cmd)

    @classmethod
    def check_ssh_or_throw(cls, host):
        cssh = cls.check_ssh(host)
        if type(cssh) == Exception:
            raise Exception
        else:
            return cssh

    @classmethod
    def check_ssh(cls, host):
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
        try:
            output = check_output(code, shell=True)
            return output
        except OSError as e:
            print("Execution failed:", e, file=sys.stderr)

    @staticmethod
    def list2cmdline(seq):
        slist = []
        for item in seq:
            slist.append(shlex.quote(item))
        return " ".join(slist)

    @staticmethod
    def p_expect(pexpect_child, variants_dict, ssh=False):
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
        self.user = user
        self.password = password
        self.sshhost = sshhost
        self.cached_update_time = None
        self.remove_dbs = ["TABLE_SCHEMA", "information_schema", "mysql", "performance_schema"]
        self.remove_tables = []

    def query(self, query):
        pexvs = {}
        pexvs["mysql_pass"] = "Enter password:"
        pexvs["eof"] = pexpect.EOF

        cmd = Console.list2cmdline(["mysql", "-u" + self.user, "-p", "-e", query])

        if self.sshhost:
            Console.check_ssh_or_throw(self.sshhost)
            cmd = "ssh " + self.sshhost + " " + Console.list2cmdline([cmd])

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
        if self.cached_update_time is None:
            self.fill_cached_update_time()
        return self.cached_update_time[database][table]

    def call_dump(self, options, cmd_before="", cmd_after=""):
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

        cmd = "/bin/bash -c " + Console.list2cmdline([" && ".join(cmds)])

        if self.sshhost:
            Console.check_ssh_or_throw(self.sshhost)
            cmd = "ssh " + self.sshhost + " " + Console.list2cmdline([cmd])

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

    def dump_dbs(self, dbs, root_folder, use_update_time=True):
        Console.check_ssh_or_throw(self.sshhost)
        for db in dbs:
            folder = root_folder + "/" + db
            Rsync.check_dest_folder(folder, self.sshhost)

            for tbl in dbs[db]:
                table_update_date = self.get_table_change_date(db, tbl)

                filename = folder + "/" + tbl + ".structure.sql"
                self.call_dump(" -r " + Console.list2cmdline([filename]) + " " + Console.list2cmdline(
                        [
                            "--no-data",
                            "--add-drop-table",
                            db,
                            tbl
                        ]),
                        cmd_after=("echo -e '-- TMVERSION: #{version}#\\n" +
                                            "-- DB: #{db}#\\n" +
                                            "-- TBL: #{tbl}#\\n" +
                                            "-- TABLEUPDATEDATE: #{date}#' >> {filename}").format(
                                                date=table_update_date,
                                                filename=filename,
                                                version=TimeMachineVersion,
                                                tbl=tbl,
                                                db=db
                                   )
                )
                filename = folder + "/" + tbl + ".data.sql"
                self.call_dump(" -r " + Console.list2cmdline([filename]) + " " + Console.list2cmdline(
                        [
                            "--no-create-info",
                            db,
                            tbl
                        ]),
                        cmd_after=("echo -e '-- TMVERSION: #{version}#\\n" +
                                            "-- DB: #{db}#\\n" +
                                            "-- TBL: #{tbl}#\\n" +
                                            "-- TABLEUPDATEDATE: #{date}#' >> {filename}").format(
                                                date=table_update_date,
                                                filename=filename,
                                                version=TimeMachineVersion,
                                                tbl=tbl,
                                                db=db
                                            )
                )

    def get_dbs_and_tbls(self):
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
        selected_dbs = {}
        for rule in filters:
            if len(rule) != 3:
                raise Exception("filters Rule must be a list with 3 items")
            action, db, tables_raw = rule
            if action not in ["include", "exclude"]:
                raise Exception("first element of filters Rule must be 'include' or 'exclude'")
            if type(db).__name__ not in ["str", "SRE_Pattern"]:
                raise Exception(
                        "second element of filters Rule must be 'str' or 're.compile', but it's: " + type(db).__name__)
            if type(db).__name__ == "str":
                if db == "*":
                    db = re.compile(".*")
                else:
                    db = re.compile("^" + db + "$")
            if type(tables_raw).__name__ != "list":
                tables_raw = [tables_raw]

            tables = []
            for table in tables_raw:
                if type(table) == str:
                    if table == "*":
                        tables.append(re.compile(".*"))
                    else:
                        tables.append(re.compile("^" + table + "$"))
                elif type(table).__name__ == "SRE_Pattern":
                    tables.append(table)
                else:
                    raise Exception(
                            "tables must be 'str' or 're.compile', but one of tables' type:" + type(table).__name__)

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
    def check_dest_folder(dest, dest_host):
        """
        Убедиться в том, что папка назначения существует.
        Пытается создать папку со всеми родительскими папками
        :param dest: Папка
        :param dest_host: SSH-хост, или даже Пользователь@Хост
        """
        Console.check_ssh_or_throw(dest_host)
        cmd = Console.list2cmdline(["mkdir", "-p", dest])
        if dest_host:
            cmd = "ssh " + dest_host + " " + Console.list2cmdline([cmd])
        print("checking folder by command: " + cmd)
        Console.call_shell(cmd)

    def get_exists_progress_folders(self, dest, dest_host, tmp_dir="in-progress-"):
        """
        Получает список существующих папок in-progress
        :param dest: путь
        :param dest_host: пользователь@хост
        :param tmp_dir: формат имени папки (с чего она начинается)
        :return:

        """
        Console.check_ssh_or_throw(dest_host)
        cmd = "find '{dest}' -name {tmp_dir}* -maxdepth 1"
        if dest_host:
            cmd = 'ssh {dest_host} "' + cmd + '"'
        cmd = cmd.format(dest=dest, dest_host=dest_host, tmp_dir=tmp_dir)
        try:
            print(cmd)
            res = sorted([re.sub("^" + dest + "/", "", path) for path in
                          Console.call_shell_and_return(cmd).decode("UTF-8").split("\n") if path])
        except Exception as e:
            res = ""
        return res

    def mv(self, src, dest, host=""):
        """
        Выполняет команду "mv" на локальном или на удалённом хосте
        :param src: исходное имя
        :param dest: конечное имя
        :param host: пользователь@хост
        """
        cmd = "mv '" + src + "' '" + dest + "'"
        if host:
            cmd = "ssh " + host + " \"" + cmd + "\""
        Console.call_shell(cmd)

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
                    self.mv(dest_path + "/" + folder, dest_path + "/" + renamed, dest_host)
            self.mv(dest_path + "/" + last_folder, dest_path + "/" + cur_dir, dest_host)

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

        self.check_dest_folder(dest['path'], dest['host'])

        self.use_exists_progress_folders(dest['path'], dest['host'], params['cur_tmp_dir'])

        cmds = [
            (
                "rsync -axv --info=progress2 --delete {exclude_str} --link-dest='{latest_dir}' '{src_full}' '{dest_full}/{cur_tmp_dir}'",
                True),
            ("{cmd_pre} mv '{dest_path}/{cur_tmp_dir}' '{dest_path}/{date}' {cmd_post}", False),
            ("{cmd_pre} rm -f '{dest_path}'/Latest {cmd_post}", False),
            ("{cmd_pre} ln -s '{dest_path}/{date}' '{dest_path}'/Latest {cmd_post}", False)
        ]

        for (cmd, is_rsync) in cmds:
            raw_cmd = cmd.format(**params)
            print("Command: " + raw_cmd)
            if (is_rsync):
                self.go(raw_cmd, callback)
            else:
                Console.call_shell(raw_cmd)
