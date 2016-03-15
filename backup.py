#!/usr/bin/python3
""" Linux Time Machine

Makes backup copies in a way as Mac' TimeMachine does.

Detailed documentation can be found at https://mihanentalpo.me/....

Required: Python 3.2 or later
Required packages: pexpect, pyyaml, json

"""

TimeMachineVersion = 1

__version__ = str(TimeMachineVersion)
__license__ = """Copyright (c) 2000-2016, Mihanentalpo, All rights reserved.
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 'AS IS'
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE."""


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
from collections import OrderedDict as Odict
from io import StringIO


class Tools:
    @staticmethod
    def get_nested_dict_value(dictionary, *keys):
        """
        Get element from nested dict object, or None, if it doesn't exists
        For, exampl, if we have data:
        a = {"fruits": {"apple": {"color":"red", "price":"100"}, "orange": {"color":"orange", "proce":50}}}
        Get apple's price:
        apple_price = Tools.get_nested_dict_value(a, "fruits", "apple", "price")
        Get all orange's data:
        orange_info = Tools.get_nested_dict_value(a, "fruits", "orange")
        Try to get non-existing data would return Non
        watermelon_price = Tools.get_nested_dict_value(a, "fruits", "watermelon", "price")
        :param dictionary: nested dict objct
        :param keys: array of keys, sequentally taken form dicts
        :return:
        """
        pointer = dictionary
        for key in keys:
            if key not in pointer:
                return None
            else:
                pointer = pointer[key]
        return pointer

    @staticmethod
    def make_time_delta(src):
        if type(src) == datetime.timedelta:
            delta = src
        elif type(src) == dict:
            params = {}
            for name in ["days", "weeks", "hours", "minutes", "seconds", "milliseconds", "microseconds"]:
                if name in src:
                    params[name] = src[name]
            delta = datetime.timedelta(**params)
        elif type(src) == str:
            matches = re.findall(
                "(([0-9]+)\ *(days|weeks|hours|minutes|seconds|milliseconds|microseconds))",
                re.sub("[,;]", " ", src)
            )
            params = {}
            for match in matches:
                num = int(match[1])
                name = match[2]
                params[name] = num

            delta = datetime.timedelta(**params)

        return delta


class Conf:
    """
    Configuration reader class
    reads files of py, json and yaml types.
    File structure have to be:

    for python:

    variants = {
        "variant1" : {
            ...
        },
        "variant2" : {
            ...
        }
        ...
    }

    for json:

    {
        "variant1" : {
            ...
        },
        "variant2" : {
            ...
        }
    }

    for yaml:

    variant1:
      ...
    variant2:
      ...

    """
    @staticmethod
    def read_conf_dir(dir_path):
        """
        Read all config files in spcified folder, in alphabetical order. So, if files conain identical variants,
        the ones, read early would be replaced by the ones, read later.
        :param dir_path: path to folder
        :return: nested dict, with merged backup variants from all files
        """
        if (not os.path.exists(dir_path)):
            print("Configuration folder '{}' doesn't exists".format(dir_path))
        filenames = [file for file in os.listdir(dir_path) if re.search("\.(py3?|ya?ml|json)$", file)]
        files = [dir_path + "/" + file for file in sorted(filenames)]
        if len(files) == 0:
            print("There are no config files in folder '{}'".format(dir_path))
        conf = Odict()
        print("Found config files:" + ", ".join(files))
        for file in files:
            variants = Conf.read_conf_file(file)
            if variants is not None:
                conf.update(variants)
        return conf

    @staticmethod
    def read_conf_files(files):
        """
        Read list of config files
        :param files: file list
        :return: nested dict with merged backup variants from all files
        """
        data = {}
        assert isinstance(files, (list, set))
        for file in files:
            file_data = Conf.read_conf_file(file)
            data.update(file_data)
        return data

    @staticmethod
    def read_py_conf_file(file):
        """
        Read .py config file
        :param file: filename
        :return: nested dict with variants, readed from file
        """
        path = os.path.dirname(file)
        curpath = os.path.curdir
        os.chdir(path)
        with open(file, "r") as f:
            code = f.read()
        new_module = types.ModuleType("new_temporary_module")
        exec(code, new_module.__dict__)
        os.chdir(curpath)
        if "variants" in new_module.__dict__:
            return new_module.variants
        else:
            pass
            #raise Exception("File {} should contain 'variants' variable, but it's not.".format(file))

    @staticmethod
    def read_conf_file(filename):
        """
        Read single config file
        :param filename: file name, should have "*.py", "*.json", "*.yaml" or "*.yml" extension, so, loader
                         could recognize, what method should be used to load file
        :return: dict, containing backup variants from file
        """
        assert isinstance(filename, str)

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
        Remove file from local or remote host. Just a single file!
        :param path: str file path
        :param host: str ssh-host
        :return:
        """
        cmd = Console.cmd(Console.list2cmdline(["rm", path]), host)
        print("Command: " + cmd)
        Console.call_shell(cmd)

    @staticmethod
    def get_backup_dirs(path, host=""):
        """
        Get all backup copies dirs, in some path.
        backup dirs are copies with names like "2016-10-11_12:44:01", each is a copy, made at some time
        :param path: str Path, where backups was made
        :param host: str ssh host (if any)
        :return: list dirnames (like "2016-10-11_12:44:01")
        """
        cmd = Console.cmd(
            Console.list2cmdline(
                [
                    "find", path,
                    "-type", "d",
                    "-maxdepth", "1",
                    "-regextype", "grep",
                    "-regex", path + "/[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}_[0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}"
                ]
            ), host
        )

        if host:
            Console.check_ssh_or_throw(host)

        backup_dirs = sorted([
            d[len(path)+1:] for d in Console.call_shell_and_return(cmd).decode("UTF-8").split("\n") if d
        ], reverse=True)

        return backup_dirs

    @staticmethod
    def get_dirname_of_datetime(date):
        """
        Get dir name from datetime object
        :param date: datetime object
        :return: str dir name
        """
        dir = date.strftime("%Y-%m-%d_%H:%M:%S")
        return dir

    @staticmethod
    def get_datetime_of_dirname(dir):
        """
        Get datetime object from dirname "2016-03-13_21:42:29"
        :param dir: str имя папки
        :return: datetime объект даты/времени
        """
        try:
            date = datetime.datetime.strptime(dir, "%Y-%m-%d_%H:%M:%S")
        except Exception as e:
            date = None
        return date

    @staticmethod
    def mv(src, dest, host=""):
        """
        Call "mv" console command on local or remove host
        :param src: source name
        :param dest: destination name
        :param host: ssh-host
        """
        cmd = Console.cmd(
            Console.list2cmdline(["mv", src, dest]), host
        )
        Console.call_shell(cmd)

    @staticmethod
    def cmd(cmd, sshhost=""):
        """
        Wrap console command into ssh call, or just return it, if no sshhost suplied
        :param cmd: command
        :param sshhost: ssh-host
        :return:
        """
        if sshhost:
            cmd = "ssh " + sshhost + " " + Console.list2cmdline([cmd])
        return cmd

    @staticmethod
    def call_shell(code):
        """
        Run console command on a local host.
        :param code: Command
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
    def get_lastbackup_timedelta(dest_path, dest_host):
        """
        Return timedelta between now and last backup
        :param dest_path: str backup dest dir
        :param dest_host: str backup ssh host
        :return:
        """
        backup_dirs = Console.get_backup_dirs(dest_path, dest_host)
        if len(backup_dirs):
            first_date = Console.get_datetime_of_dirname(backup_dirs[0])
            delta = datetime.datetime.now() - first_date
        else:
            delta = datetime.datetime.now() - datetime.datetime(1970, 1, 1, 0, 0, 0)
        return delta

    @staticmethod
    def check_dest_folder(dest_path, dest_host):
        """
        Ensure, that destination folder exists. If it's not, create it by
        "mkdir -p" command, which creates folder and all it's parents.
        After that, put result in cache, so, next calls would be much faster.
        Works locally or remotely
        :param dest_path: str destination folder
        :param dest_host: str sshhost of destination
        """
        Console.check_ssh_or_throw(dest_host)
        if dest_host in Console._checked_dest_folders:
            if dest_path in Console._checked_dest_folders[dest_host]:
                return True
        else:
            Console._checked_dest_folders[dest_host] = {}
        cmd = Console.cmd(Console.list2cmdline(["mkdir", "-p", dest_path]), dest_host)
        print("checking folder by command: " + cmd)
        Console.call_shell(cmd)
        Console._checked_dest_folders[dest_host][dest_path] = True

    @classmethod
    def write_file(cls, filename, content, sshhost=""):
        """
        Write file to local or remote host, by console command.
        Used, for example, to write a bash script, that checks mysql_dump files for creation datetime
        :param filename: str filename
        :param content: str content of the file
        :param sshhost: str sshhost
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
        Check if ssh host accessible, and throw an exception otherwise.
        Uses check_ssh method.
        :param host: str sshhost
        :return: Boolean, (usually it's True)
        """
        cssh = cls.check_ssh(host)
        if type(cssh) == Exception:
            raise Exception
        else:
            return cssh

    @classmethod
    def check_ssh(cls, host):
        """
        Check if ssh host is accessible without password.
        Caching result of check, so, next tries would be blazing fast
        :param host: sshhost
        :return: True, if connection successfully established, and Exception otherwise (used by check_ssh_or_throw)
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
        Run console command, and returns textual result of it.
        :param code: code, that should be runned in the consoloe
        :return: str, text, returned by a command
        """
        try:
            output = check_output(code, shell=True)
            return output
        except OSError as e:
            print("Execution failed:", e, file=sys.stderr)

    @staticmethod
    def list2cmdline(seq):
        """
        Convert an array, consists of command and arguments to a shell-ready command string
        Example: list2cmdline(["ls", "-la", "/home/my folder with spaces/somethere"]) would return:
        ls -la "/home/my folder with spaces/somethere" (its escaping params, that needed it)
        :param seq: array of command and arguments
        :return: resulting command
        """
        slist = []
        for item in seq:
            slist.append(shlex.quote(item))
        return " ".join(slist)

    @staticmethod
    def p_expect(pexpect_child, variants_dict, ssh=False):
        """
        Wraper pexpect object, that returns meaningfull names for happened events, not just numbers.
        Usage:
            p = pexpect.spawn("mysql -uroot -p 'show databases;'")
            result = p_expect(p, {"mysql want password":"Enter password", "some error":"Error"}),
            in case, of mysql echoes "Enter password", string "mysql want password" would be returned
        Also, could adequately react to a ssh errors, that could be caused by inability to connect without password
        :param pexpect_child: pexpect object, returned by call of pexpect.spawn(...)
        :param variants_dict: dict, which has event names in the keys, and event recognition strings as the values
        :param ssh: True/False Use ssh testing? If enabled, and SSH issued a error, Excetion would be raised
        :return: str name of event, recognized by pexpect
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
        :param user: mysql user
        :param password: mysql password
        :param sshhost: sshhost, there mysqlserver is placed, or, there it could be reached from
        """
        self.user = user
        self.password = password
        self.sshhost = sshhost
        self.cached_update_time = None
        self.remove_dbs = ["TABLE_SCHEMA", "information_schema", "mysql", "performance_schema"]
        self.remove_tables = []

    def query(self, query):
        """
        Execute SQL query and return results. Query is executed with use of console mysql client on a host.
        Result returned in form, used by console mysql client, no parsing is made, so result should be parsed manually
        :param query: SQL-query
        :return: text, returned by mysql server.
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
        Fill table's update time cache.
        Executes SQL-query, that take UPDATE_TIME of every table in every database on the server, and but it into
        nested dict, for future fast access
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
        Get table update_time. Used to compare last dumped file's information and current update_time, to skip
        not changed tables from dumping. Use cached data, if it's not available, fills cache.
        :param database: database name
        :param table: table name
        :return: str update_time in mysql datetime format
        """
        if self.cached_update_time is None:
            self.fill_cached_update_time()
        return Tools.get_nested_dict_value(self.cached_update_time, database, table)

    def call_dump(self, options, cmd_before="", cmd_after=""):
        """
        Run mysqldump script on server
        :param options: list of usual mysqldump options, passed to a mysqldump. Don't use -u and -p here!
        :param cmd_before: console command, that should be runned before mysqldump start
        :param cmd_after: console command, that should be runned after mysqldump finished
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
        """
        Remove mysql dumps from a folder.
        Removes all *.sql files from specified folder, and then tries to remove all the empty folders found inside it.
        If no other files (not *.sql) was places there, folder would be fully cleaned
        :param root_folder: str folder, there dump was places
        :return:
        """
        print("Removing dump from: " + root_folder)
        Console.call_shell(
            Console.cmd("find '" + root_folder + "' -type f -name *.sql -exec rm {} \;", self.sshhost)
        )
        Console.call_shell(
            Console.cmd("find '" + root_folder + "' -type d -empty -delete")
        )


    def dump_dbs(self, dbs, root_folder, force_dump_intact=False):
        """
        Run mysql_dump of databases. Fully aoutmatic wrapper around call_dump method
        Create separate folder for each database. Each table stored in two sql-files:
        *.data.sql - dump of the data, *.structure.sql - dump of table's structure (CREATE TABLE query)
        Appends special info to every file, contains backuper version, table update_time. With the help of this info,
        found in previous versions of dump files, function bypasses some tables, which update_time not changed till the
        last dump.

        :param dbs: dict, there keys are database names, and values are lists's of tables names
        :param root_folder: folder, where to store backup
        :param force_dump_intact: True/False, do we need to ignore table's update_time, stored in previous dump files?
        """
        old_dump_info = self.get_old_dump_info(root_folder)

        def dump_params(filename, tbl, db, save_data, save_structure):
            """
            This closure form parameters for mysql_dump call with specific database and table
            :param filename: str dump filename
            :param tbl: str table name
            :param db: str database name
            :param save_data: boolean store table data?
            :param save_structure: boolean store table structure?
                    (save_data and save_structure could not be both True or both False)
            :return: dict of params
            """
            table_update_date = self.get_table_change_date(db, tbl)

            base_filename = os.path.basename(filename)

            table_old_update_date = Tools.get_nested_dict_value(old_dump_info, db, tbl, base_filename)

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
            Closure, starts dump for a single table
            :param filename: str dump filename
            :param tbl: str table name
            :param db: str database name
            :param save_data: boolean store table data?
            :param save_structure: boolean store table structure?
                   (save_data and save_structure could not be both True or both False)
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
        Get information about existing dump files
        Upload to a remote (or local) host bash script, that scans dump folder, and extracts data lines,
        containing update_time, and outputs it.
        After upload, run the script, and recieve all it's return data.
        :param folder: str root folder of previous dums
        :return: nested dict, containing info about dump's update_time
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
        Get all database and tables list
        run mysql query, that returns all the databases and tables from mysql server.
        :return: dict, where keys are database names, and values are list's consists of tables.
                 for example: {"my_database_1" : ["table1", "table2", "table3"], "my_database_2": ["table4", "table5"]}
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
        Filter databases and tables by specified criteries.

        :param dbs: dict, contains databases and tables, in format, returned by get_dbs_and_tbls
        :param filters: filters list. Each filter is also a list, consists of three values - action, database, table
                        Example:
                        [
                            ["include", "*", "*"] # include all databases and tables
                            ["exclude", "*", "_log$"] # exclude all tables, which name ends with "_log", all databases
                            ["include", "mydb", "important_log"] # include table important_log from mydb database
                        ]
                        first parameter should be "include" or "exclude"
                        second parameter - "*", or regular expression, defines rule of selection databases
                                           ("*" - is analog of ".*" regular expression)
                        third parameter is analogous to second parameter, but for table selection

                        At the beginning, there are nothing selected, filters are runned one by one, and, according to
                        it's actions ("include" or "exclude") adding DBs and tables to the resulting list, or removing
                        from it.

        :return: dict Databases and tables, in format, similiar to dbs param
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
    Class, used to run Rsync
    """
    def __init__(self):
        """
        Init function.
        build line_parsers - it's a list of parser rules, that used to get useful information form rsync output.
        every parser rule is a dict, consists of three fields:
        "type" - name of line type (for example, "progress" means, that this is line, contains progress information)
        "re" - regular expression, that line would be compared to, and in case of success, it would be source of
                information (for example, string line (?P<bytes>[0-9]+) would put "bytes" into result of regexp
                matching. Dict with this params would be passed into "parser" function
        "parser" - lambda or function, taking single dict parameter with data, acquired from succesfull regular
                expression run. "parser" should return dict, that would be final information, ready to use. This
                dict passed to a rsync output callback, used in "timemechine" function

        """
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
        """
        Default rsync information print callback
        :param data:
        :return:
        """
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
        Get existing in-progress folders
        :param dest: str destication path
        :param dest_host: destination ssh host
        :param tmp_dir: in-progress dir prefix
        :return:

        """
        Console.check_ssh_or_throw(dest_host)
        cmd = Console.cmd("find '{dest}' -maxdepth 1 -name {tmp_dir}*", dest_host)
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
        Use existing in-progress folder as current (by renaming it to current datetime)
        For example, if your previuos backup was interrupted, and temporary progress folder
        had name "in-progress-2015-12-25_10:00:00", and you want to untilize it by under name
        "in-progress-2015-12-25_10:30:05", this function will rename it to you (and only the last folder, if there
        are several folders, having name, starts with "in-progress-"
        :param dest_path: destination path
        :param dest_host: destination sshhost
        :param cur_dir: Current progress folder name, like "in-progress-2015-12-25_10:30:05"
        :param tmp_dir: Prefix of the progress folders' names
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
        Parse line, outputted by rsync, and call callback to process result data.
        Rules of parsing are placed in self.line_parsers
        Example of callback is in default_callback function
        :param line: str line
        :param callback: function, that accepts dict, and doing something with it.
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
        """
        Run rsync, with raw command line and callback to process rsync's output
        :param cmd: command line, that runs rsync
        :param progress_callback: callback, used by parse_line function
        :return:
        """
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
        """
        Run rsync backup by build it's command line and pass it to "go" function of the class.
        Checks destination folder, and untilize existing in-progress-* folder, if any.
        :param src: dict, source location that must contain "path" and "host" fields,
                    for example {"path":"/home", "host": ""}
        :param dest: dict, formatted like src param, for example:
                    for example {"path":"/mnt/raid/backup/my_home_dir", "host": "backuper@my_backup_server.local"}
        :param exclude: list of excludes, passed to rsync. Example:
                        [
                            "*.log", "*.tar.gz", "*.sql", # exclude files of specific patterns
                            "home/guest_user", "home/user/torrents", # exclude specific paths
                        ]
        :param callback: function, that would parse output of rsync (passed into "go" and "parse_line")
        """
        assert isinstance(src, dict)
        assert "path" in src
        assert "host" in src
        assert isinstance(dest, dict)
        assert "path" in dest
        assert "host" in dest

        Console.check_ssh_or_throw(dest['host'])
        Console.check_ssh_or_throw(src['host'])

        exclude_str = " ".join(['--exclude "{}"'.format(item) for item in exclude])

        date = Console.get_dirname_of_datetime(datetime.datetime.now())

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
    """
    Run backup variants - full backup operation, include files and mysql (if needed) backup.
    :param variants: dict, contains backup variants. Keys of this dict is variant names, and values are dicts itself,
                     each one contains options, that should be passed to Rsync.timemachine and Mysql.dump_dbs
                     Example:
                     {
                        "my_home": {
                            "src": {"path":"/home/me", "host":""},
                            "dest": {"path":"/mnt/raid/backup/me_home", "host":"me@backupserver.local"},
                            "exclude" : ["*.log", "*~", "me/tmp", "me/Music", "me/Torrents"]
                            "mysqldump" : {
                                "user" : "root",
                                "password" : "grE4%0_re^$",
                                "sshhost": "",
                                "filters": [
                                    ["include", "*", "*"],
                                    ["exclude", "_recovery$", "*"]
                                ],
                                "folder": "/home/me/mysql_dump"
                            }
                        }
                     }
    :param rsync_callback: callback, used to utilize information, outputted by rsync.
                     default is Rsync.default_callback (can be used as an example)
    :return:
    """
    def print_asterisked(text):
        print("**" + "*" * len(text) + "**")
        print("* " + text + " *")
        print("**" + "*" * len(text) + "**")

    assert(type(variants) in [dict, Odict])
    summ_time = 0
    for variant_name in variants:

        variant = copy.deepcopy(variants[variant_name])

        print_asterisked("Backuping variant `" + variant_name + "`")

        start_time = time.time()

        mysqldump = None

        if "min_timedelta" in variant:
            min_timedelta = Tools.make_time_delta(variant["min_timedelta"])
            print("Min timedelta is: " + str(min_timedelta))
            lastbackup_timedelta = Console.get_lastbackup_timedelta(variant['dest']['path'], variant['dest']['host'])
            print("Last backup timedelta is: " + str(lastbackup_timedelta))
            if lastbackup_timedelta > min_timedelta:
                print("Last backup was further when min timedelta, continue to backup")
            else:
                print_asterisked("Backup of variant `" + variant_name + "` is skipped, to high backup frequency")
                continue
            del variant["min_timedelta"]

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
