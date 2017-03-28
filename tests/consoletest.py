"""
Unit test for Console class in LinuxTimeMachine.backup
"""

from LinuxTimeMachine.backup import Console
from LinuxTimeMachine.backup import Log
from LinuxTimeMachine.backup import logging

import unittest
import re
import os
import random
import datetime
import pexpect


class ConsoleTestCase(unittest.TestCase):

    def setUp(self):
        Log.I(logging.ERROR, reset=True)

    def get_random_file(self):
        r = random.randint(1, 1000000)
        filename = "/tmp/test_" + str(r) + ".txt"
        while os.path.exists("/tmp/test_" + str(r) + ".txt"):
            r = random.randint(1, 1000000)
            filename = "/tmp/test_" + str(r) + ".txt"
        return filename

    def test_call_shell(self):
        code = int(Console.call_shell("/bin/false"))
        self.assertTrue(code == 1, "Return of /bin/false")

    def test_call_shell_and_return(self):
        ret = Console.call_shell_and_return("echo 'test'").decode("UTF-8").strip()
        self.assertTrue(ret == "test", "echo 'test'")

    def test_check_dest_folder(self):
        filename = self.get_random_file()
        os.mkdir(filename)
        self.assertTrue(Console.check_dest_folder(filename), "Really existent folder")
        os.rmdir(filename)
        filename2 = self.get_random_file()
        self.assertTrue(Console.check_dest_folder(filename2), "Really non-existent folder")
        self.assertTrue(os.path.exists(filename2))
        os.rmdir(filename2)

    def test_check_file_exists(self):
        filename = self.get_random_file()
        self.assertFalse(Console.check_file_exists(filename))
        with open(filename, "w") as f:
            f.write("test")
        self.assertTrue(Console.check_file_exists(filename))
        os.unlink(filename)

    def test_check_src_folder(self):
        filename = self.get_random_file()
        self.assertFalse(Console.check_src_folder(filename))
        with open(filename, "w") as f:
            f.write("test")
        self.assertTrue(Console.check_src_folder(filename))
        os.unlink(filename)

    def test_check_ssh(self):
        pass

    def test_check_ssh_or_throw(self):
        pass

    def test_cmd(self):
        cmd = "echo 'test'"
        ssh = "user@server -p 22000"
        ssh_cmd = """ssh user@server -p 22000 'echo '"'"'test'"'"''"""
        self.assertTrue(Console.cmd(cmd, ssh).strip() == ssh_cmd)

    def test_get_backup_dirs(self):
        path = self.get_random_file()
        os.mkdir(path)
        dirs = ["2015-05-11_10:33:23", "2016-03-12_00:31:13"]
        for d in dirs:
            os.mkdir(path + "/" + d)
        backup_dirs = Console.get_backup_dirs(path)
        for d in dirs:
            os.rmdir(path + "/" + d)
        os.rmdir(path)
        self.assertEqual(set(dirs), set(backup_dirs))

    def test_get_datetime_of_dirname(self):
        date_should_be = datetime.datetime(2015, 5, 11, 10, 33, 23)
        date = Console.get_datetime_of_dirname("2015-05-11_10:33:23")
        self.assertEqual(date, date_should_be)

    def test_get_dirname_of_datetime(self):
        date = datetime.datetime(2015, 5, 11, 10, 33, 23)
        folder = Console.get_dirname_of_datetime(date)
        folder_should_be = "2015-05-11_10:33:23"
        self.assertEqual(folder, folder_should_be)

    def test_dirname_and_datetime_consistency(self):
        folder_should_be = "2015-05-11_10:33:23"
        self.assertEqual(
            Console.get_dirname_of_datetime(Console.get_datetime_of_dirname(folder_should_be)),
            folder_should_be
        )

    def test_get_lastbackup_timedelta(self):
        now_datetime = datetime.datetime.now()
        path = self.get_random_file()
        os.mkdir(path)
        dirs = ["2015-05-11_10:33:23", "2016-03-12_00:31:13", "2014-11-30_15:50:23"]
        for d in dirs:
            os.mkdir(path + "/" + d)
        timedelta = Console.get_lastbackup_timedelta(path, "", now_datetime)
        for d in dirs:
            os.rmdir(path + "/" + d)
        os.rmdir(path)
        should_timedelta = now_datetime - datetime.datetime(2016, 3, 12, 0, 31, 13)
        self.assertEqual(timedelta, should_timedelta)


    def test_list2cmdline(self):
        self.assertEqual(
            Console.list2cmdline(
                ["ls", "-l", "/dev/tty*"]
            ),
            "ls -l '/dev/tty*'"
        )
        self.assertEqual(
            Console.list2cmdline(
                ["ssh", "user@server", "--port", "22000",
                 Console.list2cmdline(
                     ["ls", "-l", "/dev/tty*"]
                 )
                 ]
            ),
            """ssh user@server --port 22000 'ls -l '"'"'/dev/tty*'"'"''"""
        )


    def test_mv(self):
        should_txt = "test"
        file1 = self.get_random_file()
        with open(file1, "w") as f:
            f.write(should_txt)
        file2 = self.get_random_file()
        Console.mv(file1, file2)
        txt = ""
        with open(file2, "r") as f:
            txt = f.read()
        file1ex = os.path.exists(file1)
        file2ex = os.path.exists(file2)
        os.unlink(file2)
        self.assertFalse(file1ex)
        self.assertTrue(file2ex)
        self.assertEqual(txt, should_txt)

    def test_p_expect(self):
        p = pexpect.spawn("bash")
        p.sendline("echo hello")
        result_hello = Console.p_expect(p, {
            "hello result": "hello"
        })
        self.assertEqual(result_hello, "hello result")

    def test_rm(self):
        tempname = self.get_random_file()
        remove_non_existent_ret = Console.rm_file(tempname)
        with open(tempname, "w") as f:
            f.write("test")
        remove_existent_ret = Console.rm_file(tempname)

        self.assertTrue(remove_existent_ret)
        self.assertFalse(remove_non_existent_ret)

    def test_write_file(self):
        tempname = self.get_random_file()
        writed_content = "First line\nSecond line"
        Console.write_file(tempname, writed_content)
        with open(tempname, "r") as f:
            content = f.read()
        os.unlink(tempname)
        self.assertEqual(content, writed_content + "\n")


if __name__ == "__main__":
    unittest.main()
