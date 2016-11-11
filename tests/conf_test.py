from LinuxTimeMachine.backup import Conf
import unittest
import os
import inspect

class ConfTestCase(unittest.TestCase):
    def dir(self):
        return os.path.dirname(os.path.realpath(__file__))

    def test_read_conf_dir(self):
        pass

    def test_read_conf_file(self):
        conf1 = Conf.read_conf_file(self.dir() + "/setup/conf/file1.yml")
        conf2 = Conf.read_conf_file(self.dir() + "/setup/conf/file2.py")
        file3 = self.dir() + "/setup/conf/file3.json"
        conf3 = Conf.read_conf_file(file3)

    def test_read_conf_files(self):
        confs = Conf.read_conf_dir(self.dir() + "/setup/conf/")

    def test_read_py_conf_file(self):
        pass


