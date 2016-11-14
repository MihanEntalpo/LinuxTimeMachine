from .common import Log
from .common import Tools
from raven import Client as RavenClient
import re
import importlib
import os
import json
import yaml

def ravenClient(dsn=None):
    """
    :return: RavenClient
    """
    if not hasattr(ravenClient, "client_object"):
        if dsn is None:
            if True:
                dsn = "https://5eecb9a8baa5425dac7bbb781e69188d:1b1ce7c7bd3d489bad7998b8f2fecbf2@sentry.mihanentalpo.me/16"
            else:
                dsn = ""
        ravenClient.client_object = RavenClient(dsn)
    return ravenClient.client_object

class MainConf:

    @staticmethod
    def I(confFile=None):
        if not hasattr(MainConf.I, "instance"):
            MainConf.I.instance = MainConf(confFile)
        return MainConf.I.instance

    def __init__(self, confFile=None):
        self.confFile=confFile
        self.conf = {}
        if confFile is not None:
            self.readConf()
        self.raven_dsn = self.conf.get("raven_dsn", "")
        if self.raven_dsn:
            ravenClient(self.raven_dsn)

    def loadFile(self, confFile):
        print("Loading main conf from " + confFile)
        regs = {
            "py": ".*\.py3?$",
            "json": ".*\.json$",
            "yaml": ".*\.ya?ml$"
        }
        filetype = None
        for typename in regs:
            if re.search(regs[typename], confFile):
                filetype = typename
                print("File type is:" + typename)
                break
        if filetype is None:
            raise Exception("File type of " + confFile + " not detected. Extension should be .py, .py3, .json, .yml, .yaml")

        if filetype == "json":
            with open(confFile, "r") as f:
                self.conf = json.load(f)
        elif filetype == "yaml":
            with open(confFile, "r") as f:
                self.conf = yaml.load(f)
        elif filetype == "py":
            spec = importlib.util.spec_from_file_location("module.name", "/path/to/file.py")
            foo = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(foo)
            self.conf = foo.conf

    def readConf(self, confFile=None):
        if confFile is not None:
            self.confFile = confFile
        if self.confFile and os.path.exists(self.confFile):
            self.loadFile(self.confFile)

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
            Log.error("Configuration folder '{}' doesn't exists".format(dir_path))
        filenames = [file for file in os.listdir(dir_path) if re.search("\.(py3?|ya?ml|json)$", file)]
        files = [dir_path + "/" + file for file in sorted(filenames)]
        if len(files) == 0:
            Log.error("There are no config files in folder '{}'".format(dir_path))
        conf = Odict()
        Log.info("Found config files: " + ", ".join(files))
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
        justfile = os.path.basename(file)
        with open(justfile, "r") as f:
            code = f.read()
        new_module = types.ModuleType("new_temporary_module")
        exec(code, new_module.__dict__)
        os.chdir(curpath)
        if "variants" in new_module.__dict__:
            return new_module.variants
        else:
            pass


    @staticmethod
    def read_conf_file(filename):
        """
        Read single config file
        :param filename: file name, should have "*.py", "*.json", "*.yaml" or "*.yml" extension, so, loader
                         could recognize, what method should be used to load file
        :return: dict, containing backup variants from file
        """
        assert isinstance(filename, str)
        if not os.path.exists(filename):
            raise exceptions.ConfigFileNotExists("File `" + filename + "` not exists")

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
            raise exceptions.BadConfigFile("Config file {} must have extension .py, .json, .yaml or .yml".format(filename))
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