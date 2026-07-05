from .common import Log
from .common import Tools
from . import exceptions

from collections import OrderedDict as Odict

import re
import importlib
import importlib.util
import os
import json
import yaml
import sys


class DummyRavenCallable():
    def __init__(self, field_name):
        self.field_name = field_name
    def __call__(self, *args, **kwargs):
        Log.debug("Called DummyRavenObject->%s", self.field_name)


class DummyRavenObject():
    def __getattr__(self, item):
        Log.debug("Requested item `%s` from DummyRavenObject", item)
        return DummyRavenCallable(item)


class SentryClientWrapper:
    def __init__(self, dsn):
        self.module = importlib.import_module("sentry_sdk")
        self.module.init(dsn=dsn)

    def capture_exceptions(self, exc):
        self.module.capture_exception(exc)


def ravenClient(dsn=None):
    """
    Returns Sentry-compatible client object (or dummy object when DSN/dependency is absent).
    """
    if not hasattr(ravenClient, "client_object"):
        if dsn is None:
            return DummyRavenObject()

        if importlib.util.find_spec("sentry_sdk") is not None:
            ravenClient.client_object = SentryClientWrapper(dsn)
        else:
            Log.warning("Sentry DSN is configured, but sentry_sdk is not installed")
            ravenClient.client_object = DummyRavenObject()

    return ravenClient.client_object


class MainConf:

    @staticmethod
    def I(confFile=None):
        if not hasattr(MainConf.I, "instance"):
            MainConf.I.instance = MainConf(confFile)
        return MainConf.I.instance

    def __init__(self, confFile=None):
        self.confFile=confFile
        if not confFile:
            confFile = os.path.expanduser("~/.config/LinuxTimeMachine/mainconf.json")
        self.conf = {}
        if confFile is not None:
            self.readConf(confFile)
        self.raven_dsn = self.conf.get("raven_dsn", "")
        self.default_sweep = self.conf.get("default_sweep", [])
        self.loglevel = self.conf.get("loglevel", "INFO")
        Log.I(self.loglevel, sys.stdout, True)
        if self.raven_dsn:
            ravenClient(self.raven_dsn)

    def loadFile(self, confFile):
        Log.info("Loading main conf from %s", confFile)
        regs = {
            "json": r".*\.json$",
            "yaml": r".*\.ya?ml$"
        }
        filetype = None
        for typename in regs:
            if re.search(regs[typename], confFile):
                filetype = typename
                Log.debug("Main config file type is: %s", typename)
                break
        if filetype is None:
            raise Exception("File type of " + confFile + " not detected. Extension should be .json, .yml, .yaml")

        if filetype == "json":
            with open(confFile, "r") as f:
                self.conf = json.load(f)
        elif filetype == "yaml":
            with open(confFile, "r") as f:
                self.conf = yaml.safe_load(f)

    def readConf(self, confFile=None):
        if confFile is not None:
            self.confFile = confFile
        if self.confFile:
            if os.path.exists(self.confFile):
                self.loadFile(self.confFile)
            else:
                Log.error("mainConf file `{}` not found".format(self.confFile))

class Conf:
    """
    Configuration reader class
    reads files of json and yaml types.
    File structure have to be:

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
        filenames = [file for file in os.listdir(dir_path) if re.search(r"\.(ya?ml|json)$", file)]
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
    def read_conf_file(filename):
        """
        Read single config file
        :param filename: file name, should have "*.json", "*.yaml" or "*.yml" extension, so, loader
                         could recognize, what method should be used to load file
        :return: dict, containing backup variants from file
        """
        assert isinstance(filename, str)
        if not os.path.exists(filename):
            raise exceptions.ConfigFileNotExists("File `" + filename + "` not exists")

        regs = {
            "json": r".*\.json$",
            "yaml": r".*\.ya?ml$"
        }

        filetype = None
        for curtype in regs:
            if re.search(regs[curtype], filename):
                filetype = curtype
                break
        if filetype is None:
            raise exceptions.BadConfigFile("Config file {} must have extension .json, .yaml or .yml".format(filename))
        content = ""
        with open(filename, "r") as f:
            content = f.read()

        conf = {}

        if content:
            if filetype == "json":
                conf = json.loads(content)
            elif filetype == "yaml":
                conf = yaml.safe_load(content)

        return conf
