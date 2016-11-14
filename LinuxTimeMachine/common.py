import sys
import logging
import re
import datetime

class Log:

    _singleton = None

    @staticmethod
    def I(loglevel=logging.DEBUG, logfile=sys.stdout, reset=False):
        """
        Singleton object, used to log message
        :return: :Log
        """
        if Log._singleton is None or reset == True:
            Log._singleton = Log(loglevel, logfile)

        return Log._singleton

    def __init__(self, loglevel=logging.DEBUG, logfile=sys.stdout):
        self.logger = logging.getLogger("LinuxTimeMachine")
        self.logger.setLevel(loglevel)
        self.logger.addHandler(
            logging.StreamHandler(logfile)
        )

    @staticmethod
    def error(msg, *args, **kwargs):
        Log.I().logger.error(msg, *args, **kwargs)

    @staticmethod
    def info(msg, *args, **kwargs):
        Log.I().logger.info(msg, *args, **kwargs)

    @staticmethod
    def warning(msg, *args, **kwargs):
        Log.I().logger.warning(msg, *args, **kwargs)

    @staticmethod
    def debug(msg, *args, **kwargs):
        try:
            Log.I().logger.debug(msg, *args, **kwargs)
        except TypeError as e:
            Log.I().logger.error("Error:'{}' trying to logger.debug('{}', '{}', '{}')".format(str(e), msg, str(args), str(kwargs)))


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
