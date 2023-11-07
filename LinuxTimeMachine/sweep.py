import copy
import datetime
import os
import sys

from LinuxTimeMachine import exceptions
from LinuxTimeMachine.backup import Console
from LinuxTimeMachine.common import Log, Tools
from LinuxTimeMachine.conf import MainConf, ravenClient


def sweep(variants, verbose=False, imitate=False):
    Console.print_asterisked("Starting sweeping{}".format(" IMITATING, NO ACTUALLY REMOVING DATA" if imitate else ""))
    for variant_name in variants:
        try:
            variant = copy.deepcopy(variants[variant_name])
            sweep_params = variant.get("sweep", [])
            if sweep_params == "default":
                sweep_params = MainConf.I().default_sweep

            sweep_conf = SweepConfList(sweep_params)

            if len(sweep_conf.parsed_sweep_conf) == 0:
                print("Sweep for variant `{}` isn't configured".format(variant_name))
                continue

            dirs = Console.get_backup_dirs_with_dates(
                variant["dest"]["path"], variant["dest"]["host"], dates_as_integer=True
            )

            if dirs and len(dirs) > 0:
                newest = dirs[0]['date']
            else:
                newest = datetime.datetime.now().timestamp()

            for i in range(len(dirs)):
                dirs[i]["time_from_now"] = int(newest - dirs[i]['date'])
                swc = sweep_conf.get_sweep_conf_by_timestamp(dirs[i]["time_from_now"])
                if swc:
                    swc.data_array.append(dirs[i])

            to_remove_cnt = 0
            for swcl in sweep_conf.parsed_sweep_conf:
                print(swcl.get_conf_decription())
                if swcl.data_array:
                    swcl.data_array = sorted(swcl.data_array, key=lambda item: item['time_from_now'])
                    to_remove = swcl.sweep_data_items("time_from_now", "to_remove")
                    to_remove_cnt += to_remove
                    if verbose:
                        print("    Found items:")
                        for i in range(len(swcl.data_array)):
                            print("        item: {}, {}".format(
                                swcl.data_array[i]['name'], "REMOVE" if swcl.data_array[i]['to_remove'] else "KEEP"
                            )
                            )
                    else:
                        print("    Found data items:{}, items to remove:{}, items to stay:{}".format(
                            len(swcl.data_array), to_remove, len(swcl.data_array) - to_remove)
                        )
                else:
                    print("    No data items in this interval")

            if to_remove_cnt > 0:

                if not imitate:

                    print("Removing data items...")
                    removed_cnt = 0
                    for swcl in reversed(sweep_conf.parsed_sweep_conf):
                        for i in reversed(range(len(swcl.data_array))):
                            item = swcl.data_array[i]
                            if item['to_remove']:
                                removed_cnt += 1
                                if verbose:
                                    print("Removing {} ({} of {})".format(item['name'], removed_cnt, to_remove_cnt))
                                Console.rm_dir(variant["dest"]["path"] + "/" + item['name'], variant["dest"]["host"])
                else:
                    print("Not removing data items, caused by --imitate flag")
            else:
                print("Everything clean, nothing to remove")


        except TypeError as e:
            Log.error(
                "Sweep of variant `{}` error: {}:{} at {}:{}, skipping".format(
                    variant_name,
                    str(type(e)),
                    str(e),
                    os.path.split(sys.exc_info()[-1].tb_frame.f_code.co_filename)[1],
                    sys.exc_info()[-1].tb_lineno
                )
            )
            ravenClient().capture_exceptions(e)


class SweepConfList:
    """
    Список строк конфигурации частоты копий
    """

    def __init__(self, sweep_dict):
        self.parsed_sweep_conf = []
        for period_str in sweep_dict:
            line = SweepConfLine(period_str, sweep_dict[period_str])
            self.parsed_sweep_conf.append(line)

        self.parsed_sweep_conf = sorted(self.parsed_sweep_conf, key=lambda scl: scl.period.get_days())

    def get_sweep_conf_by_timestamp(self, timestamp):
        for sweep_conf in self.parsed_sweep_conf:
            if sweep_conf.period.get_seconds() > timestamp:
                return sweep_conf


class LastSweepPeriod:
    """
    Класс, определяющий период с текущего момента, в течении которого действует правило на интервал резервных копий.
    Период формируется из строки вида "last 4 days", "last 1 year" и так далее.
    """

    def __init__(self, str_period):
        self.src_string = str_period
        period_matches = {}
        if not Tools.re_match(
                "^(last\ ((?P<num>[0-9\.]+)\ )?(?P<unit>hour|year|month|day|week)s?)|(?P<other>all others?)$",
                str_period.strip(),
                period_matches
        ):
            raise exceptions.BadSweepConf(
                (
                        "Error on sweep conf, period string is:'{}', "
                        + "but it should be like 'last [N] [hour|month|day|week|year]', or "
                        + "'all other' for all items, not suited in other periods"
                ).format(str_period)
            )
        self.all_other = (period_matches['other'] is not None)

        if self.all_other:
            self.num = 90000
            self.unit = "year"
        else:
            if period_matches["num"] is None:
                period_matches["num"] = 1
            else:
                period_matches["num"] = Tools.toFloat(period_matches["num"])
            self.num = Tools.toFloat(period_matches['num'])
            self.unit = period_matches['unit']

    def get_description(self):

        if self.all_other:
            return "all other"

        if self.num == 1:
            nums = ""
        elif self.num == int(self.num):
            nums = str(int(self.num))
        else:
            nums = str(self.num)

        units = self.unit
        if self.num > 1:
            units += "s"
        if self.num != 1:
            units = " " + units

        return "last {}{}".format(nums, units)

    def get_days(self):
        last_days = 0
        if self.unit == "day":
            last_days = self.num
        elif self.unit == "week":
            last_days = self.num * 7
        elif self.unit == "month":
            last_days = self.num * 365.2425 / 12
        elif self.unit == "year":
            last_days = self.num * 365.2425
        return last_days

    def get_seconds(self):
        return self.get_days() * 3600 * 24


class SweepInterval:
    """
    Класс интервала очистки, т.е. минимального интервала между двумя соседними резервными копиями,
    меньше которого не должно быть
    """

    def __init__(self, str_interval):
        self.src_string = str_interval

        interval_matches = {}
        if not Tools.re_match(
                "^(?P<all>all)|((?P<items>[0-9\.]+)\ per\ (?P<num>[0-9\.]+)?\ ?(?P<unit>hour|year|month|day|week)s?)$",
                str_interval,
                interval_matches
        ):
            raise exceptions.BadSweepConf(
                (
                        "Error on sweep conf, interval string is:'{}', "
                        + "but it should be like 'all' or '[N] per [M] [hour|month|day|week|year]'"
                ).format(str_interval)
            )

        interval_days = 0

        self.is_all = True if interval_matches['all'] else False

        if interval_matches["num"] is None:
            interval_matches["num"] = 1

        self.items = Tools.toFloat(interval_matches['items'])
        self.num = Tools.toFloat(interval_matches["num"])
        self.unit = interval_matches['unit']

    def get_description(self):
        if self.is_all:
            return "all items"
        else:
            items = self.items if int(self.items) != self.items else int(self.items)
            num = self.num if int(self.num) != self.num else int(self.num)
            units = self.unit
            if self.num == 1:
                num = ""
            else:
                units = " " + units + "s"

            return "{} items per {}{}".format(items, num, units)

    def get_seconds_between(self):
        sec = 0
        if self.is_all:
            sec = 1
        elif self.unit == "hour":
            sec = self.num * 3600 / self.items
        elif self.unit == "day":
            sec = self.num * 24 * 3600 / self.items
        elif self.unit == "week":
            sec = self.num * 24 * 3600 * 7 / self.items
        elif self.unit == "month":
            sec = Tools.toFloat(self.num) * (365.2425 / 12) * 24 * 3600 / self.items
        elif self.unit == "year":
            sec = Tools.toFloat(self.num) * 365.2425 * 24 * 3600 / self.items
        return sec


class SweepConfLine:
    """
    Класс строки конфигурации прореживания бэкапов
    """

    def __init__(self, last_period_str, interval_str):
        self.interval = SweepInterval(interval_str)
        self.period = LastSweepPeriod(last_period_str)
        self.data_array = []

    def get_conf_decription(self):
        return "For {} keep {}".format(
            self.period.get_description(),
            self.interval.get_description()
        )

    def sweep_data_items(self, time_field, clean_field):
        to_remove = 0

        center = 0
        min_t = 999999999999
        max_t = 0
        for i in range(len(self.data_array)):
            self.data_array[i][clean_field] = None
            center += self.data_array[i][time_field] / len(self.data_array)
            min_t = min(min_t, self.data_array[i][time_field])
            max_t = max(max_t, self.data_array[i][time_field])

        center = int(center)

        interval = self.interval.get_seconds_between()

        # print("center:", center, "min:", min_t, "max:", max_t, "amplitude:", max_t - min_t, "interval:", interval)

        if interval > 0:
            central_node_i, central_node_value = min(enumerate(self.data_array),
                                                     key=lambda x: abs(x[1][time_field] - center))
            # print("central_node_i", central_node_i, "central_node_value", central_node_value[time_field])

            central_node_value[clean_field] = False

            td_i = central_node_i
            tu_i = central_node_i

            td = central_node_value[time_field]
            tu = central_node_value[time_field]

            while td > min_t:
                td -= interval
                if td_i >= 0:
                    while td_i >= 0 and self.data_array[td_i][time_field] > td:
                        if self.data_array[td_i][clean_field] is None:
                            self.data_array[td_i][clean_field] = True
                            to_remove += 1
                        td_i -= 1

                    if td_i >= 0 and self.data_array[td_i][time_field] <= td:
                        if self.data_array[td_i][clean_field] is None:
                            self.data_array[td_i][clean_field] = False
                        td = self.data_array[td_i][time_field]

            while tu < max_t:
                tu += interval
                if tu_i < len(self.data_array):
                    while tu_i < len(self.data_array) and self.data_array[tu_i][time_field] < tu:
                        if self.data_array[tu_i][clean_field] is None:
                            self.data_array[tu_i][clean_field] = True
                            to_remove += 1
                        tu_i += 1

                    if tu_i < len(self.data_array) and self.data_array[tu_i][time_field] >= tu:
                        if self.data_array[tu_i][clean_field] is None:
                            self.data_array[tu_i][clean_field] = False
                        tu = self.data_array[tu_i][time_field]
            return to_remove