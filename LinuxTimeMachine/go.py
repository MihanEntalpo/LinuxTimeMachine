#!/usr/bin/python3
from .conf import Conf
from .backup import go as backup_go
from LinuxTimeMachine.sweep import sweep as sweep_go
from .conf import MainConf
from .common import Log
import click
import os
import re
import json
import yaml
import sys
import importlib.util

def process_variants(conf_dir, conf, run, dontrun, here):
    conf_data = {}
    confs = {}

    if here and len(run):
        Log.error("Error: --run and --here should not be used together")
        return None

    if len(conf):
        conf_files = [item.name for item in conf]
        Log.info("Using specified config files: %s", ", ".join(conf_files))
        conf_data = Conf.read_conf_files(conf_files)
    elif conf_dir:
        Log.info("Using specified config folder `%s`", conf_dir)
        conf_data = Conf.read_conf_dir(conf_dir)
    else:
        dir = os.path.expanduser("~/.config/LinuxTimeMachine/variants")
        Log.info("Using default config folder `%s`", dir)
        if not os.path.exists(dir):
            os.makedirs(dir)
        conf_data = Conf.read_conf_dir(dir)

    if conf_data and len(conf_data) > 0:

        if here:
            here_found = []
            herepath = os.path.realpath(here)
            if herepath:
                for variant in conf_data:
                    src = conf_data[variant]['src']
                    for x in ["src", "dest"]:
                        if conf_data[variant][x]['host'] == "":
                            path = os.path.realpath(conf_data[variant][x]['path'])
                            if os.path.commonprefix([path, herepath]) == path:
                                here_found.append(variant)
                                Log.info("Found variant for current path: %s", variant)
                                Log.debug("path:%s, herepath:%s, common prefix:%s", path, herepath, os.path.commonprefix([path, herepath]))
            if len(here_found) == 0:
                Log.warning("No variants found for path `%s`", here)
            else:
                Log.info("Variants found for path `%s`: %s", here, ", ".join(here_found))

            if len(here_found):
                Log.info("Variants found for current path")

        if len(run):
            Log.info("Specified variants: %s", ", ".join(run))
            confs = {}
            for variant in run:
                if variant in conf_data:
                    confs[variant] = conf_data[variant]
                else:
                    Log.warning("Variant `%s` does not exist in loaded config", variant)
        else:
            Log.info("Using all variants")
            confs = conf_data

        if len(dontrun):
            Log.info("Skipping variants: %s", ", ".join(dontrun))
            for variant in dontrun:
                if variant in confs:
                    del confs[variant]

    return confs

@click.group(help="LinuxTimeMachine control tool. To display help on a command, use <command> --help")
def cli():
    pass


@cli.command()
@click.option(
    "--conf_dir", type=click.Path(exists=True, dir_okay=True, readable=True), metavar="<path>",
    help="Directory, where config files should be searched\nIgnored, if --conf_dir is specified"
)
@click.option(
    "--conf", default=[], type=click.File(mode="r"), metavar="<filename>",
    help="Conf file, that should be used. May be used several times for multiple files.",
    multiple=True
)
@click.option(
    "--run", default=[], type=click.STRING, metavar="<variant name>",
    help="Variant name, that should be backuped. May be used several times for multiple variants", multiple=True
)
@click.option(
    "--dontrun", default=[], type=click.STRING, metavar="<variant name>",
    help="Variant name, that should be skipped from backup. May be used several times for multiple variants", multiple=True
)
@click.option(
    "--verbose", "-v", default=False, is_flag=True, help="Display full config, not just names and descriptions"
)
@click.option(
    "--here", "-h", default="", type=click.STRING, metavar="<path>",
    help="Try to use use config, that have relation to current directory"
)
@click.option(
    "--mainconf", "-mc", type=click.STRING, metavar="<main config file>",
    help="File with main config options, if not specified, ~/.config/LinuxTimeMachine/mainconf.json loaded, " +
         "or default values are used", default="~/.config/LinuxTimeMachine/mainconf.json"
)
def list(conf_dir, conf, run, dontrun, verbose, here, mainconf=""):
    """
    Show backup variants, selected by parameters
    :param conf_dir: dir, that should be searched for variant's conf files
    :param conf: conf filename(s), that should be loaded as a variants source
    :param run:  variant(s) name(s), that should be selected
    :param dontrun: variants(s) name(s), that shouldn't be selected
    :param verbose: display full loaded variants information
    :param here: try to look for variant, that has rlation to the current directory (or specified one)
    :param mainconf: mainconf file, that contains main parameters of LinuxTimeMachine.
    """

    MainConf.I(mainconf if mainconf else None)

    confs = process_variants(conf_dir, conf, run, dontrun, here)

    Log.info("Variants:")
    if verbose:
        Log.info("%s", json.dumps(confs, indent=4))
    else:
        maxlen = 0
        for varname in confs:
            if len(varname) > maxlen:
                maxlen = len(varname)
        for varname in confs:
            if "description" in confs[varname]:
                description = confs[varname]["description"]
            else:
                description = "No description available"
            Log.info("%s: %s", varname + (" " * (maxlen - len(varname))), description)


@cli.command()
def test():
    Log.info("test")


@cli.command()
@click.option(
    "--conf_dir", type=click.Path(exists=True, dir_okay=True, readable=True), metavar="<path>",
    help="Directory, where config files should be searched\nIgnored, if --conf_dir is specified"
)
@click.option(
    "--conf", default=[], type=click.File(mode="r"), metavar="<filename>",
    help="Conf file, that should be used. May be used several times for multiple files.",
    multiple=True
)
@click.option(
    "--run", default=[], type=click.STRING, metavar="<variant name>",
    help="Variant name, that should be backuped. May be used several times for multiple variants", multiple=True
)
@click.option(
    "--dontrun", default=[], type=click.STRING, metavar="<variant name>",
    help="Variant name, that should be skipped from backup. May be used several times for multiple variants", multiple=True
)
@click.option(
    "--verbose", "-v", default=False, is_flag=True, help="Display verbose backup info"
)
@click.option(
    "--here", "-h", default=False, is_flag=True, help="Try to use use config, that have relation to current location"
)
@click.option(
    "--mainconf", "-mc", type=click.STRING, metavar="<main config file>",
    help="File with main config options, if not specified, default values are used", default=""
)
@click.option(
    "--skip-frequency-check", "skip_frequency_check", default=False, is_flag=True,
    help="Skip backup frequency check and run backup even if it was made recently",
)
def backup(conf_dir, conf, run, dontrun, verbose, here, mainconf="", skip_frequency_check=False):
    """
    Start backup, configured by config files, places in ~/.config/LinuxTimeMachine/variants,
    or by command line parameters --cond_dir or --conf
    """
    MainConf.I(mainconf if mainconf else None)

    confs = process_variants(conf_dir, conf, run, dontrun, here)

    Log.info("Variants to run:")
    Log.info("%s", json.dumps(confs, indent=4))
    if confs and len(confs):
        backup_go(confs, verbose=verbose, skip_frequency_check=skip_frequency_check)
    else:
        Log.warning("There are no variants to run")


@cli.command()
@click.option(
    "--conf_dir", type=click.Path(exists=True, dir_okay=True, readable=True), metavar="<path>",
    help="Directory, where config files should be searched\nIgnored, if --conf_dir is specified"
)
@click.option(
    "--conf", default=[], type=click.File(mode="r"), metavar="<filename>",
    help="Conf file, that should be used. May be used several times for multiple files.",
    multiple=True
)
@click.option(
    "--run", default=[], type=click.STRING, metavar="<variant name>",
    help="Variant name, that should be sweeped. May be used several times for multiple variants", multiple=True
)
@click.option(
    "--dontrun", default=[], type=click.STRING, metavar="<variant name>",
    help="Variant name, that should be skipped from sweep. May be used several times for multiple variants", multiple=True
)
@click.option(
    "--verbose", "-v", default=False, is_flag=True, help="Display verbose sweep info"
)
@click.option(
    "--imitate", "-i", default=False, is_flag=True, help="Imitate action, don't actually remove data"
)
@click.option(
    "--here", "-h", default=False, is_flag=True, help="Try to use use config, that have relation to current location"
)
@click.option(
    "--mainconf", "-mc", type=click.STRING, metavar="<main config file>",
    help="File with main config options, if not specified, default values are used", default=""
)
def sweep(conf_dir, conf, run, dontrun, verbose, imitate, here, mainconf=""):
    """
    Run sweep (cleaning of old backup data items.
    Configuration should be set in section "sweep" of variant.
    """
    MainConf.I(mainconf if mainconf else None)

    confs = process_variants(conf_dir, conf, run, dontrun, here)

    Log.info("Variants to sweep: %s", len(confs))

    if confs and len(confs):
        sweep_go(confs, verbose, imitate)


if __name__ == "__main__":
    cli(obj={})
