#!/usr/bin/python3
from backup import Conf
from backup import go as backup_go
import click
import os
import json

def process_variants(conf_dir, conf, run, dontrun, here):
    conf_data = {}

    if here and len(run):
        print("Error: --run and --here shouldn't be used together!")
        return None

    if len(conf):
        conf_files = [item.name for item in conf]
        print("Using specified config files: {}".format(", ".join(conf_files)))
        conf_data = Conf.read_conf_files(conf_files)
    elif conf_dir:
        print("Using specified config folder '{}'".format(conf_dir))
        conf_data = Conf.read_conf_dir(conf_dir)
    else:
        dir = os.path.expanduser("~/.config/LinuxTimeMachine/variants")
        print("Using default config folder '{}'".format(dir))
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
                                print("Found variant of here:" + variant)
                                print(
                                    "path:{}, herepath:{}, common prefix:{}".format(
                                        path, herepath, os.path.commonprefix([path, herepath])
                                    )
                                )
            if len(here_found) == 0:
                print("No variants found for here path '" + here + "'")
            else:
                print("Variants found at here path '{}': {}".format(here, ", ".join(here_found)))

            if len(here_found):
                print("Varaints found here: {}")

        if len(run):
            print("Specified variants: {}".format(", ".join(run)))
            confs = {}
            for variant in run:
                if variant in conf_data:
                    confs[variant] = conf_data[variant]
                else:
                    print("Variant '{}' not exists in readed conf".format(variant))
        else:
            print("All the variants")
            confs = conf_data

        if len(dontrun):
            print("Skipping variants: {}".format(", ".join(dontrun)))
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
    "--conf", default="", type=click.File(mode="r"), metavar="<filename>",
    help="Conf file, that should be used. May be used several times for multiple files.",
    multiple=True
)
@click.option(
    "--run", default="", type=click.STRING, metavar="<variant name>",
    help="Variant name, that should be backuped. May be used several times for multiple variants", multiple=True
)
@click.option(
    "--dontrun", default="", type=click.STRING, metavar="<variant name>",
    help="Variant name, that should be skipped from backup. May be used several times for multiple variants", multiple=True
)
@click.option(
    "--verbose", "-v", default=False, is_flag=True, help="Display full config, not just names and descriptions"
)
@click.option(
    "--here", "-h", default="", type=click.STRING, metavar="<path>", help="Try to use use config, that have relation to current directory"
)
def list(conf_dir, conf, run, dontrun, verbose, here):
    """
    List backup variants, selected by
    :param conf_dir:
    :param conf:
    :return:
    """
    confs = process_variants(conf_dir, conf, run, dontrun, here)

    print("variants:")
    if verbose:
        print(json.dumps(confs, indent=4))
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
            print(varname + (" " * (maxlen - len(varname))) + ": " + description)


@cli.command()
@click.option(
    "--conf_dir", type=click.Path(exists=True, dir_okay=True, readable=True), metavar="<path>",
    help="Directory, where config files should be searched\nIgnored, if --conf_dir is specified"
)
@click.option(
    "--conf", default="", type=click.File(mode="r"), metavar="<filename>",
    help="Conf file, that should be used. May be used several times for multiple files.",
    multiple=True
)
@click.option(
    "--run", default="", type=click.STRING, metavar="<variant name>",
    help="Variant name, that should be backuped. May be used several times for multiple variants", multiple=True
)
@click.option(
    "--dontrun", default="", type=click.STRING, metavar="<variant name>",
    help="Variant name, that should be skipped from backup. May be used several times for multiple variants", multiple=True
)
@click.option(
    "--verbose", "-v", default=False, is_flag=True, help="Display verbose backup info"
)
@click.option(
    "--here", "-h", default=False, is_flag=True, help="Try to use use config, that have relation to current location"
)
def backup(conf_dir, conf, run, dontrun, verbose, here):
    """
    Start backup, configured by config files, places in ~/.config/LinuxTimeMachine/variants,
    or by command line parameters --cond_dir or --conf
    """

    confs = process_variants(conf_dir, conf, run, dontrun, here)

    print("variants to run:")
    print(json.dumps(confs, indent=4))
    if confs and len(confs):
        backup_go(confs)


if __name__ == "__main__":
    cli(obj={})
