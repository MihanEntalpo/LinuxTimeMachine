#!/usr/bin/python3
import backup
import click
import os
import sys


@click.group(help="LinuxTimeMachine control tool.To display help on a command, use <command> --help")
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
def backup(conf_dir, conf, run):
    """
    Start backup, configured by config files, places in ~/.config/LinuxTimeMachine/variants,
    or by command line parameters --cond_dir or --conf
    """
    conf_data = {}
    if len(conf):
        conf_files = [item.name for item in conf]
        print("Using specified config files: {}".format(", ".join(conf_files)))
        conf_data = backup.Conf.read_conf_files(conf_files)
    elif conf_dir:
        print("Using specified config folder '{}'".format(conf_dir))
        conf_data = backup.Conf.read_conf_dir(conf_dir)
    else:
        dir = os.path.expanduser("~/.config/LinuxTimeMachine/variants")
        print("Using default config folder '{}'".format(dir))
        if not os.path.exists(dir):
            os.makedirs(dir)
        conf_data = backup.Conf.read_conf_dir(dir)

    if conf_data and len(conf_data) > 0:
        if len(run):
            print("Running backup of specified variants: {}".format(", ".format(run)))
            confs = {}
            for variant in run:
                if variant in conf_data:
                    confs[variant] = conf_data[variant]
                else:
                    print("Variant '{}' not exists in readed conf".format(variant))
        else:
            print("Running backup of all the variants")
            confs = conf_data

        print("confs to run:")
        print(confs)
        if confs and len(confs):
            backup.go(confs)


if __name__ == "__main__":
    cli(obj={})
