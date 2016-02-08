import backup
import click
import os


@click.command()
@click.option(
    "--conf_dir", type=click.Path(exists=True, dir_okay=True, readable=True),
    help="Directory, where config files should be searched"
)
@click.option(
    "--conf", default="", type=click.File(mode="r"),
    help="Conf file, that should be used", multiple=True
)
@click.option(
    "--run", default="", type=click.STRING,
    help="Variant name, that shoud be backuped", multiple=True
)
@click.option("--verbose", default=False, help="Display verbose information about backup process", is_flag=True)
def run(conf_dir, conf, verbose, run):
    conf_data = {}
    if len(conf):
        conf_files = [item.name for item in conf]
        print("Указаны сторонние конфигурационные файлы:")
        conf_data = backup.Conf.read_conf_files(conf_files)
    elif conf_dir:
        print("Указан сторонний каталог с конфигурационными файлами")
        conf_data = backup.Conf.read_conf_dir(conf_dir)
    else:
        print("Используем каталог с конфиг-файлами по умолчанию")
        dir = os.path.realpath("~/.config/LinuxTimeMachine/variants")
        if not os.path.exists(dir):
            os.makedirs(dir)
        conf_data = backup.Conf.read_conf_dir(conf_dir)

    if (len(run)):
        confs = {}
        for variant in run:
            confs[variant] = conf_data[variant]
    else:
        confs = conf_data

    backup.go(confs)


if __name__ == "__main__":
    run()
