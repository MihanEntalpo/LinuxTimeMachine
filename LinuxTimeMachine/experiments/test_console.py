import backup
import json

#variants = backup.Conf.read_conf_dir("/home/mihanentalpo/.config/LinuxTimeMachine/variants")

backup.Console.check_ssh_or_throw("")

print(backup.Console.check_file_exists("/tmp/1"))



