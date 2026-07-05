import unittest
from unittest.mock import patch

from LinuxTimeMachine import backup


class BackupHooksTestCase(unittest.TestCase):
    def test_run_variant_command_uses_variant_source_host(self):
        calls = []

        def fake_call_shell(cmd):
            calls.append(cmd)
            return 0

        variants = {
            "app": {
                "src": {"path": "/src", "host": "user@example.com"},
                "dest": {"path": "/dest", "host": ""},
                "pre_backup_cmd": "systemctl stop app",
                "post_backup_cmd": "systemctl start app",
            }
        }

        with patch.object(backup.Console, "call_shell", side_effect=fake_call_shell), \
             patch.object(backup.Rsync, "timemachine", return_value=None):
            backup.go(variants)

        self.assertEqual(
            calls[0],
            backup.Console.cmd(
                backup.Console.list2cmdline(["/bin/bash", "-c", "systemctl stop app"]),
                "user@example.com"
            )
        )
        self.assertEqual(
            calls[1],
            backup.Console.cmd(
                backup.Console.list2cmdline(["/bin/bash", "-c", "systemctl start app"]),
                "user@example.com"
            )
        )

    def test_failed_pre_backup_command_skips_backup_and_post_command(self):
        variants = {
            "app": {
                "src": {"path": "/src", "host": ""},
                "dest": {"path": "/dest", "host": ""},
                "pre_backup_cmd": "false",
                "post_backup_cmd": "echo done",
            }
        }

        with patch.object(backup.Console, "call_shell", return_value=1) as call_shell, \
             patch.object(backup.Rsync, "timemachine", return_value=None) as timemachine:
            backup.go(variants)

        call_shell.assert_called_once_with(backup.Console.list2cmdline(["/bin/bash", "-c", "false"]))
        timemachine.assert_not_called()

    def test_post_backup_command_skipped_when_backup_fails(self):
        variants = {
            "app": {
                "src": {"path": "/src", "host": ""},
                "dest": {"path": "/dest", "host": ""},
                "pre_backup_cmd": "echo ready",
                "post_backup_cmd": "echo done",
            }
        }

        with patch.object(backup.Console, "call_shell", return_value=0) as call_shell, \
             patch.object(backup.Rsync, "timemachine", side_effect=backup.exceptions.RsyncError("failed")):
            backup.go(variants)

        call_shell.assert_called_once_with(backup.Console.list2cmdline(["/bin/bash", "-c", "echo ready"]))


if __name__ == "__main__":
    unittest.main()
