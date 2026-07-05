from datetime import timedelta
import unittest
from LinuxTimeMachine.backup import Tools
from LinuxTimeMachine.backup import Log
import io
import logging

class ToolsTestCase(unittest.TestCase):
    def test_get_nested_dict_value(self):
        self.assertEqual(Tools.get_nested_dict_value({
            "a": { "b" : {"c": 7}}
        }, "a", "b", "c"), 7)

        self.assertIsNone(Tools.get_nested_dict_value({}, "a", "b", "c"))

    def test_make_time_delta(self):
        td = timedelta(days=1,seconds=2,milliseconds=3,minutes=4,hours=5,weeks=6)
        self.assertEqual(td, Tools.make_time_delta(td))
        self.assertEqual(td, Tools.make_time_delta(
            {"days":1, "seconds":2, "milliseconds":3, "minutes":4, "hours":5, "weeks":6}
        ))
        self.assertEqual(td, Tools.make_time_delta(
            "1 days 2 seconds 3 milliseconds 4 minutes 5 hours 6 weeks"
        ))



class LogTestCase(unittest.TestCase):
    def test_reset_replaces_handler_without_duplicate_messages(self):
        first_stream = io.StringIO()
        second_stream = io.StringIO()

        Log.I(logging.INFO, first_stream, reset=True)
        Log.info("first")
        Log.I(logging.INFO, second_stream, reset=True)
        Log.info("second")

        self.assertEqual(first_stream.getvalue(), "first\n")
        self.assertEqual(second_stream.getvalue(), "second\n")
        self.assertEqual(len(Log.I().logger.handlers), 1)

    def test_logger_does_not_propagate_to_root_handlers(self):
        root_stream = io.StringIO()
        root_handler = logging.StreamHandler(root_stream)
        root_logger = logging.getLogger()
        root_logger.addHandler(root_handler)

        try:
            local_stream = io.StringIO()
            Log.I(logging.INFO, local_stream, reset=True)
            Log.info("local")

            self.assertEqual(local_stream.getvalue(), "local\n")
            self.assertEqual(root_stream.getvalue(), "")
        finally:
            root_logger.removeHandler(root_handler)
            root_handler.close()
