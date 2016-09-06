from datetime import timedelta
import unittest
from LinuxTimeMachine.backup import Tools

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

