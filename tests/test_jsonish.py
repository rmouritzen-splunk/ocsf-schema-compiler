import unittest

from ocsf_schema_compiler.jsonish import JValue, j_integer


class TestJSONish(unittest.TestCase):
    def test_j_integer(self):
        intValue: JValue = 1
        _ = j_integer(intValue)

        with self.assertRaisesRegex(
            AssertionError,
            "j_integer: expected integer number but got boolean: True",
        ):
            boolValue: JValue = True
            _ = j_integer(boolValue)
