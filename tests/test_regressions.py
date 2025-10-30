import logging
import unittest
from pathlib import Path
from sys import stderr

from diff import diff_objects, formatted_diffs
from ocsf_schema_compiler.compiler import SchemaCompiler
from ocsf_schema_compiler.jsonish import read_json_object_file

BASE_DIR = Path(__file__).parent


class TestRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        logging.basicConfig(format="%(levelname)s: %(message)s", style="%", stream=stderr, level="INFO")

    def setUp(self):
        print(file=stderr)  # so logs start on new line

    def test_v1_6_0(self):
        compiler = SchemaCompiler(Path(BASE_DIR, 'uncompiled-schemas/ocsf-schema-v1.6.0'))
        schema = compiler.compile()

        baseline_schema = read_json_object_file(Path(BASE_DIR, 'compiled-baselines/schema-v1.6.0.json'))
        ok, diffs = diff_objects(schema, baseline_schema)
        self.assertTrue(ok, f"schema should match baseline:\n{formatted_diffs(diffs)}")

    def test_v1_6_0_browser_mode(self):
        compiler = SchemaCompiler(Path(BASE_DIR, 'uncompiled-schemas/ocsf-schema-v1.6.0'), browser_mode=True)
        schema = compiler.compile()

        baseline_schema = read_json_object_file(Path(BASE_DIR, 'compiled-baselines/browser-schema-v1.6.0.json'))
        ok, diffs = diff_objects(schema, baseline_schema)
        self.assertTrue(ok, f"schema should match baseline:\n{formatted_diffs(diffs)}")

    def test_v1_6_0_with_aws_v1_0_0(self):
        compiler = SchemaCompiler(Path(BASE_DIR, 'uncompiled-schemas/ocsf-schema-v1.6.0'),
                                  extensions_paths=[Path(BASE_DIR, 'uncompiled-schemas/aws-v1.0.0')])
        schema = compiler.compile()

        baseline_schema = read_json_object_file(Path(BASE_DIR, 'compiled-baselines/schema-v1.6.0-aws-v1.0.0.json'))
        ok, diffs = diff_objects(schema, baseline_schema)
        self.assertTrue(ok, f"schema should match baseline:\n{formatted_diffs(diffs)}")

    def test_v1_0_0_rc_2_with_splunk_v1_16_2(self):
        compiler = SchemaCompiler(Path(BASE_DIR, 'uncompiled-schemas/ocsf-schema-v1.0.0-rc.2'),
                                  ignore_platform_extensions=True,
                                  extensions_paths=[Path(BASE_DIR, 'uncompiled-schemas/splunk-v1.16.2')])
        schema = compiler.compile()

        baseline_schema = read_json_object_file(
            Path(BASE_DIR, 'compiled-baselines/schema-v1.0.0-rc.2-splunk-v1.16.2.json'))
        ok, diffs = diff_objects(schema, baseline_schema)
        self.assertTrue(ok, f"schema should match baseline:\n{formatted_diffs(diffs)}")


if __name__ == '__main__':
    unittest.main()
