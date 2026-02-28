import logging
import unittest
from pathlib import Path
from sys import stderr
from typing import override

from ocsf_schema_compiler.compiler import SchemaCompiler
from ocsf_schema_compiler.exceptions import SchemaException

BASE_DIR = Path(__file__).parent


class TestBadRegressions(unittest.TestCase):
    """
    Test cases where extension has item that shadows base schema item with same name.
    """

    @classmethod
    @override
    def setUpClass(cls):
        logging.basicConfig(
            format="%(levelname)s: %(message)s", style="%", stream=stderr, level="INFO"
        )

    @override
    def setUp(self):
        print(file=stderr)  # so logs start on new line

    def test_v1_6_0_with_extension_shadowing(self):
        for kind in ["category", "dictionary-attribute", "class", "object", "profile"]:
            for allow_shadowing in [False, True]:
                with self.subTest(kind=kind, allow_shadowing=allow_shadowing):
                    compiler = SchemaCompiler(
                        Path(BASE_DIR, "uncompiled-schemas/ocsf-schema-v1.6.0"),
                        extensions_paths=[
                            Path(
                                BASE_DIR,
                                f"uncompiled-schemas/extension-shadow-{kind}",
                            )
                        ],
                        allow_shadowing=allow_shadowing,
                    )

                    if allow_shadowing:
                        _ = compiler.compile()
                    else:
                        kind_in_message = kind.replace("-", " ")
                        with self.assertRaisesRegex(
                            SchemaException, f"shadows base schema {kind_in_message}"
                        ):
                            _ = compiler.compile()
