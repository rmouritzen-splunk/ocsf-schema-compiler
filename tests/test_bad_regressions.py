import logging
import unittest
from pathlib import Path
from sys import stderr
from typing import override

from ocsf_schema_compiler.compiler import SchemaCompiler
from ocsf_schema_compiler.exceptions import SchemaException

BASE_DIR = Path(__file__).parent


class TestBadRegressions(unittest.TestCase):
    """Test cases where compilation should always fail."""

    @classmethod
    @override
    def setUpClass(cls):
        logging.basicConfig(
            format="%(levelname)s: %(message)s", style="%", stream=stderr, level="INFO"
        )

    @override
    def setUp(self):
        print(file=stderr)  # so logs start on new line

    def test_v1_6_0_with_extension_is_array_change(self):
        compiler = SchemaCompiler(
            Path(BASE_DIR, "uncompiled-schemas/ocsf-schema-v1.6.0"),
            extensions_paths=[
                Path(BASE_DIR, "uncompiled-schemas/bad-extension-is-array-change")
            ],
        )

        with self.assertRaisesRegex(SchemaException, "is_array"):
            _ = compiler.compile()

    def test_v1_6_0_with_extension_illegal_scoped_name(self):
        for kind in [
            "category",
            "dictionary-attribute",
            "dictionary-type",
            "class",
            "object",
            "profile",
        ]:
            # Allowing shadowing does not fix this case.
            # Here we are using an extension scope where one should not exist.
            for allow_shadowing in [False, True]:
                # Use of unscoped dictionary types also does not affect this case.
                # This only applies to dictionary types.
                for unscoped_dictionary_types in [False, True]:
                    with self.subTest(
                        kind=kind,
                        allow_shadowing=allow_shadowing,
                        unscoped_dictionary_types=unscoped_dictionary_types,
                    ):
                        compiler = SchemaCompiler(
                            Path(BASE_DIR, "uncompiled-schemas/ocsf-schema-v1.6.0"),
                            extensions_paths=[
                                Path(
                                    BASE_DIR,
                                    f"uncompiled-schemas/bad-extension-scoped-{kind}",
                                )
                            ],
                            allow_shadowing=allow_shadowing,
                            unscoped_dictionary_types=unscoped_dictionary_types,
                        )

                        with self.assertRaisesRegex(
                            SchemaException,
                            "Illegal use of extension-scope in extension",
                        ):
                            _ = compiler.compile()
