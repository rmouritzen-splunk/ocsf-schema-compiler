import logging
import unittest
from pathlib import Path
from sys import stderr
from typing import override

from ocsf_schema_compiler.compiler import SchemaCompiler
from ocsf_schema_compiler.exceptions import SchemaException

BASE_DIR = Path(__file__).parent


class TestDictionaryTypeRegressions(unittest.TestCase):
    """
    Test cases where where extension dictionary type shadows or collides with base
    schema. Dictionary types defined in extensions have special treatment.

    In the old compiler, all dictionary types were unscoped, includes those defined in
    extensions.

    In the new compiler, dictionary types defined in platform extensions are unscoped
    for backwards compatibility, and other dictionary types defined in other extensions
    are scoped by default with an option to unscope them.
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

    def test_v1_6_0_with_extension_colliding_dictionary_type_shadows(self):
        compiler = SchemaCompiler(
            Path(BASE_DIR, "uncompiled-schemas/ocsf-schema-v1.6.0"),
            extensions_paths=[
                Path(BASE_DIR, "uncompiled-schemas/extension-colliding-dictionary-type")
            ],
        )

        self.assertEqual(
            False,
            compiler.unscoped_dictionary_types,
            "Unscoped dictionary types should be disabled",
        )

        with self.assertRaisesRegex(
            SchemaException, "shadows base schema dictionary type"
        ):
            _ = compiler.compile()

    def test_v1_6_0_with_extension_colliding_dictionary_type_allow_shadowing(self):
        compiler = SchemaCompiler(
            Path(BASE_DIR, "uncompiled-schemas/ocsf-schema-v1.6.0"),
            extensions_paths=[
                Path(BASE_DIR, "uncompiled-schemas/extension-colliding-dictionary-type")
            ],
            allow_shadowing=True,
        )

        self.assertEqual(
            False,
            compiler.unscoped_dictionary_types,
            "Unscoped dictionary types should be disabled",
        )

        # This should succeed
        _ = compiler.compile()

    def test_v1_6_0_with_extension_colliding_dictionary_type_collides(self):
        compiler = SchemaCompiler(
            Path(BASE_DIR, "uncompiled-schemas/ocsf-schema-v1.6.0"),
            extensions_paths=[
                Path(BASE_DIR, "uncompiled-schemas/extension-colliding-dictionary-type")
            ],
            unscoped_dictionary_types=True,
        )

        with self.assertRaisesRegex(
            SchemaException, "collides with base schema dictionary type"
        ):
            _ = compiler.compile()

    def test_v1_6_0_with_extension_colliding_dictionary_type_allow_shadowing_collides(
        self,
    ):
        compiler = SchemaCompiler(
            Path(BASE_DIR, "uncompiled-schemas/ocsf-schema-v1.6.0"),
            extensions_paths=[
                Path(BASE_DIR, "uncompiled-schemas/extension-colliding-dictionary-type")
            ],
            unscoped_dictionary_types=True,
            allow_shadowing=True,
        )

        # Allowing shadowing does not help when dictionary types are unscoped
        # This remains a collisions
        with self.assertRaisesRegex(
            SchemaException, "collides with base schema dictionary type"
        ):
            _ = compiler.compile()
