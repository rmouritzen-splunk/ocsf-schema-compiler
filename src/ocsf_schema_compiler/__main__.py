import dataclasses
import json
import logging
from argparse import ArgumentParser
from pathlib import Path
from sys import stderr
from time import perf_counter

from compiler import SchemaCompiler
from exceptions import SchemaException
from jsonish import JObject

logger = logging.getLogger(__name__)


class CustomEncoder(json.JSONEncoder):
    def default(self, obj):
        if dataclasses.is_dataclass(obj):
            return dataclasses.asdict(obj)
        return super().default(obj)


def items_to_legacy(items: JObject, kind: str, objects: JObject) -> JObject:
    legacy_items = {}
    for item_name, item in items.items():
        if "extension" in item:
            legacy_items[f'{item["extension"]}/{item_name}'] = item
        else:
            legacy_items[item_name] = item
        if "attributes" in item:
            for attribute_name, attribute in item["attributes"].items():
                if "extension" in attribute and "object_type" in attribute:
                    attribute["object_type"] = f'{attribute["extension"]}/{attribute["object_type"]}'
    return legacy_items


def dictionary_to_legacy(dictionary: dict) -> None:
    legacy_attributes = {}
    for attribute_name, attribute in dictionary["attributes"].items():
        if "extension" in attribute:
            extension = attribute["extension"]
            if "object_type" in attribute:
                attribute["object_type"] = f'{extension}/{attribute["object_type"]}'
            legacy_attributes[f'{extension}/{attribute_name}'] = attribute
        else:
            legacy_attributes[attribute_name] = attribute
    dictionary["attributes"] = legacy_attributes


def main():
    parser = ArgumentParser(
        description="Open Cybersecurity Schema Framework Schema Compiler."
                    " Compile an OCSF schema directory structure down to a single JSON object"
                    " written to standard output."
                    " Source code at https://github.com/ocsf/ocsf-schema-compiler.",
    )
    parser.add_argument(
        "path",
        type=Path,
        help="path to an OCSF schema directory (e.g., a git clone of https://github.com/ocsf/ocsf-schema)")
    parser.add_argument(
        "-i", "--ignore-platform-extensions",
        action="store_true",
        default=False,
        help="ignore platform extensions (if any); these are in an extensions directory under the schema directory")
    parser.add_argument(
        "-e", "--extensions-path",
        action="append",
        type=Path,
        metavar="PATH",
        dest="extensions_paths",
        help="optional path to a directory containing one or more OCSF schema extensions; can be repeated")
    parser.add_argument(
        "-b", "--include-browser-data",
        action="store_true",
        default=False,
        help="include extra data needed by the schema browser (the OCSF Server)")
    parser.add_argument(
        "-t", "--tolerate-errors",
        action="store_true",
        default=False,
        help="tolerate common extension errors during schema compilation")

    parser.add_argument(
        "-l", "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        default="INFO",
        help="log level (default: %(default)s); logs are written to standard error")

    args = parser.parse_args()

    logging.basicConfig(format="%(levelname)s: %(message)s", style="%", stream=stderr, level=args.log_level)

    start_seconds = perf_counter()

    compiler = SchemaCompiler(args.path, args.ignore_platform_extensions, args.extensions_paths,
                              args.include_browser_data, args.tolerate_errors)
    schema = compiler.compile()

    duration = perf_counter() - start_seconds
    logger.info("Schema compilation took %.3f seconds", duration)

    # Output in legacy format
    # TODO: Add command line arg to pick output format.
    # TODO: Add compiler output format version. Original (legacy) should be 0.
    # TODO: Add extension information
    # TODO: Add profile information. Profiles from extensions should be extension scoped.
    legacy_classes = items_to_legacy(schema.classes, "class", schema.objects)
    legacy_objects = items_to_legacy(schema.objects, "object", schema.objects)
    dictionary_to_legacy(schema.dictionary)
    output = {
        "base_event": legacy_classes.get("base_event"),
        "classes": legacy_classes,
        "objects": legacy_objects,
        "dictionary_attributes": schema.dictionary.get("attributes"),
        "types": schema.dictionary.get("types", {}).get("attributes"),
        "version": schema.version
    }
    print(json.dumps(output))

    # TODO: debugging friendly version:
    # print(json.dumps(schema, cls=CustomEncoder, indent=2, sort_keys=True))
    # print(json.dumps(schema.classes["registry_value_activity"], cls=CustomEncoder, indent=2, sort_keys=True))
    # print(json.dumps(schema.objects["process"], cls=CustomEncoder, indent=2, sort_keys=True))
    # print(json.dumps(schema.dictionary, cls=CustomEncoder, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
