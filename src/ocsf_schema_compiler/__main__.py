import dataclasses
import json
import logging
from argparse import ArgumentParser
from pathlib import Path
from sys import stderr
from time import perf_counter

from compiler import SchemaCompiler
from jsonish import JObject

logger = logging.getLogger(__name__)


class CustomEncoder(json.JSONEncoder):
    def default(self, obj):
        if dataclasses.is_dataclass(obj):
            return dataclasses.asdict(obj)
        return super().default(obj)


def fix_name(name: str, item: JObject) -> str:
    if "extension" in item:
        return f'{item["extension"]}/{name}'
    return name


def fix_attribute_object_type(attribute: JObject, objects: JObject) -> None:
    if "object_type" in attribute:
        obj_name = attribute["object_type"]
        if obj_name in objects:
            obj = objects[obj_name]
            if "extension" in obj:
                attribute["object_type"] = f'{obj["extension"]}/{attribute["object_type"]}'


def items_to_legacy(items: JObject, objects: JObject) -> JObject:
    legacy_items = {}
    for item_name, item in items.items():
        legacy_items[fix_name(item_name, item)] = item
        if "attributes" in item:
            for attribute_name, attribute in item["attributes"].items():
                fix_attribute_object_type(attribute, objects)
    return legacy_items


def dictionary_to_legacy(dictionary: dict, objects: JObject) -> None:
    legacy_attributes = {}
    for attribute_name, attribute in dictionary["attributes"].items():
        fix_attribute_object_type(attribute, objects)
        legacy_attributes[fix_name(attribute_name, attribute)] = attribute
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
    # output = {
    #     "base_event": schema.classes.get("base_event"),
    #     "classes": schema.classes,
    #     "objects": schema.objects,
    #     "dictionary_attributes": schema.dictionary.get("attributes"),
    #     "types": schema.dictionary.get("types", {}).get("attributes"),
    #     "version": schema.version
    # }
    legacy_classes = items_to_legacy(schema.classes, schema.objects)
    legacy_objects = items_to_legacy(schema.objects, schema.objects)
    dictionary_to_legacy(schema.dictionary, schema.objects)
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
