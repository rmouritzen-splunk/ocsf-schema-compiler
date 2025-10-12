import dataclasses
import json
import logging
from argparse import ArgumentParser
from pathlib import Path
from sys import stderr

from compiler import SchemaCompiler

logger = logging.getLogger(__name__)


class CustomEncoder(json.JSONEncoder):
    def default(self, obj):
        if dataclasses.is_dataclass(obj):
            return dataclasses.asdict(obj)
        return super().default(obj)


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

    compiler = SchemaCompiler(args.path, args.ignore_platform_extensions, args.extensions_paths,
                              args.include_browser_data, args.tolerate_errors)
    schema = compiler.compile()
    # TODO: final version:
    #   print(json.dumps(schema, cls=CustomEncoder))
    # TODO: debugging friendly version:
    # print(json.dumps(schema, cls=CustomEncoder, indent=2, sort_keys=True))
    # print(json.dumps(schema.classes["base_event"], cls=CustomEncoder, indent=2, sort_keys=True))
    print(json.dumps(schema.objects["file"], cls=CustomEncoder, indent=2, sort_keys=True))
    # print(json.dumps(schema.dictionary, cls=CustomEncoder, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
