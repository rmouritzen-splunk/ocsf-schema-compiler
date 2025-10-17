import json
import logging
from argparse import ArgumentParser
from pathlib import Path
from sys import stderr
from time import perf_counter

from compiler import SchemaCompiler

logger = logging.getLogger(__name__)


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
        "-s", "--scope-extension-keys",
        action="store_true",
        default=False,
        help="scope extension keys (default: %(default)s)")
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
                              args.include_browser_data, args.scope_extension_keys, args.tolerate_errors)
    output = compiler.compile()

    duration = perf_counter() - start_seconds
    logger.info("Schema compilation took %.3f seconds", duration)

    print(json.dumps(output))


if __name__ == '__main__':
    main()
