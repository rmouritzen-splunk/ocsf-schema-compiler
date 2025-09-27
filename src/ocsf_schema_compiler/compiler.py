import json
import logging
import os
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from utils import json_type_from_value

logger = logging.getLogger(__name__)

type JSONValueType = Optional[dict | list | tuple | str | int | float | bool]
type StrValueDict = dict[str, JSONValueType]


@dataclass
class Schema:
    version: str
    categories: StrValueDict
    classes: StrValueDict
    objects: Optional[StrValueDict]
    dictionary: Optional[StrValueDict]
    profiles: Optional[StrValueDict]


@dataclass
class Extension:
    uid: int
    name: str
    is_platform_extension: bool
    caption: Optional[str]
    description: Optional[str]
    version: str
    classes: Optional[StrValueDict]
    objects: Optional[StrValueDict]
    dictionary: Optional[StrValueDict]
    profiles: Optional[StrValueDict]


class SchemaCompiler:
    def __init__(
            self,
            schema_path: Path,
            ignore_platform_extensions: bool,
            extensions_paths: Optional[list[Path]],
            include_browser_data: bool
    ) -> None:
        self.schema_path: Path = schema_path
        self.ignore_platform_extensions: bool = ignore_platform_extensions
        self.extensions_paths: Optional[list[Path]] = extensions_paths
        self.include_browser_data: bool = include_browser_data

        logger.info("Compiling schema.path: %s", self.schema_path)
        logger.info("Path: %s", self.schema_path)
        if self.ignore_platform_extensions:
            logger.info("Ignoring platform extensions (if any) at path: %s", self.schema_path / "extensions")
        else:
            logger.info("Including platform extensions (if any) at path: %s", self.schema_path / "extensions")
        if self.extensions_paths:
            logger.info("Including extensions paths: %s", ", ".join(list(map(str, self.extensions_paths))))
        if self.include_browser_data:
            logger.info("Including extra information needed by the schema browser (the OCSF Server)")

        self.version: Optional[str] = None
        self.categories: Optional[StrValueDict] = None
        self.raw_classes: Optional[StrValueDict] = None
        self.raw_objects: Optional[StrValueDict] = None
        self.raw_dictionary: Optional[StrValueDict] = None
        self.raw_profiles: Optional[StrValueDict] = None
        self.extensions: dict[str, Extension] = OrderedDict()

    def compile(self) -> Schema:
        if self.schema_path.is_dir():
            pass
        else:
            raise FileNotFoundError(f"Schema path does not exist: {self.schema_path}")

        self.read_version()
        self.categories = read_json_object_file(self.schema_path / "categories.json")
        self.raw_dictionary = read_json_object_file(self.schema_path / "dictionary.json")
        self.raw_classes = self.read_classes(self.schema_path)
        self.raw_objects = self.read_objects(self.schema_path)
        self.raw_profiles = self.read_profiles(self.schema_path)
        self.read_all_extensions()

        # TODO
        return Schema(
            version=self.version,
            categories=self.categories,
            classes=self.raw_classes,  # TODO: change to compiled classes
            objects=self.raw_objects,  # TODO: change to compiled objects
            dictionary=self.raw_dictionary,  # TODO: change to compiled dictionary
            profiles=self.raw_profiles,  # TODO: change to compiled profiles
            # TODO: add extension information
        )

    def read_version(self) -> None:
        version_path = self.schema_path / "version.json"
        try:
            obj = read_json_object_file(version_path)
            self.version = obj["version"]
        except FileNotFoundError as e:
            raise FileNotFoundError(
                f"Schema version file does not exist (is this a schema directory?): {version_path}") from e
        except KeyError as e:
            raise KeyError(f'The "version" key is missing in the schema version file: {version_path}') from e

    @staticmethod
    def read_classes(base_path: Path) -> StrValueDict:
        return SchemaCompiler.read_items(base_path, "events")

    @staticmethod
    def read_objects(base_path: Path) -> StrValueDict:
        return SchemaCompiler.read_items(base_path, "objects")

    @staticmethod
    def read_profiles(base_path: Path) -> StrValueDict:
        return SchemaCompiler.read_items(base_path, "profiles")

    def read_all_extensions(self) -> None:
        if not self.ignore_platform_extensions:
            self.read_extensions(self.schema_path / "extensions", True)
        if self.extensions_paths:
            for extensions_path in self.extensions_paths:
                self.read_extensions(extensions_path, False)

    def read_extensions(self, base_path: Path, is_platform_extension: bool) -> None:
        for dir_path, dir_names, file_names in os.walk(base_path, topdown=False):
            for file_name in file_names:
                if file_name == "extension.json":
                    # we found an extension at dir_path
                    extension = self.read_extension(Path(dir_path), is_platform_extension)
                    self.extensions[extension.name] = extension
                    logger.info("Added extension %s from directory %s", extension.name, dir_path)

    def read_extension(self, base_path: Path, is_platform_extension: bool) -> Extension:
        logger.info("Reading extension directory: %s", base_path)
        # This should only be called after we know that extension.json exists in base_path,
        # so there's no need for extra error handling.
        extension_info_path = base_path / "extension.json"
        info = read_json_object_file(extension_info_path)
        raw_classes = self.read_extension_classes(base_path)
        raw_objects = self.read_extension_objects(base_path)
        dictionary_path = base_path / "dictionary.json"
        if dictionary_path.is_file():
            raw_dictionary = read_json_object_file(base_path / "dictionary.json")
        else:
            raw_dictionary = {}
        raw_profiles = self.read_extension_profiles(base_path)

        try:
            if is_platform_extension and "version" not in info:
                # Fall back to overall schema version for platform extensions that do not specify their own version
                version = self.version
            else:
                version = info["version"]
            return Extension(
                uid=info["uid"],
                name=info["name"],
                is_platform_extension=is_platform_extension,
                caption=info.get("caption"),
                description=info.get("description"),
                version=version,
                classes=raw_classes,
                objects=raw_objects,
                dictionary=raw_dictionary,
                profiles=raw_profiles,
            )
        except KeyError as e:
            raise KeyError(f"Extension has malformed extension.json file - missing {e}: {extension_info_path}") from e

    @staticmethod
    def read_extension_classes(base_path: Path) -> StrValueDict:
        return SchemaCompiler.read_items(base_path, "events", is_extension=True)

    @staticmethod
    def read_extension_objects(base_path: Path) -> StrValueDict:
        return SchemaCompiler.read_items(base_path, "objects", is_extension=True)

    @staticmethod
    def read_extension_profiles(base_path: Path) -> StrValueDict:
        return SchemaCompiler.read_items(base_path, "profiles", is_extension=True)

    @staticmethod
    def read_items(base_path: Path, kind: str, is_extension=False) -> StrValueDict:
        """
        Read schema type items found in kind directory under base_path, recursively, and returns dict with
        unprocessed items, each keyed by their name attribute or for extension patches, keyed by the name of the
        item being patched.
        """
        # event classes can be organized in subdirectories, so we must walk to find all the event class JSON files
        item_path = base_path / kind
        items = OrderedDict()
        for dir_path, dir_names, file_names in os.walk(item_path, topdown=False):
            for file_name in file_names:
                if file_name.endswith(".json"):
                    file_path = Path(dir_path, file_name)
                    obj = read_json_object_file(file_path)
                    if is_extension:
                        if "name" in obj:
                            items[obj["name"]] = obj
                        elif "extends" in obj:
                            obj["_is_patch"] = True
                            items[obj["extends"]] = obj
                        else:
                            raise KeyError(
                                f'Extension {kind} file does not have a "name" or "extends" attribute: {file_path}')
                    else:
                        try:
                            items[obj["name"]] = obj
                        except KeyError as e:
                            raise KeyError(f'The "name" key is missing in {kind} file: {file_path}') from e
        return items


def read_json_object_file(path: Path) -> StrValueDict:
    with open(path) as f:
        v = json.load(f)
        if not isinstance(v, dict):
            t = json_type_from_value(v)
            raise TypeError(f"Schema file contains a JSON {t} value, but should contain an object: {path}")
        return v


def schema_compile(
        schema_path: Path,
        ignore_platform_extensions: bool,
        extensions_paths: list[Path],
        include_browser_data: bool,
) -> Schema:
    schema_compiler = SchemaCompiler(schema_path, ignore_platform_extensions, extensions_paths, include_browser_data)
    return schema_compiler.compile()
