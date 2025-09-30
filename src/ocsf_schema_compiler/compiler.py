import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from utils import deep_merge, extension_category_uid, json_type_from_value

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
    categories: Optional[StrValueDict]
    classes: Optional[StrValueDict]
    objects: Optional[StrValueDict]
    dictionary: Optional[StrValueDict]
    profiles: Optional[StrValueDict]


type StrExtensionDict = dict[str, Extension]


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

        self.version: str = "0.0.0"  # cached to use as fallback for extension versions
        self.categories: StrValueDict = {}
        self.dictionary: StrValueDict = {}
        self.classes: StrValueDict = {}
        self.objects: StrValueDict = {}
        self.profiles: StrValueDict = {}
        self.extensions: StrExtensionDict = {}

    def compile(self) -> Schema:
        if self.schema_path.is_dir():
            pass
        else:
            raise FileNotFoundError(f"Schema path does not exist: {self.schema_path}")

        self._read_version()
        self.categories = _read_json_object_file(self.schema_path / "categories.json")
        self.dictionary: StrValueDict = _read_json_object_file(self.schema_path / "dictionary.json")
        self.classes: StrValueDict = _read_structured_items(self.schema_path, "events")
        self.objects: StrValueDict = _read_structured_items(self.schema_path, "objects")
        self.profiles: StrValueDict = _read_structured_items(self.schema_path, "profiles")
        self._read_all_extensions()

        self.preprocess_extensions()
        self.merge_categories_from_extensions()
        self.merge_dictionary_from_extensions()
        self.tweak_dictionary_object_types()

        # TODO: process includes in classes, deal with profiles
        # TODO: process includes in objects, deal with profiles
        # TODO: merge classes from extensions (before or after includes?)
        # TODO: merge objects from extensions (before or after includes?)
        # TODO: process classes:
        #       - observables (detect collisions, build up information for schema browser)
        #       - patches (patching extends)
        #       - resolve (flatten) inheritance (normal extends)
        #       - save informational complete class hierarchy (for schema browser)
        #       - remove "hidden" intermediate classes
        # TODO: process objects:
        #       - observables (detect collisions, build up information for schema browser)
        #       - patches (patching extends)
        #       - resolve (flatten) inheritance (normal extends)
        #       - save informational complete object hierarchy (for schema browser)
        #       - remove "hidden" intermediate objects
        # TODO: merge dictionary into classes and objects (in Elixir, Utils.update_dictionary/4)
        # TODO: observables from dictionary (in Elixir, Cache..observables_from_dictionary/2)
        # TODO: process profiles (in Elixir JsonReady.read_profiles / Cache.update_profiles)
        # TODO: More objects processing
        # TODO: Profiles.sanity_check
        # TODO: More classes processing
        # TODO: Extract and further process base_event
        # TODO: Fix entities (fix up / track missing attribute "requirement" values)
        # TODO: Profit!

        return Schema(
            version=self.version,
            categories=self.categories,
            classes=self.classes,  # TODO: change to compiled classes
            objects=self.objects,  # TODO: change to compiled objects
            dictionary=self.dictionary,  # TODO: change to compiled dictionary
            profiles=self.profiles,  # TODO: change to compiled profiles (information about profiles)
            # TODO: add extension information
        )

    def _read_version(self) -> None:
        version_path = self.schema_path / "version.json"
        try:
            obj = _read_json_object_file(version_path)
            self.version = obj["version"]
        except FileNotFoundError as e:
            raise FileNotFoundError(
                f"Schema version file does not exist (is this a schema directory?): {version_path}") from e
        except KeyError as e:
            raise KeyError(f'The "version" key is missing in the schema version file: {version_path}') from e

    def _read_all_extensions(self) -> None:
        if not self.ignore_platform_extensions:
            self._read_extensions(self.schema_path / "extensions", True)
        if self.extensions_paths:
            for extensions_path in self.extensions_paths:
                self._read_extensions(extensions_path, False)

    def _read_extensions(self, base_path: Path, is_platform_extension: bool) -> None:
        for dir_path, dir_names, file_names in os.walk(base_path, topdown=False):
            for file_name in file_names:
                if file_name == "extension.json":
                    # we found an extension at dir_path
                    extension = self._read_extension(Path(dir_path), is_platform_extension)
                    self.extensions[extension.name] = extension
                    logger.info("Added extension %s from directory %s", extension.name, dir_path)

    def _read_extension(self, base_path: Path, is_platform_extension: bool) -> Extension:
        logger.info("Reading extension directory: %s", base_path)
        # This should only be called after we know that extension.json exists in base_path,
        # so there's no need for extra error handling.
        extension_info_path = base_path / "extension.json"
        info = _read_json_object_file(extension_info_path)
        categories_path = base_path / "categories.json"
        if categories_path.is_file():
            categories = _read_json_object_file(categories_path)
        else:
            categories = {}
        classes = _read_structured_items(base_path, "events", is_extension=True)
        objects = _read_structured_items(base_path, "objects", is_extension=True)
        dictionary_path = base_path / "dictionary.json"
        if dictionary_path.is_file():
            dictionary = _read_json_object_file(base_path / "dictionary.json")
        else:
            dictionary = {}
        profiles = _read_structured_items(base_path, "profiles", is_extension=True)

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
                categories=categories,
                classes=classes,
                objects=objects,
                dictionary=dictionary,
                profiles=profiles,
            )
        except KeyError as e:
            raise KeyError(f"Extension has malformed extension.json file - missing {e}: {extension_info_path}") from e

    def preprocess_extensions(self) -> None:
        for extension_name, extension in self.extensions.items():
            if "attributes" in extension.categories:
                try:
                    for attribute_name, attribute in extension.categories["attributes"].items():
                        attribute["uid"] = extension_category_uid(extension.uid, attribute["uid"])
                        attribute["extension"] = extension_name
                        attribute["extension_id"] = extension.uid
                except KeyError as e:
                    raise KeyError(f"Malformed category in extension {extension.name} - missing {e}") from e

    def merge_categories_from_extensions(self) -> None:
        if "attributes" not in self.categories:
            self.categories["attributes"] = {}
        attributes = self.categories["attributes"]
        for extension_name, extension in self.extensions.items():
            if "attributes" in extension.categories:
                deep_merge(attributes, extension.categories["attributes"])

    def merge_dictionary_from_extensions(self) -> None:
        if "attributes" not in self.dictionary:
            self.dictionary["attributes"] = {}
        attributes = self.dictionary["attributes"]

        if "types" not in self.dictionary:
            self.dictionary["types"] = {}
        types = self.dictionary["types"]
        if "attributes" not in types:
            types["attributes"] = {}
        types_attributes = types["attributes"]

        for extension_name, extension in self.extensions.items():
            if extension.dictionary:
                if "attributes" in extension.dictionary:
                    deep_merge(attributes, extension.dictionary["attributes"])
                if "types" in extension.dictionary and "attributes" in extension.dictionary["types"]:
                    deep_merge(types_attributes, extension.dictionary["types"]["attributes"])

    def tweak_dictionary_object_types(self) -> None:
        """Converts dictionary types not defined in dictionary's types to object types."""
        types = self.dictionary["types"]["attributes"]
        if types is None:
            types = {}
        for attribute_name, attribute in self.dictionary["attributes"].items():
            attribute_type = attribute.get("type")
            if attribute_type not in types:
                attribute["type"] = "object_t"
                attribute["object_type"] = attribute_type


def _read_json_object_file(path: Path) -> StrValueDict:
    with open(path) as f:
        v = json.load(f)
        if not isinstance(v, dict):
            t = json_type_from_value(v)
            raise TypeError(f"Schema file contains a JSON {t} value, but should contain an object: {path}")
        return v


def _read_structured_items(base_path: Path, kind: str, is_extension=False) -> Optional[StrValueDict]:
    """
    Read schema structured items found in `kind` directory under `base_path`, recursively, and returns dict with
    unprocessed items, each keyed by their name attribute or for extension patches, keyed by the name of the
    item being patched.
    """
    # event classes can be organized in subdirectories, so we must walk to find all the event class JSON files
    item_path = base_path / kind
    items = {}
    for dir_path, dir_names, file_names in os.walk(item_path, topdown=False):
        for file_name in file_names:
            if file_name.endswith(".json"):
                file_path = Path(dir_path, file_name)
                obj = _read_json_object_file(file_path)
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


def schema_compile(
        schema_path: Path,
        ignore_platform_extensions: bool,
        extensions_paths: list[Path],
        include_browser_data: bool,
) -> Schema:
    schema_compiler = SchemaCompiler(schema_path, ignore_platform_extensions, extensions_paths, include_browser_data)
    return schema_compiler.compile()
