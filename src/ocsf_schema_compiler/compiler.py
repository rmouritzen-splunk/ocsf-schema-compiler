import json
import logging
import os
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from utils import deep_merge, extension_category_uid, json_type_from_value

logger = logging.getLogger(__name__)


class SchemaException(Exception):
    pass


type JSONValueType = Optional[dict | list | tuple | str | int | float | bool]
type StrValueDict = dict[str, JSONValueType]


@dataclass
class Schema:
    version: str
    categories: StrValueDict
    classes: StrValueDict
    objects: StrValueDict
    dictionary: StrValueDict
    profiles: StrValueDict


@dataclass
class Extension:
    base_path: Path
    uid: int
    name: str
    is_platform_extension: bool
    caption: Optional[str]
    description: Optional[str]
    version: str
    categories: StrValueDict
    classes: StrValueDict
    class_patches: StrValueDict
    objects: StrValueDict
    object_patches: StrValueDict
    dictionary: StrValueDict
    profiles: StrValueDict


@dataclass
class ItemsAndPatches:
    items: StrValueDict
    patches: StrValueDict


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
        self.include_cache: dict[Path, StrValueDict] = {}

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
        self._annotate_extension_items()

        self._resolve_includes()
        self._resolve_extension_includes()

        self._merge_categories_from_extensions()
        self._merge_classes_from_extensions()
        self._merge_objects_from_extensions()
        self._merge_dictionary_from_extensions()
        self._mark_dictionary_object_types()

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
        #       or do this while resolving includes?
        # TODO: More objects processing
        # TODO: Profiles.sanity_check
        # TODO: More classes processing
        # TODO: Extract and further process base_event
        # TODO: Fix entities (fix up / track missing attribute "requirement" values)
        # TODO: Profit!

        return Schema(
            version=self.version,
            categories=self.categories,
            classes=self.classes,
            objects=self.objects,
            dictionary=self.dictionary,
            profiles=self.profiles,  # TODO: change to profiles information
            # TODO: add extensions information
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

        items_and_patches = _read_extension_structured_items(base_path, "events")
        classes = items_and_patches.items
        class_patches = items_and_patches.patches

        items_and_patches = _read_extension_structured_items(base_path, "objects")
        objects = items_and_patches.items
        object_patches = items_and_patches.patches

        dictionary_path = base_path / "dictionary.json"
        if dictionary_path.is_file():
            dictionary = _read_json_object_file(base_path / "dictionary.json")
        else:
            dictionary = {}
        profiles = _read_structured_items(base_path, "profiles")

        try:
            if is_platform_extension and "version" not in info:
                # Fall back to overall schema version for platform extensions that do not specify their own version
                version = self.version
            else:
                version = info["version"]
            return Extension(
                base_path=base_path,
                uid=info["uid"],
                name=info["name"],
                is_platform_extension=is_platform_extension,
                caption=info.get("caption"),
                description=info.get("description"),
                version=version,
                categories=categories,
                classes=classes,
                class_patches=class_patches,
                objects=objects,
                object_patches=object_patches,
                dictionary=dictionary,
                profiles=profiles,
            )
        except KeyError as e:
            raise KeyError(f"Extension has malformed extension.json file - missing {e}: {extension_info_path}") from e

    def _annotate_extension_items(self) -> None:
        for extension_name, extension in self.extensions.items():
            if "attributes" in extension.categories:
                try:
                    for category_detail in extension.categories["attributes"].values():
                        category_detail["uid"] = extension_category_uid(extension.uid, category_detail["uid"])
                        category_detail["extension"] = extension_name
                        category_detail["extension_id"] = extension.uid
                except KeyError as e:
                    raise KeyError(f"Malformed category in extension {extension.name} - missing {e}") from e

            for cls in extension.classes.values():
                cls["extension"] = extension_name
                cls["extension_id"] = extension.uid

            for obj in extension.objects.values():
                obj["extension"] = extension_name
                obj["extension_id"] = extension.uid

    def _resolve_includes(self) -> None:
        path_resolver = lambda file_name: self.schema_path / file_name
        for cls in self.classes.values():
            self._resolve_item_includes(cls, f"class {cls.get("name")}", path_resolver)
        for obj in self.objects.values():
            self._resolve_item_includes(obj, f"object {obj.get("name")}", path_resolver)

    def _resolve_extension_includes(self) -> None:
        for extension in self.extensions.values():
            path_resolver = lambda file_name: self._resolve_extension_include_path(extension, file_name)
            for cls in extension.classes.values():
                context = f"extension {extension.name} class {cls.get("name")}"
                self._resolve_item_includes(cls, context, path_resolver)
            for obj in extension.objects.values():
                context = f"extension {extension.name} object {obj.get("name")}"
                self._resolve_item_includes(obj, context, path_resolver)

    def _resolve_extension_include_path(self, extension: Extension, file_name: str) -> Path:
        extension_path = extension.base_path / file_name
        if extension_path.is_file():
            return extension_path
        path = self.schema_path / file_name
        if path.is_file():
            return path
        raise FileNotFoundError(f"Extension {extension.name} $include {file_name} not found in"
                                f" extension directory {extension.base_path} or schema directory {self.schema_path}")

    def _resolve_item_includes(
            self,
            item: Optional[StrValueDict],
            context: str,
            path_resolver: Callable[[str], Path]
    ) -> None:
        if item and "attributes" in item:
            if "$include" in item["attributes"]:
                sub_context = f"{context} attributes.$include"
                # Get $include value and remove it from item attributes
                include_value = item["attributes"].pop("$include")
                if isinstance(include_value, str):
                    include_path = path_resolver(include_value)
                    self._merge_attributes_include(item, sub_context, include_path)
                elif isinstance(include_value, list):
                    for include_file_name in include_value:
                        include_path = path_resolver(include_file_name)
                        self._merge_attributes_include(item, sub_context, include_path)
                else:
                    t = json_type_from_value(include_value)
                    raise TypeError(f"Illegal {sub_context} value type: expected string or array (list), but got {t}")

            for attribute_name, attribute_detail in item["attributes"].items():
                if isinstance(attribute_detail, dict) and "$include" in attribute_detail:
                    sub_context = f"{context} attributes.{attribute_name}.$include"
                    # Get $include value and remove it from attribute
                    include_value = attribute_detail.pop("$include")
                    if isinstance(include_value, str):
                        include_path = path_resolver(include_value)
                        self._merge_attribute_detail_include(
                            item["attributes"], attribute_name, attribute_detail, sub_context, include_path)
                    else:
                        t = json_type_from_value(include_value)
                        raise TypeError(f"Illegal {sub_context} value type: expected string, but got {t}")

    def _merge_attributes_include(self, item: StrValueDict, context: str, include_path: Path) -> None:
        include_item = self._get_include_contents(context, include_path)

        # Create new attributes for item, starting with included attributes
        # Include files should always have "attributes", but we will be defensive.
        if "attributes" in include_item:
            attributes = deepcopy(include_item["attributes"])
        else:
            attributes = {}  # This should never happen, but is possible

        # item["attributes"] should exist at this point, so no need to double-check
        # Merge item's attributes on top of the copy of the include attribute, preferring item's data
        deep_merge(attributes, item["attributes"])
        # replace item "attributes" with merged / resolved include attributes
        item["attributes"] = attributes

    def _merge_attribute_detail_include(
            self,
            attributes: StrValueDict,
            attribute_name: str,
            attribute_detail: StrValueDict,
            context: str,
            include_path: Path) -> None:
        include_item = self._get_include_contents(context, include_path)

        # Create new attribute_detail for attributes.{attribute_name}, starting with included_item
        # Include files should always have "attributes", but we will be defensive.
        new_attribute_detail = deepcopy(include_item)

        # Merge original attribute detail on top of the copy of the included attribute_detail, preferring the original
        deep_merge(new_attribute_detail, attribute_detail)
        # replace existing attribute detail with the new merged detail
        attributes[attribute_name] = new_attribute_detail

    def _get_include_contents(self, context: str, include_path: Path) -> StrValueDict:
        if include_path in self.include_cache:
            return self.include_cache[include_path]

        try:
            include_item = _read_json_object_file(include_path)
            self.include_cache[include_path] = include_item
            return include_item
        except FileNotFoundError as e:
            raise FileNotFoundError(f"{context} file does not exist: {include_path}") from e

    def _merge_classes_from_extensions(self):
        for extension_name, extension in self.extensions.items():
            if extension.classes:
                for class_name, class_detail in extension.classes.items():
                    if class_name in self.classes:
                        logger.warning("%s extension class %s is overwriting existing class",
                                       extension.name, class_name)
                    self.classes[class_name] = class_detail

    def _merge_objects_from_extensions(self):
        for extension_name, extension in self.extensions.items():
            if extension.objects:
                for object_name, object_detail in extension.objects.items():
                    if object_name in self.objects:
                        logger.warning("%s extension object %s is overwriting existing object",
                                       extension.name, object_name)
                    self.objects[object_name] = object_detail

    def _merge_categories_from_extensions(self) -> None:
        if "attributes" not in self.categories:
            self.categories["attributes"] = {}
        attributes = self.categories["attributes"]
        for extension_name, extension in self.extensions.items():
            if "attributes" in extension.categories:
                deep_merge(attributes, extension.categories["attributes"])

    def _merge_dictionary_from_extensions(self) -> None:
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

    def _mark_dictionary_object_types(self) -> None:
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


def _read_structured_items(base_path: Path, kind: str) -> StrValueDict:
    """
    Read schema structured items found in `kind` directory under `base_path`, recursively, and returns dict with
    unprocessed items, each keyed by their name attribute.
    """
    # event classes can be organized in subdirectories, so we must walk to find all the event class JSON files
    item_path = base_path / kind
    items = {}
    for dir_path, dir_names, file_names in os.walk(item_path, topdown=False):
        for file_name in file_names:
            if file_name.endswith(".json"):
                file_path = Path(dir_path, file_name)
                obj = _read_json_object_file(file_path)
                try:
                    name = obj["name"]
                    if name not in items:
                        items[obj["name"]] = obj
                    else:
                        raise SchemaException(f"{kind} {name} is already defined, file: {file_path}")
                except KeyError as e:
                    raise KeyError(f'The "name" key is missing in {kind} file: {file_path}') from e
    return items


def _read_extension_structured_items(base_path: Path, kind: str) -> ItemsAndPatches:
    """
    Read schema structured items found in `kind` directory under `base_path`, recursively, and returns dataclass with
    unprocessed items and patches. Items are each keyed by their name attribute and patches are keyed by the name of
    the item to patch.
    """
    # event classes can be organized in subdirectories, so we must walk to find all the event class JSON files
    item_path = base_path / kind
    items = {}
    patches = {}
    for dir_path, dir_names, file_names in os.walk(item_path, topdown=False):
        for file_name in file_names:
            if file_name.endswith(".json"):
                file_path = Path(dir_path, file_name)
                obj = _read_json_object_file(file_path)
                if "name" in obj:
                    name = obj["name"]
                    if name not in items:
                        items[obj["name"]] = obj
                    else:
                        raise SchemaException(f"Extension {kind} {name} is already defined, file: {file_path}")
                elif "extends" in obj:
                    patch_name = obj["extends"]
                    if patch_name not in patches:
                        patches[obj["extends"]] = obj
                    else:
                        raise SchemaException(
                            f"Extension {kind} patch {patch_name} is already defined, file: {file_path}")
                else:
                    raise KeyError(
                        f'Extension {kind} file does not have a "name" or "extends" attribute: {file_path}')
    return ItemsAndPatches(items=items, patches=patches)


def schema_compile(
        schema_path: Path,
        ignore_platform_extensions: bool,
        extensions_paths: list[Path],
        include_browser_data: bool,
) -> Schema:
    schema_compiler = SchemaCompiler(schema_path, ignore_platform_extensions, extensions_paths, include_browser_data)
    return schema_compiler.compile()
