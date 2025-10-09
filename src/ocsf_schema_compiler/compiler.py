import json
import logging
import os
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from utils import (
    deep_merge, json_type_from_value, put_non_none,
    extension_scoped_category_uid, category_scoped_class_uid, class_uid_scoped_type_uid
)

logger = logging.getLogger(__name__)


class SchemaException(Exception):
    pass


# Type aliases for JSON-compatible types. See https://json.org.
# Yes, these are circular, and Python is OK with that.
# As with all Python type hints, these improve code readability and help IDEs identify type mismatches.

# JValue is type alias for types compatible with JSON values.
type JValue = JObject | JArray | str | int | float | bool | None
# JObject is a type alias for dictionary compatible with a JSON object.
type JObject = dict[str, JValue]
# JArray is a type alias for types compatible with a JSON array.
# Note: a custom encoder is required to encode Python sets.
type JArray = list[JValue] | tuple[JValue]


@dataclass
class Schema:
    version: str
    categories: JObject  # needed for browser UI
    classes: JObject
    objects: JObject
    dictionary: JObject  # needed for browser UI
    profiles: JObject  # needed for browser UI


@dataclass
class Extension:
    base_path: Path
    uid: int
    name: str
    is_platform_extension: bool
    caption: Optional[str]
    description: Optional[str]
    version: str
    categories: JObject
    classes: JObject
    class_patches: JObject
    objects: JObject
    object_patches: JObject
    dictionary: JObject
    profiles: JObject


# Type alias for dictionary from patch item name to a list of patch objects.
# The value is list since different extensions can patch the same thing.
type PatchDict = dict[str, list[JObject]]


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

        logger.info("Schema path: %s", self.schema_path)
        if self.ignore_platform_extensions:
            logger.info("Ignoring platform extensions (if any) at path: %s", self.schema_path / "extensions")
        else:
            logger.info("Including platform extensions (if any) at path: %s", self.schema_path / "extensions")
        if self.extensions_paths:
            logger.info("Including extensions path(s): %s", ", ".join(list(map(str, self.extensions_paths))))
        if self.include_browser_data:
            logger.info("Including extra information needed by the schema browser (the OCSF Server)")

        self._is_compiled = False
        self._version: str = "0.0.0"  # cached to use as fallback for extension versions
        self._categories: JObject = {}
        self._dictionary: JObject = {}
        self._classes: JObject = {}
        # class patches consolidated from all extensions
        self._class_patches: PatchDict = {}
        self._objects: JObject = {}
        # object patches consolidated from all extensions
        self._object_patches: PatchDict = {}
        self._profiles: JObject = {}
        self._include_cache: dict[Path, JObject] = {}
        # Observable type_id values extracted from all observable sources
        # Used to detect collisions and populate the observable object's type_id enum
        self._observable_type_id_dict: JObject = {}
        # Slice of classes before removing "hidden" / abstract classes
        self._all_classes: JObject = {}
        # Slice of objects before removing "hidden" / abstract objects
        self._all_objects: JObject = {}

    def compile(self) -> Schema:
        if self._is_compiled:
            raise SchemaException("Schema already compiled (compile can only be run once)")
        self._is_compiled = True

        logger.info("Compiling schema")

        if self.schema_path.is_dir():
            pass
        else:
            raise FileNotFoundError(f"Schema path does not exist: {self.schema_path}")

        self._read_base_schema()
        extensions = self._read_all_extensions()

        self._resolve_includes()
        self._resolve_extension_includes(extensions)

        self._merge_categories_from_extensions(extensions)
        self._merge_classes_from_extensions(extensions)
        self._merge_objects_from_extensions(extensions)
        self._merge_dictionary_from_extensions(extensions)

        self._consolidate_extension_patches(extensions)

        self._enrich_dictionary_object_types()

        self._process_classes()
        self._process_objects()

        self._enrich_and_validate_dictionary()

        # TODO: observables from dictionary (in Elixir, Cache..observables_from_dictionary/2)
        # TODO: process profiles (in Elixir JsonReady.read_profiles / Cache.update_profiles)
        #       or do this while resolving includes?
        # TODO: More objects processing:
        #       Utils.update_objects, Cache.update_observable, Cache.update_objects, Cache.final_check
        # TODO: Profiles.sanity_check
        # TODO: More classes processing:
        #       Cache.update_classes, Cache.final_check
        # TODO: Extract and further process base_event: Cache.final_check
        #       NOTE: This doesn't seem necessary since in Python we are updating in-place.
        # TODO: Fix entities (fix up / track missing attribute "requirement" values)
        #
        # TODO: enrich classes and objects with dictionary attribute information
        #       See: Cache.export_classes, Cache.export_objects
        #       NOTE: This is different from how the OCSF Server works. Let's try it and strip out the enrich magic
        #             from the server.
        #
        # TODO: Profit!

        # TODO: Double-check compiled schema: diff against Elixir-generated schema
        # TODO: Handle include_browser_data. Probably strip keys with leading underscores
        #       (as opposed to skipping adding browser information, which would skip some validation checks).

        return Schema(
            version=self._version,
            categories=self._categories,
            classes=self._classes,
            objects=self._objects,
            dictionary=self._dictionary,
            profiles=self._profiles,  # TODO: change to profiles information
            # TODO: add extensions information
        )

    def _read_base_schema(self):
        self._read_version()
        self._categories = _read_json_object_file(self.schema_path / "categories.json")
        self._dictionary = _read_json_object_file(self.schema_path / "dictionary.json")
        self._classes = _read_structured_items(self.schema_path, "events")
        self._objects = _read_structured_items(self.schema_path, "objects")
        self._profiles = self._read_and_enrich_profiles()

    def _read_version(self) -> None:
        version_path = self.schema_path / "version.json"
        try:
            obj = _read_json_object_file(version_path)
            self._version = obj["version"]
        except FileNotFoundError as e:
            raise SchemaException(
                f"Schema version file does not exist (is this a schema directory?): {version_path}") from e
        except KeyError as e:
            raise SchemaException(f'The "version" key is missing in the schema version file: {version_path}') from e

    def _read_all_extensions(self) -> list[Extension]:
        extensions: list[Extension] = []
        if not self.ignore_platform_extensions:
            self._read_extensions(extensions, self.schema_path / "extensions", is_platform_extension=True)
        if self.extensions_paths:
            for extensions_path in self.extensions_paths:
                self._read_extensions(extensions, extensions_path, is_platform_extension=False)

        self._enrich_extension_items(extensions)
        return extensions

    def _read_extensions(
        self, extensions: list[Extension], base_path: Path, is_platform_extension: bool
    ) -> None:
        for dir_path, dir_names, file_names in os.walk(base_path, topdown=False):
            for file_name in file_names:
                if file_name == "extension.json":
                    # we found an extension at dir_path
                    extension = self._read_extension(Path(dir_path), is_platform_extension)
                    extensions.append(extension)
                    if is_platform_extension:
                        logger.info('Read platform extension "%s" from directory: %s', extension.name, dir_path)
                    else:
                        logger.info('Read extension "%s" from directory: %s', extension.name, dir_path)

    def _read_extension(self, base_path: Path, is_platform_extension: bool) -> Extension:
        if is_platform_extension:
            logger.info("Reading platform extension directory: %s", base_path)
        else:
            logger.info("Reading extension directory: %s", base_path)
        # This should only be called after we know that extension.json exists in base_path,
        # so there's no need for extra error handling.
        extension_info_path = base_path / "extension.json"
        info = _read_json_object_file(extension_info_path)

        uid = info.get("uid")
        name = info.get("name")
        if not isinstance(uid, int):
            t = json_type_from_value(uid)
            raise SchemaException(f'The extension "uid" must be an integer but got {t}: {extension_info_path}')
        if not isinstance(name, str):
            t = json_type_from_value(name)
            raise SchemaException(f'The extension "name" must be a string but got {t}: {extension_info_path}')

        categories_path = base_path / "categories.json"
        if categories_path.is_file():
            categories = _read_json_object_file(categories_path)
        else:
            categories = {}

        classes, class_patches = _read_patchable_structured_items(base_path, "events")
        objects, object_patches = _read_patchable_structured_items(base_path, "objects")

        dictionary_path = base_path / "dictionary.json"
        if dictionary_path.is_file():
            dictionary = _read_json_object_file(base_path / "dictionary.json")
        else:
            dictionary = {}

        profiles = self._read_and_enrich_extension_profiles(uid, name, base_path)

        try:
            if is_platform_extension and "version" not in info:
                # Fall back to overall schema version for platform extensions that do not specify their own version
                version = self._version
            else:
                version = info["version"]
            return Extension(
                base_path=base_path,
                uid=uid,
                name=name,
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
            raise SchemaException(
                f"Extension has malformed extension.json file - missing {e}: {extension_info_path}") from e

    @staticmethod
    def _enrich_extension_items(extensions: list[Extension]) -> None:
        for extension in extensions:
            try:
                for category_detail in extension.categories.setdefault("attributes", {}).values():
                    category_detail["uid"] = extension_scoped_category_uid(extension.uid, category_detail["uid"])
                    category_detail["extension"] = extension.name
                    category_detail["extension_id"] = extension.uid
            except KeyError as e:
                raise SchemaException(f'Malformed category in extension "{extension.name}" - missing {e}') from e

            for cls in extension.classes.values():
                cls["extension"] = extension.name
                cls["extension_id"] = extension.uid

            for cls_patch in extension.class_patches.values():
                cls_patch["extension"] = extension.name
                cls_patch["extension_id"] = extension.uid

            for obj in extension.objects.values():
                obj["extension"] = extension.name
                obj["extension_id"] = extension.uid

            for obj_patch in extension.object_patches.values():
                obj_patch["extension"] = extension.name
                obj_patch["extension_id"] = extension.uid

            for dictionary_attribute in extension.dictionary.setdefault("attributes", {}).values():
                dictionary_attribute["extension"] = extension.name
                dictionary_attribute["extension_id"] = extension.uid

            for profile in extension.profiles.values():
                profile["extension"] = extension.name
                profile["extension_id"] = extension.uid
                for profile_attribute in profile.setdefault("attributes", {}).values():
                    profile_attribute["extension"] = extension.name
                    profile_attribute["extension_id"] = extension.uid

    def _read_and_enrich_profiles(self) -> JObject:
        return _read_structured_items(self.schema_path, "profiles", self._enrich_profile)

    def _read_and_enrich_extension_profiles(
        self, extension_id: int, extension_name: str, base_path: Path
    ) -> JObject:
        item_callback = lambda path, item: self._enrich_extension_profile(extension_id, extension_name, path, item)
        return _read_structured_items(base_path, "profiles", item_callback)

    def _enrich_profile(self, path: Path, profile: JObject) -> None:
        attributes = profile.setdefault("attributes", {})
        profile_name = profile.get("name")
        if not isinstance(profile_name, str):
            raise SchemaException(f'Profile "name" value must be a string,'
                                  f' but got {json_type_from_value(profile_name)}')
        for attribute in attributes.values():
            attribute["profile"] = profile_name
        self._include_cache[path] = profile

    def _enrich_extension_profile(
        self, extension_id: int, extension_name: str, path: Path, profile: JObject
    ) -> None:
        attributes = profile.setdefault("attributes", {})
        profile_name = profile.get("name")
        if not isinstance(extension_name, str):
            raise SchemaException(f'Extension "{extension_name}" profile "name" value must be a string,'
                                  f' but got {json_type_from_value(profile_name)}')
        for attribute in attributes.values():
            attribute["profile"] = profile_name
            attribute["extension_id"] = extension_id
            attribute["extension"] = extension_name
        self._include_cache[path] = profile

    def _resolve_includes(self) -> None:
        path_resolver = lambda file_name: self.schema_path / file_name
        for cls in self._classes.values():
            self._resolve_item_includes(cls, f'class "{cls.get("name")}"', path_resolver)
        for obj in self._objects.values():
            self._resolve_item_includes(obj, f'object "{obj.get("name")}"', path_resolver)

    def _resolve_extension_includes(self, extensions: list[Extension]) -> None:
        for extension in extensions:
            path_resolver = lambda file_name: self._resolve_extension_include_path(extension, file_name)

            for cls in extension.classes.values():
                context = f'extension "{extension.name}" class "{cls.get("name")}"'
                self._resolve_item_includes(cls, context, path_resolver)

            for cls_patch in extension.class_patches.values():
                context = f'extension "{extension.name}" class patch "{cls_patch.get("name")}"'
                self._resolve_item_includes(cls_patch, context, path_resolver)

            for obj in extension.objects.values():
                context = f'extension "{extension.name}" object "{obj.get("name")}"'
                self._resolve_item_includes(obj, context, path_resolver)

            for obj_patch in extension.object_patches.values():
                context = f'extension "{extension.name}" object patch "{obj_patch.get("name")}"'
                self._resolve_item_includes(obj_patch, context, path_resolver)

    def _resolve_extension_include_path(self, extension: Extension, file_name: str) -> Path:
        extension_path = extension.base_path / file_name
        if extension_path.is_file():
            return extension_path
        path = self.schema_path / file_name
        if path.is_file():
            return path
        raise FileNotFoundError(f'Extension "{extension.name}" "$include" {file_name} not found in'
                                f' extension directory {extension.base_path} or schema directory {self.schema_path}')

    def _resolve_item_includes(
        self,
        item: Optional[JObject],
        context: str,
        path_resolver: Callable[[str], Path]
    ) -> None:
        item_attributes = item.setdefault("attributes", {})

        # First resolve $include at "attributes" level. These are commonly used for profiles.
        # An include at this level has the common item JSON object structure with keys like
        # "name", "caption", "description", and "attributes". Of these, only the "attributes"
        # are merged.
        #
        # This value of the "$include" key can be single string or an array of strings. Each string is a path relative
        # to the base directory of the schema, or for extensions, the base directory of the extension OR the schema.
        #
        # The merge prefers existing values. The existing attributes details (if any) are merged on top of
        # (a copy of) the include contents.
        #
        # This example shows the array form of an $include:
        # {
        #    "name": "foo",
        #    ... other item details
        #    "attributes": {
        #       "$include": [
        #         "profiles/bar.json",
        #         "profiles/baz.json",
        #       ]
        #       "qux": {
        #          ... attribute details
        #       },
        #       ... other attributes
        #    }
        # }
        if "$include" in item_attributes:
            sub_context = f"{context} attributes.$include"
            # Get $include value and remove it from item attributes
            include_value = item_attributes.pop("$include")
            if isinstance(include_value, str):
                include_path = path_resolver(include_value)
                self._merge_attributes_include(item, sub_context, include_path)
            elif isinstance(include_value, list):
                for include_file_name in include_value:
                    include_path = path_resolver(include_file_name)
                    self._merge_attributes_include(item, sub_context, include_path)
            else:
                raise TypeError(f"Illegal {sub_context} value type:"
                                f" expected string or array (list), but got {json_type_from_value(include_value)}")

        # Second resolve $include in attribute details. An include at this level is a JSON object containing
        # exactly the information to merge in. These are (or were) used to extract common enum values.
        # The merge prefers existing values. The existing attributes details (if any) are merged on top of
        #
        # The value of the "$include" key must be a single string. The string is a path relative to the base of the
        # schema, or for extensions, the base directory of the extension OR the schema.
        #
        # The merge prefers existing values. The existing attributes details (if any) are merged on top of
        # (a copy of) the include contents.
        #
        # Example:
        # {
        #    "name": "foo",
        #    ... other item details
        #    "attributes": {
        #       "baz_id": {
        #          "$include": "enum/baz.json"
        #           ... other attribute details (if any)
        #       },
        #       ... other attributes
        #    }
        # }
        #
        # attributes may have been modified, so we need to get them again, though now we know they exist
        item_attributes = item["attributes"]
        for attribute_key, attribute in item_attributes.items():
            if isinstance(attribute, dict) and "$include" in attribute:
                sub_context = f"{context} attributes.{attribute_key}.$include"
                # Get $include value and remove it from attribute
                include_value = attribute.pop("$include")
                if isinstance(include_value, str):
                    include_path = path_resolver(include_value)
                    self._merge_attribute_detail_include(
                        item_attributes, attribute_key, attribute, sub_context, include_path)
                else:
                    raise TypeError(f"Illegal {sub_context} value type: expected string,"
                                    f" but got {json_type_from_value(include_value)}")

    def _merge_attributes_include(self, item: JObject, context: str, include_path: Path) -> None:
        include_item = self._get_include_contents(context, include_path)

        # Create new attributes for item, starting with included attributes
        # Include files should always have "attributes", but we will be defensive.
        if "attributes" in include_item:
            attributes = deepcopy(include_item["attributes"])
        else:
            logger.warning("Include file suspiciously has no attributes: %s", include_path)
            return  # Nothing to merge. This should never happen, but is possible.

        # item["attributes"] should exist at this point, so no need to double-check
        # Merge item's attributes on top of the copy of the include attribute, preferring item's data
        deep_merge(attributes, item["attributes"])
        # replace item "attributes" with merged / resolved include attributes
        item["attributes"] = attributes

    def _merge_attribute_detail_include(
        self,
        attributes: JObject,
        attribute_key: str,
        attribute: JObject,
        context: str,
        include_path: Path) -> None:
        include_item = self._get_include_contents(context, include_path)

        # Create new attribute_detail for attributes.{attribute_name}, starting with included_item
        # Include files should always have "attributes", but we will be defensive.
        new_attribute = deepcopy(include_item)

        # Merge original attribute detail on top of the copy of the included attribute_detail, preferring the original
        deep_merge(new_attribute, attribute)
        # replace existing attribute detail with the new merged detail
        attributes[attribute_key] = new_attribute

    def _get_include_contents(self, context: str, include_path: Path) -> JObject:
        if include_path in self._include_cache:
            return self._include_cache[include_path]

        try:
            include_item = _read_json_object_file(include_path)
            self._include_cache[include_path] = include_item
            return include_item
        except FileNotFoundError as e:
            raise SchemaException(f"{context} file does not exist: {include_path}") from e

    def _merge_classes_from_extensions(self, extensions: list[Extension]) -> None:
        for extension in extensions:
            if extension.classes:
                self._merge_extension_items(extension.name, extension.classes, self._classes, "class")

    def _merge_objects_from_extensions(self, extensions: list[Extension]) -> None:
        for extension in extensions:
            if extension.objects:
                self._merge_extension_items(extension.name, extension.objects, self._objects, "object")

    @staticmethod
    def _merge_extension_items(extension_name: str, extension_items: JObject, items: JObject, kind: str) -> None:
        for ext_item_key, ext_item in extension_items.items():
            if ext_item_key in items:
                item_caption = ext_item.get("caption", "")
                if "extension" in ext_item:
                    raise SchemaException(f'Collision: extension "{extension_name}" {kind} "{ext_item_key}" collides'
                                          f' with extension "{ext_item["extension"]}" {kind}'
                                          f' with caption "{item_caption}"')
                else:
                    raise SchemaException(f'Collision: extension "{extension_name}" {kind} "{ext_item_key}" collides'
                                          f' with base schema {kind} with caption "{item_caption}"')
            items[ext_item_key] = ext_item

    def _merge_categories_from_extensions(self, extensions: list[Extension]) -> None:
        categories_attributes = self._categories.setdefault("attributes", {})
        for extension in extensions:
            ext_categories_attributes = extension.categories.setdefault("attributes", {})
            deep_merge(categories_attributes, ext_categories_attributes)

    def _merge_dictionary_from_extensions(self, extensions: list[Extension]) -> None:
        dictionary_attributes = self._dictionary.setdefault("attributes", {})
        dictionary_types = self._dictionary.setdefault("types", {})
        dictionary_types_attributes = dictionary_types.setdefault("attributes", {})

        for extension in extensions:
            ext_dictionary_attributes = extension.dictionary.setdefault("attributes", {})
            deep_merge(dictionary_attributes, ext_dictionary_attributes)

            ext_dictionary_types = extension.dictionary.setdefault("types", {})
            ext_dictionary_types_attributes = ext_dictionary_types.setdefault("attributes", {})
            deep_merge(dictionary_types_attributes, ext_dictionary_types_attributes)

    def _consolidate_extension_patches(self, extensions: list[Extension]) -> None:
        for extension in extensions:
            for patch_key, patch in extension.class_patches.items():
                patches = self._class_patches.setdefault(patch_key, [])
                patches.append(patch)
            for patch_key, patch in extension.object_patches.items():
                patches = self._object_patches.setdefault(patch_key, [])
                patches.append(patch)

    def _enrich_dictionary_object_types(self) -> None:
        """Converts dictionary types not defined in dictionary's types to object types."""
        types = self._dictionary.setdefault("types", {})
        types_attributes = types.setdefault("attributes", {})
        for attribute_key, attribute in self._dictionary.setdefault("attributes", {}).items():
            attribute_type = attribute.get("type")
            if attribute_type not in types_attributes:
                attribute["type"] = "object_t"
                attribute["object_type"] = attribute_type

    def _process_classes(self) -> None:
        # Extracting observables is easier to do before resolving (flattening) "extends" inheritance since afterward
        # the observable type_id will be propagated to all children of an event class.
        self._observables_from_classes()

        self._resolve_patches(self._classes, self._class_patches, "class")
        self._resolve_extends(self._classes, "class")

        # Save informational complete class hierarchy (for schema browser)
        # TODO: only do this when self.include_browser_data is True?
        for cls_key, cls in self._classes.items():
            cls_slice = {}
            for k in ["name", "caption", "extends", "extension"]:
                if k in cls:
                    cls_slice[k] = cls[k]
            cls_slice["is_hidden"] = _is_hidden_class(cls_key, cls)
            self._all_classes[cls_key] = cls_slice

        # Remove hidden classes
        self._classes = {name: cls for name, cls in self._classes.items() if not _is_hidden_class(name, cls)}

        self._enrich_classes()

    def _enrich_classes(self) -> None:
        # enrich classes
        for cls_key, cls in self._classes.items():
            # update class uid
            category_key = cls.get("category")
            category = self._categories.setdefault("attributes", {}).get(category_key)
            if category:
                cls["category_name"] = category.get("caption")
                category_uid = category.get("uid", 0)
            else:
                category_uid = 0

            cls_uid = category_scoped_class_uid(category_uid, cls.get("uid", 0))
            cls["uid"] = cls_uid

            # add/update type_uid attribute
            cls_attributes = cls.setdefault("attributes", {})
            cls_caption = cls.get("caption", "UNKNOWN")
            type_uid_attribute = cls_attributes.setdefault("type_uid", {})
            type_uid_enum = {}
            if "activity_id" in cls_attributes and "enum" in cls_attributes["activity_id"]:
                activity_enum = cls_attributes["activity_id"]["enum"]
                for activity_enum_key, activity_enum_value in activity_enum.items():
                    enum_key = str(class_uid_scoped_type_uid(cls_uid, int(activity_enum_key)))
                    enum_value = deepcopy(activity_enum_value)
                    enum_caption = f"{cls_caption}: {activity_enum_value.get("caption", "<unknown>")}"
                    enum_value["caption"] = enum_caption
                    type_uid_enum[enum_key] = enum_value
            else:
                raise SchemaException(f'Class "{cls_key}" has invalid "activity_id" definition: "enum" not defined')
            type_uid_enum[str(class_uid_scoped_type_uid(cls_uid, 0))] = {
                "caption": f"{cls_caption}: Unknown",
            }
            type_uid_attribute["enum"] = type_uid_enum
            # TODO: Only add when self.include_browser_data is True?
            type_uid_attribute["_source"] = cls_key

            # add class_uid and class_name attributes
            cls_uid_attribute = cls_attributes.setdefault("class_uid", {})
            cls_name_attribute = cls_attributes.setdefault("class_name", {})
            cls_uid_key = str(cls_uid)
            enum = {cls_uid_key: {"caption": cls_caption, "description": cls.get("description", "")}}
            cls_uid_attribute["enum"] = enum
            # TODO: Only add when self.include_browser_data is True?
            cls_uid_attribute["_source"] = cls_key
            cls_name_attribute["description"] = (f"The event class name,"
                                                 f" as defined by class_uid value: <code>{cls_caption}</code>.")

            # add category_uid
            # add/update category_uid and category_name attributes
            if category:
                category_uid = category.get("uid", 0)
                cls["category_uid"] = category_uid

                category_uid_attribute = cls_attributes.setdefault("category_uid", {})
                enum = category_uid_attribute.setdefault("enum", {})
                category_uid_key = str(category_uid)
                enum[category_uid_key] = deepcopy(category)

                category_name_attribute = cls_attributes.setdefault("category_name", {})
                category_name_attribute["description"] = (f"The event category name, as defined by category_uid value:"
                                                          f" <code>{category.get("caption", "")}</code>.)")
            else:
                if category_key == "other":
                    logger.info('Class "%s" uses special undefined category "other"', cls_key)
                elif category_key is None:
                    logger.warning('Class "%s" has no category', cls_key)
                else:
                    logger.warning('Class "%s" has undefined category "%s"', cls_key, category_key)

    def _process_objects(self) -> None:
        # Extracting observables is easier to do before resolving (flattening) "extends" inheritance since afterward
        # the observable type_id will be propagated to all children of an object.
        self._observables_from_objects()

        self._resolve_patches(self._objects, self._object_patches, "object")
        self._resolve_extends(self._objects, "object")

        # Save informational complete object hierarchy (for schema browser)
        # TODO: only do this when self.include_browser_data is True?
        for obj_key, obj in self._objects.items():
            obj_slice = {}
            for k in ["name", "caption", "extends", "extension"]:
                if k in obj:
                    obj_slice[k] = obj[k]
                obj_slice["is_hidden"] = _is_hidden_object(obj_key)
            self._all_objects[obj_key] = obj_slice

        # Remove hidden objects
        self._objects = {name: obj for name, obj in self._objects.items() if not _is_hidden_object(name)}

    def _observables_from_classes(self) -> None:
        """Detect observable collisions and build up information for schema browser."""
        for cls_key, cls in self._classes.items():
            self._validate_class_observables(cls_key, cls, "base schema", is_patch=False)
            self._observables_from_item_attributes(self._classes, cls_key, cls, "Class", is_patch=False)
            self._observables_from_item_observables(self._classes, cls_key, cls, "Class", is_patch=False)

        for patch_key, patch_list in self._class_patches.items():
            for patch in patch_list:
                context = f'"{patch["extension"]}" extension patch'
                self._validate_class_observables(patch_key, patch, context, is_patch=True)
                self._observables_from_item_attributes(self._classes, patch_key, patch, "Class", is_patch=True)
                self._observables_from_item_observables(self._classes, patch_key, patch, "Class", is_patch=True)

    @staticmethod
    def _validate_class_observables(cls_key: str, cls: JObject, context: str, is_patch: bool) -> None:
        if "observable" in cls:
            raise SchemaException(
                f'Illegal definition of one or more attributes with "observable" in {context} class'
                f' "{cls_key}". Defining class-level observables is not supported (this would be'
                f' redundant). Instead use the "class_uid" attribute for querying, correlating, and'
                f' reporting.')

        if not is_patch and _is_hidden_class(cls_key, cls):
            attributes = cls.setdefault("attributes", {})
            for attribute in attributes.values():
                if "observable" in attribute:
                    raise SchemaException(
                        f'Illegal definition of one or more attributes with "observable" definition in'
                        f' {context} hidden class "{cls_key}". This would cause colliding definitions'
                        f' of the same observable type_id values in all children of this class. Instead,'
                        f' define observables (of any kind) in non-hidden child classes of "{cls_key}".')

            if "observables" in cls:
                raise SchemaException(
                    f'Illegal "observables" definition in {context} hidden class "{cls_key}".'
                    f' This would cause colliding definitions of the same observable type_id values in'
                    f' all children of this class. Instead, define observables (of any kind) in'
                    f' non-hidden child classes of "{cls_key}".')

    def _observables_from_objects(self) -> None:
        """Detect observable collisions and build up information for schema browser."""
        for obj_key, obj in self._objects.items():
            context = "base schema"
            self._validate_object_observables(obj_key, obj, "base schema", is_patch=False)
            self._observables_from_object(obj_key, obj, context)
            self._observables_from_item_attributes(self._objects, obj_key, obj, "Object", is_patch=False)
            # Not supported:
            # self._observables_from_item_observables(self._objects, obj_key, obj, "Object", is_patch=False)

        for patch_key, patch_list in self._object_patches.items():
            for patch in patch_list:
                context = f'"{patch["extension"]}" extension patch'
                self._validate_object_observables(patch_key, patch, context, is_patch=True)
                self._observables_from_object(patch_key, patch, context)
                self._observables_from_item_attributes(self._objects, patch_key, patch, "Object", is_patch=True)
                # Not supported:
                # self._observables_from_item_observables(self._objects, patch_key, patch, "Object", is_patch=True)

    @staticmethod
    def _validate_object_observables(obj_key: str, obj: JObject, context: str, is_patch: bool) -> None:
        if "observables" in obj:
            # Attribute-path observables would be tricky to implement as an machine-driven enrichment.
            # It would require tracking the relative from the point of the object down that tree of an
            # overall OCSF event.
            raise SchemaException(
                f'Illegal "observables" definition in {context} object "{obj_key}".'
                f' Object-specific attribute path observables are not supported.'
                f' Please file an issue if you find this feature necessary.')

        if not is_patch and _is_hidden_object(obj_key):
            attributes = obj.setdefault("attributes", {})
            for attribute_detail in attributes.values():
                if "observable" in attribute_detail:
                    raise SchemaException(
                        f'Illegal definition of one or more attributes with "observable" definition in'
                        f' {context} hidden object "{obj_key}". This would cause colliding definitions'
                        f' of the same observable type_id values in all children of this object. Instead,'
                        f' define observables (of any kind) in non-hidden child objects of "{obj_key}".')

            if "observable" in obj:
                raise SchemaException(
                    f'Illegal "observable" definition in {context} hidden object "{obj_key}".'
                    f' This would cause colliding definitions of the same observable type_id values in'
                    f' all children of this object. Instead, define observables (of any kind) in'
                    f' non-hidden child objects of "{obj_key}".')

    def _observables_from_object(self, obj_key: str, obj: JObject, context: str) -> None:
        caption = self._find_item_caption(self._objects, obj_key, obj)
        if "observable" in obj:
            observable_type_id = str(obj["observable"])

            if observable_type_id in self._observable_type_id_dict:
                raise SchemaException(
                    f'Collision of observable type_id {observable_type_id} between'
                    f' "{caption}" object "observable" and'
                    f' "{self._observable_type_id_dict[observable_type_id]["caption"]}"')

            self._observable_type_id_dict[observable_type_id] = self._make_observable_enum_entry(
                caption, caption, "Object")

    def _observables_from_item_attributes(
        self,
        items: JObject,
        item_key: str,
        item: JObject,
        kind: str,  # title-case kind; should be "Class" or "Object"
        is_patch: bool,
    ) -> None:
        if is_patch:
            caption = self._find_parent_item_caption(items, item_key, item)
        else:
            caption = self._find_item_caption(items, item_key, item)
        for attribute_key, attribute in item.setdefault("attributes", {}).items():
            if "observable" in attribute:
                observable_type_id = str(attribute["observable"])

                if observable_type_id in self._observable_type_id_dict:
                    raise SchemaException(
                        f'Collision of observable type_id {observable_type_id} between'
                        f' "{caption}" {kind} attribute "{attribute_key}" and'
                        f' "{self._observable_type_id_dict[observable_type_id]["caption"]}"')

                self._observable_type_id_dict[observable_type_id] = self._make_observable_enum_entry(
                    f"{caption} {kind}: {attribute_key}",
                    f'{kind}-specific attribute "{attribute_key}" for the {caption} {kind}.',
                    f"{kind}-Specific Attribute")

    def _observables_from_item_observables(
        self, items: JObject, item_key: str, item: JObject, kind: str, is_patch: bool
    ) -> None:
        # kind should be title-case: "Class" or "Object"
        if "observables" in item:
            if is_patch:
                caption = self._find_parent_item_caption(items, item_key, item)
            else:
                caption = self._find_item_caption(items, item_key, item)
            for attribute_path, observable_type_id_num in item["observables"].items():
                observable_type_id = str(observable_type_id_num)
                if observable_type_id in self._observable_type_id_dict:
                    raise SchemaException(
                        f'Collision of observable type_id {observable_type_id} between'
                        f' "{caption}" {kind} attribute path "{attribute_path}" and'
                        f' "{self._observable_type_id_dict[observable_type_id]["caption"]}"')

                self._observable_type_id_dict[observable_type_id] = self._make_observable_enum_entry(
                    f"{caption} {kind}: {attribute_path}",
                    f'{kind}-specific attribute "{attribute_path}" for the {caption} {kind}.',
                    f"{kind}-Specific Attribute")

    @staticmethod
    def _make_observable_enum_entry(caption: str, description: str, observable_kind: str) -> JObject:
        return {
            "caption": caption,
            "description": f"Observable by {observable_kind}.<br>{description}",
            "_observable_kind": observable_kind
        }

    @staticmethod
    def _find_item_caption(items: JObject, item_key: str, item: JObject) -> str:
        if "caption" in item:
            return item["caption"]
        return SchemaCompiler._find_parent_item_caption(items, item_key, item)

    @staticmethod
    def _find_parent_item_caption(items: JObject, item_key: str, item: JObject) -> str:
        current_item = item
        while True:
            if "extends" in item:
                parent_key = current_item["extends"]
                if parent_key in items:
                    parent_item = items[parent_key]
                    if "caption" in parent_item:
                        return parent_item["caption"]
                    current_item = parent_item
                else:
                    raise SchemaException(f'Ancestor "{parent_key}" of "{item_key}" is undefined.')
            else:
                break
        return item_key  # fallback

    @staticmethod
    def _resolve_patches(items: JObject, patches: PatchDict, kind: str) -> None:
        for patch_key, patch_list in patches.items():
            for patch in patch_list:
                base_key = patch["extends"]  # this will be the same as patch_name
                assert patch_key == base_key, "Patch name should match extends base name"
                extension_name = patch.get("extension", "<unknown>")
                logger.info('"%s" %s from "%s" extension is patching "%s"', patch_key, kind, extension_name, base_key)
                if base_key not in items:
                    raise SchemaException(f'"{patch_key}" {kind} from "{extension_name}" extension'
                                          f' is attempting to patch undefined {kind} "{base_key}"')
                base = items[base_key]
                SchemaCompiler._merge_profiles(base, patch)
                deep_merge(base.setdefault("attributes", {}), patch.setdefault("attributes", {}))
                # Top-level observable.
                # Only occurs in objects, but is safe to do for classes too.
                put_non_none(base, "observable", patch.get("observable"))
                # Top-level path-based observables.
                # Only occurs in classes, but is safe to do for objects too.
                put_non_none(base, "observables", patch.get("observables"))
                put_non_none(base, "references", patch.get("references"))
                # Top-level attribute associations.
                # Only occurs in classes, but is safe to do for objects too.
                put_non_none(base, "associations", patch.get("associations"))
                SchemaCompiler._patch_constraints(base, patch)

    @staticmethod
    def _merge_profiles(dest: JObject, source: JObject) -> None:
        dest_profiles = set(dest.get("profiles", []))
        source_profiles = set(source.get("profiles", []))
        merged = dest_profiles.union(source_profiles)
        if merged:  # avoid adding "profiles" if neither base nor patch had any
            dest["profiles"] = sorted(merged)  # sorts and converts to list (otherwise profiles are randomly sorted)

    @staticmethod
    def _patch_constraints(base: JObject, patch: JObject) -> None:
        if "constraints" in patch:
            constraints = patch["constraints"]
            if constraints:
                base["constraints"] = constraints
            else:
                # Remove base constraints if patch explicitly defines an empty constraints list
                del base["constraints"]

    @staticmethod
    def _resolve_extends(items: JObject, kind: str) -> None:
        for item_key, item in items.items():
            SchemaCompiler._resolve_item_extends(items, item_key, item, kind)

    @staticmethod
    def _resolve_item_extends(items: JObject, item_key: str, item: JObject, kind: str) -> None:
        if item_key is None or item is None:
            return

        parent_key = item.get("extends")
        SchemaCompiler._resolve_item_extends(items, parent_key, items.get(parent_key), kind)
        assert parent_key == item.get("extends"), (f'{kind} "{item_key}" "extends" value should not change after'
                                                   f' recursively processing parent: original value: "{parent_key}",'
                                                   f' current value: "{item.get("extends")}"')

        if parent_key:
            parent_item = items.get(parent_key)
            if parent_item:
                # Create flattened item by merging item on top of a copy of it's parent with the result
                # that new and overlapping things in item "win" over those in parent.
                # This new item replaces the existing one.
                new_item = deepcopy(parent_item)
                # The values of most keys simply replace what is in the parent, except for attributes and profiles
                for source_key, source_value in item.items():
                    if source_key == "attributes":
                        new_attributes = new_item.get("attributes", {})
                        deep_merge(new_attributes, source_value)
                        # Remove any keys that have null (None) values
                        # TODO: This doesn't seem to happen. Still needed?
                        #       After everything is working, try removing.
                        for k, v in new_attributes.items():
                            if v is None:
                                logger.debug('Attribute "%s" is None in %s "%s"', k, kind, item_key)
                        new_attributes = dict((k, v) for k, v in new_attributes.items() if v is not None)
                        new_item["attributes"] = new_attributes
                    elif source_key == "profiles":
                        SchemaCompiler._merge_profiles(new_item, item)
                    else:
                        # Only replace value if source isn't None (JSON null)
                        # TODO: This doesn't seem to happen. Still needed?
                        #       After everything is working, try removing.
                        if source_value is not None:
                            new_item[source_key] = source_value
                        else:
                            logger.debug('Not merging null value of key "%s" in %s "%s"', source_key, kind, item_key)
                items[item_key] = new_item
            else:
                raise SchemaException(f'{kind} "{item.get("name", "<unknown>")}"'
                                      f' extends undefined {kind} "{parent_key}"')

    def _enrich_and_validate_dictionary(self):
        self._add_common_dictionary_attribute_links()
        self._add_class_dictionary_attribute_links()
        self._add_object_dictionary_attribute_links()
        self._enrich_and_validate_dictionary_attribute_types()
        self._add_datetime_sibling_dictionary_attributes()
        pass

    @staticmethod
    def _make_link(group: str, item_name: str, item: JObject) -> JObject:
        """
        Create link reference. The group value should be "common", "class", or "object", with "common" being a group
        holding the "base_event" class, which is treated specially.
        """
        link: JObject = {
            "group": group,
            "type": item_name,
            "caption": item.get("caption", "*No name*")
        }
        if "@deprecated" in item:
            link["@deprecated"] = True
        return link

    def _add_link_to_dictionary_attributes(self, kind: str, item_name: str, item: JObject, link: JObject) -> None:
        dictionary_attributes = self._dictionary.setdefault("attributes", {})
        item_attributes = item.setdefault("attributes", {})
        for item_attribute_key, item_attribute in item_attributes.items():
            enriched_link = deepcopy(link)
            # TODO: Are "attribute_keys" used for all types or only object types? (Seems like only object types.)
            #       Once everything is working, try only setting "attribute_keys" for object types.
            enriched_link["attribute_keys"] = [item_attribute_key]
            # TODO: Do we need to do special extension processing from Utils.update_attributes?
            #       It looks like this was a hack to avoid defining extension attributes in its dictionary.
            #       That code is NOT replicated here.
            if item_attribute_key in dictionary_attributes:
                dictionary_attribute = dictionary_attributes[item_attribute_key]
                links = dictionary_attribute.setdefault("_links", [])
                links.append(enriched_link)
            else:
                raise SchemaException(f'{kind} "{item_name}" uses undefined attribute "{item_attribute_key}"')

    def _add_common_dictionary_attribute_links(self):
        if "base_event" not in self._classes:
            raise SchemaException('Schema has not defined a "base_event" class')
        base_event = self._classes["base_event"]
        link = self._make_link("common", "base_event", base_event)
        self._add_link_to_dictionary_attributes("class", "base_event", base_event, link)

    def _add_class_dictionary_attribute_links(self):
        for cls_name, cls in self._classes.items():
            link = self._make_link("class", cls_name, cls)
            self._add_link_to_dictionary_attributes("class", cls_name, cls, link)

    def _add_object_dictionary_attribute_links(self):
        for obj_name, obj in self._objects.items():
            link = self._make_link("object", obj_name, obj)
            self._add_link_to_dictionary_attributes("object", obj_name, obj, link)

    def _enrich_and_validate_dictionary_attribute_types(self):
        dictionary_attributes = self._dictionary.setdefault("attributes", {})
        dictionary_types = self._dictionary.setdefault("types", {}).setdefault("attributes", {})

        for attribute_key, attribute in dictionary_attributes.items():
            if "type" in attribute:
                attribute_type = attribute["type"]
            else:
                raise SchemaException(f'Dictionary attribute'
                                      f' {self._name_with_possible_extension(attribute_key, attribute)}'
                                      f' does not define "type"')

            if attribute_type == "object_t":
                # Object dictionary type
                # Add "object_name" to attribute details based on caption.
                # NOTE: This must be done after resolving patches and extends so caption is resolved.
                # TODO: self._enrich_dictionary_object_types() transforms original object attribute type to
                #       "object_t" and sets "object_type". Why not do both at this point?
                #       After everything it working, change the approach and make sure the end result is the same.
                object_type = attribute["object_type"]
                if object_type in self._objects:
                    obj = self._objects[object_type]
                    obj["object_name"] = obj.get("caption", "")
                else:
                    raise SchemaException(
                        f'Undefined object type in dictionary attribute "{attribute_key}": "{object_type}"')
            else:
                # Normal dictionary type
                if attribute_type in dictionary_types:
                    type_detail = dictionary_types[attribute_type]
                    if "caption" in type_detail:
                        attribute["type_name"] = type_detail["caption"]
                    else:
                        raise SchemaException(f'Dictionary attribute type "{attribute_type}"'
                                              f' does not define "caption"')
                else:
                    raise SchemaException(f'Dictionary attribute'
                                          f' {self._name_with_possible_extension(attribute_key, attribute)}'
                                          f' has undefined "type" of "{attribute_type}"')

    @staticmethod
    def _name_with_possible_extension(name: str, detail: JObject) -> str:
        if "extension" in detail:
            return f'"{name}" from extension "{detail["extension"]}"'
        return name

    def _add_datetime_sibling_dictionary_attributes(self) -> None:
        """
        When "datetime" profile and "datetime_t" dictionary type are both define,
        add magic datetime dictionary attributes as siblings to dictionary attributes with type "timestamp_t".
        """
        got_datetime_profile = "datetime" in self._profiles
        got_datetime_t = "datetime_t" in self._dictionary.setdefault("types", {}).setdefault("attributes", {})
        if got_datetime_profile and got_datetime_t:
            # Add datetime siblings
            dictionary_attributes = self._dictionary.setdefault("attributes", {})
            # We can't add dictionary_attributes while iterator, so instead add to another dict and then merge
            additions = {}
            for attribute_key, attribute in dictionary_attributes.items():
                if attribute.get("type") == "timestamp_t":
                    sibling = deepcopy(attribute)
                    sibling["type"] = "datetime_t"
                    sibling["type_name"] = "Datetime"
                    additions[self._make_datetime_attribute_name(attribute_key)] = sibling
            dictionary_attributes.update(additions)
        elif got_datetime_profile:
            raise SchemaException('Schema defines "datetime" profile but does not define "datetime_t" dictionary type')
        elif got_datetime_t:
            raise SchemaException('Schema defines "datetime_t" dictionary type but does not define "datetime" profile')
        else:
            logger.info('This schema does not define the "datetime" profile and "datetime_t" dictionary type,'
                        ' so datetime siblings of timestamp_t attributes will not be added.')

    @staticmethod
    def _make_datetime_attribute_name(timestamp_name: str) -> str:
        return f'{timestamp_name}_dt'

def _read_json_object_file(path: Path) -> JObject:
    with open(path) as f:
        v = json.load(f)
        if not isinstance(v, dict):
            t = json_type_from_value(v)
            raise TypeError(f"Schema file contains a JSON {t} value, but should contain an object: {path}")
        return v


def _read_structured_items(
    base_path: Path, kind: str, item_callback_fn: Callable[[Path, JObject], None] = None
) -> JObject:
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
                name = obj.get("name")

                # The way this is tested, "no value" happens when attribute is missing, JSON null (Python None),
                # or an empty value (an empty string, JSON array, JSON object, or even a numeric zero).
                if not name:
                    raise SchemaException(f'The "name" value in {kind} file must have a value: {file_path}')

                # Ensure name is a string
                if not isinstance(name, str):
                    raise SchemaException(f'The "name" value in {kind} file must be a string,'
                                          f' but got {json_type_from_value(name)}: {file_path}')

                if name in items:
                    existing = items[name]
                    raise SchemaException(f'Collision of "name" in {kind} file: "{name}" with caption'
                                          f' "{obj.get("caption", "")}", collides with {kind} with caption'
                                          f' "{existing.get("caption", "")}",'
                                          f' file: {file_path}')
                else:
                    items[name] = obj
                    if item_callback_fn:
                        item_callback_fn(file_path, obj)

    return items


def _read_patchable_structured_items(base_path: Path, kind: str) -> tuple[JObject, JObject]:
    """
    Read schema "patchable" structured items found in `kind` directory under `base_path`, recursively, and returns
    dataclass with unprocessed items and patches. Extension classes and objects are patchable structured items. Items
    are each keyed by their name attribute and patches are keyed by the name of the item to patch.

    Returns tuple of items dictionary and patches dictionary.
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
                # An extension "patch" occurs in two cases:
                #   1. The item has an "extends" key but no "name" key. This is the common case in practice.
                #   2. The item has both the "name" and "extends" keys, and both have the same value.
                name = obj.get("name")
                extends = obj.get("extends")

                # A structured item (a class, object, etc.) must have a name OR an extends value
                # The way this is tested, "no value" happens when attribute is missing, JSON null (Python None),
                # or an empty value (an empty string, JSON array, JSON object, or even a numeric zero).
                if not name and not extends:
                    raise SchemaException(
                        f'Extension {kind} file does not have a "name" or "extends" value: {file_path}')

                # Ensure values are strings
                if name and not isinstance(name, str):
                    raise SchemaException(f'The "name" value in extension {kind} file must be a string,'
                                          f' but got {json_type_from_value(name)}: {file_path}')
                if extends and not isinstance(extends, str):
                    raise SchemaException(f'The "extends" value in extension {kind} file must be a string,'
                                          f' but got {json_type_from_value(extends)}: {file_path}')

                if not name or name == extends:
                    # This is a patch definition.
                    # An extension event class or object is a patch when it only defines "extends"
                    # or (weirdly) when "name" and "extends" have the same value. This second case is not used
                    # by any version of schema on https://github.com/ocsf/ocsf-schema or the Splunk extension at
                    # https://github.com/ocsf/splunk, but has always been possible and we need to support it.
                    patch_key = extends  # for clarity
                    if patch_key in patches:
                        existing = patches[patch_key]
                        raise SchemaException(f'Collision of patch name ("extends" key) in extension {kind} file:'
                                              f' "{patch_key}" with caption "{obj.get("caption", "")}", collides with'
                                              f' existing {kind} with caption "{existing.get("caption", "")}",'
                                              f' file: {file_path}')
                    else:
                        patches[patch_key] = obj
                else:
                    # This is a normal definition.
                    if name in items:
                        existing = items[name]
                        raise SchemaException(f'Collision of "name" in extension {kind} file: "{name}" with caption'
                                              f' "{obj.get("caption", "")}", collides with {kind} with caption'
                                              f' "{existing.get("caption", "")}", file: {file_path}')
                    else:
                        items[name] = obj

    return items, patches


def _is_hidden_class(cls_key: str, cls: JObject) -> bool:
    return cls_key != "base_event" and "uid" not in cls


def _is_hidden_object(obj_key: str) -> bool:
    return obj_key.startswith("_")


def schema_compile(
    schema_path: Path,
    ignore_platform_extensions: bool,
    extensions_paths: list[Path],
    include_browser_data: bool,
) -> Schema:
    schema_compiler = SchemaCompiler(schema_path, ignore_platform_extensions, extensions_paths, include_browser_data)
    return schema_compiler.compile()
