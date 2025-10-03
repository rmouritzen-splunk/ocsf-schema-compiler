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


# Type aliases for JSON-compatible types. See https://json.org.
# Yes, these are circular, and Python is OK with that.
# JValue is type alias for types compatible with JSON values.
type JValue = JObject | JArray | str | int | float | bool | None
# JObject is a type alias for dictionary compatible with a JSON object.
type JObject = dict[str, JValue]
# JArray is a type alias for types compatible with a JSON array.
type JArray = list[JValue] | tuple[JValue]


@dataclass
class Schema:
    version: str
    categories: JObject
    classes: JObject
    objects: JObject
    dictionary: JObject
    profiles: JObject


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

        logger.info("Compiling schema.path: %s", self.schema_path)
        logger.info("Path: %s", self.schema_path)
        if self.ignore_platform_extensions:
            logger.info("Ignoring platform extensions (if any) at path: %s", self.schema_path / "extensions")
        else:
            logger.info("Including platform extensions (if any) at path: %s", self.schema_path / "extensions")
        if self.extensions_paths:
            logger.info("Including extensions path(s): %s", ", ".join(list(map(str, self.extensions_paths))))
        if self.include_browser_data:
            logger.info("Including extra information needed by the schema browser (the OCSF Server)")

        self._version: str = "0.0.0"  # cached to use as fallback for extension versions
        self._categories: JObject = {}
        self._dictionary: JObject = {}
        self._classes: JObject = {}
        self._class_patches: PatchDict = {}
        self._objects: JObject = {}
        self._object_patches: PatchDict = {}
        self._profiles: JObject = {}
        self._include_cache: dict[Path, JObject] = {}
        self._observable_type_id_dict: JObject = {}

    def compile(self) -> Schema:
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

        # TODO: merge dictionary into classes and objects (in Elixir, Utils.update_dictionary/4)
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
        # TODO: Profit!
        #       Handle include_browser_data, which could be stripping keys with leading underscores,
        #       as opposed to adding in browser information after fully compiling (which wouldn't work).

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
                    category_detail["uid"] = extension_category_uid(extension.uid, category_detail["uid"])
                    category_detail["extension"] = extension.name
                    category_detail["extension_id"] = extension.uid
            except KeyError as e:
                raise SchemaException(f'Malformed category in extension "{extension.name}" - missing {e}') from e

            for cls in extension.classes.values():
                cls["extension"] = extension.name
                cls["extension_id"] = extension.uid

            for cls in extension.class_patches.values():
                cls["extension"] = extension.name
                cls["extension_id"] = extension.uid

            for obj in extension.objects.values():
                obj["extension"] = extension.name
                obj["extension_id"] = extension.uid

            for obj in extension.object_patches.values():
                obj["extension"] = extension.name
                obj["extension_id"] = extension.uid

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
        return _read_structured_items(self.schema_path, "profiles", self._profile_callback)

    def _read_and_enrich_extension_profiles(
            self, extension_id: int, extension_name: str, base_path: Path
    ) -> JObject:
        item_callback = lambda path, item: self._extension_profile_callback(extension_id, extension_name, path, item)
        return _read_structured_items(base_path, "profiles", item_callback)

    def _profile_callback(self, path: Path, profile: JObject) -> None:
        attributes = profile.setdefault("attributes", {})
        profile_name = profile.get("name")
        if not isinstance(profile_name, str):
            raise SchemaException(f'Profile "name" value must be a string,'
                                  f' but got {json_type_from_value(profile_name)}')
        for attribute_detail in attributes.values():
            attribute_detail["profile"] = profile_name
        self._include_cache[path] = profile

    def _extension_profile_callback(
            self, extension_id: int, extension_name: str, path: Path, profile: JObject
    ) -> None:
        attributes = profile.setdefault("attributes", {})
        profile_name = profile.get("name")
        if not isinstance(extension_name, str):
            raise SchemaException(f'Extension "{extension_name}" profile "name" value must be a string,'
                                  f' but got {json_type_from_value(profile_name)}')
        for attribute_detail in attributes.values():
            attribute_detail["profile"] = profile_name
            attribute_detail["extension_id"] = extension_id
            attribute_detail["extension"] = extension_name
        self._include_cache[path] = profile

    def _resolve_includes(self) -> None:
        path_resolver = lambda file_name: self.schema_path / file_name
        for cls in self._classes.values():
            self._resolve_item_includes(cls, f"class {cls.get("name")}", path_resolver)
        for obj in self._objects.values():
            self._resolve_item_includes(obj, f"object {obj.get("name")}", path_resolver)

    def _resolve_extension_includes(self, extensions: list[Extension]) -> None:
        for extension in extensions:
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
                t = json_type_from_value(include_value)
                raise TypeError(f"Illegal {sub_context} value type: expected string or array (list), but got {t}")

        # Second resolve $include at in attribute details. An include at this level is a JSON object containing
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
        for attribute_name, attribute_detail in item_attributes.items():
            if isinstance(attribute_detail, dict) and "$include" in attribute_detail:
                sub_context = f"{context} attributes.{attribute_name}.$include"
                # Get $include value and remove it from attribute
                include_value = attribute_detail.pop("$include")
                if isinstance(include_value, str):
                    include_path = path_resolver(include_value)
                    self._merge_attribute_detail_include(
                        item_attributes, attribute_name, attribute_detail, sub_context, include_path)
                else:
                    t = json_type_from_value(include_value)
                    raise TypeError(f"Illegal {sub_context} value type: expected string, but got {t}")

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
            attribute_name: str,
            attribute_detail: JObject,
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

    def _get_include_contents(self, context: str, include_path: Path) -> JObject:
        if include_path in self._include_cache:
            return self._include_cache[include_path]

        try:
            include_item = _read_json_object_file(include_path)
            self._include_cache[include_path] = include_item
            return include_item
        except FileNotFoundError as e:
            raise SchemaException(f"{context} file does not exist: {include_path}") from e

    def _merge_classes_from_extensions(self, extensions: list[Extension]):
        for extension in extensions:
            if extension.classes:
                for class_name, class_detail in extension.classes.items():
                    if class_name in self._classes:
                        # logger.warning('"%s" extension class "%s" is overwriting existing class',
                        #                extension.name, class_name)
                        if "extension" in class_detail:
                            raise SchemaException(f'Collision: "{extension.name}" class "{class_name}"'
                                                  f' collides with extension {class_detail["extension"]} class'
                                                  f' with caption {class_detail.get("caption"), ""}')
                        else:
                            raise SchemaException(f'Collision: "{extension.name}" class "{class_name}"'
                                                  f' collides with base class'
                                                  f' with caption {class_detail.get("caption"), ""}')
                    self._classes[class_name] = class_detail

    def _merge_objects_from_extensions(self, extensions: list[Extension]):
        for extension in extensions:
            if extension.objects:
                for object_name, object_detail in extension.objects.items():
                    if object_name in self._objects:
                        # logger.warning('"%s" extension object "%s" is overwriting existing object',
                        #                extension.name, object_name)
                        if "extension" in object_detail:
                            raise SchemaException(f'Collision: "{extension.name}" object "{object_name}"'
                                                  f' collides with extension {object_detail["extension"]} object'
                                                  f' with caption {object_detail.get("caption"), ""}')
                        else:
                            raise SchemaException(f'Collision: "{extension.name}" object "{object_name}"'
                                                  f' collides with base object'
                                                  f' with caption {object_detail.get("caption"), ""}')
                    self._objects[object_name] = object_detail

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
            for patch_name, patch_detail in extension.class_patches.items():
                patches = self._class_patches.setdefault(patch_name, [])
                patches.append(patch_detail)
            for patch_name, patch_detail in extension.object_patches.items():
                patches = self._object_patches.setdefault(patch_name, [])
                patches.append(patch_detail)

    def _enrich_dictionary_object_types(self) -> None:
        """Converts dictionary types not defined in dictionary's types to object types."""
        types = self._dictionary.setdefault("types", {})
        types_attributes = types.setdefault("attributes", {})
        for attribute_name, attribute in self._dictionary.setdefault("attributes", {}).items():
            attribute_type = attribute.get("type")
            if attribute_type not in types_attributes:
                attribute["type"] = "object_t"
                attribute["object_type"] = attribute_type

    def _process_classes(self) -> None:
        self._observables_from_classes()
        # TODO: process classes:
        #       - patches (patching extends)
        #       - resolve (flatten) inheritance (normal extends)
        #       - save informational complete class hierarchy (for schema browser)
        #       - enrich classes with scoped UIDs (Cache.enrich_class)
        #       - remove "hidden" intermediate classes
        for class_name, class_detail in self._classes.items():
            pass

    def _process_objects(self) -> None:
        self._observables_from_objects()
        # TODO: process objects:
        #       - observables (detect collisions, build up information for schema browser)
        #       - patches (patching extends)
        #       - resolve (flatten) inheritance (normal extends)
        #       - save informational complete object hierarchy (for schema browser)
        #       - remove "hidden" intermediate objects
        for object_name, object_detail in self._objects.items():
            pass

    def _observables_from_classes(self) -> None:
        """Detect observable collisions and build up information for schema browser."""
        for class_name, class_detail in self._classes.items():
            context = "base schema"
            self._validate_class_observables(class_name, class_detail, "base schema", is_patch=False)
            self._observables_from_item_attributes(self._classes, class_name, class_detail, "Class", is_patch=False)
            self._observables_from_item_observables(self._classes, class_name, class_detail, "Class",is_patch=False)

        for patch_name, patch_detail_list in self._class_patches.items():
            for patch_detail in patch_detail_list:
                context = f'"{patch_detail["extension"]}" extension patch'
                self._validate_class_observables(patch_name, patch_detail, context, is_patch=True)
                self._observables_from_item_attributes(self._classes, patch_name, patch_detail, "Class", is_patch=True)
                self._observables_from_item_observables(self._classes, patch_name, patch_detail, "Class", is_patch=True)

    @staticmethod
    def _validate_class_observables(class_name: str, class_detail: JObject, context: str, is_patch: bool) -> None:
        if "observable" in class_detail:
            raise SchemaException(
                f'Illegal definition of one or more attributes with "observable" in {context} class'
                f' "{class_name}". Defining class-level observables is not supported (this would be'
                f' redundant). Instead use the "class_uid" attribute for querying, correlating, and'
                f' reporting.')

        if not is_patch and _is_hidden_class(class_name, class_detail):
            attributes = class_detail.setdefault("attributes", {})
            for attribute_detail in attributes.values():
                if "observable" in attribute_detail:
                    raise SchemaException(
                        f'Illegal definition of one or more attributes with "observable" definition in'
                        f' {context} hidden class "{class_name}". This would cause colliding definitions'
                        f' of the same observable type_id values in all children of this class. Instead,'
                        f' define observables (of any kind) in non-hidden child classes of "{class_name}".')

            if "observables" in class_detail:
                raise SchemaException(
                    f'Illegal "observables" definition in {context} hidden class "{class_name}".'
                    f' This would cause colliding definitions of the same observable type_id values in'
                    f' all children of this class. Instead, define observables (of any kind) in'
                    f' non-hidden child classes of "{class_name}".')

    def _observables_from_objects(self) -> None:
        """Detect observable collisions and build up information for schema browser."""
        for object_name, object_detail in self._objects.items():
            context = "base schema"
            self._validate_object_observables(object_name, object_detail, "base schema", is_patch=False)
            self._observables_from_object(object_name, object_detail, context)
            self._observables_from_item_attributes(self._objects, object_name, object_detail, "Object", is_patch=False)
            # Not supported:
            # self._observables_from_item_observables(
            #     self._objects, object_name, object_detail, "Object", is_patch=False)

        for patch_name, patch_detail_list in self._object_patches.items():
            for patch_detail in patch_detail_list:
                context = f'"{patch_detail["extension"]}" extension patch'
                self._validate_object_observables(patch_name, patch_detail, context, is_patch=True)
                self._observables_from_object(patch_name, patch_detail, context)
                self._observables_from_item_attributes(self._objects, patch_name, patch_detail, "Object", is_patch=True)
                # Not supported:
                # self._observables_from_item_observables(
                #     self._objects, patch_name, patch_detail, "Object", is_patch=True)

    @staticmethod
    def _validate_object_observables(object_name: str, object_detail: JObject, context: str, is_patch: bool) -> None:
        if "observables" in object_detail:
            # Attribute-path observables would be tricky to implement as an machine-driven enrichment.
            # It would require tracking the relative from the point of the object down that tree of an
            # overall OCSF event.
            raise SchemaException(
                f'Illegal "observables" definition in {context} object "{object_name}".'
                f' Object-specific attribute path observables are not supported.'
                f' Please file an issue if you find this feature necessary.')

        if not is_patch and _is_hidden_object(object_name):
            attributes = object_detail.setdefault("attributes", {})
            for attribute_detail in attributes.values():
                if "observable" in attribute_detail:
                    raise SchemaException(
                        f'Illegal definition of one or more attributes with "observable" definition in'
                        f' {context} hidden object "{object_name}". This would cause colliding definitions'
                        f' of the same observable type_id values in all children of this object. Instead,'
                        f' define observables (of any kind) in non-hidden child objects of "{object_name}".')

            if "observable" in object_detail:
                raise SchemaException(
                    f'Illegal "observable" definition in {context} hidden object "{object_name}".'
                    f' This would cause colliding definitions of the same observable type_id values in'
                    f' all children of this object. Instead, define observables (of any kind) in'
                    f' non-hidden child objects of "{object_name}".')

    def _observables_from_object(self, object_name: str, object_detail: JObject, context: str) -> None:
        pass # TODO

    def _observables_from_item_attributes(
            self,
            items: JObject,
            item_name: str,
            item: JObject,
            kind: str,  # title-case kind; should be "Class" or "Object"
            is_patch: bool,
    ) -> None:
        if is_patch:
            caption = self._find_parent_item_caption(items, item_name, item)
        else:
            caption = self._find_item_caption(items, item_name, item)
        for attribute_name, attribute_detail in item.setdefault("attributes", {}).items():
            if "observable" in attribute_detail:
                observable_type_id = attribute_detail["observable"]
                if observable_type_id in self._observable_type_id_dict:
                    raise SchemaException(
                        f'Collision of observable type_id {observable_type_id} between'
                        f' "{caption}" {kind} attribute "{attribute_name}" and'
                        f' "{self._observable_type_id_dict[observable_type_id]["caption"]}"')
                self._observable_type_id_dict[observable_type_id] = self._make_observable_enum_entry(
                    f"{caption} {kind}: {attribute_name}",
                    f'{kind}-specific attribute "{attribute_name}" for the {caption} {kind}.',
                    f"{kind}-Specific Attribute")

    def _observables_from_item_observables(
            self,
            items: JObject,
            item_name: str,
            item: JObject,
            kind: str,  # title-case kind; should be "Class" or "Object"
            is_patch: bool,
    ) -> None:
        if "observables" in item:
            if is_patch:
                caption = self._find_parent_item_caption(items, item_name, item)
            else:
                caption = self._find_item_caption(items, item_name, item)
            for attribute_path, observable_type_id in item["observables"].items():
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
    def _find_item_caption(items: JObject, item_name: str, item: JObject) -> str:
        if "caption" in item:
            return item["caption"]
        return SchemaCompiler._find_parent_item_caption(items, item_name, item)

    @staticmethod
    def _find_parent_item_caption(items: JObject, item_name: str, item: JObject) -> str:
        current_item = item
        while True:
            if "extends" in item:
                parent_name = current_item["extends"]
                if parent_name in items:
                    parent_item = items[parent_name]
                    if "caption" in parent_item:
                        return parent_item["caption"]
                    current_item = parent_item
                else:
                    raise SchemaException(f'Ancestor "{parent_name}" of "{item_name}" is undefined.')
            else:
                break
        return item_name  # fallback


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
                    t = json_type_from_value(name)
                    raise SchemaException(
                        f'The "name" value in {kind} file must be a string but got {t}: {file_path}')

                if name not in items:
                    items[name] = obj
                    if item_callback_fn:
                        item_callback_fn(file_path, obj)
                else:
                    current_caption = obj.get("caption", "")
                    existing = items[name]
                    existing_caption = existing.get("caption", "")
                    raise SchemaException(f'Collision of {kind} name: "{name}", caption "{current_caption}"'
                                          f' collides with {kind} with caption "{existing_caption}",'
                                          f' file: {file_path}')
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
                    t = json_type_from_value(name)
                    raise SchemaException(
                        f'Extension {kind} file "name" value must be a string but got {t}: {file_path}')
                if extends and not isinstance(extends, str):
                    t = json_type_from_value(extends)
                    raise SchemaException(
                        f'Extension {kind} file "extends" value must be a string but got {t}: {file_path}')

                if name and name != extends:  # if not a patch
                    if name not in items:
                        items[name] = obj
                    else:
                        current_caption = obj.get("caption", "")
                        existing = items[name]
                        existing_caption = existing.get("caption", "")
                        raise SchemaException(f'Collision of {kind} name: "{name}", caption "{current_caption}"'
                                              f' collides with {kind} with caption "{existing_caption}",'
                                              f' file: {file_path}')
                elif extends:  # if a patch
                    patch_name = extends
                    if patch_name not in patches:
                        patches[patch_name] = obj
                    else:
                        existing = patches[patch_name]
                        current_caption = obj.get("caption", "")
                        existing_caption = existing.get("caption", "")
                        raise SchemaException(f'Collision of extension {kind} patch name ("extends" key):'
                                              f' "{patch_name}", caption "{current_caption}",'
                                              f' collides with {kind} with caption "{existing_caption}",'
                                              f' file: {file_path}')
                else:
                    raise SchemaException(
                        f'Extension {kind} file does not have a "name" or "extends" attribute: {file_path}')
    return items, patches


def _is_hidden_class(class_name: str, class_detail: JObject) -> bool:
    return class_name != "base_event" and "uid" not in class_detail


def _is_hidden_object(object_name: str) -> bool:
    return object_name.startswith("_")


def schema_compile(
        schema_path: Path,
        ignore_platform_extensions: bool,
        extensions_paths: list[Path],
        include_browser_data: bool,
) -> Schema:
    schema_compiler = SchemaCompiler(schema_path, ignore_platform_extensions, extensions_paths, include_browser_data)
    return schema_compiler.compile()
