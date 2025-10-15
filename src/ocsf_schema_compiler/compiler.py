import logging
import os
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from exceptions import SchemaException
from jsonish import (
    JObject, json_type_from_value, read_json_object_file, read_structured_items, read_patchable_structured_items
)
from utils import (
    deep_merge, put_non_none,
    is_hidden_class, is_hidden_object,
    extension_scoped_category_uid, category_scoped_class_uid, class_uid_scoped_type_uid
)

logger = logging.getLogger(__name__)


@dataclass
class Schema:
    version: str
    categories: JObject  # needed for browser UI
    classes: JObject
    objects: JObject
    dictionary: JObject  # needed for browser UI
    profiles: JObject  # needed for browser UI
    extensions: JObject  # needed for browser UI
    # TODO: add all_classes and all_objects for browser UI


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
type PatchList = list[JObject]  # list of patches for an item name
type PatchDict = dict[str, PatchList]  # dict of item name to list of patches


class SchemaCompiler:
    def __init__(
        self,
        schema_path: Path,
        ignore_platform_extensions: bool,
        extensions_paths: Optional[list[Path]],
        include_browser_data: bool = False,
        tolerate_errors: bool = False,
    ) -> None:
        self.schema_path: Path = schema_path
        self.ignore_platform_extensions: bool = ignore_platform_extensions
        self.extensions_paths: Optional[list[Path]] = extensions_paths
        self.include_browser_data: bool = include_browser_data
        self.tolerate_errors: bool = tolerate_errors

        logger.info("Schema path: %s", self.schema_path)
        if self.ignore_platform_extensions:
            logger.info("Ignoring platform extensions (if any) at path: %s", self.schema_path / "extensions")
        else:
            logger.info("Including platform extensions (if any) at path: %s", self.schema_path / "extensions")
        if self.extensions_paths:
            logger.info("Including extensions path(s): %s", ", ".join(list(map(str, self.extensions_paths))))
        if self.include_browser_data:
            logger.info("Including extra information needed by the schema browser (the OCSF Server)")
        else:
            logger.info("Not including extra information needed by the schema browser (the OCSF Server)")

        self._is_compiled: bool = False
        self._error_count: int = 0
        self._warning_count: int = 0
        self._version: str = "0.0.0"  # cached to use as fallback for extension versions
        self._categories: JObject = {}
        self._dictionary: JObject = {}
        self._classes: JObject = {}
        # class patches consolidated from all extensions
        self._class_patches: PatchDict = {}
        self._objects: JObject = {}
        # object patches consolidated from all extensions
        self._object_patches: PatchDict = {}
        # Profile keyed by name only (unscoped names)
        self._profiles: JObject = {}
        # Same self._profiles as above, but using extension scoped names
        self._extension_scoped_profiles: JObject = {}
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

        if not self.schema_path.is_dir():
            raise FileNotFoundError(f"Schema path does not exist: {self.schema_path}")

        self._read_base_schema()

        # The extensions returned here are the information about the extension without the things it defines,
        # which are processed and merged by _read_and_merge_extensions.
        extensions = self._read_and_merge_extensions()

        self._enrich_dictionary_object_types()

        self._process_classes()
        self._process_objects()

        self._enrich_and_validate_dictionary()
        self._observables_from_dictionary()

        self._enrich_profiles_attributes_from_dictionary()  # TODO: Why are only profile attributes enriched?
        self._validate_object_profiles_and_add_links()
        if self.include_browser_data:
            self._add_object_links()
        self._update_observable_enum()
        self._consolidate_object_profiles()
        self._verify_object_attributes_and_add_datetime()

        self._validate_class_profiles_and_add_links()
        self._consolidate_class_profiles()
        self._verify_class_attributes_and_add_datetime()

        self._ensure_attributes_have_requirement()

        self._finish_attributes()

        if not self.include_browser_data:
            self._delete_browser_data()

        # TODO: Double-check compiled schema: diff against Elixir-generated schema
        # TODO: Handle include_browser_data. Probably strip keys with leading underscores
        #       (as opposed to skipping adding browser information, which would skip some validation checks).
        # TODO: Support item attributes affected by more than one profile / extension.
        #       See _merge_attribute_detail.
        # TODO: Reevaluate uses of "_source" and "_source_patched". Some may not be used in schema browser.

        if self._error_count and self._warning_count:
            logger.error("Compile completed with %d error(s) and %d warning(s)", self._error_count, self._warning_count)
        elif self._error_count and not self._warning_count:
            logger.error("Compile completed with %d error(s)", self._error_count)
        elif self._warning_count:
            logger.warning("Compile completed with %d warnings(s)", self._warning_count)
        else:
            logger.info("Compile completed successfully")

        return Schema(
            version=self._version,
            categories=self._categories,
            classes=self._classes,
            objects=self._objects,
            dictionary=self._dictionary,
            profiles=self._profiles,
            extensions=extensions,
        )

    def _tolerable_error(self, exception: SchemaException) -> None:
        """
        Log or raise exception for a particular schema error.

        Some forms of errors can be tolerated but should be fixed. These mainly occur with schema extensions that are
        not routinely validated against the OCSF metaschema.
        """
        # TODO: Remove all of this tolerable error stuff after the "splunk" extension is fixed
        if self.tolerate_errors:
            self._error_count += 1
            logger.error("Schema error: %s", str(exception))
        else:
            raise exception

    def _warning(self, message: str, *args, **kwargs) -> None:
        self._warning_count += 1
        logger.warning(message, *args, **kwargs)

    def _read_base_schema(self) -> None:
        self._read_version()
        self._categories = read_json_object_file(self.schema_path / "categories.json")
        self._dictionary = read_json_object_file(self.schema_path / "dictionary.json")
        self._classes = read_structured_items(self.schema_path, "events")
        self._objects = read_structured_items(self.schema_path, "objects")
        self._profiles = self._read_and_enrich_profiles()
        self._resolve_includes()

    def _read_version(self) -> None:
        version_path = self.schema_path / "version.json"
        try:
            obj = read_json_object_file(version_path)
            self._version = obj["version"]
        except FileNotFoundError as e:
            raise SchemaException(
                f"Schema version file does not exist (is this a schema directory?): {version_path}") from e
        except KeyError as e:
            raise SchemaException(f'The "version" key is missing in the schema version file: {version_path}') from e

    def _read_and_merge_extensions(self) -> JObject:
        extensions: list[Extension] = self._read_extensions()
        self._resolve_extension_includes(extensions)

        for extension in extensions:
            self._fix_extension_profile_uses(extension)

        self._merge_categories_from_extensions(extensions)
        self._merge_classes_from_extensions(extensions)
        self._merge_objects_from_extensions(extensions)
        self._merge_dictionary_from_extensions(extensions)
        self._merge_profiles_from_extensions(extensions)

        self._consolidate_extension_patches(extensions)

        extension_dict: JObject = {}
        for extension in extensions:
            extension_dict[extension.name] = {
                "uid": extension.uid,
                "name": extension.name,
                "platform_extension?": extension.is_platform_extension,
                "caption": extension.caption,
                "description": extension.description,
                "version": extension.version,
            }
        return extension_dict

    def _read_extensions(self) -> list[Extension]:
        extensions: list[Extension] = []
        if not self.ignore_platform_extensions:
            self._read_extensions_in_path(extensions, self.schema_path / "extensions", is_platform_extension=True)
        if self.extensions_paths:
            for extensions_path in self.extensions_paths:
                self._read_extensions_in_path(extensions, extensions_path, is_platform_extension=False)

        self._enrich_extension_items(extensions)
        return extensions

    def _read_extensions_in_path(
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
        info = read_json_object_file(extension_info_path)

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
            categories = read_json_object_file(categories_path)
        else:
            categories = {}

        classes, class_patches = read_patchable_structured_items(base_path, "events")
        objects, object_patches = read_patchable_structured_items(base_path, "objects")

        dictionary_path = base_path / "dictionary.json"
        if dictionary_path.is_file():
            dictionary = read_json_object_file(base_path / "dictionary.json")
        else:
            dictionary = {}

        profiles = self._read_and_enrich_extension_profiles(base_path)

        if is_platform_extension and "version" not in info:
            # Fall back to overall schema version for platform extensions that do not specify their own version
            version = self._version
        elif "version" in info:
            version = info["version"]
        else:
            raise SchemaException(f'Extension extension.json file is missing "version": {extension_info_path}')

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

            for dictionary_type in extension.dictionary.setdefault("types", {}).setdefault("attributes", {}).values():
                dictionary_type["extension"] = extension.name
                dictionary_type["extension_id"] = extension.uid

            for profile in extension.profiles.values():
                profile["extension"] = extension.name
                profile["extension_id"] = extension.uid
                # We do not want to add extension and extension_id profiles for two reasons.
                #   1. Some attributes will be defined in base schema and so this would be wrong.
                #   2. The dictionary attribute information is merged with class and object attributes, so the
                #      attributes actually from the extension will be properly annotated

    def _read_and_enrich_profiles(self) -> JObject:
        return read_structured_items(self.schema_path, "profiles", self._enrich_profile)

    def _read_and_enrich_extension_profiles(self, base_path: Path) -> JObject:
        return read_structured_items(base_path, "profiles", self._enrich_profile)

    def _enrich_profile(self, path: Path, profile: JObject) -> None:
        attributes = profile.setdefault("attributes", {})
        profile_name = profile.get("name")
        annotations = profile.get("annotations")
        for attribute_name, attribute in attributes.items():
            attribute["profile"] = profile_name
            if annotations:
                self._add_attribute_annotations(annotations, attribute)
        self._include_cache[path] = profile

    def _fix_extension_profile_uses(self, extension: Extension) -> None:
        self._fix_extension_profile_uses_in_items(extension, extension.classes, "class")
        self._fix_extension_profile_uses_in_items(extension, extension.class_patches, "class patch")
        self._fix_extension_profile_uses_in_items(extension, extension.objects, "object")
        self._fix_extension_profile_uses_in_items(extension, extension.object_patches, "object patch")

    def _fix_extension_profile_uses_in_items(self, extension: Extension, items: JObject, kind: str) -> None:
        # Structured items can be classes, objects, class patches, or object patches
        for item_name, item in items.items():
            item_context = f'Extension "{extension.name}" {kind} "{item_name}"'
            profiles_names = item.get("profiles")
            if profiles_names:
                profiles_context = f'{item_context} "profiles"'
                is_any_fixed = False
                new_profile_names = []
                for profile_name in profiles_names:
                    is_fixed, fixed_name = self._fix_extension_profile(extension, profile_name, profiles_context)
                    if is_fixed:
                        is_any_fixed = True
                        new_profile_names.append(fixed_name)
                    else:
                        new_profile_names.append(profile_name)
                if is_any_fixed:
                    item["profiles"] = new_profile_names

            for attribute_name, attribute in item.setdefault("attributes", {}).items():
                profile_name = attribute.get("profile")
                if profile_name:
                    attribute_context = f'{item_context} attribute "{attribute_name}"'
                    is_fixed, fixed_name = self._fix_extension_profile(extension, profile_name, attribute_context)
                    if is_fixed:
                        attribute["profile"] = fixed_name

    def _fix_extension_profile(
        self, extension: Extension, profile_name: Optional[str], context: str
    ) -> tuple[bool, Optional[str]]:
        """
        Validates a profile reference used in an extension.
        Raises a SchemaException if validation fails.
        Returns False, None if profile_name is good, and True, str if the profile name should be changed.
        """
        if profile_name:
            # A "profile" can be set to null, meaning the attribute is not affected by any profile (always active)
            if "/" in profile_name:
                split = profile_name.split("/")
                extension_name = split[0]
                if extension_name != extension.name:
                    raise SchemaException(f'{context} references profile "{profile_name}" that is scoped to a'
                                          f' different extension: "{extension_name}"')
                unscoped_profile_name = split[1]
                if unscoped_profile_name in extension.profiles:
                    logger.debug('%s uses scoped profile "%s"', context, profile_name)
                else:
                    raise SchemaException(f'{context} references profile "{profile_name}" that is undefined in this'
                                          f' extension and is not a platform extension')
            else:
                if profile_name in extension.profiles:
                    # This profile is defined, but should be scoped
                    scoped_profile_name = f'{extension.name}/{profile_name}'
                    self._warning('%s references unscoped profile "%s"; changing to "%s"',
                                  context, profile_name, scoped_profile_name)
                    return True, scoped_profile_name
                elif profile_name in self._profiles:
                    # this is fine
                    logger.info('%s uses base schema profile "%s"', context, profile_name)
                else:
                    raise SchemaException(f'{context} references profile "{profile_name}" that is undefined in this'
                                          f' extension and the base schema; note that references to extension profiles'
                                          f' should be scoped, e.g., "{extension.name}/{profile_name}"')
        return False, None

    @staticmethod
    def _add_attribute_annotations(annotations: JObject, attribute: JObject) -> None:
        for key, value in annotations.items():
            # Only add annotation mappings that do no exist already in annotation
            if key not in attribute:
                attribute[key] = value

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

        # TODO: Enable via flag or carefully determine if include is overwriting anything,
        #       perhaps with a new overwrite flag to utils.deep_merge.
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
        for attribute_name, attribute in item_attributes.items():
            if isinstance(attribute, dict) and "$include" in attribute:
                sub_context = f"{context} attributes.{attribute_name}.$include"
                # Get $include value and remove it from attribute
                include_value = attribute.pop("$include")
                if isinstance(include_value, str):
                    include_path = path_resolver(include_value)
                    self._merge_attribute_detail_include(
                        item_attributes, attribute_name, attribute, sub_context, include_path)
                else:
                    raise TypeError(f"Illegal {sub_context} value type: expected string,"
                                    f" but got {json_type_from_value(include_value)}")

    def _merge_attributes_include(self, item: JObject, context: str, include_path: Path) -> None:
        include_item = self._get_include_contents(context, include_path)

        # Include file content should always have "attributes", but we will be defensive.
        if "attributes" not in include_item:
            self._warning("Include file suspiciously has no attributes: %s", include_path)
            return  # Nothing to merge. This should never happen (because it does nothing), but is possible.

        # Create merged attributes by merging item's attributes on top of included attributes
        # resulting in merge with base of included attributes, overridden by item's.

        attributes = deepcopy(include_item["attributes"])

        # But first add in annotations, if any
        if "annotations" in include_item:
            annotations = include_item["annotations"]
            for attribute in attributes.values():
                self._add_attribute_annotations(annotations, attribute)

        # item["attributes"] should exist at this point, so no need to double-check
        # Merge item's attributes on top of the copy of the include attribute, preferring item's data
        SchemaCompiler._merge_attributes(attributes, item["attributes"], context)

        # replace item "attributes" with merged / resolved include attributes
        item["attributes"] = attributes

    def _merge_attribute_detail_include(
        self,
        attributes: JObject,
        attribute_name: str,
        attribute: JObject,
        context: str,
        include_path: Path
    ) -> None:
        include_attribute = self._get_include_contents(context, include_path)

        # Create merged attribute detail for attributes.{attribute_name} by merging item attribute's details
        # on top of included attribute details resulting in merge with base of included details overridden by item's.

        new_attribute = deepcopy(include_attribute)

        # Merge original attribute detail on top of the copy of the included attribute_detail, preferring the original
        deep_merge(new_attribute, attribute)

        # replace existing attribute detail with the new merged detail
        attributes[attribute_name] = new_attribute

    def _get_include_contents(self, context: str, include_path: Path) -> JObject:
        if include_path in self._include_cache:
            return self._include_cache[include_path]

        try:
            include_item = read_json_object_file(include_path)
            self._include_cache[include_path] = include_item
            return include_item
        except FileNotFoundError as e:
            raise SchemaException(f"{context} file does not exist: {include_path}") from e

    def _merge_categories_from_extensions(self, extensions: list[Extension]) -> None:
        categories_attributes = self._categories.setdefault("attributes", {})
        for extension in extensions:
            ext_categories_attributes = extension.categories.setdefault("attributes", {})
            deep_merge(categories_attributes, ext_categories_attributes)

    def _merge_classes_from_extensions(self, extensions: list[Extension]) -> None:
        for extension in extensions:
            if extension.classes:
                self._merge_extension_items(extension.name, extension.classes, self._classes, "class")

    def _merge_objects_from_extensions(self, extensions: list[Extension]) -> None:
        for extension in extensions:
            if extension.objects:
                self._merge_extension_items(extension.name, extension.objects, self._objects, "object")

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

    def _merge_profiles_from_extensions(self, extensions: list[Extension]) -> None:
        # TODO: Should extension profiles be extension scoped?
        #       No other extension items are scoped, at least not effectively.
        #       This answer affects concrete event.
        #       This question needs to be asked of the community, as this could break existing usage.
        #       Final answer might be allowing either form in concrete events.
        for extension in extensions:
            if extension.profiles:
                self._merge_extension_items(extension.name, extension.profiles, self._profiles, "profile")
                # Also merge with extension scoped profiles dictionary
                for profile_name, profile in extension.profiles.items():
                    # TODO
                    if "/" in profile_name:
                        raise SchemaException(
                            f'Unexpected scoped profile in "{extension.name}" profile "{profile_name}"')
                    scoped_name = f'{extension.name}/{profile_name}'
                    if scoped_name in self._extension_scoped_profiles:
                        other_profile = self._extension_scoped_profiles[scoped_name]
                        raise SchemaException(
                            f'Collision: extension "{extension.name}" profile with extension scoped name'
                            f' "{scoped_name}" collides'
                            f' with extension "{other_profile.get("extension", "")}" profile'
                            f' with caption "{other_profile.get("caption", "")}"')
                    else:
                        self._extension_scoped_profiles[scoped_name] = profile

    @staticmethod
    def _merge_extension_items(extension_name: str, extension_items: JObject, items: JObject, kind: str) -> None:
        for ext_item_name, ext_item in extension_items.items():
            if ext_item_name in items:
                item = items[ext_item_name]
                if "extension" in item:
                    raise SchemaException(f'Collision: extension "{extension_name}" {kind} with name "{ext_item_name}"'
                                          f' collides with extension "{item["extension"]}" {kind}'
                                          f' with caption "{item.get("caption", "")}"')
                else:
                    raise SchemaException(f'Collision: extension "{extension_name}" {kind} with name "{ext_item_name}"'
                                          f' collides with base schema {kind} with caption "{item.get("caption", "")}"')
            items[ext_item_name] = ext_item

    def _consolidate_extension_patches(self, extensions: list[Extension]) -> None:
        for extension in extensions:
            for patch_name, patch in extension.class_patches.items():
                patches = self._class_patches.setdefault(patch_name, [])
                patches.append(patch)
            for patch_name, patch in extension.object_patches.items():
                patches = self._object_patches.setdefault(patch_name, [])
                patches.append(patch)

    def _enrich_dictionary_object_types(self) -> None:
        """Converts dictionary types not defined in dictionary's types to object types."""
        types = self._dictionary.setdefault("types", {})
        types_attributes = types.setdefault("attributes", {})
        for attribute_name, attribute in self._dictionary.setdefault("attributes", {}).items():
            attribute_type = attribute.get("type")
            if attribute_type not in types_attributes:
                attribute["type"] = "object_t"
                attribute["object_type"] = attribute_type
                if attribute_type in self._objects:
                    attribute["object_name"] = self._objects[attribute_type].get("caption")
                else:
                    raise SchemaException(f'Dictionary attribute "{attribute_name}"'
                                          f' uses undefined object "{attribute_type}"')

    def _process_classes(self) -> None:
        # Extracting observables is easier to do before resolving (flattening) "extends" inheritance since afterward
        # the observable type_id enumerations will be propagated to all children of event classes.
        self._observables_from_classes()

        if self.include_browser_data:
            self._add_source_to_item_attributes(self._classes, "class")
            self._add_source_to_patch_item_attributes(self._class_patches, "class")
        self._resolve_patches(self._classes, self._class_patches, "class")
        self._resolve_extends(self._classes, "class")

        if self.include_browser_data:
            # Save informational complete class hierarchy (for schema browser)
            for cls_name, cls in self._classes.items():
                cls_slice = {}
                for k in ["name", "caption", "extends", "extension"]:
                    if k in cls:
                        cls_slice[k] = cls[k]
                # TODO: Change "is_hidden" to "hidden?" to be consistent with "deprecated?".
                #       The uses of "is_hidden" will need to be changed in the schema browser as well.
                cls_slice["is_hidden"] = is_hidden_class(cls_name, cls)
                self._all_classes[cls_name] = cls_slice

        # Remove hidden classes
        self._classes = {name: cls for name, cls in self._classes.items() if not is_hidden_class(name, cls)}

        self._enrich_classes()

    def _enrich_classes(self) -> None:
        # enrich classes
        for cls_name, cls in self._classes.items():
            # update class uid
            category_key = cls.get("category")
            category = self._categories.setdefault("attributes", {}).get(category_key)
            if category:
                cls["category_name"] = category.get("caption")
                category_uid = category.get("uid", 0)
            else:
                category_uid = 0

            if "extension_id" in cls:
                scoped_category_uid = extension_scoped_category_uid(cls["extension_id"], category_uid)
                cls_uid = category_scoped_class_uid(scoped_category_uid, cls.get("uid", 0))
            else:
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
                raise SchemaException(f'Class "{cls_name}" has invalid "activity_id" definition: "enum" not defined')
            type_uid_enum[str(class_uid_scoped_type_uid(cls_uid, 0))] = {
                "caption": f"{cls_caption}: Unknown",
            }
            type_uid_attribute["enum"] = type_uid_enum

            if self.include_browser_data:
                type_uid_attribute["_source"] = cls_name

            # add class_uid and class_name attributes
            cls_uid_attribute = cls_attributes.setdefault("class_uid", {})
            cls_name_attribute = cls_attributes.setdefault("class_name", {})
            cls_uid_key = str(cls_uid)
            enum = {cls_uid_key: {"caption": cls_caption, "description": cls.get("description", "")}}
            cls_uid_attribute["enum"] = enum

            if self.include_browser_data:
                cls_uid_attribute["_source"] = cls_name

            cls_name_attribute["description"] = (f"The event class name,"
                                                 f" as defined by class_uid value: <code>{cls_caption}</code>.")

            # add category_uid
            # add/update category_uid and category_name attributes
            if category:
                cls["category_uid"] = category_uid

                category_uid_attribute = cls_attributes.setdefault("category_uid", {})
                # Replace existing enum; leaf classes only include their one category
                # Doing ths prevents including base_event's 0 - Uncategorized enum value.
                enum = {}
                category_uid_key = str(category_uid)
                enum[category_uid_key] = deepcopy(category)
                category_uid_attribute["enum"] = enum

                category_name_attribute = cls_attributes.setdefault("category_name", {})
                category_name_attribute["description"] = (f"The event category name, as defined by category_uid value:"
                                                          f" <code>{category.get("caption", "")}</code>.")
            else:
                if category_key == "other":
                    logger.info('Class "%s" uses special undefined category "other"', cls_name)
                    cls["category_uid"] = 0
                elif category_key is None:
                    # TODO: self._warning('Class "%s" has no category', cls_name)
                    raise SchemaException(f'Class "{cls_name}" has no category')
                else:
                    # TODO: self._warning('Class "%s" has undefined category "%s"', cls_name, category_key)
                    raise SchemaException(f'Class "{cls_name}" has undefined category "{category_key}"')

    def _process_objects(self) -> None:
        # Extracting observables is easier to do before resolving (flattening) "extends" inheritance since afterward
        # the observable type_id enumerations will be propagated to all children of objects.
        self._observables_from_objects()

        if self.include_browser_data:
            self._add_source_to_item_attributes(self._objects, "object")
            self._add_source_to_patch_item_attributes(self._object_patches, "object")
        self._resolve_patches(self._objects, self._object_patches, "object")
        self._resolve_extends(self._objects, "object")

        if self.include_browser_data:
            # Save informational complete object hierarchy (for schema browser)
            for obj_name, obj in self._objects.items():
                obj_slice = {}
                for k in ["name", "caption", "extends", "extension"]:
                    if k in obj:
                        obj_slice[k] = obj[k]
                    # TODO: Change "is_hidden" to "hidden?" to be consistent with "deprecated?".
                    #       The uses of "is_hidden" will need to be changed in the schema browser as well.
                    obj_slice["is_hidden"] = is_hidden_object(obj_name)
                self._all_objects[obj_name] = obj_slice

        # Remove hidden objects
        self._objects = {name: obj for name, obj in self._objects.items() if not is_hidden_object(name)}

    def _observables_from_classes(self) -> None:
        """Detect observable collisions and build up information for schema browser."""
        for cls_name, cls in self._classes.items():
            context = "base schema"
            self._validate_class_observables(cls_name, cls, "base schema", is_patch=False)
            self._observables_from_item_attributes(self._classes, cls_name, cls, "Class", context, is_patch=False)
            self._observables_from_item_observables(self._classes, cls_name, cls, "Class", context, is_patch=False)

        for patch_name, patch_list in self._class_patches.items():
            for patch in patch_list:
                context = f'"{patch["extension"]}" extension patch'
                self._validate_class_observables(patch_name, patch, context, is_patch=True)
                self._observables_from_item_attributes(
                    self._classes, patch_name, patch, "Class", context, is_patch=True)
                self._observables_from_item_observables(
                    self._classes, patch_name, patch, "Class", context, is_patch=True)

    @staticmethod
    def _validate_class_observables(cls_name: str, cls: JObject, context: str, is_patch: bool) -> None:
        if "observable" in cls:
            raise SchemaException(
                f'Illegal definition of one or more attributes with "observable" in {context} class'
                f' "{cls_name}". Defining class-level observables is not supported (this would be'
                f' redundant). Instead use the "class_uid" attribute for querying, correlating, and'
                f' reporting.')

        if not is_patch and is_hidden_class(cls_name, cls):
            attributes = cls.setdefault("attributes", {})
            for attribute in attributes.values():
                if "observable" in attribute:
                    raise SchemaException(
                        f'Illegal definition of one or more attributes with "observable" definition in'
                        f' {context} hidden class "{cls_name}". This would cause colliding definitions'
                        f' of the same observable type_id values in all children of this class. Instead,'
                        f' define observables (of any kind) in non-hidden child classes of "{cls_name}".')

            if "observables" in cls:
                raise SchemaException(
                    f'Illegal "observables" definition in {context} hidden class "{cls_name}".'
                    f' This would cause colliding definitions of the same observable type_id values in'
                    f' all children of this class. Instead, define observables (of any kind) in'
                    f' non-hidden child classes of "{cls_name}".')

    def _observables_from_objects(self) -> None:
        """Detect observable collisions and build up information for schema browser."""
        for obj_name, obj in self._objects.items():
            context = "base schema"
            self._validate_object_observables(obj_name, obj, "base schema", is_patch=False)
            self._observables_from_object(obj_name, obj, context)
            self._observables_from_item_attributes(self._objects, obj_name, obj, "Object", context, is_patch=False)
            # Not supported:
            # self._observables_from_item_observables(self._objects, obj_name, obj, "Object", context, is_patch=False)

        for patch_name, patch_list in self._object_patches.items():
            for patch in patch_list:
                context = f'extension "{patch["extension"]}" patch'
                self._validate_object_observables(patch_name, patch, context, is_patch=True)
                self._observables_from_object(patch_name, patch, context)
                self._observables_from_item_attributes(
                    self._objects, patch_name, patch, "Object", context, is_patch=True)
                # Not supported:
                # self._observables_from_item_observables(
                #     self._objects, patch_name, patch, "Object", context, is_patch=True)

    @staticmethod
    def _validate_object_observables(obj_name: str, obj: JObject, context: str, is_patch: bool) -> None:
        if "observables" in obj:
            # Attribute-path observables would be tricky to implement as an machine-driven enrichment.
            # It would require tracking the relative from the point of the object down that tree of an
            # overall OCSF event.
            raise SchemaException(
                f'Illegal "observables" definition in {context} object "{obj_name}".'
                f' Object-specific attribute path observables are not supported.'
                f' Please file an issue if you find this feature necessary.')

        if not is_patch and is_hidden_object(obj_name):
            attributes = obj.setdefault("attributes", {})
            for attribute_detail in attributes.values():
                if "observable" in attribute_detail:
                    raise SchemaException(
                        f'Illegal definition of one or more attributes with "observable" definition in'
                        f' {context} hidden object "{obj_name}". This would cause colliding definitions'
                        f' of the same observable type_id values in all children of this object. Instead,'
                        f' define observables (of any kind) in non-hidden child objects of "{obj_name}".')

            if "observable" in obj:
                raise SchemaException(
                    f'Illegal "observable" definition in {context} hidden object "{obj_name}".'
                    f' This would cause colliding definitions of the same observable type_id values in'
                    f' all children of this object. Instead, define observables (of any kind) in'
                    f' non-hidden child objects of "{obj_name}".')

    def _observables_from_object(self, obj_name: str, obj: JObject, context: str) -> None:
        caption, description = self._find_item_caption_and_description(self._objects, obj_name, obj)
        if "observable" in obj:
            observable_type_id = str(obj["observable"])

            if observable_type_id in self._observable_type_id_dict:
                entry = self._observable_type_id_dict[observable_type_id]
                raise SchemaException(
                    f'Collision of observable type_id {observable_type_id} between'
                    f' {context} "{caption}" object "observable" and'
                    f' {entry["_observable_kind"]} with caption "{entry["caption"]}"')

            entry = self._make_observable_enum_entry(caption, description, "Object")
            self._observable_type_id_dict[observable_type_id] = entry

    def _observables_from_item_attributes(
        self,
        items: JObject,
        item_name: str,
        item: JObject,
        kind: str,  # title-case kind; should be "Class" or "Object"
        context: str,
        is_patch: bool,
    ) -> None:
        if is_patch:
            caption, _ = self._find_parent_item_caption_and_description(items, item_name, item)
        else:
            caption, _ = self._find_item_caption_and_description(items, item_name, item)
        for attribute_name, attribute in item.setdefault("attributes", {}).items():
            if "observable" in attribute:
                observable_type_id = str(attribute["observable"])
                if observable_type_id in self._observable_type_id_dict:
                    entry = self._observable_type_id_dict[observable_type_id]
                    raise SchemaException(
                        f'Collision of observable type_id {observable_type_id} between'
                        f' {context} {kind} "{item_name}" with caption "{caption}" attribute "{attribute_name}" and'
                        f' {entry["_observable_kind"]} with caption "{entry["caption"]}"')

                self._observable_type_id_dict[observable_type_id] = self._make_observable_enum_entry(
                    f"{caption} {kind}: {attribute_name}",
                    f'{kind}-specific attribute "{attribute_name}" for the {caption} {kind}.',
                    f"{kind}-Specific Attribute")

    def _observables_from_item_observables(
        self, items: JObject, item_name: str, item: JObject, kind: str, context: str, is_patch: bool
    ) -> None:
        # kind should be title-case: "Class" or "Object"
        if "observables" in item:
            if is_patch:
                caption, _ = self._find_parent_item_caption_and_description(items, item_name, item)
            else:
                caption, _ = self._find_item_caption_and_description(items, item_name, item)
            for attribute_path, observable_type_id_num in item["observables"].items():
                observable_type_id = str(observable_type_id_num)
                if observable_type_id in self._observable_type_id_dict:
                    entry = self._observable_type_id_dict[observable_type_id]
                    raise SchemaException(
                        f'Collision of observable type_id {observable_type_id} between'
                        f' {context} {kind} "{item_name}" with caption "{caption}" attribute path "{attribute_path}"'
                        f' and {entry["_observable_kind"]} with caption "{entry["caption"]}"')

                self._observable_type_id_dict[observable_type_id] = self._make_observable_enum_entry(
                    f"{caption} {kind}: {attribute_path}",
                    f'{kind}-specific attribute "{attribute_path}" for the {caption} {kind}.',
                    f"{kind}-Specific Attribute")

    @staticmethod
    def _make_observable_enum_entry(caption: str, description: str, observable_kind: str) -> JObject:
        # TODO: Only add "_observable_kind" when self.include_browser_data is True?
        #       This would require removing use of this in collision exceptions.
        return {
            "caption": caption,
            "description": f"Observable by {observable_kind}.<br>{description}",
            "_observable_kind": observable_kind
        }

    @staticmethod
    def _find_item_caption_and_description(items: JObject, item_name: str, item: JObject) -> tuple[str, str]:
        if "caption" in item:
            caption = item["caption"]
            description = item.get("description", caption)
            return caption, description
        return SchemaCompiler._find_parent_item_caption_and_description(items, item_name, item)

    @staticmethod
    def _find_parent_item_caption_and_description(items: JObject, item_name: str, item: JObject) -> tuple[str, str]:
        current_item = item
        while True:
            if "extends" in item:
                parent_name = current_item["extends"]
                if parent_name in items:
                    parent_item = items[parent_name]
                    if "caption" in parent_item:
                        caption = parent_item["caption"]
                        description = parent_item.get("description", caption)
                        return caption, description
                    current_item = parent_item
                else:
                    raise SchemaException(f'Ancestor "{parent_name}" of "{item_name}" is undefined.')
            else:
                break
        return item_name, item_name  # fallback

    @staticmethod
    def _add_source_to_item_attributes(items: JObject, kind: str) -> None:
        for item_name, item in items.items():
            for attribute_name, attribute in item.setdefault("attributes", {}).items():
                try:
                    attribute["_source"] = item_name
                except TypeError as e:
                    if "extension" in item:
                        kind = f'"{item["extension"]}" extension {kind}'
                    raise SchemaException(f'Invalid attribute type in "{attribute_name}" of {kind} "{item_name}":'
                                          f' expected object, but got {json_type_from_value(attribute)}, ') from e

    @staticmethod
    def _add_source_to_patch_item_attributes(patch_dict: PatchDict, kind: str) -> None:
        for patch_name, patches in patch_dict.items():
            for patch in patches:
                for attribute_name, attribute in patch.setdefault("attributes", {}).items():
                    try:
                        attribute["_source"] = patch_name
                        # Because attribute_source done before patching with _resolve_patches, we need to capture the
                        # final "patched" type for use by the UI when displaying the source. Other uses of "_source"
                        # require the original pre-patched source.
                        attribute["_source_patched"] = patch["extends"]
                    except TypeError as e:
                        raise SchemaException(f'Invalid attribute type in "{attribute_name}"'
                                              f' of extension "{patch["extension"]}" {kind} patch "{patch_name}":'
                                              f' expected object, but got {json_type_from_value(attribute)}, ') from e
                    except KeyError as e:
                        raise SchemaException(f'Attribute "extends" missing in "{attribute_name}" of extension'
                                              f' "{patch["extension"]}" {kind} patch "{patch_name}"') from e

    @staticmethod
    def _resolve_patches(items: JObject, patches: PatchDict, kind: str) -> None:
        for patch_name, patch_list in patches.items():
            for patch in patch_list:
                base_name = patch["extends"]  # this will be the same as patch_name
                assert patch_name == base_name, "Patch name should match extends base name"
                context = f'extension "{patch.get("extension", "<unknown>")}" {kind} patch "{patch_name}"'
                logger.info('%s is patching "%s"', context, base_name)
                if base_name not in items:
                    raise SchemaException(f'{context} attempted to patch undefined {kind} "{base_name}"')
                base = items[base_name]
                SchemaCompiler._merge_profiles(base, patch)

                SchemaCompiler._merge_attributes(
                    base.setdefault("attributes", {}), patch.setdefault("attributes", {}), context)

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
    def _merge_attributes(dest_attributes: JObject, source_attributes: JObject, context: str) -> None:
        for source_attribute_name, source_attribute in source_attributes.items():
            if source_attribute_name in dest_attributes:
                dest_attribute = dest_attributes[source_attribute_name]
                SchemaCompiler._merge_attribute_detail(
                    dest_attribute, source_attribute, f'{context} attribute "{source_attribute_name}"')
            else:
                dest_attributes[source_attribute_name] = source_attribute

    @staticmethod
    def _merge_attribute_detail(dest_attribute: JObject, source_attribute: JObject, context: str) -> None:
        for source_key, source_value in source_attribute.items():
            if source_key == "profile":
                if source_value is None:  # special meaning: don't enable via profile
                    # TODO: delete key. Leave for now to help diffs with Elixir export by being consistent with it.
                    pass
                else:
                    if "profile" in dest_attribute and dest_attribute["profile"] != source_value:
                        # TODO: We cannot currently handle merging attribute details from multiple profiles.
                        #       We need to handle profiles and patching the same attribute from multiple
                        #       extensions and/or profiles. The following (at least) will need to become lists
                        #       everywhere (before any merging): "profile", "extension", and "extension_id".
                        #       During merge we will also need to reconcile "requirement" and possibly other
                        #       attribute details.
                        raise SchemaException(f'{context} attempted merge of "profile" with different non-null value'
                                              f' "{source_value}", existing: {dest_attribute}')

            if (source_key in dest_attribute
                and isinstance(dest_attribute[source_key], dict) and isinstance(source_value, dict)):
                # TODO: Detect collisions, perhaps with overwrite flag in utils.deep_merge
                deep_merge(dest_attribute[source_key], source_value)
            else:
                dest_attribute[source_key] = source_value

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
        for item_name, item in items.items():
            SchemaCompiler._resolve_item_extends(items, item_name, item, kind)

    @staticmethod
    def _resolve_item_extends(items: JObject, item_name: str, item: JObject, kind: str) -> None:
        if item_name is None or item is None:
            return

        parent_name = item.get("extends")
        SchemaCompiler._resolve_item_extends(items, parent_name, items.get(parent_name), kind)
        assert parent_name == item.get("extends"), (f'{kind} "{item_name}" "extends" value should not change after'
                                                    f' recursively processing parent: original value: "{parent_name}",'
                                                    f' current value: "{item.get("extends", "<deleted>")}"')

        if parent_name:
            parent_item = items.get(parent_name)
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
                                logger.debug('Attribute "%s" is None in %s "%s"', k, kind, item_name)
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
                            logger.debug('Not merging null value of key "%s" in %s "%s"', source_key, kind, item_name)
                items[item_name] = new_item
            else:
                raise SchemaException(f'{kind} "{item.get("name", "<unknown>")}"'
                                      f' extends undefined {kind} "{parent_name}"')

    def _enrich_and_validate_dictionary(self) -> None:
        if self.include_browser_data:
            self._add_common_dictionary_attribute_links()
            self._add_class_dictionary_attribute_links()
            self._add_object_dictionary_attribute_links()
        self._enrich_and_validate_dictionary_attribute_types()
        self._add_datetime_sibling_dictionary_attributes()

    def _add_common_dictionary_attribute_links(self) -> None:
        if not self.include_browser_data:
            return
        if "base_event" not in self._classes:
            raise SchemaException('Schema has not defined a "base_event" class')
        base_event = self._classes["base_event"]
        link = self._make_link("common", "base_event", base_event)
        self._add_links_to_dictionary_attributes("class", "base_event", base_event, link)

    def _add_class_dictionary_attribute_links(self) -> None:
        if not self.include_browser_data:
            return
        for cls_name, cls in self._classes.items():
            link = self._make_link("class", cls_name, cls)
            self._add_links_to_dictionary_attributes("class", cls_name, cls, link)

    def _add_object_dictionary_attribute_links(self) -> None:
        if not self.include_browser_data:
            return
        for obj_name, obj in self._objects.items():
            link = self._make_link("object", obj_name, obj)
            self._add_links_to_dictionary_attributes("object", obj_name, obj, link)

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
        if item.get("@deprecated"):
            link["deprecated?"] = True
        return link

    def _add_links_to_dictionary_attributes(self, kind: str, item_name: str, item: JObject, link: JObject) -> None:
        if not self.include_browser_data:
            return
        dictionary_attributes = self._dictionary.setdefault("attributes", {})
        item_attributes = item.setdefault("attributes", {})
        for item_attribute_name, item_attribute in item_attributes.items():
            enriched_link = deepcopy(link)
            # TODO: Are "attribute_keys" used for all types or only object types? (Seems like only object types.)
            #       Once everything is working, try only setting "attribute_keys" for object types.
            enriched_link["attribute_keys"] = [item_attribute_name]
            # TODO: Do we need to do special extension processing from Utils.update_attributes?
            #       It looks like this was a hack to avoid defining extension attributes in its dictionary.
            #       That code is NOT replicated here.
            if item_attribute_name in dictionary_attributes:
                dictionary_attribute = dictionary_attributes[item_attribute_name]
                links = dictionary_attribute.setdefault("_links", [])
                links.append(enriched_link)
            else:
                raise SchemaException(f'{kind} "{item_name}" uses undefined attribute "{item_attribute_name}"')

    def _enrich_and_validate_dictionary_attribute_types(self) -> None:
        dictionary_attributes = self._dictionary.setdefault("attributes", {})
        dictionary_types = self._dictionary.setdefault("types", {}).setdefault("attributes", {})

        for attribute_name, attribute in dictionary_attributes.items():
            if "type" in attribute:
                attribute_type = attribute["type"]
            else:
                raise SchemaException(f'Dictionary attribute'
                                      f' {self._name_with_possible_extension(attribute_name, attribute)}'
                                      f' does not define "type"')

            if attribute_type == "object_t":
                # Object dictionary type
                # Add "object_name" to attribute details based on caption.
                # NOTE: This must be done after resolving patches and extends so caption is resolved.
                # TODO: self._enrich_dictionary_object_types() also sets "object_name", which seems unnecessary and
                #       too early anyway.
                object_type = attribute["object_type"]
                if object_type in self._objects:
                    obj = self._objects[object_type]
                    attribute["object_name"] = obj.get("caption", "")
                else:
                    raise SchemaException(
                        f'Undefined object type in dictionary attribute "{attribute_name}": "{object_type}"')
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
                                          f' {self._name_with_possible_extension(attribute_name, attribute)}'
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
        dictionary_types = self._dictionary.setdefault("types", {}).setdefault("attributes", {})
        got_datetime_t = "datetime_t" in dictionary_types
        got_timestamp_t = "timestamp_t" in dictionary_types
        if got_datetime_profile and got_datetime_t and got_timestamp_t:
            logger.info('Datetime siblings of attributes with the "timestamp_t" type will be added because the'
                        ' following are defined in the schema: the "datetime" profile,'
                        ' the "datetime_t" dictionary type, and the "timestamp_t" dictionary type.')
            # Add datetime siblings
            dictionary_attributes = self._dictionary.setdefault("attributes", {})
            # We can't add dictionary_attributes while iterator, so instead add to another dict and then merge
            additions = {}
            for attribute_name, attribute in dictionary_attributes.items():
                if attribute.get("type") == "timestamp_t":
                    sibling = deepcopy(attribute)
                    # TODO: fix up attribute_keys in _links if they are actually used (Elixir codes do NOT fix up)
                    sibling["type"] = "datetime_t"
                    sibling["type_name"] = "Datetime"
                    additions[self._make_datetime_attribute_name(attribute_name)] = sibling
            dictionary_attributes.update(additions)
        elif got_datetime_profile:
            raise SchemaException('Schema defines "datetime" profile but does not define "datetime_t" dictionary type')
        elif got_datetime_t:
            raise SchemaException('Schema defines "datetime_t" dictionary type but does not define "datetime" profile')
        else:
            logger.info('This schema does not define the "datetime" profile or the "datetime_t" dictionary type,'
                        ' so datetime siblings of timestamp_t attributes will not be added.')

    @staticmethod
    def _make_datetime_attribute_name(timestamp_name: str) -> str:
        return f'{timestamp_name}_dt'

    def _observables_from_dictionary(self) -> None:
        types = self._dictionary.setdefault("types", {}).setdefault("attributes", {})
        attributes = self._dictionary.setdefault("attributes", {})
        self._observables_from_dictionary_items(types, "Dictionary Type")
        self._observables_from_dictionary_items(attributes, "Dictionary Attribute")

    def _observables_from_dictionary_items(self, items: JObject, kind: str) -> None:
        for key, detail in items.items():
            if "observable" in detail:
                observable_type_id = str(detail["observable"])
                if observable_type_id in self._observable_type_id_dict:
                    entry = self._observable_type_id_dict[observable_type_id]
                    raise SchemaException(f'Collision of observable type_id {observable_type_id} between {kind}'
                                          f' "{key}" {kind} with caption "{detail.get("caption")}"'
                                          f' and {entry["kind"]} with caption "{entry["caption"]}"')
                else:
                    entry = self._make_observable_enum_entry(
                        detail.get("caption", ""), detail.get("description", ""), kind)
                    self._observable_type_id_dict[observable_type_id] = entry

    def _enrich_profiles_attributes_from_dictionary(self) -> None:
        dictionary_attributes = self._dictionary.setdefault("attributes", {})
        for profile_name, profile in self._profiles.items():
            for profile_attribute_name, profile_attribute in profile.setdefault("attributes", {}).items():
                if profile_attribute_name in dictionary_attributes:
                    dictionary_attribute = dictionary_attributes[profile_attribute_name]
                    for key in ["caption", "description", "is_array", "enum", "type", "type_name",
                                "object_name", "object_type", "observable", "source", "references", "sibling",
                                "@deprecated"]:
                        value = dictionary_attribute.get(key)
                        if value is not None and key not in profile_attribute:
                            profile_attribute[key] = value
                    # TODO: This "profile" key is added in self._enrich_profiles then removed here. Why bother?
                    del profile_attribute["profile"]
                else:
                    # TODO: This is an actual error that the Elixir compile hid via a weird hack.
                    #       The "splunk" extension has several instances of this problem.
                    #       These errors must either be fixed, or this compile needs to replicate the hack from Elixir.
                    if "extension" in profile:
                        source = f'extension "{profile["extension"]}" profile "{profile_name}"'
                    else:
                        source = f'profile "{profile_name}"'
                    self._tolerable_error(SchemaException(f'Attribute "{profile_attribute_name}" in {source}'
                                                          f' is not a defined dictionary attribute'
                                                          f' (found when enriching profile attributes)'))

    def _validate_object_profiles_and_add_links(self) -> None:
        self._validate_profiles_and_add_links("object", self._objects)

    def _validate_class_profiles_and_add_links(self) -> None:
        self._validate_profiles_and_add_links("class", self._classes)

    def _validate_profiles_and_add_links(self, group: str, items: JObject) -> None:
        # TODO: check attributes
        # TODO: check profile attributes (but don't add links for profiles)
        for item_name, item in items.items():
            if "profiles" in item:
                for profile_name in item["profiles"]:
                    if profile_name in self._profiles:
                        profile = self._profiles[profile_name]
                        if "extension" in profile:
                            self._warning('Profile "%s" from extension "%s" used without scope in %s "%s"'
                                          ' (got "%s", expected "%s/%s")',
                                          profile_name, profile["extension"], group, item_name,
                                          profile_name, profile["extension"], profile_name)
                    elif profile_name in self._extension_scoped_profiles:
                        profile = self._extension_scoped_profiles[profile_name]
                    else:
                        if "extension" in item:
                            description = f'extension "{item["extension"]}" {group} "{item_name}"'
                        else:
                            description = f'{group} "{item_name}"'
                        raise SchemaException(f'{description} uses undefined profile "{profile_name}"')

                    if self.include_browser_data:
                        link = self._make_link(group, item_name, item)
                        links = profile.get("_links", [])
                        links.append(link)

    def _add_object_links(self) -> None:
        if not self.include_browser_data:
            return

        dictionary_attributes = self._dictionary.setdefault("attributes", {})
        for obj_name, obj in self._objects.items():
            links = []
            for attribute_name, attribute in dictionary_attributes.items():
                if attribute.get("object_type") == obj_name and "_links" in attribute:
                    links.extend(deepcopy(attribute["_links"]))

            # Group by group and type and merge attribute_keys
            grouped_links = {}
            for link in links:
                group_key = f"{link["group"]}:{link["type"]}"
                if group_key in grouped_links:
                    group = grouped_links[group_key]
                    group_attribute_keys = group["attribute_keys"]
                    for key in link["attribute_keys"]:
                        if key not in group_attribute_keys:
                            group_attribute_keys.append(key)
                else:
                    grouped_links[group_key] = link

            # final result is the values of the grouped_link dict
            obj["_links"] = list(grouped_links.values())

    def _update_observable_enum(self) -> None:
        if "observable" in self._objects:
            observable = self._objects["observable"]
            dest_enum_dict = observable.setdefault("attributes", {}).setdefault("type_id", {}).setdefault("enum", {})
            for source_type_id_key, source_enum_detail in self._observable_type_id_dict.items():
                if source_type_id_key in dest_enum_dict:
                    raise SchemaException(f'Collision of observable type_id {source_type_id_key} between'
                                          f' "{source_enum_detail.get("caption", "")}"'
                                          f' and "{dest_enum_dict[source_type_id_key].get("caption", "")}"'
                                          f' (detected during merge)')
                else:
                    dest_enum_dict[source_type_id_key] = source_enum_detail

    def _consolidate_object_profiles(self) -> None:
        """Update object profiles to includes profiles from all attributes with object types."""
        self._consolidate_profiles("object", self._objects)

    def _consolidate_class_profiles(self) -> None:
        """Update class profiles to includes profiles from all attributes with object types."""
        self._consolidate_profiles("class", self._classes)

    # TODO: Flat implementation based on _links. (This code changes to always create _links.)
    #       NOTE: This implementation does NOT work for all cases. Elixir code has (had) the same issue.
    # def _consolidate_profiles(self, group: str, items: JObject) -> None:
    #     for obj in self._objects.values():
    #         if "profiles" in obj and "_links" in obj:
    #             for link in obj["_links"]:
    #                 if link["group"] == group:
    #                     item = items[link["type"]]
    #                     self._merge_profiles(item, obj)

    # TODO: Recursive implementation
    def _consolidate_profiles(self, group: str, items: JObject) -> None:
        for item_name, item in items.items():
            profiles_dict: dict[str, Optional[list[str]]] = {}
            try:
                if group == "class":
                    # The recursive step is for objects. For classes, we need to do the first step here.
                    if "profiles" in item:
                        # Need to tweak ke for class so it does not collide with object names
                        profiles_dict[f'class:{item_name}'] = item["profiles"]

                    for attribute_name, attribute in item.setdefault("attributes", {}).items():
                        # This happens before enriching attributes with dictionary information,
                        # so we need to do extra work to determine actual type
                        object_type = self._find_object_type(attribute_name, attribute)
                        if object_type:
                            self._gather_profiles(object_type, profiles_dict)

                else:
                    # for object, we can jump straight to _gather_profiles
                    self._gather_profiles(item_name, profiles_dict)
            except SchemaException as e:
                raise SchemaException(f'Consolidating profiles of {group} "{item_name}" failed: {e}') from e

            all_profiles: set[str] = set()
            for profile_list in profiles_dict.values():
                if profile_list:
                    all_profiles.update(profile_list)

            if all_profiles:
                sorted_profiles = sorted(all_profiles)
                if logger.isEnabledFor(logging.DEBUG):
                    items_with_profiles = []
                    for n, l in profiles_dict.items():
                        if l:
                            items_with_profiles.append(n)
                    items_with_profiles.sort()
                    original_profiles = item.get("profiles")
                    if sorted_profiles == original_profiles:
                        logger.debug('Consolidated profiles of %s "%s": profiles unchanged.', group, item_name)
                    else:
                        logger.debug(f'Consolidated profiles of %s "%s".'
                                     f'\n    Original profiles: %s.'
                                     f'\n    Consolidated from: %s.'
                                     f'\n    Consolidated profiles: %s.',
                                     group, item_name, original_profiles, items_with_profiles, sorted_profiles)
                item["profiles"] = sorted_profiles
            else:
                logger.debug('Consolidated profiles of %s "%s": no profiles.', group, item_name)

    def _gather_profiles(self, obj_name: str, profiles_dict: dict[str, list[str]]) -> None:
        """Gather profiles from obj_name object (if any) and its attributes that are object types, recursively."""
        if obj_name in profiles_dict:
            return  # obj_name already processed

        if obj_name not in self._objects:
            raise SchemaException(f'object "{obj_name}" is not defined')
        obj = self._objects[obj_name]

        # We specifically want actual and None values since profiles_dict is doing both gathering profiles
        # and marking objects that have been processed.
        profiles_dict[obj_name] = obj.get("profiles")

        for attribute_name, attribute in obj.setdefault("attributes", {}).items():
            object_type = self._find_object_type(attribute_name, attribute)
            if object_type:
                self._gather_profiles(object_type, profiles_dict)

    def _find_object_type(self, attribute_name, attribute: JObject) -> Optional[str]:
        """
        Determine object type of unprocessed object or class attribute
        (an attribute not yet merged with dictionary attribute information).
        Returns None is if attribute is not an object type (it's a dictionary type).
        """
        # We haven't merged dictionary attributes on to class and object attributes yet,
        # so "object_type" should not yet be present.
        # The logic in this method depends on the unprocessed "type",
        # and will not work if "type" has already been changed to "object_t" and "object_type" added for object types.
        assert "object_type" not in attribute, \
            f'Object attribute "{attribute_name}" unexpectedly already has "object_type"'

        if "type" in attribute:
            # The class or object defines the type. This occurs sometimes when type is refined in a specific case.
            # These types should only ever be dictionary types
            assert attribute["type"] in self._dictionary.setdefault("types").setdefault("attributes", {}), \
                f'Object attribute "{attribute_name}" should be a defined dictionary type'
            return None

        dictionary_attributes = self._dictionary.setdefault("attributes", {})
        if attribute_name not in dictionary_attributes:
            raise SchemaException(f'attribute "{attribute_name}" is not a defined dictionary attributes')
        dictionary_attribute = dictionary_attributes[attribute_name]
        if "object_type" in dictionary_attribute:
            return dictionary_attribute["object_type"]
        return None

    def _verify_object_attributes_and_add_datetime(self) -> None:
        self._verify_item_attributes_and_add_datetime(self._objects, "object")

    def _verify_class_attributes_and_add_datetime(self) -> None:
        self._verify_item_attributes_and_add_datetime(self._classes, "class")

    def _verify_item_attributes_and_add_datetime(self, items: JObject, kind: str) -> None:
        dictionary_attributes = self._dictionary.setdefault("attributes", {})

        got_datetime_profile = "datetime" in self._profiles
        got_datetime_t = "datetime_t" in self._dictionary.setdefault("types", {}).setdefault("attributes", {})
        add_datetime = got_datetime_profile and got_datetime_t

        for item_name, item in items.items():
            dt_attribute_additions: JObject = {}  # we cannot add attributes while iterating attributes
            attributes = item.setdefault("attributes", {})
            for attribute_name, attribute in attributes.items():
                dictionary_attribute = dictionary_attributes.get(attribute_name, {})
                if "description" not in attribute:
                    # No description. Make sure fallback dictionary description isn't meant to be overridden.
                    dictionary_description = dictionary_attribute.get("description", "")
                    if "See specific usage" in dictionary_description:
                        self._warning('Please update the "description" of %s "%s" attribute "%s": "%s"',
                                      kind, item_name, attribute_name, dictionary_description)

                if add_datetime:
                    if "type" in attribute:
                        attribute_type = attribute["type"]
                    else:
                        attribute_type = dictionary_attribute.get("type")
                    if attribute_type == "timestamp_t":
                        dt_attribute = deepcopy(attribute)
                        dt_attribute["profile"] = "datetime"
                        dt_attribute["requirement"] = "optional"
                        dt_attribute_additions[self._make_datetime_attribute_name(attribute_name)] = dt_attribute

            if dt_attribute_additions:
                attributes.update(dt_attribute_additions)
                profiles = item.setdefault("profiles", [])
                if "datetime" not in profiles:
                    profiles.append("datetime")
                    profiles.sort()  # keep profiles sorted

    def _ensure_attributes_have_requirement(self) -> None:
        # Track attributes in profiles, classes, and objects that incorrectly do _not_ have a "requirement"
        missing_requirements: list[str] = []
        self._ensure_item_attributes_have_requirement(self._profiles, "profile", missing_requirements)
        self._ensure_item_attributes_have_requirement(self._classes, "class", missing_requirements)
        self._ensure_item_attributes_have_requirement(self._objects, "object", missing_requirements)
        if missing_requirements:
            missing_requirements.sort()
            self._warning('%d attribute(s) do not have a "requirement" field, a value of "optional" will be used: %s',
                          len(missing_requirements), ", ".join(missing_requirements))

    @staticmethod
    def _ensure_item_attributes_have_requirement(items: JObject, kind: str, missing_requirements: list[str]) -> None:
        for item_name, item in items.items():
            for attribute_name, attribute in item.setdefault("attributes", {}).items():
                if "requirement" not in attribute:
                    attribute["requirement"] = "optional"
                    if "extension" in item:
                        actual_kind = f'extension "{item["extension"]}" {kind}'
                    else:
                        actual_kind = kind
                    missing_requirements.append(f'{actual_kind} "{item_name}" attribute "{attribute_name}"')

    def _finish_attributes(self):
        self._finish_item_attributes(self._classes, "class")
        self._finish_item_attributes(self._objects, "object")
        # TODO: Is this redundant with _enrich_profiles_attributes_from_dictionary?
        #       Perhaps we can remove _enrich_profiles_attributes_from_dictionary.
        self._finish_item_attributes(self._profiles, "profile")

    def _finish_item_attributes(self, items: JObject, kind: str) -> None:
        dictionary_attributes = self._dictionary.setdefault("attributes", {})
        for item_name, item in items.items():
            attributes = item.setdefault("attributes", {})
            new_attributes = {}
            for attribute_name, attribute in attributes.items():
                if attribute_name in dictionary_attributes:
                    new_attribute = deepcopy(dictionary_attributes[attribute_name])
                    deep_merge(new_attribute, attribute)
                    new_attributes[attribute_name] = new_attribute
                else:
                    # TODO: This is an identical error as found in _enrich_profiles_attributes_from_dictionary
                    #       and occurs with the current "splunk" extension.
                    if "extension" in item:
                        actual_kind = f'extension "{item["extension"]}" {kind}'
                    else:
                        actual_kind = kind
                    self._tolerable_error(SchemaException(f'Attribute "{attribute_name}" in {actual_kind} "{item_name}"'
                                                          f' is not a defined dictionary attribute'
                                                          f' (found when finishing attributes)'))
            item["attributes"] = new_attributes
            if self.include_browser_data:
                self._add_sibling_of_to_attributes(new_attributes)

    @staticmethod
    def _add_sibling_of_to_attributes(attributes: JObject) -> None:
        # This must be done after finalizing attributes so full enum attribute details are present.
        # Specifically the enum attribute "sibling" key.

        sibling_of_dict: dict[str, str] = {}
        # Enum attributes point to their enum sibling through the :sibling attribute,
        # however the siblings do _not_ refer back to their related enum attribute, so let's build that.
        # First pass, iterate attributes to find enum attributes and create mapping to their siblings.
        for attribute_name, attribute in attributes.items():
            if "sibling" in attribute:
                # This is an enum attribute
                sibling_of_dict[attribute["sibling"]] = attribute_name

        if not sibling_of_dict:
            # no enum attributes present in attributes, so nothing to do
            return  # skip iterating attributes again uselessly

        # Second pass, look for enum attributes and add "_sibling_of" mapping
        for attribute_name, attribute in attributes.items():
            if attribute_name in sibling_of_dict:
                # This is an enum sibling. Add "_sibling_of" pointing back to its related enum attribute.
                attribute["_sibling_of"] = sibling_of_dict[attribute_name]

    def _delete_browser_data(self) -> None:
        deleted_keys: set[str] = set()
        self._clean(self._classes, deleted_keys)
        self._clean(self._objects, deleted_keys)
        self._clean(self._dictionary, deleted_keys)
        self._clean(self._profiles, deleted_keys)
        logger.info("Deleted keys only needed by schema browser: %s", ", ".join(sorted(deleted_keys)))

    @staticmethod
    def _clean(obj: JObject, deleted_keys: set[str]) -> None:
        keys_to_delete: list[str] = []
        for key, value in obj.items():
            if key.startswith("_"):
                keys_to_delete.append(key)
            elif isinstance(value, dict):
                # This is a dict mapped to a key we are keeping
                SchemaCompiler._clean(value, deleted_keys)
        for key in keys_to_delete:
            del obj[key]
            deleted_keys.add(key)
