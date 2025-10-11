import json
import os
from pathlib import Path
from typing import Callable, Any

from exceptions import SchemaException

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


def json_type_from_value(value: Any) -> str:
    """Return JSON type for a Python value. See https://json.org. This is intended for error messages."""
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "number (int)"
    if isinstance(value, float):
        return "number (float)"
    if isinstance(value, bool):
        if value:
            return "true"
        return "false"
    if value is None:
        return "null"
    return f"non-JSON type: {type(value).__name__}"


def read_json_object_file(path: Path) -> JObject:
    with open(path) as f:
        v = json.load(f)
        if not isinstance(v, dict):
            t = json_type_from_value(v)
            raise TypeError(f"Schema file contains a JSON {t} value, but should contain an object: {path}")
        return v


def read_structured_items(
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
                obj = read_json_object_file(file_path)
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


def read_patchable_structured_items(base_path: Path, kind: str) -> tuple[JObject, JObject]:
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
                obj = read_json_object_file(file_path)
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
                    patch_name = extends  # for clarity
                    if patch_name in patches:
                        existing = patches[patch_name]
                        raise SchemaException(f'Collision of patch name ("extends" key) in extension {kind} file:'
                                              f' "{patch_name}" with caption "{obj.get("caption", "")}", collides with'
                                              f' existing {kind} with caption "{existing.get("caption", "")}",'
                                              f' file: {file_path}')
                    else:
                        patches[patch_name] = obj
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
