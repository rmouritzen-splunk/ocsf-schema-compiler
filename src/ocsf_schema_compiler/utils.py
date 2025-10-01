from typing import Any


def deep_merge(dest: Any, source: Any) -> None:
    """
    In-place merge a source dictionary into a destination dictionary, modifying the destination dictionary.
    Note: this merge does not deep merge dictionaries inside lists.
    """
    if isinstance(dest, dict) and isinstance(source, dict):
        for source_key, source_value in source.items():
            if source_key in dest:
                dest_value = dest[source_key]
                if isinstance(dest_value, dict) and isinstance(source_value, dict):
                    deep_merge(dest_value, source_value)
                else:
                    # This replaces dest[source_key] with source_value
                    dest[source_key] = source_value
            else:
                dest[source_key] = source_value


def extension_category_uid(extension_uid: int, original_category_uid: int) -> int:
    """Return an extension-specific category UID."""
    assert original_category_uid < 100  # TODO: Remove (debugging)
    return extension_uid * 100 + original_category_uid


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
