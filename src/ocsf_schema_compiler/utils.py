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


def put_non_none(d: dict, k: Any, v: Any) -> None:
    if v is not None:
        d[k] = v


def extension_scoped_category_uid(extension_uid: int, original_category_uid: int) -> int:
    """Return an extension-specific category UID."""
    assert original_category_uid < 100, \
        f"category_uid {original_category_uid} should be less than 100 (not yet extension UID scoped)"
    return extension_uid * 100 + original_category_uid


def category_scoped_class_uid(category_uid: int, cls_uid: int) -> int:
    """Return a category-specific class UID."""
    assert category_uid < 100, f"category_uid {category_uid} should be less than 100 (not extension UID scoped)"
    assert cls_uid < 1000, f"class UID {cls_uid} should be less than 1000 (not yet category UID scoped)"
    return category_uid * 1000 + cls_uid


def class_uid_scoped_type_uid(cls_uid: int, type_uid: int) -> int:
    """Return a class-specific type UID."""
    assert type_uid < 1000, f"type_uid {type_uid} should be less than 1000 (not class UID scoped)"
    return cls_uid * 1000 + type_uid