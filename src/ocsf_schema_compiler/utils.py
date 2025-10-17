from typing import Any

from jsonish import JObject


def deep_merge(dest: dict, source: dict) -> None:
    """
    In-place merge a source dictionary into a destination dictionary, modifying the destination dictionary.
    Note: this merge does not merge lists or deep merge dictionaries inside lists. List values are simply overwritten.
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


def put_non_none(d: dict, k: Any, v: Any) -> None:
    if v is not None:
        d[k] = v


def is_hidden_class(cls_name: str, cls: JObject) -> bool:
    return cls_name != "base_event" and "uid" not in cls


def is_hidden_object(obj_name: str) -> bool:
    return obj_name.startswith("_")


def extension_scoped_category_uid(extension_uid: int, category_uid: int) -> int:
    """Return an extension-specific category UID."""
    assert category_uid < 100, \
        f"category_uid {category_uid} should be less than 100 (not yet extension UID scoped)"
    return extension_uid * 100 + category_uid


def category_scoped_class_uid(category_uid: int, cls_uid: int) -> int:
    """Return a category-specific class UID."""
    assert cls_uid < 1000, f"class UID {cls_uid} should be less than 1000 (not yet category UID scoped)"
    return category_uid * 1000 + cls_uid


def class_uid_scoped_type_uid(cls_uid: int, type_uid: int) -> int:
    """Return a class-specific type UID."""
    assert type_uid < 100, f"type_uid {type_uid} should be less than 1000 (not class UID scoped)"
    return cls_uid * 100 + type_uid


def to_extension_scoped_name(name: str, item: JObject) -> str:
    if "extension" in item:
        return f'{item["extension"]}/{name}'
    return name


def add_extension_scope_to_attribute_object_type(attribute: JObject, objects: JObject) -> None:
    if "object_type" in attribute:
        obj_name = attribute["object_type"]
        if obj_name in objects:
            obj = objects[obj_name]
            if "extension" in obj:
                attribute["object_type"] = f'{obj["extension"]}/{attribute["object_type"]}'


def add_extension_scope_to_items(items: JObject, objects: JObject) -> JObject:
    scoped_items = {}
    for item_name, item in items.items():
        scoped_items[to_extension_scoped_name(item_name, item)] = item
        if "attributes" in item:
            for attribute_name, attribute in item["attributes"].items():
                add_extension_scope_to_attribute_object_type(attribute, objects)
    return scoped_items


def add_extension_scope_to_dictionary(dictionary: dict, objects: JObject) -> None:
    scoped_attributes = {}
    for attribute_name, attribute in dictionary["attributes"].items():
        add_extension_scope_to_attribute_object_type(attribute, objects)
        scoped_attributes[to_extension_scoped_name(attribute_name, attribute)] = attribute
    dictionary["attributes"] = scoped_attributes
