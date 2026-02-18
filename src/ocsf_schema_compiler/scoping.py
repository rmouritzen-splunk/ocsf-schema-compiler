def extension_scoped_category_uid(extension_uid: int, category_uid: int) -> int:
    """Return an extension-specific category UID for a base schema category."""
    assert category_uid < 100, (
        f"category_uid {category_uid} should be less than 100"
        " (not yet extension UID scoped); is this an extension category?"
    )
    return extension_uid * 100 + category_uid


def category_scoped_class_uid(category_uid: int, cls_uid: int) -> int:
    """Return a category-specific class UID."""
    assert cls_uid < 1000, (
        f"class UID {cls_uid} should be less than 1000 (not yet category UID scoped)"
    )
    return category_uid * 1000 + cls_uid


def class_uid_scoped_type_uid(cls_uid: int, type_uid: int) -> int:
    """Return a class-specific type UID."""
    assert type_uid < 100, (
        f"type_uid {type_uid} should be less than 1000 (not class UID scoped)"
    )
    return cls_uid * 100 + type_uid


def to_extension_scoped_name(extension: str, name: str) -> str:
    """Returns an extension-scoped name."""
    return f"{extension}/{name}"
