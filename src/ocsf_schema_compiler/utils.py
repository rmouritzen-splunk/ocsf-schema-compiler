from typing import Any

def json_type_from_value(value: Any) -> str:
    """Return JSON type for a Python value. See https://json.org."""
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