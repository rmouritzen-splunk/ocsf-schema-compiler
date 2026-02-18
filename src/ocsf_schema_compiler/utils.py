import json


def pretty_json_encode(v: object) -> str:
    return json.dumps(v, indent=4, sort_keys=True)


def quote_string(s: str | None) -> str:
    """
    Returns string s surrounded by quotes if it is a string, or "<none>" without
    quotes if the s is None.
    """
    if s:
        return f'"{s}"'
    return "<none>"
