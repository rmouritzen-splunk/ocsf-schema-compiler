import json


def pretty_json_encode(v: object) -> str:
    return json.dumps(v, indent=4, sort_keys=True)


def quote_string(s: str | None, none_string: str = "<none>") -> str:
    """
    Returns string s surrounded by quotes if it is a string, or none_string
    without quotes if it is None ("<none>" by default).
    """
    if s:
        return f'"{s}"'
    return none_string


def quote_name_string(s: str | None) -> str:
    return quote_string(s, "<unnamed>")
