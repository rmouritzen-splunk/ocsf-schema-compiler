import json


def pretty_json_encode(v: object) -> str:
    return json.dumps(v, indent=4, sort_keys=True)
