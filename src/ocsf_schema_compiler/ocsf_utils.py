from ocsf_schema_compiler.exceptions import SchemaException
from ocsf_schema_compiler.jsonish import JObject


def is_hidden_class(cls_name: str, cls: JObject) -> bool:
    return cls_name != "base_event" and "uid" not in cls


def is_hidden_object(obj_name: str) -> bool:
    return obj_name.startswith("_")


def requirement_to_rank(requirement: str | None) -> int:
    if requirement == "required":
        return 3
    if requirement == "recommended":
        return 2
    if requirement == "optional":
        return 1
    if requirement is None:
        return 0
    raise SchemaException(f'Unknown requirement: "{requirement}"')


def rank_to_requirement(rank: int) -> str | None:
    if rank == 3:
        return "required"
    if rank == 2:
        return "recommended"
    if rank == 1:
        return "optional"
    if rank == 0:
        return None
    raise SchemaException(f"Unknown rank: {rank}")
