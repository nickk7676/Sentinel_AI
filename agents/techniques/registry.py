from agents.techniques.base import Technique

_REGISTRY: dict[str, Technique] = {}


def register(technique: Technique) -> Technique:
    if technique.id in _REGISTRY:
        raise ValueError(f"technique {technique.id!r} already registered")
    _REGISTRY[technique.id] = technique
    return technique


def get_technique(technique_id: str) -> Technique:
    try:
        return _REGISTRY[technique_id]
    except KeyError:
        available = ", ".join(sorted(_REGISTRY)) or "(none registered)"
        raise KeyError(f"Unknown technique {technique_id!r}. Available: {available}") from None


def list_techniques() -> list[Technique]:
    return list(_REGISTRY.values())
