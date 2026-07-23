import importlib
import pkgutil

from agents.techniques.base import Technique
from agents.techniques.registry import get_technique, list_techniques, register

DEFAULT_TECHNIQUE_ID = "sql_injection"

# Auto-import every sibling module so each technique's module-level register()
# call fires. Adding agents/techniques/<new_technique>.py is the only step
# needed to plug in a new technique - nothing here needs editing.
for _mod in pkgutil.iter_modules(__path__):
    if _mod.name not in ("base", "registry"):
        importlib.import_module(f"{__name__}.{_mod.name}")
del _mod

__all__ = ["Technique", "get_technique", "list_techniques", "register", "DEFAULT_TECHNIQUE_ID"]
