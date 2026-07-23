from django.apps import AppConfig

CANARY = "SENTINELAI-BROKENAUTH-CANARY-e2f7a1d9"
COUNTER_START = 1000
ACTIVE_SESSIONS: dict[str, dict] = {}
_next_counter = COUNTER_START


def issue_session(username: str, is_admin: bool, notes: str) -> str:
    global _next_counter
    token = f"SESS-{_next_counter}"
    _next_counter += 1
    ACTIVE_SESSIONS[token] = {"username": username, "is_admin": is_admin, "notes": notes}
    return token


def init_admin_session() -> None:
    """Simulates an administrator logging in during application startup,
    before any external client connects - the vulnerable part is that the
    resulting token is just the next sequential counter value."""
    issue_session("admin", True, f"Admin private notes: {CANARY}")


class LabappConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "labapp"

    def ready(self) -> None:
        init_admin_session()
