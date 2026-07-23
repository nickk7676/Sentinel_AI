import os
import secrets
import sqlite3

from django.apps import AppConfig

DB_PATH = "/tmp/lab_sql_injection_django.db"
SEEDED_USER = "admin"
SEEDED_PASSWORD = secrets.token_urlsafe(12)


def init_db() -> None:
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE users (username TEXT, password TEXT)")
    conn.execute("INSERT INTO users VALUES (?, ?)", (SEEDED_USER, SEEDED_PASSWORD))
    conn.commit()
    conn.close()


class LabappConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "labapp"

    def ready(self) -> None:
        init_db()
