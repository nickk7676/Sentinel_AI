import os

from django.apps import AppConfig

BASE_DIR = "/tmp/lab_path_traversal_django"
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
SECRET_DIR = os.path.join(BASE_DIR, "secret")
CANARY = "SENTINELAI-PATHTRAV-CANARY-c19d6b3e"


def init_files() -> None:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(SECRET_DIR, exist_ok=True)
    with open(os.path.join(REPORTS_DIR, "report1.txt"), "w") as f:
        f.write("Q1 sales report: revenue up 4% quarter over quarter.\n")
    with open(os.path.join(REPORTS_DIR, "readme.txt"), "w") as f:
        f.write("This directory contains quarterly report exports.\n")
    with open(os.path.join(SECRET_DIR, "canary.txt"), "w") as f:
        f.write(CANARY + "\n")


class LabappConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "labapp"

    def ready(self) -> None:
        init_files()
