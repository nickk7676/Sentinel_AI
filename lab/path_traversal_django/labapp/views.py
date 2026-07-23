"""
Deliberately vulnerable report-download view - Django variant.

Same exploitable path traversal as lab/path_traversal/app.py (naive
os.path.join, no normalization/allowlist check on GET /download - do not
copy this pattern anywhere else), reproduced through Django (Step 5). Same
directory layout (sibling "secret" dir next to "reports", holding
canary.txt) as lab/path_traversal/app.py since
agents/techniques/path_traversal.py's red-team prompt hardcodes the exact
payload shape against a candidate list that includes "secret".
"""

import os
import time

from django.http import HttpResponse, JsonResponse

from .apps import REPORTS_DIR

LOG_LINES: list[str] = []


def _log(line: str) -> None:
    LOG_LINES.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {line}\n")


def download(request):
    filename = request.GET.get("file", "")

    # Deliberately vulnerable: naive join, no normalization or allowlist
    # check, so "../" sequences in `filename` escape REPORTS_DIR.
    path = os.path.join(REPORTS_DIR, filename)

    try:
        with open(path, "r", errors="replace") as f:
            content = f.read()
        status = 200
        error = None
    except (FileNotFoundError, IsADirectoryError, PermissionError) as exc:
        content = ""
        status = 404
        error = str(exc)

    escaped = not os.path.realpath(path).startswith(os.path.realpath(REPORTS_DIR))
    _log(f"DOWNLOAD_REQUEST file={filename!r} resolved_path={path!r} status={status} escaped={escaped}")

    return JsonResponse({"filename": filename, "content": content, "error": error}, status=status)


def logs(request):
    since = int(request.GET.get("since", 0) or 0)
    contents = "".join(LOG_LINES)
    return JsonResponse({"lines": contents[since:], "offset": len(contents)})


def healthz(request):
    return HttpResponse("ok", status=200)
