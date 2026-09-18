"""Small shared helpers (formatting, IO, error collection)."""

from __future__ import annotations

from pathlib import Path
import datetime as dt
import html
import json
import re

def esc(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def hum(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "–"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024.0
    return "–"


def iso(ts, local=True) -> str:
    if not ts:
        return "–"
    try:
        d = dt.datetime.fromtimestamp(float(ts)).astimezone()
    except (OverflowError, OSError, ValueError):
        return "–"
    return d.strftime("%Y-%m-%d %H:%M:%S")


def mt(p: Path):
    try:
        return p.stat().st_mtime
    except OSError:
        return None


def read_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def read_text(p: Path, limit=200_000):
    try:
        return p.read_text(encoding="utf-8", errors="replace")[:limit]
    except Exception:
        return None


def fname(p) -> str:
    return re.sub(r"\\+", "/", str(p))


class Ctx:
    """Accumulates warnings/errors so a partial failure still yields a report."""

    def __init__(self):
        self.warnings = []
        self.errors = []

    def warn(self, msg):
        self.warnings.append(msg)

    def error(self, label, exc):
        self.errors.append({"where": label, "error": f"{type(exc).__name__}: {exc}"})

    def guard(self, label, fn, default=None):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - forensic tool must not abort
            self.error(label, exc)
            return default
