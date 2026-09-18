"""Filesystem lock: verify, quarantine+lock, restore."""

from __future__ import annotations

from pathlib import Path
import datetime as dt
import os
import shutil
import subprocess

from .detection import detect_processes, real_platform
from .messages import tr
from .util import Ctx

def lock_platform_key(plat):
    return {"windows": "Windows", "macos": "macOS"}.get(plat, "Linux")


def lock_commands(plat, cp_path):
    """Remediation commands bound to the *detected* paths, so they stay correct
    for non-default data dirs, other user names and cross-inspection."""
    cp = str(cp_path)
    if plat == "windows":
        return {
            tr("m052"): "python diagnose.py --apply-lock",
            tr("m053"): (
                tr("m054", p0=cp, p1=cp, p2=cp, p3=cp)
            ),
            tr("m029"): f'icacls "{cp}" /reset /T',
        }
    if plat == "macos":
        return {
            tr("m027"): "python diagnose.py --apply-lock",
            tr("m028"): tr("m055", p0=cp),
            tr("m029"): f'chflags nouchg "{cp}"',
        }
    return {
        tr("m027"): "python diagnose.py --apply-lock",
        tr("m028"): tr("m030", p0=cp),
        tr("m029"): f'sudo chattr -i "{cp}"',
    }


def current_user_principal():
    """icacls needs a resolvable principal: DOMAIN\\user when available."""
    if real_platform() != "windows":
        return (os.environ.get("USER") or "").strip()
    try:
        r = subprocess.run(["whoami"], capture_output=True, text=True, timeout=15)
        v = (r.stdout or "").strip().splitlines()
        if v and v[0].strip():
            return v[0].strip()
    except Exception:
        pass
    dom = (os.environ.get("USERDOMAIN") or "").strip()
    usr = (os.environ.get("USERNAME") or os.environ.get("USER") or "").strip()
    return f"{dom}\\{usr}" if dom and usr else usr


def _run(cmd, ctx: Ctx):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as exc:
        ctx.error(" ".join(cmd), exc)
        return 1, str(exc)


def _write_probe(d: Path):
    p = d / f".forensics-probe-{os.getpid()}"
    try:
        p.write_text("probe", encoding="utf-8")
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"
    try:
        p.unlink()
    except OSError:
        pass
    return True, tr("m031")


def verify_lock(cp: Path, ctx: Ctx):
    if not cp.exists():
        return {"locked": None, "detail": tr("m056")}
    cp.mkdir(parents=True, exist_ok=True)
    ok, detail = _write_probe(cp)
    return {"locked": not ok, "detail": detail}


def apply_lock(data_dir: Path, ctx: Ctx, assume_yes: bool, force: bool):
    cp = data_dir / "v2" / "checkpoints"
    log = []
    proc = detect_processes()
    if proc.get("running") and not force:
        log.append(tr("m057", p0=proc.get('count')))
        return {"ok": False, "log": log, "proc": proc}

    v2 = data_dir / "v2"
    v2.mkdir(parents=True, exist_ok=True)
    if cp.exists():
        ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        q = v2 / f"checkpoints-quarantine-{ts}"
        try:
            shutil.move(str(cp), str(q))
            log.append(tr("m085", p0=q))
        except Exception as exc:
            ctx.error("quarantine", exc)
            log.append(tr("m123", p0=exc))
            return {"ok": False, "log": log, "proc": proc}
    else:
        log.append(tr("m058"))

    cp.mkdir(parents=True, exist_ok=True)
    system = real_platform()
    if system == "windows":
        user = current_user_principal()
        code, out = _run(["icacls", str(cp), "/inheritance:r"], ctx)
        log.append(f"icacls /inheritance:r -> rc={code}")
        grants = [
            "icacls",
            str(cp),
            "/grant:r",
            f"{user}:(OI)(CI)(RX)",
            "/grant:r",
            "SYSTEM:(OI)(CI)(F)",
            "/grant:r",
            "Administrators:(OI)(CI)(F)",
        ]
        code, out = _run(grants, ctx)
        if code != 0 and "\\" in user:
            # some setups cannot resolve DOMAIN\\user for icacls: retry bare
            log.append(tr("m086", p0=user))
            grants[3] = f"{user.split(chr(92))[-1]}:(OI)(CI)(RX)"
            code, out = _run(grants, ctx)
        log.append(tr("m059", p0=user, p1=code, p2=out.strip()[:200]))
    elif system == "macos":
        code, out = _run(["chflags", "uchg", str(cp)], ctx)
        log.append(f"chflags uchg -> rc={code} {out.strip()[:200]}")
    else:
        code, out = _run(["chattr", "+i", str(cp)], ctx)
        if code != 0:
            log.append(tr("m124"))
        log.append(f"chattr +i -> rc={code} {out.strip()[:200]}")

    check = verify_lock(cp, ctx)
    log.append(
        tr("m032", p0=tr("n001") if check['locked'] else tr("n002"), p1=check['detail'])
    )
    return {"ok": bool(check["locked"]), "log": log, "verify": check, "proc": proc}


def unlock(data_dir: Path, ctx: Ctx):
    cp = data_dir / "v2" / "checkpoints"
    log = []
    if not cp.exists():
        return {"ok": False, "log": [tr("m056")]}
    system = real_platform()
    if system == "windows":
        code, out = _run(["icacls", str(cp), "/reset", "/T"], ctx)
        log.append(f"icacls /reset -> rc={code} {out.strip()[:200]}")
    elif system == "macos":
        code, out = _run(["chflags", "nouchg", str(cp)], ctx)
        log.append(f"chflags nouchg -> rc={code}")
    else:
        code, out = _run(["chattr", "-i", str(cp)], ctx)
        log.append(f"chattr -i -> rc={code} {out.strip()[:200]}")
    check = verify_lock(cp, ctx)
    log.append(tr("m032", p0=tr("n003") if not check['locked'] else tr("n004"), p1=check['detail']))
    for q in sorted((data_dir / "v2").glob("checkpoints-quarantine-*")):
        log.append(tr("m060", p0=q))
    return {"ok": not check["locked"], "log": log}
