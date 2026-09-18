"""Command line entry point: argument parsing and wiring."""

from __future__ import annotations

from pathlib import Path
import argparse
import datetime as dt
import json
import platform
import re
import sys

from .collect import collect_aux, collect_log_mentions, collect_workspace
from .constants import SCHEMA, VERDICTS
from .detection import _bundle_roots, _running_exe, data_dir_candidates, detect_processes, find_client_targets, install_candidates, read_asar_version, real_platform, resolve_data_dir, resolve_home, resolve_platform, resolve_user_data_dir
from .diffing import diff_reports
from .locking import apply_lock, unlock, verify_lock
from . import messages
from .messages import detect_lang, set_lang, tr
from .report import render_html
from .signatures import scan_signatures
from .util import Ctx, read_json, read_text
from .verdict import decide

def build_doc(args, ctx: Ctx):
    plat = resolve_platform(args)
    home = resolve_home(args)
    data_dir, data_how = resolve_data_dir(args, home, plat)

    cands = install_candidates(args, home, plat, data_dir)
    targets = find_client_targets(cands)
    if not targets:
        # lazy probe: only pay for it when the cheap locations came up empty
        exe, how = _running_exe()
        if exe:
            extra = _bundle_roots(exe, how)
            cands = cands + extra
            targets = find_client_targets(extra)

    sig = scan_signatures(targets, ctx, enabled=not args.no_scan)

    client = {
        "install_dir": sig.get("install_dir"),
        "install_how": sig.get("install_how"),
        "asar": sig.get("target"),
        "version": None,
        "candidates_tried": [{"path": str(p), "how": how} for p, how in cands],
        "targets": sig.get("candidates") or [],
        "scan_attempts": sig.get("attempts") or [],
    }
    chosen = None
    if sig.get("target"):
        chosen = Path(sig["target"])
    elif targets:
        chosen = targets[0][0]
    if chosen is not None:
        if chosen.suffix == ".asar":
            client["version"] = read_asar_version(chosen)
            yml = read_text(chosen.parent / "app-update.yml", 2000)
            if yml and not client["version"]:
                m = re.search(r"version:\s*(\S+)", yml)
                client["version"] = m.group(1) if m else None
        elif chosen.is_dir():
            pkg = read_json(chosen / "package.json")
            client["version"] = (pkg or {}).get("version")

    cp_root = data_dir / "v2" / "checkpoints"
    workspaces = []
    if cp_root.is_dir():
        for d in sorted(p for p in cp_root.iterdir() if p.is_dir()):
            ws = ctx.guard(f"workspace {d.name}", lambda d=d: collect_workspace(d, ctx, args.redact))
            if ws:
                workspaces.append(ws)

    aux = ctx.guard("aux", lambda: collect_aux(data_dir, ctx, home, plat), {}) or {}
    doc = {
        "schema": SCHEMA,
        "lang": messages.LANG,
        "generated_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S %z"),
        "detection": {
            "platform": plat,
            "platform_source": tr("m091") if str(getattr(args, "platform", "auto")) != "auto" else tr("m092"),
            "home": str(home),
            "home_source": tr("m093") if getattr(args, "home", None) else tr("m094"),
            "data_dir": str(data_dir),
            "data_dir_how": data_how,
            "checkpoints": str(data_dir / "v2" / "checkpoints"),
        },
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "host": platform.node(),
            "python": platform.python_version(),
        },
        "client": client,
        "signatures": sig,
        "workspaces": workspaces,
        "aux": aux,
        "processes": detect_processes(),
        "log_mentions": ctx.guard("logs", lambda: collect_log_mentions(data_dir, ctx), {}) or {},
        "warnings": ctx.warnings,
        "errors": ctx.errors,
        "redacted": bool(args.redact),
    }

    timeline = []
    for w in workspaces:
        if w.get("state_mtime"):
            timeline.append((w["state_mtime"], tr("m125", p0=w['key'])))
        for m in w["manifests"]:
            timeline.append((m.get("createdAt", 0) / 1000 or m.get("mtime"), tr("m126", p0=w['key'])))
        for e in w["extra_manifests"]:
            timeline.append((e.get("createdAt", 0) / 1000 or e.get("mtime"), tr("m127", p0=w['key'])))
        for p in w["pending"]:
            timeline.append((p.get("mtime"), tr("m128", p0=w['key'], p1=p['file'])))
    doc["timeline"] = [(t, l) for t, l in timeline if t]

    doc["verdict"] = decide(doc)
    doc["lock_state"] = verify_lock(cp_root, ctx)
    doc["reproduce"] = (
        tr("m001", p0=Path(__file__).name, p1=data_dir / 'v2' / 'checkpoints', p2=client.get('asar') or '<app.asar>', p3=client.get('asar') or '<app.asar>')
    )
    return doc


def main(argv=None):
    if sys.version_info < (3, 9):
        print(
            tr("m065", p0=platform.python_version()),
            file=sys.stderr,
        )
        return 2
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="ZCode workspace-snapshot upload forensics (read-only by default)")
    ap.add_argument("--zcode-dir", help="ZCode data dir (default: auto-probed, ~/.zcode)")
    ap.add_argument("--install-dir", help="ZCode install dir (auto-probed when omitted)")
    ap.add_argument("--home", help="override the user home dir (cross-inspection / testing)")
    ap.add_argument(
        "--platform",
        choices=("auto", "windows", "macos", "linux"),
        default="auto",
        help="override OS detection (inspection of a mounted/foreign install only; lock ops require the real OS)",
    )
    ap.add_argument(
        "--lang",
        choices=("auto", "en", "zh"),
        default="auto",
        help="report/console language; auto follows the system locale",
    )
    ap.add_argument("--list-paths", action="store_true", help="print the path-detection ledger and exit")
    ap.add_argument("--out", help="HTML output path")
    ap.add_argument("--json", dest="json_out", help="JSON output path (default: <html>.json)")
    ap.add_argument("--no-json", action="store_true", help="skip writing the JSON sidecar")
    ap.add_argument("--no-scan", action="store_true", help="skip the app.asar signature scan")
    ap.add_argument("--redact", action="store_true", help="mask paths, branch names and remote hosts")
    ap.add_argument("--diff", help="compare against a previous JSON report")
    ap.add_argument("--apply-lock", action="store_true", help="quarantine + lock the checkpoints dir")
    ap.add_argument("--unlock", action="store_true", help="restore write access")
    ap.add_argument("--verify-lock", action="store_true", help="only probe whether the checkpoints dir is writable")
    ap.add_argument("--yes", action="store_true", help="skip confirmation prompts")
    ap.add_argument("--force", action="store_true", help="proceed even if ZCode is running")
    args = ap.parse_args(argv)

    set_lang(detect_lang(args.lang))

    ctx = Ctx()
    plat = resolve_platform(args)
    home = resolve_home(args)
    data_dir, data_how = resolve_data_dir(args, home, plat)

    if args.list_paths:
        cands = install_candidates(args, home, plat, data_dir)
        targets = find_client_targets(cands)
        ledger = {
            "platform": {"resolved": plat, "real": real_platform(), "system()": platform.system()},
            "home": str(home),
            "data_dir": {"path": str(data_dir), "how": data_how, "exists": data_dir.is_dir()},
            "data_dir_candidates": [
                {"path": str(p), "how": how, "exists": p.is_dir()}
                for p, how in data_dir_candidates(args, home, plat)
            ],
            "user_data_dir": dict(
                zip(("path", "how"), (lambda t: (str(t[0]) if t[0] else None, t[1]))(resolve_user_data_dir(home, plat)))
            ),
            "client_targets": [{"target": str(t), "how": how, "is_file": t.is_file()} for t, _d, how in targets],
            "install_candidates": [
                {"path": str(p), "how": how, "is_dir": p.is_dir()} for p, how in cands
            ],
            "checkpoints": str(data_dir / "v2" / "checkpoints"),
        }
        print(json.dumps(ledger, ensure_ascii=False, indent=2))
        return 0

    if args.apply_lock or args.unlock:
        if plat != real_platform():
            print(
                tr("m095", p0=plat, p1=real_platform()),
                file=sys.stderr,
            )
            return 2

    if args.verify_lock:
        r = verify_lock(data_dir / "v2" / "checkpoints", ctx)
        print(json.dumps(r, ensure_ascii=False, indent=2))
        return 0 if r["locked"] else 1

    if args.unlock:
        if not (args.yes or sys.stdin.isatty()):
            print(tr("m096"), file=sys.stderr)
            return 2
        if not args.yes and input(tr("m176")).strip().lower() != "y":
            print(tr("m097"))
            return 0
        r = unlock(data_dir, ctx)
        print("\n".join(r["log"]))
        return 0 if r["ok"] else 1

    doc = build_doc(args, ctx)

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = Path(args.out) if args.out else Path.cwd() / f"zcode-upload-report-{stamp}.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(doc), encoding="utf-8")

    json_path = None
    if args.json_out:
        json_path = Path(args.json_out)
    elif not args.no_json:
        json_path = out.with_suffix(".json")
    if json_path:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")

    v = doc["verdict"]
    print(f"verdict : {v['code']} ({tr(VERDICTS[v['code']][0])}) confidence={v['confidence']}")
    print(f"HTML    : {out.resolve()}")
    if json_path:
        print(f"JSON    : {json_path.resolve()}")
    if args.diff:
        print(tr("m066"))
        for line in diff_reports(Path(args.diff), doc, ctx):
            print(f"  - {line}")
    for w in doc["warnings"]:
        print(f"warning : {w}")
    for e in doc["errors"]:
        print(f"error   : {e['where']}: {e['error']}")

    if args.apply_lock:
        print(tr("m067"))
        print(tr("m068", p0=data_dir / 'v2' / 'checkpoints'))
        print(tr("m069"))
        if not args.yes:
            if not sys.stdin.isatty():
                print(tr("m129"), file=sys.stderr)
                return 2
            if input(tr("m177")).strip().lower() != "y":
                print(tr("m130"))
                return 0
        r = apply_lock(data_dir, ctx, args.yes, args.force)
        for line in r["log"]:
            print(f"  {line}")
        print(tr("m098") if r["ok"] else tr("m099"))
        return 0 if r["ok"] else 1
    return 0
