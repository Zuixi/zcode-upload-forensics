#!/usr/bin/env python3
"""ZCode workspace-snapshot upload forensics.

Read-only by default: collects local evidence about ZCode's "repo snapshot"
capture/upload pipeline, decides a verdict from the truth table, and renders a
single self-contained HTML report.

    python diagnose.py                     # auto-detect -> HTML + JSON in cwd
    python diagnose.py --redact            # mask paths / branch names / remote hosts
    python diagnose.py --no-scan           # skip the (slow) app.asar signature scan
    python diagnose.py --diff prev.json    # show what changed since a previous run
    python diagnose.py --verify-lock       # check whether the checkpoints dir is locked
    python diagnose.py --apply-lock        # quarantine + lock (needs confirmation)
    python diagnose.py --unlock            # restore write access

Stdlib only. No network access. Never prints file *contents* of the workspace.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

SKILL_VERSION = "1.0.0"
SCHEMA = "zcode-upload-forensics/v1"

# --------------------------------------------------------------------------
# Signature needles: evidence that the installed client contains the
# snapshot pipeline, plus the code lineage that makes "accepted == uploaded"
# hold. Sorted by length at scan time so the regex alternation is longest-match.
# --------------------------------------------------------------------------
NEEDLES = {
    # --- mechanism (does this build ship the silent-upload pipeline?) ---
    "endpoint": b"/api/v1/snapshot/upload-credential",
    "artifact_name": b"repo-snapshot.tar.gz.enc",
    "keywrap": b"rsa-oaep-sha256",
    "oss_form": b"x-oss-security-token",
    "manifest_schema": b"repo_snapshot_manifest/v2",
    "extra_schema": b"repo_snapshot_extra_manifest/v1",
    "capture_hook": b"captureBeforePrompt",
    "max_size_error": b"RepoSnapshotArtifactMaxSizeExceededError",
    # --- semantics (does "accepted" still mean "OSS POST returned 2xx"?) ---
    "state_field": b"lastAcceptedManifestHash",
    "mark_accepted": b"markAcceptedManifest",
    "upload_object": b"uploadObject",
    "oss_callback": b"oss-callback",
    "payload_too_large": b"payload_too_large",
    "incremental": b"incremental",
}

MECHANISM_NEEDLES = [
    "endpoint",
    "artifact_name",
    "keywrap",
    "state_field",
    "capture_hook",
]
SEMANTIC_PAIR = ("mark_accepted", "upload_object")
SEMANTIC_MAX_DISTANCE = 8000  # bytes; adjacency heuristic, see references/evidence-map.md
GATE_NEEDLE = b"snapshot"

SENSITIVE_PATTERNS = [
    ("环境变量文件", re.compile(r"(^|/)\.env(\..+)?$", re.I)),
    ("私钥 / 证书", re.compile(r"\.(pem|key|p12|pfx|jks|keystore|crt|cer)$", re.I)),
    ("SSH key", re.compile(r"(^|/)(id_rsa|id_ed25519|id_ecdsa|known_hosts)$", re.I)),
    ("凭据 / 令牌命名", re.compile(r"(secret|token|credential|passwd|password|api[-_]?key)", re.I)),
    ("数据库 / 转储", re.compile(r"\.(sql|dump|sqlite|sqlite3|db)$", re.I)),
    ("云/工具凭据目录", re.compile(r"(^|/)\.(aws|ssh|kube|gnupg|docker)(/|$)", re.I)),
    ("部署密钥 / CI", re.compile(r"(deploy[-_]?key|\.npmrc|\.pypirc|\.netrc|id_deploy)", re.I)),
]

# Global files that ride along in the extra-manifest (privacy surface #2).
EXTRA_MANIFEST_GROUPS = {
    "global-configs": "客户端全局配置（settings.behavior.json / skills.json 等）",
}

VERDICTS = {
    "UPLOADED": ("已上传", "#b91c1c", "至少一次工作区快照已成功 POST 到厂商云对象存储。"),
    "PACKED_PENDING": ("已打包待传", "#c2410c", "工作区已打包加密落盘且尚未成功上传，重试仍在进行。"),
    "CAPTURED_NOT_ACCEPTED": ("已捕获未确认", "#a16207", "有捕获产物，但没有「已接受」记录；可能失败重试或人工清理。"),
    "INCONCLUSIVE": ("无法判定", "#7c3aed", "存在机制运行痕迹但关键证据已被清理，不能得出「安全」结论。"),
    "NO_LOCAL_TRACE": ("未发现本地痕迹", "#15803d", "客户端有该机制但不含本机捕获产物。"),
    "FEATURE_ABSENT": ("无该机制", "#15803d", "未在安装目录中发现快照上传链路的代码签名。"),
}

EN_LABELS = {
    "UPLOADED": "snapshot(s) successfully uploaded to vendor OSS",
    "PACKED_PENDING": "packed locally, upload not confirmed",
    "CAPTURED_NOT_ACCEPTED": "captured, accept record missing",
    "INCONCLUSIVE": "traces present but key evidence missing",
    "NO_LOCAL_TRACE": "no local capture artifacts",
    "FEATURE_ABSENT": "pipeline signatures not found in this build",
}

TRUTH_TABLE = [
    ("FEATURE_ABSENT", "✘", "–", "–", "–"),
    ("NO_LOCAL_TRACE", "✔", "–", "–", "–"),
    ("CAPTURED_NOT_ACCEPTED", "✔", "–", "–", "✔"),
    ("PACKED_PENDING", "✔", "–", "✔", "✔"),
    ("UPLOADED", "✔", "✔", "–", "✔"),
    ("INCONCLUSIVE", "✔", "痕迹被清理", "?", "?"),
]


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
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


# --------------------------------------------------------------------------
# detection -- no path is hardcoded: everything is probed, and the report
# records *how* each path was found so a human can audit the detection.
# --------------------------------------------------------------------------
PLATFORM_KEYS = ("windows", "macos", "linux")
DATA_DIR_ENV = ("ZCODE_DATA_BASE_DIR", "ZCODE_DATA_DIR", "ZCODE_HOME")
INSTALL_ENV = ("ZCODE_INSTALL_DIR", "ZCODE_APP_PATH", "ZCODE_HOME")
# product/executable spellings observed across installers and platforms
PRODUCT_NAMES = ("Zcode", "ZCode", "zcode", "ZCODE")
EXE_NAMES = ("ZCode", "zcode", "ZCode.exe", "zcode.exe")
# loose JS bundles: the same pipeline also ships inside components that ZCode
# pushes into its own data dir (remote-host assets, computer-use runtime).
BUNDLE_FILES = ("zcode-server.cjs", "zcode-server.mjs", "server.cjs", "main.cjs", "index.cjs")


def real_platform():
    return {"Windows": "windows", "Darwin": "macos"}.get(platform.system(), "linux")


def resolve_platform(args):
    p = str(getattr(args, "platform", None) or "auto").lower()
    return real_platform() if p == "auto" else p


def resolve_home(args):
    """HOME on POSIX/USERPROFILE on Windows -- never assume a username."""
    if getattr(args, "home", None):
        return Path(args.home).expanduser()
    keys = ("USERPROFILE", "HOME") if real_platform() == "windows" else ("HOME", "USERPROFILE")
    for k in keys:
        v = (os.environ.get(k) or "").strip()
        if v:
            try:
                p = Path(v)
                if p.is_dir():
                    return p
            except OSError:
                continue
    return Path(os.path.expanduser("~"))


def _dedup_pairs(pairs):
    seen, uniq = set(), []
    for p, how in pairs:
        try:
            key = os.path.normcase(str(p))
        except OSError:
            continue
        if key and key not in seen:
            seen.add(key)
            uniq.append((p, how))
    return uniq


def data_dir_candidates(args, home, plat):
    """-> [(Path, how)]. An explicit --zcode-dir is authoritative: no falling
    back to another location behind the user's back (forensics tool)."""
    out = []
    if getattr(args, "zcode_dir", None):
        return [(Path(args.zcode_dir).expanduser(), "--zcode-dir 显式指定")]
    for k in DATA_DIR_ENV:
        v = (os.environ.get(k) or "").strip()
        if v:
            out.append((Path(v).expanduser(), f"环境变量 {k}"))
    out.append((home / ".zcode", f"用户主目录 {home} 下的默认数据根"))
    if plat == "linux":
        # WSL inspecting the Windows side of the same machine
        mnt = Path("/mnt/c/Users")
        try:
            if mnt.is_dir():
                for u in sorted(mnt.iterdir()):
                    if (u / ".zcode").is_dir():
                        out.append((u / ".zcode", f"WSL 可见的 Windows 用户目录 {u}"))
        except OSError:
            pass
    return _dedup_pairs(out)


def resolve_data_dir(args, home, plat):
    cands = data_dir_candidates(args, home, plat)
    for p, how in cands:
        try:
            if p.is_dir():
                return p, how
        except OSError:
            continue
    return cands[0][0], cands[0][1] + "（不存在）"


def _windows_registry_installs():
    """Uninstall registry keys: the most reliable source for a non-default
    install drive (e.g. D:\\Program Files\\Zcode) or a per-user install."""
    out = []
    try:
        import winreg  # noqa: PLC0415 - Windows-only
    except ImportError:
        return out
    subkeys = (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    )
    for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        for sub in subkeys:
            try:
                with winreg.OpenKey(root, sub) as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, name) as sk:
                                disp = str(winreg.QueryValueEx(sk, "DisplayName")[0])
                                if "zcode" not in disp.lower():
                                    continue
                                for value in ("InstallLocation", "DisplayIcon", "UninstallString"):
                                    try:
                                        raw = str(winreg.QueryValueEx(sk, value)[0] or "").strip().strip('"')
                                    except OSError:
                                        continue
                                    if not raw:
                                        continue
                                    cand = Path(raw)
                                    if value == "DisplayIcon":
                                        cand = cand.parent
                                    if cand.is_dir():
                                        out.append((cand, f"注册表 {disp} 的 {value}"))
                                        break
                        except OSError:
                            continue
            except OSError:
                continue
    return out


def _windows_drive_roots():
    import string  # noqa: PLC0415

    roots = []
    for letter in string.ascii_uppercase:
        p = Path(f"{letter}:\\")
        try:
            if p.exists():
                roots.append(p)
        except OSError:
            continue
    return roots


def _which_installs():
    """PATH lookup -- works for AppImage wrappers, npm-style shims, brew links."""
    out = []
    for name in EXE_NAMES:
        found = shutil.which(name)
        if found:
            try:
                out.append((Path(found).resolve().parent, f"PATH 中的 {name}"))
            except OSError:
                continue
    return out


def _running_exe():
    """Ask the running client where it lives -- the strongest signal, and the
    only one that works for AppImage mounts and renamed bundles."""
    try:
        if real_platform() == "windows":
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-Process -Name ZCode,zcode -ErrorAction SilentlyContinue |"
                " Select-Object -First 1 -ExpandProperty Path)",
            ]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
            for line in (r.stdout or "").splitlines():
                line = line.strip()
                if line and "zcode" in line.lower():
                    return Path(line), "运行中的 ZCode 进程可执行文件路径"
            return None, None
        proc = Path("/proc")
        if proc.is_dir():
            for entry in proc.glob("[0-9]*/exe"):
                try:
                    target = os.readlink(entry)
                except OSError:
                    continue
                if "zcode" in target.lower():
                    return Path(target), "运行中的 ZCode 进程可执行文件（/proc）"
        r = subprocess.run(["ps", "-Ao", "comm="], capture_output=True, text=True, timeout=20)
        for line in (r.stdout or "").splitlines():
            s = line.strip()
            if s and Path(s).name.lower().startswith("zcode"):
                return Path(s), "运行中的 ZCode 进程可执行文件（ps）"
    except Exception:
        return None, None
    return None, None


def _bundle_roots(exe_path, how):
    """Derive install roots from an executable path, incl. macOS bundles."""
    out = [(exe_path.parent, how)]
    try:
        parent = exe_path.parent
        out.append((parent.parent, how))
        out.append((parent.parent / "Resources", how + "（macOS bundle）"))
        out.append((parent / "resources", how))
        # .../ZCode.app/Contents/MacOS/ZCode -> .../ZCode.app/Contents/Resources
        for up in (parent, parent.parent, parent.parent.parent):
            out.append((up / "Resources", how))
    except OSError:
        pass
    return out


def install_candidates(args, home, plat, data_dir=None):
    """-> [(Path, how)]. An explicit --install-dir is authoritative: probing other
    installs would silently answer a different question than the one asked."""
    if getattr(args, "install_dir", None):
        return [(Path(args.install_dir).expanduser(), "--install-dir 显式指定")]
    out = []
    for k in INSTALL_ENV:
        v = (os.environ.get(k) or "").strip()
        if v:
            out.append((Path(v).expanduser(), f"环境变量 {k}"))
    out += _which_installs()

    if plat == "windows":
        out += _windows_registry_installs()
        for var in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA", "ProgramData"):
            base = os.environ.get(var)
            if not base:
                continue
            for name in PRODUCT_NAMES:
                out.append((Path(base) / name, f"%{var}%\\{name}"))
                out.append((Path(base) / "Programs" / name, f"%{var}%\\Programs\\{name}"))
        for drive in _windows_drive_roots():
            for sub in ("Program Files", "Program Files (x86)"):
                for name in PRODUCT_NAMES:
                    out.append((drive / sub / name, f"{drive}{sub}\\{name}"))
            for name in PRODUCT_NAMES:
                out.append((drive / name, f"{drive}{name}"))
    elif plat == "macos":
        for apps in (Path("/Applications"), home / "Applications", Path("/Applications/Utilities")):
            for name in PRODUCT_NAMES:
                out.append((apps / f"{name}.app" / "Contents" / "Resources", f"{apps}/{name}.app"))
                out.append((apps / f"{name}.app" / "Contents", f"{apps}/{name}.app"))
        out.append((Path("/usr/local/lib/zcode/resources"), "/usr/local/lib/zcode"))
        out.append((Path("/opt/homebrew/lib/zcode/resources"), "/opt/homebrew/lib/zcode"))
    else:
        for base in ("/opt", "/usr/lib", "/usr/share", "/usr/local/lib", "/snap"):
            for name in PRODUCT_NAMES:
                out.append((Path(base) / name / "resources", f"{base}/{name}"))
                out.append((Path(base) / name, f"{base}/{name}"))
        for name in PRODUCT_NAMES:
            out.append((home / ".local/share" / name / "resources", f"~/.local/share/{name}"))
            out.append((home / ".local/opt" / name / "resources", f"~/.local/opt/{name}"))

    # bundled app copies and leftovers next to the data dir
    out += [
        (home / ".zcode" / "computer-use", "数据目录下的 computer-use 副本"),
        (home / ".zcode" / "v2" / "computer-use", "数据目录下的 computer-use 副本"),
    ]
    if data_dir is not None and data_dir != home / ".zcode":
        out += [
            (data_dir / "computer-use", "数据目录下的 computer-use 副本"),
            (data_dir / "v2" / "computer-use", "数据目录下的 computer-use 副本"),
        ]
    if data_dir is not None:
        # remote-host / runtime assets ZCode pushes to a machine that may have no
        # desktop client at all -- on such a host this is the only copy of the code
        out.append((data_dir / "server", "数据目录下的 ZCode 远端 host bundle"))
    return _dedup_pairs(out)


def client_targets_under(d):
    """Known shapes of a ZCode client/host payload inside one directory."""
    found = []
    try:
        for rel in ("resources/app.asar", "app.asar"):
            p = d / rel
            if p.is_file():
                found.append(p)
        for rel in ("resources/app", "app"):
            p = d / rel
            if p.is_dir() and (p / "package.json").is_file():
                found.append(p)
        for name in BUNDLE_FILES:
            p = d / name
            if p.is_file():
                found.append(p)
            p = d / "server" / name
            if p.is_file():
                found.append(p)
        if not found:
            # nested layouts (e.g. computer-use/<version>/.../app.asar)
            for p in sorted(d.glob("*/*/app.asar"))[:4]:
                if p.is_file():
                    found.append(p)
    except OSError:
        pass
    return found


def find_client_targets(cands):
    """-> [(target, install_dir, how)] ordered by candidate priority."""
    out = []
    seen = set()
    for d, how in cands:
        for target in client_targets_under(d):
            key = os.path.normcase(str(target))
            if key in seen:
                continue
            seen.add(key)
            out.append((target, d, how))
    return out


def read_asar_version(asar: Path):
    """Pull the root package.json version out of an asar without extracting it."""
    if asar.suffix != ".asar":
        return None
    try:
        with asar.open("rb") as fh:
            head = fh.read(16)
            if len(head) < 16:
                return None
            json_size = int.from_bytes(head[12:16], "little")
            header = json.loads(fh.read(json_size).decode("utf-8", "replace"))
            base = 16 + json_size
            entry = (header.get("files") or {}).get("package.json")
            if not entry or "offset" not in entry:
                return None
            fh.seek(base + int(entry["offset"]))
            raw = fh.read(int(entry.get("size", 0)))
            pkg = json.loads(raw.decode("utf-8", "replace"))
            return pkg.get("version")
    except Exception:
        return None


# --------------------------------------------------------------------------
# signature scan
# --------------------------------------------------------------------------
def _file_contains(path: Path, needle: bytes, chunk=8 << 20) -> bool:
    overlap = len(needle) - 1
    tail = b""
    try:
        with path.open("rb") as fh:
            while True:
                buf = fh.read(chunk)
                if not buf:
                    return False
                if needle in tail + buf:
                    return True
                tail = buf[-overlap:] if overlap > 0 else b""
    except OSError:
        return False


def _count_needles(blob: bytes, counts, positions, base=0, cap=8):
    keys = sorted(NEEDLES, key=lambda k: -len(NEEDLES[k]))
    pat = re.compile(b"|".join(re.escape(NEEDLES[k]) for k in keys))
    rev = {NEEDLES[k]: k for k in keys}
    for m in pat.finditer(blob):
        k = rev.get(m.group(0))
        if k is None:
            continue
        counts[k] += 1
        bucket = positions.setdefault(k, [])
        if len(bucket) < cap:
            bucket.append(base + m.start())
    return counts, positions


def _scan_one(path: Path, counts, positions, chunk=8 << 20):
    overlap = max(len(v) for v in NEEDLES.values()) - 1
    tail, base = b"", 0
    with path.open("rb") as fh:
        while True:
            buf = fh.read(chunk)
            if not buf:
                break
            data = tail + buf
            _count_needles(data, counts, positions, base - len(tail))
            tail = data[-overlap:] if overlap > 0 else b""
            base += len(buf)
    return counts, positions


def _scan_target(target, ctx: Ctx, counts, positions):
    """Scan one candidate payload. Returns whether the gate word was present."""
    if target.is_dir():
        files = [
            p
            for p in target.rglob("*")
            if p.is_file()
            and p.suffix in (".js", ".mjs", ".cjs")
            and "node_modules" not in p.parts
        ]
        gated = [p for p in files if _file_contains(p, GATE_NEEDLE)]
        total = sum(p.stat().st_size for p in gated)
        budget = 250 * 1024 * 1024
        if total > budget:
            ctx.warn(f"{target} 超过 250MB，仅扫描前 250MB 的 JS")
        for p in gated:
            if budget <= 0:
                break
            try:
                budget -= p.stat().st_size
            except OSError:
                continue
            ctx.guard(f"scan {p}", lambda p=p: _scan_one(p, counts, positions))
        return bool(gated)
    try:
        gate = _file_contains(target, GATE_NEEDLE)
    except OSError as exc:
        ctx.error(f"scan {target}", exc)
        return False
    if gate:
        ctx.guard(f"scan {target}", lambda: _scan_one(target, counts, positions))
    return gate


def scan_signatures(targets, ctx: Ctx, enabled=True, max_targets=3):
    """Try candidate payloads in priority order, stopping as soon as the
    mechanism signatures are confirmed (a stale or unrelated bundle must not
    mask a good one, and a machine may only carry one of them)."""
    result = {
        "scanned": False,
        "source": None,
        "gate_hit": None,
        "counts": {k: 0 for k in NEEDLES},
        "mechanism_hits": 0,
        "mechanism_total": len(MECHANISM_NEEDLES),
        "semantic_invariant": "unverified",
        "semantic_distance": None,
        "target": None,
        "attempts": [],
    }
    targets = list(targets or [])
    result["candidates"] = [{"target": str(t), "how": how} for t, _d, how in targets]
    if not enabled:
        result["note"] = "已按 --no-scan 跳过"
        return result
    if not targets:
        result["note"] = "未找到 app.asar / 客户端 bundle，无法做代码签名验证"
        return result

    best = None
    for target, install_dir, how in targets[:max_targets]:
        counts, positions = {k: 0 for k in NEEDLES}, {k: [] for k in NEEDLES}
        gate = _scan_target(target, ctx, counts, positions)
        hits = sum(1 for k in MECHANISM_NEEDLES if counts.get(k))
        result["attempts"].append(
            {"target": str(target), "how": how, "gate_hit": gate, "mechanism_hits": hits}
        )
        ctx.guard(f"stat {target}", lambda t=target: result["attempts"][-1].update(
            {"bytes": t.stat().st_size if t.is_file() else None, "mtime": mt(t)}
        ))
        if gate and (best is None or hits > best[1]):
            best = (target, hits, install_dir, how, counts, positions)
        if hits >= len(MECHANISM_NEEDLES):
            break

    result["scanned"] = True
    if best is None:
        result["gate_hit"] = False
        result["note"] = "所有候选 payload 都未命中 gate 关键词，该安装不具备此机制"
        return result

    target, hits, install_dir, how, counts, positions = best
    result["target"] = str(target)
    result["install_dir"] = str(install_dir) if install_dir else None
    result["install_how"] = how
    result["counts"] = counts
    result["gate_hit"] = True
    if target.is_file():
        result["target_bytes"] = target.stat().st_size
        result["target_mtime"] = mt(target)
    result["mechanism_hits"] = hits
    marks = positions.get("mark_accepted", [])
    uploads = positions.get("upload_object", [])
    best = None
    for a in marks:
        for b in uploads:
            d = abs(a - b)
            if best is None or d < best:
                best = d
    result["semantic_distance"] = best
    if best is not None and best <= SEMANTIC_MAX_DISTANCE:
        result["semantic_invariant"] = "verified-heuristic"
    elif marks and uploads:
        result["semantic_invariant"] = "pair-present-far-apart"
    else:
        result["semantic_invariant"] = "unverified"
    return result


# --------------------------------------------------------------------------
# evidence collection
# --------------------------------------------------------------------------
def classify_files(files, ctx: Ctx, label):
    """files: list of {"path","sizeBytes"} from a manifest."""
    total = 0
    groups = {}
    sensitive = []
    branches, remotes, worktrees = set(), set(), set()
    counts = {"git": 0, "reflog": 0, "refs": 0, "worktree": 0}
    for f in files or []:
        p = fname(f.get("path", ""))
        size = int(f.get("sizeBytes") or 0)
        total += size
        if p.startswith(".git/"):
            counts["git"] += 1
            seg = p.split("/")
            key = ".git/" + (seg[1] if len(seg) > 1 else "?")
            if p.startswith(".git/logs/"):
                counts["reflog"] += 1
            if p.startswith(".git/refs/"):
                counts["refs"] += 1
            m = re.match(r"^\.git/refs/heads/(.+)$", p)
            if m:
                branches.add(m.group(1))
            m = re.match(r"^\.git/refs/remotes/([^/]+)/", p)
            if m:
                remotes.add(m.group(1))
            m = re.match(r"^\.git/worktrees/([^/]+)/", p)
            if m:
                counts["worktree"] += 1
                worktrees.add(m.group(1))
        else:
            key = p.split("/")[0] or "(root)"
        groups[key] = groups.get(key, 0) + size
        for name, pat in SENSITIVE_PATTERNS:
            if pat.search(p):
                sensitive.append({"kind": name, "path": p, "sizeBytes": size})
                break
    top = sorted(
        ({"name": k, "bytes": v, "pct": (100.0 * v / total if total else 0)} for k, v in groups.items()),
        key=lambda r: -r["bytes"],
    )[:20]
    return {
        "label": label,
        "files": len(files or []),
        "bytes": total,
        "top_groups": top,
        "git_counts": counts,
        "branches": sorted(branches),
        "remotes": sorted(remotes),
        "worktrees": sorted(worktrees),
        "sensitive": sensitive,
    }


def read_local_git_remotes(workspace_path: Path):
    """Read the *local* .git/config remotes: the manifest only carries the file
    size, so this is the closest available proxy for what a snapshot contains."""
    cfg = workspace_path / ".git" / "config"
    txt = read_text(cfg, 20_000)
    if not txt:
        return None
    out, cur = [], None
    for line in txt.splitlines():
        m = re.match(r'^\s*\[remote\s+"([^"]+)"\]', line)
        if m:
            cur = {"name": m.group(1), "url": None}
            out.append(cur)
            continue
        m = re.match(r"^\s*\[(.+)\]", line)
        if m:
            cur = None
            continue
        m = re.match(r"^\s*url\s*=\s*(.+?)\s*$", line)
        if m and cur is not None:
            cur["url"] = m.group(1)
    return out or None


def collect_workspace(wdir: Path, ctx: Ctx, redact: bool):
    ws = {
        "key": wdir.name,
        "dir": str(wdir),
        "dir_mtime": mt(wdir),
        "state": None,
        "state_mtime": None,
        "manifests": [],
        "extra_manifests": [],
        "pending": [],
        "tmp": [],
        "warnings": [],
    }
    sp = wdir / "state.json"
    st = read_json(sp)
    ws["state_mtime"] = mt(sp)
    if st is None and sp.exists():
        ws["warnings"].append("state.json 存在但无法解析（可能正在写入或被截断）")
    if isinstance(st, dict):
        ws["state"] = st
        ws["workspace_path"] = st.get("workspacePath") or st.get("workspaceKey")
        ws["failure_count"] = st.get("failureCount")
        ws["last_compressed"] = st.get("lastCompressedSize")
        ws["accepted_hash"] = st.get("lastAcceptedManifestHash")
        ws["accepted_path"] = st.get("lastAcceptedManifestPath")
        ws["accepted_extra_hash"] = st.get("lastAcceptedExtraManifestHash")
        # some builds keep the in-flight upload inside state.json
        for k in ("pendingUpload", "activeUpload", "latestPendingUpload"):
            if st.get(k):
                ws["in_state_upload"] = {"field": k, "kind": st[k].get("kind"), "createdAt": st[k].get("createdAt")}

    for sub, bucket in (("manifests", "manifests"), ("extra-manifests", "extra_manifests")):
        d = wdir / sub
        if not d.is_dir():
            continue
        for f in sorted(d.iterdir()):
            if not f.is_file():
                continue
            entry = {"file": f.name, "bytes": f.stat().st_size, "mtime": mt(f)}
            doc = read_json(f)
            if isinstance(doc, dict):
                entry["schema"] = doc.get("schema")
                entry["createdAt"] = doc.get("createdAt")
                entry["workspaceKey"] = doc.get("workspaceKey")
                if sub == "manifests":
                    entry.update(classify_files(doc.get("files"), ctx, f.name))
                    stats = doc.get("stats") or {}
                    entry["stats"] = stats
                    entry["bytes"] = int(stats.get("includedBytes") or entry["bytes"])
                    entry["manifest_files"] = int(stats.get("includedFileCount") or entry["files"])
                else:
                    fid = []
                    for g in doc.get("groups") or []:
                        for x in g.get("files") or []:
                            fid.append(
                                {
                                    "groupId": g.get("groupId"),
                                    "path": fname(x.get("path")),
                                    "sizeBytes": x.get("sizeBytes"),
                                    "source": x.get("source"),
                                }
                            )
                    entry["included"] = fid
                    entry["stats"] = doc.get("stats")
                entry["hash"] = hashlib.sha256(f.read_bytes()).hexdigest()[:16]
            else:
                entry["parse_error"] = True
            ws[bucket].append(entry)

    for sub, bucket in (("pending", "pending"), ("tmp", "tmp")):
        d = wdir / sub
        if d.is_dir():
            for f in sorted(d.rglob("*")):
                if f.is_file():
                    ws[bucket].append(
                        {"file": str(f.relative_to(wdir)), "bytes": f.stat().st_size, "mtime": mt(f)}
                    )

    # timeline anomaly: the manifests dir was touched after the last state write
    md = wdir / "manifests"
    md_ok = False
    if md.is_dir() and ws["state_mtime"]:
        if (mt(md) or 0) > ws["state_mtime"] + 1:
            md_ok = True
            ws["warnings"].append(
                f"manifests/ 目录 mtime（{iso(mt(md))}）晚于 state.json（{iso(ws['state_mtime'])}）"
                "：存在一次未被记录的捕获活动"
            )
    ws["timeline_anomaly"] = md_ok

    # baseline vs increment heuristic
    lc = ws.get("last_compressed") or {}
    enc, plain = lc.get("encryptedSizeBytes"), lc.get("workspaceSizeBytes")
    if enc and plain and plain > 1_000_000:
        ratio = float(enc) / float(plain)
        ws["size_ratio"] = ratio
        if ratio < 0.35:
            ws["ratio_hint"] = (
                f"加密产物/清单体积 = {ratio:.3f} ≪ 1。.git/objects 本身已是 zlib 压缩、gzip 几乎不再压缩，"
                "比值远小于 1 说明这次是增量 delta，进而说明**更早存在一次全量基线**（即完整工作区曾经上传过）。"
            )

    if ws.get("workspace_path"):
        if redact:
            ws["workspace_path_display"] = "<redacted>" + Path(str(ws["workspace_path"])).name
        else:
            ws["workspace_path_display"] = ws["workspace_path"]
        try:
            ws["local_git_remotes"] = read_local_git_remotes(Path(str(ws["workspace_path"])))
        except Exception:
            ws["local_git_remotes"] = None

    if redact:
        ws["branch_count"] = len(ws["manifests"][0].get("branches", [])) if ws["manifests"] else 0
        for m in ws["manifests"]:
            m["branches"] = [hashlib.sha1(b.encode()).hexdigest()[:8] for b in m.get("branches", [])]
            m["remotes"] = [hashlib.sha1(b.encode()).hexdigest()[:8] for b in m.get("remotes", [])]
            m["worktrees"] = [hashlib.sha1(b.encode()).hexdigest()[:8] for b in m.get("worktrees", [])]
            m["sensitive"] = [
                dict(s, path="…/" + Path(s["path"]).name) for s in m.get("sensitive", [])
            ]
        for e in ws["extra_manifests"]:
            for i in e.get("included", []):
                if i.get("path"):
                    i["path"] = "…/" + Path(str(i["path"])).name
    return ws


def user_data_candidates(home, plat):
    """Electron userData dir per platform -- product name is probed, not assumed."""
    out = []
    if plat == "windows":
        for var in ("APPDATA", "LOCALAPPDATA"):
            base = (os.environ.get(var) or "").strip()
            if base:
                for name in PRODUCT_NAMES:
                    out.append((Path(base) / name, f"%{var}%\\{name}"))
    elif plat == "macos":
        for name in PRODUCT_NAMES:
            out.append((home / "Library" / "Application Support" / name, f"~/Library/Application Support/{name}"))
    else:
        for name in PRODUCT_NAMES:
            out.append((home / ".config" / name, f"~/.config/{name}"))
            out.append((home / ".config" / name.lower(), f"~/.config/{name.lower()}"))
    return _dedup_pairs(out)


def resolve_user_data_dir(home, plat):
    """Prefer a name match, but also accept a sibling Chromium profile so a
    product rename does not silently disable this check."""
    cands = user_data_candidates(home, plat)
    for d, how in cands:
        try:
            if d.is_dir() and ((d / ".updaterId").exists() or (d / "session" / "Local Storage").is_dir()):
                return d, how + "（含 Chromium 配置特征）"
        except OSError:
            continue
    for d, how in cands:
        try:
            if d.is_dir():
                return d, how + "（仅目录存在）"
        except OSError:
            continue
    return None, None


def collect_aux(data_dir: Path, ctx: Ctx, home=None, plat=None):
    aux = {"data_dir": str(data_dir), "exists": data_dir.is_dir()}
    v2 = data_dir / "v2"
    setting = read_json(v2 / "setting.json")
    if isinstance(setting, dict):
        aux["settings"] = {
            k: setting.get(k)
            for k in (
                "optimizeAgentExperienceEnabled",
                "repoSnapshotIndexingEnabled",
                "repoSnapshotIndexingUserConfigured",
                "modelIoFullRetentionEnabled",
                "instantGrepIndexingEnabled",
                "memoryEnabled",
            )
            if k in setting
        }
        aux["recent_projects"] = setting.get("recentProjects") or []
        sessions = []
        for s in setting.get("lastWorkspaceSession") or []:
            if isinstance(s, dict):
                sessions.append(
                    {
                        "kind": s.get("kind"),
                        "workspacePath": s.get("workspacePath"),
                        "remote": bool(str(s.get("workspaceIdentity") or "").strip()),
                        "purpose": s.get("workspacePurpose"),
                    }
                )
        aux["sessions"] = sessions
    cred = read_json(v2 / "credentials.json")
    if isinstance(cred, dict):
        aux["credential_keys"] = sorted(cred.keys())
        aux["login_token_present"] = any(
            re.search(r"(jwt|access_token|oauth:active_provider)", k) for k in cred
        )
    aux["checkpoints_present"] = (v2 / "checkpoints").exists()
    aux["certs"] = [str(p) for p in (v2 / "certs").glob("*")] if (v2 / "certs").is_dir() else []
    aux["appdata_client_dir"], aux["appdata_client_how"] = (None, None)
    if home is not None:
        d, how = resolve_user_data_dir(home, plat or real_platform())
        aux["appdata_client_dir"], aux["appdata_client_how"] = (str(d) if d else None, how)
    aux["log_dates"] = []
    logs = v2 / "logs"
    if logs.is_dir():
        aux["log_dates"] = sorted(p.stem for p in logs.glob("*.log"))[-10:]
    return aux


def collect_log_mentions(data_dir: Path, ctx: Ctx):
    """Cheap textual corroboration. Counts only, never dump content."""
    pats = {
        "git-checkpoint 通道": re.compile(r"git-checkpoint"),
        "repo-wiki": re.compile(r"repo-wiki"),
        "repo-snapshot-upload 日志": re.compile(r"repo-snapshot-upload"),
        "upload-credential 请求": re.compile(r"snapshot/upload-credential"),
        "zcode.z.ai": re.compile(r"zcode\.z\.ai"),
    }
    out = {k: 0 for k in pats}
    roots = [data_dir / "v2" / "logs", data_dir / "cli" / "log"]
    for root in roots:
        if not root.is_dir():
            continue
        for f in sorted(root.glob("*")):
            if not f.is_file() or f.stat().st_size > 40 * 1024 * 1024:
                continue
            txt = None
            try:
                txt = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for k, p in pats.items():
                out[k] += len(p.findall(txt))
    return out


def detect_processes():
    try:
        if platform.system() == "Windows":
            r = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq ZCode.exe", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            n = len([l for l in r.stdout.splitlines() if "ZCode" in l])
            return {"running": n > 0, "count": n}
        r = subprocess.run(["ps", "-A", "-o", "comm"], capture_output=True, text=True, timeout=20)
        n = len([l for l in r.stdout.splitlines() if "ZCode" in l or "zcode" in l])
        return {"running": n > 0, "count": n}
    except Exception:
        return {"running": None, "count": None}


# --------------------------------------------------------------------------
# verdict
# --------------------------------------------------------------------------
def decide(doc):
    ws_list = doc["workspaces"]
    sig = doc["signatures"]
    aux = doc["aux"]
    scanned = bool(sig.get("scanned"))
    feature = (sig.get("mechanism_hits") or 0) >= 3
    invariant = sig.get("semantic_invariant")
    token = bool(aux.get("login_token_present"))
    has_local = bool(ws_list) or bool(aux.get("checkpoints_present"))

    uploaded = [w for w in ws_list if w.get("accepted_hash") and not w.get("pending")]
    pending = [w for w in ws_list if w.get("pending") or w.get("in_state_upload")]
    captured = [w for w in ws_list if w.get("manifests")]

    reasons, falsifiers = [], []
    # Local physical evidence outranks the code-signature interpreter: if the
    # client build cannot be resolved (drift / custom install), the evidence
    # still stands -- we only lose the ability to *interpret* it, so we
    # downgrade confidence instead of falling back to a clean verdict.
    if uploaded:
        code, conf = "UPLOADED", "high" if invariant == "verified-heuristic" else "medium"
        for w in uploaded:
            reasons.append(
                f"工作区 {w.get('workspace_path_display') or w['key']}：state.json 记录了 "
                f"lastAcceptedManifestHash={str(w.get('accepted_hash'))[:16]}…，且 pending/ 为空。"
            )
        reasons.append(
            "按客户端代码，lastAcceptedManifestHash 只在 OSS PostObject 返回 2xx 之后由 markAcceptedManifest 写入。"
        )
        if invariant == "verified-heuristic":
            reasons.append(
                f"本机客户端静态检查：markAcceptedManifest 与 uploadObject 的最近距离 {sig.get('semantic_distance')}B，"
                "支持「accepted = 上传成功」这条不变式（启发式）。"
            )
        else:
            falsifiers.append("该版本未能静态验证「accepted = 上传成功」，结论降级为 medium。")
            doc["warnings"].append("语义不变式未通过静态检查，verdict 置信度已降级。")
        falsifiers.append("若能证明该版本存在不经过 uploadObject 的 markAcceptedManifest 调用点，则本条不成立。")
    elif pending:
        code, conf = "PACKED_PENDING", "high" if feature else "medium"
        reasons.append("存在尚未成功上传的加密产物（pending/ 或 state.json 内的 in-flight upload）。")
        falsifiers.append("产物可能属于已被服务端去重的对象，但本地无可靠旁证。")
    elif captured:
        code, conf = "CAPTURED_NOT_ACCEPTED", "medium"
        reasons.append("有清单产物但没有 accepted 记录：捕获发生过，上传结果未知。")
        falsifiers.append("若该工作区的 state.json 被外部工具重写/回滚，accepted 记录可能丢失。")
    elif has_local:
        code, conf = "INCONCLUSIVE", "low"
        reasons.append("存在机制运行痕迹（目录/配置），但关键状态文件缺失或为空。")
        reasons.append("注意：ZCode 退出时会清空 checkpoints 目录，因此「目录为空」不能推出「从未上传」。")
        falsifiers.append("需结合备份/文件系统日志确认 checkpoints 内容是否被删除，而非从未产生。")
    elif feature:
        code, conf = "NO_LOCAL_TRACE", "medium"
        reasons.append("客户端具备该机制，但本机没有任何工作区捕获产物。")
        falsifiers.append("若 ZCode 曾以其他系统账户运行，证据不在当前用户目录下。")
    else:
        code, conf = "FEATURE_ABSENT", "medium"
        reasons.append("既无本地捕获产物，安装目录的代码签名里也没有命中快照上传链路的关键字符串。")
        falsifiers.append("自定义安装路径未被探测到，请用 --install-dir 重跑；版本升级也可能改变签名。")

    if has_local and scanned and not feature:
        doc["warnings"].append(
            "本地存在捕获痕迹，但代码签名未命中关键机制字符串（可能版本漂移或非标准安装）：机制未经确认。"
        )
    if doc["processes"].get("running"):
        reasons.append("ZCode 当前正在运行，登录态下继续使用会再次触发捕获。")
    if token:
        reasons.append("credentials.json 中存在登录 token，机制处于激活条件。")
    else:
        reasons.append("未发现登录 token：上传链路当前不会被触发（历史记录仍然有效）。")

    return {
        "code": code,
        "label": VERDICTS[code][0],
        "confidence": conf,
        "reasons": reasons,
        "falsifiers": falsifiers,
        "affected_workspaces": [w.get("workspace_path_display") or w["key"] for w in ws_list],
    }


# --------------------------------------------------------------------------
# HTML report
# --------------------------------------------------------------------------
CSS = """
:root{--ink:#1f2328;--mut:#57606a;--line:#d8dee4;--bg:#f6f8fa;--acc:#0969da}
*{box-sizing:border-box}
body{margin:0;padding:32px 20px 80px;font:15px/1.65 -apple-system,"Segoe UI",Roboto,"Noto Sans SC",sans-serif;color:var(--ink);background:#fff}
main{max-width:1080px;margin:0 auto}
h1{font-size:24px;margin:0 0 4px}
h2{font-size:19px;margin:36px 0 12px;padding-bottom:6px;border-bottom:2px solid var(--line)}
h3{font-size:16px;margin:22px 0 8px}
.badge{display:inline-block;padding:6px 14px;border-radius:999px;color:#fff;font-weight:700;font-size:18px;margin-right:10px}
.meta{color:var(--mut);font-size:13px}
.tldr{background:var(--bg);border-left:5px solid var(--acc);padding:14px 18px;border-radius:6px;margin:18px 0}
table{border-collapse:collapse;width:100%;margin:10px 0;font-size:13.5px}
th,td{border:1px solid var(--line);padding:7px 10px;text-align:left;vertical-align:top}
th{background:var(--bg);font-weight:600}
tr.hit td{background:#fff5f5;font-weight:600}
tr.hit.meh td{background:#fff8e6}
code,kbd{background:var(--bg);padding:1px 5px;border-radius:4px;font-family:ui-monospace,Consolas,monospace;font-size:12.5px}
pre{background:#0d1117;color:#e6edf3;padding:14px 16px;border-radius:8px;overflow:auto;font-size:12.5px;line-height:1.5}
details{margin:8px 0}
summary{cursor:pointer;color:var(--acc)}
.card{border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:14px 0}
.card.warn{border-left:5px solid #d1242f;background:#fff8f8}
.kv{display:grid;grid-template-columns:200px 1fr;gap:4px 14px;font-size:13.5px}
.kv div:nth-child(odd){color:var(--mut)}
.bar{height:10px;background:var(--bg);border-radius:5px;overflow:hidden;min-width:80px}
.bar>i{display:block;height:100%;background:var(--acc)}
.pill{display:inline-block;background:var(--bg);border:1px solid var(--line);border-radius:999px;padding:1px 9px;margin:2px 4px 2px 0;font-size:12px}
.ok{color:#15803d;font-weight:600}.bad{color:#b91c1c;font-weight:600}.muted{color:var(--mut)}
ul{margin:6px 0 6px 20px;padding:0}
li{margin:3px 0}
footer{margin-top:50px;color:var(--mut);font-size:12.5px;border-top:1px solid var(--line);padding-top:14px}
@media print{body{padding:0}pre{background:#f6f8fa;color:#111}}
"""


def kv(rows):
    out = ["<div class='kv'>"]
    for k, v in rows:
        out.append(f"<div>{esc(k)}</div><div>{v if isinstance(v, str) and v.startswith('<') else esc(v)}</div>")
    out.append("</div>")
    return "".join(out)


def render_html(doc):
    v = doc["verdict"]
    label, color, meaning = VERDICTS[v["code"]]
    P = []
    P.append(f"<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>")
    P.append("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    P.append(f"<title>ZCode 上传取证报告 · {esc(label)}</title><style>{CSS}</style></head><body><main>")
    P.append("<h1>ZCode 工作区快照上传 · 取证报告</h1>")
    P.append(
        f"<div class='meta'>生成于 {esc(doc['generated_at'])} · {esc(doc['os']['system'])} {esc(doc['os']['release'])} "
        f"· 主机 {esc(doc['os']['host'])} · ZCode {esc(doc['client'].get('version') or '未知')} "
        f"· 采集脚本 v{esc(SKILL_VERSION)}</div>"
    )

    P.append(
        f"<div class='tldr' style='border-left-color:{color}'>"
        f"<span class='badge' style='background:{color}'>{esc(label)}</span>"
        f"<span class='muted'>verdict=<code>{esc(v['code'])}</code> · 置信度 {esc(v['confidence'])}</span>"
        f"<p style='margin:10px 0 0'>{esc(meaning)}</p></div>"
    )

    P.append("<h2>一、结论与依据</h2><ul>")
    for r in v["reasons"]:
        P.append(f"<li>{esc(r)}</li>")
    P.append("</ul>")
    if v["falsifiers"]:
        P.append("<h3>可以推翻本结论的条件（falsifiers）</h3><ul class='muted'>")
        for r in v["falsifiers"]:
            P.append(f"<li>{esc(r)}</li>")
        P.append("</ul>")

    P.append("<h2>二、判定表命中行</h2><table><tr><th>verdict</th><th>机制存在</th><th>accepted hash</th><th>pending 密文</th><th>清单产物</th></tr>")
    for code, a, b, c, d in TRUTH_TABLE:
        cls = ""
        if code == v["code"]:
            cls = " class='hit" + ("" if v["confidence"] == "high" else " meh") + "'"
        mark = " ← 命中" if code == v["code"] else ""
        P.append(
            f"<tr{cls}><td><code>{esc(code)}</code> {esc(VERDICTS[code][0])}{mark}</td>"
            f"<td>{esc(a)}</td><td>{esc(b)}</td><td>{esc(c)}</td><td>{esc(d)}</td></tr>"
        )
    P.append("</table>")

    # --- workspaces ---
    P.append("<h2>三、工作区证据</h2>")
    if not doc["workspaces"]:
        P.append("<p class='muted'>未发现任何工作区快照目录。</p>")
    for w in doc["workspaces"]:
        cls = "card warn" if (w.get("accepted_hash") or w.get("pending")) else "card"
        P.append(f"<div class='{cls}'><h3>{esc(w.get('workspace_path_display') or w['key'])}</h3>")
        st = w.get("state") or {}
        P.append(
            kv(
                [
                    ("checkpoints key", f"<code>{esc(w['key'])}</code>"),
                    ("state.json 写入时间", esc(iso(w.get("state_mtime")))),
                    ("accepted manifest hash", (f"<code>{esc(str(w.get('accepted_hash'))[:16])}…</code>" + " <span class='bad'>← 已通过上传落账</span>") if w.get("accepted_hash") else "<span class='muted'>无</span>"),
                    ("失败重试计数 failureCount", esc(st.get("failureCount", "–"))),
                    ("pending 密文", ("<span class='bad'>" + ", ".join(f"{esc(p['file'])} ({hum(p['bytes'])})" for p in w["pending"]) + "</span>") if w["pending"] else "<span class='ok'>空</span>"),
                    ("state 内 in-flight", esc((w.get("in_state_upload") or {}).get("kind") or "–")),
                ]
            )
        )
        lc = w.get("last_compressed") or {}
        if lc:
            P.append(
                "<h3>最近一次打包记录 <code>lastCompressedSize</code></h3>"
                + kv(
                    [
                        ("加密产物", f"{hum(lc.get('encryptedSizeBytes'))}（{esc(lc.get('encryptedSizeBytes'))} B）"),
                        ("清单体积 workspaceSize", f"{hum(lc.get('workspaceSizeBytes'))}（{esc(lc.get('workspaceSizeBytes'))} B）"),
                        ("manifestHash", f"<code>{esc(str(lc.get('manifestHash'))[:16])}…</code>"),
                        ("recordedAt", esc(iso((lc.get("recordedAt") or 0) / 1000))),
                    ]
                )
            )
            if w.get("ratio_hint"):
                P.append(f"<p>⚠️ {esc(w['ratio_hint'])}</p>")

        for m in w["manifests"]:
            P.append(
                f"<h3>清单 <code>{esc(m['file'][:16])}…</code></h3>"
                + kv(
                    [
                        ("文件数 / 体积", f"{esc(m.get('manifest_files'))} 个 / {hum(m.get('bytes'))}"),
                        ("清单生成时间", esc(iso((m.get("createdAt") or 0) / 1000))),
                        ("工作区", esc(m.get("workspaceKey"))),
                        (".git 相关文件数", f"objects 等 {esc(m['git_counts']['git'])} 个（其中 reflog {esc(m['git_counts']['reflog'])}、refs {esc(m['git_counts']['refs'])}、worktree {esc(m['git_counts']['worktree'])}）"),
                        ("分支数 / worktree 数", f"{esc(len(m.get('branches') or []))} / {esc(len(m.get('worktrees') or []))}"),
                    ]
                )
            )
            if m.get("top_groups"):
                P.append("<table><tr><th>目录 / 分组</th><th>体积</th><th>占比</th><th></th></tr>")
                for g in m["top_groups"][:12]:
                    P.append(
                        f"<tr><td><code>{esc(g['name'])}</code></td><td>{hum(g['bytes'])}</td>"
                        f"<td>{g['pct']:.1f}%</td><td><span class='bar' style='width:120px;display:inline-block'><i style='width:{min(g['pct'],100):.1f}%'></i></span></td></tr>"
                    )
                P.append("</table>")
            if m.get("branches"):
                P.append(
                    "<details><summary>被打包的分支名（" + str(len(m["branches"])) + "）</summary><p>"
                    + "".join(f"<span class='pill'>{esc(b)}</span>" for b in m["branches"][:200])
                    + "</p></details>"
                )
            if m.get("worktrees"):
                P.append(
                    "<details><summary>worktree（" + str(len(m["worktrees"])) + "）</summary><p>"
                    + "".join(f"<span class='pill'>{esc(b)}</span>" for b in m["worktrees"])
                    + "</p></details>"
                )
            if m.get("sensitive"):
                P.append("<h4>敏感模式命中（只列路径，不读取内容）</h4><table><tr><th>类别</th><th>路径</th><th>体积</th></tr>")
                for s in m["sensitive"][:60]:
                    P.append(f"<tr><td>{esc(s['kind'])}</td><td><code>{esc(s['path'])}</code></td><td>{hum(s['sizeBytes'])}</td></tr>")
                P.append("</table>")

        if w.get("local_git_remotes"):
            P.append("<h4>本地 <code>.git/config</code> 对照（清单只带体积，这里是内容参照）</h4><ul>")
            for r in w["local_git_remotes"]:
                P.append(f"<li><code>{esc(r['name'])}</code> → <code>{esc(r['url'])}</code></li>")
            P.append("</ul>")

        for e in w["extra_manifests"]:
            P.append(f"<h4>随包上传的全局配置 <code>{esc(e['file'][:12])}…</code></h4>")
            if e.get("included"):
                P.append("<table><tr><th>分组</th><th>文件</th><th>来源</th></tr>")
                for i in e["included"]:
                    P.append(
                        f"<tr><td>{esc(EXTRA_MANIFEST_GROUPS.get(i.get('groupId'), i.get('groupId')))}</td>"
                        f"<td><code>{esc(i.get('path'))}</code></td><td class='muted'>{esc(i.get('source'))}</td></tr>"
                    )
                P.append("</table>")
        for wn in w.get("warnings", []):
            P.append(f"<p class='bad'>⚠️ {esc(wn)}</p>")
        P.append("</div>")

    # --- detection ledger (proves nothing is hardcoded) ---
    det = doc.get("detection") or {}
    P.append("<h2>四、路径探测依据（无硬编码）</h2>")
    P.append(
        kv(
            [
                ("目标平台", f"<code>{esc(det.get('platform'))}</code>（{esc(det.get('platform_source'))}）"),
                ("用户主目录", f"<code>{esc(det.get('home'))}</code>（{esc(det.get('home_source'))}）"),
                ("数据根目录", f"<code>{esc(det.get('data_dir'))}</code> —— {esc(det.get('data_dir_how'))}"),
                ("checkpoints", f"<code>{esc(det.get('checkpoints'))}</code>"),
                ("安装目录", f"<code>{esc(doc['client'].get('install_dir'))}</code> —— {esc(doc['client'].get('install_how'))}"),
                ("Electron userData", f"<code>{esc((doc.get('aux') or {}).get('appdata_client_dir'))}</code> —— {esc((doc.get('aux') or {}).get('appdata_client_how'))}"),
            ]
        )
    )
    tried = doc["client"].get("candidates_tried") or []
    P.append(
        f"<details><summary>已探测的安装位置候选（{len(tried)} 个，前 40）</summary>"
        "<table><tr><th>路径</th><th>来源</th></tr>"
    )
    for c in tried[:40]:
        P.append(f"<tr><td><code>{esc(c['path'])}</code></td><td class='muted'>{esc(c['how'])}</td></tr>")
    P.append("</table></details>")

    # --- client code ---
    sig = doc["signatures"]
    P.append("<h2>五、客户端代码签名（语义验证）</h2>")
    P.append(
        kv(
            [
                ("扫描目标", f"<code>{esc(sig.get('target'))}</code>（{hum(sig.get('target_bytes'))}，mtime {esc(iso(sig.get('target_mtime')))})"),
                ("扫描状态", "已完成" if sig.get("scanned") else f"未完成：{esc(sig.get('note'))}"),
                ("gate 词命中", {True: "<span class='bad'>是</span>", False: "<span class='ok'>否</span>", None: "–"}[sig.get("gate_hit")]),
                ("机制签名命中", f"{esc(sig.get('mechanism_hits'))} / {esc(sig.get('mechanism_total'))}"),
                ("语义不变式", {"verified-heuristic": f"<span class='bad'>已支持（邻近 {esc(sig.get('semantic_distance'))}B，启发式）</span>", "pair-present-far-apart": "成对出现但距离过远", "unverified": "<span class='muted'>未验证</span>"}[sig.get("semantic_invariant")]),
            ]
        )
    )
    if sig.get("counts"):
        P.append("<details><summary>逐条签名命中次数</summary><table><tr><th>签名</th><th>命中</th></tr>")
        for k, c in sorted(sig["counts"].items(), key=lambda x: -x[1]):
            P.append(f"<tr><td><code>{esc(k)}</code></td><td>{esc(c)}</td></tr>")
        P.append("</table></details>")

    # --- aux ---
    aux = doc["aux"]
    P.append("<h2>六、辅助痕迹</h2>")
    P.append(
        kv(
            [
                ("数据目录", f"<code>{esc(aux.get('data_dir'))}</code>"),
                ("登录 token", "<span class='bad'>存在（机制处于激活条件）</span>" if aux.get("login_token_present") else "<span class='muted'>未发现</span>"),
                ("客户端进程", ("<span class='bad'>运行中</span>" if doc["processes"].get("running") else "未运行") if doc["processes"].get("running") is not None else "未知"),
                (
                    "checkpoints 写权限",
                    "<span class='ok'>已锁定（写探针被拒）</span>"
                    if (doc.get("lock_state") or {}).get("locked")
                    else "<span class='bad'>可写 —— 尚未阻断</span>",
                ),
                ("optimizeAgentExperienceEnabled", esc((aux.get("settings") or {}).get("optimizeAgentExperienceEnabled"))),
                ("repoSnapshotIndexingEnabled", esc((aux.get("settings") or {}).get("repoSnapshotIndexingEnabled"))),
                ("本地 CA", esc(", ".join(aux.get("certs") or []) or "无")),
            ]
        )
    )
    if aux.get("sessions"):
        P.append("<h4>工作区注册表（lastWorkspaceSession）</h4><table><tr><th>类型</th><th>路径</th><th>远程</th></tr>")
        for s in aux["sessions"]:
            # NOTE: keep the conditional outside the f-string -- a backslash inside
            # an f-string expression is a SyntaxError before Python 3.12 (PEP 701),
            # and macOS ships system python3 3.9.
            remote_txt = (
                '<span class="muted">远程（本机客户端不落快照）</span>'
                if s.get("remote")
                else "本地（会落快照）"
            )
            P.append(
                f"<tr><td>{esc(s.get('kind'))}</td><td><code>{esc(s.get('workspacePath'))}</code></td>"
                f"<td>{remote_txt}</td></tr>"
            )
        P.append("</table>")
    if doc.get("log_mentions"):
        P.append("<h4>日志计数（只统计，不转储内容）</h4><table><tr><th>模式</th><th>出现次数</th></tr>")
        for k, c in doc["log_mentions"].items():
            P.append(f"<tr><td>{esc(k)}</td><td>{esc(c)}</td></tr>")
        P.append("</table>")

    # --- timeline ---
    P.append("<h2>七、证据时间线</h2><table><tr><th>时间</th><th>事件</th></tr>")
    for t, lbl in sorted(doc["timeline"])[::-1][:40]:
        P.append(f"<tr><td>{esc(iso(t))}</td><td>{esc(lbl)}</td></tr>")
    P.append("</table>")

    # --- remediation ---
    P.append("<h2>八、处置建议</h2>")
    P.append(
        "<p>默认只打印命令。<b>加锁是可逆的</b>：先隔离证据目录、再施加不可写锁，随时可用 "
        "<code>--unlock</code> 恢复。加锁前请先退出 ZCode，否则文件被占用。</p>"
    )
    for plat, cmds in lock_commands(doc["detection"]["platform"], doc["detection"]["checkpoints"]).items():
        P.append(f"<h4>{esc(plat)}</h4><pre>{esc(cmds)}</pre>")
    P.append(
        "<p class='muted'>已验证过的收尾方式：<code>python diagnose.py --apply-lock</code>"
        "（隔离 + 加锁 + 写探针验证）与 <code>--unlock</code>（恢复）。</p>"
    )
    P.append(
        "<h3>事件响应口径</h3><ul>"
        "<li>已上传的密文<b>不可撤回</b>：解密钥由服务端下发、私钥只在云端，本地无法解密也无法撤回。</li>"
        "<li>按「源码 + 完整 Git 历史已外泄」评估：轮换历史上出现过的 token / 密码 / 内部地址凭据。</li>"
        "<li>检查 <code>.git/config</code> 里的内部 remote 主机名与私有仓库路径是否可用于横向定位。</li>"
        "<li>继续使用前先加锁；如需彻底隔离，改用独立账户或虚拟机运行 ZCode。</li>"
        "</ul>"
    )

    # --- unknown / appendix ---
    P.append("<h2>九、未能确定的部分</h2><ul>")
    for w in doc["warnings"]:
        P.append(f"<li>⚠️ {esc(w)}</li>")
    for e in doc["errors"]:
        P.append(f"<li>采集错误（{esc(e['where'])}）：<code>{esc(e['error'])}</code></li>")
    if not doc["warnings"] and not doc["errors"]:
        P.append("<li class='muted'>无</li>")
    P.append("</ul>")

    P.append("<h2>十、附录：复现命令</h2><pre>")
    P.append(esc(doc["reproduce"]))
    P.append("</pre>")

    P.append(
        "<footer>本报告由 <code>zcode-upload-forensics</code> 生成，数据全部来自本机文件系统，"
        "未联网、未解密、未读取工作区文件内容。<b>报告包含仓库路径、分支名与内部主机名，请勿提交仓库或外发。</b></footer>"
    )
    P.append("</main></body></html>")
    return "".join(P)


# --------------------------------------------------------------------------
# locking
# --------------------------------------------------------------------------
def lock_platform_key(plat):
    return {"windows": "Windows", "macos": "macOS"}.get(plat, "Linux")


def lock_commands(plat, cp_path):
    """Remediation commands bound to the *detected* paths, so they stay correct
    for non-default data dirs, other user names and cross-inspection."""
    cp = str(cp_path)
    if plat == "windows":
        return {
            "推荐（脚本内置，可验证）": "python diagnose.py --apply-lock",
            "手工（icacls 拒绝写入）": (
                f'rmdir /s /q "{cp}"\n'
                f'mkdir "{cp}"\n'
                f'icacls "{cp}" /inheritance:r '
                '/grant:r "%USERNAME%:(OI)(CI)(RX)" /grant:r "SYSTEM:(OI)(CI)(F)" '
                '/grant:r "Administrators:(OI)(CI)(F)"\n'
                ":: 验证：应当报“拒绝访问”\n"
                f'echo x > "{cp}\\probe"'
            ),
            "恢复": f'icacls "{cp}" /reset /T',
        }
    if plat == "macos":
        return {
            "推荐": "python diagnose.py --apply-lock",
            "手工": f'chflags uchg "{cp}"   # 验证：touch 该目录下文件应报 Operation not permitted',
            "恢复": f'chflags nouchg "{cp}"',
        }
    return {
        "推荐": "python diagnose.py --apply-lock",
        "手工": f'sudo chattr +i "{cp}"   # 验证：touch 该目录下文件应报 Operation not permitted',
        "恢复": f'sudo chattr -i "{cp}"',
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
    return True, "写入成功"


def verify_lock(cp: Path, ctx: Ctx):
    if not cp.exists():
        return {"locked": None, "detail": "checkpoints 目录不存在"}
    cp.mkdir(parents=True, exist_ok=True)
    ok, detail = _write_probe(cp)
    return {"locked": not ok, "detail": detail}


def apply_lock(data_dir: Path, ctx: Ctx, assume_yes: bool, force: bool):
    cp = data_dir / "v2" / "checkpoints"
    log = []
    proc = detect_processes()
    if proc.get("running") and not force:
        log.append(f"检测到 ZCode 正在运行（{proc.get('count')} 个进程）。请先完全退出 ZCode，或用 --force 强制继续。")
        return {"ok": False, "log": log, "proc": proc}

    v2 = data_dir / "v2"
    v2.mkdir(parents=True, exist_ok=True)
    if cp.exists():
        ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        q = v2 / f"checkpoints-quarantine-{ts}"
        try:
            shutil.move(str(cp), str(q))
            log.append(f"证据目录已隔离到：{q}（保留全部 .enc / state.json，随时可回查或删除）")
        except Exception as exc:
            ctx.error("quarantine", exc)
            log.append(f"隔离失败：{exc}")
            return {"ok": False, "log": log, "proc": proc}
    else:
        log.append("未发现 checkpoints 目录，直接创建空目录后加锁。")

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
            log.append(f"icacls 以 {user} 授权失败，回退到裸用户名重试")
            grants[3] = f"{user.split(chr(92))[-1]}:(OI)(CI)(RX)"
            code, out = _run(grants, ctx)
        log.append(f"icacls 授权（{user} 只读）-> rc={code} {out.strip()[:200]}")
    elif system == "macos":
        code, out = _run(["chflags", "uchg", str(cp)], ctx)
        log.append(f"chflags uchg -> rc={code} {out.strip()[:200]}")
    else:
        code, out = _run(["chattr", "+i", str(cp)], ctx)
        if code != 0:
            log.append("chattr +i 失败（通常需要 root）：请用 sudo 重跑，或改用 ACL。")
        log.append(f"chattr +i -> rc={code} {out.strip()[:200]}")

    check = verify_lock(cp, ctx)
    log.append(
        f"写探针验证：{'✅ 已阻断写入' if check['locked'] else '❌ 仍可写入 —— 阻断未生效'}（{check['detail']}）"
    )
    return {"ok": bool(check["locked"]), "log": log, "verify": check, "proc": proc}


def unlock(data_dir: Path, ctx: Ctx):
    cp = data_dir / "v2" / "checkpoints"
    log = []
    if not cp.exists():
        return {"ok": False, "log": ["checkpoints 目录不存在"]}
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
    log.append(f"写探针验证：{'仍可写入 ✅ 已恢复' if not check['locked'] else '❌ 仍不可写'}（{check['detail']}）")
    for q in sorted((data_dir / "v2").glob("checkpoints-quarantine-*")):
        log.append(f"待处理隔离目录：{q}（确认无需取证后可删除）")
    return {"ok": not check["locked"], "log": log}


# --------------------------------------------------------------------------
# diff
# --------------------------------------------------------------------------
def diff_reports(prev_path: Path, doc, ctx: Ctx):
    prev = read_json(prev_path)
    if not isinstance(prev, dict):
        return [f"无法读取上一次报告：{prev_path}"]
    out = []
    if prev.get("verdict", {}).get("code") != doc["verdict"]["code"]:
        out.append(
            f"verdict 变化：{prev.get('verdict', {}).get('code')} → {doc['verdict']['code']}"
        )
    pmap = {w.get("key"): w for w in prev.get("workspaces") or []}
    for w in doc["workspaces"]:
        p = pmap.get(w["key"])
        if not p:
            out.append(f"新增工作区：{w.get('workspace_path_display') or w['key']}")
            continue
        if p.get("accepted_hash") != w.get("accepted_hash"):
            out.append(
                f"{w['key']}：accepted hash {str(p.get('accepted_hash'))[:12]} → {str(w.get('accepted_hash'))[:12]}（新增一次成功上传）"
            )
        if p.get("failure_count") != w.get("failure_count"):
            out.append(f"{w['key']}：failureCount {p.get('failure_count')} → {w.get('failure_count')}")
        if len(p.get("pending") or []) != len(w.get("pending") or []):
            out.append(f"{w['key']}：pending 数量 {len(p.get('pending') or [])} → {len(w.get('pending') or [])}")
        if (p.get("state_mtime") or 0) != (w.get("state_mtime") or 0):
            out.append(f"{w['key']}：state.json 更新 {iso(p.get('state_mtime'))} → {iso(w.get('state_mtime'))}")
    if prev.get("client", {}).get("version") != doc["client"].get("version"):
        out.append(
            f"客户端版本变化：{prev.get('client', {}).get('version')} → {doc['client'].get('version')}（签名结论需复核）"
        )
    return out or ["与上一次报告相比，没有发现变化。"]


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
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
        "generated_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S %z"),
        "detection": {
            "platform": plat,
            "platform_source": "--platform 覆盖" if str(getattr(args, "platform", "auto")) != "auto" else "platform.system() 自动探测",
            "home": str(home),
            "home_source": "--home 指定" if getattr(args, "home", None) else "USERPROFILE/HOME 环境变量",
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
            timeline.append((w["state_mtime"], f"[{w['key']}] state.json 写入"))
        for m in w["manifests"]:
            timeline.append((m.get("createdAt", 0) / 1000 or m.get("mtime"), f"[{w['key']}] 清单落盘"))
        for e in w["extra_manifests"]:
            timeline.append((e.get("createdAt", 0) / 1000 or e.get("mtime"), f"[{w['key']}] 全局配置清单落盘"))
        for p in w["pending"]:
            timeline.append((p.get("mtime"), f"[{w['key']}] 待传密文 {p['file']}"))
    doc["timeline"] = [(t, l) for t, l in timeline if t]

    doc["verdict"] = decide(doc)
    doc["lock_state"] = verify_lock(cp_root, ctx)
    doc["reproduce"] = (
        f"# 采集脚本（只读）\n"
        f"python {Path(__file__).name} --redact --json report.json\n\n"
        f"# 手工复核关键点\n"
        f'find "{data_dir / "v2" / "checkpoints"}" -name state.json -exec grep -H lastAcceptedManifestHash {{}} \\;\n'
        f'grep -a -c "snapshot/upload-credential" "{client.get("asar") or "<app.asar>"}"\n'
        f'grep -a -o "markAcceptedManifest" "{client.get("asar") or "<app.asar>"}" | wc -l'
    )
    return doc


def main(argv=None):
    if sys.version_info < (3, 9):
        print(
            f"本脚本需要 Python 3.9+（当前 {platform.python_version()}）；请用较新的解释器运行。",
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
                f"--platform={plat} 与真实系统 {real_platform()} 不一致：路径探测可以跨系统，加锁/解锁必须在本机上执行。",
                file=sys.stderr,
            )
            return 2

    if args.verify_lock:
        r = verify_lock(data_dir / "v2" / "checkpoints", ctx)
        print(json.dumps(r, ensure_ascii=False, indent=2))
        return 0 if r["locked"] else 1

    if args.unlock:
        if not (args.yes or sys.stdin.isatty()):
            print("非交互环境，请追加 --yes 确认。", file=sys.stderr)
            return 2
        if not args.yes and input("将恢复 checkpoints 目录的写权限，继续？[y/N] ").strip().lower() != "y":
            print("已取消。")
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
    print(f"verdict : {v['code']} ({EN_LABELS.get(v['code'], '')}) confidence={v['confidence']}")
    print(f"HTML    : {out.resolve()}")
    if json_path:
        print(f"JSON    : {json_path.resolve()}")
    if args.diff:
        print("\n== 与上一次报告对比 ==")
        for line in diff_reports(Path(args.diff), doc, ctx):
            print(f"  - {line}")
    for w in doc["warnings"]:
        print(f"warning : {w}")
    for e in doc["errors"]:
        print(f"error   : {e['where']}: {e['error']}")

    if args.apply_lock:
        print("\n-- 即将隔离并锁定 checkpoints 目录 --")
        print(f"目标：{data_dir / 'v2' / 'checkpoints'}")
        print("影响：ZCode 的「检查点回滚 / 时间线」功能将不可用；补全、对话、工具调用不受影响。可用 --unlock 恢复。")
        if not args.yes:
            if not sys.stdin.isatty():
                print("非交互环境，请追加 --yes 确认；本次未执行加锁。", file=sys.stderr)
                return 2
            if input("确认执行？[y/N] ").strip().lower() != "y":
                print("已取消加锁。")
                return 0
        r = apply_lock(data_dir, ctx, args.yes, args.force)
        for line in r["log"]:
            print(f"  {line}")
        print("✅ 已阻断" if r["ok"] else "❌ 阻断未生效，请查看上面的输出")
        return 0 if r["ok"] else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
