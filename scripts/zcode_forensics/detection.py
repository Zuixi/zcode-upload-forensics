"""Path, install and payload discovery (no hardcoded paths)."""

from __future__ import annotations

from pathlib import Path
import json
import os
import platform
import shutil
import subprocess

from .messages import tr

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
        return [(Path(args.zcode_dir).expanduser(), tr("m070"))]
    for k in DATA_DIR_ENV:
        v = (os.environ.get(k) or "").strip()
        if v:
            out.append((Path(v).expanduser(), tr("m100", p0=k)))
    out.append((home / ".zcode", tr("m033", p0=home)))
    if plat == "linux":
        # WSL inspecting the Windows side of the same machine
        mnt = Path("/mnt/c/Users")
        try:
            if mnt.is_dir():
                for u in sorted(mnt.iterdir()):
                    if (u / ".zcode").is_dir():
                        out.append((u / ".zcode", tr("m164", p0=u)))
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
    return cands[0][0], cands[0][1] + tr("m034")


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
                                        out.append((cand, tr("m178", p0=disp, p1=value)))
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
                out.append((Path(found).resolve().parent, tr("m131", p0=name)))
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
                    return Path(line), tr("m132")
            return None, None
        proc = Path("/proc")
        if proc.is_dir():
            for entry in proc.glob("[0-9]*/exe"):
                try:
                    target = os.readlink(entry)
                except OSError:
                    continue
                if "zcode" in target.lower():
                    return Path(target), tr("m133")
        r = subprocess.run(["ps", "-Ao", "comm="], capture_output=True, text=True, timeout=20)
        for line in (r.stdout or "").splitlines():
            s = line.strip()
            if s and Path(s).name.lower().startswith("zcode"):
                return Path(s), tr("m101")
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
        return [(Path(args.install_dir).expanduser(), tr("m071"))]
    out = []
    for k in INSTALL_ENV:
        v = (os.environ.get(k) or "").strip()
        if v:
            out.append((Path(v).expanduser(), tr("m100", p0=k)))
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
        (home / ".zcode" / "computer-use", tr("m035")),
        (home / ".zcode" / "v2" / "computer-use", tr("m035")),
    ]
    if data_dir is not None and data_dir != home / ".zcode":
        out += [
            (data_dir / "computer-use", tr("m035")),
            (data_dir / "v2" / "computer-use", tr("m035")),
        ]
    if data_dir is not None:
        # remote-host / runtime assets ZCode pushes to a machine that may have no
        # desktop client at all -- on such a host this is the only copy of the code
        out.append((data_dir / "server", tr("m072")))
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
                return d, how + tr("m134")
        except OSError:
            continue
    for d, how in cands:
        try:
            if d.is_dir():
                return d, how + tr("m135")
        except OSError:
            continue
    return None, None

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
