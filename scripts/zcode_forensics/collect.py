"""Evidence collection from the data directory."""

from __future__ import annotations

from pathlib import Path
import hashlib
import re

from .constants import SENSITIVE_PATTERNS
from .detection import real_platform, resolve_user_data_dir
from .messages import tr
from .util import Ctx, fname, iso, mt, read_json, read_text

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
        ws["warnings"].append(tr("m036"))
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
                tr("m074", p0=iso(mt(md)), p1=iso(ws['state_mtime']))
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
                tr("m037", p0=format(ratio, ".3f"))
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
        tr("m005"): re.compile(r"git-checkpoint"),
        "repo-wiki": re.compile(r"repo-wiki"),
        tr("m006"): re.compile(r"repo-snapshot-upload"),
        tr("m007"): re.compile(r"snapshot/upload-credential"),
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
