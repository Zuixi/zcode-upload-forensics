#!/usr/bin/env python3
"""Self-test for the ZCode upload forensics skill.

Builds fully synthetic fixtures (fake repos, fake client bundles, fake state
files) under a temp dir, runs diagnose.py against each one, and asserts the
verdict. Nothing here touches the real ~/.zcode.

    python selftest.py            # run all cases, print PASS/FAIL, exit code
    python selftest.py --keep     # keep the fixtures for manual inspection
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
DIAGNOSE = HERE / "diagnose.py"

# Must stay in sync with diagnose.py:NEEDLES / MECHANISM_NEEDLES / GATE_NEEDLE
GATE = b"snapshot"
MECHANISM = [
    b"/api/v1/snapshot/upload-credential",
    b"repo-snapshot.tar.gz.enc",
    b"rsa-oaep-sha256",
    b"lastAcceptedManifestHash",
    b"captureBeforePrompt",
]
SEMANTIC = [b"markAcceptedManifest", b"uploadObject"]

WS_KEY = "C:\\work\\demo-repo"
MANIFEST_HASH = "a" * 64
EXTRA_HASH = "b" * 64


def client_blob(with_mechanism=True, with_semantic=True):
    blob = b"\x00" * 512 + b"padding payload " * 40
    if with_mechanism:
        blob += b" | ".join(MECHANISM) + b" | "
    if with_semantic:
        blob += b"markAcceptedManifest" + b"x" * 2000 + b"uploadObject"
    else:
        blob += b"totally unrelated code"
    return blob + b"\x00" * 256


def write(path: Path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def manifest_json(with_git=True):
    files = [
        {"path": ".git/config", "sizeBytes": 1275},
        {"path": ".git/objects/ab/cdef0123456789", "sizeBytes": 4_000_000},
        {"path": ".git/logs/HEAD", "sizeBytes": 16_144},
        {"path": ".git/refs/heads/main", "sizeBytes": 41},
        {"path": ".git/refs/heads/feature/internal-roadmap", "sizeBytes": 41},
        {"path": ".git/worktrees/wt-a/index", "sizeBytes": 60_721},
        {"path": "src/app.py", "sizeBytes": 20_000},
        {"path": "backend/.env.example", "sizeBytes": 458},
        {"path": "docs/secret-plan.md", "sizeBytes": 1_200},
    ]
    if not with_git:
        files = [f for f in files if not f["path"].startswith(".git/")]
    total = sum(f["sizeBytes"] for f in files)
    return {
        "schema": "repo_snapshot_manifest/v2",
        "workspaceKey": WS_KEY,
        "createdAt": 1789583849341,
        "files": files,
        "stats": {"includedFileCount": len(files), "includedBytes": total},
    }


def extra_manifest_json():
    return {
        "schema": "repo_snapshot_extra_manifest/v1",
        "createdAt": 1789583849341,
        "groups": [
            {
                "groupId": "global-configs",
                "files": [
                    {"path": "settings.behavior.json", "sizeBytes": 807, "source": "app-memory:global-settings"},
                    {"path": "AGENTS.md", "sizeBytes": 512, "source": "app-memory:global-instructions"},
                ],
            }
        ],
        "stats": {"includedFileCount": 2, "includedBytes": 1319},
    }


def state_json(accepted=True, failure_count=4):
    st = {
        "workspacePath": WS_KEY,
        "workspaceKey": WS_KEY,
        "lastCompressedSize": {
            "encryptedSizeBytes": 444_594,
            "workspaceSizeBytes": 20_721_137,
            "manifestHash": MANIFEST_HASH,
            "recordedAt": 1789583849341,
        },
        "failureCount": failure_count,
    }
    if accepted:
        st["lastAcceptedManifestHash"] = MANIFEST_HASH
        st["lastAcceptedManifestPath"] = f"<checkpoints>/manifests/{MANIFEST_HASH}.json"
        st["lastAcceptedExtraManifestHash"] = EXTRA_HASH
        st["lastAcceptedExtraManifestPath"] = f"<checkpoints>/extra-manifests/{EXTRA_HASH}.json"
    return st


def build_case(root: Path, name, *, install=True, mechanism=True, semantic=True,
               checkpoints="full", pending=False, accepted=True, redact_safe=False):
    base = root / name
    zcode = base / "zcode"
    install_dir = base / "install"
    if install:
        (install_dir / "resources").mkdir(parents=True, exist_ok=True)
        (install_dir / "resources" / "app.asar").write_bytes(
            client_blob(with_mechanism=mechanism, with_semantic=semantic)
        )
    write(
        zcode / "v2" / "setting.json",
        json.dumps(
            {
                "optimizeAgentExperienceEnabled": False,
                "repoSnapshotIndexingEnabled": True,
                "repoSnapshotIndexingUserConfigured": True,
                "recentProjects": [WS_KEY],
                "lastWorkspaceSession": [
                    {"kind": "local", "workspacePath": WS_KEY, "workspacePurpose": "project"},
                    {
                        "kind": "remote",
                        "workspacePath": "/srv/remote-repo",
                        "workspaceIdentity": "remote:ssh:10.0.0.5:22:dev:/srv/remote-repo",
                        "workspacePurpose": "project",
                    },
                ],
            }
        ),
    )
    write(zcode / "v2" / "credentials.json", json.dumps({"zcodejwttoken": "synthetic", "oauth:active_provider": "bigmodel"}))

    cp = zcode / "v2" / "checkpoints"
    if checkpoints in ("full", "empty"):
        if checkpoints == "empty":
            cp.mkdir(parents=True, exist_ok=True)
        else:
            wd = cp / "0123456789ab"
            (wd / "pending").mkdir(parents=True, exist_ok=True)
            (wd / "tmp").mkdir(parents=True, exist_ok=True)
            write(wd / "state.json", json.dumps(state_json(accepted=accepted)))
            write(wd / "manifests" / f"{MANIFEST_HASH}.json", json.dumps(manifest_json()))
            write(wd / "extra-manifests" / f"{EXTRA_HASH}.json", json.dumps(extra_manifest_json()))
            if pending:
                (wd / "pending" / "0123456789ab.enc").write_bytes(b"\x01" * 4096)
    return base


def run_case(base: Path, extra_args=()):
    out = base / "report.html"
    js = base / "report.json"
    cmd = [
        sys.executable,
        str(DIAGNOSE),
        "--zcode-dir",
        str(base / "zcode"),
        "--install-dir",
        str(base / "install"),
        "--out",
        str(out),
        "--json",
        str(js),
        *extra_args,
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    doc = json.loads(js.read_text(encoding="utf-8")) if js.exists() else None
    return r, doc, out


def build_posix_case(root: Path, name, plat):
    """Simulate a foreign OS layout (macOS / Linux) that this machine is not."""
    base = root / name
    home = base / "home"
    wd = home / ".zcode" / "v2" / "checkpoints" / "0123456789ab"
    (wd / "pending").mkdir(parents=True, exist_ok=True)
    (wd / "tmp").mkdir(parents=True, exist_ok=True)
    write(wd / "state.json", json.dumps(state_json(accepted=True)))
    write(wd / "manifests" / f"{MANIFEST_HASH}.json", json.dumps(manifest_json()))
    write(wd / "extra-manifests" / f"{EXTRA_HASH}.json", json.dumps(extra_manifest_json()))
    write(
        home / ".zcode" / "v2" / "setting.json",
        json.dumps({"repoSnapshotIndexingUserConfigured": True, "recentProjects": [WS_KEY]}),
    )
    write(home / ".zcode" / "v2" / "credentials.json", json.dumps({"zcodejwttoken": "synthetic"}))

    if plat == "macos":
        res = home / "Applications" / "ZCode.app" / "Contents" / "Resources"
    else:
        res = home / ".local" / "share" / "ZCode" / "resources"
    res.mkdir(parents=True, exist_ok=True)
    (res / "app.asar").write_bytes(client_blob())
    if plat == "macos":
        ud = home / "Library" / "Application Support" / "ZCode"
    else:
        ud = home / ".config" / "ZCode"
    (ud / "session" / "Local Storage").mkdir(parents=True, exist_ok=True)
    (ud / ".updaterId").write_text("synthetic", encoding="utf-8")
    return base, home, res


def run_diag(json_path: Path, html_path: Path, extra_args=(), env_extra=None, install_dir=None):
    args = list(extra_args)
    if install_dir is not None:
        args += ["--install-dir", str(install_dir)]
    cmd = [sys.executable, str(DIAGNOSE), "--out", str(html_path), "--json", str(json_path), *args]
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)
    doc = json.loads(json_path.read_text(encoding="utf-8")) if json_path.exists() else None
    return r, doc


def run_case(base: Path, extra_args=(), env_extra=None):
    out = base / "report.html"
    js = base / "report.json"
    cmd = [
        str(DIAGNOSE),
        "--zcode-dir",
        str(base / "zcode"),
        "--install-dir",
        str(base / "install"),
        "--out",
        str(out),
        "--json",
        str(js),
        *extra_args,
    ]
    r = subprocess.run(
        [sys.executable, *cmd],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, **(env_extra or {})},
    )
    doc = json.loads(js.read_text(encoding="utf-8")) if js.exists() else None
    return r, doc, out


import os  # noqa: E402  (used by run_diag env handling)


import os  # noqa: E402  (used by run_diag env handling)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    root = Path(tempfile.mkdtemp(prefix="zcfx-selftest-"))
    failures = []
    print(f"fixtures: {root}\n")

    def check(name, cond, detail=""):
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}{'' if cond else ' :: ' + detail}")
        if not cond:
            failures.append(name)

    # 1) accepted hash + pristine pending  -> UPLOADED (high)
    b = build_case(root, "01-uploaded")
    r, doc, html = run_case(b)
    print("case 01 uploaded")
    check("rc=0", r.returncode == 0, r.stderr[-400:])
    check("verdict=UPLOADED", doc and doc["verdict"]["code"] == "UPLOADED", str(doc and doc["verdict"]))
    check("confidence=high", doc and doc["verdict"]["confidence"] == "high")
    check("invariant verified", doc and doc["signatures"]["semantic_invariant"] == "verified-heuristic")
    check("html rendered", html.exists() and "UPLOADED" in html.read_text(encoding="utf-8"))
    m = (doc or {}).get("workspaces", [{}])[0].get("manifests", [{}])[0]
    check("git history counted", m.get("bytes", 0) > 4_000_000 and m.get("git_counts", {}).get("reflog") == 1)
    check("sensitive flagged", any(s["path"] == "backend/.env.example" for s in m.get("sensitive", [])))
    check("extra-manifest captured", (doc or {}).get("workspaces", [{}])[0].get("extra_manifests"))

    # 2) pending ciphertext -> PACKED_PENDING
    b = build_case(root, "02-pending", pending=True, accepted=False)
    r, doc, _ = run_case(b)
    print("case 02 pending")
    check("verdict=PACKED_PENDING", doc and doc["verdict"]["code"] == "PACKED_PENDING", str(doc and doc["verdict"]["code"]))
    check("pending listed", (doc or {}).get("workspaces", [{}])[0].get("pending"))

    # 3) manifest, no accept, no pending -> CAPTURED_NOT_ACCEPTED
    b = build_case(root, "03-captured", accepted=False)
    r, doc, _ = run_case(b)
    print("case 03 captured")
    check("verdict=CAPTURED_NOT_ACCEPTED", doc and doc["verdict"]["code"] == "CAPTURED_NOT_ACCEPTED", str(doc and doc["verdict"]["code"]))

    # 4) emptied checkpoints + traces -> INCONCLUSIVE (must NOT say safe)
    b = build_case(root, "04-wiped", checkpoints="empty")
    r, doc, _ = run_case(b)
    print("case 04 wiped")
    check("verdict=INCONCLUSIVE", doc and doc["verdict"]["code"] == "INCONCLUSIVE", str(doc and doc["verdict"]["code"]))
    check("warns about quit-time purge", any("退出时" in x for x in (doc or {}).get("verdict", {}).get("reasons", [])))

    # 5) mechanism present, nothing captured -> NO_LOCAL_TRACE
    b = build_case(root, "05-no-trace", checkpoints=None)
    r, doc, _ = run_case(b)
    print("case 05 no-trace")
    check("verdict=NO_LOCAL_TRACE", doc and doc["verdict"]["code"] == "NO_LOCAL_TRACE", str(doc and doc["verdict"]["code"]))

    # 6) no signatures at all -> FEATURE_ABSENT
    b = build_case(root, "06-absent", install=True, mechanism=False, semantic=False, checkpoints=None)
    r, doc, _ = run_case(b)
    print("case 06 absent")
    check("verdict=FEATURE_ABSENT", doc and doc["verdict"]["code"] == "FEATURE_ABSENT", str(doc and doc["verdict"]["code"]))
    check("gate not hit", doc and doc["signatures"]["gate_hit"] is False)

    # 7) signature drift: gate hit but needles gone -> keep local evidence, downgrade
    b = build_case(root, "07-drift", mechanism=False, semantic=False)
    r, doc, _ = run_case(b)
    print("case 07 drift")
    check("verdict=UPLOADED", doc and doc["verdict"]["code"] == "UPLOADED", str(doc and doc["verdict"]["code"]))
    check("confidence downgraded", doc and doc["verdict"]["confidence"] == "medium")
    check("drift warning raised", any("版本漂移" in w for w in (doc or {}).get("warnings", [])))

    # 8) --no-scan must not crash and must warn
    b = build_case(root, "08-noscan")
    r, doc, _ = run_case(b, extra_args=["--no-scan"])
    print("case 08 no-scan")
    check("verdict=UPLOADED", doc and doc["verdict"]["code"] == "UPLOADED", str(doc and doc["verdict"]["code"]))
    check("scan marked skipped", doc and doc["signatures"]["scanned"] is False)

    # 9) --redact masks branch names / remotes, keeps counts
    b = build_case(root, "09-redact")
    r, doc, _ = run_case(b, extra_args=["--redact"])
    print("case 09 redact")
    m = (doc or {}).get("workspaces", [{}])[0].get("manifests", [{}])[0]
    check("branches hashed", all(len(x) == 8 for x in m.get("branches", [])) and m.get("branches"))
    check("workspace path masked", "<redacted>" in str((doc or {}).get("workspaces", [{}])[0].get("workspace_path_display")))

    # 10) --diff detects a newly accepted upload
    b = build_case(root, "10-diff", accepted=False)
    _, doc1, _ = run_case(b)
    prev = b / "prev.json"
    prev.write_text(json.dumps(doc1, ensure_ascii=False), encoding="utf-8")
    write(b / "zcode" / "v2" / "checkpoints" / "0123456789ab" / "state.json", json.dumps(state_json(accepted=True)))
    r, doc2, _ = run_case(b, extra_args=["--diff", str(prev)])
    print("case 10 diff")
    check("diff reports accept change", "accepted hash" in r.stdout or "→" in r.stdout, r.stdout[-300:])

    # 11) foreign OS layout: macOS bundle + ~/Library Application Support
    base, home, bundle = build_posix_case(root, "11-macos-layout", "macos")
    r, doc = run_diag(
        base / "r.json", base / "r.html", ["--platform", "macos", "--home", str(home)], install_dir=bundle
    )
    print("case 11 macos layout")
    check("platform resolved", doc and doc["detection"]["platform"] == "macos", str(doc and doc["detection"]))
    check("asar found in .app bundle", doc and ".app" in str(doc["client"].get("asar")).lower(), str(doc and doc["client"].get("asar")))
    check("verdict=UPLOADED", doc and doc["verdict"]["code"] == "UPLOADED", str(doc and doc["verdict"]["code"]))
    check("userData via Application Support", doc and "Application Support" in str(doc["aux"].get("appdata_client_dir")), str(doc and doc["aux"].get("appdata_client_dir")))

    # 12) Linux layout + env-var override beats the default ~/.zcode
    base, home, bundle = build_posix_case(root, "12-linux-layout", "linux")
    alt = base / "alt-data"
    alt.mkdir(parents=True, exist_ok=True)
    r, doc = run_diag(
        base / "r.json",
        base / "r.html",
        ["--platform", "linux", "--home", str(home)],
        env_extra={"ZCODE_DATA_BASE_DIR": str(alt)},
        install_dir=bundle,
    )
    print("case 12 linux layout + env override")
    check("platform resolved", doc and doc["detection"]["platform"] == "linux")
    check("env override wins", doc and str(doc["detection"]["data_dir"]).endswith("alt-data"), str(doc and doc["detection"]["data_dir"]))
    check("asar found under ~/.local/share", doc and ".local" in str(doc["client"].get("asar")), str(doc and doc["client"].get("asar")))
    check("userData via ~/.config", doc and ".config" in str(doc["aux"].get("appdata_client_dir")))

    # 13) --list-paths prints the detection ledger (auditable, no hardcoding)
    base, home, bundle = build_posix_case(root, "13-ledger", "linux")
    r = subprocess.run(
        [
            sys.executable,
            str(DIAGNOSE),
            "--platform",
            "linux",
            "--home",
            str(home),
            "--install-dir",
            str(bundle),
            "--list-paths",
        ],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    print("case 13 detection ledger")
    try:
        led = json.loads(r.stdout)
    except Exception:
        led = None
    check("ledger is json", led is not None, r.stdout[:200])
    check("has data_dir candidates", bool(led and led.get("data_dir_candidates")))
    check("has install candidates", bool(led and led.get("install_candidates")))
    check("records how", all("how" in c for c in (led or {}).get("data_dir_candidates", [])))

    # 14) lock ops must refuse a platform override
    base, home, _bundle = build_posix_case(root, "14-lock-guard", "linux")
    r = subprocess.run(
        [sys.executable, str(DIAGNOSE), "--platform", "linux", "--home", str(home), "--apply-lock", "--yes", "--force"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    print("case 14 lock guard on platform override")
    check("rc=2 refused", r.returncode == 2, f"rc={r.returncode}")
    check("explains why", "不一致" in r.stderr, r.stderr[:200])

    # 15) no desktop client at all: only the remote-host bundle pushed into the
    #     data dir (real case found on a macOS box used as an SSH workspace host)
    base = root / "15-host-bundle"
    wd = base / "zcode" / "v2" / "checkpoints" / "0123456789ab"
    (wd / "pending").mkdir(parents=True, exist_ok=True)
    write(wd / "state.json", json.dumps(state_json(accepted=True)))
    write(wd / "manifests" / f"{MANIFEST_HASH}.json", json.dumps(manifest_json()))
    write(base / "zcode" / "v2" / "credentials.json", json.dumps({"zcodejwttoken": "synthetic"}))
    srv = base / "zcode" / "server"
    srv.mkdir(parents=True, exist_ok=True)
    (srv / "zcode-server.cjs").write_bytes(client_blob())
    r, doc, _ = run_case(base, extra_args=["--install-dir", str(srv)])
    print("case 15 host bundle only (no app.asar)")
    check("verdict=UPLOADED", doc and doc["verdict"]["code"] == "UPLOADED", str(doc and doc["verdict"]["code"]))
    check("mechanism confirmed from bundle", doc and doc["signatures"]["mechanism_hits"] == doc["signatures"]["mechanism_total"], str(doc and doc["signatures"].get("mechanism_hits")))
    check("target is the .cjs bundle", doc and str(doc["client"].get("asar")).endswith("zcode-server.cjs"), str(doc and doc["client"].get("asar")))

    print()
    if failures:
        print(f"FAILED ({len(failures)}): " + ", ".join(failures))
    else:
        print("all cases passed")
    if not args.keep:
        shutil.rmtree(root, ignore_errors=True)
    else:
        print(f"kept: {root}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
