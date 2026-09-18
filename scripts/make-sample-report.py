#!/usr/bin/env python3
"""Regenerate the committed sample report from a fully synthetic fixture.

The fixture is built in a temporary directory and never touches a real
``~/.zcode``, so the published sample contains no real paths, hashes or branch
names. Run it whenever the report layout changes:

    python3 scripts/make-sample-report.py                 # -> docs/sample-report.html
    python3 scripts/make-sample-report.py --out /tmp/x.html
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import selftest as st  # noqa: E402  (synthetic builders: client bundle, manifests, state)

REPO_ROOT = HERE.parent
DEFAULT_OUT = REPO_ROOT / "docs" / "sample-report.html"

WS_UPLOADED = "/home/dev/projects/demo-repo"
WS_PENDING = "/home/dev/projects/internal-tools"
WS_CAPTURED = "/home/dev/notes"
EXTRA_HASH = "3c9f1d7a5e02b846c1d93f60a7e4b2c85d1e0f39a6b47c28159dfa36e0c7b492"


def write(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False),
        encoding="utf-8",
    )


def manifest(workspace: str, files, created_at: int) -> dict:
    return {
        "schema": "repo_snapshot_manifest/v2",
        "workspaceKey": workspace,
        "createdAt": created_at,
        "files": files,
        "stats": {
            "includedFileCount": len(files),
            "includedBytes": sum(f["sizeBytes"] for f in files),
        },
    }


def state(workspace: str, *, accepted: bool, encrypted: int, plain: int, manifest_hash: str, failure_count=None):
    doc = {
        "workspacePath": workspace,
        "workspaceKey": workspace,
        "lastCompressedSize": {
            "encryptedSizeBytes": encrypted,
            "workspaceSizeBytes": plain,
            "manifestHash": manifest_hash,
            "recordedAt": 1789583849341,
        },
    }
    if accepted:
        doc["lastAcceptedManifestHash"] = manifest_hash
        doc["lastAcceptedManifestPath"] = f"<checkpoints>/manifests/{manifest_hash}.json"
        doc["lastAcceptedExtraManifestHash"] = EXTRA_HASH
        doc["lastAcceptedExtraManifestPath"] = f"<checkpoints>/extra-manifests/{EXTRA_HASH}.json"
    if failure_count is not None:
        doc["failureCount"] = failure_count
    return doc


def build(root: Path) -> Path:
    """Create the synthetic machine state. Returns the case directory."""
    base = root
    zcode = base / "zcode"
    install = base / "install"

    # --- client bundle with the pipeline signatures -----------------------
    (install / "resources").mkdir(parents=True, exist_ok=True)
    (install / "resources" / "app.asar").write_bytes(st.client_blob())
    write(install / "resources" / "app-update.yml", "provider: generic\nurl: https://updates.example.invalid\n")

    # --- machine-wide client state ---------------------------------------
    write(
        zcode / "v2" / "setting.json",
        {
            "optimizeAgentExperienceEnabled": False,
            "repoSnapshotIndexingEnabled": True,
            "repoSnapshotIndexingUserConfigured": True,
            "recentProjects": [WS_UPLOADED, WS_PENDING, WS_CAPTURED],
            "lastWorkspaceSession": [
                {"kind": "local", "workspacePath": WS_UPLOADED, "workspacePurpose": "project"},
                {"kind": "local", "workspacePath": WS_PENDING, "workspacePurpose": "project"},
                {
                    "kind": "remote",
                    "workspacePath": "/srv/build-agent/checkout",
                    "workspaceIdentity": "remote:ssh:10.0.0.5:22:dev:/srv/build-agent/checkout",
                    "workspacePurpose": "project",
                },
            ],
        },
    )
    write(zcode / "v2" / "credentials.json", {"zcodejwttoken": "synthetic.jwt.value", "oauth:active_provider": "example"})
    write(zcode / "v2" / "telemetry-state.json", {"deviceMid": "00000000-0000-0000-0000-000000000000"})
    (zcode / "v2" / "certs").mkdir(parents=True, exist_ok=True)
    write(zcode / "v2" / "certs" / "zcode-network-ca.pem", "-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----\n")
    for day in ("2026-09-17", "2026-09-18"):
        write(zcode / "v2" / "logs" / f"{day}.log", "git-checkpoint channel registered\nrepo-wiki generation requested\n")

    # --- workspace 1: uploaded, rich Git evidence -------------------------
    wd = zcode / "v2" / "checkpoints" / "a1b2c3d4e5f6"
    (wd / "pending").mkdir(parents=True, exist_ok=True)
    (wd / "tmp").mkdir(parents=True, exist_ok=True)
    files = [
        {"path": ".git/objects/pack/pack-4f2a1c9d.pack", "sizeBytes": 11_800_000},
        {"path": ".git/objects/ab/cdef0123456789abcdef0123456789abcdef01", "sizeBytes": 420_000},
        {"path": ".git/logs/HEAD", "sizeBytes": 16_144},
        {"path": ".git/logs/refs/heads/main", "sizeBytes": 6_733},
        {"path": ".git/logs/refs/heads/feat/pricing-experiment", "sizeBytes": 2_673},
        {"path": ".git/refs/heads/main", "sizeBytes": 41},
        {"path": ".git/refs/heads/release/2.1", "sizeBytes": 41},
        {"path": ".git/refs/remotes/origin/main", "sizeBytes": 41},
        {"path": ".git/packed-refs", "sizeBytes": 46},
        {"path": ".git/config", "sizeBytes": 1_275},
        {"path": ".git/worktrees/wt-docs/index", "sizeBytes": 60_721},
        {"path": ".git/worktrees/wt-docs/logs/HEAD", "sizeBytes": 10_285},
        {"path": ".git/worktrees/wt-perf/index", "sizeBytes": 56_591},
        {"path": "src/app/main.ts", "sizeBytes": 92_000},
        {"path": "src/app/pricing.ts", "sizeBytes": 41_500},
        {"path": "backend/api/handlers.py", "sizeBytes": 63_400},
        {"path": "backend/.env.example", "sizeBytes": 458},
        {"path": "infra/deploy.key", "sizeBytes": 1_688},
        {"path": "infra/terraform/prod.tf", "sizeBytes": 12_400},
        {"path": "data/seed/dump.sql", "sizeBytes": 890_000},
        {"path": "docs/architecture.md", "sizeBytes": 22_300},
        {"path": "docs/roadmap-2026.md", "sizeBytes": 8_100},
        {"path": "README.md", "sizeBytes": 4_200},
    ]
    m1 = manifest(WS_UPLOADED, files, 1789583849341)
    h1 = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    write(wd / "state.json", state(WS_UPLOADED, accepted=True, encrypted=444_594, plain=20_721_137, manifest_hash=h1, failure_count=19))
    write(wd / "manifests" / f"{h1}.json", m1)
    write(wd / "extra-manifests" / f"{EXTRA_HASH}.json", st.extra_manifest_json())

    # --- workspace 2: packed, upload not confirmed ------------------------
    wd2 = zcode / "v2" / "checkpoints" / "f6e5d4c3b2a1"
    (wd2 / "pending").mkdir(parents=True, exist_ok=True)
    (wd2 / "tmp").mkdir(parents=True, exist_ok=True)
    files2 = [
        {"path": ".git/objects/pack/pack-9911aa33.pack", "sizeBytes": 3_400_000},
        {"path": ".git/logs/HEAD", "sizeBytes": 3_100},
        {"path": ".git/refs/heads/main", "sizeBytes": 41},
        {"path": "services/parser/main.go", "sizeBytes": 74_000},
        {"path": "deploy/k8s/prod.yaml", "sizeBytes": 9_800},
    ]
    m2 = manifest(WS_PENDING, files2, 1789665890084)
    h2 = hashlib.sha256(json.dumps(files2, sort_keys=True).encode()).hexdigest()
    write(wd2 / "state.json", state(WS_PENDING, accepted=False, encrypted=812_004, plain=3_659_211, manifest_hash=h2, failure_count=3))
    write(wd2 / "manifests" / f"{h2}.json", m2)
    (wd2 / "pending" / "f6e5d4c3b2a1.enc").write_bytes(b"\x00" * 2048)

    # --- workspace 3: captured, no accept record --------------------------
    wd3 = zcode / "v2" / "checkpoints" / "0011aa22bb33"
    (wd3 / "pending").mkdir(parents=True, exist_ok=True)
    (wd3 / "tmp").mkdir(parents=True, exist_ok=True)
    files3 = [
        {"path": ".git/objects/ab/cdef0123456789", "sizeBytes": 180_000},
        {"path": ".git/logs/HEAD", "sizeBytes": 900},
        {"path": "meeting-notes/2026-09-12.md", "sizeBytes": 3_400},
        {"path": "drafts/postgres-tuning.md", "sizeBytes": 21_000},
    ]
    m3 = manifest(WS_CAPTURED, files3, 1789063325140)
    h3 = hashlib.sha256(json.dumps(files3, sort_keys=True).encode()).hexdigest()
    write(wd3 / "state.json", state(WS_CAPTURED, accepted=False, encrypted=61_233, plain=310_400, manifest_hash=h3))
    write(wd3 / "manifests" / f"{h3}.json", m3)

    # --- make one workspace show the "unrecorded capture" warning ---------
    later = os.path.getmtime(wd3 / "state.json") + 90
    os.utime(wd3 / "manifests", (later, later))
    return base


def main() -> int:
    ap = argparse.ArgumentParser(description="Regenerate the committed sample report")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help=f"output path (default: {DEFAULT_OUT})")
    ap.add_argument("--lang", default="en", choices=("en", "zh"), help="report language for the sample")
    args = ap.parse_args()

    # A stable directory name (not mkdtemp) keeps fixture *paths* identical
    # between runs, so the masked sample stays readable and diffs stay small.
    root = Path(tempfile.gettempdir()) / "demo-machine"
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True, exist_ok=True)
    try:
        base = build(root)
        out = Path(args.out)
        cmd = [
            sys.executable,
            str(HERE / "diagnose.py"),
            "--lang", args.lang, "--redact", "paths",
            "--zcode-dir", str(base / "zcode"),
            "--install-dir", str(base / "install"),
            "--out", str(out),
            "--json", str(out.with_suffix(".json")),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        if proc.returncode != 0:
            return proc.returncode
        print(f"written: {out} ({out.stat().st_size} bytes)")
        return 0
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
