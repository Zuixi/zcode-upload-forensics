"""Signature needles, schemas and static tables."""

from __future__ import annotations

import re

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
    ("s002", re.compile(r"(^|/)\.env(\..+)?$", re.I)),
    ("s003", re.compile(r"\.(pem|key|p12|pfx|jks|keystore|crt|cer)$", re.I)),
    ("s021", re.compile(r"(^|/)(id_rsa|id_ed25519|id_ecdsa|known_hosts)$", re.I)),
    ("s004", re.compile(r"(secret|token|credential|passwd|password|api[-_]?key)", re.I)),
    ("s005", re.compile(r"\.(sql|dump|sqlite|sqlite3|db)$", re.I)),
    ("s006", re.compile(r"(^|/)\.(aws|ssh|kube|gnupg|docker)(/|$)", re.I)),
    ("s007", re.compile(r"(deploy[-_]?key|\.npmrc|\.pypirc|\.netrc|id_deploy)", re.I)),
]

# Global files that ride along in the extra-manifest (privacy surface #2).
EXTRA_MANIFEST_GROUPS = {
    "global-configs": "s001",
}

VERDICTS = {
    "UPLOADED": ("s008", "#b91c1c", "s009"),
    "PACKED_PENDING": ("s010", "#c2410c", "s011"),
    "CAPTURED_NOT_ACCEPTED": ("s012", "#a16207", "s013"),
    "INCONCLUSIVE": ("s014", "#7c3aed", "s015"),
    "NO_LOCAL_TRACE": ("s016", "#15803d", "s017"),
    "FEATURE_ABSENT": ("s018", "#15803d", "s019"),
}

TRUTH_TABLE = [
    ("FEATURE_ABSENT", "✘", "–", "–", "–"),
    ("NO_LOCAL_TRACE", "✔", "–", "–", "–"),
    ("CAPTURED_NOT_ACCEPTED", "✔", "–", "–", "✔"),
    ("PACKED_PENDING", "✔", "–", "✔", "✔"),
    ("UPLOADED", "✔", "✔", "–", "✔"),
    ("INCONCLUSIVE", "✔", "s020", "?", "?"),
]
