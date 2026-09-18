"""Truth-table decision plus machine-readable flags."""

from __future__ import annotations

from .constants import VERDICTS
from .messages import tr

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
                tr("m075", p0=w.get('workspace_path_display') or w['key'], p1=str(w.get('accepted_hash'))[:16])
            )
        reasons.append(
            tr("m038")
        )
        if invariant == "verified-heuristic":
            reasons.append(
                tr("m076", p0=sig.get('semantic_distance'))
            )
        else:
            falsifiers.append(tr("m077"))
            doc["warnings"].append(tr("m078"))
        falsifiers.append(tr("m039"))
    elif pending:
        code, conf = "PACKED_PENDING", "high" if feature else "medium"
        reasons.append(tr("m079"))
        falsifiers.append(tr("m080"))
    elif captured:
        code, conf = "CAPTURED_NOT_ACCEPTED", "medium"
        reasons.append(tr("m102"))
        falsifiers.append(tr("m103"))
    elif has_local:
        code, conf = "INCONCLUSIVE", "low"
        reasons.append(tr("m136"))
        reasons.append(tr("m137"))
        falsifiers.append(tr("m138"))
    elif feature:
        code, conf = "NO_LOCAL_TRACE", "medium"
        reasons.append(tr("m150"))
        falsifiers.append(tr("m151"))
    else:
        code, conf = "FEATURE_ABSENT", "medium"
        reasons.append(tr("m152"))
        falsifiers.append(tr("m153"))

    if has_local and scanned and not feature:
        doc["warnings"].append(
            tr("m040")
        )
    if doc["processes"].get("running"):
        reasons.append(tr("m041"))
    if token:
        reasons.append(tr("m042"))
    else:
        reasons.append(tr("m043"))

    return {
        "code": code,
        "label": tr(VERDICTS[code][0]),
        "confidence": conf,
        "reasons": reasons,
        "falsifiers": falsifiers,
        "affected_workspaces": [w.get("workspace_path_display") or w["key"] for w in ws_list],
        # Locale-independent machine-readable signals: use these in tests and
        # automation instead of matching rendered prose.
        "flags": {
            "pipeline_confirmed": bool(feature),
            "signature_scan_done": scanned,
            "invariant_verified": invariant == "verified-heuristic",
            "accepted_records": bool(uploaded),
            "pending_artifacts": bool(pending),
            "capture_artifacts": bool(captured),
            "evidence_wiped": bool(has_local and not ws_list),
            "signature_drift": bool(has_local and scanned and not feature),
            "token_present": token,
            "client_running": bool(doc["processes"].get("running")),
        },
    }
