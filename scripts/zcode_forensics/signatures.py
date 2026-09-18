"""Client bundle signature scan and invariant heuristic."""

from __future__ import annotations

from pathlib import Path
import re

from .constants import GATE_NEEDLE, MECHANISM_NEEDLES, NEEDLES, SEMANTIC_MAX_DISTANCE
from .messages import tr
from .util import Ctx, mt

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
            ctx.warn(tr("m073", p0=target))
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
        result["note"] = tr("m002")
        return result
    if not targets:
        result["note"] = tr("m003")
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
        result["note"] = tr("m004")
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
