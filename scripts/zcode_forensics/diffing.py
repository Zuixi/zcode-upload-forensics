"""Comparison against a previous report."""

from __future__ import annotations

from pathlib import Path

from .messages import tr
from .util import Ctx, iso, read_json

def diff_reports(prev_path: Path, doc, ctx: Ctx):
    prev = read_json(prev_path)
    if not isinstance(prev, dict):
        return [tr("m061", p0=prev_path)]
    out = []
    if prev.get("verdict", {}).get("code") != doc["verdict"]["code"]:
        out.append(
            tr("m062", p0=prev.get('verdict', {}).get('code'), p1=doc['verdict']['code'])
        )
    pmap = {w.get("key"): w for w in prev.get("workspaces") or []}
    for w in doc["workspaces"]:
        p = pmap.get(w["key"])
        if not p:
            out.append(tr("m087", p0=w.get('workspace_path_display') or w['key']))
            continue
        if p.get("accepted_hash") != w.get("accepted_hash"):
            out.append(
                tr("m088", p0=w['key'], p1=str(p.get('accepted_hash'))[:12], p2=str(w.get('accepted_hash'))[:12])
            )
        if p.get("failure_count") != w.get("failure_count"):
            out.append(f"{w['key']}：failureCount {p.get('failure_count')} → {w.get('failure_count')}")
        if len(p.get("pending") or []) != len(w.get("pending") or []):
            out.append(tr("m089", p0=w['key'], p1=len(p.get('pending') or []), p2=len(w.get('pending') or [])))
        if (p.get("state_mtime") or 0) != (w.get("state_mtime") or 0):
            out.append(tr("m090", p0=w['key'], p1=iso(p.get('state_mtime')), p2=iso(w.get('state_mtime'))))
    if prev.get("client", {}).get("version") != doc["client"].get("version"):
        out.append(
            tr("m063", p0=prev.get('client', {}).get('version'), p1=doc['client'].get('version'))
        )
    return out or [tr("m064")]
