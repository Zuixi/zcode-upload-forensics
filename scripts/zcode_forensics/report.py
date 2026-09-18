"""Single-file HTML report rendering."""

from __future__ import annotations

from .constants import EXTRA_MANIFEST_GROUPS, SKILL_VERSION, TRUTH_TABLE, VERDICTS
from .locking import lock_commands
from .messages import tr
from .util import esc, hum, iso

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
    label, meaning = tr(label), tr(meaning)
    P = []
    P.append(f"<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>")
    P.append("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    P.append(tr("m008", p0=esc(label), p1=CSS))
    P.append(tr("m009"))
    P.append(
        tr("m010", p0=esc(doc['generated_at']), p1=esc(doc['os']['system']), p2=esc(doc['os']['release']), p3=esc(doc['os']['host']), p4=esc(doc['client'].get('version') or tr("n005")), p5=esc(SKILL_VERSION))
    )

    P.append(
        tr("m011", p0=color, p1=color, p2=esc(label), p3=esc(v['code']), p4=esc(v['confidence']), p5=esc(meaning))
    )

    P.append(tr("m012"))
    for r in v["reasons"]:
        P.append(f"<li>{esc(r)}</li>")
    P.append("</ul>")
    if v["falsifiers"]:
        P.append(tr("m044"))
        for r in v["falsifiers"]:
            P.append(f"<li>{esc(r)}</li>")
        P.append("</ul>")

    P.append(tr("m013"))
    for code, a, b, c, d in TRUTH_TABLE:
        cls = ""
        if code == v["code"]:
            cls = " class='hit" + ("" if v["confidence"] == "high" else " meh") + "'"
        mark = tr("m045") if code == v["code"] else ""
        P.append(
            f"<tr{cls}><td><code>{esc(code)}</code> {esc(tr(VERDICTS[code][0]))}{mark}</td>"
            f"<td>{esc(tr(a))}</td><td>{esc(tr(b))}</td><td>{esc(tr(c))}</td><td>{esc(tr(d))}</td></tr>"
        )
    P.append("</table>")

    # --- workspaces ---
    P.append(tr("m014"))
    if not doc["workspaces"]:
        P.append(tr("m046"))
    for w in doc["workspaces"]:
        cls = "card warn" if (w.get("accepted_hash") or w.get("pending")) else "card"
        P.append(f"<div class='{cls}'><h3>{esc(w.get('workspace_path_display') or w['key'])}</h3>")
        st = w.get("state") or {}
        P.append(
            kv(
                [
                    ("checkpoints key", f"<code>{esc(w['key'])}</code>"),
                    (tr("m139"), esc(iso(w.get("state_mtime")))),
                    ("accepted manifest hash", (f"<code>{esc(str(w.get('accepted_hash'))[:16])}…</code>" + tr("m165")) if w.get("accepted_hash") else tr("m154")),
                    (tr("m140"), esc(st.get("failureCount", "–"))),
                    (tr("m141"), ("<span class='bad'>" + ", ".join(f"{esc(p['file'])} ({hum(p['bytes'])})" for p in w["pending"]) + "</span>") if w["pending"] else tr("m155")),
                    (tr("m142"), esc((w.get("in_state_upload") or {}).get("kind") or "–")),
                ]
            )
        )
        lc = w.get("last_compressed") or {}
        if lc:
            P.append(
                tr("m104")
                + kv(
                    [
                        (tr("m166"), f"{hum(lc.get('encryptedSizeBytes'))}（{esc(lc.get('encryptedSizeBytes'))} B）"),
                        (tr("m167"), f"{hum(lc.get('workspaceSizeBytes'))}（{esc(lc.get('workspaceSizeBytes'))} B）"),
                        ("manifestHash", f"<code>{esc(str(lc.get('manifestHash'))[:16])}…</code>"),
                        ("recordedAt", esc(iso((lc.get("recordedAt") or 0) / 1000))),
                    ]
                )
            )
            if w.get("ratio_hint"):
                P.append(f"<p>⚠️ {esc(w['ratio_hint'])}</p>")

        for m in w["manifests"]:
            P.append(
                tr("m105", p0=esc(m['file'][:16]))
                + kv(
                    [
                        (tr("m168"), tr("m169", p0=esc(m.get('manifest_files')), p1=hum(m.get('bytes')))),
                        (tr("m170"), esc(iso((m.get("createdAt") or 0) / 1000))),
                        (tr("m171"), esc(m.get("workspaceKey"))),
                        (tr("m172"), tr("m173", p0=esc(m['git_counts']['git']), p1=esc(m['git_counts']['reflog']), p2=esc(m['git_counts']['refs']), p3=esc(m['git_counts']['worktree']))),
                        (tr("m174"), f"{esc(len(m.get('branches') or []))} / {esc(len(m.get('worktrees') or []))}"),
                    ]
                )
            )
            if m.get("top_groups"):
                P.append(tr("m106"))
                for g in m["top_groups"][:12]:
                    P.append(
                        f"<tr><td><code>{esc(g['name'])}</code></td><td>{hum(g['bytes'])}</td>"
                        f"<td>{g['pct']:.1f}%</td><td><span class='bar' style='width:120px;display:inline-block'><i style='width:{min(g['pct'],100):.1f}%'></i></span></td></tr>"
                    )
                P.append("</table>")
            if m.get("branches"):
                P.append(
                    tr("m175") + str(len(m["branches"])) + "）</summary><p>"
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
                P.append(tr("m107"))
                for s in m["sensitive"][:60]:
                    P.append(f"<tr><td>{esc(tr(s['kind']))}</td><td><code>{esc(s['path'])}</code></td><td>{hum(s['sizeBytes'])}</td></tr>")
                P.append("</table>")

        if w.get("local_git_remotes"):
            P.append(tr("m081"))
            for r in w["local_git_remotes"]:
                P.append(f"<li><code>{esc(r['name'])}</code> → <code>{esc(r['url'])}</code></li>")
            P.append("</ul>")

        for e in w["extra_manifests"]:
            P.append(tr("m082", p0=esc(e['file'][:12])))
            if e.get("included"):
                P.append(tr("m108"))
                for i in e["included"]:
                    P.append(
                        f"<tr><td>{esc(tr(EXTRA_MANIFEST_GROUPS.get(i.get('groupId'), i.get('groupId'))))}</td>"
                        f"<td><code>{esc(i.get('path'))}</code></td><td class='muted'>{esc(i.get('source'))}</td></tr>"
                    )
                P.append("</table>")
        for wn in w.get("warnings", []):
            P.append(f"<p class='bad'>⚠️ {esc(wn)}</p>")
        P.append("</div>")

    # --- detection ledger (proves nothing is hardcoded) ---
    det = doc.get("detection") or {}
    P.append(tr("m015"))
    P.append(
        kv(
            [
                (tr("m109"), f"<code>{esc(det.get('platform'))}</code>（{esc(det.get('platform_source'))}）"),
                (tr("m110"), f"<code>{esc(det.get('home'))}</code>（{esc(det.get('home_source'))}）"),
                (tr("m111"), f"<code>{esc(det.get('data_dir'))}</code> —— {esc(det.get('data_dir_how'))}"),
                ("checkpoints", f"<code>{esc(det.get('checkpoints'))}</code>"),
                (tr("m112"), f"<code>{esc(doc['client'].get('install_dir'))}</code> —— {esc(doc['client'].get('install_how'))}"),
                ("Electron userData", f"<code>{esc((doc.get('aux') or {}).get('appdata_client_dir'))}</code> —— {esc((doc.get('aux') or {}).get('appdata_client_how'))}"),
            ]
        )
    )
    tried = doc["client"].get("candidates_tried") or []
    P.append(
        tr("m016", p0=len(tried))
    )
    for c in tried[:40]:
        P.append(f"<tr><td><code>{esc(c['path'])}</code></td><td class='muted'>{esc(c['how'])}</td></tr>")
    P.append("</table></details>")

    # --- client code ---
    sig = doc["signatures"]
    P.append(tr("m017"))
    P.append(
        kv(
            [
                (tr("m113"), f"<code>{esc(sig.get('target'))}</code>（{hum(sig.get('target_bytes'))}，mtime {esc(iso(sig.get('target_mtime')))})"),
                (tr("m114"), tr("m143") if sig.get("scanned") else tr("m144", p0=esc(sig.get('note')))),
                (tr("m115"), {True: tr("m156"), False: tr("m157"), None: "–"}[sig.get("gate_hit")]),
                (tr("m116"), f"{esc(sig.get('mechanism_hits'))} / {esc(sig.get('mechanism_total'))}"),
                (tr("m117"), {"verified-heuristic": tr("m158", p0=esc(sig.get('semantic_distance'))), "pair-present-far-apart": tr("m159"), "unverified": tr("m160")}[sig.get("semantic_invariant")]),
            ]
        )
    )
    if sig.get("counts"):
        P.append(tr("m047"))
        for k, c in sorted(sig["counts"].items(), key=lambda x: -x[1]):
            P.append(f"<tr><td><code>{esc(k)}</code></td><td>{esc(c)}</td></tr>")
        P.append("</table></details>")

    # --- aux ---
    aux = doc["aux"]
    P.append(tr("m018"))
    P.append(
        kv(
            [
                (tr("m118"), f"<code>{esc(aux.get('data_dir'))}</code>"),
                (tr("m119"), tr("m145") if aux.get("login_token_present") else tr("m146")),
                (tr("m120"), (tr("m161") if doc["processes"].get("running") else tr("m162")) if doc["processes"].get("running") is not None else tr("m147")),
                (
                    tr("m121"),
                    tr("m148")
                    if (doc.get("lock_state") or {}).get("locked")
                    else tr("m149"),
                ),
                ("optimizeAgentExperienceEnabled", esc((aux.get("settings") or {}).get("optimizeAgentExperienceEnabled"))),
                ("repoSnapshotIndexingEnabled", esc((aux.get("settings") or {}).get("repoSnapshotIndexingEnabled"))),
                (tr("m122"), esc(", ".join(aux.get("certs") or []) or tr("m163"))),
            ]
        )
    )
    if aux.get("sessions"):
        P.append(tr("m048"))
        for s in aux["sessions"]:
            # NOTE: keep the conditional outside the f-string -- a backslash inside
            # an f-string expression is a SyntaxError before Python 3.12 (PEP 701),
            # and macOS ships system python3 3.9.
            remote_txt = (
                tr("m083")
                if s.get("remote")
                else tr("m084")
            )
            P.append(
                f"<tr><td>{esc(s.get('kind'))}</td><td><code>{esc(s.get('workspacePath'))}</code></td>"
                f"<td>{remote_txt}</td></tr>"
            )
        P.append("</table>")
    if doc.get("log_mentions"):
        P.append(tr("m049"))
        for k, c in doc["log_mentions"].items():
            P.append(f"<tr><td>{esc(k)}</td><td>{esc(c)}</td></tr>")
        P.append("</table>")

    # --- timeline ---
    P.append(tr("m019"))
    for t, lbl in sorted(doc["timeline"])[::-1][:40]:
        P.append(f"<tr><td>{esc(iso(t))}</td><td>{esc(lbl)}</td></tr>")
    P.append("</table>")

    # --- remediation ---
    P.append(tr("m020"))
    P.append(
        tr("m021")
    )
    for plat, cmds in lock_commands(doc["detection"]["platform"], doc["detection"]["checkpoints"]).items():
        P.append(f"<h4>{esc(plat)}</h4><pre>{esc(cmds)}</pre>")
    P.append(
        tr("m022")
    )
    P.append(
        tr("m023")
    )

    # --- unknown / appendix ---
    P.append(tr("m024"))
    for w in doc["warnings"]:
        P.append(f"<li>⚠️ {esc(w)}</li>")
    for e in doc["errors"]:
        P.append(tr("m050", p0=esc(e['where']), p1=esc(e['error'])))
    if not doc["warnings"] and not doc["errors"]:
        P.append(tr("m051"))
    P.append("</ul>")

    P.append(tr("m025"))
    P.append(esc(doc["reproduce"]))
    P.append("</pre>")

    P.append(
        tr("m026")
    )
    P.append("</main></body></html>")
    return "".join(P)
