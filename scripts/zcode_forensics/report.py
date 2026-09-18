"""Single-file HTML report rendering.

Layout is a stack of cards: one hero card carrying the verdict, then one card
per report section. All markup is produced here; the message table only holds
text, so the visual design can change without touching translations.
"""

from __future__ import annotations

from . import messages
from .constants import EXTRA_MANIFEST_GROUPS, SKILL_VERSION, TRUTH_TABLE, VERDICTS
from .locking import lock_commands
from .messages import tr
from .util import esc, hum, iso

# Which accent tone a verdict gets in the hero card.
TONE = {
    "UPLOADED": "danger",
    "PACKED_PENDING": "warn",
    "CAPTURED_NOT_ACCEPTED": "warn",
    "INCONCLUSIVE": "neutral",
    "NO_LOCAL_TRACE": "ok",
    "FEATURE_ABSENT": "ok",
}

# Flags surfaced as chips in the hero card: flag -> (message id, chip class)
HERO_FLAGS = (
    ("accepted_records", "t021", "chip--danger"),
    ("pending_artifacts", "t022", "chip--warn"),
    ("evidence_wiped", "t023", "chip--warn"),
    ("signature_drift", "t024", "chip--warn"),
    ("token_present", "t025", ""),
    ("client_running", "t026", ""),
)

CSS = """
*,*::before,*::after{box-sizing:border-box}
:root{
  color-scheme:light;
  --bg:#eef1f5; --surface:#fff; --surface-2:#f6f8fb;
  --ink:#111827; --ink-2:#374151; --muted:#6b7280; --line:#e4e8ee;
  --accent:#1d5fd0; --accent-soft:#e8f0fe;
  --ok:#0f7a48; --ok-soft:#e6f6ee;
  --warn:#9a5b00; --warn-soft:#fff4e5;
  --danger:#b3261e; --danger-soft:#fdecea;
  --radius:16px; --radius-sm:10px;
  --shadow:0 1px 1px rgba(16,24,40,.04), 0 10px 28px -18px rgba(16,24,40,.40);
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
}
@media (prefers-color-scheme:dark){
  :root{
    color-scheme:dark;
    --bg:#0b0f14; --surface:#131922; --surface-2:#0f151d;
    --ink:#e7ecf3; --ink-2:#c4ccd8; --muted:#8b97a6; --line:#222c38;
    --accent:#6aa6ff; --accent-soft:#16233a;
    --ok:#4ec98a; --ok-soft:#10251b;
    --warn:#e5b567; --warn-soft:#2a2113;
    --danger:#ff8a80; --danger-soft:#2b1512;
    --shadow:0 1px 1px rgba(0,0,0,.5), 0 14px 34px -20px rgba(0,0,0,.9);
  }
}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Noto Sans SC","PingFang SC","Microsoft YaHei",sans-serif;
  -webkit-font-smoothing:antialiased}
.page{max-width:1120px;margin:0 auto;padding:26px 18px 72px}

/* ---------- hero ---------- */
.hero{position:relative;background:var(--surface);border:1px solid var(--line);
  border-radius:var(--radius);box-shadow:var(--shadow);padding:22px 24px 20px;overflow:hidden}
.hero::before{content:"";position:absolute;left:0;top:0;bottom:0;width:6px;background:var(--tone)}
.hero__head{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
h1{font-size:17px;font-weight:600;margin:0;color:var(--ink-2);letter-spacing:.01em}
.verdict{display:inline-flex;align-items:center;gap:8px;padding:6px 16px;border-radius:999px;
  background:var(--tone);color:#fff;font-weight:700;font-size:16.5px;letter-spacing:.01em;
  box-shadow:0 8px 18px -10px var(--tone)}
.hero__chips{display:flex;gap:6px;flex-wrap:wrap;margin:14px 0 0}
.hero__meaning{margin:14px 0 0;font-size:15.5px;color:var(--ink);max-width:70ch}
.hero__meta{margin:12px 0 0;color:var(--muted);font-size:12.5px}

/* ---------- chips / pills ---------- */
.chip{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:999px;
  font-size:12px;font-weight:600;background:var(--surface-2);border:1px solid var(--line);color:var(--ink-2)}
.chip--ok{background:var(--ok-soft);color:var(--ok);border-color:transparent}
.chip--warn{background:var(--warn-soft);color:var(--warn);border-color:transparent}
.chip--danger{background:var(--danger-soft);color:var(--danger);border-color:transparent}
.chip--mono{font-family:var(--mono);font-weight:500}
.pill{display:inline-block;font-family:var(--mono);font-size:11.5px;background:var(--surface-2);
  border:1px solid var(--line);border-radius:999px;padding:2px 9px;margin:0 4px 4px 0}

/* ---------- navigation ---------- */
.toc{position:sticky;top:0;z-index:9;display:flex;gap:6px;flex-wrap:wrap;
  margin:16px 0 14px;padding:10px 0;background:linear-gradient(var(--bg) 72%,transparent)}
.toc a{font-size:12.5px;color:var(--ink-2);text-decoration:none;padding:4px 11px;
  border-radius:999px;border:1px solid var(--line);background:var(--surface);white-space:nowrap}
.toc a:hover{border-color:var(--accent);color:var(--accent)}

/* ---------- cards ---------- */
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);
  box-shadow:var(--shadow);margin:0 0 16px;overflow:hidden}
.card__head{display:flex;align-items:center;gap:10px;padding:13px 20px;
  background:var(--surface-2);border-bottom:1px solid var(--line)}
.card__num{display:inline-grid;place-items:center;width:24px;height:24px;flex:0 0 auto;border-radius:8px;
  background:var(--accent-soft);color:var(--accent);font:700 12px/1 var(--mono)}
.card__title{margin:0;font-size:14.5px;font-weight:600;letter-spacing:.01em}
.card__note{margin-left:auto;font-size:12px;color:var(--muted);text-align:right}
.card__body{padding:18px 20px}
.card__body>:first-child{margin-top:0}
.card__body>:last-child{margin-bottom:0}

.sub{background:var(--surface-2);border:1px solid var(--line);border-radius:var(--radius-sm);
  padding:14px 16px;margin:14px 0}
.sub__title{margin:0 0 10px;font-size:13px;font-weight:600;color:var(--ink-2);
  display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.sub__title code{font-weight:500}
.sub--alert{background:var(--danger-soft);border-color:transparent}
.sub--warn{background:var(--warn-soft);border-color:transparent}

/* ---------- stats ---------- */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(158px,1fr));gap:10px}
.stat{background:var(--surface-2);border:1px solid var(--line);border-radius:var(--radius-sm);padding:10px 12px}
.stat__k{font-size:10.5px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--muted)}
.stat__v{margin-top:3px;font-size:14.5px;font-weight:600;word-break:break-word}
.stat--ok .stat__v{color:var(--ok)}
.stat--warn .stat__v{color:var(--warn)}
.stat--danger .stat__v{color:var(--danger)}

/* ---------- key/value ---------- */
.kv{display:grid;grid-template-columns:minmax(140px,230px) 1fr;gap:7px 18px;margin:0;font-size:13.5px}
.kv dt{color:var(--muted)}
.kv dd{margin:0;word-break:break-word}

/* ---------- tables ---------- */
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:var(--radius-sm);margin:12px 0}
table{border-collapse:collapse;width:100%;font-size:13px}
thead th{background:var(--surface-2);color:var(--muted);font-size:10.5px;font-weight:700;
  letter-spacing:.07em;text-transform:uppercase;text-align:left;padding:9px 12px;
  border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:9px 12px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover td{background:var(--surface-2)}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
tr.hit td{background:var(--accent-soft)}
tr.hit td:first-child{box-shadow:inset 3px 0 0 var(--accent)}
tr.hit:hover td{background:var(--accent-soft)}

/* ---------- bits ---------- */
code{font-family:var(--mono);font-size:12.3px;background:var(--surface-2);border:1px solid var(--line);
  border-radius:6px;padding:1px 5px;word-break:break-word}
pre{background:#0d1117;color:#e6edf3;border-radius:var(--radius-sm);padding:14px 16px;margin:12px 0;
  overflow:auto;font-family:var(--mono);font-size:12.3px;line-height:1.55}
ul{margin:8px 0;padding-left:20px}
li{margin:5px 0}
li::marker{color:var(--muted)}
p{margin:10px 0}
details{margin:12px 0}
summary{cursor:pointer;font-size:13px;font-weight:600;color:var(--accent);
  padding:6px 0;list-style-position:inside}
summary:hover{text-decoration:underline}
details[open]>summary{margin-bottom:6px}
.bar{display:block;height:8px;min-width:90px;background:var(--accent-soft);border-radius:999px;overflow:hidden}
.bar>i{display:block;height:100%;background:var(--accent);border-radius:999px}
.muted{color:var(--muted)}
.ok{color:var(--ok);font-weight:600}
.bad{color:var(--danger);font-weight:600}
.foot{color:var(--muted);font-size:12.5px;border-top:1px solid var(--line);margin-top:26px;padding-top:14px}
.foot code{font-size:11.8px}
@media (max-width:640px){
  .page{padding:16px 12px 56px}
  .kv{grid-template-columns:1fr;gap:2px 0}
  .kv dd{margin-bottom:8px}
  .hero{padding:18px}
}
@media print{
  :root{--bg:#fff;--surface:#fff;--surface-2:#f6f8fb;--shadow:none}
  .page{max-width:none;padding:0}
  .toc{display:none}
  .card,.sub,.stat{break-inside:avoid}
  pre{background:#f6f8fb;color:#111;border:1px solid var(--line)}
  details{display:block}
  details>summary{list-style:none}
}
"""


# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------
class _HTML(str):
    """Marks a value as already-safe markup. Never build one from user data."""


def _kv(rows) -> str:
    out = ['<dl class="kv">']
    for key, val in rows:
        body = val if isinstance(val, _HTML) or (isinstance(val, str) and val.startswith("<")) else esc(val)
        out.append(f"<dt>{esc(key)}</dt><dd>{body}</dd>")
    out.append("</dl>")
    return "".join(out)


def _h(markup: str) -> _HTML:
    return _HTML(markup)


def _stats(items) -> str:
    out = ['<div class="stats">']
    for key, val, kind in items:
        cls = f" stat--{kind}" if kind else ""
        out.append(f'<div class="stat{cls}"><div class="stat__k">{esc(key)}</div><div class="stat__v">{val}</div></div>')
    out.append("</div>")
    return "".join(out)


def _table(headers, rows, hit_rows=(), num_cols=()) -> str:
    out = ['<div class="tablewrap"><table><thead><tr>']
    for i, h in enumerate(headers):
        cls = ' class="num"' if i in num_cols else ""
        out.append(f"<th{cls}>{esc(h)}</th>")
    out.append("</tr></thead><tbody>")
    for idx, row in enumerate(rows):
        cls = " class='hit'" if idx in hit_rows else ""
        out.append(f"<tr{cls}>")
        for i, cell in enumerate(row):
            tcls = ' class="num"' if i in num_cols else ""
            out.append(f"<td{tcls}>{cell}</td>")
        out.append("</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


def _chip(text, kind="", mono=False) -> str:
    cls = "chip" + (f" chip--{kind}" if kind else "") + (" chip--mono" if mono else "")
    return f'<span class="{cls}">{esc(text)}</span>'


def _sub(title, body, kind="") -> str:
    cls = f" sub sub--{kind}" if kind else " sub"
    return f'<div class="{cls}"><div class="sub__title">{title}</div>{body}</div>'


def _card(num, title, body, note="") -> str:
    note_html = f'<div class="card__note">{note}</div>' if note else ""
    return (
        f'<section class="card" id="c{num}">'
        f'<div class="card__head"><span class="card__num">{num}</span>'
        f'<h2 class="card__title">{esc(title)}</h2>{note_html}</div>'
        f'<div class="card__body">{body}</div></section>'
    )


def _details(summary, body) -> str:
    return f"<details><summary>{esc(summary)}</summary>{body}</details>"


def _table_of(top_groups) -> str:
    rows = []
    for g in top_groups:
        pct = min(g["pct"], 100)
        rows.append(
            [
                f"<code>{esc(g['name'])}</code>",
                hum(g["bytes"]),
                f'<span class="muted">{g["pct"]:.1f}%</span>',
                f'<span class="bar" style="width:130px"><i style="width:{pct:.1f}%"></i></span>',
            ]
        )
    return _table([tr("t010"), tr("t011"), tr("t012"), ""], rows, num_cols=(1,))


# --------------------------------------------------------------------------
# sections
# --------------------------------------------------------------------------
def _hero(doc, label, color, meaning) -> str:
    v = doc["verdict"]
    flags = v.get("flags") or {}
    chips = "".join(_chip(tr(mid), cls) for flag, mid, cls in HERO_FLAGS if flags.get(flag))
    chips += _chip(v["code"], "mono", mono=True)
    tone = TONE.get(v["code"], "neutral")
    return (
        f'<header class="hero" style="--tone:var(--{tone})">'
        f'<div class="hero__head"><h1>{esc(tr("m009"))}</h1>'
        f'<span class="verdict">{esc(label)}</span></div>'
        f'<div class="hero__chips">{chips}</div>'
        f'<p class="hero__meaning">{esc(meaning)}</p>'
        f'<p class="hero__meta">{tr("m010", p0=esc(doc["generated_at"]), p1=esc(doc["os"]["system"]), p2=esc(doc["os"]["release"]), p3=esc(doc["os"]["host"]), p4=esc(doc["client"].get("version") or tr("n005")), p5=esc(SKILL_VERSION))}</p>'
        f"</header>"
    )


def _sec_conclusion(v) -> str:
    body = ["<ul>"]
    for r in v["reasons"]:
        body.append(f"<li>{esc(r)}</li>")
    body.append("</ul>")
    if v["falsifiers"]:
        inner = "<ul>" + "".join(f"<li>{esc(r)}</li>" for r in v["falsifiers"]) + "</ul>"
        body.append(_sub(esc(tr("m044")), inner, kind="warn"))
    return _card(1, tr("m012"), "".join(body), note=_chip(f'{tr("t027")}: {v["confidence"]}'))


def _sec_truth_table(v) -> str:
    rows, hit = [], ()
    for idx, (code, a, b, c, d) in enumerate(TRUTH_TABLE):
        mark = tr("m045") if code == v["code"] else ""
        rows.append(
            [
                f"<code>{esc(code)}</code> {esc(tr(VERDICTS[code][0]))}<span class='muted'>{esc(mark)}</span>",
                esc(tr(a)),
                esc(tr(b)),
                esc(tr(c)),
                esc(tr(d)),
            ]
        )
        if code == v["code"]:
            hit = (idx,)
    return _card(2, tr("m013"), _table([tr("t001"), tr("t002"), tr("t003"), tr("t004"), tr("t005")], rows, hit))


def _workspace_card(w) -> str:
    st = w.get("state") or {}
    accepted = bool(w.get("accepted_hash"))
    pending = w.get("pending") or []
    if accepted and not pending:
        state_chip = _chip(tr("t029"), "danger")
    elif pending:
        state_chip = _chip(tr("t030"), "warn")
    else:
        state_chip = _chip(tr("t031"), "warn")

    head = (
        f'<div class="card__head">'
        f'<h3 class="card__title"><code>{esc(w.get("workspace_path_display") or w["key"])}</code></h3>'
        f'<div class="card__note">{state_chip}</div></div>'
    )

    body = []
    body.append(
        _stats(
            [
                (tr("m139"), esc(iso(w.get("state_mtime"))), ""),
                (
                    "accepted hash",
                    (
                        f"<code>{esc(str(w.get('accepted_hash'))[:16])}…</code> " + _chip(tr("m165"), "danger")
                        if accepted
                        else f'<span class="muted">{esc(tr("m154"))}</span>'
                    ),
                    "",
                ),
                (tr("m140"), esc(st.get("failureCount", "–")), ""),
                (tr("m141"), esc(len(pending)) if pending else esc(tr("m155")), "danger" if pending else "ok"),
                (tr("m142"), esc((w.get("in_state_upload") or {}).get("kind") or "–"), ""),
            ]
        )
    )

    lc = w.get("last_compressed") or {}
    if lc:
        rows = [
            (tr("m166"), _h(f"{hum(lc.get('encryptedSizeBytes'))} <span class='muted'>({esc(lc.get('encryptedSizeBytes'))} B)</span>")),
            (tr("m167"), _h(f"{hum(lc.get('workspaceSizeBytes'))} <span class='muted'>({esc(lc.get('workspaceSizeBytes'))} B)</span>")),
            ("manifestHash", f"<code>{esc(str(lc.get('manifestHash'))[:16])}…</code>"),
            ("recordedAt", esc(iso((lc.get("recordedAt") or 0) / 1000))),
        ]
        # ratio_hint comes from our own message table (plus a float) and may carry
        # inline markup such as <b>; everything else in the report is escaped.
        extra = f'<p class="bad">⚠ {w["ratio_hint"]}</p>' if w.get("ratio_hint") else ""
        body.append(_sub(esc(tr("m104")), _kv(rows) + extra, kind="alert" if w.get("ratio_hint") else ""))

    for m in w["manifests"]:
        rows = [
            (tr("m168"), tr("m169", p0=esc(m.get("manifest_files")), p1=hum(m.get("bytes")))),
            (tr("m170"), esc(iso((m.get("createdAt") or 0) / 1000))),
            (tr("m171"), esc(m.get("workspaceKey"))),
            (
                tr("m172"),
                tr("m173", p0=esc(m["git_counts"]["git"]), p1=esc(m["git_counts"]["reflog"]), p2=esc(m["git_counts"]["refs"]), p3=esc(m["git_counts"]["worktree"])),
            ),
            (tr("m174"), f"{esc(len(m.get('branches') or []))} / {esc(len(m.get('worktrees') or []))}"),
        ]
        inner = [_kv(rows)]
        if m.get("top_groups"):
            inner.append(_sub(esc(tr("m106")), _table_of(m["top_groups"][:10])))
        if m.get("branches"):
            pills = "".join(f'<span class="pill">{esc(b)}</span>' for b in m["branches"][:200])
            inner.append(_details(tr("m175") + str(len(m["branches"])) + ")", f"<p>{pills}</p>"))
        if m.get("worktrees"):
            pills = "".join(f'<span class="pill">{esc(b)}</span>' for b in m["worktrees"])
            inner.append(_details(tr("t028") + f" ({len(m['worktrees'])})", f"<p>{pills}</p>"))
        if m.get("sensitive"):
            rows = [[esc(tr(s["kind"])), f"<code>{esc(s['path'])}</code>", f'<span class="num">{hum(s["sizeBytes"])}</span>'] for s in m["sensitive"][:60]]
            inner.append(_sub(esc(tr("m107")), _table([tr("t013"), tr("t006"), tr("t011")], rows, num_cols=(2,))))
        body.append(_sub(tr("m105", p0=esc(m["file"][:16])), "".join(inner)))

    if w.get("local_git_remotes"):
        items = "".join(f"<li><code>{esc(r['name'])}</code> → <code>{esc(r['url'])}</code></li>" for r in w["local_git_remotes"])
        body.append(_sub(esc(tr("m081")), f"<ul>{items}</ul>"))

    for e in w["extra_manifests"]:
        inner = []
        if e.get("included"):
            rows = [
                [esc(tr(EXTRA_MANIFEST_GROUPS.get(i.get("groupId"), i.get("groupId")))), f"<code>{esc(i.get('path'))}</code>", f'<span class="muted">{esc(i.get("source"))}</span>']
                for i in e["included"]
            ]
            inner.append(_table([tr("t014"), tr("t015"), tr("t007")], rows))
        body.append(_sub(esc(tr("m082", p0=e["file"][:12])), "".join(inner)))

    for wn in w.get("warnings", []):
        body.append(f'<p class="bad">⚠ {esc(wn)}</p>')

    return f'<section class="card">{head}<div class="card__body">{"".join(body)}</div></section>'


def _workspace_rank(w) -> int:
    """Most significant first: an accepted upload beats a pending artifact."""
    if w.get("accepted_hash") and not w.get("pending"):
        return 0
    if w.get("pending") or w.get("in_state_upload"):
        return 1
    if w.get("manifests"):
        return 2
    return 3


def _sec_workspaces(doc) -> str:
    if not doc["workspaces"]:
        body = f'<p class="muted">{esc(tr("m046"))}</p>'
    else:
        ordered = sorted(doc["workspaces"], key=lambda w: (_workspace_rank(w), str(w.get("workspace_path_display") or w["key"])))
        body = "".join(_workspace_card(w) for w in ordered)
    return _card(3, tr("m014"), body, note=f'{len(doc["workspaces"])}')


def _sec_detection(doc) -> str:
    det = doc.get("detection") or {}
    aux = doc.get("aux") or {}
    rows = [
        (tr("m109"), f"<code>{esc(det.get('platform'))}</code> <span class='muted'>{esc(det.get('platform_source'))}</span>"),
        (tr("m110"), f"<code>{esc(det.get('home'))}</code> <span class='muted'>{esc(det.get('home_source'))}</span>"),
        (tr("m111"), f"<code>{esc(det.get('data_dir'))}</code> <span class='muted'>{esc(det.get('data_dir_how'))}</span>"),
        ("checkpoints", f"<code>{esc(det.get('checkpoints'))}</code>"),
        (tr("m112"), f"<code>{esc(doc['client'].get('install_dir'))}</code> <span class='muted'>{esc(doc['client'].get('install_how'))}</span>"),
        ("Electron userData", f"<code>{esc(aux.get('appdata_client_dir'))}</code> <span class='muted'>{esc(aux.get('appdata_client_how'))}</span>"),
    ]
    body = [_kv(rows)]
    tried = doc["client"].get("candidates_tried") or []
    if tried:
        trows = [[f"<code>{esc(c['path'])}</code>", f'<span class="muted">{esc(c["how"])}</span>'] for c in tried[:40]]
        body.append(_details(tr("m016", p0=len(tried)), _table([tr("t006"), tr("t007")], trows)))
    return _card(4, tr("m015"), "".join(body))


def _sec_signatures(doc) -> str:
    sig = doc["signatures"]
    inv = {"verified-heuristic": _chip(tr("m158", p0=esc(sig.get("semantic_distance"))), "danger"),
           "pair-present-far-apart": _chip(tr("m159"), "warn"),
           "unverified": _chip(tr("m160"), "warn")}.get(sig.get("semantic_invariant"), esc(sig.get("semantic_invariant")))
    rows = [
        (tr("m113"), f"<code>{esc(sig.get('target'))}</code> <span class='muted'>{hum(sig.get('target_bytes'))} · mtime {esc(iso(sig.get('target_mtime')))}</span>"),
        (tr("m114"), esc(tr("m143")) if sig.get("scanned") else esc(tr("m144", p0=sig.get("note") or ""))),
        (tr("m115"), {True: _chip(tr("m156"), "danger"), False: _chip(tr("m157"), "ok"), None: "–"}[sig.get("gate_hit")]),
        (tr("m116"), _chip(f"{sig.get('mechanism_hits')} / {sig.get('mechanism_total')}", "ok" if sig.get("mechanism_hits") == sig.get("mechanism_total") else "warn", mono=True)),
        (tr("m117"), inv),
    ]
    body = [_kv(rows)]
    if sig.get("counts"):
        crows = [[f"<code>{esc(k)}</code>", f'<span class="num">{esc(c)}</span>'] for k, c in sorted(sig["counts"].items(), key=lambda x: -x[1])]
        body.append(_details(tr("m047"), _table([tr("t008"), tr("t009")], crows, num_cols=(1,))))
    return _card(5, tr("m017"), "".join(body))


def _sec_aux(doc) -> str:
    aux = doc["aux"]
    running = doc["processes"].get("running")
    rows = [
        (tr("m118"), f"<code>{esc(aux.get('data_dir'))}</code>"),
        (tr("m119"), _chip(tr("m145"), "danger") if aux.get("login_token_present") else _chip(tr("m146"), "")),
        (tr("m120"), (_chip(tr("m161"), "warn") if running else _chip(tr("m162"), "ok")) if running is not None else esc(tr("m147"))),
        (tr("m121"), _chip(tr("m148"), "ok") if (doc.get("lock_state") or {}).get("locked") else _chip(tr("m149"), "warn")),
        ("optimizeAgentExperienceEnabled", f"<code>{esc((aux.get('settings') or {}).get('optimizeAgentExperienceEnabled'))}</code>"),
        ("repoSnapshotIndexingEnabled", f"<code>{esc((aux.get('settings') or {}).get('repoSnapshotIndexingEnabled'))}</code>"),
        (tr("m122"), esc(", ".join(aux.get("certs") or []) or tr("m163"))),
    ]
    body = [_kv(rows)]
    if aux.get("sessions"):
        srows = []
        for s in aux["sessions"]:
            remote_txt = _chip(tr("m083"), "") if s.get("remote") else _chip(tr("m084"), "warn")
            srows.append([esc(s.get("kind")), f"<code>{esc(s.get('workspacePath'))}</code>", remote_txt])
        body.append(_sub(esc(tr("m048")), _table([tr("t013"), tr("t006"), tr("t016")], srows)))
    if doc.get("log_mentions"):
        lrows = [[esc(k), esc(c)] for k, c in doc["log_mentions"].items()]
        body.append(_sub(esc(tr("m049")), _table([tr("t017"), tr("t018")], lrows, num_cols=(1,))))
    return _card(6, tr("m018"), "".join(body))


def _sec_timeline(doc) -> str:
    rows = [[esc(iso(t)), esc(lbl)] for t, lbl in sorted(doc["timeline"])[::-1][:40]]
    body = _table([tr("t019"), tr("t020")], rows) if rows else f'<p class="muted">{esc(tr("m051"))}</p>'
    return _card(7, tr("m019"), body, note=f"{len(doc['timeline'])}")


def _sec_remediation(doc) -> str:
    body = [tr("m021")]
    for plat, cmds in lock_commands(doc["detection"]["platform"], doc["detection"]["checkpoints"]).items():
        body.append(f'<div class="sub"><div class="sub__title">{esc(plat)}</div><pre>{esc(cmds)}</pre></div>')
    body.append(tr("m022"))
    body.append(tr("m023"))
    return _card(8, tr("m020"), "".join(body))


def _sec_unknown(doc) -> str:
    if not doc["warnings"] and not doc["errors"]:
        body = f'<p class="muted">{esc(tr("m051"))}</p>'
    else:
        body = ["<ul>"]
        for w in doc["warnings"]:
            body.append(f'<li class="bad">⚠ {esc(w)}</li>')
        for e in doc["errors"]:
            body.append(tr("m050", p0=esc(e["where"]), p1=esc(e["error"])))
        body.append("</ul>")
        body = "".join(body)
    return _card(9, tr("m024"), body)


def _sec_reproduce(doc) -> str:
    return _card(10, tr("m025"), f'<pre>{esc(doc["reproduce"])}</pre>')


# --------------------------------------------------------------------------
def render_html(doc) -> str:
    v = doc["verdict"]
    label, color, meaning = VERDICTS[v["code"]]
    label, meaning = tr(label), tr(meaning)
    lang = "zh-CN" if messages.LANG == "zh" else "en"

    sections = [
        _sec_conclusion(v),
        _sec_truth_table(v),
        _sec_workspaces(doc),
        _sec_detection(doc),
        _sec_signatures(doc),
        _sec_aux(doc),
        _sec_timeline(doc),
        _sec_remediation(doc),
        _sec_unknown(doc),
        _sec_reproduce(doc),
    ]
    toc = "".join(
        f'<a href="#c{i}">{i}. {esc(tr(mid))}</a>'
        for i, mid in enumerate(("m012", "m013", "m014", "m015", "m017", "m018", "m019", "m020", "m024", "m025"), start=1)
    )
    return (
        "<!doctype html>"
        f'<html lang="{lang}"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<meta name="color-scheme" content="light dark">'
        f'<title>{esc(tr("m008", p0=label))}</title><style>{CSS}</style></head><body>'
        f'<div class="page">{_hero(doc, label, color, meaning)}'
        f'<nav class="toc">{toc}</nav><main>{"".join(sections)}</main>'
        f'<footer class="foot">{tr("m026")}</footer></div></body></html>'
    )
