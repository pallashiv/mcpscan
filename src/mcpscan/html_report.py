"""Self-contained HTML report (``--format html``).

One file, no network: inline CSS and JS locked down by a Content-Security-Policy that allows
only those exact inline blocks (by hash) and nothing else, so the page cannot load or send
anything. The findings ride along as a JSON data block and are rendered client-side with
``textContent`` only, so text from a hostile scanned file can never become markup.

The output is deterministic (no timestamps), like every other format.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, List, Optional

from . import __version__
from .models import Finding, ScanResult
from .report import locate
from .rules import RULE_INFO

_CSS = r"""
:root {
  color-scheme: light;
  --sans: system-ui, -apple-system, "Segoe UI", sans-serif;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  --page: #f9f9f7; --surface: #fcfcfb; --raised: #f3f2ee;
  --ink: #0b0b0b; --ink2: #52514e; --muted: #898781;
  --grid: #e1e0d9; --base: #c3c2b7; --border: rgba(11,11,11,.12);
  --accent: #2a78d6; --ok: #006300;
  --critical: #d03b3b; --high: #ec835a; --medium: #fab219; --low: #2a78d6;
  --shadow: 0 2px 6px -2px rgba(11,11,11,.14);
}
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) {
    color-scheme: dark;
    --page: #0d0d0d; --surface: #1a1a19; --raised: #222221;
    --ink: #ffffff; --ink2: #c3c2b7; --muted: #898781;
    --grid: #2c2c2a; --base: #383835; --border: rgba(255,255,255,.13);
    --accent: #3987e5; --ok: #0ca30c; --low: #3987e5;
    --shadow: 0 2px 6px -2px rgba(0,0,0,.5);
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --page: #0d0d0d; --surface: #1a1a19; --raised: #222221;
  --ink: #ffffff; --ink2: #c3c2b7; --muted: #898781;
  --grid: #2c2c2a; --base: #383835; --border: rgba(255,255,255,.13);
  --accent: #3987e5; --ok: #0ca30c; --low: #3987e5;
  --shadow: 0 2px 6px -2px rgba(0,0,0,.5);
}

* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0; background: var(--page); color: var(--ink);
  font: 14px/1.5 var(--sans); -webkit-font-smoothing: antialiased;
}
button { font: inherit; color: inherit; background: none; border: 0; padding: 0; cursor: pointer; text-align: inherit; }
button:focus-visible, input:focus-visible, select:focus-visible, summary:focus-visible {
  outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 4px;
}
code, pre, .mono { font-family: var(--mono); }
.sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
.sprite { position: absolute; width: 0; height: 0; overflow: hidden; }
svg.ic { width: 1em; height: 1em; flex: none; display: inline-block; vertical-align: -0.125em; }

.wrap { max-width: 1080px; margin: 0 auto; padding: 0 20px 56px; }

/* ---- top bar ---- */
.top { position: sticky; top: 0; z-index: 20; background: var(--surface); border-bottom: 1px solid var(--border); }
.top-in { max-width: 1080px; margin: 0 auto; padding: 11px 20px; display: flex; align-items: center; gap: 14px; }
.brand { font-weight: 650; letter-spacing: -.01em; font-size: 15px; }
a.brand { text-decoration: none; color: inherit; }
a.brand:hover { color: var(--accent); }
.file { color: var(--ink2); font: 12.5px var(--mono); padding: 3px 8px; border: 1px solid var(--border); border-radius: 5px;
  max-width: 34ch; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; background: var(--raised); }
.spacer { flex: 1; }
.local { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; color: var(--ink2); padding: 3px 8px;
  border-radius: 5px; border: 1px solid var(--border); }
.local svg { color: var(--ok); }
.iconbtn { width: 30px; height: 30px; border-radius: 6px; display: grid; place-items: center; border: 1px solid var(--border); background: var(--surface); color: var(--ink2); }
.iconbtn:hover { color: var(--ink); background: var(--raised); }

/* ---- page nav (only present when this report is one of a linked set, e.g. the demo site) ---- */
.pagenav { background: var(--raised); border-bottom: 1px solid var(--border); }
.pagenav-in { max-width: 1080px; margin: 0 auto; padding: 8px 20px; display: flex; align-items: center; gap: 4px; flex-wrap: wrap; font-size: 12.5px; }
.pagenav a { color: var(--ink2); text-decoration: none; padding: 4px 9px; border-radius: 5px; }
.pagenav a:hover { background: var(--surface); color: var(--ink); }
.pagenav a.home { color: var(--ink2); font-weight: 600; padding-left: 0; }
.pagenav a.current { background: var(--surface); color: var(--ink); border: 1px solid var(--border); font-weight: 600; }
.pagenav .sep { color: var(--muted); }

/* ---- summary ---- */
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; }
.summary { margin-top: 20px; padding: 14px 16px; }
.summary-main { display: flex; align-items: baseline; flex-wrap: wrap; gap: 6px 8px; }
.fig-wrap { display: flex; align-items: baseline; gap: 5px; font-weight: 700; font-size: 15px; }
.fig-wrap #fig { display: inline; }
.summary-sep { color: var(--muted); }
.verdict { color: var(--ink2); margin: 0; font-weight: 400; font-size: 13.5px; display: inline; }
.verdict b { color: var(--ink); font-weight: 600; }
.sevfilters { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
button.sev { cursor: pointer; border: 1px solid transparent; }
button.sev:hover { border-color: color-mix(in srgb, var(--c) 40%, transparent); }
button.sev[aria-pressed="true"] { background: color-mix(in srgb, var(--c) 22%, transparent); border-color: color-mix(in srgb, var(--c) 55%, transparent); }
button.sev[data-n="0"] { opacity: .45; }
.meta { margin-top: 10px; font-size: 12px; color: var(--muted); }

/* ---- filters ---- */
.filters { margin-top: 20px; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.search { position: relative; flex: 1 1 260px; }
.search svg { position: absolute; left: 11px; top: 50%; transform: translateY(-50%); color: var(--muted); width: 15px; height: 15px; pointer-events: none; }
input[type="search"], select {
  width: 100%; height: 34px; border-radius: 6px; border: 1px solid var(--border); background: var(--surface); color: var(--ink);
  font: inherit; font-size: 13.5px; padding: 0 10px;
}
input[type="search"] { padding-left: 33px; }
select { width: auto; max-width: 210px; padding-right: 28px; cursor: pointer; text-overflow: ellipsis; }
kbd { font: 11px var(--mono); color: var(--muted); border: 1px solid var(--border); border-radius: 4px; padding: 1px 5px; position: absolute; right: 9px; top: 50%; transform: translateY(-50%); }
.seg-ctl { display: inline-flex; padding: 2px; border-radius: 6px; border: 1px solid var(--border); background: var(--surface); }
.seg-ctl button { padding: 4px 10px; border-radius: 4px; font-size: 13px; color: var(--ink2); }
.seg-ctl button[aria-pressed="true"] { background: var(--raised); color: var(--ink); box-shadow: inset 0 0 0 1px var(--border); font-weight: 600; }
.ghost { height: 34px; padding: 0 10px; border-radius: 6px; color: var(--ink2); font-size: 13px; border: 1px solid transparent; }
.ghost:hover { background: var(--raised); color: var(--ink); }
.ghost[hidden] { display: none; }

/* ---- by rule ---- */
.panel { margin-top: 14px; padding: 14px 16px 10px; }
.panel-h { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; margin-bottom: 8px; }
.panel-h h2 { margin: 0; font-size: 12.5px; letter-spacing: .02em; font-weight: 600; color: var(--ink2); }
.panel-h span { font-size: 12px; color: var(--muted); }
.rules { display: grid; gap: 1px; }
.rrow { display: grid; grid-template-columns: minmax(150px, 280px) 1fr 34px; gap: 14px; align-items: center; padding: 5px 6px; margin: 0 -6px; border-radius: 5px; }
.rrow:hover { background: var(--raised); }
.rrow[aria-pressed="true"] { background: color-mix(in srgb, var(--accent) 10%, transparent); box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--accent) 45%, transparent); }
.rrow .nm { display: flex; gap: 9px; align-items: baseline; min-width: 0; }
.rrow .nm .mono { font-size: 12px; color: var(--ink2); }
.rrow .nm span:last-child { font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.track { height: 8px; border-radius: 0; background: transparent; position: relative; border-left: 1px solid var(--base); }
.bar { height: 100%; background: var(--accent); border-radius: 0; min-width: 3px; transition: width .35s ease; }
.rrow .n { text-align: right; font-size: 12.5px; color: var(--ink2); font-variant-numeric: tabular-nums; }

/* ---- findings ---- */
.list-h { margin: 26px 0 8px; display: flex; align-items: baseline; justify-content: space-between; }
.list-h h2 { margin: 0; font-size: 15px; letter-spacing: -.005em; }
.list-h span { color: var(--muted); font-size: 12.5px; }
.group { margin-top: 18px; }
.group-h { display: flex; align-items: center; gap: 8px; font-size: 12.5px; font-weight: 600; color: var(--ink2); margin: 0 2px 6px; }
.group-h svg { color: var(--c); width: 14px; height: 14px; }
.group-h .ct { color: var(--muted); font-weight: 500; }
.finding { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; margin-bottom: 6px; overflow: hidden; position: relative; transition: border-color .15s; }
.finding::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px; background: var(--c); }
.finding:hover { border-color: color-mix(in srgb, var(--c) 40%, var(--border)); }
.f-head { width: 100%; display: grid; grid-template-columns: 100px 64px minmax(0, 1fr) 16px; gap: 6px 12px; align-items: center; padding: 10px 14px 10px 17px; }
.sev { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; padding: 2px 8px 2px 6px; border-radius: 4px;
  background: color-mix(in srgb, var(--c) 14%, transparent); color: var(--ink); width: max-content; }
.sev svg { color: var(--c); width: 14px; height: 14px; }
.rid { font: 12px var(--mono); color: var(--ink2); }
.f-main { min-width: 0; }
.f-title { font-weight: 600; display: block; font-size: 13.5px; }
.f-where { font-size: 12.5px; color: var(--ink2); display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.f-where code { font-size: 12px; color: var(--ink); }
.chev { color: var(--muted); transition: transform .2s; }
.open .chev { transform: rotate(90deg); }
.f-body { padding: 2px 17px 16px 17px; display: grid; gap: 12px; border-top: 1px solid var(--grid); }
.f-body[hidden] { display: none; }
.f-body h4 { margin: 12px 0 5px; font-size: 11px; letter-spacing: .06em; text-transform: uppercase; color: var(--muted); font-weight: 600; }
.f-body p { margin: 0; color: var(--ink2); max-width: 78ch; font-size: 13px; }
.f-body p b { color: var(--ink); font-weight: 600; }
.ev { position: relative; margin: 0; padding: 10px 12px; border-radius: 5px; background: var(--raised); border: 1px solid var(--border);
  font-size: 12px; line-height: 1.55; white-space: pre-wrap; word-break: break-word; color: var(--ink); }
.actions { display: flex; flex-wrap: wrap; gap: 8px; }
.btn { display: inline-flex; align-items: center; gap: 6px; height: 30px; padding: 0 10px; border-radius: 5px; font-size: 12.5px; color: var(--ink2);
  border: 1px solid var(--border); background: var(--surface); }
.btn:hover { color: var(--ink); background: var(--raised); }
.btn.done { color: var(--ok); border-color: color-mix(in srgb, var(--ok) 50%, var(--border)); }

.empty { text-align: center; padding: 48px 20px; color: var(--ink2); border: 1px dashed var(--base); border-radius: 6px; }
.empty .big { width: 40px; height: 40px; color: var(--ok); margin: 0 auto 10px; display: block; }
.empty h3 { margin: 0 0 4px; color: var(--ink); font-size: 16px; }
.empty p { margin: 0 auto 14px; max-width: 52ch; font-size: 13.5px; }
details.supp { margin-top: 26px; }
details.supp summary { cursor: pointer; color: var(--ink2); font-size: 13px; padding: 8px 2px; }
details.supp .finding { opacity: .8; }
.note { font-size: 12px; color: var(--muted); margin-top: 8px; }
footer { margin-top: 36px; color: var(--muted); font-size: 12px; display: flex; flex-wrap: wrap; gap: 6px 18px; justify-content: space-between; }

#tip { position: fixed; z-index: 50; pointer-events: none; opacity: 0; transition: opacity .12s; max-width: 320px; padding: 8px 11px;
  border-radius: 6px; background: var(--surface); color: var(--ink); border: 1px solid var(--base); box-shadow: var(--shadow); font-size: 12.5px; }
#tip.on { opacity: 1; }
#tip .v { font-weight: 650; display: block; }
#tip .l { color: var(--ink2); display: block; }
#tip .row { display: flex; align-items: center; gap: 8px; margin-top: 3px; }
#tip .row i { width: 12px; height: 3px; border-radius: 2px; display: inline-block; }

.nojs table { width: 100%; border-collapse: collapse; font-size: 13px; margin: 20px 0; }
.nojs th, .nojs td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--grid); vertical-align: top; }

@media (max-width: 860px) {
  .f-head { grid-template-columns: 96px minmax(0, 1fr) 16px; }
  .f-head .rid { display: none; }
  .rrow { grid-template-columns: minmax(110px, 44%) 1fr 30px; }
  .file { display: none; } .local span { display: none; }
}
@media (prefers-reduced-motion: reduce) { * { transition: none !important; animation: none !important; } }
@media print {
  :root { color-scheme: light; --page: #fff; --surface: #fff; --raised: #f5f5f3; --ink: #000; --ink2: #333; --border: #ccc; --shadow: none; }
  .top, .filters, .actions, .ghost, #tip { display: none !important; }
  .f-body[hidden] { display: grid !important; } .finding { break-inside: avoid; }
}
"""

_SPRITE = r"""
<svg class="sprite" width="0" height="0" aria-hidden="true" focusable="false">
  <symbol id="i-critical" viewBox="0 0 20 20"><path fill="currentColor" d="M7 1.5h6L18.5 7v6L13 18.5H7L1.5 13V7L7 1.5Zm2.2 4.3v5.2h1.6V5.8H9.2Zm0 6.6v1.7h1.6v-1.7H9.2Z"/></symbol>
  <symbol id="i-high" viewBox="0 0 20 20"><path fill="currentColor" d="M10 2 19 17.5H1L10 2Zm-.8 5.6v5h1.6v-5H9.2Zm0 6.2v1.6h1.6v-1.6H9.2Z"/></symbol>
  <symbol id="i-medium" viewBox="0 0 20 20"><path fill="currentColor" d="m10 1.5 8.5 8.5-8.5 8.5L1.5 10 10 1.5Zm-.8 4.6v4.6h1.6V6.1H9.2Zm0 5.8v1.6h1.6v-1.6H9.2Z"/></symbol>
  <symbol id="i-low" viewBox="0 0 20 20"><path fill="currentColor" d="M10 1.5a8.5 8.5 0 1 1 0 17 8.5 8.5 0 0 1 0-17Zm-.8 4.4v.1h1.6v-.1H9.2Zm0 2.4v6h1.6v-6H9.2Z"/></symbol>
  <symbol id="i-shield" viewBox="0 0 20 20"><path fill="currentColor" d="M10 1.2 17 3.8v5.3c0 4.3-2.9 7.4-7 9.7-4.1-2.3-7-5.4-7-9.7V3.8l7-2.6Zm-1 9.3-2-2-1.1 1.1L9 12.7l4.6-4.6-1.1-1.1L9 10.5Z"/></symbol>
  <symbol id="i-lock" viewBox="0 0 20 20"><path fill="currentColor" d="M10 1.8a3.7 3.7 0 0 1 3.7 3.7v2H15a1 1 0 0 1 1 1v8.2a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V8.5a1 1 0 0 1 1-1h1.3v-2A3.7 3.7 0 0 1 10 1.8Zm0 1.7a2 2 0 0 0-2 2v2h4v-2a2 2 0 0 0-2-2Z"/></symbol>
  <symbol id="i-search" viewBox="0 0 20 20"><path fill="currentColor" d="M8.5 2a6.5 6.5 0 0 1 5.2 10.4l4.4 4.4-1.2 1.2-4.4-4.4A6.5 6.5 0 1 1 8.5 2Zm0 1.7a4.8 4.8 0 1 0 0 9.6 4.8 4.8 0 0 0 0-9.6Z"/></symbol>
  <symbol id="i-chev" viewBox="0 0 20 20"><path fill="currentColor" d="m7 4 6 6-6 6-1.3-1.3L10.4 10 5.7 5.3 7 4Z"/></symbol>
  <symbol id="i-copy" viewBox="0 0 20 20"><path fill="currentColor" d="M6 2h9a1 1 0 0 1 1 1v10h-1.7V3.7H6V2Zm-2 3h8a1 1 0 0 1 1 1v11a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1Zm.7 1.7v9.6h6.6V6.7H4.7Z"/></symbol>
  <symbol id="i-check" viewBox="0 0 20 20"><path fill="currentColor" d="m8 13.6-3.5-3.5-1.3 1.3L8 16.2 17 7.2l-1.3-1.3L8 13.6Z"/></symbol>
  <symbol id="i-sun" viewBox="0 0 20 20"><path fill="currentColor" d="M10 6a4 4 0 1 1 0 8 4 4 0 0 1 0-8Zm-.8-4.5h1.6v2.3H9.2V1.5Zm0 14.7h1.6v2.3H9.2v-2.3ZM1.5 9.2h2.3v1.6H1.5V9.2Zm14.7 0h2.3v1.6h-2.3V9.2ZM3.9 4.9l1.1-1.1 1.6 1.6-1.1 1.1-1.6-1.6Zm9.5 9.7 1.1-1.1 1.6 1.6-1.1 1.1-1.6-1.6ZM4.9 16.1l-1.1-1.1 1.6-1.6 1.1 1.1-1.6 1.6Zm9.7-9.5-1.1-1.1 1.6-1.6 1.1 1.1-1.6 1.6Z"/></symbol>
</svg>
"""

_JS = r"""
(() => {
"use strict";
const data = JSON.parse(document.getElementById("data").textContent);
const SEVS = ["critical", "high", "medium", "low"];
const LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const SVGNS = "http://www.w3.org/2000/svg";
const $ = (id) => document.getElementById(id);

// ---- tiny DOM helper: text only ever goes through textContent / createTextNode ----
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) if (kid != null) el.append(kid);
  return el;
}
function icon(name, cls) {
  const s = document.createElementNS(SVGNS, "svg");
  s.setAttribute("class", "ic" + (cls ? " " + cls : ""));
  s.setAttribute("aria-hidden", "true");
  const u = document.createElementNS(SVGNS, "use");
  u.setAttribute("href", "#i-" + name);
  s.append(u);
  return s;
}
const plural = (n, w) => n + " " + w + (n === 1 ? "" : "s");
const sevRank = (s) => SEVS.indexOf(s);
const setColor = (el, sev) => el.style.setProperty("--c", "var(--" + sev + ")");

// ---- state (mirrored into the URL hash so a view can be shared or bookmarked) ----
const state = { q: "", sev: new Set(), rule: "", group: "severity" };
const open = new Set();
function readHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  state.q = p.get("q") || "";
  state.rule = p.get("rule") || "";
  state.group = ["severity", "subject", "rule", "none"].includes(p.get("group")) ? p.get("group") : "severity";
  if (p.get("theme") === "light" || p.get("theme") === "dark") document.documentElement.dataset.theme = p.get("theme");
  state.sev = new Set((p.get("sev") || "").split(",").filter((s) => SEVS.includes(s)));
  for (const i of (p.get("open") || "").split(",")) if (/^\d+$/.test(i)) open.add(+i);
}
function writeHash() {
  const p = new URLSearchParams();
  if (state.q) p.set("q", state.q);
  if (state.sev.size) p.set("sev", SEVS.filter((s) => state.sev.has(s)).join(","));
  if (state.rule) p.set("rule", state.rule);
  if (state.group !== "severity") p.set("group", state.group);
  if (open.size) p.set("open", [...open].sort((a, b) => a - b).join(","));
  const s = p.toString();
  try { history.replaceState(null, "", s ? "#" + s : location.pathname + location.search); } catch (e) { /* file:// quirks */ }
}

const findings = data.findings.map((f, i) => ({ ...f, id: i, _hay: [f.rule_id, f.title, f.subject, f.field, f.evidence, f.remediation, f.severity].join(" ").toLowerCase() }));
const byQ = (f) => !state.q || f._hay.includes(state.q.toLowerCase());
const byRule = (f) => !state.rule || f.rule_id === state.rule;
const bySev = (f) => !state.sev.size || state.sev.has(f.severity);
const count = (list) => { const c = { critical: 0, high: 0, medium: 0, low: 0 }; for (const f of list) c[f.severity]++; return c; };

// ---- tooltip (one element, textContent only, also on keyboard focus) ----
const tip = $("tip");
function showTip(lines, x, y) {
  tip.replaceChildren(...lines.map((l) => l.key
    ? h("span", { class: "row" }, Object.assign(h("i"), {}), h("span", { class: "l", text: l.text }))
    : h("span", { class: l.cls, text: l.text })));
  lines.forEach((l, i) => { if (l.key) tip.children[i].firstChild.style.background = "var(--" + l.key + ")"; });
  tip.classList.add("on");
  const w = tip.offsetWidth, hgt = tip.offsetHeight;
  tip.style.left = Math.max(8, Math.min(innerWidth - w - 8, x + 14)) + "px";
  tip.style.top = Math.max(8, Math.min(innerHeight - hgt - 8, y + 16)) + "px";
}
const hideTip = () => tip.classList.remove("on");
function bindTip(el, linesFn) {
  el.addEventListener("pointermove", (e) => showTip(linesFn(), e.clientX, e.clientY));
  el.addEventListener("pointerleave", hideTip);
  el.addEventListener("focus", () => { const r = el.getBoundingClientRect(); showTip(linesFn(), r.left + 12, r.top + r.height / 2 - 24); });
  el.addEventListener("blur", hideTip);
}

// ---- clipboard with a fallback for pages opened from disk ----
async function copy(text, btn) {
  let ok = false;
  try { await navigator.clipboard.writeText(text); ok = true; } catch (e) {
    const t = h("textarea", { "aria-hidden": "true" }); t.value = text; t.style.position = "fixed"; t.style.opacity = "0";
    document.body.append(t); t.select();
    try { ok = document.execCommand("copy"); } catch (e2) { ok = false; }
    t.remove();
  }
  const label = btn.querySelector("span");
  const old = label.textContent;
  btn.classList.toggle("done", ok);
  label.textContent = ok ? "Copied" : "Copy failed";
  setTimeout(() => { btn.classList.remove("done"); label.textContent = old; }, 1400);
}
const copyBtn = (label, text) => {
  const b = h("button", { class: "btn", type: "button" }, icon("copy"), h("span", { text: label }));
  b.addEventListener("click", () => copy(text, b));
  return b;
};

// ---- summary line and severity filters ----
function renderSummary(shown, facet) {
  const total = findings.length, allc = count(findings);
  const figKids = [document.createTextNode(String(shown.length))];
  if (total !== shown.length) figKids.push(h("small", { text: "of " + total }));
  $("fig").replaceChildren(...figKids);
  const n = allc.critical, hi = allc.high;
  let msg;
  if (!total) msg = h("span", { class: "verdict" }, h("b", { text: "No findings." }), " None of Mcpscan's rules matched this file. That is not proof it is safe.");
  else if (n) msg = h("span", { class: "verdict" }, h("b", { text: plural(n, "critical issue") }), " need attention first" + (hi ? ", then " + plural(hi, "high-severity finding") : "") + ".");
  else if (hi) msg = h("span", { class: "verdict" }, h("b", { text: plural(hi, "high-severity finding") }), " worth reviewing first.");
  else msg = h("span", { class: "verdict" }, "No critical or high-severity findings. ", h("b", { text: plural(total, "lower-severity note") }), ".");
  $("verdict").replaceChildren(msg);

  const fc = count(facet);
  $("sevfilters").replaceChildren(...SEVS.map((s) => {
    const btn = h("button", { class: "sev", type: "button", "aria-pressed": String(state.sev.has(s)), "data-n": String(fc[s]) },
      icon(s), LABEL[s] + " ", h("b", { text: String(fc[s]) }));
    setColor(btn, s);
    btn.addEventListener("click", () => toggleSev(s));
    return btn;
  }));

  const rulesHit = new Set(findings.map((f) => f.rule_id)).size;
  const ruleTotal = Object.keys(data.rules).length;
  const parts = [
    data.tools ? plural(data.tools, "tool") + " scanned" : null,
    data.servers ? plural(data.servers, "server") + " scanned" : null,
    rulesHit + " of " + ruleTotal + " rules triggered",
    data.suppressed.length ? plural(data.suppressed.length, "finding") + " suppressed" : null,
  ].filter(Boolean);
  $("summary-meta").textContent = parts.join(" · ");
}

// ---- by rule ----
function renderRules() {
  const facet = findings.filter((f) => byQ(f) && bySev(f));
  const groups = new Map();
  for (const f of facet) { if (!groups.has(f.rule_id)) groups.set(f.rule_id, []); groups.get(f.rule_id).push(f); }
  const rows = [...groups.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
  const max = Math.max(1, ...rows.map((r) => r[1].length));
  $("rules-sub").textContent = rows.length ? plural(rows.length, "rule") + " triggered" : "";
  $("rules").replaceChildren(...rows.map(([rid, list]) => {
    const info = data.rules[rid] || { name: rid };
    const bar = h("div", { class: "bar" }); bar.style.width = (list.length / max * 100) + "%";
    const row = h("button", { class: "rrow", type: "button", "aria-pressed": String(state.rule === rid), "aria-label": rid + " " + info.name + ": " + plural(list.length, "finding") },
      h("span", { class: "nm" }, h("span", { class: "mono", text: rid }), h("span", { text: info.name })),
      h("span", { class: "track" }, bar),
      h("span", { class: "n", text: String(list.length) }));
    row.addEventListener("click", () => { state.rule = state.rule === rid ? "" : rid; update(); });
    const c = count(list);
    bindTip(row, () => [{ cls: "v", text: plural(list.length, "finding") }, { cls: "l", text: rid + ": " + info.name },
      ...SEVS.filter((s) => c[s]).map((s) => ({ key: s, text: c[s] + " " + LABEL[s].toLowerCase() }))]);
    return row;
  }));
  $("rules-panel").hidden = !rows.length;
}

// ---- findings list ----
function ignoreSnippet(f) {
  const o = { rule: f.rule_id, subject: f.subject };
  if (f.field) o.field = f.field;
  o.reason = "TODO: why this is accepted";
  return JSON.stringify({ ignore: [o] }, null, 2);
}
function findingText(f) {
  return "[" + f.severity.toUpperCase() + "] " + f.rule_id + " " + f.title + "\nwhere: " + f.subject + (f.field ? " > " + f.field : "") +
    (f.line ? " (line " + f.line + ")" : "") + "\nevidence: " + f.evidence + "\nfix: " + f.remediation;
}
function findingEl(f, extra) {
  const isOpen = open.has(f.id);
  const info = data.rules[f.rule_id] || { name: f.rule_id, summary: "" };
  const bodyId = "b" + (extra ? "s" : "") + f.id;
  const head = h("button", { class: "f-head", type: "button", "aria-expanded": String(isOpen), "aria-controls": bodyId },
    h("span", { class: "sev" }, icon(f.severity), LABEL[f.severity]),
    h("span", { class: "rid", text: f.rule_id }),
    h("span", { class: "f-main" },
      h("span", { class: "f-title", text: f.title }),
      h("span", { class: "f-where" }, h("code", { text: f.subject }), f.field ? " › " + f.field : "", f.line > 1 ? " · line " + f.line : "")),
    icon("chev", "chev"));
  const body = h("div", { class: "f-body", id: bodyId, hidden: !isOpen },
    h("div", {}, h("h4", { text: "Evidence" }), h("pre", { class: "ev" }, h("code", { text: f.evidence }))),
    h("div", {}, h("h4", { text: "How to fix" }), h("p", { text: f.remediation })),
    h("div", {}, h("h4", { text: "About this rule" }), h("p", {}, h("b", { text: info.name }), ": " + info.summary)),
    extra ? h("p", { class: "note", text: "Suppressed by " + extra.source + (extra.reason ? ": " + extra.reason : "") }) : null,
    h("div", { class: "actions" }, copyBtn("Copy finding", findingText(f)), extra ? null : copyBtn("Copy ignore rule", ignoreSnippet(f))));
  const el = h("article", { class: "finding" + (isOpen ? " open" : "") }, head, body);
  setColor(el, f.severity);
  head.addEventListener("click", () => {
    const now = body.hidden;
    body.hidden = !now; head.setAttribute("aria-expanded", String(now)); el.classList.toggle("open", now);
    if (!extra) { now ? open.add(f.id) : open.delete(f.id); writeHash(); }
  });
  return el;
}
function groupsOf(list) {
  const key = { severity: (f) => f.severity, subject: (f) => f.subject, rule: (f) => f.rule_id, none: () => "" }[state.group];
  const m = new Map();
  for (const f of list) { const k = key(f); if (!m.has(k)) m.set(k, []); m.get(k).push(f); }
  let keys = [...m.keys()];
  if (state.group === "severity") keys.sort((a, b) => sevRank(a) - sevRank(b));
  else keys.sort((a, b) => Math.min(...m.get(a).map((f) => sevRank(f.severity))) - Math.min(...m.get(b).map((f) => sevRank(f.severity))) || a.localeCompare(b));
  return keys.map((k) => [k, m.get(k)]);
}
function renderList(shown) {
  const box = $("list");
  box.replaceChildren();
  $("list-count").textContent = shown.length === findings.length ? plural(findings.length, "finding") : shown.length + " of " + findings.length + " shown";
  if (!findings.length) {
    box.append(h("div", { class: "empty" }, icon("shield", "big"), h("h3", { text: "Nothing to report" }),
      h("p", { text: "None of Mcpscan's rules matched. It checks what a server declares, not what its code does." })));
    return;
  }
  if (!shown.length) {
    const b = h("button", { class: "btn", type: "button" }, h("span", { text: "Clear filters" }));
    b.addEventListener("click", clearAll);
    box.append(h("div", { class: "empty" }, h("h3", { text: "No findings match these filters" }), h("p", { text: "Try a different search, or clear the filters." }), b));
    return;
  }
  for (const [k, list] of groupsOf(shown)) {
    const g = h("section", { class: "group" });
    if (state.group !== "none") {
      const lead = state.group === "severity" ? icon(k) : null;
      if (lead) setColor(lead, k);
      g.append(h("div", { class: "group-h" }, lead, h("span", { text: state.group === "severity" ? LABEL[k] : k }), h("span", { class: "ct", text: String(list.length) })));
    }
    for (const f of list) g.append(findingEl(f));
    box.append(g);
  }
}
function renderSuppressed() {
  const box = $("supp");
  box.replaceChildren();
  box.hidden = !data.suppressed.length && !data.staleBaseline;
  if (box.hidden) return;
  const sum = h("summary", { text: plural(data.suppressed.length, "suppressed finding") + " (baseline or ignore file)" });
  const inner = h("div", {});
  data.suppressed.forEach((s, i) => inner.append(findingEl({ ...s, id: 100000 + i }, s)));
  if (data.staleBaseline) inner.append(h("p", { class: "note", text: "The baseline has " + plural(data.staleBaseline, "stale entry") + " (fixed or renamed). Regenerate it with --write-baseline." }));
  box.append(sum, inner);
}

// ---- wiring ----
function toggleSev(s) { state.sev.has(s) ? state.sev.delete(s) : state.sev.add(s); update(); }
function clearAll() { state.q = ""; state.sev.clear(); state.rule = ""; $("q").value = ""; update(); }
function update() {
  const facet = findings.filter((f) => byQ(f) && byRule(f));
  const shown = facet.filter(bySev);
  renderSummary(shown, facet);
  renderRules();
  renderList(shown);
  $("clear").hidden = !(state.q || state.sev.size || state.rule);
  const rs = $("rule");
  if (rs.value !== state.rule) rs.value = state.rule;
  for (const b of document.querySelectorAll("[data-group]")) b.setAttribute("aria-pressed", String(b.dataset.group === state.group));
  writeHash();
}

function init() {
  document.title = "Mcpscan report · " + (data.path.split(/[\\/]/).pop() || data.path);
  $("file").textContent = data.path; $("file").title = data.path;
  $("meta").textContent = "mcpscan " + data.version + " · " + [data.tools ? plural(data.tools, "tool") : "", data.servers ? plural(data.servers, "server") : ""].filter(Boolean).join(", ") + " scanned";
  const rules = [...new Set(findings.map((f) => f.rule_id))].sort();
  $("rule").append(...rules.map((r) => h("option", { value: r, text: r + " · " + ((data.rules[r] || {}).name || "") })));
  readHash();
  $("q").value = state.q;
  $("q").addEventListener("input", (e) => { state.q = e.target.value.trim(); update(); });
  $("rule").addEventListener("change", (e) => { state.rule = e.target.value; update(); });
  for (const b of document.querySelectorAll("[data-group]")) b.addEventListener("click", () => { state.group = b.dataset.group; update(); });
  $("clear").addEventListener("click", clearAll);
  $("expand").addEventListener("click", () => {
    const all = document.querySelectorAll("#list .finding");
    const anyClosed = [...all].some((a) => !a.classList.contains("open"));
    for (const a of all) {
      const head = a.querySelector(".f-head");
      if (a.classList.contains("open") !== anyClosed) head.click();
    }
  });
  $("theme").addEventListener("click", () => {
    const root = document.documentElement;
    const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
    try { localStorage.setItem("mcpscan-theme", root.dataset.theme); } catch (e) { /* storage may be blocked */ }
  });
  try { const t = localStorage.getItem("mcpscan-theme"); if (t === "light" || t === "dark") document.documentElement.dataset.theme = t; } catch (e) { /* ignore */ }
  addEventListener("keydown", (e) => {
    if (e.key === "/" && document.activeElement !== $("q") && !e.metaKey && !e.ctrlKey) { e.preventDefault(); $("q").focus(); }
    else if (e.key === "Escape") { if (document.activeElement === $("q")) $("q").blur(); hideTip(); }
  });
  addEventListener("hashchange", () => { readHash(); $("q").value = state.q; update(); });
  renderSuppressed();
  update();
}
init();
})();
"""

_BODY = """
<header class="top"><div class="top-in">
  <div class="brand">Mcpscan</div>
  <span class="file" id="file"></span>
  <span class="spacer"></span>
  <span class="local" title="This page has a Content-Security-Policy that blocks all network access."><svg class="ic" aria-hidden="true"><use href="#i-lock"/></svg><span>Local report &middot; nothing was uploaded</span></span>
  <button class="iconbtn" id="theme" type="button" aria-label="Toggle light and dark theme"><svg class="ic" aria-hidden="true"><use href="#i-sun"/></svg></button>
</div></header>

<main class="wrap">
  <section class="card summary" aria-label="Summary">
    <div class="summary-main">
      <span class="fig-wrap"><span id="fig" aria-live="polite"></span> findings</span>
      <span id="verdict"></span>
    </div>
    <div class="sevfilters" id="sevfilters" role="group" aria-label="Filter by severity"></div>
    <div class="meta" id="summary-meta"></div>
  </section>

  <section class="filters" aria-label="Filters">
    <label class="search"><span class="sr-only">Search findings</span><svg class="ic" aria-hidden="true"><use href="#i-search"/></svg>
      <input id="q" type="search" placeholder="Search findings" autocomplete="off" spellcheck="false"><kbd>/</kbd></label>
    <label><span class="sr-only">Filter by rule</span><select id="rule"><option value="">All rules</option></select></label>
    <div class="seg-ctl" role="group" aria-label="Group findings by">
      <button type="button" data-group="severity" aria-pressed="true">Severity</button>
      <button type="button" data-group="subject" aria-pressed="false">Tool / server</button>
      <button type="button" data-group="rule" aria-pressed="false">Rule</button>
      <button type="button" data-group="none" aria-pressed="false">Flat</button>
    </div>
    <button class="ghost" id="clear" type="button" hidden>Clear filters</button>
    <span class="spacer"></span>
    <button class="ghost" id="expand" type="button">Expand / collapse all</button>
  </section>

  <section class="card panel" id="rules-panel">
    <div class="panel-h"><h2>Findings by rule</h2><span id="rules-sub"></span></div>
    <div class="rules" id="rules"></div>
  </section>

  <div class="list-h"><h2>Findings</h2><span id="list-count"></span></div>
  <div id="list"></div>
  <details class="supp" id="supp" hidden></details>

  <footer><span id="meta"></span><span>Static analysis only. Mcpscan never connects to or runs the servers it scans.</span></footer>
</main>
<div id="tip" role="tooltip"></div>
"""


def _esc(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


def _hash(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii") + "'"


def _finding_dict(f: Finding, text: Any) -> Dict[str, Any]:
    d = f.to_dict()
    d["line"] = locate(text, f.subject)
    return d


def _payload(result: ScanResult) -> Dict[str, Any]:
    return {
        "version": __version__,
        "path": result.path,
        "inputType": result.input_type,
        "tools": result.tool_count,
        "servers": result.server_count,
        "staleBaseline": result.stale_baseline,
        "rules": {rid: {"name": i.name, "summary": i.summary} for rid, i in RULE_INFO.items()},
        "findings": [_finding_dict(f, result.source_text) for f in result.findings],
        "suppressed": [
            {**_finding_dict(s.finding, result.source_text), "source": s.source, "reason": s.reason}
            for s in result.suppressed
        ],
    }


def _json_for_script(payload: Dict[str, Any]) -> str:
    """JSON that is safe inside a <script> block: no character can close the tag or start a comment."""
    raw = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    return raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _noscript_table(findings: List[Finding]) -> str:
    if not findings:
        return "<p>No findings.</p>"
    rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            _esc(f.severity.label), _esc(f.rule_id), _esc(f.subject + (" > " + f.field if f.field else "")),
            _esc(f.title), _esc(f.evidence))
        for f in findings
    )
    return ("<table><thead><tr><th>Severity</th><th>Rule</th><th>Where</th><th>Finding</th><th>Evidence</th></tr></thead>"
            "<tbody>" + rows + "</tbody></table>")


def _render_nav(nav: Dict[str, Any]) -> str:
    """A slim strip linking to sibling reports, e.g. the demo site's five examples.

    Not used for an ordinary ``mcpscan scan --format html`` report, which is a single
    standalone file with nothing to link to; only passed by callers (like the demo site
    generator) that know the report is part of a linked set.
    """
    links = "".join(
        '<a href="{}"{}>{}</a>'.format(_esc(item["href"]), ' class="current"' if item.get("current") else "", _esc(item["label"]))
        for item in nav["items"]
    )
    return (
        '<nav class="pagenav"><div class="pagenav-in">'
        '<a class="home" href="' + _esc(nav["home"]) + '">&larr; Home</a>'
        '<span class="sep">/</span>' + links +
        "</div></nav>\n"
    )


def render_html(result: ScanResult, nav: Optional[Dict[str, Any]] = None) -> str:
    csp = ("default-src 'none'; style-src " + _hash(_CSS) + "; script-src " + _hash(_JS) +
           "; img-src data:; base-uri 'none'; form-action 'none'")
    body = _BODY
    if nav:
        body = body.replace('<div class="brand">Mcpscan</div>', '<a class="brand" href="' + _esc(nav["home"]) + '">Mcpscan</a>', 1)
        body = body.replace('<main class="wrap">', _render_nav(nav) + '<main class="wrap">', 1)
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta http-equiv="Content-Security-Policy" content="' + csp + '">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="color-scheme" content="light dark">\n'
        "<title>Mcpscan report</title>\n"
        "<style>" + _CSS + "</style>\n</head>\n<body>\n"
        + _SPRITE + body +
        '<noscript><div class="wrap nojs"><h2>Mcpscan report</h2><p>This report needs JavaScript for its interactive view. '
        "The findings are listed here.</p>" + _noscript_table(result.findings) + "</div></noscript>\n"
        '<script type="application/json" id="data">' + _json_for_script(_payload(result)) + "</script>\n"
        "<script>" + _JS + "</script>\n</body>\n</html>\n"
    )
