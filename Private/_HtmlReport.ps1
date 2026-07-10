# HTML report export (v0.1). Renders the run's summary + per-finding results into a
# single SELF-CONTAINED .html file: inline CSS/JS, no CDN or network dependency, so
# the report opens anywhere (including offline/air-gapped boxes) and can be archived
# next to the CSV. Light/dark follows the OS (prefers-color-scheme).
#
# Design notes (kept deliberately boring and readable):
#   - Result states use a fixed STATUS palette (good/warning/serious/critical +
#     neutral gray for Skipped), never the categorical series colors, and every
#     status is always paired with its text label -- color never carries meaning
#     alone (the light-mode warning/serious steps are sub-3:1 by design and rely
#     on that pairing).
#   - The category chart is a single-hue (blue) magnitude bar chart -- comparing
#     counts is a sequential job, not an identity job, so it gets one hue.
#   - The findings table IS the accessibility fallback: every number in the charts
#     can be read from it.

function Export-HtHtmlReport {
    param(
        [Parameter(Mandatory)] $Summary,
        [Parameter(Mandatory)] $Results,
        [Parameter(Mandatory)] [string] $Path,
        [hashtable] $Meta = @{}
    )

    $payload = [pscustomobject]@{
        meta    = [pscustomobject]$Meta
        summary = $Summary
        results = $Results
    }
    # '</' must not appear literally inside the embedded <script> block (it would
    # terminate it). '<\/' is the standard JSON-safe escape; JSON.parse restores it.
    $json = ($payload | ConvertTo-Json -Depth 6 -Compress) -replace '</', '<\/'

    $title = "HardeningTomcat - $($Meta.list) - $($Meta.host)"
    $titleEsc = $title -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;'

    $html = $script:HtHtmlReportTemplate.Replace('__HT_TITLE__', $titleEsc).Replace('__HT_PAYLOAD__', $json)
    Set-Content -Path $Path -Value $html -Encoding UTF8 -WhatIf:$false
}

# The template is a single-quoted here-string: nothing inside is interpolated by
# PowerShell, so the JS/CSS reads exactly as written. Placeholders __HT_TITLE__ and
# __HT_PAYLOAD__ are substituted with .Replace() above.
$script:HtHtmlReportTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__HT_TITLE__</title>
<style>
  :root {
    --plane: #f9f9f7; --surface: #fcfcfb;
    --ink: #0b0b0b; --ink-2: #52514e; --muted: #898781;
    --grid: #e1e0d9; --border: rgba(11,11,11,0.10);
    --ok: #0ca30c; --warn: #fab219; --serious: #ec835a; --crit: #d03b3b; --skip: #898781;
    --seq: #2a78d6; --seq-track: #e1e0d9;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --plane: #0d0d0d; --surface: #1a1a19;
      --ink: #ffffff; --ink-2: #c3c2b7; --muted: #898781;
      --grid: #2c2c2a; --border: rgba(255,255,255,0.10);
      --seq: #3987e5; --seq-track: #2c2c2a;
    }
  }
  * { box-sizing: border-box; margin: 0; }
  body {
    background: var(--plane); color: var(--ink);
    font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif;
    padding: 24px; max-width: 1180px; margin: 0 auto;
  }
  h1 { font-size: 20px; font-weight: 650; }
  .meta { color: var(--ink-2); margin: 4px 0 20px; font-size: 13px; }
  .meta b { color: var(--ink); font-weight: 600; }
  .card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 10px; padding: 18px 20px; margin-bottom: 16px;
  }
  .card h2 { font-size: 13px; font-weight: 600; color: var(--ink-2); margin-bottom: 12px;
             text-transform: uppercase; letter-spacing: .04em; }
  /* ---- KPI row ---- */
  .kpis { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 16px; }
  .tile { background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
          padding: 14px 18px; min-width: 128px; flex: 1; }
  .tile .lbl { font-size: 12px; color: var(--ink-2); margin-bottom: 2px; }
  .tile .val { font-size: 30px; font-weight: 650; }
  .tile .sub { font-size: 12px; color: var(--muted); margin-top: 2px; }
  .tile.hero .val { font-size: 44px; }
  .tile .dotlbl { display: inline-block; width: 9px; height: 9px; border-radius: 50%;
                  margin-right: 6px; vertical-align: baseline; }
  .meter { height: 6px; border-radius: 3px; background: var(--seq-track); margin-top: 10px; overflow: hidden; }
  .meter > div { height: 100%; border-radius: 3px; background: var(--seq); }
  /* ---- stacked result bar ---- */
  .stack { display: flex; height: 28px; border-radius: 4px; overflow: hidden; gap: 2px; }
  .stack .seg { min-width: 3px; }
  .legend { display: flex; gap: 18px; flex-wrap: wrap; margin-top: 12px; font-size: 13px; color: var(--ink-2); }
  .legend .dotlbl { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 6px; }
  .legend b { color: var(--ink); font-weight: 600; }
  /* ---- category bars ---- */
  .catrow { display: grid; grid-template-columns: 300px 1fr 52px; align-items: center;
            gap: 10px; padding: 3px 0; }
  .catrow .name { font-size: 12.5px; color: var(--ink-2); text-align: right;
                  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .catrow .track { height: 18px; position: relative; }
  .catrow .bar { height: 100%; background: var(--seq); border-radius: 0 4px 4px 0; min-width: 2px; }
  .catrow .val { font-size: 12.5px; color: var(--ink-2); font-variant-numeric: tabular-nums; }
  /* ---- table ---- */
  .filters { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 12px; align-items: center; }
  .filters select, .filters input {
    background: var(--surface); color: var(--ink); border: 1px solid var(--grid);
    border-radius: 6px; padding: 6px 9px; font: inherit; font-size: 13px;
  }
  .filters input { flex: 1; min-width: 200px; }
  .count { font-size: 12.5px; color: var(--muted); margin-left: auto; white-space: nowrap; }
  .tblwrap { overflow-x: auto; }
  table { border-collapse: collapse; width: 100%; font-size: 12.8px; }
  th { text-align: left; color: var(--muted); font-weight: 600; font-size: 11.5px;
       text-transform: uppercase; letter-spacing: .03em; padding: 6px 10px;
       border-bottom: 1px solid var(--grid); white-space: nowrap; }
  td { padding: 6px 10px; border-bottom: 1px solid var(--grid); vertical-align: top; }
  td.num { font-variant-numeric: tabular-nums; white-space: nowrap; }
  td .chip { display: inline-flex; align-items: center; gap: 6px; white-space: nowrap; font-weight: 600; }
  td .chip .dotlbl { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
  td.checked { color: var(--ink-2); max-width: 340px; overflow-wrap: anywhere; }
  td.obs { max-width: 220px; overflow-wrap: anywhere; color: var(--ink-2); }
  /* ---- tooltip ---- */
  #tip { position: fixed; pointer-events: none; background: var(--ink); color: var(--plane);
         padding: 6px 10px; border-radius: 6px; font-size: 12.5px; display: none; z-index: 10;
         max-width: 340px; }
  footer { color: var(--muted); font-size: 12px; margin-top: 20px; }
</style>
</head>
<body>
<h1>HardeningTomcat report</h1>
<div class="meta" id="meta"></div>
<div class="kpis" id="kpis"></div>
<div class="card"><h2>Result distribution</h2><div class="stack" id="stack"></div><div class="legend" id="legend"></div></div>
<div class="card"><h2>Failed findings by category</h2><div id="cats"></div></div>
<div class="card"><h2>Findings</h2>
  <div class="filters">
    <select id="fResult"></select>
    <select id="fSeverity"></select>
    <select id="fMethod"></select>
    <input id="fSearch" type="search" placeholder="Search name, id, path, value...">
    <span class="count" id="fCount"></span>
  </div>
  <div class="tblwrap"><table>
    <thead><tr><th>ID</th><th>Result</th><th>Sev</th><th>Lvl</th><th>Name</th><th>Method</th><th>Checked</th><th>Observed</th><th>Expected</th></tr></thead>
    <tbody id="tbody"></tbody>
  </table></div>
</div>
<div id="tip"></div>
<footer id="foot"></footer>
<script type="application/json" id="ht-data">__HT_PAYLOAD__</script>
<script>
(function () {
  'use strict';
  // Typographic chars via charcodes: the generating .ps1 must stay pure ASCII
  // (PowerShell 5.1 reads BOM-less files as ANSI and mojibakes UTF-8 literals).
  var MIDDOT = String.fromCharCode(183);   // middle dot separator
  var EMDASH = String.fromCharCode(8212);  // em dash
  var D = JSON.parse(document.getElementById('ht-data').textContent);
  var results = Array.isArray(D.results) ? D.results : (D.results ? [D.results] : []);
  var S = D.summary || {};
  var M = D.meta || {};

  // Status palette: fixed roles, always paired with a text label.
  var STATUS = {
    Passed:  { color: 'var(--ok)',      label: 'Passed'  },
    Low:     { color: 'var(--warn)',    label: 'Low'     },
    Medium:  { color: 'var(--serious)', label: 'Medium'  },
    High:    { color: 'var(--crit)',    label: 'High'    },
    Skipped: { color: 'var(--skip)',    label: 'Skipped' },
    Survey:  { color: 'var(--seq)',     label: 'Survey'  }
  };
  var ORDER = ['Passed', 'Low', 'Medium', 'High', 'Skipped', 'Survey'];

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }
  function dot(color) { var d = el('span', 'dotlbl'); d.style.background = color; return d; }
  function pct(n, total) { return total > 0 ? (100 * n / total).toFixed(1) + '%' : '0%'; }

  // ---- tooltip ----
  var tip = document.getElementById('tip');
  function tipOn(target, text) {
    target.addEventListener('mousemove', function (ev) {
      tip.textContent = text;
      tip.style.display = 'block';
      var x = Math.min(ev.clientX + 14, window.innerWidth - tip.offsetWidth - 8);
      tip.style.left = x + 'px';
      tip.style.top = (ev.clientY + 16) + 'px';
    });
    target.addEventListener('mouseleave', function () { tip.style.display = 'none'; });
  }

  // ---- meta line ----
  (function () {
    var m = document.getElementById('meta');
    function add(label, value) {
      if (value === undefined || value === null || value === '') return;
      if (m.childNodes.length) m.appendChild(document.createTextNode('  ' + MIDDOT + '  '));
      var b = el('b', null, value);
      m.appendChild(document.createTextNode(label + ' '));
      m.appendChild(b);
    }
    add('List:', M.list); add('Host:', M.host); add('Mode:', M.mode);
    add('Level:', M.level); add('Generated:', M.generated);
    add('Duration:', M.duration ? M.duration + 's' : '');
    document.getElementById('foot').textContent =
      'Generated by HardeningTomcat ' + (M.version || '') + ' ' + EMDASH +
      ' self-contained report; charts summarize the table below, which is the authoritative view.';
  })();

  // ---- KPI tiles ----
  (function () {
    var k = document.getElementById('kpis');
    var failed = (S.Low || 0) + (S.Medium || 0) + (S.High || 0);
    var hero = el('div', 'tile hero');
    hero.appendChild(el('div', 'lbl', 'Score'));
    hero.appendChild(el('div', 'val', (S.Percent !== undefined ? S.Percent + '%' : '-')));
    hero.appendChild(el('div', 'sub', S.Score || ''));
    var meter = el('div', 'meter'); var fill = el('div');
    fill.style.width = Math.max(0, Math.min(100, S.Percent || 0)) + '%';
    meter.appendChild(fill); hero.appendChild(meter);
    k.appendChild(hero);

    function tile(label, value, color, sub) {
      var t = el('div', 'tile');
      var l = el('div', 'lbl'); if (color) l.appendChild(dot(color));
      l.appendChild(document.createTextNode(label)); t.appendChild(l);
      t.appendChild(el('div', 'val', String(value)));
      if (sub) t.appendChild(el('div', 'sub', sub));
      return t;
    }
    k.appendChild(tile('Total findings', S.Total || 0));
    k.appendChild(tile('Passed', S.Passed || 0, STATUS.Passed.color));
    k.appendChild(tile('Failed', failed, STATUS.High.color,
      'High ' + (S.High || 0) + ' ' + MIDDOT + ' Med ' + (S.Medium || 0) + ' ' + MIDDOT + ' Low ' + (S.Low || 0)));
    k.appendChild(tile('Skipped', S.Skipped || 0, STATUS.Skipped.color, 'not evaluated'));
    if (M.mode === 'Strike') {
      k.appendChild(tile('Applied', S.Applied || 0, 'var(--seq)',
        (S.ApplyFailed ? S.ApplyFailed + ' FAILED' : 'no failures')));
    }
  })();

  // ---- stacked result bar (part-to-whole, status colors, 2px gaps) ----
  (function () {
    var counts = {};
    ORDER.forEach(function (s) { counts[s] = 0; });
    results.forEach(function (r) { if (counts[r.Result] !== undefined) counts[r.Result]++; });
    var total = results.length;
    var stack = document.getElementById('stack');
    var legend = document.getElementById('legend');
    ORDER.forEach(function (s) {
      var n = counts[s];
      if (!n) return;
      var seg = el('div', 'seg');
      seg.style.background = STATUS[s].color;
      seg.style.flexGrow = n;
      tipOn(seg, STATUS[s].label + ': ' + n + ' of ' + total + ' (' + pct(n, total) + ')');
      stack.appendChild(seg);
      var item = el('span');
      item.appendChild(dot(STATUS[s].color));
      item.appendChild(document.createTextNode(STATUS[s].label + ' '));
      var b = el('b', null, n + ' (' + pct(n, total) + ')');
      item.appendChild(b);
      legend.appendChild(item);
    });
  })();

  // ---- failed-by-category bars (magnitude -> one sequential hue) ----
  (function () {
    var byCat = {};
    results.forEach(function (r) {
      var isFail = (r.Result === 'Low' || r.Result === 'Medium' || r.Result === 'High');
      var c = r.Category || '(uncategorized)';
      if (!byCat[c]) byCat[c] = { fail: 0, total: 0 };
      byCat[c].total++;
      if (isFail) byCat[c].fail++;
    });
    var rows = Object.keys(byCat)
      .map(function (c) { return { cat: c, fail: byCat[c].fail, total: byCat[c].total }; })
      .filter(function (r) { return r.fail > 0; })
      .sort(function (a, b) { return b.fail - a.fail; });
    var TOP = 12;
    if (rows.length > TOP) {
      var rest = rows.slice(TOP);
      rows = rows.slice(0, TOP);
      rows.push({
        cat: 'Other (' + rest.length + ' categories)',
        fail: rest.reduce(function (a, r) { return a + r.fail; }, 0),
        total: rest.reduce(function (a, r) { return a + r.total; }, 0)
      });
    }
    var host = document.getElementById('cats');
    if (!rows.length) { host.appendChild(el('div', 'meta', 'No failed findings.')); return; }
    var max = rows[0].fail;
    rows.forEach(function (r) {
      var row = el('div', 'catrow');
      var name = el('span', 'name', r.cat); name.title = r.cat;
      var track = el('div', 'track');
      var bar = el('div', 'bar');
      bar.style.width = Math.max(2, 100 * r.fail / max) + '%';
      track.appendChild(bar);
      tipOn(row, r.cat + ': ' + r.fail + ' failed of ' + r.total + ' findings');
      row.appendChild(name); row.appendChild(track);
      row.appendChild(el('span', 'val', String(r.fail)));
      host.appendChild(row);
    });
  })();

  // ---- findings table with filters ----
  (function () {
    var tbody = document.getElementById('tbody');
    var selResult = document.getElementById('fResult');
    var selSev = document.getElementById('fSeverity');
    var selMethod = document.getElementById('fMethod');
    var search = document.getElementById('fSearch');
    var countEl = document.getElementById('fCount');

    function fill(sel, label, values) {
      sel.appendChild(new Option('All ' + label, ''));
      values.forEach(function (v) { sel.appendChild(new Option(v, v)); });
    }
    function distinct(field) {
      var seen = {};
      results.forEach(function (r) { var v = r[field]; if (v) seen[v] = true; });
      return Object.keys(seen).sort();
    }
    fill(selResult, 'results', ORDER.filter(function (s) {
      return results.some(function (r) { return r.Result === s; });
    }));
    fill(selSev, 'severities', distinct('Severity'));
    fill(selMethod, 'methods', distinct('Method'));

    function render() {
      var fR = selResult.value, fS = selSev.value, fM = selMethod.value;
      var q = search.value.toLowerCase();
      tbody.textContent = '';
      var shown = 0;
      results.forEach(function (r) {
        if (fR && r.Result !== fR) return;
        if (fS && r.Severity !== fS) return;
        if (fM && r.Method !== fM) return;
        if (q) {
          var hay = ((r.ID || '') + ' ' + (r.Name || '') + ' ' + (r.Checked || '') + ' ' +
                     (r.Observed || '') + ' ' + (r.Recommended || '') + ' ' + (r.Detail || '')).toLowerCase();
          if (hay.indexOf(q) === -1) return;
        }
        shown++;
        var tr = document.createElement('tr');
        tr.appendChild(el('td', 'num', r.ID || ''));
        var tdRes = el('td'); var chip = el('span', 'chip');
        var st = STATUS[r.Result] || { color: 'var(--muted)', label: r.Result };
        chip.appendChild(dot(st.color));
        chip.appendChild(document.createTextNode(st.label));
        tdRes.appendChild(chip); tr.appendChild(tdRes);
        tr.appendChild(el('td', null, r.Severity || ''));
        tr.appendChild(el('td', null, r.Level || ''));
        var tdName = el('td', null, r.Name || ''); tdName.title = r.Detail || '';
        tr.appendChild(tdName);
        tr.appendChild(el('td', null, r.Method || ''));
        tr.appendChild(el('td', 'checked', r.Checked || ''));
        tr.appendChild(el('td', 'obs', r.Observed || ''));
        var tdExp = el('td', 'obs', (r.Operator && r.Operator !== '=' ? r.Operator + ' ' : '') + (r.Recommended || ''));
        tr.appendChild(tdExp);
        tbody.appendChild(tr);
      });
      countEl.textContent = 'showing ' + shown + ' of ' + results.length;
    }
    [selResult, selSev, selMethod].forEach(function (s) { s.addEventListener('change', render); });
    search.addEventListener('input', render);
    render();
  })();
})();
</script>
</body>
</html>
'@
