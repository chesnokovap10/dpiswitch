// The live page. Unlike the other pages it is drawn here: the server sends
// the core's connections as a stream (see live.go) -- the whole state
// first, then what changed, every second -- and the rows are kept and
// redrawn in place.
//
// Failed dials come as rows of their own, with what the core said and how
// many times the same one failed.
//
// The stream is open only while the page is seen: a tab in the background,
// a window minimized, a pause close it, and the server stops asking the
// core once no page watches.
'use strict';
(function () {
  const root = document.getElementById('live');
  if (!root) return;
  const $ = id => document.getElementById(id);
  const W = JSON.parse($('lwords').textContent);
  const tbody = $('lrows');
  const locale = document.documentElement.lang || 'en';
  const IDLE = 30000; // no traffic this long: idle
  const MAX = 1000;   // rows drawn at most; the filter narrows the rest

  // id -> row; closed, failed and forbidden ones in the order they came
  const open = new Map(), closed = new Map(), failed = new Map(), blocked = new Map();
  let now = 0, keep = [500, 600], tot = null, ready = false, down = '', err = '';
  let es = null, paused = false, dropped = false;

  // what the page is looking at: kept per browser, a viewing preference
  const pref = {tab: 'open', route: '', noprobe: false, sort: 'start', desc: true};
  try { Object.assign(pref, JSON.parse(localStorage.getItem('live') || '{}')); } catch (e) {}
  const save = () => { try { localStorage.setItem('live', JSON.stringify(pref)); } catch (e) {} };
  // closed ones and failures cleared stay cleared for this tab, a reload included
  let clearedAt = 0;
  try { clearedAt = +sessionStorage.getItem('liveCleared') || 0; } catch (e) {}

  // --- words and numbers ---
  const fmt = (s, ...a) => { let i = 0; return s.replace(/%[ds]/g, () => a[i++]); };
  const dec = (x, d) => x.toLocaleString(locale, {minimumFractionDigits: d, maximumFractionDigits: d});
  function size(b) {
    if (b < 1024) return b + ' ' + W.B;
    const u = [W.KB, W.MB, W.GB];
    let i = -1;
    do { b /= 1024; i++; } while (b >= 1024 && i < u.length - 1);
    return dec(b, b < 10 ? 1 : 0) + ' ' + u[i];
  }
  const speed = b => b > 0 ? size(b) + W.perSec : '';
  function dur(ms) {
    const s = Math.max(0, Math.floor(ms / 1000));
    if (s < 60) return fmt(W.sec, s);
    if (s < 3600) return fmt(W.min, Math.floor(s / 60));
    return fmt(W.hour, Math.floor(s / 3600), Math.floor(s % 3600 / 60));
  }
  const label = r => W[r.route] || r.route;
  const clock = ms => new Date(ms).toLocaleTimeString(locale);
  const why = r => W['why.' + r.why] || r.why;

  // --- the stream ---
  function start() {
    if (es || paused || document.hidden) return;
    es = new EventSource(root.dataset.stream);
    es.onmessage = e => { dropped = false; take(JSON.parse(e.data)); };
    es.onerror = () => {
      dropped = true;
      // refused -- a key gone, the UI restarted on another: the browser
      // gives up on its own, so it is tried again here
      if (es && es.readyState === EventSource.CLOSED) {
        es = null;
        setTimeout(start, 5000);
      }
      state();
    };
    state();
  }
  function stop() {
    if (es) { es.close(); es = null; }
  }
  document.addEventListener('visibilitychange', () => document.hidden ? stop() : start());
  addEventListener('pagehide', stop);
  addEventListener('pageshow', e => { if (e.persisted) start(); });

  function take(m) {
    now = m.t; ready = m.ready; down = m.down || ''; err = m.err || ''; tot = m.tot;
    if (m.keep) keep = m.keep;
    if (m.kind === 'full') {
      // the state as it stands. The closed ones this page saw stay: the
      // server forgets them once no page has watched for a while.
      for (const r of open.values()) if (r._tr) r._tr.remove();
      open.clear();
      for (const r of m.conns || []) open.set(r.id, r);
      for (const r of m.closed || []) {
        if (r.end > clearedAt && !closed.has(r.id)) closed.set(r.id, r);
      }
      for (const r of m.failed || []) fail(r);
    } else {
      for (const r of m.add || []) {
        // sent again when the core told more of it: drawn anew
        const o = open.get(r.id);
        if (o && o._tr) o._tr.remove();
        open.set(r.id, r);
      }
      for (const u of m.upd || []) {
        const r = open.get(u.id);
        if (r) { r.up = u.up; r.down = u.down; r.us = u.us; r.ds = u.ds; r.act = u.act; }
      }
      for (const g of m.gone || []) {
        const r = open.get(g.id);
        if (!r) continue;
        open.delete(g.id);
        r.end = g.end; r.us = 0; r.ds = 0;
        closed.set(r.id, r);
      }
      for (const r of m.fail || []) fail(r);
    }
    trim(closed);
    trim(failed);
    trim(blocked);
    draw();
  }

  // A failure comes again when the same one fails again: the row on the
  // page takes its new count and time. A try the forbidden list refused
  // comes the same way, and is listed apart.
  function fail(r) {
    if (r.end <= clearedAt) return;
    const m = r.route === 'reject' ? blocked : failed;
    const o = m.get(r.id);
    if (!o) { m.set(r.id, r); return; }
    o.n = r.n; o.end = r.end; o.err = r.err; o._hay = null;
    if (o.ip !== r.ip) { o.ip = r.ip; if (o._ip) o._ip.textContent = r.ip || ''; }
    m.delete(o.id);
    m.set(o.id, o);
  }

  // the same ones the server keeps: the newest, none too old. Every row is
  // looked at: a failure counted again ends anew, and the rows that came
  // with a reload join after the ones this page kept.
  function trim(map) {
    const cut = now - keep[1] * 1000;
    const drop = r => { map.delete(r.id); if (r._tr) r._tr.remove(); };
    for (const r of [...map.values()]) if (r.end < cut) drop(r);
    if (map.size > keep[0]) {
      [...map.values()].sort((a, b) => a.end - b.end).slice(0, map.size - keep[0]).forEach(drop);
    }
  }

  // --- drawing ---
  function mk(r) {
    const tr = document.createElement('tr');
    tr.className = 'r-' + (r.probe ? 'probe' : r.route);
    const td = cls => { const c = tr.insertCell(); if (cls) c.className = cls; return c; };
    r._st = document.createElement('span');
    td('c-st').append(r._st);
    const p = td('c-p');
    p.textContent = r.proc || '—';
    p.title = r.path || '';
    const h = td('c-h');
    if (r.host) { h.textContent = r.host; h.title = r.host; }
    else { h.textContent = W.noname; h.classList.add('muted'); }
    r._ip = td();
    r._ip.textContent = r.ip || '';
    td('num').textContent = r.port || '';
    const b = document.createElement('span');
    b.className = 'pb p-' + r.proto + (r.sure ? '' : ' guess');
    b.textContent = r.proto;
    b.title = r.sure ? W.sure : W.byPort;
    td().append(b);
    const rt = td('c-r');
    rt.textContent = label(r) + (r.probe ? ' · ' + W.probe : '');
    rt.title = r.chain + (r.rule ? '\n' + r.rule : '');
    if (r.why) {
      // no speed and no bytes: what the core said takes their place
      const w = td('c-why');
      w.colSpan = 4;
      r._v = [w, td('num')];
    } else {
      r._v = [td('num'), td('num'), td('num'), td('num'), td('num')];
      r._v[4].title = W.started + ' ' + clock(r.start);
    }
    r._x = td('c-x');
    // the detector's own are not closed from here: that only breaks a check
    if (!r.probe && !r.why) {
      const x = document.createElement('button');
      x.type = 'button';
      x.className = 'lx';
      x.textContent = '✕';
      x.title = W.close;
      x.dataset.id = r.id;
      r._x.append(x);
    }
    r._last = [];
    r._tr = tr;
  }

  function paint(r) {
    if (!r._tr) mk(r);
    const st = r.why ? (r.route === 'reject' ? 'blocked' : 'failed') : r.end ? 'closed' : now - r.act > IDLE ? 'idle' : 'open';
    if (r._state !== st) {
      r._state = st;
      r._st.className = 'st ' + st;
      r._tr.classList.toggle('closed', st === 'closed');
      r._tr.classList.toggle('failed', st === 'failed' || st === 'blocked');
      if (st === 'closed') r._x.textContent = '';
    }
    const t = st === 'failed' ? W.failed : st === 'blocked' ? W.blocked : st === 'closed' ? fmt(W.closedAgo, dur(now - r.end)) : st === 'idle' ? W.idle : W.open;
    if (r._st.title !== t) r._st.title = t;
    let v;
    if (r.why) {
      // the last time it failed; the first, when it failed more than once
      v = [why(r) + (r.n > 1 ? ' ×' + r.n : ''), clock(r.end)];
      const t0 = r.err + (r.n > 1 ? '\n' + fmt(W.attempts, r.n) : ''), t1 = r.n > 1 ? fmt(W.firstAt, clock(r.start)) : '';
      if (r._v[0].title !== t0) r._v[0].title = t0;
      if (r._v[1].title !== t1) r._v[1].title = t1;
    } else {
      v = [speed(r.ds), speed(r.us), size(r.down), size(r.up), dur((r.end || now) - r.start)];
    }
    for (let i = 0; i < v.length; i++) {
      if (r._last[i] !== v[i]) { r._last[i] = v[i]; r._v[i].textContent = v[i]; }
    }
  }

  const NUM = {port: 1, ds: 1, us: 1, down: 1, up: 1, start: 1};
  function cmp(a, b) {
    const k = pref.sort;
    let d;
    if (NUM[k]) d = (a[k] || 0) - (b[k] || 0);
    else {
      const x = k === 'route' ? label(a) : a[k] || '', y = k === 'route' ? label(b) : b[k] || '';
      // the blank ones last, whichever way
      if (!x !== !y) return x ? -1 : 1;
      d = x.localeCompare(y, locale, {numeric: true});
    }
    if (pref.desc) d = -d;
    return d || b.start - a.start || (a.id < b.id ? -1 : 1);
  }

  const hay = r => r._hay ||
    (r._hay = [r.host, r.proc, r.ip, r.port, r.proto, label(r), r.why ? why(r) : ''].join(' ').toLowerCase());

  function draw() {
    const q = $('lfilter').value.trim().toLowerCase();
    const all = [open, closed, failed, blocked];
    const maps = pref.tab === 'all' ? all : [{open, closed, failed, blocked}[pref.tab] || open];
    const list = [], count = new Map(all.map(m => [m, 0]));
    for (const m of all) {
      for (const r of m.values()) {
        if (pref.noprobe && r.probe) continue;
        count.set(m, count.get(m) + 1);
        if (!maps.includes(m) || pref.route && r.route !== pref.route || q && !hay(r).includes(q)) continue;
        list.push(r);
      }
    }
    list.sort(cmp);
    const n = Math.min(list.length, MAX);
    for (let i = 0; i < n; i++) {
      const r = list[i];
      paint(r);
      const at = tbody.children[i];
      if (at !== r._tr) tbody.insertBefore(r._tr, at || null);
    }
    while (tbody.children.length > n) tbody.lastChild.remove();

    $('n-open').textContent = count.get(open);
    $('n-closed').textContent = count.get(closed);
    $('n-failed').textContent = count.get(failed);
    $('n-blocked').textContent = count.get(blocked);
    let e = '';
    if (!ready) e = W.loading;
    else if (list.length > MAX) e = fmt(W.shown, MAX, list.length);
    else if (!list.length) {
      e = q || pref.route ? W.noMatch : pref.tab === 'closed' ? W.noClosed : pref.tab === 'failed' ? W.noFailed :
        pref.tab === 'blocked' ? W.noBlocked : W.noOpen;
    }
    $('lempty').textContent = e;
    $('lempty').hidden = !e;

    if (tot) {
      $('t-open').textContent = open.size;
      $('t-ds').textContent = size(tot.ds) + W.perSec;
      $('t-us').textContent = size(tot.us) + W.perSec;
      $('t-tot').textContent = '↓ ' + size(tot.down) + ' · ↑ ' + size(tot.up);
      $('t-mem').textContent = W.sinceStart + (tot.mem ? ' · ' + fmt(W.memory, size(tot.mem)) : '');
    }
    const bn = $('lbanner');
    bn.textContent = down === 'stopped' ? W.stopped : down ? W.error + ' ' + err : '';
    bn.hidden = !down;
    state();
  }

  function state() {
    const s = $('lstate');
    s.textContent = paused ? W.paused : dropped ? W.reconnect : '● ' + W.live;
    s.title = paused ? W.pausedHint : dropped ? '' : W.liveHint;
    s.className = paused ? 'muted' : dropped ? 'warn-t' : 'ok-t';
    $('lpause').textContent = paused ? W.resume : W.pause;
  }

  // --- controls ---
  function on(group, attr, key) {
    const g = $(group);
    const mark = () => { for (const b of g.children) b.classList.toggle('on', b.dataset[attr] === pref[key]); };
    mark();
    g.addEventListener('click', e => {
      const b = e.target.closest('button');
      if (!b) return;
      pref[key] = b.dataset[attr];
      mark(); save(); draw();
    });
  }
  on('ltabs', 'tab', 'tab');
  on('lroutes', 'route', 'route');

  const np = $('lnoprobe');
  np.checked = pref.noprobe;
  np.addEventListener('change', () => { pref.noprobe = np.checked; save(); draw(); });
  $('lfilter').addEventListener('input', draw);

  const heads = root.querySelectorAll('th[data-sort]');
  function arrows() {
    for (const th of heads) {
      th.classList.toggle('asc', th.dataset.sort === pref.sort && !pref.desc);
      th.classList.toggle('desc', th.dataset.sort === pref.sort && pref.desc);
    }
  }
  arrows();
  for (const th of heads) {
    th.addEventListener('click', () => {
      const k = th.dataset.sort;
      // numbers start from the biggest, names from A
      pref.desc = k === pref.sort ? !pref.desc : !!NUM[k];
      pref.sort = k;
      arrows(); save(); draw();
    });
  }

  $('lpause').addEventListener('click', () => {
    paused = !paused;
    if (paused) stop(); else start();
    state();
  });
  $('lclear').addEventListener('click', () => {
    for (const m of [closed, failed, blocked]) {
      for (const r of m.values()) if (r._tr) r._tr.remove();
      m.clear();
    }
    // the server forgets them too: a failure after this is counted from
    // one, not added to the count before it
    fetch('/act/liveclear', {method: 'POST'}).catch(() => {});
    // before the first answer there is no server time yet
    clearedAt = now || Date.now();
    try { sessionStorage.setItem('liveCleared', String(now)); } catch (e) {}
    draw();
  });

  tbody.addEventListener('click', async e => {
    const x = e.target.closest('button.lx');
    if (!x) return;
    x.disabled = true;
    try {
      const r = await fetch('/act/liveclose', {method: 'POST', body: new URLSearchParams({id: x.dataset.id})});
      if (!r.ok) throw new Error((await r.text()).trim() || r.status + ' ' + r.statusText);
      // the row turns closed with the next tick
    } catch (err) {
      x.disabled = false;
      alert(W.closeFail + ' ' + err.message);
    }
  });

  draw();
  start();
})();
