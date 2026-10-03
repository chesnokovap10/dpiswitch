// The live page. Unlike the other pages it is drawn here: the server sends
// the core's connections as a stream (see live.go) -- the whole state
// first, then what changed, every second -- and the rows are kept and
// redrawn in place.
//
// Failed dials come as rows of their own, with what the core said and how
// many times the same one failed.
//
// The server keeps the connections closed and the failures of the core's
// whole run. The stream is open while the window is seen, on whatever page
// of it -- the table is drawn only while Live is shown, and is current the
// moment it is; a tab in the background, a window minimized, a pause close
// the stream; opened again, it brings only what came meanwhile.
//
// A row clicked is picked, and holds its place; right-clicked, it opens a
// menu that sends its site, address or program to one of the lists.
'use strict';
pageInit.live = function (sec) {
  const root = sec.querySelector('#live');
  if (!root) return;
  const $ = id => document.getElementById(id);
  // the page shown: the table is drawn; away, it is drawn when shown
  const shown = () => !sec.classList.contains('away');
  let stale = false;
  sec.addEventListener('pg:show', () => { if (stale) draw(); });
  sec.addEventListener('pg:hide', () => unpick());
  const W = JSON.parse($('lwords').textContent);
  const tbody = $('lrows');
  const locale = document.documentElement.lang || 'en';
  const IDLE = 30000; // no traffic this long: idle
  const MAX = 1000;   // rows drawn at most; the filter narrows the rest

  // id -> row; closed, failed and forbidden ones in the order they came
  const open = new Map(), closed = new Map(), failed = new Map(), blocked = new Map();
  let now = 0, keep = 100000, tot = null, ready = false, down = '', err = '';
  let es = null, paused = false, dropped = false;
  // the server's history this page holds, and the last of it seen
  let sess = '', lastSeq = 0;
  // the row picked, and where it was picked (see below)
  let sel = null, selAt = 0;
  const seen = q => { if (q > lastSeq) lastSeq = q; };
  // the row's menu, shared with the verdicts page (see rowmenu.js)
  const menu = rowMenu(W), closeMenu = () => menu.close();

  // what the page is looking at: kept per browser, a viewing preference
  const pref = {tab: 'open', route: '', sort: 'start', desc: true};
  try { Object.assign(pref, JSON.parse(localStorage.getItem('live') || '{}')); } catch (e) {}
  const save = () => { try { localStorage.setItem('live', JSON.stringify(pref)); } catch (e) {} };

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
  function started(t) {
    const d = new Date(t), today = d.toDateString() === new Date(now).toDateString();
    const hm = d.toLocaleTimeString(locale, {hour: '2-digit', minute: '2-digit'});
    return today ? fmt(W.sinceAt, hm) :
      fmt(W.sinceOn, d.toLocaleDateString(locale, {day: 'numeric', month: 'short'}) + ', ' + hm);
  }
  const speed = b => b > 0 ? size(b) + W.perSec : '';
  function dur(ms) {
    const s = Math.max(0, Math.floor(ms / 1000));
    if (s < 60) return fmt(W.sec, s);
    if (s < 3600) return fmt(W.min, Math.floor(s / 60));
    if (s < 2 * 86400) return fmt(W.hour, Math.floor(s / 3600), Math.floor(s % 3600 / 60));
    return fmt(W.day, Math.floor(s / 86400), Math.floor(s % 86400 / 3600));
  }
  const label = r => W[r.route] || r.route;
  const clock = ms => new Date(ms).toLocaleTimeString(locale);
  const why = r => W['why.' + r.why] || r.why;

  // --- the stream ---
  function start() {
    if (es || paused || document.hidden) return;
    // coming back to the history it holds, the page asks for what came since
    es = new EventSource(root.dataset.stream + (sess ? '?sess=' + encodeURIComponent(sess) + '&since=' + lastSeq : ''));
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

  function drop(map) {
    for (const r of map.values()) if (r._tr) r._tr.remove();
    map.clear();
  }

  function take(m) {
    now = m.t; ready = m.ready; down = m.down || ''; err = m.err || ''; tot = m.tot;
    if (m.keep) keep = m.keep;
    if (m.kind === 'full') {
      // the state as it stands. Of the history the page holds it takes what
      // came since; of another -- the core ran anew, a page cleared it -- it
      // drops what it held.
      const picked = sel && sel.id;
      drop(open);
      if (!(m.part && m.sess === sess)) {
        drop(closed); drop(failed); drop(blocked);
        lastSeq = 0;
      }
      sess = m.sess;
      for (const r of m.conns || []) open.set(r.id, r);
      for (const r of m.closed || []) {
        seen(r.seq);
        if (!closed.has(r.id)) closed.set(r.id, r);
      }
      for (const r of m.failed || []) fail(r);
      // the row picked is the same one drawn anew, or gone
      if (picked) {
        sel = open.get(picked) || closed.get(picked) || failed.get(picked) || blocked.get(picked) || null;
        if (!sel) closeMenu();
      }
    } else {
      for (const r of m.add || []) {
        // sent again when the core told more of it: drawn anew
        const o = open.get(r.id);
        if (o && o._tr) o._tr.remove();
        if (o && o === sel) sel = r;
        open.set(r.id, r);
      }
      for (const u of m.upd || []) {
        const r = open.get(u.id);
        if (r) { r.up = u.up; r.down = u.down; r.us = u.us; r.ds = u.ds; r.act = u.act; }
      }
      for (const g of m.gone || []) {
        seen(g.seq);
        const r = open.get(g.id);
        if (!r) continue;
        open.delete(g.id);
        r.end = g.end; r.seq = g.seq; r.us = 0; r.ds = 0;
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
    seen(r.seq);
    const m = r.route === 'reject' ? blocked : failed;
    const o = m.get(r.id);
    if (!o) { m.set(r.id, r); return; }
    o.n = r.n; o.end = r.end; o.err = r.err; o.seq = r.seq; o._hay = null;
    if (o.ip !== r.ip) { o.ip = r.ip; if (o._ip) o._ip.textContent = r.ip || ''; }
    m.delete(o.id);
    m.set(o.id, o);
  }

  // the same ones the server keeps: the newest, whatever their age. The
  // rows are in the order they came, a failure counted again moved last:
  // the oldest are first.
  function trim(map) {
    let n = map.size - keep;
    for (const r of map.values()) {
      if (n-- <= 0) break;
      map.delete(r.id);
      if (r._tr) r._tr.remove();
      if (r === sel) unpick();
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
    tr._r = r;
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
  // one collator for every comparison: localeCompare with options makes one
  // each time, and sorting a long history by a name took seconds
  const coll = new Intl.Collator(locale, {numeric: true});
  function cmp(a, b) {
    const k = pref.sort;
    let d;
    if (NUM[k]) d = (a[k] || 0) - (b[k] || 0);
    else {
      const x = k === 'route' ? label(a) : a[k] || '', y = k === 'route' ? label(b) : b[k] || '';
      // the blank ones last, whichever way
      if (!x !== !y) return x ? -1 : 1;
      d = coll.compare(x, y);
    }
    if (pref.desc) d = -d;
    // a row against itself is 0: firstSorted's scans stop at the pivot on
    // that, and with 1 the right one ran past the start of the list
    return d || b.start - a.start || (a.id === b.id ? 0 : a.id < b.id ? -1 : 1);
  }

  // The first k rows in the order of cmp, sorted: what the table draws. A
  // history of the core's whole run holds up to a hundred thousand rows a
  // tab, and sorting them all every second froze the page; the rows that
  // make it to the table are picked out first (quickselect), and only they
  // are sorted. cmp orders every two rows apart, so the pick is exact.
  function firstSorted(list, k) {
    if (list.length <= 2 * k) return list.sort(cmp).slice(0, k);
    let lo = 0, hi = list.length - 1;
    while (lo < hi) {
      const p = list[lo + Math.floor(Math.random() * (hi - lo + 1))];
      let i = lo, j = hi;
      while (i <= j) {
        while (cmp(list[i], p) < 0) i++;
        while (cmp(list[j], p) > 0) j--;
        if (i <= j) { const t = list[i]; list[i] = list[j]; list[j] = t; i++; j--; }
      }
      if (k - 1 <= j) hi = j;
      else if (k - 1 >= i) lo = i;
      else break;
    }
    return list.slice(0, k).sort(cmp);
  }

  const hay = r => r._hay ||
    (r._hay = [r.host, r.proc, r.ip, r.port, r.proto, label(r), r.why ? why(r) : ''].join(' ').toLowerCase());

  function draw() {
    if (!shown()) { stale = true; return; }
    stale = false;
    const q = $('lfilter').value.trim().toLowerCase();
    const all = [open, closed, failed, blocked];
    const maps = pref.tab === 'all' ? all : [{open, closed, failed, blocked}[pref.tab] || open];
    const list = [], count = new Map(all.map(m => [m, 0]));
    for (const m of all) {
      for (const r of m.values()) {
        count.set(m, count.get(m) + 1);
        if (!maps.includes(m) || pref.route && r.route !== pref.route || q && !hay(r).includes(q)) continue;
        list.push(r);
      }
    }
    const found = list.length;
    const rows = firstSorted(list, MAX);
    // the row picked stays where it was picked, whatever became of it since
    if (sel) {
      const i = rows.indexOf(sel);
      if (i >= 0) rows.splice(i, 1);
      rows.splice(Math.min(selAt, rows.length, MAX - 1), 0, sel);
    }
    const n = Math.min(rows.length, MAX);
    for (let i = 0; i < n; i++) {
      const r = rows[i];
      paint(r);
      r._tr.classList.toggle('sel', r === sel);
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
    else if (found > MAX) e = fmt(W.shown, MAX, found);
    else if (!found && !sel) {
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
      // when the core started: the totals count from then. A clock time, not
      // a span: a span would count the laptop's sleep too, the core lives
      // through it
      const m = $('t-mem');
      m.textContent = (tot.since ? started(tot.since) : W.sinceStart) +
        (tot.mem ? ' · ' + fmt(W.memory, size(tot.mem)) : '');
      m.title = tot.since ? fmt(W.coreStarted, new Date(tot.since).toLocaleString(locale)) : '';
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
    root.classList.toggle('paused', paused);
  }

  // --- controls ---
  // a tab takes the press, not the click, as the menu's do (see ui.js);
  // the click after it finds it taken, and a key's click still takes it
  function on(group, attr, key) {
    const g = $(group);
    const mark = () => { for (const b of g.children) b.classList.toggle('on', b.dataset[attr] === pref[key]); };
    mark();
    const pick = e => {
      const b = e.target.closest('button');
      if (!b || pref[key] === b.dataset[attr]) return;
      pref[key] = b.dataset[attr];
      unpick(); mark(); save(); draw();
    };
    g.addEventListener('pointerdown', e => { if (e.button === 0 && e.pointerType === 'mouse') pick(e); });
    g.addEventListener('click', pick);
  }
  on('ltabs', 'tab', 'tab');
  on('lroutes', 'route', 'route');

  $('lfilter').addEventListener('input', () => { unpick(); draw(); });

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
      unpick(); arrows(); save(); draw();
    });
  }

  $('lpause').addEventListener('click', () => {
    paused = !paused;
    if (paused) stop(); else start();
    state();
  });
  $('lclear').addEventListener('click', () => {
    if (sel && !open.has(sel.id)) unpick();
    drop(closed); drop(failed); drop(blocked);
    // the server forgets them too, for every page: a failure after this is
    // counted from one, not added to the count before it
    fetch('/act/liveclear', {method: 'POST'}).catch(() => {});
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

  // --- the row picked, and its menu ---
  // A row picked holds its place in the table: sorted by speed the rows
  // move every second, and the one looked at, or acted on from the menu,
  // must not move from under the cursor. A click anywhere else lets it go;
  // so does a change of what the table shows.
  function pick(r) {
    if (sel === r) return;
    unpick();
    sel = r;
    selAt = Math.max(0, Array.prototype.indexOf.call(tbody.children, r._tr));
    r._tr.classList.add('sel');
  }
  function unpick() {
    closeMenu();
    if (!sel) return;
    if (sel._tr) sel._tr.classList.remove('sel');
    sel = null;
  }

  // picked as the button goes down, not up: a click waits for the button
  // to come back, and the frame showed some 225 ms after the press
  tbody.addEventListener('pointerdown', e => {
    if (e.button !== 0 && e.button !== 2) return;
    const tr = e.target.closest('tr');
    if (tr && tr._r) pick(tr._r);
  });
  tbody.addEventListener('contextmenu', e => {
    const tr = e.target.closest('tr');
    if (!tr || !tr._r) return;
    e.preventDefault();
    const r = tr._r;
    pick(r);
    menu.open(whats(r), e.clientX, e.clientY, {path: r.path, run: () => reveal(r)});
  });
  document.addEventListener('mousedown', e => {
    if (sel && !e.target.closest('#lmenu, #lrows tr')) unpick();
  });
  document.addEventListener('keydown', e => {
    if (e.key !== 'Escape' || !shown()) return;
    if (menu.shown()) closeMenu(); else unpick();
  });

  // What goes to a list: the whole domain, the name alone, the address or
  // the program -- as the lists write them. The whole domain comes first:
  // a site's own names come and go (rr3.sn-4g5e.googlevideo.com). The
  // address only for a connection with no name: a list's address routes the
  // connections made to it by address, and a named one would go on as it
  // went.
  function whats(r) {
    const out = [];
    if (r.dom) out.push(['+.' + r.dom, W.whatDomain]);
    if (r.host && r.host !== r.dom) out.push([r.host, W.whatName]);
    if (r.ip && !r.host) out.push([r.ip, W.whatAddr]);
    // the detector's checks are its own: its program is not the user's
    if (r.proc && !r.probe) out.push([r.proc, W.whatProg]);
    return out;
  }

  async function reveal(r) {
    try {
      const res = await fetch('/act/livereveal', {method: 'POST', body: new URLSearchParams({id: r.id})});
      if (!res.ok) throw new Error((await res.text()).trim() || res.status + ' ' + res.statusText);
      const j = await res.json();
      if (!j.ok) menu.toast(j.msg, false);
    } catch (e) {
      menu.toast(W.notOpened + ' ' + e.message, false);
    }
  }

  draw();
  start();
};
