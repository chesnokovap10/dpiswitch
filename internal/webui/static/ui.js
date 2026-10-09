// The pages are rendered by the Go server; this only saves what the page
// would otherwise reload for. A form with data-swap="id" is sent in the
// background and the server's answer replaces that element's content; a
// form with data-instant sends each control the moment it changes; an
// element with data-poll="url" refreshes itself every data-every seconds,
// one with data-sync="url" when an action elsewhere on the page answers,
// one with data-fresh="url" when its page is shown again.
//
// Every page lives in this one document (see "pages" below): the menu shows
// another at once, as a program's tabs do. Each page was a document of its
// own, and a tab of the menu took up to half a second to come up.
'use strict';

// Answers can come back out of order: a refresh started before a change
// may land after it and show the state before. Each element keeps the
// number of its latest request, and only that one's answer is shown.
const latest = new WeakMap();
function ticket(el) {
  const n = (latest.get(el) || 0) + 1;
  latest.set(el, n);
  return () => latest.get(el) === n;
}

// Requests to one part go one at a time. Two quick changes sent together
// were served together: the one sent last could be saved first, and its
// answer -- the one shown -- lacked the other change, though the file had
// both. In a queue the last answer comes after every save before it.
const queues = new Map();
function swap(url, body, target, changed) {
  const run = () => send(url, body, target, changed);
  const p = (queues.get(target) || Promise.resolve()).then(run, run);
  queues.set(target, p);
  return p;
}

function failed(el, text) {
  const m = document.createElement('div');
  m.className = 'msg bad';
  m.textContent = text;
  el.append(m);
}

// --- pages ---
// The page asked for comes with the document; the others are fetched right
// after it is drawn, and kept. Each is a section of <main>, one shown at a
// time; the rest are "away": not drawn, but laid out once and kept so
// (content-visibility, see ui.css) -- the verdicts' table of 1700 rows took
// 100 ms to lay out each time it was shown anew.
const main = document.getElementById('pages');
const pageNames = main ? main.dataset.pages.split(' ') : [];
const sections = new Map(), loading = new Map();
let current = main && main.querySelector('section.pg');
if (current) sections.set(current.dataset.page, current);
// what a page's own script does with its section, once it is in the
// document: pageInit[name](section) -- see live.js, verdicts.js. A page
// learns it is shown or left by the events pg:show and pg:hide.
const pageInit = {};

// a part by its id, in the page shown first: two pages may hold the same
// one -- the second tunnel's .conf dialog, on the overview and on its page
function byId(id) {
  const sel = '#' + CSS.escape(id);
  return (current && current.querySelector(sel)) || document.getElementById(id);
}
// whether an element is in a page or a tab not shown
const away = el => !!el.closest('.away');
// in a tab not shown, in whatever page
function tabAway(el) {
  const a = el.closest('.away');
  return !!a && !a.matches('.pg');
}
const period = el => (+el.dataset.every || 5) * 1000;
// fn once the next frame is drawn: what a switch shows comes first, the
// refreshes after it
function afterPaint(fn) { requestAnimationFrame(() => setTimeout(fn, 0)); }

function pageOf(u) {
  const n = u.pathname.slice(1);
  return u.origin === location.origin && pageNames.includes(n) ? n : '';
}

// load: a page's section, fetched once
function load(name) {
  if (sections.has(name)) return Promise.resolve(sections.get(name));
  if (!loading.has(name)) {
    const p = fetch('/frag/' + name + '/content').then(async r => {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const html = await r.text();
      const sec = document.createElement('section');
      sec.className = 'pg away';
      sec.dataset.page = name;
      sec.dataset.url = '/' + name;
      sec.innerHTML = html;
      main.append(sec);
      sections.set(name, sec);
      // drawn just now: the first refresh is one period away
      const now = Date.now();
      for (const el of sec.querySelectorAll('[data-poll]')) if (!tabAway(el)) due.set(el, now + period(el));
      init(sec);
      warm(sec);
      return sec;
    });
    loading.set(name, p);
    p.catch(() => loading.delete(name));
  }
  return loading.get(name);
}

function init(sec) {
  const f = pageInit[sec.dataset.page];
  if (f) {
    try { f(sec); } catch (e) { console.error(e); }
  }
  for (const el of sec.querySelectorAll('[data-follow]')) if (follows(el, true)) el.scrollTop = el.scrollHeight;
  // a page's tabs not shown are fetched now, to show at once when picked
  for (const p of sec.querySelectorAll('[data-panels] > [data-poll]')) {
    if (p.childNodes.length) continue;
    due.set(p, Date.now() + period(p));
    poll(p);
  }
}

// A page fetched is laid out once, unseen, and kept so: the first time it
// is shown costs a frame, as every other time does. So is one whose part
// was drawn anew while away.
function warm(sec) {
  if (!sec.classList.contains('away') || sec.classList.contains('warm')) return;
  sec.classList.add('warm');
  afterPaint(() => sec.classList.remove('warm'));
}
const warming = new WeakMap();
function warmSoon(sec) {
  clearTimeout(warming.get(sec));
  warming.set(sec, setTimeout(() => warm(sec), 100));
}

// show: one page in place of the one shown
function show(sec) {
  const was = current;
  current = sec;
  const name = sec.dataset.page;
  sec.classList.remove('away', 'warm');
  if (was && was !== sec) {
    was.classList.add('away');
    // a plain form's result is said once, on the page it came back to
    for (const f of was.querySelectorAll('.pgflash')) f.remove();
    was.dispatchEvent(new Event('pg:hide'));
  }
  document.body.dataset.page = name;
  for (const a of document.querySelectorAll('#navitems a')) a.classList.toggle('on', a.getAttribute('href') === '/' + name);
  // the frame's parts are drawn for the page shown: its menu item lit
  for (const id of ['header', 'navitems', 'svcbox']) {
    const el = document.getElementById(id);
    if (!el || !el.dataset.poll) continue;
    el.dataset.poll = el.dataset.poll.replace(/^\/frag\/[^/]+\//, '/frag/' + name + '/');
    ticket(el); // an answer on its way is of the page before
  }
  following(sec);
  sec.dispatchEvent(new Event('pg:show'));
  afterPaint(() => { if (current === sec) freshen(sec); });
}

// freshen: what a page or a tab just shown says, brought up to date. A
// part refreshing by itself is asked when its period is over -- it waited
// while away; one refreshed by actions, and one marked data-fresh, always,
// unless the user has edits in it not saved.
function freshen(root) {
  const now = Date.now();
  const sel = '[data-poll],[data-sync],[data-fresh]';
  for (const el of [root, ...root.querySelectorAll(sel)]) {
    if (!el.matches(sel) || away(el)) continue;
    if (el.dataset.poll) {
      if ((due.get(el) || 0) > now) continue;
      due.set(el, now + period(el));
    } else if (el.dataset.fresh && dirty(el)) continue;
    poll(el);
  }
}

// dirty: whether a part has a field changed and not saved
function dirty(el) {
  for (const f of el.querySelectorAll('textarea, input, select')) {
    if (f.type === 'checkbox' || f.type === 'radio') {
      if (f.checked !== f.defaultChecked) return true;
    } else if (f.tagName === 'SELECT') {
      for (const o of f.options) if (o.selected !== o.defaultSelected) return true;
    } else if (f.type !== 'hidden' && f.type !== 'file' && f.value !== f.defaultValue) return true;
  }
  return false;
}

// setURL: the address bar follows what is shown; push for a new step back
function setURL(u, push) {
  const to = u.pathname + u.search + u.hash;
  if (to !== location.pathname + location.search + location.hash) {
    if (push) history.pushState({page: pageOf(u)}, '', to);
    else history.replaceState(Object.assign({}, history.state), '', to);
  }
  const sec = sections.get(pageOf(u));
  if (sec) sec.dataset.url = u.pathname + u.search;
}

// go: show the page of url, and its tab. A link of the menu, with no tab
// of its own, shows the page as it was left.
let navs = 0;
async function go(url, push) {
  const u = new URL(url, location.href);
  const name = pageOf(u);
  if (!name) { location.href = u.href; return; }
  const n = ++navs;
  let sec = sections.get(name);
  if (!sec) {
    try { sec = await load(name); } catch (e) { location.href = u.href; return; }
    if (n !== navs) return; // another was asked for meanwhile
  }
  // a step back shows its address as it is: no tab in it is the first
  if (push && !u.search && sec.dataset.url) u.search = new URL(sec.dataset.url, location.href).search;
  if (sec !== current) show(sec);
  for (const t of sec.querySelectorAll('[data-tabs]')) {
    const first = t.querySelector('[data-tab]');
    const v = u.searchParams.get(t.dataset.tabs) || (!push && first && first.dataset.tab);
    if (v) tab(sec, t.dataset.tabs, v);
  }
  setURL(u, push);
  // what else of the address is the page's own: the verdicts' network
  sec.dispatchEvent(new CustomEvent('pg:url', {detail: u}));
  if (u.hash) point(u.hash.slice(1));
}
addEventListener('popstate', () => go(location.href, false));

// A page's own tabs -- the verdicts', the logs' -- each with a part of its
// own, kept: [data-tabs=param] holds the links (data-tab), [data-panels=
// param] the parts, one shown. The address says the tab as param.
function tab(sec, param, value, byUser) {
  const bar = sec.querySelector('[data-tabs="' + param + '"]');
  const stack = sec.querySelector('[data-panels="' + param + '"]');
  const panel = stack && [...stack.children].find(p => p.dataset.tab === value);
  if (!bar || !panel || !panel.classList.contains('away')) return;
  for (const a of bar.querySelectorAll('[data-tab]')) a.classList.toggle('on', a.dataset.tab === value);
  for (const p of stack.children) p.classList.toggle('away', p !== panel);
  // the bar's own refresh draws its counts with this tab lit
  if (bar.dataset.poll) {
    bar.dataset.poll = withParam(bar.dataset.poll, param, value);
    ticket(bar);
  }
  following(panel);
  stack.dispatchEvent(new Event('tab:show'));
  if (byUser) {
    const loc = new URL(location.href);
    loc.searchParams.set(param, value);
    setURL(loc, true);
  }
  afterPaint(() => { if (!away(panel)) freshen(panel); });
}

function withParam(url, name, value) {
  const u = new URL(url, location.href);
  if (value === '' || value == null) u.searchParams.delete(name);
  else u.searchParams.set(name, value);
  return u.pathname + u.search;
}

// A link to a page shows it at once. The menu and the tabs take the press,
// not the click: a click waits for the button to come back up, a quarter
// of a second after it went down. The click that follows finds the page
// already shown, and does nothing more.
function pageLink(e) {
  if (e.button !== 0 || e.ctrlKey || e.shiftKey || e.metaKey || e.altKey) return null;
  const a = e.target.closest('a[href]');
  if (!a || a.target || a.hasAttribute('download')) return null;
  const u = new URL(a.href, location.href);
  return pageOf(u) ? {a, u} : null;
}
function follow(a, u) {
  const bar = a.closest('[data-tabs]');
  if (bar && a.dataset.tab && current && current.contains(bar)) {
    tab(current, bar.dataset.tabs, a.dataset.tab, true);
    return;
  }
  go(u, true);
}
document.addEventListener('pointerdown', e => {
  if (e.pointerType !== 'mouse') return;
  const l = pageLink(e);
  if (l && l.a.closest('#navitems, [data-tabs]')) follow(l.a, l.u);
});
document.addEventListener('click', e => {
  if (e.defaultPrevented) return;
  const l = pageLink(e);
  if (!l) return;
  e.preventDefault();
  follow(l.a, l.u);
});

// the language switch comes back to the page shown, with its tab
document.addEventListener('click', e => {
  const a = e.target.closest('#langs a');
  if (!a) return;
  const u = new URL(a.href, location.href);
  u.searchParams.set('back', location.pathname + location.search);
  a.href = u.pathname + u.search;
}, true);

// changed: the control an instant form sent. The answer redraws the whole
// form, and a field being typed into meanwhile -- another one -- would
// get the saved value back and lose what was typed; it keeps its text,
// focus and caret. The control sent takes the server's value: a refused
// change shows as refused.
async function send(url, body, target, changed) {
  const el = byId(target);
  if (!el) return;
  const current = ticket(el);
  try {
    const r = await fetch(url, {method: 'POST', body});
    // an HTTP error is not a part of the page: a refused key, a server
    // error page would have replaced the form
    if (!r.ok) {
      if (current()) failed(el, 'HTTP ' + r.status + ' ' + r.statusText);
      return;
    }
    const html = await r.text();
    if (!current()) return;
    const a = document.activeElement;
    const keep = changed !== undefined && a && el.contains(a) && a.name && a.name !== changed &&
      'value' in a ? {name: a.name, value: a.value, s: a.selectionStart, e: a.selectionEnd} : null;
    el.innerHTML = html;
    reblink(el);
    el._html = undefined;
    // an answer may carry a new value for a field outside it: the DNS test
    // puts the address that answered in place of the one written
    for (const f of el.querySelectorAll('[data-fill]')) {
      const t = (el.closest('.pg') || document).querySelector('[name="' + CSS.escape(f.dataset.fill) + '"]');
      if (t) t.value = f.textContent;
      f.remove();
    }
    // a dialog whose save was refused comes back open, on what was typed
    for (const d of el.querySelectorAll('dialog[data-show]')) d.showModal();
    // an action may change what other parts show: the mode is in the header
    // and in the settings, and one changed in either left the other showing
    // the old one. The rest are drawn afresh now, not in five seconds or
    // never -- those of a page not shown when it is; those with no period
    // of their own are data-sync.
    for (const p of document.querySelectorAll('[data-poll],[data-sync]')) {
      if (p === el || p.contains(el) || el.contains(p)) continue;
      if (p.dataset.poll) due.set(p, 0); else poll(p);
    }
    if (keep) {
      const b = el.querySelector('[name="' + CSS.escape(keep.name) + '"]');
      if (b) {
        b.value = keep.value;
        b.focus();
        try { b.setSelectionRange(keep.s, keep.e); } catch (e) { /* not a text field */ }
      }
    }
  } catch (e) {
    if (current()) failed(el, String(e));
  }
}

document.addEventListener('submit', e => {
  if (e.defaultPrevented) return;
  const f = e.target;
  const q = (e.submitter && e.submitter.dataset.confirm) || f.dataset.confirm;
  if (q && !confirm(q)) { e.preventDefault(); return; }
  const b = e.submitter, label = b && b.textContent;
  if (b && b.dataset.busy) {
    // a plain form reloads the page: the button is disabled after the
    // submission has taken its value, or the value is lost
    setTimeout(() => { b.disabled = true; b.textContent = b.dataset.busy; });
  }
  if (!f.dataset.swap) return;
  e.preventDefault();
  const fd = new FormData(f);
  if (b && b.name) fd.append(b.name, b.value);
  // a button may send the form elsewhere, with the answer going elsewhere too
  const url = (b && b.getAttribute('formaction')) || f.action;
  swap(url, new URLSearchParams(fd), (b && b.dataset.target) || f.dataset.swap).then(() => {
    // a button outside the part replaced comes back to itself
    if (b && b.isConnected && b.dataset.busy) { b.disabled = false; b.textContent = label; }
  });
});

document.addEventListener('change', e => {
  const el = e.target, f = el.form;
  if (!f || !f.dataset.instant || !el.name) return;
  const fd = new URLSearchParams();
  fd.append('field', el.name);
  fd.append('value', el.type === 'checkbox' ? (el.checked ? '1' : '0') : el.value);
  for (const h of f.querySelectorAll('input[type=hidden]')) fd.append(h.name, h.value);
  swap(f.action, fd, f.dataset.swap, el.name);
});

document.addEventListener('click', e => {
  const o = e.target.closest('[data-open]');
  if (o) byId(o.dataset.open).showModal();
  const c = e.target.closest('[data-close]');
  if (c) c.closest('dialog').close();
});

// A dialog left unsent -- Cancel, Esc -- shows what is saved when opened
// again, not what was typed into it and dropped. A refused save's dialog
// was drawn on what was typed: the part it came in is drawn afresh. close
// does not bubble: it is caught on its way down.
document.addEventListener('close', e => {
  const d = e.target;
  if (!(d instanceof HTMLDialogElement)) return;
  const f = d.querySelector('form[data-reset]');
  if (f) f.reset();
  const part = d.dataset.refresh && d.parentElement && d.parentElement.closest('[id]');
  if (part) refresh(part, d.dataset.refresh);
}, true);

async function refresh(el, url) {
  const current = ticket(el);
  const r = await fetch(url).catch(() => null);
  if (!r || !r.ok) return;
  const html = await r.text();
  if (current()) {
    el.innerHTML = html;
    reblink(el);
    el._html = undefined;
  }
}

// A .conf form has a text field and a file picker, and the server takes
// the file first. What the field shows must be what is sent: a file picked
// is shown in the field, and a file dropped on the field, or the field
// edited, drops the file picked before -- it used to be sent instead of
// the text on screen.
// A file is read in the background: only the last one picked or dropped
// fills the field, and none does once the field is edited by hand.
function confFile(f) { return f && f.querySelector('input[type=file]'); }
function readInto(t, file) {
  const current = ticket(t);
  const fr = new FileReader();
  fr.onload = () => { if (current()) t.value = fr.result; };
  fr.readAsText(file);
}
document.addEventListener('dragover', e => { if (e.target.closest('[data-drop]')) e.preventDefault(); });
document.addEventListener('drop', e => {
  const t = e.target.closest('[data-drop]');
  if (!t || !e.dataTransfer.files[0]) return;
  e.preventDefault();
  const p = confFile(t.form);
  if (p) p.value = '';
  readInto(t, e.dataTransfer.files[0]);
});
document.addEventListener('change', e => {
  const p = e.target;
  if (p.type !== 'file' || !p.form || !p.files[0]) return;
  const t = p.form.querySelector('[data-drop]');
  if (t) readInto(t, p.files[0]);
});
document.addEventListener('input', e => {
  const t = e.target.closest('[data-drop]');
  if (!t) return;
  ticket(t);
  const p = confFile(t.form);
  if (p) p.value = '';
});

// --- polling ---
const due = new Map();
// a refresh still under way: the timer does not start another beside it.
// Each refresh clears its own mark whatever happened: one outrun by an
// action's answer used to leave the mark behind, and the part never
// refreshed again.
const busy = new WeakMap();
// Nor is text selected in a part, to be copied: a log line selected was
// gone within three seconds.
function selectedIn(el) {
  const s = getSelection();
  return s && !s.isCollapsed && (el.contains(s.anchorNode) || el.contains(s.focusNode));
}
async function poll(el) {
  // a field being edited is not replaced under the user's hands. A field
  // only: a menu item or a button keeps the focus once clicked -- the pages
  // are one document -- and the menu's counts stopped there for good, "0 · 0"
  // from a reset while the verdicts page under them was full again.
  const a = document.activeElement;
  if (a !== el && el.contains(a) && a.matches('input, textarea, select, [contenteditable]')) return;
  if (selectedIn(el)) return;
  // a newer request -- the filter's, an action's -- wins over this one
  const current = ticket(el);
  const mark = {};
  busy.set(el, mark);
  try {
    const url = el.dataset.poll || el.dataset.sync || el.dataset.fresh;
    const r = await fetch(url, {signal: AbortSignal.timeout(15000)}).catch(() => null);
    if (!r || !r.ok) return;
    const html = await r.text();
    if (!current() || selectedIn(el)) return;
    // the same as drawn: nothing to lay out again -- the verdicts' table
    // came every ten seconds, and took a tenth of a second each time
    if (html === el._html) return;
    const top = el.scrollTop;
    const bottom = top + el.clientHeight >= el.scrollHeight - 4;
    const follow = el.dataset.follow !== undefined && follows(el, bottom);
    const at = el.dataset.follow !== undefined && !follow ? readingAt(el) : null;
    el.innerHTML = html;
    reblink(el);
    el._html = html;
    if (follow) el.scrollTop = el.scrollHeight;
    else if (!at || !backTo(el, at)) el.scrollTop = top;
    const sec = el.closest('.pg');
    if (sec && sec.classList.contains('away')) warmSoon(sec);
  } catch (e) {
    // the body cut off by the timeout: the next period tries again
  } finally {
    if (busy.get(el) === mark) busy.delete(el);
  }
}
// Where a reader is in a part of lines, one to a row: the line at the top
// of the view, and how far into it. A log's last 400 lines are a window
// that slides, and with "follow" off the text being read went up out of
// view as lines were added -- 30 lines in three seconds, 30 lines up. It is
// found again by its text, at or above where it was.
function readingAt(el) {
  const cs = getComputedStyle(el);
  const lh = parseFloat(cs.lineHeight), pad = parseFloat(cs.paddingTop) || 0;
  if (!(lh > 0)) return null;
  const pos = Math.max(el.scrollTop - pad, 0);
  const i = Math.floor(pos / lh);
  const lines = el.textContent.split('\n');
  return i < lines.length ? {i, text: lines[i], off: el.scrollTop - pad - i * lh, lh, pad} : null;
}
function backTo(el, at) {
  const lines = el.textContent.split('\n');
  for (let j = Math.min(at.i, lines.length - 1); j >= 0; j--) {
    if (lines[j] === at.text) {
      el.scrollTop = at.pad + j * at.lh + at.off;
      return true;
    }
  }
  return false;
}

setInterval(() => {
  const now = Date.now();
  for (const el of document.querySelectorAll('[data-poll]')) {
    // a page or a tab not shown waits: it is drawn afresh when shown
    if (away(el)) continue;
    // the page came rendered: the first refresh is one period away
    if (!due.has(el)) { due.set(el, now + period(el)); continue; }
    if (due.get(el) <= now && !busy.has(el)) { due.set(el, now + period(el)); poll(el); }
  }
}, 500);

// The verdict filter refreshes its table as it is typed into: the parts
// it names, or the self-refreshing parts in them -- each tab's table; those
// not shown when they are.
let filterTimer;
document.addEventListener('input', e => {
  const q = e.target.closest('[data-filter]');
  if (!q) return;
  clearTimeout(filterTimer);
  filterTimer = setTimeout(() => {
    for (const id of q.dataset.filter.split(' ')) {
      const t = byId(id);
      if (!t) continue;
      for (const el of t.matches('[data-poll]') ? [t] : t.querySelectorAll('[data-poll]')) {
        el.dataset.poll = withParam(el.dataset.poll, 'q', q.value);
        if (away(el)) due.set(el, 0); else poll(el);
      }
    }
    const loc = new URL(location.href);
    loc.searchParams.set('q', q.value);
    setURL(loc, false);
  }, 200);
});

// A part with data-follow shows its newest lines, at the bottom: on the log
// page as its "follow" switch says, kept per browser -- a viewing
// preference; elsewhere while it is scrolled to the bottom. With no switch
// it never followed: the overview's events showed their oldest lines, the
// newest hidden below. The switch is the page's own: the overview's events
// followed the log page's once both were in the document.
function followSwitch(el) {
  const sec = el.closest('.pg');
  return sec && sec.querySelector('#follow');
}
function follows(el, atBottom) {
  const c = followSwitch(el);
  return c ? c.checked : atBottom;
}
// a part following its switch, shown: at its end, before it is drawn
function following(root) {
  for (const el of [root, ...root.querySelectorAll('[data-follow]')]) {
    if (el.matches('[data-follow]') && !away(el) && followSwitch(el) && follows(el)) el.scrollTop = el.scrollHeight;
  }
}
document.addEventListener('change', e => {
  if (e.target.id !== 'follow') return;
  try { localStorage.setItem('follow', e.target.checked ? '1' : '0'); } catch (err) {}
});
function followPref(sec) {
  const c = sec.querySelector('#follow');
  if (c) {
    try { c.checked = localStorage.getItem('follow') !== '0'; } catch (e) {}
  }
}

// The page scrolls in its section, not the window, and "back" restores only
// the window's scroll: a page left from its middle came back at the top,
// save when the browser kept it whole. Where the section stood is kept in
// the page's history entry and put back when the entry is returned to.
function keepScroll() {
  if (!current) return;
  try { history.replaceState(Object.assign({}, history.state, {top: current.scrollTop}), ''); } catch (e) {}
}
(function () {
  if (!main) return;
  let t;
  main.addEventListener('scroll', () => { clearTimeout(t); t = setTimeout(keepScroll, 150); }, true);
  addEventListener('pagehide', keepScroll);
})();

// what blinks: a checkbox is too small to be seen blinking, its label goes
// with it
function blinkTarget(id) {
  const el = byId(id);
  if (el && el.matches('input[type=checkbox], input[type=radio]') && el.closest('label')) return el.closest('label');
  return el;
}
function blinkOn(el, elapsed) {
  el.classList.remove('blink');
  void el.offsetWidth; // restarts the animation on a second click
  // carried on where it was, in an element drawn anew
  el.style.animationDelay = elapsed ? -elapsed + 'ms' : '';
  el.classList.add('blink');
  el.addEventListener('animationend', () => { el.classList.remove('blink'); el.style.animationDelay = ''; }, {once: true});
}
// The part pointed at blinks on when the part around it is drawn anew: a
// page shown has its parts refreshed right after (see freshen), and the
// settings' fields, the DNS boxes and the second tunnel's switch were
// replaced by new ones a frame into their blink -- it was not seen at all.
let blinking = null;
const BLINK_MS = 1800; // .blink in ui.css: 0.6 s three times
function reblink(root) {
  if (!blinking) return;
  const elapsed = performance.now() - blinking.at;
  if (elapsed >= BLINK_MS) { blinking = null; return; }
  const el = blinkTarget(blinking.id);
  if (el && root.contains(el) && !el.classList.contains('blink')) blinkOn(el, elapsed);
}

// A help link points at a part of a page (/settings#attempts): it is shown
// and its edge blinks, to say where to look. Not again on "back".
function point(id) {
  id = id && decodeURIComponent(id);
  const el = id && blinkTarget(id);
  if (!el) return;
  el.scrollIntoView({block: 'center'});
  blinking = {id, at: performance.now()};
  blinkOn(el, 0);
  // the browser focuses the anchor's target when it can (the log, a field, a
  // checkbox), and its focus ring stayed after the blink: the blink says where
  // to look, not the ring, as on every other link
  const t = byId(id);
  const unfocus = () => { const a = document.activeElement; if (a && a !== document.body && (a === t || el.contains(a))) a.blur(); };
  unfocus();
  requestAnimationFrame(unfocus);
}

// The start: the page that came with the document is set going, and the
// others are fetched once it is drawn, one after another.
document.addEventListener('DOMContentLoaded', () => {
  if (!current) return;
  current.dataset.url = location.pathname + location.search;
  followPref(current);
  init(current);
  history.replaceState(Object.assign({}, history.state, {page: current.dataset.page}), '');
  const nav = performance.getEntriesByType('navigation')[0];
  const st = history.state;
  if (nav && nav.type !== 'navigate' && typeof st.top === 'number') current.scrollTop = st.top;
  // after the browser's own jump to the anchor, which would undo the centring
  if (!nav || nav.type !== 'back_forward') addEventListener('load', () => point(location.hash.slice(1)));
  afterPaint(async () => {
    for (const name of pageNames) {
      if (sections.has(name)) continue;
      try {
        followPref(await load(name));
      } catch (e) {
        // fetched when asked for
      }
      await new Promise(r => setTimeout(r, 0));
    }
  });
});
addEventListener('hashchange', () => point(location.hash.slice(1)));

// The tunnels' state -- the header's chips, the overview's and the second
// tunnel's -- follows the tunnels every second: the parts they are in are
// drawn every five or ten, and the chips said green while a part below
// still said the tunnel was down (see tunnelpulse.go). Not while hidden.
setInterval(async () => {
  if (document.hidden || !document.querySelector('[data-tunnel]')) return;
  const r = await fetch('/api/tunnels').catch(() => null);
  if (!r || !r.ok) return;
  const st = await r.json().catch(() => ({}));
  for (const c of document.querySelectorAll('[data-tunnel]')) {
    const s = st[c.dataset.tunnel];
    if (!s) continue;
    const dot = c.querySelector('.dot');
    if (dot) dot.className = 'dot ' + (s.alive ? 'ok' : 'bad');
    const text = c.dataset.tunnel + ' ' + s.text;
    if (c.lastChild && c.lastChild.nodeType === Node.TEXT_NODE) {
      if (c.lastChild.textContent !== text) c.lastChild.textContent = text;
    }
  }
  // the overview's and the second tunnel's state, drawn as the template does
  for (const c of document.querySelectorAll('[data-tstate]')) {
    const s = st[c.dataset.tstate];
    if (!s) continue;
    const key = s.alive + '|' + s.pill + '|' + s.note;
    if (c.dataset.key === key) continue;
    c.dataset.key = key;
    const p = document.createElement('span');
    p.className = 'pill ' + (s.alive ? 'ok' : 'bad');
    p.textContent = s.pill;
    c.replaceChildren(p);
    if (!s.alive && s.note) {
      const m = document.createElement('span');
      m.className = 'muted';
      m.textContent = s.note;
      c.append(' ', m);
    }
  }
}, 1000);
