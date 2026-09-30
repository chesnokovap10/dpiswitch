// The pages are rendered by the Go server; this only saves what the page
// would otherwise reload for. A form with data-swap="id" is sent in the
// background and the server's answer replaces that element's content; a
// form with data-instant sends each control the moment it changes; an
// element with data-poll="url" refreshes itself every data-every seconds,
// one with data-sync="url" when an action elsewhere on the page answers.
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

// changed: the control an instant form sent. The answer redraws the whole
// form, and a field being typed into meanwhile -- another one -- would
// get the saved value back and lose what was typed; it keeps its text,
// focus and caret. The control sent takes the server's value: a refused
// change shows as refused.
async function send(url, body, target, changed) {
  const el = document.getElementById(target);
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
    // an answer may carry a new value for a field outside it: the DNS test
    // puts the address that answered in place of the one written
    for (const f of el.querySelectorAll('[data-fill]')) {
      const t = document.querySelector('[name="' + CSS.escape(f.dataset.fill) + '"]');
      if (t) t.value = f.textContent;
      f.remove();
    }
    // a dialog whose save was refused comes back open, on what was typed
    for (const d of el.querySelectorAll('dialog[data-show]')) d.showModal();
    // an action may change what other parts show: the mode is in the header
    // and in the settings, and one changed in either left the other showing
    // the old one. The rest are drawn afresh now, not in five seconds or
    // never; those with no period of their own are data-sync.
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
  if (o) document.getElementById(o.dataset.open).showModal();
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
  if (current()) el.innerHTML = html;
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
  // a field being edited is not replaced under the user's hands
  if (el.contains(document.activeElement) && document.activeElement !== el) return;
  if (selectedIn(el)) return;
  // a newer request -- the filter's, an action's -- wins over this one
  const current = ticket(el);
  const mark = {};
  busy.set(el, mark);
  try {
    const r = await fetch(el.dataset.poll || el.dataset.sync, {signal: AbortSignal.timeout(15000)}).catch(() => null);
    if (!r || !r.ok) return;
    const html = await r.text();
    if (!current() || selectedIn(el)) return;
    const top = el.scrollTop;
    const bottom = top + el.clientHeight >= el.scrollHeight - 4;
    const follow = el.dataset.follow !== undefined && follows(bottom);
    const at = el.dataset.follow !== undefined && !follow ? readingAt(el) : null;
    el.innerHTML = html;
    if (follow) el.scrollTop = el.scrollHeight;
    else if (!at || !backTo(el, at)) el.scrollTop = top;
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
    const every = (+el.dataset.every || 5) * 1000;
    // the page came rendered: the first refresh is one period away
    if (!due.has(el)) { due.set(el, now + every); continue; }
    if (due.get(el) <= now && !busy.has(el)) { due.set(el, now + every); poll(el); }
  }
}, 500);

// the verdict filter refreshes its table as it is typed into
let filterTimer;
document.addEventListener('input', e => {
  const q = e.target.closest('[data-filter]');
  if (!q) return;
  clearTimeout(filterTimer);
  filterTimer = setTimeout(() => {
    for (const id of q.dataset.filter.split(' ')) {
      const t = document.getElementById(id);
      const u = new URL(t.dataset.poll, location.href);
      u.searchParams.set('q', q.value);
      t.dataset.poll = u.pathname + u.search;
      history.replaceState(history.state, '', location.pathname + '?' + u.searchParams);
      poll(t);
    }
  }, 200);
});

// A part with data-follow shows its newest lines, at the bottom: on the log
// page as its "follow" switch says, kept per browser -- a viewing
// preference; elsewhere while it is scrolled to the bottom. With no switch
// it never followed: the overview's events showed their oldest lines, the
// newest hidden below.
function follows(atBottom) {
  const c = document.getElementById('follow');
  return c ? c.checked : atBottom;
}
(function () {
  const c = document.getElementById('follow');
  if (c) {
    try { c.checked = localStorage.getItem('follow') !== '0'; } catch (e) {}
    c.addEventListener('change', () => { try { localStorage.setItem('follow', c.checked ? '1' : '0'); } catch (e) {} });
  }
  for (const el of document.querySelectorAll('[data-follow]')) {
    if (follows(true)) el.scrollTop = el.scrollHeight;
  }
})();

// The page scrolls in <main>, not the window, and "back" restores only the
// window's scroll: a page left from its middle came back at the top, save
// when the browser kept it whole. Where <main> stood is kept in the page's
// history entry and put back when the entry is returned to.
(function () {
  const main = document.querySelector('main');
  if (!main) return;
  const keep = () => {
    try { history.replaceState(Object.assign({}, history.state, {top: main.scrollTop}), ''); } catch (e) {}
  };
  let t;
  main.addEventListener('scroll', () => { clearTimeout(t); t = setTimeout(keep, 150); });
  // a link followed before the scroll settled
  document.addEventListener('click', e => { if (e.target.closest('a[href]')) { clearTimeout(t); keep(); } }, true);
  addEventListener('pagehide', keep);
  const nav = performance.getEntriesByType('navigation')[0];
  const st = history.state;
  if (nav && nav.type !== 'navigate' && st && typeof st.top === 'number') main.scrollTop = st.top;
})();

// A help link points at a part of a page (/settings#attempts): it is shown
// and its edge blinks, to say where to look. Not again on "back".
function point(id) {
  let el = id && document.getElementById(decodeURIComponent(id));
  if (!el) return;
  // a checkbox is too small to be seen blinking: its label goes with it
  if (el.matches('input[type=checkbox], input[type=radio]') && el.closest('label')) el = el.closest('label');
  el.scrollIntoView({block: 'center'});
  el.classList.remove('blink');
  void el.offsetWidth; // restarts the animation on a second click
  el.classList.add('blink');
  el.addEventListener('animationend', () => el.classList.remove('blink'), {once: true});
  // the browser focuses the anchor's target when it can (the log, a field, a
  // checkbox), and its focus ring stayed after the blink: the blink says where
  // to look, not the ring, as on every other link
  const t = document.getElementById(decodeURIComponent(id));
  const unfocus = () => { const a = document.activeElement; if (a && a !== document.body && (a === t || el.contains(a))) a.blur(); };
  unfocus();
  requestAnimationFrame(unfocus);
}
(function () {
  const nav = performance.getEntriesByType('navigation')[0];
  // after the browser's own jump to the anchor, which would undo the centring
  if (!nav || nav.type !== 'back_forward') addEventListener('load', () => point(location.hash.slice(1)));
  addEventListener('hashchange', () => point(location.hash.slice(1)));
})();
