// A row's menu, the same on Live and on Verdicts: what of the row to send
// -- the whole domain, the name alone, the address, the program -- and to
// which list or preset, with what that came to shown for a few seconds.
// The page says what a row can send (see open); the menu's markup is the
// "rowmenu" template, one for both pages: they share the document, and so
// the menu -- each asks for it, and gets the same one.
'use strict';

// The rows picked, on Live and on Verdicts alike, as a file manager picks
// them: a click picks one row, Ctrl+click adds one or takes it away, and
// Shift+click a range from the row clicked before it -- with Ctrl too,
// added to those picked. sel: the rows picked, a Set; order: the rows as
// the table shows them; anchor: where a range starts. Returns the rows
// picked and the anchor now.
function pickRows(sel, order, item, e, anchor) {
  const ctrl = e.ctrlKey || e.metaKey;
  const a = anchor == null ? -1 : order.indexOf(anchor);
  if (e.shiftKey && a >= 0) {
    const b = order.indexOf(item);
    const next = ctrl ? new Set(sel) : new Set();
    for (let i = Math.min(a, b); i <= Math.max(a, b); i++) next.add(order[i]);
    return {sel: next, anchor};
  }
  if (ctrl) {
    const next = new Set(sel);
    if (next.has(item)) next.delete(item); else next.add(item);
    return {sel: next, anchor: item};
  }
  return {sel: new Set([item]), anchor: item};
}

function rowMenu(W) {
  if (!rowMenu.one) rowMenu.one = makeRowMenu(W);
  return rowMenu.one;
}
function makeRowMenu(W) {
  const $ = id => document.getElementById(id);
  const menu = $('lmenu'), sub = $('lpresets'), reveal = $('lreveal'), revealHr = $('lrevealhr');
  // the lines the item picked sends, and what the file location opens
  let what = [], onReveal = null;

  // ws: [value, title, label] items, the first picked. A value is one line,
  // shown as it is, or the lines of the rows picked, shown by the label
  // with the lines themselves in the tooltip. rev: the program's file and
  // what opens it, on Live only and for one row
  function open(ws, x, y, rev) {
    const w = $('lwhat');
    w.textContent = '';
    ws.forEach(([v, t, label], i) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = label || v;
      b._v = [].concat(v);
      b.title = Array.isArray(v) ? t + '\n\n' + b._v.slice(0, 20).join('\n') + (b._v.length > 20 ? '\n…' : '') : t;
      b.classList.toggle('on', i === 0);
      w.append(b);
    });
    what = ws.length ? w.firstChild._v : [];
    w.hidden = !ws.length;
    for (const b of menu.querySelectorAll('[data-to], #lpresetbtn')) b.disabled = !what.length;
    onReveal = rev && rev.path ? rev.run : null;
    // the program's file is Live's: a verdict's row has none
    reveal.hidden = revealHr.hidden = !rev;
    reveal.disabled = !onReveal;
    reveal.title = rev && rev.path || W.noPath;
    presets();
    menu.hidden = false;
    menu.classList.remove('left');
    const mw = menu.offsetWidth, mh = menu.offsetHeight;
    const left = Math.max(4, Math.min(x, innerWidth - mw - 4));
    menu.style.left = left + 'px';
    menu.style.top = Math.max(4, Math.min(y, innerHeight - mh - 4)) + 'px';
    // the presets open to the side there is room on
    menu.classList.toggle('left', left + mw + 220 > innerWidth);
  }
  function close() {
    menu.hidden = true;
    sub.classList.remove('shown');
    sub.style.top = '';
    what = [];
    onReveal = null;
  }

  // the menu is where the cursor was: a click elsewhere, a scroll or a
  // resize takes it away -- not a scroll of its own list of presets
  document.addEventListener('mousedown', e => { if (!e.target.closest('#lmenu')) close(); });
  document.addEventListener('scroll', e => { if (!menu.contains(e.target)) close(); }, true);
  menu.addEventListener('contextmenu', e => e.preventDefault());
  addEventListener('resize', close);
  addEventListener('blur', close);

  // The presets open beside their item, level with it: near the bottom of
  // the window they ran off it. Moved up as far as they must to fit -- they
  // are never taller than the window (60vh), and scroll past that.
  function fitSub() {
    sub.style.top = '';
    const r = sub.getBoundingClientRect();
    if (!r.height) return; // not shown
    const over = r.bottom - (innerHeight - 4);
    if (over > 0) sub.style.top = (-5 - Math.min(over, r.top - 4)) + 'px';
  }
  // on hover the list shows at once; the frame after, it has its size
  sub.parentElement.addEventListener('mouseenter', () => requestAnimationFrame(fitSub));

  // the presets as they are now: another tab may have added one
  async function presets() {
    sub.textContent = '';
    try {
      const r = await fetch('/live/presets');
      if (!r.ok) throw new Error(r.status);
      const ps = await r.json();
      sub.textContent = '';
      requestAnimationFrame(fitSub); // filled while shown: its height changed
      for (const p of ps) {
        const b = document.createElement('button');
        b.type = 'button';
        b.textContent = p.title;
        b.dataset.preset = p.id;
        if (!p.on) { b.classList.add('off'); b.title = W.presetOff; }
        sub.append(b);
      }
      if (!ps.length) {
        const n = document.createElement('div');
        n.className = 'muted';
        n.textContent = W.noPresets;
        sub.append(n);
      }
    } catch (e) {
      sub.textContent = '';
    }
  }

  $('lwhat').addEventListener('click', e => {
    const b = e.target.closest('button');
    if (!b) return;
    what = b._v;
    for (const c of $('lwhat').children) c.classList.toggle('on', c === b);
  });
  // the presets open on hover, and on a click for those without a mouse
  $('lpresetbtn').addEventListener('click', () => {
    sub.classList.toggle('shown');
    requestAnimationFrame(fitSub);
  });
  menu.addEventListener('click', e => {
    const b = e.target.closest('button');
    if (!b || b.disabled) return;
    if (b.dataset.to) send(b.dataset.to, '');
    else if (b.dataset.preset) send('preset', b.dataset.preset);
  });
  reveal.addEventListener('click', () => {
    const run = onReveal;
    close();
    if (run) run();
  });

  async function send(to, preset) {
    const vs = what;
    close();
    if (!vs.length) return;
    const body = new URLSearchParams({to});
    for (const v of vs) body.append('entry', v);
    if (preset) body.set('preset', preset);
    toast(W.sending, true);
    try {
      const res = await fetch('/act/liveadd', {method: 'POST', body});
      if (!res.ok) throw new Error((await res.text()).trim() || res.status + ' ' + res.statusText);
      const j = await res.json();
      toast(j.msg, j.ok);
    } catch (e) {
      toast(W.notSent + ' ' + e.message, false);
    }
  }

  // what an action came to, for a few seconds
  let toastTimer;
  function toast(text, ok) {
    const t = $('ltoast');
    t.textContent = text;
    t.className = 'toast ' + (ok ? 'ok' : 'bad');
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, ok ? 6000 : 12000);
  }

  return {open, close, shown: () => !menu.hidden, toast};
}
