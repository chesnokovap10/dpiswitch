// The verdicts page's rows, as Live's: a click picks one, Ctrl and Shift
// pick more (see pickRows), a right-click opens the menu that sends their
// domains, names or addresses to a list (see rowmenu.js), and ✕ resets the
// verdicts -- the names go back to the tunnel, and the detector checks
// them anew when they are used. Both act on every row picked when the row
// they are on is one of them.
//
// Each tab's table is kept, and the one shown is drawn anew every ten
// seconds (see ui.js): the row picked is found again by its key, and let go
// when it is gone.
//
// The network: memory keeps verdicts per ISP, and the header's network,
// on this page, opens the list of them. The one picked has its verdicts
// shown, and the reset and ✕ act on it. Leaving the page goes back to the
// current network: coming back, its verdicts are the ones shown.
'use strict';
pageInit.verdicts = function (sec) {
  const page = sec.querySelector('#verdicts');
  const box = sec.querySelector('#vtable');
  if (!page || !box) return;
  const W = JSON.parse(sec.querySelector('#vwords').textContent);
  const menu = rowMenu(W);
  const fmt = (s, ...a) => { let i = 0; return s.replace(/%[ds]/g, () => a[i++]); };
  const shown = () => !sec.classList.contains('away');
  let sel = new Set(); // the keys of the rows picked
  let anchor = '';      // the key a Shift range starts from
  let net = page.dataset.net || ''; // the network shown, '' the current one
  const chipEl = () => document.getElementById('netchip');
  const cur = () => { const c = chipEl(); return c ? c.dataset.cur : page.dataset.cur; };

  // the tab's table shown
  const table = () => box.querySelector(':scope > :not(.away)');
  const rows = () => { const t = table(); return t ? Array.from(t.querySelectorAll('tr[data-key]')) : []; };
  // the rows picked, as the table shows them
  const picked = () => rows().filter(tr => sel.has(tr.dataset.key));
  // The rows picked marked, and their ✕ saying it resets them all; the ones
  // the table no longer shows -- reset, or gone to another tab -- let go
  function mark() {
    const seen = new Set();
    for (const tr of rows()) {
      const on = sel.has(tr.dataset.key);
      tr.classList.toggle('sel', on);
      if (on) seen.add(tr.dataset.key);
      const x = tr.querySelector('button.lx');
      if (x) {
        if (x.dataset.t === undefined) x.dataset.t = x.title;
        const t = on && sel.size > 1 ? fmt(W.forgetMany, sel.size) : x.dataset.t;
        if (x.title !== t) x.title = t;
      }
    }
    for (const tr of box.querySelectorAll('tr.sel')) if (!seen.has(tr.dataset.key) || !sel.has(tr.dataset.key)) tr.classList.remove('sel');
    if (seen.size < sel.size) {
      sel = seen;
      if (!sel.size) unpick(); else mark();
    }
  }
  new MutationObserver(mark).observe(box, {childList: true, subtree: true});
  // another tab: its rows are others
  box.addEventListener('tab:show', () => unpick());

  function setSel(next, a) {
    sel = next;
    anchor = a;
    mark();
  }
  function unpick() {
    menu.close();
    sel = new Set();
    anchor = '';
    for (const tr of box.querySelectorAll('tr.sel')) tr.classList.remove('sel');
    for (const x of box.querySelectorAll('button.lx[data-t]')) x.title = x.dataset.t;
  }

  // What goes to a list, as on Live: the whole domain first, then the name
  // alone; an address for a verdict an address has of its own
  function whats(tr) {
    const k = tr.dataset.key, d = tr.dataset;
    if (k.startsWith('+.')) return [[k, W.whatDomain]];
    if (d.addr) return [[d.addr, W.whatAddr]];
    const out = [];
    if (d.dom) out.push(['+.' + d.dom, W.whatDomain]);
    if (k !== d.dom) out.push([k, W.whatName]);
    return out;
  }
  // the same for the rows picked: their whole domains, and their names --
  // each row's widest line, and its own: the name, the whole domain of a
  // row that is one, the address of one with an address
  function whatsMany(trs) {
    const doms = new Set(), names = new Set();
    for (const tr of trs) {
      doms.add(whats(tr)[0][0]);
      names.add(tr.dataset.addr || tr.dataset.key);
    }
    const out = [[[...doms], W.whatDomain, fmt(W.whatDomains, doms.size)]];
    if ([...names].join() !== [...doms].join()) out.push([[...names], W.whatName, fmt(W.whatNames, names.size)]);
    return out;
  }

  // picked as the button goes down, as on Live; ✕ acts on the click. The
  // right button and ✕ on a row picked keep the rows picked: they act on
  // them all
  box.addEventListener('pointerdown', e => {
    if (e.button !== 0 && e.button !== 2) return;
    const tr = e.target.closest('tr[data-key]');
    if (!tr) return;
    const k = tr.dataset.key;
    if ((e.button === 2 || e.target.closest('button.lx')) && sel.has(k)) return;
    if (e.button === 2) { setSel(new Set([k]), k); return; }
    const p = pickRows(sel, rows().map(r => r.dataset.key), k, e, anchor);
    setSel(p.sel, p.anchor);
  });
  // a Shift+click picks rows, not the text between them
  box.addEventListener('mousedown', e => { if (e.shiftKey && e.target.closest('tr[data-key]')) e.preventDefault(); });
  box.addEventListener('click', e => {
    const tr = e.target.closest('tr[data-key]');
    const x = e.target.closest('button.lx');
    if (!tr || !x) return;
    forget(sel.has(tr.dataset.key) && sel.size > 1 ? picked() : [tr], x);
  });
  box.addEventListener('contextmenu', e => {
    const tr = e.target.closest('tr[data-key]');
    if (!tr) return;
    e.preventDefault();
    if (!sel.has(tr.dataset.key)) setSel(new Set([tr.dataset.key]), tr.dataset.key);
    const trs = picked();
    menu.open(trs.length > 1 ? whatsMany(trs) : whats(tr), e.clientX, e.clientY);
  });
  document.addEventListener('mousedown', e => {
    if (sel.size && !e.target.closest('#lmenu, #vtable tr[data-key]')) unpick();
  });
  document.addEventListener('keydown', e => {
    if (e.key !== 'Escape' || !shown()) return;
    if (nets) closeNets();
    else if (menu.shown()) menu.close();
    else unpick();
  });

  // the verdicts of the rows given reset, in one request
  async function forget(trs, x) {
    const xs = trs.map(tr => tr.querySelector('button.lx')).filter(Boolean);
    for (const b of xs) b.disabled = true;
    // focus in the table holds its refresh off (see poll in ui.js)
    x.blur();
    menu.toast(W.forgetting, true);
    const body = new URLSearchParams({net});
    for (const tr of trs) body.append('key', tr.dataset.key);
    try {
      const r = await fetch('/act/forget', {method: 'POST', body});
      if (!r.ok) throw new Error((await r.text()).trim() || r.status + ' ' + r.statusText);
      const j = await r.json();
      menu.toast(j.msg, j.ok);
      // the table and the tabs' counts drawn now, not in ten seconds
      for (const p of document.querySelectorAll('[data-poll]')) due.set(p, 0);
    } catch (err) {
      for (const b of xs) b.disabled = false;
      menu.toast(W.notForgot + ' ' + err.message, false);
    }
  }

  // --- the network shown ---
  const form = sec.querySelector('#vresetform');
  const note = sec.querySelector('#vnetnote');

  // the header's network says the one shown, marked when it is not the
  // current one; the header is drawn anew every five seconds, and so is it
  function chip() {
    const c = chipEl();
    if (!c) return;
    const other = shown() && net !== '';
    const id = c.querySelector('.netid');
    if (id) id.textContent = other ? net : c.dataset.cur;
    c.classList.toggle('other', other);
  }
  const header = document.getElementById('header');
  if (header) new MutationObserver(chip).observe(header, {childList: true});

  function setNet(n) {
    if (n === cur()) n = '';
    if (n === net) return;
    net = n;
    page.dataset.net = n;
    unpick();
    // every tab's table and the counts, of the network now; the ones not
    // shown too, so that a tab picked next shows it at once
    for (const el of sec.querySelectorAll('[data-poll]')) {
      el.dataset.poll = withParam(el.dataset.poll, 'net', n);
      due.set(el, Date.now() + period(el));
      poll(el);
    }
    // the reset is of the network shown, and asks so
    form.elements.net.value = n;
    form.dataset.confirm = fmt(n ? W.resetNet : W.resetCur, n || cur());
    note.hidden = !n;
    note.textContent = n ? fmt(W.netNote, n, cur()) : '';
    // the address says it: a reload -- the reset's among them -- comes
    // back to the network shown
    if (shown()) {
      const loc = new URL(location.href);
      if (n) loc.searchParams.set('net', n); else loc.searchParams.delete('net');
      setURL(loc, false);
    } else {
      sec.dataset.url = withParam(sec.dataset.url || '/verdicts', 'net', n);
    }
    chip();
  }

  // the list of networks, under the header's
  let nets = null;
  function openNets() {
    const c = chipEl();
    if (!c) return;
    let list = [];
    try { list = JSON.parse(c.dataset.nets || 'null') || []; } catch (e) {}
    nets = document.createElement('div');
    nets.className = 'cmenu netmenu';
    for (const x of list) {
      const b = document.createElement('button');
      b.type = 'button';
      b.dataset.net = x.id;
      b.classList.toggle('on', x.id === (net || c.dataset.cur));
      const id = document.createElement('span');
      id.textContent = x.id;
      b.append(id);
      if (x.id === c.dataset.cur) {
        const k = document.createElement('span');
        k.className = 'ok-t';
        k.textContent = W.netCur;
        b.append(k);
      }
      const m = document.createElement('span');
      m.className = 'muted';
      m.textContent = fmt(W.netNames, x.names);
      b.append(m);
      nets.append(b);
    }
    nets.addEventListener('click', e => {
      const b = e.target.closest('button[data-net]');
      if (!b) return;
      closeNets();
      setNet(b.dataset.net);
    });
    document.body.append(nets);
    const r = c.getBoundingClientRect();
    nets.style.left = Math.max(4, Math.min(r.left, innerWidth - nets.offsetWidth - 4)) + 'px';
    nets.style.top = (r.bottom + 4) + 'px';
  }
  function closeNets() {
    if (nets) nets.remove();
    nets = null;
  }
  // opened on the press, as the menu's tabs are
  document.addEventListener('pointerdown', e => {
    if (!shown()) return;
    if (e.target.closest('#netchip')) {
      if (e.button !== 0) return;
      if (nets) closeNets(); else openNets();
      return;
    }
    if (nets && !nets.contains(e.target)) closeNets();
  });
  addEventListener('resize', closeNets);
  addEventListener('blur', closeNets);

  // back to the current network once the page is left
  sec.addEventListener('pg:hide', () => {
    closeNets();
    unpick();
    setNet('');
    chip();
  });
  sec.addEventListener('pg:show', chip);
  // an address with a network -- "back" to one shown before -- shows it,
  // and its filter
  sec.addEventListener('pg:url', e => {
    setNet(e.detail.searchParams.get('net') || '');
    const f = sec.querySelector('#vfilter'), q = e.detail.searchParams.get('q') || '';
    if (f && f.value !== q) {
      f.value = q;
      f.dispatchEvent(new Event('input', {bubbles: true}));
    }
  });
  chip();
};
