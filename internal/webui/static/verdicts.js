// The verdicts page's rows, as Live's: a click picks one, a right-click
// opens the menu that sends its domain, name or address to a list (see
// rowmenu.js), and ✕ resets its verdict -- the name goes back to the
// tunnel, and the detector checks it anew when it is used.
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
  let sel = ''; // the key of the row picked
  let net = page.dataset.net || ''; // the network shown, '' the current one
  const chipEl = () => document.getElementById('netchip');
  const cur = () => { const c = chipEl(); return c ? c.dataset.cur : page.dataset.cur; };

  // the tab's table shown
  const table = () => box.querySelector(':scope > :not(.away)');
  function rowOf(key) {
    const t = table();
    if (!t) return null;
    for (const tr of t.querySelectorAll('tr[data-key]')) if (tr.dataset.key === key) return tr;
    return null;
  }
  function mark() {
    for (const tr of box.querySelectorAll('tr.sel')) tr.classList.remove('sel');
    const tr = sel && rowOf(sel);
    if (tr) tr.classList.add('sel');
    else if (sel) unpick();
  }
  new MutationObserver(mark).observe(box, {childList: true, subtree: true});
  // another tab: its rows are others
  box.addEventListener('tab:show', () => unpick());

  function pick(tr) {
    sel = tr.dataset.key;
    mark();
  }
  function unpick() {
    menu.close();
    sel = '';
    for (const tr of box.querySelectorAll('tr.sel')) tr.classList.remove('sel');
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

  // picked as the button goes down, as on Live; ✕ acts on the click
  box.addEventListener('pointerdown', e => {
    if (e.button !== 0 && e.button !== 2) return;
    const tr = e.target.closest('tr[data-key]');
    if (tr) pick(tr);
  });
  box.addEventListener('click', e => {
    const tr = e.target.closest('tr[data-key]');
    const x = e.target.closest('button.lx');
    if (tr && x) forget(tr, x);
  });
  box.addEventListener('contextmenu', e => {
    const tr = e.target.closest('tr[data-key]');
    if (!tr) return;
    e.preventDefault();
    pick(tr);
    menu.open(whats(tr), e.clientX, e.clientY);
  });
  document.addEventListener('mousedown', e => {
    if (sel && !e.target.closest('#lmenu, #vtable tr[data-key]')) unpick();
  });
  document.addEventListener('keydown', e => {
    if (e.key !== 'Escape' || !shown()) return;
    if (nets) closeNets();
    else if (menu.shown()) menu.close();
    else unpick();
  });

  async function forget(tr, x) {
    x.disabled = true;
    // focus in the table holds its refresh off (see poll in ui.js)
    x.blur();
    menu.toast(W.forgetting, true);
    try {
      const r = await fetch('/act/forget', {method: 'POST', body: new URLSearchParams({key: tr.dataset.key, net})});
      if (!r.ok) throw new Error((await r.text()).trim() || r.status + ' ' + r.statusText);
      const j = await r.json();
      menu.toast(j.msg, j.ok);
      // the table and the tabs' counts drawn now, not in ten seconds
      for (const p of document.querySelectorAll('[data-poll]')) due.set(p, 0);
    } catch (err) {
      x.disabled = false;
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
