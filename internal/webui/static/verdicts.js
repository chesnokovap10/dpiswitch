// The verdicts page's rows, as Live's: a click picks one, a right-click
// opens the menu that sends its domain, name or address to a list (see
// rowmenu.js), and ✕ resets its verdict -- the name goes back to the
// tunnel, and the detector checks it anew when it is used.
//
// The table is drawn anew every ten seconds (see ui.js): the row picked is
// found again by its key, and let go when it is gone.
'use strict';
(function () {
  const box = document.getElementById('vtable');
  if (!box) return;
  const W = JSON.parse(document.getElementById('vwords').textContent);
  const menu = rowMenu(W);
  let sel = ''; // the key of the row picked

  function rowOf(key) {
    for (const tr of box.querySelectorAll('tr[data-key]')) if (tr.dataset.key === key) return tr;
    return null;
  }
  function mark() {
    for (const tr of box.querySelectorAll('tr.sel')) tr.classList.remove('sel');
    const tr = sel && rowOf(sel);
    if (tr) tr.classList.add('sel');
    else if (sel) unpick();
  }
  new MutationObserver(mark).observe(box, {childList: true});

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

  box.addEventListener('click', e => {
    const tr = e.target.closest('tr[data-key]');
    if (!tr) return;
    const x = e.target.closest('button.lx');
    if (x) forget(tr, x); else pick(tr);
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
    if (e.key !== 'Escape') return;
    if (menu.shown()) menu.close(); else unpick();
  });

  async function forget(tr, x) {
    x.disabled = true;
    // focus in the table holds its refresh off (see poll in ui.js)
    x.blur();
    menu.toast(W.forgetting, true);
    try {
      const r = await fetch('/act/forget', {method: 'POST', body: new URLSearchParams({key: tr.dataset.key})});
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
})();
