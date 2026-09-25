// The pages are rendered by the Go server; this only saves what the page
// would otherwise reload for. A form with data-swap="id" is sent in the
// background and the server's answer replaces that element's content; a
// form with data-instant sends each control the moment it changes; an
// element with data-poll="url" refreshes itself every data-every seconds.
'use strict';

async function swap(url, body, target) {
  const el = document.getElementById(target);
  try {
    const r = await fetch(url, {method: 'POST', body});
    if (el) el.innerHTML = await r.text();
  } catch (e) {
    if (el) el.insertAdjacentHTML('beforeend', '<div class="msg bad">' + e + '</div>');
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
  swap(f.action, fd, f.dataset.swap);
});

document.addEventListener('click', e => {
  const o = e.target.closest('[data-open]');
  if (o) document.getElementById(o.dataset.open).showModal();
  const c = e.target.closest('[data-close]');
  if (c) c.closest('dialog').close();
});

// a .conf dropped on its field is read into it
document.addEventListener('dragover', e => { if (e.target.closest('[data-drop]')) e.preventDefault(); });
document.addEventListener('drop', e => {
  const t = e.target.closest('[data-drop]');
  if (!t || !e.dataTransfer.files[0]) return;
  e.preventDefault();
  const fr = new FileReader();
  fr.onload = () => { t.value = fr.result; };
  fr.readAsText(e.dataTransfer.files[0]);
});

// --- polling ---
const due = new Map();
async function poll(el) {
  // a field being edited is not replaced under the user's hands
  if (el.contains(document.activeElement) && document.activeElement !== el) return;
  const r = await fetch(el.dataset.poll).catch(() => null);
  if (!r || !r.ok) return;
  const html = await r.text();
  const top = el.scrollTop;
  el.innerHTML = html;
  el.scrollTop = el.dataset.follow !== undefined && followOn() ? el.scrollHeight : top;
}
setInterval(() => {
  const now = Date.now();
  for (const el of document.querySelectorAll('[data-poll]')) {
    const every = (+el.dataset.every || 5) * 1000;
    // the page came rendered: the first refresh is one period away
    if (!due.has(el)) { due.set(el, now + every); continue; }
    if (due.get(el) <= now) { due.set(el, now + every); poll(el); }
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
      history.replaceState(null, '', location.pathname + '?' + u.searchParams);
      poll(t);
    }
  }, 200);
});

// "follow" on the log page: kept per browser, it is a viewing preference
function followOn() {
  const c = document.getElementById('follow');
  return c ? c.checked : false;
}
(function () {
  const c = document.getElementById('follow');
  if (!c) return;
  try { c.checked = localStorage.getItem('follow') !== '0'; } catch (e) {}
  c.addEventListener('change', () => { try { localStorage.setItem('follow', c.checked ? '1' : '0'); } catch (e) {} });
  const log = document.getElementById('log');
  if (log) log.scrollTop = log.scrollHeight;
})();
