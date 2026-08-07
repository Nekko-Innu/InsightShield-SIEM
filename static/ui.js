// Insight Shield UI — vanilla JS (no framework). Loaded by _base.html.
(function () {
  'use strict';

  // ---------- Toast ----------
  const region = document.getElementById('toast-region');
  function toast(message, category = 'info', ttl = 4000) {
    if (!region) return;
    const el = document.createElement('div');
    el.className = 'toast toast-' + (category === 'success' ? 'success'
                                   : category === 'error'   ? 'error'
                                   : category === 'warning' ? 'warn'
                                   : category === 'throttle' ? 'warn' : 'info');
    el.setAttribute('role', category === 'error' ? 'alert' : 'status');
    el.textContent = message;
    region.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 200); }, ttl);
  }
  window.wpToast = toast;

  // Hydrate flash messages from server-rendered seed
  const seed = document.getElementById('flash-seed');
  if (seed) {
    seed.querySelectorAll('span[data-category]').forEach(s => {
      toast(s.textContent.trim(), s.dataset.category);
    });
  }

  // ---------- Poll-failure toast tracker ----------
  // Several pollers below hit the network every 15s (severity bars, manager
  // alert feed, IT dashboard SSE-fallback). Toasting on every miss would
  // spam the user during a brief network blip — toast once after N
  // consecutive failures, and once more on recovery. Shared across ui.js
  // and dashboard-it-realtime.js via window.wpPollFailure.
  const _pollFailCounts = {};
  function pollFailure(key, ok, threshold = 3) {
    if (ok) {
      if ((_pollFailCounts[key] || 0) >= threshold) {
        toast('Live updates restored.', 'success', 3000);
      }
      _pollFailCounts[key] = 0;
      return;
    }
    _pollFailCounts[key] = (_pollFailCounts[key] || 0) + 1;
    if (_pollFailCounts[key] === threshold) {
      toast('Live updates paused — check connection.', 'warning', 6000);
    }
  }
  window.wpPollFailure = pollFailure;

  // ---------- Client-side error capture ----------
  // Reports uncaught JS errors and unhandled promise rejections to the
  // server so they land in the same error_log table as backend exceptions
  // (visible in Settings -> Errors). Best-effort: failures to report are
  // swallowed, never surfaced to the user.
  function reportClientError(message, stack) {
    // /api/client-error is login_required, so a JS error on the login page
    // only ever earned a 302 to the login page. Nothing was logged and the
    // POST was pure noise in the access log.
    if (document.body.dataset.authed !== '1') return;
    const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
    fetch('/api/client-error', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify({
        message: String(message || '').slice(0, 2000),
        stack: String(stack || '').slice(0, 8000),
        url: window.location.pathname,
      }),
    }).catch(() => { /* best-effort — never block on this */ });
  }
  window.addEventListener('error', e => {
    reportClientError(e.message, e.error && e.error.stack);
  });
  window.addEventListener('unhandledrejection', e => {
    const reason = e.reason;
    reportClientError(
      reason && reason.message ? reason.message : String(reason),
      reason && reason.stack,
    );
  });

  const tbody = document.getElementById('alerts-tbody');

  // ---------- Round F follow-up: full-row click navigation ----------
  // Actions column was dropped from the IT alerts table — clicking
  // anywhere on a row now navigates to /alert/<id>. Event delegation
  // (single listener on #alerts-tbody) is required because SSE prepends
  // new rows after page load via dashboard-it-realtime.js's
  // tbody.insertAdjacentHTML('afterbegin', row_html). A static
  // querySelectorAll().forEach() would miss those.
  //
  // Gated on tbody existing so login / manager / alert-detail pages
  // (which don't have #alerts-tbody) are unaffected.
  if (tbody) {
    tbody.addEventListener('click', ev => {
      // Ignore clicks on interactive descendants (links, buttons) so
      // future inline controls inside cells keep working without the
      // row-navigation hijacking them.
      if (ev.target.closest('a, button, [data-no-row-click]')) return;
      const row = ev.target.closest('tr[data-alert-id]');
      if (!row) return;
      const id = row.dataset.alertId;
      if (id) window.location.href = '/alert/' + encodeURIComponent(id);
    });
  }

  // ---------- Dashboard filter submit ----------
  // The filtering itself lives in db.search_alerts now. What used to be
  // ~70 lines of match()/apply() over the rendered rows is one submit:
  // the old version could only ever hide rows that were already on the
  // page, so an alert past row 50 was unreachable by any control here.
  // The <select>s and the hide-low checkbox submit on change; #search
  // submits on Enter, which is what type="search" does for free.
  const alertFilters = document.getElementById('alert-filters');
  if (alertFilters) {
    alertFilters.addEventListener('change', () => alertFilters.submit());
  }

  // ---------- Dashboard severity bar chart ----------
  // Round 6: API now returns an array of {key,label,count,levels} in fixed
  // crit -> info order. The bar renderer is exposed as window.renderSevBars
  // so the SSE consumer (dashboard-it-realtime.js) can call it directly
  // with a payload from a severity_update event without an extra fetch.
  const sevBars = document.getElementById('sev-bars');
  if (sevBars) {
    function renderSevBars(arr) {
      // arr: [{key,label,count,levels}, ...] in any order. Defensive: skip
      // anything we don't recognise so a server-side typo doesn't blank the
      // UI; missing keys default to 0 below.
      if (!Array.isArray(arr)) return;
      const counts = { info: 0, low: 0, med: 0, high: 0, crit: 0 };
      for (const entry of arr) {
        if (entry && entry.key in counts) {
          counts[entry.key] = Number(entry.count) || 0;
        }
      }
      const maxCount = Math.max(...Object.values(counts), 1);
      let total = 0;
      for (const k of Object.keys(counts)) {
        const bar   = sevBars.querySelector(`[data-sev="${k}"]`);
        const label = document.getElementById(`count-${k}`);
        if (bar)   bar.style.width = ((counts[k] / maxCount) * 100) + '%';
        if (label) label.textContent = counts[k];
        total += counts[k];
      }
      const tot = document.getElementById('sev-total');
      if (tot) tot.textContent = total;
    }
    window.renderSevBars = renderSevBars;

    async function fetchAndRender(range) {
      try {
        const res = await fetch(`/api/severity-breakdown?range=${range}`,
                                 { cache: 'no-store' });
        if (res.ok) {
          renderSevBars(await res.json());
          pollFailure('sev-bars', true);
        } else {
          pollFailure('sev-bars', false);
        }
      } catch { pollFailure('sev-bars', false); /* leave bars at last-known values */ }
    }

    document.querySelectorAll('.range-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.range-btn').forEach(b => {
          b.classList.remove('bg-teal-600', 'text-white');
          b.classList.add('bg-slate-100', 'text-slate-600');
        });
        btn.classList.add('bg-teal-600', 'text-white');
        btn.classList.remove('bg-slate-100', 'text-slate-600');
        fetchAndRender(btn.dataset.range);
      });
    });
    fetchAndRender('24h');
  }

  // ---------- Tabs (role=tablist) ----------
  document.querySelectorAll('[role="tablist"]').forEach(list => {
    const tabs = Array.from(list.querySelectorAll('[role="tab"]'));
    tabs.forEach((tab, i) => {
      tab.addEventListener('click', () => activate(tab));
      tab.addEventListener('keydown', e => {
        if (e.key === 'ArrowRight') { e.preventDefault(); activate(tabs[(i + 1) % tabs.length]); }
        if (e.key === 'ArrowLeft')  { e.preventDefault(); activate(tabs[(i - 1 + tabs.length) % tabs.length]); }
        if (e.key === 'Home')       { e.preventDefault(); activate(tabs[0]); }
        if (e.key === 'End')        { e.preventDefault(); activate(tabs[tabs.length - 1]); }
      });
    });
    function activate(tab) {
      tabs.forEach(t => {
        const panel = document.getElementById(t.getAttribute('aria-controls'));
        const active = t === tab;
        t.setAttribute('aria-selected', active ? 'true' : 'false');
        t.setAttribute('tabindex', active ? '0' : '-1');
        if (panel) panel.hidden = !active;
      });
      tab.focus();
    }
  });

  // ---------- Modal (stateless DOM delegation) ----------
  // Finds the nearest ancestor modal and hides it.
  function closeModal(modal) {
    if (!modal) return;
    modal.hidden = true;
  }
  function closeModalFrom(el) { closeModal(el.closest('[role="dialog"]')); }

  window.wpOpenModal = function (id) {
    const m = document.getElementById(id);
    if (!m) return;
    m.hidden = false;
    // Focus the first interactive child for keyboard users.
    const focusable = m.querySelector(
      '[data-modal-close], button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    if (focusable) focusable.focus();
  };

  // Cancel / X buttons — works no matter when the modal was opened.
  document.addEventListener('click', e => {
    const closer = e.target.closest('[data-modal-close]');
    if (closer) { e.preventDefault(); closeModalFrom(closer); return; }
    // Click on the backdrop (the dialog element itself, not its inner card) → close.
    const backdrop = e.target;
    if (backdrop && backdrop.matches && backdrop.matches('[role="dialog"]') && !backdrop.hidden) {
      closeModal(backdrop);
    }
  });

  // Escape key closes any visible modal.
  document.addEventListener('keydown', e => {
    if (e.key !== 'Escape') return;
    document.querySelectorAll('[role="dialog"]:not([hidden])').forEach(closeModal);
  });

  // Forms inside modals with `data-async-submit` submit via fetch so the
  // page doesn't navigate to the JSON response. On success the modal
  // closes, a toast shows, and the page reloads to reflect new state.
  document.addEventListener('submit', async e => {
    const form = e.target;
    if (!form.matches('form[data-async-submit]')) return;
    e.preventDefault();
    const btn = form.querySelector('button[type="submit"], button:not([type])');
    if (btn) btn.disabled = true;
    try {
      const r = await fetch(form.action, {
        method: form.method || 'post',
        headers: { 'Accept': 'application/json' },
        body: new FormData(form),
      });
      const data = await r.json().catch(() => ({}));
      closeModalFrom(form);
      if (r.ok && data.success) {
        toast(data.message || 'Done.', 'success');
        setTimeout(() => window.location.reload(), 600);
      } else {
        toast(data.message || 'Request failed.', 'error');
      }
    } catch {
      toast('Network error — try again.', 'error');
    } finally {
      if (btn) btn.disabled = false;
    }
  });

  // ---------- Copy to clipboard ----------
  document.querySelectorAll('[data-copy]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const src = document.querySelector(btn.dataset.copy);
      if (!src) return;
      try {
        await navigator.clipboard.writeText(src.textContent);
        toast('Copied to clipboard', 'success', 1800);
      } catch { toast('Copy failed', 'error'); }
    });
  });

  // ---------- Humanized time ----------
  function humanize(iso) {
    const d = new Date(iso); if (isNaN(d)) return iso;
    const s = Math.floor((Date.now() - d.getTime()) / 1000);
    if (s < 60)    return s + 's ago';
    if (s < 3600)  return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  }
  function tickTimes() {
    document.querySelectorAll('time[datetime][data-humanize]').forEach(t => {
      t.textContent = humanize(t.getAttribute('datetime'));
    });
  }
  tickTimes();
  setInterval(tickTimes, 30000);

  // ---------- Manager dashboard polling ----------
  const feed = document.getElementById('alerts-feed');
  if (feed && feed.dataset.pollUrl) {
    setInterval(async () => {
      try {
        const r = await fetch(feed.dataset.pollUrl, { headers: { 'Accept': 'application/json' } });
        if (!r.ok) { pollFailure('manager-feed', false); return; }
        pollFailure('manager-feed', true);
        const { latest_id } = await r.json();
        if (latest_id && String(latest_id) !== feed.dataset.latestId) {
          feed.dataset.latestId = String(latest_id);
          toast('New alert received — refresh to view', 'warning', 6000);
        }
      } catch { pollFailure('manager-feed', false); }
    }, 15000);
  }

  // ---------- Password show/hide (legacy click-to-toggle) ----------
  // Kept for any page still using data-toggle-password. UI rework Round C
  // moved login.html to the hold-to-show pattern below; this handler stays
  // a no-op on pages without [data-toggle-password] elements.
  document.querySelectorAll('[data-toggle-password]').forEach(btn => {
    btn.addEventListener('click', () => {
      const input = document.querySelector(btn.dataset.togglePassword);
      if (!input) return;
      const isPw = input.type === 'password';
      input.type = isPw ? 'text' : 'password';
      btn.textContent = isPw ? 'Hide' : 'Show';
      btn.setAttribute('aria-pressed', isPw ? 'true' : 'false');
    });
  });

  // ---------- Password hold-to-show (UI rework Round C) ----------
  // Press-and-hold reveals the password; release re-masks. Better against
  // shoulder-surfing than click-to-toggle, which leaves the password
  // visible until the user remembers to click again. Listens to mouse
  // (mousedown/up/leave) and touch (touchstart/end/cancel) so it works
  // on both desktop and phone. mouseleave is the safety net for the case
  // where the user drags the cursor off the button while still holding.
  //
  // The button can carry two paired icon spans — [data-eye-closed]
  // (default) and [data-eye-open] (held). When present, the controller
  // swaps the `hidden` attribute on each so the icon visually flips
  // between closed-eye and open-eye while the user holds. Pages that
  // omit the paired icons get the input.type swap only — backward
  // compatible with the original Round C markup.
  document.querySelectorAll('[data-hold-password]').forEach(btn => {
    const input = document.querySelector(btn.dataset.holdPassword);
    if (!input) return;
    const eyeClosed = btn.querySelector('[data-eye-closed]');
    const eyeOpen   = btn.querySelector('[data-eye-open]');
    function reveal() {
      input.type = 'text';
      btn.setAttribute('aria-pressed', 'true');
      if (eyeClosed) eyeClosed.hidden = true;
      if (eyeOpen)   eyeOpen.hidden   = false;
    }
    function mask() {
      input.type = 'password';
      btn.setAttribute('aria-pressed', 'false');
      if (eyeClosed) eyeClosed.hidden = false;
      if (eyeOpen)   eyeOpen.hidden   = true;
    }
    btn.addEventListener('mousedown',  e => { e.preventDefault(); reveal(); });
    btn.addEventListener('mouseup',    mask);
    btn.addEventListener('mouseleave', mask);
    btn.addEventListener('touchstart', e => { e.preventDefault(); reveal(); }, { passive: false });
    btn.addEventListener('touchend',   mask);
    btn.addEventListener('touchcancel', mask);
    // Keyboard: Enter/Space simulate a tap — reveal on keydown, mask on keyup.
    btn.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); reveal(); }
    });
    btn.addEventListener('keyup', e => {
      if (e.key === 'Enter' || e.key === ' ') mask();
    });
  });

  // ---------- Cog dropdown menu (UI rework Round B) ----------
  // Header [data-menu-root] > [data-menu-toggle] + [data-menu-panel].
  // Click toggle to open; click outside the root or press Escape to close.
  // Each menu item closes the menu on activation so a click-then-navigate
  // cycle doesn't leave the panel open. Self-gates on [data-menu-toggle]
  // so this block no-ops on pre-Round-B pages or pages without a menu
  // (e.g. /login renders before authentication and has no header nav).
  document.querySelectorAll('[data-menu-toggle]').forEach(toggle => {
    const root  = toggle.closest('[data-menu-root]');
    const panel = root && root.querySelector('[data-menu-panel]');
    if (!root || !panel) return;

    function setOpen(open) {
      panel.hidden = !open;
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    }

    toggle.addEventListener('click', e => {
      e.stopPropagation();
      setOpen(panel.hidden);
    });

    // Close when activating any menu item (the click navigates / submits).
    panel.querySelectorAll('[role="menuitem"]').forEach(item => {
      item.addEventListener('click', () => setOpen(false));
    });

    // Click outside the menu root closes it. Single document-level
    // listener per menu instance — fine for the one-menu-per-page case
    // we have today.
    document.addEventListener('click', e => {
      if (panel.hidden) return;
      if (!root.contains(e.target)) setOpen(false);
    });

    // Escape closes the menu and refocuses the toggle for keyboard users.
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && !panel.hidden) {
        setOpen(false);
        toggle.focus();
      }
    });
  });
})();
