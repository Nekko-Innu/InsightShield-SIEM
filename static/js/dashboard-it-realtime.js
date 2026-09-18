// static/js/dashboard-it-realtime.js
// Round 4: wires the IT dashboard alert table + severity bar chart to the
// SSE stream from /api/events/stream. Loaded only on /dashboard/it via
// _base.html's {% block scripts %} (gated to current_user.role == 'IT_ADMIN').
//
// Manager dashboard's existing 15s polling stays untouched (this module
// short-circuits when #alerts-tbody is absent).

(function () {
  "use strict";

  const tbody = document.getElementById("alerts-tbody");
  if (!tbody) return;  // not on the IT dashboard

  if (!window.InsightShieldSSE) {
    console.warn("dashboard-it-realtime: sse.js missing");
    return;
  }

  // Filtering moved to SQL, so a live alert may simply not belong on the view
  // the user is looking at — a CRITICAL-only filter, or page 3. The server
  // decides via data-filtered; this file never re-implements the filter. On a
  // filtered view the row is counted and offered as a reload, not inserted.
  const filtered = tbody.dataset.filtered === "1";
  const perPage = Number(tbody.dataset.perPage) || 0;
  let pendingCount = 0;

  // On a filtered view a new alert isn't inserted — it's only counted behind
  // the "N new alerts · Reload" chip, so a HIGH/CRITICAL can sit unseen until
  // the IT admin remembers to click. Auto-reload for HIGH/CRITICAL so an attack
  // can't hide behind the chip. Gated to:
  //  - HIGH/CRITICAL only: low-severity noise (or an alert the active filter
  //    excludes) must not yank the page out from under someone mid-read, and
  //    this keeps us from re-implementing the server filter (see below).
  //  - page 1 only: alerts are newest-first, so they only ever land on page 1;
  //    reloading page 3 wouldn't show the new alert anyway. Later pages keep the
  //    manual chip.
  // ponytail: one-shot 3s debounce — a burst coalesces into a single reload.
  const onFirstPage = (new URLSearchParams(location.search).get("page") || "1") === "1";
  let reloadTimer = null;
  function autoReloadFor(severity) {
    if (!onFirstPage || reloadTimer) return;
    const sev = (severity || "").toUpperCase();
    if (sev !== "HIGH" && sev !== "CRITICAL") return;
    reloadTimer = setTimeout(function () { window.location.reload(); }, 3000);
  }

  function showPendingChip() {
    let chip = document.getElementById("new-alerts-chip");
    if (!chip) {
      chip = document.createElement("button");
      chip.id = "new-alerts-chip";
      chip.type = "button";
      chip.className =
        "w-full px-4 py-2 text-sm text-brand-700 bg-brand-50 border-b " +
        "border-surface-200 hover:bg-brand-100 text-left";
      chip.addEventListener("click", function () { window.location.reload(); });
      // Above the .table-scroll wrapper, not inside it — the wrapper is
      // capped at 420px and a chip inside would scroll out of sight.
      const scroller = tbody.parentNode.parentNode;
      scroller.parentNode.insertBefore(chip, scroller);
    }
    chip.textContent =
      pendingCount + (pendingCount === 1 ? " new alert" : " new alerts") + " · Reload";
  }

  const sse = new window.InsightShieldSSE("/api/events/stream", {
    onEvent: function (type, data) {
      if (type === "new_alert") {
        // De-dupe: skip if a row with the same data-alert-id is already
        // present. Covers a race where the polling fallback's fetch and
        // the SSE event deliver the same row.
        if (data && data.id && tbody.querySelector('tr[data-alert-id="' + data.id + '"]')) {
          return;
        }
        if (filtered) {
          pendingCount += 1;
          showPendingChip();
          autoReloadFor(data && data.severity);
          return;
        }
        if (data && data.row_html) {
          // Drop the "No alerts." placeholder before the first live row lands
          // on top of it.
          const placeholder = tbody.querySelector("tr:not([data-alert-id])");
          if (placeholder) placeholder.remove();
          tbody.insertAdjacentHTML("afterbegin", data.row_html);
          // Drop the row pushed off the end so the pager's "Showing 1–50 of N"
          // keeps describing what is actually on screen.
          const rows = tbody.querySelectorAll("tr[data-alert-id]");
          if (perPage && rows.length > perPage) {
            rows[rows.length - 1].remove();
          }
          if (window.wpToast) {
            window.wpToast(
              "New " + (data.severity || "alert") + " alert",
              "info",
              5000,
            );
          }
        }
      } else if (type === "severity_update") {
        // Round 6 wires window.renderSevBars; until then this is a no-op.
        if (window.renderSevBars && data && data.breakdown) {
          window.renderSevBars(data.breakdown);
        }
      }
      // agent_status events arrive in Round 5 once the producer thread is wired.
    },
    onPollFallback: function () {
      console.info("SSE unavailable - polling fallback active");
      if (window.wpToast) {
        window.wpToast("Live updates offline - polling every 15s", "warning", 6000);
      }
      // Round 6: real polling. Two independent ticks on the same 15s
      // interval — alert-table watermark check + severity bar refetch.
      // The watermark seed is the topmost row's data-alert-id (rendered
      // by _alert_row.html). If that's missing (empty table), seed at 0
      // so the very first new alert triggers a refresh.
      const firstRow = tbody.querySelector("tr[data-alert-id]");
      let latestSeen = firstRow ? Number(firstRow.dataset.alertId) || 0 : 0;

      function tick() {
        // Alert watermark: any new alert ID -> full page reload.
        // Partial DOM update would need a /api/alerts/since?id=N endpoint
        // returning row HTML; out of scope for the fallback path. Reload
        // is correct and matches the manager-dashboard fallback pattern.
        fetch("/api/alerts/latest", { cache: "no-store" })
          .then(function (r) {
            if (window.wpPollFailure) window.wpPollFailure("it-alerts-latest", r.ok);
            return r.ok ? r.json() : null;
          })
          .then(function (data) {
            if (!data) return;
            const id = Number(data.latest_id) || 0;
            if (id > latestSeen) {
              latestSeen = id;
              if (window.wpToast) {
                window.wpToast("New alerts received - reloading", "info", 2500);
              }
              setTimeout(function () { window.location.reload(); }, 800);
            }
          })
          .catch(function () {
            if (window.wpPollFailure) window.wpPollFailure("it-alerts-latest", false);
            /* next tick retries */
          });

        // Severity-bar refetch: in-place update via the renderSevBars
        // global that ui.js exposes in Round 6. Range is fixed at 24h
        // for the fallback — the range buttons still work and simply
        // override the next call.
        if (window.renderSevBars) {
          fetch("/api/severity-breakdown?range=24h", { cache: "no-store" })
            .then(function (r) {
              if (window.wpPollFailure) window.wpPollFailure("it-sev-bars", r.ok);
              return r.ok ? r.json() : null;
            })
            .then(function (data) {
              if (Array.isArray(data)) window.renderSevBars(data);
            })
            .catch(function () {
              if (window.wpPollFailure) window.wpPollFailure("it-sev-bars", false);
            });
        }
      }

      const intervalId = setInterval(tick, 15000);
      window.addEventListener("beforeunload", function () {
        clearInterval(intervalId);
      });
    },
  });

  sse.start();
  // Tear down on tab unload to be polite to gunicorn worker slots.
  window.addEventListener("beforeunload", function () { sse.stop(); });
})();
