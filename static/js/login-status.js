// static/js/login-status.js
// Insight Shield — Round 5 (Part 5: Dynamic agent status)
//
// Polls /api/status every 30s and updates the login page's status chip +
// per-device dots. Public endpoint (no auth) so this works before sign-in.
// SSE is intentionally not used here — the login page is unauthenticated
// and SSE would tie up gunicorn worker slots for every visitor.
//
// Self-gates on [data-status-dot]: if the hook isn't present (i.e. we're
// on a non-login page that accidentally inherited this script), the
// module exits without scheduling the interval.

(function () {
  "use strict";

  const dot     = document.querySelector("[data-status-dot]");
  const summary = document.querySelector("[data-status-summary]");
  const counts  = document.querySelector("[data-status-counts]");
  if (!dot) return;  // not the login page

  // Map snapshot.dot_color (green/amber/red) -> design-tokens.css variable.
  // The CSS variables already exist (--status-online/degraded/offline);
  // this map just aliases the snapshot's coarse name to the token.
  const COLOR_TO_TOKEN = {
    green: "var(--status-online)",
    amber: "var(--status-degraded)",
    red:   "var(--status-offline)",
  };

  function applySnapshot(snap) {
    if (!snap) return;

    // System-status chip
    const token = COLOR_TO_TOKEN[snap.dot_color] || COLOR_TO_TOKEN.red;
    dot.style.backgroundColor = token;
    if (summary && snap.summary) {
      summary.textContent = snap.summary;
    }
    if (counts && typeof snap.agents_online === "number"
        && typeof snap.agents_total === "number") {
      counts.textContent = "(" + snap.agents_online + "/" + snap.agents_total + " online)";
    }

    // Per-device dot color follows the overall state:
    //   green -> all device dots green
    //   amber -> green for online indicators, but coarse summary takes over
    //            (we don't have per-device data on the public endpoint)
    //   red   -> all device dots red
    // This is intentionally coarse — the public /api/status payload
    // strips the per-agent list to avoid leaking surface area.
    document.querySelectorAll("[data-device-dot]").forEach(function (el) {
      el.style.backgroundColor = token;
    });
    document.querySelectorAll("[data-device-label]").forEach(function (el) {
      if (snap.dot_color === "red") {
        el.textContent = "unreachable";
      } else if (snap.dot_color === "amber") {
        el.textContent = "checking…";
      } else {
        el.textContent = "monitoring…";
      }
    });
  }

  function poll() {
    fetch("/api/status", { credentials: "same-origin", cache: "no-store" })
      .then(function (r) {
        if (!r.ok) throw new Error("status " + r.status);
        return r.json();
      })
      .then(applySnapshot)
      .catch(function (err) {
        // Server unreachable: paint everything red but don't break the
        // login form. Console-warn instead of toast since the user is
        // mid-typing credentials and we don't want to distract.
        console.warn("login-status: poll failed", err);
        applySnapshot({
          dot_color: "red",
          summary: "Status unavailable",
          agents_online: 0,
          agents_total: 0,
        });
      });
  }

  // Initial poll fires immediately, then every 30s.
  poll();
  const interval = setInterval(poll, 30000);

  // Stop polling if the user leaves the page (e.g. logs in -> dashboard).
  window.addEventListener("beforeunload", function () {
    clearInterval(interval);
  });
})();
