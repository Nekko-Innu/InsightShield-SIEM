// static/js/sse.js
// Insight Shield — Round 4 SSE connection helper.
//
// Public API (window.InsightShieldSSE):
//   const sse = new InsightShieldSSE("/api/events/stream", {
//     onEvent: (type, data) => { ... },     // every event
//     onPollFallback: () => { ... },        // 3 reconnect failures hit
//   });
//   sse.start();
//
// Reconnect: 3 attempts with exponential backoff (1s, 2s, 4s). After
// the third failure the connection is abandoned and onPollFallback fires
// once. Round 4's consumer (dashboard-it-realtime.js) shows a toast on
// fallback; Round 6 will swap in a /api/alerts/latest polling loop.

(function () {
  "use strict";

  class InsightShieldSSE {
    constructor(url, opts) {
      opts = opts || {};
      this.url = url;
      this.onEvent = opts.onEvent || function () {};
      this.onPollFallback = opts.onPollFallback || function () {};
      this._attempts = 0;
      this._maxAttempts = 3;
      this._es = null;
      this._fellBack = false;
    }

    start() {
      if (this._fellBack) return;
      this._open();
    }

    stop() {
      if (this._es) {
        this._es.close();
        this._es = null;
      }
    }

    _open() {
      try {
        this._es = new EventSource(this.url);
      } catch (e) {
        console.warn("SSE: EventSource construction failed", e);
        return this._maybeFallback();
      }
      this._es.addEventListener("new_alert",       (e) => this._dispatch("new_alert", e));
      this._es.addEventListener("severity_update", (e) => this._dispatch("severity_update", e));
      this._es.addEventListener("agent_status",    (e) => this._dispatch("agent_status", e));
      this._es.onopen = () => {
        // Successful open resets the backoff counter so a transient blip
        // doesn't accumulate toward the 3-strike fallback.
        this._attempts = 0;
      };
      this._es.onerror = () => {
        if (this._es) {
          this._es.close();
          this._es = null;
        }
        this._maybeFallback();
      };
    }

    _dispatch(type, e) {
      try {
        const data = JSON.parse(e.data);
        this.onEvent(type, data);
      } catch (err) {
        console.warn("SSE: parse error on", type, err);
      }
    }

    _maybeFallback() {
      this._attempts += 1;
      if (this._attempts > this._maxAttempts) {
        this._fellBack = true;
        console.warn("SSE: reconnect attempts exhausted, falling back to polling");
        this.onPollFallback();
        return;
      }
      const backoffMs = Math.pow(2, this._attempts - 1) * 1000;  // 1s, 2s, 4s
      console.warn(
        "SSE: reconnect in",
        backoffMs,
        "ms (attempt", this._attempts, "of", this._maxAttempts, ")"
      );
      setTimeout(() => this._open(), backoffMs);
    }
  }

  window.InsightShieldSSE = InsightShieldSSE;
})();
