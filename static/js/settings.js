// settings.js
// Insight Shield — Settings page client-side helpers.
// Loaded only on /admin/settings via _base.html's {% block scripts %}.
//
// Behaviours wired:
//   1. Click-to-reveal masked credentials (10s auto-mask).
//   2. Provider Add: template dropdown auto-fills base_url + auth fields.
//   3. (Round F §17.6 F5) Edit button → open shared modal pre-filled.
//   4. (Round F §17.6 F5) Modal Save → fan-out POST to per-field endpoints.
//   5. (Round F §17.6 F5) Test button → AJAX probe + status row update + toast.
//   6. AI provider reorder + provider-toggle + delete remain server-rendered
//      per-row forms (no JS needed); the SMS/Telegram service toggle uses
//      data-async-submit + ui.js global handler now that the endpoint
//      returns JSON when called via fetch.

(function () {
  "use strict";

  // ── 1. Click-to-reveal ────────────────────────────────────────────────
  document.addEventListener("click", async (ev) => {
    const btn = ev.target.closest(".btn-reveal");
    if (!btn || btn.disabled) return;
    const card = btn.closest("form, section");
    if (!card) return;
    const input = card.querySelector('input[type="password"]');
    if (!input) return;

    const service = input.dataset.service;
    const keyName = input.dataset.keyName || "API_KEY";
    const csrf = document.getElementById("csrf-token")?.value || "";

    btn.disabled = true;
    try {
      const body = new URLSearchParams({ key_name: keyName, _csrf: csrf });
      const r = await fetch(`/admin/settings/api-keys/${encodeURIComponent(service)}/reveal`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      });
      if (!r.ok) {
        console.warn("reveal failed:", r.status);
        window.wpToast?.("Could not reveal credential.", "error");
        btn.disabled = false;
        return;
      }
      const data = await r.json();
      const plaintext = data.value || "";
      const originalType = input.type;
      const originalPlaceholder = input.placeholder;
      input.type = "text";
      input.value = plaintext;
      input.placeholder = "";

      // Auto-restore mask after 10s
      setTimeout(() => {
        input.type = originalType;
        input.value = "";
        input.placeholder = originalPlaceholder;
        btn.disabled = false;
      }, 10000);
    } catch (e) {
      console.error("reveal error:", e);
      window.wpToast?.("Could not reveal credential.", "error");
      btn.disabled = false;
    }
  });

  // ── Round F §17.6 F5 helpers ──────────────────────────────────────────
  function getCsrf() {
    return (
      document.getElementById("csrf-token")?.value ||
      document.querySelector('input[name="_csrf"]')?.value ||
      ""
    );
  }

  function setStatusDot(card, statusToken /* 'online' | 'offline' */) {
    const tone = statusToken === "online" ? "online" : "offline";
    const colorVar = `var(--status-${tone})`;
    const dot = card.querySelector("[data-status-dot]");
    const label = card.querySelector("[data-status-label]");
    if (dot) dot.style.backgroundColor = colorVar;
    if (label) {
      label.textContent = tone.toUpperCase();
      label.style.color = colorVar;
    }
  }

  function showTestResult(card, kind /* 'success' | 'error' */, message) {
    const slot = card.querySelector("[data-test-result]");
    if (!slot) return;
    const prefix = kind === "success" ? "✓ " : "✕ ";
    slot.textContent = prefix + message;
    slot.className = `test-result test-result--${kind}`;
    slot.hidden = false;
    // Auto-fade after 4s. Re-running Test cancels the prior fade timer
    // by clearing the dataset id (light bookkeeping, no leak).
    const ticket = ++slot.dataset.fadeTicket || 1;
    slot.dataset.fadeTicket = ticket;
    setTimeout(() => {
      if (slot.dataset.fadeTicket !== String(ticket)) return;
      slot.classList.add("test-result--fading");
      setTimeout(() => {
        if (slot.dataset.fadeTicket !== String(ticket)) return;
        slot.hidden = true;
        slot.classList.remove("test-result--fading");
      }, 300);
    }, 4000);
  }

  // ── 3. Test button — live probe via /admin/settings/test/<svc> ────────
  document.addEventListener("click", async (ev) => {
    const btn = ev.target.closest("[data-service-test]");
    if (!btn || btn.disabled) return;
    const svc = btn.dataset.serviceTest;
    const card = document.querySelector(`[data-service-card="${svc}"]`);
    if (!card) return;

    const iconSpan = btn.querySelector("[data-test-icon]");
    const origText = iconSpan ? iconSpan.textContent : "";
    if (iconSpan) iconSpan.innerHTML = '<span class="spinner" aria-label="testing"></span>';
    btn.disabled = true;

    try {
      const r = await fetch(
        `/admin/settings/test/${encodeURIComponent(svc)}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ _csrf: getCsrf() }),
        }
      );
      const data = await r.json().catch(() => ({}));
      if (data.status === "rate_limited") {
        window.wpToast?.(data.message || "Rate limited.", "warning", 3500);
      } else if (data.status === "online") {
        setStatusDot(card, "online");
        showTestResult(card, "success", data.message || "Online.");
        window.wpToast?.(data.message || `${svc} online.`, "success", 3000);
      } else {
        // 'offline' or unknown
        setStatusDot(card, "offline");
        showTestResult(card, "error", data.message || "Offline.");
        window.wpToast?.(data.message || `${svc} offline.`, "error", 4000);
      }
    } catch (e) {
      window.wpToast?.("Test failed: " + (e.message || "network error"), "error", 4000);
    } finally {
      btn.disabled = false;
      if (iconSpan) iconSpan.textContent = origText;
    }
  });

  // ── 4. Edit button — read JSON island, populate modal, open ──────────
  document.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-service-edit]");
    if (!btn) return;
    const svc = btn.dataset.serviceEdit;
    const islandEl = document.getElementById(`service-edit-config-${svc}`);
    if (!islandEl) return;
    let cfg;
    try {
      cfg = JSON.parse(islandEl.textContent || "{}");
    } catch (e) {
      console.error("bad service-edit-config island:", e);
      return;
    }

    const titleEl = document.getElementById("settings-edit-modal-title");
    const subtitleEl = document.getElementById("settings-edit-modal-subtitle");
    const fieldsEl = document.getElementById("settings-edit-fields");
    if (!titleEl || !fieldsEl) return;

    titleEl.textContent = `Edit ${cfg.label || svc}`;
    if (subtitleEl) subtitleEl.textContent = cfg.subtitle || "";

    // Build form fields from the config. Each input carries its own
    // endpoint + extra-form-data on data-* attrs so the Save handler can
    // fan out without re-parsing the config.
    fieldsEl.innerHTML = "";
    (cfg.fields || []).forEach((f, idx) => {
      const wrap = document.createElement("div");
      wrap.className = "space-y-1";

      const id = `settings-edit-field-${idx}`;
      const label = document.createElement("label");
      label.htmlFor = id;
      label.className = "block text-sm font-medium text-slate-700";
      label.textContent = f.label || f.name || "Field";
      wrap.appendChild(label);

      const input = document.createElement("input");
      input.id = id;
      input.type = f.type === "password" ? "password" : "text";
      input.className =
        "w-full rounded-md border border-surface-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none";
      if (f.type === "password") input.classList.add("font-mono");
      input.placeholder =
        f.placeholder ||
        (f.current_set ? "— enter to replace —" : "— not set —");
      if (f.type !== "password") input.value = f.current_value || "";
      input.dataset.endpoint = f.endpoint || "";
      input.dataset.fieldName = f.name || "value";
      input.dataset.extraData = JSON.stringify(f.extra || {});
      input.dataset.isPassword = f.type === "password" ? "1" : "0";
      wrap.appendChild(input);

      if (f.hint) {
        const hint = document.createElement("p");
        hint.className = "text-xs text-slate-500";
        hint.textContent = f.hint;
        wrap.appendChild(hint);
      }

      fieldsEl.appendChild(wrap);
    });

    if (typeof window.wpOpenModal === "function") {
      window.wpOpenModal("settings-edit-modal");
    }
  });

  // ── 5. Edit modal Save — fan-out POST to per-field endpoints ─────────
  const editForm = document.getElementById("settings-edit-form");
  if (editForm) {
    // Capture-phase + stopImmediatePropagation so the global
    // data-async-submit handler in ui.js never fires for THIS form (we
    // need multi-endpoint fan-out, not a single POST). Other forms with
    // data-async-submit (toggle, etc.) keep using the global handler.
    editForm.addEventListener(
      "submit",
      async (ev) => {
        ev.preventDefault();
        ev.stopImmediatePropagation();

        const inputs = Array.from(
          editForm.querySelectorAll("[data-endpoint]")
        );
        const submitBtn = editForm.querySelector('button[type="submit"]');
        const csrf = getCsrf();
        if (submitBtn) submitBtn.disabled = true;

        // Skip blank password fields (operator left untouched -> no change).
        // Always POST text fields, even when blank, so the operator can
        // explicitly clear a value.
        const toPost = inputs.filter((i) =>
          i.dataset.isPassword === "1" ? i.value !== "" : true
        );
        if (toPost.length === 0) {
          // Nothing to do — close & toast.
          window.wpToast?.("No changes.", "info", 1800);
          if (submitBtn) submitBtn.disabled = false;
          editForm.closest('[role="dialog"]').hidden = true;
          return;
        }

        try {
          const results = await Promise.all(
            toPost.map(async (input) => {
              const endpoint = input.dataset.endpoint;
              const fieldName = input.dataset.fieldName;
              const extra = JSON.parse(input.dataset.extraData || "{}");
              const body = new URLSearchParams({
                _csrf: csrf,
                [fieldName]: input.value,
                ...extra,
              });
              const r = await fetch(endpoint, {
                method: "POST",
                headers: {
                  "Content-Type": "application/x-www-form-urlencoded",
                  Accept: "application/json",
                },
                body,
              });
              return { ok: r.ok, status: r.status, endpoint };
            })
          );
          const failures = results.filter((x) => !x.ok);
          editForm.closest('[role="dialog"]').hidden = true;
          if (failures.length === 0) {
            window.wpToast?.(
              `${results.length} field${results.length === 1 ? "" : "s"} saved.`,
              "success",
              2000
            );
            setTimeout(() => window.location.reload(), 700);
          } else {
            window.wpToast?.(
              `${failures.length}/${results.length} field(s) failed to save.`,
              "error",
              4000
            );
          }
        } catch (e) {
          window.wpToast?.(
            "Save failed: " + (e.message || "network error"),
            "error",
            4000
          );
        } finally {
          if (submitBtn) submitBtn.disabled = false;
        }
      },
      true /* capture phase — runs before global ui.js handler */
    );
  }

  // ── 2. Provider template dropdown ─────────────────────────────────────
  const tplSelect = document.getElementById("provider-template-select");
  const tplJsonEl = document.getElementById("provider-templates-json");
  if (tplSelect && tplJsonEl) {
    let templates = {};
    try {
      templates = JSON.parse(tplJsonEl.textContent || "{}");
    } catch (e) {
      console.warn("Bad provider-templates JSON island:", e);
    }
    tplSelect.addEventListener("change", () => {
      const tpl = templates[tplSelect.value];
      if (!tpl) return;
      const form = tplSelect.closest("form");
      if (!form) return;
      const fill = (name, value) => {
        const f = form.querySelector(`[name="${name}"]`);
        if (f) f.value = value;
      };
      fill("base_url", tpl.base_url || "");
      fill("auth_header", tpl.auth_header || "Authorization");
      fill("auth_prefix", tpl.auth_prefix || "");
      fill("request_format", tpl.request_format || "openai_compat");
      // Pre-fill the label with the template name (operator usually edits
      // it for Custom but Groq/OpenAI/etc. it's fine as-is).
      const labelInput = form.querySelector('[name="label"]');
      if (labelInput && !labelInput.value) labelInput.value = tplSelect.value;
    });
  }

  // Confirm-before-submit, driven by a data attribute rather than an inline
  // onsubmit that interpolates the value.
  //
  // The provider delete button used to build its message with
  // {{ p.label | tojson }} inside a double-quoted onsubmit. Jinja's tojson
  // escapes < > & and ' but NOT ", so the JSON string's own quote closed the
  // attribute and everything after it parsed as new attributes on the form --
  // a label of `x onmouseover=alert(1) y` became a live event handler, which
  // script-src 'unsafe-inline' happily runs, next to a CSRF token sitting in a
  // readable meta tag. It also meant the dialog never actually worked: the
  // handler was a syntax error for every label, valid or not.
  //
  // data-confirm goes through normal attribute autoescaping, where " becomes
  // &#34;, and the value reaches JS as text that is never parsed as code.
  document.addEventListener("submit", (e) => {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    const message = form.dataset.confirm;
    if (message && !window.confirm(message)) e.preventDefault();
  });

  // ── Backups tab: select-all box and the Restore command modal ──
  document.addEventListener("change", (e) => {
    if (e.target.id !== "backup-select-all") return;
    document.querySelectorAll('input[name="names"][form="delete-selected"]')
      .forEach((box) => { box.checked = e.target.checked; });
  });
  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-restore-name]");
    if (!btn) return;
    // textContent, never innerHTML: the name ends up in a root shell.
    document.getElementById("restore-name").textContent = btn.dataset.restoreName;
    window.wpOpenModal("restore-modal");
  });
})();
