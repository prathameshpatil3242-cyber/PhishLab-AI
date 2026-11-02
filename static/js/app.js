/* =====================================================================
   app.js — shared helpers (navigation, CSRF token, small utilities)
   ===================================================================== */
(function () {
  "use strict";

  /* ---- mobile sidebar ---- */
  var sidebar = document.getElementById("sidebar");
  var scrim = document.getElementById("sidebarScrim");
  var toggle = document.getElementById("menuToggle");

  function setOpen(open) {
    if (!sidebar) return;
    sidebar.classList.toggle("is-open", open);
    if (scrim) scrim.hidden = !open;
    if (toggle) toggle.setAttribute("aria-expanded", String(open));
  }

  if (toggle) {
    toggle.addEventListener("click", function () {
      setOpen(!sidebar.classList.contains("is-open"));
    });
  }
  if (scrim) scrim.addEventListener("click", function () { setOpen(false); });

  /* ---- desktop collapse (double-click the logo area) ---- */
  var brand = document.querySelector(".brand");
  if (brand) {
    brand.addEventListener("click", function () {
      if (window.matchMedia("(min-width: 901px)").matches) {
        sidebar.classList.toggle("is-collapsed");
      }
    });
  }

  /* ---- CSRF token helper for fetch() ---- */
  window.PhishLab = window.PhishLab || {};
  var meta = document.querySelector('meta[name="csrf-token"]');
  window.PhishLab.csrf = meta ? meta.getAttribute("content") : "";

  /**
   * POST JSON to a PhishLab endpoint with the CSRF header.
   * Returns { ok, data } or { ok:false, error }.
   */
  window.PhishLab.postJSON = function (url, payload) {
    return fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": window.PhishLab.csrf
      },
      body: JSON.stringify(payload || {})
    }).then(function (res) {
      return res.json().catch(function () {
        return { ok: false, error: "Unexpected server response (" + res.status + ")." };
      }).then(function (data) {
        return { ok: res.ok && data.ok !== false, status: res.status, data: data };
      });
    }).catch(function () {
      return { ok: false, status: 0, data: { ok: false, error: "Network error — is the Flask server still running?" } };
    });
  };

  /* ---- auto-hide flash messages ---- */
  window.setTimeout(function () {
    document.querySelectorAll(".flash").forEach(function (el) {
      el.style.transition = "opacity .5s ease";
      el.style.opacity = "0";
      window.setTimeout(function () { el.remove(); }, 600);
    });
  }, 7000);

  /* ---- scroll reveal (public pages) ---- */
  var revealables = document.querySelectorAll(".reveal");
  if (revealables.length) {
    if ("IntersectionObserver" in window) {
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-in");
            io.unobserve(entry.target);
          }
        });
      }, { threshold: 0.12, rootMargin: "0px 0px -40px 0px" });
      revealables.forEach(function (el) { io.observe(el); });
    } else {
      revealables.forEach(function (el) { el.classList.add("is-in"); });
    }
  }

  /* ---- animated counters ---- */
  function animateCount(el) {
    var target = parseFloat(el.getAttribute("data-count-to") || "0");
    var suffix = el.getAttribute("data-suffix") || "";
    var decimals = (String(target).split(".")[1] || "").length;
    var duration = 1100;
    var start = null;

    function frame(ts) {
      if (start === null) start = ts;
      var p = Math.min((ts - start) / duration, 1);
      var eased = 1 - Math.pow(1 - p, 3);           // ease-out cubic
      el.textContent = (target * eased).toFixed(decimals) + suffix;
      if (p < 1) window.requestAnimationFrame(frame);
      else el.textContent = target.toFixed(decimals) + suffix;
    }
    window.requestAnimationFrame(frame);
  }

  var counters = document.querySelectorAll("[data-count-to]");
  if (counters.length) {
    if ("IntersectionObserver" in window) {
      var cio = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            animateCount(entry.target);
            cio.unobserve(entry.target);
          }
        });
      }, { threshold: 0.4 });
      counters.forEach(function (el) { cio.observe(el); });
    } else {
      counters.forEach(animateCount);
    }
  }

  /* ---- pricing: monthly / yearly toggle ---- */
  var pricing = document.querySelector(".pricing");
  if (pricing) {
    var opts = pricing.querySelectorAll("[data-period-btn]");
    var pill = pricing.querySelector(".billing-pill");
    var amounts = pricing.querySelectorAll(".plan-amount[data-m]");
    var notes = pricing.querySelectorAll("[data-billed-note]");

    function movePill(btn) {
      if (!pill || !btn) return;
      pill.style.width = btn.offsetWidth + "px";
      pill.style.transform = "translateX(" + (btn.offsetLeft - 5) + "px)";
    }

    function tweenAmount(el, to) {
      var from = parseFloat(el.textContent.replace(/[^\d.]/g, "")) || 0;
      if (from === to) { el.textContent = String(to); return; }
      var duration = 420;
      var start = null;
      function frame(ts) {
        if (start === null) start = ts;
        var p = Math.min((ts - start) / duration, 1);
        var eased = 1 - Math.pow(1 - p, 3);
        el.textContent = String(Math.round(from + (to - from) * eased));
        if (p < 1) window.requestAnimationFrame(frame);
        else el.textContent = String(to);
      }
      window.requestAnimationFrame(frame);
    }

    function setPeriod(period) {
      pricing.setAttribute("data-period", period);
      opts.forEach(function (btn) {
        var on = btn.getAttribute("data-period-btn") === period;
        btn.classList.toggle("is-active", on);
        btn.setAttribute("aria-pressed", String(on));
        if (on) movePill(btn);
      });
      amounts.forEach(function (el) {
        var value = parseInt(el.getAttribute(period === "y" ? "data-y" : "data-m"), 10);
        if (!isNaN(value)) tweenAmount(el, value);
      });
      notes.forEach(function (note) {
        var card = note.closest(".plan");
        var amountEl = card ? card.querySelector(".plan-amount") : null;
        var value = amountEl
          ? parseInt(amountEl.getAttribute(period === "y" ? "data-y" : "data-m"), 10)
          : NaN;
        if (value === 0) { note.textContent = "Free forever"; return; }
        note.textContent = period === "y"
          ? "Billed annually · $" + (value * 12) + " / user / year"
          : "Billed monthly";
      });
    }

    opts.forEach(function (btn) {
      btn.addEventListener("click", function () {
        setPeriod(btn.getAttribute("data-period-btn"));
      });
    });

    // keep the pill aligned with the active option
    var active = pricing.querySelector(".billing-opt.is-active") || opts[0];
    movePill(active);
    window.addEventListener("resize", function () {
      movePill(pricing.querySelector(".billing-opt.is-active"));
    });
    if (document.fonts && document.fonts.ready) {
      document.fonts.ready.then(function () {
        movePill(pricing.querySelector(".billing-opt.is-active"));
      });
    }
  }

  /* ---- highlight the marketing nav item for the current page ---- */
  var here = window.location.pathname.replace(/\/$/, "") || "/";
  document.querySelectorAll(".mkt-link").forEach(function (link) {
    try {
      var path = new URL(link.href, window.location.origin).pathname.replace(/\/$/, "") || "/";
      if (path === here) link.classList.add("is-active");
    } catch (err) { /* cross-origin or malformed — ignore */ }
  });
})();
