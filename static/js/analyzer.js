/* =====================================================================
   analyzer.js — enhancements for the "Analyze Message" and "URL Analyzer"
   pages.

   Behaviour:
     * counts characters as you type,
     * fills the box with safe fictional samples,
     * submits the form with fetch() so the result appears without reload,
     * falls back to a normal HTML form post when JavaScript is unavailable
       (the Flask routes handle both).
   ===================================================================== */
(function () {
  "use strict";

  var SAMPLES = {
    phish:
      "From: security@paypa1-verify.com\n" +
      "Subject: Urgent: your account will be suspended\n\n" +
      "Dear customer,\n\n" +
      "We detected unauthorized activity on your account. Your account will be " +
      "closed within 24 hours unless you verify it now. Reply with your password " +
      "and one-time code, or click here to verify immediately:\n" +
      "http://192.168.10.44/verify/account\n\n" +
      "Failure to respond will lead to permanent suspension. Do not tell anyone " +
      "about this notice.\n\n" +
      "— Account Security Team",
    legit:
      "From: lab-coordinator@tkiet.example.edu\n" +
      "Subject: Cyber Security lab batch — room change\n\n" +
      "Hello everyone,\n\n" +
      "Tomorrow's Cyber Security lab will run in Room 204 instead of Room 110. " +
      "Please bring your laptops and the printed worksheet. No action is required " +
      "from you other than noting the room change.\n\n" +
      "Regards,\nLab Coordinator"
  };

  /* ---------------- message page ---------------- */
  var form = document.getElementById("analyzeForm");
  var input = document.getElementById("messageInput");
  var counter = document.getElementById("charCount");
  var panel = document.getElementById("resultPanel");

  if (input && counter) {
    var updateCount = function () { counter.textContent = String(input.value.length); };
    input.addEventListener("input", updateCount);
    updateCount();
  }

  document.querySelectorAll("[data-sample]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      if (!input) return;
      input.value = SAMPLES[btn.getAttribute("data-sample")] || "";
      input.dispatchEvent(new Event("input"));
      input.focus();
    });
  });

  var clearBtn = document.getElementById("clearBtn");
  if (clearBtn && input) {
    clearBtn.addEventListener("click", function () {
      input.value = "";
      input.dispatchEvent(new Event("input"));
      if (panel) {
        panel.innerHTML =
          '<div class="empty-state"><p class="empty-ico">&#9888;</p>' +
          "<p>Cleared. Paste a message and press <strong>Analyze message</strong>.</p></div>";
      }
      input.focus();
    });
  }

  if (form && input && panel) {
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      var text = input.value.trim();
      panel.innerHTML = '<div class="empty-state"><p class="muted">Analyzing…</p></div>';

      window.PhishLab.postJSON("/api/analyze", { message: text }).then(function (res) {
        if (res.ok && res.data.html) {
          panel.innerHTML = res.data.html;
        } else {
          var msg = (res.data && res.data.error) || "Analysis failed.";
          panel.innerHTML = '<div class="flash flash-error" role="alert">' +
            escapeHtml(msg) + "</div>";
        }
        panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
      });
    });
  }

  /* ---------------- URL page ---------------- */
  var urlForm = document.getElementById("urlForm");
  var urlInput = document.getElementById("urlInput");
  var urlPanel = document.getElementById("urlResultPanel");

  document.querySelectorAll("[data-url]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      if (!urlInput) return;
      urlInput.value = btn.getAttribute("data-url") || "";
      urlInput.focus();
    });
  });

  var clearUrlBtn = document.getElementById("clearUrlBtn");
  if (clearUrlBtn && urlInput) {
    clearUrlBtn.addEventListener("click", function () {
      urlInput.value = "";
      if (urlPanel) {
        urlPanel.innerHTML =
          '<div class="empty-state"><p class="empty-ico">&#8599;</p><p>Cleared.</p></div>';
      }
      urlInput.focus();
    });
  }

  if (urlForm && urlInput && urlPanel) {
    urlForm.addEventListener("submit", function (event) {
      event.preventDefault();
      var value = urlInput.value.trim();
      urlPanel.innerHTML = '<div class="empty-state"><p class="muted">Inspecting the URL text…</p></div>';

      window.PhishLab.postJSON("/api/url", { url: value }).then(function (res) {
        if (res.ok && res.data.html) {
          urlPanel.innerHTML = res.data.html;
        } else {
          var msg = (res.data && res.data.error) || "URL analysis failed.";
          urlPanel.innerHTML = '<div class="flash flash-error" role="alert">' +
            escapeHtml(msg) + "</div>";
        }
        urlPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
      });
    });
  }

  function escapeHtml(text) {
    return String(text).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
})();
