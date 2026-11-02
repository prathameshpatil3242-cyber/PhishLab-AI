/* =====================================================================
   dashboard.js — Chart.js widgets + the "train model" button
   Reads window.PHISHLAB_STATS (injected by templates/dashboard.html).
   ===================================================================== */
(function () {
  "use strict";

  var stats = window.PHISHLAB_STATS || {};
  var hasChart = typeof window.Chart !== "undefined";

  var COLORS = {
    violet: "#7c5cff",
    violetSoft: "rgba(124,92,255,.55)",
    lime: "#b8ff3d",
    limeSoft: "rgba(184,255,61,.55)",
    warn: "#ffb020",
    danger: "#ff5d73",
    ok: "#3ddc97",
    grid: "rgba(154,160,199,.14)",
    text: "#9aa0c7"
  };

  Chart.defaults.color = COLORS.text;
  Chart.defaults.borderColor = COLORS.grid;
  Chart.defaults.font.family = '"Segoe UI", Roboto, Arial, sans-serif';

  function fade(ctx, color) {
    var gradient = ctx.createLinearGradient(0, 0, 0, 260);
    gradient.addColorStop(0, color);
    gradient.addColorStop(1, "rgba(0,0,0,0)");
    return gradient;
  }

  /* ---------------- 1. Common warning signs (bar) ---------------- */
  var indicatorCanvas = document.getElementById("indicatorChart");
  if (indicatorCanvas && hasChart) {
    var indicators = stats.common_indicators || [];
    if (!indicators.length) {
      indicatorCanvas.replaceWith(emptyBox("No indicators recorded yet."));
    } else {
      var ctxI = indicatorCanvas.getContext("2d");
      new Chart(indicatorCanvas, {
        type: "bar",
        data: {
          labels: indicators.map(function (i) { return i.name; }),
          datasets: [{
            label: "Occurrences",
            data: indicators.map(function (i) { return i.count; }),
            backgroundColor: fade(ctxI, "rgba(124,92,255,.85)"),
            borderColor: COLORS.violet,
            borderWidth: 1,
            borderRadius: 7
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: "y",
          plugins: { legend: { display: false } },
          scales: {
            x: { beginAtZero: true, ticks: { precision: 0 } },
            y: { ticks: { font: { size: 11 } } }
          }
        }
      });
    }
  }

  /* ---------------- 2. Training exercise outcomes ---------------- */
  var outcomeCanvas = document.getElementById("outcomeChart");
  if (outcomeCanvas && hasChart) {
    var correct = stats.quiz_correct_total || 0;
    var answered = stats.quiz_answered_total || 0;
    var incorrect = stats.quiz_incorrect_total || 0;

    if (!answered) {
      outcomeCanvas.replaceWith(emptyBox("No quiz answers yet — take the quiz first."));
    } else {
      new Chart(outcomeCanvas, {
        type: "doughnut",
        data: {
          labels: ["Correct answers", "Incorrect answers"],
          datasets: [{
            data: [correct, incorrect],
            backgroundColor: [COLORS.lime, COLORS.danger],
            borderColor: "#11142b",
            borderWidth: 3,
            hoverOffset: 6
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: "62%",
          plugins: {
            legend: { position: "bottom", labels: { boxWidth: 12, padding: 14 } },
            tooltip: {
              callbacks: {
                label: function (c) {
                  var pct = Math.round(100 * c.parsed / (correct + incorrect));
                  return " " + c.label + ": " + c.parsed + " (" + pct + "%)";
                }
              }
            }
          }
        }
      });
    }
  }

  /* ---------------- 3. Classification distribution ---------------- */
  var classCanvas = document.getElementById("classChart");
  if (classCanvas && hasChart) {
    var counts = stats.classification_counts || {};
    var keys = Object.keys(counts);
    if (!keys.length) {
      classCanvas.replaceWith(emptyBox("No analyses stored yet."));
    } else {
      new Chart(classCanvas, {
        type: "polarArea",
        data: {
          labels: keys,
          datasets: [{
            data: keys.map(function (k) { return counts[k]; }),
            backgroundColor: [
              "rgba(255,93,115,.65)", "rgba(255,176,32,.65)",
              "rgba(184,255,61,.65)", "rgba(124,92,255,.65)",
              "rgba(61,220,151,.65)"
            ],
            borderColor: "#11142b",
            borderWidth: 2
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: "bottom", labels: { boxWidth: 12, padding: 10 } } },
          scales: { r: { grid: { color: COLORS.grid }, ticks: { backdropColor: "transparent" } } }
        }
      });
    }
  }

  function emptyBox(text) {
    var div = document.createElement("div");
    div.className = "empty-state";
    div.innerHTML = '<p class="muted small">' + text + "</p>";
    return div;
  }

  /* ---------------- train model button ---------------- */
  var trainBtn = document.getElementById("trainBtn");
  var trainStatus = document.getElementById("trainStatus");
  if (trainBtn) {
    trainBtn.addEventListener("click", function () {
      trainBtn.disabled = true;
      trainBtn.textContent = "Training…";
      if (trainStatus) trainStatus.textContent = "Training the TF-IDF + Naive Bayes model…";

      window.PhishLab.postJSON("/api/train", {}).then(function (res) {
        if (res.ok && res.data.metrics) {
          var m = res.data.metrics;
          if (trainStatus) {
            trainStatus.textContent =
              "Trained on " + m.train_samples + " samples, tested on " + m.test_samples +
              " held-out samples — accuracy " + (m.accuracy * 100).toFixed(1) +
              "%, F1 " + (m.f1_weighted * 100).toFixed(1) + "%. Reloading…";
          }
          window.setTimeout(function () { window.location.reload(); }, 1400);
        } else {
          trainBtn.disabled = false;
          trainBtn.textContent = "Train model now";
          if (trainStatus) {
            trainStatus.textContent = (res.data && res.data.error) || "Training failed.";
          }
        }
      });
    });
  }
})();
