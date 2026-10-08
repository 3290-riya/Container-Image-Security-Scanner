/**
 * Container Image Security Scanner — Frontend JS
 * Handles: drag-drop upload, severity checkboxes, form submission,
 *          collapsible sections, score ring animation, demo scan button.
 */

(function () {
  "use strict";

  /* ── File input / drag-drop ── */
  var dropZone  = document.getElementById("dropZone");
  var fileInput = document.getElementById("fileInput");
  var fileLabel = document.getElementById("fileSelected");

  function showFilename(name) {
    if (fileLabel) {
      fileLabel.textContent = name ? "Selected: " + name : "";
    }
  }

  if (dropZone && fileInput) {
    // Click anywhere in the drop-zone opens the file picker
    dropZone.addEventListener("click", function (e) {
      var cl = e.target.classList;
      if (
        e.target === dropZone ||
        cl.contains("upload-icon") ||
        cl.contains("upload-text") ||
        cl.contains("upload-subtext")
      ) {
        fileInput.click();
      }
    });

    fileInput.addEventListener("change", function () {
      if (fileInput.files && fileInput.files.length > 0) {
        showFilename(fileInput.files[0].name);
      }
    });

    // Drag-and-drop events
    ["dragenter", "dragover"].forEach(function (evt) {
      dropZone.addEventListener(evt, function (e) {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.add("drag-over");
      });
    });
    ["dragleave", "drop"].forEach(function (evt) {
      dropZone.addEventListener(evt, function (e) {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.remove("drag-over");
      });
    });
    dropZone.addEventListener("drop", function (e) {
      var dt = e.dataTransfer;
      if (dt && dt.files && dt.files.length > 0) {
        fileInput.files = dt.files;
        showFilename(dt.files[0].name);
      }
    });
  }

  /* ── Assemble hidden inputs from checkboxes ── */
  function assembleSeverities() {
    var cbs  = document.querySelectorAll(".sev-cb:checked");
    var vals = Array.from(cbs).map(function (cb) { return cb.value; });
    var inp  = document.getElementById("severitiesInput");
    if (inp) inp.value = vals.join(",") || "CRITICAL,HIGH,MEDIUM,LOW";
  }

  function assembleFailOn() {
    var cbs  = document.querySelectorAll(".fail-cb:checked");
    var vals = Array.from(cbs).map(function (cb) { return cb.value; });
    var inp  = document.getElementById("failOnInput");
    if (inp) inp.value = vals.join(",") || "CRITICAL";
  }

  function assembleFormat() {
    var radios = document.querySelectorAll("[name='report_format_radio']");
    var val = "all";
    radios.forEach(function (r) { if (r.checked) val = r.value; });
    var inp = document.getElementById("reportFormatInput");
    if (inp) inp.value = val;
  }

  document.querySelectorAll(".sev-cb").forEach(function (cb) {
    cb.addEventListener("change", assembleSeverities);
  });
  document.querySelectorAll(".fail-cb").forEach(function (cb) {
    cb.addEventListener("change", assembleFailOn);
  });
  document.querySelectorAll("[name='report_format_radio']").forEach(function (r) {
    r.addEventListener("change", assembleFormat);
  });

  /* ── Form submission guard ── */
  var scanForm  = document.getElementById("scanForm");
  var submitBtn = document.getElementById("submitBtn");

  if (scanForm) {
    scanForm.addEventListener("submit", function (e) {
      // Assemble all hidden values right before submit
      assembleSeverities();
      assembleFailOn();
      assembleFormat();

      // Validate a file is chosen
      if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
        e.preventDefault();
        alert("Please select a file to scan.");
        return;
      }

      // Disable button to prevent double-submit
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = "Submitting…";
      }
    });
  }

  /* ── Demo scan button ── */
  var demoForm = document.getElementById("demoForm");
  var demoBtn  = document.getElementById("demoBtn");

  if (demoForm && demoBtn) {
    demoForm.addEventListener("submit", function () {
      demoBtn.disabled = true;
      demoBtn.textContent = "Starting demo scan…";
    });
  }

  /* ── Collapsible sections ── */
  document.querySelectorAll(".section-header[data-target]").forEach(function (header) {
    header.addEventListener("click", function () {
      var targetId = header.getAttribute("data-target");
      var target   = document.getElementById(targetId);
      var toggle   = header.querySelector(".section-toggle");
      if (!target) return;
      var hidden = target.style.display === "none";
      target.style.display = hidden ? "" : "none";
      if (toggle) toggle.classList.toggle("collapsed", !hidden);
    });
  });

  /* ── Score ring animation ── */
  var ring = document.getElementById("scoreRingFill");
  if (ring) {
    var score  = parseFloat(ring.getAttribute("data-score") || "0");
    var r      = parseFloat(ring.getAttribute("r") || "54");
    var circ   = 2 * Math.PI * r;
    var offset = circ - (score / 100) * circ;
    ring.style.strokeDasharray  = circ;
    ring.style.strokeDashoffset = circ; // start at 0%
    // Animate after a short delay so the transition fires
    setTimeout(function () {
      ring.style.strokeDashoffset = offset;
    }, 100);
  }

})();
