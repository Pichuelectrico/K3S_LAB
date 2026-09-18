(function () {
  function selectCard(card) {
    var group = card.parentElement;
    if (!group || group.getAttribute("data-select") !== "single") return;
    group.querySelectorAll(".sel").forEach(function (el) { el.classList.remove("sel"); });
    card.classList.add("sel");
    updateSummary();
  }

  document.querySelectorAll(".type-card, .node-card").forEach(function (card) {
    card.addEventListener("click", function () { selectCard(card); });
    card.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        selectCard(card);
      }
    });
  });

  var stepper = document.getElementById("stepper");
  var panels = document.querySelectorAll(".wizard-panel");
  var step = 1;

  function showStep(n) {
    step = n;
    panels.forEach(function (p) {
      p.classList.toggle("on", Number(p.getAttribute("data-step")) === n);
    });
    if (stepper) {
      stepper.querySelectorAll(".step").forEach(function (s, i) {
        var idx = i + 1;
        s.classList.toggle("on", idx === n);
        s.classList.toggle("done", idx < n);
      });
    }
    updateSummary();
  }

  document.querySelectorAll("[data-next]").forEach(function (btn) {
    btn.addEventListener("click", function () { showStep(Math.min(3, step + 1)); });
  });
  document.querySelectorAll("[data-prev]").forEach(function (btn) {
    btn.addEventListener("click", function () { showStep(Math.max(1, step - 1)); });
  });

  var gpu = document.getElementById("opt-gpu");
  var gpuIndex = document.getElementById("opt-gpu-index");
  var home = document.getElementById("opt-home");

  function selectedValue(selector) {
    var el = document.querySelector(selector + ".sel");
    return el ? (el.getAttribute("data-value") || el.textContent.trim()) : "—";
  }

  function updateSummary() {
    var t = document.getElementById("sum-type");
    var n = document.getElementById("sum-node");
    var g = document.getElementById("sum-gpu");
    var h = document.getElementById("sum-home");
    if (!t) return;
    t.textContent = selectedValue(".type-card");
    n.textContent = selectedValue(".node-card");
    if (gpuIndex) gpuIndex.disabled = !(gpu && gpu.checked);
    if (g) g.textContent = gpu && gpu.checked ? gpuIndex.value : "No";
    if (h) h.textContent = home && home.checked ? "Montado" : "Efímero";
  }

  if (gpu) gpu.addEventListener("change", updateSummary);
  if (gpuIndex) gpuIndex.addEventListener("change", updateSummary);
  if (home) home.addEventListener("change", updateSummary);
  updateSummary();

  var search = document.getElementById("env-search");
  var table = document.getElementById("env-table");
  var filters = document.getElementById("status-filters");
  var status = "all";

  function filterRows() {
    if (!table) return;
    var q = (search && search.value || "").toLowerCase().trim();
    table.querySelectorAll("tbody tr").forEach(function (row) {
      var st = row.getAttribute("data-status") || "";
      var text = row.textContent.toLowerCase();
      var okStatus = status === "all" || st === status;
      var okText = !q || text.indexOf(q) !== -1;
      row.classList.toggle("row-hidden", !(okStatus && okText));
    });
  }

  if (search) search.addEventListener("input", filterRows);
  if (filters) {
    filters.querySelectorAll(".chip").forEach(function (chip) {
      chip.addEventListener("click", function () {
        filters.querySelectorAll(".chip").forEach(function (c) { c.classList.remove("on"); });
        chip.classList.add("on");
        status = chip.getAttribute("data-status") || "all";
        filterRows();
      });
    });
  }
})();
