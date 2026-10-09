// MalDet — shared front-end behavior

// Scroll reveal. Content is only hidden once this runs, so without JS (or
// with reduced motion, handled in CSS) every section is simply visible.
(function () {
  if (!('IntersectionObserver' in window)) { return; }
  document.documentElement.classList.add('js-reveal');
  document.addEventListener('DOMContentLoaded', function () {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          io.unobserve(entry.target);
        }
      });
    }, { rootMargin: '0px 0px -8% 0px', threshold: 0.08 });
    document.querySelectorAll('.reveal').forEach(function (el) { io.observe(el); });
  });
})();

document.addEventListener('DOMContentLoaded', function () {
  var scanForm = document.getElementById('scanForm');
  var scanSubmitBtn = document.getElementById('scanSubmitBtn');

  if (scanForm && scanSubmitBtn) {
    scanForm.addEventListener('submit', function () {
      scanSubmitBtn.disabled = true;
      scanSubmitBtn.innerHTML =
        '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Queuing scan…';
    });
  }

  var rescanBtn = document.getElementById('rescanBtn');
  if (rescanBtn) {
    rescanBtn.addEventListener('click', function () {
      rescanBtn.classList.add('disabled');
      rescanBtn.setAttribute('aria-disabled', 'true');
      rescanBtn.innerHTML =
        '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Rescanning…';
    });
  }

  var registerSearch = document.getElementById('registerSearch');
  var registerTable = document.getElementById('registerTable');
  if (registerSearch && registerTable) {
    var noMatchesRow = document.getElementById('registerNoMatches');
    var countLabel = document.getElementById('registerCount');
    var rows = Array.prototype.filter.call(
      registerTable.querySelectorAll('tbody tr'),
      function (row) { return row !== noMatchesRow; }
    );

    registerSearch.addEventListener('input', function () {
      var q = registerSearch.value.trim().toLowerCase();
      var visible = 0;
      rows.forEach(function (row) {
        var match = row.textContent.toLowerCase().indexOf(q) !== -1;
        row.style.display = match ? '' : 'none';
        if (match) visible++;
      });
      if (noMatchesRow) noMatchesRow.style.display = visible === 0 ? '' : 'none';
      if (countLabel) {
        countLabel.textContent = q
          ? 'Showing ' + visible + ' of ' + rows.length + ' repositories'
          : 'All repositories (' + rows.length + ')';
      }
    });
  }

  var toolFilterChips = document.querySelectorAll('.tool-filter-chip');
  toolFilterChips.forEach(function (chip) {
    chip.addEventListener('click', function () {
      var nowPressed = chip.getAttribute('aria-pressed') !== 'true';
      chip.setAttribute('aria-pressed', String(nowPressed));
      var tool = chip.getAttribute('data-tool');
      var section = document.querySelector('.tool-section[data-tool="' + tool + '"]');
      if (section) section.style.display = nowPressed ? '' : 'none';
    });
  });

  var hideNoiseToggle = document.getElementById('hideNoiseToggle');
  var findingsSections = document.getElementById('findingsSections');
  if (hideNoiseToggle && findingsSections) {
    hideNoiseToggle.addEventListener('click', function () {
      var active = hideNoiseToggle.getAttribute('aria-pressed') === 'true';
      hideNoiseToggle.setAttribute('aria-pressed', String(!active));
      findingsSections.classList.toggle('hide-noise', !active);
      hideNoiseToggle.textContent = active ? 'Hide likely noise' : 'Show likely noise';
    });
  }
});
