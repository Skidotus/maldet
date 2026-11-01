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

// Verdict resolve — the one authored entrance on the site.
//
// The scale lays itself out left to right, the verdict lands on its step,
// and the scores count up to meet it. It marks the thing this product
// exists to produce, which is why it appears on the hero card and on the
// detail page's verdict panels and nowhere else.
//
// Runs once per element, on first sight. Numbers are already correct in the
// markup, so a failed script or a reduced-motion preference leaves a card
// that is right and still rather than a card full of zeroes.
(function () {
  var targets = document.querySelectorAll('[data-resolve]');
  if (!targets.length) { return; }

  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function countUp(el, to, duration) {
    var start = null;
    function frame(now) {
      if (start === null) { start = now; }
      var t = Math.min((now - start) / duration, 1);
      // Exponential ease-out: most of the distance is covered early, so the
      // number settles rather than crawling to its value.
      var eased = t === 1 ? 1 : 1 - Math.pow(2, -10 * t);
      el.textContent = Math.round(to * eased);
      if (t < 1) { window.requestAnimationFrame(frame); }
      else { el.textContent = to; }
    }
    window.requestAnimationFrame(frame);
  }

  function resolve(el) {
    el.classList.add('is-resolved');
    if (reduce) { return; }

    var nums = el.querySelectorAll('[data-score]');
    for (var i = 0; i < nums.length; i++) {
      var target = parseInt(nums[i].getAttribute('data-score'), 10);
      // A zero needs no count, and a non-number should keep whatever the
      // server rendered.
      if (!isFinite(target) || target === 0) { continue; }
      nums[i].textContent = '0';
      countUp(nums[i], target, 900);
    }
  }

  if (reduce || !('IntersectionObserver' in window) || !window.requestAnimationFrame) {
    for (var i = 0; i < targets.length; i++) { targets[i].classList.add('is-resolved'); }
    return;
  }

  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (!entry.isIntersecting) { return; }
      io.unobserve(entry.target);
      resolve(entry.target);
    });
  }, { threshold: 0.4 });

  for (var j = 0; j < targets.length; j++) { io.observe(targets[j]); }
})();
