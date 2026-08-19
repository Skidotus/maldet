// MalDet — shared front-end behavior

document.addEventListener('DOMContentLoaded', function () {
  var scanForm = document.getElementById('scanForm');
  var scanSubmitBtn = document.getElementById('scanSubmitBtn');

  if (scanForm && scanSubmitBtn) {
    scanForm.addEventListener('submit', function () {
      scanSubmitBtn.disabled = true;
      scanSubmitBtn.innerHTML =
        '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Scanning…';
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
          ? 'Showing ' + visible + ' of ' + rows.length + ' entries'
          : 'All Entries (' + rows.length + ')';
      }
    });
  }
});
