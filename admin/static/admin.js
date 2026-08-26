'use strict';

// Confirmation on destructive submits. Suspending a tenant stops a paying
// customer's DNS within a second, and revoking a token breaks whatever uses
// it — neither should be one stray click away.
document.querySelectorAll('form[data-confirm]').forEach(function (form) {
  form.addEventListener('submit', function (e) {
    if (!window.confirm(form.dataset.confirm)) {
      e.preventDefault();
    }
  });
});

// Copy the freshly minted API token. It is shown exactly once, so a failed
// copy means creating another.
document.querySelectorAll('.copy').forEach(function (btn) {
  btn.addEventListener('click', function () {
    var el = document.getElementById(btn.dataset.copy);
    if (!el) { return; }

    var confirmCopy = function () {
      var original = btn.textContent;
      btn.textContent = 'Copied';
      setTimeout(function () { btn.textContent = original; }, 1500);
    };

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(el.textContent.trim()).then(confirmCopy).catch(select);
    } else {
      select();
    }

    function select() {
      var range = document.createRange();
      range.selectNodeContents(el);
      var sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    }
  });
});
