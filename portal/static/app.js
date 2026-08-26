// No framework and no build step: the portal is a handful of pages, and a
// customer on a metered connection abroad should not pay for a bundle.
'use strict';

// Copy-to-clipboard for the tenant hostname.
//
// Customers type this into a phone settings field. Mistyping one character
// produces a service that silently does nothing, which is a support message.
document.querySelectorAll('.copy').forEach(function (btn) {
  btn.addEventListener('click', function () {
    var el = document.getElementById(btn.dataset.copy);
    if (!el) { return; }

    var text = el.textContent.trim();
    var confirm = function () {
      var original = btn.textContent;
      btn.textContent = btn.dataset.copied || 'Copied';
      setTimeout(function () { btn.textContent = original; }, 1500);
    };

    // The clipboard API needs a secure context. Selecting the text is the
    // fallback, so the customer can copy it by hand rather than retyping.
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(confirm).catch(function () { selectText(el); });
    } else {
      selectText(el);
    }
  });
});

function selectText(el) {
  var range = document.createRange();
  range.selectNodeContents(el);
  var sel = window.getSelection();
  sel.removeAllRanges();
  sel.addRange(range);
}

// The DNS check.
//
// The page asks for a hostname nobody has ever looked up. Resolving it is the
// entire test: the request that follows is expected to fail, and its failure
// says nothing either way. What matters is whether the DNS query reached our
// resolver, which the resolver reports back.
var runBtn = document.getElementById('run-check');

if (runBtn) {
  runBtn.addEventListener('click', function () {
    var result = document.getElementById('check-result');
    var fixes = document.getElementById('check-fixes');
    var list = document.getElementById('fix-list');

    runBtn.disabled = true;
    var label = runBtn.textContent;
    runBtn.textContent = runBtn.dataset.checking || 'Checking...';
    result.hidden = true;
    fixes.hidden = true;

    fetch('/check/start')
      .then(function (r) { return r.json(); })
      .then(function (start) {
        // no-cors means we cannot read the outcome, and nothing is listening
        // on that name in any case. Triggering the lookup is the point.
        return fetch('https://' + start.probe_host + '/', {
          mode: 'no-cors',
          cache: 'no-store'
        })
          .catch(function () { /* expected */ })
          .then(function () {
            // Give the query a moment to arrive and be recorded.
            return new Promise(function (resolve) { setTimeout(resolve, 900); });
          })
          .then(function () {
            return fetch('/check/result/' + start.nonce);
          });
      })
      .then(function (r) { return r.json(); })
      .then(function (res) {
        result.hidden = false;
        result.className = 'flash ' + (res.found ? 'ok' : 'error');
        result.textContent = res.message || '';

        if (res.found && res.protocol) {
          var detail = document.createElement('div');
          detail.className = 'muted';
          detail.textContent = res.protocol;
          result.appendChild(detail);
        }

        if (!res.found && res.fixes && res.fixes.length) {
          list.innerHTML = '';
          res.fixes.forEach(function (f) {
            var li = document.createElement('li');
            // textContent, never innerHTML: these strings come from the server
            // and there is no reason to let them carry markup.
            li.textContent = f;
            list.appendChild(li);
          });
          fixes.hidden = false;
        }
      })
      .catch(function () {
        result.hidden = false;
        result.className = 'flash error';
        result.textContent = 'Check failed. Please try again.';
      })
      .finally(function () {
        runBtn.disabled = false;
        runBtn.textContent = label;
      });
  });
}

if ('serviceWorker' in navigator) {
  window.addEventListener('load', function () {
    navigator.serviceWorker.register('/sw.js').catch(function () { /* optional */ });
  });
}
