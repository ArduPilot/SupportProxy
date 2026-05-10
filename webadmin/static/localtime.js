/*
  Rewrite every <time datetime="..."> on the page so its visible text
  shows the timestamp in the *viewer's* timezone, not the server's.

  The server emits ISO 8601 UTC in the datetime attribute and a UTC
  fallback string as the element's textContent — viewers without JS
  see the UTC time; viewers with JS see their local time.
 */
(function () {
    'use strict';

    function pad(n) {
        return n < 10 ? '0' + n : '' + n;
    }

    // Match the server's "YYYY-MM-DD HH:MM:SS" so the rewritten text
    // has the same width as the no-JS fallback. Without that, full-page
    // refreshes flash a reflowed column when JS replaces the UTC text
    // with toLocaleString output of a different length.
    function fmt(d) {
        return d.getFullYear() + '-' +
               pad(d.getMonth() + 1) + '-' +
               pad(d.getDate()) + ' ' +
               pad(d.getHours()) + ':' +
               pad(d.getMinutes()) + ':' +
               pad(d.getSeconds());
    }

    function rewrite() {
        var nodes = document.querySelectorAll('time[datetime]');
        for (var i = 0; i < nodes.length; i++) {
            var t = nodes[i];
            if (t.dataset.localtimeApplied) {
                continue;
            }
            var d = new Date(t.getAttribute('datetime'));
            if (isNaN(d.getTime())) {
                continue;
            }
            t.dataset.localtimeApplied = '1';
            t.textContent = fmt(d);
            // The datetime attr already carries UTC; expose it in the
            // tooltip so hovering over a row tells the viewer where
            // the time came from.
            if (!t.title) {
                t.title = t.getAttribute('datetime') + ' (UTC)';
            }
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', rewrite);
    } else {
        rewrite();
    }
})();
