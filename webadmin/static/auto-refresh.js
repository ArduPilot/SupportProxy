/*
  In-place auto-refresh of the page's <main> content. Used by the
  live-connection and log list views; replaces the old
  <meta http-equiv="refresh"> approach so the page never blanks
  between paints (Firefox doesn't paint-hold across full-page
  navigations, so meta-refresh visibly flashes the header/logo
  even when every asset is cached).

  Activation: <body data-auto-refresh="N"> sets the cadence in
  seconds. Empty / 0 / non-numeric disables it.

  Helper scripts that need to re-process freshly-injected content
  (localtime.js, password-toggle.js) listen for the 'pageupdate'
  event we dispatch after each successful swap.
 */
(function () {
    'use strict';

    var seconds = parseInt(document.body && document.body.dataset.autoRefresh, 10);
    if (!isFinite(seconds) || seconds <= 0) {
        return;
    }

    var inFlight = false;

    async function tick() {
        if (inFlight) {
            return;
        }
        if (document.hidden) {
            // Don't waste cycles when the tab isn't visible.
            return;
        }
        inFlight = true;
        try {
            var r = await fetch(location.href, {
                credentials: 'same-origin',
                redirect: 'manual',
                headers: { 'X-Auto-Refresh': '1' },
            });
            if (!r.ok) {
                return;
            }
            var html = await r.text();
            var doc = new DOMParser().parseFromString(html, 'text/html');
            var newMain = doc.querySelector('main');
            var oldMain = document.querySelector('main');
            if (!newMain || !oldMain) {
                return;
            }
            oldMain.replaceWith(newMain);
            document.dispatchEvent(new CustomEvent('pageupdate'));
        } catch (e) {
            // network blip — try again next tick
        } finally {
            inFlight = false;
        }
    }

    setInterval(tick, seconds * 1000);
})();
