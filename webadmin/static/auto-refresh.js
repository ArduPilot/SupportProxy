/*
  In-place auto-refresh of the page's <main> content. Used by the
  live-connection and log list views; replaces the old
  <meta http-equiv="refresh"> approach so the page never blanks
  between paints (Firefox doesn't paint-hold across full-page
  navigations, so meta-refresh visibly flashes the header/logo
  even when every asset is cached).

  Activation: <body data-auto-refresh="N"> sets the cadence in
  seconds. Empty / 0 / non-numeric disables it.

  The swap is SKIPPED while any <form> in <main> is "dirty" (a
  control's current state differs from the value the server sent),
  so an in-progress edit on a page that also auto-refreshes — e.g.
  the owner /me page, which has both an edit form and a live
  connections table — isn't clobbered before the user can submit.
  Once the form is saved (full page reload) or reset, refreshing
  resumes.

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

    // True if any form control under <main> has been changed from the
    // value/checked/selected state the server rendered. Compares
    // against the DOM's default* properties, which reflect the
    // original HTML attributes.
    function mainFormDirty() {
        var forms = document.querySelectorAll('main form');
        for (var f = 0; f < forms.length; f++) {
            var els = forms[f].elements;
            for (var i = 0; i < els.length; i++) {
                var el = els[i];
                var t = (el.type || '').toLowerCase();
                if (t === 'submit' || t === 'button' || t === 'reset'
                        || t === 'hidden' || t === 'file') {
                    continue;
                }
                if (t === 'checkbox' || t === 'radio') {
                    if (el.checked !== el.defaultChecked) {
                        return true;
                    }
                } else if (el.tagName === 'SELECT') {
                    for (var o = 0; o < el.options.length; o++) {
                        if (el.options[o].selected
                                !== el.options[o].defaultSelected) {
                            return true;
                        }
                    }
                } else if (typeof el.value === 'string'
                           && typeof el.defaultValue === 'string') {
                    if (el.value !== el.defaultValue) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    async function tick() {
        if (inFlight) {
            return;
        }
        if (document.hidden) {
            // Don't waste cycles when the tab isn't visible.
            return;
        }
        if (mainFormDirty()) {
            // The user is mid-edit — don't overwrite their work. We'll
            // try again on the next tick; once they submit or reset,
            // the form is no longer dirty and refreshing resumes.
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
