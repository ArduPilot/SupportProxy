/*
  Auto-attach a show/hide eye button to every <input type="password"> on
  the page. Idempotent: re-running (e.g. after a partial DOM update)
  skips inputs already wrapped.

  No deps: written so it works without a build step.
 */
(function () {
    'use strict';

    var EYE_OPEN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
    var EYE_SHUT = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';

    function attach(input) {
        if (input.dataset.toggleAttached) {
            return;
        }
        input.dataset.toggleAttached = '1';

        var wrap = document.createElement('span');
        wrap.className = 'password-wrap';
        input.parentNode.insertBefore(wrap, input);
        wrap.appendChild(input);

        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'toggle';
        // The eye is a convenience — keep it out of the tab order so
        // tabbing through forms doesn't land on it.
        btn.tabIndex = -1;
        btn.setAttribute('aria-label', 'Show passphrase');
        btn.innerHTML = EYE_OPEN;
        btn.addEventListener('click', function () {
            var revealing = input.type === 'password';
            input.type = revealing ? 'text' : 'password';
            btn.setAttribute(
                'aria-label', revealing ? 'Hide passphrase' : 'Show passphrase');
            btn.innerHTML = revealing ? EYE_SHUT : EYE_OPEN;
        });
        wrap.appendChild(btn);
    }

    function init() {
        var inputs = document.querySelectorAll('input[type=password]');
        for (var i = 0; i < inputs.length; i++) {
            attach(inputs[i]);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
    // Re-scan after auto-refresh.js swaps <main> in-place so any
    // newly-injected password fields get the eye too.
    document.addEventListener('pageupdate', init);
})();
