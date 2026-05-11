/*
  Two small affordances on the admin "Add a new entry" form:

  1. port2 auto-suggest. When the admin types port1, port2 is
     pre-filled with port1+1000 (the SupportProxy convention). The
     auto-fill stops the moment the admin types into port2 manually,
     so an explicit choice is never clobbered.

  2. "Generate" button next to the passphrase input. Produces 12
     characters from [A-Za-z0-9] via crypto.getRandomValues() and
     flips the input to type=text so the admin can copy + share the
     value out-of-band. The existing password-toggle eye widget
     re-attached on pageupdate still lets them switch back to dots.

  Loaded from base.html with `defer`, so it's a no-op on pages
  without the form (everything is gated on getElementById hits).
 */
(function () {
    'use strict';

    var PASSPHRASE_LEN = 12;
    var PASSPHRASE_CHARS =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    function generatePassphrase(len) {
        var out = new Array(len);
        var arr = new Uint32Array(len);
        window.crypto.getRandomValues(arr);
        for (var i = 0; i < len; i++) {
            out[i] = PASSPHRASE_CHARS.charAt(arr[i] % PASSPHRASE_CHARS.length);
        }
        return out.join('');
    }

    function attachPortAutosuggest() {
        var port1 = document.getElementById('port1');
        var port2 = document.getElementById('port2');
        if (!port1 || !port2 || port1.dataset.suggestAttached) {
            return;
        }
        port1.dataset.suggestAttached = '1';
        port1.addEventListener('input', function () {
            var v = parseInt(port1.value, 10);
            if (isNaN(v)) {
                return;
            }
            // Only fill port2 if it's empty OR was previously
            // auto-filled by us. Once the admin types into port2
            // their choice sticks.
            if (port2.value === '' || port2.dataset.autofilled === '1') {
                port2.value = String(v + 1000);
                port2.dataset.autofilled = '1';
            }
        });
        port2.addEventListener('input', function () {
            // Admin took over — stop auto-suggesting.
            port2.dataset.autofilled = '';
        });
    }

    function attachPassphraseGenerator() {
        var pw = document.getElementById('passphrase');
        if (!pw || pw.dataset.generatorAttached) {
            return;
        }
        pw.dataset.generatorAttached = '1';

        var btn = document.createElement('button');
        btn.type = 'button';
        btn.textContent = 'Generate';
        btn.className = 'generate-passphrase';
        btn.setAttribute('aria-label',
                         'Generate a random 12-character passphrase');
        btn.addEventListener('click', function () {
            pw.value = generatePassphrase(PASSPHRASE_LEN);
            // Flip to text so the admin can read + copy it. The
            // password-toggle eye widget still lets them switch back.
            pw.type = 'text';
            pw.focus();
            pw.select();
        });

        // password-toggle.js (loaded before us) wraps the input in a
        // <span class="password-wrap">. Place the Generate button
        // next to that wrap, inside the same .field div, so it sits
        // alongside the eye button.
        var field = pw.closest('.field') || pw.parentNode;
        field.appendChild(btn);
    }

    function attach() {
        attachPortAutosuggest();
        attachPassphraseGenerator();
    }

    document.addEventListener('DOMContentLoaded', attach);
    document.addEventListener('pageupdate', attach);
}());
