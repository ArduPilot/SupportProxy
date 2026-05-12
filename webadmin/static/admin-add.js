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
        var count = document.getElementById('count');
        if (!port1 || !port2 || port1.dataset.suggestAttached) {
            return;
        }
        port1.dataset.suggestAttached = '1';

        function syncPort2FromPort1() {
            var v = parseInt(port1.value, 10);
            if (isNaN(v)) {
                return;
            }
            // Only fill port2 if it's empty OR was previously
            // auto-filled by us. Once the admin types into port2
            // manually their choice sticks (until count>1 takes over).
            if (port2.value === '' || port2.dataset.autofilled === '1') {
                port2.value = String(v + 1000);
                port2.dataset.autofilled = '1';
            }
        }
        port1.addEventListener('input', syncPort2FromPort1);
        port2.addEventListener('input', function () {
            port2.dataset.autofilled = '';
        });

        // When count > 1 the explicit port2 field is ignored by the
        // server (port2 is derived as port1+1000 per entry). Signal
        // that by making port2 readonly and pinning it to the base
        // port2 (port1+1000). readonly — not disabled — so the field
        // is still submitted and the DataRequired validator passes.
        if (count) {
            function syncCountState() {
                var c = parseInt(count.value, 10);
                var v = parseInt(port1.value, 10);
                if (!isNaN(c) && c > 1) {
                    port2.readOnly = true;
                    port2.dataset.autofilled = '1';
                    if (!isNaN(v)) {
                        port2.value = String(v + 1000);
                    }
                } else if (port2.readOnly) {
                    port2.readOnly = false;
                    syncPort2FromPort1();
                }
            }
            count.addEventListener('input', syncCountState);
            port1.addEventListener('input', syncCountState);
            syncCountState();
        }
    }

    function attachPartnerTextCopy() {
        var box = document.querySelector('.partner-text-box');
        var btn = document.querySelector('.copy-partner-text');
        if (!box || !btn || btn.dataset.copyAttached) {
            return;
        }
        btn.dataset.copyAttached = '1';
        btn.addEventListener('click', function () {
            box.focus();
            box.select();
            var ok = false;
            try {
                ok = document.execCommand('copy');
            } catch (e) {
                ok = false;
            }
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(box.value).then(function () {
                    btn.textContent = 'Copied';
                }, function () { /* keep whatever execCommand did */ });
            }
            if (ok) {
                btn.textContent = 'Copied';
            }
            setTimeout(function () { btn.textContent = 'Copy to clipboard'; },
                       2000);
        });
    }

    function makeGenerateButton(label, onClick) {
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.textContent = 'Generate';
        btn.className = 'generate-passphrase';
        btn.setAttribute('aria-label', label);
        btn.addEventListener('click', onClick);
        return btn;
    }

    // Add-form variant: single "passphrase" field. Scoped to the
    // admin "Add a new entry" form (admin_list.html), NOT the login
    // form — both fields are named "passphrase" so WTForms gives them
    // the same id, but a Generate button has no business on the login
    // page.
    function attachAddFormGenerator() {
        var form = document.querySelector('form.admin-add-form');
        if (!form) {
            return;
        }
        var pw = form.querySelector('#passphrase')
                 || form.querySelector('input[name="passphrase"]');
        if (!pw || pw.dataset.generatorAttached) {
            return;
        }
        pw.dataset.generatorAttached = '1';

        var btn = makeGenerateButton(
            'Generate a random 12-character passphrase',
            function () {
                pw.value = generatePassphrase(PASSPHRASE_LEN);
                // Flip to text so the admin can read + copy it.
                // The password-toggle eye widget still lets them
                // switch back to dots.
                pw.type = 'text';
                pw.focus();
                pw.select();
            });

        // password-toggle.js (loaded before us) wraps the input in
        // <span class="password-wrap">. Place Generate inside the
        // same .field div so it sits alongside the eye button.
        var field = pw.closest('.field') || pw.parentNode;
        field.appendChild(btn);
    }

    // Edit-form variant: dual "new_passphrase" + "confirm_passphrase"
    // fields. Used on the admin and owner edit pages. The button
    // fills BOTH so the EqualTo validator passes immediately and the
    // admin/owner can save without retyping. We avoid the existing
    // KeyEntry's hashed-only design by NOT trying to show the
    // current passphrase (we don't have it) — clicking Generate
    // rotates the passphrase instead.
    function attachEditFormGenerator() {
        var newpw = document.getElementById('new_passphrase');
        var confirm = document.getElementById('confirm_passphrase');
        if (!newpw || !confirm || newpw.dataset.generatorAttached) {
            return;
        }
        newpw.dataset.generatorAttached = '1';

        var btn = makeGenerateButton(
            'Generate a new random 12-character passphrase',
            function () {
                var v = generatePassphrase(PASSPHRASE_LEN);
                newpw.value = v;
                confirm.value = v;
                // Reveal both so the admin can verify + copy before
                // submitting. The password-toggle eye buttons still
                // let either be hidden again.
                newpw.type = 'text';
                confirm.type = 'text';
                newpw.focus();
                newpw.select();
            });

        var field = newpw.closest('.field') || newpw.parentNode;
        field.appendChild(btn);
    }

    function attach() {
        attachPortAutosuggest();
        attachAddFormGenerator();
        attachEditFormGenerator();
        attachPartnerTextCopy();
    }

    document.addEventListener('DOMContentLoaded', attach);
    document.addEventListener('pageupdate', attach);
}());
