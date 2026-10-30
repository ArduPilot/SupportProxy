/*
  "Create & copy link" on the live video page: asks the server for a
  signed, expiring public viewing URL for one slot, shows it, and puts it
  on the clipboard.
 */
(function () {
  'use strict';

  function legacyCopy() {
    try { return document.execCommand('copy'); } catch (e) { return false; }
  }

  /*
    Put the link on the clipboard, resolving true if it got there.

    The link only exists once the server has answered, but browsers
    allow a clipboard write only during the click that asked for it, and
    Safari is strict about it. So the write is started here, inside the
    click, with a ClipboardItem holding a promise for the text: the
    browser keeps the permission while the promise settles. Browsers
    without ClipboardItem write the text once it is known instead.
   */
  function copyLater(urlPromise) {
    var cb = navigator.clipboard;
    if (cb && cb.write && window.ClipboardItem) {
      var blob = urlPromise.then(function (u) {
        return new Blob([u], { type: 'text/plain' });
      });
      // The caller handles a failed request; this only needs not to throw.
      blob.catch(function () {});
      try {
        return cb.write([new ClipboardItem({ 'text/plain': blob })]).then(
          function () { return true; },
          function () { return false; });
      } catch (e) { /* fall through to the plain write */ }
    }
    return urlPromise.then(function (u) {
      if (cb && cb.writeText) {
        return cb.writeText(u).then(function () { return true; },
                                    function () { return legacyCopy(); });
      }
      return legacyCopy();
    }, function () { return false; });
  }

  var boxes = document.querySelectorAll('.video-share');
  Array.prototype.forEach.call(boxes, function (box) {
    var create = box.querySelector('.share-create');
    var hours = box.querySelector('.share-hours');
    var result = box.querySelector('.share-result');
    var input = box.querySelector('.share-url');
    var note = box.querySelector('.share-note');
    var noteText = note.textContent;

    var busy = false;

    create.addEventListener('click', function () {
      // Not `disabled`: that would drop the button's focus, and the
      // clipboard refuses a page that is not focused.
      if (busy) { return; }
      busy = true;
      var body = new URLSearchParams();
      body.set('slot', box.getAttribute('data-slot'));
      body.set('hours', hours.value);
      var urlPromise = fetch(box.getAttribute('data-share-url'), {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'X-CSRFToken': box.getAttribute('data-csrf') },
        body: body
      })
        .then(function (r) {
          if (!r.ok) { throw new Error('HTTP ' + r.status); }
          return r.json();
        })
        .then(function (j) { return j.url; });

      var copied = copyLater(urlPromise);

      urlPromise.then(function (url) {
        input.value = url;
        result.hidden = false;
        input.focus();
        input.select();
        return copied.then(function (ok) {
          if (!ok) {
            // The URL is selected: Ctrl+C is all that is left to do.
            ok = legacyCopy();
          }
          note.textContent = (ok ? 'Link copied. '
                                 : 'Press Ctrl+C to copy the link. ')
                             + noteText;
          note.hidden = false;
        });
      }, function () {
        note.textContent = 'Could not create a link.';
        note.hidden = false;
      }).then(function () { busy = false; });
    });
  });
})();
