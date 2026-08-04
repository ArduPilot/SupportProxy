/*
  Collapse the video settings when video is not enabled, and show only
  as many port slots as the entry actually uses.

  The block is long -- three ports with per-slot options, two passwords,
  a grace window and a disk budget -- and every one of those is
  irrelevant until the entry actually has video turned on. Showing them
  regardless makes the edit page look like it is mostly about video when
  for most entries it is about none of it.

  Progressive enhancement: the markup ships visible and this hides it,
  so an entry is never left with settings the operator cannot reach if
  the script fails to load. The initial state is applied before first
  paint where possible (the script is deferred, so it runs before
  DOMContentLoaded fires) to avoid a visible collapse.
 */
(function () {
    'use strict';

    // Show slot rows 1..count. Rows past the count stay in the DOM and
    // keep submitting, so lowering the count and raising it again does
    // not lose that slot's options -- the server decides what to store.
    function applyCount(root) {
        var select = root.querySelector('#video_port_count');
        if (!select) {
            // Owner form has no selector; the server already emitted the
            // right rows, so leave them as they are.
            return;
        }
        var count = parseInt(select.value, 10);
        if (isNaN(count)) {
            return;
        }
        var rows = root.querySelectorAll('.video-slot');
        for (var i = 0; i < rows.length; i++) {
            rows[i].hidden =
                parseInt(rows[i].getAttribute('data-slot'), 10) > count;
        }
    }

    function wire(root) {
        var checkbox = root.querySelector('#video_enabled');
        var panel = root.querySelector('#video-options');
        if (!checkbox || !panel) {
            return;
        }
        var apply = function () {
            panel.hidden = !checkbox.checked;
            applyCount(root);
        };
        // Guard against being wired twice: auto-refresh.js re-runs
        // helpers over freshly-injected content.
        if (!checkbox.dataset.videoToggleWired) {
            checkbox.dataset.videoToggleWired = '1';
            checkbox.addEventListener('change', apply);
        }
        var select = root.querySelector('#video_port_count');
        if (select && !select.dataset.videoToggleWired) {
            select.dataset.videoToggleWired = '1';
            select.addEventListener('change', apply);
        }
        apply();
    }

    function init() {
        wire(document);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // auto-refresh.js swaps <main> in place and fires 'pageupdate';
    // re-apply afterwards or the panel returns expanded on a disabled entry.
    document.addEventListener('pageupdate', init);
})();
