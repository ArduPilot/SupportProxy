/*
  Public viewer for a share link.

  Browsers with Media Source Extensions play the live MPEG-TS over a
  WebSocket, which is the lowest-latency path. Those without it -- every
  iPhone browser in practice, since they all use WebKit -- fall back to
  HLS, which Safari plays natively. HLS runs several seconds behind;
  there is no way around that without partial segments.

  Both paths reconnect on their own. A viewer watching a flight is not
  going to reload the page when the publisher restarts.
 */
(function () {
  'use strict';

  var box = document.getElementById('watch');
  if (!box) { return; }
  var video = document.getElementById('player');
  var statusEl = document.getElementById('status');
  var hlsUrl = box.getAttribute('data-hls-url');
  var tokenUrl = box.getAttribute('data-token-url');
  var host = box.getAttribute('data-host');
  var port = box.getAttribute('data-port');
  var number = box.getAttribute('data-number');
  var scheme = (window.location.protocol === 'https:') ? 'wss' : 'ws';

  function say(msg) { statusEl.textContent = msg; }

  var hasMse = !!window.MediaSource && !!window.mpegts && mpegts.isSupported();
  var hasHls = !!video.canPlayType('application/vnd.apple.mpegurl');

  video.addEventListener('playing', function () {
    var size = video.videoWidth
        ? ' ' + video.videoWidth + '\u00d7' + video.videoHeight : '';
    say('Playing' + size);
  });

  // Both players ask the same question when something fails: is the
  // link itself dead? ws-token answers with the link's own status.
  // Calls back with 'expired', 'invalid' or 'ok' (also on a network
  // error, which is worth retrying).
  function probeLink(done) {
    fetch(tokenUrl, { credentials: 'omit' })
      .then(function (r) {
        done(r.status === 410 ? 'expired' : r.status === 404 ? 'invalid' : 'ok');
      })
      .catch(function () { done('ok'); });
  }

  function linkDeadMessage(state) {
    return state === 'expired' ? 'This link has expired.'
                               : 'This link is no longer valid.';
  }

  function startHls() {
    var retryMs = 1000;
    var pending = false;
    var lastTime = -1;
    var stuckTicks = 0;
    var stopped = false;
    var timer = null;
    var watchdog = null;

    function stop(state) {
      stopped = true;
      clearTimeout(timer);
      clearInterval(watchdog);
      try { video.pause(); } catch (e) { /* not playing */ }
      video.removeAttribute('src');
      video.load();
      say(linkDeadMessage(state));
    }

    function load() {
      if (stopped) { return; }
      // The query only defeats a cached 503; relative segment URLs
      // resolve against the path, so it is not carried onto them.
      video.src = hlsUrl + '?_=' + Date.now();
      video.load();
      var p = video.play();
      if (p && p.catch) { p.catch(function () { say('Ready \u2014 press play.'); }); }
    }

    function retry() {
      if (pending || stopped) { return; }
      pending = true;
      var wait = retryMs;
      retryMs = Math.min(retryMs * 2, 5000);
      say('Waiting for the stream\u2026');
      // The player cannot tell a dead link from a stream that is down,
      // so ask before trying again.
      timer = setTimeout(function () {
        probeLink(function (state) {
          pending = false;
          if (state === 'ok') { load(); } else { stop(state); }
        });
      }, wait);
    }

    video.addEventListener('playing', function () { retryMs = 1000; });
    video.addEventListener('error', retry);
    video.addEventListener('ended', retry);

    // A live playlist that stops advancing raises no event at all.
    watchdog = setInterval(function () {
      if (video.paused || pending) { stuckTicks = 0; return; }
      if (video.currentTime === lastTime) {
        if (++stuckTicks >= 3) { stuckTicks = 0; retry(); }
      } else {
        stuckTicks = 0;
      }
      lastTime = video.currentTime;
    }, 4000);

    say('Connecting\u2026');
    load();
  }

  function startMse() {
    var player = null;
    var pending = false;
    var retryMs = 1000;
    var mediaErrors = 0;
    var gaveUp = false;
    var timer = null;

    function teardown() {
      if (!player) { return; }
      try { player.pause(); } catch (e) { /* not playing */ }
      try { player.unload(); } catch (e) { /* not loaded */ }
      try { player.detachMediaElement(); } catch (e) { /* not attached */ }
      try { player.destroy(); } catch (e) { /* already gone */ }
      player = null;
    }

    function schedule() {
      if (pending || gaveUp) { return; }
      pending = true;
      var wait = retryMs;
      retryMs = Math.min(retryMs * 2, 5000);
      timer = setTimeout(function () { pending = false; connect(); }, wait);
    }

    function giveUp(why) {
      gaveUp = true;
      // A retry queued before we got here must not attach a new player
      // on top of the HLS fallback.
      clearTimeout(timer);
      pending = false;
      teardown();
      if (hasHls) {
        say('Switching to a compatible player\u2026');
        startHls();
      } else {
        say(why);
      }
    }

    function start(tok) {
      var url = scheme + '://' + host + ':' + port + '/v' + number +
                '?t=' + encodeURIComponent(tok);
      player = mpegts.createPlayer(
        { type: 'mpegts', isLive: true, url: url },
        { enableWorker: true, liveBufferLatencyChasing: true });

      // A publisher going away is a clean close, not an error.
      player.on(mpegts.Events.LOADING_COMPLETE, function () {
        say('Stream ended \u2014 waiting for it to return\u2026');
        schedule();
      });
      player.on(mpegts.Events.ERROR, function (type, detail) {
        var permanent =
            (detail === mpegts.ErrorDetails.MEDIA_CODEC_UNSUPPORTED
             || detail === mpegts.ErrorDetails.MEDIA_FORMAT_UNSUPPORTED);
        if (type === mpegts.ErrorTypes.MEDIA_ERROR) {
          mediaErrors++;
          if (permanent || mediaErrors >= 3) {
            giveUp('This browser cannot play this video format.');
            return;
          }
        }
        say('Waiting for the stream\u2026');
        schedule();
      });
      player.attachMediaElement(video);
      player.load();
      video.play().catch(function () { say('Ready \u2014 press play.'); });
    }

    function connect() {
      if (gaveUp) { return; }
      teardown();
      fetch(tokenUrl, { credentials: 'omit' })
        .then(function (r) {
          if (r.status === 410) {
            gaveUp = true;
            say('This link has expired.');
            return null;
          }
          if (r.status === 404) {
            gaveUp = true;
            say('This link is no longer valid.');
            return null;
          }
          return r.ok ? r.json() : undefined;
        })
        .then(function (j) {
          if (j === null) { return; }
          if (!j || !j.token) {
            say('Waiting for the stream\u2026');
            schedule();
            return;
          }
          start(j.token);
        })
        .catch(function () { say('Reconnecting\u2026'); schedule(); });
    }

    video.addEventListener('playing', function () {
      retryMs = 1000;
      mediaErrors = 0;
    });
    video.addEventListener('ended', function () {
      say('Stream ended \u2014 waiting for it to return\u2026');
      schedule();
    });

    say('Connecting\u2026');
    connect();
  }

  if (hasMse) {
    startMse();
  } else if (hasHls) {
    startHls();
  } else {
    say('This browser cannot play the live stream.');
  }
})();
