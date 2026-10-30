// MalDet — Truchet tiles behind the hero.
//
// A grid of squares, each holding two quarter-circle arcs that join the
// midpoints of its edges. There are only two orientations, and one is the
// other rotated a quarter turn -- which is why a flip can be *rotated*
// rather than crossfaded, and why the lines never break while it happens.
// Paths run continuously from tile to tile, so the whole field reads as one
// maze that nobody drew.
//
// Every few seconds a single tile turns. You tend to catch it from the
// corner of your eye rather than watch it, which is the intended effect.
//
// The useful consequence of flipping one tile at a time: between flips the
// image is identical frame to frame, so there is nothing to animate. The
// loop runs only while a tile is mid-turn and stops again afterwards --
// idle cost is a timer, not a redraw.
(function () {
  'use strict';

  var canvas = document.querySelector('.hero__canvas');
  if (!canvas || !canvas.getContext || !window.requestAnimationFrame) { return; }

  var ctx = canvas.getContext('2d');
  if (!ctx) { return; }

  // --- the look -----------------------------------------------------
  var JADE = '163, 217, 184';          // --green-glow
  var TILE = 68;                       // px; the arcs read as arcs below ~48
  var LINE = 1.4;
  var ALPHA = 0.42;                    // multiplied by the layer's CSS opacity

  var TURN_MS = 900;                   // how long one tile takes to turn
  var GAP_MIN = 1400;                  // pause between turns
  var GAP_MAX = 3600;

  // Occasionally two at once, so the rhythm is not metronomic.
  var DOUBLE_CHANCE = 0.22;

  var cols = 0, rows = 0, offX = 0, offY = 0;
  var width = 0, height = 0;
  var tiles = [];                      // angle in quarter-turns: 0 or 1
  var moving = [];                     // tiles mid-turn
  var frame = null;
  var timer = null;
  var reduced = false;

  function easeInOut(t) {
    // Cubic. Starts and ends still, which is what stops a turn looking
    // mechanical.
    return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
  }

  function resize() {
    var rect = canvas.getBoundingClientRect();
    if (!rect.width || !rect.height) { return false; }

    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = rect.width;
    height = rect.height;
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.lineCap = 'round';

    // One tile of overhang on each side, and the grid centred, so the
    // pattern is never visibly cut off at a particular column.
    cols = Math.ceil(width / TILE) + 2;
    rows = Math.ceil(height / TILE) + 2;
    offX = (width - cols * TILE) / 2;
    offY = (height - rows * TILE) / 2;
    return true;
  }

  function seed() {
    tiles = new Array(cols * rows);
    for (var i = 0; i < tiles.length; i++) {
      tiles[i] = Math.random() < 0.5 ? 0 : 1;
    }
    moving = [];
  }

  function drawTile(col, row, quarterTurns) {
    var x = offX + col * TILE;
    var y = offY + row * TILE;
    var half = TILE / 2;

    ctx.save();
    ctx.translate(x + half, y + half);
    ctx.rotate(quarterTurns * Math.PI / 2);
    ctx.translate(-half, -half);

    // Two quarter circles, centred on opposite corners, radius half a tile.
    // Their ends land exactly on edge midpoints, which is what lets
    // neighbours join up regardless of how either is turned.
    ctx.beginPath();
    ctx.arc(0, 0, half, 0, Math.PI / 2);
    ctx.stroke();

    ctx.beginPath();
    ctx.arc(TILE, TILE, half, Math.PI, Math.PI * 1.5);
    ctx.stroke();

    ctx.restore();
  }

  function draw(now) {
    ctx.clearRect(0, 0, width, height);
    ctx.strokeStyle = 'rgba(' + JADE + ',' + ALPHA + ')';
    ctx.lineWidth = LINE;

    // Turning tiles are held in a small list, so the common case -- a tile
    // that is not moving -- costs one lookup rather than a search.
    var active = {};
    for (var m = 0; m < moving.length; m++) {
      var mv = moving[m];
      var t = (now - mv.start) / TURN_MS;
      if (t >= 1) { t = 1; }
      active[mv.index] = mv.from + (mv.to - mv.from) * easeInOut(t);
    }

    for (var row = 0; row < rows; row++) {
      for (var col = 0; col < cols; col++) {
        var index = row * cols + col;
        var angle = active[index] !== undefined ? active[index] : tiles[index];
        drawTile(col, row, angle);
      }
    }
  }

  function step(now) {
    var still = [];
    for (var i = 0; i < moving.length; i++) {
      var mv = moving[i];
      if (now - mv.start >= TURN_MS) {
        // Keep the angle in 0..1 so it never grows without bound over a
        // long session; the two orientations are a quarter turn apart and
        // a half turn is the identity for this tile.
        tiles[mv.index] = mv.to % 2;
      } else {
        still.push(mv);
      }
    }
    moving = still;

    draw(now);

    if (moving.length) {
      frame = window.requestAnimationFrame(step);
    } else {
      // Nothing is changing, so stop drawing entirely until the next turn.
      frame = null;
      schedule();
    }
  }

  function turnOne() {
    var index = Math.floor(Math.random() * tiles.length);
    for (var i = 0; i < moving.length; i++) {
      if (moving[i].index === index) { return; }   // already turning
    }
    moving.push({
      index: index,
      from: tiles[index],
      // Always forward. Alternating direction reads as a wobble rather
      // than a turn.
      to: tiles[index] + 1,
      start: (window.performance && performance.now) ? performance.now() : Date.now()
    });
  }

  function schedule() {
    if (reduced) { return; }
    window.clearTimeout(timer);
    timer = window.setTimeout(function () {
      turnOne();
      if (Math.random() < DOUBLE_CHANCE) { turnOne(); }
      if (frame === null) { frame = window.requestAnimationFrame(step); }
    }, GAP_MIN + Math.random() * (GAP_MAX - GAP_MIN));
  }

  function stop() {
    window.clearTimeout(timer);
    if (frame !== null) { window.cancelAnimationFrame(frame); frame = null; }
  }

  function start() {
    if (reduced || frame !== null || timer !== null) { return; }
    schedule();
  }

  // --- reduced motion -------------------------------------------------
  // The pattern is the design; the turning is the part somebody asked not
  // to have. So it is still drawn, just never moves again.
  var query = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;

  function apply() {
    reduced = !!(query && query.matches);
    stop();
    timer = null;
    if (!resize()) { return; }
    seed();
    draw(0);
    if (!reduced) { schedule(); }
  }

  if (query) {
    var onChange = function () { apply(); };
    if (query.addEventListener) { query.addEventListener('change', onChange); }
    else if (query.addListener) { query.addListener(onChange); }
  }

  // --- stop when nobody can see it ------------------------------------
  if ('IntersectionObserver' in window) {
    new IntersectionObserver(function (entries) {
      if (entries[0] && entries[0].isIntersecting) { start(); }
      else { stop(); timer = null; }
    }, { threshold: 0 }).observe(canvas);
  }

  document.addEventListener('visibilitychange', function () {
    if (document.hidden) { stop(); timer = null; } else { start(); }
  });

  var resizeTimer = null;
  window.addEventListener('resize', function () {
    window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(apply, 180);
  });

  apply();
})();
