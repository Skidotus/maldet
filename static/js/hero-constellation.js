// MalDet — the drifting dependency graph behind the hero.
//
// Nodes wander slowly and draw a line to any neighbour they come close to,
// so links form and break as they pass. That is the shape of the thing this
// project analyses -- packages, and what they depend on -- without being a
// literal diagram of anything.
//
// It is decoration, so it gives up easily: no canvas element, no 2D context,
// no requestAnimationFrame, or a visitor who asked for reduced motion, and
// it does nothing at all. The hero still has its gradients underneath.
(function () {
  'use strict';

  var canvas = document.querySelector('.hero__canvas');
  if (!canvas || !canvas.getContext || !window.requestAnimationFrame) { return; }

  var ctx = canvas.getContext('2d');
  if (!ctx) { return; }

  // --- the look -----------------------------------------------------
  // Jade, matching --green-glow. Written out rather than read from CSS
  // because this runs per frame and getComputedStyle is not free.
  var JADE = '163, 217, 184';

  var NODE_ALPHA = 0.55;   // multiplied by the canvas's own CSS opacity
  var LINK_ALPHA = 0.28;   // at zero distance, fading to 0 at LINK_DIST
  var LINK_DIST = 150;     // px before two nodes stop acknowledging each other
  var SPEED = 0.12;        // px per frame; ~7px a second, deliberately dull
  var DENSITY = 26000;     // one node per this many px² of hero

  // A hard ceiling regardless of screen size. A 4K monitor would otherwise
  // ask for hundreds of nodes, and the link check is O(n²).
  var MAX_NODES = 38;

  var nodes = [];
  var width = 0;
  var height = 0;
  var running = false;
  var frame = null;

  function resize() {
    var rect = canvas.getBoundingClientRect();
    if (!rect.width || !rect.height) { return false; }

    // Draw at device resolution so the dots are not soft on a HiDPI screen,
    // then scale the context so the rest of this code can think in CSS px.
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = rect.width;
    height = rect.height;
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return true;
  }

  function seed() {
    var count = Math.min(MAX_NODES, Math.round((width * height) / DENSITY));
    nodes = [];
    for (var i = 0; i < count; i++) {
      var angle = Math.random() * Math.PI * 2;
      nodes.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: Math.cos(angle) * SPEED,
        vy: Math.sin(angle) * SPEED,
        // A little variation so it does not read as a regular pattern.
        r: 1.1 + Math.random() * 1.5
      });
    }
  }

  function draw() {
    ctx.clearRect(0, 0, width, height);

    var i, j, a, b, dx, dy, dist;

    // Links first, so the dots sit on top of them.
    for (i = 0; i < nodes.length; i++) {
      a = nodes[i];
      for (j = i + 1; j < nodes.length; j++) {
        b = nodes[j];
        dx = a.x - b.x;
        dy = a.y - b.y;
        dist = Math.sqrt(dx * dx + dy * dy);
        if (dist >= LINK_DIST) { continue; }
        ctx.strokeStyle = 'rgba(' + JADE + ',' + (LINK_ALPHA * (1 - dist / LINK_DIST)).toFixed(3) + ')';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.stroke();
      }
    }

    ctx.fillStyle = 'rgba(' + JADE + ',' + NODE_ALPHA + ')';
    for (i = 0; i < nodes.length; i++) {
      a = nodes[i];
      ctx.beginPath();
      ctx.arc(a.x, a.y, a.r, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  function step() {
    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      n.x += n.vx;
      n.y += n.vy;

      // Wrap rather than bounce: bouncing makes the edges visible as walls,
      // and a graph has no walls. The margin keeps a dot from blinking out
      // the instant its centre crosses.
      if (n.x < -LINK_DIST) { n.x = width + LINK_DIST; }
      if (n.x > width + LINK_DIST) { n.x = -LINK_DIST; }
      if (n.y < -LINK_DIST) { n.y = height + LINK_DIST; }
      if (n.y > height + LINK_DIST) { n.y = -LINK_DIST; }
    }
    draw();
    frame = window.requestAnimationFrame(step);
  }

  function start() {
    if (running) { return; }
    running = true;
    frame = window.requestAnimationFrame(step);
  }

  function stop() {
    running = false;
    if (frame !== null) {
      window.cancelAnimationFrame(frame);
      frame = null;
    }
  }

  // --- reduced motion -------------------------------------------------
  // One static frame rather than nothing: the texture is part of the
  // design, the movement is the part somebody asked not to have.
  var query = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;

  function apply() {
    if (!resize()) { return; }
    seed();
    if (query && query.matches) {
      stop();
      draw();
    } else {
      start();
    }
  }

  if (query) {
    var onChange = function () { apply(); };
    if (query.addEventListener) { query.addEventListener('change', onChange); }
    else if (query.addListener) { query.addListener(onChange); }
  }

  // --- stop when nobody can see it ------------------------------------
  // A hero scrolled off the top, or a background tab, should not be
  // animating. This is a laptop-battery question as much as a CPU one.
  if ('IntersectionObserver' in window) {
    new IntersectionObserver(function (entries) {
      var visible = entries[0] && entries[0].isIntersecting;
      if (visible && !(query && query.matches)) { start(); } else { stop(); }
    }, { threshold: 0 }).observe(canvas);
  }

  document.addEventListener('visibilitychange', function () {
    if (document.hidden) { stop(); }
    else if (!(query && query.matches)) { start(); }
  });

  // Debounced: a drag-resize fires this continuously, and reseeding on each
  // event would restart the whole field dozens of times.
  var resizeTimer = null;
  window.addEventListener('resize', function () {
    window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(apply, 180);
  });

  apply();
})();
