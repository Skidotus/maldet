"""Build the social share card and screenshot it to static/img/og-card.png.

    python3 design/og-card/build.py

The card is generated rather than drawn by hand so it stays tied to the
site: same palette tokens, same Octocat mark, and the same Truchet field the
hero animates. A screenshot of the live page would have been easier and
wrong -- a share card has to read at thumbnail size, where a screenshot of a
web page is mush.

Deliberately carries no counts. The corpus grows, and a card baked with
"184 repositories" becomes a quiet lie the first week after it is made.
What it claims instead -- six engines, two verdicts -- is structural and
stays true.
"""

import base64
import os
import pathlib
import random
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "static" / "img" / "og-card.jpg"
SHOT = ROOT / "static" / "img" / ".og-card.shot.png"
HTML = pathlib.Path(__file__).parent / "card.html"

W, H = 1200, 630
TILE = 84

# Palette, lifted from static/css/style.css rather than re-picked by eye.
FOREST_900 = "#0a1d15"
FOREST_950 = "#05110c"
JADE = "#a3d9b8"
IVORY = "#f1f0e8"
MUTED = "#a8b8ad"


def truchet(seed=7):
    """The hero's pattern, frozen. Same geometry as hero-truchet.js: two
    quarter arcs on opposite corners, one orientation being the other turned
    a quarter, so paths run on across tile boundaries."""
    rng = random.Random(seed)
    half = TILE / 2
    out = []
    for row in range(H // TILE + 2):
        for col in range(W // TILE + 2):
            x, y = col * TILE, row * TILE
            # Transcribed from hero-truchet.js rather than re-derived: arcs
            # centred on two opposite corners, radius half a tile, so both
            # ends land exactly on edge midpoints and neighbours join up.
            if rng.random() < 0.5:
                # centres: top-left and bottom-right
                # Sweep 1: the short way, hugging the corner. Sweep 0 takes
                # the long way round and draws a pinwheel instead of a maze.
                out.append(f'<path d="M{x + half} {y} A{half} {half} 0 0 1 {x} {y + half}"/>')
                out.append(f'<path d="M{x + half} {y + TILE} A{half} {half} 0 0 1 {x + TILE} {y + half}"/>')
            else:
                # the same tile turned a quarter: top-right and bottom-left
                out.append(f'<path d="M{x + half} {y} A{half} {half} 0 0 0 {x + TILE} {y + half}"/>')
                out.append(f'<path d="M{x + half} {y + TILE} A{half} {half} 0 0 0 {x} {y + half}"/>')
    return "\n".join(out)


def logo_data_uri():
    path = ROOT / "static" / "img" / "logo.png"
    return "data:image/png;base64," + base64.b64encode(path.read_bytes()).decode()


def build_html():
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@500&display=swap" rel="stylesheet">
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ width: {W}px; height: {H}px; overflow: hidden;
          font-family: "IBM Plex Sans", system-ui, sans-serif;
          background: {FOREST_900}; color: {IVORY}; }}
  .card {{ position: relative; width: {W}px; height: {H}px;
           background:
             radial-gradient(62% 58% at 80% 26%, rgba(163,217,184,0.16), transparent 68%),
             radial-gradient(48% 48% at 8% 92%, rgba(25,58,44,0.95), transparent 70%),
             linear-gradient(170deg, {FOREST_900} 0%, {FOREST_950} 100%);
           overflow: hidden; }}
  .pattern {{ position: absolute; inset: 0; opacity: 0.22; }}
  .inner {{ position: relative; height: 100%; padding: 72px 80px;
            display: flex; flex-direction: column; justify-content: space-between; }}
  .top {{ display: flex; align-items: center; gap: 18px; }}
  .top img {{ width: 60px; height: 60px; }}
  .wordmark {{ font-size: 30px; font-weight: 700; letter-spacing: -0.02em; }}
  h1 {{ font-size: 62px; line-height: 1.07; font-weight: 700; letter-spacing: -0.035em;
        max-width: 17ch; }}
  h1 em {{ font-style: normal; color: {JADE}; }}
  .axes {{ display: flex; gap: 56px; margin-top: 30px; }}
  .axis {{ display: flex; flex-direction: column; gap: 9px; }}
  .axis b {{ font-size: 19px; font-weight: 600; letter-spacing: -0.01em; }}
  .axis span {{ font-size: 15.5px; color: {MUTED}; }}
  .scale {{ display: flex; gap: 5px; margin-top: 3px; }}
  .scale i {{ width: 30px; height: 6px; border-radius: 3px; background: rgba(241,240,232,0.17); }}
  .scale i.on {{ background: {JADE}; box-shadow: 0 0 0 2px {FOREST_950}, 0 0 0 3px {JADE}; }}
  .foot {{ display: flex; align-items: center; justify-content: space-between;
           border-top: 1px solid rgba(241,240,232,0.13); padding-top: 24px; }}
  .url {{ font-family: "IBM Plex Mono", monospace; font-size: 19px; color: {JADE}; }}
  .engines {{ font-size: 15.5px; color: {MUTED}; }}
</style></head>
<body>
  <div class="card">
    <svg class="pattern" viewBox="0 0 {W} {H}" fill="none" stroke="{JADE}" stroke-width="1.6">
      {truchet()}
    </svg>
    <div class="inner">
      <div class="top">
        <img src="{logo_data_uri()}" alt="">
        <span class="wordmark">MalDet</span>
      </div>
      <div>
        <h1>Know what a repository hides <em>before you run it.</em></h1>
        <div class="axes">
          <div class="axis">
            <b>Vulnerability</b>
            <span>Mistakes an attacker could use</span>
            <div class="scale"><i></i><i></i><i class="on"></i><i></i><i></i></div>
          </div>
          <div class="axis">
            <b>Malicious pattern</b>
            <span>Signs the code means harm</span>
            <div class="scale"><i class="on"></i><i></i><i></i><i></i><i></i></div>
          </div>
        </div>
      </div>
      <div class="foot">
        <span class="url">maldet-fyp.my</span>
        <span class="engines">Six engines &middot; two verdicts &middot; one scan</span>
      </div>
    </div>
  </div>
</body></html>"""


def main():
    HTML.write_text(build_html())
    OUT.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        "google-chrome", "--headless=new", "--disable-gpu", "--hide-scrollbars",
        f"--window-size={W},{H}",
        f"--screenshot={SHOT}",
        HTML.resolve().as_uri(),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if not SHOT.exists():
        sys.exit(f"screenshot failed\n{r.stderr[-1500:]}")

    # Chrome only writes PNG, which is the wrong format for this: the card is
    # mostly smooth gradient, where PNG cannot do better than 400KB and JPEG
    # is indistinguishable at a fifth of that. Every link preview anyone
    # generates pays that difference.
    from PIL import Image
    png_size = SHOT.stat().st_size
    Image.open(SHOT).convert("RGB").save(
        OUT, quality=90, optimize=True, progressive=True
    )
    SHOT.unlink()
    print(f"  {OUT.relative_to(ROOT)}  {OUT.stat().st_size // 1024}KB "
          f"(from {png_size // 1024}KB PNG)")


if __name__ == "__main__":
    main()
