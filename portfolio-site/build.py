"""Render the Endon AI portfolio into static files.

Content (content.py) + templates (Jinja2) + static assets are composed into two outputs:

* ``dist/index.html``    — a full, self-contained HTML document for hosting (endonai.com).
* ``dist/embed.html``    — the same page as inner content only (no <head>/<body> wrappers),
  for embedding in a host that supplies its own document skeleton.

Both inline the CSS and JS, so the page is a single portable file with no build step at
serve time. Fonts load from Google Fonts (the one external host used).

    python portfolio-site/build.py
"""

from __future__ import annotations

import datetime
from pathlib import Path

import content
from jinja2 import Environment, FileSystemLoader, select_autoescape

ROOT = Path(__file__).resolve().parent
TEMPLATES = ROOT / "templates"
STATIC = ROOT / "static"
DIST = ROOT / "dist"

FONTS_LINK = (
    '<link rel="preconnect" href="https://fonts.googleapis.com">'
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
    '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?'
    "family=Chivo:wght@600;700;800&"
    "family=IBM+Plex+Mono:wght@400;500&"
    'family=IBM+Plex+Sans:wght@400;500;600;700&display=swap">'
)


def render_body() -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("body.html.j2")
    return template.render(
        profile=content.PROFILE,
        links=content.LINKS,
        stats=content.STATS,
        domains=content.DOMAINS,
        platform_intro=content.PLATFORM_INTRO,
        projects=content.PROJECTS,
        cases=content.CASE_STUDIES,
        about=content.ABOUT,
        year=datetime.date.today().year,
    )


def standalone(body: str, css: str, js: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="{content.SITE_DESCRIPTION}">
<meta property="og:title" content="{content.SITE_TITLE}">
<meta property="og:description" content="{content.SITE_DESCRIPTION}">
<meta property="og:type" content="website">
<title>{content.SITE_TITLE}</title>
{FONTS_LINK}
<style>
{css}
</style>
</head>
<body>
{body}
<script>
{js}
</script>
</body>
</html>
"""


def embed(body: str, css: str, js: str) -> str:
    # No <head>/<body>: for a host that wraps content in its own skeleton. Title + style at top.
    return f"""{FONTS_LINK}
<title>Endon AI Portfolio</title>
<style>
{css}
</style>
{body}
<script>
{js}
</script>
"""


def main() -> None:
    body = render_body()
    css = (STATIC / "styles.css").read_text(encoding="utf-8")
    js = (STATIC / "main.js").read_text(encoding="utf-8")

    DIST.mkdir(exist_ok=True)
    (DIST / "index.html").write_text(standalone(body, css, js), encoding="utf-8")
    (DIST / "embed.html").write_text(embed(body, css, js), encoding="utf-8")
    print(f"Built dist/index.html and dist/embed.html ({len(body)} bytes of markup).")


if __name__ == "__main__":
    main()
