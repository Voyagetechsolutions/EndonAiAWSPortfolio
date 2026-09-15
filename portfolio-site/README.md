# Endon AI — Portfolio Site

The public-facing home for the [Endon AI](../README.md) platform and its case studies:
a single, self-contained static page for **endonai.com**.

It is generated in Python (content + Jinja2 templates → static HTML), so it stays
consistent with the "Python throughout" theme of the platform and is trivial to host —
no runtime, no framework, one file.

## What it is

A security-operations-console aesthetic: a cool signal-teal accent for the platform
working, a separate warm scale for threat severities, a hand-built architecture diagram,
and three expandable case files carrying the real metrics from the shipped projects
(26/26 posture detection, the `mallory` privilege-escalation path, sub-second containment).
Light and dark themes, responsive to phone width.

## Structure

```text
portfolio-site/
├── content.py              all copy and data (profile, projects, case studies)
├── templates/
│   ├── body.html.j2        page markup
│   └── diagram.svg         the platform architecture diagram (theme-aware)
├── static/
│   ├── styles.css          the design system (tokens, both themes)
│   └── main.js             theme toggle, scroll settle, active-nav
├── build.py                renders -> dist/
├── dist/                   build output (git-ignored)
│   ├── index.html          full standalone document — deploy this
│   └── embed.html          inner-content variant (for a host with its own skeleton)
└── infrastructure/         optional secure AWS static hosting (CDK)
```

Content and presentation are separated: change a metric or ship a project by editing
`content.py`, and rebuild.

## Build

```bash
pip install "jinja2>=3.1"
python portfolio-site/build.py
```

This writes `dist/index.html` (a single self-contained file — CSS and JS inlined, fonts
from Google Fonts) and `dist/embed.html`.

## Deploy

**Any static host.** `dist/index.html` is fully self-contained; drop it anywhere
(GitHub Pages, Netlify, S3).

**AWS, securely (on theme).** The [infrastructure/](infrastructure/) folder is an
optional AWS CDK app that hosts the site the way a security engineer should: a **private**
S3 bucket (no public access) behind CloudFront with Origin Access Control, HTTPS only, and
a response-headers policy (HSTS, `X-Content-Type-Options`, frame-deny, a locked-down
Content-Security-Policy). Pass a domain and ACM certificate to serve `endonai.com`.

```bash
cd portfolio-site && python build.py
cd infrastructure && cdk deploy \
  -c domain=endonai.com -c hostedZoneId=<zone> -c certArn=<us-east-1 ACM cert>
```

Without the domain context it deploys to the CloudFront URL, which is enough to preview.

## Before publishing

The GitHub and LinkedIn handles in [`content.py`](content.py) (`LINKS`) are **placeholders**
— confirm or replace them with your real profiles. The contact email is set to
`mthokochaza@gmail.com`.
