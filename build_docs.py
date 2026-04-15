#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "markdown>=3.5",
#   "pygments>=2.17",
# ]
# ///
"""
build_docs.py ─ turn docs/*.md into a static VuePress-style site in dist/.

Core logic is ~50 lines: walk the docs directory, parse each .md with
the python-markdown library (fenced code + codehilite + tables + toc),
extract the first H1 as the page title, wrap in an inline HTML template
with a left sidebar navigation listing every page, write to dist/.

Everything else is template + CSS, both inlined in this file so the
script stays self-contained and one-click runnable via `uv run`.
"""
from __future__ import annotations

import html
import re
import shutil
from pathlib import Path

import markdown

ROOT = Path(__file__).parent
DOCS_DIR = ROOT / "docs"
DIST_DIR = ROOT / "dist"
SITE_TITLE = "Cloudbirds Cam RE"
SITE_SUBTITLE = "Reverse engineering a cheap Chinese IP camera"


# ──────────────────────────── core: parsing ─────────────────────────────

def read_pages() -> list[dict]:
    """Walk docs/, parse each .md, return a sorted list of page dicts.

    Each dict has: slug, input_path, output_path, title, nav_label, html,
    and toc_html (from the markdown TOC extension).
    """
    md = markdown.Markdown(
        extensions=["fenced_code", "codehilite", "tables", "toc", "attr_list"],
        extension_configs={
            "codehilite": {"css_class": "highlight", "guess_lang": False},
            "toc": {"permalink": "¶"},
        },
    )
    pages: list[dict] = []
    for path in sorted(DOCS_DIR.glob("*.md")):
        md.reset()
        source = path.read_text(encoding="utf-8")
        body_html = md.convert(source)
        title = extract_title(source, fallback=path.stem)
        slug = "index" if path.stem.lower() == "readme" else path.stem
        nav_label = nav_label_from(path.stem, title)
        pages.append({
            "slug": slug,
            "input_path": path,
            "output_path": DIST_DIR / f"{slug}.html",
            "title": title,
            "nav_label": nav_label,
            "html": body_html,
            "toc_html": getattr(md, "toc", ""),
        })
    # Make sure the README/index is first in nav regardless of filename order
    pages.sort(key=lambda p: (0 if p["slug"] == "index" else 1, p["slug"]))
    return pages


def extract_title(source: str, fallback: str) -> str:
    """Return the text of the first level-1 heading, else `fallback`."""
    for line in source.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return fallback


def nav_label_from(stem: str, title: str) -> str:
    """Friendly sidebar label.

    For files named NN-slug.md where the title starts with "NN · Rest",
    use "Rest" as the sidebar label (hiding the redundant number).
    Otherwise use the full title.
    """
    m = re.match(r"^\d{2}\s*·\s*(.*)$", title)
    if m:
        return m.group(1).strip()
    return title


# ──────────────────────────── core: rendering ───────────────────────────

def render_page(page: dict, pages: list[dict]) -> str:
    """Combine a single page dict with the global nav into final HTML."""
    nav_html = render_nav(pages, active_slug=page["slug"])
    title = html.escape(page["title"])
    return TEMPLATE.format(
        site_title=html.escape(SITE_TITLE),
        site_subtitle=html.escape(SITE_SUBTITLE),
        page_title=title,
        content=page["html"],
        nav=nav_html,
        pygments_css=PYGMENTS_CSS,
        base_css=BASE_CSS,
    )


def render_nav(pages: list[dict], active_slug: str) -> str:
    items = []
    for p in pages:
        active = " class=\"active\"" if p["slug"] == active_slug else ""
        label = html.escape(p["nav_label"])
        items.append(f'  <li><a href="{p["slug"]}.html"{active}>{label}</a></li>')
    return "<ul class=\"nav\">\n" + "\n".join(items) + "\n</ul>"


def build() -> None:
    if DIST_DIR.exists():
        shutil.rmtree(DIST_DIR)
    DIST_DIR.mkdir(parents=True)

    pages = read_pages()
    if not pages:
        raise SystemExit(f"no .md files found in {DOCS_DIR}")

    for page in pages:
        output = render_page(page, pages)
        page["output_path"].write_text(output, encoding="utf-8")
        print(f"  wrote {page['output_path'].relative_to(ROOT)}  ({page['title']})")

    print(f"\ndone: {len(pages)} pages → {DIST_DIR.relative_to(ROOT)}/")


# ──────────────────────────── templates & CSS ──────────────────────────

TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{page_title} — {site_title}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
{base_css}
{pygments_css}
</style>
<script>
(() => {{
  const saved = localStorage.getItem("theme");
  const prefersDark = matchMedia("(prefers-color-scheme: dark)").matches;
  const theme = saved || (prefersDark ? "dark" : "light");
  document.documentElement.dataset.theme = theme;
}})();
</script>
</head>
<body>
<header class="topbar">
  <div class="topbar-inner">
    <a class="brand" href="index.html">
      <span class="brand-title">{site_title}</span>
      <span class="brand-sub">{site_subtitle}</span>
    </a>
    <button class="theme-toggle" aria-label="toggle theme" onclick="toggleTheme()">
      <svg class="icon-sun"  viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>
      <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
    </button>
  </div>
</header>
<div class="layout">
  <aside class="sidebar">
{nav}
  </aside>
  <main class="content">
    <article class="markdown">
{content}
    </article>
  </main>
</div>
<script>
function toggleTheme() {{
  const root = document.documentElement;
  const next = root.dataset.theme === "dark" ? "light" : "dark";
  root.dataset.theme = next;
  localStorage.setItem("theme", next);
}}
</script>
</body>
</html>
"""


BASE_CSS = """
:root {
  --font-body: 'Inter', system-ui, -apple-system, sans-serif;
  --font-mono: 'JetBrains Mono', ui-monospace, monospace;
  --content-max: 760px;
  --sidebar-w: 260px;
  --topbar-h: 58px;
}

/* light theme (default) */
:root[data-theme="light"] {
  --bg:         #ffffff;
  --bg-alt:     #fafafa;
  --bg-elev:    #f4f4f5;
  --border:     #e5e7eb;
  --border-h:   #d4d4d8;
  --text:       #18181b;
  --text-sec:   #52525b;
  --text-muted: #a1a1aa;
  --accent:     #ea580c;
  --accent-h:   #c2410c;
  --link:       #ea580c;
  --code-bg:    #f4f4f5;
  --code-border:#e4e4e7;
  --inline-bg:  #f4f4f5;
  --kbd-bg:     #f4f4f5;
  --shadow:     0 1px 3px rgba(0,0,0,0.04);
}

/* dark theme */
:root[data-theme="dark"] {
  --bg:         #0a0a0f;
  --bg-alt:     #12121a;
  --bg-elev:    #1a1a26;
  --border:     #2a2a3a;
  --border-h:   #3a3a52;
  --text:       #e8e8f0;
  --text-sec:   #9898b0;
  --text-muted: #5e5e78;
  --accent:     #fb923c;
  --accent-h:   #fdba74;
  --link:       #fb923c;
  --code-bg:    #12121a;
  --code-border:#22222e;
  --inline-bg:  #1a1a26;
  --kbd-bg:     #22222e;
  --shadow:     0 1px 3px rgba(0,0,0,0.4);
}

* { box-sizing: border-box; margin: 0; padding: 0; }

html, body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-body);
  line-height: 1.7;
  -webkit-font-smoothing: antialiased;
}

a { color: var(--link); text-decoration: none; }
a:hover { color: var(--accent-h); text-decoration: underline; }

/* topbar */
.topbar {
  position: sticky; top: 0; z-index: 100;
  height: var(--topbar-h);
  background: var(--bg);
  border-bottom: 1px solid var(--border);
  backdrop-filter: blur(8px);
}
.topbar-inner {
  max-width: 1400px;
  margin: 0 auto;
  height: 100%;
  padding: 0 28px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.brand { display: flex; flex-direction: column; line-height: 1.2; }
.brand-title { font-weight: 700; font-size: 15px; color: var(--text); }
.brand-sub   { font-size: 11px; color: var(--text-muted); }
.brand:hover { text-decoration: none; }

.theme-toggle {
  background: transparent;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 8px;
  cursor: pointer;
  color: var(--text-sec);
  display: flex;
  align-items: center;
  transition: all .2s;
}
.theme-toggle:hover { border-color: var(--border-h); color: var(--text); }
.theme-toggle svg { width: 16px; height: 16px; }
:root[data-theme="light"] .icon-moon { display: none; }
:root[data-theme="dark"]  .icon-sun  { display: none; }

/* layout */
.layout {
  max-width: 1400px;
  margin: 0 auto;
  display: grid;
  grid-template-columns: var(--sidebar-w) 1fr;
  gap: 0;
}

.sidebar {
  position: sticky;
  top: var(--topbar-h);
  align-self: start;
  height: calc(100vh - var(--topbar-h));
  overflow-y: auto;
  padding: 28px 20px 28px 28px;
  border-right: 1px solid var(--border);
}
.sidebar .nav {
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: 1px;
}
.sidebar .nav a {
  display: block;
  padding: 7px 12px;
  border-radius: 6px;
  color: var(--text-sec);
  font-size: 14px;
  font-weight: 500;
}
.sidebar .nav a:hover {
  background: var(--bg-elev);
  color: var(--text);
  text-decoration: none;
}
.sidebar .nav a.active {
  background: rgba(234, 88, 12, 0.08);
  color: var(--accent);
  font-weight: 600;
}
:root[data-theme="dark"] .sidebar .nav a.active {
  background: rgba(251, 146, 60, 0.1);
}

/* main content */
.content {
  padding: 40px 56px 120px;
  min-width: 0;
}
.markdown {
  max-width: var(--content-max);
}

/* typography */
.markdown h1 {
  font-size: 32px;
  font-weight: 700;
  color: var(--text);
  margin: 0 0 8px;
  letter-spacing: -0.02em;
  line-height: 1.2;
}
.markdown h2 {
  font-size: 22px;
  font-weight: 700;
  color: var(--text);
  margin: 48px 0 14px;
  padding-top: 20px;
  border-top: 1px solid var(--border);
  letter-spacing: -0.01em;
}
.markdown h3 {
  font-size: 17px;
  font-weight: 600;
  color: var(--text);
  margin: 32px 0 10px;
}
.markdown h4 {
  font-size: 15px;
  font-weight: 600;
  color: var(--text);
  margin: 24px 0 8px;
}
.markdown p {
  color: var(--text);
  margin: 14px 0;
  font-size: 15px;
}
.markdown ul, .markdown ol {
  color: var(--text);
  margin: 14px 0 14px 22px;
  font-size: 15px;
}
.markdown li { margin: 6px 0; }
.markdown li p { margin: 6px 0; }

/* header anchor "¶" */
.markdown .headerlink {
  color: var(--text-muted);
  opacity: 0;
  margin-left: 8px;
  transition: opacity .15s;
  font-weight: 400;
  text-decoration: none;
}
.markdown h1:hover .headerlink,
.markdown h2:hover .headerlink,
.markdown h3:hover .headerlink,
.markdown h4:hover .headerlink { opacity: 1; }

/* inline code */
.markdown code {
  font-family: var(--font-mono);
  font-size: 13px;
  background: var(--inline-bg);
  border: 1px solid var(--code-border);
  border-radius: 4px;
  padding: 1px 6px;
  color: var(--text);
}

/* code blocks (codehilite wraps them in .highlight) */
.markdown .highlight,
.markdown pre {
  background: var(--code-bg);
  border: 1px solid var(--code-border);
  border-radius: 10px;
  padding: 14px 16px;
  margin: 18px 0;
  overflow-x: auto;
  box-shadow: var(--shadow);
}
.markdown .highlight pre,
.markdown pre {
  background: transparent;
  border: none;
  padding: 0;
  margin: 0;
  box-shadow: none;
}
.markdown .highlight pre code,
.markdown pre code {
  background: transparent;
  border: none;
  padding: 0;
  font-size: 13px;
  line-height: 1.6;
  color: var(--text);
}

/* tables */
.markdown table {
  border-collapse: collapse;
  margin: 20px 0;
  width: 100%;
  font-size: 14px;
}
.markdown th, .markdown td {
  text-align: left;
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
.markdown th {
  font-weight: 600;
  color: var(--text);
  background: var(--bg-alt);
  border-bottom: 2px solid var(--border);
}
.markdown td code {
  font-size: 12px;
}

/* blockquote */
.markdown blockquote {
  border-left: 3px solid var(--accent);
  background: var(--bg-alt);
  margin: 18px 0;
  padding: 12px 18px;
  color: var(--text-sec);
  border-radius: 0 8px 8px 0;
}
.markdown blockquote p:first-child { margin-top: 0; }
.markdown blockquote p:last-child  { margin-bottom: 0; }

/* horizontal rule */
.markdown hr {
  border: none;
  border-top: 1px solid var(--border);
  margin: 32px 0;
}

/* emphasis */
.markdown strong { font-weight: 600; color: var(--text); }
.markdown em { font-style: italic; }

/* responsive */
@media (max-width: 900px) {
  .layout { grid-template-columns: 1fr; }
  .sidebar {
    position: static;
    height: auto;
    border-right: none;
    border-bottom: 1px solid var(--border);
    padding: 16px 20px;
  }
  .content { padding: 24px 20px 80px; }
}

/* scrollbar styling (dark only — light uses system) */
:root[data-theme="dark"] ::-webkit-scrollbar { width: 10px; height: 10px; }
:root[data-theme="dark"] ::-webkit-scrollbar-track { background: var(--bg); }
:root[data-theme="dark"] ::-webkit-scrollbar-thumb {
  background: var(--border-h);
  border-radius: 5px;
}
"""


# Pygments classes for syntax highlighting — generated with:
#   from pygments.formatters import HtmlFormatter
#   HtmlFormatter(style='default').get_style_defs('.highlight')
# We embed two palettes and scope them with [data-theme] so they swap
# with the site theme toggle.
PYGMENTS_CSS = """
/* light palette — inspired by Pygments 'default' */
:root[data-theme="light"] .highlight .k  { color: #7c3aed; font-weight: 600; }  /* keyword */
:root[data-theme="light"] .highlight .kd { color: #7c3aed; }                     /* keyword.declaration */
:root[data-theme="light"] .highlight .kn { color: #7c3aed; }                     /* keyword.namespace */
:root[data-theme="light"] .highlight .kc { color: #7c3aed; }                     /* keyword.constant */
:root[data-theme="light"] .highlight .n  { color: #18181b; }                     /* name */
:root[data-theme="light"] .highlight .na { color: #0891b2; }                     /* name.attribute */
:root[data-theme="light"] .highlight .nb { color: #0891b2; }                     /* name.builtin */
:root[data-theme="light"] .highlight .nf { color: #c026d3; }                     /* name.function */
:root[data-theme="light"] .highlight .nc { color: #0891b2; font-weight: 600; }   /* name.class */
:root[data-theme="light"] .highlight .nt { color: #c026d3; }                     /* name.tag */
:root[data-theme="light"] .highlight .s  { color: #16a34a; }                     /* string */
:root[data-theme="light"] .highlight .s1 { color: #16a34a; }
:root[data-theme="light"] .highlight .s2 { color: #16a34a; }
:root[data-theme="light"] .highlight .sr { color: #16a34a; }
:root[data-theme="light"] .highlight .m  { color: #ea580c; }                     /* number */
:root[data-theme="light"] .highlight .mi { color: #ea580c; }
:root[data-theme="light"] .highlight .mf { color: #ea580c; }
:root[data-theme="light"] .highlight .mh { color: #ea580c; }                     /* hex */
:root[data-theme="light"] .highlight .c  { color: #71717a; font-style: italic; } /* comment */
:root[data-theme="light"] .highlight .c1 { color: #71717a; font-style: italic; }
:root[data-theme="light"] .highlight .cm { color: #71717a; font-style: italic; }
:root[data-theme="light"] .highlight .o  { color: #18181b; }                     /* operator */
:root[data-theme="light"] .highlight .p  { color: #52525b; }                     /* punctuation */
:root[data-theme="light"] .highlight .err{ color: #dc2626; }                     /* error */

/* dark palette — inspired by Pygments 'monokai' but tuned to our theme */
:root[data-theme="dark"] .highlight .k   { color: #c084fc; font-weight: 600; }
:root[data-theme="dark"] .highlight .kd  { color: #c084fc; }
:root[data-theme="dark"] .highlight .kn  { color: #c084fc; }
:root[data-theme="dark"] .highlight .kc  { color: #c084fc; }
:root[data-theme="dark"] .highlight .n   { color: #e8e8f0; }
:root[data-theme="dark"] .highlight .na  { color: #22d3ee; }
:root[data-theme="dark"] .highlight .nb  { color: #22d3ee; }
:root[data-theme="dark"] .highlight .nf  { color: #f472b6; }
:root[data-theme="dark"] .highlight .nc  { color: #22d3ee; font-weight: 600; }
:root[data-theme="dark"] .highlight .nt  { color: #f472b6; }
:root[data-theme="dark"] .highlight .s   { color: #4ade80; }
:root[data-theme="dark"] .highlight .s1  { color: #4ade80; }
:root[data-theme="dark"] .highlight .s2  { color: #4ade80; }
:root[data-theme="dark"] .highlight .sr  { color: #4ade80; }
:root[data-theme="dark"] .highlight .m   { color: #fb923c; }
:root[data-theme="dark"] .highlight .mi  { color: #fb923c; }
:root[data-theme="dark"] .highlight .mf  { color: #fb923c; }
:root[data-theme="dark"] .highlight .mh  { color: #fb923c; }
:root[data-theme="dark"] .highlight .c   { color: #5e5e78; font-style: italic; }
:root[data-theme="dark"] .highlight .c1  { color: #5e5e78; font-style: italic; }
:root[data-theme="dark"] .highlight .cm  { color: #5e5e78; font-style: italic; }
:root[data-theme="dark"] .highlight .o   { color: #e8e8f0; }
:root[data-theme="dark"] .highlight .p   { color: #9898b0; }
:root[data-theme="dark"] .highlight .err { color: #f87171; }
"""


if __name__ == "__main__":
    build()
