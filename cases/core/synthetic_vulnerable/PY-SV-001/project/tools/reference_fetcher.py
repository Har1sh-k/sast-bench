"""Reference fetcher tool — retrieves content from a URL.

VULNERABLE: This tool accepts arbitrary URLs from the agent planner
without enforcing a host allowlist or scheme restriction.
"""

import requests


def extract_title(html: str) -> str:
    """Extract a rough title from HTML content."""
    start = html.find("<title>")
    end = html.find("</title>")
    if start != -1 and end != -1:
        return html[start + 7 : end].strip()
    return "Untitled"


def fetch_reference(url: str) -> dict:                          # line 15
    """Fetch a reference URL and return metadata.

    This function receives URLs directly from the agent planner,
    which are ultimately sourced from model output. There is no
    validation on the target host or URL scheme before the request
    is made.

    A host allowlist (e.g., restricting to pubmed.ncbi.nlm.nih.gov,
    api.semanticscholar.org) would prevent SSRF here but is missing.
    """
    try:
        response = requests.get(url, timeout=10)                # line 27
        response.raise_for_status()
        title = extract_title(response.text)
        return {
            "url": url,
            "status": "ok",
            "title": title,
        }                                                       # line 34
    except requests.RequestException as exc:
        return {
            "url": url,
            "status": "error",
            "title": str(exc),
        }
