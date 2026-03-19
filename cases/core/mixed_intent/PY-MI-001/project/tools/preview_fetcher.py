"""Preview / attachment fetcher — retrieves arbitrary preview URLs.

VULNERABLE: This tool accepts URLs directly from the agent planner
(which are ultimately sourced from LLM output) and issues an HTTP
request without any host-allowlist or scheme check.  An attacker who
can influence the model's output can redirect this fetch to internal
services (e.g. cloud metadata endpoints, internal APIs).
"""

import requests

from config.settings import MAX_PREVIEW_SIZE_BYTES, REQUEST_TIMEOUT, USER_AGENT


def fetch_preview(url: str) -> dict:                             # line 15
    """Fetch a preview or attachment from an arbitrary URL.

    No host validation is applied — the URL is passed directly to
    ``requests.get``.  This is the vulnerable code path.

    Parameters
    ----------
    url : str
        Any URL provided by the agent planner (model-controlled).

    Returns
    -------
    dict
        ``{"url", "status", "content_type", "size", "snippet"}``
        describing the fetched resource.
    """
    try:
        response = requests.get(                                 # line 33
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            stream=True,
        )
        response.raise_for_status()

        content = response.content[:MAX_PREVIEW_SIZE_BYTES]
        return {
            "url": url,
            "status": "ok",
            "content_type": response.headers.get("Content-Type", "unknown"),
            "size": len(content),
            "snippet": content[:300].decode("utf-8", errors="replace"),
        }                                                        # line 47
    except requests.RequestException as exc:
        return {
            "url": url,
            "status": "error",
            "content_type": None,
            "size": 0,
            "snippet": str(exc),
        }
