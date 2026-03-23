"""Clinical data fetcher — retrieves information from approved medical sources.

SAFE: Every request is gated by the host-allowlist guard before any
network I/O takes place.  Only pre-approved clinical hosts (e.g.
PubMed, ClinicalTrials.gov, FDA) will be contacted.
"""

import requests

from config.settings import REQUEST_TIMEOUT, USER_AGENT
from guards.host_policy import HostNotAllowedError, enforce_host_allowlist


def fetch_clinical_data(url: str) -> dict:                       # line 14
    """Fetch structured clinical data from an approved source.

    The host-allowlist guard is applied **before** the HTTP request is
    issued, ensuring that only URLs targeting known medical data
    providers are reachable.

    Parameters
    ----------
    url : str
        A URL pointing to a clinical data API (must be on the allowlist).

    Returns
    -------
    dict
        ``{"url", "status", "snippet"}`` describing the outcome.
    """
    try:
        enforce_host_allowlist(url)                              # guard ✓
    except (HostNotAllowedError, ValueError) as exc:
        return {
            "url": url,
            "status": "blocked",
            "snippet": str(exc),
        }

    try:
        response = requests.get(                                 # line 38
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        response.raise_for_status()
        return {
            "url": url,
            "status": "ok",
            "snippet": response.text[:500],
        }                                                        # line 47
    except requests.RequestException as exc:
        return {
            "url": url,
            "status": "error",
            "snippet": str(exc),
        }
