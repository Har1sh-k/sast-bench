"""Host-allowlist guard for outbound HTTP requests.

This module enforces that a URL's host is present in an explicit
allowlist before any network I/O occurs.  It is the primary mitigation
against SSRF in the clinical data-fetching path.
"""

from urllib.parse import urlparse

from config.settings import APPROVED_CLINICAL_HOSTS


class HostNotAllowedError(Exception):
    """Raised when a URL targets a host outside the allowlist."""


def enforce_host_allowlist(url: str) -> None:
    """Validate that *url* targets an approved clinical host.

    Raises
    ------
    HostNotAllowedError
        If the host component of *url* is not in the configured allowlist.
    ValueError
        If the URL cannot be parsed or has no hostname.
    """
    parsed = urlparse(url)

    if not parsed.hostname:
        raise ValueError(f"URL has no hostname: {url}")

    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme '{parsed.scheme}' in URL: {url}")

    if parsed.hostname not in APPROVED_CLINICAL_HOSTS:
        raise HostNotAllowedError(
            f"Host '{parsed.hostname}' is not in the approved clinical-host "
            f"allowlist.  Allowed hosts: {APPROVED_CLINICAL_HOSTS}"
        )
