"""Target-URL allowlist + scope guard (trust-&-safety boundary).

The platform is authorized to issue requests against exactly one target,
identified by its base URL. :class:`TargetAllowlist` is bound to that base URL
at construction and every outbound URL must be checked against it before use.

A URL is in scope only if it shares the base URL's scheme, host, and port
*exactly*. This deliberately rejects:

- a different host (obviously out of scope),
- a scheme downgrade (``http`` when the authorized scope is ``https``),
- a different port,
- subdomains of the authorized host (``evil.<host>`` is not ``<host>``),
- non-``http(s)`` schemes (``file://``, ``gopher://``, ...), and
- any URL that carries userinfo in its netloc (``user@host``), the classic
  SSRF host-confusion trick where the "real" host is smuggled into the
  userinfo component while the actual connection target is attacker
  controlled (or vice versa).

Host comparison is case-insensitive, per the DNS/URL host-matching rules.
"""

from __future__ import annotations

from urllib.parse import SplitResult, urlsplit

_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}


class OutOfScopeError(Exception):
    """Raised when a URL falls outside the authorized target scope."""


def _effective_port(parsed: SplitResult) -> int | None:
    """Return the explicit port, or the scheme's default port if unset."""

    if parsed.port is not None:
        return parsed.port
    return _DEFAULT_PORTS.get(parsed.scheme)


class TargetAllowlist:
    """Guard bound to a single authorized base URL.

    Only URLs matching the base URL's scheme, host, and port are considered
    in scope. Construct one guard per authorized target and use it to check
    every outbound URL before the platform issues a request.
    """

    def __init__(self, allowed_base_url: str) -> None:
        if not allowed_base_url:
            raise ValueError("allowed_base_url must not be empty")

        parsed = urlsplit(allowed_base_url)
        if not parsed.scheme:
            raise ValueError(
                f"allowed_base_url must include a scheme (e.g. 'https://'): "
                f"{allowed_base_url!r}"
            )
        if not parsed.hostname:
            raise ValueError(
                f"allowed_base_url must include a host: {allowed_base_url!r}"
            )

        self._base = parsed
        self._scheme = parsed.scheme.lower()
        self._host = parsed.hostname.lower()
        self._port = _effective_port(parsed)

    def is_allowed(self, url: str) -> bool:
        """Return True only if ``url`` matches the authorized scheme/host/port."""

        parsed = urlsplit(url)

        # Reject any URL carrying userinfo in the netloc (SSRF host-confusion).
        if parsed.username is not None or parsed.password is not None:
            return False

        if not parsed.scheme or not parsed.hostname:
            return False

        if parsed.scheme.lower() != self._scheme:
            return False

        if parsed.hostname.lower() != self._host:
            return False

        if _effective_port(parsed) != self._port:
            return False

        return True

    def check(self, url: str) -> str:
        """Return ``url`` unchanged if in scope; otherwise raise :class:`OutOfScopeError`."""

        if not self.is_allowed(url):
            raise OutOfScopeError(
                f"URL is out of scope for authorized target "
                f"{self._base.geturl()!r}: {url!r}"
            )
        return url
