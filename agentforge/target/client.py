"""TargetClient (T2 / TRO-134) — execute attack turns + confidential token exchange.

Two jobs against the live target, both over a guarded HTTP surface:

1. ``exchange_code`` mirrors the server-side confidential SMART code→token
   exchange (see the target repo's ``oe-module-copilot/public/launch-exchange.php``):
   a ``grant_type=authorization_code`` POST to the token endpoint that mints the
   launch-bound access token.
2. ``execute`` runs a multi-turn attack ``input_sequence`` against the copilot
   routes using that token, returning the final turn's response.

Every outbound URL — whether resolved from a relative route or passed in
directly as a token endpoint — is checked against the T1 :class:`TargetAllowlist`
before anything is sent. The HTTP transport is INJECTED (``transport(method,
url, headers, body) -> tuple[int, dict|str]``); this client never imports
``requests``/``httpx`` or otherwise does its own networking, so it can be
exercised in tests without touching the network. The real transport is wired
up in a later ticket.
"""

from __future__ import annotations

from typing import Any, Callable

from agentforge.contracts.result import InputTurn, TargetResponse
from agentforge.target.allowlist import TargetAllowlist

Transport = Callable[[str, str, dict[str, Any], Any], tuple[int, Any]]


class TargetClientError(Exception):
    """Raised when the target transport fails or returns an unusable response."""


class TargetClient:
    """Executes attack turns and confidential token exchanges against one target."""

    def __init__(
        self,
        *,
        base_url: str,
        allowlist: TargetAllowlist,
        transport: Transport,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._allowlist = allowlist
        self._transport = transport

    def _resolve_route(self, route: str) -> tuple[str, str]:
        """Split an ``InputTurn.route`` into (method, url).

        ``route`` is either ``"METHOD /path"`` (resolved against ``base_url``)
        or ``"METHOD https://absolute/url"`` (used as-is).
        """
        method, _, target = route.partition(" ")
        method = method.strip().upper()
        target = target.strip()
        if target.startswith("http://") or target.startswith("https://"):
            url = target
        else:
            url = f"{self._base_url}{target if target.startswith('/') else '/' + target}"
        return method, url

    def execute(self, *, access_token: str, input_sequence: list[InputTurn]) -> TargetResponse:
        """Issue each turn in order and return a response built from the last one."""
        if not input_sequence:
            raise ValueError("input_sequence must not be empty")

        status: int
        body: Any
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        for turn in input_sequence:
            method, url = self._resolve_route(turn.route)
            self._allowlist.check(url)
            try:
                status, body = self._transport(method, url, headers, turn.payload)
            except Exception as exc:  # noqa: BLE001 - deliberately wrap any transport failure
                raise TargetClientError(f"transport failed for {method} {url}: {exc}") from exc

        return TargetResponse(http_status=status, body=body)

    def exchange_code(
        self,
        *,
        token_url: str,
        code: str,
        state: str,
        verifier: str,
        redirect_uri: str,
        client_id: str,
        client_secret: str,
    ) -> tuple[str, str | None]:
        """Confidential authorization_code→token exchange; returns (access_token, patient)."""
        # `state` is intentionally unused here: this client is the sole holder of
        # {code, state} in a driver-controlled harness (no browser-mediated redirect
        # to defend), so the state<->session replay/CSRF binding stays the server's
        # job (launch-exchange.php: SmartLaunchSession::consume). Kept in the
        # signature to mirror the server contract, NOT a dropped security check.
        self._allowlist.check(token_url)

        body = {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        try:
            status, resp_body = self._transport("POST", token_url, headers, body)
        except Exception as exc:  # noqa: BLE001 - deliberately wrap any transport failure
            raise TargetClientError(f"transport failed for POST {token_url}: {exc}") from exc

        if not isinstance(resp_body, dict):
            raise TargetClientError(f"token endpoint returned a non-JSON body: {resp_body!r}")

        if not (200 <= status < 300):
            raise TargetClientError(
                f"token endpoint returned HTTP {status}: {resp_body!r}"
            )

        access_token = resp_body.get("access_token")
        if not access_token:
            raise TargetClientError(f"token endpoint response is missing access_token: {resp_body!r}")

        patient = resp_body.get("patient")
        return access_token, patient
