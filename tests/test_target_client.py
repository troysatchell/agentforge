"""Frozen tests (T2 / TRO-134) — TargetClient: execute attacks + token exchange.

The client reaches the live target over its guarded HTTP surface. Two jobs:
(1) the confidential SMART code→token exchange (mirrors the server-side
``launch-exchange.php``) that mints the launch-bound access token, and
(2) executing an attack ``input_sequence`` against the copilot routes with that
token. Every outbound URL is gated by the T1 allowlist. The HTTP transport is
INJECTED, so these tests never touch the network — the live transport is wired
in a later ticket. These tests are the frozen contract for the ticket.
"""

from __future__ import annotations

import pytest

from agentforge.contracts.result import InputTurn, TargetResponse
from agentforge.target.allowlist import OutOfScopeError, TargetAllowlist
from agentforge.target.client import TargetClient, TargetClientError

BASE = "https://openemr-production-4eba.up.railway.app"
TOKEN_URL = f"{BASE}/oauth2/default/token"


class FakeTransport:
    """Records each call; returns preset (status, body) tuples in order.

    Signature the client must call it with:
    ``transport(method: str, url: str, headers: dict, body) -> tuple[int, dict|str]``.
    """

    def __init__(self, responses=None, raises=False):
        self.responses = responses if responses is not None else [(200, {"reply": "ok"})]
        self.raises = raises
        self.calls = []
        self._i = 0

    def __call__(self, method, url, headers, body):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body})
        if self.raises:
            raise ConnectionError("network down")
        resp = self.responses[min(self._i, len(self.responses) - 1)]
        self._i += 1
        return resp


def _client(transport, **kw):
    params = dict(base_url=BASE, allowlist=TargetAllowlist(BASE), transport=transport)
    params.update(kw)
    return TargetClient(**params)


# --- execute() ---------------------------------------------------------------

def test_execute_issues_turn_with_bearer_token_and_returns_response():
    t = FakeTransport([(200, {"reply": "hello"})])
    seq = [InputTurn(turn_index=0, route="POST /apis/default/api/copilot/turn", payload={"message": "hi"})]
    resp = _client(t).execute(access_token="tok-123", input_sequence=seq)
    assert isinstance(resp, TargetResponse)
    assert resp.http_status == 200
    call = t.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == f"{BASE}/apis/default/api/copilot/turn"
    assert call["headers"].get("Authorization") == "Bearer tok-123"
    assert call["body"] == {"message": "hi"}


def test_execute_returns_final_turn_response_for_multiturn():
    t = FakeTransport([(200, {"a": 1}), (403, {"b": 2})])
    seq = [
        InputTurn(turn_index=0, route="POST /apis/default/api/copilot/turn", payload={}),
        InputTurn(turn_index=1, route="POST /apis/default/api/copilot/turn", payload={}),
    ]
    resp = _client(t).execute(access_token="t", input_sequence=seq)
    assert len(t.calls) == 2
    assert resp.http_status == 403
    assert resp.body == {"b": 2}


def test_execute_rejects_off_target_absolute_route():
    t = FakeTransport()
    seq = [InputTurn(turn_index=0, route="GET https://evil.example.com/steal", payload={})]
    with pytest.raises(OutOfScopeError):
        _client(t).execute(access_token="t", input_sequence=seq)
    assert t.calls == []  # never issued a request to the off-target host


def test_execute_empty_sequence_raises_value_error():
    with pytest.raises(ValueError):
        _client(FakeTransport()).execute(access_token="t", input_sequence=[])


def test_execute_wraps_transport_failure_in_target_client_error():
    t = FakeTransport(raises=True)
    seq = [InputTurn(turn_index=0, route="POST /apis/default/api/copilot/turn", payload={})]
    with pytest.raises(TargetClientError):
        _client(t).execute(access_token="t", input_sequence=seq)


# --- exchange_code() ---------------------------------------------------------

def test_exchange_code_returns_access_token_and_patient():
    t = FakeTransport([(200, {"access_token": "launch-bound-xyz", "patient": "patient-uuid-123"})])
    token, patient = _client(t).exchange_code(
        token_url=TOKEN_URL, code="code-1", state="s", verifier="verifier-1",
        redirect_uri=f"{BASE}/cb", client_id="cid", client_secret="csecret",
    )
    assert token == "launch-bound-xyz"
    assert patient == "patient-uuid-123"
    call = t.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == TOKEN_URL
    body = call["body"]
    assert body.get("grant_type") == "authorization_code"
    assert body.get("code") == "code-1"
    assert body.get("code_verifier") == "verifier-1"
    assert body.get("client_id") == "cid"


def test_exchange_code_missing_token_raises():
    t = FakeTransport([(400, {"error": "invalid_grant"})])
    with pytest.raises(TargetClientError):
        _client(t).exchange_code(
            token_url=TOKEN_URL, code="c", state="s", verifier="v",
            redirect_uri=f"{BASE}/cb", client_id="cid", client_secret="cs",
        )


def test_exchange_code_enforces_allowlist_on_token_url():
    t = FakeTransport([(200, {"access_token": "x"})])
    with pytest.raises(OutOfScopeError):
        _client(t).exchange_code(
            token_url="https://evil.example.com/token", code="c", state="s", verifier="v",
            redirect_uri="https://evil.example.com/cb", client_id="cid", client_secret="cs",
        )
    assert t.calls == []


def test_target_client_error_is_exception_subclass():
    assert issubclass(TargetClientError, Exception)
