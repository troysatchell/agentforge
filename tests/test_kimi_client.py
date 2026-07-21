"""Frozen tests (T3 / TRO-135) — Kimi client (Moonshot OpenAI-compatible).

A thin client over Moonshot's ``/chat/completions``. The HTTP transport is
INJECTED so these tests never touch the network: a fake transport records the
request and returns a canned OpenAI-shaped response. These tests are the frozen
contract for the ticket.
"""

from __future__ import annotations

import pytest

from agentforge.redteam.kimi_client import KimiClient, KimiError

BASE = "https://api.moonshot.ai/v1"


class RecordingTransport:
    """Fake transport: records the last call, returns a preset response.

    Signature matches what KimiClient must call it with:
    ``transport(url: str, headers: dict, json_body: dict) -> dict`` (parsed JSON).
    """

    def __init__(self, response):
        self.response = response
        self.url = None
        self.headers = None
        self.body = None
        self.calls = 0

    def __call__(self, url, headers, json_body):
        self.calls += 1
        self.url = url
        self.headers = headers
        self.body = json_body
        return self.response


def _ok(content="ATTACK_SPEC"):
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}


def _client(transport, **kw):
    params = dict(api_key="sk-moonshot-test", base_url=BASE, model="kimi-k2.6", transport=transport)
    params.update(kw)
    return KimiClient(**params)


def test_complete_posts_to_chat_completions_endpoint():
    t = RecordingTransport(_ok())
    _client(t).complete(system="you are a pentester", user="probe the target")
    assert t.url == f"{BASE}/chat/completions"
    assert t.calls == 1


def test_authorization_header_is_bearer_api_key():
    t = RecordingTransport(_ok())
    _client(t).complete(system="s", user="u")
    auth = t.headers.get("Authorization")
    assert auth == "Bearer sk-moonshot-test"


def test_request_body_carries_model_and_ordered_messages():
    t = RecordingTransport(_ok())
    _client(t).complete(system="SYS", user="USR")
    assert t.body["model"] == "kimi-k2.6"
    assert t.body["messages"] == [
        {"role": "system", "content": "SYS"},
        {"role": "user", "content": "USR"},
    ]


def test_complete_returns_assistant_message_content():
    t = RecordingTransport(_ok(content="hello-from-kimi"))
    out = _client(t).complete(system="s", user="u")
    assert out == "hello-from-kimi"


def test_response_format_is_included_when_provided_and_absent_otherwise():
    t1 = RecordingTransport(_ok())
    _client(t1).complete(system="s", user="u", response_format={"type": "json_object"})
    assert t1.body.get("response_format") == {"type": "json_object"}

    t2 = RecordingTransport(_ok())
    _client(t2).complete(system="s", user="u")
    assert "response_format" not in t2.body


def test_temperature_is_forwarded_when_provided():
    t = RecordingTransport(_ok())
    _client(t).complete(system="s", user="u", temperature=0.9)
    assert t.body.get("temperature") == 0.9


def test_base_url_trailing_slash_is_normalized():
    t = RecordingTransport(_ok())
    _client(t, base_url=BASE + "/").complete(system="s", user="u")
    assert t.url == f"{BASE}/chat/completions"  # no double slash


def test_empty_api_key_is_rejected_at_construction():
    t = RecordingTransport(_ok())
    with pytest.raises(ValueError):
        _client(t, api_key="")


def test_error_response_shape_raises_kimi_error():
    t = RecordingTransport({"error": {"message": "rate limited", "type": "rate_limit"}})
    with pytest.raises(KimiError):
        _client(t).complete(system="s", user="u")


def test_missing_choices_raises_kimi_error():
    t = RecordingTransport({"id": "x", "object": "chat.completion"})
    with pytest.raises(KimiError):
        _client(t).complete(system="s", user="u")


def test_kimi_error_is_an_exception_subclass():
    assert issubclass(KimiError, Exception)
