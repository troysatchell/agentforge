"""Frozen tests (T1 / TRO-122) — Target-URL allowlist + scope guard.

Trust-&-safety boundary: the platform may only issue requests to the sanctioned
target. The guard matches scheme + host + port against the authorized base URL and
rejects everything else, including SSRF host-confusion tricks (userinfo in netloc)
and scheme downgrades. These tests are the frozen contract for the ticket.
"""

from __future__ import annotations

import pytest

from agentforge.target.allowlist import OutOfScopeError, TargetAllowlist

BASE = "https://openemr-production-4eba.up.railway.app"


def test_same_origin_url_is_allowed():
    guard = TargetAllowlist(BASE)
    url = f"{BASE}/apis/default/api/copilot/turn"
    assert guard.is_allowed(url) is True
    assert guard.check(url) == url  # check() returns the url unchanged when allowed


def test_exact_base_url_is_allowed():
    guard = TargetAllowlist(BASE)
    assert guard.is_allowed(BASE) is True


def test_different_host_is_rejected():
    guard = TargetAllowlist(BASE)
    assert guard.is_allowed("https://evil.example.com/apis/default/api/copilot/turn") is False
    with pytest.raises(OutOfScopeError):
        guard.check("https://evil.example.com/apis/default/api/copilot/turn")


def test_scheme_downgrade_is_rejected():
    guard = TargetAllowlist(BASE)
    # http where the authorized scope is https must never be allowed
    assert guard.is_allowed(f"http://openemr-production-4eba.up.railway.app/x") is False
    with pytest.raises(OutOfScopeError):
        guard.check("http://openemr-production-4eba.up.railway.app/x")


def test_different_port_is_rejected():
    guard = TargetAllowlist(BASE)
    assert guard.is_allowed("https://openemr-production-4eba.up.railway.app:8443/x") is False


def test_userinfo_host_confusion_is_rejected():
    guard = TargetAllowlist(BASE)
    # Classic SSRF trick: real host in userinfo, attacker host as the actual netloc host.
    assert guard.is_allowed("https://openemr-production-4eba.up.railway.app@evil.com/x") is False
    # And the reverse: attacker userinfo, real host — reject any URL carrying userinfo at all.
    assert guard.is_allowed("https://evil.com@openemr-production-4eba.up.railway.app/x") is False


def test_subdomain_is_not_the_same_host():
    guard = TargetAllowlist(BASE)
    assert guard.is_allowed("https://evil.openemr-production-4eba.up.railway.app/x") is False


def test_host_match_is_case_insensitive():
    guard = TargetAllowlist(BASE)
    assert guard.is_allowed("https://OPENEMR-PRODUCTION-4EBA.UP.RAILWAY.APP/x") is True


def test_out_of_scope_error_names_the_offending_url():
    guard = TargetAllowlist(BASE)
    bad = "https://evil.example.com/x"
    with pytest.raises(OutOfScopeError) as exc:
        guard.check(bad)
    assert "evil.example.com" in str(exc.value)


def test_out_of_scope_error_is_an_exception_subclass():
    assert issubclass(OutOfScopeError, Exception)


def test_empty_base_url_is_rejected_at_construction():
    with pytest.raises(ValueError):
        TargetAllowlist("")


def test_base_url_without_scheme_is_rejected_at_construction():
    with pytest.raises(ValueError):
        TargetAllowlist("openemr-production-4eba.up.railway.app")


def test_non_http_url_is_rejected():
    guard = TargetAllowlist(BASE)
    # file:// / gopher:// etc. must never be considered in-scope
    assert guard.is_allowed("file:///etc/passwd") is False


def test_malformed_url_fails_closed_as_out_of_scope():
    guard = TargetAllowlist(BASE)
    # Parser-level garbage (e.g. a malformed IPv6 literal) must fail CLOSED as
    # out-of-scope — never leak a raw ValueError out of the guard's contract.
    assert guard.is_allowed("https://[::1/x") is False
    with pytest.raises(OutOfScopeError):
        guard.check("https://[::1/x")
