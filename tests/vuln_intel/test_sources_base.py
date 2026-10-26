"""Connector foundations: rate limiting, retries, redirects, and size caps."""
from __future__ import annotations

import httpx
import pytest

from core.vuln_intel.sources.base import (
    Cursor,
    HttpClient,
    RateLimiter,
    ResponseTooLargeError,
    RetryPolicy,
    SourceHTTPError,
    SourceMetadata,
    SourceParseError,
    SourceUnavailableError,
)


def _metadata(**overrides) -> SourceMetadata:
    data = {
        "source_id": "test",
        "name": "Test",
        "base_url": "https://good.test",
        "rate_limit_requests": 1000,
        "rate_limit_period_seconds": 0.0,
    }
    data.update(overrides)
    return SourceMetadata(**data)


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    )


def test_source_metadata_derives_allowed_host():
    metadata = _metadata()
    assert metadata.allowed_hosts == ("good.test",)


def test_cursor_round_trip():
    cursor = Cursor(start_index=40, page=2, token="abc")
    assert Cursor.from_dict(cursor.to_dict()) == cursor
    assert Cursor.from_dict(None) == Cursor()


def test_retry_policy_backoff_and_retry_after():
    policy = RetryPolicy(max_attempts=3, base_delay=1.0, max_delay=10.0, jitter=0.0)
    assert policy.delay_for(1) == 1.0
    assert policy.delay_for(2) == 2.0
    assert policy.delay_for(3) == 4.0
    assert policy.delay_for(3, retry_after=1.5) == 1.5
    assert policy.delay_for(3, retry_after=1000) == 10.0
    assert policy.should_retry_status(429) is True
    assert policy.should_retry_status(503) is True
    assert policy.should_retry_status(404) is False


@pytest.mark.asyncio
async def test_rate_limiter_spaces_requests():
    now = [0.0]
    sleeps = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)
        now[0] += seconds

    limiter = RateLimiter(2, 10.0, clock=lambda: now[0], sleep=fake_sleep)
    await limiter.acquire()
    now[0] = 1.0
    await limiter.acquire()
    assert sleeps == [4.0]
    assert limiter.sleeps == [4.0]


@pytest.mark.asyncio
async def test_http_client_returns_json():
    async def handler(request):
        return httpx.Response(200, json={"ok": True})

    client = _client(handler)
    http = HttpClient(
        _metadata(),
        client=client,
        rate_limiter=RateLimiter(1000, 0.0),
        retry_policy=RetryPolicy(max_attempts=1),
    )
    try:
        assert await http.get_json("https://good.test/data") == {"ok": True}
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_http_client_retries_429_then_succeeds():
    calls = []

    async def handler(request):
        calls.append(request.url)
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        return httpx.Response(200, json={"ok": True})

    client = _client(handler)
    http = HttpClient(
        _metadata(),
        client=client,
        rate_limiter=RateLimiter(1000, 0.0),
        retry_policy=RetryPolicy(max_attempts=2, base_delay=0.0, jitter=0.0),
    )
    try:
        assert await http.get_json("https://good.test/data") == {"ok": True}
        assert len(calls) == 2
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_http_client_gives_up_after_retry_budget():
    async def handler(request):
        return httpx.Response(500)

    client = _client(handler)
    http = HttpClient(
        _metadata(),
        client=client,
        rate_limiter=RateLimiter(1000, 0.0),
        retry_policy=RetryPolicy(max_attempts=2, base_delay=0.0, jitter=0.0),
    )
    try:
        with pytest.raises(SourceUnavailableError):
            await http.get_json("https://good.test/data")
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_http_client_does_not_retry_404():
    async def handler(request):
        return httpx.Response(404)

    client = _client(handler)
    http = HttpClient(
        _metadata(),
        client=client,
        rate_limiter=RateLimiter(1000, 0.0),
        retry_policy=RetryPolicy(max_attempts=3, base_delay=0.0, jitter=0.0),
    )
    try:
        with pytest.raises(SourceHTTPError) as exc:
            await http.get_json("https://good.test/missing")
        assert exc.value.status == 404
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_http_client_rejects_redirect_to_disallowed_host():
    calls = []

    async def handler(request):
        calls.append(str(request.url))
        if request.url.host == "good.test":
            return httpx.Response(302, headers={"Location": "https://evil.test/data"})
        return httpx.Response(200, json={"ok": True})

    client = _client(handler)
    http = HttpClient(
        _metadata(),
        client=client,
        rate_limiter=RateLimiter(1000, 0.0),
        retry_policy=RetryPolicy(max_attempts=1),
    )
    try:
        with pytest.raises(SourceHTTPError) as exc:
            await http.get_json("https://good.test/data")
        assert "disallowed host" in str(exc.value)
        assert any("evil.test" in call for call in calls)
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_http_client_rejects_oversized_response():
    async def handler(request):
        return httpx.Response(200, content=b'{"data": "' + b"x" * 100 + b'"}')

    client = _client(handler)
    http = HttpClient(
        _metadata(),
        client=client,
        max_bytes=10,
        rate_limiter=RateLimiter(1000, 0.0),
        retry_policy=RetryPolicy(max_attempts=1),
    )
    try:
        with pytest.raises(ResponseTooLargeError):
            await http.get_json("https://good.test/data")
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_http_client_rejects_invalid_json():
    async def handler(request):
        return httpx.Response(200, text="not json")

    client = _client(handler)
    http = HttpClient(
        _metadata(),
        client=client,
        rate_limiter=RateLimiter(1000, 0.0),
        retry_policy=RetryPolicy(max_attempts=1),
    )
    try:
        with pytest.raises(SourceParseError):
            await http.get_json("https://good.test/data")
    finally:
        await client.aclose()
