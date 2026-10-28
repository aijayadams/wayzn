"""Stale detection, self-healing and auth/stream recovery (2026-10-24 incident)."""

import logging
import threading
import types

import pytest
import requests
import urllib3

from custom_components.wayzn import coordinator as coord_mod
from custom_components.wayzn.coordinator import (
    CLOUD_TIMESTAMP_STALE_THRESHOLD,
    STALE_RECOVERY_DELAYS_S,
    STALE_STATUS_LOG_INTERVAL_S,
    STREAM_STALE_THRESHOLD,
    WayznDataUpdateCoordinator,
)
from custom_components.wayzn.wayzn_client import wayzn_core as core

ENTRY_DATA = {
    "email": "dog@example.com",
    "password": "not-a-real-password",
    "api_key": "fake-key",
    "device_id": "dev1",
    "label": "Dog Door",
}


class FakeAuth:
    """Fake Firebase sign-in: counts calls, can be told to fail."""

    def __init__(self, clock):
        self.clock = clock
        self.calls = 0
        self.fail_with = None

    def __call__(self, email, password, api_key, timeout=20):
        self.calls += 1
        if self.fail_with is not None:
            raise self.fail_with
        return {"idToken": f"token-{self.calls}", "expiresIn": "3600"}


@pytest.fixture
def auth(monkeypatch, clock):
    fake = FakeAuth(clock)
    monkeypatch.setattr(core, "fb_sign_in_email_password", fake)
    return fake


@pytest.fixture
def node(monkeypatch, clock):
    """The Firebase tokens node the poll reads; the test sets its TimeStamp."""
    state = {"ControlState": 15, "TimeStamp": clock.time()}
    monkeypatch.setattr(core, "db_get", lambda db, path, token: dict(state))
    return state


@pytest.fixture
def coordinator(hass, clock, auth):
    entry = types.SimpleNamespace(data=dict(ENTRY_DATA))
    c = WayznDataUpdateCoordinator(hass, entry)
    c.restarts = 0

    async def fake_restart():
        c.restarts += 1

    c._async_restart_streaming = fake_restart
    return c


def _healthy_stream(c, clock):
    c._stream_healthy = True
    c._last_stream_event = clock.monotonic()


# --------------------------------------------------------------------------
# Stale (door stopped reporting) -> self-heal attempts -> recover
# --------------------------------------------------------------------------

def test_idle_door_with_fresh_heartbeat_is_not_stale(coordinator, clock, node, run):
    for _ in range(60):  # 10 minutes of 10s polls, door idle, heartbeat fresh
        clock.advance(10)
        node["TimeStamp"] = clock.time() - 5
        _healthy_stream(coordinator, clock)
        run(coordinator.async_refresh())
    assert coordinator.last_update_success and not coordinator.stale


def test_frozen_timestamp_goes_stale_then_recovers(coordinator, hass, clock, node, auth, run, caplog):
    caplog.set_level(logging.INFO)
    frozen = clock.time()
    node["TimeStamp"] = frozen

    # Polls keep succeeding while the door's heartbeat is frozen.
    while clock.time() - frozen <= CLOUD_TIMESTAMP_STALE_THRESHOLD:
        clock.advance(10)
        _healthy_stream(coordinator, clock)
        run(coordinator.async_refresh())
    assert coordinator.stale
    assert coordinator.last_update_success  # our link is fine
    assert "the Wayzn cloud stopped updating" in caplog.text
    assert "this poll succeeded and the stream is alive" in caplog.text

    # Entering stale schedules a recovery attempt at once: forced sign-in
    # (paced: a sign-in happened <5 min ago, so the cached token is reused),
    # stream restart, refresh.
    run(hass.run_tasks())
    assert coordinator.restarts == 1
    assert coordinator._stale_recovery_attempts == 1
    assert "WAYZN STALE RECOVERY attempt #1" in caplog.text

    # Three hours of frozen heartbeat: attempts follow the ladder, a status
    # line is logged every STALE_STATUS_LOG_INTERVAL_S, sign-ins stay rare.
    sign_ins_before = auth.calls
    for _ in range(3 * 360):
        clock.advance(10)
        _healthy_stream(coordinator, clock)
        run(coordinator.async_refresh())
        run(hass.run_tasks())
    attempts = coordinator._stale_recovery_attempts
    # 0, +5m, +10m, +20m, +40m, +60m, +60m... within 3h -> 6 attempts after the first
    assert 6 <= attempts <= 8
    assert auth.calls - sign_ins_before <= attempts
    assert caplog.text.count("WAYZN STILL STALE") >= (3 * 3600) // STALE_STATUS_LOG_INTERVAL_S - 1
    assert coordinator.stale

    # The door reports again: recovered on the next poll, notification cleared.
    clock.advance(10)
    node["TimeStamp"] = clock.time()
    run(coordinator.async_refresh())
    assert not coordinator.stale
    assert "WAYZN STALE RECOVERED after 3h" in caplog.text
    run(hass.run_tasks())
    assert ("persistent_notification", "dismiss", {"notification_id": "wayzn_stale_state"}) in hass.service_calls


def test_stream_down_alone_does_not_mark_fresh_polls_stale(coordinator, clock, node, run):
    node["TimeStamp"] = clock.time()
    coordinator._stream_healthy = False
    coordinator._last_stream_event = 0.0
    clock.advance(10)
    node["TimeStamp"] = clock.time()
    run(coordinator.async_refresh())
    assert not coordinator.stale


def test_stream_shows_fresher_timestamp_than_poll_is_called_out(coordinator, hass, clock, node, run, caplog):
    frozen = clock.time()
    node["TimeStamp"] = frozen
    clock.advance(CLOUD_TIMESTAMP_STALE_THRESHOLD + 10)
    coordinator._last_sse_cloud_ts = clock.time() - 5  # stream says the door is alive
    _healthy_stream(coordinator, clock)
    run(coordinator.async_refresh())
    assert coordinator.stale  # poll stays authoritative
    assert "WAYZN SOURCE DISAGREEMENT" in caplog.text


def test_sse_timestamp_extraction():
    ev = core.SSEEvent("patch", "/", {"TimeStamp": 1792514908000, "Mask": [1]})
    assert WayznDataUpdateCoordinator._extract_timestamp_from_event(ev) == 1792514908.0
    ev = core.SSEEvent("put", "/TimeStamp", 1792514908)
    assert WayznDataUpdateCoordinator._extract_timestamp_from_event(ev) == 1792514908.0
    ev = core.SSEEvent("patch", "/ControlState", 15)
    assert WayznDataUpdateCoordinator._extract_timestamp_from_event(ev) is None


# --------------------------------------------------------------------------
# Stream watchdog: silent-but-open stream, dead thread
# --------------------------------------------------------------------------

def test_watchdog_restarts_silent_stream(coordinator, hass, clock, node, run, caplog):
    _healthy_stream(coordinator, clock)
    clock.advance(STREAM_STALE_THRESHOLD + 5)  # keep-alives stopped, TCP still "open"
    node["TimeStamp"] = clock.time()
    run(coordinator.async_refresh())
    run(hass.run_tasks())
    assert coordinator.restarts == 1
    assert "stream stale (no events in" in caplog.text
    assert not coordinator.stale  # fresh polls: honest data, just slower


def test_watchdog_restarts_dead_thread_even_when_poll_fails(coordinator, hass, clock, monkeypatch, run, caplog):
    dead = threading.Thread(target=lambda: None)
    dead.start()
    dead.join()
    coordinator._stream_thread = dead
    coordinator._stream_stop = threading.Event()  # not asked to stop

    def boom(*a):
        raise requests.exceptions.ConnectionError("network down")

    monkeypatch.setattr(core, "db_get", boom)
    run(coordinator.async_refresh())
    run(hass.run_tasks())
    assert not coordinator.last_update_success
    assert coordinator.restarts == 1
    assert "thread exited unexpectedly" in caplog.text


def test_watchdog_backs_off_after_three_restarts_but_keeps_polling_fast(coordinator, hass, clock, node, run):
    for i in range(5):
        _healthy_stream(coordinator, clock)
        clock.advance(STREAM_STALE_THRESHOLD + 5)
        node["TimeStamp"] = clock.time()
        run(coordinator.async_refresh())
        run(hass.run_tasks())
    assert coordinator.restarts == 3
    delayed = [h for h in hass.loop.later if not h.cancelled]
    assert delayed and delayed[-1].delay == STREAM_STALE_THRESHOLD * 2
    assert coordinator.update_interval.total_seconds() == coord_mod.FALLBACK_POLL_INTERVAL


# --------------------------------------------------------------------------
# Token expiry, refresh, failures
# --------------------------------------------------------------------------

def _token(c):
    return c._get_cached_or_fresh_token("e", "p", "k")


def test_token_cached_until_expiry_then_refreshed(coordinator, clock, auth, caplog):
    caplog.set_level(logging.INFO)
    assert _token(coordinator) == "token-1"
    clock.advance(3000)
    assert _token(coordinator) == "token-1"  # still valid
    clock.advance(600)  # past expiresIn - 60s
    assert _token(coordinator) == "token-2"
    assert auth.calls == 2
    assert "Firebase sign-in OK" in caplog.text


def test_failed_refresh_is_logged_and_backed_off(coordinator, clock, auth, caplog):
    _token(coordinator)
    clock.advance(3600)  # expired
    auth.fail_with = requests.exceptions.ConnectTimeout("timed out")
    with pytest.raises(core.WayznError):
        _token(coordinator)
    assert "Firebase sign-in failed (1 in a row)" in caplog.text
    # Within the 30s failure backoff no new sign-in is attempted (old token returned)
    clock.advance(10)
    assert _token(coordinator) == "token-1"
    assert auth.calls == 2
    # After the backoff it retries, and recovery is logged
    clock.advance(25)
    auth.fail_with = None
    assert _token(coordinator) == "token-3"
    assert "Firebase sign-in recovered after 1 failure(s)" in caplog.text


def test_failure_backoff_grows_and_caps(coordinator, clock, auth):
    auth.fail_with = requests.exceptions.ConnectionError("down")
    attempts_at = []
    for _ in range(200):  # 2000s of 10s polls
        before = auth.calls
        try:
            _token(coordinator)
        except core.WayznError:
            pass
        if auth.calls != before:
            attempts_at.append(clock.monotonic())
        clock.advance(10)
    gaps = [b - a for a, b in zip(attempts_at, attempts_at[1:])]
    assert gaps[:4] == [30, 60, 120, 240]
    assert all(g == 300 for g in gaps[4:])


def test_transient_signin_error_is_update_failed_not_reauth(coordinator, auth, node, run):
    auth.fail_with = core.WayznError("Firebase login failed (HTTP 503): UNAVAILABLE")
    run(coordinator.async_refresh())  # UpdateFailed is swallowed by the stub
    assert not coordinator.last_update_success


def test_bad_credentials_raise_reauth(coordinator, auth, node, run):
    from homeassistant.exceptions import ConfigEntryAuthFailed

    auth.fail_with = core.WayznAuthError("Firebase rejected the credentials: INVALID_PASSWORD")
    with pytest.raises(ConfigEntryAuthFailed):
        run(coordinator._async_update_data())


def test_fb_sign_in_classifies_credential_errors(monkeypatch):
    def fake_post(url, json, timeout):
        return types.SimpleNamespace(
            status_code=400,
            json=lambda: {"error": {"message": json["email"], "code": 400}},
            text="",
        )

    monkeypatch.setattr(core.requests, "post", fake_post)
    with pytest.raises(core.WayznAuthError):
        core.fb_sign_in_email_password("INVALID_LOGIN_CREDENTIALS", "x", "k")
    with pytest.raises(core.WayznError) as err:
        core.fb_sign_in_email_password("TOO_MANY_ATTEMPTS_TRY_LATER", "x", "k")
    assert not isinstance(err.value, core.WayznAuthError)


# --------------------------------------------------------------------------
# db_stream: silent open connection, auth refresh failure (regression guards:
# the socket read timeout is the in-thread keep-alive watchdog, and a failed
# refresh must reconnect rather than end the stream)
# --------------------------------------------------------------------------

class FakeRaw:
    def __init__(self, lines, then=None):
        self.lines = list(lines)
        self.then = then

    def readline(self):
        if self.lines:
            return self.lines.pop(0)
        if self.then is not None:
            raise self.then
        return b""


class FakeResponse:
    def __init__(self, raw, status_code=200):
        self.raw = raw
        self.status_code = status_code

    def raise_for_status(self):
        pass

    def close(self):
        pass


def _keepalive():
    return [b"event: keep-alive\n", b"data: null\n", b"\n"]


def test_db_stream_reconnects_after_read_timeout(monkeypatch):
    stop = threading.Event()
    stop.wait = lambda t=None: False  # no real sleeping on backoff
    responses = [
        FakeResponse(FakeRaw(_keepalive(), then=urllib3.exceptions.ReadTimeoutError(None, None, "Read timed out."))),
        FakeResponse(FakeRaw([b"event: put\n", b'data: {"path":"/","data":{"ControlState":15}}\n', b"\n"])),
    ]
    gets = []

    def fake_get(url, **kw):
        gets.append(kw["params"]["auth"])
        return responses.pop(0)

    monkeypatch.setattr(core.requests, "get", fake_get)
    events = []
    for ev in core.db_stream("tokens", "/dev1", "tok", stop_event=stop):
        events.append(ev.event)
        if ev.event == "put":
            stop.set()
    assert events == ["keep-alive", "put"]
    assert len(gets) == 2


def test_db_stream_survives_failed_auth_refresh(monkeypatch):
    stop = threading.Event()
    stop.wait = lambda t=None: False
    responses = [
        FakeResponse(FakeRaw([b"event: auth_revoked\n", b"data: null\n", b"\n"])),
        FakeResponse(FakeRaw([]), status_code=401),  # old token rejected; refresh fails again
        FakeResponse(FakeRaw([]), status_code=401),  # refresh succeeds this time
        FakeResponse(FakeRaw([b"event: put\n", b'data: {"path":"/","data":{"ControlState":15}}\n', b"\n"])),
    ]
    gets = []
    monkeypatch.setattr(core.requests, "get", lambda url, **kw: (gets.append(kw["params"]["auth"]), responses.pop(0))[1])
    refreshes = iter([RuntimeError("sign-in timed out"), RuntimeError("still down"), "fresh-token"])

    def on_auth_expired():
        r = next(refreshes)
        if isinstance(r, Exception):
            raise r
        return r

    events = []
    for ev in core.db_stream("tokens", "/dev1", "old-token", stop_event=stop, on_auth_expired=on_auth_expired):
        events.append(ev.event)
        stop.set()
    assert events == ["put"]
    assert gets == ["old-token", "old-token", "old-token", "fresh-token"]


# --------------------------------------------------------------------------
# Two failure modes: door silent -> available + unknown; link down -> unavailable
# --------------------------------------------------------------------------

def _cover(c):
    from custom_components.wayzn.cover import WayznCover

    return WayznCover(c, types.SimpleNamespace(data=dict(ENTRY_DATA)))


def test_door_silent_keeps_cover_available_with_unknown_state(coordinator, hass, clock, node, run, caplog):
    """Door rebooted: link OK, TimeStamp frozen (2026-10-24 power cycle)."""
    frozen = clock.time()
    node["TimeStamp"] = frozen
    node["ControlState"] = 14  # last report before the reboot: closed
    while clock.time() - frozen <= CLOUD_TIMESTAMP_STALE_THRESHOLD:
        clock.advance(10)
        _healthy_stream(coordinator, clock)
        run(coordinator.async_refresh())
    cover = _cover(coordinator)
    assert coordinator.stale
    assert cover.available  # HA can still send open/close
    assert cover.is_closed is None  # honest unknown, not the stale "closed"
    assert not cover.is_opening and not cover.is_closing
    assert coordinator.data["state"] == "unknown"
    assert "door state set to unknown; the cover stays available" in caplog.text

    # A stream update while silent does not resurrect a confident state.
    coordinator._async_apply_sse_state({"controlstate": 14, "state": "closed"})
    assert cover.is_closed is None

    # Commands while silent: no optimistic "opening" either.
    monkey_sent = []
    coordinator._send_command_sync = lambda dev, tok, cmd: monkey_sent.append(cmd)
    run(coordinator.async_send_command("open"))
    assert monkey_sent == ["open"]
    assert coordinator.data["state"] == "unknown"

    # The door reports again: real state returns.
    clock.advance(10)
    node["TimeStamp"] = clock.time()
    run(coordinator.async_refresh())
    assert not coordinator.stale
    assert cover.available and cover.is_closed is True


def test_link_failure_makes_cover_unavailable(coordinator, clock, node, auth, run):
    run(coordinator.async_refresh())
    cover = _cover(coordinator)
    assert cover.available
    clock.advance(3600)  # token expired, and sign-in now fails
    auth.fail_with = requests.exceptions.ConnectionError("no route to Firebase")
    run(coordinator.async_refresh())
    assert not cover.available
    assert not coordinator.stale  # this is our link, not the door
