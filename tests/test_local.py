"""Tests for local mode (LocalBrainCoordinator, the wayzn-brain HTTP API).

Unit tests use a fake HTTP session. One live test talks to a real door when
WAYZN_BRAIN_HOST and WAYZN_BRAIN_TOKEN are set; it only reads /api/status, so it
never moves the door.
"""

import asyncio
import os
import sys
import types

import aiohttp
import pytest

# The coordinator imports HA's aiohttp helper: stub it (the session is injected per test).
_aio = types.ModuleType("homeassistant.helpers.aiohttp_client")
_aio.async_get_clientsession = lambda hass: getattr(hass, "session", None)
sys.modules.setdefault("homeassistant.helpers.aiohttp_client", _aio)

from homeassistant.exceptions import HomeAssistantError  # noqa: E402  (conftest stub)
from custom_components.wayzn import local_coordinator as lc  # noqa: E402


class _Resp:
    def __init__(self, status, body):
        self.status, self._body = status, body

    async def json(self, content_type=None):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class FakeSession:
    """Replies from a script: list of (status, body) or exceptions, per path."""

    def __init__(self, script):
        self.script = {k: list(v) for k, v in script.items()}
        self.calls = []

    def request(self, method, url, headers=None, timeout=None, json=None):
        path = url.split("//", 1)[1].split("/", 1)[1]
        self.calls.append((method, "/" + path, headers, json) if json is not None else (method, "/" + path, headers))
        nxt = self.script["/" + path].pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return _Resp(*nxt)


def _status(state="closed", age=500, **kw):
    b = {"state": state, "detail": state, "position": "known", "p": -75, "fault": None,
         "presence": False, "occupied": False, "auto": True, "hold": False,
         "grideye_ok": True, "status_age_ms": age, "uptime_s": 100}
    b.update(kw)
    return (200, b)


def _coord(hass, script):
    hass.session = FakeSession(script)
    entry = types.SimpleNamespace(data={"host": "door.test", "token": "t0k"})
    return lc.LocalBrainCoordinator(hass, entry)


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    async def _no_sleep(_s):
        return None
    monkeypatch.setattr(lc.asyncio, "sleep", _no_sleep)


def test_fresh_status_maps_through(hass, run):
    c = _coord(hass, {"/api/status": [_status("closed")]})
    run(c.async_refresh())
    assert c.data["state"] == "closed" and not c.stale and c.last_update_success
    assert hass.session.calls[0][2]["Authorization"] == "Bearer t0k"
    assert c.diagnostics["door_detail"] == "closed"


@pytest.mark.parametrize("st", [_status("unknown"), _status("open", age=20000)])
def test_unproven_state_is_unknown(hass, run, st):
    c = _coord(hass, {"/api/status": [st]})
    run(c.async_refresh())
    assert c.data["state"] == "unknown" and c.stale


def test_unreachable_is_unknown_but_available(hass, run):
    # Available so HA still delivers open commands; honest unknown state.
    c = _coord(hass, {"/api/status": [aiohttp.ClientConnectionError("down")]})
    run(c.async_refresh())
    assert c.data["state"] == "unknown" and c.stale and c.last_update_success


def test_bad_token_fails_the_update(hass, run):
    c = _coord(hass, {"/api/status": [(401, {"ok": False})]})
    run(c.async_refresh())
    assert not c.last_update_success


def test_open_retries_through_network_errors(hass, run):
    c = _coord(hass, {"/api/open": [aiohttp.ClientConnectionError("x"), asyncio.TimeoutError(), (200, {"ok": True})]})
    run(c.async_send_command("open"))
    assert [m for m, p, _ in hass.session.calls] == ["POST"] * 3
    assert len(hass.loop.later) == len(lc.COMMAND_VERIFY_DELAYS)  # verification scheduled


def test_open_that_never_arrives_is_surfaced(hass, run):
    c = _coord(hass, {"/api/open": [aiohttp.ClientConnectionError("x")] * lc.OPEN_ATTEMPTS})
    with pytest.raises(HomeAssistantError):
        run(c.async_send_command("open"))
    run(hass.run_tasks())
    assert any(s == "create" and d["notification_id"] == lc.NOTIFY_COMMAND_ID for _, s, d in hass.service_calls)


def test_refused_close_says_why_and_is_not_retried(hass, run):
    c = _coord(hass, {"/api/close": [(409, {"ok": False, "reason": "doorway not clear"})]})
    with pytest.raises(HomeAssistantError, match="doorway not clear"):
        run(c.async_send_command("close"))
    assert len(hass.session.calls) == 1


def test_command_that_misses_target_notifies(hass, run):
    c = _coord(hass, {"/api/open": [(200, {"ok": True})]})
    run(c.async_send_command("open"))
    c.data = {"state": "closed"}  # door never moved
    run(c._verify(c._command_seq, "open", 30, True))
    run(hass.run_tasks())
    assert any(d.get("notification_id") == lc.NOTIFY_COMMAND_ID for _, s, d in hass.service_calls if s == "create")


def test_oscillation_is_an_error(hass, run):
    seq = [_status(s) for s in ["open", "closed", "open", "closed", "open"]]
    c = _coord(hass, {"/api/status": seq})
    for _ in seq:
        run(c.async_refresh())
    run(hass.run_tasks())
    assert c.diagnostics["oscillation"]
    assert any(d.get("notification_id") == lc.NOTIFY_OSC_ID for _, s, d in hass.service_calls if s == "create")


def test_auto_toggle_is_confirmed(hass, run):
    c = _coord(hass, {"/api/auto": [(200, {"ok": True})], "/api/status": [_status(auto=False)]})
    run(c.async_set_auto(False))
    assert hass.session.calls[0][3] == {"on": False}


def test_auto_toggle_that_does_not_take_raises(hass, run):
    c = _coord(hass, {"/api/auto": [(200, {"ok": True})], "/api/status": [_status(auto=True)]})
    with pytest.raises(HomeAssistantError, match="auto=True"):
        run(c.async_set_auto(False))


def test_auto_toggle_refused_raises(hass, run):
    c = _coord(hass, {"/api/auto": [(400, {"ok": False, "reason": "bad body"})]})
    with pytest.raises(HomeAssistantError, match="bad body"):
        run(c.async_set_auto(True))


def _status_settings(**kw):
    st = _status()
    st[1]["settings"] = {"auto_open": True, "auto_close": True, "obstruction_detection": True, "hold_s": 15,
                         "open_percent": 45.2, "open_counts": -6136, "presence_threshold": 1.0,
                         "occupied_threshold": 0.6, "noise_c": 0.7, **kw}
    return st


def test_settings_change_is_confirmed(hass, run):
    c = _coord(hass, {"/api/settings": [(200, {"ok": True})], "/api/status": [_status_settings(hold_s=30)]})
    run(c.async_set_settings({"hold_s": 30}))
    assert hass.session.calls[0][3] == {"hold_s": 30}
    assert c.settings["hold_s"] == 30


def test_settings_refused_says_why(hass, run):
    c = _coord(hass, {"/api/settings": [(400, {"ok": False, "reason": "hold_s out of range 3.00..600.00"})]})
    with pytest.raises(HomeAssistantError, match="out of range"):
        run(c.async_set_settings({"hold_s": 1}))


def test_settings_that_do_not_take_raise(hass, run):
    c = _coord(hass, {"/api/settings": [(200, {"ok": True})], "/api/status": [_status_settings(open_percent=45.2)]})
    with pytest.raises(HomeAssistantError, match="open_percent"):
        run(c.async_set_settings({"open_percent": 60.0}))


def test_settings_unknown_when_stale(hass, run):
    st = _status_settings()
    st[1]["state"] = "unknown"
    c = _coord(hass, {"/api/status": [st]})
    run(c.async_refresh())
    assert c.settings == {}


@pytest.mark.skipif(not os.environ.get("WAYZN_BRAIN_HOST"), reason="set WAYZN_BRAIN_HOST/TOKEN for the live test")
def test_live_status_only(hass, run):
    async def go():
        async with aiohttp.ClientSession() as s:
            hass.session = s
            entry = types.SimpleNamespace(data={"host": os.environ["WAYZN_BRAIN_HOST"],
                                                "token": os.environ["WAYZN_BRAIN_TOKEN"]})
            c = lc.LocalBrainCoordinator(hass, entry)
            await c.async_refresh()
            return c
    c = run(go())
    print("live:", c.data["state"], c.diagnostics, c.settings)
    assert c.last_update_success and c.data["state"] in ("open", "closed", "opening", "closing", "unknown")
