"""Local mode: talk to the wayzn-brain ESP32 on the door over the LAN.

The Wayzn cloud is gone; the door now runs the wayzn-brain firmware (aijayadams/wayzn-afterlife,
docs/API.md). This coordinator speaks its small HTTP API and offers the same
interface the cover entity already uses with the cloud coordinator:
``data["state"]``, ``stale``, ``last_update_success``, ``diagnostics`` and
``async_send_command()``.

Principles (AGENTS.md): never show a stale state (unknown instead); commands are
always sent whatever the believed state; open is retried; a command that doesn't
reach its target is surfaced, never silent; oscillation is surfaced as an error.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from datetime import timedelta
from typing import Any, Deque, Dict, Optional

import aiohttp
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import CONF_HOST, CONF_TOKEN, DOMAIN

_LOGGER = logging.getLogger(__name__)

POLL_IDLE = timedelta(seconds=5)
POLL_ACTIVE = timedelta(seconds=1)  # while moving and for a while after a command
ACTIVE_AFTER_COMMAND_S = 30
HTTP_TIMEOUT_S = 4
OPEN_ATTEMPTS = 3  # never lock a dog out: retry an open on network errors
STALE_STATUS_MS = 15000  # the brain already reports unknown past this; double check here
COMMAND_VERIFY_DELAYS = (5, 15, 30)
# A close the door accepted while the doorway was occupied runs once it clears (the door gives up
# after 5 min), so check over a longer window before calling it failed.
PENDING_CLOSE_VERIFY_DELAYS = (30, 120, 320)
OSCILLATION_WINDOW_S = 300
OSCILLATION_MAX_TRANSITIONS = 3
NOTIFY_COMMAND_ID = "wayzn_command_failed"
NOTIFY_OSC_ID = "wayzn_oscillation"
NOTIFY_LINK_ID = "wayzn_brain_unreachable"
LINK_ALERT_AFTER_S = 120


class LocalBrainCoordinator(DataUpdateCoordinator):
    """Polls the wayzn-brain status endpoint and sends commands."""

    def __init__(self, hass: HomeAssistant, config_entry) -> None:
        super().__init__(hass, _LOGGER, name=f"{DOMAIN}_local", update_interval=POLL_IDLE)
        self.config_entry = config_entry
        self._host: str = config_entry.data[CONF_HOST]
        self._token: str = config_entry.data[CONF_TOKEN]
        self._session = async_get_clientsession(hass)
        self._stale = True
        self._stale_reason: Optional[str] = "no status yet"
        self._stale_since: Optional[float] = time.time()
        self._last_poll_at: Optional[float] = None
        self._last_ok_at: Optional[float] = None
        self._raw: Dict[str, Any] = {}
        self._active_until = 0.0
        self._command_seq = 0
        self._consecutive_command_failures = 0
        self._command_anomaly_active = False
        self._transitions: Deque[float] = deque()
        self._last_terminal: Optional[str] = None
        self._oscillation_active = False
        self._link_alert_active = False

    # ------------------------------------------------------------------ http
    @property
    def _base(self) -> str:
        return f"http://{self._host}"

    async def _request(self, method: str, path: str) -> tuple[int, Dict[str, Any]]:
        headers = {"Authorization": f"Bearer {self._token}"}
        async with self._session.request(
            method, self._base + path, headers=headers, timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT_S)
        ) as resp:
            try:
                body = await resp.json(content_type=None)
            except (aiohttp.ContentTypeError, ValueError):
                body = {}
            return resp.status, body or {}

    # ------------------------------------------------------------------ poll
    async def _async_update_data(self) -> Dict[str, Any]:
        self._last_poll_at = time.time()
        try:
            status, body = await self._request("GET", "/api/status")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            self._enter_stale(f"door unreachable: {e.__class__.__name__}")
            self._check_link_alert()
            # Keep the entity available (HA skips service calls to unavailable entities;
            # an open must still be attempted) but report an honest unknown.
            return {"state": "unknown"}
        if status == 401:
            self._enter_stale("API token rejected")
            raise UpdateFailed("wayzn-brain rejected the API token")
        if status != 200:
            self._enter_stale(f"HTTP {status}")
            return {"state": "unknown"}

        self._last_ok_at = time.time()
        self._clear_link_alert()
        self._raw = body
        state = body.get("state", "unknown")
        age = body.get("status_age_ms")
        if state == "unknown" or (isinstance(age, (int, float)) and age > STALE_STATUS_MS):
            self._enter_stale(f"door reports {state} (detail {body.get('detail')}, status age {age} ms)")
            state = "unknown"
        else:
            self._exit_stale()
        self._track_transitions(state)
        moving = state in ("opening", "closing")
        active = moving or time.monotonic() < self._active_until
        self.update_interval = POLL_ACTIVE if active else POLL_IDLE
        return {"state": state, "brain": body}

    # ------------------------------------------------------------------ staleness
    @property
    def stale(self) -> bool:
        return self._stale

    def _enter_stale(self, reason: str) -> None:
        if not self._stale:
            _LOGGER.warning("wayzn-brain state unknown: %s", reason)
            self._stale_since = time.time()
        self._stale = True
        self._stale_reason = reason

    def _exit_stale(self) -> None:
        if self._stale:
            _LOGGER.info("wayzn-brain state fresh again (was: %s)", self._stale_reason)
        self._stale = False
        self._stale_reason = None
        self._stale_since = None

    def _check_link_alert(self) -> None:
        since = self._last_ok_at or self._stale_since or time.time()
        if not self._link_alert_active and time.time() - since > LINK_ALERT_AFTER_S:
            self._link_alert_active = True
            self._notify(
                NOTIFY_LINK_ID,
                "Dog door not reachable",
                f"Home Assistant can't reach the dog door ({self._host}) for over "
                f"{LINK_ALERT_AFTER_S}s. Its state is unknown; open/close commands may not arrive.",
            )

    def _clear_link_alert(self) -> None:
        if self._link_alert_active:
            self._link_alert_active = False
            self._dismiss(NOTIFY_LINK_ID)

    # ------------------------------------------------------------------ oscillation
    def _track_transitions(self, state: str) -> None:
        if state not in ("open", "closed"):
            return
        if self._last_terminal is not None and state != self._last_terminal:
            now = time.monotonic()
            self._transitions.append(now)
            while self._transitions and now - self._transitions[0] > OSCILLATION_WINDOW_S:
                self._transitions.popleft()
            if len(self._transitions) > OSCILLATION_MAX_TRANSITIONS and not self._oscillation_active:
                self._oscillation_active = True
                _LOGGER.error(
                    "DOG DOOR OSCILLATING: %d open/closed transitions in %ds",
                    len(self._transitions), OSCILLATION_WINDOW_S,
                )
                self._notify(
                    NOTIFY_OSC_ID,
                    "Dog door is oscillating",
                    f"{len(self._transitions)} open/closed transitions in {OSCILLATION_WINDOW_S}s. "
                    "This is a fault, not normal use: check the door and its automations.",
                )
            elif len(self._transitions) <= 1 and self._oscillation_active:
                self._oscillation_active = False
                self._dismiss(NOTIFY_OSC_ID)
        self._last_terminal = state

    # ------------------------------------------------------------------ commands
    async def async_send_command(self, command: str) -> None:
        """Send open/close. Always sent, whatever we believe the state is."""
        if command not in ("open", "close", "stop"):
            raise HomeAssistantError(f"unknown command {command}")
        self._command_seq += 1
        seq = self._command_seq
        self._active_until = time.monotonic() + ACTIVE_AFTER_COMMAND_S
        attempts = OPEN_ATTEMPTS if command == "open" else 1
        last_err: Optional[Exception] = None
        for attempt in range(1, attempts + 1):
            try:
                status, body = await self._request("POST", f"/api/{command}")
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_err = e
                _LOGGER.warning("wayzn-brain %s attempt %d/%d failed: %s", command, attempt, attempts, e)
                await asyncio.sleep(1)
                continue
            if status == 200 and body.get("ok"):
                _LOGGER.info("wayzn-brain accepted %s%s", command,
                             f" ({body['reason']})" if body.get("reason") else "")
                self.update_interval = POLL_ACTIVE
                await self.async_request_refresh()
                if command != "stop":
                    pending = command == "close" and "waiting" in (body.get("reason") or "")
                    self._schedule_verification(command, seq, PENDING_CLOSE_VERIFY_DELAYS if pending else COMMAND_VERIFY_DELAYS)
                return
            reason = body.get("reason") or f"HTTP {status}"
            if status == 401:
                raise HomeAssistantError("Dog door rejected the API token")
            # Refused on purpose (e.g. close while the doorway is occupied): say why.
            _LOGGER.warning("wayzn-brain refused %s: %s", command, reason)
            raise HomeAssistantError(f"Dog door refused {command}: {reason}")
        self._consecutive_command_failures += 1
        self._notify(
            NOTIFY_COMMAND_ID,
            "Dog door didn't get the command",
            f"'{command}' could not be delivered to the door ({self._host}) after {attempts} "
            f"attempt(s): {last_err}. If a dog is waiting, check the door now.",
        )
        self._command_anomaly_active = True
        raise HomeAssistantError(f"Dog door unreachable: {last_err}")

    async def async_set_auto(self, on: bool) -> None:
        """Turn the door's Grid-EYE auto-open on/off, then confirm it took."""
        headers = {"Authorization": f"Bearer {self._token}"}
        last_err: Optional[Exception] = None
        for attempt in range(1, 4):
            try:
                async with self._session.request(
                    "POST", self._base + "/api/auto", headers=headers, json={"on": on},
                    timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT_S),
                ) as resp:
                    body = await resp.json(content_type=None) or {}
                    if resp.status == 200 and body.get("ok"):
                        break
                    raise HomeAssistantError(f"Dog door refused auto {'on' if on else 'off'}: "
                                             f"{body.get('reason') or resp.status}")
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_err = e
                await asyncio.sleep(1)
        else:
            raise HomeAssistantError(f"Dog door unreachable: {last_err}")
        await self.async_refresh()
        got = ((self.data or {}).get("brain") or {}).get("auto")
        if got is not on:
            raise HomeAssistantError(f"Dog door reports auto={got} after setting it {on}")
        _LOGGER.info("wayzn-brain auto-open %s", "on" if on else "off")

    @property
    def settings(self) -> Dict[str, Any]:
        """The door's settings as last reported in /api/status (empty if unknown)."""
        if self._stale:
            return {}
        return ((self.data or {}).get("brain") or {}).get("settings") or {}

    async def async_set_settings(self, changes: Dict[str, Any]) -> None:
        """POST /api/settings (all or nothing on the door), then confirm every value took."""
        headers = {"Authorization": f"Bearer {self._token}"}
        try:
            async with self._session.request(
                "POST", self._base + "/api/settings", headers=headers, json=changes,
                timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT_S),
            ) as resp:
                body = await resp.json(content_type=None) or {}
                status = resp.status
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            raise HomeAssistantError(f"Dog door unreachable: {e}") from e
        if status != 200 or not body.get("ok"):
            raise HomeAssistantError(f"Dog door refused {changes}: {body.get('reason') or status}")
        await self.async_refresh()
        got = self.settings
        for k, v in changes.items():
            have = got.get(k)
            same = abs(have - v) <= 0.051 if isinstance(v, float) and isinstance(have, (int, float)) else have == v
            if not same:
                raise HomeAssistantError(f"Dog door reports {k}={have} after setting it to {v}")
        _LOGGER.info("wayzn-brain settings changed: %s", changes)

    def _schedule_verification(self, command: str, seq: int, delays=COMMAND_VERIFY_DELAYS) -> None:
        target = "open" if command == "open" else "closed"
        for delay in delays:
            final = delay == delays[-1]
            self.hass.loop.call_later(
                delay,
                lambda d=delay, f=final: self.hass.async_create_task(self._verify(seq, target, d, f)),
            )

    async def _verify(self, seq: int, target: str, delay: int, final: bool) -> None:
        if seq != self._command_seq:
            return  # superseded by a newer command
        await self.async_request_refresh()
        state = (self.data or {}).get("state")
        if state == target:
            self._consecutive_command_failures = 0
            if self._command_anomaly_active:
                self._command_anomaly_active = False
                self._dismiss(NOTIFY_COMMAND_ID)
            return
        if not final:
            return
        self._consecutive_command_failures += 1
        brain = (self.data or {}).get("brain") or {}
        _LOGGER.error(
            "DOG DOOR COMMAND FAILED: not %s %ds after the command (state=%s, detail=%s, fault=%s)",
            target, delay, state, brain.get("detail"), brain.get("fault"),
        )
        if not self._command_anomaly_active:
            self._command_anomaly_active = True
            self._notify(
                NOTIFY_COMMAND_ID,
                "Dog door didn't reach the commanded state",
                f"Told to be '{target}', but after {delay}s it reports '{state}' "
                f"(detail: {brain.get('detail')}, fault: {brain.get('fault')}). "
                "If a dog is waiting at the door, check it now.",
            )

    # ------------------------------------------------------------------ notifications
    def _notify(self, nid: str, title: str, message: str) -> None:
        self.hass.async_create_task(
            self.hass.services.async_call(
                "persistent_notification", "create",
                {"notification_id": nid, "title": title, "message": message},
            )
        )

    def _dismiss(self, nid: str) -> None:
        self.hass.async_create_task(
            self.hass.services.async_call("persistent_notification", "dismiss", {"notification_id": nid})
        )

    # ------------------------------------------------------------------ diagnostics
    @property
    def diagnostics(self) -> Dict[str, Any]:
        def iso(ts: Optional[float]) -> Optional[str]:
            return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts)) if ts else None

        b = self._raw
        return {
            "mode": "local",
            "host": self._host,
            "stale": self._stale,
            "stale_reason": self._stale_reason,
            "stale_since": iso(self._stale_since),
            "last_poll_at": iso(self._last_poll_at),
            "last_ok_at": iso(self._last_ok_at),
            "consecutive_command_failures": self._consecutive_command_failures,
            "oscillation": self._oscillation_active,
            "door_detail": b.get("detail"),
            "door_position": b.get("position"),
            "door_fault": b.get("fault"),
            "door_occupied": b.get("occupied"),
            "door_presence": b.get("presence"),
            "door_auto": b.get("auto"),
            "door_hold": b.get("hold"),
            "door_close_pending": b.get("close_pending"),
            "door_grideye_ok": b.get("grideye_ok"),
            "door_status_age_ms": b.get("status_age_ms"),
            "door_uptime_s": b.get("uptime_s"),
        }

    def start_streaming(self) -> None:  # interface parity with the cloud coordinator
        return

    def stop_streaming(self) -> None:
        return
