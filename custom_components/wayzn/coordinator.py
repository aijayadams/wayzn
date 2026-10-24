"""DataUpdateCoordinator for Wayzn integration with Firebase SSE streaming."""

import asyncio
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .wayzn_client import wayzn_core as core
from .const import (
    CONF_AGENTURL,
    CONF_API_KEY,
    CONF_DEVICE_ID,
    CONF_DEVICE_LABEL,
    CONF_EMAIL,
    CONF_KNUM,
    CONF_PASSWORD,
    CONF_WKEY,
    DEFAULT_POLL_INTERVAL,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

# Polling interval — used as heartbeat/fallback when streaming is active
HEARTBEAT_POLL_INTERVAL = 120  # seconds (SSE keep-alives arrive every ~30s)
FALLBACK_POLL_INTERVAL = 10  # seconds when streaming is down — aggressive to compensate
STREAM_STALE_THRESHOLD = 60  # seconds — if no SSE event in this window, stream is dead

# Command verification: poll at these delays after a command; if the door
# hasn't reached the target state by the LAST delay, log ERROR and notify.
COMMAND_VERIFY_DELAYS = (5, 15, 30)

# Data honesty: if the Firebase snapshot's own TimeStamp is older than this,
# the cloud data may be stale — mark the entity unavailable instead of
# confidently showing a possibly-wrong state (2026-08-11: wrong "open" for ~6h
# was worse than an honest "unknown").
#
# TimeStamp is a device heartbeat, not an "on change" field: the door rewrites
# it about every 10s even when idle (HA recorder 2026-10-14..24: age never
# above 24s except one 112s blip). So an old TimeStamp while our own polls
# succeed means the DOOR has stopped reporting to the cloud (2026-10-24:
# frozen 12:27:44-15:41 PDT while every poll and the stream were fine).
CLOUD_TIMESTAMP_STALE_THRESHOLD = 300  # seconds (5 min)

# Self-healing while stale. Each attempt forces a Firebase re-sign-in and
# restarts the SSE stream, which rules out (and repairs) a stuck token or
# connection on our side. Delay before attempt n+1 is STALE_RECOVERY_DELAYS_S[n]
# (last value repeats): at most one sign-in per hour once settled, so this can
# never hammer Firebase auth (2026-08-11 rate-limit incident).
STALE_RECOVERY_DELAYS_S = (300, 600, 1200, 2400, 3600)
# While stale, log a status line this often so a long gap is never silent.
STALE_STATUS_LOG_INTERVAL_S = 600

# Firebase sign-in pacing. Successful sign-ins: at most one per
# AUTH_MIN_INTERVAL_S unless the token has expired. Failed sign-ins back off
# 30, 60, 120, 240, then AUTH_MIN_INTERVAL_S — failures used to be retried on
# every 10s poll because only successes were rate-limited.
AUTH_MIN_INTERVAL_S = 300
AUTH_FAILURE_BACKOFF_S = (30, 60, 120, 240)

# Stream thread restarts after it dies or goes silent: the first 3 are
# immediate, then 60, 120, 240s, capped here. Polling keeps
# running at FALLBACK_POLL_INTERVAL the whole time.
STREAM_MAX_RESTART_BACKOFF_S = 300

# Drift alerting: after this many consecutive polls disagreeing with the SSE
# stream's last-known state, notify (once per episode).
DRIFT_ALERT_THRESHOLD = 3

# Persistent notification IDs (one per anomaly type — an episode updates in
# place, and is dismissed when the condition clears)
NOTIFY_STALE_ID = "wayzn_stale_state"
NOTIFY_DRIFT_ID = "wayzn_state_drift"
NOTIFY_COMMAND_ID = "wayzn_command_failed"
NOTIFY_OSCILLATION_ID = "wayzn_state_oscillation"
NOTIFY_SETTING_ID = "wayzn_setting_not_applied"

# Settings writes: poll the device node until the change reads back.
SETTING_VERIFY_TIMEOUT_S = 30
SETTING_VERIFY_INTERVAL_S = 3

# Oscillation detection: rapid open/close/open cycles are an ERROR, not a
# state (2026-08-12: classifier/Wayzn interaction flapped the door every ~30s
# for 20min — wear on the hardware, spam to the user). Count TERMINAL-state
# transitions only (open/closed); one full open+close cycle = 2 transitions,
# so >3 in the window means at least two full flap cycles.
OSCILLATION_WINDOW_S = 300  # seconds
OSCILLATION_MAX_TRANSITIONS = 3

# Command tracking for logging (grace window removed — trust Firebase directly)


def _fmt_duration(seconds: float) -> str:
    """Human duration for logs: 45s, 12m05s, 3h08m."""
    seconds = int(max(0, seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"


class WayznDataUpdateCoordinator(DataUpdateCoordinator):
    """Coordinator for Wayzn device data updates.

    Primary state updates come from a Firebase SSE streaming connection,
    giving sub-second latency on state changes. A periodic poll serves as
    a heartbeat/fallback in case the stream disconnects.
    """

    def __init__(self, hass: HomeAssistant, config_entry) -> None:
        """Initialize the coordinator."""
        self.config_entry = config_entry
        self._auth_token: Optional[str] = None
        self._token_expires_at: Optional[float] = None
        self._last_fresh_auth_time: float = 0.0  # time.time() of last successful sign-in
        self._last_auth_attempt_time: float = 0.0  # time.time() of last sign-in attempt
        self._auth_failures: int = 0  # consecutive failed sign-ins
        self._auth_lock = threading.Lock()  # poll executor and SSE thread both sign in

        # SSE streaming state
        self._stream_thread: Optional[threading.Thread] = None
        self._stream_stop: threading.Event = threading.Event()
        self._stream_healthy: bool = False
        self._last_stream_event: float = 0.0  # monotonic timestamp of last SSE event
        self._stream_response = None  # Active SSE response, closed on stop to unblock iter_lines
        self._stream_connected_at: float = 0.0  # monotonic time when SSE last connected
        self._consecutive_reconnects: int = 0  # watchdog reconnect counter for backoff
        self._last_sse_cloud_ts: Optional[float] = None  # newest device TimeStamp seen on SSE

        # Restart coordination
        self._restart_in_progress: bool = False

        # Command verification state
        self._last_command: Optional[str] = None  # "open" or "close"
        self._last_command_time: float = 0.0  # monotonic timestamp
        self._command_seq: int = 0  # bumped per command; stale verifications self-cancel
        self._consecutive_command_failures: int = 0
        self._command_anomaly_active: bool = False

        # SSE-tracked last-known state (compared against polls for drift detection)
        self._last_sse_state: Optional[str] = None
        self._last_sse_controlstate: Optional[int] = None
        self._last_sse_event_wall: Optional[float] = None  # time.time() of last SSE event

        # Drift detection state
        self.drift_events_total: int = 0
        self._last_drift_at: Optional[float] = None
        self._consecutive_drift_polls: int = 0

        # Data honesty (staleness) state
        self._stale: bool = False
        self._last_poll_wall: Optional[float] = None
        self._cloud_timestamp: Optional[float] = None  # epoch seconds from Firebase TimeStamp
        self._cloud_timestamp_age_s: Optional[float] = None
        self._stale_reason: Optional[str] = None
        self._stale_since_wall: Optional[float] = None
        self._stale_since: float = 0.0  # monotonic
        self._stale_recovery_attempts: int = 0
        self._next_stale_recovery_at: float = 0.0  # monotonic
        self._last_stale_status_log: float = 0.0  # monotonic
        self._stale_poll_controlstate: Optional[int] = None

        # Circuit breaker: handle for a watchdog-scheduled delayed SSE restart
        self._delayed_restart_handle = None

        # Oscillation detection: recent terminal-state transitions (monotonic, state)
        from collections import deque
        self._terminal_history: deque = deque(maxlen=64)
        self._oscillation_active: bool = False
        # Door state tracking
        # (direction tracking removed — trust Firebase directly)

        # Settings: newest Mask TimeStamp applied (SSE patches arrive out of
        # order), and one settings write at a time.
        self._mask_ts: Optional[float] = None
        self._settings_lock = asyncio.Lock()

        super().__init__(
            hass,
            _LOGGER,
            name=f"Wayzn {config_entry.data.get(CONF_DEVICE_LABEL, 'Dog Door')}",
            update_interval=timedelta(seconds=FALLBACK_POLL_INTERVAL),
        )

    # ========================================================================
    # Auth token management
    # ========================================================================

    def _get_cached_or_fresh_token(
        self, email: str, password: str, api_key: str, force: bool = False,
        auth_timeout: int = 20,
    ) -> str:
        """Return the cached ID token if valid, otherwise sign in again.

        Thread-safe (the poll executor and the SSE thread both call it).
        Sign-ins are paced so nothing can hammer Firebase auth:
          - after a success, no new sign-in for AUTH_MIN_INTERVAL_S unless the
            cached token has actually expired (force=True does not bypass it);
          - after a failure, back off AUTH_FAILURE_BACKOFF_S, then
            AUTH_MIN_INTERVAL_S.
        While paced, the cached token is returned if there is one (it may be
        rejected; that surfaces as a normal poll/stream error), otherwise
        WayznError. Every sign-in success and failure is logged.

        Raises core.WayznAuthError only when Firebase rejects the credentials.
        """
        with self._auth_lock:
            now = time.time()
            token_valid = bool(
                self._auth_token and self._token_expires_at
                and now < (self._token_expires_at - 60)
            )
            if token_valid and not force:
                return self._auth_token

            wait = self._auth_wait_remaining(now, token_valid)
            if wait > 0:
                if self._auth_token:
                    _LOGGER.debug(
                        "Firebase sign-in paced (%.0fs left); using cached token", wait,
                    )
                    return self._auth_token
                raise core.WayznError(
                    f"Firebase sign-in paced after {self._auth_failures} failure(s): "
                    f"next attempt in {wait:.0f}s"
                )

            self._last_auth_attempt_time = now
            try:
                auth = core.fb_sign_in_email_password(
                    email, password, api_key, timeout=auth_timeout
                )
                token = auth.get("idToken")
                if not token:
                    raise core.WayznError("Firebase sign-in returned no ID token")
            except Exception as e:
                self._auth_failures += 1
                _LOGGER.warning(
                    "Firebase sign-in failed (%d in a row): %s — next attempt in %ds",
                    self._auth_failures, e, int(self._auth_wait_remaining(time.time(), False)),
                )
                if isinstance(e, core.WayznError):
                    raise
                raise core.WayznError(f"Firebase sign-in failed: {e}") from e

            try:
                expires_in = int(auth.get("expiresIn", 3600))
            except (ValueError, TypeError):
                expires_in = 3600
            if self._auth_failures:
                _LOGGER.warning(
                    "Firebase sign-in recovered after %d failure(s)", self._auth_failures,
                )
            else:
                _LOGGER.info("Firebase sign-in OK (token valid %ds)", expires_in)
            self._auth_failures = 0
            self._auth_token = token
            self._last_fresh_auth_time = time.time()
            self._token_expires_at = self._last_fresh_auth_time + expires_in
            return token

    def _auth_wait_remaining(self, now: float, token_valid: bool) -> float:
        """Seconds until another sign-in attempt is allowed (0 = now)."""
        if self._auth_failures:
            idx = min(self._auth_failures, len(AUTH_FAILURE_BACKOFF_S) + 1) - 1
            delay = (AUTH_FAILURE_BACKOFF_S + (AUTH_MIN_INTERVAL_S,))[idx]
            return max(0.0, self._last_auth_attempt_time + delay - now)
        if self._last_fresh_auth_time and (token_valid or self._auth_token is None):
            return max(0.0, self._last_fresh_auth_time + AUTH_MIN_INTERVAL_S - now)
        return 0.0  # never signed in, or the cached token has expired

    def _get_fresh_token_sync(self) -> str:
        """Get a fresh auth token (for SSE auth refresh callback).

        Uses cached token first to avoid hammering Firebase on every SSE reconnect.
        Only forces fresh auth if the cached token is expired.
        Uses a shorter timeout (8s) to avoid blocking the SSE thread for too long,
        since the event loop staleness watchdog might be waiting for this thread to exit.
        """
        email = self.config_entry.data[CONF_EMAIL]
        password = self.config_entry.data[CONF_PASSWORD]
        api_key = self.config_entry.data[CONF_API_KEY]
        # Don't force=True here — use cached token if still valid.
        # This prevents hammering Firebase on every SSE reconnect cycle.
        # Use shorter timeout (8s) for SSE context — if Firebase is slow,
        # better to fail fast and let the reconnect loop retry with backoff.
        # A failure raises; db_stream logs it and retries on its backoff.
        return self._get_cached_or_fresh_token(
            email, password, api_key, force=False, auth_timeout=8
        )

    # ========================================================================
    # Command verification
    # ========================================================================

    # ========================================================================
    # Polling (heartbeat / fallback)
    # ========================================================================

    async def _async_update_data(self) -> Dict[str, Any]:
        """Fetch device status from Firebase (poll).

        Runs every FALLBACK_POLL_INTERVAL (or HEARTBEAT_POLL_INTERVAL while
        the stream is healthy). Polls are the authoritative read and the
        fallback whenever the stream is down. The stream watchdog runs first,
        so it still runs when the fetch itself fails.
        """
        self._check_stream_watchdog()
        try:
            email = self.config_entry.data[CONF_EMAIL]
            password = self.config_entry.data[CONF_PASSWORD]
            api_key = self.config_entry.data[CONF_API_KEY]
            device_id = self.config_entry.data[CONF_DEVICE_ID]

            try:
                id_token = await self.hass.async_add_executor_job(
                    self._get_cached_or_fresh_token, email, password, api_key
                )
            except core.WayznAuthError as e:
                raise ConfigEntryAuthFailed(f"Authentication failed: {e}") from e
            # Other sign-in errors are transient: UpdateFailed below, retried
            # on the next poll within the sign-in backoff.

            status = await self.hass.async_add_executor_job(
                self._get_status_summary, device_id, id_token
            )

            _LOGGER.debug(
                "Poll: controlstate=%s, state=%s, stream_healthy=%s",
                status.get("controlstate"),
                status.get("state"),
                self._stream_healthy,
            )

            # --- Data honesty / drift checks -------------------------------
            self._last_poll_wall = time.time()
            self._update_cloud_freshness(status.get("cloud_timestamp"))
            self._evaluate_staleness(status)

            # Compare this authoritative poll against the SSE-tracked state
            self._check_drift(status)

            # Track transitions for oscillation detection
            self._record_terminal_state(status.get("state"))

            self._mask_ts = status.get("cloud_timestamp")

            # Poll results are authoritative — trust Firebase directly.
            # Returning `status` overwrites coordinator.data even when it
            # differs from what SSE last delivered — that is intentional.
            return status

        except ConfigEntryAuthFailed:
            raise
        except core.WayznError as e:
            _LOGGER.error("Error fetching Wayzn device status: %s", e)
            raise UpdateFailed(f"Error fetching device status: {e}") from e
        except Exception as e:
            _LOGGER.error("Unexpected error fetching device status: %s", e)
            raise UpdateFailed(f"Unexpected error: {e}") from e

    def _check_stream_watchdog(self) -> None:
        """Restart the SSE stream if it is silent, never connected, or died.

        Event loop only. Three failure shapes:
          - stale: connected, but no event (not even a keep-alive) for
            STREAM_STALE_THRESHOLD — TCP open but nothing flowing;
          - dead-on-connect: thread alive, never received an event;
          - died: the thread exited without being asked to (previously
            nothing ever restarted it; polls carried on silently).
        The first 3 restarts are immediate, later ones back off (60/120/240s,
        cap STREAM_MAX_RESTART_BACKOFF_S). Polling stays at the fallback
        interval throughout — the poll is the safety net, so it is never
        slowed down while the stream is unhealthy.
        """
        now = time.monotonic()
        thread = self._stream_thread
        stream_stale = (
            self._stream_healthy
            and self._last_stream_event > 0
            and (now - self._last_stream_event) > STREAM_STALE_THRESHOLD
        )
        dead_on_connect = (
            not self._stream_healthy
            and self._stream_connected_at > 0
            and (now - self._stream_connected_at) > STREAM_STALE_THRESHOLD
            and thread is not None
            and thread.is_alive()
        )
        died = (
            thread is not None
            and not thread.is_alive()
            and not self._stream_stop.is_set()
            and not self._restart_in_progress
        )
        if not (stream_stale or dead_on_connect or died):
            if self._stream_healthy:
                self._consecutive_reconnects = 0
                self._cancel_delayed_restart()
            return

        self._consecutive_reconnects += 1
        if stream_stale:
            reason = f"stale (no events in {int(now - self._last_stream_event)}s)"
        elif dead_on_connect:
            reason = f"dead-on-connect (no events in {int(now - self._stream_connected_at)}s)"
        else:
            reason = "thread exited unexpectedly"

        self._signal_stream_stop()
        if self._consecutive_reconnects > 3:
            backoff = min(
                STREAM_STALE_THRESHOLD * (2 ** (self._consecutive_reconnects - 4)),
                STREAM_MAX_RESTART_BACKOFF_S,
            )
            _LOGGER.warning(
                "SSE: stream %s, restart #%d in %ds (backing off; polling every %ds meanwhile)",
                reason, self._consecutive_reconnects, int(backoff), FALLBACK_POLL_INTERVAL,
            )
            self._schedule_delayed_restart(backoff)
        else:
            _LOGGER.warning(
                "SSE: stream %s, restart #%d now", reason, self._consecutive_reconnects,
            )
            self.hass.async_create_task(self._async_restart_streaming())

    def _evaluate_staleness(self, status: Dict[str, Any]) -> None:
        """Decide stale/fresh after a SUCCESSFUL poll, and self-heal while stale.

        A successful poll proves our side works (sign-in, network, Firebase
        read); its TimeStamp proves the door is still reporting. Stream health
        alone no longer makes data stale: if the stream is down, the poll is
        the fresh source and the watchdog restarts the stream. (A failed poll
        already makes entities unavailable via last_update_success.)
        """
        age = self._cloud_timestamp_age_s
        if age is None or age <= CLOUD_TIMESTAMP_STALE_THRESHOLD:
            if self._stale:
                self._exit_stale(
                    f"door TimeStamp is fresh again (age {int(age)}s)" if age is not None
                    else "poll succeeded and the snapshot has no TimeStamp to judge"
                )
            return

        now = time.monotonic()
        if not self._stale:
            self._enter_stale(
                f"the door has not reported to the Wayzn cloud for {int(age)}s "
                f"(Firebase TimeStamp, limit {CLOUD_TIMESTAMP_STALE_THRESHOLD}s; "
                "normally refreshed every ~10s). Our link is fine: this poll "
                f"succeeded and the stream is {self._stream_status_text()}"
            )
        self._log_stale_controlstate(status)
        self._check_stream_vs_poll_timestamp()

        if now >= self._next_stale_recovery_at:
            # Book the attempt here (synchronously) so two polls can't both
            # schedule one before the task runs.
            n = self._stale_recovery_attempts
            self._stale_recovery_attempts = n + 1
            self._next_stale_recovery_at = now + STALE_RECOVERY_DELAYS_S[
                min(n, len(STALE_RECOVERY_DELAYS_S) - 1)
            ]
            self.hass.async_create_task(self._async_stale_recovery(n + 1))
        if now - self._last_stale_status_log >= STALE_STATUS_LOG_INTERVAL_S:
            self._last_stale_status_log = now
            _LOGGER.warning(
                "WAYZN STILL STALE for %s: door TimeStamp age %ds; last poll OK; "
                "stream %s; %d recovery attempt(s), next in %ds; HA cannot "
                "command the door while the entity is unavailable",
                _fmt_duration(now - self._stale_since), int(age),
                self._stream_status_text(), self._stale_recovery_attempts,
                max(0, int(self._next_stale_recovery_at - now)),
            )

    async def _async_stale_recovery(self, attempt: int) -> None:
        """One self-healing attempt: force re-sign-in, restart the stream.

        Paced by STALE_RECOVERY_DELAYS_S and by the sign-in pacing, so the
        worst case is one sign-in per hour. If the door itself has stopped
        reporting this cannot fix it — but it rules out (and repairs) a stuck
        token or connection on our side, and the log says which it was.
        """
        if not self._stale:
            return
        _LOGGER.warning(
            "WAYZN STALE RECOVERY attempt #%d (stale for %s): forcing Firebase "
            "re-sign-in and restarting the SSE stream",
            attempt, _fmt_duration(time.monotonic() - self._stale_since),
        )
        try:
            await self.hass.async_add_executor_job(
                lambda: self._get_cached_or_fresh_token(
                    self.config_entry.data[CONF_EMAIL],
                    self.config_entry.data[CONF_PASSWORD],
                    self.config_entry.data[CONF_API_KEY],
                    force=True,
                )
            )
        except Exception as e:  # logged; the next attempt follows the ladder
            _LOGGER.warning("WAYZN STALE RECOVERY: re-sign-in failed: %s", e)
        self._signal_stream_stop()
        await self._async_restart_streaming()
        await self.async_request_refresh()

    def _stream_status_text(self) -> str:
        if not self._stream_healthy or self._last_stream_event <= 0:
            return "down (polling every %ds)" % FALLBACK_POLL_INTERVAL
        return "alive (last event %ds ago)" % int(time.monotonic() - self._last_stream_event)

    def _log_stale_controlstate(self, status: Dict[str, Any]) -> None:
        """While stale, log ControlState changes the poll still sees.

        Tells us afterwards whether the node froze entirely or only the
        heartbeat stopped.
        """
        cs = status.get("controlstate")
        if self._stale_poll_controlstate is not None and cs != self._stale_poll_controlstate:
            _LOGGER.warning(
                "WAYZN STALE: ControlState changed %s -> %s although the door "
                "TimeStamp is frozen", self._stale_poll_controlstate, cs,
            )
        self._stale_poll_controlstate = cs

    def _check_stream_vs_poll_timestamp(self) -> None:
        """Cross-check: does the stream show a fresher device TimeStamp than the poll?

        If so the poll path is serving old data (not the door), and we say so
        loudly. The poll stays authoritative for state.
        """
        sse_ts = self._last_sse_cloud_ts
        poll_ts = self._cloud_timestamp
        if sse_ts is None or poll_ts is None:
            return
        if sse_ts - poll_ts > STREAM_STALE_THRESHOLD and time.time() - sse_ts <= CLOUD_TIMESTAMP_STALE_THRESHOLD:
            _LOGGER.warning(
                "WAYZN SOURCE DISAGREEMENT: the stream saw a door TimeStamp %ds "
                "old but the poll returns one %ds old — the poll path is serving "
                "old data, not the door. Trusting the poll (stale).",
                int(time.time() - sse_ts), int(time.time() - poll_ts),
            )

    def _get_status_summary(
        self, device_id: str, id_token: str
    ) -> Dict[str, Any]:
        """Get device status summary (sync function for executor)."""
        try:
            status_data = core.db_get("tokens", f"/{device_id}", id_token)
            controlstate = None
            position = None
            open_to = None
            cloud_ts = None
            if isinstance(status_data, dict):
                controlstate = status_data.get("ControlState")
                position = status_data.get("Position")
                open_to = status_data.get("OpenTo")
                # Cloud-provided freshness signal — the device/cloud updates
                # TimeStamp on every write; if this is old, the whole snapshot
                # (including ControlState) may be stale.
                try:
                    cloud_ts = float(status_data.get("TimeStamp"))
                    if cloud_ts > 1e12:  # milliseconds
                        cloud_ts /= 1000.0
                except (TypeError, ValueError):
                    cloud_ts = None
            raw_label = core.controlstate_label(controlstate)
            cs_int = int(controlstate) if controlstate is not None else 0
            resolved = self._resolve_door_state(
                cs_int, raw_label, position, open_to,
            )
            return {
                "controlstate": controlstate,
                "state": resolved,
                "cloud_timestamp": cloud_ts,
                # Settings ride along on the poll (heartbeat ≤120s); SSE only
                # carries door state, see _async_apply_sse_state.
                "settings": core.extract_settings(status_data) if isinstance(status_data, dict) else {},
            }
        except core.WayznError as e:
            raise e
        except Exception as e:
            raise core.WayznError(f"Failed to get device status: {e}") from e

    # ========================================================================
    # Data honesty, drift detection, anomaly notifications
    # ========================================================================

    @property
    def stale(self) -> bool:
        """True when we cannot vouch for the data we're showing.

        Cover.availability keys off this: a wrong "open" is worse than an
        honest "unavailable" (2026-08-11: HA showed "open" for ~6h on a
        physically closed door).
        """
        return self._stale

    def _update_cloud_freshness(self, cloud_ts: Optional[float]) -> None:
        """Record the cloud snapshot's own TimeStamp and its age."""
        if cloud_ts is None:
            # Can't judge freshness without the field — don't flag what we
            # can't see, but stop trusting a previously-good reading.
            self._cloud_timestamp = None
            self._cloud_timestamp_age_s = None
            return
        self._cloud_timestamp = cloud_ts
        self._cloud_timestamp_age_s = time.time() - cloud_ts

    def _enter_stale(self, reason: str) -> None:
        """Mark data untrustworthy (log + notify once per episode)."""
        if self._stale:
            return
        now = time.monotonic()
        self._stale = True
        self._stale_reason = reason
        self._stale_since = now
        self._stale_since_wall = time.time()
        self._stale_recovery_attempts = 0
        self._next_stale_recovery_at = now  # first attempt right away
        self._last_stale_status_log = now
        self._stale_poll_controlstate = None
        _LOGGER.warning("WAYZN STALE: %s — entity marked unavailable", reason)
        self._notify_anomaly(
            NOTIFY_STALE_ID,
            "Wayzn door state is stale",
            f"{reason}. The door entity has been marked unavailable rather "
            "than showing a possibly-wrong state, so Home Assistant cannot "
            "open or close the door until it recovers. Check the Wayzn app "
            "for the real door position.",
        )

    def _exit_stale(self, reason: str) -> None:
        """Recover from stale mode (log once)."""
        if not self._stale:
            return
        duration = _fmt_duration(time.monotonic() - self._stale_since)
        self._stale = False
        self._stale_reason = None
        self._stale_since_wall = None
        _LOGGER.warning(
            "WAYZN STALE RECOVERED after %s: %s (%d recovery attempt(s) made) — "
            "entity available again",
            duration, reason, self._stale_recovery_attempts,
        )
        self._clear_anomaly(NOTIFY_STALE_ID)

    def _check_drift(self, status: Dict[str, Any]) -> None:
        """Compare an authoritative poll against the last SSE-delivered state.

        On disagreement the poll wins (poll results are authoritative), but a
        disagreement means the stream and the REST snapshot were telling two
        different stories — historically the precursor to wrong door state in
        HA. Log loudly; notify after DRIFT_ALERT_THRESHOLD consecutive polls.
        Transient states (opening/closing) are skipped: during a real state
        transition the two channels legitimately lag each other.
        """
        if self._last_sse_controlstate is None or self._last_sse_state is None:
            return  # nothing from SSE yet to compare

        poll_cs = status.get("controlstate")
        poll_state = status.get("state")

        if poll_state in ("opening", "closing") or self._last_sse_state in ("opening", "closing"):
            return  # transition in flight — lag between channels is expected

        if poll_state == self._last_sse_state and poll_cs == self._last_sse_controlstate:
            if self._consecutive_drift_polls:
                _LOGGER.info("Drift resolved: poll now matches SSE (%s)", poll_state)
            self._consecutive_drift_polls = 0
            self._clear_anomaly(NOTIFY_DRIFT_ID)
            return

        self.drift_events_total += 1
        self._consecutive_drift_polls += 1
        self._last_drift_at = time.time()
        _LOGGER.warning(
            "WAYZN DRIFT: poll says controlstate=%s state=%s, SSE last said "
            "controlstate=%s state=%s — trusting poll",
            poll_cs, poll_state, self._last_sse_controlstate, self._last_sse_state,
        )
        if self._consecutive_drift_polls == DRIFT_ALERT_THRESHOLD:
            self._notify_anomaly(
                NOTIFY_DRIFT_ID,
                "Wayzn door state drift",
                f"The door's cloud snapshot has disagreed with its live event "
                f"stream {self._consecutive_drift_polls} polls in a row "
                f"(poll: {poll_state}, stream: {self._last_sse_state}). "
                "Showing the polled value. If the physical door doesn't match, "
                "check the Wayzn app.",
            )

    def _notify_anomaly(self, notification_id: str, title: str, message: str) -> None:
        """Create/replace a persistent notification for an anomaly.

        Callers gate on episode transitions so this fires once per episode,
        not per cycle. Must be called from the event loop.
        """
        self.hass.async_create_task(
            self.hass.services.async_call(
                "persistent_notification",
                "create",
                {
                    "notification_id": notification_id,
                    "title": title,
                    "message": message,
                },
            )
        )

    def _clear_anomaly(self, notification_id: str) -> None:
        """Dismiss a persistent notification. Must be called from the event loop."""
        self.hass.async_create_task(
            self.hass.services.async_call(
                "persistent_notification",
                "dismiss",
                {"notification_id": notification_id},
            )
        )

    def _record_terminal_state(self, state: str) -> None:
        """Track terminal door-state transitions and detect oscillation.

        Called from both paths that produce truth: the poll (event loop) and
        SSE updates (stream thread). deque append is safe from both.

        Only 'open'/'closed' are recorded — transient states (opening/closing)
        don't count, so a single normal open+close cycle = 2 transitions and
        doesn't alert. Oscillation = more than OSCILLATION_MAX_TRANSITIONS in
        OSCILLATION_WINDOW_S seconds: an ERROR to surface, never to tolerate
        silently (waiting dog + hardware wear + notification spam downstream).
        """
        if state not in ("open", "closed"):
            return
        now = time.monotonic()
        if self._terminal_history and self._terminal_history[-1][1] == state:
            return  # no transition
        self._terminal_history.append((now, state))

        window_start = now - OSCILLATION_WINDOW_S
        recent = [t for t, _ in self._terminal_history if t >= window_start]

        if len(recent) > OSCILLATION_MAX_TRANSITIONS:
            if not self._oscillation_active:
                self._oscillation_active = True
                _LOGGER.error(
                    "WAYZN OSCILLATION: %d open/close transitions in %ds — door "
                    "is flapping. This is an error condition, not a state.",
                    len(recent), OSCILLATION_WINDOW_S,
                )
                self.hass.loop.call_soon_threadsafe(
                    self._notify_anomaly,
                    NOTIFY_OSCILLATION_ID,
                    "Wayzn door is oscillating",
                    f"The door has changed open/closed state {len(recent)} times "
                    f"in {OSCILLATION_WINDOW_S // 60} minutes — something is "
                    "flapping it (check the door and the deck classifier). "
                    "This wears the hardware and can trap a dog.",
                )
        elif self._oscillation_active:
            self._oscillation_active = False
            _LOGGER.warning(
                "WAYZN OSCILLATION ENDED: transitions settled below threshold"
            )
            self.hass.loop.call_soon_threadsafe(
                self._clear_anomaly, NOTIFY_OSCILLATION_ID
            )

    @property
    def diagnostics(self) -> Dict[str, Any]:
        """Snapshot of link health, exposed as cover entity attributes.

        One attribute view answers "is the link healthy right now?".
        """
        def _iso(ts: Optional[float]) -> Optional[str]:
            if ts is None:
                return None
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

        return {
            "stale": self._stale,
            "stale_reason": self._stale_reason,
            "stale_since": _iso(self._stale_since_wall),
            "stale_recovery_attempts": self._stale_recovery_attempts,
            "auth_failures": self._auth_failures,
            "sse_connected": self._stream_healthy,
            "last_sse_event_at": _iso(self._last_sse_event_wall),
            "last_poll_at": _iso(self._last_poll_wall),
            "last_drift_at": _iso(self._last_drift_at),
            "drift_events_total": self.drift_events_total,
            "cloud_timestamp_age_s": (
                int(self._cloud_timestamp_age_s)
                if self._cloud_timestamp_age_s is not None
                else None
            ),
            "consecutive_command_failures": self._consecutive_command_failures,
        }

    # ========================================================================
    # SSE Streaming
    # ========================================================================

    def start_streaming(self) -> None:
        """Start the SSE streaming thread."""
        if self._stream_thread is not None and self._stream_thread.is_alive():
            _LOGGER.debug("SSE stream thread already running")
            return

        # Create a NEW stop event for each thread lifecycle to avoid
        # race conditions where clearing the old event also un-stops
        # a zombie thread from a previous cycle.
        self._stream_stop = threading.Event()
        self._stream_thread = threading.Thread(
            target=self._stream_loop,
            name=f"wayzn-sse-{self.config_entry.data.get(CONF_DEVICE_LABEL, 'door')}",
            daemon=True,
        )
        self._stream_thread.start()
        _LOGGER.info("SSE streaming started")

    def _cancel_delayed_restart(self) -> None:
        """Cancel any pending circuit-breaker restart (event loop only)."""
        if self._delayed_restart_handle is not None:
            self._delayed_restart_handle.cancel()
            self._delayed_restart_handle = None

    def stop_streaming(self) -> None:
        """Stop the SSE streaming thread."""
        # May run on an executor thread — cancel the handle on the loop.
        self.hass.loop.call_soon_threadsafe(self._cancel_delayed_restart)
        self._stream_stop.set()
        self._stream_healthy = False

        # Force-close the active SSE response to unblock iter_lines()
        resp = self._stream_response
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass
            self._stream_response = None

        if self._stream_thread is not None:
            self._stream_thread.join(timeout=5)
            self._stream_thread = None
        _LOGGER.info("SSE streaming stopped")

        # Revert to fallback polling
        self.update_interval = timedelta(seconds=FALLBACK_POLL_INTERVAL)

    def _signal_stream_stop(self) -> None:
        """Signal the SSE thread to stop without joining (non-blocking).

        Safe to call from the event loop — never blocks. The thread will
        exit on its own once stop_event is set and the response is closed.
        Old thread reference is cleared; a subsequent start_streaming()
        creates a fresh thread.
        """
        self._stream_stop.set()
        self._stream_healthy = False

        # Close the active SSE response in a fire-and-forget thread.
        # resp.close() can contend with iter_lines() in the SSE thread,
        # blocking for hundreds of seconds (observed: 278s on 2026-06-13).
        # Moving the close off MainThread keeps the event loop responsive.
        resp = self._stream_response
        if resp is not None:
            self._stream_response = None
            def _close_response():
                try:
                    resp.close()
                except Exception:
                    pass
            threading.Thread(
                target=_close_response, daemon=True, name="wayzn-resp-close"
            ).start()

        # Don't join — the thread will exit on its own
        self._stream_thread = None

        # Revert to fallback polling
        self.update_interval = timedelta(seconds=FALLBACK_POLL_INTERVAL)
        _LOGGER.debug("SSE stream stop signaled (non-blocking)")

    def _schedule_delayed_restart(self, delay: float) -> None:
        """Circuit breaker: attempt one SSE restart after a watchdog backoff.

        Called from the event loop (the poll). Without this, the 4th+
        watchdog trip left the stream permanently dead — nothing restarted
        it. Backoff values come from the watchdog (60/120/240, cap 300s) so
        we never hammer Firebase auth (2026-08-11 rate-limit incident).
        """
        if self._delayed_restart_handle is not None:
            self._delayed_restart_handle.cancel()

        def _do_restart() -> None:
            self._delayed_restart_handle = None
            if self._stream_healthy:
                return
            if self._stream_thread is not None and self._stream_thread.is_alive():
                return  # a live stream thread already exists
            _LOGGER.info("SSE: backoff elapsed, attempting circuit-breaker restart")
            self.hass.async_create_task(self._async_restart_streaming())

        self._delayed_restart_handle = self.hass.loop.call_later(delay, _do_restart)

    async def _async_restart_streaming(self) -> None:
        """Restart SSE streaming without blocking the event loop.

        Runs the blocking thread join in an executor, then starts fresh.
        Serialized via _restart_in_progress flag to prevent pile-up.
        """
        if self._restart_in_progress:
            _LOGGER.debug("SSE restart already in progress, skipping")
            return
        self._restart_in_progress = True
        try:
            # Run blocking stop (with thread join) off the event loop
            await self.hass.async_add_executor_job(self.stop_streaming)
            self.start_streaming()
        except Exception as e:
            _LOGGER.error("SSE restart failed: %s", e)
            self.update_interval = timedelta(seconds=FALLBACK_POLL_INTERVAL)
        finally:
            self._restart_in_progress = False

    def _stream_loop(self) -> None:
        """Background thread: consume Firebase SSE events and push state updates."""
        device_id = self.config_entry.data[CONF_DEVICE_ID]
        path = f"/{device_id}"

        # Capture the stop event at thread start — self._stream_stop may be
        # replaced by start_streaming() for the next thread lifecycle.
        stop_event = self._stream_stop

        # Get initial auth token
        try:
            id_token = self._get_fresh_token_sync()
        except Exception as e:
            _LOGGER.error("SSE: failed to get initial auth token: %s", e)
            return

        def on_auth_expired() -> str:
            """Refresh auth token when SSE connection gets a 401."""
            _LOGGER.info("SSE: refreshing auth token")
            return self._get_fresh_token_sync()

        def on_response(resp) -> None:
            """Track the active SSE response so stop_streaming can close it."""
            self._stream_response = resp
            if resp is not None:
                self._stream_connected_at = time.monotonic()

        try:
            for event in core.db_stream(
                "tokens",
                path,
                id_token,
                stop_event=stop_event,
                on_auth_expired=on_auth_expired,
                on_response=on_response,
            ):
                if stop_event.is_set():
                    break

                if event.event == "keep-alive":
                    self._last_stream_event = time.monotonic()
                    self._last_sse_event_wall = time.time()
                    if not self._stream_healthy:
                        self._stream_healthy = True
                        # Switch to longer heartbeat interval
                        self.hass.loop.call_soon_threadsafe(
                            self._set_heartbeat_interval
                        )
                    continue

                # Handle put/patch events
                if event.event in ("put", "patch"):
                    self._stream_healthy = True
                    self._last_stream_event = time.monotonic()
                    self._last_sse_event_wall = time.time()

                    # Full-state put at "/" means initial connect or reconnect.
                    # Always schedule a verification poll to catch anything
                    # missed during SSE gaps (auth_revoked, reconnect delays).
                    is_full_state = (event.event == "put" and event.path == "/")
                    if is_full_state:
                        _LOGGER.info(
                            "SSE: received full state put (connect/reconnect), "
                            "scheduling verification poll"
                        )
                        self.hass.loop.call_soon_threadsafe(
                            self._schedule_reconnect_poll
                        )

                    sse_ts = self._extract_timestamp_from_event(event)
                    if sse_ts is not None and (
                        self._last_sse_cloud_ts is None or sse_ts > self._last_sse_cloud_ts
                    ):
                        self._last_sse_cloud_ts = sse_ts

                    mask_update = self._extract_mask_from_event(event)
                    if mask_update is not None:
                        self.hass.loop.call_soon_threadsafe(
                            self._async_apply_sse_mask, *mask_update
                        )

                    new_data = self._extract_state_from_event(event)
                    if new_data is not None:
                        new_state = new_data.get("state", "unknown")
                        _LOGGER.debug(
                            "SSE: state update: controlstate=%s, state=%s",
                            new_data.get("controlstate"),
                            new_state,
                        )

                        # Track for poll-vs-SSE drift detection
                        self._last_sse_controlstate = new_data.get("controlstate")
                        self._last_sse_state = new_state

                        # Track transitions for oscillation detection
                        self._record_terminal_state(new_state)

                        # Trust SSE state directly — no grace window suppression
                        self.hass.loop.call_soon_threadsafe(
                            self._async_apply_sse_state, new_data
                        )
                    elif is_full_state:
                        # Full state put but no ControlState found — this is
                        # unexpected and means we can't determine door state
                        # from SSE alone. Log and rely on the verification poll.
                        _LOGGER.warning(
                            "SSE: full state put at '/' missing ControlState, "
                            "data keys: %s",
                            list(event.data.keys()) if isinstance(event.data, dict) else type(event.data).__name__,
                        )
                    else:
                        # Partial event without ControlState (other field updates)
                        _LOGGER.debug(
                            "SSE: event at path '%s' without ControlState (ignored)",
                            event.path,
                        )

        except Exception as e:
            _LOGGER.error("SSE: stream loop exited with error: %s", e)
        finally:
            self._stream_healthy = False
            if not stop_event.is_set():
                # Stream died unexpectedly, revert to fallback polling
                self.hass.loop.call_soon_threadsafe(
                    self._set_fallback_interval
                )

    def _async_apply_sse_state(self, new_data: Dict[str, Any]) -> None:
        """Apply an SSE door-state update without dropping poll-only data.

        SSE events carry only controlstate/state; settings come from polls.
        Runs on the event loop so self.data is read and written in one place.
        """
        self.async_set_updated_data({**(self.data or {}), **new_data})

    @staticmethod
    def _extract_timestamp_from_event(event: core.SSEEvent) -> Optional[float]:
        """Return the device TimeStamp (epoch s) carried by an SSE event, if any."""
        raw = None
        if event.path == "/" and isinstance(event.data, dict):
            raw = event.data.get("TimeStamp")
        elif event.path == "/TimeStamp":
            raw = event.data
        try:
            ts = float(raw)
        except (TypeError, ValueError):
            return None
        return ts / 1000.0 if ts > 1e12 else ts

    @staticmethod
    def _extract_mask_from_event(event: core.SSEEvent) -> Optional[tuple]:
        """Return (mask, cloud_ts) if an SSE event carries a new Mask, else None.

        The door pushes Mask patches at "/" (several per second during motion;
        bit 1 of each cell is live motion). Each carries its TimeStamp.
        """
        if event.path == "/" and isinstance(event.data, dict) and isinstance(event.data.get("Mask"), list):
            try:
                ts = float(event.data.get("TimeStamp"))
            except (TypeError, ValueError):
                ts = None
            return event.data["Mask"], ts
        if event.path == "/Mask" and isinstance(event.data, list):
            return event.data, None
        return None

    def _async_apply_sse_mask(self, mask: list, cloud_ts: Optional[float]) -> None:
        """Apply a live Mask from SSE to settings (event loop).

        Deliberately not async_set_updated_data: that reschedules the next
        poll, and a stream of motion patches would keep postponing the
        authoritative poll that staleness and drift checks depend on.
        """
        if not self.data or "settings" not in self.data:
            return  # no poll yet; the first poll brings the full settings
        if cloud_ts is not None and self._mask_ts is not None and cloud_ts < self._mask_ts:
            return  # older than what we already show
        if cloud_ts is not None:
            self._mask_ts = cloud_ts
        settings = {**self.data["settings"], **core.decode_mask(mask)}
        self.data = {**self.data, "settings": settings}
        self.async_update_listeners()

    def _extract_state_from_event(self, event: core.SSEEvent) -> Optional[Dict[str, Any]]:
        """Extract ControlState from an SSE event and return status dict.

        Handles both full-state puts (path="/") and partial patches (path="/ControlState").
        Returns None if the event doesn't contain a ControlState change,
        or if the ControlState value is unmapped (would produce "unknown" state).

        Rejecting unmapped states from SSE prevents sensor data from pulsing
        between valid states and "unknown" — the poll cycle handles edge cases.
        """
        controlstate = None
        position = None
        open_to = None

        if event.path == "/" and isinstance(event.data, dict):
            # Full state put or patch at root — only process if ControlState present
            if "ControlState" not in event.data:
                return None
            controlstate = event.data["ControlState"]
            position = event.data.get("Position")
            open_to = event.data.get("OpenTo")
        elif event.path == "/ControlState" and event.data is not None:
            # Direct ControlState patch
            controlstate = event.data
        elif isinstance(event.data, dict) and "ControlState" in event.data:
            # Nested patch that includes ControlState
            controlstate = event.data["ControlState"]
            position = event.data.get("Position")
            open_to = event.data.get("OpenTo")
        else:
            # Event doesn't contain ControlState — could be other fields
            return None

        # Validate controlstate is a valid integer — SSE can deliver unexpected types
        try:
            controlstate = int(controlstate)
        except (TypeError, ValueError):
            _LOGGER.warning(
                "SSE: ControlState is not a valid integer: %r (ignored)",
                controlstate,
            )
            return None

        state_label = core.controlstate_label(controlstate)

        # Reject unmapped ControlState values that would produce "unknown" state.
        # These cause sensor data to pulse between valid states and "unknown".
        # The poll cycle will maintain the correct state from the API.
        if state_label == "unknown":
            _LOGGER.info(
                "SSE: unmapped ControlState %d → 'unknown' (ignored, relying on poll)",
                controlstate,
            )
            return None

        resolved = self._resolve_door_state(
            controlstate, state_label, position, open_to,
        )

        return {
            "controlstate": controlstate,
            "state": resolved,
        }

    def _resolve_door_state(
        self, controlstate: int, state_label: str,
        position: Optional[float] = None, open_to: Optional[float] = None,
    ) -> str:
        """Resolve the door state from Firebase ControlState.

        Trust Firebase directly — the Wayzn app uses the same API and
        correctly shows all state transitions. Map ControlState labels
        to HA cover states:
          open      → open
          opening   → opening
          closing   → closing
          closed    → closed
          locked / locked_or_ajar / disengaged / paused / heat_detected
                    → closed (genuinely closed from a dog's perspective)
          unknown/unmapped → "unknown" (never guess: not lying beats a
                    confident wrong state; "unknown" also keeps close-side
                    automations from treating an unsure door as shut)
        """
        if state_label in ("open",):
            return "open"
        if state_label in ("opening",):
            return "opening"
        if state_label in ("closing",):
            return "closing"
        if state_label in ("closed",):
            return "closed"

        if state_label == "unknown":
            _LOGGER.info(
                "ControlState %d is unmapped — reporting 'unknown' rather "
                "than guessing a direction",
                controlstate,
            )
            return "unknown"

        # Anything else (locked_or_ajar, disengaged, paused, heat_detected,
        # locked) is genuinely a not-open state for the door panel.
        _LOGGER.debug(
            "ControlState %d label '%s' mapped to 'closed' (default)",
            controlstate, state_label,
        )
        return "closed"

    def _set_heartbeat_interval(self) -> None:
        """Switch to longer heartbeat interval (called from event loop)."""
        self.update_interval = timedelta(seconds=HEARTBEAT_POLL_INTERVAL)
        _LOGGER.debug("Poll interval set to heartbeat (%ds)", HEARTBEAT_POLL_INTERVAL)

    def _set_fallback_interval(self) -> None:
        """Switch to normal polling interval (called from event loop)."""
        self.update_interval = timedelta(seconds=FALLBACK_POLL_INTERVAL)
        _LOGGER.debug("Poll interval set to fallback (%ds)", FALLBACK_POLL_INTERVAL)

    def _schedule_reconnect_poll(self) -> None:
        """Schedule a verification poll after SSE reconnect.

        After any SSE reconnect, there's a window where state changes may
        have been missed. Poll Firebase directly to reconcile. Uses a short
        delay (3s) to let the SSE initial put settle first, then verifies
        with an authoritative poll.
        """
        async def _reconnect_verify():
            _LOGGER.info("Running post-reconnect verification poll")
            await self.async_request_refresh()

        self.hass.loop.call_later(3, lambda: asyncio.ensure_future(_reconnect_verify()))

    # ========================================================================
    # Device commands
    # ========================================================================

    async def async_send_command(self, command: str) -> None:
        """Send a command to the device (open/close).

        Commands are ALWAYS sent to the device, regardless of the currently
        believed state — the believed state may be wrong (2026-08-11: cloud
        said "open" while the physical door was closed; an unsuppressed open
        command was the only thing that could rescue a locked-out dog).
        """
        try:
            email = self.config_entry.data[CONF_EMAIL]
            password = self.config_entry.data[CONF_PASSWORD]
            api_key = self.config_entry.data[CONF_API_KEY]
            device_id = self.config_entry.data[CONF_DEVICE_ID]

            # Track command for verification (stale verifications self-cancel)
            self._last_command = command
            self._last_command_time = time.monotonic()
            self._command_seq += 1
            seq = self._command_seq

            # Optimistic state update for responsive UI — will be corrected
            # by the next poll or SSE event with real Firebase data
            optimistic_state = "opening" if command == "open" else "closing"
            if self.data:
                optimistic_data = self.data.copy()
                optimistic_data["state"] = optimistic_state
                self.async_set_updated_data(optimistic_data)

            _LOGGER.debug("Issuing command '%s'", command)

            id_token = await self.hass.async_add_executor_job(
                self._get_cached_or_fresh_token, email, password, api_key
            )

            await self.hass.async_add_executor_job(
                self._send_command_sync, device_id, id_token, command
            )

            # Verify the door actually reaches the commanded state.
            self._schedule_command_verification(command, seq)

        except core.WayznError as e:
            _LOGGER.error("Failed to send command: %s", e)
            self._handle_command_failure(command)
            raise UpdateFailed(f"Failed to send command: {e}") from e
        except Exception as e:
            _LOGGER.error("Unexpected error sending command: %s", e)
            self._handle_command_failure(command)
            raise UpdateFailed(f"Unexpected error: {e}") from e

    async def async_set_mask_cell(self, cell: int, enabled: bool) -> None:
        """Enable/disable one motion detection cell and verify it took.

        Reads the cell fresh before sending, because the app's toggle command
        carries the cell's current value XOR 1. On no read-back within
        SETTING_VERIFY_TIMEOUT_S, raises and leaves a persistent notification.
        """
        async with self._settings_lock:
            def read_cell(node: Dict[str, Any]) -> int:
                return int(node["Mask"][cell])

            current = read_cell(await self.hass.async_add_executor_job(self._fetch_node_sync))
            if bool(current & 1) != enabled:
                await self._async_send_setting(
                    core.update_mask_command(current, cell),
                    lambda node: bool(read_cell(node) & 1) == enabled,
                    f"detection cell {cell} {'on' if enabled else 'off'}",
                )
            await self.async_request_refresh()

    def _fetch_node_sync(self) -> Dict[str, Any]:
        """Read tokens:/{device_id} (sync, for the executor)."""
        email = self.config_entry.data[CONF_EMAIL]
        password = self.config_entry.data[CONF_PASSWORD]
        api_key = self.config_entry.data[CONF_API_KEY]
        id_token = self._get_cached_or_fresh_token(email, password, api_key)
        node = core.db_get("tokens", f"/{self.config_entry.data[CONF_DEVICE_ID]}", id_token)
        if not isinstance(node, dict):
            raise HomeAssistantError("Wayzn device node is empty")
        return node

    async def _async_send_setting(self, command: str, applied, description: str) -> None:
        """Send a signed settings command, then poll until applied(node) is true."""
        email = self.config_entry.data[CONF_EMAIL]
        password = self.config_entry.data[CONF_PASSWORD]
        api_key = self.config_entry.data[CONF_API_KEY]
        device_id = self.config_entry.data[CONF_DEVICE_ID]
        try:
            id_token = await self.hass.async_add_executor_job(
                self._get_cached_or_fresh_token, email, password, api_key
            )
            await self.hass.async_add_executor_job(
                self._send_command_sync, device_id, id_token, command
            )
        except core.WayznError as e:
            raise HomeAssistantError(f"Wayzn: failed to send {description}: {e}") from e

        deadline = time.monotonic() + SETTING_VERIFY_TIMEOUT_S
        while time.monotonic() < deadline:
            await asyncio.sleep(SETTING_VERIFY_INTERVAL_S)
            if applied(await self.hass.async_add_executor_job(self._fetch_node_sync)):
                _LOGGER.info("Setting applied and verified: %s (%s)", description, command)
                self._clear_anomaly(NOTIFY_SETTING_ID)
                return

        _LOGGER.warning("Setting NOT applied after %ss: %s (%s)", SETTING_VERIFY_TIMEOUT_S, description, command)
        self._notify_anomaly(
            NOTIFY_SETTING_ID,
            "Wayzn setting not applied",
            f"Sent {description} to the door, but it did not read back within "
            f"{SETTING_VERIFY_TIMEOUT_S}s. Check the setting in the Wayzn app.",
        )
        raise HomeAssistantError(f"Wayzn: {description} was sent but not confirmed by the door")

    def _handle_command_failure(self, command: str) -> None:
        """Handle a command that raised during send (event loop context).

        A delivery error (e.g. the 20s agent.electricimp.com read timeouts of
        2026-08-11) does NOT prove the device didn't receive the command, so
        we schedule a resync poll — one timed-out command must never leave
        the optimistic 'opening/closing' state wedged. Also notify, since a
        failed open is exactly the dog-lockout scenario.
        """
        self._consecutive_command_failures += 1
        self.hass.loop.call_later(
            8,
            lambda: asyncio.ensure_future(self.async_request_refresh()),
        )
        if not self._command_anomaly_active:
            self._command_anomaly_active = True
            self._notify_anomaly(
                NOTIFY_COMMAND_ID,
                "Wayzn door command failed",
                f"Sending '{command}' to the door failed (cloud/agent did not "
                "respond cleanly). The door may still have moved — state will "
                "re-sync shortly, but check the door if a dog may be waiting.",
            )

    def _schedule_command_verification(self, command: str, seq: int) -> None:
        """Verify the door reaches the commanded state (event loop context).

        Wayzn cloud takes 5-15s to reflect a move in Firebase. Poll at each
        delay in COMMAND_VERIFY_DELAYS; success at any point clears any
        command-failure notification. If the FINAL check still doesn't show
        the target state, log ERROR and notify — a dog lockout must be
        visible, not silent.
        """
        target = "open" if command == "open" else "closed"
        for delay in COMMAND_VERIFY_DELAYS:
            is_final = delay == COMMAND_VERIFY_DELAYS[-1]
            self.hass.loop.call_later(
                delay,
                lambda s=seq, t=target, f=is_final, d=delay: asyncio.ensure_future(
                    self._async_verify_command(s, t, f, d)
                ),
            )

    async def _async_verify_command(
        self, seq: int, target: str, is_final: bool, delay: int
    ) -> None:
        """Single verification poll; skips if a newer command superseded this one."""
        if seq != self._command_seq:
            return
        await self.async_request_refresh()
        state = (self.data or {}).get("state")

        if state == target:
            _LOGGER.info(
                "Command verification: door reached %s (%ds after command)",
                target, delay,
            )
            self._consecutive_command_failures = 0
            if self._command_anomaly_active:
                self._command_anomaly_active = False
                self._clear_anomaly(NOTIFY_COMMAND_ID)
            return

        if not is_final:
            _LOGGER.debug(
                "Command verification (%ds): state=%s, waiting for %s",
                delay, state, target,
            )
            return

        self._consecutive_command_failures += 1
        _LOGGER.error(
            "WAYZN COMMAND FAILED: door did not reach %s within %ds of command "
            "(state=%s). The device may not have received the command — a "
            "waiting dog could be locked out. Consecutive failures: %d",
            target, COMMAND_VERIFY_DELAYS[-1], state,
            self._consecutive_command_failures,
        )
        if not self._command_anomaly_active:
            self._command_anomaly_active = True
            self._notify_anomaly(
                NOTIFY_COMMAND_ID,
                "Wayzn door didn't respond to command",
                f"The door was told to reach '{target}' but still reports "
                f"'{state}' after {COMMAND_VERIFY_DELAYS[-1]}s. The device "
                "may not have received the command — if a dog is waiting at "
                "the door, check it now.",
            )

    def _send_command_sync(
        self, device_id: str, id_token: str, command: str
    ) -> None:
        """Send command to device (sync function for executor)."""
        import requests

        try:
            wkey = self.config_entry.data.get(CONF_WKEY)
            knum = self.config_entry.data.get(CONF_KNUM)
            agenturl = self.config_entry.data.get(CONF_AGENTURL)

            if not wkey:
                raise core.WayznError("No wKey found in config entry")
            if not agenturl:
                raise core.WayznError("No agent URL found in config entry")

            # Fetch nonce from nonce DB
            nonce_data = core.db_get("nonce", f"/{device_id}", id_token)
            nonce = nonce_data.get("nonce")
            if not nonce:
                raise core.WayznError("No nonce found in nonce DB for device")

            knum_parsed, key_bytes = core.parse_wkey(wkey)
            auth_header = core.compute_auth(
                command, nonce, key_bytes, core.DEFAULT_HASH_ALGORITHM
            )

            headers = {
                "User-Agent": "wayzn-ha/0.2",
                "Authorization": auth_header,
                "x-WayznKNum": str(knum or knum_parsed),
            }

            response = requests.post(
                agenturl, headers=headers, data=command, timeout=20,
            )

            if response.status_code >= 400:
                raise core.WayznError(
                    f"Agent returned error {response.status_code}: {response.text[:200]}"
                )

            _LOGGER.debug("Command '%s' sent successfully", command)

        except core.WayznError as e:
            raise e
        except requests.RequestException as e:
            raise core.WayznError(f"Failed to send request to agent: {e}") from e
        except Exception as e:
            raise core.WayznError(f"Unexpected error sending command: {e}") from e
