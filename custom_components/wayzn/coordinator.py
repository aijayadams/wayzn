"""DataUpdateCoordinator for Wayzn integration with Firebase SSE streaming."""

import asyncio
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
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
CLOUD_TIMESTAMP_STALE_THRESHOLD = 300  # seconds (5 min)

# Drift alerting: after this many consecutive polls disagreeing with the SSE
# stream's last-known state, notify (once per episode).
DRIFT_ALERT_THRESHOLD = 3

# Persistent notification IDs (one per anomaly type — an episode updates in
# place, and is dismissed when the condition clears)
NOTIFY_STALE_ID = "wayzn_stale_state"
NOTIFY_DRIFT_ID = "wayzn_state_drift"
NOTIFY_COMMAND_ID = "wayzn_command_failed"
NOTIFY_OSCILLATION_ID = "wayzn_state_oscillation"

# Oscillation detection: rapid open/close/open cycles are an ERROR, not a
# state (2026-08-12: classifier/Wayzn interaction flapped the door every ~30s
# for 20min — wear on the hardware, spam to the user). Count TERMINAL-state
# transitions only (open/closed); one full open+close cycle = 2 transitions,
# so >3 in the window means at least two full flap cycles.
OSCILLATION_WINDOW_S = 300  # seconds
OSCILLATION_MAX_TRANSITIONS = 3

# Command tracking for logging (grace window removed — trust Firebase directly)


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
        self._last_fresh_auth_time: float = 0.0  # time.time() of last fresh Firebase sign-in
        self._auth_rate_limit_secs: float = 300.0  # min 5 minutes between fresh auth calls

        # SSE streaming state
        self._stream_thread: Optional[threading.Thread] = None
        self._stream_stop: threading.Event = threading.Event()
        self._stream_healthy: bool = False
        self._last_stream_event: float = 0.0  # monotonic timestamp of last SSE event
        self._stream_response = None  # Active SSE response, closed on stop to unblock iter_lines
        self._stream_connected_at: float = 0.0  # monotonic time when SSE last connected
        self._consecutive_reconnects: int = 0  # watchdog reconnect counter for backoff
        self._max_reconnect_backoff: float = 300.0  # max 5 min backoff between reconnects

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

        # Circuit breaker: handle for a watchdog-scheduled delayed SSE restart
        self._delayed_restart_handle = None

        # Oscillation detection: recent terminal-state transitions (monotonic, state)
        from collections import deque
        self._terminal_history: deque = deque(maxlen=64)
        self._oscillation_active: bool = False
        # Door state tracking
        # (direction tracking removed — trust Firebase directly)

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
        """Get cached auth token if valid, otherwise authenticate fresh.

        Rate-limits fresh Firebase sign-in calls to prevent API key revocation
        from excessive auth hammering (e.g., SSE reconnect loops).

        Args:
            auth_timeout: Firebase auth request timeout in seconds.
                          Use shorter values for SSE reconnect context.
        """
        import time

        now = time.time()

        if not force and self._auth_token and self._token_expires_at:
            if now < (self._token_expires_at - 60):
                return self._auth_token

        # Rate-limit: refuse fresh auth if we just did one recently
        elapsed_since_last_auth = now - self._last_fresh_auth_time
        if self._last_fresh_auth_time > 0 and elapsed_since_last_auth < self._auth_rate_limit_secs:
            if self._auth_token:
                _LOGGER.warning(
                    "Auth rate-limited: last fresh auth was %.0fs ago (min %ds), using cached token",
                    elapsed_since_last_auth,
                    self._auth_rate_limit_secs,
                )
                return self._auth_token
            else:
                _LOGGER.error(
                    "Auth rate-limited and no cached token available; "
                    "last fresh auth was %.0fs ago (min %ds)",
                    elapsed_since_last_auth,
                    self._auth_rate_limit_secs,
                )
                raise core.WayznError(
                    f"Firebase auth rate-limited: retry after {self._auth_rate_limit_secs - elapsed_since_last_auth:.0f}s"
                )

        _LOGGER.debug("Authenticating with fresh credentials")
        auth = core.fb_sign_in_email_password(email, password, api_key, timeout=auth_timeout)
        self._last_fresh_auth_time = time.time()  # track AFTER the call
        self._auth_token = auth.get("idToken")

        if not self._auth_token:
            raise core.WayznError("No ID token in response")

        try:
            expires_in = int(auth.get("expiresIn", 3600))
        except (ValueError, TypeError):
            expires_in = 3600

        self._token_expires_at = time.time() + expires_in
        return self._auth_token

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

        When SSE streaming is healthy, this runs infrequently as a heartbeat.
        When streaming is down, this is the primary update mechanism.
        """
        try:
            email = self.config_entry.data[CONF_EMAIL]
            password = self.config_entry.data[CONF_PASSWORD]
            api_key = self.config_entry.data[CONF_API_KEY]
            device_id = self.config_entry.data[CONF_DEVICE_ID]

            try:
                id_token = await self.hass.async_add_executor_job(
                    self._get_cached_or_fresh_token, email, password, api_key
                )
            except core.WayznError as e:
                raise ConfigEntryAuthFailed(f"Authentication failed: {e}") from e

            status = await self.hass.async_add_executor_job(
                self._get_status_summary, device_id, id_token
            )

            _LOGGER.debug(
                "Poll: controlstate=%s, state=%s, stream_healthy=%s",
                status.get("controlstate"),
                status.get("state"),
                self._stream_healthy,
            )

            # Staleness watchdog: if stream claims healthy but no events
            # received in STREAM_STALE_THRESHOLD seconds, restart it
            now = time.monotonic()
            stream_stale = (
                self._stream_healthy
                and self._last_stream_event > 0
                and (now - self._last_stream_event) > STREAM_STALE_THRESHOLD
            )
            # Dead-on-connect: SSE connected but never received ANY event
            dead_on_connect = (
                not self._stream_healthy
                and self._stream_connected_at > 0
                and (now - self._stream_connected_at) > STREAM_STALE_THRESHOLD
                and self._stream_thread is not None
                and self._stream_thread.is_alive()
            )
            if stream_stale or dead_on_connect:
                self._consecutive_reconnects += 1
                reason = "stale" if stream_stale else "dead-on-connect"

                # Exponential backoff: 60s, 120s, 240s, capped at 300s
                backoff = min(
                    STREAM_STALE_THRESHOLD * (2 ** (self._consecutive_reconnects - 1)),
                    self._max_reconnect_backoff,
                )
                elapsed = int(now - (self._last_stream_event if stream_stale else self._stream_connected_at))

                if self._consecutive_reconnects > 3:
                    _LOGGER.warning(
                        "SSE: stream %s (no events in %ds), reconnect #%d — "
                        "backing off %ds before restart to avoid auth hammering",
                        reason, elapsed, self._consecutive_reconnects, int(backoff),
                    )
                    # Circuit breaker: signal stop, back off to heartbeat
                    # pacing, then attempt ONE restart when the backoff
                    # elapses. (Previously the 4th+ watchdog trip left the
                    # stream permanently dead — nothing ever restarted it.)
                    self._signal_stream_stop()
                    self.update_interval = timedelta(seconds=backoff)
                    self._schedule_delayed_restart(backoff)
                else:
                    _LOGGER.warning(
                        "SSE: stream %s (no events in %ds), reconnect #%d, restarting",
                        reason, elapsed, self._consecutive_reconnects,
                    )
                    # Signal stop immediately, then schedule async restart
                    # that joins the old thread off the event loop
                    self._signal_stream_stop()
                    self.hass.async_create_task(self._async_restart_streaming())
            elif self._stream_healthy:
                # Stream is healthy — reset consecutive reconnect counter
                self._consecutive_reconnects = 0
                # Cancel any pending circuit-breaker restart
                self._cancel_delayed_restart()

            # --- Data honesty / drift checks -------------------------------
            self._last_poll_wall = time.time()
            self._update_cloud_freshness(status.get("cloud_timestamp"))

            stream_dead = stream_stale or dead_on_connect
            cloud_stale = (
                self._cloud_timestamp_age_s is not None
                and self._cloud_timestamp_age_s > CLOUD_TIMESTAMP_STALE_THRESHOLD
            )
            if cloud_stale:
                self._enter_stale(
                    f"Firebase TimeStamp is {int(self._cloud_timestamp_age_s)}s old "
                    f"(limit {CLOUD_TIMESTAMP_STALE_THRESHOLD}s) — cloud data may "
                    "not reflect the physical door"
                )
            elif stream_dead:
                self._enter_stale("SSE stream is down and beyond the watchdog threshold")
            elif self._stale:
                self._exit_stale("polls are fresh and the stream is healthy")

            # Compare this authoritative poll against the SSE-tracked state
            self._check_drift(status)

            # Track transitions for oscillation detection
            self._record_terminal_state(status.get("state"))

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
        self._stale = True
        _LOGGER.warning("WAYZN STALE: %s — entity marked unavailable", reason)
        self._notify_anomaly(
            NOTIFY_STALE_ID,
            "Wayzn door state is stale",
            f"{reason}. The door entity has been marked unavailable rather "
            "than showing a possibly-wrong state. Check the Wayzn app for "
            "the real door position.",
        )

    def _exit_stale(self, reason: str) -> None:
        """Recover from stale mode (log once)."""
        if not self._stale:
            return
        self._stale = False
        _LOGGER.warning("WAYZN STALE RECOVERED: %s — entity available again", reason)
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
