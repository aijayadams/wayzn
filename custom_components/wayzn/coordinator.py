"""DataUpdateCoordinator for Wayzn integration with Firebase SSE streaming."""

import asyncio
import logging
import threading
import time
from datetime import timedelta
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
FALLBACK_POLL_INTERVAL = DEFAULT_POLL_INTERVAL  # 30 seconds when streaming is down
STREAM_STALE_THRESHOLD = 120  # seconds — if no SSE event in this window, stream is dead


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

        # SSE streaming state
        self._stream_thread: Optional[threading.Thread] = None
        self._stream_stop: threading.Event = threading.Event()
        self._stream_healthy: bool = False
        self._last_stream_event: float = 0.0  # monotonic timestamp of last SSE event

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
        self, email: str, password: str, api_key: str, force: bool = False
    ) -> str:
        """Get cached auth token if valid, otherwise authenticate fresh."""
        import time

        if not force and self._auth_token and self._token_expires_at:
            if time.time() < (self._token_expires_at - 60):
                return self._auth_token

        _LOGGER.debug("Authenticating with fresh credentials")
        auth = core.fb_sign_in_email_password(email, password, api_key)
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
        """Get a fresh auth token (for SSE auth refresh callback)."""
        email = self.config_entry.data[CONF_EMAIL]
        password = self.config_entry.data[CONF_PASSWORD]
        api_key = self.config_entry.data[CONF_API_KEY]
        return self._get_cached_or_fresh_token(email, password, api_key, force=True)

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
            if (
                self._stream_healthy
                and self._last_stream_event > 0
                and (time.monotonic() - self._last_stream_event) > STREAM_STALE_THRESHOLD
            ):
                _LOGGER.warning(
                    "SSE: stream stale (no events in %ds), restarting",
                    int(time.monotonic() - self._last_stream_event),
                )
                self.stop_streaming()
                self.start_streaming()

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
            if isinstance(status_data, dict):
                controlstate = status_data.get("ControlState")
            return {
                "controlstate": controlstate,
                "state": core.controlstate_label(controlstate),
            }
        except core.WayznError as e:
            raise e
        except Exception as e:
            raise core.WayznError(f"Failed to get device status: {e}") from e

    # ========================================================================
    # SSE Streaming
    # ========================================================================

    def start_streaming(self) -> None:
        """Start the SSE streaming thread."""
        if self._stream_thread is not None and self._stream_thread.is_alive():
            _LOGGER.debug("SSE stream thread already running")
            return

        self._stream_stop.clear()
        self._stream_thread = threading.Thread(
            target=self._stream_loop,
            name=f"wayzn-sse-{self.config_entry.data.get(CONF_DEVICE_LABEL, 'door')}",
            daemon=True,
        )
        self._stream_thread.start()
        _LOGGER.info("SSE streaming started")

    def stop_streaming(self) -> None:
        """Stop the SSE streaming thread."""
        self._stream_stop.set()
        self._stream_healthy = False
        if self._stream_thread is not None:
            self._stream_thread.join(timeout=5)
            self._stream_thread = None
        _LOGGER.info("SSE streaming stopped")

        # Revert to fallback polling
        self.update_interval = timedelta(seconds=FALLBACK_POLL_INTERVAL)

    def _stream_loop(self) -> None:
        """Background thread: consume Firebase SSE events and push state updates."""
        device_id = self.config_entry.data[CONF_DEVICE_ID]
        path = f"/{device_id}"

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

        try:
            for event in core.db_stream(
                "tokens",
                path,
                id_token,
                stop_event=self._stream_stop,
                on_auth_expired=on_auth_expired,
            ):
                if self._stream_stop.is_set():
                    break

                if event.event == "keep-alive":
                    self._last_stream_event = time.monotonic()
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
                    new_data = self._extract_state_from_event(event)
                    if new_data is not None:
                        _LOGGER.debug(
                            "SSE: state update: controlstate=%s, state=%s",
                            new_data.get("controlstate"),
                            new_data.get("state"),
                        )
                        # Push update to HA on the event loop
                        self.hass.loop.call_soon_threadsafe(
                            self.async_set_updated_data, new_data
                        )

        except Exception as e:
            _LOGGER.error("SSE: stream loop exited with error: %s", e)
        finally:
            self._stream_healthy = False
            if not self._stream_stop.is_set():
                # Stream died unexpectedly, revert to fallback polling
                self.hass.loop.call_soon_threadsafe(
                    self._set_fallback_interval
                )

    def _extract_state_from_event(self, event: core.SSEEvent) -> Optional[Dict[str, Any]]:
        """Extract ControlState from an SSE event and return status dict.

        Handles both full-state puts (path="/") and partial patches (path="/ControlState").
        Returns None if the event doesn't contain a ControlState change.
        """
        controlstate = None

        if event.path == "/" and isinstance(event.data, dict):
            # Full state put or patch at root — only process if ControlState present
            if "ControlState" not in event.data:
                return None
            controlstate = event.data["ControlState"]
        elif event.path == "/ControlState" and event.data is not None:
            # Direct ControlState patch
            controlstate = event.data
        elif isinstance(event.data, dict) and "ControlState" in event.data:
            # Nested patch that includes ControlState
            controlstate = event.data["ControlState"]
        else:
            # Event doesn't contain ControlState — could be other fields
            return None

        return {
            "controlstate": controlstate,
            "state": core.controlstate_label(controlstate),
        }

    def _set_heartbeat_interval(self) -> None:
        """Switch to longer heartbeat interval (called from event loop)."""
        self.update_interval = timedelta(seconds=HEARTBEAT_POLL_INTERVAL)
        _LOGGER.debug("Poll interval set to heartbeat (%ds)", HEARTBEAT_POLL_INTERVAL)

    def _set_fallback_interval(self) -> None:
        """Switch to normal polling interval (called from event loop)."""
        self.update_interval = timedelta(seconds=FALLBACK_POLL_INTERVAL)
        _LOGGER.debug("Poll interval set to fallback (%ds)", FALLBACK_POLL_INTERVAL)

    # ========================================================================
    # Device commands
    # ========================================================================

    async def async_send_command(self, command: str) -> None:
        """Send a command to the device (open/close)."""
        try:
            email = self.config_entry.data[CONF_EMAIL]
            password = self.config_entry.data[CONF_PASSWORD]
            api_key = self.config_entry.data[CONF_API_KEY]
            device_id = self.config_entry.data[CONF_DEVICE_ID]

            # Optimistic state update for responsive UI
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

            # If streaming is active, the SSE event will confirm the state change.
            # If not, trigger a poll to pick it up.
            if not self._stream_healthy:
                await self.async_request_refresh()

        except core.WayznError as e:
            _LOGGER.error("Failed to send command: %s", e)
            raise UpdateFailed(f"Failed to send command: {e}") from e
        except Exception as e:
            _LOGGER.error("Unexpected error sending command: %s", e)
            raise UpdateFailed(f"Unexpected error: {e}") from e

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
