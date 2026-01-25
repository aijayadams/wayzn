"""DataUpdateCoordinator for Wayzn integration."""

import asyncio
import logging
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

# Polling intervals
NORMAL_POLL_INTERVAL = DEFAULT_POLL_INTERVAL  # 30 seconds
ACTIVE_POLL_INTERVAL = 2  # 2 seconds during active commands
MAX_ACTIVE_POLL_TIME = 60  # Maximum 60 seconds of fast polling


class WayznDataUpdateCoordinator(DataUpdateCoordinator):
    """Coordinator for Wayzn device data updates."""

    def __init__(self, hass: HomeAssistant, config_entry) -> None:
        """Initialize the coordinator."""
        self.config_entry = config_entry
        self._auth_token: Optional[str] = None
        self._token_expires_at: Optional[float] = None
        self._pending_command: Optional[str] = None
        self._target_state: Optional[str] = None
        self._active_command_start: Optional[float] = None

        super().__init__(
            hass,
            _LOGGER,
            name=f"Wayzn {config_entry.data.get(CONF_DEVICE_LABEL, 'Dog Door')}",
            update_interval=timedelta(seconds=NORMAL_POLL_INTERVAL),
        )

    def _get_cached_or_fresh_token(
        self, email: str, password: str, api_key: str, force: bool = False
    ) -> str:
        """Get cached auth token if valid, otherwise authenticate fresh.

        This reduces Firebase API calls and prevents hitting password verification quota limits.
        """
        import time

        # Check if we have a valid cached token (with 60 second skew for safety)
        if not force and self._auth_token and self._token_expires_at:
            if time.time() < (self._token_expires_at - 60):
                _LOGGER.debug("Using cached authentication token")
                return self._auth_token

        # Token expired or not cached, authenticate fresh
        _LOGGER.debug("Authenticating with fresh credentials")
        auth = core.fb_sign_in_email_password(email, password, api_key)
        self._auth_token = auth.get("idToken")

        if not self._auth_token:
            raise core.WayznError("No ID token in response")

        # Store token expiry time
        try:
            expires_in = int(auth.get("expiresIn", 3600))
        except (ValueError, TypeError):
            expires_in = 3600

        import time
        self._token_expires_at = time.time() + expires_in

        return self._auth_token

    async def _async_update_data(self) -> Dict[str, Any]:
        """Fetch device status from Firebase."""
        try:
            # Get credentials from config entry
            email = self.config_entry.data[CONF_EMAIL]
            password = self.config_entry.data[CONF_PASSWORD]
            api_key = self.config_entry.data[CONF_API_KEY]
            device_id = self.config_entry.data[CONF_DEVICE_ID]

            # Get cached or fresh token (reduces Firebase quota usage)
            try:
                id_token = await self.hass.async_add_executor_job(
                    self._get_cached_or_fresh_token, email, password, api_key
                )
            except core.WayznError as e:
                raise ConfigEntryAuthFailed(f"Authentication failed: {e}") from e

            # Fetch device status summary
            status = await self.hass.async_add_executor_job(
                self._get_status_summary, device_id, id_token
            )

            _LOGGER.debug("Device status: controlstate=%s, state=%s", status.get("controlstate"), status.get("state"))

            # Check if we should adjust polling frequency
            await self._update_poll_interval(status)

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
            # Get device status from tokens database
            status_data = core.db_get("tokens", f"/{device_id}", id_token)

            # Extract control state and convert to label
            controlstate = None
            if isinstance(status_data, dict):
                controlstate = status_data.get("ControlState")

            state_label = core.controlstate_label(controlstate)

            return {
                "controlstate": controlstate,
                "state": state_label,
            }

        except core.WayznError as e:
            raise e
        except Exception as e:
            raise core.WayznError(f"Failed to get device status: {e}") from e

    async def _update_poll_interval(self, status: Dict[str, Any]) -> None:
        """Update polling interval based on active commands."""
        import time

        if not self._pending_command:
            # No active command, use normal polling
            self.update_interval = timedelta(seconds=NORMAL_POLL_INTERVAL)
            return

        # Check if we've reached the target state
        current_state = status.get("state")
        if current_state == self._target_state:
            _LOGGER.debug(
                "Target state '%s' reached, reverting to normal polling", self._target_state
            )
            self._pending_command = None
            self._target_state = None
            self._active_command_start = None
            self.update_interval = timedelta(seconds=NORMAL_POLL_INTERVAL)
            return

        # Check if we've exceeded max active polling time
        if self._active_command_start:
            elapsed = time.time() - self._active_command_start
            if elapsed > MAX_ACTIVE_POLL_TIME:
                _LOGGER.warning(
                    "Active command timeout after %.1f seconds, reverting to normal polling",
                    elapsed,
                )
                self._pending_command = None
                self._target_state = None
                self._active_command_start = None
                self.update_interval = timedelta(seconds=NORMAL_POLL_INTERVAL)
                return

        # Still waiting for target state, use fast polling
        self.update_interval = timedelta(seconds=ACTIVE_POLL_INTERVAL)

    async def async_send_command(self, command: str) -> None:
        """Send a command to the device (open/close)."""
        try:
            import time

            email = self.config_entry.data[CONF_EMAIL]
            password = self.config_entry.data[CONF_PASSWORD]
            api_key = self.config_entry.data[CONF_API_KEY]
            device_id = self.config_entry.data[CONF_DEVICE_ID]

            # Set up fast polling for this command
            self._pending_command = command
            self._target_state = "open" if command == "open" else "closed"
            self._active_command_start = time.time()

            # Optimistic state update: immediately show opening/closing to make UI responsive
            optimistic_state = "opening" if command == "open" else "closing"
            if self.data:
                optimistic_data = self.data.copy()
                optimistic_data["state"] = optimistic_state
                self.data = optimistic_data
                self.async_update_listeners()

            _LOGGER.debug(
                "Issuing command '%s', expecting state '%s'. Starting fast polling.",
                command,
                self._target_state,
            )

            # Get cached or fresh token for command
            id_token = await self.hass.async_add_executor_job(
                self._get_cached_or_fresh_token, email, password, api_key
            )

            await self.hass.async_add_executor_job(
                self._send_command_sync, device_id, id_token, command
            )

            # Trigger immediate refresh to get latest state
            await self.async_refresh()

        except core.WayznError as e:
            _LOGGER.error("Failed to send command: %s", e)
            # Reset pending command on error
            self._pending_command = None
            self._target_state = None
            self._active_command_start = None
            raise UpdateFailed(f"Failed to send command: {e}") from e
        except Exception as e:
            _LOGGER.error("Unexpected error sending command: %s", e)
            # Reset pending command on error
            self._pending_command = None
            self._target_state = None
            self._active_command_start = None
            raise UpdateFailed(f"Unexpected error: {e}") from e

    def _send_command_sync(
        self, device_id: str, id_token: str, command: str
    ) -> None:
        """Send command to device (sync function for executor)."""
        import requests

        try:

            # Get device info from config entry
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

            # Parse wkey to get key bytes
            knum_parsed, key_bytes = core.parse_wkey(wkey)

            # Compute authorization header
            auth_header = core.compute_auth(
                command, nonce, key_bytes, core.DEFAULT_HASH_ALGORITHM
            )

            # Prepare headers
            headers = {
                "User-Agent": "wayzn-ha/0.1",
                "Authorization": auth_header,
                "x-WayznKNum": str(knum or knum_parsed),
            }

            # Send POST request to agent
            response = requests.post(
                agenturl,
                headers=headers,
                data=command,
                timeout=20,
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
