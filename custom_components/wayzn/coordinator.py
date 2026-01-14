"""DataUpdateCoordinator for Wayzn integration."""

import logging
from datetime import timedelta
from typing import Any, Dict, Optional

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from . import wayzn_core as core
from .const import (
    CONF_API_KEY,
    CONF_DEVICE_ID,
    CONF_DEVICE_LABEL,
    CONF_EMAIL,
    CONF_PASSWORD,
    DEFAULT_POLL_INTERVAL,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


class WayznDataUpdateCoordinator(DataUpdateCoordinator):
    """Coordinator for Wayzn device data updates."""

    def __init__(self, hass: HomeAssistant, config_entry) -> None:
        """Initialize the coordinator."""
        self.config_entry = config_entry
        self._auth_token: Optional[str] = None

        super().__init__(
            hass,
            _LOGGER,
            name=f"Wayzn {config_entry.data[CONF_DEVICE_LABEL]}",
            update_interval=timedelta(seconds=DEFAULT_POLL_INTERVAL),
        )

    async def _async_update_data(self) -> Dict[str, Any]:
        """Fetch device status from Firebase."""
        try:
            # Get credentials from config entry
            email = self.config_entry.data[CONF_EMAIL]
            password = self.config_entry.data[CONF_PASSWORD]
            api_key = self.config_entry.data[CONF_API_KEY]
            device_id = self.config_entry.data[CONF_DEVICE_ID]

            # Authenticate (will use cached token if valid)
            try:
                auth = await self.hass.async_add_executor_job(
                    core.fb_sign_in_email_password, email, password, api_key
                )
                self._auth_token = auth.get("idToken")

                if not self._auth_token:
                    raise core.WayznError("No ID token in response")

            except core.WayznError as e:
                raise ConfigEntryAuthFailed(f"Authentication failed: {e}") from e

            # Fetch device status summary
            status = await self.hass.async_add_executor_job(
                self._get_status_summary, email, password, api_key, device_id
            )

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
        self, email: str, password: str, api_key: str, device_id: str
    ) -> Dict[str, Any]:
        """Get device status summary (sync function for executor)."""
        # Create a minimal config structure for wayzn_core
        # Since wayzn_core expects a config path, we'll work around it
        # by directly calling the functions it needs

        try:
            # Authenticate to get token
            auth = core.fb_sign_in_email_password(email, password, api_key)
            id_token = auth.get("idToken")

            if not id_token:
                raise core.WayznError("No ID token in response")

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

    async def async_send_command(self, command: str) -> None:
        """Send a command to the device (open/close)."""
        try:
            email = self.config_entry.data[CONF_EMAIL]
            password = self.config_entry.data[CONF_PASSWORD]
            api_key = self.config_entry.data[CONF_API_KEY]
            device_id = self.config_entry.data[CONF_DEVICE_ID]

            await self.hass.async_add_executor_job(
                self._send_command_sync, email, password, api_key, device_id, command
            )

            # Trigger immediate refresh
            await self.async_refresh()

        except core.WayznError as e:
            _LOGGER.error("Failed to send command: %s", e)
            raise UpdateFailed(f"Failed to send command: {e}") from e
        except Exception as e:
            _LOGGER.error("Unexpected error sending command: %s", e)
            raise UpdateFailed(f"Unexpected error: {e}") from e

    def _send_command_sync(
        self, email: str, password: str, api_key: str, device_id: str, command: str
    ) -> None:
        """Send command to device (sync function for executor)."""
        import requests

        try:
            # Authenticate
            auth = core.fb_sign_in_email_password(email, password, api_key)
            id_token = auth.get("idToken")

            if not id_token:
                raise core.WayznError("No ID token in response")

            # Resolve device context (get wkey, nonce, agent URL)
            ctx = core.resolve_imp_context(
                cfg_path=None,
                force_login=False,
                id_token_override=id_token,
                device_id=device_id,
            )

            # Parse wkey to get key bytes
            knum, key_bytes = core.parse_wkey(ctx["wkey"])

            # Compute authorization header
            auth_header = core.compute_auth(
                command, ctx["nonce"], key_bytes, core.DEFAULT_HASH_ALGORITHM
            )

            # Prepare headers
            headers = {
                "User-Agent": "wayzn-ha/0.1",
                "Authorization": auth_header,
                "x-WayznKNum": str(knum),
            }

            # Send POST request to agent
            response = requests.post(
                ctx["agenturl"],
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
