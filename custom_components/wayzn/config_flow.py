"""Config flow for Wayzn integration."""

import logging
from typing import Any, Dict, Optional

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.helpers import config_validation as cv

from .const import (
    CONF_API_KEY,
    CONF_DEVICE_ID,
    CONF_DEVICE_LABEL,
    CONF_EMAIL,
    CONF_PASSWORD,
    CONF_QR_CODE,
    CONF_WKEY,
    CONF_KNUM,
    CONF_AGENTURL,
    ERROR_AUTH_FAILED,
    ERROR_CANNOT_CONNECT,
    ERROR_DEVICE_NOT_FOUND,
    ERROR_INVALID_QR,
)

_LOGGER = logging.getLogger(__name__)


class WayznConfigFlow(config_entries.ConfigFlow):
    """Handle a config flow for Wayzn."""

    VERSION = 1
    DOMAIN = "wayzn"

    def __init__(self):
        """Initialize the config flow."""
        self._credentials: Dict[str, str] = {}

    async def async_step_user(
        self, user_input: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Handle the initial step - collect Firebase credentials."""
        errors = {}

        if user_input is not None:
            # Import here to avoid issues at module load time
            from . import wayzn_core as core

            try:
                email = user_input[CONF_EMAIL]
                password = user_input[CONF_PASSWORD]
                api_key = user_input[CONF_API_KEY]

                # Test authentication
                auth = await self.hass.async_add_executor_job(
                    core.fb_sign_in_email_password, email, password, api_key
                )

                if not auth.get("idToken"):
                    errors["base"] = ERROR_AUTH_FAILED
                else:
                    self._credentials = {
                        CONF_EMAIL: email,
                        CONF_PASSWORD: password,
                        CONF_API_KEY: api_key,
                    }
                    return await self.async_step_device()

            except Exception as e:
                _LOGGER.error("Authentication error: %s", e)
                errors["base"] = ERROR_AUTH_FAILED

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_EMAIL): cv.string,
                    vol.Required(CONF_PASSWORD): cv.string,
                    vol.Required(CONF_API_KEY): cv.string,
                }
            ),
            errors=errors,
        )

    async def async_step_device(
        self, user_input: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Handle the device step - collect QR code."""
        errors = {}

        if user_input is not None:
            # Import here to avoid issues at module load time
            from . import wayzn_core as core

            try:
                qr_code = user_input[CONF_QR_CODE]

                # Parse QR code
                qr_data = await self.hass.async_add_executor_job(
                    core.parse_qr, qr_code
                )

                device_id = qr_data["device_id"]

                # Check if already configured
                await self.async_set_unique_id(device_id)
                self._abort_if_unique_id_configured()

                # Fetch agent URL
                auth = await self.hass.async_add_executor_job(
                    core.fb_sign_in_email_password,
                    self._credentials[CONF_EMAIL],
                    self._credentials[CONF_PASSWORD],
                    self._credentials[CONF_API_KEY],
                )
                id_token = auth.get("idToken")

                agenturl = await self.hass.async_add_executor_job(
                    core.fetch_device_agenturl, device_id, id_token
                )

                # Create config entry
                return self.async_create_entry(
                    title=qr_data["label"],
                    data={
                        CONF_EMAIL: self._credentials[CONF_EMAIL],
                        CONF_PASSWORD: self._credentials[CONF_PASSWORD],
                        CONF_API_KEY: self._credentials[CONF_API_KEY],
                        CONF_DEVICE_ID: device_id,
                        CONF_DEVICE_LABEL: qr_data["label"],
                        CONF_WKEY: qr_data["wkey"],
                        CONF_KNUM: qr_data["knum"],
                        CONF_AGENTURL: agenturl,
                        "qr": qr_code,
                    },
                )

            except Exception as e:
                _LOGGER.error("Device setup error: %s", e)
                errors["base"] = ERROR_DEVICE_NOT_FOUND

        return self.async_show_form(
            step_id="device",
            data_schema=vol.Schema({vol.Required(CONF_QR_CODE): cv.string}),
            errors=errors,
        )
