"""Config flow for Wayzn integration."""

import logging
from typing import Any, Dict, Optional

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.helpers import config_validation as cv

from . import wayzn_core as core
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
    DOMAIN,
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
        self._device_info: Dict[str, Any] = {}

    async def async_step_user(
        self, user_input: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Handle the initial step - collect Firebase credentials."""
        errors: Dict[str, str] = {}

        if user_input is not None:
            # Validate credentials
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
                    # Store credentials for next step
                    self._credentials = {
                        CONF_EMAIL: email,
                        CONF_PASSWORD: password,
                        CONF_API_KEY: api_key,
                    }
                    return await self.async_step_device()

            except core.WayznError as e:
                _LOGGER.error("Wayzn authentication failed: %s", e)
                errors["base"] = ERROR_AUTH_FAILED
            except Exception as e:
                _LOGGER.error("Unexpected error during authentication: %s", e)
                errors["base"] = ERROR_CANNOT_CONNECT

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
        errors: Dict[str, str] = {}

        if user_input is not None:
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
                try:
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

                    # Store device info
                    self._device_info = {
                        CONF_DEVICE_ID: device_id,
                        CONF_DEVICE_LABEL: qr_data["label"],
                        CONF_WKEY: qr_data["wkey"],
                        CONF_KNUM: qr_data["knum"],
                        CONF_AGENTURL: agenturl,
                        "qr": qr_code,
                    }

                    # Create config entry
                    return self.async_create_entry(
                        title=qr_data["label"],
                        data={
                            **self._credentials,
                            **self._device_info,
                        },
                    )

                except core.WayznError as e:
                    _LOGGER.error("Failed to fetch device info: %s", e)
                    errors["base"] = ERROR_DEVICE_NOT_FOUND

            except core.WayznError:
                _LOGGER.error("Invalid QR code format")
                errors["base"] = ERROR_INVALID_QR
            except Exception as e:
                _LOGGER.error("Unexpected error processing QR code: %s", e)
                errors["base"] = ERROR_CANNOT_CONNECT

        return self.async_show_form(
            step_id="device",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_QR_CODE): cv.string,
                }
            ),
            errors=errors,
        )

    async def async_step_reauth(self, user_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle reauth flow for expired credentials."""
        entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )

        if entry is None:
            return self.async_abort(reason="reauth_failed")

        if user_input is not None:
            errors: Dict[str, str] = {}

            try:
                email = entry.data[CONF_EMAIL]
                password = user_input[CONF_PASSWORD]
                api_key = entry.data[CONF_API_KEY]

                # Test new credentials
                auth = await self.hass.async_add_executor_job(
                    core.fb_sign_in_email_password, email, password, api_key
                )

                if not auth.get("idToken"):
                    errors["base"] = ERROR_AUTH_FAILED
                else:
                    # Update entry with new password
                    self.hass.config_entries.async_update_entry(
                        entry,
                        data={**entry.data, CONF_PASSWORD: password},
                    )
                    await self.hass.config_entries.async_reload(entry.entry_id)
                    return self.async_abort(reason="reauth_successful")

            except core.WayznError as e:
                _LOGGER.error("Reauth failed: %s", e)
                errors["base"] = ERROR_AUTH_FAILED
            except Exception as e:
                _LOGGER.error("Unexpected error during reauth: %s", e)
                errors["base"] = ERROR_CANNOT_CONNECT

            return self.async_show_form(
                step_id="reauth",
                data_schema=vol.Schema(
                    {
                        vol.Required(CONF_PASSWORD): cv.string,
                    }
                ),
                errors=errors,
                description_placeholders={
                    "email": entry.data[CONF_EMAIL],
                },
            )

        return self.async_show_form(
            step_id="reauth",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_PASSWORD): cv.string,
                }
            ),
            description_placeholders={
                "email": entry.data[CONF_EMAIL],
            },
        )
