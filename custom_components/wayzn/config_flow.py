"""Config flow for Wayzn integration."""

import logging
from typing import Any, Dict, Optional

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.helpers import config_validation as cv

from .const import (
    CONF_HOST,
    CONF_MODE,
    CONF_TOKEN,
    DEFAULT_LOCAL_HOST,
    DEFAULT_LOCAL_LABEL,
    MODE_LOCAL,
    CONF_AGENTURL,
    CONF_API_KEY,
    CONF_DEVICE_ID,
    CONF_DEVICE_LABEL,
    CONF_EMAIL,
    CONF_KNUM,
    CONF_PASSWORD,
    CONF_QR_CODE,
    CONF_WKEY,
    DOMAIN,
    ERROR_AUTH_FAILED,
    ERROR_CANNOT_CONNECT,
    ERROR_DEVICE_NOT_FOUND,
    ERROR_INVALID_QR,
)

_LOGGER = logging.getLogger(__name__)


class WayznConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Wayzn."""

    VERSION = 1

    def __init__(self):
        """Initialize the config flow."""
        self._credentials: Dict[str, str] = {}
        self._device_info: Dict[str, Any] = {}
        self._reauth_entry = None

    async def async_step_user(
        self, user_input: Optional[Dict[str, Any]] = None
    ) -> ConfigFlowResult:
        """Choose: the local wayzn-brain door, or the (retired) Wayzn cloud."""
        return self.async_show_menu(step_id="user", menu_options=["local", "cloud"])

    async def async_step_local(
        self, user_input: Optional[Dict[str, Any]] = None
    ) -> ConfigFlowResult:
        """Local mode: the door's own wayzn-brain HTTP API on the LAN."""
        errors: Dict[str, str] = {}
        if user_input is not None:
            host = user_input[CONF_HOST].strip()
            token = user_input[CONF_TOKEN].strip()
            device_id = user_input[CONF_DEVICE_ID].strip()
            try:
                import aiohttp
                from homeassistant.helpers.aiohttp_client import async_get_clientsession

                session = async_get_clientsession(self.hass)
                async with session.get(
                    f"http://{host}/api/status",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 401:
                        errors["base"] = ERROR_AUTH_FAILED
                    elif resp.status != 200:
                        errors["base"] = ERROR_CANNOT_CONNECT
                    else:
                        body = await resp.json(content_type=None)
                        if "state" not in body:
                            errors["base"] = ERROR_CANNOT_CONNECT
            except Exception as e:  # unreachable, DNS, timeout
                _LOGGER.error("wayzn-brain not reachable at %s: %s", host, e)
                errors["base"] = ERROR_CANNOT_CONNECT
            if not errors:
                await self.async_set_unique_id(device_id)
                self._abort_if_unique_id_configured()
                label = user_input[CONF_DEVICE_LABEL].strip()
                return self.async_create_entry(
                    title=label,
                    data={
                        CONF_MODE: MODE_LOCAL,
                        CONF_HOST: host,
                        CONF_TOKEN: token,
                        CONF_DEVICE_ID: device_id,
                        CONF_DEVICE_LABEL: label,
                    },
                )
        return self.async_show_form(
            step_id="local",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_HOST, default=DEFAULT_LOCAL_HOST): cv.string,
                    vol.Required(CONF_TOKEN): cv.string,
                    vol.Required(CONF_DEVICE_LABEL, default=DEFAULT_LOCAL_LABEL): cv.string,
                    vol.Required(CONF_DEVICE_ID, default="wayzn-brain"): cv.string,
                }
            ),
            errors=errors,
        )

    async def async_step_cloud(
        self, user_input: Optional[Dict[str, Any]] = None
    ) -> ConfigFlowResult:
        """Handle the cloud step - collect Firebase credentials."""
        errors: Dict[str, str] = {}

        if user_input is not None:
            # Validate credentials
            try:
                from .wayzn_client import wayzn_core as core

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

            except Exception as e:
                _LOGGER.error("Authentication failed: %s", e)
                errors["base"] = ERROR_AUTH_FAILED

        return self.async_show_form(
            step_id="cloud",
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
    ) -> ConfigFlowResult:
        """Handle the device step - collect QR code."""
        errors: Dict[str, str] = {}

        if user_input is not None:
            try:
                from .wayzn_client import wayzn_core as core

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

                except Exception as e:
                    _LOGGER.error("Failed to fetch device info: %s", e)
                    errors["base"] = ERROR_DEVICE_NOT_FOUND

            except Exception as e:
                _LOGGER.error("Invalid QR code format: %s", e)
                errors["base"] = ERROR_INVALID_QR

        return self.async_show_form(
            step_id="device",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_QR_CODE): cv.string,
                }
            ),
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Reauth flow — triggered by HA when ConfigEntryAuthFailed is raised
    # ------------------------------------------------------------------

    async def async_step_reauth(
        self, entry_data: Dict[str, Any]
    ) -> ConfigFlowResult:
        """Handle reauth trigger from HA (credentials expired / API key invalid)."""
        self._reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: Optional[Dict[str, Any]] = None
    ) -> ConfigFlowResult:
        """Show reauth form and validate new credentials."""
        errors: Dict[str, str] = {}

        if user_input is not None:
            try:
                from .wayzn_client import wayzn_core as core

                entry = self._reauth_entry
                email = entry.data[CONF_EMAIL]
                password = user_input[CONF_PASSWORD]
                api_key = user_input.get(CONF_API_KEY, entry.data.get(CONF_API_KEY, ""))

                # Test authentication with the new credentials
                auth = await self.hass.async_add_executor_job(
                    core.fb_sign_in_email_password, email, password, api_key
                )

                if not auth.get("idToken"):
                    errors["base"] = ERROR_AUTH_FAILED
                else:
                    # Auth succeeded — update the config entry with new credentials
                    new_data = {**entry.data}
                    new_data[CONF_PASSWORD] = password
                    if api_key:
                        new_data[CONF_API_KEY] = api_key

                    self.hass.config_entries.async_update_entry(
                        entry, data=new_data
                    )
                    await self.hass.config_entries.async_reload(entry.entry_id)
                    return self.async_abort(reason="reauth_successful")

            except Exception as e:
                _LOGGER.error("Reauth failed: %s", e)
                errors["base"] = ERROR_AUTH_FAILED

        # Pre-fill the current API key so the user can see / change it
        current_api_key = ""
        if self._reauth_entry:
            current_api_key = self._reauth_entry.data.get(CONF_API_KEY, "")

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_PASSWORD): cv.string,
                    vol.Optional(CONF_API_KEY, default=current_api_key): cv.string,
                }
            ),
            errors=errors,
            description_placeholders={
                "email": self._reauth_entry.data.get(CONF_EMAIL, "") if self._reauth_entry else "",
            },
        )
