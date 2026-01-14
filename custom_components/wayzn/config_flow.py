"""Config flow for Wayzn integration."""

import logging
from typing import Any, Dict, Optional

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.helpers import config_validation as cv

_LOGGER = logging.getLogger(__name__)


class WayznConfigFlow(config_entries.ConfigFlow):
    """Handle a config flow for Wayzn."""

    VERSION = 1
    DOMAIN = "wayzn"

    async def async_step_user(self, user_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle the initial step."""
        if user_input is not None:
            return self.async_create_entry(
                title="Wayzn Device",
                data=user_input,
            )

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required("email"): cv.string,
                    vol.Required("password"): cv.string,
                    vol.Required("api_key"): cv.string,
                }
            ),
        )
