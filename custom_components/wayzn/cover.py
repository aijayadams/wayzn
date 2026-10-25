"""Cover entity for Wayzn devices."""

import logging
from typing import Any, Dict, Optional

from homeassistant.components.cover import (
    CoverDeviceClass,
    CoverEntity,
    CoverEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    CONF_DEVICE_ID,
    CONF_DEVICE_LABEL,
    DOMAIN,
)
from .coordinator import WayznDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up Wayzn cover from a config entry."""
    coordinator: WayznDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]

    async_add_entities([WayznCover(coordinator, entry)])


class WayznCover(CoordinatorEntity, CoverEntity):
    """Representation of a Wayzn device as a cover."""

    _attr_device_class = CoverDeviceClass.DOOR
    _attr_supported_features = CoverEntityFeature.OPEN | CoverEntityFeature.CLOSE
    _attr_name = None  # Use device name from device registry
    _attr_has_entity_name = True

    def __init__(
        self, coordinator: WayznDataUpdateCoordinator, config_entry: ConfigEntry
    ) -> None:
        """Initialize the Wayzn cover entity."""
        super().__init__(coordinator)
        self._config_entry = config_entry

    @property
    def unique_id(self) -> str:
        """Return unique ID for this entity."""
        return self._config_entry.data[CONF_DEVICE_ID]

    @property
    def name(self) -> str:
        """Return the name of the cover."""
        return self._config_entry.data[CONF_DEVICE_LABEL]

    @property
    def device_info(self) -> Dict[str, Any]:
        """Return device information."""
        return {
            "identifiers": {(DOMAIN, self._config_entry.data[CONF_DEVICE_ID])},
            "name": self._config_entry.data[CONF_DEVICE_LABEL],
            "manufacturer": "Wayzn",
            "model": "Smart Pet Door",
        }

    @property
    def is_closed(self) -> Optional[bool]:
        """Return if cover is closed.

        "unknown" (unmapped ControlState) returns None — HA renders the
        entity as unknown rather than confidently lying about direction.
        """
        if self.coordinator.data is None or self.coordinator.stale:
            return None

        state = self.coordinator.data.get("state")
        if state == "unknown":
            return None
        closed_states = ["closed", "locked", "locked_or_ajar", "disengaged"]
        return state in closed_states

    @property
    def is_opening(self) -> bool:
        """Return if cover is opening."""
        if self.coordinator.data is None or self.coordinator.stale:
            return False

        return self.coordinator.data.get("state") == "opening"

    @property
    def is_closing(self) -> bool:
        """Return if cover is closing."""
        if self.coordinator.data is None or self.coordinator.stale:
            return False

        return self.coordinator.data.get("state") == "closing"

    @property
    def available(self) -> bool:
        """Available unless our own link to the Wayzn cloud is broken.

        Unavailable only when the last poll failed (sign-in or Firebase read
        errors). When the link is fine but the door has stopped reporting
        (coordinator.stale), the cover stays available with state unknown
        (is_closed None): HA skips service calls to unavailable entities, and
        open/close must keep working — commands are the only rescue path
        when belief is wrong (2026-10-24: 3h with no HA control after a door
        power cycle). A wrong "open" is still never shown.
        """
        return self.coordinator.last_update_success

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        """Link-health diagnostics — one attribute view answers "is it healthy?"."""
        coordinator: WayznDataUpdateCoordinator = self.coordinator
        return coordinator.diagnostics

    async def async_open_cover(self, **kwargs: Any) -> None:
        """Open the cover."""
        await self.coordinator.async_send_command("open")

    async def async_close_cover(self, **kwargs: Any) -> None:
        """Close the cover."""
        await self.coordinator.async_send_command("close")
