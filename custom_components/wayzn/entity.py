"""Shared base for Wayzn settings entities (sensor, binary_sensor)."""

from typing import Any, Dict, Optional

from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_DEVICE_ID, CONF_DEVICE_LABEL, DOMAIN
from .coordinator import WayznDataUpdateCoordinator


class WayznSettingEntity(CoordinatorEntity):
    """An entity showing one decoded field of coordinator.data["settings"].

    Settings refresh on every coordinator poll (≤120s heartbeat), not on SSE.
    Availability follows the cover: unavailable when the last update failed or
    the coordinator has flagged its data as stale. A field we could not read
    shows as unknown, never as a default.
    """

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: WayznDataUpdateCoordinator,
        config_entry: ConfigEntry,
        key: str,
    ) -> None:
        super().__init__(coordinator)
        self._key = key
        device_id = config_entry.data[CONF_DEVICE_ID]
        self._attr_unique_id = f"{device_id}_{key}"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, device_id)},
            "name": config_entry.data[CONF_DEVICE_LABEL],
            "manufacturer": "Wayzn",
            "model": "Smart Pet Door",
        }

    @property
    def settings(self) -> Dict[str, Any]:
        return (self.coordinator.data or {}).get("settings") or {}

    @property
    def setting(self) -> Optional[Any]:
        return self.settings.get(self._key)

    @property
    def available(self) -> bool:
        coordinator: WayznDataUpdateCoordinator = self.coordinator
        return coordinator.last_update_success and not coordinator.stale
