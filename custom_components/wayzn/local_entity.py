"""Shared base for local-mode (wayzn-brain) setting entities."""

from typing import Any, Optional

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_DEVICE_ID, CONF_DEVICE_LABEL, DOMAIN


class LocalSettingEntity(CoordinatorEntity):
    """One key of the door's settings (GET /api/status "settings", POST /api/settings).

    The value lives on the door; it is unknown (None) whenever the door's state is not
    fresh, never a remembered guess. Writes are confirmed by re-reading the door.
    """

    _attr_has_entity_name = True
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator, entry: ConfigEntry, key: str, name: str) -> None:
        super().__init__(coordinator)
        self._key = key
        device_id = entry.data[CONF_DEVICE_ID]
        self._attr_unique_id = f"{device_id}_{key}"
        self._attr_name = name
        self._attr_device_info = {
            "identifiers": {(DOMAIN, device_id)},
            "name": entry.data[CONF_DEVICE_LABEL],
            "manufacturer": "Wayzn",
            "model": "Smart Pet Door",
        }

    @property
    def setting(self) -> Optional[Any]:
        return self.coordinator.settings.get(self._key)

    async def _set(self, value: Any) -> None:
        await self.coordinator.async_set_settings({self._key: value})
