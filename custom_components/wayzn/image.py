"""Image entity rendering the motion detection area like the Wayzn app."""

from typing import Any, Dict, List, Optional

from homeassistant.components.image import ImageEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util import dt as dt_util

from .const import DOMAIN
from .entity import WayznSettingEntity

# Layout and colours match the app's Motion Detection screen: 4 columns ×
# 5 rows, row-major from the top, door on the left (InstallOrientation 1).
GRID_COLUMNS = 4
CELL = 60
GAP = 3
DOOR_WIDTH = 28
# Mask values are two bits per cell: bit 0 = enabled for detection, bit 1 =
# motion detected in that cell right now (the app's buildPixelColor map).
CELL_COLORS = {
    0: "#EEEEEE",  # disabled (grey 200)
    1: "#66BB6A",  # enabled (green 400)
    2: "#616161",  # disabled, motion now (grey 700)
    3: "#FFA726",  # enabled, motion now (orange 400)
}
COLOR_GRID_LINE = "#555555"
COLOR_DOOR = "#9E9E9E"


def render_mask_svg(mask: List[int], door_on_left: bool) -> str:
    """Render the 20-cell detection mask as an SVG grid."""
    rows = (len(mask) + GRID_COLUMNS - 1) // GRID_COLUMNS
    grid_x = DOOR_WIDTH + GAP * 2 if door_on_left else 0
    width = grid_x + GRID_COLUMNS * CELL
    height = rows * CELL
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="-2 -2 {width + 4} {height + 4}" '
        f'width="{width + 4}" height="{height + 4}">'
    ]
    if door_on_left:
        parts.append(
            f'<rect x="0" y="0" width="{DOOR_WIDTH}" height="{height}" rx="3" '
            f'fill="none" stroke="{COLOR_DOOR}" stroke-width="3"/>'
        )
    for i, cell in enumerate(mask):
        x = grid_x + (i % GRID_COLUMNS) * CELL
        y = (i // GRID_COLUMNS) * CELL
        fill = CELL_COLORS.get(cell, "none")
        parts.append(
            f'<rect x="{x}" y="{y}" width="{CELL}" height="{CELL}" fill="{fill}" '
            f'stroke="{COLOR_GRID_LINE}" stroke-width="2"/>'
        )
    parts.append("</svg>")
    return "".join(parts)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up the Wayzn detection-area image."""
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([WayznDetectionAreaImage(hass, coordinator, entry)])


class WayznDetectionAreaImage(WayznSettingEntity, ImageEntity):
    """Green = enabled, light grey = disabled, orange/dark grey = motion now."""

    _attr_name = "Motion detection area"
    _attr_content_type = "image/svg+xml"

    def __init__(self, hass: HomeAssistant, coordinator, entry: ConfigEntry) -> None:
        WayznSettingEntity.__init__(self, coordinator, entry, "detection_mask")
        ImageEntity.__init__(self, hass)
        self._rendered_for: Optional[tuple] = None
        self._svg: Optional[bytes] = None
        self._refresh_image()

    def _refresh_image(self) -> None:
        mask = self.setting
        key = (tuple(mask), self.settings.get("install_orientation")) if mask else None
        if key == self._rendered_for:
            return
        self._rendered_for = key
        self._svg = (
            render_mask_svg(mask, door_on_left=self.settings.get("install_orientation") == 1).encode()
            if mask
            else None
        )
        self._attr_image_last_updated = dt_util.utcnow()

    @callback
    def _handle_coordinator_update(self) -> None:
        self._refresh_image()
        super()._handle_coordinator_update()

    async def async_image(self) -> Optional[bytes]:
        return self._svg

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        mask = self.setting
        return {
            "mask": mask,
            "cells_enabled": self.settings.get("detection_cells_enabled"),
            "cells_with_motion": self.settings.get("detection_cells_with_motion"),
        }
