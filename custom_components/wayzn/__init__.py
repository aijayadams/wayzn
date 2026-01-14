"""Wayzn integration for Home Assistant."""

import logging

from .const import DOMAIN, PLATFORMS

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass, entry) -> bool:
    """Set up Wayzn from a config entry."""
    # Import here to avoid issues at load time
    from .coordinator import WayznDataUpdateCoordinator

    hass.data.setdefault(DOMAIN, {})

    # Create coordinator
    coordinator = WayznDataUpdateCoordinator(hass, entry)

    # Perform first refresh
    try:
        await coordinator.async_config_entry_first_refresh()
    except Exception as e:
        # ConfigEntryAuthFailed will be imported when needed
        from homeassistant.exceptions import ConfigEntryAuthFailed
        if isinstance(e, ConfigEntryAuthFailed):
            return False
        raise

    # Store coordinator in hass.data
    hass.data[DOMAIN][entry.entry_id] = coordinator

    # Forward setup to platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Register update listener
    entry.async_on_unload(entry.add_update_listener(async_reload_entry))

    return True


async def async_unload_entry(hass, entry) -> bool:
    """Unload a config entry."""
    # Unload platforms
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        # Remove coordinator
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok


async def async_reload_entry(hass, entry) -> None:
    """Reload config entry."""
    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)
