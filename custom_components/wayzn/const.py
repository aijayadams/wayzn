"""Constants for Wayzn integration."""

DOMAIN = "wayzn"

# Config entry keys
CONF_EMAIL = "email"
CONF_PASSWORD = "password"
CONF_API_KEY = "api_key"
CONF_QR_CODE = "qr_code"
CONF_DEVICE_ID = "device_id"
CONF_DEVICE_LABEL = "label"
CONF_WKEY = "wkey"
CONF_KNUM = "knum"
CONF_AGENTURL = "agenturl"

# Local mode (wayzn-brain on the door, aijayadams/wayzn-brain docs/API.md)
CONF_MODE = "mode"
MODE_CLOUD = "cloud"
MODE_LOCAL = "local"
CONF_HOST = "host"
CONF_TOKEN = "token"
DEFAULT_LOCAL_HOST = "wayzn-esp.local"
DEFAULT_LOCAL_LABEL = "Dog Door Direct"  # keeps entity_id cover.dog_door_direct

# Defaults
DEFAULT_POLL_INTERVAL = 30  # seconds
DEFAULT_TIMEOUT = 20  # seconds

# Platforms
PLATFORMS = ["cover", "sensor", "binary_sensor", "image", "switch"]
LOCAL_PLATFORMS = ["cover"]  # MVP: the door itself; settings stay on the door's console

# Error messages
ERROR_AUTH_FAILED = "auth_failed"
ERROR_INVALID_QR = "invalid_qr"
ERROR_DEVICE_NOT_FOUND = "device_not_found"
ERROR_CANNOT_CONNECT = "cannot_connect"
