#!/usr/bin/env python3
"""Wayzn smart device client library.

Provides core functionality for:
- Firebase authentication and token management
- Device registry management
- Firebase RTDB operations
- Device control (signing and sending commands)
"""

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import time
from typing import Any, Dict, Optional, TypedDict

import requests


class WayznError(RuntimeError):
    """Base exception for Wayzn client errors."""
    pass


# ============================================================================
# Type definitions
# ============================================================================

class AuthToken(TypedDict, total=False):
    """Firebase authentication token response."""
    idToken: str
    refreshToken: str
    localId: str
    expiresIn: str
    obtained_at: int


class DeviceInfo(TypedDict, total=False):
    """Device registry entry."""
    label: str
    wkey: str
    knum: str
    qr: str
    agenturl: str


class ControlContext(TypedDict):
    """Resolved device control context."""
    device_id: str
    wkey: str
    nonce: str
    agenturl: str


class ConfigData(TypedDict, total=False):
    """Static configuration data."""
    firebase: Dict[str, str]
    device_registry: Dict[str, DeviceInfo]
    agent_url: str


# ============================================================================
# Configuration constants
# ============================================================================

CONFIG_FILE_DEFAULT = "wayzn_config.json"
AUTH_CACHE_FILE_DEFAULT = ".wayzn_auth_cache.json"

# Config keys
CONFIG_KEY_FIREBASE = "firebase"
CONFIG_KEY_DEVICE_REGISTRY = "device_registry"


# ============================================================================
# Firebase configuration
# ============================================================================

FIREBASE_DBS = {
    "app": "https://wayzn-app.firebaseio.com",
    "account_info": "https://wayzn-app-account-info.firebaseio.com",
    "nonce": "https://wayzn-app-nonce.firebaseio.com",
    "tokens": "https://wayzn-app-tokens.firebaseio.com",
    "global": "https://wayzn-app-global.firebaseio.com",
    "push": "https://wayzn-app-push-notifications.firebaseio.com",
}

# Device control configuration
DEFAULT_HASH_ALGORITHM = "sha256"
REQUEST_TIMEOUT = 20


# ============================================================================
# Configuration management
# ============================================================================

def _module_dir() -> Path:
    """Get the directory of this module."""
    return Path(__file__).parent


def config_path(path: Optional[str] = None) -> Path:
    """Resolve config file path (absolute or relative to module)."""
    if path:
        p = Path(path)
        if p.is_absolute():
            return p
        return _module_dir() / path
    return _module_dir() / CONFIG_FILE_DEFAULT


def _auth_cache_path(cfg_path: Optional[Path] = None) -> Path:
    """Derive auth cache path from config path.

    If config is wayzn_config.json -> .wayzn_auth_cache.json
    If config is /path/to/custom.json -> /path/to/.custom_auth_cache.json
    """
    if cfg_path is None:
        cfg_path = config_path()
    else:
        cfg_path = Path(cfg_path)

    stem = cfg_path.stem
    suffix = cfg_path.suffix
    cache_name = f".{stem}_auth_cache{suffix}"
    return cfg_path.parent / cache_name


def load_config(path: Optional[str] = None) -> ConfigData:
    """Load JSON config file."""
    cfg_path = config_path(path)
    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as e:
        raise WayznError(f"Invalid JSON in {cfg_path}: {e}")
    except Exception as e:
        raise WayznError(f"Failed to load config from {cfg_path}: {e}")
    return {}


def save_config(cfg: ConfigData, path: Optional[str] = None) -> None:
    """Save config to JSON file."""
    cfg_path = config_path(path)
    cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=True), encoding="utf-8")



# ============================================================================
# Firebase authentication
# ============================================================================

def fb_sign_in_email_password(email: str, password: str, api_key: str) -> Dict[str, Any]:
    """Sign in to Firebase using email/password.

    Args:
        email: Firebase account email
        password: Firebase account password
        api_key: Firebase API key from config

    Returns a dict with fields:
      - idToken: JWT for API calls
      - refreshToken: Token for refreshing the ID token
      - localId: User UID
      - expiresIn: Token expiry in seconds
    """
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
    payload = {"email": email, "password": password, "returnSecureToken": True}
    r = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
    if r.status_code >= 400:
        try:
            err = r.json()
        except Exception:
            err = {"error": {"message": r.text.strip(), "code": r.status_code}}
        raise WayznError(f"Firebase login failed: {err}")
    return r.json()


def load_firebase_config(cfg_path: Optional[str] = None) -> Dict[str, str]:
    """Load Firebase configuration (credentials and API key) from config."""
    cfg = load_config(cfg_path)
    firebase = cfg.get(CONFIG_KEY_FIREBASE, {})
    return firebase


def load_credentials(cfg_path: Optional[str] = None) -> Optional[Dict[str, str]]:
    """Load stored email/password from config."""
    firebase = load_firebase_config(cfg_path)
    email = firebase.get("email")
    password = firebase.get("password")
    if email:
        return {"email": email, "password": password or ""}
    return None


def _load_auth_cache(cache_path: Path) -> Optional[AuthToken]:
    """Load authentication token from cache file."""
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("idToken"):
            return data
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        return None
    return None


def _save_auth_cache(cache_path: Path, auth: AuthToken) -> None:
    """Save authentication token to cache file with restricted permissions."""
    cache_path.write_text(json.dumps(auth, indent=2, ensure_ascii=True), encoding="utf-8")
    # Set cache file permissions to 0600 (rw-------)
    cache_path.chmod(0o600)


def load_cached_auth(cfg_path: Optional[str] = None) -> Optional[AuthToken]:
    """Load cached authentication token from cache file."""
    cfg_p = config_path(cfg_path)
    cache_path = _auth_cache_path(cfg_p)
    return _load_auth_cache(cache_path)


def persist_auth(cfg_path: Optional[str], auth: AuthToken) -> None:
    """Save authentication token to cache file."""
    if not isinstance(auth, dict) or not auth.get("idToken"):
        return

    cfg_p = config_path(cfg_path)
    cache_path = _auth_cache_path(cfg_p)

    # Validate config doesn't have old auth cache
    cfg = load_config(cfg_path)
    if "firebase_auth" in cfg:
        raise WayznError(
            "Old authentication data found in config. "
            "Please remove 'firebase_auth' key from your config file. "
            "Auth tokens are now stored separately in .wayzn_auth_cache.json"
        )

    # Add timestamp if not present
    if not auth.get("obtained_at"):
        auth = dict(auth)
        auth["obtained_at"] = int(time.time())

    _save_auth_cache(cache_path, auth)


def _auth_is_valid(auth: AuthToken, skew_seconds: int = 60) -> bool:
    """Check if cached authentication token is still valid."""
    try:
        exp = int(auth.get("expiresIn", 0))
    except (ValueError, TypeError):
        exp = 0
    obtained = auth.get("obtained_at")
    try:
        obtained = int(obtained)
    except (ValueError, TypeError):
        obtained = 0
    if exp <= 0 or obtained <= 0:
        return False
    return (obtained + exp - skew_seconds) > int(time.time())


def get_valid_auth(cfg_path: Optional[str] = None, force: bool = False) -> AuthToken:
    """Get valid Firebase authentication token.

    Uses cached token if still valid; otherwise attempts login with stored credentials.
    """
    if not force:
        cached = load_cached_auth(cfg_path)
        if cached and _auth_is_valid(cached):
            return cached
    creds = load_credentials(cfg_path)
    if not creds or not creds.get("email"):
        raise WayznError("No ID token or credentials found")

    # Load API key from Firebase config
    firebase_cfg = load_firebase_config(cfg_path)
    api_key = firebase_cfg.get("api_key")
    if not api_key:
        raise WayznError("No Firebase API key found in config")

    resp: AuthToken = fb_sign_in_email_password(creds["email"], creds.get("password", ""), api_key)
    persist_auth(cfg_path, resp)
    return resp


def resolve_id_token(explicit: Optional[str] = None, cfg_path: Optional[str] = None, force: bool = False) -> str:
    """Get an ID token for API calls.

    Uses explicit token if provided; otherwise gets from cache or by logging in.
    """
    if explicit:
        return explicit
    auth = get_valid_auth(cfg_path, force=force)
    id_token = auth.get("idToken")
    if not id_token:
        raise WayznError("Failed to obtain ID token")
    return id_token



# ============================================================================
# Device control: key operations and signing
# ============================================================================

def parse_wkey(wkey: str) -> Tuple[str, bytes]:
    """Parse device wKey from '<knum>:<base64>' format.

    Returns (knum, key_bytes).
    """
    if ":" not in wkey:
        raise WayznError("wKey must be in '<knum>:<base64>' format")
    knum, key_b64 = wkey.split(":", 1)
    key_bytes = base64.b64decode(key_b64)
    return knum, key_bytes


def compute_auth(cmd: str, nonce: str, key_bytes: bytes, algo: str = "sha256") -> str:
    """Compute HMAC-based authorization header for device control.

    Signs the command string with a device nonce and secret key.
    Returns the base64-encoded digest suitable for Authorization header.
    """
    msg = f"{cmd},{nonce}".encode("utf-8")
    if algo == "sha1":
        digest = hmac.new(key_bytes, msg, hashlib.sha1).digest()
    else:
        digest = hmac.new(key_bytes, msg, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")



# ============================================================================
# QR code and device registry
# ============================================================================

def parse_qr(qr: str) -> Dict[str, str]:
    """Parse QR code string into device information.

    QR format: 'QR-Code:<b64_key>:<knum>:<device_id_hex>:<label>'

    Returns a dict with keys: wkey, knum, device_id, label, qr
    """
    if not qr.startswith("QR-Code:"):
        raise WayznError("QR should start with 'QR-Code:'")
    parts = qr.split(":", 4)
    if len(parts) < 5:
        raise WayznError("Unexpected QR format; expected 5 parts")
    _, b64, knum, devhex, label = parts
    return {
        "wkey": f"{knum}:{b64}",
        "knum": knum,
        "device_id": devhex,
        "label": label,
        "qr": qr,
    }


def load_device_registry(cfg_path: Optional[str] = None) -> Dict[str, Dict[str, DeviceInfo]]:
    """Load device registry from config."""
    cfg = load_config(cfg_path)
    registry = cfg.get(CONFIG_KEY_DEVICE_REGISTRY, {})
    if isinstance(registry, dict):
        return {"devices": registry}
    return {"devices": {}}


def save_device_registry(data: Dict[str, Dict[str, DeviceInfo]], cfg_path: Optional[str] = None) -> None:
    """Save device registry to config."""
    cfg = load_config(cfg_path)
    cfg[CONFIG_KEY_DEVICE_REGISTRY] = data.get("devices", {})
    save_config(cfg, cfg_path)



# ============================================================================
# Firebase Realtime Database (RTDB) operations
# ============================================================================

def db_url(db_key: str, path: str) -> str:
    """Construct Firebase RTDB URL for a given database and path."""
    base = FIREBASE_DBS[db_key].rstrip("/")
    p = path.strip("/")
    return f"{base}/{p}.json"


def _maybe_appcheck_headers() -> Dict[str, str]:
    """Include Firebase AppCheck token if configured via WAYZN_APPCHECK env var."""
    hdr = {}
    tok = os.environ.get("WAYZN_APPCHECK")
    if tok:
        hdr["X-Firebase-AppCheck"] = tok
    return hdr


def _alt_host(url: str) -> str:
    """Try alternative Firebase host for legacy firebaseio.com URLs."""
    if ".firebaseio.com" in url:
        return url.replace(".firebaseio.com", "-default-rtdb.firebaseio.com")
    return url


def db_get(db_key: str, path: str, id_token: str) -> Dict[str, Any]:
    """Fetch data from Firebase RTDB.

    Attempts primary URL first, then falls back to alternative host if available.
    """
    url = db_url(db_key, path)
    params = {"auth": id_token}
    headers = _maybe_appcheck_headers()
    try:
        r = requests.get(url, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception:
        # Try alt host (-default-rtdb)
        alt = _alt_host(url)
        if alt != url:
            r = requests.get(alt, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
            r.raise_for_status()
            return r.json()
        raise


def db_patch(db_key: str, path: str, id_token: str, obj: Dict[str, Any]) -> Dict[str, Any]:
    """Update data in Firebase RTDB with JSON merge."""
    url = db_url(db_key, path)
    r = requests.patch(url, params={"auth": id_token}, headers=_maybe_appcheck_headers(), json=obj, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()


def db_shallow(db_key: str, path: str, id_token: str) -> Dict[str, Any]:
    """Fetch shallow view of Firebase RTDB path (keys only)."""
    url = db_url(db_key, path)
    r = requests.get(url, params={"auth": id_token, "shallow": "true"}, headers=_maybe_appcheck_headers(), timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()



# ============================================================================
# Device resolution and control context
# ============================================================================

def resolve_device_id(device_id: Optional[str], cfg_path: Optional[str] = None) -> str:
    """Resolve device ID from explicit value or auto-select from registry.

    If device_id is provided, returns it directly.
    If registry has exactly one device, returns that device ID.
    Otherwise raises WayznError.
    """
    if device_id:
        return device_id
    reg = load_device_registry(cfg_path)
    devices = reg.get("devices", {})
    if len(devices) == 1:
        return list(devices.keys())[0]
    if devices:
        raise WayznError("No device-id provided and registry has multiple devices")
    raise WayznError("No device-id provided and registry is empty")


def find_value_by_keys(data: Any, keys: set) -> Optional[str]:
    """Recursively search a nested structure for a value with any of the given keys."""
    if isinstance(data, dict):
        for k, v in data.items():
            if k in keys:
                return v
            found = find_value_by_keys(v, keys)
            if found is not None:
                return found
    elif isinstance(data, list):
        for item in data:
            found = find_value_by_keys(item, keys)
            if found is not None:
                return found
    return None


def fetch_device_agenturl(device_id: str, id_token: str) -> str:
    """Fetch agent URL for a device from the nonce RTDB.

    Queries the nonce database to get the agenturl for a specific device.
    This is called during device import to cache the URL with device properties.
    """
    try:
        nonce_data = db_get("nonce", f"/{device_id}", id_token)
    except Exception as e:
        raise WayznError(f"Failed to fetch nonce data for device: {e}")

    agenturl = nonce_data.get("agenturl")
    if not agenturl:
        raise WayznError(f"No agenturl found in nonce DB for device {device_id}")
    return agenturl


def resolve_imp_context(
    cfg_path: Optional[str],
    force_login: bool,
    id_token_override: Optional[str],
    device_id: Optional[str],
) -> ControlContext:
    """Resolve all information needed to control a device via Electric Imp.

    Fetches from:
      - device_id from registry
      - wkey and agenturl (device secret and agent URL) from registry
      - nonce from Firebase nonce DB

    Returns ControlContext with: device_id, wkey, nonce, agenturl
    """
    device_id = resolve_device_id(device_id, cfg_path)
    id_token = resolve_id_token(id_token_override, cfg_path, force=force_login)

    reg = load_device_registry(cfg_path)
    entry = reg.get("devices", {}).get(device_id, {})

    # Get device secret and agent URL from registry
    wkey = entry.get("wkey")
    if not wkey:
        raise WayznError("No wKey found in registry for device")

    agenturl = entry.get("agenturl")
    if not agenturl:
        raise WayznError("No agenturl found in registry for device")

    # Fetch nonce from nonce DB
    try:
        nonce_data = db_get("nonce", f"/{device_id}", id_token)
        nonce = nonce_data.get("nonce")
    except Exception as e:
        raise WayznError(f"Failed to read nonce: {e}")

    if not nonce:
        raise WayznError("No nonce found in nonce DB for device")

    return ControlContext(device_id=device_id, wkey=wkey, nonce=nonce, agenturl=agenturl)



# ============================================================================
# Device status and control state
# ============================================================================

CONTROLSTATE_LABELS = {
    # Door states
    7: "open",
    12: "opening",
    13: "closing",
    14: "closed",
    15: "open",
    30: "closed",
    37: "opening",
    # Locked/ajar states (position-dependent in app, use generic label)
    5: "locked_or_ajar",
    18: "locked_or_ajar",
    22: "locked_or_ajar",
    33: "locked_or_ajar",
    34: "locked_or_ajar",
    35: "locked_or_ajar",
    36: "locked_or_ajar",
    # Disengaged states
    26: "disengaged",
    27: "disengaged",
    28: "disengaged",
    29: "disengaged",
    # Other states
    25: "paused",
    39: "locked",
    38: "heat_detected",
}


def controlstate_label(value: Optional[int]) -> str:
    """Convert numeric control state to human-readable label."""
    if value is None:
        return "unknown"
    return CONTROLSTATE_LABELS.get(int(value), "unknown")


def get_status(
    cfg_path: Optional[str],
    force_login: bool,
    id_token: Optional[str],
    device_id: Optional[str],
    db: str,
    uid: Optional[str],
) -> Any:
    """Fetch device or user status from Firebase.

    For 'app' DB: fetches user profile (requires uid or resolves from login)
    For other DBs: fetches device data (resolves device_id from registry)
    """
    token = resolve_id_token(id_token, cfg_path, force=force_login)

    resolved_device = None
    if db != "app":
        resolved_device = resolve_device_id(device_id, cfg_path)

    if db == "app":
        if not uid:
            cached = get_valid_auth(cfg_path, force=force_login)
            uid = cached.get("localId") if cached else None
        if not uid:
            raise WayznError("No UID provided for app DB")
        return db_get("app", f"/{uid}", token)

    return db_get(db, f"/{resolved_device}", token)


def get_status_summary(
    cfg_path: Optional[str],
    force_login: bool,
    id_token: Optional[str],
    device_id: Optional[str],
) -> Dict[str, Any]:
    """Get brief device status summary (control state and readable label)."""
    data = get_status(cfg_path, force_login, id_token, device_id, "tokens", None)
    controlstate = None
    if isinstance(data, dict):
        controlstate = data.get("ControlState")
    return {
        "controlstate": controlstate,
        "state": controlstate_label(controlstate),
    }
