#!/usr/bin/env python3
"""Wayzn smart device client CLI.

Control and manage Wayzn smart devices (petdoors, locks, etc.) via Firebase
and Electric Imp backend. Supports authentication, device registration,
status querying, and device control operations.
"""

import json
import os
from typing import Any, Dict, Optional

import click
import requests

from . import wayzn_core as core


# ============================================================================
# CLI Configuration
# ============================================================================

USER_AGENT = "wayzn-client/0.2"
CONTROL_REQUEST_TIMEOUT = 15


# ============================================================================
# CLI Context and error handling
# ============================================================================

class AppContext:
    """Maintains session state: config path and authentication options."""
    def __init__(self, config: Optional[str], force_login: bool) -> None:
        self.config = config
        self.force_login = force_login


def _handle_error(err: Exception) -> None:
    """Format and display Wayzn library errors to user, exit on known errors."""
    if isinstance(err, core.WayznError):
        click.echo(str(err), err=True)
        raise SystemExit(2)
    raise err



# ============================================================================
# Main CLI group
# ============================================================================

@click.group()
@click.option("--config", default="wayzn_config.json", show_default=True, help="Config file path (JSON, relative to module)")
@click.option("--force-login", is_flag=True, help="Ignore cached auth and login again")
@click.pass_context
def cli(ctx: click.Context, config: str, force_login: bool) -> None:
    """Wayzn device client and control utility."""
    ctx.obj = AppContext(config, force_login)


# ============================================================================
# Authentication and device management
# ============================================================================

@cli.command("login")
@click.pass_obj
def login_cmd(ctx: AppContext) -> None:
    """Authenticate with Firebase and display token information."""
    try:
        auth = core.get_valid_auth(ctx.config, force=ctx.force_login)
    except Exception as e:
        _handle_error(e)
    click.echo(json.dumps(auth, indent=2))


@cli.command("devices")
@click.pass_obj
def devices_cmd(ctx: AppContext) -> None:
    """List all devices in the registry."""
    try:
        reg = core.load_device_registry(ctx.config)
    except Exception as e:
        _handle_error(e)
    devices = reg.get("devices", {})
    out = []
    for did, rec in devices.items():
        label = None
        if isinstance(rec, dict):
            label = rec.get("label")
        out.append({"id": did, "label": label})
    click.echo(json.dumps(out, indent=2, ensure_ascii=False))


@cli.command("import-qr")
@click.option("--qr", required=True, help="QR string: 'QR-Code:<b64>:<knum>:<hex>:<label>'")
@click.option("--out", default=None, help="Output config file (default: --config)")
@click.pass_obj
def import_qr_cmd(ctx: AppContext, qr: str, out: Optional[str]) -> None:
    """Import and register a device from QR code.

    Flow:
      1. Parse QR code to extract device info
      2. Authenticate with Firebase
      3. Fetch agent URL from nonce RTDB for this device
      4. Store device with all properties in registry
    """
    # Parse QR code
    try:
        info = core.parse_qr(qr)
    except Exception as e:
        _handle_error(e)

    cfg_path = out or ctx.config
    device_id = info["device_id"]

    # Get authentication token
    try:
        id_token = core.resolve_id_token(None, cfg_path, ctx.force_login)
    except Exception as e:
        _handle_error(e)

    # Fetch agent URL from nonce RTDB
    try:
        agenturl = core.fetch_device_agenturl(device_id, id_token)
    except Exception as e:
        _handle_error(e)

    # Store device in registry
    reg = core.load_device_registry(cfg_path)
    reg.setdefault("devices", {})
    reg["devices"][device_id] = {
        "label": info["label"],
        "wkey": info["wkey"],
        "knum": info["knum"],
        "qr": info["qr"],
        "agenturl": agenturl,
    }
    core.save_device_registry(reg, cfg_path)

    # Show what was imported
    output = dict(info)
    output["agenturl"] = agenturl
    click.echo(json.dumps(output, indent=2))


@cli.command("status")
@click.option("--device-id", required=False, help="Device ID (Imp_ID)")
@click.option("--id-token", default=None, help="Firebase ID token (optional)")
@click.option("--db", type=click.Choice(["nonce", "tokens", "app"]), default="tokens", show_default=True, help="Database to query")
@click.option("--uid", default=None, help="User UID (required for app DB)")
@click.option("--verbose", is_flag=True, help="Show full status payload")
@click.option("--pretty", is_flag=True, help="Pretty print JSON (verbose mode only)")
@click.pass_obj
def status_cmd(
    ctx: AppContext,
    device_id: Optional[str],
    id_token: Optional[str],
    db: str,
    uid: Optional[str],
    verbose: bool,
    pretty: bool,
) -> None:
    """Query device status from Firebase."""
    try:
        if verbose:
            data = core.get_status(ctx.config, ctx.force_login, id_token, device_id, db, uid)
        else:
            data = core.get_status_summary(ctx.config, ctx.force_login, id_token, device_id)
    except Exception as e:
        _handle_error(e)
    click.echo(json.dumps(data, indent=2 if (verbose and pretty) else None, ensure_ascii=False))



# ============================================================================
# Debug commands (Firebase RTDB inspection)
# ============================================================================

@cli.group("debug")
def debug_group() -> None:
    """Debug and troubleshooting helpers for Firebase inspection."""


@debug_group.command("get")
@click.argument("id_token")
@click.argument("db", type=click.Choice(sorted(core.FIREBASE_DBS.keys())))
@click.argument("path")
def debug_get(id_token: str, db: str, path: str) -> None:
    """Fetch JSON data from a Firebase RTDB path."""
    try:
        data = core.db_get(db, path, id_token)
    except Exception as e:
        _handle_error(e)
    click.echo(json.dumps(data, indent=2, ensure_ascii=False))


@debug_group.command("patch")
@click.argument("id_token")
@click.argument("db", type=click.Choice(sorted(core.FIREBASE_DBS.keys())))
@click.argument("path")
@click.argument("json_payload")
def debug_patch(id_token: str, db: str, path: str, json_payload: str) -> None:
    """Update Firebase RTDB data with JSON merge."""
    try:
        obj = json.loads(json_payload)
        data = core.db_patch(db, path, id_token, obj)
    except json.JSONDecodeError as e:
        click.echo(f"Invalid JSON payload: {e}", err=True)
        raise SystemExit(2)
    except Exception as e:
        _handle_error(e)
    click.echo(json.dumps(data, indent=2, ensure_ascii=False))


@debug_group.command("scan")
@click.option("--login-local", is_flag=True, help="Use config file credentials to login")
@click.option("--id-token", default=None, help="Firebase ID token")
@click.option("--db", type=click.Choice(sorted(core.FIREBASE_DBS.keys())), default="app", show_default=True)
@click.option("--path", default="/", show_default=True, help="Database path to scan (returns keys only)")
@click.pass_obj
def debug_scan(ctx: AppContext, login_local: bool, id_token: Optional[str], db: str, path: str) -> None:
    """Scan database path (shallow query, keys only)."""
    if login_local:
        try:
            auth = core.get_valid_auth(ctx.config, force=ctx.force_login)
        except Exception as e:
            _handle_error(e)
        id_token = auth.get("idToken")
    else:
        if not id_token:
            click.echo("--id-token required when not using --login-local", err=True)
            raise SystemExit(2)
    try:
        data = core.db_shallow(db, path, id_token)
    except Exception as e:
        _handle_error(e)
    click.echo(json.dumps(data, indent=2, ensure_ascii=False))


@debug_group.command("discover")
@click.option("--login-local", is_flag=True, help="Use config file credentials to login")
@click.option("--id-token", default=None, help="Firebase ID token")
@click.option("--uid", default=None, help="User UID (required if using --id-token)")
@click.option("--outdir", default="captures", show_default=True, help="Directory to write JSON snapshots")
@click.pass_obj
def debug_discover(ctx: AppContext, login_local: bool, id_token: Optional[str], uid: Optional[str], outdir: str) -> None:
    """Capture all device-related data from Firebase for inspection.

    Captures standard paths from app, tokens, and nonce databases.
    Writes results to --outdir as individual JSON files.
    """
    if login_local:
        try:
            auth = core.get_valid_auth(ctx.config, force=ctx.force_login)
        except Exception as e:
            _handle_error(e)
        id_token = auth.get("idToken")
        uid = auth.get("localId")
        if not uid:
            click.echo("No UID in cached auth; re-login may be required", err=True)
            raise SystemExit(2)
    else:
        if not id_token or not uid:
            click.echo("--id-token and --uid required when not using --login-local", err=True)
            raise SystemExit(2)

    click.echo(f"UID: {uid}")
    paths = [
        ("app", f"/users/{uid}", "users_self.json"),
        ("app", "/devices", "devices.json"),
        ("app", f"/users/{uid}/devices", "users_devices.json"),
        ("app", f"/devicesByUser/{uid}", "devices_by_user.json"),
        ("app", "/sharekeys", "sharekeys.json"),
        ("tokens", f"/users/{uid}", "tokens_user.json"),
    ]

    os.makedirs(outdir, exist_ok=True)
    summary = []
    for db, path, fname in paths:
        try:
            data = core.db_get(db, path, id_token)
            outp = os.path.join(outdir, fname)
            with open(outp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            size = 0
            try:
                size = len(json.dumps(data))
            except Exception:
                pass
            nonempty = bool(data)
            click.echo(f"OK {db}:{path} -> {fname} nonempty={nonempty} size~{size}")
            summary.append((db, path, nonempty, size, fname))
        except Exception as e:
            click.echo(f"ERR {db}:{path} -> {e}")
    click.echo("\nSummary:")
    for db, path, nonempty, size, fname in summary:
        click.echo(f"- {db}:{path} -> {fname} nonempty={nonempty} size~{size}")



# ============================================================================
# Device control via Electric Imp
# ============================================================================

@cli.group("control")
def control_group() -> None:
    """Send commands to devices via Electric Imp agent."""


def _send_device_command(ctx: AppContext, action: str, device_id: Optional[str], id_token: Optional[str]) -> None:
    """Send a command to a device.

    Flow:
      1. Resolve device context (device_id, wkey, nonce, agent URL)
      2. Compute HMAC-SHA256 signature of command with nonce
      3. POST command to agent with signed headers
    """
    # Resolve all context from config/database
    try:
        ctx_data = core.resolve_imp_context(ctx.config, ctx.force_login, id_token, device_id)
    except Exception as e:
        _handle_error(e)

    # Parse device secret key
    try:
        knum_val, key_bytes = core.parse_wkey(ctx_data["wkey"])
    except Exception as e:
        _handle_error(e)

    # Build request headers with signature
    headers = {
        "User-Agent": USER_AGENT,
        "Authorization": core.compute_auth(action, ctx_data["nonce"], key_bytes, core.DEFAULT_HASH_ALGORITHM),
        "x-WayznKNum": str(knum_val),
    }

    # Send command to device
    try:
        r = requests.post(ctx_data["agenturl"], headers=headers, data=action, timeout=CONTROL_REQUEST_TIMEOUT)
        click.echo(f"HTTP {r.status_code}")
        click.echo(r.text[:500])
    except Exception as e:
        click.echo(f"Request failed: {e}", err=True)
        raise SystemExit(1)


@control_group.command("open")
@click.option("--device-id", required=False, help="Device ID (auto-select if registry has one device)")
@click.option("--id-token", default=None, help="Firebase ID token (auto-fetch if not provided)")
@click.pass_obj
def control_open(ctx: AppContext, device_id: Optional[str], id_token: Optional[str]) -> None:
    """Open device (e.g., unlock a petdoor)."""
    _send_device_command(ctx, "open", device_id, id_token)


@control_group.command("close")
@click.option("--device-id", required=False, help="Device ID (auto-select if registry has one device)")
@click.option("--id-token", default=None, help="Firebase ID token (auto-fetch if not provided)")
@click.pass_obj
def control_close(ctx: AppContext, device_id: Optional[str], id_token: Optional[str]) -> None:
    """Close device (e.g., lock a petdoor)."""
    _send_device_command(ctx, "close", device_id, id_token)


if __name__ == "__main__":
    cli()
