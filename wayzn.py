#!/usr/bin/env python3
"""Wayzn smart device client CLI entrypoint.

This is a convenience wrapper. You can also run:
  python -m custom_components.wayzn.wayzn_client.cli
"""

import sys

# Import and run the CLI
from custom_components.wayzn.wayzn_client import cli as cli_module

if __name__ == "__main__":
    cli_module.cli()
