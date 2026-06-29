#!/usr/bin/env bash

set -euo pipefail

install_root="${MESHCORE_ROOT:-/opt/meshcore-pi}"
config_file="${1:-/etc/meshcore/config.toml}"

exec "${install_root}/venv/bin/python" "${install_root}/meshcore.py" "${config_file}"