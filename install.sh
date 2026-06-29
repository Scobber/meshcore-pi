#!/usr/bin/env bash

set -euo pipefail

source_dir="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
install_root="${INSTALL_ROOT:-/opt/meshcore-pi}"
config_dir="${CONFIG_DIR:-/etc/meshcore}"
data_dir="${DATA_DIR:-/var/lib/meshcore}"
log_dir="${LOG_DIR:-/var/log/meshcore}"
service_name="meshcore"
service_file="${source_dir}/systemd/meshcore.service"
launcher_file="${source_dir}/meshcore-start.sh"

if [[ ! -f "${source_dir}/meshcore.py" ]]; then
    echo "ERROR: source_dir must point at the Meshcore repository root" >&2
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: install.sh must be run as root" >&2
    exit 1
fi

if [[ ! -f "${service_file}" ]]; then
    echo "ERROR: missing systemd unit at ${service_file}" >&2
    exit 1
fi

if [[ ! -f "${launcher_file}" ]]; then
    echo "ERROR: missing launcher script at ${launcher_file}" >&2
    exit 1
fi

seed_config="${source_dir}/config.toml"
if [[ ! -f "${seed_config}" ]]; then
    if [[ -f "${source_dir}/example-config.toml" ]]; then
        seed_config="${source_dir}/example-config.toml"
    else
        echo "ERROR: missing config.toml and example-config.toml in ${source_dir}" >&2
        exit 1
    fi
fi

updating_existing=0
if [[ -f "${install_root}/meshcore.py" || -f "${install_root}/meshcore-start.sh" ]]; then
    updating_existing=1
fi

service_was_active=0
if systemctl is-active --quiet "${service_name}.service"; then
    service_was_active=1
    systemctl stop "${service_name}.service"
fi

install -d -m 0755 "${install_root}"

# Update the runtime in place; preserve venv to avoid unnecessary rebuilds.
if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
        --exclude '.git/' \
        --exclude 'venv/' \
        --exclude '__pycache__/' \
        --exclude '*.pyc' \
        --exclude 'contacts.mesh' \
        --exclude '*-contacts.mesh' \
        --exclude 'channels.json' \
        "${source_dir}/" "${install_root}/"
else
    # Best-effort fallback if rsync is unavailable.
    find "${install_root}" -mindepth 1 -maxdepth 1 \
        ! -name venv \
        ! -name contacts.mesh \
        ! -name '*-contacts.mesh' \
        ! -name channels.json \
        -exec rm -rf {} +
    (
        cd "${source_dir}"
        tar --exclude='.git' --exclude='venv' --exclude='__pycache__' \
            --exclude='contacts.mesh' --exclude='*-contacts.mesh' --exclude='channels.json' -cf - .
    ) | (
        cd "${install_root}"
        tar -xf -
    )
fi

install -d -m 0755 "${config_dir}" "${data_dir}" "${log_dir}"

created_config=0
if [[ ! -f "${config_dir}/config.toml" ]]; then
    install -m 0644 "${seed_config}" "${config_dir}/config.toml"
    created_config=1
fi

if [[ ${created_config} -eq 1 ]]; then
    python3 - <<'PY' "${source_dir}" "${config_dir}/config.toml" "${log_dir}/meshcore.log"
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])

import tomllib
from configuration import toml_dumps

config_path = Path(sys.argv[2])
log_path = sys.argv[3]

with config_path.open("rb") as f:
    data = tomllib.load(f)

log_cfg = data.get("log")
if not isinstance(log_cfg, dict):
    log_cfg = {}
    data["log"] = log_cfg

if not log_cfg.get("file"):
    log_cfg["file"] = log_path
    config_path.write_text(toml_dumps(data), encoding="utf-8")
PY
fi

if [[ ! -f "${config_dir}/channels.json" && -f "${source_dir}/channels.json" ]]; then
    install -m 0644 "${source_dir}/channels.json" "${config_dir}/channels.json"
fi

if [[ ! -f "${config_dir}/contacts.mesh" && -f "${source_dir}/contacts.mesh" ]]; then
    install -m 0644 "${source_dir}/contacts.mesh" "${config_dir}/contacts.mesh"
fi

if ! id -u meshcore >/dev/null 2>&1; then
    useradd --system --home-dir "${install_root}" --create-home --shell /usr/sbin/nologin meshcore
fi

usermod -a -G spi,gpio,dialout meshcore >/dev/null 2>&1 || true

chown -R meshcore:meshcore "${install_root}" "${config_dir}" "${data_dir}" "${log_dir}"

if [[ ! -d "${install_root}/venv" ]]; then
    python3 -m venv "${install_root}/venv"
fi

"${install_root}/venv/bin/python" -m pip install --upgrade pip
"${install_root}/venv/bin/python" -m pip install pycryptodome aiotools pyserial_asyncio typing-extensions LoRaRF "scapy==2.5.0"

install -m 0644 "${service_file}" "/etc/systemd/system/${service_name}.service"
install -m 0755 "${launcher_file}" "${install_root}/meshcore-start.sh"
systemctl daemon-reload

if [[ ${service_was_active} -eq 1 ]]; then
    systemctl start "${service_name}.service"
fi

if [[ ${updating_existing} -eq 1 ]]; then
    echo "Updated Meshcore at ${install_root}"
else
    echo "Installed Meshcore to ${install_root}"
fi
echo "Config path: ${config_dir}/config.toml"
echo "Data path: ${data_dir}"
echo "Log path: ${log_dir}"
echo "Service: systemctl enable --now ${service_name}.service"