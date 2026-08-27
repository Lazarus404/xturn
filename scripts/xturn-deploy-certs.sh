#!/usr/bin/env bash
set -euo pipefail

# lego --renew-hook target: copies renewed PEMs into xturn's cert directory.
#
# Required environment:
#   XTURN_CERT_DOMAIN   DNS name passed to lego (e.g. turn.tstitch.me)
#
# Optional environment:
#   XTURN_LEGO_PATH     lego data dir (default: /etc/xturn/lego)
#   XTURN_CERT_DIR      destination dir (default: /etc/xturn/certs)
#   XTURN_USER          owner of installed files (default: xturn)
#   XTURN_SERVICE       systemd unit to HUP for instant reload (optional)

DOMAIN="${XTURN_CERT_DOMAIN:?set XTURN_CERT_DOMAIN}"
LEGO_PATH="${XTURN_LEGO_PATH:-/etc/xturn/lego}"
CERT_DIR="${XTURN_CERT_DIR:-/etc/xturn/certs}"
XTURN_USER="${XTURN_USER:-xturn}"

src_cert="${LEGO_PATH}/certificates/${DOMAIN}.crt"
src_key="${LEGO_PATH}/certificates/${DOMAIN}.key"

install -d -m 0750 -o "${XTURN_USER}" -g "${XTURN_USER}" "${CERT_DIR}"
install -m 0640 -o "${XTURN_USER}" -g "${XTURN_USER}" "${src_cert}" "${CERT_DIR}/${DOMAIN}.crt"
install -m 0640 -o "${XTURN_USER}" -g "${XTURN_USER}" "${src_key}" "${CERT_DIR}/${DOMAIN}.key"

if [[ -n "${XTURN_SERVICE:-}" ]]; then
  systemctl kill -s HUP "${XTURN_SERVICE}"
fi
