#!/bin/sh
# Only the hub container may open the escrow signer's forward on the Docker bridge (KI-11).
#
# escrow-signer-tunnel binds 172.18.0.1:9500 so the hub container can reach the signer, and
# with it every other container on aicom_aicom_net: three first-party ones when that was
# written, fifteen on 2026-10-22, among them product frontends the factory generated. The
# bearer token and the signer's own policy still stand between them and a signature; this
# takes the port away from everything but the hub.
#
# Rules live in their own chain, rebuilt from the hub's CURRENT addresses on every run (a
# recreated container gets a new one). No hub container, no address: the chain rejects
# everyone, so the failure mode is "collection pauses", never "the port opens".
#
#   install -m 755 signer-hub-only.sh /usr/local/sbin/
#   cp signer-hub-only.service signer-hub-only.timer /etc/systemd/system/
#   systemctl daemon-reload && systemctl enable --now signer-hub-only.timer
#
# Undo: systemctl disable --now signer-hub-only.timer
#       iptables -D INPUT -d 172.18.0.1 -p tcp --dport 9500 -j ESCROW_SIGNER
#       iptables -F ESCROW_SIGNER && iptables -X ESCROW_SIGNER
set -eu
HUB="${HUB_CONTAINER:-modelmarket-hub}"
BIND="${SIGNER_BIND:-172.18.0.1}"
PORT="${SIGNER_PORT:-9500}"
CHAIN=ESCROW_SIGNER

addrs="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$HUB" 2>/dev/null || true)"
running="$(docker inspect -f '{{.State.Running}}' "$HUB" 2>/dev/null || echo false)"
[ "$running" = "true" ] || addrs=""

iptables -N "$CHAIN" 2>/dev/null || true
# Build the new rule set in a fresh chain and swap it in, so there is no moment with an
# empty chain (which would let everyone through).
NEW="${CHAIN}_NEW"
iptables -N "$NEW" 2>/dev/null || iptables -F "$NEW"
for a in $addrs; do
  case "$a" in *.*.*.*) iptables -A "$NEW" -s "$a" -j RETURN ;; esac
done
# tcp-reset is only valid in a rule that matches TCP itself.
iptables -A "$NEW" -p tcp -j REJECT --reject-with tcp-reset
iptables -I INPUT -d "$BIND" -p tcp --dport "$PORT" -j "$NEW"
while iptables -D INPUT -d "$BIND" -p tcp --dport "$PORT" -j "$CHAIN" 2>/dev/null; do :; done
iptables -F "$CHAIN"
iptables -E "$CHAIN" "${CHAIN}_OLD" 2>/dev/null && iptables -X "${CHAIN}_OLD"
iptables -E "$NEW" "$CHAIN"
echo "signer port ${BIND}:${PORT} open to: ${addrs:-nobody}"
