#!/bin/sh
# Wave 4 Phase 2 — teardown. Reverses phase2_veto_gate_apply.sh.
#
# Source of truth:
#   docs/superpowers/specs/2026-04-15-veto-gate-firmware-capture-design.md §6 Phase 8
#
# Finds every rule tagged with the 'camre' comment marker, flips the
# -A/-I prefix to -D, and deletes them. Never touches non-camre rules.
# Also removes the dnsmasq cam-override.conf and hard-restarts the main
# dnsmasq via the UDM supervisor (SIGHUP is NOT sufficient — see ERR-010).
#
# Run on the UDM as root:
#
#   ssh root@192.168.5.1 'sh -s' < scripts/phase2_veto_gate_teardown.sh

set -e

echo "=== tearing down all camre rules across nat + filter tables ==="
for t in nat filter; do
  iptables-save -t "$t" \
    | grep -F camre \
    | sed 's/^-A /-D /' \
    | while IFS= read -r rule; do
        # shellcheck disable=SC2086
        iptables -t "$t" $rule 2>/dev/null && echo "  dropped: $rule" || true
      done
done

echo ""
echo "=== removing dnsmasq cam-override.conf ==="
rm -f /run/dnsmasq.dhcp.conf.d/cam-override.conf
if [ -f /run/dnsmasq-main.pid ]; then
  kill "$(cat /run/dnsmasq-main.pid)" && echo "  main dnsmasq killed; supervisor will respawn"
fi

echo ""
echo "=== verification ==="
echo "--- any remaining camre rules? (expect none) ---"
if iptables-save | grep -F camre; then
  echo "WARNING: some camre rules survived teardown"
else
  echo "clean"
fi
echo ""
echo "--- cam-override.conf present? (expect absent) ---"
ls -la /run/dnsmasq.dhcp.conf.d/cam-override.conf 2>&1 | head -1

echo ""
echo "=== done. Restart dnsmasq check: after ~5s, dig the former sinkhole ==="
echo "  dig @192.168.5.1 +short user.hapseemate.cn"
echo ""
echo "Expected: the REAL cloud IP (190.92.254.71) once dnsmasq has respawned."
