#!/bin/sh
# Wave 4 Phase 2 — apply default-deny cam egress with universal DNAT.
#
# Source of truth:
#   docs/superpowers/specs/2026-04-15-veto-gate-firmware-capture-design.md §4
#
# This script tears down the narrow Session 6 camre rules and replaces them
# with the Wave 4 default-deny catch-all:
#
#   - NTP (UDP/123) from the cam passes through to real servers
#   - TCP/443 from the cam → Mac:8443 (TLS MITM)
#   - TCP/80  from the cam → Mac:8080 (plain-HTTP MITM, unified into
#                                      mitm_cbs_proxy.py via first-byte sniff)
#   - Any other TCP from the cam → Mac:8443 (catch-all; logged and rejected)
#   - Any UDP (not 123) from the cam → Mac:32100 (supernode proxy / raw log)
#   - FORWARD-chain LOG+DROP for anything that escapes the PREROUTING
#     catch-alls (should never fire)
#
# Run on the UDM as root:
#
#   ssh root@192.168.5.1 'sh -s' < scripts/phase2_veto_gate_apply.sh
#
# Teardown is in scripts/phase2_veto_gate_teardown.sh (apply surgically
# reverses this). Both scripts operate only on rules carrying the
# 'camre' comment marker — native Unifi rules are never touched.

set -e

CAM=192.168.5.37
MAC=192.168.5.233

echo "=== 0. tear down any existing camre rules ==="
# Use grep -F (literal) camre because iptables-save renders the comment bare
# when it has no spaces — see ERRATA.md ERR-010.
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
echo "=== 1. Phase 3a — universal DNAT catch-all from $CAM to $MAC ==="

# Allow NTP through unmolested (cam needs real time for TLS cert validity).
iptables -t nat -I PREROUTING 2 -s $CAM -p udp --dport 123 \
  -j ACCEPT -m comment --comment "camre-ntp-allow"

# TCP port 443 → Mac:8443 (TLS MITM — veto gate terminates TLS, dispatches by SNI)
iptables -t nat -I PREROUTING 3 -s $CAM -p tcp --dport 443 \
  -j DNAT --to-destination $MAC:8443 -m comment --comment "camre-veto-tls"

# TCP port 80 → Mac:8443 (unified HTTP path via first-byte sniffing)
iptables -t nat -I PREROUTING 3 -s $CAM -p tcp --dport 80 \
  -j DNAT --to-destination $MAC:8443 -m comment --comment "camre-veto-http"

# All other TCP → Mac:8443 catch-all (will be rejected at the unified sniff
# layer and logged — any match here is a finding)
iptables -t nat -A PREROUTING -s $CAM -p tcp \
  -j DNAT --to-destination $MAC:8443 -m comment --comment "camre-veto-tcp-catchall"

# UDP not-NTP → Mac:32100 catch-all (supernode proxy absorbs Kalay; unknowns
# are logged by that proxy as "unknown session" entries)
iptables -t nat -A PREROUTING -s $CAM -p udp \
  -j DNAT --to-destination $MAC:32100 -m comment --comment "camre-veto-udp-catchall"

# Return path MASQUERADE for Mac responses back to cam
iptables -t nat -A POSTROUTING -s $CAM -d $MAC -j MASQUERADE \
  -m comment --comment "camre-veto-masq"

echo ""
echo "=== 2. FORWARD chain backup — LOG+DROP anything that escapes PREROUTING ==="

# This should never fire. If it does, the cam reached WAN via a path the
# PREROUTING rules missed — a finding worth documenting.
iptables -I FORWARD 1 -i br4 -o eth4 -s $CAM -p udp --dport 123 \
  -j ACCEPT -m comment --comment "camre-fwd-ntp"
iptables -I FORWARD 2 -i br4 -o eth4 -s $CAM \
  -j LOG --log-prefix "CAMRE-UNEXPECTED: " --log-level 6 \
  -m comment --comment "camre-fwd-log"
iptables -I FORWARD 3 -i br4 -o eth4 -s $CAM \
  -j DROP -m comment --comment "camre-fwd-drop"

echo ""
echo "=== 3. verification ==="
echo "--- camre rules in NAT table ---"
iptables-save -t nat | grep -F camre
echo ""
echo "--- camre rules in filter table ---"
iptables-save -t filter | grep -F camre
echo ""
echo "=== done. Now run Phase 0 dig test from the Mac: ==="
echo "  for h in p2p5.cloudbirds.cn user.hapseemate.cn public.dayunlinks.cn; do"
echo "    dig @192.168.5.1 +short \"\$h\" | head -1"
echo "  done"
echo ""
echo "Expected: all three return 203.0.113.37."
echo ""
echo "Then restart the Mac-side proxy to pick up the new veto code:"
echo "  kill <current mitm_cbs_proxy pid> && python3 mitm_cbs_proxy.py > /tmp/cam-listen/mitm_cbs.log 2>&1 &"
