# nix/scenarios/netconf-vlan.nix
#
# Stands up a single-VLAN scenario on a host pair for exercising the
# series3-flowdis-fastpath VLAN extension (extensions-draft/0001).
# Adds a single 802.1Q sub-interface (vlan100 by default) over the
# bare data-plane link on both ends, assigns a /29, and validates with
# ping. `down` removes only what `up` created — never touches the
# NixOS-managed static IP on the underlying physical iface.
#
# Usage:
#   OP=up   L=l L2=l2 GEN_DEV=enp35s0f0np0 DUT_DEV=enp35s0f0np0 \
#     nix run .#netconf-vlan
#   OP=down L=l L2=l2 GEN_DEV=enp35s0f0np0 DUT_DEV=enp35s0f0np0 \
#     nix run .#netconf-vlan
#   OP=verify ... nix run .#netconf-vlan
#
# Tunables (env, defaults shown):
#   VLAN_ID=100              (1..4094)
#   VLAN_NAME=vlan100        (linux iface name; auto if unset: vlan$VLAN_ID)
#   GEN_V4=10.10.40.2        generator IP in the VLAN
#   DUT_V4=10.10.40.5        DUT IP in the VLAN
#   PREFIX=29                /29 mask (4 usable addrs, room for .2/.5 pair)

{ pkgs }:

let
  libSh = builtins.readFile ./lib.sh;
in
pkgs.writeShellApplication {
  name = "netconf-vlan";

  runtimeInputs = with pkgs; [
    openssh
    coreutils
    iproute2  # provided remotely; included locally for cross-checks
  ];

  text = ''
    set -u

    ${libSh}

    require_op
    require_env L L2 GEN_DEV DUT_DEV

    VLAN_ID=''${VLAN_ID:-100}
    VLAN_NAME=''${VLAN_NAME:-vlan''${VLAN_ID}}
    GEN_V4=''${GEN_V4:-10.10.40.2}
    DUT_V4=''${DUT_V4:-10.10.40.5}
    PREFIX=''${PREFIX:-29}

    case "$OP" in
      up)
        # Idempotency: tear down any prior leftover before re-creating.
        SSH root@"$L"  "ip link del $VLAN_NAME 2>/dev/null || true"
        SSH root@"$L2" "ip link del $VLAN_NAME 2>/dev/null || true"

        # If anything below fails partway, tear down what we've added.
        cleanup_partial() {
          SSH root@"$L"  "ip link del $VLAN_NAME 2>/dev/null || true" || true
          SSH root@"$L2" "ip link del $VLAN_NAME 2>/dev/null || true" || true
        }
        trap cleanup_partial ERR

        SSH root@"$L"  "ip link add link $GEN_DEV name $VLAN_NAME type vlan id $VLAN_ID"
        SSH root@"$L"  "ip addr add $GEN_V4/$PREFIX dev $VLAN_NAME"
        SSH root@"$L"  "ip link set $VLAN_NAME up"

        SSH root@"$L2" "ip link add link $DUT_DEV name $VLAN_NAME type vlan id $VLAN_ID"
        SSH root@"$L2" "ip addr add $DUT_V4/$PREFIX dev $VLAN_NAME"
        SSH root@"$L2" "ip link set $VLAN_NAME up"

        # Give the link a moment to come up before ping. Carrier on a
        # vlan sub-iface tracks the parent, so this is usually instant.
        sleep 1

        if ! SSH root@"$L" "ping -c3 -W2 -I $VLAN_NAME $DUT_V4" >/dev/null 2>&1; then
          log "ping $L -> $L2 over $VLAN_NAME failed; cleaning up"
          cleanup_partial
          exit 1
        fi
        trap - ERR

        emit_env L_SCENARIO_DEV  "$VLAN_NAME"
        emit_env L_SCENARIO_V4   "$GEN_V4"
        emit_env L_SCENARIO_MAC  "$(read_mac "$L"  "$VLAN_NAME")"
        emit_env L2_SCENARIO_DEV "$VLAN_NAME"
        emit_env L2_SCENARIO_V4  "$DUT_V4"
        emit_env L2_SCENARIO_MAC "$(read_mac "$L2" "$VLAN_NAME")"
        log "vlan id=$VLAN_ID up: $L($GEN_V4) <-> $L2($DUT_V4) on $VLAN_NAME"
        ;;

      down)
        SSH root@"$L"  "ip link del $VLAN_NAME 2>/dev/null || true" || true
        SSH root@"$L2" "ip link del $VLAN_NAME 2>/dev/null || true" || true
        log "vlan id=$VLAN_ID down"
        ;;

      verify)
        SSH root@"$L"  "ip -br link show $VLAN_NAME"  >/dev/null 2>&1 || {
          log "verify: $L lacks $VLAN_NAME"; exit 1;
        }
        SSH root@"$L2" "ip -br link show $VLAN_NAME"  >/dev/null 2>&1 || {
          log "verify: $L2 lacks $VLAN_NAME"; exit 1;
        }
        SSH root@"$L" "ping -c3 -W2 -I $VLAN_NAME $DUT_V4" >/dev/null 2>&1 || {
          log "verify: ping $L -> $L2 over $VLAN_NAME failed"; exit 1;
        }
        log "vlan id=$VLAN_ID verify: OK"
        ;;
    esac
  '';
}
