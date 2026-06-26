# nix/scenarios/netconf-qinq.nix
#
# Stands up a QinQ (802.1AD outer S-tag + 802.1Q inner C-tag) scenario
# on a host pair for exercising extensions-draft/0002. Creates a
# stacked sub-interface tree on both ends:
#
#   <DEV> -> svlan<S> (id=S, proto 802.1ad)
#         -> cvlan<C> (id=C, proto 802.1q, link=svlan<S>)
#
# Assigns a /29 on the innermost cvlan and validates with ping.
# `down` removes the cvlan and svlan in that order; never touches the
# NixOS-managed static IP on the underlying physical iface.
#
# Usage:
#   OP=up   L=l L2=l2 GEN_DEV=enp35s0f0np0 DUT_DEV=enp35s0f0np0 \
#     nix run .#netconf-qinq
#
# Tunables (env, defaults shown):
#   SVLAN_ID=10              outer S-tag VID (1..4094)
#   CVLAN_ID=100             inner C-tag VID
#   GEN_V4=10.10.41.2        generator IP on the cvlan
#   DUT_V4=10.10.41.5        DUT IP on the cvlan
#   PREFIX=29

{ pkgs }:

let
  libSh = builtins.readFile ./lib.sh;
in
pkgs.writeShellApplication {
  name = "netconf-qinq";

  runtimeInputs = with pkgs; [
    openssh
    coreutils
    iproute2
  ];

  text = ''
    set -u

    ${libSh}

    require_op
    require_env L L2 GEN_DEV DUT_DEV

    SVLAN_ID=''${SVLAN_ID:-10}
    CVLAN_ID=''${CVLAN_ID:-100}
    SVLAN_NAME=svlan''${SVLAN_ID}
    CVLAN_NAME=cvlan''${CVLAN_ID}
    GEN_V4=''${GEN_V4:-10.10.41.2}
    DUT_V4=''${DUT_V4:-10.10.41.5}
    PREFIX=''${PREFIX:-29}

    do_down_remote() {
      local host="$1"
      # cvlan first (child), then svlan (parent). Tolerate missing.
      SSH root@"$host" "ip link del $CVLAN_NAME 2>/dev/null || true" || true
      SSH root@"$host" "ip link del $SVLAN_NAME 2>/dev/null || true" || true
    }

    case "$OP" in
      up)
        # Idempotency: tear down any stale stack first.
        do_down_remote "$L"
        do_down_remote "$L2"

        cleanup_partial() {
          do_down_remote "$L"
          do_down_remote "$L2"
        }
        trap cleanup_partial ERR

        # Outer S-tag (8021AD) on the physical iface
        SSH root@"$L"  "ip link add link $GEN_DEV name $SVLAN_NAME type vlan id $SVLAN_ID proto 802.1ad"
        SSH root@"$L"  "ip link set $SVLAN_NAME up"
        SSH root@"$L2" "ip link add link $DUT_DEV name $SVLAN_NAME type vlan id $SVLAN_ID proto 802.1ad"
        SSH root@"$L2" "ip link set $SVLAN_NAME up"

        # Inner C-tag (8021Q) on top of the S-tag.
        # MTU=1492 = phys_mtu(1500) - 2x VLAN tags(8 bytes). The Linux vlan
        # driver inherits parent MTU by default instead of subtracting the
        # tag size, so without this clamp TCP MSS auto-negotiates to 1460,
        # producing 1522-byte wire frames that some mlx5 variants (e.g.
        # the one in hp1/hp3 with rx-vlan-stag-filter: on [fixed]) silently
        # drop while a standard one-tag 1518-byte frame still passes. UDP
        # masked the bug because iperf3's default UDP blksize is 1200.
        SSH root@"$L"  "ip link add link $SVLAN_NAME name $CVLAN_NAME type vlan id $CVLAN_ID proto 802.1q"
        SSH root@"$L"  "ip link set $CVLAN_NAME mtu 1492"
        SSH root@"$L"  "ip addr add $GEN_V4/$PREFIX dev $CVLAN_NAME"
        SSH root@"$L"  "ip link set $CVLAN_NAME up"
        SSH root@"$L2" "ip link add link $SVLAN_NAME name $CVLAN_NAME type vlan id $CVLAN_ID proto 802.1q"
        SSH root@"$L2" "ip link set $CVLAN_NAME mtu 1492"
        SSH root@"$L2" "ip addr add $DUT_V4/$PREFIX dev $CVLAN_NAME"
        SSH root@"$L2" "ip link set $CVLAN_NAME up"

        sleep 1

        if ! SSH root@"$L" "ping -c3 -W2 -I $CVLAN_NAME $DUT_V4" >/dev/null 2>&1; then
          log "ping $L -> $L2 over $CVLAN_NAME failed (S=$SVLAN_ID C=$CVLAN_ID); cleaning up"
          cleanup_partial
          exit 1
        fi
        trap - ERR

        emit_env L_SCENARIO_DEV  "$CVLAN_NAME"
        emit_env L_SCENARIO_V4   "$GEN_V4"
        emit_env L_SCENARIO_MAC  "$(read_mac "$L"  "$CVLAN_NAME")"
        emit_env L2_SCENARIO_DEV "$CVLAN_NAME"
        emit_env L2_SCENARIO_V4  "$DUT_V4"
        emit_env L2_SCENARIO_MAC "$(read_mac "$L2" "$CVLAN_NAME")"
        log "qinq S=$SVLAN_ID C=$CVLAN_ID up: $L($GEN_V4) <-> $L2($DUT_V4) on $CVLAN_NAME"
        ;;

      down)
        do_down_remote "$L"
        do_down_remote "$L2"
        log "qinq S=$SVLAN_ID C=$CVLAN_ID down"
        ;;

      verify)
        for h in "$L" "$L2"; do
          SSH root@"$h" "ip -br link show $SVLAN_NAME" >/dev/null 2>&1 || {
            log "verify: $h lacks $SVLAN_NAME"; exit 1;
          }
          SSH root@"$h" "ip -br link show $CVLAN_NAME" >/dev/null 2>&1 || {
            log "verify: $h lacks $CVLAN_NAME"; exit 1;
          }
        done
        SSH root@"$L" "ping -c3 -W2 -I $CVLAN_NAME $DUT_V4" >/dev/null 2>&1 || {
          log "verify: ping $L -> $L2 over $CVLAN_NAME failed"; exit 1;
        }
        log "qinq S=$SVLAN_ID C=$CVLAN_ID verify: OK"
        ;;
    esac
  '';
}
