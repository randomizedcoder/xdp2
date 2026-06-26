# nix/scenarios/netconf-vxlan.nix
#
# Stands up a VXLAN overlay between a host pair for exercising the
# series3-flowdis-fastpath VXLAN-inner extension (extensions-draft/0003,
# RFC EXPERIMENT) and the existing eth+IPv4+UDP outer fast-path.
#
# Topology: the underlying physical link (assumed already configured by
# NixOS, e.g. 10.10.4.0/29 between L and L2) carries the VXLAN UDP
# encapsulation. A vxlan10 interface is created on each end and given a
# /24 in 192.168.100.0/24 (overlay), so iperf or tcpreplay through the
# vxlan iface generates encapsulated traffic over the bare underlay.
#
# Usage:
#   OP=up   L=l L2=l2 GEN_DEV=enp35s0f0np0 DUT_DEV=enp35s0f0np0 \
#     GEN_UNDERLAY_V4=10.10.4.2 DUT_UNDERLAY_V4=10.10.4.5 \
#     nix run .#netconf-vxlan
#
# Tunables (env, defaults shown):
#   VNI=10                   VXLAN VNI (1..16777215)
#   DSTPORT=4789             IANA VXLAN UDP port — matches the dissector
#                            inner-descent check in extensions-draft/0003
#   GEN_OVERLAY_V4=192.168.100.1
#   DUT_OVERLAY_V4=192.168.100.2
#   PREFIX=24
#   GEN_UNDERLAY_V4 (req)    addr of L on the bare link (remote arg from L2 side)
#   DUT_UNDERLAY_V4 (req)    addr of L2 on the bare link (remote arg from L side)

{ pkgs }:

let
  libSh = builtins.readFile ./lib.sh;
in
pkgs.writeShellApplication {
  name = "netconf-vxlan";

  runtimeInputs = with pkgs; [
    openssh
    coreutils
    iproute2
  ];

  text = ''
    set -u

    ${libSh}

    require_op
    require_env L L2 GEN_DEV DUT_DEV GEN_UNDERLAY_V4 DUT_UNDERLAY_V4

    VNI=''${VNI:-10}
    DSTPORT=''${DSTPORT:-4789}
    VX_NAME=vxlan''${VNI}
    GEN_OVERLAY_V4=''${GEN_OVERLAY_V4:-192.168.100.1}
    DUT_OVERLAY_V4=''${DUT_OVERLAY_V4:-192.168.100.2}
    PREFIX=''${PREFIX:-24}

    # Open / close the underlay UDP dstport in the NixOS firewall on
    # both hosts so VXLAN frames can actually be received. Idempotent:
    # iptables -C checks-and-skips if the rule already exists. Same
    # pattern as series3-soak-x86.nix's ensure_fw().
    open_fw() {
      local host="$1"
      SSH root@"$host" "
        iptables -C nixos-fw -p udp --dport $DSTPORT -j ACCEPT 2>/dev/null \
          || iptables -I nixos-fw 1 -p udp --dport $DSTPORT -j ACCEPT
      " >/dev/null 2>&1 || true
    }
    close_fw() {
      local host="$1"
      SSH root@"$host" "
        iptables -D nixos-fw -p udp --dport $DSTPORT -j ACCEPT 2>/dev/null
      " >/dev/null 2>&1 || true
    }

    case "$OP" in
      up)
        SSH root@"$L"  "ip link del $VX_NAME 2>/dev/null || true"
        SSH root@"$L2" "ip link del $VX_NAME 2>/dev/null || true"

        cleanup_partial() {
          SSH root@"$L"  "ip link del $VX_NAME 2>/dev/null || true" || true
          SSH root@"$L2" "ip link del $VX_NAME 2>/dev/null || true" || true
          close_fw "$L"
          close_fw "$L2"
        }
        trap cleanup_partial ERR

        open_fw "$L"
        open_fw "$L2"

        # Point-to-point VXLAN: remote address is the peer's underlay IP.
        # `dev <iface>` pins the encap source to the bare link (not the
        # mgmt iface). `local` sets the source IP for outer packets.
        SSH root@"$L" "ip link add $VX_NAME type vxlan id $VNI \
            local $GEN_UNDERLAY_V4 remote $DUT_UNDERLAY_V4 \
            dev $GEN_DEV dstport $DSTPORT"
        SSH root@"$L" "ip addr add $GEN_OVERLAY_V4/$PREFIX dev $VX_NAME"
        SSH root@"$L" "ip link set $VX_NAME up"

        SSH root@"$L2" "ip link add $VX_NAME type vxlan id $VNI \
            local $DUT_UNDERLAY_V4 remote $GEN_UNDERLAY_V4 \
            dev $DUT_DEV dstport $DSTPORT"
        SSH root@"$L2" "ip addr add $DUT_OVERLAY_V4/$PREFIX dev $VX_NAME"
        SSH root@"$L2" "ip link set $VX_NAME up"

        sleep 1

        if ! SSH root@"$L" "ping -c3 -W2 -I $VX_NAME $DUT_OVERLAY_V4" >/dev/null 2>&1; then
          log "ping $L -> $L2 over $VX_NAME (VNI=$VNI) failed; cleaning up"
          cleanup_partial
          exit 1
        fi
        trap - ERR

        emit_env L_SCENARIO_DEV  "$VX_NAME"
        emit_env L_SCENARIO_V4   "$GEN_OVERLAY_V4"
        emit_env L_SCENARIO_MAC  "$(read_mac "$L"  "$VX_NAME")"
        emit_env L2_SCENARIO_DEV "$VX_NAME"
        emit_env L2_SCENARIO_V4  "$DUT_OVERLAY_V4"
        emit_env L2_SCENARIO_MAC "$(read_mac "$L2" "$VX_NAME")"
        emit_env VXLAN_DSTPORT   "$DSTPORT"
        log "vxlan VNI=$VNI dstport=$DSTPORT up: $L($GEN_OVERLAY_V4) <-> $L2($DUT_OVERLAY_V4) on $VX_NAME"
        ;;

      down)
        SSH root@"$L"  "ip link del $VX_NAME 2>/dev/null || true" || true
        SSH root@"$L2" "ip link del $VX_NAME 2>/dev/null || true" || true
        close_fw "$L"
        close_fw "$L2"
        log "vxlan VNI=$VNI down"
        ;;

      verify)
        for h in "$L" "$L2"; do
          SSH root@"$h" "ip -br link show $VX_NAME" >/dev/null 2>&1 || {
            log "verify: $h lacks $VX_NAME"; exit 1;
          }
        done
        SSH root@"$L" "ping -c3 -W2 -I $VX_NAME $DUT_OVERLAY_V4" >/dev/null 2>&1 || {
          log "verify: ping $L -> $L2 over $VX_NAME failed"; exit 1;
        }
        log "vxlan VNI=$VNI verify: OK"
        ;;
    esac
  '';
}
