# nix/scenarios/netconf-geneve.nix
#
# Stands up a Geneve overlay (UDP port 6081, TEB inner Ethernet) over
# the underlay physical iface for exercising the Geneve-inner descent
# RFC EXPERIMENT (xdp2 v4-namespace patch 5, kernel commit
# 1ccdeb669b34). Mirror of netconf-vxlan.nix in shape.
#
# Usage:
#   OP=up   L=l L2=l2 GEN_DEV=enp35s0f0np0 DUT_DEV=enp35s0f0np0 \
#     GEN_UNDERLAY_V4=10.10.4.2 DUT_UNDERLAY_V4=10.10.4.5 \
#     nix run .#netconf-geneve
#
# Tunables (env, defaults shown):
#   VNI=10                            Geneve VNI
#   DST_PORT=6081                     UDP dst port (IANA Geneve)
#   GEN_UNDERLAY_V4 / DUT_UNDERLAY_V4 mandatory
#   GEN_V4=192.168.101.1              gen IP inside the overlay
#   DUT_V4=192.168.101.2              DUT IP inside the overlay
#   PREFIX=24

{ pkgs }:

let
  libSh = builtins.readFile ./lib.sh;
in
pkgs.writeShellApplication {
  name = "netconf-geneve";

  runtimeInputs = with pkgs; [ openssh coreutils iproute2 ];

  text = ''
    set -u
    ${libSh}
    require_op
    require_env L L2 GEN_DEV DUT_DEV GEN_UNDERLAY_V4 DUT_UNDERLAY_V4

    VNI=''${VNI:-10}
    DST_PORT=''${DST_PORT:-6081}
    TUN_NAME=''${TUN_NAME:-geneve''${VNI}}
    GEN_V4=''${GEN_V4:-192.168.101.1}
    DUT_V4=''${DUT_V4:-192.168.101.2}
    PREFIX=''${PREFIX:-24}

    open_geneve_fw() {
      # Open Geneve UDP port on the nixos-fw chain so the proto can
      # reach the host's geneve socket on the receiver. (Geneve
      # encap'd traffic terminates in-kernel; no IP filter needed.
      # But the outer UDP delivery does pass the input chain.)
      local host="$1"
      SSH root@"$host" "
        iptables -C nixos-fw -p udp --dport $DST_PORT -j ACCEPT 2>/dev/null \
          || iptables -I nixos-fw 1 -p udp --dport $DST_PORT -j ACCEPT
      " >/dev/null 2>&1 || true
    }
    close_geneve_fw() {
      local host="$1"
      SSH root@"$host" "iptables -D nixos-fw -p udp --dport $DST_PORT -j ACCEPT 2>/dev/null" >/dev/null 2>&1 || true
    }

    case "$OP" in
      up)
        SSH root@"$L"  "ip link del $TUN_NAME 2>/dev/null || true"
        SSH root@"$L2" "ip link del $TUN_NAME 2>/dev/null || true"

        cleanup_partial() {
          SSH root@"$L"  "ip link del $TUN_NAME 2>/dev/null || true" || true
          SSH root@"$L2" "ip link del $TUN_NAME 2>/dev/null || true" || true
          close_geneve_fw "$L"
          close_geneve_fw "$L2"
        }
        trap cleanup_partial ERR

        open_geneve_fw "$L"
        open_geneve_fw "$L2"

        SSH root@"$L"  "ip link add $TUN_NAME type geneve id $VNI remote $DUT_UNDERLAY_V4 dstport $DST_PORT"
        SSH root@"$L"  "ip addr add $GEN_V4/$PREFIX dev $TUN_NAME"
        SSH root@"$L"  "ip link set $TUN_NAME up"

        SSH root@"$L2" "ip link add $TUN_NAME type geneve id $VNI remote $GEN_UNDERLAY_V4 dstport $DST_PORT"
        SSH root@"$L2" "ip addr add $DUT_V4/$PREFIX dev $TUN_NAME"
        SSH root@"$L2" "ip link set $TUN_NAME up"

        sleep 1
        if ! SSH root@"$L" "ping -c3 -W2 -I $TUN_NAME $DUT_V4" >/dev/null 2>&1; then
          log "ping $L -> $L2 over $TUN_NAME failed; cleaning up"
          cleanup_partial
          exit 1
        fi
        trap - ERR

        emit_env L_SCENARIO_DEV  "$TUN_NAME"
        emit_env L_SCENARIO_V4   "$GEN_V4"
        emit_env L_SCENARIO_MAC  "$(read_mac "$L"  "$TUN_NAME")"
        emit_env L2_SCENARIO_DEV "$TUN_NAME"
        emit_env L2_SCENARIO_V4  "$DUT_V4"
        emit_env L2_SCENARIO_MAC "$(read_mac "$L2" "$TUN_NAME")"
        log "geneve $TUN_NAME (VNI=$VNI dstport=$DST_PORT) up: $L($GEN_V4) <-> $L2($DUT_V4)"
        ;;
      down)
        SSH root@"$L"  "ip link del $TUN_NAME 2>/dev/null || true" || true
        SSH root@"$L2" "ip link del $TUN_NAME 2>/dev/null || true" || true
        close_geneve_fw "$L"
        close_geneve_fw "$L2"
        log "geneve $TUN_NAME down"
        ;;
      verify)
        for h in "$L" "$L2"; do
          SSH root@"$h" "ip -br link show $TUN_NAME" >/dev/null 2>&1 || {
            log "verify: $h lacks $TUN_NAME"; exit 1;
          }
        done
        SSH root@"$L" "ping -c3 -W2 -I $TUN_NAME $DUT_V4" >/dev/null 2>&1 || {
          log "verify: ping $L -> $L2 over $TUN_NAME failed"; exit 1;
        }
        log "geneve $TUN_NAME verify: OK"
        ;;
    esac
  '';
}
