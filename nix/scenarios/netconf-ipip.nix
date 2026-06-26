# nix/scenarios/netconf-ipip.nix
#
# Stands up an IPv4-in-IPv4 IPIP tunnel scenario for exercising
# series3-flowdis-fastpath v4-namespace/0003 (the IPIP family fast-
# path). Creates a point-to-point ipip0 tunnel between the two pair
# members over the underlay physical iface, assigns a /29 inside the
# tunnel, and validates with ping. `down` removes only what `up`
# created.
#
# Usage:
#   OP=up   L=l L2=l2 GEN_DEV=enp35s0f0np0 DUT_DEV=enp35s0f0np0 \
#     GEN_UNDERLAY_V4=10.10.4.2 DUT_UNDERLAY_V4=10.10.4.5 \
#     nix run .#netconf-ipip
#
# Tunables (env, defaults shown):
#   TUN_NAME=ipip0                   tunnel iface name
#   GEN_UNDERLAY_V4 / DUT_UNDERLAY_V4 mandatory; remote / local for
#                                    `ip link add type ipip` on each end
#   GEN_V4=10.10.42.2                generator IP *inside* the tunnel
#   DUT_V4=10.10.42.5                DUT IP *inside* the tunnel
#   PREFIX=29

{ pkgs }:

let
  libSh = builtins.readFile ./lib.sh;
in
pkgs.writeShellApplication {
  name = "netconf-ipip";

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

    TUN_NAME=''${TUN_NAME:-ipip0}
    GEN_V4=''${GEN_V4:-10.10.42.2}
    DUT_V4=''${DUT_V4:-10.10.42.5}
    PREFIX=''${PREFIX:-29}

    open_ipip_fw() {
      # NixOS default firewall (nixos-fw chain) refuses anything not
      # explicitly accepted, so IPv4 protocol 4 (IPIP) tunnel traffic
      # gets log-refused both directions. Insert an ACCEPT rule on
      # both ends; cleanup removes it.
      local host="$1"
      SSH root@"$host" "
        iptables -C nixos-fw -p 4 -j ACCEPT 2>/dev/null \
          || iptables -I nixos-fw 1 -p 4 -j ACCEPT
      " >/dev/null 2>&1 || true
    }
    close_ipip_fw() {
      local host="$1"
      SSH root@"$host" "iptables -D nixos-fw -p 4 -j ACCEPT 2>/dev/null" >/dev/null 2>&1 || true
    }

    case "$OP" in
      up)
        SSH root@"$L"  "ip link del $TUN_NAME 2>/dev/null || true"
        SSH root@"$L2" "ip link del $TUN_NAME 2>/dev/null || true"

        cleanup_partial() {
          SSH root@"$L"  "ip link del $TUN_NAME 2>/dev/null || true" || true
          SSH root@"$L2" "ip link del $TUN_NAME 2>/dev/null || true" || true
          close_ipip_fw "$L"
          close_ipip_fw "$L2"
        }
        trap cleanup_partial ERR

        open_ipip_fw "$L"
        open_ipip_fw "$L2"

        # Each end's `ip link add` swaps remote/local relative to its
        # underlay position.
        SSH root@"$L"  "ip link add $TUN_NAME type ipip \
                          remote $DUT_UNDERLAY_V4 local $GEN_UNDERLAY_V4 dev $GEN_DEV"
        SSH root@"$L"  "ip addr add $GEN_V4/$PREFIX dev $TUN_NAME"
        SSH root@"$L"  "ip link set $TUN_NAME up"
        # Disable tx-checksum offload on the tunnel iface. Some mlx5
        # silicon revisions (notably the variant on hp1/hp3) mis-
        # compute TCP/UDP checksums when the kernel asks the NIC to
        # checksum a packet that's IPIP-encapsulated by the tunnel
        # driver — TCP SYN traverses but with a bad inner checksum
        # so the receiver silently drops it. iperf3 times out with
        # "Connection timed out" while ICMP-in-IPIP traverses fine
        # (kernel computes ICMP checksum in software). The CPU cost
        # of software-computing TCP/UDP checksums on the tunnel
        # iface is negligible vs the flow_dissector cost we're
        # actually measuring. Other mlx5 variants (hp2/hp5) don't
        # need this but the change is harmless there.
        SSH root@"$L"  "ethtool -K $TUN_NAME tx off 2>/dev/null || true"

        SSH root@"$L2" "ip link add $TUN_NAME type ipip \
                          remote $GEN_UNDERLAY_V4 local $DUT_UNDERLAY_V4 dev $DUT_DEV"
        SSH root@"$L2" "ip addr add $DUT_V4/$PREFIX dev $TUN_NAME"
        SSH root@"$L2" "ip link set $TUN_NAME up"
        SSH root@"$L2" "ethtool -K $TUN_NAME tx off 2>/dev/null || true"

        sleep 1

        if ! SSH root@"$L" "ping -c3 -W2 -I $TUN_NAME $DUT_V4" >/dev/null 2>&1; then
          log "ping $L -> $L2 over $TUN_NAME failed; cleaning up"
          cleanup_partial
          exit 1
        fi
        trap - ERR

        emit_env L_SCENARIO_DEV  "$TUN_NAME"
        emit_env L_SCENARIO_V4   "$GEN_V4"
        emit_env L_SCENARIO_MAC  "$(read_mac "$L"  "$GEN_DEV")"
        emit_env L2_SCENARIO_DEV "$TUN_NAME"
        emit_env L2_SCENARIO_V4  "$DUT_V4"
        emit_env L2_SCENARIO_MAC "$(read_mac "$L2" "$DUT_DEV")"
        log "ipip $TUN_NAME up: $L($GEN_V4) <-> $L2($DUT_V4) over underlay $GEN_UNDERLAY_V4<->$DUT_UNDERLAY_V4"
        ;;

      down)
        SSH root@"$L"  "ip link del $TUN_NAME 2>/dev/null || true" || true
        SSH root@"$L2" "ip link del $TUN_NAME 2>/dev/null || true" || true
        close_ipip_fw "$L"
        close_ipip_fw "$L2"
        log "ipip $TUN_NAME down"
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
        log "ipip $TUN_NAME verify: OK"
        ;;
    esac
  '';
}
