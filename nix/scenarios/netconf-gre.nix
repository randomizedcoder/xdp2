# nix/scenarios/netconf-gre.nix
#
# Stands up a plain-GRE (v0, no flags) inner-IPv4 tunnel scenario for
# exercising the GRE byte-identical fast-path (v4-namespace patch 4 /
# kernel commit a7efd58a733d). Each end creates a `gre0` tunnel via
# `ip link add type gre` over the underlay physical iface, assigns a
# /29 inside, validates with ping. `down` removes only what `up`
# created.
#
# Mirror of netconf-ipip.nix in shape. Same NixOS-firewall workaround
# (open proto 47 on both ends) is required — the default nixos-fw
# chain refuses non-listed protocols.
#
# Same mlx5 TX-checksum workaround as netconf-ipip.nix: the hp1/hp3
# silicon revision mis-computes TCP/UDP checksums for GRE-encapped
# packets the same way it does for IPIP. Disable tx-checksum on the
# tunnel iface; harmless on hosts that don't need it.
#
# Usage:
#   OP=up   L=l L2=l2 GEN_DEV=enp35s0f0np0 DUT_DEV=enp35s0f0np0 \
#     GEN_UNDERLAY_V4=10.10.4.2 DUT_UNDERLAY_V4=10.10.4.5 \
#     nix run .#netconf-gre
#
# Tunables (env, defaults shown):
#   TUN_NAME=gre0                    tunnel iface name
#   GEN_UNDERLAY_V4 / DUT_UNDERLAY_V4 mandatory; remote/local
#   GEN_V4=10.10.44.2                gen IP inside the tunnel
#   DUT_V4=10.10.44.5                DUT IP inside the tunnel
#   PREFIX=29

{ pkgs }:

let
  libSh = builtins.readFile ./lib.sh;
in
pkgs.writeShellApplication {
  name = "netconf-gre";

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

    # gre0 is auto-created by the `gre` kernel module as a fallback
    # device on module-load; clashes with `ip link add gre0 type gre`
    # ("RTNETLINK answers: File exists"). Use a unique name.
    TUN_NAME=''${TUN_NAME:-gretest0}
    GEN_V4=''${GEN_V4:-10.10.44.2}
    DUT_V4=''${DUT_V4:-10.10.44.5}
    PREFIX=''${PREFIX:-29}

    open_gre_fw() {
      # NixOS firewall refuses non-listed IP protocols. Open proto 47
      # (IPPROTO_GRE) on both ends bracketing the scenario. Symmetric
      # with open_ipip_fw in netconf-ipip.nix.
      local host="$1"
      SSH root@"$host" "
        iptables -C nixos-fw -p 47 -j ACCEPT 2>/dev/null \
          || iptables -I nixos-fw 1 -p 47 -j ACCEPT
      " >/dev/null 2>&1 || true
    }
    close_gre_fw() {
      local host="$1"
      SSH root@"$host" "iptables -D nixos-fw -p 47 -j ACCEPT 2>/dev/null" >/dev/null 2>&1 || true
    }

    case "$OP" in
      up)
        SSH root@"$L"  "ip link del $TUN_NAME 2>/dev/null || true"
        SSH root@"$L2" "ip link del $TUN_NAME 2>/dev/null || true"

        cleanup_partial() {
          SSH root@"$L"  "ip link del $TUN_NAME 2>/dev/null || true" || true
          SSH root@"$L2" "ip link del $TUN_NAME 2>/dev/null || true" || true
          close_gre_fw "$L"
          close_gre_fw "$L2"
        }
        trap cleanup_partial ERR

        open_gre_fw "$L"
        open_gre_fw "$L2"

        # `ip link add type gre` creates a plain v0/no-flags GRE tunnel
        # (no `key`/`csum`/`seq` options → maps to our byte-identical
        # fast-path subset).
        SSH root@"$L"  "ip link add $TUN_NAME type gre \
                          remote $DUT_UNDERLAY_V4 local $GEN_UNDERLAY_V4 dev $GEN_DEV"
        SSH root@"$L"  "ip addr add $GEN_V4/$PREFIX dev $TUN_NAME"
        SSH root@"$L"  "ip link set $TUN_NAME up"
        # Disable tx-checksum offload on the tunnel — same mlx5 hp1/hp3
        # silicon issue we hit on netconf-ipip.nix. GRE-encapped TCP/UDP
        # gets bad inner checksum when offloaded; ICMP works either way.
        SSH root@"$L"  "ethtool -K $TUN_NAME tx off 2>/dev/null || true"

        SSH root@"$L2" "ip link add $TUN_NAME type gre \
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
        log "gre $TUN_NAME up: $L($GEN_V4) <-> $L2($DUT_V4) over underlay $GEN_UNDERLAY_V4<->$DUT_UNDERLAY_V4"
        ;;

      down)
        SSH root@"$L"  "ip link del $TUN_NAME 2>/dev/null || true" || true
        SSH root@"$L2" "ip link del $TUN_NAME 2>/dev/null || true" || true
        close_gre_fw "$L"
        close_gre_fw "$L2"
        log "gre $TUN_NAME down"
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
        log "gre $TUN_NAME verify: OK"
        ;;
    esac
  '';
}
