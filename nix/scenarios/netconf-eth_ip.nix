# nix/scenarios/netconf-eth_ip.nix
#
# Bare ETH+IPv4 "scenario" — the original v3 fast-path itself, with
# no overlay, no encap, no VLAN tag. Stands up nothing; just emits
# the underlay device + IP + MAC as the scenario vars so the existing
# orchestrators can drive iperf3 / pktgen directly between the two
# underlay endpoints.
#
# Why this exists: the orchestrators' scenario_sysctl() switch already
# maps an unknown scenario name to net.flow_dissector.eth_ip as a
# fallback, but every prior matrix run set SCENARIOS to a list of
# encap shapes (vlan, qinq, vxlan, ...) — the bare ETH+IP fast-path
# (the foundation every other shape descends from) was never measured
# stand-alone. Adding this thin scenario closes that gap.
#
# `up` runs a ping over the underlay so the orchestrator's
# scenario.env probe succeeds; `down` and `verify` are no-ops.
#
# Usage:
#   OP=up   L=hp1 L2=hp3 GEN_DEV=enp1s0f0np0 DUT_DEV=enp1s0f0np0 \
#     GEN_UNDERLAY_V4=10.10.2.1 DUT_UNDERLAY_V4=10.10.2.3 \
#     nix run .#netconf-eth_ip
#   OP=down ... nix run .#netconf-eth_ip
#
# Required env: L L2 GEN_DEV DUT_DEV GEN_UNDERLAY_V4 DUT_UNDERLAY_V4

{ pkgs }:

let
  libSh = builtins.readFile ./lib.sh;
in
pkgs.writeShellApplication {
  name = "netconf-eth_ip";

  runtimeInputs = with pkgs; [ openssh coreutils iproute2 ];

  text = ''
    set -u

    ${libSh}

    require_op
    require_env L L2 GEN_DEV DUT_DEV GEN_UNDERLAY_V4 DUT_UNDERLAY_V4

    case "$OP" in
      up)
        if ! SSH root@"$L" "ping -c3 -W2 -I $GEN_DEV $DUT_UNDERLAY_V4" >/dev/null 2>&1; then
          log "ping $L -> $L2 over underlay $GEN_DEV failed"
          exit 1
        fi

        emit_env L_SCENARIO_DEV  "$GEN_DEV"
        emit_env L_SCENARIO_V4   "$GEN_UNDERLAY_V4"
        emit_env L_SCENARIO_MAC  "$(read_mac "$L"  "$GEN_DEV")"
        emit_env L2_SCENARIO_DEV "$DUT_DEV"
        emit_env L2_SCENARIO_V4  "$DUT_UNDERLAY_V4"
        emit_env L2_SCENARIO_MAC "$(read_mac "$L2" "$DUT_DEV")"
        log "eth_ip up: $L($GEN_UNDERLAY_V4) <-> $L2($DUT_UNDERLAY_V4) on underlay $GEN_DEV/$DUT_DEV (no encap)"
        ;;
      down)
        log "eth_ip down: no-op (nothing was set up)"
        ;;
      verify)
        for h in "$L" "$L2"; do
          SSH root@"$h" "ip -br link show $GEN_DEV" >/dev/null 2>&1 || {
            log "verify: $h underlay $GEN_DEV not present"; exit 1;
          }
        done
        log "eth_ip verify: OK (underlay healthy on both ends)"
        ;;
    esac
  '';
}
