# nix/scenarios/netconf-mpls.nix
#
# Stands up a single-label MPLS scenario for exercising series3-
# flowdis-fastpath v4-namespace/0002. Each host loads the mpls_router
# module, enables mpls.conf.<iface>.input=1, assigns its underlay /29,
# and installs an MPLS encap route to push a 1-label label towards the
# peer. The "data plane" is the underlay iface with the new MPLS LSE
# stack stamped on outgoing IP packets; the orchestrator's iperf3 still
# uses the underlay IPs as endpoints, but the wire bytes are MPLS-
# encapped.
#
# Test infrastructure caveat: this scenario requires the kernel to
# have CONFIG_MPLS_ROUTING=y or =m. NixOS-default kernels have =m;
# we modprobe mpls_router and load af_mpls. If the host lacks both,
# `up` fails and the orchestrator skips this scenario for that pair.
#
# Usage:
#   OP=up   L=l L2=l2 GEN_DEV=enp35s0f0np0 DUT_DEV=enp35s0f0np0 \
#     GEN_UNDERLAY_V4=10.10.4.2 DUT_UNDERLAY_V4=10.10.4.5 \
#     nix run .#netconf-mpls
#
# Tunables (env, defaults shown):
#   MPLS_LABEL_GEN_TO_DUT=100        label gen pushes towards DUT
#   MPLS_LABEL_DUT_TO_GEN=200        label DUT pushes towards gen
#   GEN_UNDERLAY_V4 / DUT_UNDERLAY_V4 mandatory
#   GEN_V4_LOOP=10.10.43.2/32        gen-side loopback (decap target)
#   DUT_V4_LOOP=10.10.43.5/32        DUT-side loopback (decap target)

{ pkgs }:

let
  libSh = builtins.readFile ./lib.sh;
in
pkgs.writeShellApplication {
  name = "netconf-mpls";

  runtimeInputs = with pkgs; [
    openssh
    coreutils
    iproute2
    kmod
  ];

  text = ''
    set -u

    ${libSh}

    require_op
    require_env L L2 GEN_DEV DUT_DEV GEN_UNDERLAY_V4 DUT_UNDERLAY_V4

    MPLS_LABEL_GEN_TO_DUT=''${MPLS_LABEL_GEN_TO_DUT:-100}
    MPLS_LABEL_DUT_TO_GEN=''${MPLS_LABEL_DUT_TO_GEN:-200}
    GEN_V4_LOOP=''${GEN_V4_LOOP:-10.10.43.2}
    DUT_V4_LOOP=''${DUT_V4_LOOP:-10.10.43.5}
    LOOP_PREFIX=''${LOOP_PREFIX:-32}

    setup_host_mpls() {
      local host="$1" iface="$2" loop="$3" peer_loop="$4" \
            in_label="$5" out_label="$6" peer_underlay="$7"

      # Load module + enable per-iface MPLS input. Tolerate
      # "already loaded".
      SSH root@"$host" "
        modprobe mpls_router || true
        modprobe mpls_iptunnel || true
        sysctl -w net.mpls.platform_labels=1048576 >/dev/null 2>&1 || true
        sysctl -w net.mpls.conf.$iface.input=1 >/dev/null 2>&1 || true
        sysctl -w net.mpls.conf.lo.input=1 >/dev/null 2>&1 || true
      "

      # Loopback /32 as the decap target so iperf3 has a stable
      # endpoint on each side, independent of the underlay link.
      SSH root@"$host" "ip addr add $loop/$LOOP_PREFIX dev lo 2>/dev/null || true"

      # Decap rule: incoming packets with $in_label pop the label
      # and route to the local loopback.
      SSH root@"$host" "ip -f mpls route del $in_label 2>/dev/null || true"
      SSH root@"$host" "ip -f mpls route add $in_label dev lo"

      # Encap rule: outgoing IP to the peer's loop pushes $out_label
      # and forwards via the underlay iface.
      SSH root@"$host" "ip route del $peer_loop/$LOOP_PREFIX 2>/dev/null || true"
      SSH root@"$host" "ip route add $peer_loop/$LOOP_PREFIX \
                          encap mpls $out_label \
                          via inet $peer_underlay dev $iface"
    }

    teardown_host_mpls() {
      local host="$1" loop="$2" peer_loop="$3" in_label="$4"
      SSH root@"$host" "ip route del $peer_loop/$LOOP_PREFIX 2>/dev/null || true" || true
      SSH root@"$host" "ip -f mpls route del $in_label 2>/dev/null || true" || true
      SSH root@"$host" "ip addr del $loop/$LOOP_PREFIX dev lo 2>/dev/null || true" || true
    }

    case "$OP" in
      up)
        cleanup_partial() {
          teardown_host_mpls "$L"  "$GEN_V4_LOOP" "$DUT_V4_LOOP" "$MPLS_LABEL_DUT_TO_GEN"
          teardown_host_mpls "$L2" "$DUT_V4_LOOP" "$GEN_V4_LOOP" "$MPLS_LABEL_GEN_TO_DUT"
        }
        trap cleanup_partial ERR

        # Gen side: gen pushes LABEL_GEN_TO_DUT outward, decap on
        # LABEL_DUT_TO_GEN inbound.
        setup_host_mpls "$L"  "$GEN_DEV" "$GEN_V4_LOOP" "$DUT_V4_LOOP" \
                        "$MPLS_LABEL_DUT_TO_GEN" "$MPLS_LABEL_GEN_TO_DUT" \
                        "$DUT_UNDERLAY_V4"
        # DUT side: mirror.
        setup_host_mpls "$L2" "$DUT_DEV" "$DUT_V4_LOOP" "$GEN_V4_LOOP" \
                        "$MPLS_LABEL_GEN_TO_DUT" "$MPLS_LABEL_DUT_TO_GEN" \
                        "$GEN_UNDERLAY_V4"

        sleep 1

        if ! SSH root@"$L" "ping -c3 -W2 -I $GEN_V4_LOOP $DUT_V4_LOOP" >/dev/null 2>&1; then
          log "ping $L($GEN_V4_LOOP) -> $L2($DUT_V4_LOOP) over MPLS failed; cleaning up"
          cleanup_partial
          exit 1
        fi
        trap - ERR

        # Use the loopback /32s as the "scenario interface" addrs;
        # iperf3 binds to those, packets traverse MPLS-encapped over
        # the underlay iface (which is where the flow_dissector
        # decapsulating on RX will see the MPLS labels).
        emit_env L_SCENARIO_DEV  "lo"
        emit_env L_SCENARIO_V4   "$GEN_V4_LOOP"
        emit_env L2_SCENARIO_DEV "lo"
        emit_env L2_SCENARIO_V4  "$DUT_V4_LOOP"
        log "mpls labels=$MPLS_LABEL_GEN_TO_DUT/$MPLS_LABEL_DUT_TO_GEN up: $L($GEN_V4_LOOP) <-> $L2($DUT_V4_LOOP)"
        ;;

      down)
        teardown_host_mpls "$L"  "$GEN_V4_LOOP" "$DUT_V4_LOOP" "$MPLS_LABEL_DUT_TO_GEN"
        teardown_host_mpls "$L2" "$DUT_V4_LOOP" "$GEN_V4_LOOP" "$MPLS_LABEL_GEN_TO_DUT"
        log "mpls labels=$MPLS_LABEL_GEN_TO_DUT/$MPLS_LABEL_DUT_TO_GEN down"
        ;;

      verify)
        for h in "$L" "$L2"; do
          SSH root@"$h" "ip -f mpls route show" 2>&1 | grep -qE "($MPLS_LABEL_GEN_TO_DUT|$MPLS_LABEL_DUT_TO_GEN)" || {
            log "verify: $h lacks expected MPLS routes"; exit 1;
          }
        done
        SSH root@"$L" "ping -c3 -W2 -I $GEN_V4_LOOP $DUT_V4_LOOP" >/dev/null 2>&1 || {
          log "verify: MPLS-encapped ping $L -> $L2 failed"; exit 1;
        }
        log "mpls verify: OK"
        ;;
    esac
  '';
}
