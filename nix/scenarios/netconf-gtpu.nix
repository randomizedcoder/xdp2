# nix/scenarios/netconf-gtpu.nix
#
# Stands up a GTP-U tunnel for exercising the GTP-U inner descent
# RFC EXPERIMENT (xdp2 v4-namespace patch 6, kernel commit
# 32607b7ae687). Unlike VXLAN / Geneve which have native `ip link
# add type X` working with no userspace, GTP-U needs the `gtp-tunnel`
# tool from libgtpnl to install the per-TEID forwarding entries
# after `ip link add type gtp` creates the device.
#
# If libgtpnl isn't present on the testbed, this scenario logs a
# clear "REQUIRES libgtpnl" message and exits 1; the orchestrator's
# scenario-up failure path skips the scenario for that pair, so the
# rest of the matrix still runs.
#
# Reference for the setup pattern:
#   tools/testing/selftests/net/gtp.sh in net-next.
#
# Usage:
#   OP=up   L=l L2=l2 GEN_DEV=enp35s0f0np0 DUT_DEV=enp35s0f0np0 \
#     GEN_UNDERLAY_V4=10.10.4.2 DUT_UNDERLAY_V4=10.10.4.5 \
#     nix run .#netconf-gtpu
#
# Tunables (env):
#   TEID=0x12345678                  Tunnel Endpoint Identifier
#   DST_PORT=2152                    UDP dst port (IANA GTP1U_PORT)
#   GEN_V4=192.168.102.1             gen IP inside the overlay
#   DUT_V4=192.168.102.2             DUT IP inside the overlay
#   PREFIX=24

{ pkgs }:

let
  libSh = builtins.readFile ./lib.sh;
in
pkgs.writeShellApplication {
  name = "netconf-gtpu";

  runtimeInputs = with pkgs; [ openssh coreutils iproute2 ];

  text = ''
    set -u
    ${libSh}
    require_op
    require_env L L2 GEN_DEV DUT_DEV GEN_UNDERLAY_V4 DUT_UNDERLAY_V4

    TEID=''${TEID:-0x12345678}
    DST_PORT=''${DST_PORT:-2152}
    TUN_NAME=''${TUN_NAME:-gtputest}
    GEN_V4=''${GEN_V4:-192.168.102.1}
    DUT_V4=''${DUT_V4:-192.168.102.2}
    PREFIX=''${PREFIX:-24}

    require_gtp_tunnel() {
      local host="$1"
      SSH root@"$host" "command -v gtp-tunnel >/dev/null 2>&1 \
        || command -v gtp-tunnel >/dev/null 2>&1 || \
        echo MISSING" 2>&1 | grep -q MISSING && return 1
      return 0
    }

    case "$OP" in
      up)
        for h in "$L" "$L2"; do
          if ! SSH root@"$h" "command -v gtp-tunnel >/dev/null 2>&1"; then
            log "REQUIRES gtp-tunnel (from libgtpnl) on $h. Skipping."
            log "libgtpnl isn't packaged in nixpkgs by that name as"
            log "of 2026-06. Options to get gtp-tunnel installed:"
            log "  (1) build libgtpnl manually from"
            log "      https://git.osmocom.org/libgtpnl/ on the host"
            log "      and copy gtp-tunnel into /usr/local/bin"
            log "  (2) author a nixos derivation for libgtpnl and add"
            log "      it to environment.systemPackages on the testbed"
            log "  (3) use the Osmocom osmo-ggsn package (which depends"
            log "      on libgtpnl) but that's a much heavier setup"
            log "Without gtp-tunnel, the kernel side (the patch + the"
            log "gtpu_inner sysctl) is functional but we have no way"
            log "to drive traffic through a GTP-U session for the"
            log "matrix orchestrator. Phase E GTP-U fast-path is still"
            log "deployed on the testbed; matrix data requires (1) or (2)."
            exit 1
          fi
        done

        SSH root@"$L"  "ip link del $TUN_NAME 2>/dev/null || true"
        SSH root@"$L2" "ip link del $TUN_NAME 2>/dev/null || true"

        cleanup_partial() {
          SSH root@"$L"  "ip link del $TUN_NAME 2>/dev/null || true" || true
          SSH root@"$L2" "ip link del $TUN_NAME 2>/dev/null || true" || true
        }
        trap cleanup_partial ERR

        # Open a UDP socket for the gtp device, then create the device
        # bound to that socket. role=sgsn lets us tunnel from this host;
        # the matched-TEID inner-IP destination must be reachable.
        SSH root@"$L"  "modprobe gtp; \
          ip link add $TUN_NAME type gtp role sgsn hashsize 1024 2>&1 || true; \
          ip addr add $GEN_V4/$PREFIX dev $TUN_NAME; \
          ip link set $TUN_NAME up; \
          gtp-tunnel add $TUN_NAME v1 $TEID $TEID $GEN_V4 $DUT_UNDERLAY_V4"
        SSH root@"$L2" "modprobe gtp; \
          ip link add $TUN_NAME type gtp role sgsn hashsize 1024 2>&1 || true; \
          ip addr add $DUT_V4/$PREFIX dev $TUN_NAME; \
          ip link set $TUN_NAME up; \
          gtp-tunnel add $TUN_NAME v1 $TEID $TEID $DUT_V4 $GEN_UNDERLAY_V4"

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
        log "gtpu $TUN_NAME (TEID=$TEID port=$DST_PORT) up: $L($GEN_V4) <-> $L2($DUT_V4)"
        ;;
      down)
        SSH root@"$L"  "ip link del $TUN_NAME 2>/dev/null || true" || true
        SSH root@"$L2" "ip link del $TUN_NAME 2>/dev/null || true" || true
        log "gtpu $TUN_NAME down"
        ;;
      verify)
        for h in "$L" "$L2"; do
          SSH root@"$h" "ip -br link show $TUN_NAME" >/dev/null 2>&1 || {
            log "verify: $h lacks $TUN_NAME"; exit 1;
          }
        done
        log "gtpu $TUN_NAME verify: OK"
        ;;
    esac
  '';
}
