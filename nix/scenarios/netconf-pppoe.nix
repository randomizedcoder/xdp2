# nix/scenarios/netconf-pppoe.nix
#
# Stands up a PPPoE session between a host pair for exercising a
# future PPPoE fast-path candidate (not in extensions-draft today —
# noted in kernel-patches/series3-flowdis-fastpath/docs/packet-flow-context.md
# section 10).
#
# Topology:
#   DUT runs `pppoe-server` as access concentrator on the bare iface.
#   GEN runs `pppd` with rp-pppoe.so plugin against the same iface.
#   A point-to-point ppp0 forms on each end with pppd-negotiated /32s.
#
# Prerequisites on both hosts (assumed installed via NixOS module):
#   - ppp        (provides pppd)
#   - rp-pppoe   (provides pppoe-server and the rp-pppoe.so pppd plugin)
#   - Kernel CONFIG_PPPOE=y/m, CONFIG_PPP_ASYNC, CONFIG_PPP_DEFLATE
#
# The first-cut implementation here uses /tmp/-staged ephemeral
# config files (PAP secrets, server options). All under /tmp/, never
# touches /etc/.
#
# Usage:
#   OP=up   L=l L2=l2 GEN_DEV=enp35s0f0np0 DUT_DEV=enp35s0f0np0 \
#     nix run .#netconf-pppoe
#
# Tunables (env, defaults shown):
#   PPP_USER=xdp2testuser
#   PPP_PASS=xdp2testpass
#   PPP_AC_NAME=xdp2-ac           PPPoE Access Concentrator name
#   PPP_SERVER_LOCAL_V4=10.10.42.1
#   PPP_SERVER_REMOTE_V4=10.10.42.2

{ pkgs }:

let
  libSh = builtins.readFile ./lib.sh;
in
pkgs.writeShellApplication {
  name = "netconf-pppoe";

  runtimeInputs = with pkgs; [
    openssh
    coreutils
  ];

  text = ''
    set -u

    ${libSh}

    require_op
    require_env L L2 GEN_DEV DUT_DEV

    PPP_USER=''${PPP_USER:-xdp2testuser}
    PPP_PASS=''${PPP_PASS:-xdp2testpass}
    PPP_AC_NAME=''${PPP_AC_NAME:-xdp2-ac}
    PPP_SERVER_LOCAL_V4=''${PPP_SERVER_LOCAL_V4:-10.10.42.1}
    PPP_SERVER_REMOTE_V4=''${PPP_SERVER_REMOTE_V4:-10.10.42.2}

    SECRETS_PATH=/tmp/netconf-pppoe-secrets
    SERVER_OPTIONS=/tmp/netconf-pppoe-server-options
    CLIENT_OPTIONS=/tmp/netconf-pppoe-client-options
    SERVER_PIDFILE=/tmp/netconf-pppoe-server.pid
    CLIENT_PIDFILE=/tmp/netconf-pppoe-client.pid

    do_down_remote() {
      local host="$1"
      # Kill server + client + remove staged files. Tolerate missing.
      # Restore the pre-scenario /etc/ppp/pap-secrets if we backed
      # one up; otherwise remove the one we wrote so we don't leave
      # PAP creds lying around.
      SSH root@"$host" "
        if [ -r $SERVER_PIDFILE ]; then kill \$(cat $SERVER_PIDFILE) 2>/dev/null; rm -f $SERVER_PIDFILE; fi
        if [ -r $CLIENT_PIDFILE ]; then kill \$(cat $CLIENT_PIDFILE) 2>/dev/null; rm -f $CLIENT_PIDFILE; fi
        pkill -f pppoe-server 2>/dev/null; pkill -f 'pppd .*rp-pppoe' 2>/dev/null
        if [ -f ''${SECRETS_PATH}.backup ]; then
          mv ''${SECRETS_PATH}.backup /etc/ppp/pap-secrets
        else
          rm -f /etc/ppp/pap-secrets
        fi
        rm -f $SECRETS_PATH $SERVER_OPTIONS $CLIENT_OPTIONS
        true
      " || true
    }

    case "$OP" in
      up)
        do_down_remote "$L"
        do_down_remote "$L2"

        cleanup_partial() {
          do_down_remote "$L"
          do_down_remote "$L2"
        }
        trap cleanup_partial ERR

        # --- DUT side (pppoe-server access concentrator) ---
        # Stage a minimal PAP secrets file. pppd has its PAP secrets
        # path baked in at compile time (/etc/ppp/pap-secrets); there
        # is no CLI override, so we install the credentials there
        # directly. The /etc/ppp dir on NixOS is created on-demand
        # the first time pppd runs; ensure it exists with mkdir -p.
        # We back up any prior content and restore on teardown to be
        # nice to a host that legitimately uses pppd outside our
        # scenario (rare but cheap).
        SSH root@"$L2" "
          mkdir -p /etc/ppp
          [ -f /etc/ppp/pap-secrets ] && cp /etc/ppp/pap-secrets ''${SECRETS_PATH}.backup 2>/dev/null || true
          echo '$PPP_USER * $PPP_PASS *' > /etc/ppp/pap-secrets
          chmod 600 /etc/ppp/pap-secrets
        "

        SSH root@"$L2" "cat > $SERVER_OPTIONS <<EOF
require-pap
login
auth
lcp-echo-interval 30
lcp-echo-failure 4
ms-dns 1.1.1.1
noipdefault
nodefaultroute
nobsdcomp
nodeflate
pap-restart 2
maxfail 0
mtu 1492
mru 1492
EOF
chmod 600 $SERVER_OPTIONS"

        SSH root@"$L2" "
          pppoe-server -I $DUT_DEV -L $PPP_SERVER_LOCAL_V4 -R $PPP_SERVER_REMOTE_V4 \
            -N 1 -C $PPP_AC_NAME -S 'xdp2-svc' \
            -O $SERVER_OPTIONS -k > /tmp/netconf-pppoe-server.log 2>&1 &
          echo \$! > $SERVER_PIDFILE
        "

        # --- GEN side (pppd client) ---
        SSH root@"$L" "
          mkdir -p /etc/ppp
          [ -f /etc/ppp/pap-secrets ] && cp /etc/ppp/pap-secrets ''${SECRETS_PATH}.backup 2>/dev/null || true
          echo '$PPP_USER * $PPP_PASS *' > /etc/ppp/pap-secrets
          chmod 600 /etc/ppp/pap-secrets
        "

        # pppd looks for plugins in its compiled-in path (inside the
        # ppp nix-store derivation's lib/pppd/<ver>/), where rp-pppoe
        # isn't because it's packaged separately. Pass the absolute
        # path through /run/current-system/sw/lib/ — that's a
        # systemPackages symlink farm that includes rp-pppoe.so once
        # rp-pppoe is in environment.systemPackages on the host.
        SSH root@"$L" "cat > $CLIENT_OPTIONS <<EOF
plugin /run/current-system/sw/lib/rp-pppoe.so
nic-$GEN_DEV
user $PPP_USER
hide-password
noauth
persist
maxfail 0
defaultroute-metric 1024
mtu 1492
mru 1492
lcp-echo-interval 30
lcp-echo-failure 4
nobsdcomp
nodeflate
EOF
chmod 600 $CLIENT_OPTIONS"

        SSH root@"$L" "
          pppd file $CLIENT_OPTIONS > /tmp/netconf-pppoe-client.log 2>&1 &
          echo \$! > $CLIENT_PIDFILE
        "

        # Wait up to 30s for ppp0 to appear on the GEN side with the
        # expected peer IP.
        log "waiting for ppp0 to come up on $L (up to 30s)"
        local_iface=""
        for _ in $(seq 1 30); do
          if SSH root@"$L" "ip -br link show ppp0" >/dev/null 2>&1; then
            local_iface=ppp0
            break
          fi
          sleep 1
        done
        if [ -z "$local_iface" ]; then
          log "ppp0 did not appear on $L within 30s; tearing down. Server log:"
          SSH root@"$L2" "tail -40 /tmp/netconf-pppoe-server.log 2>/dev/null" >&2 || true
          log "Client log:"
          SSH root@"$L" "tail -40 /tmp/netconf-pppoe-client.log 2>/dev/null" >&2 || true
          cleanup_partial
          exit 1
        fi

        # Read the negotiated local IP for the env emit. PPP link
        # appears as soon as LCP is up; IPCP negotiation (which
        # assigns the IP) takes another 0.5-2s. Retry briefly so we
        # don't lose this race when the link is healthy.
        gen_v4=""
        for _ in $(seq 1 10); do
          gen_v4=$(SSH root@"$L" "ip -4 -br addr show ppp0 | awk '{print \$3}' | cut -d/ -f1")
          [ -n "$gen_v4" ] && break
          sleep 1
        done
        if [ -z "$gen_v4" ]; then
          log "ppp0 has no IPv4 address after 10s of IPCP wait; tearing down"
          SSH root@"$L" "tail -40 /tmp/netconf-pppoe-client.log 2>/dev/null" >&2 || true
          cleanup_partial
          exit 1
        fi

        if ! SSH root@"$L" "ping -c3 -W2 -I ppp0 $PPP_SERVER_LOCAL_V4" >/dev/null 2>&1; then
          log "ping $L -> $L2 over ppp0 failed"
          cleanup_partial
          exit 1
        fi
        trap - ERR

        emit_env L_SCENARIO_DEV  "ppp0"
        emit_env L_SCENARIO_V4   "$gen_v4"
        emit_env L2_SCENARIO_DEV "ppp0"
        emit_env L2_SCENARIO_V4  "$PPP_SERVER_LOCAL_V4"
        log "pppoe up: $L($gen_v4) <-> $L2($PPP_SERVER_LOCAL_V4) on ppp0"
        log "NOTE: PPPoE userspace pppd caps wire rate well below NIC line rate"
        ;;

      down)
        do_down_remote "$L"
        do_down_remote "$L2"
        log "pppoe down"
        ;;

      verify)
        SSH root@"$L"  "ip -br link show ppp0" >/dev/null 2>&1 || {
          log "verify: $L lacks ppp0"; exit 1;
        }
        SSH root@"$L" "ping -c3 -W2 -I ppp0 $PPP_SERVER_LOCAL_V4" >/dev/null 2>&1 || {
          log "verify: ping $L -> $L2 over ppp0 failed"; exit 1;
        }
        log "pppoe verify: OK"
        ;;
    esac
  '';
}
