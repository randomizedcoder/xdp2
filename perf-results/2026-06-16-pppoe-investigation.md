# PPPoE testbed investigation (2026-06-16)

Investigation into why the netconf-pppoe.nix scenario fails on the NixOS-flavoured hp testbeds, surfaced during the v4 Phase D full matrix run.

## What we fixed

Three real bugs in the scenario script and supporting plumbing:

1. **`plugin rp-pppoe.so`** (relative) couldn't be loaded by NixOS-packaged pppd. The pppd binary's compiled-in plugin search path is `/nix/store/<hash>-ppp-2.5.2/lib/pppd/2.5.2/`, which contains only plugins built into the ppp derivation itself. rp-pppoe is a separate nixpkgs derivation; its `rp-pppoe.so` lives at `/nix/store/<hash>-rp-pppoe-4.0/lib/rp-pppoe.so` and is symlinked into `/run/current-system/sw/lib/rp-pppoe.so` via systemPackages. Fix: pass the absolute path through the system-path symlink. Committed in xdp2 `2dc0a82`.

2. **`file $SECRETS_PATH`** in the pppd options file was making pppd parse the PAP secrets as if they were more options. The secrets file content `"xdp2testuser * xdp2testpass *"` got tokenized; first token `xdp2testuser` doesn't match any pppd option → error "unrecognized option 'xdp2testuser'". pppd has its PAP secrets path baked in at compile time as `/etc/ppp/pap-secrets` with no CLI override. Fix: write secrets there directly; remove the `file` line. Backup + restore any pre-existing file on teardown. Committed in `2dc0a82`.

3. **IPCP race**: the script's wait loop checks once for an IPv4 address after the link appears, but PPP IPCP negotiation takes another 0.5–2s. Single check raced and lost. Fix: 10-iteration retry loop. Committed in `2dc0a82`.

## What still doesn't work — root cause TBD

Even with all three fixes, `pppoe-server` on the DUT side accepts the PADI but never sends PADO. We confirmed this via tcpdump on the receiver side:

```
22:10:26.281559 f8:f2:1e:38:c3:50 > ff:ff:ff:ff:ff:ff, ethertype PPPoE D (0x8863),
                length 60: PPPoE PADI [Service-Name] [Host-Uniq "5844"]
22:10:31.286530 f8:f2:1e:38:c3:50 > ff:ff:ff:ff:ff:ff, ethertype PPPoE D (0x8863), ...
22:10:41.291501 ... PADI [Host-Uniq "5844"]
22:11:01.311308 f8:f2:1e:38:c3:50 > 00:00:00:00:00:00, ethertype PPPoE D (0x8863),
                length 60: PPPoE PADR [Service-Name] [Host-Uniq "5844"]
```

Note the **PADR destination MAC is `00:00:00:00:00:00`** — uninitialised. That's pppd's "I never received a PADO so I don't have a peer MAC, retrying PADR anyway with whatever I have in the buffer" behaviour. Smoking gun: PADO never arrives.

Meanwhile on the server side, `pppoe-server -d` only logs:

```
Session 1 local 10.99.43.1 remote 10.99.43.2
```

— which is the per-session capacity print at startup, not a per-PADI receipt log. So we can't tell from the debug output whether the server is even SEEING the PADI frames.

## Confirmed not the cause

- **L2 path**: hp2↔hp5 are back-to-back DAC-connected; no intermediate switch could filter. tcpdump on the receiver confirms PADI traverses with the expected source/dest MAC.
- **Userspace firewall**: NixOS firewall is inactive on hp* (we confirmed earlier in the v3 deploy); INPUT chain is empty / default ACCEPT. Plus PPPoE is L2 ethertype 0x8863; iptables doesn't see it. nft ruleset is also empty.
- **Kernel-mode flag**: tried both `pppoe-server -k` (kernel-mode) and without — same failure mode. So not the kernel pppoe module's RX path.
- **Service-name mismatch**: server runs without `-S` (any service-name accepted); client PADI has empty service-name field. Should match.
- **Plugin loading**: client side loads rp-pppoe.so cleanly per its own log.
- **NixOS pap-secrets file path**: client-side pppd reaches PAP negotiation only AFTER discovery, so this isn't the discovery-failure cause (though we did need to fix it for the negotiation to succeed once Discovery is fixed).

## Candidate hypotheses

1. **mlx5 ethertype RX filter**: the hp* fleet has mlx5 NICs with flow-steering rules that may default-route only IP/IPv6/ARP/STP ethertypes to the host kernel, dropping unknown ones. We saw earlier (during the qinq investigation) that this silicon revision has `rx-vlan-stag-filter: on [fixed]` — there may be a parallel `rx-ethertype-filter` that drops PPPoE frames before they reach the host stack. tcpdump runs after the kernel netdev RX hook though, and we see PADI arriving in tcpdump — so the inbound path works. But pppoe-server's *outbound* PADO might be dropped by an equivalent TX filter.
2. **pppoe-server's AF_PACKET socket binding**: pppoe-server uses `AF_PACKET` raw sockets to send/recv Ethernet frames directly. If it bound to the wrong iface OR the bind silently failed, the server could be alive but invisible to the wire. Need to strace pppoe-server during PADI to verify.
3. **NixOS pppoe-server packaging quirk**: rp-pppoe is a relatively old package; the NixOS build may have skipped some build-time option that the server needs. Compare nixpkgs/pkgs/os-specific/linux/rp-pppoe/default.nix vs a working distro's build.
4. **MTU / packet padding**: PADI frames are tiny (32 bytes ethernet payload before pppoe-server pads to 60 = minimum frame). pppoe-server may be rejecting frames where the AC's expected padding is wrong.

## Next steps when picking this back up

1. `strace -e trace=network -p $(pgrep pppoe-server)` while PADI arrives — does the server see the bytes?
2. `tcpdump -ne -i enp1s0f0np0 -A ether proto 0x8863` and compare full byte-level content vs a known-working PPPoE exchange (e.g. from a working ISP capture).
3. Try a different PPPoE client implementation: `pppoe -I enp1s0f0np0` (the discover-only tool in rp-pppoe) to isolate whether it's pppd-plugin specific or pppoe-server specific.
4. Try the same scenario on a non-NixOS host with the same nixpkgs rp-pppoe version to rule out a kernel/NIC issue.
5. Check if there's a more modern PPPoE server (`accel-ppp`) that works on NixOS.

## Status

PPPoE Discovery is **deferred as a testbed-infrastructure issue**, separate from the v4 kernel patch series. The kernel-side PPPoE fast-path patch (v4 patch 5) is byte-identical to the slow path's `ETH_P_PPP_SES` case — both fail equally when no PPPoE session exists. Once Discovery works, the fast-path's measurable saving will surface in the receiver softirq column the same way MPLS / VLAN / QinQ did in the v4 matrix.

The three scenario-script fixes committed in `2dc0a82` remain useful even with this issue outstanding — they remove three layers of *separate* failure modes that would have masked the underlying Discovery problem if we'd encountered them piecemeal.
