# l ↔ l2 DAC link failure — investigation closed, swap-out planned

## TL;DR

DAC cables arrived for the l/l2 25 GbE pair. They came up cleanly when swapped into hp1↔hp3, so the cables are fine. They will not link on l/l2 because **l/l2 ship with generic-Mellanox OEM firmware on their ConnectX-4 Lx that refuses to read the DAC's I²C EEPROM**, whereas hp1/hp3's HP-OEM firmware skips that check.

Decision: **not chasing the firmware fix.** Two more HP-OEM ConnectX-4 Lx NICs have been ordered to replace l/l2's NICs. Drop-in swap when they arrive resolves this without firmware adventures.

## What we observed (2026-06-15)

Same chip on all four hosts — ConnectX-4 Lx, PCI ID `15b3:1015`, driver `mlx5_core`.

| host | firmware | PSID | link with arrived DAC |
|---|---|---|---|
| hp1 | 14.27.4000 | **HP_**2420110034 | up (25 Gb/s, "Direct Attach Copper") |
| hp3 | 14.27.4000 | **HP_**2420110034 | up (25 Gb/s, "Direct Attach Copper") |
| l2 | 14.32.1908 | **MT_**2470111034 | down, EEPROM read fails |
| l | (n/a — SSH key not enrolled) | n/a | down |

l2 ethtool readout (relevant excerpt):

```
Port: Other
Speed: Unknown!
Auto-negotiation: on
Link detected: no (EEPROM issue)
```

`ethtool -m enp35s0f0np0` on l2:

```
netlink error: mlx5_core: Query module eeprom by page failed,
               read 0 bytes, err -5, status 3
netlink error: Input/output error
```

`err -5` is EIO — the NIC firmware refused or could not complete I²C to the cable. Below link negotiation; the firmware is not even acknowledging there is a working transceiver in the cage. Same cable in hp1/hp3 reads EEPROM and links to 25 Gb/s without issue.

## Why this is firmware, not cable or hardware

- Cable is fine: confirmed working in hp1↔hp3 (same physical pair, same brand as the historical hp1/hp3 DACs).
- Same NIC silicon as hp1/hp3: PCI 15b3:1015, same driver, same `mlx5_core` version.
- The PSID difference (`HP_…` vs `MT_…`) is the OEM personality stamped on the firmware. Generic Mellanox firmware on ConnectX-4 family carries stricter module-verification: it will refuse to power up the I²C bus on transceivers whose vendor/part EEPROM strings are not on the firmware's allowlist. HP-OEM firmware on the same chip skips the verification step.

The fix-in-place options (cross-flash to community `mlnx_ofed` 14.32.2004+ or 14.33.x with relaxed verification, or set `CONNECTOR_DETECT_BYPASS`-class knobs via `mlxconfig`) are real but would have cost the rest of the evening and pulled both NICs out of contention while flashing. With replacements on order, not worth it.

### What we actually tried (so we don't redo it)

- `mstflint -d 23:00.0 q`: PSID `MT_2470111034`, FW `14.32.1908` dated 2025-08-17 — already current as of investigation. No newer 14.32.x released publicly.
- `mstconfig -d 23:00.0 q`: dumped all 179 settings on l2's ConnectX-4 Lx OCP. Categories present: PCIe (lane/speed/ASPM), VFs (SR-IOV/MSI-X), per-port link-keep-alive, DCBX, RoCE/CNP, FlexParser, boot/UEFI/PXE, safe mode, tracer. **Zero settings touching transceiver verification, EEPROM trust, module allowlist, or I²C policy.** This is not a configurable knob on this card variant.
- Card type: `MCX4421A-ACA_Bx` — Mellanox OEM OCP form factor card, distinct silicon SKU from the HP-OEM PCIe `MCX4121A-XCAT` family on hp1/hp3. So cross-flashing the HP firmware binary onto l2 is a non-starter — different physical board, different firmware target.
- The remaining theoretical route (cross-flash to a hypothetical newer non-OEM Mellanox firmware that relaxes verification) carries brick risk and no published evidence it would help. Closed.

### Firmware bump attempt (2026-06-15 evening)

Spotted that Nvidia had released `14.32.1912` (vs. `14.32.1908` on l2). Same-PSID upgrade — no brick risk. Flashed l2's `MT_2470111034` device with `fw-ConnectX4Lx-rel-14_32_1912-MCX4421A-ACA_Bx-UEFI-14.25.17-FlexBoot-3.6.502.bin` via `mstflint`, soft-reset via `mstfwreset -l 3`. Burn + load clean. **Verification behaviour unchanged**: `Port: Other`, `Link detected: no (EEPROM issue)`, same `mlx5_core: Query module eeprom by page failed, err -5, status 3`. Nvidia did not relax module trust in this revision. Confirms firmware-flash path is closed for this card variant.

### Important update — only l2 needs replacement

While diagnosing, we discovered that `l`'s card has PSID `HP_2420110034` (same OEM as hp1/hp3), not `MT_2470` like l2's. Loopback test on l (one DAC end-to-end between its two ports) brought up 25 Gb/s, full duplex, "Direct Attach Copper" — confirming l's NIC is healthy and reads the DAC EEPROM exactly like hp1/hp3 do. So the originally-reported "no link on l/l2" was solely l2 refusing the DAC; l was always going to link up once it had a partner.

Action: keep l's existing NIC. Swap only l2's. The second HP NIC currently in transit becomes a spare (or could go into hp2/hp5 if dual-port fleet symmetry is desired).

## When the replacement NICs arrive

1. Pull current ConnectX-4 Lx from l and l2; install replacements.
2. Confirm firmware reads `HP_…` PSID on `ethtool -i enp…np0` (matching hp1/hp3).
3. Cable up with the new DACs — link should be 25 Gb/s, "Direct Attach Copper", `Link detected: yes` immediately. No mlxconfig / no kernel module changes required.
4. Update `~/nixos/{l,l2}/` if MAC addresses change driver-naming on either side. The PCI bus position should stay the same so `enp…` names probably don't change.
5. Bring up the smoke matrix on the l/l2 pair to fold them into the testbed fleet alongside the hp/pi5 pairs. The series3 v3 patches are kernel-version-portable so the existing test-kernel/ patches apply unchanged.

## SSH note

`l` is rejecting all forwarded agent keys (id_ed25519, id_rsa, runpod, gitlab). Either no key enrolled for root on l, or the local keys differ from what's authorized. Resolve from console next time you're at the rack — independent of the cable problem.

## Cross-refs

- 2026-06-13 runbook (what we'd planned to do when DACs arrived): `perf-results/2026-06-13-l-l2-next-steps.md`
- v3 series patches that will be deployed on l/l2 once linked: `kernel-patches/series3-flowdis-fastpath/v3-namespace/`
- Memory entry capturing the firmware-PSID lesson so future me reaches for `ethtool -i` PSID compare first: `feedback_mellanox_oem_firmware_psid.md`
