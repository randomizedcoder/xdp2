-- SPDX-License-Identifier: BSD-2-Clause-FreeBSD
--
-- DPDK-pktgen Lua startup script for the ntuple+template bench.
--
-- Driven from samples/flow_dissector/pktgen_dpdk_ntuple_template.sh which
-- exports these env vars before launching `pktgen -f <this-file>`:
--
--   PKTGEN_DST_IP     target IPv4 (e.g. 10.1.0.5)
--   PKTGEN_DST_MAC    target L2 (e.g. 3c:fd:fe:aa:bb:cc) — pktgen
--                     doesn't ARP; we feed it the MAC directly.
--   PKTGEN_DPORT      UDP dst port (default 443)
--   PKTGEN_PKT_SIZE   frame size including headers (default 1400)
--   PKTGEN_SRC_IP     source IPv4 (default 10.1.0.2 — hp2)
--
-- Port 0 is the only port pktgen sees because the driver script
-- whitelists exactly one PCI device via -a. That keeps the config
-- uniform regardless of how many NICs the peer has.
--
-- Why UDP-only: the FD rule on the target steers by (proto=UDP, dport),
-- so we just need stable UDP flows. No TCP state machine involved.

local dst_ip   = os.getenv("PKTGEN_DST_IP")  or "10.1.0.5"
local dst_mac  = os.getenv("PKTGEN_DST_MAC") or "3c:fd:fe:00:00:00"
local src_ip   = os.getenv("PKTGEN_SRC_IP")  or "10.1.0.2"
local dport    = tonumber(os.getenv("PKTGEN_DPORT"))    or 443
local pkt_size = tonumber(os.getenv("PKTGEN_PKT_SIZE")) or 1400

-- Configure port 0 as a single UDP flow to the FD-matched dport.
pktgen.set("0", "size", pkt_size)
pktgen.set("0", "rate", 100)              -- 100% = line rate; start high, cap via hw
pktgen.set("0", "count", 0)               -- 0 = run forever
pktgen.set("0", "sport", 12345)
pktgen.set("0", "dport", dport)
pktgen.set_ipaddr("0", "src", src_ip .. "/24")
pktgen.set_ipaddr("0", "dst", dst_ip)
pktgen.set_mac("0", "dst", dst_mac)
pktgen.set_proto("0", "udp")
pktgen.set_type("0", "ipv4")

-- Kick traffic. `start all` begins TX on every configured port; since
-- we only touched port 0, only port 0 transmits.
pktgen.start("all")

-- Keep the interpreter alive so pktgen stays in its event loop. The
-- driver script stops the bench via SIGTERM to the pktgen pid, which
-- triggers pktgen's own teardown before this function ever returns.
while true do
    pktgen.delay(1000)   -- ms
end
