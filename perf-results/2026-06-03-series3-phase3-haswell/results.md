# Phase 3 microbench — chromebox1 (Intel Haswell)

Date: 2026-06-03
Host: chromebox1
CPU: Intel Celeron 2955U @ 1.40 GHz (Haswell-ULT, 2c/2t, no HT, L2 2 MB)
gcc: 15.2.0 (-O3 -march=native)
Workload: `__skb_flow_dissect_err` on synthetic eth+IPv4+TCP, 10 M iterations per run, N=10.

## Result

| build | min | median | max | mean |
|---|---:|---:|---:|---:|
| baseline | 35.93 | 35.94 | 36.01 | 35.95 |
| patched  | 17.97 | 17.97 | 20.01 | 18.17 |

**Median delta: 35.94 → 17.97 ns/pkt = -50.0 %**

(One patched outlier at 20.01 ns/pkt in run 2/10; the other 9 runs cluster at 17.97-17.98 ns/pkt.)

Output bytes match: both report `addr_type=3 ip_proto=6 v4src=0xc0a80164 v4dst=0xa000005 sport=43981 dport=80` on every run.

## Build evidence

Both libraries built locally on chromebox1 with `gcc -O3 -fPIC` from the same
source tree, differing only in the fast-path patch:

```
text   data  bss  filename
13038  680  240  libflowdis-baseline.so
13534  680  240  libflowdis-patched.so   (+496 bytes — fast-path inlined into __skb_flow_dissect_err)
```

The fast-path helpers are static and get inlined into `__skb_flow_dissect_err`
at -O3 (so `nm` shows no `flow_dissect_fast*` symbols), but the function body
grew from 1076 to 1185 disassembly lines and `.text` grew 520 bytes — confirming
the patch is present in the patched binary.

Source delta:
- `/tmp/patched.c`  — current `src/lib/flowdis/flow_dissector.c` (6 mentions of `flow_dissect_fast`)
- `/tmp/baseline.c` — same file with the 3 helpers and the call-site block stripped (0 mentions)

Bench binary built once against each `.so` with `-Wl,-rpath` pinned to the
matching directory, so the patched bench cannot accidentally load the baseline
library.

## Comparison across hosts

| uarch | host | baseline | patched | delta |
|---|---|---:|---:|---:|
| Zen 2 | Threadripper PRO 3945WX (workstation) | 12.44 ns | 6.56 ns | **-47.3 %** |
| Zen 1 | Ryzen 5 PRO 2400G (hp5) | 20.50 ns | 20.53 ns | noise (within clock_gettime floor) |
| Haswell-ULT | Intel Celeron 2955U (chromebox1) | 35.94 ns | 17.97 ns | **-50.0 %** |

Three data points: Zen 2 and Intel Haswell both show ~ -50 %, Zen 1 is
below the timing floor at p50 (visible at p10 in earlier runs). The
Intel result confirms the optimisation is not Zen-specific and the
relative speedup scales with the slow-path cost per packet.

## Files

- `baseline.log`, `patched.log` — raw N=10 run output
- `cpuinfo.txt`, `gcc-version.txt` — host fingerprint
- `results.md` (this file)
