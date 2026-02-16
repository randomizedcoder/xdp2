# Modern BPF Architecture Design for XDP2

**Status:** PROPOSAL
**Created:** 2026-02-11
**Author:** Claude (with user collaboration)
**Related:** `xdp-bpf-compatibility-defect.md`, `sample-tests-expansion-log.md`

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Current XDP2 Architecture](#current-xdp2-architecture)
3. [Modern BPF Ecosystem Overview](#modern-bpf-ecosystem-overview)
4. [Gap Analysis](#gap-analysis)
5. [Proposed Architecture](#proposed-architecture)
6. [Migration Strategy](#migration-strategy)
7. [Implementation Details](#implementation-details)
8. [Risk Assessment](#risk-assessment)
9. [Appendices](#appendices)

---

## Executive Summary

XDP2 currently uses a template-based code generation approach for BPF/XDP programs that
is incompatible with modern BPF constraints. This document proposes adopting the modern
libbpf + BTF + CO-RE stack to:

1. **Fix current blocking issues** - Stack argument limitations, API mismatches
2. **Improve portability** - Run on different kernel versions without recompilation
3. **Simplify build process** - Use standard libbpf skeleton generation
4. **Enable better tooling** - Full BTF support for debugging and introspection

The migration can be done incrementally while maintaining backward compatibility with
the existing userspace parser functionality.

---

## Current XDP2 Architecture

### Overview

XDP2 is a high-performance packet parser library with two execution modes:

1. **Userspace Mode** - Direct parsing in userspace applications (works correctly)
2. **XDP/BPF Mode** - Parsing in kernel XDP hooks (currently broken)

### How the API Became BPF-Incompatible

Understanding how the current 6-argument API evolved helps explain why XDP/BPF mode is broken.

#### Original Design (BPF-Compatible)

The original API in commit `b0e916b` used **3 arguments**, which fits within BPF's 5-register limit:

```c
// Original xdp2_ctrl_data contained header info
struct xdp2_hdr_data {
    size_t hdr_len;      // Header length
    size_t hdr_offset;   // Header offset from packet start
    __u8 tlv_levels;
    __u16 pkt_csum;
    __u16 hdr_csum;
};

struct xdp2_ctrl_data {
    struct xdp2_packet_data pkt;
    struct xdp2_hdr_data hdr;      // ← Header info lived here
    struct xdp2_var_data var;      // ← var.metadata was the metadata pointer
};

// Original function signature - 3 args, BPF compatible!
void (*extract_metadata)(
    const void *hdr,               // R1
    void *frame,                   // R2
    const struct xdp2_ctrl_data ctrl  // R3 (passed by value)
);

// Metadata extraction accessed header info via ctrl:
frame->l3_off = ctrl.hdr.hdr_offset;
```

#### The Refactoring (Commit `4e14212`)

On Sep 30, 2025, the API was refactored to use explicit function arguments instead of
packing everything into the `ctrl` struct. The commit message states:

> "Take hdr_len and hdr_offest out of the control data structure, these are now
> passed as explicit function arguments"

This changed the signature from 3 to 6 arguments:

| Change | Old Location | New Location | Args |
|--------|--------------|--------------|------|
| Header length | `ctrl.hdr.hdr_len` | `size_t hdr_len` param | +1 |
| Header offset | `ctrl.hdr.hdr_offset` | `size_t hdr_off` param | +1 |
| Metadata ptr | `ctrl.var.metadata` | `void *metadata` param | +1 |
| Control data | passed by value | passed by pointer | same |

```c
// New function signature - 6 args, NOT BPF compatible!
void (*extract_metadata)(
    const void *hdr,                      // R1
    size_t hdr_len,                       // R2
    size_t hdr_off,                       // R3
    void *metadata,                       // R4
    void *frame,                          // R5
    const struct xdp2_ctrl_data *ctrl     // STACK ← Exceeds BPF limit!
);
```

#### Why This Broke BPF

The refactoring made the API "cleaner" from a userspace perspective—explicit parameters
are easier to understand than nested struct access. However:

1. **BPF only has 5 argument registers (R1-R5)** - The 6th argument must go on the stack
2. **BPF verifier rejects stack arguments** - It cannot guarantee safety with dynamic stack usage
3. **The old design was accidentally BPF-friendly** - Packing data into `ctrl` kept arg count low

#### The Template Wasn't Updated

The code generation template (`xdp_def.template.c`) still references the **old** API:

```c
// Template generates code like this:
len = ctrl.hdr.hdr_len - offset;      // ← ctrl.hdr no longer exists!
ctrl.hdr.hdr_offset += offset;        // ← ctrl.hdr no longer exists!
```

This means the XDP code path has been broken since the refactoring—it was likely
never tested after the API change.

#### Summary

| Version | Args | BPF Compatible | Status |
|---------|------|----------------|--------|
| Original (`b0e916b`) | 3 | ✓ Yes | Was working |
| After refactor (`4e14212`) | 6 | ✗ No | Broken |
| Template code | — | — | References old API |

The path forward requires either:
1. **Reverting to a packed-struct approach** for BPF (≤5 args)
2. **Adopting modern BPF patterns** with inline functions and context structs (this document's proposal)

### Options for Reducing to ≤5 Arguments

This section explores various approaches to make the API BPF-compatible again.

#### Current 6-Argument Signature (Broken)

```c
void (*extract_metadata)(
    const void *hdr,                      // R1
    size_t hdr_len,                       // R2
    size_t hdr_off,                       // R3
    void *metadata,                       // R4
    void *frame,                          // R5
    const struct xdp2_ctrl_data *ctrl     // STACK ← Exceeds BPF limit!
);
```

---

#### Option 1: Pack `hdr_len` and `hdr_off` into one `uint64_t`

Headers are typically small (< 64KB). Pack both into a single 64-bit value:

```c
// Pack: upper 32 bits = offset, lower 32 bits = length
uint64_t hdr_info = ((uint64_t)hdr_off << 32) | hdr_len;

void (*extract_metadata)(
    const void *hdr,           // R1
    uint64_t hdr_info,         // R2 (packed len + off)
    void *metadata,            // R3
    void *frame,               // R4
    const struct xdp2_ctrl_data *ctrl  // R5 ✓
);

// Unpack inside function:
size_t hdr_len = hdr_info & 0xFFFFFFFF;
size_t hdr_off = hdr_info >> 32;
```

| Aspect | Assessment |
|--------|------------|
| **Pros** | Minimal API change, backward compatible pattern |
| **Cons** | Requires bit manipulation on every call |
| **Performance** | ~1-2 cycles for pack/unpack (shift + mask) |
| **Kernel usage** | Rare; kernel prefers explicit parameters |
| **HFT suitability** | Acceptable; bit ops are very fast on modern CPUs |

---

#### Option 2: Derive `hdr_off` from pointer arithmetic

If `ctrl` contains the packet base pointer, offset can be computed:

```c
void (*extract_metadata)(
    const void *hdr,           // R1
    size_t hdr_len,            // R2
    void *metadata,            // R3
    void *frame,               // R4
    const struct xdp2_ctrl_data *ctrl  // R5 ✓
);

// Inside function:
size_t hdr_off = (const char *)hdr - (const char *)ctrl->pkt.packet;
```

| Aspect | Assessment |
|--------|------------|
| **Pros** | Cleaner API, offset is always derivable |
| **Cons** | Requires packet base pointer in ctrl; one pointer subtraction |
| **Performance** | 1 cycle for pointer subtraction |
| **Kernel usage** | Common pattern; skb->data offsets work this way |
| **HFT suitability** | Excellent; pointer arithmetic is essentially free |

---

#### Option 3: Merge `metadata` and `frame`

Analysis of the code suggests `metadata` and `frame` may be redundant—`frame` IS the
metadata structure in many cases:

```c
void (*extract_metadata)(
    const void *hdr,           // R1
    size_t hdr_len,            // R2
    size_t hdr_off,            // R3
    void *frame,               // R4 (metadata IS frame)
    const struct xdp2_ctrl_data *ctrl  // R5 ✓
);
```

| Aspect | Assessment |
|--------|------------|
| **Pros** | Removes genuinely redundant parameter |
| **Cons** | Requires audit to confirm metadata == frame everywhere |
| **Performance** | Saves one register, zero runtime cost |
| **Kernel usage** | Very common; avoid redundant parameters |
| **HFT suitability** | Excellent; fewer args = faster calls |

---

#### Option 4: Drop `ctrl` for BPF path

Many metadata extractors don't actually use `ctrl`:

```c
// Example: ctrl is passed but never used!
#define XDP2_METADATA_TEMP_ether(NAME, STRUCT)
static void NAME(const void *veth, size_t hdr_len, size_t hdr_off,
                 void *imetadata, void *iframe,
                 const struct xdp2_ctrl_data *ctrl)  // ← Never referenced!
{
    struct STRUCT *frame = iframe;
    frame->eth_proto = ((struct ethhdr *)veth)->h_proto;
    memcpy(frame->eth_addrs, ...);
}
```

For BPF, generate without `ctrl`:

```c
void (*extract_metadata)(
    const void *hdr,           // R1
    size_t hdr_len,            // R2
    size_t hdr_off,            // R3
    void *metadata,            // R4
    void *frame                // R5 ✓
);
```

| Aspect | Assessment |
|--------|------------|
| **Pros** | No runtime cost; removes unused parameter |
| **Cons** | Need to audit which functions actually need ctrl |
| **Performance** | Zero overhead—parameter simply not passed |
| **Kernel usage** | Standard practice; don't pass unused params |
| **HFT suitability** | Excellent; eliminates unnecessary work |

---

#### Option 5: Context struct (standard BPF pattern)

Pack all parameters into a struct, pass one pointer:

```c
struct xdp2_extract_ctx {
    const void *hdr;
    size_t hdr_len;
    size_t hdr_off;
    void *metadata;
    void *frame;
    const struct xdp2_ctrl_data *ctrl;
};

void (*extract_metadata)(
    struct xdp_md *xdp,              // R1 (BPF context)
    struct xdp2_extract_ctx *ctx     // R2 ✓
);
```

| Aspect | Assessment |
|--------|------------|
| **Pros** | Unlimited parameters, very standard BPF idiom |
| **Cons** | Struct must live on stack (512 byte limit); indirection |
| **Performance** | ~2-4 cycles per field access (load from memory vs register) |
| **Kernel usage** | Very common; `struct pt_regs`, `struct bpf_sock`, etc. |
| **HFT suitability** | Good; slight overhead from memory loads |

---

#### Option 6: Use XDP Context Directly (Recommended for XDP)

This option deserves special attention as it's the **idiomatic XDP pattern** that
experienced XDP developers will expect.

##### The XDP Context Structure

Every XDP program receives `struct xdp_md *ctx`:

```c
struct xdp_md {
    __u32 data;           // Pointer to packet start (as u32)
    __u32 data_end;       // Pointer to packet end (as u32)
    __u32 data_meta;      // Pointer to metadata area (before packet)
    __u32 ingress_ifindex; // Incoming interface index
    __u32 rx_queue_index;  // RX queue index
    __u32 egress_ifindex;  // Egress interface (for XDP_REDIRECT)
};
```

##### Proposed API

```c
static __always_inline int
extract_ether(struct xdp_md *ctx, size_t offset, struct flow_key *key)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data + offset;

    // MANDATORY bounds check - verifier requires this
    if ((void *)(eth + 1) > data_end)
        return -1;

    // Safe to access - verifier has proven bounds
    key->eth_proto = eth->h_proto;
    memcpy(key->eth_src, eth->h_source, ETH_ALEN);
    memcpy(key->eth_dst, eth->h_dest, ETH_ALEN);

    return sizeof(*eth);  // Return bytes consumed
}
```

##### Why This Is Superior for XDP

**1. Built-in Bounds Checking (Security)**

The current API passes `hdr_len` but never uses it. With XDP context, bounds
checking is **mandatory and verified**:

```c
// Current XDP2 (UNSAFE - hdr_len ignored!)
static void extract_ether(const void *hdr, size_t hdr_len, ...)
{
    // hdr_len is passed but NEVER checked!
    frame->eth_proto = ((struct ethhdr *)hdr)->h_proto;  // Potential overflow!
}

// XDP-idiomatic (SAFE - verifier enforces bounds)
static int extract_ether(struct xdp_md *ctx, size_t offset, ...)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = (void *)(long)ctx->data + offset;

    if ((void *)(eth + 1) > data_end)  // REQUIRED by verifier
        return -1;

    // Verifier PROVES this access is safe
    key->eth_proto = eth->h_proto;
}
```

**2. Verifier Integration**

The BPF verifier understands `ctx->data` and `ctx->data_end` specially. When you
perform bounds checks against these values, the verifier tracks the proven range:

```c
// Verifier state tracking:
void *data = ctx->data;      // Verifier: data is packet start
void *data_end = ctx->data_end;  // Verifier: data_end is packet end

struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)  // Verifier: if true, eth+14 > end
    return XDP_DROP;

// Verifier now KNOWS: eth through eth+13 is safe to read
__u16 proto = eth->h_proto;  // Verifier: ALLOWED (within proven range)
```

With arbitrary `void *hdr` pointers, the verifier cannot make these guarantees.

**3. Familiar to XDP Developers**

Every XDP tutorial, kernel sample, and libbpf-bootstrap example uses this pattern:

```c
// From kernel samples/bpf/xdp1_kern.c
SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if (eth + 1 > data_end)
        return XDP_DROP;
    // ...
}
```

Developers joining the XDP2 project will immediately understand this pattern.

**4. All Information Is Derivable**

Instead of passing 6 separate parameters, everything comes from `ctx`:

| Current Param | Derived From Context |
|---------------|---------------------|
| `hdr` | `ctx->data + offset` |
| `hdr_len` | Implicit via `ctx->data_end` check |
| `hdr_off` | Passed as `offset` parameter |
| `metadata` | Passed as output struct |
| `frame` | Same as metadata (merged) |
| `ctrl` | Not needed for inline extractors |

**5. Future-Proof**

As XDP evolves, using the standard context provides automatic compatibility:

- **XDP multi-buffer** (kernel 5.18+): `ctx->data` may span multiple pages
- **XDP metadata** (`ctx->data_meta`): Pre-packet area for inter-program communication
- **XDP hardware offload**: Same API works with NIC-offloaded XDP
- **AF_XDP zero-copy**: Context remains the interface

**6. Enables Chained Parsing**

The return value can indicate bytes consumed, enabling clean chaining:

```c
SEC("xdp")
int xdp_parser(struct xdp_md *ctx)
{
    struct flow_key key = {};
    size_t offset = 0;
    int ret;

    ret = extract_ether(ctx, offset, &key);
    if (ret < 0) return XDP_DROP;
    offset += ret;

    if (key.eth_proto == htons(ETH_P_IP)) {
        ret = extract_ipv4(ctx, offset, &key);
        if (ret < 0) return XDP_DROP;
        offset += ret;

        if (key.ip_proto == IPPROTO_TCP || key.ip_proto == IPPROTO_UDP) {
            ret = extract_ports(ctx, offset, &key);
            if (ret < 0) return XDP_DROP;
        }
    }

    // Use key for flow tracking...
    return XDP_PASS;
}
```

**7. Performance Characteristics**

| Aspect | Assessment |
|--------|------------|
| **Arguments** | 3 (ctx, offset, output) - all in registers |
| **Bounds check** | ~2-3 instructions (compare + branch) |
| **Memory loads** | `ctx->data` and `ctx->data_end` likely cached in registers |
| **Verifier overhead** | Load-time only, zero runtime cost |
| **Inlining** | `__always_inline` eliminates call overhead |

##### Dual API Design

For XDP2 to support both userspace and XDP, a dual API could work:

```c
// Userspace API (existing pattern)
void extract_ether_userspace(const void *hdr, size_t hdr_len,
                             struct metadata *meta);

// XDP API (new idiomatic pattern)
static __always_inline int
extract_ether_xdp(struct xdp_md *ctx, size_t offset, struct metadata *meta);

// Macro to select appropriate version
#ifdef __bpf__
#define extract_ether extract_ether_xdp
#else
#define extract_ether extract_ether_userspace
#endif
```

##### Summary Table

| Aspect | Assessment |
|--------|------------|
| **Pros** | Idiomatic XDP, built-in security, verifier integration, familiar pattern |
| **Cons** | Different API for BPF vs userspace (but this is normal) |
| **Performance** | Excellent; reuses already-loaded context, zero unnecessary args |
| **Kernel usage** | **THE standard pattern** for all XDP programs |
| **HFT suitability** | Excellent; minimal args, mandatory bounds checking catches bugs early |
| **Security** | **Best option** - verifier-enforced bounds checking |
| **Learning curve** | Low for XDP developers; this is what they expect |

---

#### Option 7: Inline everything (eliminate function calls)

For BPF, don't use function calls—inline all extraction logic:

```c
SEC("xdp")
int xdp_parser(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Inline ethernet extraction (no function call)
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    __u16 eth_proto = eth->h_proto;
    // ... continue inline
}
```

| Aspect | Assessment |
|--------|------------|
| **Pros** | No argument limit, no call overhead, maximum performance |
| **Cons** | Code duplication, loses abstraction, larger BPF program |
| **Performance** | Optimal; zero function call overhead |
| **Kernel usage** | Common for hot paths; `__always_inline` everywhere |
| **HFT suitability** | **Best for absolute performance** |

---

#### Option 8: Tagged pointers (exotic)

Use low bits of aligned pointers to encode small values:

```c
// Pointers are 8-byte aligned, low 3 bits always 0
// Encode header length class in low bits
uintptr_t tagged_hdr = (uintptr_t)hdr | (len_class & 0x7);

void (*extract_metadata)(
    uintptr_t tagged_hdr,      // R1 (pointer + encoded bits)
    size_t hdr_off,            // R2
    void *metadata,            // R3
    void *frame,               // R4
    const struct xdp2_ctrl_data *ctrl  // R5 ✓
);
```

| Aspect | Assessment |
|--------|------------|
| **Pros** | Creative use of otherwise-wasted bits |
| **Cons** | Complex, error-prone, limited encoding (3 bits = 8 values) |
| **Performance** | ~2 cycles to mask/extract |
| **Kernel usage** | Used in specialized cases (e.g., radix trees, RCU) |
| **HFT suitability** | Not recommended; complexity outweighs benefit |

---

### Performance Comparison Summary

| Option | Args | Runtime Overhead | Memory Overhead | Kernel-Style | HFT Rank |
|--------|------|------------------|-----------------|--------------|----------|
| 1. Pack len+off | 5 | ~2 cycles (bit ops) | None | Rare | 4 |
| 2. Derive offset | 5 | ~1 cycle (ptr sub) | None | Common | 2 |
| 3. Merge meta+frame | 5 | Zero | None | Common | 1 |
| 4. Drop unused ctrl | 5 | Zero | None | Standard | 1 |
| 5. Context struct | 2 | ~2-4 cycles/field | 48 bytes stack | Common | 3 |
| 6. XDP ctx direct | 3 | Zero | None | Standard | 1 |
| 7. Full inline | 0 | Zero | Code size | Common | **Best** |
| 8. Tagged pointers | 5 | ~2 cycles | None | Rare | 5 |

---

### Audit Results: Actual Parameter Usage

An audit of all 37 `XDP2_METADATA_TEMP_*` macros in `parser_metadata.h` reveals
**most parameters are never used**:

#### Audit Summary

| Parameter | Declared | Actually Used | Notes |
|-----------|----------|---------------|-------|
| `hdr` (void*) | 37 | 37 | ✓ Always used - the header pointer |
| `hdr_len` (size_t) | 37 | **0** | ✗ NEVER used in any macro! |
| `hdr_off` (size_t) | 37 | **5** | Only in `*_off` variants |
| `imetadata` (void*) | 37 | **0** | ✗ NEVER used in any macro! |
| `iframe` (void*) | 37 | 37 | ✓ Always used - the output struct |
| `ctrl` (struct*) | 37 | **0** | ✗ NEVER used in any macro! |

#### Key Finding

**4 out of 6 parameters are completely unused!**

```c
// Current signature: 6 args
static void NAME(const void *veth, size_t hdr_len, size_t hdr_off,
                 void *imetadata, void *iframe,
                 const struct xdp2_ctrl_data *ctrl)
{
    struct STRUCT *frame = iframe;      // Only iframe is used
    frame->eth_proto = eth->h_proto;    // Direct access to header
    memcpy(frame->eth_addrs, ...);      // No hdr_len, imetadata, or ctrl!
}
```

#### Macros That Use `hdr_off` (5 total)

| Macro | Usage |
|-------|-------|
| `XDP2_METADATA_TEMP_ether_off` | `frame->l2_off = hdr_off` |
| `XDP2_METADATA_TEMP_ipv4` | `frame->l3_off = hdr_off` |
| `XDP2_METADATA_TEMP_ipv6` | `frame->l3_off = hdr_off` |
| `XDP2_METADATA_TEMP_ports_off` | `frame->l4_off = hdr_off` |

#### Minimal API (Based on Audit)

For the 32 macros that don't use `hdr_off`:
```c
// Only 2 args needed!
static void NAME(const void *hdr, void *frame);
```

For the 5 macros that use `hdr_off`:
```c
// Only 3 args needed!
static void NAME(const void *hdr, size_t hdr_off, void *frame);
```

#### Implications

This audit proves that **Options 3 and 4 combined** can reduce the API from 6 to 2-3
arguments with **zero functionality loss**:

| Before | After | Reduction |
|--------|-------|-----------|
| 6 args (BPF incompatible) | 2-3 args | 50-67% fewer args |
| Stack spill required | All in registers | Zero stack overhead |
| Unused data passed | Only used data | Cleaner API |

This is the **lowest-risk, highest-impact fix** because it removes parameters that
are already dead code.

### Recommendation for High-Frequency Trading

For absolute minimum latency:

1. **Primary: Option 7 (Full Inline)** - Zero function call overhead
2. **Secondary: Options 3+4 combined** - Remove redundant params, 4-arg API
3. **Fallback: Option 6 (XDP context)** - 3 args, BPF-native

The key insight for HFT is that **function call overhead matters**. Even with 5 arguments
fitting in registers, a function call requires:
- Push return address
- Jump to function
- Function prologue
- Function epilogue
- Return jump

Full inlining eliminates all of this. Modern compilers with `__always_inline` will
inline aggressively, and BPF programs benefit from being "unrolled" single blocks.

### Proposed Benchmarking Strategy

To verify actual performance of each approach:

```c
// Benchmark harness structure
struct benchmark_result {
    uint64_t cycles_min;
    uint64_t cycles_avg;
    uint64_t cycles_max;
    uint64_t calls;
};

// Use RDTSC for cycle-accurate measurement
static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

// Benchmark template
#define BENCHMARK(name, iterations, code) do {          \
    uint64_t start = rdtsc();                           \
    for (int i = 0; i < iterations; i++) { code; }      \
    uint64_t end = rdtsc();                             \
    printf("%s: %lu cycles/iter\n", name,               \
           (end - start) / iterations);                 \
} while(0)
```

**Benchmark scenarios:**

| Test | Description | Measures |
|------|-------------|----------|
| B1: Arg passing | Call empty function with N args | Register vs stack spill |
| B2: Bit pack/unpack | Pack and unpack hdr_info | Option 1 overhead |
| B3: Ptr arithmetic | Compute offset from pointers | Option 2 overhead |
| B4: Struct field access | Access fields via ctx pointer | Option 5 overhead |
| B5: Inline vs call | Same logic, inline vs function | Option 7 benefit |
| B6: Full parser | Parse Eth+IP+TCP packet | End-to-end comparison |

**For BPF-specific benchmarking:**

```bash
# Use bpftool to measure BPF program performance
bpftool prog profile id <PROG_ID> cycles

# Or XDP-specific benchmarks
xdp-bench throughput -i eth0 -p xdp_parser.o
```

### Code Generation Pipeline

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
│  parser.c   │───▶│ xdp2-compiler│───▶│ parser.xdp.h│───▶│ flow_tracker │
│ (user code) │    │ (ClangTool)  │    │ (generated) │    │   .xdp.o     │
└─────────────┘    └──────────────┘    └─────────────┘    └──────────────┘
```

1. **User writes `parser.c`** - Defines parse nodes, metadata extractors, protocol tables
2. **xdp2-compiler processes** - Uses libclang to analyze AST, generates optimized parser
3. **Template expansion** - `xdp_def.template.c` generates BPF-specific code
4. **Clang compiles** - `clang -target bpf` produces BPF bytecode

### Current File Structure

```
src/
├── include/xdp2/
│   ├── parser.h              # Core parser definitions
│   ├── parser_types.h        # Type definitions (xdp2_ctrl_data, etc.)
│   ├── parser_metadata.h     # XDP2_METADATA_TEMP_* macros
│   ├── bpf.h                 # BPF-specific helpers
│   └── proto_defs/           # Protocol definitions (ether, ipv4, tcp, etc.)
├── templates/xdp2/
│   └── xdp_def.template.c    # Python template for code generation
└── tools/compiler/
    └── src/main.cpp          # xdp2-compiler implementation
```

### Current Metadata Extraction Pattern

```c
// From src/include/xdp2/parser_metadata.h

#define XDP2_METADATA_TEMP_ether(NAME, TYPE)                              \
static void NAME(const void *hdr, size_t hdr_len, size_t hdr_off,         \
                 void *_meta, void *_frame,                               \
                 const struct xdp2_ctrl_data *ctrl)                       \
{                                                                          \
    TYPE *metadata = _meta;                                                \
    const struct ethhdr *eth = hdr;                                        \
                                                                           \
    memcpy(metadata->addrs.ether.h_dest, eth->h_dest, ETH_ALEN);          \
    memcpy(metadata->addrs.ether.h_source, eth->h_source, ETH_ALEN);      \
    metadata->addrs.ether.h_proto = eth->h_proto;                          \
}
```

**Problems with this pattern:**
1. `TYPE` can be a large struct (hundreds of bytes)
2. `memcpy` operations may require stack temporaries
3. Function signature has 6 parameters (BPF limit is 5 in registers)
4. Compiler may need to spill arguments to stack

### Current Issues (Detailed)

#### Issue 1: Stack Arguments

BPF architecture fundamentally limits:
- **Register arguments:** Maximum 5 (R1-R5)
- **Stack size:** 512 bytes total
- **No dynamic allocation:** All stack usage must be compile-time determinable

The 6-parameter function signature forces stack spilling:

```c
void extract_metadata(
    const void *hdr,           // R1
    size_t hdr_len,            // R2
    size_t hdr_off,            // R3
    void *_meta,               // R4
    void *_frame,              // R5
    const struct xdp2_ctrl_data *ctrl  // STACK! ← Problem
)
```

#### Issue 2: Template API Mismatch

The template `xdp_def.template.c` references obsolete struct members:

```c
// Generated code references:
ctrl.hdr.hdr_len      // ← Doesn't exist
ctrl.hdr.hdr_offset   // ← Doesn't exist
tlv_ctrl              // ← Undeclared variable
```

The `xdp2_ctrl_data` struct was refactored but templates weren't updated.

#### Issue 3: Large Struct Operations

```c
// This triggers stack allocation in BPF:
TYPE *metadata = _meta;
metadata->addrs.ether.h_dest = ...;  // Large struct access
```

When `TYPE` is `xdp2_metadata_all` (potentially 200+ bytes), operations on it
may exceed BPF verifier limits.

---

## Modern BPF Ecosystem Overview

### BPF Virtual Machine Architecture

Before diving into modern BPF features, it's important to understand why BPF has constraints
that differ from native code. **BPF is a virtual machine** running inside the Linux kernel,
not direct CPU execution.

#### The BPF Register Set

The BPF VM has exactly 11 64-bit registers:

| Register | Purpose | Notes |
|----------|---------|-------|
| R0 | Return value / exit code | Also holds function return values |
| R1 | 1st function argument | Caller-saved |
| R2 | 2nd function argument | Caller-saved |
| R3 | 3rd function argument | Caller-saved |
| R4 | 4th function argument | Caller-saved |
| R5 | 5th function argument | Caller-saved |
| R6 | General purpose | Callee-saved |
| R7 | General purpose | Callee-saved |
| R8 | General purpose | Callee-saved |
| R9 | General purpose | Callee-saved |
| R10 | Frame pointer (read-only) | Points to 512-byte stack |

**This is why there's a 5-argument limit** - R1 through R5 are the only registers available
for passing function arguments. Unlike x86-64 (which has 16 GPRs) or ARM64 (31 GPRs), the
BPF VM deliberately uses a minimal register set.

#### Why Only 11 Registers?

This is a deliberate design choice, not a hardware limitation:

1. **Verifier Simplicity**
   - The BPF verifier must prove every program is safe before loading into the kernel
   - It tracks the state (type, bounds, null-ness) of every register at every instruction
   - Fewer registers = smaller state space = faster verification = quicker program load times
   - Example: A program with 1000 instructions and 11 registers has tractable state; 32 registers would explode the verification complexity

2. **Portability**
   - BPF bytecode is JIT-compiled to native CPU instructions at load time
   - A minimal register set maps cleanly to all architectures:
     - x86-64: 16 GPRs → easily accommodates 11 BPF registers
     - ARM64: 31 GPRs → easily accommodates 11 BPF registers
     - Older 32-bit architectures: May need register pairs, but still manageable
   - A larger BPF register set would complicate JIT for register-constrained targets

3. **Security**
   - BPF programs run in kernel context with elevated privileges
   - A restrictive, well-defined calling convention minimizes attack surface
   - Every instruction is verified; fewer registers mean fewer things to verify

4. **Determinism**
   - BPF programs must terminate (no infinite loops)
   - Bounded execution time is required for kernel safety
   - Simple calling conventions help enforce predictable behavior

#### The Stack Argument Problem

When a function has more than 5 arguments, the 6th and beyond must be passed on the stack:

```c
// This function signature CANNOT work in BPF:
void extract_metadata(
    const void *hdr,                      // R1 ✓
    size_t hdr_len,                       // R2 ✓
    size_t hdr_off,                       // R3 ✓
    void *_meta,                          // R4 ✓
    void *_frame,                         // R5 ✓
    const struct xdp2_ctrl_data *ctrl     // STACK ✗ (no register available)
)
```

The BPF verifier will reject any program that tries to pass arguments via stack because:
- Stack argument passing requires runtime stack manipulation
- The verifier cannot guarantee stack safety with dynamic argument counts
- BPF's fixed 512-byte stack is already constrained

#### The Solution: Context Structs

The standard workaround is to pass a pointer to a struct containing all parameters:

```c
// BPF-compatible: 2 arguments (fits in R1, R2)
struct extract_ctx {
    const void *hdr;
    size_t hdr_len;
    size_t hdr_off;
    void *meta;
    void *frame;
    const struct xdp2_ctrl_data *ctrl;
};

static __always_inline void
extract_metadata(struct xdp_md *xdp, struct extract_ctx *ctx)
{
    // Access all parameters through ctx->
}
```

Or even simpler - inline everything so function calls are eliminated:

```c
// Best for BPF: No function call overhead, no argument passing
static __always_inline int
parse_and_extract(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    // ... inline all parsing logic here
}
```

This is the approach taken by modern BPF programs and the one proposed for XDP2.

---

### BTF (BPF Type Format)

BTF is a compact, efficient format for encoding type information in BPF programs.

**Key Features:**
- Embedded in kernel (since Linux 5.2+)
- Embedded in BPF ELF objects
- Enables type-aware operations at runtime
- Generated automatically by `clang -g -target bpf`

**BTF Data Locations:**
```
/sys/kernel/btf/vmlinux          # Kernel types
program.bpf.o:.BTF section       # Program types
```

### CO-RE (Compile Once, Run Everywhere)

CO-RE allows BPF programs to access kernel structures portably across versions.

**How it works:**
1. Program compiled with BTF on build machine
2. At load time, libbpf compares program BTF with kernel BTF
3. Field offsets are **relocated** to match running kernel
4. Same binary works on different kernel versions

**CO-RE Macros (from bpf/bpf_core_read.h):**

```c
// Safe struct field access with relocation
__u32 pid = BPF_CORE_READ(task, pid);

// Equivalent to:
__u32 pid;
bpf_core_read(&pid, sizeof(pid), &task->pid);

// Field existence check
if (bpf_core_field_exists(task->pid)) {
    // Access pid field
}

// Field offset at runtime
int off = bpf_core_field_offset(struct task_struct, pid);
```

### libbpf and Skeletons

Modern libbpf provides a "skeleton" abstraction for BPF programs.

**Workflow:**
```
┌─────────────┐    ┌──────────┐    ┌────────────┐    ┌─────────────┐
│ program.bpf.c│───▶│  clang   │───▶│program.bpf.o│───▶│   bpftool   │
│  (BPF code) │    │-target bpf│   │(BPF object)│    │gen skeleton│
└─────────────┘    └──────────┘    └────────────┘    └─────────────┘
                                                            │
                                                            ▼
                                                    ┌───────────────┐
                                                    │program.skel.h │
                                                    │(C header with │
                                                    │ embedded BPF) │
                                                    └───────────────┘
```

**Generated skeleton provides:**
```c
struct program_bpf {
    struct bpf_object_skeleton *skeleton;
    struct bpf_object *obj;
    struct {
        struct bpf_map *my_map;
    } maps;
    struct {
        struct bpf_program *xdp_prog;
    } progs;
    struct {
        struct bpf_link *xdp_prog;
    } links;
};

// Usage:
struct program_bpf *skel = program_bpf__open();
program_bpf__load(skel);
program_bpf__attach(skel);
```

### BPF Helpers for Packet Parsing

Modern BPF provides helpers specifically for packet access:

```c
// Direct packet access (XDP)
void *data = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;

// Bounds checking (required by verifier)
if (data + sizeof(struct ethhdr) > data_end)
    return XDP_DROP;

struct ethhdr *eth = data;

// BPF_CORE_READ for kernel structs (not needed for packet data)
// Packet data is already in BPF-accessible memory
```

### vmlinux.h - All Kernel Types

Instead of including individual kernel headers, modern BPF uses:

```c
#include "vmlinux.h"  // Generated from kernel BTF
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
```

**Generating vmlinux.h:**
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

---

## Gap Analysis

### Feature Comparison

| Feature | XDP2 Current | Modern libbpf | Gap |
|---------|-------------|---------------|-----|
| Type format | DWARF (via -g) | BTF | Partial BTF exists |
| Portability | Build-time kernel | CO-RE relocations | No CO-RE |
| Loading | Custom or iproute2 | libbpf skeleton | No skeleton |
| Headers | Multiple kernel headers | Single vmlinux.h | Multiple headers |
| Metadata | Template macros | Inline BPF code | Template issues |
| Arguments | 6-param functions | 5-param max | Stack overflow |
| Struct access | Direct assignment | BPF-safe patterns | Verifier failures |

### Compatibility Matrix

| Kernel Version | BTF | CO-RE | libbpf | XDP | XDP2 Status |
|----------------|-----|-------|--------|-----|-------------|
| < 4.8 | No | No | No | No | N/A |
| 4.8 - 4.18 | No | No | Basic | Basic | Untested |
| 4.18 - 5.2 | Partial | No | Yes | Full | Untested |
| 5.2 - 5.8 | Yes | Partial | Yes | Full | Should work |
| 5.8+ | Yes | Yes | Yes | Full | Target |

---

## Proposed Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────────────┐
│                        XDP2 Library                                  │
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐ │
│  │  Userspace API  │  │   BPF/XDP API   │  │  Shared Definitions │ │
│  │  (unchanged)    │  │   (new design)  │  │  (protocols, etc.)  │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────────┘ │
│           │                   │                      │              │
│           ▼                   ▼                      ▼              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐ │
│  │ parser.c        │  │ parser.bpf.c    │  │ xdp2_protos.h       │ │
│  │ (user parsers)  │  │ (BPF parsers)   │  │ (shared protocol    │ │
│  │                 │  │                 │  │  definitions)       │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────────┘ │
│           │                   │                                     │
│           ▼                   ▼                                     │
│  ┌─────────────────┐  ┌─────────────────┐                          │
│  │ xdp2-compiler   │  │ clang + bpftool │                          │
│  │ (generates      │  │ (generates      │                          │
│  │  optimized      │  │  skeleton)      │                          │
│  │  userspace)     │  │                 │                          │
│  └─────────────────┘  └─────────────────┘                          │
│           │                   │                                     │
│           ▼                   ▼                                     │
│  ┌─────────────────┐  ┌─────────────────┐                          │
│  │ parser.p.c      │  │ parser.skel.h   │                          │
│  │ (optimized      │  │ (embedded BPF   │                          │
│  │  userspace)     │  │  + loader API)  │                          │
│  └─────────────────┘  └─────────────────┘                          │
└─────────────────────────────────────────────────────────────────────┘
```

### New File Structure

```
src/
├── include/xdp2/
│   ├── parser.h              # Core parser (unchanged)
│   ├── parser_types.h        # Shared types
│   ├── parser_metadata.h     # Userspace metadata macros
│   ├── bpf/                  # NEW: BPF-specific headers
│   │   ├── parser_bpf.h      # BPF parser helpers
│   │   ├── metadata_bpf.h    # BPF metadata extraction
│   │   └── helpers.h         # BPF helper wrappers
│   └── proto_defs/           # Protocol definitions (shared)
├── bpf/                      # NEW: BPF source files
│   ├── vmlinux.h             # Generated kernel types
│   ├── xdp2_common.bpf.h     # Common BPF definitions
│   └── parsers/              # BPF parser implementations
│       ├── simple.bpf.c      # Simple tuple parser
│       ├── tlvs.bpf.c        # TLV-aware parser
│       └── custom.bpf.c      # Template for custom parsers
└── tools/
    ├── compiler/             # xdp2-compiler (unchanged)
    └── bpfgen/               # NEW: BPF skeleton generator wrapper
```

### BPF Program Structure

```c
// src/bpf/parsers/simple.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Protocol definitions shared with userspace
#include "xdp2/proto_defs/proto_ether.h"
#include "xdp2/proto_defs/proto_ipv4.h"

// BPF-specific metadata structure (stack-friendly)
struct xdp2_flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  pad[3];
} __attribute__((packed));

// BPF map for flow tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct xdp2_flow_key);
    __type(value, __u64);
} flow_map SEC(".maps");

// Inline parser functions (no stack spilling)
static __always_inline int
parse_eth(void *data, void *data_end, __u16 *eth_proto, void **next_hdr)
{
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return -1;

    *eth_proto = bpf_ntohs(eth->h_proto);
    *next_hdr = eth + 1;
    return 0;
}

static __always_inline int
parse_ipv4(void *data, void *data_end, struct xdp2_flow_key *key, void **next_hdr)
{
    struct iphdr *iph = data;

    if ((void *)(iph + 1) > data_end)
        return -1;

    // Bounds check for variable header length
    __u8 hdr_len = iph->ihl * 4;
    if ((void *)iph + hdr_len > data_end)
        return -1;

    key->src_ip = iph->saddr;
    key->dst_ip = iph->daddr;
    key->protocol = iph->protocol;

    *next_hdr = (void *)iph + hdr_len;
    return 0;
}

static __always_inline int
parse_ports(void *data, void *data_end, struct xdp2_flow_key *key)
{
    // TCP and UDP have ports at same offset
    struct {
        __be16 source;
        __be16 dest;
    } *ports = data;

    if ((void *)(ports + 1) > data_end)
        return -1;

    key->src_port = bpf_ntohs(ports->source);
    key->dst_port = bpf_ntohs(ports->dest);
    return 0;
}

SEC("xdp")
int xdp2_parser(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    void *cursor = data;

    struct xdp2_flow_key key = {};
    __u16 eth_proto;

    // Parse Ethernet
    if (parse_eth(cursor, data_end, &eth_proto, &cursor) < 0)
        return XDP_PASS;

    // Check for IP
    if (eth_proto != ETH_P_IP)
        return XDP_PASS;

    // Parse IPv4
    if (parse_ipv4(cursor, data_end, &key, &cursor) < 0)
        return XDP_PASS;

    // Parse ports for TCP/UDP
    if (key.protocol == IPPROTO_TCP || key.protocol == IPPROTO_UDP) {
        if (parse_ports(cursor, data_end, &key) < 0)
            return XDP_PASS;
    }

    // Update flow map
    __u64 *count = bpf_map_lookup_elem(&flow_map, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&flow_map, &key, &init, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

### Key Design Principles

#### 1. Stack-Friendly Metadata

**Current (problematic):**
```c
// Large struct passed/returned
void extract_metadata(const void *hdr, ..., TYPE *metadata) {
    metadata->field1 = ...;  // May spill to stack
    metadata->field2 = ...;
}
```

**Proposed (BPF-safe):**
```c
// Small, focused structs on stack
struct xdp2_flow_key key = {};  // 16 bytes, fits in registers

static __always_inline void
extract_flow_key(void *data, struct xdp2_flow_key *key) {
    // Direct assignment to small struct
    key->src_ip = ...;
}
```

#### 2. Inline Everything

**Current:**
```c
// Template generates regular functions
static void ether_metadata(...) { ... }
static void ipv4_metadata(...) { ... }
```

**Proposed:**
```c
// Force inlining to avoid function call overhead
static __always_inline int parse_eth(...) { ... }
static __always_inline int parse_ipv4(...) { ... }
```

#### 3. Bounds Checking Pattern

**Required by BPF verifier:**
```c
// ALWAYS check bounds before access
if ((void *)(eth + 1) > data_end)
    return -1;

// Now verifier knows eth is safe to access
__u16 proto = eth->h_proto;
```

#### 4. Map-Based Communication

**Current (incompatible):**
```c
// Returns metadata to caller
void *metadata;
parser_extract(pkt, &metadata);
process(metadata);
```

**Proposed:**
```c
// BPF communicates via maps
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    ...
} events SEC(".maps");

// Send parsed data to userspace
bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                      &parsed_data, sizeof(parsed_data));
```

---

## Migration Strategy

### Phase 1: Parallel Development (Low Risk)

**Goal:** Create new BPF infrastructure without breaking existing code.

**Tasks:**
1. Create `src/bpf/` directory structure
2. Generate `vmlinux.h` for target kernels
3. Write reference BPF parser (`simple.bpf.c`)
4. Create skeleton build integration
5. Add test for BPF parser loading

**Duration estimate:** 2-3 weeks

**Files to create:**
```
src/bpf/
├── vmlinux.h
├── xdp2_common.bpf.h
└── parsers/simple.bpf.c

src/tools/bpfgen/
├── Makefile
└── generate-skeleton.sh

nix/
└── bpf.nix  # BPF build support
```

### Phase 2: Protocol Sharing (Medium Risk)

**Goal:** Share protocol definitions between userspace and BPF.

**Tasks:**
1. Refactor `proto_defs/` to be BPF-compatible
2. Remove glibc dependencies from protocol headers
3. Use `__attribute__((packed))` consistently
4. Test both userspace and BPF compilation

**Duration estimate:** 1-2 weeks

**Changes to existing files:**
```
src/include/xdp2/proto_defs/
├── proto_ether.h   # Add BPF guards
├── proto_ipv4.h    # Remove glibc deps
├── proto_tcp.h     # etc.
└── ...
```

### Phase 3: Metadata Refactoring (Higher Risk)

**Goal:** Create BPF-compatible metadata extraction.

**Tasks:**
1. Define small, stack-friendly metadata structs
2. Create BPF-specific extraction macros
3. Maintain userspace macros for compatibility
4. Update documentation

**Duration estimate:** 2-3 weeks

**New header structure:**
```c
// src/include/xdp2/bpf/metadata_bpf.h

// Small struct for flow identification
struct xdp2_bpf_flow_key {
    union {
        __be32 v4;
        struct in6_addr v6;
    } src_addr;
    union {
        __be32 v4;
        struct in6_addr v6;
    } dst_addr;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    __u8 ip_version;
    __u8 flags;
    __u8 pad;
} __attribute__((packed));

// Inline extraction (no function call)
#define XDP2_BPF_EXTRACT_IPV4(iph, key) do {     \
    (key)->src_addr.v4 = (iph)->saddr;           \
    (key)->dst_addr.v4 = (iph)->daddr;           \
    (key)->protocol = (iph)->protocol;           \
    (key)->ip_version = 4;                       \
} while(0)
```

### Phase 4: Template Removal (Higher Risk)

**Goal:** Replace template-based code generation with direct BPF code.

**Tasks:**
1. Deprecate `xdp_def.template.c`
2. Create BPF parser library
3. Document migration path for users
4. Update samples to use new approach

**Duration estimate:** 3-4 weeks

### Phase 5: Skeleton Integration

**Goal:** Use libbpf skeletons for loading.

**Tasks:**
1. Integrate `bpftool gen skeleton` into build
2. Create userspace loading library
3. Add attach/detach helpers
4. Create comprehensive tests

**Duration estimate:** 2 weeks

---

## Implementation Details

### Build System Changes

#### Makefile Integration

```makefile
# New BPF build targets

CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
BPF_CFLAGS += -I$(VMLINUX_DIR) -I$(XDP2_INCLUDE)

# Generate vmlinux.h from running kernel
$(VMLINUX_DIR)/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile BPF object
%.bpf.o: %.bpf.c $(VMLINUX_DIR)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Generate skeleton header
%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@
```

#### Nix Integration

```nix
# nix/bpf.nix

{ pkgs, lib }:

let
  llvmPackages = pkgs.llvmPackages_17;
in {
  buildBpfProgram = { name, src, ... }@args:
    pkgs.stdenv.mkDerivation ({
      inherit name src;

      nativeBuildInputs = [
        llvmPackages.clang
        pkgs.bpftools
        pkgs.linuxHeaders
      ];

      buildPhase = ''
        # Generate vmlinux.h
        bpftool btf dump file ${pkgs.linuxPackages.kernel}/lib/modules/*/build/vmlinux format c > vmlinux.h

        # Compile BPF
        clang -g -O2 -target bpf \
          -I. -I${pkgs.linuxHeaders}/include \
          -c ${name}.bpf.c -o ${name}.bpf.o

        # Generate skeleton
        bpftool gen skeleton ${name}.bpf.o > ${name}.skel.h
      '';

      installPhase = ''
        mkdir -p $out/{include,lib}
        cp ${name}.skel.h $out/include/
        cp ${name}.bpf.o $out/lib/
      '';
    } // args);
}
```

### Userspace Loader

```c
// src/lib/xdp2/bpf_loader.c

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>

#include "xdp2/bpf_loader.h"

struct xdp2_bpf_ctx {
    void *skel;                    // Skeleton object
    int prog_fd;                   // Program FD
    int ifindex;                   // Attached interface
    struct bpf_link *link;         // XDP link
};

int xdp2_bpf_load(struct xdp2_bpf_ctx **ctx, const char *prog_name)
{
    struct xdp2_bpf_ctx *c = calloc(1, sizeof(*c));
    if (!c)
        return -ENOMEM;

    // Open and load skeleton
    // (Actual code depends on generated skeleton)

    *ctx = c;
    return 0;
}

int xdp2_bpf_attach(struct xdp2_bpf_ctx *ctx, const char *ifname, int flags)
{
    int ifindex = if_nametoindex(ifname);
    if (!ifindex)
        return -errno;

    ctx->ifindex = ifindex;

    // Attach XDP program
    LIBBPF_OPTS(bpf_xdp_attach_opts, opts);

    int err = bpf_xdp_attach(ifindex, ctx->prog_fd, flags, &opts);
    if (err)
        return err;

    return 0;
}

int xdp2_bpf_detach(struct xdp2_bpf_ctx *ctx)
{
    if (ctx->ifindex) {
        bpf_xdp_detach(ctx->ifindex, 0, NULL);
        ctx->ifindex = 0;
    }
    return 0;
}

void xdp2_bpf_destroy(struct xdp2_bpf_ctx *ctx)
{
    if (!ctx)
        return;

    xdp2_bpf_detach(ctx);

    // Destroy skeleton
    // (Actual code depends on generated skeleton)

    free(ctx);
}
```

### Example: Migrated flow_tracker_simple

**Before (template-based, broken):**
```c
// samples/xdp/flow_tracker_simple/parser.c

#include "xdp2/parser.h"
#include "xdp2/parser_metadata.h"

XDP2_METADATA_TEMP_ether(ether_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_ipv4(ipv4_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_ports(ports_metadata, xdp2_metadata_all)

// ... complex macro-based setup
```

**After (direct BPF, working):**
```c
// samples/xdp/flow_tracker_simple/flow_tracker.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct flow_key {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u8 proto;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, __u64);
} flows SEC(".maps");

SEC("xdp")
int flow_tracker(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // IPv4
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u8 hdr_len = iph->ihl * 4;
    if ((void *)iph + hdr_len > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Ports
    struct {
        __be16 sport;
        __be16 dport;
    } *ports = (void *)iph + hdr_len;

    if ((void *)(ports + 1) > data_end)
        return XDP_PASS;

    // Build key
    struct flow_key key = {
        .saddr = iph->saddr,
        .daddr = iph->daddr,
        .sport = ports->sport,
        .dport = ports->dport,
        .proto = iph->protocol,
    };

    // Update counter
    __u64 *cnt = bpf_map_lookup_elem(&flows, &key);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&flows, &key, &one, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

### TLV Parsing in BPF

TLV (Type-Length-Value) parsing requires careful bounds checking:

```c
// BPF-safe TLV parsing

struct tcp_opt_timestamp {
    __u32 ts_val;
    __u32 ts_ecr;
};

static __always_inline int
parse_tcp_options(void *opt_start, void *opt_end, void *data_end,
                  struct tcp_opt_timestamp *ts_out)
{
    __u8 *opt = opt_start;

    #pragma unroll
    for (int i = 0; i < 10; i++) {  // Max 10 options
        if ((void *)opt >= opt_end || (void *)opt >= data_end)
            break;

        __u8 kind = *opt;

        if (kind == 0)  // End of options
            break;

        if (kind == 1) {  // NOP
            opt++;
            continue;
        }

        // Need at least 2 bytes for kind + length
        if ((void *)(opt + 2) > data_end || (void *)(opt + 2) > opt_end)
            break;

        __u8 len = opt[1];
        if (len < 2)
            break;

        if ((void *)(opt + len) > data_end || (void *)(opt + len) > opt_end)
            break;

        if (kind == 8 && len == 10) {  // Timestamp
            struct tcp_opt_timestamp *ts = (void *)(opt + 2);
            if ((void *)(ts + 1) <= data_end) {
                ts_out->ts_val = bpf_ntohl(ts->ts_val);
                ts_out->ts_ecr = bpf_ntohl(ts->ts_ecr);
            }
        }

        opt += len;
    }

    return 0;
}
```

---

## Risk Assessment

### Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Kernel version incompatibility | Medium | High | Use CO-RE, test on multiple kernels |
| BPF verifier rejection | Medium | Medium | Extensive testing, use known patterns |
| Performance regression | Low | Medium | Benchmark against current (userspace) |
| Build system complexity | Medium | Low | Good documentation, Nix integration |

### Migration Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Breaking existing users | Medium | High | Parallel development, deprecation period |
| Incomplete protocol coverage | Medium | Medium | Prioritize common protocols |
| Documentation gaps | Medium | Low | Document as we go |

### Compatibility Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Old kernel support | High | Medium | Document minimum versions |
| Missing BTF | Medium | Medium | Fallback to DWARF |
| libbpf API changes | Low | Low | Pin libbpf version |

---

## Appendices

### A. BPF Verifier Error Reference

Common errors and solutions:

| Error | Cause | Solution |
|-------|-------|----------|
| "stack arguments not supported" | >5 function arguments | Reduce args or inline |
| "unbounded memory access" | Missing bounds check | Add `if (ptr + size > end)` |
| "R1 invalid mem access" | Null pointer dereference | Check for NULL |
| "back-edge from insn X to Y" | Unbounded loop | Use `#pragma unroll` |
| "max stack size exceeded" | >512 bytes on stack | Reduce local variables |

### B. Kernel Version Requirements

| Feature | Minimum Kernel |
|---------|----------------|
| Basic XDP | 4.8 |
| XDP_REDIRECT | 4.14 |
| BTF | 5.2 |
| CO-RE | 5.2 |
| BPF trampolines | 5.5 |
| BPF LSM | 5.7 |
| Ring buffer | 5.8 |

### C. Tool Versions

Recommended minimum versions:

| Tool | Version | Notes |
|------|---------|-------|
| clang | 11+ | BPF target support |
| libbpf | 0.8+ | CO-RE support |
| bpftool | 5.13+ | Skeleton generation |
| pahole | 1.21+ | BTF generation |

### D. Testing Strategy

```bash
# 1. Unit test BPF loading
./test_bpf_load

# 2. Test on veth pair
ip link add veth0 type veth peer name veth1
./xdp2_test --attach veth0

# 3. Send test traffic
./send_test_packets veth1

# 4. Verify maps
bpftool map dump name flows

# 5. Cleanup
ip link del veth0
```

### E. References

1. [BPF CO-RE Reference Guide](https://nakryiko.com/posts/bpf-core-reference-guide/)
2. [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)
3. [BPF Portability and CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html)
4. [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
5. [Linux BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)

---

## Document History

| Date | Author | Changes |
|------|--------|---------|
| 2026-02-11 | Claude | Initial draft |
| 2026-02-11 | Claude | Added BPF VM architecture section explaining 5-register limit |
| 2026-02-11 | Claude | Added API evolution history showing how 3-arg became 6-arg |
| 2026-02-11 | Claude | Added 8 options for reducing args with performance analysis |
| 2026-02-11 | Claude | Added audit showing 4 of 6 params are unused (ctrl, imetadata, hdr_len) |
