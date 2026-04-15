# Lecture 10: Porting the Compiler and XDP Target -- C++ to Rust

The XDP2 compiler (Lecture 5) is a C++ tool that extracts parse graphs from C
source and generates optimized code. This lecture examines how to port it to
Rust, and how to target eBPF using Rust-native frameworks.

## 10.1 Strategy: Compiler as Artifact Producer

The compiler is a **tool** -- it reads input files and produces output
artifacts (optimized C, eBPF code, dot graphs, JSON IR). This makes it
lower-risk to port than the runtime:

- The output format does not change (still generating C or eBPF code)
- You can validate the Rust compiler's output against the C++ compiler's
  output for identical inputs
- You can port one phase at a time, mixing C++ and Rust phases

## 10.2 Phase 1: AST Extraction -- The Hardest Part

The C++ compiler uses Clang LibTooling to parse C source and extract XDP2
macro invocations from the AST
([src/tools/compiler/include/xdp2gen/ast-consumer/](../src/tools/compiler/include/xdp2gen/ast-consumer/)).
This is the hardest part to port because Rust's Clang bindings are limited.

### Four Options

| Approach | Effort | Fidelity | Dependencies |
|---|---|---|---|
| **Consume JSON IR** | Low | High | Requires C++ compiler as frontend |
| **tree-sitter** | Medium | Medium | Pure Rust, no LLVM |
| **clang-sys FFI** | High | High | Requires LLVM/Clang libs |
| **Custom macro parser** | Medium | Low | Pure Rust, fragile |

**Recommended**: Start with **JSON IR** consumption. The existing C++ compiler
already outputs JSON IR (see Lecture 5, section 5.4). Write a Rust tool that
reads this JSON and performs graph construction + code generation in Rust:

```
[C source] --C++ compiler--> [JSON IR] --Rust tool--> [output.c / .dot]
```

This decouples the hardest problem (Clang AST parsing) from the parts that
benefit most from Rust (graph algorithms, code generation).

Long-term, **tree-sitter** with a C grammar can match XDP2_* macro
invocations structurally:

```rust
// tree-sitter query to find XDP2_MAKE_PARSE_NODE invocations
let query = Query::new(c_language, r#"
    (call_expression
        function: (identifier) @fn_name
        arguments: (argument_list) @args
        (#match? @fn_name "^XDP2_MAKE_PARSE_NODE$"))
"#)?;
```

## 10.3 Phase 2: Graph Construction -- Boost Graph to petgraph

This is the most straightforward translation. The C++ code uses Boost Graph
Library ([graph.h](../src/tools/compiler/include/xdp2gen/graph.h)):

```cpp
// C++ (Boost Graph Library)
using graph_t = boost::adjacency_list<
    boost::vecS, boost::vecS, boost::directedS,
    vertex_property, edge_property>;
```

Direct `petgraph` equivalent:

```rust
use petgraph::graph::{DiGraph, NodeIndex};

type ParseGraph = DiGraph<VertexProperty, EdgeProperty>;
```

### Vertex and Edge Properties

```rust
// From graph.h vertex_property (simplified)
struct VertexProperty {
    name: String,
    parser_node: String,
    metadata: Option<String>,
    handler: Option<String>,
    table: Option<String>,
    overlay: Option<bool>,
    encap: Option<bool>,
    // ...
}

// From graph.h edge_property
struct EdgeProperty {
    macro_name: String,
    macro_value: u32,
    is_back_edge: bool,       // Encapsulation cycle
}
```

### Key Algorithm Translations

**Cycle detection** (C++: custom BFS visitor, graph.h:340--371):

```rust
// Rust (petgraph) -- much simpler
use petgraph::algo::is_cyclic_directed;

if is_cyclic_directed(&graph) {
    // Find and mark back-edges
    let mut dfs = DfsPostOrder::new(&graph, root);
    // ... mark edges that create cycles as back_edge = true
}
```

**BFS depth assignment** (C++: custom visitor, graph.h:378--412):

```rust
use petgraph::visit::Bfs;

let mut bfs = Bfs::new(&graph, root);
let mut depths: HashMap<NodeIndex, usize> = HashMap::new();
depths.insert(root, 0);

while let Some(node) = bfs.next(&graph) {
    let depth = graph.neighbors_directed(node, Incoming)
        .filter_map(|parent| depths.get(&parent))
        .max()
        .map(|d| d + 1)
        .unwrap_or(0);
    depths.insert(node, depth);
}
```

**Graphviz output** (C++: custom `dotify` function, graph.h:488--546):

```rust
use petgraph::dot::{Dot, Config};

let dot = Dot::with_attr_getters(
    &graph,
    &[Config::EdgeNoLabel],
    &|_, edge| format!("label=\"{}\"", edge.weight().macro_name),
    &|_, (_, node)| format!("label=\"{}\"", node.name),
);
println!("{}", dot);
```

### petgraph Advantages Over Boost Graph

| Feature | Boost Graph | petgraph |
|---|---|---|
| Type safety | Template-heavy, errors are cryptic | Generic, clear errors |
| Index stability | Depends on container type | `StableGraph` option |
| Visitor pattern | Required for BFS/DFS | Iterator-based (more Rust-idiomatic) |
| Serialization | Manual | `serde` support via feature flag |
| Memory safety | Manual (raw pointers possible) | Guaranteed (safe Rust) |

**Pitfall**: petgraph's default `Graph` invalidates `NodeIndex` values when
nodes are removed. If your compiler removes nodes during optimization, use
`StableGraph` instead.

## 10.4 Phase 3: Code Generation

The C++ compiler uses custom template files with `<!--(macro ...)-->` syntax
([src/templates/xdp2/](../src/templates/xdp2/)).

**Rust replacement -- Tera templates:**

```rust
use tera::{Tera, Context};

let tera = Tera::new("templates/**/*.tera")?;
let mut ctx = Context::new();
ctx.insert("parser_name", &parser.name);
ctx.insert("nodes", &nodes);

// Generate optimized C
let output = tera.render("c_def.tera", &ctx)?;
std::fs::write("output.c", output)?;
```

Tera uses Jinja2-like syntax, replacing the custom `<!--(macro)-->` system:

```
{# Tera template equivalent of c_def.template.c #}
static int {{ parser_name }}_opt_parse(
    const struct xdp2_parser *parser, void *hdr, size_t len,
    void *metadata, struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
{% for node in nodes %}
    /* Node: {{ node.name }} */
    if (parse_node == &{{ node.name }}.pn) {
        {{ node.inline_body }}
    }
{% endfor %}
}
```

Alternative: **Askama** (compile-time checked templates) for catching template
errors at build time rather than runtime.

## 10.5 The eBPF Target: Aya Framework

The current XDP target generates C code compiled by Clang to eBPF bytecode.
The **Aya** framework enables writing eBPF programs directly in Rust.

### Current C Approach (from Lecture 6)

```c
SEC("prog")
int xdp_prog(struct xdp_md *ctx) {
    struct flow_tracker_ctx *parser_ctx = xdp2_get_ctx();
    /* ... initialize, parse, flow_track ... */
    return XDP_PASS;
}
```

### Aya Rust Equivalent

```rust
use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

#[xdp]
pub fn xdp_prog(ctx: XdpContext) -> u32 {
    match process_packet(&ctx) {
        Ok(()) => xdp_action::XDP_PASS,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn process_packet(ctx: &XdpContext) -> Result<(), ParseError> {
    let data = unsafe {
        core::slice::from_raw_parts(
            ctx.data() as *const u8,
            ctx.data_end() - ctx.data(),
        )
    };
    // Parse using generated inline code (same architecture as C version)
    // ...
    Ok(())
}
```

### Aya vs libbpf-rs

| Feature | Aya | libbpf-rs |
|---|---|---|
| eBPF program language | Rust (`aya-bpf`) | C (compiled by Clang) |
| Userspace loader | Rust (`aya`) | Rust (wraps C libbpf) |
| Tail call support | Yes | Yes |
| Per-CPU maps | Yes | Yes |
| BTF support | Yes | Yes |
| Maturity | Production (Cloudflare, etc.) | Production |
| C dependency | None | Requires libbpf + clang |

**Recommendation**: Use **libbpf-rs** initially (keep generating C eBPF code,
manage from Rust userspace). Migrate to **Aya** when the generated parser code
is rewritten in Rust.

## 10.6 The Rust Kernel eBPF Ecosystem (2025--2026)

| Component | Purpose | Status |
|---|---|---|
| `aya` | Userspace eBPF loader/manager | Stable, production-ready |
| `aya-bpf` | Write eBPF programs in Rust | Stable |
| `aya-log` | Logging from eBPF to userspace | Stable |
| `bpf-linker` | LLVM-based linker for Rust eBPF | Required for `aya-bpf` |
| `libbpf-rs` | Rust bindings to libbpf | Stable |
| `vmlinux` | BTF-generated kernel type bindings | Niche but useful |
| Rust-for-Linux | Kernel modules in Rust | Separate from eBPF; different use case |

Note: **Rust-for-Linux** (kernel module support) is distinct from eBPF Rust.
XDP2's eBPF programs run in the eBPF VM, not as kernel modules, so
Rust-for-Linux is not directly relevant.

## 10.7 What to Port First

| Component | Priority | Rationale |
|---|---|---|
| Graph construction | **High** | Clean BGL -> petgraph mapping; well-tested algorithms |
| Code generation | **Medium** | Template replacement is straightforward |
| JSON IR consumption | **Medium** | Enables Rust backend without touching Clang |
| AST extraction | **Low** | Keep C++ compiler or use JSON IR bridge |
| eBPF programs | **Low** | Keep generating C until Aya integration matures |
| Protocol definitions | **Incremental** | Port one family at a time alongside runtime |

## 10.8 Architecture of a Rust XDP2 Compiler

```
xdp2-compiler-rs/
├── src/
│   ├── main.rs                 # CLI entry point (clap)
│   ├── frontend/
│   │   ├── json_ir.rs          # Parse JSON IR from C++ compiler
│   │   └── tree_sitter.rs      # Direct C source parsing (future)
│   ├── graph/
│   │   ├── types.rs            # VertexProperty, EdgeProperty
│   │   ├── construction.rs     # Build petgraph from frontend data
│   │   ├── analysis.rs         # Cycle detection, depth leveling
│   │   └── dot.rs              # Graphviz output
│   ├── codegen/
│   │   ├── c_backend.rs        # Generate optimized C parser
│   │   ├── xdp_backend.rs      # Generate eBPF C code
│   │   └── rust_backend.rs     # Generate Rust parser (future)
│   └── ir/
│       ├── types.rs            # PIR data structures
│       └── json.rs             # JSON serialization (serde)
├── templates/
│   ├── c_def.tera              # Optimized C output template
│   └── xdp_def.tera            # XDP eBPF output template
├── tests/
│   └── golden/                 # Golden test files from C++ compiler
└── Cargo.toml
```

## 10.9 Common Pitfalls and Mitigations

| Pitfall | Symptom | Mitigation |
|---|---|---|
| petgraph index invalidation | Panic on node access after removal | Use `StableGraph` or avoid node removal |
| Tera template errors at runtime | Silent wrong output | Golden tests comparing against C++ compiler output |
| Clang AST in Rust loses semantic info | Wrong type resolution | Use JSON IR bridge; accept lower fidelity |
| Aya eBPF hitting verifier limits | Program rejected by kernel | Same tail-call architecture as C; use `bpf_linker` optimizations |
| Lifetime issues with graph cross-refs | Compile errors | Use index-based references (`NodeIndex`) not Rust `&` references |
| Code gen output differs from C++ | Subtle bugs | Byte-level diff testing of generated code |

## 10.10 Exercise

Take the JSON IR output from the C++ compiler for the `flow_tracker_simple`
parser. Write a Rust program using `petgraph` and `serde_json` to:

1. Deserialize the JSON IR into Rust structs
2. Build a `petgraph::DiGraph` from the parse nodes and protocol tables
3. Run cycle detection and depth assignment
4. Generate a `.dot` file

Compare the `.dot` output against the C++ compiler's `.dot` output for the
same parser.

---

[< Lecture 9: Porting the Runtime -- C to Rust](lecture09-rust-runtime.md) | [Table of Contents](README.md) | [Lecture 11: High-Performance Parsing >](lecture11-performance.md)
