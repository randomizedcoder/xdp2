# nix/compiler-verify.nix
#
# Compiler verification framework — compare C++ and Rust xdp2-compiler output.
#
# Extracts JSON IR and DOT graphs from the C++ compiler for each XDP sample,
# feeds them through the Rust compiler, and compares the results.
#
# Targets:
#   nix build .#compiler-ir-extract      — extract JSON IR + DOT from C++ compiler
#   nix build .#compiler-rust-generate   — generate Rust DOT + JSON from C++ IR
#   nix build .#compiler-verify-json     — compare C++ vs Rust JSON (primary)
#   nix build .#compiler-verify-dot      — compare C++ vs Rust DOT topology
#   nix build .#compiler-verify-all      — aggregate all verification results
#
# Architecture:
#   parser.c ──[C++ xdp2-compiler]──→ cpp.json, cpp.dot
#                                          │
#                    ┌─────────────────────┘
#                    ▼
#   cpp.json ──[Rust xdp2-rs-compiler]──→ rust.json, rust.dot
#                                          │
#                    ┌─────────────────────┘
#                    ▼
#   diff cpp.json rust.json   (primary: JSON roundtrip fidelity)
#   diff cpp.dot  rust.dot    (secondary: graph topology)
#

{ pkgs
, xdp2        # The pre-built xdp2 package (provides C++ xdp2-compiler)
, xdp2Rs      # Rust xdp2-rs build (provides xdp2-rs-compiler binary)
}:

let
  # Import LLVM configuration — must match what xdp2 was built with
  llvmConfig = import ./llvm.nix { inherit pkgs; lib = pkgs.lib; llvmVersion = 18; };
  llvmPackages = llvmConfig.llvmPackages;

  # Use unwrapped clang for BPF compilation environment
  bpfClang = llvmPackages.clang-unwrapped;

  # XDP sample directories to test
  samples = [ "flow_tracker_simple" "flow_tracker_combo" "flow_tracker_tlvs" "flow_tracker_tmpl" ];
  samplesSrc = ../samples/xdp;

  # Shared environment setup for the C++ compiler (matches nix/xdp-samples.nix)
  cppCompilerEnv = ''
    export XDP2DIR="${xdp2}"
    export INCDIR="${xdp2}/include"
    export BINDIR="${xdp2}/bin"
    export LIBDIR="${xdp2}/lib"

    # Environment variables needed by xdp2-compiler (uses libclang internally)
    export XDP2_CLANG_VERSION="${llvmConfig.version}"
    export XDP2_CLANG_RESOURCE_PATH="${llvmConfig.paths.clangResourceDir}"
    export XDP2_C_INCLUDE_PATH="${llvmConfig.paths.clangResourceDir}/include"
    export XDP2_GLIBC_INCLUDE_PATH="${pkgs.stdenv.cc.libc.dev}/include"
    export XDP2_LINUX_HEADERS_PATH="${pkgs.linuxHeaders}/include"

    # Library path for xdp2-compiler (needs libclang, LLVM, Boost)
    export LD_LIBRARY_PATH="${llvmPackages.llvm.lib}/lib:${llvmPackages.libclang.lib}/lib:${pkgs.boost}/lib"

    # Include paths for C compilation (parser.c → parser.o)
    export CFLAGS="-I${xdp2}/include"
    CFLAGS="$CFLAGS -I${llvmConfig.paths.clangResourceDir}/include"
    CFLAGS="$CFLAGS -I${pkgs.stdenv.cc.libc.dev}/include"
    CFLAGS="$CFLAGS -I${pkgs.linuxHeaders}/include"
  '';

in
{
  # ── Phase 1: Extract JSON IR + DOT from C++ compiler ─────────────
  ir-extract = pkgs.runCommand "compiler-ir-extract" {
    nativeBuildInputs = [
      pkgs.gnumake
      bpfClang
      xdp2
    ];
    buildInputs = [
      pkgs.linuxHeaders
    ];
  } ''
    ${cppCompilerEnv}

    mkdir -p $out/cpp

    echo "=== Extracting JSON IR and DOT from C++ xdp2-compiler ==="

    passed=0
    failed=0

    for sample in ${builtins.concatStringsSep " " samples}; do
      sampleDir="${samplesSrc}/$sample"
      if [ ! -d "$sampleDir" ]; then
        echo "SKIP: $sample (directory not found)"
        continue
      fi

      echo ""
      echo "--- $sample ---"

      # Copy sample to writable directory (compiler may create temp files)
      workdir=$(mktemp -d)
      cp -r "$sampleDir"/* "$workdir/"
      cd "$workdir"

      # Step 1: Compile parser.c to parser.o (needed by xdp2-compiler)
      if ! ${bpfClang}/bin/clang $CFLAGS -g -O2 -c -o parser.o parser.c 2>&1; then
        echo "  FAIL: parser.o compilation failed"
        failed=$((failed + 1))
        continue
      fi

      # Step 2: Extract JSON IR
      if $BINDIR/xdp2-compiler -I$INCDIR -i parser.c -o $out/cpp/$sample.json 2>&1; then
        echo "  OK: $sample.json"
      else
        echo "  FAIL: JSON extraction failed"
        failed=$((failed + 1))
        continue
      fi

      # Step 3: Extract DOT graph
      if $BINDIR/xdp2-compiler -I$INCDIR -i parser.c -o $out/cpp/$sample.dot 2>&1; then
        echo "  OK: $sample.dot"
      else
        echo "  WARN: DOT extraction failed (non-fatal)"
      fi

      passed=$((passed + 1))
    done

    echo ""
    echo "=== IR Extract Summary ==="
    echo "Passed: $passed"
    echo "Failed: $failed"
    echo "Total:  $((passed + failed))"

    # Create summary file
    echo "passed=$passed" > $out/summary.txt
    echo "failed=$failed" >> $out/summary.txt
  '';

  # ── Phase 2: Generate Rust output from C++ JSON IR ───────────────
  rust-generate = let irExtract = (import ./compiler-verify.nix {
    inherit pkgs xdp2 xdp2Rs;
  }).ir-extract; in pkgs.runCommand "compiler-rust-generate" {
    nativeBuildInputs = [
      xdp2Rs.build  # Provides xdp2-rs-compiler binary
    ];
  } ''
    mkdir -p $out/rust

    echo "=== Generating Rust output from C++ JSON IR ==="

    passed=0
    failed=0

    for sample in ${builtins.concatStringsSep " " samples}; do
      cppJson="${irExtract}/cpp/$sample.json"

      if [ ! -f "$cppJson" ]; then
        echo "SKIP: $sample (no C++ JSON found)"
        continue
      fi

      echo ""
      echo "--- $sample ---"

      # Run Rust compiler with --compat flag to normalize C++ JSON
      if xdp2-rs-compiler \
          --compat \
          --input "$cppJson" \
          --output-json "$out/rust/$sample.json" \
          --output-dot "$out/rust/$sample.dot" 2>&1; then
        echo "  OK: $sample.json + $sample.dot"
        passed=$((passed + 1))
      else
        echo "  FAIL: Rust compiler failed on $sample"
        failed=$((failed + 1))
      fi
    done

    echo ""
    echo "=== Rust Generate Summary ==="
    echo "Passed: $passed"
    echo "Failed: $failed"

    echo "passed=$passed" > $out/summary.txt
    echo "failed=$failed" >> $out/summary.txt
  '';

  # ── Phase 3a: Compare JSON IR (primary verification) ─────────────
  verify-json = let
    irExtract = (import ./compiler-verify.nix { inherit pkgs xdp2 xdp2Rs; }).ir-extract;
    rustGen = (import ./compiler-verify.nix { inherit pkgs xdp2 xdp2Rs; }).rust-generate;
  in pkgs.runCommand "compiler-verify-json" {
    nativeBuildInputs = [ pkgs.jq pkgs.diffutils ];
  } ''
    mkdir -p $out/diffs

    echo "=== JSON IR Comparison: C++ vs Rust ==="

    passed=0
    failed=0
    skipped=0

    for sample in ${builtins.concatStringsSep " " samples}; do
      cppJson="${irExtract}/cpp/$sample.json"
      rustJson="${rustGen}/rust/$sample.json"

      if [ ! -f "$cppJson" ] || [ ! -f "$rustJson" ]; then
        echo "SKIP: $sample (missing JSON)"
        skipped=$((skipped + 1))
        continue
      fi

      echo ""
      echo "--- $sample ---"

      # Normalize C++ JSON: sort keys, strip fields Rust doesn't model
      jq -S '
        # Strip top-level fields Rust does not model
        del(.metadata, .counters) |
        # Strip per-node fields Rust does not model
        (.["parse-nodes"] // []) |= [.[] | del(
          .metadata,
          ."counter-actions",
          ."cond-exprs",
          ."next-node"
        )] |
        # Normalize parsers: strip file_name
        (.parsers // []) |= [.[] | del(.file_name)]
      ' "$cppJson" > /tmp/cpp_norm.json 2>/dev/null || true

      # Normalize Rust JSON: sort keys, strip null values for cleaner diff
      jq -S '
        # Remove null values recursively for cleaner comparison
        walk(if type == "object" then with_entries(select(.value != null)) else . end)
      ' "$rustJson" > /tmp/rust_norm.json 2>/dev/null || true

      # Compare
      if diff -u /tmp/cpp_norm.json /tmp/rust_norm.json > "$out/diffs/$sample.diff" 2>&1; then
        echo "  PASS: JSON matches"
        passed=$((passed + 1))
      else
        echo "  DIFF: JSON differences found (see $out/diffs/$sample.diff)"
        # Show first 20 lines of diff
        head -20 "$out/diffs/$sample.diff" | sed 's/^/    /'
        failed=$((failed + 1))
      fi
    done

    echo ""
    echo "=== JSON Verification Summary ==="
    echo "Passed:  $passed"
    echo "Failed:  $failed"
    echo "Skipped: $skipped"
    echo "Total:   $((passed + failed + skipped))"

    cat > $out/summary.txt << EOF
    passed=$passed
    failed=$failed
    skipped=$skipped
    EOF
  '';

  # ── Phase 3b: Compare DOT graph topology ─────────────────────────
  verify-dot = let
    irExtract = (import ./compiler-verify.nix { inherit pkgs xdp2 xdp2Rs; }).ir-extract;
    rustGen = (import ./compiler-verify.nix { inherit pkgs xdp2 xdp2Rs; }).rust-generate;
  in pkgs.runCommand "compiler-verify-dot" {
    nativeBuildInputs = [ pkgs.gnugrep pkgs.gnused pkgs.coreutils pkgs.diffutils ];
  } ''
    mkdir -p $out/diffs

    echo "=== DOT Graph Topology Comparison: C++ vs Rust ==="

    passed=0
    failed=0
    skipped=0

    for sample in ${builtins.concatStringsSep " " samples}; do
      cppDot="${irExtract}/cpp/$sample.dot"
      rustDot="${rustGen}/rust/$sample.dot"

      if [ ! -f "$cppDot" ] || [ ! -f "$rustDot" ]; then
        echo "SKIP: $sample (missing DOT)"
        skipped=$((skipped + 1))
        continue
      fi

      echo ""
      echo "--- $sample ---"

      # Extract canonical node set (node names from labels)
      grep -oP 'label="[^"]*"' "$cppDot" | sort > /tmp/cpp_nodes.txt 2>/dev/null || true
      grep -oP 'label="[^"]*"' "$rustDot" | sort > /tmp/rust_nodes.txt 2>/dev/null || true

      # Extract canonical edge set (source -> target with label)
      grep -E '\->' "$cppDot" | sed 's/^[[:space:]]*//' | sort > /tmp/cpp_edges.txt 2>/dev/null || true
      grep -E '\->' "$rustDot" | sed 's/^[[:space:]]*//' | sort > /tmp/rust_edges.txt 2>/dev/null || true

      # Compare nodes
      node_diff=""
      if ! diff -u /tmp/cpp_nodes.txt /tmp/rust_nodes.txt > /tmp/node_diff.txt 2>&1; then
        node_diff="nodes differ"
      fi

      # Compare edges
      edge_diff=""
      if ! diff -u /tmp/cpp_edges.txt /tmp/rust_edges.txt > /tmp/edge_diff.txt 2>&1; then
        edge_diff="edges differ"
      fi

      if [ -z "$node_diff" ] && [ -z "$edge_diff" ]; then
        echo "  PASS: Graph topology matches"
        echo "  Nodes: $(wc -l < /tmp/cpp_nodes.txt) | Edges: $(wc -l < /tmp/cpp_edges.txt)"
        passed=$((passed + 1))
      else
        echo "  DIFF: $node_diff $edge_diff"
        {
          echo "=== $sample NODE DIFF ==="
          cat /tmp/node_diff.txt
          echo ""
          echo "=== $sample EDGE DIFF ==="
          cat /tmp/edge_diff.txt
        } > "$out/diffs/$sample.diff"
        # Show summary
        cpp_nodes=$(wc -l < /tmp/cpp_nodes.txt)
        rust_nodes=$(wc -l < /tmp/rust_nodes.txt)
        cpp_edges=$(wc -l < /tmp/cpp_edges.txt)
        rust_edges=$(wc -l < /tmp/rust_edges.txt)
        echo "  C++ nodes: $cpp_nodes, Rust nodes: $rust_nodes"
        echo "  C++ edges: $cpp_edges, Rust edges: $rust_edges"
        failed=$((failed + 1))
      fi
    done

    echo ""
    echo "=== DOT Verification Summary ==="
    echo "Passed:  $passed"
    echo "Failed:  $failed"
    echo "Skipped: $skipped"
    echo "Total:   $((passed + failed + skipped))"

    cat > $out/summary.txt << EOF
    passed=$passed
    failed=$failed
    skipped=$skipped
    EOF
  '';

  # ── Aggregate: run all verifications ─────────────────────────────
  verify-all = let
    self = import ./compiler-verify.nix { inherit pkgs xdp2 xdp2Rs; };
  in pkgs.runCommand "compiler-verify-all" {
    nativeBuildInputs = [ pkgs.coreutils ];
  } ''
    mkdir -p $out

    echo "============================================"
    echo "  XDP2 Compiler Verification Report"
    echo "============================================"
    echo ""

    # Collect results from each phase
    echo "--- IR Extract ---"
    cat "${self.ir-extract}/summary.txt" 2>/dev/null || echo "  (not available)"
    echo ""

    echo "--- Rust Generate ---"
    cat "${self.rust-generate}/summary.txt" 2>/dev/null || echo "  (not available)"
    echo ""

    echo "--- JSON Comparison ---"
    cat "${self.verify-json}/summary.txt" 2>/dev/null || echo "  (not available)"
    echo ""

    echo "--- DOT Comparison ---"
    cat "${self.verify-dot}/summary.txt" 2>/dev/null || echo "  (not available)"
    echo ""

    echo "============================================"

    # Copy all diffs for inspection
    mkdir -p $out/json-diffs $out/dot-diffs
    cp -r "${self.verify-json}/diffs"/* $out/json-diffs/ 2>/dev/null || true
    cp -r "${self.verify-dot}/diffs"/* $out/dot-diffs/ 2>/dev/null || true

    # Copy raw outputs for manual inspection
    mkdir -p $out/cpp $out/rust
    cp -r "${self.ir-extract}/cpp"/* $out/cpp/ 2>/dev/null || true
    cp -r "${self.rust-generate}/rust"/* $out/rust/ 2>/dev/null || true

    echo "Done — see $out/ for full results"
  '';
}
