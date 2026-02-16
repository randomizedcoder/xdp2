# num_args Branch Merge Plan

**Created:** 2026-02-16
**Status:** Planning
**Goal:** Merge upstream `num_args` branch (5-arg API) with all Nix infrastructure and C++ fixes

---

## Background

### Current State

- **Working directory:** `/home/das/Downloads/xdp2`
- **Current branch:** `feature/nix-sample-tests`
- **Backup location:** `/home/das/Downloads/xdp2-backup-2026_02_16/`

### The Problem

1. Current branch has 6-arg API changes (from main's 3-arg)
2. Upstream `num_args` branch has 5-arg API (better for eBPF limits)
3. Current branch has critical Nix build fixes we must preserve
4. Need to combine: 5-arg API + Nix fixes + working samples

### Resources

- **Upstream repo:** `https://github.com/xdp2-dev/xdp2.git`
- **num_args branch clone:** `/home/das/Downloads/xdp2_num_args/xdp2` (already checked out)
- **Fork repo:** `https://github.com/randomizedcoder/xdp2`

---

## API Comparison

| Version | Extract/Handler Signature | Notes |
|---------|---------------------------|-------|
| **main (3-arg)** | `extract_*(v, hdr_len, _meta)` | Original |
| **current (6-arg)** | `extract_*(v, hdr_len, hdr_off, _meta, _frame, ctrl)` | Too many args for eBPF |
| **num_args (5-arg)** | `extract_*(v, hdr_len, _meta, frame, ctrl)` | Target - uses `xdp2_parse_hdr_offset()` helper |

---

## Files Analysis

### Files That Will NOT Conflict (safe to copy/cherry-pick)

These files are either new or only modified in our branch, not in `num_args`:

#### New Files (Nix Infrastructure)
```
nix/derivation.nix
nix/devshell.nix
nix/llvm.nix
nix/packages.nix
nix/tests/default.nix
nix/tests/simple-parser.nix
nix/tests/simple-parser-debug.nix
nix/tests/offset-parser.nix
nix/tests/ports-parser.nix
nix/tests/flow-tracker-combo.nix
nix/tests/xdp-build.nix
nix/patches/01-nix-clang-system-includes.patch (may be obsolete)
nix/patches/02-tentative-definition-null-check.patch
flake.nix
```

#### New Files (C++ Compiler Fixes)
```
src/tools/compiler/include/xdp2gen/assert.h
src/tools/compiler/include/xdp2gen/clang-tool-config.h
src/tools/compiler/src/clang-tool-config.cpp
```

#### Modified Files (C++ Compiler - no upstream changes)
```
src/tools/compiler/src/main.cpp
  - Uses clang_tool_config::from_environment() in two places
  - Uses apply_config() for both ClangTool instances
  - Fix for std::optional crash in parse_dump (~line 1405)

src/tools/compiler/include/xdp2gen/ast-consumer/graph_consumer.h
  - Added "proto_def" to is_cur_field_of_interest check (line 595)
  - CRITICAL FIX: enables parser_node population for graph vertices

src/tools/compiler/src/template.cpp
  - Minor changes (10 lines added)

src/tools/compiler/Makefile
  - Added clang-tool-config.cpp to build
```

#### Documentation (all new)
```
documentation/cpp-style-guide.md
documentation/nix/clang-tool-refactor-plan.md
documentation/nix/clang-tool-refactor-log.md
documentation/nix/optimized_parser_extraction_defect.md
documentation/nix/phase6_segfault_defect.md
documentation/nix/sample-tests-design.md
documentation/nix/sample-tests-expansion-log.md
documentation/nix/sample-tests-expansion-plan.md
documentation/nix/xdp-bpf-compatibility-defect.md
documentation/nix/defect-sample-api-mismatch.md
documentation/nix/fix-plan-sample-api.md
documentation/nix/flake_comparison_bpftrace_bcc.md
documentation/nix/modern-bpf-architecture-design.md
documentation/nix/nix_refactor_log.md
```

### Files That WILL Conflict (need manual resolution)

Both branches modified these files:

```
samples/parser/offset_parser/parser.c
samples/parser/ports_parser/parser.c
samples/parser/simple_parser/parser_notmpl.c
samples/parser/simple_parser/run_parser.h
samples/xdp/flow_tracker_combo/flow_parser.c
src/include/xdp2/parser.h
src/include/xdp2/bpf.h
src/include/xdp2/utility.h
```

**Resolution Strategy:** Use `num_args` versions as base, they have the correct 5-arg API.

---

## Execution Plan

### Step 1: Preserve Current Work

**Goal:** Commit all current changes to a branch named `nix_progress`

```bash
cd /home/das/Downloads/xdp2

# Rename current branch to nix_progress
git branch -m feature/nix-sample-tests nix_progress

# Stage all changes
git add -A

# Commit with descriptive message
git commit -m "$(cat <<'EOF'
WIP: Nix infrastructure + 6-arg API samples

This commit preserves all Nix build infrastructure and C++ compiler
fixes developed for building xdp2 on NixOS.

Key changes:
- ClangTool configuration abstraction (clang-tool-config.h/cpp)
- Assertion infrastructure (assert.h)
- proto_def fix in graph_consumer.h (enables optimized parser)
- std::optional crash fix in main.cpp
- Complete Nix build system (flake.nix, nix/*.nix)
- Nix test infrastructure (nix/tests/*.nix)
- C++ style guide documentation

Note: Samples use 6-arg API which is incompatible with eBPF.
This branch is preserved for reference; the num_args_and_nix
branch will have the correct 5-arg API.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"

# Verify commit
git log -1 --stat
```

**Checkpoint:** Verify the commit saved everything.

---

### Step 2: Create New Branch and Merge num_args

**Goal:** Create `num_args_and_nix` branch with upstream 5-arg API

```bash
cd /home/das/Downloads/xdp2

# Go back to main
git checkout main

# Create new branch
git checkout -b num_args_and_nix

# Add upstream remote (if not already added)
git remote add upstream https://github.com/xdp2-dev/xdp2.git || true

# Fetch upstream
git fetch upstream

# Merge num_args branch
git merge upstream/num_args -m "Merge upstream num_args branch (5-arg API)"
```

**Checkpoint:** Verify merge succeeded and we have 5-arg API.

---

### Step 3: Apply Nix Infrastructure

**Goal:** Copy all Nix-related files from nix_progress

```bash
cd /home/das/Downloads/xdp2

# Copy entire nix/ directory
git checkout nix_progress -- nix/

# Copy flake.nix
git checkout nix_progress -- flake.nix

# Copy .gitignore changes
git checkout nix_progress -- .gitignore

# Stage and commit
git add nix/ flake.nix .gitignore
git commit -m "$(cat <<'EOF'
nix: Add complete Nix build infrastructure

- flake.nix with xdp2 package and devshell
- nix/derivation.nix for stdenv.mkDerivation
- nix/devshell.nix for development environment
- nix/llvm.nix for LLVM/Clang configuration
- nix/packages.nix for package definitions
- nix/tests/*.nix for integration tests
- nix/patches/ for build patches

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

**Checkpoint:** Verify nix/ directory is in place.

---

### Step 4: Apply C++ Compiler Fixes

**Goal:** Cherry-pick the critical C++ fixes that enable Nix builds

```bash
cd /home/das/Downloads/xdp2

# Copy new files
git checkout nix_progress -- src/tools/compiler/include/xdp2gen/assert.h
git checkout nix_progress -- src/tools/compiler/include/xdp2gen/clang-tool-config.h
git checkout nix_progress -- src/tools/compiler/src/clang-tool-config.cpp

# Copy modified files
git checkout nix_progress -- src/tools/compiler/src/main.cpp
git checkout nix_progress -- src/tools/compiler/src/template.cpp
git checkout nix_progress -- src/tools/compiler/Makefile
git checkout nix_progress -- src/tools/compiler/include/xdp2gen/ast-consumer/graph_consumer.h
git checkout nix_progress -- src/tools/compiler/include/xdp2gen/processing_utilities.h
git checkout nix_progress -- src/tools/compiler/include/xdp2gen/program-options/log_handler.h

# Stage and commit
git add src/tools/compiler/
git commit -m "$(cat <<'EOF'
compiler: Add ClangTool configuration for Nix builds

Key fixes:
- clang-tool-config.h/cpp: Unified ClangTool configuration
  - Reads XDP2_C_INCLUDE_PATH, XDP2_GLIBC_INCLUDE_PATH,
    XDP2_LINUX_HEADERS_PATH from environment
  - Applies -isystem flags to both ClangTool instances

- graph_consumer.h: Add "proto_def" to is_cur_field_of_interest
  - Fixes optimized parser by populating parser_node field
  - Without this, graph edges are not created correctly

- main.cpp: Fix std::optional crash in parse_dump
  - Check next_proto_data.has_value() before accessing

- assert.h: Assertion infrastructure with Boost.Assert wrappers
  - XDP2_REQUIRE_NOT_NULL, XDP2_REQUIRE, XDP2_ENSURE macros
  - Controlled by -DXDP2_ENABLE_ASSERTS=1

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

**Checkpoint:** Verify compiler changes are in place.

---

### Step 5: Apply Documentation

**Goal:** Copy documentation files

```bash
cd /home/das/Downloads/xdp2

# Copy documentation
git checkout nix_progress -- documentation/

# Stage and commit
git add documentation/
git commit -m "$(cat <<'EOF'
docs: Add C++ style guide and Nix documentation

- documentation/cpp-style-guide.md: Coding conventions
- documentation/nix/: Nix build documentation and defect logs

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

**Checkpoint:** Verify documentation is in place.

---

### Step 6: Update Samples for 5-arg API

**Goal:** Ensure samples work with the 5-arg API from num_args

The `num_args` branch already updated the samples. We need to verify they work
and potentially add any Makefile improvements (like rpath settings).

```bash
cd /home/das/Downloads/xdp2

# Check if samples from num_args are correct
# (they should be, since we merged num_args in Step 2)

# Copy any Makefile improvements from nix_progress (rpath, etc.)
# Review and selectively apply:
git diff nix_progress -- samples/parser/simple_parser/Makefile
git diff nix_progress -- samples/parser/offset_parser/Makefile
git diff nix_progress -- samples/parser/ports_parser/Makefile
git diff nix_progress -- samples/xdp/flow_tracker_combo/Makefile
```

**Manual Review Required:** Compare Makefiles and apply useful improvements.

---

### Step 7: Test the Build

**Goal:** Verify everything builds and tests pass

```bash
cd /home/das/Downloads/xdp2

# Test Nix build
nix build .#xdp2

# Run tests
nix build .#tests.simple-parser
./result/bin/xdp2-test-simple-parser

# Test other samples
nix build .#tests.offset-parser
nix build .#tests.ports-parser
```

**Checkpoint:** All tests pass.

---

### Step 8: Cleanup and Push

**Goal:** Push branches to remote

```bash
cd /home/das/Downloads/xdp2

# Push preserved branch
git push -u origin nix_progress

# Push new combined branch
git push -u origin num_args_and_nix
```

---

## Rollback Plan

If anything goes wrong:

1. **Backup exists at:** `/home/das/Downloads/xdp2-backup-2026_02_16/`
2. **Original branch preserved as:** `nix_progress`
3. **Can always:** `git checkout nix_progress` to return to current state

---

## Checklist

- [ ] Step 1: Commit current work to `nix_progress`
- [ ] Step 2: Create `num_args_and_nix` and merge upstream
- [ ] Step 3: Apply Nix infrastructure
- [ ] Step 4: Apply C++ compiler fixes
- [ ] Step 5: Apply documentation
- [ ] Step 6: Update/verify samples
- [ ] Step 7: Test builds
- [ ] Step 8: Push branches

---

## Notes

- The `proto_def` fix in `graph_consumer.h` is critical - without it, the optimized parser fails
- The ClangTool config ensures both ClangTool instances get system include paths
- The 5-arg API uses `xdp2_parse_hdr_offset(v, ctrl)` instead of passing `hdr_off` directly
- eBPF has a limit of 5 arguments for BPF helper functions, hence the API change
