# Optimized Parser Proto Table Extraction Defect

## Executive Summary

The xdp2-compiler's optimized parser generation (`-O` flag) fails on Nix builds because the `extract_struct_constants` function creates a ClangTool with incomplete configuration. This causes the proto table consumer to see incomplete array types and miss table definitions, resulting in generated parsers that output "Unknown addr type 0" instead of properly routing protocols.

**Status:** Root cause identified, fix requires architectural changes
**Impact:** High - Optimized parser is non-functional on Nix
**Affected:** All Nix builds using `nix build .#xdp2` or the dev shell

---

## Problem Statement

When running the simple_parser sample with the `-O` (optimized) flag:

```bash
# Basic mode works correctly
./parser_notmpl data/pcaps/tcp_ipv6.pcap
# Output: IPv6: ::1:51648->::1:631 ...

# Optimized mode fails
./parser_notmpl -O data/pcaps/tcp_ipv6.pcap
# Output: Unknown addr type 0 ...
```

The optimized parser should produce identical protocol routing to the basic parser, but instead fails to identify IPv6 packets because the protocol routing switch statements are missing from the generated code.

---

## Technical Background

### How xdp2-compiler Works

The xdp2-compiler generates optimized parser code by:

1. **Graph Consumer** - Parses the source file to build a graph of parse nodes
2. **Proto Table Consumer** - Extracts protocol routing tables (maps protocol values to parse nodes)
3. **Code Generation** - Uses the graph and tables to generate switch statements for protocol routing

The protocol tables (`ether_table`, `ip_table`, etc.) define how to route packets based on protocol values (e.g., `ETH_P_IP` → `ipv4_node`).

### The ClangTool Configuration Problem

The xdp2-compiler creates **two separate ClangTool instances**:

1. **First ClangTool** (in `create_clang_tool`, line ~194):
   - Used by the graph consumer
   - Receives `-resource-dir` argument
   - Receives `-isystem` flags for system headers (via patch `01-nix-clang-system-includes.patch`)

2. **Second ClangTool** (in `extract_struct_constants`, line ~1632):
   - Used by proto table, proto node, and flag fields consumers
   - Only receives `-resource-dir` (after our fix)
   - **Missing**: `-isystem` flags for linux headers, glibc, clang builtins

This configuration mismatch causes the second ClangTool to parse the source file with incomplete header resolution.

---

## Debugging Infrastructure

### Debug Test Target

A dedicated Nix test target was created to diagnose the issue:

```bash
nix build .#tests.simple-parser-debug
./result-debug/bin/xdp2-test-simple-parser-debug
```

This test:
1. Runs xdp2-compiler with `--verbose` flag
2. Compiles and runs both basic and optimized parsers
3. Saves all output to `./debug-output/` directory

### Debug Output Files

| File | Purpose |
|------|---------|
| `compiler-verbose.txt` | Full xdp2-compiler verbose output |
| `proto-tables.txt` | Extracted proto table consumer messages |
| `graph.txt` | Graph building output |
| `analysis.txt` | Generated file analysis (line counts, switch statements) |
| `comparison.txt` | Basic vs optimized parser output comparison |
| `parser_notmpl.p.c` | The generated parser source code |

### Debug Instrumentation Added

The following debug output was added to `proto-tables.h`:

```cpp
// Log ALL VarDecls containing "table" in name or type
if (name.find("table") != std::string::npos ||
    type.find("table") != std::string::npos) {
    plog::log(std::cout)
        << "[proto-tables-all] VarDecl: " << name
        << " type=" << type
        << " hasInit=" << (var_decl->hasInit() ? "yes" : "no")
        << " isDefinition=" << (var_decl->isThisDeclarationADefinition() ==
            clang::VarDecl::Definition ? "yes" : "no")
        << std::endl;
}

// Log when table types are found
if (is_type_some_table) {
    plog::log(std::cout)
        << "[proto-tables] Found table VarDecl: "
        << var_decl->getNameAsString()
        << " type=" << type
        << " hasInit=" << (var_decl->hasInit() ? "yes" : "no")
        << " stmtClass=" << (var_decl->hasInit() && var_decl->getInit()
            ? var_decl->getInit()->getStmtClassName() : "N/A")
        << std::endl;
}
```

Debug output was also added to `main.cpp` to trace ClangTool configuration:

```cpp
// In create_clang_tool:
plog::log(std::cout) << "[create_clang_tool] Resource dir from macro: "
    << XDP2_STRINGIFY(XDP2_CLANG_RESOURCE_PATH) << std::endl;

// In extract_struct_constants:
plog::log(std::cout) << "[nix-fix] Adding resource-dir: "
    << XDP2_STRINGIFY(XDP2_CLANG_RESOURCE_PATH) << std::endl;
```

---

## Root Cause Analysis

### Observation 1: Array Types Differ Between ClangTools

**First ClangTool (graph consumer)** sees complete types:
```
Decl name: __ether_table
 == Var
type |const struct xdp2_proto_table_entry[2]|
 TYPE DECL: const struct xdp2_proto_table_entry[2]
```

**Second ClangTool (proto table consumer)** sees incomplete types:
```
[proto-tables-all] VarDecl: __ether_table type=const struct xdp2_proto_table_entry[] hasInit=no isDefinition=no
```

The array size `[2]` vs `[]` is the key difference. Without the size, clang treats this as an incomplete type.

### Observation 2: hasInit() Returns False for Actual Definitions

The proto table consumer sees all table definitions with `hasInit=no`:

```
[proto-tables-all] VarDecl: ether_table type=const struct xdp2_proto_table hasInit=no isDefinition=no
[proto-tables-all] VarDecl: ip_table type=const struct xdp2_proto_table hasInit=no isDefinition=no
[proto-tables-all] VarDecl: __ether_table type=const struct xdp2_proto_table_entry[] hasInit=no isDefinition=no
[proto-tables-all] VarDecl: __tcp_tlv_table type=const struct xdp2_proto_tlvs_table_entry[1] hasInit=yes isDefinition=yes
```

Note that `tcp_tlv_table` works correctly (`hasInit=yes`), but `ether_table` and `ip_table` do not.

### Observation 3: tcp_tlv_table Works Because It Uses Different Macros

The tables are defined using these macros in `parser_notmpl.c`:

```c
// Uses __cpu_to_be16() macro from Linux headers
XDP2_MAKE_PROTO_TABLE(ether_table,
    ( __cpu_to_be16(ETH_P_IP), ipv4_node ),
    ( __cpu_to_be16(ETH_P_IPV6), ipv6_node )
);

// Uses simple integer constants
XDP2_MAKE_TLV_TABLE(tcp_tlv_table,
    ( TCPOPT_TIMESTAMP, tcp_opt_timestamp_node )
);
```

The `__cpu_to_be16()` macro requires Linux kernel headers to resolve. Without the `-isystem` flag pointing to linux headers, clang cannot evaluate the initializer.

### Observation 4: System Include Paths Are Missing

The first ClangTool receives these via `01-nix-clang-system-includes.patch`:

```cpp
const char* linux_headers = getenv("XDP2_LINUX_HEADERS_PATH");
if (linux_headers) {
    Tool.appendArgumentsAdjuster(clang::tooling::getInsertArgumentAdjuster(
        {"-isystem", linux_headers},
        clang::tooling::ArgumentInsertPosition::BEGIN));
}
```

The second ClangTool in `extract_struct_constants` does NOT have this code.

---

## Attempted Fix and Complications

### Fix Attempted

Added the same system include path logic to `extract_struct_constants`:

```cpp
const char* clang_include = getenv("XDP2_C_INCLUDE_PATH");
const char* glibc_include = getenv("XDP2_GLIBC_INCLUDE_PATH");
const char* linux_headers = getenv("XDP2_LINUX_HEADERS_PATH");
if (linux_headers) {
    Tool.appendArgumentsAdjuster(clang::tooling::getInsertArgumentAdjuster(
        {"-isystem", linux_headers},
        clang::tooling::ArgumentInsertPosition::BEGIN));
}
// ... similar for glibc_include and clang_include
```

### Complication: Build Failure in Other Samples

Adding complete header paths exposed a latent bug in other sample parsers:

```
/nix/store/.../optional:1172: constexpr _Tp* std::optional<_Tp>::operator->()
[with _Tp = xdp2gen::llvm::packet_buffer_offset_masked_multiplied]:
Assertion 'this->_M_is_engaged()' failed.
make[2]: *** [Makefile:47: parser.json] Aborted (core dumped)
```

This assertion failure occurs in the `parse_dump` sample (not `simple_parser`), suggesting that more complete header resolution exposes pre-existing issues in metadata extraction code.

---

## Generated Code Comparison

### Working Parser (Ubuntu, ~676 lines)

Contains 4 switch statements for protocol routing:

```c
switch (type) {
    case 0x0800: // ETH_P_IP
        return parse_ipv4_node(...);
    case 0x86dd: // ETH_P_IPV6
        return parse_ipv6_node(...);
    default:
        return XDP2_STOP_UNKNOWN_PROTO;
}
```

### Broken Parser (Nix, ~601 lines)

Contains only 1 switch statement, missing protocol routing:

```c
switch (type) {
    // No cases - falls through to default
    default:
        return XDP2_STOP_UNKNOWN_PROTO;  // "Unknown addr type 0"
}
```

---

## Recommended Next Steps

### Option A: Refactor ClangTool Creation (Recommended)

**Goal:** Ensure both ClangTool instances use identical configuration.

**Implementation:**
1. Create a shared helper function `configure_clang_tool(ClangTool& tool)` that adds:
   - Resource directory (`-resource-dir`)
   - System include paths (`-isystem` for linux headers, glibc, clang builtins)

2. Call this helper from both `create_clang_tool` and `extract_struct_constants`

3. Remove duplicate code from `01-nix-clang-system-includes.patch`

**Estimated changes:**
- `src/tools/compiler/src/main.cpp`: ~30 lines refactored
- `nix/patches/01-nix-clang-system-includes.patch`: Updated to match

**Risk:** Low - This is a straightforward refactor

### Option B: Investigate and Fix the Optional Assertion

**Goal:** Understand why complete header resolution causes assertion failures.

**Investigation steps:**
1. Identify which sample triggers the failure (`parse_dump` based on error output)
2. Add debug output to `xdp2gen::llvm::packet_buffer_offset_masked_multiplied`
3. Determine what metadata is missing when the optional is accessed
4. Fix the root cause (likely a missing null check or incorrect assumption)

**Risk:** Medium - May uncover deeper issues in metadata extraction

### Option C: Hybrid Approach (Recommended Path Forward)

1. **Phase 1:** Implement Option A (refactor ClangTool creation)
2. **Phase 2:** Add a conditional to skip problematic samples during initial testing
3. **Phase 3:** Implement Option B to fix the underlying assertion issue
4. **Phase 4:** Remove the sample skip and verify all samples work

---

## Files Modified During Investigation

| File | Changes |
|------|---------|
| `src/tools/compiler/src/main.cpp` | Added debug output, attempted system include fix |
| `src/tools/compiler/include/xdp2gen/ast-consumer/proto-tables.h` | Added debug output for VarDecl processing, changed to iterate all decls in group |
| `src/tools/compiler/include/xdp2gen/ast-consumer/graph_consumer.h` | Added null check (from patch) |
| `nix/derivation.nix` | Temporarily disabled patch for debugging |
| `nix/tests/simple-parser-debug.nix` | Created debug test target |
| `nix/tests/default.nix` | Added simple-parser-debug entry |
| `nix/patches/02-tentative-definition-null-check.patch` | Multiple iterations, currently needs regeneration |

---

## How to Reproduce

```bash
# 1. Build and run the debug test
nix build .#tests.simple-parser-debug
./result-debug/bin/xdp2-test-simple-parser-debug

# 2. Check the comparison result
cat debug-output/comparison.txt
# Expected: "RESULT: Optimized parser is NOT working correctly"

# 3. Examine proto table extraction
cat debug-output/proto-tables.txt
# Shows which tables were analyzed (only tcp_tlv_table currently)

# 4. Compare array types in verbose output
grep "\[proto-tables-all\]" debug-output/compiler-verbose.txt
# Shows hasInit=no for ether_table and ip_table

# 5. Check generated code
grep -c "switch (type)" debug-output/parser_notmpl.p.c
# Should be 4, but returns 1 on Nix
```

---

---

## Proposed Refactoring Plan

The debugging process revealed that the xdp2-compiler codebase has several areas that would benefit from refactoring. The current code is difficult to debug, lacks unit tests, and has duplicated logic across multiple files.

### Objectives

| ID | Objective | Priority |
|----|-----------|----------|
| A | Add compile-time debug logging mechanism | High |
| B | Create shared helper functions (DRY principle) | High |
| C | General code quality improvements | Medium |
| D | Add unit tests | High |
| E | Add runtime assertions | Medium |

---

### Objective A: Compile-Time Debug Logging

**Problem:** Currently, debug output is scattered throughout the codebase using `plog::log()`. This output is always compiled in, even when not needed, and there's no structured way to enable/disable different categories of debug output.

**Proposed Solution:** Create a debug logging framework with:

1. **Compile-time categories** - Enable specific debug areas without affecting others
2. **Zero overhead when disabled** - Use macros that compile to nothing
3. **Structured output** - Consistent format for parsing/analysis

**Implementation:**

```cpp
// src/tools/compiler/include/xdp2gen/debug_log.h

#pragma once
#include <iostream>
#include <string_view>

namespace xdp2gen::debug {

// Debug categories - enable via -DXDP2_DEBUG_<CATEGORY>=1
enum class Category {
    ClangTool,      // ClangTool configuration and arguments
    ProtoTable,     // Proto table extraction
    ProtoNode,      // Proto node extraction
    Graph,          // Graph building
    AST,            // AST traversal details
    CodeGen,        // Code generation
    All             // Enable all categories
};

// Compile-time check if category is enabled
template<Category C>
constexpr bool is_enabled() {
#ifdef XDP2_DEBUG_ALL
    return true;
#else
    if constexpr (C == Category::ClangTool) {
#ifdef XDP2_DEBUG_CLANGTOOL
        return true;
#endif
    } else if constexpr (C == Category::ProtoTable) {
#ifdef XDP2_DEBUG_PROTOTABLE
        return true;
#endif
    } else if constexpr (C == Category::Graph) {
#ifdef XDP2_DEBUG_GRAPH
        return true;
#endif
    }
    // ... other categories
    return false;
#endif
}

// Zero-overhead debug log macro
#define XDP2_DEBUG(category, ...) \
    do { \
        if constexpr (xdp2gen::debug::is_enabled<category>()) { \
            std::cout << "[" << #category << "] " << __VA_ARGS__ << std::endl; \
        } \
    } while(0)

// Scoped debug context (for indentation/nesting)
class ScopedContext {
public:
    ScopedContext(Category cat, std::string_view name);
    ~ScopedContext();
private:
    Category cat_;
    std::string_view name_;
    static thread_local int depth_;
};

#define XDP2_DEBUG_SCOPE(category, name) \
    xdp2gen::debug::ScopedContext _debug_scope_##__LINE__(category, name)

} // namespace xdp2gen::debug
```

**Usage Example:**

```cpp
// In proto-tables.h
#include "xdp2gen/debug_log.h"
using xdp2gen::debug::Category;

bool HandleTopLevelDecl(clang::DeclGroupRef D) override {
    XDP2_DEBUG_SCOPE(Category::ProtoTable, "HandleTopLevelDecl");

    for (auto *decl : D) {
        if (decl->getKind() == clang::Decl::Var) {
            auto var_decl = clang::dyn_cast<clang::VarDecl>(decl);
            auto type = var_decl->getType().getAsString();

            XDP2_DEBUG(Category::ProtoTable,
                "VarDecl: " << var_decl->getNameAsString()
                << " type=" << type
                << " hasInit=" << var_decl->hasInit());
            // ...
        }
    }
}
```

**Build Integration:**

```makefile
# In compiler/Makefile
ifdef XDP2_DEBUG
    EXTRA_CXXFLAGS += -DXDP2_DEBUG_ALL=1
endif

# Or enable specific categories:
# make XDP2_DEBUG_PROTOTABLE=1
```

---

### Objective B: Shared Helper Functions (DRY)

**Problem:** The following code patterns are duplicated:

1. ClangTool configuration (resource-dir, system includes)
2. VarDecl type checking for proto tables
3. RecordType null checking before getDecl()
4. InitListExpr processing

**Proposed Helper Functions:**

```cpp
// src/tools/compiler/include/xdp2gen/clang_tool_config.h

#pragma once
#include <clang/Tooling/Tooling.h>
#include <optional>
#include <string>

namespace xdp2gen {

/**
 * Configuration for ClangTool instances.
 * Centralizes all the configuration that needs to be consistent
 * across multiple ClangTool uses.
 */
struct ClangToolConfig {
    std::optional<std::string> resource_dir;
    std::optional<std::string> clang_include_path;
    std::optional<std::string> glibc_include_path;
    std::optional<std::string> linux_headers_path;

    // Load configuration from environment variables
    static ClangToolConfig from_environment();

    // Load configuration from command-line args
    static ClangToolConfig from_args(/* args */);
};

/**
 * Apply configuration to a ClangTool instance.
 * This ensures consistent configuration across all ClangTool uses.
 */
void configure_clang_tool(clang::tooling::ClangTool& tool,
                          const ClangToolConfig& config);

/**
 * Create a fully configured ClangTool from an OptionsParser.
 */
clang::tooling::ClangTool create_configured_clang_tool(
    clang::tooling::CommonOptionsParser& options_parser,
    const ClangToolConfig& config);

} // namespace xdp2gen
```

```cpp
// src/tools/compiler/include/xdp2gen/ast_helpers.h

#pragma once
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <optional>
#include <string>

namespace xdp2gen::ast {

/**
 * Proto table type categories
 */
enum class TableType {
    ProtoTable,         // xdp2_proto_table
    TlvsTable,          // xdp2_proto_tlvs_table
    FlagFieldsTable,    // xdp2_proto_flag_fields_table
    Unknown
};

/**
 * Check if a type string represents a proto table type.
 * Returns the specific table type or Unknown.
 */
TableType classify_table_type(const std::string& type_str);

/**
 * Safely get RecordDecl from an InitListExpr.
 * Returns nullptr if the type is void or not a record type.
 * This handles the tentative definition case where getAs<RecordType>()
 * returns nullptr.
 */
clang::RecordDecl* get_record_decl_safe(const clang::InitListExpr* init_expr);

/**
 * Check if a VarDecl represents an actual definition (not a forward declaration).
 * Combines hasInit() and isThisDeclarationADefinition() checks.
 */
bool is_actual_definition(const clang::VarDecl* var_decl);

/**
 * Extract table name from a VarDecl that may have been created by
 * XDP2_MAKE_PROTO_TABLE or similar macros.
 */
std::optional<std::string> extract_table_name(const clang::VarDecl* var_decl);

/**
 * Information about a proto table extracted from AST
 */
struct ProtoTableInfo {
    std::string name;
    TableType type;
    bool has_initializer;
    bool is_definition;
    std::string type_string;

    // Source location for error reporting
    std::string source_location;
};

/**
 * Extract proto table information from a VarDecl.
 * Returns nullopt if the VarDecl is not a proto table.
 */
std::optional<ProtoTableInfo> extract_proto_table_info(
    const clang::VarDecl* var_decl);

} // namespace xdp2gen::ast
```

---

### Objective C: General Code Quality Improvements

**1. Consistent Error Handling Pattern**

Currently, errors are handled inconsistently (some functions return bool, others return int, some throw). Propose a consistent pattern:

```cpp
// src/tools/compiler/include/xdp2gen/result.h

#pragma once
#include <variant>
#include <string>

namespace xdp2gen {

template<typename T>
class Result {
public:
    static Result<T> ok(T value) { return Result(std::move(value)); }
    static Result<T> error(std::string msg) { return Result(std::move(msg)); }

    bool is_ok() const { return std::holds_alternative<T>(data_); }
    bool is_error() const { return !is_ok(); }

    const T& value() const { return std::get<T>(data_); }
    T& value() { return std::get<T>(data_); }
    const std::string& error() const { return std::get<std::string>(data_); }

private:
    explicit Result(T value) : data_(std::move(value)) {}
    explicit Result(std::string error) : data_(std::move(error)) {}

    std::variant<T, std::string> data_;
};

} // namespace xdp2gen
```

**2. Const Correctness**

Many functions take non-const pointers when they should take const pointers. Review and fix const correctness throughout.

**3. Modern C++ Patterns**

Replace raw pointer patterns with:
- `std::unique_ptr` for ownership
- `std::optional` for nullable values
- `std::string_view` for non-owning string references
- Range-based algorithms where appropriate

**4. Code Organization**

The `main.cpp` file is ~1800 lines. Split into logical modules:
- `clang_tool_setup.cpp` - ClangTool creation and configuration
- `graph_operations.cpp` - Graph building and manipulation
- `code_generation.cpp` - Output file generation
- `main.cpp` - Argument parsing and orchestration

---

### Objective D: Unit Tests

**Test Framework:** Use Catch2 (header-only, modern C++)

**Test Categories:**

#### D.1: ClangTool Configuration Tests

```cpp
// tests/clang_tool_config_test.cpp

#include <catch2/catch.hpp>
#include "xdp2gen/clang_tool_config.h"

TEST_CASE("ClangToolConfig loads from environment", "[config]") {
    // Set up test environment
    setenv("XDP2_C_INCLUDE_PATH", "/test/clang/include", 1);
    setenv("XDP2_GLIBC_INCLUDE_PATH", "/test/glibc/include", 1);
    setenv("XDP2_LINUX_HEADERS_PATH", "/test/linux/include", 1);

    auto config = xdp2gen::ClangToolConfig::from_environment();

    REQUIRE(config.clang_include_path.has_value());
    CHECK(config.clang_include_path.value() == "/test/clang/include");

    REQUIRE(config.glibc_include_path.has_value());
    CHECK(config.glibc_include_path.value() == "/test/glibc/include");

    REQUIRE(config.linux_headers_path.has_value());
    CHECK(config.linux_headers_path.value() == "/test/linux/include");
}

TEST_CASE("ClangToolConfig handles missing environment variables", "[config]") {
    unsetenv("XDP2_C_INCLUDE_PATH");
    unsetenv("XDP2_GLIBC_INCLUDE_PATH");
    unsetenv("XDP2_LINUX_HEADERS_PATH");

    auto config = xdp2gen::ClangToolConfig::from_environment();

    CHECK_FALSE(config.clang_include_path.has_value());
    CHECK_FALSE(config.glibc_include_path.has_value());
    CHECK_FALSE(config.linux_headers_path.has_value());
}

TEST_CASE("configure_clang_tool adds correct arguments", "[config]") {
    // This would require mocking or a test ClangTool
    // Test that the argument adjusters are added in correct order
}
```

#### D.2: AST Helper Tests

```cpp
// tests/ast_helpers_test.cpp

#include <catch2/catch.hpp>
#include "xdp2gen/ast_helpers.h"

TEST_CASE("classify_table_type identifies proto table types", "[ast]") {
    using namespace xdp2gen::ast;

    CHECK(classify_table_type("const struct xdp2_proto_table") == TableType::ProtoTable);
    CHECK(classify_table_type("const struct xdp2_proto_tlvs_table") == TableType::TlvsTable);
    CHECK(classify_table_type("const struct xdp2_proto_flag_fields_table") == TableType::FlagFieldsTable);
    CHECK(classify_table_type("const struct some_other_type") == TableType::Unknown);
    CHECK(classify_table_type("int") == TableType::Unknown);
}

TEST_CASE("get_record_decl_safe handles null cases", "[ast]") {
    // Test with nullptr input
    CHECK(xdp2gen::ast::get_record_decl_safe(nullptr) == nullptr);

    // Would need mock InitListExpr for more tests
}
```

#### D.3: Proto Table Extraction Integration Tests

```cpp
// tests/proto_table_extraction_test.cpp

#include <catch2/catch.hpp>
#include "test_fixtures.h"

TEST_CASE("Proto table extraction finds ether_table", "[integration]") {
    // Use a minimal test source file
    const char* source = R"(
        #include "xdp2/parser.h"
        XDP2_MAKE_PROTO_TABLE(test_table,
            ( 0x0800, test_node1 ),
            ( 0x86dd, test_node2 )
        );
    )";

    auto tables = extract_proto_tables_from_source(source);

    REQUIRE(tables.size() == 1);
    CHECK(tables[0].name == "test_table");
    CHECK(tables[0].has_initializer == true);
    CHECK(tables[0].is_definition == true);
}

TEST_CASE("Proto table extraction handles forward declarations", "[integration]") {
    const char* source = R"(
        #include "xdp2/parser.h"
        XDP2_DECL_PROTO_TABLE(forward_table);  // Forward declaration
    )";

    auto tables = extract_proto_tables_from_source(source);

    REQUIRE(tables.size() == 1);
    CHECK(tables[0].name == "forward_table");
    CHECK(tables[0].has_initializer == false);
    CHECK(tables[0].is_definition == false);
}

TEST_CASE("Proto table extraction distinguishes forward decl from definition", "[integration]") {
    const char* source = R"(
        #include "xdp2/parser.h"
        XDP2_DECL_PROTO_TABLE(my_table);  // Forward declaration
        XDP2_MAKE_PROTO_TABLE(my_table,   // Actual definition
            ( 0x0800, test_node )
        );
    )";

    auto tables = extract_proto_tables_from_source(source);

    // Should find both: one forward decl, one definition
    REQUIRE(tables.size() == 2);

    auto forward_decl = std::find_if(tables.begin(), tables.end(),
        [](const auto& t) { return !t.is_definition; });
    auto definition = std::find_if(tables.begin(), tables.end(),
        [](const auto& t) { return t.is_definition; });

    REQUIRE(forward_decl != tables.end());
    REQUIRE(definition != tables.end());

    CHECK(forward_decl->has_initializer == false);
    CHECK(definition->has_initializer == true);
}
```

#### D.4: End-to-End Tests

```cpp
// tests/e2e_parser_generation_test.cpp

#include <catch2/catch.hpp>
#include "test_fixtures.h"

TEST_CASE("Generated parser contains protocol routing switches", "[e2e]") {
    // Compile simple_parser with xdp2-compiler
    auto result = run_xdp2_compiler("samples/parser/simple_parser/parser_notmpl.c");

    REQUIRE(result.success);

    // Check the generated .p.c file
    auto generated_code = read_file(result.output_path);

    // Should have 4 switch statements for protocol routing
    int switch_count = count_occurrences(generated_code, "switch (type)");
    CHECK(switch_count >= 4);

    // Should have specific protocol cases
    CHECK(contains(generated_code, "case 0x0800")); // ETH_P_IP
    CHECK(contains(generated_code, "case 0x86dd")); // ETH_P_IPV6
}

TEST_CASE("Generated parser produces correct output", "[e2e]") {
    // Build and run the parser
    auto parser = build_parser("samples/parser/simple_parser/parser_notmpl.c");

    // Run with test pcap
    auto basic_output = parser.run("data/pcaps/tcp_ipv6.pcap");
    auto opt_output = parser.run("-O", "data/pcaps/tcp_ipv6.pcap");

    // Both should identify IPv6 packets
    CHECK(count_occurrences(basic_output, "IPv6:") == 12);
    CHECK(count_occurrences(opt_output, "IPv6:") == 12);

    // Optimized should NOT have "Unknown addr type"
    CHECK(count_occurrences(opt_output, "Unknown addr type") == 0);
}
```

---

### Objective E: Runtime Assertions

**Problem:** The code has several places where null pointers or invalid states can occur but are not caught early.

**Proposed Assertions:**

```cpp
// src/tools/compiler/include/xdp2gen/assertions.h

#pragma once
#include <cassert>
#include <iostream>
#include <source_location>

namespace xdp2gen {

// Always-on assertion for critical invariants
#define XDP2_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            std::cerr << "ASSERTION FAILED: " << (message) << "\n" \
                      << "  Condition: " << #condition << "\n" \
                      << "  Location: " << __FILE__ << ":" << __LINE__ << "\n"; \
            std::abort(); \
        } \
    } while(0)

// Debug-only assertion (disabled in release builds)
#ifndef NDEBUG
#define XDP2_DEBUG_ASSERT(condition, message) XDP2_ASSERT(condition, message)
#else
#define XDP2_DEBUG_ASSERT(condition, message) ((void)0)
#endif

// Precondition check
#define XDP2_REQUIRE(condition, message) \
    XDP2_ASSERT(condition, "Precondition failed: " message)

// Postcondition check
#define XDP2_ENSURE(condition, message) \
    XDP2_ASSERT(condition, "Postcondition failed: " message)

// Null pointer check with descriptive message
#define XDP2_REQUIRE_NOT_NULL(ptr, name) \
    XDP2_REQUIRE((ptr) != nullptr, #name " must not be null")

} // namespace xdp2gen
```

**Usage in Existing Code:**

```cpp
// In proto-tables.h - before the fix
clang::RecordDecl *initializer_list_decl =
    initializer_list_expr->getType()
        ->getAs<clang::RecordType>()  // Can return nullptr!
        ->getDecl();                   // CRASH if nullptr

// After adding assertions
auto *recordType = initializer_list_expr->getType()->getAs<clang::RecordType>();
XDP2_REQUIRE_NOT_NULL(recordType,
    "InitListExpr RecordType (may be tentative definition)");
clang::RecordDecl *initializer_list_decl = recordType->getDecl();
```

```cpp
// In main.cpp - before calling graph operations
void process_graph_vertex(const Graph& graph, VertexDescriptor vd) {
    XDP2_REQUIRE(vd < num_vertices(graph),
        "Vertex descriptor out of range");

    const auto& vertex = graph[vd];
    XDP2_REQUIRE(!vertex.name.empty(),
        "Vertex name must not be empty");

    // ... processing
}
```

**Key Assertion Points:**

| Location | Assertion |
|----------|-----------|
| `proto-tables.h:HandleTopLevelDecl` | `D` is not empty |
| `proto-tables.h:InitListExpr processing` | RecordType not null |
| `graph_consumer.h:_process_xdp2_parse_node` | VarDecl has initializer |
| `main.cpp:create_clang_tool` | OptionsParser is valid |
| `main.cpp:extract_struct_constants` | Graph is not empty after parsing |
| Code generation | All required tables were extracted |

---

### Test Execution Plan

**1. Unit Tests (Fast, Run on Every Commit)**

```bash
# Build and run unit tests
cd src/tools/compiler
make test

# Or with Nix
nix build .#tests.xdp2-compiler-unit
```

**2. Integration Tests (Medium, Run on PR)**

```bash
# Test proto table extraction with sample sources
nix build .#tests.xdp2-compiler-integration
```

**3. End-to-End Tests (Slow, Run on Main Branch)**

```bash
# Full parser generation and execution tests
nix build .#tests.simple-parser
nix build .#tests.simple-parser-debug
```

**4. Nix-Specific Regression Test**

```bash
# Specifically tests the optimized parser issue
nix build .#tests.simple-parser-optimized

# This test should:
# 1. Build parser_notmpl with xdp2-compiler
# 2. Run with -O flag on tcp_ipv6.pcap
# 3. Assert that output contains "IPv6:" and NOT "Unknown addr type"
```

---

### Implementation Priority

| Phase | Tasks | Effort |
|-------|-------|--------|
| 1 | Create `ClangToolConfig` and `configure_clang_tool` helper | 2 hours |
| 1 | Add assertions to critical null-pointer paths | 1 hour |
| 1 | Add Nix regression test for optimized parser | 1 hour |
| 2 | Implement debug logging framework | 3 hours |
| 2 | Create AST helper functions | 2 hours |
| 2 | Add unit tests for new helpers | 2 hours |
| 3 | Refactor main.cpp into modules | 4 hours |
| 3 | Add integration tests | 3 hours |
| 4 | Add end-to-end tests | 2 hours |
| 4 | Documentation and cleanup | 2 hours |

**Total Estimated Effort:** ~22 hours

---

## References

- `documentation/nix/phase6_segfault_defect.md` - Related investigation into clang version differences
- `nix/patches/01-nix-clang-system-includes.patch` - System include path patch for first ClangTool
- `nix/patches/02-tentative-definition-null-check.patch` - Null check for tentative definitions
