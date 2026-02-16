# ClangTool Configuration Refactor Implementation Plan

## Overview

This document provides a phased implementation plan for fixing the optimized parser extraction defect on Nix builds. The root cause is that `extract_struct_constants` creates a second ClangTool without the system include paths that `create_clang_tool` receives.

The plan follows the XDP2 C++ style guide and emphasizes:
- Small, testable functions
- Assertions for early failure detection and debugging
- DRY (Don't Repeat Yourself) principle
- Idiomatic C++ patterns

---

## Phase 1: Assertion Infrastructure

**Goal:** Integrate Boost.Assert for invariant checking, providing clear diagnostic output for debugging the Nix issue. Since the project already uses Boost, we leverage `BOOST_ASSERT_MSG` rather than rolling our own.

### Boost.Assert Overview

| Macro | Behavior |
|-------|----------|
| `BOOST_ASSERT(expr)` | Like `assert()`, disabled when `NDEBUG` is set |
| `BOOST_ASSERT_MSG(expr, msg)` | Same, but with a message string |
| `BOOST_VERIFY(expr)` | Always evaluates `expr`, even in release builds |
| `BOOST_VERIFY_MSG(expr, msg)` | Always evaluates, with message |

For the Nix debugging case, we use `BOOST_ASSERT_MSG` for invariants (can be disabled in production) and provide a thin wrapper for null-pointer checks that gives better context.

### Files to Create

#### `src/tools/compiler/include/xdp2gen/assert.h`

```cpp
// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
/*
 * Assertion utilities for xdp2-compiler.
 *
 * Thin wrappers around Boost.Assert for common patterns.
 *
 * Compile-time control:
 *   -DXDP2_ENABLE_ASSERTS=1   Enable all XDP2 assertions
 *   -DNDEBUG                  Disable BOOST_ASSERT (standard behavior)
 *
 * For Nix debug builds, define XDP2_ENABLE_ASSERTS in the derivation.
 * For production builds, leave it undefined for zero overhead.
 */

#ifndef XDP2GEN_ASSERT_H
#define XDP2GEN_ASSERT_H

#include <boost/assert.hpp>

namespace xdp2gen {

/*
 * Null pointer check that returns the pointer if valid.
 *
 * When XDP2_ENABLE_ASSERTS is defined:
 *   - Checks ptr != nullptr, aborts with message if null
 *   - Returns ptr for chaining
 *
 * When XDP2_ENABLE_ASSERTS is NOT defined:
 *   - Compiles to just returning ptr (zero overhead)
 *
 * Usage:
 *   auto *decl = xdp2_require_not_null(record_type->getDecl(),
 *                                      "RecordDecl from RecordType");
 */
template <typename T>
inline T *xdp2_require_not_null(T *ptr, [[maybe_unused]] char const *context)
{
#ifdef XDP2_ENABLE_ASSERTS
    BOOST_ASSERT_MSG(ptr != nullptr, context);
#endif
    return ptr;
}

/*
 * Const pointer overload.
 */
template <typename T>
inline T const *xdp2_require_not_null(T const *ptr, [[maybe_unused]] char const *context)
{
#ifdef XDP2_ENABLE_ASSERTS
    BOOST_ASSERT_MSG(ptr != nullptr, context);
#endif
    return ptr;
}

} // namespace xdp2gen

/*
 * Convenience macros for pre/postconditions.
 *
 * When XDP2_ENABLE_ASSERTS is defined:
 *   - Expands to BOOST_ASSERT_MSG
 *
 * When XDP2_ENABLE_ASSERTS is NOT defined:
 *   - Expands to nothing (zero overhead)
 */

#ifdef XDP2_ENABLE_ASSERTS

#define XDP2_REQUIRE(condition, message) \
    BOOST_ASSERT_MSG((condition), "Precondition: " message)

#define XDP2_ENSURE(condition, message) \
    BOOST_ASSERT_MSG((condition), "Postcondition: " message)

#else

#define XDP2_REQUIRE(condition, message) ((void)0)
#define XDP2_ENSURE(condition, message)  ((void)0)

#endif // XDP2_ENABLE_ASSERTS

#endif // XDP2GEN_ASSERT_H
```

### Build Configuration

#### Makefile Integration

```makefile
# In src/tools/compiler/Makefile

# Debug/test builds: enable assertions
ifdef XDP2_DEBUG
    EXTRA_CXXFLAGS += -DXDP2_ENABLE_ASSERTS=1
endif

# Or explicitly:
# make XDP2_DEBUG=1
```

#### Nix Integration

The default `xdp2` build has assertions disabled. Debug and test targets enable them.

```nix
# In nix/derivation.nix

{ lib, stdenv, ... }:

let
  # Base derivation - assertions DISABLED (production default)
  xdp2 = stdenv.mkDerivation {
    pname = "xdp2";
    # ... normal build, no XDP2_ENABLE_ASSERTS
  };

  # Debug variant - assertions ENABLED
  xdp2-debug = xdp2.overrideAttrs (old: {
    pname = "xdp2-debug";

    NIX_CFLAGS_COMPILE = (old.NIX_CFLAGS_COMPILE or "")
      + " -DXDP2_ENABLE_ASSERTS=1";

    # Optional: also disable optimizations for better stack traces
    # NIX_CFLAGS_COMPILE = ... + " -O0 -g";
  });

in {
  inherit xdp2 xdp2-debug;
}
```

```nix
# In flake.nix - expose both variants

packages.x86_64-linux = {
  default = xdp2;
  xdp2 = xdp2;           # nix build .#xdp2        (no asserts)
  xdp2-debug = xdp2-debug; # nix build .#xdp2-debug  (with asserts)
};
```

#### Test Targets

```nix
# nix/tests/default.nix

{ pkgs, xdp2, xdp2-debug }:
{
  # Production tests - use normal build
  simple-parser = import ./simple-parser.nix {
    inherit pkgs xdp2;
  };

  # Debug tests - use assertion-enabled build
  simple-parser-debug = import ./simple-parser-debug.nix {
    inherit pkgs;
    xdp2 = xdp2-debug;  # Assertions enabled
  };

  # Optimized parser regression test - use debug build to catch issues
  simple-parser-optimized = import ./simple-parser-optimized.nix {
    inherit pkgs;
    xdp2 = xdp2-debug;  # Assertions enabled
  };
}
```

#### Usage Summary

```bash
# Production build (default, no assertions)
nix build .#xdp2

# Debug build (with assertions)
nix build .#xdp2-debug

# Run tests with assertions enabled
nix build .#tests.simple-parser-debug
nix build .#tests.simple-parser-optimized
```

### Files to Modify

#### `src/tools/compiler/include/xdp2gen/ast-consumer/proto-tables.h`

Add include and assertions at critical null-check points:

```cpp
// Add at top with other includes
#include "xdp2gen/assert.h"
```

1. **Line ~136** - After `getAs<RecordType>()` (already has null check, add assertion for documentation):
   ```cpp
   auto *recordType = initType->getAs<clang::RecordType>();
   if (!recordType) {
       // Tentative definition - skip, actual definition processed later
       plog::log(std::cout) << "[proto-tables] Skipping tentative definition: "
           << table_decl_name << std::endl;
       continue;
   }
   // Invariant: recordType is valid after the null check above
   ```

2. **Line ~259-262** - Nested `getAs<RecordType>()` in entry extraction (currently has NO null check):
   ```cpp
   // Before (current - no null check, potential crash):
   clang::RecordDecl *ent_decl =
       ent_value->getType()
           ->getAs<clang::RecordType>()
           ->getDecl();

   // After (with defensive null check):
   auto *ent_record_type = ent_value->getType()->getAs<clang::RecordType>();
   if (!ent_record_type) {
       plog::log(std::cout) << "[proto-tables] Skipping entry with null RecordType"
           << std::endl;
       continue;
   }
   clang::RecordDecl *ent_decl = xdp2gen::xdp2_require_not_null(
       ent_record_type->getDecl(),
       "entry RecordDecl from RecordType");
   ```

### When to Use Each Assert Style

| Pattern | When to Use |
|---------|-------------|
| `BOOST_ASSERT_MSG(expr, msg)` | Invariants that can be disabled in release |
| `BOOST_VERIFY_MSG(expr, msg)` | Checks that must always run (expr has needed side effects) |
| `xdp2_require_not_null(ptr, ctx)` | Null checks where you want the pointer returned |
| `XDP2_REQUIRE(cond, msg)` | Preconditions (function entry) |
| `XDP2_ENSURE(cond, msg)` | Postconditions (function exit) |

### Definition of Done

- [ ] `xdp2gen/assert.h` created with conditionally-compiled Boost.Assert wrappers
- [ ] `proto-tables.h` includes `xdp2gen/assert.h`
- [ ] Null check added at line ~259 (entry extraction)
- [ ] Code compiles without warnings (with and without `XDP2_ENABLE_ASSERTS`)
- [ ] Without `XDP2_ENABLE_ASSERTS`: assertions compile to nothing (zero overhead)
- [ ] With `XDP2_ENABLE_ASSERTS`: Boost assertion output on null (not segfault)
- [ ] Makefile supports `make XDP2_DEBUG=1` to enable assertions
- [ ] Nix `xdp2-debug` derivation variant enables assertions

---

## Phase 2: ClangTool Configuration Abstraction

**Goal:** Create a single source of truth for ClangTool configuration, eliminating duplication between `create_clang_tool` and `extract_struct_constants`.

### Files to Create

#### `src/tools/compiler/include/xdp2gen/clang-tool-config.h`

```cpp
// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
/*
 * ClangTool configuration utilities.
 *
 * Provides a unified configuration structure and helper functions
 * to ensure consistent ClangTool setup across all uses.
 */

#ifndef XDP2GEN_CLANG_TOOL_CONFIG_H
#define XDP2GEN_CLANG_TOOL_CONFIG_H

#include <optional>
#include <string>
#include <vector>

#include <clang/Tooling/Tooling.h>

namespace xdp2gen {

/*
 * Configuration for ClangTool instances.
 *
 * Encapsulates all paths and settings needed for consistent
 * ClangTool behavior across different environments (Ubuntu, Nix).
 */
struct clang_tool_config {
    // Clang resource directory (stddef.h, stdarg.h, etc.)
    std::optional<std::string> resource_dir;

    // Clang builtin headers path (-isystem)
    std::optional<std::string> clang_include_path;

    // Glibc headers path (-isystem)
    std::optional<std::string> glibc_include_path;

    // Linux kernel headers path (-isystem)
    std::optional<std::string> linux_headers_path;

    /*
     * Load configuration from environment variables.
     *
     * Reads:
     *   XDP2_C_INCLUDE_PATH     -> clang_include_path
     *   XDP2_GLIBC_INCLUDE_PATH -> glibc_include_path
     *   XDP2_LINUX_HEADERS_PATH -> linux_headers_path
     *
     * The resource_dir is set from XDP2_CLANG_RESOURCE_PATH macro if defined.
     */
    static clang_tool_config from_environment();

    /*
     * Check if any system include paths are configured.
     */
    bool has_system_includes() const;

    /*
     * Format configuration for debug logging.
     */
    std::string to_string() const;
};

/*
 * Apply configuration to a ClangTool instance.
 *
 * Adds argument adjusters for:
 *   -resource-dir (if configured)
 *   -isystem paths (linux headers, glibc, clang builtins)
 *
 * Order matters: linux headers first, then glibc, then clang builtins.
 * This matches the search order expected by the preprocessor.
 */
void apply_config(clang::tooling::ClangTool &tool,
                  clang_tool_config const &config);

/*
 * Create and configure a ClangTool from CommonOptionsParser.
 *
 * This is the preferred way to create a ClangTool. It ensures
 * consistent configuration across all uses.
 */
clang::tooling::ClangTool create_configured_tool(
    clang::tooling::CommonOptionsParser &options_parser,
    clang_tool_config const &config);

} // namespace xdp2gen

#endif // XDP2GEN_CLANG_TOOL_CONFIG_H
```

#### `src/tools/compiler/src/clang-tool-config.cpp`

```cpp
// SPDX-License-Identifier: BSD-2-Clause-FreeBSD

#include "xdp2gen/clang-tool-config.h"
#include "xdp2gen/program-options/log_handler.h"

#include <cstdlib>
#include <sstream>

// Stringification macro (matches main.cpp)
#define XDP2_STRINGIFY_A(X) #X
#define XDP2_STRINGIFY(X) XDP2_STRINGIFY_A(X)

namespace xdp2gen {

clang_tool_config clang_tool_config::from_environment()
{
    clang_tool_config config;

    // Resource directory from compile-time macro
#ifdef XDP2_CLANG_RESOURCE_PATH
    config.resource_dir = XDP2_STRINGIFY(XDP2_CLANG_RESOURCE_PATH);
#endif

    // System include paths from environment
    if (char const *val = std::getenv("XDP2_C_INCLUDE_PATH")) {
        config.clang_include_path = val;
    }
    if (char const *val = std::getenv("XDP2_GLIBC_INCLUDE_PATH")) {
        config.glibc_include_path = val;
    }
    if (char const *val = std::getenv("XDP2_LINUX_HEADERS_PATH")) {
        config.linux_headers_path = val;
    }

    return config;
}

bool clang_tool_config::has_system_includes() const
{
    return clang_include_path.has_value() ||
           glibc_include_path.has_value() ||
           linux_headers_path.has_value();
}

std::string clang_tool_config::to_string() const
{
    std::ostringstream oss;
    oss << "clang_tool_config {\n";

    if (resource_dir) {
        oss << "  resource_dir: " << *resource_dir << "\n";
    } else {
        oss << "  resource_dir: (not set)\n";
    }

    if (clang_include_path) {
        oss << "  clang_include_path: " << *clang_include_path << "\n";
    }
    if (glibc_include_path) {
        oss << "  glibc_include_path: " << *glibc_include_path << "\n";
    }
    if (linux_headers_path) {
        oss << "  linux_headers_path: " << *linux_headers_path << "\n";
    }

    oss << "}";
    return oss.str();
}

void apply_config(clang::tooling::ClangTool &tool,
                  clang_tool_config const &config)
{
    plog::log(std::cout) << "[clang-tool-config] Applying configuration:\n"
                         << config.to_string() << std::endl;

    // Resource directory (required for clang builtins)
    if (config.resource_dir) {
        tool.appendArgumentsAdjuster(
            clang::tooling::getInsertArgumentAdjuster(
                {"-resource-dir", config.resource_dir->c_str()},
                clang::tooling::ArgumentInsertPosition::BEGIN));
    }

    // System include paths in order: linux headers, glibc, clang builtins
    // Added at BEGIN so they appear after resource-dir in the final order
    if (config.linux_headers_path) {
        tool.appendArgumentsAdjuster(
            clang::tooling::getInsertArgumentAdjuster(
                {"-isystem", config.linux_headers_path->c_str()},
                clang::tooling::ArgumentInsertPosition::BEGIN));
    }

    if (config.glibc_include_path) {
        tool.appendArgumentsAdjuster(
            clang::tooling::getInsertArgumentAdjuster(
                {"-isystem", config.glibc_include_path->c_str()},
                clang::tooling::ArgumentInsertPosition::BEGIN));
    }

    if (config.clang_include_path) {
        tool.appendArgumentsAdjuster(
            clang::tooling::getInsertArgumentAdjuster(
                {"-isystem", config.clang_include_path->c_str()},
                clang::tooling::ArgumentInsertPosition::BEGIN));
    }
}

clang::tooling::ClangTool create_configured_tool(
    clang::tooling::CommonOptionsParser &options_parser,
    clang_tool_config const &config)
{
    clang::tooling::ClangTool tool(
        options_parser.getCompilations(),
        options_parser.getSourcePathList(),
        std::make_shared<clang::PCHContainerOperations>());

    apply_config(tool, config);

    return tool;
}

} // namespace xdp2gen
```

### Files to Modify

#### `src/tools/compiler/src/main.cpp`

1. Add include:
   ```cpp
   #include "xdp2gen/clang-tool-config.h"
   ```

2. Refactor `create_clang_tool` (line ~194):
   ```cpp
   clang::tooling::ClangTool create_clang_tool(
       llvm::Expected<clang::tooling::CommonOptionsParser> &OptionsParser,
       std::optional<std::string> resource_path)
   {
       // Load configuration from environment and compile-time macro
       auto config = xdp2gen::clang_tool_config::from_environment();

       // Override resource_dir if explicitly provided
       if (resource_path) {
           config.resource_dir = *resource_path;
       }

       // Legacy: set C_INCLUDE_PATH from XDP2_C_INCLUDE_PATH
       if (config.clang_include_path) {
           setenv("C_INCLUDE_PATH", config.clang_include_path->c_str(), 1);
       }

       plog::log(std::cout) << "OptionsParser->getSourcePathList()" << std::endl;
       for (auto &&item : OptionsParser->getSourcePathList())
           plog::log(std::cout) << std::string(item) << "\n";
       plog::log(std::cout) << std::endl;

       return xdp2gen::create_configured_tool(*OptionsParser, config);
   }
   ```

3. Refactor `extract_struct_constants` (line ~1632):
   ```cpp
   int extract_struct_constants(
       std::string cfile, std::string llvm_file, std::vector<const char *> args,
       xdp2gen::graph_t &graph,
       std::vector<xdp2gen::parser<xdp2gen::graph_t>> &roots,
       xdp2gen::clang_ast::metadata_record &metadata_record)
   {
       int argc = args.size();

       plog::log(std::cout) << "Compiler args" << std::endl;
       for (auto &&item : args)
           plog::log(std::cout) << std::string(item) << "\n";
       plog::log(std::cout) << std::endl;

       llvm::Expected<clang::tooling::CommonOptionsParser> OptionsParser =
           clang::tooling::CommonOptionsParser::create(argc, &args[0],
                                                       XDP2ToolsCompilerCategory);

       if (OptionsParser) {
           // Use shared configuration - THE FIX
           auto config = xdp2gen::clang_tool_config::from_environment();
           auto Tool = xdp2gen::create_configured_tool(*OptionsParser, config);

           clang::IgnoringDiagConsumer diagConsumer;
           Tool.setDiagnosticConsumer(&diagConsumer);

           // ... rest of function unchanged ...
       }
       // ...
   }
   ```

#### `src/tools/compiler/Makefile`

Add the new source file to compilation:
```makefile
# Add to SOURCES
SOURCES += src/clang-tool-config.cpp
```

### Definition of Done

- [ ] `xdp2gen/clang-tool-config.h` created with `clang_tool_config` struct
- [ ] `src/clang-tool-config.cpp` created with implementation
- [ ] `main.cpp` refactored to use `clang_tool_config` in both ClangTool creation sites
- [ ] Makefile updated to compile new source file
- [ ] Code compiles without warnings
- [ ] `nix build .#xdp2` succeeds
- [ ] Debug output shows configuration applied to both ClangTools
- [ ] Both ClangTools receive identical `-isystem` flags

---

## Phase 3: AST Helper Functions

**Goal:** Extract repeated AST processing patterns into small, testable helper functions.

### Files to Create

#### `src/tools/compiler/include/xdp2gen/ast-consumer/ast-helpers.h`

```cpp
// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
/*
 * AST helper utilities for Clang AST consumers.
 *
 * Small, focused functions for common AST operations.
 */

#ifndef XDP2GEN_AST_CONSUMER_AST_HELPERS_H
#define XDP2GEN_AST_CONSUMER_AST_HELPERS_H

#include <optional>
#include <string>
#include <string_view>

#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>

namespace xdp2gen {
namespace ast {

/*
 * Proto table type categories.
 */
enum class table_type {
    proto_table,        // xdp2_proto_table
    tlvs_table,         // xdp2_proto_tlvs_table
    flag_fields_table,  // xdp2_proto_flag_fields_table
    unknown
};

/*
 * Classify a type string as a proto table type.
 *
 * @param type_str The type as returned by QualType::getAsString()
 * @return The table type category
 */
table_type classify_table_type(std::string_view type_str);

/*
 * Check if a type string represents any proto table type.
 */
bool is_proto_table_type(std::string_view type_str);

/*
 * Safely get RecordType from a QualType.
 *
 * Returns nullptr for void types and tentative definitions
 * where getAs<RecordType>() would return null.
 *
 * @param qual_type The qualified type to extract from
 * @return RecordType pointer or nullptr
 */
clang::RecordType const *get_record_type_safe(clang::QualType qual_type);

/*
 * Safely get RecordDecl from an InitListExpr.
 *
 * Combines get_record_type_safe with getDecl(), returning
 * nullptr if either step fails.
 *
 * @param init_expr The initializer list expression
 * @return RecordDecl pointer or nullptr
 */
clang::RecordDecl *get_record_decl_from_init_list(
    clang::InitListExpr const *init_expr);

/*
 * Check if a VarDecl is an actual definition (not a forward declaration).
 *
 * @param var_decl The variable declaration
 * @return true if this is a definition with an initializer
 */
bool is_var_definition(clang::VarDecl const *var_decl);

/*
 * Information about a VarDecl for diagnostic purposes.
 */
struct var_decl_info {
    std::string name;
    std::string type_str;
    bool has_init;
    bool is_definition;

    std::string to_string() const;
};

/*
 * Extract diagnostic information from a VarDecl.
 */
var_decl_info get_var_decl_info(clang::VarDecl const *var_decl);

} // namespace ast
} // namespace xdp2gen

#endif // XDP2GEN_AST_CONSUMER_AST_HELPERS_H
```

#### `src/tools/compiler/src/ast-helpers.cpp`

```cpp
// SPDX-License-Identifier: BSD-2-Clause-FreeBSD

#include "xdp2gen/ast-consumer/ast-helpers.h"

#include <sstream>

namespace xdp2gen {
namespace ast {

table_type classify_table_type(std::string_view type_str)
{
    if (type_str == "const struct xdp2_proto_table") {
        return table_type::proto_table;
    }
    if (type_str == "const struct xdp2_proto_tlvs_table") {
        return table_type::tlvs_table;
    }
    if (type_str == "const struct xdp2_proto_flag_fields_table") {
        return table_type::flag_fields_table;
    }
    return table_type::unknown;
}

bool is_proto_table_type(std::string_view type_str)
{
    return classify_table_type(type_str) != table_type::unknown;
}

clang::RecordType const *get_record_type_safe(clang::QualType qual_type)
{
    // Void types return nullptr from getAs<RecordType>
    if (qual_type->isVoidType()) {
        return nullptr;
    }
    return qual_type->getAs<clang::RecordType>();
}

clang::RecordDecl *get_record_decl_from_init_list(
    clang::InitListExpr const *init_expr)
{
    if (!init_expr) {
        return nullptr;
    }

    auto *record_type = get_record_type_safe(init_expr->getType());
    if (!record_type) {
        return nullptr;
    }

    return record_type->getDecl();
}

bool is_var_definition(clang::VarDecl const *var_decl)
{
    if (!var_decl) {
        return false;
    }

    return var_decl->hasInit() &&
           var_decl->isThisDeclarationADefinition() == clang::VarDecl::Definition;
}

std::string var_decl_info::to_string() const
{
    std::ostringstream oss;
    oss << "VarDecl{name=" << name
        << ", type=" << type_str
        << ", hasInit=" << (has_init ? "yes" : "no")
        << ", isDefinition=" << (is_definition ? "yes" : "no")
        << "}";
    return oss.str();
}

var_decl_info get_var_decl_info(clang::VarDecl const *var_decl)
{
    var_decl_info info;
    if (var_decl) {
        info.name = var_decl->getNameAsString();
        info.type_str = var_decl->getType().getAsString();
        info.has_init = var_decl->hasInit();
        info.is_definition = var_decl->isThisDeclarationADefinition() ==
                             clang::VarDecl::Definition;
    }
    return info;
}

} // namespace ast
} // namespace xdp2gen
```

### Files to Modify

#### `src/tools/compiler/include/xdp2gen/ast-consumer/proto-tables.h`

Refactor to use helper functions:

```cpp
// Add includes at top
#include "xdp2gen/ast-consumer/ast-helpers.h"
#include "xdp2gen/assert.h"  // For xdp2_require_not_null

// In HandleTopLevelDecl:
virtual bool HandleTopLevelDecl(clang::DeclGroupRef D) override
{
    for (auto *decl : D) {
        if (decl->getKind() != clang::Decl::Var) {
            continue;
        }

        auto *var_decl = clang::dyn_cast<clang::VarDecl>(decl);
        auto type_str = var_decl->getType().getAsString();

        // Debug logging for table-related VarDecls
        auto info = xdp2gen::ast::get_var_decl_info(var_decl);
        if (info.name.find("table") != std::string::npos ||
            info.type_str.find("table") != std::string::npos) {
            plog::log(std::cout) << "[proto-tables-all] " << info.to_string()
                                 << std::endl;
        }

        // Check if this is a proto table type
        if (!xdp2gen::ast::is_proto_table_type(type_str)) {
            continue;
        }

        plog::log(std::cout) << "[proto-tables] Found: " << info.to_string()
                             << std::endl;

        // Skip forward declarations
        if (!var_decl->hasInit()) {
            continue;
        }

        std::string table_decl_name = var_decl->getNameAsString();
        clang::Expr *initializer_expr = var_decl->getInit();

        if (initializer_expr->getStmtClass() != clang::Stmt::InitListExprClass) {
            continue;
        }

        auto *initializer_list_expr =
            clang::dyn_cast<clang::InitListExpr>(initializer_expr);

        // Use helper for safe RecordDecl extraction
        auto *initializer_list_decl =
            xdp2gen::ast::get_record_decl_from_init_list(initializer_list_expr);

        if (!initializer_list_decl) {
            // Tentative definition - skip
            plog::log(std::cout) << "[proto-tables] Skipping tentative: "
                                 << table_decl_name << std::endl;
            continue;
        }

        // Process the table
        xdp2_proto_table_extract_data table_data;
        table_data.decl_name = table_decl_name;

        handle_init_list_expr(initializer_list_expr,
                              initializer_list_decl,
                              table_data);

        consumed_data.push_back(table_data);
    }
    return true;
}
```

### Definition of Done

- [ ] `xdp2gen/ast-consumer/ast-helpers.h` created with helper functions
- [ ] `src/ast-helpers.cpp` created with implementation
- [ ] `proto-tables.h` refactored to use helpers
- [ ] Makefile updated for new source file
- [ ] All existing tests pass
- [ ] Code is more readable with single-purpose functions

---

## Phase 4: Nix Patch Consolidation

**Goal:** Update or remove Nix patches now that the fixes are in the main codebase.

### Patches to Update

#### `nix/patches/01-nix-clang-system-includes.patch`

This patch added system include handling to `create_clang_tool`. With Phase 2, the logic moves to `clang_tool_config`, so this patch should be **removed or reduced**.

The patch currently adds environment variable reading to `create_clang_tool`. After refactoring:
- The environment reading is in `clang_tool_config::from_environment()`
- The `-isystem` appending is in `apply_config()`

**Action:** Remove the patch or update it to a minimal form if any residual differences exist.

#### `nix/patches/02-tentative-definition-null-check.patch`

This patch added the null check for tentative definitions. With Phase 1 (assertions) and Phase 3 (helpers):
- The null check is handled by `get_record_decl_from_init_list()`
- Assertions provide clear failure messages

**Action:** Regenerate this patch to reflect the new code structure, or remove if fully integrated.

### Files to Modify

#### `nix/derivation.nix`

Update patch references:
```nix
patches = [
  # Remove or update these:
  # ./patches/01-nix-clang-system-includes.patch
  # ./patches/02-tentative-definition-null-check.patch
];
```

### Definition of Done

- [ ] `01-nix-clang-system-includes.patch` removed or minimized
- [ ] `02-tentative-definition-null-check.patch` removed or regenerated
- [ ] `nix/derivation.nix` updated with new patch list
- [ ] `nix build .#xdp2` succeeds
- [ ] `nix build .#tests.simple-parser` succeeds
- [ ] Optimized parser produces correct output (not "Unknown addr type 0")

---

## Phase 5: Integration Testing

**Goal:** Verify the fix works end-to-end and add a regression test.

### Files to Create/Modify

#### `nix/tests/simple-parser-optimized.nix`

Create a dedicated test for the optimized parser:

```nix
{ pkgs, xdp2 }:

pkgs.writeShellApplication {
  name = "xdp2-test-simple-parser-optimized";

  runtimeInputs = [ xdp2 ];

  text = ''
    set -euo pipefail

    echo "=== Test: Optimized Parser Regression ==="
    echo "This test verifies that the optimized parser (-O flag) works correctly."

    SAMPLE_DIR="${xdp2}/share/xdp2/samples/parser/simple_parser"
    PCAP="${xdp2}/share/xdp2/data/pcaps/tcp_ipv6.pcap"

    cd "$SAMPLE_DIR"

    echo "--- Test 1: Basic parser (baseline) ---"
    BASIC_OUTPUT=$(./parser_notmpl "$PCAP" 2>&1)
    BASIC_IPV6_COUNT=$(echo "$BASIC_OUTPUT" | grep -c "IPv6:" || true)
    echo "Basic parser found $BASIC_IPV6_COUNT IPv6 packets"

    if [ "$BASIC_IPV6_COUNT" -lt 1 ]; then
      echo "FAIL: Basic parser should find IPv6 packets"
      exit 1
    fi

    echo "--- Test 2: Optimized parser ---"
    OPT_OUTPUT=$(./parser_notmpl -O "$PCAP" 2>&1)
    OPT_IPV6_COUNT=$(echo "$OPT_OUTPUT" | grep -c "IPv6:" || true)
    OPT_UNKNOWN_COUNT=$(echo "$OPT_OUTPUT" | grep -c "Unknown addr type" || true)

    echo "Optimized parser found $OPT_IPV6_COUNT IPv6 packets"
    echo "Optimized parser found $OPT_UNKNOWN_COUNT 'Unknown addr type' messages"

    if [ "$OPT_UNKNOWN_COUNT" -gt 0 ]; then
      echo "FAIL: Optimized parser should NOT output 'Unknown addr type'"
      echo "This indicates proto table extraction failed."
      exit 1
    fi

    if [ "$OPT_IPV6_COUNT" -lt 1 ]; then
      echo "FAIL: Optimized parser should find IPv6 packets"
      exit 1
    fi

    echo "--- Test 3: Output comparison ---"
    if [ "$BASIC_IPV6_COUNT" -ne "$OPT_IPV6_COUNT" ]; then
      echo "WARNING: Basic and optimized parsers found different IPv6 counts"
      echo "  Basic: $BASIC_IPV6_COUNT"
      echo "  Optimized: $OPT_IPV6_COUNT"
    else
      echo "PASS: Both parsers found same number of IPv6 packets"
    fi

    echo ""
    echo "=== All optimized parser tests passed! ==="
  '';
}
```

#### `nix/tests/default.nix`

Add the new test:
```nix
{ pkgs, xdp2 }:
{
  simple-parser = import ./simple-parser.nix { inherit pkgs xdp2; };
  simple-parser-debug = import ./simple-parser-debug.nix { inherit pkgs xdp2; };
  simple-parser-optimized = import ./simple-parser-optimized.nix { inherit pkgs xdp2; };
}
```

### Test Execution

```bash
# Run the regression test
nix build .#tests.simple-parser-optimized
./result/bin/xdp2-test-simple-parser-optimized

# Run all tests
nix build .#tests.simple-parser
nix build .#tests.simple-parser-debug
```

### Definition of Done

- [ ] `nix/tests/simple-parser-optimized.nix` created
- [ ] `nix/tests/default.nix` updated to include new test
- [ ] `nix build .#tests.simple-parser-optimized` passes
- [ ] Optimized parser outputs "IPv6:" not "Unknown addr type 0"
- [ ] Basic and optimized parsers produce equivalent protocol identification

---

## Phase 6: Documentation and Cleanup

**Goal:** Update documentation, remove debug code, finalize the implementation.

### Files to Modify

#### Remove Debug Code

1. **`proto-tables.h`** - Remove `[nix-debug]` logging that was added for investigation:
   - Keep the `[proto-tables]` logging at appropriate verbosity
   - Remove overly verbose "all VarDecls" logging

2. **`main.cpp`** - Clean up any temporary debug logging

#### Documentation Updates

1. **`documentation/nix/optimized_parser_extraction_defect.md`**
   - Add "Resolution" section documenting the fix
   - Update status to "Resolved"

2. **Update this plan document** with actual completion dates

### Definition of Done

- [ ] Debug logging reduced to appropriate level
- [ ] Defect documentation updated with resolution
- [ ] All tests pass
- [ ] Code compiles without warnings
- [ ] No `[nix-debug]` comments remain in production code

---

## Summary

| Phase | Description | Key Deliverables |
|-------|-------------|------------------|
| 1 | Assertion Infrastructure | `assert.h` (Boost.Assert wrappers), null checks in proto-tables.h |
| 2 | ClangTool Configuration | `clang-tool-config.h`, unified configuration |
| 3 | AST Helper Functions | `ast-helpers.h`, smaller testable functions |
| 4 | Nix Patch Consolidation | Remove/update patches |
| 5 | Integration Testing | `simple-parser-optimized.nix` regression test |
| 6 | Documentation/Cleanup | Remove debug code, update docs |

**Expected Outcome:** Both ClangTool instances in xdp2-compiler receive identical configuration, allowing the proto table consumer to properly parse `__cpu_to_be16()` macros and extract protocol routing tables. The optimized parser will correctly identify IPv6 packets.

**Assert Strategy:**
- Controlled by `-DXDP2_ENABLE_ASSERTS=1` compile flag
- Production builds: assertions compile to nothing (zero overhead)
- Debug/test builds: full Boost.Assert checking with descriptive messages
- Use `xdp2_require_not_null(ptr, "context")` for null checks that return the pointer
- Use `XDP2_REQUIRE(cond, "msg")` / `XDP2_ENSURE(cond, "msg")` for pre/postconditions
- Aligns with existing Boost usage in the codebase

---

## Appendix: Testing Checklist

After completing all phases, verify:

```bash
# Build succeeds
nix build .#xdp2

# All tests pass
nix build .#tests.simple-parser
nix build .#tests.simple-parser-optimized

# Manual verification
cd result/share/xdp2/samples/parser/simple_parser
./parser_notmpl data/pcaps/tcp_ipv6.pcap        # Should show IPv6
./parser_notmpl -O data/pcaps/tcp_ipv6.pcap     # Should show IPv6, NOT "Unknown addr type 0"
```
