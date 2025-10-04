# Nix Development Shell Redesign

## Overview

This document outlines the redesign of the XDP2 project's `flake.nix` to follow proper Nix development shell patterns instead of mixing package build phases with development environment setup.

## Current Issues

### 1. Package-like phases in development shell

The current `flake.nix` defines `xdp2-build` as a full Nix derivation with `patchPhase`, `configurePhase`, `buildPhase`, and `installPhase` (lines 387-479). These phases are meant for building packages that get installed to the Nix store, not for development environments.

### 2. Redundant build process

The development shell (`devShells.default`) references the built package and runs some of the same build steps again in the `shellHook` (lines 522-524), creating unnecessary duplication.

### 3. Complex build orchestration

The current setup builds `cppfront` and `xdp2-compiler` during the package build phase, then the development shell sets up the environment to use these pre-built binaries. This creates a complex dependency chain that's not typical for development shells.

### 4. Slow shell entry

Running build steps in `shellHook` would make each `nix develop` invocation slow, which is not ideal for development workflow.

## Requirements

### Functional Requirements

1. **Fast shell entry**: `nix develop` should enter the shell quickly without building the entire project
2. **Environment setup**: Provide all necessary tools, libraries, and environment variables
3. **Build on demand**: Allow developers to build components when needed, not during shell entry
4. **Isolation**: Maintain proper Nix isolation while providing development tools
5. **Automatic cppfront maintenance**: Automatically rebuild cppfront if it's older than 7 days
6. **Configure on entry**: Run configure script during shell entry to generate config.mk
7. **Clean builds**: All build commands should start with a clean state using `make clean`
8. **Binary validation**: All build commands should validate that binaries are created and executable
9. **Debug logging**: Support XDP2_NIX_DEBUG environment variable with levels 0-7 for detailed logging
10. **Shellcheck compliance**: All bash code must pass shellcheck validation
11. **Preserve shell prompt**: Retain the existing custom shell prompt from current flake.nix

### Non-Functional Requirements

1. **Performance**: Shell entry should be under 5 seconds
2. **Maintainability**: Clear separation between environment setup and build logic
3. **Usability**: Intuitive commands for common development tasks
4. **Debugging**: Easy access to debugging tools and verbose output

## Current Architecture Analysis

### What Works Well

1. **Comprehensive tool selection**: The `corePackages` list provides all necessary development tools
2. **Environment variable setup**: `sharedEnvVars` properly configures compiler paths and library paths
3. **Debugging support**: Comprehensive debugging tools and verbose output options

### What Needs Refactoring

1. **Remove `xdp2-build` derivation**: This package-like derivation should be eliminated
2. **Simplify `shellHook`**: Focus on environment setup and configure script execution
3. **Create build commands**: Move build logic to separate commands that can be run on demand
4. **Streamline dependencies**: Remove redundant build steps and dependencies
5. **Remove dual toolchain complexity**: Simplify to use only GCC, removing Clang support
6. **Add automatic cppfront maintenance**: Check and rebuild cppfront if needed during shell entry
7. **Ensure clean builds**: All build commands should start with `make clean` for safety
8. **Add binary validation**: All build commands should validate binaries are created and executable
9. **Preserve debug logging**: Maintain XDP2_NIX_DEBUG functionality with timing for levels > 3
10. **Ensure shellcheck compliance**: All bash code must pass shellcheck validation
11. **Preserve shell prompt**: Keep the existing custom shell prompt functionality

## Proposed Architecture

### 1. Development Shell Structure

```nix
devShells.default = pkgs.mkShell {
  packages = sharedConfig.corePackages;
  shellHook = ''
    # Environment setup
    ${sharedEnvVars}

    # Run configure script to generate config.mk
    run-configure

    # Check and rebuild cppfront if older than 7 days
    check-cppfront-age

    # Build commands available as separate functions

    # Preserve existing custom shell prompt
    export PS1="[XDP2-GCC] [\u@\h:\w]\$ "
  '';
};
```

### 2. Build Commands

Create shell functions for common build tasks:

- `build-cppfront`: Clean, build, and validate the cppfront compiler
- `build-xdp2-compiler`: Clean, build, and validate the xdp2-compiler
- `build-xdp2`: Clean, build, and validate the main XDP2 project
- `build-all`: Clean, build, and validate everything in the correct order
- `clean-build`: Clean all build artifacts

### 3. Utility Commands

Create utility functions for development tasks:

- `run-shellcheck`: Run shellcheck validation against all shell functions

### 4. Environment Setup

The `shellHook` should:
1. Set up environment variables (GCC-only, simplified)
2. Run the configure script to generate `config.mk`
3. Check cppfront age and rebuild if older than 7 days
4. Define build command functions
5. Define utility functions
6. Display helpful information about available commands

### 5. Build Logic Organization

Move build logic from phases to shell functions:

```bash
# Example build command function with clean step, validation, and debug logging
# Shellcheck-compliant version
build-cppfront() {
  local debug_level="${XDP2_NIX_DEBUG:-0}"
  local start_time=""
  local end_time=""

  # Start timing for debug levels > 3
  if [ "$debug_level" -gt 3 ]; then
    start_time=$(date +%s)
    echo "[DEBUG] build-cppfront started at $(date)"
  fi

  # Level 1: Function start
  if [ "$debug_level" -ge 1 ]; then
    echo "[DEBUG] Starting build-cppfront function"
  fi

  # Level 2: Clean step
  if [ "$debug_level" -ge 2 ]; then
    echo "[DEBUG] Cleaning cppfront build directory"
  fi
  echo "Cleaning and building cppfront-compiler..."
  cd thirdparty/cppfront || exit 1
  make clean || true  # Don't fail if clean fails

  # Level 3: Build step details
  if [ "$debug_level" -ge 3 ]; then
    echo "[DEBUG] Building cppfront-compiler with make"
  fi
  # Build logic here

  # Level 2: Validation step
  if [ "$debug_level" -ge 2 ]; then
    echo "[DEBUG] Validating cppfront-compiler binary"
  fi

  # Validate binary was created
  if [ -x "./cppfront-compiler" ]; then
    echo "✓ cppfront-compiler binary created and executable"

    # Test the binary runs correctly
    echo "Testing cppfront-compiler..."
    set +e  # Temporarily disable exit on error
    ./cppfront-compiler -version
    test_exit_code=$?
    set -e  # Re-enable exit on error

    if [ "$test_exit_code" -eq 0 ] || [ "$test_exit_code" -eq 1 ]; then
      echo "✓ cppfront-compiler runs correctly (exit code: $test_exit_code)"
    else
      echo "⚠ WARNING: cppfront-compiler returned unexpected exit code: $test_exit_code"
      echo "But binary exists and is executable, continuing..."
    fi
  else
    echo "✗ ERROR: cppfront-compiler binary not found or not executable"
    exit 1
  fi

  cd ../.. || exit 1

  # End timing for debug levels > 3
  if [ "$debug_level" -gt 3 ]; then
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    echo "[DEBUG] build-cppfront completed in ${duration} seconds"
  fi

  echo "cppfront-compiler built and validated successfully"
}

# Automatic cppfront maintenance function with debug logging
# Shellcheck-compliant version
check-cppfront-age() {
  local debug_level="${XDP2_NIX_DEBUG:-0}"
  local start_time=""
  local end_time=""

  # Start timing for debug levels > 3
  if [ "$debug_level" -gt 3 ]; then
    start_time=$(date +%s)
    echo "[DEBUG] check-cppfront-age started at $(date)"
  fi

  # Level 1: Function start
  if [ "$debug_level" -ge 1 ]; then
    echo "[DEBUG] Starting check-cppfront-age function"
  fi

  local cppfront_binary="thirdparty/cppfront/cppfront-compiler"

  # Level 2: File check
  if [ "$debug_level" -ge 2 ]; then
    echo "[DEBUG] Checking cppfront binary: $cppfront_binary"
  fi

  if [ -f "$cppfront_binary" ]; then
    local file_time
    file_time=$(stat -c %Y "$cppfront_binary")
    local current_time
    current_time=$(date +%s)
    local age_days=$(( (current_time - file_time) / 86400 ))

    # Level 3: Age calculation details
    if [ "$debug_level" -ge 3 ]; then
      echo "[DEBUG] File modification time: $file_time"
      echo "[DEBUG] Current time: $current_time"
      echo "[DEBUG] Calculated age: $age_days days"
    fi

    if [ "$age_days" -gt 7 ]; then
      echo "cppfront is $age_days days old, rebuilding..."
      build-cppfront
    else
      echo "cppfront is up to date ($age_days days old)"
    fi
  else
    echo "cppfront not found, building..."
    build-cppfront
  fi

  # End timing for debug levels > 3
  if [ "$debug_level" -gt 3 ]; then
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    echo "[DEBUG] check-cppfront-age completed in ${duration} seconds"
  fi
}

# Additional build command templates with validation placeholders and debug logging
build-xdp2-compiler() {
  local debug_level=${XDP2_NIX_DEBUG:-0}
  local start_time=""
  local end_time=""

  # Start timing for debug levels > 3
  if [ $debug_level -gt 3 ]; then
    start_time=$(date +%s)
    echo "[DEBUG] build-xdp2-compiler started at $(date)"
  fi

  # Level 1: Function start
  if [ $debug_level -ge 1 ]; then
    echo "[DEBUG] Starting build-xdp2-compiler function"
  fi

  # Level 2: Clean step
  if [ $debug_level -ge 2 ]; then
    echo "[DEBUG] Cleaning xdp2-compiler build directory"
  fi
  echo "Cleaning and building xdp2-compiler..."
  cd src/tools/compiler
  make clean || true  # Don't fail if clean fails

  # Level 3: Build step details
  if [ $debug_level -ge 3 ]; then
    echo "[DEBUG] Building xdp2-compiler with make"
  fi
  # Build logic here

  # Level 2: Validation step
  if [ $debug_level -ge 2 ]; then
    echo "[DEBUG] Validating xdp2-compiler binary"
  fi

  # TODO: Validate binary was created
  # Binary path: ./xdp2-compiler
  # Test command: ./xdp2-compiler --help
  # Expected exit codes: 0 or 1

  cd ../..

  # End timing for debug levels > 3
  if [ $debug_level -gt 3 ]; then
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    echo "[DEBUG] build-xdp2-compiler completed in ${duration} seconds"
  fi

  echo "xdp2-compiler built and validated successfully"
}

build-xdp2() {
  local debug_level=${XDP2_NIX_DEBUG:-0}
  local start_time=""
  local end_time=""

  # Start timing for debug levels > 3
  if [ $debug_level -gt 3 ]; then
    start_time=$(date +%s)
    echo "[DEBUG] build-xdp2 started at $(date)"
  fi

  # Level 1: Function start
  if [ $debug_level -ge 1 ]; then
    echo "[DEBUG] Starting build-xdp2 function"
  fi

  # Level 2: Clean step
  if [ $debug_level -ge 2 ]; then
    echo "[DEBUG] Cleaning xdp2 project build directory"
  fi
  echo "Cleaning and building xdp2 project..."
  cd src
  make clean || true  # Don't fail if clean fails

  # Level 3: Build step details
  if [ $debug_level -ge 3 ]; then
    echo "[DEBUG] Building xdp2 project with make"
  fi
  # Build logic here

  # Level 2: Validation step
  if [ $debug_level -ge 2 ]; then
    echo "[DEBUG] Validating xdp2 project binaries"
  fi

  # TODO: Validate binaries were created
  # Binary paths: TBD (need to identify main binaries)
  # Test commands: TBD (need to identify test commands)
  # Expected exit codes: TBD

  cd ..

  # End timing for debug levels > 3
  if [ $debug_level -gt 3 ]; then
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    echo "[DEBUG] build-xdp2 completed in ${duration} seconds"
  fi

  echo "xdp2 project built and validated successfully"
}

# Utility function: Run shellcheck validation on all shell functions
# Shellcheck-compliant version
run-shellcheck() {
  local debug_level="${XDP2_NIX_DEBUG:-0}"
  local start_time=""
  local end_time=""

  # Start timing for debug levels > 3
  if [ "$debug_level" -gt 3 ]; then
    start_time=$(date +%s)
    echo "[DEBUG] run-shellcheck started at $(date)"
  fi

  # Level 1: Function start
  if [ "$debug_level" -ge 1 ]; then
    echo "[DEBUG] Starting run-shellcheck function"
  fi

  # Level 2: Check shellcheck availability
  if [ "$debug_level" -ge 2 ]; then
    echo "[DEBUG] Checking shellcheck availability"
  fi

  if ! command -v shellcheck >/dev/null 2>&1; then
    echo "✗ ERROR: shellcheck not found in PATH"
    echo "Please install shellcheck to validate bash code"
    exit 1
  fi

  echo "✓ shellcheck found: $(which shellcheck)"

  # Level 3: Define function list
  if [ "$debug_level" -ge 3 ]; then
    echo "[DEBUG] Defining list of functions to check"
  fi

  local functions_to_check=(
    "build-cppfront"
    "build-xdp2-compiler"
    "build-xdp2"
    "build-all"
    "clean-build"
    "check-cppfront-age"
    "run-shellcheck"
  )

  local total_functions="${#functions_to_check[@]}"
  local passed_count=0
  local failed_count=0

  echo "Running shellcheck validation on $total_functions functions..."

  # Level 2: Validation loop
  if [ "$debug_level" -ge 2 ]; then
    echo "[DEBUG] Starting validation loop for $total_functions functions"
  fi

  for func_name in "${functions_to_check[@]}"; do
    # Level 3: Individual function check
    if [ "$debug_level" -ge 3 ]; then
      echo "[DEBUG] Checking function: $func_name"
    fi

    echo "Checking $func_name..."

    # Use type to get function definition and pipe to shellcheck
    if type "$func_name" 2>/dev/null | shellcheck -s bash -; then
      echo "✓ $func_name passed shellcheck validation"
      ((passed_count++))
    else
      echo "✗ $func_name failed shellcheck validation"
      ((failed_count++))
    fi
  done

  # Level 2: Summary
  if [ "$debug_level" -ge 2 ]; then
    echo "[DEBUG] Validation complete: $passed_count passed, $failed_count failed"
  fi

  echo ""
  echo "=== Shellcheck Validation Summary ==="
  echo "Total functions checked: $total_functions"
  echo "Passed: $passed_count"
  echo "Failed: $failed_count"

  # End timing for debug levels > 3
  if [ "$debug_level" -gt 3 ]; then
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    echo "[DEBUG] run-shellcheck completed in ${duration} seconds"
  fi

  if [ "$failed_count" -eq 0 ]; then
    echo "✓ All functions passed shellcheck validation"
    return 0
  else
    echo "✗ $failed_count function(s) failed shellcheck validation"
    return 1
  fi
}
```

## Shellcheck Compliance

All bash code in the development shell must pass shellcheck validation to ensure code quality, security, and portability.

### Shellcheck Best Practices

1. **Quote all variables**: Use `"$variable"` instead of `$variable`
2. **Handle command failures**: Use `|| exit 1` for critical commands
3. **Declare variables properly**: Use `local` for function variables
4. **Avoid command substitution in conditionals**: Store results in variables first
5. **Use proper arithmetic**: Use `$((expression))` for calculations
6. **Handle file operations safely**: Check file existence before operations

### Common Shellcheck Issues to Avoid

- **SC2086**: Double quote to prevent globbing and word splitting
- **SC2164**: Use `cd ... || exit` or `cd ... || return` in case cd fails
- **SC2004**: `$` is unnecessary on arithmetic variables
- **SC2034**: Variable appears unused (declare with `local` if needed)
- **SC2155**: Declare and assign separately to avoid masking return values

### Validation Process

All bash functions should be validated with:
```bash
shellcheck -x function_name
```

## Debug Logging System

The development shell supports comprehensive debug logging via the `XDP2_NIX_DEBUG` environment variable with levels 0-7:

### Debug Level Definitions

- **Level 0**: No debug output (default)
- **Level 1**: Function start/end messages
- **Level 2**: Major step logging (clean, build, validate)
- **Level 3**: Detailed step logging (make commands, file operations)
- **Level 4+**: Includes timing information for performance analysis
- **Level 5+**: Environment variable dumps and detailed diagnostics
- **Level 6+**: Full command execution traces
- **Level 7**: Maximum verbosity including all internal operations

### Timing System

For debug levels > 3, all build functions automatically record:
- Start time with timestamp
- End time with timestamp
- Total duration in seconds
- Performance analysis for optimization

### Usage Examples

```bash
# No debug output (default)
nix develop

# Basic function logging
XDP2_NIX_DEBUG=1 nix develop

# Detailed step logging with timing
XDP2_NIX_DEBUG=4 nix develop

# Maximum verbosity for troubleshooting
XDP2_NIX_DEBUG=7 nix develop
```

## Binary Validation Pattern

Each build command should follow this validation pattern:

1. **Check binary exists and is executable**: `[ -x "./binary-name" ]`
2. **Test binary runs correctly**: Run with appropriate test flags (e.g., `--help`, `--version`)
3. **Handle exit codes gracefully**: Use `set +e`/`set -e` to capture exit codes
4. **Provide clear feedback**: Use ✓/✗ symbols and descriptive messages
5. **Fail fast on critical errors**: Exit with error code if binary not found
6. **Continue on warnings**: Log warnings but continue if binary exists

### Placeholder Comments for Implementation

For build commands where binary paths or test commands are not yet known, use these placeholder comments:

```bash
# TODO: Validate binary was created
# Binary path: ./path/to/binary
# Test command: ./binary --test-flag
# Expected exit codes: 0 or 1
```

## Implementation Plan

### Phase 1: Analysis and Preparation
1. ✅ Document current issues and requirements
2. Identify all build steps that need to be moved to commands
3. Test current shell entry time to establish baseline

### Phase 2: Refactor Environment Setup
1. Remove `xdp2-build` derivation entirely
2. Simplify `shellHook` to focus on environment setup and configure script
3. Remove dual toolchain support, use GCC only
4. Add automatic cppfront age checking and rebuilding
5. Test shell entry performance

### Phase 3: Create Build Commands
1. Create shell functions for each build step (all include clean + validation + debug logging + shellcheck compliance):
   - `build-cppfront` (clean + build + validate cppfront + debug logging + shellcheck)
   - `build-xdp2-compiler` (clean + build + validate xdp2-compiler + debug logging + shellcheck)
   - `build-xdp2` (clean + build + validate main project + debug logging + shellcheck)
   - `build-all` (clean + build + validate everything in order + debug logging + shellcheck)
   - `clean-build` (clean all build artifacts + debug logging + shellcheck)
   - `check-cppfront-age` (for manual use + debug logging + shellcheck)
2. Create utility functions:
   - `run-shellcheck` (validate all shell functions + debug logging + shellcheck)
3. Add command discovery and help system
4. Test all build commands work correctly
5. Add placeholder comments for binary paths and test commands where needed
6. Implement debug logging system with timing for levels > 3
7. Validate all bash code with shellcheck

### Phase 4: Optimization and Polish
1. Optimize shell entry time
2. Add helpful prompts and command suggestions
3. Ensure proper error handling in build commands
4. Update documentation

### Phase 5: Testing and Validation
1. Test with GCC toolchain (Clang support removed)
2. Verify all debugging tools work correctly
3. Test build commands in various scenarios
4. Validate environment isolation
5. Test automatic cppfront maintenance functionality
6. Test debug logging system with all levels (0-7)
7. Validate timing functionality for debug levels > 3
8. Test run-shellcheck utility function
9. Run shellcheck validation on all bash code
10. Test custom shell prompt functionality

## Benefits of New Architecture

### Performance
- **Fast shell entry**: No build steps during `nix develop`
- **On-demand building**: Only build what you need, when you need it
- **Incremental builds**: Build commands can be run independently

### Maintainability
- **Clear separation**: Environment setup vs. build logic
- **Simpler structure**: No complex derivation dependencies
- **Easier debugging**: Build issues don't affect shell entry

### Usability
- **Intuitive workflow**: `nix develop` → `build-all` → develop
- **Flexible building**: Build individual components as needed
- **Better error handling**: Build errors don't prevent shell entry
- **Self-validation**: Built-in shellcheck utility for code quality assurance

## Migration Strategy

### Backward Compatibility
- Keep the same environment variables and tool selection (GCC-focused)
- Maintain support for `XDP2_NIX_DEBUG` with enhanced logging levels (remove `XDP2_USE_CLANG`)
- Preserve all debugging and development tools
- Maintain existing debug level behavior with additional timing features

### Rollback Plan
- Keep current `flake.nix` as `flake.nix.backup`
- Test new implementation thoroughly before switching
- Document any breaking changes in environment or workflow

## Success Criteria

1. **Shell entry time**: Under 5 seconds (vs. current ~30+ seconds)
2. **Functionality**: All current features preserved (GCC-only)
3. **Usability**: Clear, intuitive build commands
4. **Maintainability**: Simpler, more focused code structure
5. **Performance**: No regression in build times when using build commands
6. **Automatic maintenance**: cppfront automatically rebuilt when older than 7 days
7. **Clean builds**: All build commands start from a clean state for safety
8. **Binary validation**: All build commands validate binaries are created and executable
9. **Debug logging**: Comprehensive debug logging system with timing for performance analysis
10. **Code quality**: All bash code passes shellcheck validation
11. **User experience**: Custom shell prompt preserved for familiar development environment

## Next Steps

1. Create backup of current `flake.nix`
2. Begin Phase 2 implementation
3. Test shell entry performance improvements
4. Implement build command functions
5. Validate all functionality works as expected
