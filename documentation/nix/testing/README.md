# XDP2 Development Shell Testing Scripts

This directory contains all the Tcl/Expect test scripts for validating the XDP2 development shell functionality.

## Test Scripts Overview

### Core Functionality Tests
- **`test-dev-shell.exp`** - Comprehensive development shell functionality test
- **`test-build-functions.exp`** - Build process validation
- **`test-debug-levels.exp`** - Debug system functionality

### Build Command Tests
- **`test-all-build-commands.exp`** - Comprehensive build command testing with long timeouts
- **`test-single-build-command.exp`** - Single build command test for debugging
- **`test-defect3-debug-output.exp`** - Enhanced debug output validation

### Performance Tests
- **`test-performance.exp`** - Basic performance testing
- **`test-performance-comprehensive.exp`** - Detailed performance analysis
- **`test-key-metrics.exp`** - Focused key metrics validation

## Usage

### Make Scripts Executable
```bash
chmod +x documentation/nix/testing/*.exp
```

### Run All Tests
```bash
# Comprehensive test suite
./documentation/nix/testing/test-dev-shell.exp

# Build command tests (recommended)
./documentation/nix/testing/test-all-build-commands.exp
./documentation/nix/testing/test-single-build-command.exp

# Performance tests
./documentation/nix/testing/test-performance-comprehensive.exp
./documentation/nix/testing/test-key-metrics.exp

# Specific functionality tests
./documentation/nix/testing/test-debug-levels.exp
./documentation/nix/testing/test-build-functions.exp
```

### Run Individual Tests
```bash
# Test build commands (recommended)
./documentation/nix/testing/test-all-build-commands.exp    # All build commands
./documentation/nix/testing/test-single-build-command.exp  # Single command test

# Test specific functionality
./documentation/nix/testing/test-debug-levels.exp          # Debug system only
./documentation/nix/testing/test-build-functions.exp       # Build functions only
./documentation/nix/testing/test-performance.exp           # Performance only

# Test defect fixes
./documentation/nix/testing/test-defect3-debug-output.exp  # Enhanced debug output
```

## Test Categories

### 1. **Core Functionality Tests**
- Shell entry and environment setup
- Build function availability and execution
- Debug system functionality
- Help system and command discovery

### 2. **Performance Tests**
- Shell entry time measurement
- Function execution timing
- Environment setup performance
- Debug level performance impact

### 3. **Defect Validation Tests**
- Specific bug fixes and enhancements
- Error handling and recovery
- Edge case scenarios

## Expected Results

All tests should pass with:
- ✅ Shell entry time < 5 seconds (target: ~0.4s achieved)
- ✅ All build functions available and working
- ✅ Debug levels (0-7) functioning properly
- ✅ Help system and navigation working
- ✅ Error handling graceful and informative

## Dependencies

- **Tcl/Expect**: Required for running test scripts
- **Nix**: Required for `nix develop` command
- **Git**: Required for repository operations
- **Bash**: Required for shell functionality

## Installation

### Install Expect (if not available)
```bash
# Ubuntu/Debian
sudo apt-get install expect

# Fedora/CentOS
sudo yum install expect

# NixOS (already available in development shell)
# No additional installation needed
```

## Troubleshooting

### Common Issues
1. **Permission Denied**: Make sure scripts are executable (`chmod +x`)
2. **Expect Not Found**: Install expect package for your distribution
3. **Nix Command Failed**: Ensure Nix is properly installed and configured
4. **Git Tree Dirty**: Commit or stash changes before running tests

### Debug Mode
Run tests with debug output:
```bash
expect -d ./documentation/nix/testing/test-dev-shell.exp
```

## Test Results

For detailed test results and performance metrics, see the main documentation:
`../nix_develop_shell_only.md` - Phase 6: Integration Testing and Validation section.

## Contributing

When adding new test scripts:
1. Use portable shebang: `#!/usr/bin/env expect`
2. Include comprehensive error handling
3. Document expected results
4. Update this README with script description
5. Ensure scripts work across different Linux distributions
