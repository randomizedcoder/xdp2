# Compiler Runtime Analysis Makefile
# Analyzes xdp2-compiler runtime behavior and debugging

.PHONY: all clean help

# Default target
all: analyze_compiler_runtime analyze_segfault_context analyze_memory_layout

# Help target
help:
	@echo "Compiler Runtime Analysis - Available Targets:"
	@echo "  all                    - Run all compiler runtime analysis scripts"
	@echo "  analyze_compiler_runtime - Test xdp2-compiler with debug flags"
	@echo "  analyze_segfault_context - Capture core dumps and stack traces"
	@echo "  analyze_memory_layout    - Compare memory layouts between environments"
	@echo "  clean                  - Clean up generated files"

# Analyze compiler runtime
analyze_compiler_runtime:
	@echo "Running compiler runtime analysis..."
	@./analyze_compiler_runtime.sh

# Analyze segfault context
analyze_segfault_context:
	@echo "Running segfault context analysis..."
	@./analyze_segfault_context.sh

# Analyze memory layout
analyze_memory_layout:
	@echo "Running memory layout analysis..."
	@./analyze_memory_layout.sh

# Clean up
clean:
	@rm -f *.tmp *.log *.core core.*
	@echo "Compiler runtime analysis cleanup complete"
