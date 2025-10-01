# Package Versions Analysis Makefile
# Analyzes package versions and configurations

.PHONY: all clean help

# Default target
all: analyze_package_versions analyze_compiler_config analyze_library_paths

# Help target
help:
	@echo "Package Versions Analysis - Available Targets:"
	@echo "  all                    - Run all package analysis scripts"
	@echo "  analyze_package_versions - Extract exact versions of installed packages"
	@echo "  analyze_compiler_config  - Document compiler flags and configurations"
	@echo "  analyze_library_paths    - Map library locations and linking"
	@echo "  clean                  - Clean up generated files"

# Analyze package versions
analyze_package_versions:
	@echo "Running package versions analysis..."
	@./analyze_package_versions.sh

# Analyze compiler configuration
analyze_compiler_config:
	@echo "Running compiler configuration analysis..."
	@./analyze_compiler_config.sh

# Analyze library paths
analyze_library_paths:
	@echo "Running library paths analysis..."
	@./analyze_library_paths.sh

# Clean up
clean:
	@rm -f *.tmp *.log
	@echo "Package versions analysis cleanup complete"
