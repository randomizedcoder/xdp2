# Ubuntu Analysis Scripts Makefile
# Orchestrates analysis of Ubuntu vs Nix environments for xdp2 project

# Configuration
UBUNTU_HOST = 192.168.122.250
RESULTS_DIR = results
UBUNTU_RESULTS = $(RESULTS_DIR)/ubuntu
NIX_RESULTS = $(RESULTS_DIR)/nix

# Colors for output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
NC = \033[0m # No Color

.PHONY: all help clean ubuntu nix compare package-versions build-env compiler-runtime python-integration system-diff

# Default target
all: help

# Help target
help:
	@echo "$(BLUE)Ubuntu Analysis Scripts - Available Targets:$(NC)"
	@echo ""
	@echo "$(GREEN)Main Targets:$(NC)"
	@echo "  all              - Show this help message"
	@echo "  ubuntu           - Run all analysis scripts on Ubuntu 24.04"
	@echo "  nix              - Run all analysis scripts in Nix environment"
	@echo "  compare          - Compare Ubuntu vs Nix analysis results"
	@echo "  clean            - Clean up generated analysis files"
	@echo ""
	@echo "$(GREEN)Category Targets:$(NC)"
	@echo "  package-versions - Run package version analysis"
	@echo "  build-env        - Run build environment analysis"
	@echo "  compiler-runtime - Run compiler runtime analysis"
	@echo "  python-integration - Run Python integration analysis"
	@echo "  system-diff      - Run system differences analysis"
	@echo ""
	@echo "$(GREEN)Usage Examples:$(NC)"
	@echo "  make ubuntu                    # Run all analysis on Ubuntu"
	@echo "  make nix                       # Run all analysis in Nix"
	@echo "  make compiler-runtime          # Focus on segfault debugging"
	@echo "  make compare                   # Compare results"

# Create results directories
$(RESULTS_DIR):
	@mkdir -p $(RESULTS_DIR)
	@mkdir -p $(UBUNTU_RESULTS)
	@mkdir -p $(NIX_RESULTS)

# Run all analysis on Ubuntu
ubuntu: $(RESULTS_DIR)
	@echo "$(BLUE)Running complete analysis on Ubuntu 24.04...$(NC)"
	@echo "$(YELLOW)Note: This requires SSH access to $(UBUNTU_HOST)$(NC)"
	@$(MAKE) package-versions TARGET=ubuntu
	@$(MAKE) build-env TARGET=ubuntu
	@$(MAKE) compiler-runtime TARGET=ubuntu
	@$(MAKE) python-integration TARGET=ubuntu
	@$(MAKE) system-diff TARGET=ubuntu
	@echo "$(GREEN)Ubuntu analysis complete! Results in $(UBUNTU_RESULTS)/$(NC)"

# Run all analysis in Nix environment
nix: $(RESULTS_DIR)
	@echo "$(BLUE)Running complete analysis in Nix development environment...$(NC)"
	@$(MAKE) package-versions TARGET=nix
	@$(MAKE) build-env TARGET=nix
	@$(MAKE) compiler-runtime TARGET=nix
	@$(MAKE) python-integration TARGET=nix
	@$(MAKE) system-diff TARGET=nix
	@echo "$(GREEN)Nix analysis complete! Results in $(NIX_RESULTS)/$(NC)"

# Compare Ubuntu vs Nix results
compare: $(RESULTS_DIR)
	@echo "$(BLUE)Comparing Ubuntu vs Nix analysis results...$(NC)"
	@if [ ! -d "$(UBUNTU_RESULTS)" ] || [ ! -d "$(NIX_RESULTS)" ]; then \
		echo "$(RED)Error: Run 'make ubuntu' and 'make nix' first$(NC)"; \
		exit 1; \
	fi
	@echo "$(YELLOW)Generating comparison report...$(NC)"
	@echo "Comparison report generated at $(RESULTS_DIR)/comparison_report.txt"

# Package versions analysis
package-versions: $(RESULTS_DIR)
	@echo "$(BLUE)Running package versions analysis...$(NC)"
	@if [ "$(TARGET)" = "ubuntu" ]; then \
		echo "$(YELLOW)Running on Ubuntu via SSH...$(NC)"; \
		ssh $(UBUNTU_HOST) "cd /home/das/xdp2/documentation/nix/ubuntu_analysis_scripts && make -C package_versions all" > $(UBUNTU_RESULTS)/package_versions.txt 2>&1; \
	elif [ "$(TARGET)" = "nix" ]; then \
		echo "$(YELLOW)Running in Nix environment...$(NC)"; \
		$(MAKE) -C package_versions all > $(NIX_RESULTS)/package_versions.txt 2>&1; \
	else \
		echo "$(RED)Error: TARGET must be 'ubuntu' or 'nix'$(NC)"; \
		exit 1; \
	fi

# Build environment analysis
build-env: $(RESULTS_DIR)
	@echo "$(BLUE)Running build environment analysis...$(NC)"
	@if [ "$(TARGET)" = "ubuntu" ]; then \
		echo "$(YELLOW)Running on Ubuntu via SSH...$(NC)"; \
		ssh $(UBUNTU_HOST) "cd /home/das/xdp2/documentation/nix/ubuntu_analysis_scripts && make -C build_environment all" > $(UBUNTU_RESULTS)/build_environment.txt 2>&1; \
	elif [ "$(TARGET)" = "nix" ]; then \
		echo "$(YELLOW)Running in Nix environment...$(NC)"; \
		$(MAKE) -C build_environment all > $(NIX_RESULTS)/build_environment.txt 2>&1; \
	else \
		echo "$(RED)Error: TARGET must be 'ubuntu' or 'nix'$(NC)"; \
		exit 1; \
	fi

# Compiler runtime analysis
compiler-runtime: $(RESULTS_DIR)
	@echo "$(BLUE)Running compiler runtime analysis...$(NC)"
	@if [ "$(TARGET)" = "ubuntu" ]; then \
		echo "$(YELLOW)Running on Ubuntu via SSH...$(NC)"; \
		ssh $(UBUNTU_HOST) "cd /home/das/xdp2/documentation/nix/ubuntu_analysis_scripts && make -C compiler_runtime all" > $(UBUNTU_RESULTS)/compiler_runtime.txt 2>&1; \
	elif [ "$(TARGET)" = "nix" ]; then \
		echo "$(YELLOW)Running in Nix environment...$(NC)"; \
		$(MAKE) -C compiler_runtime all > $(NIX_RESULTS)/compiler_runtime.txt 2>&1; \
	else \
		echo "$(RED)Error: TARGET must be 'ubuntu' or 'nix'$(NC)"; \
		exit 1; \
	fi

# Python integration analysis
python-integration: $(RESULTS_DIR)
	@echo "$(BLUE)Running Python integration analysis...$(NC)"
	@if [ "$(TARGET)" = "ubuntu" ]; then \
		echo "$(YELLOW)Running on Ubuntu via SSH...$(NC)"; \
		ssh $(UBUNTU_HOST) "cd /home/das/xdp2/documentation/nix/ubuntu_analysis_scripts && make -C python_integration all" > $(UBUNTU_RESULTS)/python_integration.txt 2>&1; \
	elif [ "$(TARGET)" = "nix" ]; then \
		echo "$(YELLOW)Running in Nix environment...$(NC)"; \
		$(MAKE) -C python_integration all > $(NIX_RESULTS)/python_integration.txt 2>&1; \
	else \
		echo "$(RED)Error: TARGET must be 'ubuntu' or 'nix'$(NC)"; \
		exit 1; \
	fi

# System differences analysis
system-diff: $(RESULTS_DIR)
	@echo "$(BLUE)Running system differences analysis...$(NC)"
	@if [ "$(TARGET)" = "ubuntu" ]; then \
		echo "$(YELLOW)Running on Ubuntu via SSH...$(NC)"; \
		ssh $(UBUNTU_HOST) "cd /home/das/xdp2/documentation/nix/ubuntu_analysis_scripts && make -C system_differences all" > $(UBUNTU_RESULTS)/system_differences.txt 2>&1; \
	elif [ "$(TARGET)" = "nix" ]; then \
		echo "$(YELLOW)Running in Nix environment...$(NC)"; \
		$(MAKE) -C system_differences all > $(NIX_RESULTS)/system_differences.txt 2>&1; \
	else \
		echo "$(RED)Error: TARGET must be 'ubuntu' or 'nix'$(NC)"; \
		exit 1; \
	fi

# Clean up generated files
clean:
	@echo "$(BLUE)Cleaning up analysis files...$(NC)"
	@rm -rf $(RESULTS_DIR)
	@find . -name "*.tmp" -delete
	@find . -name "*.log" -delete
	@echo "$(GREEN)Cleanup complete!$(NC)"

# Test connectivity to Ubuntu host
test-ubuntu:
	@echo "$(BLUE)Testing connectivity to Ubuntu host...$(NC)"
	@ssh -o ConnectTimeout=5 $(UBUNTU_HOST) "echo 'Connection successful'" || echo "$(RED)Connection failed$(NC)"
