# Makefile for WAF Tools Unit Tests

.PHONY: all test test-migration test-cleanup clean help

# Default target
all: test

# Run all tests
test:
	@echo "Running all WAF tool tests..."
	@python3 run_tests.py

# Run migration tests only
test-migration:
	@echo "Running WAF migration tests..."
	@python3 run_tests.py test_waf_migrator

# Run cleanup tests only
test-cleanup:
	@echo "Running WAF cleanup tests..."
	@python3 run_tests.py test_wafv1_cleanup

# Run tests with coverage
coverage:
	@echo "Running tests with coverage..."
	@coverage run -m unittest discover -s . -p "test_*.py"
	@coverage report
	@echo "\nGenerating HTML coverage report..."
	@coverage html
	@echo "Coverage report generated in htmlcov/index.html"

# Clean up generated files
clean:
	@echo "Cleaning up..."
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "__pycache__" -delete
	@rm -rf .coverage htmlcov/
	@echo "Clean complete."

# Show help
help:
	@echo "WAF Tools Test Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  make test          - Run all tests"
	@echo "  make test-migration - Run migration tests only"
	@echo "  make test-cleanup  - Run cleanup tests only"
	@echo "  make coverage      - Run tests with coverage report"
	@echo "  make clean         - Clean up generated files"
	@echo "  make help          - Show this help message"
