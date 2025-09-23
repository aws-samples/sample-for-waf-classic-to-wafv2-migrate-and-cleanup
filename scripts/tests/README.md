# WAF Tools Unit Tests

This directory contains comprehensive unit tests for the WAF migration and cleanup tools.

## Test Coverage

### test_waf_migrator.py
Comprehensive unit tests for the WAF Classic to WAF v2 migration tool, covering:
- DependencyGraph class (resource dependency tracking)
- PlaceholderManager class (ARN placeholder management)
- WAFMigrator class (core migration functionality)
- Helper functions (AWS credentials, data conversion)
- Integration scenarios (complex WebACLs, existing resources)

### test_waf_classic_cleanup.py
Comprehensive unit tests for the WAF Classic cleanup tool, covering:
- WebACL cleanup functionality
- RuleGroup cleanup functionality
- CSV-based cleanup operations
- Safe resource deletion with dependency checks
- Batch resource deletion
- Delete all resources functionality
- Integration scenarios with complex dependencies

## Running Tests

### Run All Tests
```bash
python3 run_tests.py
```

### Run Specific Test Module
```bash
# Run only migration tests
python3 run_tests.py test_waf_migrator

# Run only cleanup tests
python3 run_tests.py test_waf_classic_cleanup
```

### Run with Python unittest directly
```bash
# Run all tests in a module
python3 -m unittest test_waf_migrator

# Run a specific test class
python3 -m unittest test_waf_migrator.TestDependencyGraph

# Run a specific test method
python3 -m unittest test_waf_migrator.TestDependencyGraph.test_add_ipset
```

## Test Structure

All tests use Python's `unittest` framework with extensive mocking to avoid actual AWS API calls.

### Common Test Patterns

1. **Mocking AWS Clients**
   ```python
   @patch('boto3.client')
   def test_something(self, mock_boto3_client):
       mock_client = Mock()
       mock_boto3_client.return_value = mock_client
   ```

2. **Testing Error Scenarios**
   - Tests verify proper error handling
   - Exception scenarios are covered
   - Rollback functionality is tested

3. **Testing Complex Scenarios**
   - Multi-region operations
   - Resources with dependencies
   - Mixed IPv4/IPv6 IPSets
   - Large-scale batch operations

## Requirements

- Python 3.x
- unittest (built-in)
- mock (built-in for Python 3.3+)

## Test Execution Tips

1. **Verbose Output**: Use `-v` flag for detailed test output
   ```bash
   python3 -m unittest -v test_waf_migrator
   ```

2. **Discover Tests**: Auto-discover all tests
   ```bash
   python3 -m unittest discover -s . -p "test_*.py"
   ```

3. **Coverage Report**: Use coverage.py to measure test coverage
   ```bash
   pip install coverage
   coverage run -m unittest discover
   coverage report
   coverage html
   ```

## Adding New Tests

When adding new functionality to the WAF tools, ensure you:
1. Add corresponding unit tests
2. Mock all AWS API calls
3. Test both success and failure scenarios
4. Include edge cases
5. Document complex test scenarios

## Troubleshooting

If tests fail:
1. Check that the common library is available in the expected location
2. Ensure all required modules are in the Python path
3. Verify mock objects are properly configured
4. Check for any real AWS API calls that should be mocked

## License

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
