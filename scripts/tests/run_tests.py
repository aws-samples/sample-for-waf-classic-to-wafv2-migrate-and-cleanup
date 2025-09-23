#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""
Test runner for WAF migration and cleanup tools
"""

import sys
import unittest
import os

# Add the test directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def run_all_tests():
    """Run all test suites"""
    # Create test loader
    loader = unittest.TestLoader()
    
    # Create test suite
    suite = unittest.TestSuite()
    
    # Add test modules
    test_modules = [
        'test_waf_classic_migrator',
        'test_waf_classic_cleanup'
    ]
    
    for module in test_modules:
        try:
            tests = loader.loadTestsFromName(module)
            suite.addTests(tests)
            print(f"✓ Loaded tests from {module}")
        except Exception as e:
            print(f"✗ Failed to load tests from {module}: {e}")
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Return exit code based on test results
    return 0 if result.wasSuccessful() else 1

def run_specific_test(test_module):
    """Run a specific test module"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    try:
        tests = loader.loadTestsFromName(test_module)
        suite.addTests(tests)
        print(f"Running tests from {test_module}")
    except Exception as e:
        print(f"Failed to load tests from {test_module}: {e}")
        return 1
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return 0 if result.wasSuccessful() else 1

if __name__ == '__main__':
    if len(sys.argv) > 1:
        # Run specific test module
        exit_code = run_specific_test(sys.argv[1])
    else:
        # Run all tests
        print("Running all WAF tool tests...\n")
        exit_code = run_all_tests()
    
    sys.exit(exit_code)
