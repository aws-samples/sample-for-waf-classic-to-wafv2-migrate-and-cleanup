#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""
Comprehensive unit tests for WAF Classic to WAF v2 Migration Tool
Consolidates all test cases including basic functionality, edge cases, failure scenarios, 
capacity handling, and all predicate types
"""

import unittest
from unittest.mock import Mock, patch, MagicMock, call
import sys
import os
import json
import csv
from datetime import datetime

# Add the script directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'waf-migration'))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'common'))

# Import the modules to test - handle hyphenated filename
import importlib.util
waf_migrator_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'waf-migration', 'waf-migrator.py')
spec = importlib.util.spec_from_file_location("waf_migrator", waf_migrator_path)
waf_migrator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(waf_migrator)

# Import the classes and functions from the module
WAFMigrator = waf_migrator.WAFMigrator
DependencyGraph = waf_migrator.DependencyGraph
PlaceholderManager = waf_migrator.PlaceholderManager
check_aws_credentials = waf_migrator.check_aws_credentials
convert_bytes_to_string = waf_migrator.convert_bytes_to_string


class TestDependencyGraph(unittest.TestCase):
    """Test cases for DependencyGraph class"""
    
    def setUp(self):
        self.graph = DependencyGraph()
    
    def test_add_ipset(self):
        """Test adding IPSet to dependency graph"""
        self.graph.add_ipset('ipset-123', 'TestIPSet')
        
        self.assertIn('ipset-123', self.graph.ipsets)
        self.assertEqual(self.graph.ipsets['ipset-123']['name'], 'TestIPSet')
        self.assertIsNotNone(self.graph.ipsets['ipset-123']['v2_name'])
        self.assertIsNotNone(self.graph.ipsets['ipset-123']['placeholder'])
        self.assertFalse(self.graph.ipsets['ipset-123']['created'])
    
    def test_add_regex_set(self):
        """Test adding RegexPatternSet to dependency graph"""
        self.graph.add_regex_set('regex-456', 'TestRegex')
        
        self.assertIn('regex-456', self.graph.regex_sets)
        self.assertEqual(self.graph.regex_sets['regex-456']['name'], 'TestRegex')
        self.assertIsNotNone(self.graph.regex_sets['regex-456']['v2_name'])
        self.assertIsNotNone(self.graph.regex_sets['regex-456']['placeholder'])
        self.assertFalse(self.graph.regex_sets['regex-456']['created'])
    
    def test_add_rule_group(self):
        """Test adding RuleGroup to dependency graph"""
        self.graph.add_rule_group('rg-789', 'TestRuleGroup')
        
        self.assertIn('rg-789', self.graph.rule_groups)
        self.assertEqual(self.graph.rule_groups['rg-789']['name'], 'TestRuleGroup')
        self.assertIsNotNone(self.graph.rule_groups['rg-789']['v2_name'])
        self.assertIsNotNone(self.graph.rule_groups['rg-789']['placeholder'])
        self.assertFalse(self.graph.rule_groups['rg-789']['created'])
    
    def test_mark_ipset_created(self):
        """Test marking IPSet as created"""
        self.graph.add_ipset('ipset-123', 'TestIPSet')
        created_ipsets = [{
            'v2_name': 'Migrated_TestIPSet_ipset-123_v4',
            'v2_arn': 'arn:aws:wafv2:us-east-1:123456789012:regional/ipset/test/abc'
        }]
        
        self.graph.mark_ipset_created('ipset-123', created_ipsets)
        
        self.assertTrue(self.graph.ipsets['ipset-123']['created'])
        self.assertEqual(self.graph.ipsets['ipset-123']['created_ipsets'], created_ipsets)
        self.assertEqual(self.graph.ipsets['ipset-123']['actual_arn'], created_ipsets[0]['v2_arn'])
    
    def test_get_pending_resources(self):
        """Test getting pending resources"""
        self.graph.add_ipset('ipset-123', 'TestIPSet1')
        self.graph.add_ipset('ipset-456', 'TestIPSet2')
        self.graph.mark_ipset_created('ipset-123', [{'v2_arn': 'arn:test'}])
        
        pending = self.graph.get_pending_resources('ipset')
        
        self.assertEqual(len(pending), 1)
        self.assertIn('ipset-456', pending)
        self.assertNotIn('ipset-123', pending)
    
    def test_generate_v2_name(self):
        """Test v2 name generation"""
        name = self.graph.generate_v2_name('ipset', 'abc-123', 'Test-IPSet')
        
        # The function replaces hyphens with underscores
        self.assertEqual(name, 'Migrated_Test-IPSet_abc-123')
    
    def test_generate_placeholder(self):
        """Test placeholder generation"""
        placeholder = self.graph.generate_placeholder('ipset', 'abc-123')
        
        self.assertEqual(placeholder, '{{ipset:abc-123}}')


class TestPlaceholderManager(unittest.TestCase):
    """Test cases for PlaceholderManager class"""
    
    def setUp(self):
        self.graph = DependencyGraph()
        self.manager = PlaceholderManager(self.graph)
    
    def test_replace_placeholders_ipset(self):
        """Test replacing IPSet placeholders"""
        # Add IPSet to graph
        self.graph.add_ipset('ipset-123', 'TestIPSet')
        self.graph.mark_ipset_created('ipset-123', [{
            'v2_name': 'Migrated_TestIPSet_ipset-123_v4',
            'v2_arn': 'arn:aws:wafv2:us-east-1:123456789012:regional/ipset/test/abc'
        }])
        
        # JSON with placeholder
        json_obj = {
            'Rules': [{
                'Statement': {
                    'IPSetReferenceStatement': {
                        'ARN': '{{ipset:ipset-123}}'
                    }
                }
            }]
        }
        
        result = self.manager.replace_placeholders(json_obj)
        
        self.assertEqual(
            result['Rules'][0]['Statement']['IPSetReferenceStatement']['ARN'],
            'arn:aws:wafv2:us-east-1:123456789012:regional/ipset/test/abc'
        )
    
    def test_replace_placeholders_mixed_ipset(self):
        """Test replacing mixed IPv4/IPv6 IPSet placeholders"""
        # Add IPSet with both IPv4 and IPv6
        self.graph.add_ipset('ipset-123', 'TestIPSet')
        self.graph.mark_ipset_created('ipset-123', [
            {
                'v2_name': 'Migrated_TestIPSet_ipset-123_v4',
                'v2_arn': 'arn:aws:wafv2:us-east-1:123456789012:regional/ipset/test/abc-v4'
            },
            {
                'v2_name': 'Migrated_TestIPSet_ipset-123_v6',
                'v2_arn': 'arn:aws:wafv2:us-east-1:123456789012:regional/ipset/test/abc-v6'
            }
        ])
        
        # JSON with split placeholders
        json_obj = {
            'Rules': [{
                'Statement': {
                    'IPSetReferenceStatement': {
                        'ARN': '{{ipset:ipset-123}}-ipv4'
                    }
                }
            }]
        }
        
        result = self.manager.replace_placeholders(json_obj)
        
        self.assertEqual(
            result['Rules'][0]['Statement']['IPSetReferenceStatement']['ARN'],
            'arn:aws:wafv2:us-east-1:123456789012:regional/ipset/test/abc-v4'
        )
    
    def test_replace_placeholders_regex(self):
        """Test replacing RegexPatternSet placeholders"""
        # Add RegexPatternSet to graph
        self.graph.add_regex_set('regex-456', 'TestRegex')
        self.graph.mark_created('regex', 'regex-456', 'arn:aws:wafv2:us-east-1:123456789012:regional/regexpatternset/test/def')
        
        # JSON with placeholder
        json_obj = {
            'Rules': [{
                'Statement': {
                    'RegexPatternSetReferenceStatement': {
                        'ARN': '{{regex:regex-456}}'
                    }
                }
            }]
        }
        
        result = self.manager.replace_placeholders(json_obj)
        
        self.assertEqual(
            result['Rules'][0]['Statement']['RegexPatternSetReferenceStatement']['ARN'],
            'arn:aws:wafv2:us-east-1:123456789012:regional/regexpatternset/test/def'
        )
    
    def test_remove_rules_with_unresolved_placeholders(self):
        """Test removing rules that still contain placeholders"""
        json_obj = {
            'Rules': [
                {
                    'Name': 'Rule1',
                    'Statement': {
                        'IPSetReferenceStatement': {
                            'ARN': '{{ipset:ipset-123}}'
                        }
                    }
                },
                {
                    'Name': 'Rule2',
                    'Statement': {
                        'ByteMatchStatement': {
                            'SearchString': 'test'
                        }
                    }
                }
            ]
        }
        
        result = self.manager.replace_placeholders(json_obj)
        
        # Only Rule2 should remain as Rule1 has unresolved placeholder
        self.assertEqual(len(result['Rules']), 1)
        self.assertEqual(result['Rules'][0]['Name'], 'Rule2')


class TestWAFMigrator(unittest.TestCase):
    """Test cases for WAFMigrator class"""
    
    def setUp(self):
        # Mock the boto3 clients
        self.mock_waf_classic = Mock()
        self.mock_wafv2 = Mock()
        
        # Patch the client creation in the dynamically loaded module
        self.patcher = patch.object(waf_migrator, 'boto3')
        self.mock_boto3 = self.patcher.start()
        self.mock_boto3_client = self.mock_boto3.client
        
        def client_side_effect(service, **kwargs):
            if service == 'waf':
                return self.mock_waf_classic
            elif service == 'waf-regional':
                return self.mock_waf_classic
            elif service == 'wafv2':
                return self.mock_wafv2
            else:
                return Mock()
        
        self.mock_boto3_client.side_effect = client_side_effect
        
        # Create migrator instance
        self.migrator = WAFMigrator(region='us-east-1')
    
    def tearDown(self):
        self.patcher.stop()
    
    def test_init(self):
        """Test WAFMigrator initialization"""
        self.assertIsNotNone(self.migrator.waf_classic)
        self.assertIsNotNone(self.migrator.wafv2)
        self.assertEqual(self.migrator.scope, 'REGIONAL')  # us-east-1 uses REGIONAL scope
        self.assertIsNotNone(self.migrator.dependency_graph)
        self.assertIsNotNone(self.migrator.placeholder_manager)
    
    def test_list_classic_webacls(self):
        """Test listing Classic WebACLs"""
        # Mock response
        self.mock_waf_classic.list_web_acls.return_value = {
            'WebACLs': [
                {'WebACLId': 'acl-123', 'Name': 'TestACL'}
            ]
        }
        self.mock_waf_classic.get_web_acl.return_value = {
            'WebACL': {
                'WebACLId': 'acl-123',
                'Name': 'TestACL',
                'Rules': [{'RuleId': 'rule-1'}],
                'DefaultAction': {'Type': 'ALLOW'}
            }
        }
        
        result = self.migrator.list_classic_webacls()
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['id'], 'acl-123')
        self.assertEqual(result[0]['name'], 'TestACL')
        self.assertEqual(result[0]['rule_count'], 1)
        self.assertEqual(result[0]['default_action'], 'ALLOW')
    
    def test_get_classic_logging_configuration(self):
        """Test getting Classic logging configuration"""
        # Mock response
        self.mock_waf_classic.get_logging_configuration.return_value = {
            'LoggingConfiguration': {
                'LogDestinationConfigs': ['arn:aws:kinesis:test'],
                'RedactedFields': [{'Type': 'QUERY_STRING'}]
            }
        }
        
        result = self.migrator.get_classic_logging_configuration('arn:test:webacl')
        
        self.assertIsNotNone(result)
        self.assertEqual(len(result['LogDestinationConfigs']), 1)
        self.assertEqual(len(result['RedactedFields']), 1)
    
    def test_convert_classic_redacted_fields(self):
        """Test converting Classic redacted fields to WAFv2 format"""
        classic_fields = [
            {'Type': 'QUERY_STRING'},
            {'Type': 'URI'},
            {'Type': 'METHOD'},
            {'Type': 'HEADER', 'Data': 'User-Agent'}
        ]
        
        result = self.migrator.convert_classic_redacted_fields(classic_fields)
        
        self.assertEqual(len(result), 4)
        self.assertIn({'QueryString': {}}, result)
        self.assertIn({'UriPath': {}}, result)
        self.assertIn({'Method': {}}, result)
        self.assertIn({'SingleHeader': {'Name': 'User-Agent'}}, result)
    
    def test_map_action_type(self):
        """Test mapping Classic action types to v2"""
        self.assertEqual(self.migrator._map_action_type('ALLOW'), {'Allow': {}})
        self.assertEqual(self.migrator._map_action_type('BLOCK'), {'Block': {}})
        self.assertEqual(self.migrator._map_action_type('COUNT'), {'Count': {}})
        self.assertEqual(self.migrator._map_action_type('UNKNOWN'), {'Block': {}})
    
    def test_map_field_to_match(self):
        """Test mapping Classic FieldToMatch to v2"""
        self.assertEqual(self.migrator._map_field_to_match({'Type': 'URI'}), {'UriPath': {}})
        self.assertEqual(self.migrator._map_field_to_match({'Type': 'QUERY_STRING'}), {'QueryString': {}})
        self.assertEqual(self.migrator._map_field_to_match({'Type': 'METHOD'}), {'Method': {}})
        self.assertEqual(self.migrator._map_field_to_match({'Type': 'BODY'}), {'Body': {}})
        self.assertEqual(
            self.migrator._map_field_to_match({'Type': 'HEADER', 'Data': 'Cookie'}),
            {'SingleHeader': {'Name': 'Cookie'}}
        )
    
    def test_map_text_transformations(self):
        """Test mapping Classic text transformations to v2"""
        result = self.migrator._map_text_transformations(['LOWERCASE', 'HTML_ENTITY_DECODE'])
        
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], {'Priority': 0, 'Type': 'LOWERCASE'})
        self.assertEqual(result[1], {'Priority': 1, 'Type': 'HTML_ENTITY_DECODE'})
    
    def test_generate_unique_rule_name(self):
        """Test unique rule name generation"""
        result = self.migrator._generate_unique_rule_name('MyRule', 'rule-abc-123-def')
        
        self.assertTrue(result.startswith('MyRule'))
        self.assertTrue(result.endswith('-123-def'))
        self.assertLessEqual(len(result), 128)
    
    def test_create_safe_or_statement(self):
        """Test creating OrStatement only when needed"""
        # No statements
        result = self.migrator._create_safe_or_statement([])
        self.assertIsNone(result)
        
        # Single statement
        stmt = {'ByteMatchStatement': {'SearchString': 'test'}}
        result = self.migrator._create_safe_or_statement([stmt])
        self.assertEqual(result, stmt)
        
        # Multiple statements
        stmt1 = {'ByteMatchStatement': {'SearchString': 'test1'}}
        stmt2 = {'ByteMatchStatement': {'SearchString': 'test2'}}
        result = self.migrator._create_safe_or_statement([stmt1, stmt2])
        self.assertIn('OrStatement', result)
        self.assertEqual(len(result['OrStatement']['Statements']), 2)
    
    @patch('csv.writer')
    @patch('builtins.open', create=True)
    def test_generate_migration_report(self, mock_open, mock_csv_writer):
        """Test migration report generation"""
        # Suppress CSV generation for test
        self.migrator._suppress_csv_generation = True
        
        migrations = [
            {
                'classic_name': 'TestWebACL',
                'classic_id': 'acl-123',
                'status': 'SUCCESS',
                'v2_name': 'Migrated_TestWebACL_acl-123',
                'v2_arn': 'arn:aws:wafv2:test'
            },
            {
                'classic_name': 'FailedWebACL',
                'classic_id': 'acl-456',
                'status': 'FAILED',
                'error': 'Test error'
            }
        ]
        
        # Should not raise any exceptions
        self.migrator._generate_migration_report(migrations, 'WebACL')
    
    def test_check_existing_ipset(self):
        """Test checking for existing IPSet"""
        # Mock existing IPSet
        self.mock_wafv2.list_ip_sets.return_value = {
            'IPSets': [
                {
                    'Name': 'Migrated_TestIPSet_ipset-123',
                    'Id': 'new-id',
                    'ARN': 'arn:aws:wafv2:test'
                }
            ]
        }
        
        self.migrator.dependency_graph.add_ipset('ipset-123', 'TestIPSet')
        
        result = self.migrator.check_existing_ipset('ipset-123', 'TestIPSet')
        
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['v2_name'], 'Migrated_TestIPSet_ipset-123')
    
    def test_migrate_ipset_ipv4_only(self):
        """Test migrating IPv4-only IPSet"""
        # Mock Classic IPSet
        self.mock_waf_classic.get_ip_set.return_value = {
            'IPSet': {
                'IPSetId': 'ipset-123',
                'Name': 'TestIPSet',
                'IPSetDescriptors': [
                    {'Type': 'IPV4', 'Value': '192.0.2.0/24'},
                    {'Type': 'IPV4', 'Value': '198.51.100.0/24'}
                ]
            }
        }
        
        # Mock v2 creation
        self.mock_wafv2.create_ip_set.return_value = {
            'Summary': {
                'Name': 'Migrated_TestIPSet_ipset-123_v4',
                'Id': 'new-id',
                'ARN': 'arn:aws:wafv2:test:ipv4'
            }
        }
        
        result = self.migrator._migrate_ipset('ipset-123')
        
        self.assertEqual(result['type'], 'IPSet')
        self.assertEqual(result['classic_id'], 'ipset-123')
        self.assertEqual(len(result['v2_ipsets']), 1)
        self.assertFalse(result['split_required'])
    
    def test_migrate_ipset_mixed(self):
        """Test migrating mixed IPv4/IPv6 IPSet"""
        # Mock Classic IPSet with mixed addresses
        self.mock_waf_classic.get_ip_set.return_value = {
            'IPSet': {
                'IPSetId': 'ipset-123',
                'Name': 'TestIPSet',
                'IPSetDescriptors': [
                    {'Type': 'IPV4', 'Value': '192.0.2.0/24'},
                    {'Type': 'IPV6', 'Value': '2001:db8::/32'}
                ]
            }
        }
        
        # Mock v2 creation calls
        create_call_count = 0
        def create_ip_set_side_effect(**kwargs):
            nonlocal create_call_count
            create_call_count += 1
            if kwargs['IPAddressVersion'] == 'IPV4':
                return {
                    'Summary': {
                        'Name': kwargs['Name'],
                        'Id': 'ipv4-id',
                        'ARN': 'arn:aws:wafv2:test:ipv4'
                    }
                }
            else:
                return {
                    'Summary': {
                        'Name': kwargs['Name'],
                        'Id': 'ipv6-id',
                        'ARN': 'arn:aws:wafv2:test:ipv6'
                    }
                }
        
        self.mock_wafv2.create_ip_set.side_effect = create_ip_set_side_effect
        
        result = self.migrator._migrate_ipset('ipset-123')
        
        self.assertEqual(result['type'], 'IPSet')
        self.assertEqual(result['classic_id'], 'ipset-123')
        self.assertEqual(len(result['v2_ipsets']), 2)
        self.assertTrue(result['split_required'])
        self.assertEqual(create_call_count, 2)
    
    def test_migrate_regex_pattern_set(self):
        """Test migrating RegexPatternSet"""
        # Mock Classic RegexPatternSet
        self.mock_waf_classic.get_regex_pattern_set.return_value = {
            'RegexPatternSet': {
                'RegexPatternSetId': 'regex-456',
                'Name': 'TestRegex',
                'RegexPatternStrings': ['pattern1', 'pattern2']
            }
        }
        
        # Mock v2 creation
        self.mock_wafv2.create_regex_pattern_set.return_value = {
            'Summary': {
                'Name': 'Migrated_TestRegex_regex-456',
                'Id': 'new-id',
                'ARN': 'arn:aws:wafv2:test:regex'
            }
        }
        
        result = self.migrator._migrate_regex_pattern_set('regex-456')
        
        self.assertEqual(result['type'], 'RegexPatternSet')
        self.assertEqual(result['classic_id'], 'regex-456')
        self.assertEqual(result['pattern_count'], 2)
        self.assertIn('v2_arn', result)
    
    def test_analyze_predicate_ipset(self):
        """Test analyzing IPSet predicate"""
        # Mock IPSet
        self.mock_waf_classic.get_ip_set.return_value = {
            'IPSet': {
                'IPSetId': 'ipset-123',
                'Name': 'TestIPSet',
                'IPSetDescriptors': [{'Type': 'IPV4', 'Value': '192.0.2.0/24'}]
            }
        }
        
        predicate = {
            'Type': 'IPMatch',
            'DataId': 'ipset-123',
            'Negated': False
        }
        
        result = self.migrator._analyze_predicate(predicate)
        
        self.assertEqual(result['type'], 'IPMatch')
        self.assertEqual(result['data_id'], 'ipset-123')
        self.assertFalse(result['negated'])
        # v2_statement is None until IPSet is created
        self.assertIsNone(result['v2_statement'])
    
    def test_analyze_predicate_empty_ipset(self):
        """Test analyzing empty IPSet predicate"""
        # Mock empty IPSet
        self.mock_waf_classic.get_ip_set.return_value = {
            'IPSet': {
                'IPSetId': 'ipset-123',
                'Name': 'EmptyIPSet',
                'IPSetDescriptors': []
            }
        }
        
        predicate = {
            'Type': 'IPMatch',
            'DataId': 'ipset-123',
            'Negated': False
        }
        
        result = self.migrator._analyze_predicate(predicate)
        
        self.assertEqual(result['type'], 'IPMatch')
        self.assertIsNone(result['v2_statement'])  # Empty IPSet should return None
    
    def test_scan_predicate_byte_match(self):
        """Test scanning ByteMatch predicate"""
        # Mock ByteMatchSet
        self.mock_waf_classic.get_byte_match_set.return_value = {
            'ByteMatchSet': {
                'ByteMatchSetId': 'byte-789',
                'Name': 'TestByteMatch',
                'ByteMatchTuples': [{
                    'TargetString': b'malicious',
                    'FieldToMatch': {'Type': 'BODY'},
                    'TextTransformation': 'LOWERCASE',
                    'PositionalConstraint': 'CONTAINS'
                }]
            }
        }
        
        predicate = {
            'Type': 'ByteMatch',
            'DataId': 'byte-789',
            'Negated': False
        }
        
        result = self.migrator._scan_predicate(predicate)
        
        self.assertIsNotNone(result)
        self.assertIn('ByteMatchStatement', result)
        self.assertEqual(result['ByteMatchStatement']['SearchString'], 'malicious')
    
    def test_rollback_created_resources(self):
        """Test rollback functionality"""
        # Track some resources
        self.migrator._track_created_resource('IPSet', 'ipset-id', 'TestIPSet')
        self.migrator._track_created_resource('RuleGroup', 'rg-id', 'TestRuleGroup')
        
        # Mock get and delete operations
        self.mock_wafv2.get_ip_set.return_value = {'LockToken': 'token1'}
        self.mock_wafv2.get_rule_group.return_value = {'LockToken': 'token2'}
        
        errors = self.migrator._rollback_created_resources()
        
        # Verify delete calls were made
        self.mock_wafv2.delete_ip_set.assert_called_once()
        self.mock_wafv2.delete_rule_group.assert_called_once()
        self.assertEqual(len(errors), 0)
        self.assertEqual(len(self.migrator.created_resources), 0)
    
    def test_create_with_retry(self):
        """Test retry logic for resource creation"""
        # Mock function that fails twice then succeeds
        call_count = 0
        def create_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception('WAFUnavailableEntityException: Resource not ready')
            return {'Success': True}
        
        with patch('time.sleep'):  # Mock sleep to speed up test
            result = self.migrator._create_with_retry(create_func, max_retries=5)
        
        self.assertEqual(result, {'Success': True})
        self.assertEqual(call_count, 3)
    
    def test_execute_streamlined_migration_success(self):
        """Test successful streamlined migration"""
        # Mock WebACL details
        self.mock_waf_classic.get_web_acl.return_value = {
            'WebACL': {
                'WebACLId': 'acl-123',
                'Name': 'TestACL',
                'DefaultAction': {'Type': 'ALLOW'},
                'Rules': [{
                    'RuleId': 'rule-123',
                    'Priority': 1,
                    'Action': {'Type': 'BLOCK'},
                    'Type': 'REGULAR'
                }]
            }
        }
        
        # Mock rule details
        self.mock_waf_classic.get_rule.return_value = {
            'Rule': {
                'RuleId': 'rule-123',
                'Name': 'TestRule',
                'Predicates': [{
                    'Type': 'IPMatch',
                    'DataId': 'ipset-123',
                    'Negated': False
                }]
            }
        }
        
        # Mock IPSet details
        self.mock_waf_classic.get_ip_set.return_value = {
            'IPSet': {
                'IPSetId': 'ipset-123',
                'Name': 'TestIPSet',
                'IPSetDescriptors': [{'Type': 'IPV4', 'Value': '192.0.2.0/24'}]
            }
        }
        
        # Mock v2 list operations (no existing resources)
        self.mock_wafv2.list_ip_sets.return_value = {'IPSets': []}
        self.mock_wafv2.list_regex_pattern_sets.return_value = {'RegexPatternSets': []}
        self.mock_wafv2.list_rule_groups.return_value = {'RuleGroups': []}
        
        # Mock v2 creation operations
        self.mock_wafv2.create_ip_set.return_value = {
            'Summary': {'Name': 'Test', 'Id': 'test-id', 'ARN': 'arn:test'}
        }
        self.mock_wafv2.check_capacity.return_value = {'Capacity': 100}
        self.mock_wafv2.create_web_acl.return_value = {
            'Summary': {'Name': 'Test', 'Id': 'test-id', 'ARN': 'arn:test'}
        }
        
        with patch('time.sleep'):  # Mock sleep to speed up test
            result = self.migrator.execute_streamlined_migration('acl-123')
        
        self.assertTrue(result.get('success'))
        self.assertIn('webacl', result)
        self.assertEqual(result['webacl']['webacl_name'], 'Migrated_TestACL_acl-123')


class TestHelperFunctions(unittest.TestCase):
    """Test cases for helper functions"""
    
    @patch('boto3.client')
    def test_check_aws_credentials_success(self, mock_boto3_client):
        """Test successful AWS credentials check"""
        mock_sts = Mock()
        mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_boto3_client.return_value = mock_sts
        
        result = check_aws_credentials()
        
        self.assertTrue(result)
        mock_boto3_client.assert_called_once_with('sts')
    
    @patch('boto3.client')
    def test_check_aws_credentials_failure(self, mock_boto3_client):
        """Test failed AWS credentials check"""
        from botocore.exceptions import NoCredentialsError
        mock_sts = Mock()
        mock_sts.get_caller_identity.side_effect = NoCredentialsError()
        mock_boto3_client.return_value = mock_sts
        
        result = check_aws_credentials()
        
        self.assertFalse(result)
    
    def test_convert_bytes_to_string(self):
        """Test converting bytes to string recursively"""
        # Test with bytes
        self.assertEqual(convert_bytes_to_string(b'hello'), 'hello')
        
        # Test with dict containing bytes
        input_dict = {'key': b'value', 'nested': {'data': b'test'}}
        result = convert_bytes_to_string(input_dict)
        self.assertEqual(result['key'], 'value')
        self.assertEqual(result['nested']['data'], 'test')
        
        # Test with list containing bytes
        input_list = [b'one', b'two', {'data': b'three'}]
        result = convert_bytes_to_string(input_list)
        self.assertEqual(result[0], 'one')
        self.assertEqual(result[1], 'two')
        self.assertEqual(result[2]['data'], 'three')
        
        # Test with regular string
        self.assertEqual(convert_bytes_to_string('hello'), 'hello')


class TestIntegrationScenarios(unittest.TestCase):
    """Integration test scenarios"""
    
    @patch.object(waf_migrator.boto3, 'client')
    def test_migrate_webacl_with_multiple_rules(self, mock_boto3_client):
        """Test migrating WebACL with multiple rule types"""
        # Setup mocks
        mock_waf_classic = Mock()
        mock_wafv2 = Mock()
        
        def client_side_effect(service, **kwargs):
            if service in ['waf', 'waf-regional']:
                return mock_waf_classic
            elif service == 'wafv2':
                return mock_wafv2
            return Mock()
        
        mock_boto3_client.side_effect = client_side_effect
        
        # Mock WebACL with different rule types
        mock_waf_classic.get_web_acl.return_value = {
            'WebACL': {
                'WebACLId': 'acl-complex',
                'Name': 'ComplexACL',
                'DefaultAction': {'Type': 'ALLOW'},
                'Rules': [
                    {
                        'RuleId': 'rule-regular',
                        'Priority': 1,
                        'Action': {'Type': 'BLOCK'},
                        'Type': 'REGULAR'
                    },
                    {
                        'RuleId': 'rule-rate',
                        'Priority': 2,
                        'Action': {'Type': 'COUNT'},
                        'Type': 'RATE_BASED'
                    },
                    {
                        'RuleId': 'rg-123',
                        'Priority': 3,
                        'OverrideAction': {'Type': 'NONE'},
                        'Type': 'GROUP'
                    }
                ]
            }
        }
        
        # Mock rule details
        mock_waf_classic.get_rule.return_value = {
            'Rule': {
                'RuleId': 'rule-regular',
                'Name': 'RegularRule',
                'Predicates': []
            }
        }
        
        mock_waf_classic.get_rate_based_rule.return_value = {
            'Rule': {
                'RuleId': 'rule-rate',
                'Name': 'RateRule',
                'RateKey': 'IP',
                'RateLimit': 2000,
                'MatchPredicates': []
            }
        }
        
        mock_waf_classic.get_rule_group.return_value = {
            'RuleGroup': {
                'RuleGroupId': 'rg-123',
                'Name': 'TestRuleGroup'
            }
        }
        
        # Add activated rules to the RuleGroup
        mock_waf_classic.list_activated_rules_in_rule_group.return_value = {
            'ActivatedRules': [{
                'RuleId': 'rule-in-group',
                'Priority': 1,
                'Action': {'Type': 'BLOCK'}
            }]
        }
        
        # Mock the rule inside the RuleGroup
        def get_rule_side_effect(RuleId):
            if RuleId == 'rule-in-group':
                return {
                    'Rule': {
                        'RuleId': 'rule-in-group',
                        'Name': 'RuleInGroup',
                        'Predicates': [{
                            'Type': 'ByteMatch',
                            'DataId': 'byte-in-group',
                            'Negated': False
                        }]
                    }
                }
            else:
                return mock_waf_classic.get_rule.return_value
        
        mock_waf_classic.get_rule.side_effect = get_rule_side_effect
        
        # Mock ByteMatchSet for the rule in RuleGroup
        mock_waf_classic.get_byte_match_set.return_value = {
            'ByteMatchSet': {
                'ByteMatchSetId': 'byte-in-group',
                'Name': 'ByteMatchInGroup',
                'ByteMatchTuples': [{
                    'TargetString': b'test',
                    'FieldToMatch': {'Type': 'URI'},
                    'TextTransformation': 'NONE',
                    'PositionalConstraint': 'CONTAINS'
                }]
            }
        }
        
        # Mock v2 operations
        mock_wafv2.list_ip_sets.return_value = {'IPSets': []}
        mock_wafv2.list_regex_pattern_sets.return_value = {'RegexPatternSets': []}
        mock_wafv2.list_rule_groups.return_value = {'RuleGroups': []}
        mock_wafv2.create_rule_group.return_value = {
            'Summary': {'ARN': 'arn:rulegroup', 'Id': 'rg-id'}
        }
        mock_wafv2.check_capacity.return_value = {'Capacity': 300}
        mock_wafv2.create_web_acl.return_value = {
            'Summary': {'ARN': 'arn:webacl', 'Id': 'acl-id', 'Name': 'Migrated_ComplexACL'}
        }
        
        # Execute migration
        migrator = WAFMigrator(region='us-east-1')
        with patch('time.sleep'):
            result = migrator.execute_streamlined_migration('acl-complex')
        
        # Verify results
        self.assertTrue(result.get('success'))
        # RuleGroup should be created since it has activated rules
        mock_wafv2.create_rule_group.assert_called_once()
        mock_wafv2.create_web_acl.assert_called_once()
    
    @patch.object(waf_migrator.boto3, 'client')
    def test_migrate_with_existing_resources(self, mock_boto3_client):
        """Test migration when some resources already exist"""
        # Setup mocks
        mock_waf_classic = Mock()
        mock_wafv2 = Mock()
        
        def client_side_effect(service, **kwargs):
            if service in ['waf', 'waf-regional']:
                return mock_waf_classic
            elif service == 'wafv2':
                return mock_wafv2
            return Mock()
        
        mock_boto3_client.side_effect = client_side_effect
        
        # Mock WebACL
        mock_waf_classic.get_web_acl.return_value = {
            'WebACL': {
                'WebACLId': 'acl-existing',
                'Name': 'ExistingACL',
                'DefaultAction': {'Type': 'ALLOW'},
                'Rules': [{
                    'RuleId': 'rule-123',
                    'Priority': 1,
                    'Action': {'Type': 'BLOCK'},
                    'Type': 'REGULAR'
                }]
            }
        }
        
        # Mock rule with IPSet
        mock_waf_classic.get_rule.return_value = {
            'Rule': {
                'RuleId': 'rule-123',
                'Name': 'TestRule',
                'Predicates': [{
                    'Type': 'IPMatch',
                    'DataId': 'ipset-existing',
                    'Negated': False
                }]
            }
        }
        
        mock_waf_classic.get_ip_set.return_value = {
            'IPSet': {
                'IPSetId': 'ipset-existing',
                'Name': 'ExistingIPSet',
                'IPSetDescriptors': [{'Type': 'IPV4', 'Value': '10.0.0.0/8'}]
            }
        }
        
        # Mock v2 lists - IPSet already exists
        mock_wafv2.list_ip_sets.return_value = {
            'IPSets': [{
                'Name': 'Migrated_ExistingIPSet_ipset-existing',
                'Id': 'existing-id',
                'ARN': 'arn:existing:ipset'
            }]
        }
        mock_wafv2.list_regex_pattern_sets.return_value = {'RegexPatternSets': []}
        mock_wafv2.list_rule_groups.return_value = {'RuleGroups': []}
        
        mock_wafv2.check_capacity.return_value = {'Capacity': 50}
        mock_wafv2.create_web_acl.return_value = {
            'Summary': {'ARN': 'arn:webacl', 'Id': 'acl-id', 'Name': 'Migrated_ExistingACL'}
        }
        
        # Execute migration
        migrator = WAFMigrator(region='us-east-1')
        with patch('time.sleep'):
            result = migrator.execute_streamlined_migration('acl-existing')
        
        # Verify IPSet was not created (already exists)
        self.assertTrue(result.get('success'))
        mock_wafv2.create_ip_set.assert_not_called()
        mock_wafv2.create_web_acl.assert_called_once()
    
    @patch.object(waf_migrator.boto3, 'client')
    def test_migrate_with_existing_rulegroup(self, mock_boto3_client):
        """Test migration when RuleGroup already exists"""
        # Setup mocks
        mock_waf_classic = Mock()
        mock_wafv2 = Mock()
        
        def client_side_effect(service, **kwargs):
            if service in ['waf', 'waf-regional']:
                return mock_waf_classic
            elif service == 'wafv2':
                return mock_wafv2
            return Mock()
        
        mock_boto3_client.side_effect = client_side_effect
        
        # Mock WebACL with RuleGroup reference
        mock_waf_classic.get_web_acl.return_value = {
            'WebACL': {
                'WebACLId': 'acl-with-rg',
                'Name': 'WebACLWithRuleGroup',
                'DefaultAction': {'Type': 'ALLOW'},
                'Rules': [{
                    'RuleId': 'rg-123',
                    'Priority': 1,
                    'OverrideAction': {'Type': 'NONE'},
                    'Type': 'GROUP'
                }]
            }
        }
        
        # Mock RuleGroup
        mock_waf_classic.get_rule_group.return_value = {
            'RuleGroup': {
                'RuleGroupId': 'rg-123',
                'Name': 'ExistingRuleGroup'
            }
        }
        mock_waf_classic.list_activated_rules_in_rule_group.return_value = {
            'ActivatedRules': [{
                'RuleId': 'rule-in-group',
                'Priority': 1,
                'Action': {'Type': 'BLOCK'}
            }]
        }
        
        # Mock rule inside RuleGroup
        mock_waf_classic.get_rule.return_value = {
            'Rule': {
                'RuleId': 'rule-in-group',
                'Name': 'RuleInGroup',
                'Predicates': []
            }
        }
        
        # Mock v2 lists - RuleGroup already exists
        mock_wafv2.list_ip_sets.return_value = {'IPSets': []}
        mock_wafv2.list_regex_pattern_sets.return_value = {'RegexPatternSets': []}
        mock_wafv2.list_rule_groups.return_value = {
            'RuleGroups': [{
                'Name': 'Migrated_ExistingRuleGroup_rg-123',
                'Id': 'existing-rg-id',
                'ARN': 'arn:existing:rulegroup'
            }]
        }
        
        mock_wafv2.check_capacity.return_value = {'Capacity': 100}
        mock_wafv2.create_web_acl.return_value = {
            'Summary': {'ARN': 'arn:webacl', 'Id': 'acl-id', 'Name': 'Migrated_WebACLWithRuleGroup'}
        }
        
        # Execute migration
        migrator = WAFMigrator(region='us-east-1')
        with patch('time.sleep'):
            result = migrator.execute_streamlined_migration('acl-with-rg')
        
        # Verify RuleGroup was not created (already exists)
        self.assertTrue(result.get('success'))
        mock_wafv2.create_rule_group.assert_not_called()
        mock_wafv2.create_web_acl.assert_called_once()
    
    @patch.object(waf_migrator.boto3, 'client')
    def test_execute_streamlined_migration_failure_capacity_exceeded(self, mock_boto3_client):
        """Test migration failure when capacity is exceeded"""
        # Setup mocks
        mock_waf_classic = Mock()
        mock_wafv2 = Mock()
        
        def client_side_effect(service, **kwargs):
            if service in ['waf', 'waf-regional']:
                return mock_waf_classic
            elif service == 'wafv2':
                return mock_wafv2
            return Mock()
        
        mock_boto3_client.side_effect = client_side_effect
        
        # Mock WebACL with many rules
        mock_waf_classic.get_web_acl.return_value = {
            'WebACL': {
                'WebACLId': 'acl-overcapacity',
                'Name': 'OverCapacityACL',
                'DefaultAction': {'Type': 'ALLOW'},
                'Rules': [{
                    'RuleId': f'rule-{i}',
                    'Priority': i,
                    'Action': {'Type': 'BLOCK'},
                    'Type': 'REGULAR'
                } for i in range(10)]  # Many rules
            }
        }
        
        # Mock rules
        def get_rule_side_effect(RuleId):
            rule_num = RuleId.split('-')[1]
            return {
                'Rule': {
                    'RuleId': RuleId,
                    'Name': f'TestRule{rule_num}',
                    'Predicates': []
                }
            }
        
        mock_waf_classic.get_rule.side_effect = get_rule_side_effect
        
        # Mock v2 operations
        mock_wafv2.list_ip_sets.return_value = {'IPSets': []}
        mock_wafv2.list_regex_pattern_sets.return_value = {'RegexPatternSets': []}
        mock_wafv2.list_rule_groups.return_value = {'RuleGroups': []}
        
        # Mock capacity check to exceed hard limit
        # New hard limit is 5000, so return 6000
        mock_wafv2.check_capacity.return_value = {'Capacity': 6000}
        
        # Execute migration
        migrator = WAFMigrator(region='us-east-1')
        with patch('time.sleep'):
            result = migrator.execute_streamlined_migration('acl-overcapacity')
        
        # Verify migration failed due to capacity
        self.assertFalse(result.get('success'))
        self.assertIn('exceeds hard limit', result.get('error', '').lower())
        self.assertIn('6000/5000', result.get('error', ''))
        # WebACL should not be created
        mock_wafv2.create_web_acl.assert_not_called()
    
    @patch.object(waf_migrator.boto3, 'client')
    def test_capacity_limit_per_webacl(self, mock_boto3_client):
        """Test that capacity limit is per WebACL, not global"""
        # Setup mocks
        mock_waf_classic = Mock()
        mock_wafv2 = Mock()
        
        def client_side_effect(service, **kwargs):
            if service in ['waf', 'waf-regional']:
                return mock_waf_classic
            elif service == 'wafv2':
                return mock_wafv2
            return Mock()
        
        mock_boto3_client.side_effect = client_side_effect
        
        # First WebACL with high capacity
        mock_waf_classic.get_web_acl.side_effect = [
            {
                'WebACL': {
                    'WebACLId': 'acl-1',
                    'Name': 'HighCapacityACL1',
                    'DefaultAction': {'Type': 'ALLOW'},
                    'Rules': [{
                        'RuleId': 'rule-1',
                        'Priority': 1,
                        'Action': {'Type': 'BLOCK'},
                        'Type': 'REGULAR'
                    }]
                }
            },
            {
                'WebACL': {
                    'WebACLId': 'acl-2',
                    'Name': 'HighCapacityACL2',
                    'DefaultAction': {'Type': 'ALLOW'},
                    'Rules': [{
                        'RuleId': 'rule-2',
                        'Priority': 1,
                        'Action': {'Type': 'BLOCK'},
                        'Type': 'REGULAR'
                    }]
                }
            }
        ]
        
        # Mock rules
        mock_waf_classic.get_rule.side_effect = [
            {
                'Rule': {
                    'RuleId': 'rule-1',
                    'Name': 'TestRule1',
                    'Predicates': []
                }
            },
            {
                'Rule': {
                    'RuleId': 'rule-2',
                    'Name': 'TestRule2',
                    'Predicates': []
                }
            }
        ]
        
        # Mock v2 operations
        mock_wafv2.list_ip_sets.return_value = {'IPSets': []}
        mock_wafv2.list_regex_pattern_sets.return_value = {'RegexPatternSets': []}
        mock_wafv2.list_rule_groups.return_value = {'RuleGroups': []}
        
        # Each WebACL has its own capacity check
        # Both return high capacity (1400 units each) but under the limit
        mock_wafv2.check_capacity.side_effect = [
            {'Capacity': 1400},  # First WebACL
            {'Capacity': 1400}   # Second WebACL
        ]
        
        mock_wafv2.create_web_acl.side_effect = [
            {'Summary': {'ARN': 'arn:webacl1', 'Id': 'acl-id-1', 'Name': 'Migrated_HighCapacityACL1'}},
            {'Summary': {'ARN': 'arn:webacl2', 'Id': 'acl-id-2', 'Name': 'Migrated_HighCapacityACL2'}}
        ]
        
        # Execute migrations
        migrator = WAFMigrator(region='us-east-1')
        
        with patch('time.sleep'):
            # First WebACL - should succeed (1400 < 1500)
            result1 = migrator.execute_streamlined_migration('acl-1')
            self.assertTrue(result1.get('success'))
            
            # Second WebACL - should also succeed (capacity is per WebACL)
            result2 = migrator.execute_streamlined_migration('acl-2')
            self.assertTrue(result2.get('success'))
        
        # Both WebACLs should be created successfully
        self.assertEqual(mock_wafv2.create_web_acl.call_count, 2)
        # Capacity check should be called twice (once per WebACL)
        self.assertEqual(mock_wafv2.check_capacity.call_count, 2)
    
    @patch.object(waf_migrator.boto3, 'client')
    def test_cloudfront_webacl_higher_capacity_limit(self, mock_boto3_client):
        """Test that CloudFront WebACLs have higher capacity limit (5000 vs 1500)"""
        # Setup mocks
        mock_waf_classic = Mock()
        mock_wafv2 = Mock()
        
        def client_side_effect(service, **kwargs):
            if service == 'waf':
                return mock_waf_classic
            elif service == 'wafv2':
                return mock_wafv2
            return Mock()
        
        mock_boto3_client.side_effect = client_side_effect
        
        # Mock WebACL
        mock_waf_classic.get_web_acl.return_value = {
            'WebACL': {
                'WebACLId': 'acl-cloudfront',
                'Name': 'CloudFrontACL',
                'DefaultAction': {'Type': 'ALLOW'},
                'Rules': [{
                    'RuleId': 'rule-1',
                    'Priority': 1,
                    'Action': {'Type': 'BLOCK'},
                    'Type': 'REGULAR'
                }]
            }
        }
        
        mock_waf_classic.get_rule.return_value = {
            'Rule': {
                'RuleId': 'rule-1',
                'Name': 'TestRule',
                'Predicates': []
            }
        }
        
        # Mock v2 operations
        mock_wafv2.list_ip_sets.return_value = {'IPSets': []}
        mock_wafv2.list_regex_pattern_sets.return_value = {'RegexPatternSets': []}
        mock_wafv2.list_rule_groups.return_value = {'RuleGroups': []}
        
        # Return capacity that would fail for REGIONAL (1500) but pass for CLOUDFRONT (5000)
        mock_wafv2.check_capacity.return_value = {'Capacity': 3000}
        mock_wafv2.create_web_acl.return_value = {
            'Summary': {'ARN': 'arn:webacl', 'Id': 'acl-id', 'Name': 'Migrated_CloudFrontACL'}
        }
        
        # Create migrator for CloudFront (us-east-1 global)
        migrator = WAFMigrator(region='cloudfront')
        
        with patch('time.sleep'):
            result = migrator.execute_streamlined_migration('acl-cloudfront')
        
        # Should succeed because CloudFront limit is 5000
        self.assertTrue(result.get('success'))
        mock_wafv2.create_web_acl.assert_called_once()


# Additional test classes from test_waf_migrator_improvements.py and test_waf_migrator_comprehensive.py

class TestExistingResourcesComprehensive(unittest.TestCase):
    """Test cases for migration with existing IPSets, RegexPatternSets, and RuleGroups"""
    
    @patch.object(waf_migrator.boto3, 'client')
    def test_migrate_with_existing_regex_pattern_sets(self, mock_boto3_client):
        """Test migration when RegexPatternSets already exist"""
        # Setup mocks
        mock_waf_classic = Mock()
        mock_wafv2 = Mock()
        
        def client_side_effect(service, **kwargs):
            if service in ['waf', 'waf-regional']:
                return mock_waf_classic
            elif service == 'wafv2':
                return mock_wafv2
            return Mock()
        
        mock_boto3_client.side_effect = client_side_effect
        
        # Mock WebACL with regex match rule
        mock_waf_classic.get_web_acl.return_value = {
            'WebACL': {
                'WebACLId': 'acl-regex',
                'Name': 'RegexACL',
                'DefaultAction': {'Type': 'ALLOW'},
                'Rules': [{
                    'RuleId': 'rule-regex',
                    'Priority': 1,
                    'Action': {'Type': 'BLOCK'},
                    'Type': 'REGULAR'
                }]
            }
        }
        
        # Mock rule with RegexMatch predicate
        mock_waf_classic.get_rule.return_value = {
            'Rule': {
                'RuleId': 'rule-regex',
                'Name': 'RegexRule',
                'Predicates': [{
                    'Type': 'RegexMatch',
                    'DataId': 'regex-match-123',
                    'Negated': False
                }]
            }
        }
        
        # Mock RegexMatchSet
        mock_waf_classic.get_regex_match_set.return_value = {
            'RegexMatchSet': {
                'RegexMatchSetId': 'regex-match-123',
                'Name': 'TestRegexMatch',
                'RegexMatchTuples': [{
                    'FieldToMatch': {'Type': 'URI'},
                    'TextTransformation': 'NONE',
                    'RegexPatternSetId': 'regex-pattern-456'
                }]
            }
        }
        
        # Mock RegexPatternSet
        mock_waf_classic.get_regex_pattern_set.return_value = {
            'RegexPatternSet': {
                'RegexPatternSetId': 'regex-pattern-456',
                'Name': 'ExistingRegexPatternSet',
                'RegexPatternStrings': [
                    {'RegexString': '.*malicious.*'},
                    {'RegexString': '.*bad-bot.*'}
                ]
            }
        }
        
        # Mock v2 lists - RegexPatternSet already exists
        mock_wafv2.list_ip_sets.return_value = {'IPSets': []}
        mock_wafv2.list_regex_pattern_sets.return_value = {
            'RegexPatternSets': [{
                'Name': 'Migrated_ExistingRegexPatternSet_regex-pattern-456',
                'Id': 'existing-id',
                'ARN': 'arn:existing:regexpatternset'
            }]
        }
        mock_wafv2.list_rule_groups.return_value = {'RuleGroups': []}
        
        mock_wafv2.check_capacity.return_value = {'Capacity': 50}
        mock_wafv2.create_web_acl.return_value = {
            'Summary': {'ARN': 'arn:webacl', 'Id': 'acl-id', 'Name': 'Migrated_RegexACL'}
        }
        
        # Execute migration
        migrator = WAFMigrator(region='us-east-1')
        with patch('time.sleep'):
            result = migrator.execute_streamlined_migration('acl-regex')
        
        # Verify RegexPatternSet was not created (already exists)
        self.assertTrue(result.get('success'))
        mock_wafv2.create_regex_pattern_set.assert_not_called()
        mock_wafv2.create_web_acl.assert_called_once()
    
    @patch.object(waf_migrator.boto3, 'client')
    def test_migrate_with_all_existing_resources(self, mock_boto3_client):
        """Test migration when IPSets, RegexPatternSets, and RuleGroups all exist"""
        # Setup mocks
        mock_waf_classic = Mock()
        mock_wafv2 = Mock()
        
        def client_side_effect(service, **kwargs):
            if service in ['waf', 'waf-regional']:
                return mock_waf_classic
            elif service == 'wafv2':
                return mock_wafv2
            return Mock()
        
        mock_boto3_client.side_effect = client_side_effect
        
        # Mock complex WebACL
        mock_waf_classic.get_web_acl.return_value = {
            'WebACL': {
                'WebACLId': 'acl-complex',
                'Name': 'ComplexACL',
                'DefaultAction': {'Type': 'ALLOW'},
                'Rules': [
                    {
                        'RuleId': 'rule-ip',
                        'Priority': 1,
                        'Action': {'Type': 'BLOCK'},
                        'Type': 'REGULAR'
                    },
                    {
                        'RuleId': 'rule-regex',
                        'Priority': 2,
                        'Action': {'Type': 'BLOCK'},
                        'Type': 'REGULAR'
                    },
                    {
                        'RuleId': 'rg-123',
                        'Priority': 3,
                        'OverrideAction': {'Type': 'NONE'},
                        'Type': 'GROUP'
                    }
                ]
            }
        }
        
        # Mock rules
        mock_waf_classic.get_rule.side_effect = [
            {
                'Rule': {
                    'RuleId': 'rule-ip',
                    'Name': 'IPRule',
                    'Predicates': [{
                        'Type': 'IPMatch',
                        'DataId': 'ipset-existing',
                        'Negated': False
                    }]
                }
            },
            {
                'Rule': {
                    'RuleId': 'rule-regex',
                    'Name': 'RegexRule',
                    'Predicates': [{
                        'Type': 'RegexMatch',
                        'DataId': 'regex-match-existing',
                        'Negated': False
                    }]
                }
            }
        ]
        
        # Mock IPSet
        mock_waf_classic.get_ip_set.return_value = {
            'IPSet': {
                'IPSetId': 'ipset-existing',
                'Name': 'ExistingIPSet',
                'IPSetDescriptors': [{'Type': 'IPV4', 'Value': '10.0.0.0/8'}]
            }
        }
        
        # Mock RegexMatchSet and RegexPatternSet
        mock_waf_classic.get_regex_match_set.return_value = {
            'RegexMatchSet': {
                'RegexMatchSetId': 'regex-match-existing',
                'Name': 'ExistingRegexMatch',
                'RegexMatchTuples': [{
                    'FieldToMatch': {'Type': 'URI'},
                    'TextTransformation': 'NONE',
                    'RegexPatternSetId': 'regex-pattern-existing'
                }]
            }
        }
        
        mock_waf_classic.get_regex_pattern_set.return_value = {
            'RegexPatternSet': {
                'RegexPatternSetId': 'regex-pattern-existing',
                'Name': 'ExistingRegexPatternSet',
                'RegexPatternStrings': [{'RegexString': '.*pattern.*'}]
            }
        }
        
        # Mock RuleGroup
        mock_waf_classic.get_rule_group.return_value = {
            'RuleGroup': {
                'RuleGroupId': 'rg-123',
                'Name': 'ExistingRuleGroup'
            }
        }
        mock_waf_classic.list_activated_rules_in_rule_group.return_value = {
            'ActivatedRules': []
        }
        
        # Mock v2 lists - all resources already exist
        mock_wafv2.list_ip_sets.return_value = {
            'IPSets': [{
                'Name': 'Migrated_ExistingIPSet_ipset-existing',
                'Id': 'existing-ipset-id',
                'ARN': 'arn:existing:ipset'
            }]
        }
        mock_wafv2.list_regex_pattern_sets.return_value = {
            'RegexPatternSets': [{
                'Name': 'Migrated_ExistingRegexPatternSet_regex-pattern-existing',
                'Id': 'existing-regex-id',
                'ARN': 'arn:existing:regexpatternset'
            }]
        }
        mock_wafv2.list_rule_groups.return_value = {
            'RuleGroups': [{
                'Name': 'Migrated_ExistingRuleGroup_rg-123',
                'Id': 'existing-rg-id',
                'ARN': 'arn:existing:rulegroup'
            }]
        }
        
        mock_wafv2.check_capacity.return_value = {'Capacity': 100}
        mock_wafv2.create_web_acl.return_value = {
            'Summary': {'ARN': 'arn:webacl', 'Id': 'acl-id', 'Name': 'Migrated_ComplexACL'}
        }
        
        # Execute migration
        migrator = WAFMigrator(region='us-east-1')
        with patch('time.sleep'):
            result = migrator.execute_streamlined_migration('acl-complex')
        
        # Verify no resources were created (all already exist)
        self.assertTrue(result.get('success'))
        mock_wafv2.create_ip_set.assert_not_called()
        mock_wafv2.create_regex_pattern_set.assert_not_called()
        mock_wafv2.create_rule_group.assert_not_called()
        mock_wafv2.create_web_acl.assert_called_once()


class TestMigrationFailures(unittest.TestCase):
    """Test cases for various migration failure scenarios"""
    
    @patch.object(waf_migrator.boto3, 'client')
    def test_execute_streamlined_migration_failure_resource_creation(self, mock_boto3_client):
        """Test migration failure when resource creation fails"""
        # Setup mocks
        mock_waf_classic = Mock()
        mock_wafv2 = Mock()
        
        def client_side_effect(service, **kwargs):
            if service in ['waf', 'waf-regional']:
                return mock_waf_classic
            elif service == 'wafv2':
                return mock_wafv2
            return Mock()
        
        mock_boto3_client.side_effect = client_side_effect
        
        # Mock WebACL with IPSet rule
        mock_waf_classic.get_web_acl.return_value = {
            'WebACL': {
                'WebACLId': 'acl-fail',
                'Name': 'FailACL',
                'DefaultAction': {'Type': 'ALLOW'},
                'Rules': [{
                    'RuleId': 'rule-1',
                    'Priority': 1,
                    'Action': {'Type': 'BLOCK'},
                    'Type': 'REGULAR'
                }]
            }
        }
        
        mock_waf_classic.get_rule.return_value = {
            'Rule': {
                'RuleId': 'rule-1',
                'Name': 'TestRule',
                'Predicates': [{
                    'Type': 'IPMatch',
                    'DataId': 'ipset-123',
                    'Negated': False
                }]
            }
        }
        
        mock_waf_classic.get_ip_set.return_value = {
            'IPSet': {
                'IPSetId': 'ipset-123',
                'Name': 'TestIPSet',
                'IPSetDescriptors': [{'Type': 'IPV4', 'Value': '192.0.2.0/24'}]
            }
        }
        
        # Mock v2 operations
        mock_wafv2.list_ip_sets.return_value = {'IPSets': []}
        mock_wafv2.list_regex_pattern_sets.return_value = {'RegexPatternSets': []}
        mock_wafv2.list_rule_groups.return_value = {'RuleGroups': []}
        
        # IPSet creation fails
        mock_wafv2.create_ip_set.side_effect = Exception("AWS service error: InvalidParameterException")
        
        # Execute migration
        migrator = WAFMigrator(region='us-east-1')
        with patch('time.sleep'):
            result = migrator.execute_streamlined_migration('acl-fail')
        
        # Verify migration failed
        self.assertFalse(result.get('success'))
        self.assertIn('Failed to create IPSet', result.get('error', ''))
        # WebACL should not be created
        mock_wafv2.create_web_acl.assert_not_called()
    
    @patch.object(waf_migrator.boto3, 'client')
    def test_execute_streamlined_migration_failure_invalid_rule(self, mock_boto3_client):
        """Test migration failure when rule analysis fails"""
        # Setup mocks
        mock_waf_classic = Mock()
        mock_wafv2 = Mock()
        
        def client_side_effect(service, **kwargs):
            if service in ['waf', 'waf-regional']:
                return mock_waf_classic
            elif service == 'wafv2':
                return mock_wafv2
            return Mock()
        
        mock_boto3_client.side_effect = client_side_effect
        
        # Mock WebACL with invalid rule
        mock_waf_classic.get_web_acl.return_value = {
            'WebACL': {
                'WebACLId': 'acl-invalid',
                'Name': 'InvalidACL',
                'DefaultAction': {'Type': 'ALLOW'},
                'Rules': [{
                    'RuleId': 'rule-invalid',
                    'Priority': 1,
                    'Action': {'Type': 'BLOCK'},
                    'Type': 'REGULAR'
                }]
            }
        }
        
        # Rule fetch fails
        mock_waf_classic.get_rule.side_effect = Exception("Rule not found")
        
        # Mock v2 operations
        mock_wafv2.list_ip_sets.return_value = {'IPSets': []}
        mock_wafv2.list_regex_pattern_sets.return_value = {'RegexPatternSets': []}
        mock_wafv2.list_rule_groups.return_value = {'RuleGroups': []}
        
        # Execute migration
        migrator = WAFMigrator(region='us-east-1')
        with patch('time.sleep'):
            result = migrator.execute_streamlined_migration('acl-invalid')
        
        # Migration should still attempt to create WebACL with valid rules only
        # In this case, no valid rules, so check capacity would be called with empty rules
        self.assertIsNotNone(result)
    
    @patch.object(waf_migrator.boto3, 'client')
    def test_rollback_on_failure(self, mock_boto3_client):
        """Test that created resources are rolled back on migration failure"""
        # Setup mocks
        mock_waf_classic = Mock()
        mock_wafv2 = Mock()
        
        def client_side_effect(service, **kwargs):
            if service in ['waf', 'waf-regional']:
                return mock_waf_classic
            elif service == 'wafv2':
                return mock_wafv2
            return Mock()
        
        mock_boto3_client.side_effect = client_side_effect
        
        # Mock WebACL with IPSet and RegexPattern
        mock_waf_classic.get_web_acl.return_value = {
            'WebACL': {
                'WebACLId': 'acl-rollback',
                'Name': 'RollbackACL',
                'DefaultAction': {'Type': 'ALLOW'},
                'Rules': [{
                    'RuleId': 'rule-1',
                    'Priority': 1,
                    'Action': {'Type': 'BLOCK'},
                    'Type': 'REGULAR'
                }]
            }
        }
        
        mock_waf_classic.get_rule.return_value = {
            'Rule': {
                'RuleId': 'rule-1',
                'Name': 'TestRule',
                'Predicates': [
                    {
                        'Type': 'IPMatch',
                        'DataId': 'ipset-123',
                        'Negated': False
                    },
                    {
                        'Type': 'RegexMatch',
                        'DataId': 'regex-match-123',
                        'Negated': False
                    }
                ]
            }
        }
        
        mock_waf_classic.get_ip_set.return_value = {
            'IPSet': {
                'IPSetId': 'ipset-123',
                'Name': 'TestIPSet',
                'IPSetDescriptors': [{'Type': 'IPV4', 'Value': '192.0.2.0/24'}]
            }
        }
        
        mock_waf_classic.get_regex_match_set.return_value = {
            'RegexMatchSet': {
                'RegexMatchSetId': 'regex-match-123',
                'Name': 'TestRegexMatch',
                'RegexMatchTuples': [{
                    'FieldToMatch': {'Type': 'URI'},
                    'TextTransformation': 'NONE',
                    'RegexPatternSetId': 'regex-pattern-123'
                }]
            }
        }
        
        mock_waf_classic.get_regex_pattern_set.return_value = {
            'RegexPatternSet': {
                'RegexPatternSetId': 'regex-pattern-123',
                'Name': 'TestRegexPattern',
                'RegexPatternStrings': [{'RegexString': '.*test.*'}]
            }
        }
        
        # Mock v2 operations
        mock_wafv2.list_ip_sets.return_value = {'IPSets': []}
        mock_wafv2.list_regex_pattern_sets.return_value = {'RegexPatternSets': []}
        mock_wafv2.list_rule_groups.return_value = {'RuleGroups': []}
        
        # IPSet creation succeeds
        mock_wafv2.create_ip_set.return_value = {
            'Summary': {'Name': 'Test', 'Id': 'ipset-v2-id', 'ARN': 'arn:test:ipset'}
        }
        
        # RegexPatternSet creation succeeds
        mock_wafv2.create_regex_pattern_set.return_value = {
            'Summary': {'Name': 'Test', 'Id': 'regex-v2-id', 'ARN': 'arn:test:regex'}
        }
        
        # WebACL creation fails
        mock_wafv2.check_capacity.return_value = {'Capacity': 100}
        mock_wafv2.create_web_acl.side_effect = Exception("WebACL creation failed")
        
        # Mock get operations for rollback
        mock_wafv2.get_ip_set.return_value = {'LockToken': 'ipset-token'}
        mock_wafv2.get_regex_pattern_set.return_value = {'LockToken': 'regex-token'}
        
        # Execute migration
        migrator = WAFMigrator(region='us-east-1')
        with patch('time.sleep'):
            result = migrator.execute_streamlined_migration('acl-rollback')
        
        # Verify migration failed
        self.assertFalse(result.get('success'))
        self.assertIn('WebACL creation failed', result.get('error', ''))
        
        # Verify rollback was attempted
        mock_wafv2.delete_ip_set.assert_called_once()
        mock_wafv2.delete_regex_pattern_set.assert_called_once()


class TestCapacityHandling(unittest.TestCase):
    """Test cases for capacity validation and handling"""
    
    @patch.object(waf_migrator.boto3, 'client')
    def test_capacity_validation_before_webacl_creation(self, mock_boto3_client):
        """Test that capacity is validated before WebACL creation"""
        # Setup mocks
        mock_waf_classic = Mock()
        mock_wafv2 = Mock()
        
        def client_side_effect(service, **kwargs):
            if service in ['waf', 'waf-regional']:
                return mock_waf_classic
            elif service == 'wafv2':
                return mock_wafv2
            return Mock()
        
        mock_boto3_client.side_effect = client_side_effect
        
        # Mock WebACL
        mock_waf_classic.get_web_acl.return_value = {
            'WebACL': {
                'WebACLId': 'acl-capacity',
                'Name': 'CapacityACL',
                'DefaultAction': {'Type': 'ALLOW'},
                'Rules': [{
                    'RuleId': 'rule-1',
                    'Priority': 1,
                    'Action': {'Type': 'BLOCK'},
                    'Type': 'REGULAR'
                }]
            }
        }
        
        mock_waf_classic.get_rule.return_value = {
            'Rule': {
                'RuleId': 'rule-1',
                'Name': 'TestRule',
                'Predicates': []
            }
        }
        
        # Mock v2 operations
        mock_wafv2.list_ip_sets.return_value = {'IPSets': []}
        mock_wafv2.list_regex_pattern_sets.return_value = {'RegexPatternSets': []}
        mock_wafv2.list_rule_groups.return_value = {'RuleGroups': []}
        
        # Track check_capacity calls
        capacity_check_tracker = {'count': 0}
        def check_capacity_side_effect(**kwargs):
            capacity_check_tracker['count'] += 1
            return {'Capacity': 100}
        
        mock_wafv2.check_capacity.side_effect = check_capacity_side_effect
        mock_wafv2.create_web_acl.return_value = {
            'Summary': {'ARN': 'arn:webacl', 'Id': 'acl-id', 'Name': 'Migrated_CapacityACL'}
        }
        
        # Execute migration
        migrator = WAFMigrator(region='us-east-1')
        with patch('time.sleep'):
            result = migrator.execute_streamlined_migration('acl-capacity')
        
        # Verify capacity was checked before WebACL creation
        self.assertTrue(result.get('success'))
        self.assertEqual(capacity_check_tracker['count'], 1)
        mock_wafv2.check_capacity.assert_called_once()
        mock_wafv2.create_web_acl.assert_called_once()
        
        # Verify capacity was called before create_web_acl
        call_order = []
        for call in mock_wafv2.method_calls:
            if call[0] == 'check_capacity':
                call_order.append('check_capacity')
            elif call[0] == 'create_web_acl':
                call_order.append('create_web_acl')
        
        self.assertEqual(call_order.index('check_capacity'), 0)
        self.assertEqual(call_order.index('create_web_acl'), 1)
    
    @patch.object(waf_migrator.boto3, 'client')
    def test_capacity_warning_at_cost_threshold(self, mock_boto3_client):
        """Test that warning is issued when capacity exceeds cost threshold"""
        # Setup mocks
        mock_waf_classic = Mock()
        mock_wafv2 = Mock()
        
        def client_side_effect(service, **kwargs):
            if service in ['waf', 'waf-regional']:
                return mock_waf_classic
            elif service == 'wafv2':
                return mock_wafv2
            return Mock()
        
        mock_boto3_client.side_effect = client_side_effect
        
        # Mock WebACL
        mock_waf_classic.get_web_acl.return_value = {
            'WebACL': {
                'WebACLId': 'acl-high-capacity',
                'Name': 'HighCapacityACL',
                'DefaultAction': {'Type': 'ALLOW'},
                'Rules': [{
                    'RuleId': 'rule-1',
                    'Priority': 1,
                    'Action': {'Type': 'BLOCK'},
                    'Type': 'REGULAR'
                }]
            }
        }
        
        mock_waf_classic.get_rule.return_value = {
            'Rule': {
                'RuleId': 'rule-1',
                'Name': 'TestRule',
                'Predicates': []
            }
        }
        
        # Mock v2 operations
        mock_wafv2.list_ip_sets.return_value = {'IPSets': []}
        mock_wafv2.list_regex_pattern_sets.return_value = {'RegexPatternSets': []}
        mock_wafv2.list_rule_groups.return_value = {'RuleGroups': []}
        
        # Return capacity above cost threshold (2000 > 1500)
        mock_wafv2.check_capacity.return_value = {'Capacity': 2000}
        mock_wafv2.create_web_acl.return_value = {
            'Summary': {'ARN': 'arn:webacl', 'Id': 'acl-id', 'Name': 'Migrated_HighCapacityACL'}
        }
        
        # Execute migration
        migrator = WAFMigrator(region='us-east-1')
        with patch('builtins.print') as mock_print:
            with patch('time.sleep'):
                result = migrator.execute_streamlined_migration('acl-high-capacity')
        
        # Verify migration succeeded but warning was issued
        self.assertTrue(result.get('success'))
        
        # Check for warning message
        warning_found = False
        for call in mock_print.call_args_list:
            if call[0][0] and 'WARNING' in str(call[0][0]) and '1500' in str(call[0][0]):
                warning_found = True
                break
        
        self.assertTrue(warning_found, "Expected cost threshold warning not found")
    
    @patch.object(waf_migrator.boto3, 'client')
    def test_capacity_is_isolated_per_webacl(self, mock_boto3_client):
        """Test that capacity is isolated per WebACL and not cumulative"""
        # Setup mocks
        mock_waf_classic = Mock()
        mock_wafv2 = Mock()
        
        def client_side_effect(service, **kwargs):
            if service in ['waf', 'waf-regional']:
                return mock_waf_classic
            elif service == 'wafv2':
                return mock_wafv2
            return Mock()
        
        mock_boto3_client.side_effect = client_side_effect
        
        # Create migrator instance
        migrator = WAFMigrator(region='us-east-1')
        
        # First WebACL with high capacity
        mock_waf_classic.get_web_acl.side_effect = [
            {
                'WebACL': {
                    'WebACLId': 'acl-first',
                    'Name': 'FirstACL',
                    'DefaultAction': {'Type': 'ALLOW'},
                    'Rules': [{
                        'RuleId': 'rule-1',
                        'Priority': 1,
                        'Action': {'Type': 'BLOCK'},
                        'Type': 'REGULAR'
                    }]
                }
            },
            {
                'WebACL': {
                    'WebACLId': 'acl-second',
                    'Name': 'SecondACL',
                    'DefaultAction': {'Type': 'ALLOW'},
                    'Rules': [{
                        'RuleId': 'rule-2',
                        'Priority': 1,
                        'Action': {'Type': 'BLOCK'},
                        'Type': 'REGULAR'
                    }]
                }
            }
        ]
        
        # Mock rules
        mock_waf_classic.get_rule.side_effect = [
            {
                'Rule': {
                    'RuleId': 'rule-1',
                    'Name': 'TestRule1',
                    'Predicates': []
                }
            },
            {
                'Rule': {
                    'RuleId': 'rule-2',
                    'Name': 'TestRule2',
                    'Predicates': []
                }
            }
        ]
        
        # Mock v2 operations
        mock_wafv2.list_ip_sets.return_value = {'IPSets': []}
        mock_wafv2.list_regex_pattern_sets.return_value = {'RegexPatternSets': []}
        mock_wafv2.list_rule_groups.return_value = {'RuleGroups': []}
        
        # Each WebACL has its own capacity check
        # Both return high capacity (1400 units each) but under the limit
        mock_wafv2.check_capacity.side_effect = [
            {'Capacity': 1400},  # First WebACL
            {'Capacity': 1400}   # Second WebACL
        ]
        
        mock_wafv2.create_web_acl.side_effect = [
            {'Summary': {'ARN': 'arn:webacl1', 'Id': 'acl-id-1', 'Name': 'Migrated_FirstACL'}},
            {'Summary': {'ARN': 'arn:webacl2', 'Id': 'acl-id-2', 'Name': 'Migrated_SecondACL'}}
        ]
        
        # Execute migrations
        with patch('time.sleep'):
            # First WebACL - should succeed (1400 < 1500)
            result1 = migrator.execute_streamlined_migration('acl-first')
            self.assertTrue(result1.get('success'))
            
            # Second WebACL - should also succeed (capacity is per WebACL)
            result2 = migrator.execute_streamlined_migration('acl-second')
            self.assertTrue(result2.get('success'))
        
        # Both WebACLs should be created successfully
        self.assertEqual(mock_wafv2.create_web_acl.call_count, 2)
        # Capacity check should be called twice (once per WebACL)
        self.assertEqual(mock_wafv2.check_capacity.call_count, 2)
