#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""
Unit tests for WAF Classic (v1) Cleanup Tool
"""

import unittest
from unittest.mock import Mock, patch, MagicMock, call
import sys
import os
import csv

# Add the script directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'waf-cleanup'))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'common'))

# Import the modules to test - handle hyphenated filename
import importlib.util
waf_classic_cleanup_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'waf-cleanup', 'waf_classic-cleanup.py')
spec = importlib.util.spec_from_file_location("waf_classic_cleanup", waf_classic_cleanup_path)
waf_classic_cleanup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(waf_classic_cleanup)

# Import the functions from the module
cleanup_webacls = waf_classic_cleanup.cleanup_webacls
cleanup_rulegroups = waf_classic_cleanup.cleanup_rulegroups
cleanup_from_csv = waf_classic_cleanup.cleanup_from_csv
delete_resource_safe = waf_classic_cleanup.delete_resource_safe
delete_resources_by_type = waf_classic_cleanup.delete_resources_by_type
delete_all_resources = waf_classic_cleanup.delete_all_resources


class TestCleanupWebACLs(unittest.TestCase):
    """Test cases for WebACL cleanup functionality"""
    
    @patch.object(waf_classic_cleanup, 'waf_classicCleanupUtils')
    @patch.object(waf_classic_cleanup, 'list_webacls_multi_region')
    @patch.object(waf_classic_cleanup, 'delete_resource_safe')
    def test_cleanup_all_webacls(self, mock_delete, mock_list, mock_cleanup_utils):
        """Test cleaning up all WebACLs in regions"""
        # Mock WebACL list
        mock_list.return_value = {
            'us-east-1': [
                {'id': 'acl-123', 'name': 'TestACL1'},
                {'id': 'acl-456', 'name': 'TestACL2'}
            ]
        }
        
        # Mock dependency analysis
        mock_cleanup_instance = Mock()
        mock_cleanup_instance.analyze_dependencies.side_effect = [
            {'safe_to_delete': True, 'dependencies': [], 'warnings': []},
            {'safe_to_delete': False, 'dependencies': ['dep1'], 'warnings': ['Warning1']}
        ]
        mock_cleanup_utils.return_value = mock_cleanup_instance
        
        # Mock delete
        mock_delete.return_value = "SUCCESS: Deleted webacl acl-123"
        
        # Execute cleanup
        cleanup_webacls(all_webacls=True, regions='us-east-1', analyze_only=False)
        
        # Verify
        mock_list.assert_called_once_with(['us-east-1'])
        self.assertEqual(mock_cleanup_instance.analyze_dependencies.call_count, 2)
        mock_delete.assert_called_once_with('webacl', 'acl-123', 'us-east-1')
    
    @patch.object(waf_classic_cleanup, 'waf_classicCleanupUtils')
    @patch.object(waf_classic_cleanup, 'search_webacls_multi_region')
    @patch.object(waf_classic_cleanup, 'delete_resource_safe')
    def test_cleanup_specific_webacls(self, mock_delete, mock_search, mock_cleanup_utils):
        """Test cleaning up specific WebACLs"""
        # Mock WebACL search
        mock_search.return_value = {
            'us-east-1': [
                {'id': 'acl-123', 'name': 'TestACL'}
            ]
        }
        
        # Mock dependency analysis
        mock_cleanup_instance = Mock()
        mock_cleanup_instance.analyze_dependencies.return_value = {
            'safe_to_delete': True,
            'dependencies': [],
            'warnings': []
        }
        mock_cleanup_utils.return_value = mock_cleanup_instance
        
        # Mock delete
        mock_delete.return_value = "SUCCESS: Deleted webacl acl-123"
        
        # Execute cleanup
        cleanup_webacls(webacl_ids='acl-123', regions='us-east-1', analyze_only=False)
        
        # Verify
        mock_search.assert_called_once_with(['acl-123'], ['us-east-1'])
        mock_cleanup_instance.analyze_dependencies.assert_called_once_with('webacl', 'acl-123')
        mock_delete.assert_called_once_with('webacl', 'acl-123', 'us-east-1')
    
    @patch.object(waf_classic_cleanup, 'waf_classicCleanupUtils')
    @patch.object(waf_classic_cleanup, 'search_webacls_multi_region')
    def test_cleanup_analyze_only(self, mock_search, mock_cleanup_utils):
        """Test analyze-only mode"""
        # Mock WebACL search
        mock_search.return_value = {
            'us-east-1': [
                {'id': 'acl-123', 'name': 'TestACL'}
            ]
        }
        
        # Mock dependency analysis
        mock_cleanup_instance = Mock()
        mock_cleanup_instance.analyze_dependencies.return_value = {
            'safe_to_delete': True,
            'dependencies': [],
            'warnings': []
        }
        mock_cleanup_utils.return_value = mock_cleanup_instance
        
        # Execute cleanup in analyze-only mode
        cleanup_webacls(webacl_ids='acl-123', regions='us-east-1', analyze_only=True)
        
        # Verify analysis was done but no deletion
        mock_cleanup_instance.analyze_dependencies.assert_called_once_with('webacl', 'acl-123')
    
    @patch.object(waf_classic_cleanup, 'WAFRegionManager')
    @patch.object(waf_classic_cleanup, 'waf_classicCleanupUtils')
    @patch.object(waf_classic_cleanup, 'list_webacls_multi_region')
    def test_cleanup_all_regions(self, mock_list, mock_cleanup_utils, mock_region_manager):
        """Test cleanup with all regions"""
        # Mock region list
        mock_region_manager.list_supported_regions.return_value = ['us-east-1', 'eu-west-1']
        
        # Mock WebACL list
        mock_list.return_value = {
            'us-east-1': [{'id': 'acl-123', 'name': 'TestACL'}],
            'eu-west-1': [{'id': 'acl-456', 'name': 'TestACL2'}]
        }
        
        # Mock dependency analysis
        mock_cleanup_instance = Mock()
        mock_cleanup_instance.analyze_dependencies.return_value = {
            'safe_to_delete': False,
            'dependencies': ['dep1'],
            'warnings': []
        }
        mock_cleanup_utils.return_value = mock_cleanup_instance
        
        # Execute cleanup
        cleanup_webacls(all_webacls=True, all_regions=True, analyze_only=True)
        
        # Verify
        mock_region_manager.list_supported_regions.assert_called_once()
        mock_list.assert_called_once_with(['us-east-1', 'eu-west-1'])
        self.assertEqual(mock_cleanup_instance.analyze_dependencies.call_count, 2)


class TestCleanupRuleGroups(unittest.TestCase):
    """Test cases for RuleGroup cleanup functionality"""
    
    @patch.object(waf_classic_cleanup, 'waf_classicCleanupUtils')
    @patch.object(waf_classic_cleanup, 'list_rulegroups_multi_region')
    @patch.object(waf_classic_cleanup, 'delete_resource_safe')
    def test_cleanup_all_rulegroups(self, mock_delete, mock_list, mock_cleanup_utils):
        """Test cleaning up all RuleGroups"""
        # Mock RuleGroup list
        mock_list.return_value = {
            'us-east-1': [
                {'id': 'rg-123', 'name': 'TestRuleGroup1'},
                {'id': 'rg-456', 'name': 'TestRuleGroup2'}
            ]
        }
        
        # Mock dependency analysis
        mock_cleanup_instance = Mock()
        mock_cleanup_instance.analyze_dependencies.side_effect = [
            {'safe_to_delete': True, 'dependencies': [], 'warnings': []},
            {'safe_to_delete': True, 'dependencies': [], 'warnings': []}
        ]
        mock_cleanup_utils.return_value = mock_cleanup_instance
        
        # Mock delete
        mock_delete.side_effect = [
            "SUCCESS: Deleted rulegroup rg-123",
            "SUCCESS: Deleted rulegroup rg-456"
        ]
        
        # Execute cleanup
        cleanup_rulegroups(all_rulegroups=True, regions='us-east-1', analyze_only=False)
        
        # Verify
        mock_list.assert_called_once_with(['us-east-1'])
        self.assertEqual(mock_cleanup_instance.analyze_dependencies.call_count, 2)
        self.assertEqual(mock_delete.call_count, 2)
    
    @patch.object(waf_classic_cleanup, 'waf_classicCleanupUtils')
    @patch.object(waf_classic_cleanup, 'search_rulegroups_multi_region')
    def test_cleanup_specific_rulegroups_with_dependencies(self, mock_search, mock_cleanup_utils):
        """Test cleaning up RuleGroups with dependencies"""
        # Mock RuleGroup search
        mock_search.return_value = {
            'us-east-1': [
                {'id': 'rg-123', 'name': 'TestRuleGroup'}
            ]
        }
        
        # Mock dependency analysis - has dependencies
        mock_cleanup_instance = Mock()
        mock_cleanup_instance.analyze_dependencies.return_value = {
            'safe_to_delete': False,
            'dependencies': ['WebACL: TestWebACL'],
            'warnings': ['RuleGroup is referenced by WebACL']
        }
        mock_cleanup_utils.return_value = mock_cleanup_instance
        
        # Execute cleanup
        cleanup_rulegroups(rulegroup_ids='rg-123', regions='us-east-1', analyze_only=False)
        
        # Verify no deletion occurred due to dependencies
        mock_cleanup_instance.analyze_dependencies.assert_called_once_with('rulegroup', 'rg-123')


class TestCleanupFromCSV(unittest.TestCase):
    """Test cases for CSV-based cleanup"""
    
    @patch.object(waf_classic_cleanup, 'waf_classicCleanupUtils')
    @patch.object(waf_classic_cleanup, 'delete_resource_safe')
    @patch('csv.DictReader')
    @patch('builtins.open', create=True)
    def test_cleanup_webacls_from_csv(self, mock_open, mock_csv_reader, mock_delete, mock_cleanup_utils):
        """Test cleaning up WebACLs from CSV file"""
        # Mock CSV content with correct column names
        mock_csv_reader.return_value = [
            {'webacl_id': 'acl-123', 'region': 'us-east-1', 'mark_for_deletion': 'DELETE'},
            {'webacl_id': 'acl-456', 'region': 'eu-west-1', 'mark_for_deletion': 'DELETE'}
        ]
        mock_file = Mock()
        mock_file.__enter__ = Mock(return_value=mock_file)
        mock_file.__exit__ = Mock(return_value=None)
        mock_open.return_value = mock_file
        
        # Mock dependency analysis
        mock_cleanup_instance = Mock()
        mock_cleanup_instance.analyze_dependencies.return_value = {
            'safe_to_delete': True,
            'dependencies': [],
            'warnings': []
        }
        mock_cleanup_utils.return_value = mock_cleanup_instance
        
        # Mock delete
        mock_delete.side_effect = [
            "SUCCESS: Deleted webacl acl-123",
            "SUCCESS: Deleted webacl acl-456"
        ]
        
        # Execute cleanup - note resource_type is 'webacls' not 'webacl'
        cleanup_from_csv('test.csv', 'webacls', analyze_only=False)
        
        # Verify
        mock_open.assert_called_once_with('test.csv', 'r')
        self.assertEqual(mock_cleanup_instance.analyze_dependencies.call_count, 2)
        self.assertEqual(mock_delete.call_count, 2)
    
    @patch.object(waf_classic_cleanup, 'waf_classicCleanupUtils')
    @patch('builtins.open', create=True)
    def test_cleanup_from_csv_with_errors(self, mock_open, mock_cleanup_utils):
        """Test CSV cleanup with file errors"""
        # Mock file not found
        mock_open.side_effect = FileNotFoundError("File not found")
        
        # Execute cleanup - should handle error gracefully
        cleanup_from_csv('nonexistent.csv', 'webacls', analyze_only=False)
        
        # Verify error was handled
        mock_open.assert_called_once_with('nonexistent.csv', 'r')


class TestDeleteResourceSafe(unittest.TestCase):
    """Test cases for safe resource deletion"""
    
    @patch('boto3.client')
    def test_delete_webacl_safe(self, mock_boto3_client):
        """Test safe deletion of WebACL"""
        # Mock WAF client
        mock_client = Mock()
        mock_boto3_client.return_value = mock_client
        
        # Mock WebACL with rules
        mock_client.get_web_acl.return_value = {
            'WebACL': {
                'WebACLId': 'acl-123',
                'Rules': [
                    {'RuleId': 'rule-1', 'Priority': 1, 'Action': {'Type': 'BLOCK'}}
                ]
            }
        }
        
        # Mock change token
        mock_client.get_change_token.return_value = {'ChangeToken': 'token-123'}
        
        # Execute deletion
        result = delete_resource_safe('webacl', 'acl-123', 'us-east-1')
        
        # Verify
        mock_client.update_web_acl.assert_called_once()
        mock_client.delete_web_acl.assert_called_once_with(
            WebACLId='acl-123',
            ChangeToken='token-123'
        )
        self.assertIn('SUCCESS', result)
    
    @patch('boto3.client')
    def test_delete_rulegroup_safe(self, mock_boto3_client):
        """Test safe deletion of RuleGroup"""
        # Mock WAF client
        mock_client = Mock()
        mock_boto3_client.return_value = mock_client
        
        # Mock activated rules
        mock_client.list_activated_rules_in_rule_group.return_value = {
            'ActivatedRules': [
                {'RuleId': 'rule-1', 'Priority': 1, 'Action': {'Type': 'BLOCK'}}
            ]
        }
        
        # Mock change token
        mock_client.get_change_token.return_value = {'ChangeToken': 'token-123'}
        
        # Execute deletion
        result = delete_resource_safe('rulegroup', 'rg-123', 'us-east-1')
        
        # Verify
        mock_client.update_rule_group.assert_called_once()
        mock_client.delete_rule_group.assert_called_once_with(
            RuleGroupId='rg-123',
            ChangeToken='token-123'
        )
        self.assertIn('SUCCESS', result)
    
    @patch('boto3.client')
    def test_delete_rule_safe(self, mock_boto3_client):
        """Test safe deletion of Rule"""
        # Mock WAF client
        mock_client = Mock()
        mock_boto3_client.return_value = mock_client
        
        # Mock rule with predicates
        mock_client.get_rule.return_value = {
            'Rule': {
                'RuleId': 'rule-123',
                'Predicates': [
                    {'Type': 'IPMatch', 'DataId': 'ipset-123', 'Negated': False}
                ]
            }
        }
        
        # Mock change token
        mock_client.get_change_token.return_value = {'ChangeToken': 'token-123'}
        
        # Execute deletion
        result = delete_resource_safe('rule', 'rule-123', 'us-east-1')
        
        # Verify
        mock_client.update_rule.assert_called_once()
        mock_client.delete_rule.assert_called_once_with(
            RuleId='rule-123',
            ChangeToken='token-123'
        )
        self.assertIn('SUCCESS', result)
    
    @patch('boto3.client')
    def test_delete_ipset_safe(self, mock_boto3_client):
        """Test safe deletion of IPSet"""
        # Mock WAF client
        mock_client = Mock()
        mock_boto3_client.return_value = mock_client
        
        # Mock IPSet with descriptors
        mock_client.get_ip_set.return_value = {
            'IPSet': {
                'IPSetId': 'ipset-123',
                'IPSetDescriptors': [
                    {'Type': 'IPV4', 'Value': '192.0.2.0/24'}
                ]
            }
        }
        
        # Mock change token
        mock_client.get_change_token.return_value = {'ChangeToken': 'token-123'}
        
        # Execute deletion
        result = delete_resource_safe('IPSet', 'ipset-123', 'us-east-1')
        
        # Verify
        mock_client.update_ip_set.assert_called_once()
        mock_client.delete_ip_set.assert_called_once_with(
            IPSetId='ipset-123',
            ChangeToken='token-123'
        )
        self.assertIn('SUCCESS', result)
    
    @patch('boto3.client')
    def test_delete_cloudfront_resource(self, mock_boto3_client):
        """Test deletion of CloudFront resources"""
        # Mock WAF client for CloudFront
        mock_client = Mock()
        mock_boto3_client.return_value = mock_client
        
        # Mock WebACL
        mock_client.get_web_acl.return_value = {
            'WebACL': {
                'WebACLId': 'acl-123',
                'Rules': []
            }
        }
        
        # Mock change token
        mock_client.get_change_token.return_value = {'ChangeToken': 'token-123'}
        
        # Execute deletion for CloudFront region
        result = delete_resource_safe('webacl', 'acl-123', 'cloudfront')
        
        # Verify WAF (not WAF-Regional) client was used
        mock_boto3_client.assert_called_with('waf', region_name='us-east-1')
        self.assertIn('SUCCESS', result)
    
    @patch('boto3.client')
    def test_delete_resource_with_error(self, mock_boto3_client):
        """Test deletion with error handling"""
        # Mock WAF client
        mock_client = Mock()
        mock_boto3_client.return_value = mock_client
        
        # Mock exception
        mock_client.get_web_acl.side_effect = Exception("API Error")
        
        # Execute deletion
        result = delete_resource_safe('webacl', 'acl-123', 'us-east-1')
        
        # Verify error handling
        self.assertIn('ERROR', result)
        self.assertIn('API Error', result)


class TestDeleteResourcesByType(unittest.TestCase):
    """Test cases for batch resource deletion"""
    
    @patch.object(waf_classic_cleanup, 'delete_resource_safe')
    @patch('time.sleep')
    def test_delete_resources_by_type(self, mock_sleep, mock_delete):
        """Test batch deletion of resources"""
        # Mock resource list
        resources = [
            {'id': 'rule-1'},
            {'id': 'rule-2'},
            {'id': 'rule-3'}
        ]
        
        # Mock delete responses
        mock_delete.side_effect = [
            "SUCCESS: Deleted rule rule-1",
            "ERROR: Failed to delete rule rule-2",
            "SUCCESS: Deleted rule rule-3"
        ]
        
        # Execute batch deletion
        delete_resources_by_type(resources, 'rule', 'us-east-1')
        
        # Verify
        self.assertEqual(mock_delete.call_count, 3)
        self.assertEqual(mock_sleep.call_count, 3)
    
    @patch.object(waf_classic_cleanup, 'delete_resource_safe')
    def test_delete_empty_resource_list(self, mock_delete):
        """Test deletion with empty resource list"""
        # Execute with empty list
        delete_resources_by_type([], 'rule', 'us-east-1')
        
        # Verify no deletions occurred
        mock_delete.assert_not_called()


class TestDeleteAllResources(unittest.TestCase):
    """Test cases for deleting all resources"""
    
    @patch.object(waf_classic_cleanup, 'waf_classicCleanupUtils')
    @patch.object(waf_classic_cleanup, 'delete_resources_by_type')
    @patch('builtins.input')
    def test_delete_all_resources_confirmed(self, mock_input, mock_delete_batch, mock_cleanup_utils):
        """Test delete all with user confirmation"""
        # Mock user confirmation
        mock_input.return_value = 'DELETE ALL'
        
        # Mock cleanup utils
        mock_cleanup_instance = Mock()
        mock_cleanup_instance.list_webacls.return_value = [{'id': 'acl-1'}]
        mock_cleanup_instance.list_rulegroups.return_value = [{'id': 'rg-1'}]
        mock_cleanup_instance.list_rules.return_value = [{'id': 'rule-1'}]
        mock_cleanup_instance.list_conditions.return_value = {
            'IPSet': [{'id': 'ipset-1'}],
            'ByteMatchSet': [{'id': 'byte-1'}]
        }
        mock_cleanup_utils.return_value = mock_cleanup_instance
        
        # Execute delete all
        delete_all_resources(regions='us-east-1')
        
        # Verify deletion order (WebACLs -> RuleGroups -> Rules -> Conditions)
        calls = mock_delete_batch.call_args_list
        self.assertEqual(len(calls), 5)  # 1 WebACL + 1 RuleGroup + 1 Rule + 2 Conditions
        
        # Verify correct order
        self.assertEqual(calls[0][0][1], 'webacl')
        self.assertEqual(calls[1][0][1], 'rulegroup')
        self.assertEqual(calls[2][0][1], 'rule')
        self.assertIn(calls[3][0][1], ['IPSet', 'ByteMatchSet'])
        self.assertIn(calls[4][0][1], ['IPSet', 'ByteMatchSet'])
    
    @patch('builtins.input')
    def test_delete_all_resources_cancelled(self, mock_input):
        """Test delete all cancelled by user"""
        # Mock user cancellation
        mock_input.return_value = 'NO'
        
        # Execute delete all
        delete_all_resources(regions='us-east-1')
        
        # Verify prompt was shown
        mock_input.assert_called_once()
    
    @patch.object(waf_classic_cleanup, 'WAFRegionManager')
    @patch.object(waf_classic_cleanup, 'waf_classicCleanupUtils')
    @patch.object(waf_classic_cleanup, 'delete_resources_by_type')
    @patch('builtins.input')
    def test_delete_all_resources_multiple_regions(self, mock_input, mock_delete_batch, 
                                                   mock_cleanup_utils, mock_region_manager):
        """Test delete all in multiple regions"""
        # Mock user confirmation
        mock_input.return_value = 'DELETE ALL'
        
        # Mock region list
        mock_region_manager.list_supported_regions.return_value = ['us-east-1', 'eu-west-1']
        
        # Mock cleanup utils
        mock_cleanup_instance = Mock()
        mock_cleanup_instance.list_webacls.return_value = []
        mock_cleanup_instance.list_rulegroups.return_value = []
        mock_cleanup_instance.list_rules.return_value = []
        mock_cleanup_instance.list_conditions.return_value = {}
        mock_cleanup_utils.return_value = mock_cleanup_instance
        
        # Execute delete all in all regions
        delete_all_resources(all_regions=True)
        
        # Verify both regions were processed
        self.assertEqual(mock_cleanup_utils.call_count, 2)


class TestIntegrationScenarios(unittest.TestCase):
    """Integration test scenarios"""
    
    @patch.object(waf_classic_cleanup, 'waf_classicCleanupUtils')
    @patch.object(waf_classic_cleanup, 'search_webacls_multi_region')
    @patch('boto3.client')
    def test_cleanup_webacl_with_all_dependencies(self, mock_boto3_client, mock_search, mock_cleanup_utils):
        """Test cleanup of WebACL with all types of dependencies"""
        # Mock WebACL search
        mock_search.return_value = {
            'us-east-1': [{'id': 'acl-complex', 'name': 'ComplexACL'}]
        }
        
        # Mock cleanup utils with complex dependencies
        mock_cleanup_instance = Mock()
        mock_cleanup_instance.analyze_dependencies.return_value = {
            'safe_to_delete': False,
            'dependencies': [
                'Associated with ALB: arn:aws:elasticloadbalancing:test',
                'Contains 5 rules',
                'References 3 RuleGroups'
            ],
            'warnings': [
                'WebACL has active associations',
                'Consider migrating to WAF v2 before deletion'
            ]
        }
        mock_cleanup_utils.return_value = mock_cleanup_instance
        
        # Execute cleanup
        cleanup_webacls(webacl_ids='acl-complex', regions='us-east-1', analyze_only=False)
        
        # Verify analysis was done but no deletion due to dependencies
        mock_cleanup_instance.analyze_dependencies.assert_called_once()
    
    @patch.object(waf_classic_cleanup, 'waf_classicCleanupUtils')
    @patch.object(waf_classic_cleanup, 'list_webacls_multi_region')
    @patch.object(waf_classic_cleanup, 'delete_resource_safe')
    @patch('time.sleep')
    def test_cleanup_performance_with_many_resources(self, mock_sleep, mock_delete, 
                                                    mock_list, mock_cleanup_utils):
        """Test cleanup performance with many resources"""
        # Mock large number of WebACLs
        webacls = [{'id': f'acl-{i}', 'name': f'TestACL{i}'} for i in range(20)]
        mock_list.return_value = {'us-east-1': webacls}
        
        # Mock cleanup utils - all safe to delete
        mock_cleanup_instance = Mock()
        mock_cleanup_instance.analyze_dependencies.return_value = {
            'safe_to_delete': True,
            'dependencies': [],
            'warnings': []
        }
        mock_cleanup_utils.return_value = mock_cleanup_instance
        
        # Mock successful deletions
        mock_delete.return_value = "SUCCESS: Deleted"
        
        # Execute cleanup
        cleanup_webacls(all_webacls=True, regions='us-east-1', analyze_only=False)
        
        # Verify all resources were processed
        self.assertEqual(mock_cleanup_instance.analyze_dependencies.call_count, 20)
        self.assertEqual(mock_delete.call_count, 20)


if __name__ == '__main__':
    unittest.main()
