#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import sys
import os
import boto3
from typing import List, Dict
from botocore.exceptions import ClientError

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from waf_region_config import WAFRegionManager

def get_waf_functions():
    """Import functions from waf-migrator.py"""
    waf_migration_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'waf-migration')
    original_cwd = os.getcwd()
    os.chdir(waf_migration_dir)
    sys.path.insert(0, waf_migration_dir)
    
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("waf_migrator", "waf-migrator.py")
        waf_migrator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(waf_migrator)
        return waf_migrator
    finally:
        os.chdir(original_cwd)

def list_webacls_multi_region(regions=None, all_regions=False):
    """List WebACLs across multiple regions"""
    waf_migrator = get_waf_functions()
    return waf_migrator.list_webacls_multi_region(regions, all_regions)

def list_rulegroups_multi_region(regions=None, all_regions=False):
    """List RuleGroups across multiple regions"""
    waf_migrator = get_waf_functions()
    return waf_migrator.list_rulegroups_multi_region(regions, all_regions)

def search_webacls_multi_region(webacl_ids, regions=None, all_regions=False):
    """Search for WebACLs by IDs across multiple regions"""
    waf_migrator = get_waf_functions()
    return waf_migrator.search_webacls_multi_region(webacl_ids, regions, all_regions)

def search_rulegroups_multi_region(rulegroup_ids, regions=None, all_regions=False):
    """Search for RuleGroups by IDs across multiple regions"""
    waf_migrator = get_waf_functions()
    return waf_migrator.search_rulegroups_multi_region(rulegroup_ids, regions, all_regions)

# WAF Cleanup specific utilities
class WAFv1CleanupUtils:
    def __init__(self, region: str):
        self.region = region
        if region == 'cloudfront':
            self.waf_client = boto3.client('waf', region_name='us-east-1')
            self.scope = 'global'
        else:
            self.waf_client = boto3.client('waf-regional', region_name=region)
            self.scope = 'regional'
        
        # Performance optimization: cache for expensive operations
        self._cache = {
            'webacls': None,          # Basic WebACL list (name, id)
            'webacl_details': {},     # Full WebACL details (rules, etc.)
            'rulegroups': None,       # Basic RuleGroup list (name, id)  
            'rulegroup_details': {},  # Full RuleGroup details (rules, etc.)
            'rule_details': {},       # Full Rule details (predicates, etc.)
        }
        self._cache_initialized = False

    def _initialize_cache(self):
        """Initialize cache with all WebACL and RuleGroup details for fast lookups"""
        if self._cache_initialized:
            return
            
        print(f"Initializing cache for region {self.region}...")
        
        try:
            # Cache basic WebACL list
            response = self.waf_client.list_web_acls()
            self._cache['webacls'] = response.get('WebACLs', [])
            
            # Cache full WebACL details
            for webacl in self._cache['webacls']:
                try:
                    details = self.waf_client.get_web_acl(WebACLId=webacl['WebACLId'])
                    self._cache['webacl_details'][webacl['WebACLId']] = details['WebACL']
                except ClientError:
                    continue
            
            # Cache basic RuleGroup list  
            response = self.waf_client.list_rule_groups()
            self._cache['rulegroups'] = response.get('RuleGroups', [])
            
            # Cache full RuleGroup details
            for rulegroup in self._cache['rulegroups']:
                try:
                    details = self.waf_client.get_rule_group(RuleGroupId=rulegroup['RuleGroupId'])
                    self._cache['rulegroup_details'][rulegroup['RuleGroupId']] = details['RuleGroup']
                except ClientError:
                    continue
                    
            self._cache_initialized = True
            print(f"Cache initialized: {len(self._cache['webacls'])} WebACLs, {len(self._cache['rulegroups'])} RuleGroups")
            
        except ClientError as e:
            print(f"WARNING: Failed to initialize cache for region {self.region}: {str(e)}")
            # Continue without cache - methods will fall back to direct API calls

    def list_webacls(self) -> List[Dict]:
        """List WebACLs with association info"""
        try:
            response = self.waf_client.list_web_acls()
            webacls = []
            for acl in response.get('WebACLs', []):
                acl_info = {
                    'id': acl['WebACLId'],
                    'name': acl['Name'],
                    'region': self.region,
                    'associations': self._get_webacl_associations(acl['WebACLId'])
                }
                webacls.append(acl_info)
            return webacls
        except ClientError as e:
            print(f"ERROR: Failed to list WebACLs in region {self.region}: {str(e)}")
            return []

    def list_rulegroups(self) -> List[Dict]:
        """List RuleGroups with usage info"""
        try:
            response = self.waf_client.list_rule_groups()
            rulegroups = []
            for rg in response.get('RuleGroups', []):
                rg_info = {
                    'id': rg['RuleGroupId'],
                    'name': rg['Name'],
                    'region': self.region,
                    'usage': self._get_rulegroup_usage(rg['RuleGroupId'])
                }
                rulegroups.append(rg_info)
            return rulegroups
        except ClientError as e:
            print(f"ERROR: Failed to list RuleGroups in region {self.region}: {str(e)}")
            return []

    def list_rules(self, include_usage: bool = True) -> List[Dict]:
        """List Rules with optional usage info (includes both regular and rate-based rules)"""
        try:
            rules = []
            
            # Initialize cache if usage is requested
            if include_usage:
                self._initialize_cache()
            
            # Get regular rules
            response = self.waf_client.list_rules()
            for rule in response.get('Rules', []):
                rule_info = {
                    'id': rule['RuleId'],
                    'name': rule['Name'],
                    'type': 'REGULAR',
                    'region': self.region,
                }
                
                if include_usage:
                    rule_info['usage'] = self._get_rule_usage_cached(rule['RuleId'])
                else:
                    rule_info['usage'] = []
                    
                rules.append(rule_info)
            
            # Get rate-based rules
            try:
                response = self.waf_client.list_rate_based_rules()
                for rule in response.get('Rules', []):
                    rule_info = {
                        'id': rule['RuleId'],
                        'name': rule['Name'],
                        'type': 'RATE_BASED',
                        'region': self.region,
                    }
                    
                    if include_usage:
                        rule_info['usage'] = self._get_rule_usage_cached(rule['RuleId'])
                    else:
                        rule_info['usage'] = []
                        
                    rules.append(rule_info)
            except Exception as e:
                # Rate-based rules might not be supported in all regions
                print(f"WARNING: Could not list rate-based rules in {self.region}: {str(e)}")
            
            return rules
        except ClientError as e:
            print(f"ERROR: Failed to list Rules in region {self.region}: {str(e)}")
            return []

    def list_conditions(self, include_usage: bool = False) -> Dict[str, List[Dict]]:
        """List all condition types with optional usage info"""
        conditions = {}
        condition_types = [
            ('ByteMatchSet', 'list_byte_match_sets'),
            ('IPSet', 'list_ip_sets'),
            ('SqlInjectionMatchSet', 'list_sql_injection_match_sets'),
            ('XssMatchSet', 'list_xss_match_sets'),
            ('SizeConstraintSet', 'list_size_constraint_sets'),
            ('GeoMatchSet', 'list_geo_match_sets'),
            ('RegexMatchSet', 'list_regex_match_sets'),
            ('RegexPatternSet', 'list_regex_pattern_sets')
        ]
        
        # Initialize cache if usage is requested (for cached lookup)
        if include_usage:
            self._initialize_cache()
        
        for condition_type, list_method in condition_types:
            try:
                if hasattr(self.waf_client, list_method):
                    response = getattr(self.waf_client, list_method)()
                    key = condition_type + 's'
                    condition_list = []
                    for item in response.get(key, []):
                        condition_info = {
                            'id': item.get(condition_type + 'Id'),
                            'name': item.get('Name'),
                            'region': self.region,
                            'type': condition_type
                        }
                        
                        if include_usage:
                            condition_info['usage'] = self._get_condition_usage_cached(condition_info['id'])
                        else:
                            condition_info['usage'] = []
                            
                        condition_list.append(condition_info)
                    conditions[condition_type] = condition_list
            except ClientError as e:
                print(f"ERROR: Failed to list {condition_type} in region {self.region}: {str(e)}")
                conditions[condition_type] = []
        
        return conditions

    def _get_webacl_associations(self, webacl_id: str) -> List[Dict]:
        """Get WebACL associations"""
        associations = []
        try:
            if self.scope == 'global':
                # CloudFront distributions
                cf_client = boto3.client('cloudfront')
                response = cf_client.list_distributions()
                for dist in response.get('DistributionList', {}).get('Items', []):
                    if dist.get('WebACLId') == webacl_id:
                        associations.append({
                            'type': 'CloudFront',
                            'id': dist['Id'],
                            'domain': dist['DomainName']
                        })
            else:
                # Regional resources (ALB, API Gateway, etc.)
                response = self.waf_client.list_resources_for_web_acl(WebACLId=webacl_id)
                for resource_arn in response.get('ResourceArns', []):
                    associations.append({
                        'type': 'Regional',
                        'arn': resource_arn
                    })
        except ClientError:
            pass
        return associations

    def _get_rulegroup_usage(self, rulegroup_id: str) -> List[Dict]:
        """Get RuleGroup usage in WebACLs"""
        usage = []
        try:
            webacls = self.list_webacls()
            for webacl in webacls:
                try:
                    response = self.waf_client.get_web_acl(WebACLId=webacl['id'])
                    for rule in response.get('WebACL', {}).get('Rules', []):
                        if rule.get('RuleId') == rulegroup_id:
                            usage.append({
                                'webacl_id': webacl['id'],
                                'webacl_name': webacl['name']
                            })
                except ClientError:
                    continue
        except Exception:
            pass
        return usage

    def _get_rule_usage(self, rule_id: str) -> List[Dict]:
        """Get Rule usage in WebACLs and RuleGroups"""
        usage = []
        try:
            # Check WebACLs
            webacls = self.list_webacls()
            for webacl in webacls:
                try:
                    response = self.waf_client.get_web_acl(WebACLId=webacl['id'])
                    for rule in response.get('WebACL', {}).get('Rules', []):
                        if rule.get('RuleId') == rule_id:
                            usage.append({
                                'type': 'WebACL',
                                'id': webacl['id'],
                                'name': webacl['name']
                            })
                except ClientError:
                    continue
            
            # Check RuleGroups
            rulegroups = self.list_rulegroups()
            for rulegroup in rulegroups:
                try:
                    response = self.waf_client.get_rule_group(RuleGroupId=rulegroup['id'])
                    for rule in response.get('RuleGroup', {}).get('ActivatedRules', []):
                        if rule.get('RuleId') == rule_id:
                            usage.append({
                                'type': 'RuleGroup',
                                'id': rulegroup['id'],
                                'name': rulegroup['name']
                            })
                except ClientError:
                    continue
        except Exception:
            pass
        return usage

    def _get_rule_usage_cached(self, rule_id: str) -> List[Dict]:
        """Get Rule usage using cached WebACL and RuleGroup data"""
        usage = []
        try:
            # Check cached WebACLs
            if self._cache['webacl_details']:
                for webacl_id, webacl_details in self._cache['webacl_details'].items():
                    for rule in webacl_details.get('Rules', []):
                        if rule.get('RuleId') == rule_id:
                            # Find the WebACL name from basic list
                            webacl_name = next(
                                (w['Name'] for w in self._cache['webacls'] if w['WebACLId'] == webacl_id),
                                webacl_id
                            )
                            usage.append({
                                'type': 'WebACL',
                                'id': webacl_id,
                                'name': webacl_name
                            })
            
            # Check cached RuleGroups
            if self._cache['rulegroup_details']:
                for rulegroup_id, rulegroup_details in self._cache['rulegroup_details'].items():
                    for rule in rulegroup_details.get('ActivatedRules', []):
                        if rule.get('RuleId') == rule_id:
                            # Find the RuleGroup name from basic list
                            rulegroup_name = next(
                                (rg['Name'] for rg in self._cache['rulegroups'] if rg['RuleGroupId'] == rulegroup_id),
                                rulegroup_id
                            )
                            usage.append({
                                'type': 'RuleGroup',
                                'id': rulegroup_id,
                                'name': rulegroup_name
                            })
        except Exception:
            # Fall back to non-cached method
            return self._get_rule_usage(rule_id)
        
        return usage

    def _get_condition_usage_cached(self, condition_id: str) -> List[Dict]:
        """Get Condition usage using cached rule data and direct API calls"""
        usage = []
        try:
            # Cache all rules once if not already cached
            if 'rules' not in self._cache or self._cache['rules'] is None:
                self._cache['rules'] = []
                
                # Get regular rules
                response = self.waf_client.list_rules()
                for rule in response.get('Rules', []):
                    self._cache['rules'].append({
                        'id': rule['RuleId'],
                        'name': rule['Name'],
                        'type': 'REGULAR'
                    })
                
                # Get rate-based rules
                try:
                    response = self.waf_client.list_rate_based_rules()
                    for rule in response.get('Rules', []):
                        self._cache['rules'].append({
                            'id': rule['RuleId'],
                            'name': rule['Name'],
                            'type': 'RATE_BASED'
                        })
                except Exception:
                    pass  # Rate-based rules might not be supported in all regions
            
            # Now check each rule for the condition
            for rule in self._cache['rules']:
                try:
                    if rule['type'] == 'REGULAR':
                        response = self.waf_client.get_rule(RuleId=rule['id'])
                        predicates = response.get('Rule', {}).get('Predicates', [])
                    else:  # RATE_BASED
                        response = self.waf_client.get_rate_based_rule(RuleId=rule['id'])
                        predicates = response.get('Rule', {}).get('MatchPredicates', [])
                    
                    for predicate in predicates:
                        if predicate.get('DataId') == condition_id:
                            usage.append({
                                'type': 'Rule',
                                'id': rule['id'],
                                'name': rule['name'],
                                'rule_type': rule['type']
                            })
                            break  # Found condition in this rule, no need to check more predicates
                except ClientError:
                    continue
                    
        except Exception:
            # Fall back to non-cached method
            return self._get_condition_usage(condition_id)
        
        return usage

    def _get_condition_usage(self, condition_id: str) -> List[Dict]:
        """Get Condition usage in Rules"""
        usage = []
        try:
            # Check regular rules
            rules = self.list_rules()
            for rule in rules:
                try:
                    if rule.get('type') == 'REGULAR':
                        response = self.waf_client.get_rule(RuleId=rule['id'])
                        predicates = response.get('Rule', {}).get('Predicates', [])
                    else:  # RATE_BASED
                        response = self.waf_client.get_rate_based_rule(RuleId=rule['id'])
                        predicates = response.get('Rule', {}).get('MatchPredicates', [])
                    
                    for predicate in predicates:
                        if predicate.get('DataId') == condition_id:
                            usage.append({
                                'type': 'Rule',
                                'id': rule['id'],
                                'name': rule['name'],
                                'rule_type': rule.get('type', 'REGULAR')
                            })
                except ClientError:
                    continue
        except Exception:
            pass
        return usage

    def analyze_dependencies(self, resource_type: str, resource_id: str) -> Dict:
        """Analyze dependencies for a resource"""
        result = {
            'resource_type': resource_type,
            'resource_id': resource_id,
            'region': self.region,
            'safe_to_delete': True,
            'dependencies': [],
            'warnings': []
        }
        
        try:
            if resource_type == 'webacl':
                associations = self._get_webacl_associations(resource_id)
                if associations:
                    result['safe_to_delete'] = False
                    result['dependencies'] = associations
                    result['warnings'].append("WebACL has active associations")
            
            elif resource_type == 'rulegroup':
                usage = self._get_rulegroup_usage(resource_id)
                if usage:
                    result['safe_to_delete'] = False
                    result['dependencies'] = usage
                    result['warnings'].append("RuleGroup is used by WebACLs")
            
            elif resource_type == 'rule':
                usage = self._get_rule_usage(resource_id)
                if usage:
                    result['safe_to_delete'] = False
                    result['dependencies'] = usage
                    result['warnings'].append("Rule is used by WebACLs or RuleGroups")
            
            elif resource_type == 'condition':
                usage = self._get_condition_usage(resource_id)
                if usage:
                    result['safe_to_delete'] = False
                    result['dependencies'] = usage
                    result['warnings'].append("Condition is used by Rules")
        
        except Exception as e:
            result['warnings'].append(f"Error analyzing dependencies: {str(e)}")
        
        return result

# Multi-region cleanup utility functions
def list_rules_multi_region(regions=None, all_regions=False):
    """List Rules across multiple regions"""
    if all_regions:
        regions = WAFRegionManager.list_supported_regions()
    elif not regions:
        regions = ['us-east-1']
    
    all_rules = {}
    for region in regions:
        try:
            cleanup = WAFv1CleanupUtils(region=region)
            rules = cleanup.list_rules()
            if rules:
                all_rules[region] = rules
        except Exception as e:
            print(f"ERROR: Failed to list Rules in region {region}: {str(e)}")
    
    return all_rules

def list_conditions_multi_region(regions=None, all_regions=False, include_usage=False):
    """List Conditions across multiple regions with optional usage info"""
    if all_regions:
        regions = WAFRegionManager.list_supported_regions()
    elif not regions:
        regions = ['us-east-1']
    
    all_conditions = {}
    for region in regions:
        try:
            cleanup = WAFv1CleanupUtils(region=region)
            conditions = cleanup.list_conditions(include_usage=include_usage)
            if conditions:
                all_conditions[region] = conditions
        except Exception as e:
            print(f"ERROR: Failed to list Conditions in region {region}: {str(e)}")
    
    return all_conditions

def search_rules_multi_region(rule_ids, regions=None, all_regions=False):
    """Search for Rules by IDs across multiple regions"""
    if all_regions:
        regions = WAFRegionManager.list_supported_regions()
    elif not regions:
        regions = ['us-east-1']
    
    found_rules = {}
    for region in regions:
        try:
            cleanup = WAFv1CleanupUtils(region=region)
            region_rules = cleanup.list_rules()
            
            for rule_id in rule_ids:
                for rule in region_rules:
                    if rule['id'] == rule_id:
                        if region not in found_rules:
                            found_rules[region] = []
                        found_rules[region].append(rule)
        except Exception as e:
            print(f"ERROR: Failed to search Rules in region {region}: {str(e)}")
    
    return found_rules

def search_conditions_multi_region(condition_ids, regions=None, all_regions=False):
    """Search for Conditions by IDs across multiple regions"""
    if all_regions:
        regions = WAFRegionManager.list_supported_regions()
    elif not regions:
        regions = ['us-east-1']
    
    found_conditions = {}
    for region in regions:
        try:
            cleanup = WAFv1CleanupUtils(region=region)
            region_conditions = cleanup.list_conditions()
            
            for condition_id in condition_ids:
                for condition_type, conditions in region_conditions.items():
                    for condition in conditions:
                        if condition['id'] == condition_id:
                            if region not in found_conditions:
                                found_conditions[region] = {}
                            if condition_type not in found_conditions[region]:
                                found_conditions[region][condition_type] = []
                            found_conditions[region][condition_type].append(condition)
        except Exception as e:
            print(f"ERROR: Failed to search Conditions in region {region}: {str(e)}")
    
    return found_conditions
