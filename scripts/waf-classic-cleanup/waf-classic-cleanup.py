#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""
WAF Classic (v1) Cleanup Tool

This tool provides cleanup capabilities for AWS WAF Classic resources
with consistent command structure and reusable components.
"""

import argparse
import sys
import os
import json
import csv
import boto3
import concurrent.futures
import time
from typing import List, Dict

from botocore.exceptions import NoCredentialsError, ClientError

# Add common directory to path
common_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'common')
sys.path.insert(0, common_path)

from waf_region_config import WAFRegionManager
from waf_utils import (
    WAFv1CleanupUtils,
    list_webacls_multi_region,
    list_rulegroups_multi_region, 
    search_webacls_multi_region,
    search_rulegroups_multi_region,
    list_rules_multi_region,
    search_rules_multi_region,
    list_conditions_multi_region,
    search_conditions_multi_region
)
from csv_export_utils import (
    export_webacls_to_csv,
    export_rulegroups_to_csv,
    export_rules_to_csv,
    export_conditions_to_csv
)

def get_detailed_webacl_info(webacl_id: str, region: str) -> Dict:
    """Get detailed WebACL information including rules and associations"""
    cleanup = WAFv1CleanupUtils(region)
    
    try:
        # Get WebACL details
        if region == 'cloudfront':
            waf_client = boto3.client('waf', region_name='us-east-1')
        else:
            waf_client = boto3.client('waf-regional', region_name=region)
        
        webacl_response = waf_client.get_web_acl(WebACLId=webacl_id)
        webacl = webacl_response['WebACL']
        
        # Get associations
        associations = cleanup._get_webacl_associations(webacl_id)
        
        # Get detailed rule information
        rules_info = []
        for rule in webacl.get('Rules', []):
            rule_info = {
                'rule_id': rule['RuleId'],
                'priority': rule['Priority'],
                'action': rule['Action']['Type']
            }
            
            # Try different rule types in order
            rule_found = False
            
            # 1. Try regular rule
            if not rule_found:
                try:
                    rule_response = waf_client.get_rule(RuleId=rule['RuleId'])
                    rule_detail = rule_response['Rule']
                    rule_info['name'] = rule_detail['Name']
                    rule_info['predicates'] = len(rule_detail.get('Predicates', []))
                    rule_info['type'] = 'Rule'
                    rule_found = True
                except ClientError:
                    pass
            
            # 2. Try rate-based rule
            if not rule_found:
                try:
                    rule_response = waf_client.get_rate_based_rule(RuleId=rule['RuleId'])
                    rule_detail = rule_response['Rule']
                    rule_info['name'] = rule_detail['Name']
                    rule_info['predicates'] = len(rule_detail.get('MatchPredicates', []))
                    rule_info['type'] = 'Rate-based Rule'
                    rule_found = True
                except ClientError:
                    pass
            
            # 3. Try rule group
            if not rule_found:
                try:
                    rule_response = waf_client.get_rule_group(RuleGroupId=rule['RuleId'])
                    rule_detail = rule_response['RuleGroup']
                    rule_info['name'] = rule_detail['Name']
                    rule_info['predicates'] = 0  # Rule groups don't have predicates directly
                    rule_info['type'] = 'Rule Group'
                    rule_found = True
                except ClientError:
                    pass
            
            # 4. Check if it's a managed rule (AWS Marketplace or AWS managed)
            if not rule_found:
                # Managed rules often have specific ID patterns
                if rule['RuleId'].startswith('AWS'):
                    rule_info['name'] = f"AWS Managed Rule ({rule['RuleId']})"
                    rule_info['predicates'] = 0
                    rule_info['type'] = 'AWS Managed Rule'
                    rule_found = True
                elif len(rule['RuleId']) == 36 and rule['RuleId'].count('-') == 4:
                    # Standard UUID format - likely a managed rule we can't access
                    rule_info['name'] = f"Managed Rule ({rule['RuleId'][:8]}...)"
                    rule_info['predicates'] = 0
                    rule_info['type'] = 'Managed Rule'
                    rule_found = True
            
            # 5. If still not found, mark as unknown
            if not rule_found:
                rule_info['name'] = f'Unknown Rule ({rule["RuleId"][:8]}...)'
                rule_info['predicates'] = 0
                rule_info['type'] = 'Unknown'
            
            rules_info.append(rule_info)
        
        # Enhanced association details
        detailed_associations = []
        for assoc in associations:
            if assoc['type'] == 'Regional':
                arn = assoc['arn']
                if 'loadbalancer' in arn:
                    # Get ALB details
                    try:
                        elbv2_client = boto3.client('elbv2', region_name=region)
                        lb_name = arn.split('/')[-2]
                        response = elbv2_client.describe_load_balancers(Names=[lb_name])
                        lb = response['LoadBalancers'][0]
                        detailed_associations.append({
                            'type': 'Application Load Balancer',
                            'name': lb['LoadBalancerName'],
                            'arn': arn,
                            'dns_name': lb['DNSName'],
                            'state': lb['State']['Code']
                        })
                    except ClientError:
                        detailed_associations.append({
                            'type': 'Application Load Balancer',
                            'name': 'Unknown',
                            'arn': arn
                        })
                elif 'apigateway' in arn:
                    # Get API Gateway details
                    try:
                        api_id = arn.split('/')[-2]
                        apigw_client = boto3.client('apigateway', region_name=region)
                        response = apigw_client.get_rest_api(restApiId=api_id)
                        detailed_associations.append({
                            'type': 'API Gateway',
                            'name': response['name'],
                            'arn': arn,
                            'api_id': api_id
                        })
                    except ClientError:
                        detailed_associations.append({
                            'type': 'API Gateway',
                            'name': 'Unknown',
                            'arn': arn
                        })
                else:
                    detailed_associations.append(assoc)
            elif assoc['type'] == 'CloudFront':
                detailed_associations.append({
                    'type': 'CloudFront Distribution',
                    'id': assoc['id'],
                    'domain': assoc['domain']
                })
        
        return {
            'webacl_id': webacl_id,
            'name': webacl['Name'],
            'region': region,
            'default_action': webacl['DefaultAction']['Type'],
            'rules_count': len(rules_info),
            'rules': rules_info,
            'associations': detailed_associations,
            'safe_to_delete': len(detailed_associations) == 0
        }
        
    except ClientError as e:
        return {
            'webacl_id': webacl_id,
            'region': region,
            'error': str(e)
        }

def cleanup_webacls(webacl_ids=None, all_webacls=False, regions=None, all_regions=False, analyze_only=False):
    """Cleanup WebACLs with dependency analysis"""
    print("=== WebACL Cleanup ===")
    
    # Determine regions
    if all_regions:
        target_regions = WAFRegionManager.list_supported_regions()
    else:
        target_regions = regions.split(',') if regions else ['us-east-1']
    
    print(f"Target regions: {', '.join(target_regions)}")
    
    # Get WebACLs to process
    if all_webacls:
        print("Processing all WebACLs in target regions...")
        all_webacls_data = list_webacls_multi_region(target_regions)
        webacls_to_process = []
        for region, webacls in all_webacls_data.items():
            for webacl in webacls:
                webacls_to_process.append((webacl['id'], region))
    else:
        webacl_id_list = webacl_ids.split(',') if webacl_ids else []
        print(f"Processing specific WebACLs: {webacl_id_list}")
        found_webacls = search_webacls_multi_region(webacl_id_list, target_regions)
        webacls_to_process = []
        for region, webacls in found_webacls.items():
            for webacl in webacls:
                webacls_to_process.append((webacl['id'], region))
    
    if not webacls_to_process:
        print("No WebACLs found to process")
        return
    
    print(f"Found {len(webacls_to_process)} WebACLs to process")
    
    # Process each WebACL
    for webacl_id, region in webacls_to_process:
        print(f"\n--- Processing WebACL {webacl_id} in {region} ---")
        
        if analyze_only:
            # Use detailed analysis for analyze mode
            detailed_info = get_detailed_webacl_info(webacl_id, region)
            
            if 'error' in detailed_info:
                print(f"ERROR: {detailed_info['error']}")
                continue
            
            print(f"WebACL Name: {detailed_info['name']}")
            print(f"Default Action: {detailed_info['default_action']}")
            print(f"Rules Count: {detailed_info['rules_count']}")
            print(f"Safe to delete: {detailed_info['safe_to_delete']}")
            
            # Show detailed rules information
            if detailed_info['rules']:
                print("\nRules:")
                for rule in detailed_info['rules']:
                    print(f"  - {rule['name']} ({rule.get('type', 'Rule')})")
                    print(f"    ID: {rule['rule_id']}, Priority: {rule['priority']}, Action: {rule['action']}")
                    print(f"    Conditions: {rule['predicates']}")
            
            # Show detailed associations
            if detailed_info['associations']:
                print(f"\nActive Associations ({len(detailed_info['associations'])}):")
                for assoc in detailed_info['associations']:
                    if assoc['type'] == 'Application Load Balancer':
                        print(f"  - ALB: {assoc['name']}")
                        print(f"    DNS: {assoc.get('dns_name', 'N/A')}")
                        print(f"    State: {assoc.get('state', 'N/A')}")
                        print(f"    ARN: {assoc['arn']}")
                    elif assoc['type'] == 'API Gateway':
                        print(f"  - API Gateway: {assoc['name']}")
                        print(f"    API ID: {assoc.get('api_id', 'N/A')}")
                        print(f"    ARN: {assoc['arn']}")
                    elif assoc['type'] == 'CloudFront Distribution':
                        print(f"  - CloudFront: {assoc['id']}")
                        print(f"    Domain: {assoc['domain']}")
                    else:
                        print(f"  - {assoc}")
                print("\nWARNING: WebACL has active associations and cannot be safely deleted")
            else:
                print("\nNo active associations found - safe to delete")
            
            print("Analysis complete (no deletion performed)")
        else:
            # Use basic analysis for deletion mode
            cleanup = WAFv1CleanupUtils(region)
            analysis = cleanup.analyze_dependencies('webacl', webacl_id)
            
            print(f"Safe to delete: {analysis['safe_to_delete']}")
            if analysis['dependencies']:
                print(f"Dependencies: {len(analysis['dependencies'])}")
                for dep in analysis['dependencies']:
                    print(f"  - {dep}")
            
            if analysis['warnings']:
                for warning in analysis['warnings']:
                    print(f"WARNING: {warning}")
            
            if analysis['safe_to_delete']:
                print("Deleting WebACL...")
                result = delete_resource_safe('webacl', webacl_id, region)
                print(result)
            else:
                print("SKIPPED: Skipping deletion due to dependencies")

def cleanup_rulegroups(rulegroup_ids=None, all_rulegroups=False, regions=None, all_regions=False, analyze_only=False):
    """Cleanup RuleGroups with dependency analysis"""
    print("=== RuleGroup Cleanup ===")
    
    # Determine regions
    if all_regions:
        target_regions = WAFRegionManager.list_supported_regions()
    else:
        target_regions = regions.split(',') if regions else ['us-east-1']
    
    print(f"Target regions: {', '.join(target_regions)}")
    
    # Get RuleGroups to process
    if all_rulegroups:
        print("Processing all RuleGroups in target regions...")
        all_rulegroups_data = list_rulegroups_multi_region(target_regions)
        rulegroups_to_process = []
        for region, rulegroups in all_rulegroups_data.items():
            for rulegroup in rulegroups:
                rulegroups_to_process.append((rulegroup['id'], region))
    else:
        rulegroup_id_list = rulegroup_ids.split(',') if rulegroup_ids else []
        print(f"Processing specific RuleGroups: {rulegroup_id_list}")
        found_rulegroups = search_rulegroups_multi_region(rulegroup_id_list, target_regions)
        rulegroups_to_process = []
        for region, rulegroups in found_rulegroups.items():
            for rulegroup in rulegroups:
                rulegroups_to_process.append((rulegroup['id'], region))
    
    if not rulegroups_to_process:
        print("No RuleGroups found to process")
        return
    
    print(f"Found {len(rulegroups_to_process)} RuleGroups to process")
    
    # Process each RuleGroup
    for rulegroup_id, region in rulegroups_to_process:
        print(f"\n--- Processing RuleGroup {rulegroup_id} in {region} ---")
        
        cleanup = WAFv1CleanupUtils(region)
        analysis = cleanup.analyze_dependencies('rulegroup', rulegroup_id)
        
        print(f"Safe to delete: {analysis['safe_to_delete']}")
        if analysis['dependencies']:
            print(f"Dependencies: {len(analysis['dependencies'])}")
            for dep in analysis['dependencies']:
                print(f"  - {dep}")
        
        if analysis['warnings']:
            for warning in analysis['warnings']:
                print(f"WARNING: {warning}")
        
        if not analyze_only:
            if analysis['safe_to_delete']:
                print("Deleting RuleGroup...")
                result = delete_resource_safe('rulegroup', rulegroup_id, region)
                print(result)
            else:
                print("SKIPPED: Skipping deletion due to dependencies")
        else:
            print("Analysis complete (no deletion performed)")

def cleanup_rules(rule_ids=None, all_rules=False, regions=None, all_regions=False, analyze_only=False):
    """Cleanup Rules with dependency analysis"""
    print("=== Rule Cleanup ===")
    
    # Determine regions
    if all_regions:
        target_regions = WAFRegionManager.list_supported_regions()
    else:
        target_regions = regions.split(',') if regions else ['us-east-1']
    
    print(f"Target regions: {', '.join(target_regions)}")
    
    # Get Rules to process
    if all_rules:
        print("Processing all Rules in target regions...")
        all_rules_data = list_rules_multi_region(target_regions)
        rules_to_process = []
        for region, rules in all_rules_data.items():
            for rule in rules:
                rules_to_process.append((rule['id'], region))
    else:
        rule_id_list = rule_ids.split(',') if rule_ids else []
        print(f"Processing specific Rules: {rule_id_list}")
        found_rules = search_rules_multi_region(rule_id_list, target_regions)
        rules_to_process = []
        for region, rules in found_rules.items():
            for rule in rules:
                rules_to_process.append((rule['id'], region))
    
    if not rules_to_process:
        print("No Rules found to process")
        return
    
    print(f"Found {len(rules_to_process)} Rules to process")
    
    # Process each Rule
    for rule_id, region in rules_to_process:
        print(f"\n--- Processing Rule {rule_id} in {region} ---")
        
        cleanup = WAFv1CleanupUtils(region)
        analysis = cleanup.analyze_dependencies('rule', rule_id)
        
        print(f"Safe to delete: {analysis['safe_to_delete']}")
        if analysis['dependencies']:
            print(f"Dependencies: {len(analysis['dependencies'])}")
            for dep in analysis['dependencies']:
                print(f"  - {dep}")
        
        if analysis['warnings']:
            for warning in analysis['warnings']:
                print(f"WARNING: {warning}")
        
        if not analyze_only:
            if analysis['safe_to_delete']:
                print("Deleting Rule...")
                result = delete_resource_safe('rule', rule_id, region)
                print(result)
            else:
                print("SKIPPED: Skipping deletion due to dependencies")
        else:
            print("Analysis complete (no deletion performed)")

def cleanup_conditions(condition_ids=None, all_conditions=False, regions=None, all_regions=False, analyze_only=False):
    """Cleanup Conditions with dependency analysis"""
    print("=== Condition Cleanup ===")
    
    # Determine regions
    if all_regions:
        target_regions = WAFRegionManager.list_supported_regions()
    else:
        target_regions = regions.split(',') if regions else ['us-east-1']
    
    print(f"Target regions: {', '.join(target_regions)}")
    
    # Get Conditions to process
    if all_conditions:
        print("Processing all Conditions in target regions...")
        all_conditions_data = list_conditions_multi_region(target_regions)
        conditions_to_process = []
        for region, conditions_by_type in all_conditions_data.items():
            for condition_type, conditions in conditions_by_type.items():
                for condition in conditions:
                    conditions_to_process.append((condition['id'], condition_type, region))
    else:
        condition_id_list = condition_ids.split(',') if condition_ids else []
        print(f"Processing specific Conditions: {condition_id_list}")
        found_conditions = search_conditions_multi_region(condition_id_list, target_regions)
        conditions_to_process = []
        for region, conditions_by_type in found_conditions.items():
            for condition_type, conditions in conditions_by_type.items():
                for condition in conditions:
                    conditions_to_process.append((condition['id'], condition_type, region))
    
    if not conditions_to_process:
        print("No Conditions found to process")
        return
    
    print(f"Found {len(conditions_to_process)} Conditions to process")
    
    # Process each Condition
    for condition_id, condition_type, region in conditions_to_process:
        print(f"\n--- Processing {condition_type} {condition_id} in {region} ---")
        
        cleanup = WAFv1CleanupUtils(region)
        analysis = cleanup.analyze_dependencies(condition_type, condition_id)
        
        print(f"Safe to delete: {analysis['safe_to_delete']}")
        if analysis['dependencies']:
            print(f"Dependencies: {len(analysis['dependencies'])}")
            for dep in analysis['dependencies']:
                print(f"  - {dep}")
        
        if analysis['warnings']:
            for warning in analysis['warnings']:
                print(f"WARNING: {warning}")
        
        if not analyze_only:
            if analysis['safe_to_delete']:
                print(f"Deleting {condition_type}...")
                result = delete_resource_safe(condition_type, condition_id, region)
                print(result)
            else:
                print("SKIPPED: Skipping deletion due to dependencies")
        else:
            print("Analysis complete (no deletion performed)")

def cleanup_from_csv(csv_files, resource_type, analyze_only=False):
    """Cleanup resources from CSV files"""
    print(f"=== CSV Cleanup - {resource_type} ===")
    
    csv_file_list = csv_files.split(',') if csv_files else []
    
    for csv_file in csv_file_list:
        print(f"\nProcessing CSV file: {csv_file}")
        
        try:
            with open(csv_file, 'r') as f:
                reader = csv.DictReader(f)
                resources_to_process = []
                
                for row in reader:
                    cleanup_resource_id = None
                    # Normalize resource type to singular form for consistency
                    resource_type_singular = resource_type.rstrip('s')
                    
                    if resource_type_singular == 'webacl':
                        cleanup_resource_id = row.get('webacl_id')
                    elif resource_type_singular == 'rulegroup':
                        cleanup_resource_id = row.get('rulegroup_id')
                    elif resource_type_singular == 'rule':
                        cleanup_resource_id = row.get('rule_id')
                    elif resource_type_singular == 'condition':
                        cleanup_resource_id = row.get('condition_id')
                    
                    region = row.get('region')
                    
                    if not cleanup_resource_id or cleanup_resource_id == 'None':
                        print(f"SKIPPING: No valid resource ID found in row")
                        continue
                        
                    if row.get('mark_for_deletion', '') != 'DELETE':
                        print(f"SKIPPING: {cleanup_resource_id} in {region} is not marked for delete")
                        continue
                    
                    # Store both the resource ID and any condition type info if present
                    if resource_type_singular == 'condition':
                        condition_type = row.get('type', resource_type_singular)
                        resources_to_process.append((cleanup_resource_id, region, condition_type))
                    else:
                        resources_to_process.append((cleanup_resource_id, region))
                
                print(f"Found {len(resources_to_process)} {resource_type} to process")
                
                # Process each resource
                for resource_info in resources_to_process:
                    if resource_type_singular == 'condition' and len(resource_info) == 3:
                        resource_id, region, condition_type = resource_info
                        print(f"\n--- Processing {condition_type} {resource_id} in {region} ---")
                        
                        cleanup = WAFv1CleanupUtils(region)
                        analysis = cleanup.analyze_dependencies(condition_type, resource_id)
                    else:
                        resource_id, region = resource_info
                        print(f"\n--- Processing {resource_type_singular} {resource_id} in {region} ---")
                        
                        cleanup = WAFv1CleanupUtils(region)
                        analysis = cleanup.analyze_dependencies(resource_type_singular, resource_id)
                    
                    print(f"Safe to delete: {analysis['safe_to_delete']}")
                    if analysis['dependencies']:
                        print(f"Dependencies: {len(analysis['dependencies'])}")
                        for dep in analysis['dependencies']:
                            print(f"  - {dep}")
                    
                    if analysis['warnings']:
                        for warning in analysis['warnings']:
                            print(f"WARNING: {warning}")
                    
                    if not analyze_only:
                        if analysis['safe_to_delete']:
                            print(f"Deleting {resource_type_singular}...")
                            if resource_type_singular == 'condition' and len(resource_info) == 3:
                                result = delete_resource_safe(condition_type, resource_id, region)
                            else:
                                result = delete_resource_safe(resource_type_singular, resource_id, region)
                            print(result)
                        else:
                            print("SKIPPED: Skipping deletion due to dependencies")
                    else:
                        print("Analysis complete (no deletion performed)")
        
        except Exception as e:
            print(f"ERROR: Failed to process CSV file {csv_file}: {str(e)}")

def delete_resource_safe(resource_type, resource_id, region):
    """Delete a single WAF resource safely with proper dependency clearing"""
    try:
        if region == 'cloudfront':
            client = boto3.client('waf', region_name='us-east-1')
        else:
            client = boto3.client('waf-regional', region_name=region)
        
        if resource_type == 'webacl':
            # Get fresh change token and WebACL details
            webacl = client.get_web_acl(WebACLId=resource_id)
            
            # Remove all rules from WebACL first
            if webacl['WebACL']['Rules']:
                updates = []
                for rule in webacl['WebACL']['Rules']:
                    updates.append({
                        'Action': 'DELETE',
                        'ActivatedRule': rule
                    })
                client.update_web_acl(
                    WebACLId=resource_id,
                    Updates=updates,
                    ChangeToken=client.get_change_token()['ChangeToken']
                )
            
            # Delete WebACL
            client.delete_web_acl(
                WebACLId=resource_id,
                ChangeToken=client.get_change_token()['ChangeToken']
            )
        
        elif resource_type == 'rulegroup':
            # Get the activated rules in the RuleGroup
            try:
                activated_rules_response = client.list_activated_rules_in_rule_group(RuleGroupId=resource_id)
                activated_rules = activated_rules_response.get('ActivatedRules', [])
                
                # Remove all activated rules from RuleGroup
                if activated_rules:
                    updates = []
                    for activated_rule in activated_rules:
                        updates.append({
                            'Action': 'DELETE',
                            'ActivatedRule': activated_rule
                        })
                    
                    client.update_rule_group(
                        RuleGroupId=resource_id,
                        Updates=updates,
                        ChangeToken=client.get_change_token()['ChangeToken']
                    )
                
                # Delete empty RuleGroup
                client.delete_rule_group(
                    RuleGroupId=resource_id,
                    ChangeToken=client.get_change_token()['ChangeToken']
                )
            except Exception as e:
                # Fallback: try to delete directly if list operation fails
                client.delete_rule_group(
                    RuleGroupId=resource_id,
                    ChangeToken=client.get_change_token()['ChangeToken']
                )
        
        elif resource_type == 'rule':
            # First, determine if this is a regular rule or rate-based rule
            rule_type = 'REGULAR'  # Default assumption
            
            try:
                # Try to get as regular rule first
                rule = client.get_rule(RuleId=resource_id)
                rule_type = 'REGULAR'
            except Exception:
                try:
                    # If that fails, try as rate-based rule
                    rule = client.get_rate_based_rule(RuleId=resource_id)
                    rule_type = 'RATE_BASED'
                except Exception as e:
                    raise Exception(f"Could not find rule {resource_id} as either regular or rate-based rule: {str(e)}")
            
            if rule_type == 'REGULAR':
                # Handle regular rule deletion - delete predicates one by one
                # Get fresh rule data
                rule = client.get_rule(RuleId=resource_id)
                predicates = rule.get('Rule', {}).get('Predicates', [])
                if predicates:
                    for predicate in predicates:
                        client.update_rule(
                            RuleId=resource_id,
                            Updates=[{
                                'Action': 'DELETE',
                                'Predicate': predicate
                            }],
                            ChangeToken=client.get_change_token()['ChangeToken']
                        )
                
                # Delete Rule
                client.delete_rule(
                    RuleId=resource_id,
                    ChangeToken=client.get_change_token()['ChangeToken']
                )
            
            elif rule_type == 'RATE_BASED':
                # Handle rate-based rule deletion - delete predicates one by one
                # Get fresh rule data
                rule = client.get_rate_based_rule(RuleId=resource_id)
                
                # Rate-based rules use 'MatchPredicates' instead of 'Predicates'
                predicates = rule.get('Rule', {}).get('MatchPredicates', [])
                rate_limit = rule.get('Rule', {}).get('RateLimit', 2000)  # Get current rate limit
                
                if predicates:
                    for predicate in predicates:
                        client.update_rate_based_rule(
                            RuleId=resource_id,
                            Updates=[{
                                'Action': 'DELETE',
                                'Predicate': predicate
                            }],
                            RateLimit=rate_limit,
                            ChangeToken=client.get_change_token()['ChangeToken']
                        )
                
                # Delete Rate-based Rule
                client.delete_rate_based_rule(
                    RuleId=resource_id,
                    ChangeToken=client.get_change_token()['ChangeToken']
                )
        
        elif resource_type == 'ByteMatchSet':
            condition = client.get_byte_match_set(ByteMatchSetId=resource_id)
            if condition['ByteMatchSet']['ByteMatchTuples']:
                updates = []
                for tuple_item in condition['ByteMatchSet']['ByteMatchTuples']:
                    updates.append({'Action': 'DELETE', 'ByteMatchTuple': tuple_item})
                client.update_byte_match_set(
                    ByteMatchSetId=resource_id,
                    Updates=updates,
                    ChangeToken=client.get_change_token()['ChangeToken']
                )
            client.delete_byte_match_set(
                ByteMatchSetId=resource_id,
                ChangeToken=client.get_change_token()['ChangeToken']
            )
        
        elif resource_type == 'IPSet':
            condition = client.get_ip_set(IPSetId=resource_id)
            if condition['IPSet']['IPSetDescriptors']:
                updates = []
                for descriptor in condition['IPSet']['IPSetDescriptors']:
                    updates.append({'Action': 'DELETE', 'IPSetDescriptor': descriptor})
                client.update_ip_set(
                    IPSetId=resource_id,
                    Updates=updates,
                    ChangeToken=client.get_change_token()['ChangeToken']
                )
            client.delete_ip_set(
                IPSetId=resource_id,
                ChangeToken=client.get_change_token()['ChangeToken']
            )
        
        elif resource_type == 'SqlInjectionMatchSet':
            condition = client.get_sql_injection_match_set(SqlInjectionMatchSetId=resource_id)
            if condition['SqlInjectionMatchSet']['SqlInjectionMatchTuples']:
                updates = []
                for tuple_item in condition['SqlInjectionMatchSet']['SqlInjectionMatchTuples']:
                    updates.append({'Action': 'DELETE', 'SqlInjectionMatchTuple': tuple_item})
                client.update_sql_injection_match_set(
                    SqlInjectionMatchSetId=resource_id,
                    Updates=updates,
                    ChangeToken=client.get_change_token()['ChangeToken']
                )
            client.delete_sql_injection_match_set(
                SqlInjectionMatchSetId=resource_id,
                ChangeToken=client.get_change_token()['ChangeToken']
            )
        
        elif resource_type == 'XssMatchSet':
            condition = client.get_xss_match_set(XssMatchSetId=resource_id)
            if condition['XssMatchSet']['XssMatchTuples']:
                updates = []
                for tuple_item in condition['XssMatchSet']['XssMatchTuples']:
                    updates.append({'Action': 'DELETE', 'XssMatchTuple': tuple_item})
                client.update_xss_match_set(
                    XssMatchSetId=resource_id,
                    Updates=updates,
                    ChangeToken=client.get_change_token()['ChangeToken']
                )
            client.delete_xss_match_set(
                XssMatchSetId=resource_id,
                ChangeToken=client.get_change_token()['ChangeToken']
            )
        
        elif resource_type == 'SizeConstraintSet':
            condition = client.get_size_constraint_set(SizeConstraintSetId=resource_id)
            if condition['SizeConstraintSet']['SizeConstraints']:
                updates = []
                for constraint in condition['SizeConstraintSet']['SizeConstraints']:
                    updates.append({'Action': 'DELETE', 'SizeConstraint': constraint})
                client.update_size_constraint_set(
                    SizeConstraintSetId=resource_id,
                    Updates=updates,
                    ChangeToken=client.get_change_token()['ChangeToken']
                )
            client.delete_size_constraint_set(
                SizeConstraintSetId=resource_id,
                ChangeToken=client.get_change_token()['ChangeToken']
            )
        
        elif resource_type == 'GeoMatchSet':
            condition = client.get_geo_match_set(GeoMatchSetId=resource_id)
            if condition['GeoMatchSet']['GeoMatchConstraints']:
                updates = []
                for constraint in condition['GeoMatchSet']['GeoMatchConstraints']:
                    updates.append({'Action': 'DELETE', 'GeoMatchConstraint': constraint})
                client.update_geo_match_set(
                    GeoMatchSetId=resource_id,
                    Updates=updates,
                    ChangeToken=client.get_change_token()['ChangeToken']
                )
            client.delete_geo_match_set(
                GeoMatchSetId=resource_id,
                ChangeToken=client.get_change_token()['ChangeToken']
            )
        
        elif resource_type == 'RegexPatternSet':
            condition = client.get_regex_pattern_set(RegexPatternSetId=resource_id)
            if condition['RegexPatternSet']['RegexPatternStrings']:
                updates = []
                for pattern in condition['RegexPatternSet']['RegexPatternStrings']:
                    updates.append({'Action': 'DELETE', 'RegexPatternString': pattern})
                client.update_regex_pattern_set(
                    RegexPatternSetId=resource_id,
                    Updates=updates,
                    ChangeToken=client.get_change_token()['ChangeToken']
                )
            client.delete_regex_pattern_set(
                RegexPatternSetId=resource_id,
                ChangeToken=client.get_change_token()['ChangeToken']
            )
        
        elif resource_type == 'RegexMatchSet':
            condition = client.get_regex_match_set(RegexMatchSetId=resource_id)
            if condition['RegexMatchSet']['RegexMatchTuples']:
                updates = []
                for tuple_item in condition['RegexMatchSet']['RegexMatchTuples']:
                    updates.append({'Action': 'DELETE', 'RegexMatchTuple': tuple_item})
                client.update_regex_match_set(
                    RegexMatchSetId=resource_id,
                    Updates=updates,
                    ChangeToken=client.get_change_token()['ChangeToken']
                )
            client.delete_regex_match_set(
                RegexMatchSetId=resource_id,
                ChangeToken=client.get_change_token()['ChangeToken']
            )
        
        return f"SUCCESS: Deleted {resource_type} {resource_id}"
    
    except Exception as e:
        return f"ERROR: Failed to delete {resource_type} {resource_id}: {str(e)}"

def delete_resources_by_type(resource_list, resource_type, region):
    """Delete resources of a specific type with progress tracking"""
    if not resource_list:
        print(f"No {resource_type} found to delete")
        return
    
    total = len(resource_list)
    print(f"\nDeleting {total} {resource_type}...")
    
    for i, resource in enumerate(resource_list, 1):
        resource_id = resource['id']
        print(f"[{i}/{total}] Deleting {resource_type}: {resource_id}")
        result = delete_resource_safe(resource_type, resource_id, region)
        if "ERROR" in result:
            print(f"  {result}")
        else:
            print(f"  SUCCESS")
        
        # Small delay to avoid rate limits
        time.sleep(0.2)

def delete_all_resources(regions=None, all_regions=False):
    """Delete all WAF resources in specified regions in proper order"""
    print("=== Delete All Resources ===")
    print("WARNING: This will delete ALL WAF Classic resources!")
    
    # Determine regions
    if all_regions:
        target_regions = WAFRegionManager.list_supported_regions()
    else:
        target_regions = regions.split(',') if regions else ['us-east-1']
    
    print(f"Target regions: {', '.join(target_regions)}")
    
    # Get confirmation
    confirm = input("Are you sure you want to delete ALL resources? Type 'DELETE ALL' to confirm: ")
    if confirm != 'DELETE ALL':
        print("Operation cancelled")
        return
    
    for region in target_regions:
        print(f"\n--- Processing region {region} ---")
        
        cleanup = WAFv1CleanupUtils(region)
        
        # Delete in proper order: WebACLs -> RuleGroups -> Rules -> Conditions
        # This ensures dependencies are removed first
        
        # 1. WebACLs (must be first as they reference RuleGroups and Rules)
        webacls = cleanup.list_webacls()
        delete_resources_by_type(webacls, 'webacl', region)
        
        # 2. RuleGroups (must be before Rules as they reference Rules)
        rulegroups = cleanup.list_rulegroups()
        delete_resources_by_type(rulegroups, 'rulegroup', region)
        
        # 3. Rules (must be before Conditions as they reference Conditions)
        rules = cleanup.list_rules()
        delete_resources_by_type(rules, 'rule', region)
        
        # 4. Conditions (can be deleted last as nothing references them)
        conditions = cleanup.list_conditions()
        for condition_type, condition_list in conditions.items():
            delete_resources_by_type(condition_list, condition_type, region)
        
        print(f"Completed processing region {region}")

def check_aws_credentials():
    """Check if AWS credentials are configured and working"""
    try:
        sts = boto3.client('sts')
        sts.get_caller_identity()
        return True
    except (NoCredentialsError, ClientError):
        return False

def handle_export_webacl(args):
    """Handle export-webacl command"""
    export_webacls_for_cleanup(
        webacl_ids=args.webacl_ids,
        all_webacls=args.all_webacls,
        regions=args.regions,
        all_regions=args.all_regions,
        filename=None
    )

def handle_export_rulegroup(args):
    """Handle export-rulegroup command"""
    export_rulegroups_for_cleanup(
        rulegroup_ids=args.rulegroup_ids,
        all_rulegroups=args.all_rulegroups,
        regions=args.regions,
        all_regions=args.all_regions,
        filename=None
    )

def handle_export_rule(args):
    """Handle export-rule command"""
    export_rules_for_cleanup(
        rule_ids=args.rule_ids,
        all_rules=args.all_rules,
        regions=args.regions,
        all_regions=args.all_regions,
        filename=None
    )

def handle_export_condition(args):
    """Handle export-condition command"""
    export_conditions_for_cleanup(
        condition_ids=args.condition_ids,
        all_conditions=args.all_conditions,
        regions=args.regions,
        all_regions=args.all_regions,
        filename=None
    )

def export_webacls_for_cleanup(webacl_ids=None, all_webacls=False, regions=None, all_regions=False, filename=None):
    """Export WebACLs to CSV for cleanup planning"""
    
    if all_regions:
        region_list = WAFRegionManager.list_supported_regions()
    else:
        region_list = regions.split(",") if regions else []
    
    if all_webacls:
        webacls_data = list_webacls_multi_region(region_list, all_regions)
    else:
        webacls_data = search_webacls_multi_region(webacl_ids, region_list, all_regions)
    
    if not webacls_data:
        print("No WebACLs found to export")
        return
    
    flat_webacls = []
    for region, webacls in webacls_data.items():
        # Create cleanup utils for this region to get association information
        cleanup = WAFv1CleanupUtils(region)
        
        for webacl in webacls:
            webacl['region'] = region
            # Add association information if not present
            if 'associations' not in webacl or webacl['associations'] is None:
                webacl['associations'] = cleanup._get_webacl_associations(webacl['id'])
            flat_webacls.append(webacl)
    
    csv_filename = export_webacls_to_csv(flat_webacls, filename)
    print(f"Exported {len(flat_webacls)} WebACLs to: {csv_filename}")

def export_rulegroups_for_cleanup(rulegroup_ids=None, all_rulegroups=False, regions=None, all_regions=False, filename=None):
    """Export RuleGroups to CSV for cleanup planning"""
    
    if all_regions:
        region_list = WAFRegionManager.list_supported_regions()
    else:
        region_list = regions.split(",") if regions else []
    
    if all_rulegroups:
        rulegroups_data = list_rulegroups_multi_region(region_list, all_regions)
    else:
        rulegroups_data = search_rulegroups_multi_region(rulegroup_ids, region_list, all_regions)
    
    if not rulegroups_data:
        print("No RuleGroups found to export")
        return
    
    flat_rulegroups = []
    for region, rulegroups in rulegroups_data.items():
        # Create cleanup utils for this region to get usage information
        cleanup = WAFv1CleanupUtils(region)
        
        for rulegroup in rulegroups:
            rulegroup['region'] = region
            # Add usage information if not present
            if 'usage' not in rulegroup or rulegroup['usage'] is None:
                rulegroup['usage'] = cleanup._get_rulegroup_usage(rulegroup['id'])
            flat_rulegroups.append(rulegroup)
    
    csv_filename = export_rulegroups_to_csv(flat_rulegroups, filename)
    print(f"Exported {len(flat_rulegroups)} RuleGroups to: {csv_filename}")

def export_rules_for_cleanup(rule_ids=None, all_rules=False, regions=None, all_regions=False, filename=None):
    """Export Rule to CSV for cleanup planning"""
    
    if all_regions:
        region_list = WAFRegionManager.list_supported_regions()
    else:
        region_list = regions.split(",") if regions else []
    
    if all_rules:
        rules_data = list_rules_multi_region(region_list, all_regions)
    else:
        rules_data = search_rules_multi_region(rule_ids, region_list, all_regions)
    
    if not rules_data:
        print("No Rule found to export")
        return
    
    # Convert to flat list for CSV export
    flat_rules = []
    for region, rules in rules_data.items():
        # Create cleanup utils for this region to get usage information
        cleanup = WAFv1CleanupUtils(region)
        
        for rule in rules:
            rule['region'] = region
            # Add usage information if not present
            if 'usage' not in rule or rule['usage'] is None:
                rule['usage'] = cleanup._get_rule_usage(rule['id'])
            flat_rules.append(rule)
    
    csv_filename = export_rules_to_csv(flat_rules, filename)
    print(f"Exported {len(flat_rules)} Rules to: {csv_filename}")

def export_conditions_for_cleanup(condition_ids=None, all_conditions=False, regions=None, all_regions=False, filename=None):
    """Export Condition to CSV for cleanup planning"""
    
    if all_regions:
        region_list = WAFRegionManager.list_supported_regions()
    else:
        region_list = regions.split(",") if regions else []
    
    if all_conditions:
        conditions_data = list_conditions_multi_region(region_list, all_regions, include_usage=True)
    else:
        conditions_data = search_conditions_multi_region(condition_ids, region_list, all_regions)
    
    if not conditions_data:
        print("No Condition found to export")
        return
    
    flat_conditions = []
    for region, conditions_by_type in conditions_data.items():
        # conditions_by_type is a dict with condition types as keys
        for condition_type, conditions in conditions_by_type.items():
            for condition in conditions:
                # Ensure condition has all necessary fields
                condition['region'] = region
                # Usage information should already be present from optimized listing
                if 'usage' not in condition:
                    condition['usage'] = []  # Default to empty if missing
                flat_conditions.append(condition)
    
    csv_filename = export_conditions_to_csv(flat_conditions, filename)
    print(f"Exported {len(flat_conditions)} Conditions to: {csv_filename}")

def main():
    # Check AWS credentials first
    if not check_aws_credentials():
        print("ERROR: AWS credentials not found or not working!")
        print()
        print("Options:")
        print("1. Run: ./waf-migrate.sh --setup-credentials")
        print("2. Run: aws configure")
        print("3. Set environment variables:")
        print("   export AWS_ACCESS_KEY_ID='your-access-key'")
        print("   export AWS_SECRET_ACCESS_KEY='your-secret-key'")
        print("   export AWS_DEFAULT_REGION='us-east-1'")
        return

    parser = argparse.ArgumentParser(description='WAF Classic (v1) Cleanup Tool')
    parser.add_argument('command', nargs='?', choices=[
        'export-webacl', 'export-rulegroup', 'export-rule', 'export-condition'
    ], help='Command to run (optional for direct cleanup operations)')

    # WebACL cleanup commands
    parser.add_argument('--webacl-ids', help='Comma-separated WebACL IDs')
    parser.add_argument('--all-webacls', action='store_true', help='Process all WebACLs')
    
    # RuleGroup cleanup commands  
    parser.add_argument('--rulegroup-ids', help='Comma-separated RuleGroup IDs')
    parser.add_argument('--all-rulegroups', action='store_true', help='Process all RuleGroups')
    
    # Rule cleanup commands
    parser.add_argument('--rule-ids', help='Comma-separated Rule IDs')
    parser.add_argument('--all-rules', action='store_true', help='Process all Rules')
    
    # Condition cleanup commands
    parser.add_argument('--condition-ids', help='Comma-separated Condition IDs')
    parser.add_argument('--all-conditions', action='store_true', help='Process all Conditions')
    
    # Region selection
    parser.add_argument('--regions', help='Comma-separated regions')
    parser.add_argument('--all-regions', action='store_true', help='Process all regions')
    
    # Analysis mode
    parser.add_argument('--analyze', action='store_true', help='Only analyze, do not delete')
    
    # CSV operations
    parser.add_argument('--csv-file', help='Comma-separated CSV files')
    parser.add_argument('--resource-type', choices=['webacls', 'rulegroups', 'rules', 'conditions'], 
                       help='Resource type for CSV operations')
    
    # Delete all
    parser.add_argument('--delete-all', action='store_true', help='Delete all resources')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.csv_file and not args.resource_type:
        parser.error("--resource-type is required when using --csv-file")
    
    if not any([args.webacl_ids, args.all_webacls, args.rulegroup_ids, args.all_rulegroups,
                args.rule_ids, args.all_rules, args.condition_ids, args.all_conditions,
                args.csv_file, args.delete_all, args.command]):
        parser.error("Must specify one of: --webacl-ids, --all-webacls, --rulegroup-ids, "
                    "--all-rulegroups, --rule-ids, --all-rules, --condition-ids, "
                    "--all-conditions, --csv-file, --delete-all")
    
    if not args.all_regions and not args.regions and not args.csv_file:
        parser.error("Must specify --regions or --all-regions (except for import CSV operations)")
    
    if args.command == 'export-webacl':
        valid_combinations = [
            # Specific WebACL IDs with regions
            (bool(args.webacl_ids), bool(args.regions), not bool(args.all_regions), not bool(args.all_webacls)),
            # All WebACLs with regions  
            (bool(args.all_webacls), bool(args.regions), not bool(args.all_regions), not bool(args.webacl_ids)),
            # All WebACLs with all regions
            (bool(args.all_webacls), bool(args.all_regions), not bool(args.regions), not bool(args.webacl_ids))
        ]
        
        if not any(all(combo) for combo in valid_combinations):
            print("ERROR: Invalid argument combination for export-webacl")
            print("Valid combinations:")
            print("  --webacl-ids <ids> --regions <regions>")
            print("  --all-webacls --regions <regions>")
            print("  --all-webacls --all-regions")
            return

    if args.command == 'export-rulegroup':
        valid_combinations = [
            # Specific RuleGroup IDs with regions
            (bool(args.rulegroup_ids), bool(args.regions), not bool(args.all_regions), not bool(args.all_rulegroups)),
            # All RuleGroups with regions
            (bool(args.all_rulegroups), bool(args.regions), not bool(args.all_regions), not bool(args.rulegroup_ids)),
            # All RuleGroups with all regions
            (bool(args.all_rulegroups), bool(args.all_regions), not bool(args.regions), not bool(args.rulegroup_ids))
        ]
        
        if not any(all(combo) for combo in valid_combinations):
            print("ERROR: Invalid argument combination for export-rulegroup")
            print("Valid combinations:")
            print("  --rulegroup-ids <ids> --regions <regions>")
            print("  --all-rulegroups --regions <regions>")
            print("  --all-rulegroups --all-regions")
            return

    if args.command == 'export-rule':
        valid_combinations = [
            # Specific RuleGroup IDs with regions
            (bool(args.rule_ids), bool(args.regions), not bool(args.all_regions), not bool(args.all_rules)),
            # All RuleGroups with regions
            (bool(args.all_rules), bool(args.regions), not bool(args.all_regions), not bool(args.rule_ids)),
            # All RuleGroups with all regions
            (bool(args.all_rules), bool(args.all_regions), not bool(args.regions), not bool(args.rule_ids))
        ]
        
        if not any(all(combo) for combo in valid_combinations):
            print("ERROR: Invalid argument combination for export-rule")
            print("Valid combinations:")
            print("  --rule-ids <ids> --regions <regions>")
            print("  --all-rules --regions <regions>")
            print("  --all-rules --all-regions")
            return

    if args.command == 'export-condition':
        valid_combinations = [
            # Specific RuleGroup IDs with regions
            (bool(args.condition_ids), bool(args.regions), not bool(args.all_regions), not bool(args.all_conditions)),
            # All RuleGroups with regions
            (bool(args.all_conditions), bool(args.regions), not bool(args.all_regions), not bool(args.condition_ids)),
            # All RuleGroups with all regions
            (bool(args.all_conditions), bool(args.all_regions), not bool(args.regions), not bool(args.condition_ids))
        ]
        
        if not any(all(combo) for combo in valid_combinations):
            print("ERROR: Invalid argument combination for export-condition")
            print("Valid combinations:")
            print("  --condition-ids <ids> --regions <regions>")
            print("  --all-conditions --regions <regions>")
            print("  --all-conditions --all-regions")
            return

    if args.command == 'export-webacl':
        handle_export_webacl(args)
    elif args.command == 'export-rulegroup':
        handle_export_rulegroup(args)
    elif args.command == 'export-rule':
        handle_export_rule(args)
    elif args.command == 'export-condition':
        handle_export_condition(args)
    elif args.csv_file:
        cleanup_from_csv(args.csv_file, args.resource_type, args.analyze)
    elif args.delete_all:
        delete_all_resources(args.regions, args.all_regions)
    elif args.webacl_ids or args.all_webacls:
        cleanup_webacls(args.webacl_ids, args.all_webacls, args.regions, args.all_regions, args.analyze)
    elif args.rulegroup_ids or args.all_rulegroups:
        cleanup_rulegroups(args.rulegroup_ids, args.all_rulegroups, args.regions, args.all_regions, args.analyze)
    elif args.rule_ids or args.all_rules:
        cleanup_rules(args.rule_ids, args.all_rules, args.regions, args.all_regions, args.analyze)
    elif args.condition_ids or args.all_conditions:
        cleanup_conditions(args.condition_ids, args.all_conditions, args.regions, args.all_regions, args.analyze)
    else:
        print(f"Unknown command")

if __name__ == '__main__':
    main()
