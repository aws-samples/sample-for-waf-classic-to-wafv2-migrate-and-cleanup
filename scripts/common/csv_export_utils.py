#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""
CSV Export Utilities for WAF Tools
Provides standardized CSV export functionality for WebACLs, RuleGroups, Rules, and Conditions
"""

import csv
import os
import boto3
from datetime import datetime
from botocore.exceptions import ClientError

def get_account_id():
    """Get current AWS account ID"""
    try:
        sts = boto3.client('sts')
        return sts.get_caller_identity()['Account']
    except:
        return 'unknown'

def export_webacls_to_csv(webacls_data, filename=None, mark_column='mark_for_deletion'):
    """Export WebACLs to CSV with standardized format"""
    if not filename:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = 'webacls_export_{}.csv'.format(timestamp)
    
    account_id = get_account_id()
    
    # Determine default value based on mark column
    default_value = 'DELETE' if mark_column == 'mark_for_deletion' else 'MIGRATE' if mark_column == 'mark_for_migration' else ''
    
    headers = [
        'webacl_name', 'webacl_id', 'region', 'scope', 'account_id', 
        'default_action', 'rules_count', 'associated_resources_NOT_MIGRATED', 
        'resource_identifiers', mark_column
    ]
    
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        
        for webacl in webacls_data:
            # Get WebACL details if not already present (for rules count and default action)
            rules_count = webacl.get('rules_count', 0)
            default_action = webacl.get('default_action', '')
            
            # If these details are missing, try to get them
            if not rules_count or not default_action:
                try:
                    region = webacl.get('region', '')
                    if region == 'cloudfront':
                        waf_client = boto3.client('waf', region_name='us-east-1')
                    else:
                        waf_client = boto3.client('waf-regional', region_name=region)
                    
                    webacl_details = waf_client.get_web_acl(WebACLId=webacl['id'])
                    rules_count = len(webacl_details.get('WebACL', {}).get('Rules', []))
                    default_action = webacl_details.get('WebACL', {}).get('DefaultAction', {}).get('Type', '')
                except:
                    pass
            
            # Format associated resources
            associated_resources = 'None'
            resource_identifiers = 'None'
            
            if webacl.get('associations'):
                assoc_list = []
                id_list = []
                for assoc in webacl['associations']:
                    assoc_type = assoc.get('type', '')
                    
                    if assoc_type == 'CloudFront Distribution':
                        # CloudFront associations
                        resource_desc = "CloudFront: {}".format(assoc.get('domain', assoc.get('id', 'Unknown')))
                        assoc_list.append(resource_desc)
                        id_list.append(assoc.get('id', 'Unknown'))
                    elif assoc_type == 'Application Load Balancer':
                        # ALB associations
                        name = assoc.get('name', 'Unknown')
                        dns_name = assoc.get('dns_name', '')
                        resource_desc = "ALB: {} ({})".format(name, dns_name) if dns_name else "ALB: {}".format(name)
                        assoc_list.append(resource_desc)
                        id_list.append(assoc.get('arn', assoc.get('name', 'Unknown')))
                    elif assoc_type == 'API Gateway':
                        # API Gateway associations
                        name = assoc.get('name', 'Unknown')
                        api_id = assoc.get('api_id', '')
                        resource_desc = "API Gateway: {} ({})".format(name, api_id) if api_id else "API Gateway: {}".format(name)
                        assoc_list.append(resource_desc)
                        id_list.append(assoc.get('arn', assoc.get('api_id', 'Unknown')))
                    elif assoc_type == 'CloudFront':
                        # Legacy CloudFront format
                        resource_desc = "CloudFront: {}".format(assoc.get('domain', assoc.get('id', 'Unknown')))
                        assoc_list.append(resource_desc)
                        id_list.append(assoc.get('id', 'Unknown'))
                    elif assoc_type == 'Regional':
                        # Legacy Regional resources format
                        arn = assoc.get('arn', '')
                        if arn:
                            # Extract resource type from ARN
                            if 'loadbalancer' in arn:
                                resource_type = 'ALB'
                            elif 'apigateway' in arn:
                                resource_type = 'API Gateway'
                            else:
                                resource_type = 'Regional Resource'
                            
                            assoc_list.append("{}: {}".format(resource_type, arn.split('/')[-1]))
                            id_list.append(arn)
                    else:
                        # Fallback for any other format
                        resource = assoc.get('resource', assoc.get('arn', assoc.get('id', 'Unknown')))
                        assoc_list.append("{}: {}".format(assoc_type, resource))
                        id_list.append(assoc.get('arn', assoc.get('id', resource)))
                
                if assoc_list:
                    associated_resources = '; '.join(assoc_list)
                    resource_identifiers = '; '.join(id_list)
            
            row = [
                webacl.get('name', ''),
                webacl.get('id', ''),
                webacl.get('region', ''),
                'global' if webacl.get('region') == 'cloudfront' else 'regional',
                account_id,
                default_action,
                rules_count,
                associated_resources,
                resource_identifiers,
                default_value  # Use default value instead of empty string
            ]
            writer.writerow(row)
    
    return filename

def export_rulegroups_to_csv(rulegroups_data, filename=None, mark_column='mark_for_deletion'):
    """Export RuleGroups to CSV with standardized format"""
    if not filename:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = 'rulegroups_export_{}.csv'.format(timestamp)
    
    account_id = get_account_id()
    
    # Determine default value based on mark column
    default_value = 'DELETE' if mark_column == 'mark_for_deletion' else 'MIGRATE' if mark_column == 'mark_for_migration' else ''
    
    headers = [
        'rulegroup_name', 'rulegroup_id', 'region', 'scope', 'account_id',
        'rules_count', 'used_by_webacls', 'webacl_identifiers', mark_column
    ]
    
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        
        for rulegroup in rulegroups_data:
            # Get RuleGroup details if rules_count is missing
            rules_count = rulegroup.get('rules_count', 0)
            
            if not rules_count and rulegroup.get('rule_count'):
                # Handle different field name
                rules_count = rulegroup.get('rule_count', 0)
            
            if not rules_count:
                # Try to fetch the actual count
                try:
                    region = rulegroup.get('region', '')
                    if region == 'cloudfront':
                        waf_client = boto3.client('waf', region_name='us-east-1')
                    else:
                        waf_client = boto3.client('waf-regional', region_name=region)
                    
                    # Get activated rules in the RuleGroup
                    activated_rules = waf_client.list_activated_rules_in_rule_group(
                        RuleGroupId=rulegroup['id']
                    )
                    rules_count = len(activated_rules.get('ActivatedRules', []))
                except:
                    pass
            
            # Format usage info
            used_by_webacls = 'None'
            webacl_identifiers = 'None'
            
            if rulegroup.get('usage'):
                usage_list = []
                id_list = []
                for usage in rulegroup['usage']:
                    if usage.get('webacl_name') and usage.get('webacl_id'):
                        usage_list.append("{} ({})".format(usage['webacl_name'], usage['webacl_id']))
                        id_list.append(usage['webacl_id'])
                
                if usage_list:
                    used_by_webacls = '; '.join(usage_list)
                    webacl_identifiers = '; '.join(id_list)
            
            row = [
                rulegroup.get('name', ''),
                rulegroup.get('id', ''),
                rulegroup.get('region', ''),
                'global' if rulegroup.get('region') == 'cloudfront' else 'regional',
                account_id,
                rules_count,
                used_by_webacls,
                webacl_identifiers,
                default_value  # Use default value instead of empty string
            ]
            writer.writerow(row)
    
    return filename

def export_rules_to_csv(rules_data, filename=None, mark_column='mark_for_deletion'):
    """Export Rules to CSV with standardized format"""
    if not filename:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = 'rules_export_{}.csv'.format(timestamp)
    
    account_id = get_account_id()
    
    # Determine default value based on mark column
    default_value = 'DELETE' if mark_column == 'mark_for_deletion' else 'MIGRATE' if mark_column == 'mark_for_migration' else ''
    
    headers = [
        'rule_name', 'rule_id', 'region', 'scope', 'account_id',
        'conditions_count', 'used_by_resources', 'resource_identifiers', mark_column
    ]
    
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        
        for rule in rules_data:
            # Get conditions count if missing
            conditions_count = rule.get('conditions_count', 0)
            
            if not conditions_count:
                # Try to fetch the actual count
                try:
                    region = rule.get('region', '')
                    if region == 'cloudfront':
                        waf_client = boto3.client('waf', region_name='us-east-1')
                    else:
                        waf_client = boto3.client('waf-regional', region_name=region)
                    
                    # Get predicates based on rule type
                    rule_type = rule.get('type', 'REGULAR')
                    if rule_type == 'RATE_BASED':
                        rule_details = waf_client.get_rate_based_rule(RuleId=rule['id'])
                        predicates = rule_details.get('Rule', {}).get('MatchPredicates', [])
                    else:
                        rule_details = waf_client.get_rule(RuleId=rule['id'])
                        predicates = rule_details.get('Rule', {}).get('Predicates', [])
                    
                    conditions_count = len(predicates)
                except:
                    pass
            
            # Format usage info
            used_by_resources = 'None'
            resource_identifiers = 'None'
            
            if rule.get('usage'):
                usage_list = []
                id_list = []
                for usage in rule['usage']:
                    resource_type = usage.get('type', 'resource')
                    resource_name = usage.get('name', usage.get('id', ''))
                    resource_id = usage.get('id', '')
                    
                    usage_list.append("{}: {}".format(resource_type, resource_name))
                    id_list.append(resource_id)
                
                if usage_list:
                    used_by_resources = '; '.join(usage_list)
                    resource_identifiers = '; '.join(id_list)
            
            row = [
                rule.get('name', ''),
                rule.get('id', ''),
                rule.get('region', ''),
                'global' if rule.get('region') == 'cloudfront' else 'regional',
                account_id,
                conditions_count,
                used_by_resources,
                resource_identifiers,
                default_value  # Use default value instead of empty string
            ]
            writer.writerow(row)
    
    return filename

def export_conditions_to_csv(conditions_data, filename=None, mark_column='mark_for_deletion'):
    """Export Conditions to CSV with standardized format"""
    if not filename:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = 'conditions_export_{}.csv'.format(timestamp)
    
    account_id = get_account_id()
    
    # Determine default value based on mark column
    default_value = 'DELETE' if mark_column == 'mark_for_deletion' else 'MIGRATE' if mark_column == 'mark_for_migration' else ''
    
    headers = [
        'condition_name', 'condition_id', 'condition_type', 'region', 'scope', 
        'account_id', 'used_by_rules', 'rule_identifiers', mark_column
    ]

    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:    
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        
        for condition in conditions_data:
            # Format usage info
            used_by_rules = 'None'
            rule_identifiers = 'None'
            
            if condition.get('usage'):
                usage_list = []
                id_list = []
                for usage in condition['usage']:
                    rule_name = usage.get('name', usage.get('id', ''))
                    rule_id = usage.get('id', '')
                    
                    usage_list.append("Rule: {}".format(rule_name))
                    id_list.append(rule_id)
                
                if usage_list:
                    used_by_rules = '; '.join(usage_list)
                    rule_identifiers = '; '.join(id_list)
            
            row = [
                condition.get('name', ''),
                condition.get('id', ''),
                condition.get('type', ''),
                condition.get('region', ''),
                'global' if condition.get('region') == 'cloudfront' else 'regional',
                account_id,
                used_by_rules,
                rule_identifiers,
                default_value
            ]
            writer.writerow(row)
    
    return filename
