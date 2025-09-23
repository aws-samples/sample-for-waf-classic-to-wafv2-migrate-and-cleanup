#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import sys
import os

# Add current directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

try:
    from waf_region_config import WAFRegionManager
    from waf_utils import (
        list_webacls_multi_region, 
        list_rulegroups_multi_region,
        list_rules_multi_region,
        list_conditions_multi_region
    )
except Exception as e:
    print(f"  Error importing modules: {e}")
    sys.exit(1)

def list_webacls_formatted(regions_str, output_format="display"):
    """List WebACLs in specified regions using common utilities"""
    if regions_str == "all-regions":
        all_webacls = list_webacls_multi_region(all_regions=True)
    else:
        regions = regions_str.split(',')
        all_webacls = list_webacls_multi_region(regions)
    
    try:
        count = 1
        webacl_map = {}
        
        for region, webacls in all_webacls.items():
            for webacl in webacls:
                if 'error' not in webacl:
                    if output_format == "display":
                        print(f"  {count}) {webacl['id']} - {webacl['name']} ({region}) - Rules: {webacl.get('rule_count', 0)}")
                    elif output_format == "map":
                        webacl_map[str(count)] = {
                            'id': webacl['id'],
                            'name': webacl['name'],
                            'region': region
                        }
                    count += 1
        
        if output_format == "map":
            return webacl_map
        elif count == 1:
            print("  No WebACLs found in the selected regions")
            
    except Exception as e:
        print(f"  Error listing WebACLs: {str(e)}")
        return {} if output_format == "map" else None

def list_rulegroups_formatted(regions_str, output_format="display"):
    """List RuleGroups in specified regions using common utilities"""
    if regions_str == "all-regions":
        all_rulegroups = list_rulegroups_multi_region(all_regions=True)
    else:
        regions = regions_str.split(',')
        all_rulegroups = list_rulegroups_multi_region(regions)
    
    try:
        count = 1
        rulegroup_map = {}
        
        for region, rulegroups in all_rulegroups.items():
            for rulegroup in rulegroups:
                if 'error' not in rulegroup:
                    if output_format == "display":
                        print(f"  {count}) {rulegroup['id']} - {rulegroup['name']} ({region}) - Rules: {rulegroup.get('rule_count', 0)}")
                    elif output_format == "map":
                        rulegroup_map[str(count)] = {
                            'id': rulegroup['id'],
                            'name': rulegroup['name'],
                            'region': region
                        }
                    count += 1
        
        if output_format == "map":
            return rulegroup_map
        elif count == 1:
            print("  No RuleGroups found in the selected regions")
            
    except Exception as e:
        print(f"  Error listing RuleGroups: {str(e)}")
        return {} if output_format == "map" else None

def list_rules_formatted(regions_str, output_format="display"):
    """List Rules in specified regions using common utilities"""
    if regions_str == "all-regions":
        all_rules = list_rules_multi_region(all_regions=True)
    else:
        regions = regions_str.split(',')
        all_rules = list_rules_multi_region(regions)
    
    try:
        count = 1
        rule_map = {}
        
        for region, rules in all_rules.items():
            for rule in rules:
                if 'error' not in rule:
                    if output_format == "display":
                        print(f"  {count}) {rule['id']} - {rule['name']} ({region})")
                    elif output_format == "map":
                        rule_map[str(count)] = {
                            'id': rule['id'],
                            'name': rule['name'],
                            'region': region
                        }
                    count += 1
        
        if output_format == "map":
            return rule_map
        elif count == 1:
            print("  No Rules found in the selected regions")
            
    except Exception as e:
        print(f"  Error listing Rules: {str(e)}")
        return {} if output_format == "map" else None

def list_conditions_formatted(regions_str, output_format="display"):
    """List Conditions in specified regions using common utilities"""
    if regions_str == "all-regions":
        all_conditions = list_conditions_multi_region(all_regions=True)
    else:
        regions = regions_str.split(',')
        all_conditions = list_conditions_multi_region(regions)
    
    try:
        count = 1
        condition_map = {}
        
        for region, conditions_by_type in all_conditions.items():
            for condition_type, conditions in conditions_by_type.items():
                for condition in conditions:
                    if 'error' not in condition:
                        if output_format == "display":
                            print(f"  {count}) {condition['id']} - {condition['name']} ({region}) - Type: {condition['type']}")
                        elif output_format == "map":
                            condition_map[str(count)] = {
                                'id': condition['id'],
                                'name': condition['name'],
                                'region': region,
                                'type': condition['type']
                            }
                        count += 1
        
        if output_format == "map":
            return condition_map
        elif count == 1:
            print("  No Conditions found in the selected regions")
            
    except Exception as e:
        print(f"  Error listing Conditions: {str(e)}")
        return {} if output_format == "map" else None

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 list_waf_resources.py <webacls|rulegroups|rules|conditions> <regions> [map]")
        sys.exit(1)
    
    resource_type = sys.argv[1]
    regions_str = sys.argv[2]
    output_format = sys.argv[3] if len(sys.argv) > 3 else "display"
    
    if resource_type == "webacls":
        result = list_webacls_formatted(regions_str, output_format)
        if output_format == "map" and result:
            for num, info in result.items():
                print(f"{num}:{info['id']}:{info['region']}")
    elif resource_type == "rulegroups":
        result = list_rulegroups_formatted(regions_str, output_format)
        if output_format == "map" and result:
            for num, info in result.items():
                print(f"{num}:{info['id']}:{info['region']}")
    elif resource_type == "rules":
        result = list_rules_formatted(regions_str, output_format)
        if output_format == "map" and result:
            for num, info in result.items():
                print(f"{num}:{info['id']}:{info['region']}")
    elif resource_type == "conditions":
        result = list_conditions_formatted(regions_str, output_format)
        if output_format == "map" and result:
            for num, info in result.items():
                print(f"{num}:{info['id']}:{info['region']}")
    else:
        print("Invalid resource type. Use 'webacls', 'rulegroups', 'rules', or 'conditions'")
        sys.exit(1)
