#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""
WAF Classic to WAF v2 Migration Tool
Converts AWS WAF Classic WebACLs to equivalent WAF v2 WebACLs
Supports WebACL and RuleGroup migration

This sample demonstrates how to migrate AWS WAF Classic resources to WAF v2.
"""

import warnings
warnings.filterwarnings("ignore")
import os
os.environ['PYTHONWARNINGS'] = 'ignore'

import boto3
import json
import argparse
from typing import List, Any
import sys
import os

# Add common directory to path for waf_region_config and utilities
common_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'common')
sys.path.insert(0, common_path)

from waf_region_config import WAFRegionManager, WAFRegionConfig
from csv_export_utils import (
    export_webacls_to_csv,
    export_rulegroups_to_csv
)
from botocore.exceptions import NoCredentialsError, ClientError

def check_aws_credentials():
    """Check if AWS credentials are configured and working"""
    try:
        sts = boto3.client('sts')
        sts.get_caller_identity()
        return True
    except (NoCredentialsError, ClientError):
        return False

def convert_bytes_to_string(obj):
    """Recursively convert bytes objects to strings in a data structure"""
    if isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    elif isinstance(obj, dict):
        return {key: convert_bytes_to_string(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_bytes_to_string(item) for item in obj]
    else:
        return obj

class DependencyGraph:
    """Manages dependencies and naming for WAF migration"""

    def __init__(self):
        self.ipsets = {}          # classic_id -> {name, v2_name, placeholder, actual_arn, created}
        self.regex_sets = {}      # classic_id -> {name, v2_name, placeholder, actual_arn, created}
        self.rule_groups = {}     # classic_id -> {name, v2_name, placeholder, actual_arn, rules_json, created}
        self.webacl_json = None   # Complete WebACL JSON with placeholders

    def add_ipset(self, classic_id, name):
        """Add IPSet to dependency graph if not already present"""
        if classic_id not in self.ipsets:
            self.ipsets[classic_id] = {
                'name': name,
                'v2_name': self.generate_v2_name('ipset', classic_id, name),
                'placeholder': self.generate_placeholder('ipset', classic_id),
                'actual_arn': None,
                'created': False
            }

    def add_regex_set(self, classic_id, name):
        """Add RegexPatternSet to dependency graph if not already present"""
        if classic_id not in self.regex_sets:
            self.regex_sets[classic_id] = {
                'name': name,
                'v2_name': self.generate_v2_name('regex', classic_id, name),
                'placeholder': self.generate_placeholder('regex', classic_id),
                'actual_arn': None,
                'created': False
            }

    def add_rule_group(self, classic_id, name):
        """Add RuleGroup to dependency graph if not already present"""
        if classic_id not in self.rule_groups:
            self.rule_groups[classic_id] = {
                'name': name,
                'v2_name': self.generate_v2_name('rulegroup', classic_id, name),
                'placeholder': self.generate_placeholder('rulegroup', classic_id),
                'actual_arn': None,
                'rules_json': None,
                'created': False
            }

    def mark_ipset_created(self, classic_id, created_ipsets):
        """Mark IPSet as created with proper ARN handling for IPv4/IPv6 split"""
        if classic_id in self.ipsets:
            self.ipsets[classic_id]['created_ipsets'] = created_ipsets
            self.ipsets[classic_id]['created'] = True
            # Store first ARN for backward compatibility
            if created_ipsets:
                self.ipsets[classic_id]['actual_arn'] = created_ipsets[0]['v2_arn']
    def mark_created(self, resource_type, classic_id, actual_arn):
        """Mark resource as created with actual ARN"""
        if resource_type == 'regex' and classic_id in self.regex_sets:
            self.regex_sets[classic_id]['actual_arn'] = actual_arn
            self.regex_sets[classic_id]['created'] = True
        elif resource_type == 'rulegroup' and classic_id in self.rule_groups:
            self.rule_groups[classic_id]['actual_arn'] = actual_arn
            self.rule_groups[classic_id]['created'] = True

    def get_pending_resources(self, resource_type):
        """Get resources that haven't been created yet"""
        if resource_type == 'ipset':
            return {k: v for k, v in self.ipsets.items() if not v['created']}
        elif resource_type == 'regex':
            return {k: v for k, v in self.regex_sets.items() if not v['created']}
        elif resource_type == 'rulegroup':
            return {k: v for k, v in self.rule_groups.items() if not v['created']}
        return {}

    def generate_v2_name(self, resource_type, classic_id, classic_name):
        """Generate deterministic v2 name: Migrated_{name}_{full-id}"""
        # Clean the original name (remove invalid characters)
        safe_name = self._make_safe_name(classic_name)

        # Use full ID instead of short ID
        return f"Migrated_{safe_name}_{classic_id}"

    def generate_placeholder(self, resource_type, classic_id):
        """Generate placeholder for ARN replacement"""
        return f"{{{{{resource_type}:{classic_id}}}}}"

    def _make_safe_name(self, name):
        """Make name safe for AWS resources"""
        import re
        # Replace invalid chars with underscores, limit length to leave room for prefix/suffix
        safe = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
        return safe[:50]  # Leave room for "Migrated_" prefix and short ID suffix

class PlaceholderManager:
    """Handles placeholder replacement in JSON templates"""

    def __init__(self, dependency_graph):
        self.graph = dependency_graph

    def replace_placeholders(self, json_obj):
        """Replace all placeholders with actual ARNs"""
        import json
        import re

        json_str = json.dumps(json_obj)

        # Track which placeholders were replaced
        replaced_placeholders = set()

        # Replace IPSet placeholders
        for classic_id, ipset_info in self.graph.ipsets.items():
            if ipset_info.get('created') and ipset_info.get('created_ipsets'):
                placeholder = self.graph.generate_placeholder('ipset', classic_id)
                created_ipsets = ipset_info['created_ipsets']

                # Handle IPv4/IPv6 split placeholders first (for mixed IPSets)
                if len(created_ipsets) > 1:
                    ipv4_placeholder = f"{placeholder}-ipv4"
                    ipv6_placeholder = f"{placeholder}-ipv6"

                    # Find IPv4 and IPv6 IPSets by checking the name suffix
                    ipv4_ipset = next((ipset for ipset in created_ipsets if ipset['v2_name'].endswith('_v4')), None)
                    ipv6_ipset = next((ipset for ipset in created_ipsets if ipset['v2_name'].endswith('_v6')), None)

                    if ipv4_placeholder in json_str and ipv4_ipset:
                        json_str = json_str.replace(ipv4_placeholder, ipv4_ipset['v2_arn'])
                        replaced_placeholders.add(ipv4_placeholder)

                    if ipv6_placeholder in json_str and ipv6_ipset:
                        json_str = json_str.replace(ipv6_placeholder, ipv6_ipset['v2_arn'])
                        replaced_placeholders.add(ipv6_placeholder)

                # Handle single IPSet placeholder (for IPv4-only, IPv6-only, or fallback for mixed)
                if placeholder in json_str:
                    if len(created_ipsets) == 1:
                        # Single IPSet - use its ARN directly
                        replacement = created_ipsets[0]['v2_arn']
                        json_str = json_str.replace(placeholder, replacement)
                        replaced_placeholders.add(placeholder)
                    else:
                        # Mixed IPSet using single placeholder - replace with OrStatement containing both IPSets
                        
                        # Find IPv4 and IPv6 IPSets
                        ipv4_ipset = next((ipset for ipset in created_ipsets if 'ipv4' in ipset['v2_name'].lower()), None)
                        ipv6_ipset = next((ipset for ipset in created_ipsets if 'ipv6' in ipset['v2_name'].lower()), None)
                        
                        if ipv4_ipset and ipv6_ipset:
                            # Create OrStatement JSON
                            or_statement_json = json.dumps({
                                'OrStatement': {
                                    'Statements': [
                                        {'IPSetReferenceStatement': {'ARN': ipv4_ipset['v2_arn']}},
                                        {'IPSetReferenceStatement': {'ARN': ipv6_ipset['v2_arn']}}
                                    ]
                                }
                            })
                            
                            # Replace ALL instances of the placeholder with the OrStatement JSON (without quotes)
                            json_str = json_str.replace(f'"{placeholder}"', or_statement_json)
                            # Also replace unquoted instances with just the first IPSet ARN as fallback
                            json_str = json_str.replace(placeholder, ipv4_ipset['v2_arn'])
                            replaced_placeholders.add(placeholder)
                        else:
                            # Fallback to using first IPSet
                            replacement = created_ipsets[0]['v2_arn']
                            json_str = json_str.replace(placeholder, replacement)
                            replaced_placeholders.add(placeholder)

        # Replace RegexPatternSet placeholders
        for classic_id, regex_info in self.graph.regex_sets.items():
            if regex_info.get('actual_arn'):
                placeholder = self.graph.generate_placeholder('regex', classic_id)
                if placeholder in json_str:
                    json_str = json_str.replace(placeholder, regex_info['actual_arn'])
                    replaced_placeholders.add(placeholder)

        # Replace RuleGroup placeholders
        for classic_id, rg_info in self.graph.rule_groups.items():
            if rg_info.get('actual_arn'):
                placeholder = self.graph.generate_placeholder('rulegroup', classic_id)
                if placeholder in json_str:
                    json_str = json_str.replace(placeholder, rg_info['actual_arn'])
                    replaced_placeholders.add(placeholder)

        # Remove rules/statements that still contain unreplaced placeholders
        result = json.loads(json_str)
        if isinstance(result, dict) and 'Rules' in result:
            # Filter out rules that still contain placeholders
            valid_rules = []
            for rule in result['Rules']:
                rule_str = json.dumps(rule)
                unresolved_placeholders = re.findall(r'\{\{[^}]+:[^}]+\}\}', rule_str)
                if not unresolved_placeholders:
                    valid_rules.append(rule)
            result['Rules'] = valid_rules

        return result

class WAFMigrator:
    def __init__(self, region='us-east-1'):
        self.region_config = WAFRegionManager.get_config(region)
        if not self.region_config:
            raise ValueError(f"Unsupported region: {region}. Supported regions: {', '.join(WAFRegionManager.list_supported_regions())}")

        self.waf_classic, self.wafv2 = self._create_clients()
        self.scope = self.region_config.v2_scope

        # Initialize dependency graph and placeholder manager
        self.dependency_graph = DependencyGraph()
        self.placeholder_manager = PlaceholderManager(self.dependency_graph)
        self._processed_rule_ids = set()  # Track processed rules to prevent duplicates
        
        # Track created resources for rollback
        self.created_resources = []
        
        # Cumulative migration tracking
        self.cumulative_webacl_migrations = []
        self.cumulative_rulegroup_migrations = []
        self._suppress_individual_reports = False

    def get_classic_logging_configuration(self, webacl_arn: str) -> dict:
        """Get WAF Classic logging configuration for a WebACL"""
        try:
            print(f"Getting Classic logging for ARN: {webacl_arn}")
            response = self.waf_classic.get_logging_configuration(ResourceArn=webacl_arn)
            logging_config = response.get('LoggingConfiguration', {})
            
            if logging_config:
                destinations = logging_config.get('LogDestinationConfigs', [])
                redacted_fields = logging_config.get('RedactedFields', [])
                print(f"Found Classic logging: {len(destinations)} destinations, {len(redacted_fields)} redacted fields")
                for i, dest in enumerate(destinations):
                    print(f"  Destination {i+1}: {dest}")
                for i, field in enumerate(redacted_fields):
                    print(f"  Redacted field {i+1}: {field}")
            else:
                print("No Classic logging configuration found")
                
            return logging_config
        except ClientError as e:
            if e.response['Error']['Code'] == 'WAFNonexistentItemException':
                print("No logging configuration exists for this WebACL")
                return {}  # No logging configuration
            print(f"Error getting logging config: {str(e)}")
            raise e

    def convert_classic_redacted_fields(self, classic_fields):
        """Convert Classic WAF redacted fields to WAFv2 format"""
        converted_fields = []
        
        for field in classic_fields:
            if isinstance(field, dict) and 'Type' in field:
                classic_type = field['Type']
                print(f"Converting Classic field: {classic_type}")
                
                # Map Classic WAF types to WAFv2 dictionary format
                if classic_type == 'QUERY_STRING':
                    converted_fields.append({'QueryString': {}})
                    print(f"  → Mapped to: QueryString")
                        
                elif classic_type == 'URI':
                    converted_fields.append({'UriPath': {}})
                    print(f"  → Mapped to: UriPath")
                        
                elif classic_type == 'METHOD':
                    converted_fields.append({'Method': {}})
                    print(f"  → Mapped to: Method")
                        
                elif classic_type == 'BODY':
                    converted_fields.append({'Body': {}})
                    print(f"  → Mapped to: Body")
                        
                elif classic_type == 'ALL_QUERY_ARGS':
                    converted_fields.append({'AllQueryArguments': {}})
                    print(f"  → Mapped to: AllQueryArguments")
                    
                elif classic_type == 'HEADER':
                    # Handle specific headers
                    header_name = field.get('Data', '')
                    if header_name:
                        converted_fields.append({'SingleHeader': {'Name': header_name}})
                        print(f"  → Mapped to: SingleHeader (Name: {header_name})")
                    else:
                        # If no specific header, use Headers (all headers)
                        converted_fields.append({'Headers': {}})
                        print(f"  → Mapped to: Headers (all headers)")
                        
                else:
                    print(f"  → No mapping found for {classic_type}, skipping")
            else:
                print(f"Unexpected field format: {field}, skipping")
        
        print(f"Converted {len(converted_fields)} fields: {converted_fields}")
        return converted_fields

    def setup_wafv2_logging(self, webacl_arn: str, classic_logging_config: dict) -> dict:
        """Set up WAFv2 logging configuration with Firehose destination"""
        if not classic_logging_config:
            return {'success': False, 'message': 'No Classic logging configuration found'}

        try:
            print(f"Setting up WAFv2 logging for ARN: {webacl_arn}")
            
            # Get Firehose destinations from Classic config
            log_destinations = classic_logging_config.get('LogDestinationConfigs', [])
            if not log_destinations:
                return {'success': False, 'message': 'No log destinations in Classic configuration'}

            print(f"Migrating {len(log_destinations)} destination(s) to WAFv2")

            # Create basic WAFv2 logging configuration
            wafv2_logging_config = {
                'ResourceArn': webacl_arn,
                'LogDestinationConfigs': log_destinations
            }

            # Convert and add redacted fields
            classic_redacted_fields = classic_logging_config.get('RedactedFields', [])
            if classic_redacted_fields:
                print(f"Converting {len(classic_redacted_fields)} redacted fields")
                converted_fields = self.convert_classic_redacted_fields(classic_redacted_fields)
                
                if converted_fields:
                    wafv2_logging_config['RedactedFields'] = converted_fields

            # Create the logging configuration
            print("Creating WAFv2 logging configuration...")
            self.wafv2.put_logging_configuration(LoggingConfiguration=wafv2_logging_config)
            print("WAFv2 logging configuration created successfully")
            
            return {
                'success': True, 
                'message': f'Logging migrated: {len(log_destinations)} destination(s), {len(converted_fields if classic_redacted_fields else [])} redacted fields',
                'destinations': log_destinations
            }

        except ClientError as e:
            error_msg = f'Failed to set up WAFv2 logging: {str(e)}'
            print(error_msg)
            return {
                'success': False, 
                'message': error_msg
            }

    def migrate_webacl_with_logging(self, webacl_id: str, migrate_logging: bool = False) -> dict:
        """Migrate WebACL with optional logging configuration"""
        print(f"Migrating WebACL {webacl_id} with logging={migrate_logging}")
        
        # First migrate the WebACL normally
        result = self.migrate_filtered_webacls([webacl_id])
        
        if not result.get('success'):
            print("WebACL migration failed - skipping logging migration")
            return result

        print("WebACL migration successful")

        # Migrate logging only if requested and WebACL migration was successful
        if migrate_logging:
            print("Starting logging migration...")
            try:
                # Get Classic WebACL ARN for logging lookup
                classic_webacl = self.waf_classic.get_web_acl(WebACLId=webacl_id)
                classic_arn = classic_webacl['WebACL']['WebACLArn']
                
                # Get Classic logging configuration
                classic_logging = self.get_classic_logging_configuration(classic_arn)
                
                if classic_logging:
                    # Get the migrated WebACL ARN
                    webacls = result.get('webacls', [])
                    v2_webacl_arn = None
                    
                    if webacls and len(webacls) > 0:
                        v2_webacl_arn = webacls[0].get('v2_arn')
                        print(f"DEBUG: Retrieved WebACL ARN: {v2_webacl_arn}")
                    
                    if v2_webacl_arn:
                        print(f"Migrating logging from Classic ARN: {classic_arn}")
                        print(f"To WAFv2 ARN: {v2_webacl_arn}")
                        
                        logging_result = self.setup_wafv2_logging(v2_webacl_arn, classic_logging)
                        
                        if logging_result['success']:
                            print(f"SUCCESS: {logging_result['message']}")
                            result['logging'] = logging_result
                        else:
                            print(f"WARNING: {logging_result['message']}")
                            result['logging'] = logging_result
                    else:
                        print("ERROR: No WebACL ARN found in migration result")
                        result['logging'] = {'success': False, 'message': 'No WebACL ARN found in migration result'}
                else:
                    print("INFO: No logging configuration found in Classic WebACL")
                    result['logging'] = {'success': False, 'message': 'No Classic logging configuration found'}
                        
            except Exception as e:
                error_msg = f"Failed to migrate logging configuration: {str(e)}"
                print(f"WARNING: {error_msg}")
                result['logging'] = {'success': False, 'message': error_msg}

        return result

    def _track_created_resource(self, resource_type: str, resource_id: str, resource_name: str):
        """Track created resources for potential rollback"""
        self.created_resources.append({
            'type': resource_type,
            'id': resource_id,
            'name': resource_name
        })

    def _rollback_created_resources(self):
        """Rollback all created resources in reverse order"""
        print("ROLLBACK: Rolling back created resources...")
        rollback_errors = []
        
        for resource in reversed(self.created_resources):
            try:
                if resource['type'] == 'WebACL':
                    self.wafv2.delete_web_acl(
                        Scope=self.scope,
                        Id=resource['id'],
                        LockToken=self._get_lock_token('WebACL', resource['id'])
                    )
                elif resource['type'] == 'RuleGroup':
                    self.wafv2.delete_rule_group(
                        Scope=self.scope,
                        Id=resource['id'],
                        LockToken=self._get_lock_token('RuleGroup', resource['id'])
                    )
                elif resource['type'] == 'IPSet':
                    self.wafv2.delete_ip_set(
                        Scope=self.scope,
                        Id=resource['id'],
                        LockToken=self._get_lock_token('IPSet', resource['id'])
                    )
                elif resource['type'] == 'RegexPatternSet':
                    self.wafv2.delete_regex_pattern_set(
                        Scope=self.scope,
                        Id=resource['id'],
                        LockToken=self._get_lock_token('RegexPatternSet', resource['id'])
                    )
                print(f"OK Rolled back {resource['type']}: {resource['name']}")
            except Exception as e:
                error_msg = f"Failed to rollback {resource['type']} {resource['name']}: {str(e)}"
                rollback_errors.append(error_msg)
                print(f"FAILED {error_msg}")
        
        self.created_resources.clear()
        return rollback_errors

    def _get_lock_token(self, resource_type: str, resource_id: str) -> str:
        """Get lock token for resource deletion"""
        try:
            if resource_type == 'WebACL':
                response = self.wafv2.get_web_acl(Scope=self.scope, Id=resource_id)
                return response['LockToken']
            elif resource_type == 'RuleGroup':
                response = self.wafv2.get_rule_group(Scope=self.scope, Id=resource_id)
                return response['LockToken']
            elif resource_type == 'IPSet':
                response = self.wafv2.get_ip_set(Scope=self.scope, Id=resource_id)
                return response['LockToken']
            elif resource_type == 'RegexPatternSet':
                response = self.wafv2.get_regex_pattern_set(Scope=self.scope, Id=resource_id)
                return response['LockToken']
        except Exception:
            return ""

    def _generate_migration_report(self, migrations: list, resource_type: str):
        """Generate table output and CSV export for migration results"""
        import csv
        from datetime import datetime
        
        if not migrations:
            return
        
        # Calculate success/fail counts
        successful_count = sum(1 for result in migrations if result.get('status') == 'SUCCESS')
        failed_count = sum(1 for result in migrations if result.get('status') == 'FAILED')
        total_count = len(migrations)
        
        # Generate table
        print("=" * 150)
        print(f"REPORT: MIGRATION REPORT - {resource_type.upper()}S (Total: {total_count}, Successful: {successful_count}, Failed: {failed_count})")
        print("=" * 150)
        
        # Process each migration
        for i, migration in enumerate(migrations, 1):
            classic_name = migration.get('classic_name', 'N/A')
            classic_id = migration.get('classic_id', 'N/A')
            # Handle region from migration data or use self.region_config
            if 'region' in migration:
                # For cumulative reports across regions
                region = migration['region']
                region_config = WAFRegionManager.get_config(region)
                region_display = f"{region_config.display_name} ({region_config.classic_endpoint})"
            else:
                # For single region reports
                region_display = f"{self.region_config.display_name} ({self.region_config.classic_endpoint})"
            
            status = migration.get('status', 'UNKNOWN')
            
            print(f"\n{i}. Classic {resource_type} Name: {classic_name}")
            print(f"   Classic {resource_type} ID:   {classic_id}")
            print(f"   Region:                      {region_display}")
            print(f"   Migration Status:            {status}")
            
            if status == 'SUCCESS':
                v2_name = migration.get('v2_name', 'N/A')
                v2_arn = migration.get('v2_arn', 'N/A')
                print(f"   v2 {resource_type} Name:      {v2_name}")
                print(f"   v2 {resource_type} ARN:       {v2_arn}")
            else:
                error_msg = migration.get('error', 'Migration failed - no specific error details available')
                print(f"   Error Message:               {error_msg}")
        
        print("\n" + "=" * 150)
        
        # CSV data generation
        csv_data = []
        csv_headers = [
            f"classic_{resource_type.lower()}_name",
            f"classic_{resource_type.lower()}_id",
            "region_name",
            "region_code", 
            "migration_status",
            f"v2_{resource_type.lower()}_name",
            f"v2_{resource_type.lower()}_arn",
            "error_message"
        ]
        csv_data.append(csv_headers)
        
        # Add CSV data rows
        for migration in migrations:
            status = migration.get('status', 'UNKNOWN')
            if status == 'SUCCESS':
                v2_arn_full = migration.get('v2_arn', 'N/A')
                error_msg = ''
            else:
                v2_arn_full = 'N/A'
                error_msg = migration.get('error', 'Migration failed - no specific error details available')
            
            # Handle region from migration data or use self.region_config
            if 'region' in migration:
                region = migration['region']
                region_config = WAFRegionManager.get_config(region)
                region_name = region_config.display_name
                region_code = region_config.classic_endpoint
            else:
                region_name = self.region_config.display_name
                region_code = self.region_config.classic_endpoint
            
            csv_data.append([
                migration.get('classic_name', 'N/A'),
                migration.get('classic_id', 'N/A'),
                region_name,
                region_code,
                status,
                migration.get('v2_name', 'N/A') if status == 'SUCCESS' else 'N/A',
                v2_arn_full,
                error_msg
            ])
        
        # Generate CSV file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_filename = f"waf_migration_{resource_type.lower()}s_cumulative_{timestamp}.csv"
        
        try:
            with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerows(csv_data)
            
            print(f"FILE: Migration report exported to CSV: {csv_filename}")
            
        except Exception as e:
            print(f"WARNING: Failed to export CSV: {str(e)}")
        
        print()

    def _create_clients(self):
        """Create appropriate WAF clients based on region configuration"""
        if self.region_config.classic_service == 'waf':
            # Global WAF for CloudFront
            classic_client = boto3.client('waf', region_name='us-east-1')
        else:
            # Regional WAF
            classic_client = boto3.client('waf-regional', region_name=self.region_config.classic_endpoint)

        v2_client = boto3.client('wafv2', region_name=self.region_config.v2_endpoint)
        return classic_client, v2_client

    def _create_safe_or_statement(self, statements: List[dict]) -> dict:
        """Create OrStatement only if we have multiple statements, otherwise return single statement or None"""
        # Filter out None/empty statements
        valid_statements = [stmt for stmt in statements if stmt is not None]
        
        if len(valid_statements) == 0:
            return None
        elif len(valid_statements) == 1:
            return valid_statements[0]
        else:
            return {'OrStatement': {'Statements': valid_statements}}

    def _map_action_type(self, classic_action: str) -> dict:
        """Map Classic WAF action type to WAF v2 action"""
        if classic_action == 'ALLOW':
            return {'Allow': {}}
        elif classic_action == 'BLOCK':
            return {'Block': {}}
        elif classic_action == 'COUNT':
            return {'Count': {}}
        else:
            # Default fallback for unknown action types
            return {'Block': {}}

    def _map_field_to_match(self, classic_field_to_match: dict) -> dict:
        """Map Classic FieldToMatch to v2 FieldToMatch with exact field details"""
        field_type = classic_field_to_match.get('Type')
        field_data = classic_field_to_match.get('Data')

        if field_type == 'URI':
            return {'UriPath': {}}
        elif field_type == 'QUERY_STRING':
            return {'QueryString': {}}
        elif field_type == 'HEADER':
            if field_data:
                return {'SingleHeader': {'Name': field_data}}
            else:
                return {'SingleHeader': {'Name': 'user-agent'}}  # Fallback
        elif field_type == 'METHOD':
            return {'Method': {}}
        elif field_type == 'BODY':
            return {'Body': {}}
        elif field_type == 'SINGLE_QUERY_ARG':
            if field_data:
                return {'SingleQueryArgument': {'Name': field_data}}
            else:
                return {'SingleQueryArgument': {'Name': 'param'}}  # Fallback
        elif field_type == 'ALL_QUERY_ARGS':
            return {'AllQueryArguments': {}}
        else:
            return {'Body': {}}  # Default fallback

    def _map_text_transformations(self, classic_transformations: List[str]) -> List[dict]:
        """Map Classic TextTransformations to v2"""
        transformation_mapping = {
            'NONE': 'NONE',
            'COMPRESS_WHITE_SPACE': 'COMPRESS_WHITE_SPACE',
            'HTML_ENTITY_DECODE': 'HTML_ENTITY_DECODE',
            'LOWERCASE': 'LOWERCASE',
            'CMD_LINE': 'CMD_LINE',
            'URL_DECODE': 'URL_DECODE'
        }

        v2_transformations = []
        for i, transform in enumerate(classic_transformations):
            v2_transformations.append({
                'Priority': i,
                'Type': transformation_mapping.get(transform, 'NONE')
            })

        return v2_transformations if v2_transformations else [{'Priority': 0, 'Type': 'NONE'}]

    def _generate_unique_rule_name(self, rule_name: str, rule_id: str) -> str:
        """Generate unique v2 rule name by blending Rule ID, staying within 128 char limit"""
        max_length = 128

        # Take last 8 characters of rule ID for uniqueness
        rule_id_suffix = rule_id[-8:] if len(rule_id) >= 8 else rule_id
        suffix = f"-{rule_id_suffix}"

        # If original name + suffix fits, use it
        if len(rule_name) + len(suffix) <= max_length:
            return rule_name + suffix

        # Otherwise, truncate name to fit suffix
        max_name_length = max_length - len(suffix)
        truncated_name = rule_name[:max_name_length]
        return truncated_name + suffix

    def _generate_safe_name(self, original_name: str, suffix: str) -> str:
        """Generate v2 name within 128 character limit"""
        max_length = 128
        if len(original_name) + len(suffix) <= max_length:
            return original_name + suffix

        # Truncate original name to fit suffix
        max_original_length = max_length - len(suffix)
        truncated_name = original_name[:max_original_length]
        return truncated_name + suffix

    def _generate_v2_name_for_analysis(self, resource_type, classic_id, classic_name):
        """Generate v2 name for analysis only - no side effects"""
        import re
        # Clean the original name (remove invalid characters)
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', classic_name)[:50]
        return f"Migrated_{safe_name}_{classic_id}"

    def print_migration_report(self, analysis: dict):
        """Print human-friendly migration report"""
        print("=" * 60)
        print(f"WebACL ANALYSIS: {analysis['webacl_name']}")
        print("=" * 60)
        print(f"Region: {self.region_config.display_name}")
        print(f"Scope: {self.region_config.v2_scope}")
        print(f"WebACL Name: {analysis['webacl_name']}")
        print(f"WebACL ID: {analysis['webacl_id']}")
        print(f"Default Action: {analysis['default_action']}")
        print(f"Total Rules: {len(analysis['rules'])}")
        print()

        # WAF v1 to v2 Mapping
        print("WAF V1 TO V2 MAPPING")
        print("-" * 40)
        v2_webacl_name = self._generate_v2_name_for_analysis('webacl', analysis['webacl_id'], analysis['webacl_name'])
        print(f"Classic WebACL: {analysis['webacl_name']} (ID: {analysis['webacl_id']})")
        print(f"WAF v2 WebACL: {v2_webacl_name}")
        
        # Check if WebACL already exists
        try:
            response = self.wafv2.list_web_acls(Scope=self.scope)
            existing_webacl = None
            for webacl in response.get('WebACLs', []):
                if webacl['Name'] == v2_webacl_name:
                    existing_webacl = webacl
                    break
            
            if existing_webacl:
                print(f"STATUS: WARNING:  ALREADY EXISTS - WebACL '{v2_webacl_name}' already exists in WAF v2")
                print(f"Existing ARN: {existing_webacl['ARN']}")
                print()
                print("WARNING:  SKIPPING DETAILED ANALYSIS - Resource already exists and will be reused during migration")
                return  # Skip the rest of the analysis
            else:
                print(f"STATUS: SUCCESS: NEW - WebACL will be created during migration")
        except Exception as e:
            print(f"STATUS: Unknown UNKNOWN - Could not check existing WebACLs: {str(e)}")
        
        print()

        # Prerequisites
        prereqs = analysis['prerequisites']
        if any(prereqs.values()):
            print("PREREQUISITES TO MIGRATE FIRST")
            print("-" * 40)
            if prereqs['ipsets']:
                print(f"IPSets: {len(prereqs['ipsets'])} items")
                for ipset_id in prereqs['ipsets'][:3]:  # Show first 3
                    print(f"   - {ipset_id}")
                if len(prereqs['ipsets']) > 3:
                    print(f"   ... and {len(prereqs['ipsets']) - 3} more")

            if prereqs['regex_pattern_sets']:
                print(f"RegexPatternSets: {len(prereqs['regex_pattern_sets'])} items")
                for regex_id in prereqs['regex_pattern_sets'][:3]:
                    print(f"   - {regex_id}")
                if len(prereqs['regex_pattern_sets']) > 3:
                    print(f"   ... and {len(prereqs['regex_pattern_sets']) - 3} more")

            if prereqs['rule_groups']:
                print(f"RuleGroups: {len(prereqs['rule_groups'])} items")
                for rg_id in prereqs['rule_groups']:
                    try:
                        # Get RuleGroup name for display
                        rg = self.waf_classic.get_rule_group(RuleGroupId=rg_id)['RuleGroup']
                        print(f"   - {rg['Name']} (ID: {rg_id})")
                    except:
                        print(f"   - {rg_id} (name unavailable)")
            print()

        # Rules analysis
        print("RULES ANALYSIS")
        print("-" * 40)
        for i, rule in enumerate(analysis['rules']):
            if 'error' in rule:
                print(f"FAILED: ERROR RULE {i+1}: {rule['name']} (Priority: {rule.get('priority', 0)})")
                print(f"   Error: {rule['error']}")
                print()
            else:
                action_label = "BLOCK" if rule['action'] == 'BLOCK' else "ALLOW"
                type_info = ""
                if rule['type'] == 'RATE_BASED':
                    type_info = f" [Rate: {rule['rate_limit']}/5min per {rule['rate_key']}]"
                elif rule['type'] == 'RuleGroup':
                    type_info = " [RuleGroup]"

                print(f"{action_label} RULE {i+1}: {rule['name']} -> {rule['name']} (Priority: {rule['priority']}){type_info}")

                # Show Classic rule info and predicates together
                if rule['type'] != 'RuleGroup':
                    print(f"   Classic Rule ID: {rule.get('rule_id', 'N/A')}")
                    if rule.get('predicates'):
                        print(f"   Classic Predicates:")
                        for pred in rule['predicates']:
                            negated = "[Negated]" if pred['negated'] else ""
                            pred_detail = self._get_classic_predicate_detail(pred)
                            print(f"    - {negated}{pred['type']} ({pred_detail})")
                else:
                    # RuleGroup - show excluded rules and internal rule info
                    print(f"   Classic Rule ID: {rule.get('rule_id', 'N/A')}")
                    print(f"   Internal Rules: {rule.get('inner_rules_count', 0)} rules")

                    # Show RuleGroup's own prerequisites
                    rg_prereqs = rule.get('rg_prerequisites', {})
                    if rg_prereqs.get('ipsets') or rg_prereqs.get('regex_pattern_sets'):
                        print(f"   RuleGroup Prerequisites:")
                        if rg_prereqs.get('ipsets'):
                            print(f"      IPSets: {len(rg_prereqs['ipsets'])} items")
                        if rg_prereqs.get('regex_pattern_sets'):
                            print(f"      RegexPatternSets: {len(rg_prereqs['regex_pattern_sets'])} items")

                    if rule.get('excluded_rules'):
                        print(f"   Excluded Rules:")
                        for excluded in rule['excluded_rules']:
                            print(f"    - {excluded['RuleId']}")
                    else:
                        print(f"   Excluded Rules: None")

                # Show v2 equivalent structure
                if rule['v2_equivalent']:
                    v2_rule = rule['v2_equivalent']
                    print(f"   v2 Rule Name: {v2_rule['Name']}")
                    print(f"   v2 Statement:")

                    # Show detailed statement structure
                    if v2_rule.get('Statement') is not None:
                        self._print_v2_statement_structure(v2_rule['Statement'], "        ")
                    else:
                        print("        Statement: None (GROUP rule)")
                        if v2_rule.get('OverrideAction'):
                            override_action = list(v2_rule['OverrideAction'].keys())[0]
                            print(f"        OverrideAction: {override_action}")
            print()
        
        print()



    def print_rulegroup_analysis_report(self, analysis: dict):
        """Print human-friendly rulegroup analysis report"""
        print("=" * 60)
        print(f"RULEGROUP ANALYSIS: {analysis['name']}")
        print("=" * 60)
        print(f"RuleGroup ID: {analysis['rulegroup_id']}")
        print(f"Internal Rules: {len(analysis['rules'])}")
        print()
        
        # WAF v1 to v2 Mapping
        print("WAF V1 TO V2 MAPPING")
        print("-" * 20)
        v2_rulegroup_name = self._generate_v2_name_for_analysis('rulegroup', analysis['rulegroup_id'], analysis['name'])
        print(f"Classic RuleGroup: {analysis['name']} (ID: {analysis['rulegroup_id']})")
        print(f"WAF v2 RuleGroup: {v2_rulegroup_name}")
        
        # Check if RuleGroup already exists
        try:
            response = self.wafv2.list_rule_groups(Scope=self.scope)
            existing_rulegroup = None
            for rg in response.get('RuleGroups', []):
                if rg['Name'] == v2_rulegroup_name:
                    existing_rulegroup = rg
                    break
            
            if existing_rulegroup:
                print(f"STATUS: WARNING:  ALREADY EXISTS - RuleGroup '{v2_rulegroup_name}' already exists in WAF v2")
                print(f"Existing ARN: {existing_rulegroup['ARN']}")
                print()
                print("WARNING:  SKIPPING DETAILED ANALYSIS - Resource already exists and will be reused during migration")
                return  # Skip the rest of the analysis
            else:
                print(f"STATUS: SUCCESS: NEW - RuleGroup will be created during migration")
        except Exception as e:
            print(f"STATUS: Unknown UNKNOWN - Could not check existing RuleGroups: {str(e)}")
        
        print()
        
        # Prerequisites
        print("\nPREREQUISITES")
        print("-" * 20)
        ipsets = analysis['prerequisites']['ipsets']
        regex_sets = analysis['prerequisites']['regex_pattern_sets']
        
        if ipsets:
            print(f"IPSets ({len(ipsets)}):")
            for ipset in ipsets:
                print(f"  - {ipset['name']} ({ipset['classic_id']})")
        
        if regex_sets:
            print(f"RegexPatternSets ({len(regex_sets)}):")
            for rps in regex_sets:
                print(f"  - {rps['name']} ({rps['classic_id']})")
        
        if not ipsets and not regex_sets:
            print("No prerequisites required")
        
        # Rules analysis
        print("\nINTERNAL RULES ANALYSIS")
        print("-" * 25)
        for i, rule in enumerate(analysis['rules']):
            print(f"Rule {i+1}: {rule['name']} (Priority: {rule['priority']})")
            print(f"  Type: {rule['type']} | Action: {rule['action']}")
            if rule['type'] == 'RATE_BASED':
                print(f"  Rate: {rule['rate_limit']}/5min per {rule['rate_key']}")
            print(f"  Predicates: {len(rule['predicates'])}")
            for j, pred in enumerate(rule['predicates']):
                print(f"    {j+1}. {pred['type']} ({'Negated' if pred['negated'] else 'Normal'})")
            print()
        
        if analysis['migration_notes']:
            print("MIGRATION NOTES")
            print("-" * 15)
            for note in analysis['migration_notes']:
                print(f"WARNING:  {note}")
        
        print("=" * 60)

    def _get_classic_predicate_detail(self, pred: dict) -> str:
        """Get detailed classic predicate information"""
        pred_type = pred['type']
        pred_id = pred['data_id']

        try:
            if pred_type == 'IPMatch':
                ip_set = self.waf_classic.get_ip_set(IPSetId=pred_id)['IPSet']
                return f"IPSet: {ip_set['Name']}"
            elif pred_type == 'GeoMatch':
                geo_set = self.waf_classic.get_geo_match_set(GeoMatchSetId=pred_id)['GeoMatchSet']
                return f"GeoMatchSet: {geo_set['Name']}"
            elif pred_type == 'ByteMatch':
                byte_set = self.waf_classic.get_byte_match_set(ByteMatchSetId=pred_id)['ByteMatchSet']
                return f"ByteMatchSet: {byte_set['Name']}"
            elif pred_type == 'SqlInjectionMatch':
                sqli_set = self.waf_classic.get_sql_injection_match_set(SqlInjectionMatchSetId=pred_id)['SqlInjectionMatchSet']
                return f"SqlInjectionMatchSet: {sqli_set['Name']}"
            elif pred_type == 'XssMatch':
                xss_set = self.waf_classic.get_xss_match_set(XssMatchSetId=pred_id)['XssMatchSet']
                return f"XssMatchSet: {xss_set['Name']}"
            elif pred_type == 'RegexMatch':
                regex_set = self.waf_classic.get_regex_match_set(RegexMatchSetId=pred_id)['RegexMatchSet']
                return f"RegexMatchSet: {regex_set['Name']}"
            elif pred_type == 'SizeConstraint':
                size_set = self.waf_classic.get_size_constraint_set(SizeConstraintSetId=pred_id)['SizeConstraintSet']
                return f"SizeConstraintSet: {size_set['Name']}"
            else:
                return f"ID: {pred_id}"
        except:
            return f"ID: {pred_id}"

    def _print_v2_statement_structure(self, statement: dict, indent: str):
        """Print detailed v2 statement structure with correct type names"""
        if statement is None:
            print(f"{indent}Statement: None (GROUP rule - see OverrideAction)")
            return

        if 'IPSetReferenceStatement' in statement:
            arn = statement['IPSetReferenceStatement']['ARN']
            ipset_name = arn.split('/')[-2] if '/' in arn else 'Unknown'
            print(f"{indent}IPSetReferenceStatement (IPSet: {ipset_name})")

        elif 'ByteMatchStatement' in statement:
            bs = statement['ByteMatchStatement']
            field = list(bs['FieldToMatch'].keys())[0]
            print(f"{indent}ByteMatchStatement (SearchString: '{bs['SearchString']}', Field: {field}, Constraint: {bs['PositionalConstraint']})")

        elif 'GeoMatchStatement' in statement:
            countries = statement['GeoMatchStatement']['CountryCodes']
            country_preview = ', '.join(countries[:5]) + ('...' if len(countries) > 5 else '')
            print(f"{indent}GeoMatchStatement (Countries: {country_preview})")

        elif 'SqliMatchStatement' in statement:
            field = list(statement['SqliMatchStatement']['FieldToMatch'].keys())[0]
            print(f"{indent}SqliMatchStatement (Field: {field})")

        elif 'XssMatchStatement' in statement:
            field = list(statement['XssMatchStatement']['FieldToMatch'].keys())[0]
            print(f"{indent}XssMatchStatement (Field: {field})")

        elif 'RegexPatternSetReferenceStatement' in statement:
            arn = statement['RegexPatternSetReferenceStatement']['ARN']
            regex_name = arn.split('/')[-2] if '/' in arn else 'Unknown'
            field = list(statement['RegexPatternSetReferenceStatement']['FieldToMatch'].keys())[0]
            print(f"{indent}RegexPatternSetReferenceStatement (RegexPatternSet: {regex_name}, Field: {field})")

        elif 'RateBasedStatement' in statement:
            rbs = statement['RateBasedStatement']
            print(f"{indent}RateBasedStatement (Limit: {rbs['Limit']}/5min per {rbs['AggregateKeyType']})")
            if 'ScopeDownStatement' in rbs:
                print(f"{indent}  ScopeDown:")
                self._print_v2_statement_structure(rbs['ScopeDownStatement'], indent + "    ")

        elif 'RuleGroupReferenceStatement' in statement:
            arn = statement['RuleGroupReferenceStatement']['ARN']
            rg_name = arn.split('/')[-2] if '/' in arn else 'Unknown'
            rg_statement = statement['RuleGroupReferenceStatement']

            if 'ExcludedRules' in rg_statement and rg_statement['ExcludedRules']:
                excluded_names = [rule['Name'] for rule in rg_statement['ExcludedRules']]
                excluded_preview = ', '.join(excluded_names[:3]) + ('...' if len(excluded_names) > 3 else '')
                print(f"{indent}RuleGroupReferenceStatement (RuleGroup: {rg_name}, ExcludedRules: {excluded_preview})")
            else:
                print(f"{indent}RuleGroupReferenceStatement (RuleGroup: {rg_name})")

        elif 'AndStatement' in statement:
            statements = statement['AndStatement']['Statements']
            print(f"{indent}AndStatement:")
            for stmt in statements:
                print(f"{indent}  -", end=" ")
                self._print_v2_statement_structure(stmt, "")

        elif 'OrStatement' in statement:
            statements = statement['OrStatement']['Statements']
            print(f"{indent}OrStatement:")
            for stmt in statements:
                print(f"{indent}  -", end=" ")
                self._print_v2_statement_structure(stmt, "")

        elif 'NotStatement' in statement:
            print(f"{indent}NotStatement:")
            print(f"{indent}  -", end=" ")
            self._print_v2_statement_structure(statement['NotStatement']['Statement'], "")

    def _get_statement_type(self, statement: dict) -> str:
        """Get the main statement type from v2 statement"""
        if 'IPSetReferenceStatement' in statement:
            return 'IPSetReference'
        elif 'ByteMatchStatement' in statement:
            return 'ByteMatch'
        elif 'SqliMatchStatement' in statement:
            return 'SqliMatch'
        elif 'XssMatchStatement' in statement:
            return 'XssMatch'
        elif 'GeoMatchStatement' in statement:
            return 'GeoMatch'
        elif 'RegexPatternSetReferenceStatement' in statement:
            return 'RegexPatternSetReference'
        elif 'RateBasedStatement' in statement:
            return 'RateBased'
        elif 'RuleGroupReferenceStatement' in statement:
            return 'RuleGroupReference'
        elif 'AndStatement' in statement:
            return 'And'
        elif 'OrStatement' in statement:
            return 'Or'
        elif 'NotStatement' in statement:
            return 'Not'
        else:
            return 'Unknown'

    def _print_statement_details(self, statement: dict, indent: str):
        """Print detailed statement structure"""
        if 'IPSetReferenceStatement' in statement:
            arn = statement['IPSetReferenceStatement']['ARN']
            ipset_name = arn.split('/')[-2] if '/' in arn else 'Unknown'
            print(f"{indent}-> References IPSet: {ipset_name}")

        elif 'ByteMatchStatement' in statement:
            bs = statement['ByteMatchStatement']
            field = list(bs['FieldToMatch'].keys())[0]
            print(f"{indent}-> Matches: '{bs['SearchString']}' in {field} ({bs['PositionalConstraint']})")

        elif 'GeoMatchStatement' in statement:
            countries = statement['GeoMatchStatement']['CountryCodes']
            print(f"{indent}-> Countries: {', '.join(countries[:5])}{'...' if len(countries) > 5 else ''}")

        elif 'RateBasedStatement' in statement:
            rbs = statement['RateBasedStatement']
            print(f"{indent}-> Rate Limit: {rbs['Limit']}/5min per {rbs['AggregateKeyType']}")
            if 'ScopeDownStatement' in rbs:
                print(f"{indent}   Scope Down: {self._get_statement_type(rbs['ScopeDownStatement'])}")

        elif 'RegexPatternSetReferenceStatement' in statement:
            arn = statement['RegexPatternSetReferenceStatement']['ARN']
            regex_name = arn.split('/')[-2] if '/' in arn else 'Unknown'
            field = list(statement['RegexPatternSetReferenceStatement']['FieldToMatch'].keys())[0]
            print(f"{indent}-> References RegexPatternSet: {regex_name} in {field}")

        elif 'RuleGroupReferenceStatement' in statement:
            arn = statement['RuleGroupReferenceStatement']['ARN']
            rg_name = arn.split('/')[-2] if '/' in arn else 'Unknown'
            print(f"{indent}-> References RuleGroup: {rg_name}")

        elif 'AndStatement' in statement:
            statements = statement['AndStatement']['Statements']
            print(f"{indent}-> AND of {len(statements)} conditions:")
            for i, stmt in enumerate(statements[:3]):  # Show first 3
                stmt_type = self._get_statement_type(stmt)
                if stmt_type == 'Not':
                    inner_type = self._get_statement_type(stmt['NotStatement']['Statement'])
                    print(f"{indent}   {i+1}. NotStatement wrapping {inner_type}")
                else:
                    print(f"{indent}   {i+1}. {stmt_type}")
            if len(statements) > 3:
                print(f"{indent}   ... and {len(statements) - 3} more")

        elif 'OrStatement' in statement:
            statements = statement['OrStatement']['Statements']
            print(f"{indent}-> OR of {len(statements)} conditions:")
            for i, stmt in enumerate(statements[:3]):  # Show first 3
                stmt_type = self._get_statement_type(stmt)
                if stmt_type == 'Not':
                    inner_type = self._get_statement_type(stmt['NotStatement']['Statement'])
                    print(f"{indent}   {i+1}. NotStatement wrapping {inner_type}")
                else:
                    print(f"{indent}   {i+1}. {stmt_type}")
            if len(statements) > 3:
                print(f"{indent}   ... and {len(statements) - 3} more")

        elif 'NotStatement' in statement:
            inner_stmt = statement['NotStatement']['Statement']
            inner_type = self._get_statement_type(inner_stmt)
            print(f"{indent}-> NotStatement wrapping {inner_type}")

        # Migration notes
        if analysis['migration_notes']:
            print("MIGRATION NOTES")
            print("-" * 40)
            for note in analysis['migration_notes']:
                print(f"WARNING: {note}")
            print()

        print("NEXT STEPS")
        print("-" * 40)
        print("1. Run 'migrate' command to create complete v2 WebACL with all dependencies")
        print("2. Associate v2 WebACL with your resources")
        print("3. Test and validate functionality")
        print("4. Decommission Classic WebACL")
        print("5. Decommission Classic WebACL")
        print("=" * 80)
    def _replace_arns_in_rules(self, rules: List[dict], migration_results: List[dict]) -> List[dict]:
        """Replace placeholder ARNs with actual ARNs from migration results"""
        # Build ARN mapping from migration results
        arn_mapping = {}


        for result in migration_results:
            # Skip failed migrations that don't have v2_name or v2_arn
            if 'error' in result or 'v2_name' not in result or 'v2_arn' not in result:
                continue

            if result.get('type') == 'IPSet':
                # Handle IPv4/IPv6 split IPSets
                for v2_ipset in result.get('v2_ipsets', []):
                    if 'v2_name' in v2_ipset and 'v2_arn' in v2_ipset:
                        placeholder_arn = f"arn:aws:wafv2:*:*:*/ipset/{v2_ipset['v2_name']}/*"
                        actual_arn = v2_ipset['v2_arn']
                        arn_mapping[placeholder_arn] = actual_arn
            elif result.get('type') == 'RegexPatternSet':
                placeholder_arn = f"arn:aws:wafv2:*:*:*/regexpatternset/{result['v2_name']}/*"
                actual_arn = result['v2_arn']
                arn_mapping[placeholder_arn] = actual_arn
            elif result.get('type') == 'RuleGroup':
                placeholder_arn = f"arn:aws:wafv2:*:*:*/rulegroup/{result['v2_name']}/*"
                actual_arn = result['v2_arn']
                arn_mapping[placeholder_arn] = actual_arn


        # Convert bytes to strings before JSON serialization
        rules_clean = convert_bytes_to_string(rules)
        
        # Replace ARNs in rules
        import json
        rules_json = json.dumps(rules_clean, indent=2)

        replacements_made = 0
        for placeholder_arn, actual_arn in arn_mapping.items():
            if placeholder_arn in rules_json:
                rules_json = rules_json.replace(placeholder_arn, actual_arn)
                replacements_made += 1
            else:
                pass

        return json.loads(rules_json)

    def migrate_prerequisites(self, webacl_id: str, dry_run: bool = True) -> dict:
        """Migrate all prerequisite resources needed for WebACL migration"""
        analysis = self.analyze_and_plan(webacl_id)
        prerequisites = analysis['prerequisites']

        results = {'prerequisites': prerequisites, 'migrations': []}

        if dry_run:
            results['dry_run'] = True
            return results

        # Step 1: Migrate IPSets and RegexPatternSets first
        successful_migrations = []  # Track only successful migrations for ARN replacement

        for ipset_id in prerequisites['ipsets']:
            try:
                result = self._migrate_ipset(ipset_id)
                results['migrations'].append(result)
                if 'error' not in result:  # Only track successful migrations
                    successful_migrations.append(result)
            except Exception as e:
                error_msg = str(e)
                if 'WAFDuplicateItemException' in error_msg:
                    # Try to find existing IPSet ARN for ARN replacement
                    # For now, skip and let ARN replacement handle missing mappings
                    results['migrations'].append({'type': 'IPSet', 'id': ipset_id, 'error': 'Already exists (skipped)'})
                else:
                    results['migrations'].append({'type': 'IPSet', 'id': ipset_id, 'error': error_msg})

        for regex_id in prerequisites['regex_pattern_sets']:
            try:
                result = self._migrate_regex_pattern_set(regex_id)
                results['migrations'].append(result)
                if 'error' not in result:  # Only track successful migrations
                    successful_migrations.append(result)
            except Exception as e:
                error_msg = str(e)
                if 'WAFDuplicateItemException' in error_msg:
                    results['migrations'].append({'type': 'RegexPatternSet', 'id': regex_id, 'error': 'Already exists (skipped)'})
                else:
                    results['migrations'].append({'type': 'RegexPatternSet', 'id': regex_id, 'error': error_msg})

        # Step 2: Migrate RuleGroups with ARN replacement
        for rg_id in prerequisites['rule_groups']:
            try:
                # Get RuleGroup analysis to build rules with placeholder ARNs
                rg = self.waf_classic.get_rule_group(RuleGroupId=rg_id)['RuleGroup']

                # Get activated rules using the correct API
                activated_rules_response = self.waf_classic.list_activated_rules_in_rule_group(RuleGroupId=rg_id)
                activated_rules = activated_rules_response.get('ActivatedRules', [])

                v2_rules = []
                migration_notes = []


                for activated_rule in activated_rules:
                    rule_id = activated_rule['RuleId']
                    rule_type = activated_rule.get('Type', 'REGULAR')


                    try:
                        if rule_type == 'REGULAR':
                            rule = self.waf_classic.get_rule(RuleId=rule_id)['Rule']
                            predicates_key = 'Predicates'
                        elif rule_type == 'RATE_BASED':
                            rule = self.waf_classic.get_rate_based_rule(RuleId=rule_id)['Rule']
                            predicates_key = 'MatchPredicates'
                        else:
                            migration_notes.append(f"Skipped unsupported rule type {rule_type} for rule {rule_id}")
                            continue

                        # Build rule analysis
                        rule_analysis = {
                            'rule_id': rule_id,
                            'name': rule['Name'],
                            'action': activated_rule['Action']['Type'],
                            'priority': activated_rule['Priority'],
                            'type': rule_type,
                            'predicates': []
                        }

                        if rule_type == 'RATE_BASED':
                            rule_analysis['rate_key'] = rule['RateKey']
                            rule_analysis['rate_limit'] = rule['RateLimit']

                        # Analyze predicates
                        for predicate in rule.get(predicates_key, []):
                            pred_analysis = self._analyze_predicate(predicate)
                            rule_analysis['predicates'].append(pred_analysis)

                        # Generate v2 rule with placeholder ARNs
                        v2_rule = self._generate_v2_rule(rule_analysis)
                        if v2_rule and v2_rule.get('Statement') is not None:
                            v2_rules.append(v2_rule)
                        else:
                            if v2_rule is None:
                                migration_notes.append(f"Failed to generate v2 rule for {rule_id}")
                            else:
                                migration_notes.append(f"Generated v2 rule for {rule_id} has None statement")

                    except Exception as e:
                        migration_notes.append(f"Skipped rule {rule_id}: {str(e)}")

                # Replace placeholder ARNs with actual ARNs from successful migrations only
                v2_rules = self._replace_arns_in_rules(v2_rules, successful_migrations)

                # Create v2 RuleGroup with actual ARNs
                v2_rule_group = {
                    'Name': self.dependency_graph.generate_v2_name('rulegroup', rg_id, rg['Name']),
                    'Scope': self.scope,
                    'Capacity': 1000,
                    'Rules': v2_rules,
                    'VisibilityConfig': {
                        'SampledRequestsEnabled': True,
                        'CloudWatchMetricsEnabled': True,
                        'MetricName': self.dependency_graph.generate_v2_name('rulegroup', rg_id, rg['Name'])
                    }
                }

                try:
                    response = self.wafv2.create_rule_group(**v2_rule_group)
                    results['migrations'].append({
                        'type': 'RuleGroup',
                        'classic_id': rg_id,
                        'classic_name': rg['Name'],
                        'v2_arn': response['Summary']['ARN'],
                        'v2_id': response['Summary']['Id'],
                        'v2_name': v2_rule_group['Name'],
                        'rules_migrated': len(v2_rules),
                        'migration_notes': migration_notes
                    })
                except Exception as create_error:
                    error_msg = str(create_error)
                    if 'WAFDuplicateItemException' in error_msg:
                        results['migrations'].append({
                            'type': 'RuleGroup',
                            'id': rg_id,
                            'error': 'Already exists (skipped)',
                            'migration_notes': migration_notes
                        })
                    else:
                        results['migrations'].append({
                            'type': 'RuleGroup',
                            'id': rg_id,
                            'error': error_msg,
                            'migration_notes': migration_notes
                        })

            except Exception as e:
                results['migrations'].append({'type': 'RuleGroup', 'id': rg_id, 'error': str(e)})

        return results

    def _migrate_ipset(self, ipset_id: str) -> dict:
        """Migrate Classic IPSet to v2 (split IPv4/IPv6 if needed)"""
        ipset = self.waf_classic.get_ip_set(IPSetId=ipset_id)['IPSet']

        # Separate IPv4 and IPv6 addresses
        ipv4_addresses = []
        ipv6_addresses = []

        for desc in ipset['IPSetDescriptors']:
            addr = desc['Value']
            if ':' in addr:  # IPv6
                ipv6_addresses.append(addr)
            else:  # IPv4
                ipv4_addresses.append(addr)

        results = []

        # Handle empty IPSet - create empty IPv4 IPSet by default
        if not ipv4_addresses and not ipv6_addresses:
            v2_ipset_empty = {
                'Name': f"{self.dependency_graph.generate_v2_name('ipset', ipset_id, ipset['Name'])}_v4",
                'Scope': self.scope,
                'IPAddressVersion': 'IPV4',
                'Addresses': []  # Empty addresses list
            }
            response = self.wafv2.create_ip_set(**v2_ipset_empty)
            results.append({
                'type': 'IPSet-IPv4-Empty',
                'classic_id': ipset_id,
                'v2_arn': response['Summary']['ARN'],
                'v2_id': response['Summary']['Id'],
                'v2_name': v2_ipset_empty['Name'],
                'address_count': 0
            })
        else:
            # Create IPv4 IPSet if needed
            if ipv4_addresses:
                v2_ipset_v4 = {
                    'Name': f"{self.dependency_graph.generate_v2_name('ipset', ipset_id, ipset['Name'])}_v4",
                    'Scope': self.scope,
                    'IPAddressVersion': 'IPV4',
                    'Addresses': ipv4_addresses
                }
                response = self.wafv2.create_ip_set(**v2_ipset_v4)
                results.append({
                    'type': 'IPSet-IPv4',
                    'classic_id': ipset_id,
                    'v2_arn': response['Summary']['ARN'],
                    'v2_id': response['Summary']['Id'],
                    'v2_name': v2_ipset_v4['Name'],
                    'address_count': len(ipv4_addresses)
                })

            # Create IPv6 IPSet if needed
            if ipv6_addresses:
                v2_ipset_v6 = {
                    'Name': f"{self.dependency_graph.generate_v2_name('ipset', ipset_id, ipset['Name'])}_v6",
                    'Scope': self.scope,
                    'IPAddressVersion': 'IPV6',
                    'Addresses': ipv6_addresses
                }
                response = self.wafv2.create_ip_set(**v2_ipset_v6)
                results.append({
                    'type': 'IPSet-IPv6',
                    'classic_id': ipset_id,
                    'v2_arn': response['Summary']['ARN'],
                    'v2_id': response['Summary']['Id'],
                    'v2_name': v2_ipset_v6['Name'],
                    'address_count': len(ipv6_addresses)
                })

        return {
            'type': 'IPSet',
            'classic_id': ipset_id,
            'classic_name': ipset['Name'],
            'v2_ipsets': results,
            'split_required': len(results) > 1,
            'empty_ipset': len(results) == 1 and results[0]['address_count'] == 0
        }
        """Migrate Classic IPSet to v2 (split IPv4/IPv6 if needed)"""
        ipset = self.waf_classic.get_ip_set(IPSetId=ipset_id)['IPSet']

        # Separate IPv4 and IPv6 addresses
        ipv4_addresses = []
        ipv6_addresses = []

        for desc in ipset['IPSetDescriptors']:
            addr = desc['Value']
            if ':' in addr:  # IPv6
                ipv6_addresses.append(addr)
            else:  # IPv4
                ipv4_addresses.append(addr)

        results = []

        # Handle empty IPSet - create empty IPv4 IPSet by default
        if not ipv4_addresses and not ipv6_addresses:
            v2_ipset_empty = {
                'Name': self._generate_safe_name(ipset['Name'], '-ipv4-migrated'),
                'Scope': self.scope,
                'IPAddressVersion': 'IPV4',
                'Addresses': []  # Empty addresses list
            }
            response = self.wafv2.create_ip_set(**v2_ipset_empty)
            results.append({
                'type': 'IPSet-IPv4-Empty',
                'classic_id': ipset_id,
                'v2_arn': response['Summary']['ARN'],
                'v2_id': response['Summary']['Id'],
                'v2_name': v2_ipset_empty['Name'],
                'address_count': 0
            })
        else:
            # Create IPv4 IPSet if needed
            if ipv4_addresses:
                v2_ipset_v4 = {
                    'Name': self._generate_safe_name(ipset['Name'], '-ipv4-migrated'),
                    'Scope': self.scope,
                    'IPAddressVersion': 'IPV4',
                    'Addresses': ipv4_addresses
                }
                response = self.wafv2.create_ip_set(**v2_ipset_v4)
                results.append({
                    'type': 'IPSet-IPv4',
                    'classic_id': ipset_id,
                    'v2_arn': response['Summary']['ARN'],
                    'v2_id': response['Summary']['Id'],
                    'v2_name': v2_ipset_v4['Name'],
                    'address_count': len(ipv4_addresses)
                })

            # Create IPv6 IPSet if needed
            if ipv6_addresses:
                v2_ipset_v6 = {
                    'Name': self._generate_safe_name(ipset['Name'], '-ipv6-migrated'),
                    'Scope': self.scope,
                    'IPAddressVersion': 'IPV6',
                    'Addresses': ipv6_addresses
                }
                response = self.wafv2.create_ip_set(**v2_ipset_v6)
                results.append({
                    'type': 'IPSet-IPv6',
                    'classic_id': ipset_id,
                    'v2_arn': response['Summary']['ARN'],
                    'v2_id': response['Summary']['Id'],
                    'v2_name': v2_ipset_v6['Name'],
                    'address_count': len(ipv6_addresses)
                })

        return {
            'type': 'IPSet',
            'classic_id': ipset_id,
            'classic_name': ipset['Name'],
            'v2_ipsets': results,
            'split_required': len(results) > 1,
            'empty_ipset': len(results) == 1 and results[0]['address_count'] == 0
        }

    def _migrate_regex_pattern_set(self, regex_id: str) -> dict:
        """Migrate Classic RegexPatternSet to v2"""
        regex_set = self.waf_classic.get_regex_pattern_set(RegexPatternSetId=regex_id)['RegexPatternSet']

        v2_regex_set = {
            'Name': self.dependency_graph.generate_v2_name('regex', regex_id, regex_set['Name']),
            'Scope': self.scope,
            'RegularExpressionList': [{'RegexString': pattern} for pattern in regex_set['RegexPatternStrings']]
        }

        try:
            response = self.wafv2.create_regex_pattern_set(**v2_regex_set)
            return {
                'type': 'RegexPatternSet',
                'classic_id': regex_id,
                'classic_name': regex_set['Name'],
                'v2_arn': response['Summary']['ARN'],
                'v2_id': response['Summary']['Id'],
                'v2_name': v2_regex_set['Name'],
                'pattern_count': len(regex_set['RegexPatternStrings'])
            }
        except Exception as e:
            return {
                'type': 'RegexPatternSet',
                'classic_id': regex_id,
                'error': str(e)
            }

    def _migrate_rule_group(self, rule_group_id: str) -> dict:
        """Migrate Classic RuleGroup to v2"""
        rule_group = self.waf_classic.get_rule_group(RuleGroupId=rule_group_id)['RuleGroup']

        # Get activated rules using the correct API
        try:
            activated_rules_response = self.waf_classic.list_activated_rules_in_rule_group(RuleGroupId=rule_group_id)
            activated_rules = activated_rules_response.get('ActivatedRules', [])
        except Exception as e:
            return {
                'type': 'RuleGroup',
                'classic_id': rule_group_id,
                'error': f'Failed to get activated rules: {str(e)}'
            }

        # Analyze rules within the RuleGroup (reuse existing logic)
        v2_rules = []
        migration_notes = []

        for activated_rule in activated_rules:
            rule_id = activated_rule['RuleId']
            rule_type = activated_rule.get('Type', 'REGULAR')

            try:
                if rule_type == 'REGULAR':
                    rule = self.waf_classic.get_rule(RuleId=rule_id)['Rule']
                    predicates_key = 'Predicates'
                elif rule_type == 'RATE_BASED':
                    rule = self.waf_classic.get_rate_based_rule(RuleId=rule_id)['Rule']
                    predicates_key = 'MatchPredicates'
                else:
                    migration_notes.append(f"Skipped unsupported rule type {rule_type} for rule {rule_id}")
                    continue

                # Build rule analysis (reuse existing structure)
                rule_analysis = {
                    'rule_id': rule_id,
                    'name': rule['Name'],
                    'action': activated_rule['Action']['Type'],
                    'priority': activated_rule['Priority'],
                    'type': rule_type,
                    'predicates': []
                }

                # Handle rate-based rule specific fields
                if rule_type == 'RATE_BASED':
                    rule_analysis['rate_key'] = rule['RateKey']
                    rule_analysis['rate_limit'] = rule['RateLimit']

                # Analyze predicates (reuse existing logic)
                for predicate in rule.get(predicates_key, []):
                    pred_analysis = self._analyze_predicate(predicate)
                    rule_analysis['predicates'].append(pred_analysis)

                # Generate v2 rule (reuse existing logic)
                v2_rule = self._generate_v2_rule(rule_analysis)
                if v2_rule:
                    v2_rules.append(v2_rule)

            except Exception as e:
                migration_notes.append(f"Skipped rule {rule_id}: {str(e)}")

        # Create v2 RuleGroup
        v2_rule_group = {
            'Name': self.dependency_graph.generate_v2_name('rulegroup', rule_group_id, rule_group['Name']),
            'Scope': self.scope,
            'Capacity': 1000,  # Default capacity, will be calculated by AWS
            'Rules': v2_rules,
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': self.dependency_graph.generate_v2_name('rulegroup', rule_group_id, rule_group['Name'])
            }
        }

        # Get prerequisite migration results to replace ARNs
        analysis = self.analyze_and_plan(rule_group_id)  # This won't work for RuleGroup ID
        # We need to get migration results from the calling context
        # For now, create without ARN replacement - this needs to be fixed in the calling method

        # Create actual v2 RuleGroup
        try:
            response = self.wafv2.create_rule_group(**v2_rule_group)
            return {
                'type': 'RuleGroup',
                'classic_id': rule_group_id,
                'classic_name': rule_group['Name'],
                'v2_arn': response['Summary']['ARN'],
                'v2_id': response['Summary']['Id'],
                'v2_name': v2_rule_group['Name'],
                'rules_migrated': len(v2_rules),
                'migration_notes': migration_notes
            }
        except Exception as e:
            return {
                'type': 'RuleGroup',
                'classic_id': rule_group_id,
                'error': str(e),
                'migration_notes': migration_notes
            }
        """Migrate Classic RuleGroup to v2"""
        rule_group = self.waf_classic.get_rule_group(RuleGroupId=rule_group_id)['RuleGroup']

        # Analyze rules within the RuleGroup (reuse existing logic)
        v2_rules = []
        migration_notes = []

        for activated_rule in rule_group.get('ActivatedRules', []):
            rule_id = activated_rule['RuleId']
            rule_type = activated_rule.get('Type', 'REGULAR')

            try:
                if rule_type == 'REGULAR':
                    rule = self.waf_classic.get_rule(RuleId=rule_id)['Rule']
                    predicates_key = 'Predicates'
                elif rule_type == 'RATE_BASED':
                    rule = self.waf_classic.get_rate_based_rule(RuleId=rule_id)['Rule']
                    predicates_key = 'MatchPredicates'
                else:
                    migration_notes.append(f"Skipped unsupported rule type {rule_type} for rule {rule_id}")
                    continue

                # Build rule analysis (reuse existing structure)
                rule_analysis = {
                    'rule_id': rule_id,
                    'name': rule['Name'],
                    'action': activated_rule['Action']['Type'],
                    'priority': activated_rule['Priority'],
                    'type': rule_type,
                    'predicates': []
                }

                # Handle rate-based rule specific fields
                if rule_type == 'RATE_BASED':
                    rule_analysis['rate_key'] = rule['RateKey']
                    rule_analysis['rate_limit'] = rule['RateLimit']

                # Analyze predicates (reuse existing logic)
                for predicate in rule.get(predicates_key, []):
                    pred_analysis = self._analyze_predicate(predicate)
                    rule_analysis['predicates'].append(pred_analysis)

                # Generate v2 rule (reuse existing logic)
                v2_rule = self._generate_v2_rule(rule_analysis)
                if v2_rule:
                    v2_rules.append(v2_rule)

            except Exception as e:
                migration_notes.append(f"Skipped rule {rule_id}: {str(e)}")

        # Create v2 RuleGroup
        v2_rule_group = {
            'Name': self._generate_safe_name(rule_group['Name'], '-migrated'),
            'Scope': self.scope,
            'Capacity': 1000,  # Default capacity, will be calculated by AWS
            'Rules': v2_rules,
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': self._generate_safe_name(rule_group['Name'], '-migrated')
            }
        }

        # Create actual v2 RuleGroup
        try:
            response = self.wafv2.create_rule_group(**v2_rule_group)
            return {
                'type': 'RuleGroup',
                'classic_id': rule_group_id,
                'classic_name': rule_group['Name'],
                'v2_arn': response['Summary']['ARN'],
                'v2_id': response['Summary']['Id'],
                'v2_name': v2_rule_group['Name'],
                'rules_migrated': len(v2_rules),
                'migration_notes': migration_notes
            }
        except Exception as e:
            return {
                'type': 'RuleGroup',
                'classic_id': rule_group_id,
                'error': str(e),
                'migration_notes': migration_notes
            }
        """Migrate Classic RegexPatternSet to v2"""
        regex_set = self.waf_classic.get_regex_pattern_set(RegexPatternSetId=regex_id)['RegexPatternSet']

        v2_regex_set = {
            'Name': self.dependency_graph.generate_v2_name('regex', regex_id, regex_set['Name']),
            'Scope': self.scope,
            'RegularExpressionList': [pattern['RegexPatternString'] for pattern in regex_set['RegexPatternStrings']]
        }

        response = self.wafv2.create_regex_pattern_set(**v2_regex_set)
        return {
            'type': 'RegexPatternSet',
            'classic_id': regex_id,
            'v2_arn': response['Summary']['ARN'],
            'v2_id': response['Summary']['Id']
        }

    def list_classic_webacls(self) -> List[dict]:
        """List all Classic WebACLs"""
        try:
            response = self.waf_classic.list_web_acls()
            webacls = []

            for webacl in response['WebACLs']:
                # Get detailed info
                detail = self.waf_classic.get_web_acl(WebACLId=webacl['WebACLId'])['WebACL']
                webacls.append({
                    'id': webacl['WebACLId'],
                    'name': webacl['Name'],
                    'rule_count': len(detail['Rules']),
                    'default_action': detail['DefaultAction']['Type']
                })

            return webacls
        except Exception as e:
            raise Exception(f"Failed to list WebACLs: {str(e)}")

    def scan_and_build_graph(self, webacl_id: str) -> dict:
        """Scan Classic WebACL and build dependency graph with v2 JSON templates"""
        try:
            # Get WebACL details
            webacl = self.waf_classic.get_web_acl(WebACLId=webacl_id)['WebACL']

            # Initialize analysis structure
            analysis = {
                'webacl_id': webacl_id,
                'webacl_name': webacl['Name'],
                'default_action': webacl['DefaultAction']['Type'],
                'rules': [],
                'capacity_validation': None,
                'migration_notes': []
            }

            # Scan all rules and build dependency graph
            v2_rules = []
            for rule_ref in webacl.get('Rules', []):
                rule_id = rule_ref['RuleId']
                rule_type = rule_ref.get('Type', 'REGULAR')

                try:
                    if rule_type == 'REGULAR':
                        rule = self.waf_classic.get_rule(RuleId=rule_id)['Rule']
                        v2_rule = self._scan_regular_rule(rule, rule_ref)
                        if v2_rule:
                            v2_rules.append(v2_rule)

                    elif rule_type == 'RATE_BASED':
                        rule = self.waf_classic.get_rate_based_rule(RuleId=rule_id)['Rule']
                        v2_rule = self._scan_rate_based_rule(rule, rule_ref)
                        if v2_rule:
                            v2_rules.append(v2_rule)

                    elif rule_type == 'GROUP':
                        rule_group = self.waf_classic.get_rule_group(RuleGroupId=rule_id)['RuleGroup']
                        v2_rule = self._scan_rule_group(rule_group, rule_ref)
                        if v2_rule:
                            v2_rules.append(v2_rule)

                    # Add rule to analysis for reporting
                    analysis['rules'].append({
                        'rule_id': rule_id,
                        'name': rule.get('Name', rule_group.get('Name', f'Rule-{rule_id}')),
                        'type': rule_type,
                        'priority': rule_ref.get('Priority', 0),
                        'action': rule_ref.get('Action', rule_ref.get('OverrideAction', {})).get('Type', 'UNKNOWN')
                    })

                except Exception as e:
                    analysis['migration_notes'].append(f"Failed to scan rule {rule_id}: {str(e)}")
                    analysis['rules'].append({
                        'rule_id': rule_id,
                        'name': f'FailedRule-{rule_id}',
                        'type': rule_type,
                        'error': str(e)
                    })

            # Build WebACL JSON template with placeholders
            self.dependency_graph.webacl_json = {
                'Name': self.dependency_graph.generate_v2_name('webacl', webacl_id, webacl['Name']),
                'Scope': self.scope,
                'DefaultAction': {'Allow': {}} if webacl['DefaultAction']['Type'] == 'ALLOW' else {'Block': {}},
                'Rules': v2_rules,
                'VisibilityConfig': {
                    'SampledRequestsEnabled': True,
                    'CloudWatchMetricsEnabled': True,
                    'MetricName': self.dependency_graph.generate_v2_name('webacl', webacl_id, webacl['Name'])
                }
            }

            # Add prerequisites summary for compatibility with print_migration_report
            analysis['prerequisites'] = {
                'ipsets': list(self.dependency_graph.ipsets.keys()),
                'regex_pattern_sets': list(self.dependency_graph.regex_sets.keys()),
                'rule_groups': list(self.dependency_graph.rule_groups.keys())
            }

            return analysis

        except Exception as e:
            raise Exception(f"Failed to scan WebACL {webacl_id}: {str(e)}")

    def _scan_regular_rule(self, rule: dict, rule_ref: dict) -> dict:
        """Scan regular rule and add dependencies to graph"""
        if 'Action' not in rule_ref:
            return None

        # Scan predicates and add to dependency graph
        v2_statements = []
        skipped_predicates = 0
        total_predicates = len(rule.get('Predicates', []))
        
        for predicate in rule.get('Predicates', []):
            statement = self._scan_predicate(predicate)
            if statement:
                v2_statements.append(statement)
            else:
                skipped_predicates += 1

        if not v2_statements:
            print(f"WARNING: Skipping rule '{rule['Name']}' (ID: {rule['RuleId']}) - all {total_predicates} predicates are empty/invalid")
            return None
        elif skipped_predicates > 0:
            print(f"WARNING: Rule '{rule['Name']}' (ID: {rule['RuleId']}) - skipped {skipped_predicates}/{total_predicates} empty predicates, using {len(v2_statements)} valid predicates")

        # Build v2 rule JSON
        v2_rule = {
            'Name': self.dependency_graph.generate_v2_name('rule', rule['RuleId'], rule['Name']),
            'Priority': rule_ref['Priority'],
            'Action': self._map_action_type(rule_ref['Action']['Type']),
            'Statement': v2_statements[0] if len(v2_statements) == 1 else {'AndStatement': {'Statements': v2_statements}},
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': self.dependency_graph.generate_v2_name('rule', rule['RuleId'], rule['Name'])
            }
        }

        return v2_rule

    def _scan_rate_based_rule(self, rule: dict, rule_ref: dict) -> dict:
        """Scan rate-based rule and add dependencies to graph"""
        if 'Action' not in rule_ref:
            return None

        # Scan predicates for scope-down statement
        v2_statements = []
        skipped_predicates = 0
        total_predicates = len(rule.get('MatchPredicates', []))
        
        for predicate in rule.get('MatchPredicates', []):
            statement = self._scan_predicate(predicate)
            if statement:
                v2_statements.append(statement)
            else:
                skipped_predicates += 1

        if skipped_predicates > 0 and v2_statements:
            print(f"WARNING: Rate-based rule '{rule['Name']}' (ID: {rule['RuleId']}) - skipped {skipped_predicates}/{total_predicates} empty predicates, using {len(v2_statements)} valid predicates")

        # Build rate-based statement
        rate_statement = {
            'Limit': rule['RateLimit'],
            'AggregateKeyType': rule['RateKey']
        }

        if v2_statements:
            rate_statement['ScopeDownStatement'] = v2_statements[0] if len(v2_statements) == 1 else {'AndStatement': {'Statements': v2_statements}}

        v2_rule = {
            'Name': self.dependency_graph.generate_v2_name('rule', rule['RuleId'], rule['Name']),
            'Priority': rule_ref['Priority'],
            'Action': self._map_action_type(rule_ref['Action']['Type']),
            'Statement': {'RateBasedStatement': rate_statement},
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': self.dependency_graph.generate_v2_name('rule', rule['RuleId'], rule['Name'])
            }
        }

        return v2_rule

    def _scan_rule_group(self, rule_group: dict, rule_ref: dict) -> dict:
        """Scan rule group and add to dependency graph"""
        if 'OverrideAction' not in rule_ref:
            return None

        rg_id = rule_group['RuleGroupId']

        # Add RuleGroup to dependency graph
        self.dependency_graph.add_rule_group(rg_id, rule_group['Name'])

        # Scan internal rules
        self._scan_rule_group_internals(rg_id)

        # Check if RuleGroup has valid rules - if not, skip the reference
        rg_info = self.dependency_graph.rule_groups[rg_id]
        if not rg_info.get('rules_json') or not rg_info['rules_json'].get('Rules'):
            print(f"WARNING: Skipping RuleGroup reference '{rule_group['Name']}' - RuleGroup has no valid rules")
            return None

        # Build v2 rule reference
        override_action_type = rule_ref['OverrideAction']['Type']
        v2_override_action = {'None': {}} if override_action_type == 'NONE' else {'Count': {}}

        v2_rule = {
            'Name': self.dependency_graph.generate_v2_name('rule', rg_id, f"{rule_group['Name']}-ref"),
            'Priority': rule_ref['Priority'],
            'OverrideAction': v2_override_action,
            'Statement': {
                'RuleGroupReferenceStatement': {
                    'ARN': self.dependency_graph.generate_placeholder('rulegroup', rg_id)
                }
            },
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': self.dependency_graph.generate_v2_name('rule', rg_id, f"{rule_group['Name']}-ref")
            }
        }

        return v2_rule

    def _scan_rule_group_internals(self, rg_id: str):
        """Scan RuleGroup internal rules and build JSON template"""
        rg_info = self.dependency_graph.rule_groups[rg_id]
        v2_rules = []
        
        try:
            activated_rules_response = self.waf_classic.list_activated_rules_in_rule_group(RuleGroupId=rg_id)
            activated_rules = activated_rules_response.get('ActivatedRules', [])

            for activated_rule in activated_rules:
                rule_id = activated_rule['RuleId']
                rule_type = activated_rule.get('Type', 'REGULAR')

                try:
                    if rule_type == 'REGULAR':
                        rule = self.waf_classic.get_rule(RuleId=rule_id)['Rule']
                        # Scan predicates for dependencies
                        for predicate in rule.get('Predicates', []):
                            self._scan_predicate(predicate)
                        # Process rule with RuleGroup priorities/actions
                        v2_rule = self._scan_regular_rule(rule, activated_rule)
                        if v2_rule:
                            v2_rules.append(v2_rule)
                    elif rule_type == 'RATE_BASED':
                        rule = self.waf_classic.get_rate_based_rule(RuleId=rule_id)['Rule']
                        # Scan predicates for dependencies
                        for predicate in rule.get('MatchPredicates', []):
                            self._scan_predicate(predicate)
                        # Process rule with RuleGroup priorities/actions
                        v2_rule = self._scan_rate_based_rule(rule, activated_rule)
                        if v2_rule:
                            v2_rules.append(v2_rule)
                except Exception as e:
                    print(f"WARNING: Failed to process RuleGroup rule {rule_id}: {e}")
                    continue

        except Exception as e:
            print(f"WARNING: Failed to scan RuleGroup {rg_id}: {e}")
        
        # Always set rules_json, even if empty or if scanning failed
        # This ensures the dependency graph has a consistent state
        rg_info['rules_json'] = {
            'Name': rg_info['v2_name'],
            'Scope': self.scope,
            'Capacity': 1000,
            'Rules': v2_rules,  # May be empty if scanning failed
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': rg_info['v2_name']
            }
        }
        
        if not v2_rules:
            print(f"WARNING: RuleGroup {rg_id} has no valid rules after scanning - rules_json will be empty")

    def _scan_predicate(self, predicate: dict) -> dict:
        """Scan predicate and add dependencies to graph"""
        pred_type = predicate['Type']
        pred_id = predicate['DataId']
        negated = predicate.get('Negated', False)

        statement = None

        if pred_type == 'IPMatch':
            # Add IPSet to dependency graph
            try:
                ipset = self.waf_classic.get_ip_set(IPSetId=pred_id)['IPSet']
                
                # Check if IPSet has actual IP addresses
                ip_descriptors = ipset.get('IPSetDescriptors', [])
                if not ip_descriptors or len(ip_descriptors) == 0:
                    return None  # Skip empty IPSets
                
                self.dependency_graph.add_ipset(pred_id, ipset['Name'])

                # Check if IPSet has both IPv4 and IPv6 addresses by scanning actual IPs
                has_ipv4 = False
                has_ipv6 = False

                for descriptor in ip_descriptors:
                    ip_value = descriptor['Value']
                    if ':' in ip_value:
                        has_ipv6 = True
                    else:
                        has_ipv4 = True

                if has_ipv4 and has_ipv6:
                    # Mixed IPv4/IPv6 - need OrStatement with both IPSets
                    ipset_info = self.dependency_graph.ipsets[pred_id]
                    ipv4_placeholder = f"{ipset_info['placeholder']}-ipv4"
                    ipv6_placeholder = f"{ipset_info['placeholder']}-ipv6"

                    statement = {
                        'OrStatement': {
                            'Statements': [
                                {'IPSetReferenceStatement': {'ARN': ipv4_placeholder}},
                                {'IPSetReferenceStatement': {'ARN': ipv6_placeholder}}
                            ]
                        }
                    }
                else:
                    # Single type (IPv4 only or IPv6 only) - use single IPSet reference
                    statement = {
                        'IPSetReferenceStatement': {
                            'ARN': self.dependency_graph.generate_placeholder('ipset', pred_id)
                        }
                    }
            except Exception:
                pass

        elif pred_type == 'RegexMatch':
            # Add RegexPatternSet to dependency graph
            try:
                regex_match_set = self.waf_classic.get_regex_match_set(RegexMatchSetId=pred_id)['RegexMatchSet']
                if regex_match_set.get('RegexMatchTuples'):
                    regex_pattern_set_id = regex_match_set['RegexMatchTuples'][0]['RegexPatternSetId']
                    regex_set = self.waf_classic.get_regex_pattern_set(RegexPatternSetId=regex_pattern_set_id)['RegexPatternSet']

                    self.dependency_graph.add_regex_set(regex_pattern_set_id, regex_set['Name'])

                    # Handle multiple RegexMatchTuples
                    tuples = regex_match_set['RegexMatchTuples']
                    if len(tuples) == 1:
                        tuple_data = tuples[0]
                        statement = {
                            'RegexPatternSetReferenceStatement': {
                                'ARN': self.dependency_graph.generate_placeholder('regex', regex_pattern_set_id),
                                'FieldToMatch': self._map_field_to_match(tuple_data['FieldToMatch']),
                                'TextTransformations': self._map_text_transformations([tuple_data['TextTransformation']])
                            }
                        }
                    else:
                        # Multiple tuples - create OrStatement
                        statements = []
                        for tuple_data in tuples:
                            statements.append({
                                'RegexPatternSetReferenceStatement': {
                                    'ARN': self.dependency_graph.generate_placeholder('regex', regex_pattern_set_id),
                                    'FieldToMatch': self._map_field_to_match(tuple_data['FieldToMatch']),
                                    'TextTransformations': self._map_text_transformations([tuple_data['TextTransformation']])
                                }
                            })
                        statement = self._create_safe_or_statement(statements)
            except Exception:
                pass

        elif pred_type == 'GeoMatch':
            # GeoMatch becomes inline GeoMatchStatement
            try:
                geo_set = self.waf_classic.get_geo_match_set(GeoMatchSetId=pred_id)['GeoMatchSet']
                countries = [constraint['Value'] for constraint in geo_set['GeoMatchConstraints']]
                statement = {
                    'GeoMatchStatement': {
                        'CountryCodes': countries
                    }
                }
            except Exception:
                pass

        elif pred_type == 'ByteMatch':
            # ByteMatch becomes inline ByteMatchStatement(s)
            try:
                byte_set = self.waf_classic.get_byte_match_set(ByteMatchSetId=pred_id)['ByteMatchSet']
                tuples = byte_set['ByteMatchTuples']
                if len(tuples) == 1:
                    tuple_data = tuples[0]
                    # Handle bytes in SearchString
                    search_string = tuple_data['TargetString']
                    if isinstance(search_string, bytes):
                        search_string = search_string.decode('utf-8', errors='replace')
                    statement = {
                        'ByteMatchStatement': {
                            'SearchString': search_string,
                            'FieldToMatch': self._map_field_to_match(tuple_data['FieldToMatch']),
                            'TextTransformations': self._map_text_transformations([tuple_data['TextTransformation']]),
                            'PositionalConstraint': tuple_data['PositionalConstraint']
                        }
                    }
                else:
                    # Multiple tuples - create OrStatement
                    statements = []
                    for tuple_data in tuples:
                        # Handle bytes in SearchString
                        search_string = tuple_data['TargetString']
                        if isinstance(search_string, bytes):
                            search_string = search_string.decode('utf-8', errors='replace')
                        statements.append({
                            'ByteMatchStatement': {
                                'SearchString': search_string,
                                'FieldToMatch': self._map_field_to_match(tuple_data['FieldToMatch']),
                                'TextTransformations': self._map_text_transformations([tuple_data['TextTransformation']]),
                                'PositionalConstraint': tuple_data['PositionalConstraint']
                            }
                        })
                    statement = self._create_safe_or_statement(statements)
            except Exception:
                pass

        elif pred_type == 'SqlInjectionMatch':
            # SqlInjectionMatch becomes inline SqliMatchStatement(s)
            try:
                sqli_set = self.waf_classic.get_sql_injection_match_set(SqlInjectionMatchSetId=pred_id)['SqlInjectionMatchSet']
                tuples = sqli_set['SqlInjectionMatchTuples']
                if len(tuples) == 1:
                    tuple_data = tuples[0]
                    statement = {
                        'SqliMatchStatement': {
                            'FieldToMatch': self._map_field_to_match(tuple_data['FieldToMatch']),
                            'TextTransformations': self._map_text_transformations([tuple_data['TextTransformation']])
                        }
                    }
                else:
                    # Multiple tuples - create OrStatement
                    statements = []
                    for tuple_data in tuples:
                        statements.append({
                            'SqliMatchStatement': {
                                'FieldToMatch': self._map_field_to_match(tuple_data['FieldToMatch']),
                                'TextTransformations': self._map_text_transformations([tuple_data['TextTransformation']])
                            }
                        })
                    statement = self._create_safe_or_statement(statements)
            except Exception:
                pass

        elif pred_type == 'XssMatch':
            # XssMatch becomes inline XssMatchStatement(s)
            try:
                xss_set = self.waf_classic.get_xss_match_set(XssMatchSetId=pred_id)['XssMatchSet']
                tuples = xss_set['XssMatchTuples']
                if len(tuples) == 1:
                    tuple_data = tuples[0]
                    statement = {
                        'XssMatchStatement': {
                            'FieldToMatch': self._map_field_to_match(tuple_data['FieldToMatch']),
                            'TextTransformations': self._map_text_transformations([tuple_data['TextTransformation']])
                        }
                    }
                else:
                    # Multiple tuples - create OrStatement
                    statements = []
                    for tuple_data in tuples:
                        statements.append({
                            'XssMatchStatement': {
                                'FieldToMatch': self._map_field_to_match(tuple_data['FieldToMatch']),
                                'TextTransformations': self._map_text_transformations([tuple_data['TextTransformation']])
                            }
                        })
                    statement = self._create_safe_or_statement(statements)
            except Exception:
                pass

        elif pred_type == 'SizeConstraint':
            # SizeConstraint becomes inline SizeConstraintStatement(s)
            try:
                size_set = self.waf_classic.get_size_constraint_set(SizeConstraintSetId=pred_id)['SizeConstraintSet']
                tuples = size_set['SizeConstraints']
                if len(tuples) == 1:
                    tuple_data = tuples[0]
                    statement = {
                        'SizeConstraintStatement': {
                            'FieldToMatch': self._map_field_to_match(tuple_data['FieldToMatch']),
                            'ComparisonOperator': tuple_data['ComparisonOperator'],
                            'Size': tuple_data['Size'],
                            'TextTransformations': self._map_text_transformations([tuple_data['TextTransformation']])
                        }
                    }
                else:
                    # Multiple tuples - create OrStatement
                    statements = []
                    for tuple_data in tuples:
                        statements.append({
                            'SizeConstraintStatement': {
                                'FieldToMatch': self._map_field_to_match(tuple_data['FieldToMatch']),
                                'ComparisonOperator': tuple_data['ComparisonOperator'],
                                'Size': tuple_data['Size'],
                                'TextTransformations': self._map_text_transformations([tuple_data['TextTransformation']])
                            }
                        })
                    statement = self._create_safe_or_statement(statements)
            except Exception:
                pass

        # Add other predicate types (GeoMatch, ByteMatch, etc.) as inline statements
        # For brevity, implementing key ones that need dependencies

        # Skip if statement is None (empty/invalid predicate)
        if statement is None:
            return None

        if statement and negated:
            statement = {'NotStatement': {'Statement': statement}}

        return statement

    def _create_with_retry(self, create_func, max_retries=5):
        """Create resource with exponential backoff retry for WAFUnavailableEntityException"""
        import time

        for attempt in range(max_retries):
            try:
                return create_func()
            except Exception as e:
                error_msg = str(e)
                if 'WAFUnavailableEntityException' in error_msg and attempt < max_retries - 1:
                    wait_time = 2 ** attempt  # Exponential backoff: 1, 2, 4, 8 seconds
                    print(f"WAITING: Resource not ready, retrying in {wait_time}s... (attempt {attempt + 1}/{max_retries})")
                    time.sleep(wait_time)
                    continue
                else:
                    raise e  # Re-raise if not WAFUnavailableEntityException or max retries reached

    def execute_streamlined_rulegroup_migration(self, rulegroup_id: str) -> dict:
        """Execute complete RuleGroup migration using dependency graph approach with atomic rollback"""
        try:
            # Clear any previous tracking
            self.created_resources.clear()
            
            # Step 1: Scan and build dependency graph for RuleGroup
            print("Step 1: Scanning RuleGroup and building dependency graph...")
            
            # Initialize dependency graph
            self.dependency_graph = DependencyGraph()
            self.placeholder_manager = PlaceholderManager(self.dependency_graph)
            
            # Get RuleGroup details
            rule_group = self.waf_classic.get_rule_group(RuleGroupId=rulegroup_id)['RuleGroup']
            
            # Add RuleGroup to dependency graph
            self.dependency_graph.add_rule_group(rulegroup_id, rule_group['Name'])
            
            # Scan RuleGroup internal rules to build dependency graph
            self._scan_rule_group_internals(rulegroup_id)

            # Check for existing individual rules that can be reused
            print("Step 1.5: Checking for existing individual rules to reuse...")
            existing_rules_found = []
            rules_to_create = []
            
            try:
                activated_rules_response = self.waf_classic.list_activated_rules_in_rule_group(RuleGroupId=rulegroup_id)
                activated_rules = activated_rules_response.get('ActivatedRules', [])
                
                for activated_rule in activated_rules:
                    rule_id = activated_rule['RuleId']
                    rule_type = activated_rule.get('Type', 'REGULAR')
                    
                    try:
                        if rule_type == 'REGULAR':
                            rule = self.waf_classic.get_rule(RuleId=rule_id)['Rule']
                        elif rule_type == 'RATE_BASED':
                            rule = self.waf_classic.get_rate_based_rule(RuleId=rule_id)['Rule']
                        else:
                            continue
                            
                        # Check if this individual rule already exists in WAF v2
                        existing_check = self.check_existing_individual_rule(rule_id, rule['Name'])
                        if existing_check['found']:
                            existing_rules_found.append({
                                'classic_rule_id': rule_id,
                                'classic_rule_name': rule['Name'],
                                'found_in_webacl': existing_check['webacl_name'],
                                'v2_rule_name': existing_check['rule_name'],
                                'activated_rule': activated_rule
                            })
                            print(f"OK Will reuse existing rule: {rule['Name']}")
                        else:
                            rules_to_create.append(activated_rule)
                            
                    except Exception as e:
                        rules_to_create.append(activated_rule)  # Default to creating if check fails
                        
            except Exception as e:
                # If we can't check, proceed with normal creation
                try:
                    activated_rules_response = self.waf_classic.list_activated_rules_in_rule_group(RuleGroupId=rulegroup_id)
                    rules_to_create = activated_rules_response.get('ActivatedRules', [])
                except:
                    rules_to_create = []
            
            if existing_rules_found:
                print(f"OK Found {len(existing_rules_found)} existing rules to reuse")
            if rules_to_create:
                print(f"OK Will create {len(rules_to_create)} new rules")

            # Debug: Show what was found
            for classic_id, info in self.dependency_graph.ipsets.items():
                print(f"  - {classic_id}: {info['name']}")
            for classic_id, info in self.dependency_graph.regex_sets.items():
                print(f"  - {classic_id}: {info['name']}")

            results = {
                'migrations': [],
                
                'success': False
            }

            try:
                # Step 2: Create IPSets and RegexPatternSets
                print("Step 2: Creating IPSets and RegexPatternSets...")

                # Create all IPSets
                pending_ipsets = self.dependency_graph.get_pending_resources('ipset')
                for classic_id, ipset_info in pending_ipsets.items():
                    # Check if IPSet already exists
                    existing_ipsets = self.check_existing_ipset(classic_id, ipset_info['name'])

                    if existing_ipsets:
                        # Log actual existing IPSet names
                        existing_names = [ipset["v2_name"] for ipset in existing_ipsets]
                        for name in existing_names:
                            print(f"OK Reusing existing IPSet: {name}")
                        result = {
                            'type': 'IPSet',
                            'classic_id': classic_id,
                            'classic_name': ipset_info['name'],
                            'v2_ipsets': existing_ipsets,
                            'v2_arn': existing_ipsets[0]['v2_arn'],
                            'reused': True
                        }
                        results['migrations'].append(result)
                        self.dependency_graph.mark_ipset_created(classic_id, existing_ipsets)
                    else:
                        # Create new IPSet
                        result = self._migrate_ipset(classic_id)
                        if 'error' in result:
                            raise Exception(f"Failed to create IPSet {ipset_info['name']}: {result['error']}")
                        
                        # Log actual created IPSet names
                        created_names = [ipset['v2_name'] for ipset in result['v2_ipsets']]
                        for name in created_names:
                            print(f"OK Created IPSet: {name}")
                        
                        results['migrations'].append(result)
                        self.dependency_graph.mark_ipset_created(classic_id, result['v2_ipsets'])
                        
                        # Track created IPSets for rollback
                        for ipset in result['v2_ipsets']:
                            self._track_created_resource('IPSet', ipset['v2_id'], ipset['v2_name'])

                # Create all RegexPatternSets
                pending_regex_sets = self.dependency_graph.get_pending_resources('regex')
                for classic_id, regex_info in pending_regex_sets.items():
                    # Check if RegexPatternSet already exists
                    existing_regex = self.check_existing_regex_pattern_set(classic_id, regex_info['name'])

                    if existing_regex:
                        print(f"OK Reusing existing RegexPatternSet: {regex_info['name']}")
                        result = {
                            'type': 'RegexPatternSet',
                            'classic_id': classic_id,
                            'classic_name': regex_info['name'],
                            'v2_arn': existing_regex['v2_arn'],
                            'v2_name': existing_regex['v2_name'],
                            'reused': True
                        }
                        results['migrations'].append(result)
                        self.dependency_graph.mark_created('regex', classic_id, existing_regex['v2_arn'])
                    else:
                        # Create new RegexPatternSet
                        result = self._migrate_regex_pattern_set(classic_id)
                        if 'error' in result:
                            raise Exception(f"Failed to create RegexPatternSet {regex_info['name']}: {result['error']}")
                        
                        print(f"OK Created RegexPatternSet: {result['v2_name']}")
                        results['migrations'].append(result)
                        self.dependency_graph.mark_created('regex', classic_id, result['v2_arn'])
                        
                        # Track created RegexPatternSet for rollback
                        self._track_created_resource('RegexPatternSet', result['v2_id'], result['v2_name'])

                # Wait for resources to propagate
                if pending_ipsets or pending_regex_sets:
                    print("WAITING: Waiting for IPSets and RegexPatternSets to propagate...")
                    import time
                    time.sleep(3)

                # Step 3: Create RuleGroup with mixed existing and new rules
                print("Step 3: Creating RuleGroup...")

                if rulegroup_id in self.dependency_graph.rule_groups:
                    rg_info = self.dependency_graph.rule_groups[rulegroup_id]
                    
                    # Check if we have rules JSON or existing rules to work with
                    if not rg_info.get('rules_json') and not existing_rules_found:
                        # No rules JSON and no existing rules - this RuleGroup cannot be migrated
                        print(f"WARNING:  RuleGroup {rg_info['name']} has no rules JSON and no existing rules to reuse")
                        return {
                            'success': False,
                            'error': f"RuleGroup '{rg_info['name']}' cannot be migrated: No rules JSON generated during scanning and no existing rules found to reuse. This may be due to unsupported rule types or scanning failures.",
                            'existing_rules_found': existing_rules_found,
                            'prerequisites': results['migrations']
                        }
                    
                    # Build custom rules list combining existing and new rules
                    combined_rules = []
                    
                    # Add existing rules as references (they exist in other WebACLs)
                    for existing_rule in existing_rules_found:
                        # Create a rule that references the existing rule's logic
                        # Since we can't directly reference rules from other WebACLs,
                        # we need to recreate the rule structure but with existing resources
                        activated_rule = existing_rule['activated_rule']
                        rule_id = activated_rule['RuleId']
                        rule_type = activated_rule.get('Type', 'REGULAR')
                        
                        try:
                            if rule_type == 'REGULAR':
                                rule = self.waf_classic.get_rule(RuleId=rule_id)['Rule']
                                v2_rule = self._scan_regular_rule(rule, activated_rule)
                            elif rule_type == 'RATE_BASED':
                                rule = self.waf_classic.get_rate_based_rule(RuleId=rule_id)['Rule']
                                v2_rule = self._scan_rate_based_rule(rule, activated_rule)
                            else:
                                continue
                                
                            if v2_rule:
                                combined_rules.append(v2_rule)
                        except Exception as e:
                            pass
                    
                    # Add new rules from the original RuleGroup JSON (only for rules that don't exist)
                    if rg_info.get('rules_json'):
                        original_rules = rg_info['rules_json'].get('Rules', [])
                        existing_rule_names = {er.get('v2_rule_name', '') for er in existing_rules_found}
                        
                        for rule in original_rules:
                            if rule['Name'] not in existing_rule_names:
                                combined_rules.append(rule)
                    else:
                        print(f"WARNING:  RuleGroup {rg_info['name']} has no rules JSON - relying on existing rules only")
                    
                    # Check if we have any rules to create the RuleGroup with
                    if not combined_rules:
                        print(f"WARNING:  RuleGroup {rg_info['name']} has no rules to migrate")
                        return {
                            'success': False,
                            'error': f"RuleGroup '{rg_info['name']}' has no rules to migrate after processing existing rules and rules JSON",
                            'existing_rules_found': existing_rules_found,
                            'prerequisites': results['migrations']
                        }
                    
                    # Create the RuleGroup JSON with combined rules
                    rg_json = {
                        'Name': rg_info['v2_name'],
                        'Scope': self.scope,
                        'Capacity': 1000,
                        'Rules': combined_rules,
                        'VisibilityConfig': {
                            'SampledRequestsEnabled': True,
                            'CloudWatchMetricsEnabled': True,
                            'MetricName': rg_info['v2_name']
                        }
                    }
                    
                    # Replace placeholders in the combined rules
                    rg_json = self.placeholder_manager.replace_placeholders(rg_json)

                    response = self._create_with_retry(lambda: self.wafv2.create_rule_group(**rg_json))
                    
                    # Track created RuleGroup for rollback
                    self._track_created_resource('RuleGroup', response['Summary']['Id'], rg_json['Name'])
                    
                    print(f"OK Created RuleGroup: {rg_json['Name']}")
                    
                    # Clear tracking since migration succeeded
                    self.created_resources.clear()
                    
                    return {
                        'success': True,
                        'v2_arn': response['Summary']['ARN'],
                        'v2_id': response['Summary']['Id'],
                        'v2_name': rg_json['Name'],
                        'rules_migrated': len(rg_json['Rules']),
                        'rules_reused': len(existing_rules_found),
                        'rules_created': len(rg_json['Rules']) - len(existing_rules_found),
                        
                        
                    }
                else:
                    return {
                        'success': False,
                        'error': f'RuleGroup {rulegroup_id} not found in dependency graph',
                        
                        
                    }

            except Exception as e:
                # Rollback all created resources
                error_msg = str(e)
                
                
                # Provide more specific error information
                if 'WAFDuplicateItemException' in error_msg:
                    # Check if this is actually about the RuleGroup or a prerequisite
                    if 'RuleGroup' in error_msg or 'rule group' in error_msg.lower():
                        if rulegroup_id in self.dependency_graph.rule_groups:
                            rg_info = self.dependency_graph.rule_groups[rulegroup_id]
                            rg_name = rg_info.get('name', 'Unknown')
                            enhanced_error = f"RuleGroup '{rg_name}' already exists in WAF v2. A RuleGroup with this name has already been migrated or created."
                        else:
                            enhanced_error = f"RuleGroup with ID '{rulegroup_id}' already exists in WAF v2. A RuleGroup with this name has already been migrated or created."
                    else:
                        # This is likely a prerequisite resource that already exists
                        enhanced_error = f"RuleGroup migration failed due to prerequisite resource conflict: {error_msg}"
                    
                    rollback_errors = self._rollback_created_resources()
                    
                    error_result = {
                        'success': False,
                        'error': enhanced_error,
                        'existing_rules_found': existing_rules_found,
                        'prerequisites': results['migrations'],
                        
                        
                    }
                    if rollback_errors:
                        error_result['rollback_errors'] = rollback_errors
                    else:
                        print("SUCCESS: Successfully rolled back all created resources")
                    
                    return error_result
                else:
                    rollback_errors = self._rollback_created_resources()
                    
                    error_result = {
                        'success': False,
                        'error': error_msg,
                        
                        
                    }
                    if rollback_errors:
                        error_result['rollback_errors'] = rollback_errors
                    else:
                        print("SUCCESS: Successfully rolled back all created resources")
                    
                    return error_result

        except Exception as e:
            return {'success': False, 'error': str(e), 'existing_rules_found': []}
        """Migrate Classic RuleGroup for FMS customers with proper ARN replacement"""
        try:
            # Get RuleGroup details
            rule_group = self.waf_classic.get_rule_group(RuleGroupId=rulegroup_id)['RuleGroup']
            
            print(f"Migrating RuleGroup: {rule_group['Name']} (ID: {rulegroup_id})")
            
            if dry_run:
                return {
                    'success': True,
                    'dry_run': True,
                    'rulegroup_name': rule_group['Name'],
                    'rulegroup_id': rulegroup_id
                }
            
            # Step 1: Scan dependencies and create prerequisites
            analysis = self.scan_rulegroup_dependencies(rulegroup_id)
            if 'error' in analysis:
                return {'success': False, 'error': analysis['error']}
            
            prereq_results = self.create_rulegroup_prerequisites(rulegroup_id)
            
            # Step 2: Build v2 rules with placeholder ARNs
            activated_rules_response = self.waf_classic.list_activated_rules_in_rule_group(RuleGroupId=rulegroup_id)
            activated_rules = activated_rules_response.get('ActivatedRules', [])
            
            v2_rules = []
            migration_notes = []
            
            for activated_rule in activated_rules:
                rule_id = activated_rule['RuleId']
                rule_type = activated_rule.get('Type', 'REGULAR')
                
                try:
                    if rule_type == 'REGULAR':
                        rule = self.waf_classic.get_rule(RuleId=rule_id)['Rule']
                        predicates_key = 'Predicates'
                    elif rule_type == 'RATE_BASED':
                        rule = self.waf_classic.get_rate_based_rule(RuleId=rule_id)['Rule']
                        predicates_key = 'MatchPredicates'
                    else:
                        migration_notes.append(f"Skipped unsupported rule type {rule_type} for rule {rule_id}")
                        continue
                    
                    # Build rule analysis
                    rule_analysis = {
                        'rule_id': rule_id,
                        'name': rule['Name'],
                        'action': activated_rule['Action']['Type'],
                        'priority': activated_rule['Priority'],
                        'type': rule_type,
                        'predicates': []
                    }
                    
                    if rule_type == 'RATE_BASED':
                        rule_analysis['rate_key'] = rule['RateKey']
                        rule_analysis['rate_limit'] = rule['RateLimit']
                    
                    # Analyze predicates
                    for predicate in rule.get(predicates_key, []):
                        pred_analysis = self._analyze_predicate(predicate)
                        rule_analysis['predicates'].append(pred_analysis)
                    
                    # Generate v2 rule with placeholder ARNs
                    v2_rule = self._generate_v2_rule(rule_analysis)
                    if v2_rule and v2_rule.get('Statement') is not None:
                        v2_rules.append(v2_rule)
                    else:
                        migration_notes.append(f"Failed to generate v2 rule for {rule_id}")
                        
                except Exception as e:
                    migration_notes.append(f"Skipped rule {rule_id}: {str(e)}")
            
            # Step 3: Replace placeholder ARNs with actual ARNs
            successful_prereqs = [r for r in prereq_results.get('ipsets', []) + prereq_results.get('regex_sets', []) if 'error' not in r]
            v2_rules = self._replace_arns_in_rules(v2_rules, successful_prereqs)
            
            # Step 4: Create v2 RuleGroup
            v2_rule_group = {
                'Name': self._generate_safe_name(rule_group['Name'], '-migrated'),
                'Scope': self.scope,
                'Capacity': 1000,
                'Rules': v2_rules,
                'VisibilityConfig': {
                    'SampledRequestsEnabled': True,
                    'CloudWatchMetricsEnabled': True,
                    'MetricName': self._generate_safe_name(rule_group['Name'], '-migrated')
                }
            }
            
            try:
                response = self.wafv2.create_rule_group(**v2_rule_group)
                return {
                    'success': True,
                    'v2_arn': response['Summary']['ARN'],
                    'v2_id': response['Summary']['Id'],
                    'v2_name': v2_rule_group['Name'],
                    'rules_migrated': len(v2_rules),
                    'migration_notes': migration_notes,
                    
                }
            except Exception as create_error:
                error_msg = str(create_error)
                if 'WAFDuplicateItemException' in error_msg:
                    return {
                        'success': False,
                        'error': 'RuleGroup already exists',
                        
                    }
                else:
                    return {
                        'success': False,
                        'error': error_msg,
                        
                    }
                
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def migrate_rulegroup(self, rulegroup_id: str, dry_run: bool = False) -> dict:
        """Migrate Classic RuleGroup with proper ARN replacement"""
        try:
            # Get RuleGroup details
            rule_group = self.waf_classic.get_rule_group(RuleGroupId=rulegroup_id)['RuleGroup']
            
            print(f"Migrating RuleGroup: {rule_group['Name']} (ID: {rulegroup_id})")
            
            if dry_run:
                return {
                    'success': True,
                    'dry_run': True,
                    'rulegroup_name': rule_group['Name'],
                    'rulegroup_id': rulegroup_id
                }
            
            # Use streamlined migration approach
            return self.execute_streamlined_rulegroup_migration(rulegroup_id)
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def scan_rulegroup_dependencies(self, rulegroup_id: str) -> dict:
        """Scan RuleGroup and identify dependencies"""
        try:
            rule_group = self.waf_classic.get_rule_group(RuleGroupId=rulegroup_id)['RuleGroup']
            activated_rules_response = self.waf_classic.list_activated_rules_in_rule_group(RuleGroupId=rulegroup_id)
            activated_rules = activated_rules_response.get('ActivatedRules', [])
            
            dependencies = {'ipsets': [], 'regex_pattern_sets': []}
            
            for activated_rule in activated_rules:
                rule_id = activated_rule['RuleId']
                rule_type = activated_rule.get('Type', 'REGULAR')
                
                try:
                    if rule_type == 'REGULAR':
                        rule = self.waf_classic.get_rule(RuleId=rule_id)['Rule']
                        predicates = rule.get('Predicates', [])
                    elif rule_type == 'RATE_BASED':
                        rule = self.waf_classic.get_rate_based_rule(RuleId=rule_id)['Rule']
                        predicates = rule.get('MatchPredicates', [])
                    else:
                        continue
                    
                    for predicate in predicates:
                        if predicate['Type'] == 'IPMatch':
                            dependencies['ipsets'].append(predicate['DataId'])
                        elif predicate['Type'] == 'RegexMatch':
                            # Get RegexPatternSet ID from RegexMatchSet
                            try:
                                regex_match_set = self.waf_classic.get_regex_match_set(RegexMatchSetId=predicate['DataId'])['RegexMatchSet']
                                if regex_match_set.get('RegexMatchTuples'):
                                    regex_pattern_set_id = regex_match_set['RegexMatchTuples'][0]['RegexPatternSetId']
                                    dependencies['regex_pattern_sets'].append(regex_pattern_set_id)
                            except Exception:
                                pass
                                
                except Exception:
                    continue
            
            # Remove duplicates
            dependencies['ipsets'] = list(set(dependencies['ipsets']))
            dependencies['regex_pattern_sets'] = list(set(dependencies['regex_pattern_sets']))
            
            return {
                'rulegroup_name': rule_group['Name'],
                'rulegroup_id': rulegroup_id,
                'activated_rules_count': len(activated_rules),
                'dependencies': dependencies
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def create_rulegroup_prerequisites(self, rulegroup_id: str) -> dict:
        """Create prerequisites for RuleGroup migration"""
        analysis = self.scan_rulegroup_dependencies(rulegroup_id)
        
        if 'error' in analysis:
            return {'error': analysis['error']}
        
        dependencies = analysis['dependencies']
        results = {'ipsets': [], 'regex_sets': []}
        
        # Create IPSets
        for ipset_id in dependencies['ipsets']:
            try:
                result = self._migrate_ipset(ipset_id)
                results['ipsets'].append(result)
            except Exception as e:
                results['ipsets'].append({'type': 'IPSet', 'id': ipset_id, 'error': str(e)})
        
        # Create RegexPatternSets
        for regex_id in dependencies['regex_pattern_sets']:
            try:
                result = self._migrate_regex_pattern_set(regex_id)
                results['regex_sets'].append(result)
            except Exception as e:
                results['regex_sets'].append({'type': 'RegexPatternSet', 'id': regex_id, 'error': str(e)})
        
        return results

    def execute_streamlined_migration(self, webacl_id: str) -> dict:
        """Execute complete migration using dependency graph approach with atomic rollback"""
        try:
            # Clear any previous tracking
            self.created_resources.clear()
            
            # Step 1: Scan and build dependency graph
            print("Step 1: Scanning WebACL and building dependency graph...")
            analysis = self.scan_and_build_graph(webacl_id)

            # Debug: Show what was found
            for classic_id, info in self.dependency_graph.ipsets.items():
                print(f"  - {classic_id}: {info['name']}")
            for classic_id, info in self.dependency_graph.regex_sets.items():
                print(f"  - {classic_id}: {info['name']}")
            for classic_id, info in self.dependency_graph.rule_groups.items():
                print(f"  - {classic_id}: {info['name']}")

            results = {
                'analysis': analysis,
                'migrations': [],
                'success': False
            }

            try:
                # Step 2: Create IPSets and RegexPatternSets (including those in RuleGroups)
                print("Step 2: Creating IPSets and RegexPatternSets...")

                # Create all IPSets (from WebACL and RuleGroups)
                pending_ipsets = self.dependency_graph.get_pending_resources('ipset')
                for classic_id, ipset_info in pending_ipsets.items():
                    # Check if IPSet already exists
                    existing_ipsets = self.check_existing_ipset(classic_id, ipset_info['name'])

                    if existing_ipsets:
                        # Log actual existing IPSet names
                        existing_names = [ipset["v2_name"] for ipset in existing_ipsets]
                        for name in existing_names:
                            print(f"OK Reusing existing IPSet: {name}")
                        result = {
                            'type': 'IPSet',
                            'classic_id': classic_id,
                            'classic_name': ipset_info['name'],
                            'v2_ipsets': existing_ipsets,
                            'v2_arn': existing_ipsets[0]['v2_arn'],
                            'reused': True
                        }
                        results['migrations'].append(result)
                        self.dependency_graph.mark_ipset_created(classic_id, existing_ipsets)
                    else:
                        result = self._create_ipset_from_graph(classic_id, ipset_info)
                        if 'error' in result:
                            raise Exception(f"Failed to create IPSet {ipset_info['name']}: {result['error']}")
                        
                        results['migrations'].append(result)
                        self.dependency_graph.mark_ipset_created(classic_id, result['v2_ipsets'])
                        
                        # Track created IPSets for rollback
                        for ipset in result['v2_ipsets']:
                            self._track_created_resource('IPSet', ipset['v2_id'], ipset['v2_name'])
                        
                        # Log actual created IPSet names
                        created_names = [ipset['v2_name'] for ipset in result['v2_ipsets']]
                        for name in created_names:
                            print(f"OK Created IPSet: {name}")

                # Create all RegexPatternSets (from WebACL and RuleGroups)
                pending_regex_sets = self.dependency_graph.get_pending_resources('regex')
                for classic_id, regex_info in pending_regex_sets.items():
                    # Check if RegexPatternSet already exists
                    existing_regex = self.check_existing_regex_set(classic_id, regex_info['name'])

                    if existing_regex:
                        print(f"OK Reusing existing RegexPatternSet: {regex_info['name']}")
                        result = {
                            'type': 'RegexPatternSet',
                            'classic_id': classic_id,
                            'classic_name': regex_info['name'],
                            'v2_arn': existing_regex['v2_arn'],
                            'v2_id': existing_regex['v2_id'],
                            'v2_name': existing_regex['v2_name'],
                            'reused': True
                        }
                        results['migrations'].append(result)
                        self.dependency_graph.mark_created('regex', classic_id, existing_regex['v2_arn'])
                    else:
                        result = self._create_regex_set_from_graph(classic_id, regex_info)
                        if 'error' in result:
                            raise Exception(f"Failed to create RegexPatternSet {regex_info['name']}: {result['error']}")
                        
                        results['migrations'].append(result)
                        self.dependency_graph.mark_created('regex', classic_id, result['v2_arn'])
                        
                        # Track created RegexPatternSet for rollback
                        self._track_created_resource('RegexPatternSet', result['v2_id'], result['v2_name'])
                        
                        print(f"OK Created RegexPatternSet: {result['v2_name']}")

                # Wait for IPSets and RegexPatternSets to propagate
                if pending_ipsets or pending_regex_sets:
                    print("WAITING: Waiting for IPSets and RegexPatternSets to propagate...")
                    import time
                    time.sleep(3)

                # Step 3: Create RuleGroups with placeholder replacement
                print("Step 3: Creating RuleGroups...")

                pending_rule_groups = self.dependency_graph.get_pending_resources('rulegroup')
                for classic_id, rg_info in pending_rule_groups.items():
                    # Check if RuleGroup already exists
                    existing_rg = self.check_existing_rule_group(classic_id, rg_info['name'])

                    if existing_rg:
                        print(f"OK Reusing existing RuleGroup: {existing_rg['v2_name']}")
                        result = {
                            'type': 'RuleGroup',
                            'classic_id': classic_id,
                            'classic_name': rg_info['name'],
                            'v2_arn': existing_rg['v2_arn'],
                            'v2_id': existing_rg['v2_id'],
                            'v2_name': existing_rg['v2_name'],
                            'reused': True
                        }
                        results['migrations'].append(result)
                        self.dependency_graph.mark_created('rulegroup', classic_id, existing_rg['v2_arn'])
                    elif rg_info.get('rules_json') and rg_info['rules_json'].get('Rules'):
                        # Replace placeholders in RuleGroup JSON
                        rg_json = self.placeholder_manager.replace_placeholders(rg_info['rules_json'])

                        response = self._create_with_retry(lambda: self.wafv2.create_rule_group(**rg_json))
                        self.dependency_graph.mark_created('rulegroup', classic_id, response['Summary']['ARN'])

                        result = {
                            'type': 'RuleGroup',
                            'classic_id': classic_id,
                            'classic_name': rg_info['name'],
                            'v2_arn': response['Summary']['ARN'],
                            'v2_id': response['Summary']['Id'],
                            'v2_name': rg_info['v2_name'],
                            'rules_migrated': len(rg_json['Rules'])
                        }
                        results['migrations'].append(result)
                        
                        # Track created RuleGroup for rollback
                        self._track_created_resource('RuleGroup', response['Summary']['Id'], rg_info['v2_name'])
                        
                        print(f"OK Created RuleGroup: {rg_info['v2_name']}")
                    else:
                        # RuleGroup has no rules JSON or empty rules - record as failed migration
                        reason = "No rules JSON generated" if not rg_info.get('rules_json') else "No valid rules found"
                        print(f"FAILED Skipped RuleGroup: {rg_info['name']} - {reason}")
                        
                        result = {
                            'type': 'RuleGroup',
                            'classic_id': classic_id,
                            'classic_name': rg_info['name'],
                            'error': f"RuleGroup migration failed: {reason}. This may be due to unsupported rule types or scanning failures.",
                            'skipped': True
                        }
                        results['migrations'].append(result)

                # Wait for RuleGroups to propagate
                if pending_rule_groups:
                    print("WAITING: Waiting for RuleGroups to propagate...")
                    import time
                    time.sleep(3)

                # Step 4: Validate capacity with actual ARNs before creating WebACL
                print("Step 4: Validating WebACL capacity...")

                webacl_json = self.placeholder_manager.replace_placeholders(self.dependency_graph.webacl_json)

                # Validate capacity with actual ARNs
                capacity_response = self.wafv2.check_capacity(Scope=self.scope, Rules=webacl_json['Rules'])
                capacity_units = capacity_response['Capacity']
                
                # Define capacity limits
                hard_limit = 5000  # Hard limit - migration fails if exceeded
                cost_threshold = 1500  # Cost threshold - warn but continue
                
                # Check against hard limit first
                if capacity_units > hard_limit:
                    error_msg = f"WebACL capacity exceeds hard limit: {capacity_units}/{hard_limit} WCUs ({capacity_units/hard_limit*100:.1f}%)"
                    print(f"FAILED: {error_msg}")
                    print("Migration cannot proceed as it would exceed WAF v2 capacity limits.")
                    
                    # Rollback all created resources
                    rollback_errors = self._rollback_created_resources()
                    
                    error_result = {
                        'error': f'Migration failed: {error_msg}',
                        'success': False,
                        'capacity_units': capacity_units,
                        'hard_limit': hard_limit
                    }
                    if rollback_errors:
                        error_result['rollback_errors'] = rollback_errors
                    else:
                        print("SUCCESS: Successfully rolled back all created resources")
                    
                    return error_result
                
                # Check against cost threshold (warn but continue)
                elif capacity_units > cost_threshold:
                    print(f"WARNING: High capacity usage ({capacity_units}/{cost_threshold} = {capacity_units/cost_threshold*100:.1f}%)")
                    print(f"Total WCUs exceed {cost_threshold} and are subject to additional costs.")
                    print("Continuing with migration...")
                # Step 5: Create WebACL with validated configuration
                print("Step 5: Creating WebACL...")

                response = self._create_with_retry(lambda: self.wafv2.create_web_acl(**webacl_json))

                # Track created WebACL for rollback
                self._track_created_resource('WebACL', response['Summary']['Id'], webacl_json['Name'])

                results['webacl'] = {
                    'success': True,
                    'webacl_arn': response['Summary']['ARN'],
                    'webacl_id': response['Summary']['Id'],
                    'webacl_name': webacl_json['Name'],
                    'rules_migrated': len(webacl_json['Rules']),
                    'capacity_units': capacity_units,
                    'capacity_percentage': f"{capacity_units/hard_limit*100:.1f}%",
                    'cost_threshold_percentage': f"{capacity_units/cost_threshold*100:.1f}%"
                }
                results['success'] = True
                
                # Clear tracking since migration succeeded
                self.created_resources.clear()
                
                print(f"SUCCESS: Migration completed successfully!")
                print(f"   WebACL ARN: {response['Summary']['ARN']}")
                print(f"   Capacity: {capacity_units}/{hard_limit} units ({capacity_units/hard_limit*100:.1f}%)")

            except Exception as e:
                # Rollback all created resources
                error_msg = str(e)
                
                # Provide more specific error information
                if 'WAFDuplicateItemException' in error_msg:
                    webacl_name = webacl_json.get('Name', 'Unknown')
                    enhanced_error = f"WebACL '{webacl_name}' already exists in WAF v2. A WebACL with this name has already been migrated or created."
                    print(f"FAILED: Migration failed: {enhanced_error}")
                    rollback_errors = self._rollback_created_resources()
                    
                    error_result = {'error': f'Migration failed: {enhanced_error}', 'success': False}
                    if rollback_errors:
                        error_result['rollback_errors'] = rollback_errors
                    else:
                        print("SUCCESS: Successfully rolled back all created resources")
                    
                    return error_result
                else:
                    print(f"FAILED: Migration failed: {error_msg}")
                    rollback_errors = self._rollback_created_resources()
                    
                    error_result = {'error': f'Migration failed: {error_msg}', 'success': False}
                    if rollback_errors:
                        error_result['rollback_errors'] = rollback_errors
                    else:
                        print("SUCCESS: Successfully rolled back all created resources")
                    
                    return error_result

            return results

        except Exception as e:
            return {'error': f'Migration failed: {str(e)}', 'success': False}

    def check_existing_ipset(self, classic_id, classic_name):
        """Check if IPSet already exists"""
        expected_name = self.dependency_graph.generate_v2_name('ipset', classic_id, classic_name)
        
        # Also check for old naming patterns for backward compatibility
        old_ipv4_name = f"{classic_name}-ipv4-migrated"
        old_ipv6_name = f"{classic_name}-ipv6-migrated"
        old_single_name = f"{classic_name}-migrated"

        try:
            response = self.wafv2.list_ip_sets(Scope=self.scope)
            existing_ipsets = []

            for ipset in response['IPSets']:
                # Check for new standardized naming pattern
                if ipset['Name'] == expected_name or ipset['Name'].startswith(f"{expected_name}_v"):
                    existing_ipsets.append({
                        'v2_name': ipset['Name'],
                        'v2_arn': ipset['ARN'],
                        'v2_id': ipset['Id'],
                        'address_count': 0  # We don't need count for reuse
                    })
                # Check for old naming patterns for backward compatibility
                elif ipset['Name'] in [old_ipv4_name, old_ipv6_name, old_single_name]:
                    existing_ipsets.append({
                        'v2_name': ipset['Name'],
                        'v2_arn': ipset['ARN'],
                        'v2_id': ipset['Id'],
                        'address_count': 0  # We don't need count for reuse
                    })

            if existing_ipsets:
                print(f"OK Found existing IPSet(s) for {classic_name}: {[ipset['v2_name'] for ipset in existing_ipsets]}")
                return existing_ipsets
        except Exception as e:
            pass

        return None

    def check_existing_regex_set(self, classic_id, classic_name):
        """Check if RegexPatternSet already exists"""
        expected_name = self.dependency_graph.generate_v2_name('regex', classic_id, classic_name)

        try:
            response = self.wafv2.list_regex_pattern_sets(Scope=self.scope)

            for regex_set in response['RegexPatternSets']:
                if regex_set['Name'] == expected_name:
                    return {
                        'v2_name': regex_set['Name'],
                        'v2_arn': regex_set['ARN'],
                        'v2_id': regex_set['Id']
                    }
        except Exception as e:
            pass

        return None

    def check_existing_regex_pattern_set(self, classic_id, classic_name):
        """Check if RegexPatternSet already exists"""
        expected_name = self.dependency_graph.generate_v2_name('regex', classic_id, classic_name)
        
        # Also check for old naming patterns for backward compatibility
        old_name = f"{classic_name}-migrated"

        try:
            response = self.wafv2.list_regex_pattern_sets(Scope=self.scope)

            for regex_set in response['RegexPatternSets']:
                # Check for new standardized naming pattern
                if regex_set['Name'] == expected_name:
                    print(f"OK Found existing RegexPatternSet for {classic_name}: {regex_set['Name']}")
                    return {
                        'v2_name': regex_set['Name'],
                        'v2_arn': regex_set['ARN'],
                        'v2_id': regex_set['Id']
                    }
                # Check for old naming pattern for backward compatibility
                elif regex_set['Name'] == old_name:
                    print(f"OK Found existing RegexPatternSet for {classic_name}: {regex_set['Name']}")
                    return {
                        'v2_name': regex_set['Name'],
                        'v2_arn': regex_set['ARN'],
                        'v2_id': regex_set['Id']
                    }
        except Exception as e:
            pass

        return None

    def check_existing_rule_group(self, classic_id, classic_name):
        """Check if RuleGroup already exists"""
        expected_name = self.dependency_graph.generate_v2_name('rulegroup', classic_id, classic_name)

        try:
            response = self.wafv2.list_rule_groups(Scope=self.scope)

            for rule_group in response['RuleGroups']:
                if rule_group['Name'] == expected_name:
                    return {
                        'v2_name': rule_group['Name'],
                        'v2_arn': rule_group['ARN'],
                        'v2_id': rule_group['Id']
                    }
        except Exception as e:
            pass

        return None

    def check_existing_individual_rule(self, classic_rule_id, classic_rule_name):
        """Check if an individual rule already exists in any WebACL in WAF v2"""
        expected_name = self.dependency_graph.generate_v2_name('rule', classic_rule_id, classic_rule_name)
        
        try:
            # List all WebACLs to check for existing rules
            response = self.wafv2.list_web_acls(Scope=self.scope)
            
            for webacl_summary in response['WebACLs']:
                try:
                    webacl = self.wafv2.get_web_acl(
                        Scope=self.scope,
                        Id=webacl_summary['Id']
                    )
                    
                    # Check if any rule in this WebACL matches our expected name
                    for rule in webacl['WebACL'].get('Rules', []):
                        if rule['Name'] == expected_name:
                            return {
                                'found': True,
                                'webacl_name': webacl_summary['Name'],
                                'webacl_id': webacl_summary['Id'],
                                'rule_name': rule['Name']
                            }
                except Exception:
                    continue  # Skip WebACLs we can't access
                    
        except Exception as e:
            pass
        
        return {'found': False}

    def _create_ipset_from_graph(self, classic_id: str, ipset_info: dict) -> dict:
        """Create IPSet using dependency graph info"""
        try:
            ipset = self.waf_classic.get_ip_set(IPSetId=classic_id)['IPSet']

            # Split IPv4 and IPv6 addresses
            ipv4_addresses = [addr for addr in ipset['IPSetDescriptors'] if ':' not in addr['Value']]
            ipv6_addresses = [addr for addr in ipset['IPSetDescriptors'] if ':' in addr['Value']]

            created_ipsets = []

            # Create IPv4 IPSet if needed
            if ipv4_addresses:
                ipv4_name = f"{ipset_info['v2_name']}_v4"
                ipv4_response = self.wafv2.create_ip_set(
                    Name=ipv4_name,
                    Scope=self.scope,
                    IPAddressVersion='IPV4',
                    Addresses=[desc['Value'] for desc in ipv4_addresses]
                )
                created_ipsets.append({
                    'v2_name': ipv4_name,
                    'v2_arn': ipv4_response['Summary']['ARN'],
                    'v2_id': ipv4_response['Summary']['Id'],
                    'address_count': len(ipv4_addresses)
                })

            # Create IPv6 IPSet if needed
            if ipv6_addresses:
                ipv6_name = f"{ipset_info['v2_name']}_v6"
                ipv6_response = self.wafv2.create_ip_set(
                    Name=ipv6_name,
                    Scope=self.scope,
                    IPAddressVersion='IPV6',
                    Addresses=[desc['Value'] for desc in ipv6_addresses]
                )
                created_ipsets.append({
                    'v2_name': ipv6_name,
                    'v2_arn': ipv6_response['Summary']['ARN'],
                    'v2_id': ipv6_response['Summary']['Id'],
                    'address_count': len(ipv6_addresses)
                })

            return {
                'type': 'IPSet',
                'classic_id': classic_id,
                'classic_name': ipset['Name'],
                'v2_ipsets': created_ipsets,
                'v2_arn': created_ipsets[0]['v2_arn'] if created_ipsets else None  # Use first for placeholder replacement
            }

        except Exception as e:
            return {'type': 'IPSet', 'classic_id': classic_id, 'error': str(e)}

    def _create_regex_set_from_graph(self, classic_id: str, regex_info: dict) -> dict:
        """Create RegexPatternSet using dependency graph info"""
        try:
            regex_set = self.waf_classic.get_regex_pattern_set(RegexPatternSetId=classic_id)['RegexPatternSet']

            # Handle RegexPatternStrings structure - it's a list of dicts with RegexString key
            regex_patterns = []
            for pattern in regex_set.get('RegexPatternStrings', []):
                if isinstance(pattern, dict) and 'RegexString' in pattern:
                    regex_patterns.append({'RegexString': pattern['RegexString']})
                elif isinstance(pattern, str):
                    regex_patterns.append({'RegexString': pattern})

            response = self.wafv2.create_regex_pattern_set(
                Name=regex_info['v2_name'],
                Scope=self.scope,
                RegularExpressionList=regex_patterns
            )

            return {
                'type': 'RegexPatternSet',
                'classic_id': classic_id,
                'classic_name': regex_set['Name'],
                'v2_arn': response['Summary']['ARN'],
                'v2_id': response['Summary']['Id'],
                'v2_name': regex_info['v2_name'],
                'pattern_count': len(regex_patterns)
            }

        except Exception as e:
            return {'type': 'RegexPatternSet', 'classic_id': classic_id, 'error': str(e)}

    def analyze_and_plan(self, webacl_id: str) -> dict:
        """Analyze Classic WebACL and create migration plan with capacity validation"""
        try:
            # Get WebACL details
            webacl = self.waf_classic.get_web_acl(WebACLId=webacl_id)['WebACL']

            analysis = {
                'webacl_name': webacl['Name'],
                'webacl_id': webacl_id,
                'default_action': webacl['DefaultAction']['Type'],
                'rules': [],
                'migration_notes': [],
                'prerequisites': {'ipsets': [], 'regex_pattern_sets': [], 'rule_groups': []},
                'capacity_validation': None
            }

            # Analyze each rule
            for rule_ref in webacl['Rules']:
                rule_id = rule_ref['RuleId']
                rule_type = rule_ref['Type']

                try:
                    if rule_type == 'REGULAR':
                        rule = self.waf_classic.get_rule(RuleId=rule_id)['Rule']
                        predicates_key = 'Predicates'
                    elif rule_type == 'RATE_BASED':
                        rule = self.waf_classic.get_rate_based_rule(RuleId=rule_id)['Rule']
                        predicates_key = 'MatchPredicates'
                    elif rule_type == 'GROUP':
                        rule_group = self.waf_classic.get_rule_group(RuleGroupId=rule_id)['RuleGroup']

                        # Analyze internal rules within RuleGroup to collect prerequisites
                        rg_prerequisites = {'ipsets': [], 'regex_pattern_sets': []}

                        # Get activated rules using the correct API
                        try:
                            activated_rules_response = self.waf_classic.list_activated_rules_in_rule_group(RuleGroupId=rule_id)
                            activated_rules = activated_rules_response.get('ActivatedRules', [])
                        except Exception as e:
                            activated_rules = []

                        for activated_rule in activated_rules:
                            inner_rule_id = activated_rule['RuleId']
                            inner_rule_type = activated_rule.get('Type', 'REGULAR')

                            try:
                                if inner_rule_type == 'REGULAR':
                                    inner_rule = self.waf_classic.get_rule(RuleId=inner_rule_id)['Rule']
                                    inner_predicates = inner_rule.get('Predicates', [])
                                elif inner_rule_type == 'RATE_BASED':
                                    inner_rule = self.waf_classic.get_rate_based_rule(RuleId=inner_rule_id)['Rule']
                                    inner_predicates = inner_rule.get('MatchPredicates', [])
                                else:
                                    continue

                                # Collect prerequisites from inner rule predicates
                                for inner_pred in inner_predicates:
                                    if inner_pred['Type'] == 'IPMatch':
                                        rg_prerequisites['ipsets'].append(inner_pred['DataId'])
                                    elif inner_pred['Type'] == 'RegexMatch':
                                        # For RegexMatch, we need to get the RegexPatternSet ID from the RegexMatchSet
                                        try:
                                            regex_match_set = self.waf_classic.get_regex_match_set(RegexMatchSetId=inner_pred['DataId'])['RegexMatchSet']
                                            if regex_match_set.get('RegexMatchTuples'):
                                                # Get RegexPatternSet ID from first tuple
                                                regex_pattern_set_id = regex_match_set['RegexMatchTuples'][0]['RegexPatternSetId']
                                                rg_prerequisites['regex_pattern_sets'].append(regex_pattern_set_id)
                                        except Exception:
                                            # Skip if we can't resolve the RegexPatternSet
                                            pass

                            except Exception:
                                # Skip problematic inner rules
                                continue

                        # Add RuleGroup prerequisites to main analysis
                        analysis['prerequisites']['ipsets'].extend(rg_prerequisites['ipsets'])
                        analysis['prerequisites']['regex_pattern_sets'].extend(rg_prerequisites['regex_pattern_sets'])

                        # Check if OverrideAction field exists (for GROUP rules)
                        if 'OverrideAction' not in rule_ref:
                            # Debug: Show what fields are actually present
                            available_fields = list(rule_ref.keys())
                            analysis['rules'].append({
                                'name': rule_group['Name'],
                                'priority': rule_ref.get('Priority', 0),
                                'type': 'RuleGroup',
                                'error': f'Missing OverrideAction field in GROUP rule reference. Available fields: {available_fields}',
                                'v2_equivalent': None  # Ensure v2_equivalent exists
                            })
                            continue

                        rule_analysis = {
                            'rule_id': rule_id,
                            'name': rule_group['Name'],
                            'action': rule_ref['OverrideAction']['Type'],  # Use OverrideAction for GROUP
                            'priority': rule_ref['Priority'],
                            'type': 'RuleGroup',
                            'excluded_rules': rule_ref.get('ExcludedRules', []),
                            'inner_rules_count': len(activated_rules),  # Use actual activated rules count
                            'rg_prerequisites': rg_prerequisites,
                            'v2_equivalent': self._generate_v2_rule_group_reference(rule_group, rule_ref)
                        }
                        analysis['rules'].append(rule_analysis)
                        analysis['prerequisites']['rule_groups'].append(rule_id)  # Store rule_id for migration
                        continue
                    else:
                        analysis['migration_notes'].append(f"Unknown rule type {rule_type} for rule {rule_id}")
                        continue

                    # Check if Action field exists
                    if 'Action' not in rule_ref:
                        # Debug: Show what fields are actually present
                        available_fields = list(rule_ref.keys())
                        analysis['rules'].append({
                            'name': rule.get('Name', f'Rule-{rule_id}'),
                            'priority': rule_ref.get('Priority', 0),
                            'type': rule_type,
                            'error': f'Missing Action field in {rule_type} rule reference. Available fields: {available_fields}',
                            'v2_equivalent': None  # Ensure v2_equivalent exists
                        })
                        continue

                    rule_analysis = {
                        'rule_id': rule_id,
                        'name': rule['Name'],
                        'action': rule_ref['Action']['Type'],
                        'priority': rule_ref['Priority'],
                        'type': rule_type,
                        'predicates': [],
                        'v2_equivalent': None
                    }

                    # Handle rate-based rule specific fields
                    if rule_type == 'RATE_BASED':
                        rule_analysis['rate_key'] = rule['RateKey']
                        rule_analysis['rate_limit'] = rule['RateLimit']

                    # Analyze predicates and collect prerequisites
                    for predicate in rule.get(predicates_key, []):
                        pred_analysis = self._analyze_predicate(predicate)
                        rule_analysis['predicates'].append(pred_analysis)

                        # Collect prerequisites
                        if pred_analysis['type'] == 'IPMatch':
                            analysis['prerequisites']['ipsets'].append(pred_analysis['data_id'])
                        elif pred_analysis['type'] == 'RegexMatch':
                            analysis['prerequisites']['regex_pattern_sets'].append(pred_analysis['data_id'])

                    # Generate v2 equivalent (only for non-GROUP rules, GROUP rules already have v2_equivalent)
                    if rule_type != 'GROUP':
                        rule_analysis['v2_equivalent'] = self._generate_v2_rule(rule_analysis)
                    analysis['rules'].append(rule_analysis)

                except Exception as e:
                    # Debug: Show rule_ref structure for troubleshooting
                    available_fields = list(rule_ref.keys()) if rule_ref else []
                    error_msg = f"{str(e)} | Rule type: {rule_type} | Available fields: {available_fields}"
                    analysis['migration_notes'].append(f"Skipped rule {rule_id}: {error_msg}")

                    # Check if Action/OverrideAction field exists for error reporting
                    action_type = 'UNKNOWN'
                    if rule_type == 'GROUP':
                        if 'OverrideAction' in rule_ref and 'Type' in rule_ref['OverrideAction']:
                            action_type = rule_ref['OverrideAction']['Type']
                    else:
                        if 'Action' in rule_ref and 'Type' in rule_ref['Action']:
                            action_type = rule_ref['Action']['Type']

                    rule_analysis = {
                        'name': f'MissingRule-{rule_id}',
                        'action': action_type,
                        'priority': rule_ref.get('Priority', 0),
                        'error': error_msg,
                        'v2_equivalent': None
                    }
                    analysis['rules'].append(rule_analysis)

            # Remove duplicates from prerequisites
            analysis['prerequisites']['ipsets'] = list(set(analysis['prerequisites']['ipsets']))
            analysis['prerequisites']['regex_pattern_sets'] = list(set(analysis['prerequisites']['regex_pattern_sets']))

            # Validate capacity using CheckCapacity API
            valid_rules = [rule['v2_equivalent'] for rule in analysis['rules']
                          if rule['v2_equivalent'] is not None]
            failed_rules = [rule for rule in analysis['rules'] if rule['v2_equivalent'] is None]

            if valid_rules:
                try:
                    capacity_response = self.wafv2.check_capacity(Scope=self.scope, Rules=valid_rules)
                    analysis['capacity_validation'] = {
                        'valid': True,
                        'capacity_units': capacity_response['Capacity'],
                        'max_capacity': 1500 if self.scope == 'REGIONAL' else 5000,
                        'valid_rules_count': len(valid_rules),
                        'failed_rules_count': len(failed_rules)
                    }
                except Exception as e:
                    analysis['capacity_validation'] = {
                        'valid': False,
                        'error': str(e),
                        'valid_rules_count': len(valid_rules),
                        'failed_rules_count': len(failed_rules)
                    }
            else:
                analysis['capacity_validation'] = {
                    'valid': False,
                    'error': 'No valid rules to validate capacity - all rules failed analysis',
                    'valid_rules_count': 0,
                    'failed_rules_count': len(failed_rules)
                }

            return analysis

        except Exception as e:
            raise Exception(f"Failed to analyze WebACL {webacl_id}: {str(e)}")



    def analyze_rulegroup(self, rulegroup_id: str) -> dict:
        """Analyze Classic RuleGroup and create migration plan"""
        try:
            rulegroup = self.waf_classic.get_rule_group(RuleGroupId=rulegroup_id)['RuleGroup']
            
            # Get activated rules separately
            activated_rules_response = self.waf_classic.list_activated_rules_in_rule_group(RuleGroupId=rulegroup_id)
            activated_rules = activated_rules_response.get('ActivatedRules', [])
            
            analysis = {
                'rulegroup_id': rulegroup_id,
                'name': rulegroup['Name'],
                'rules': [],
                'prerequisites': {'ipsets': [], 'regex_pattern_sets': []},
                'migration_notes': []
            }

            # Analyze internal rules
            for rule_ref in activated_rules:
                rule_id = rule_ref['RuleId']
                
                try:
                    # Try regular rule first
                    try:
                        rule = self.waf_classic.get_rule(RuleId=rule_id)['Rule']
                        rule_type = 'REGULAR'
                        predicates_key = 'Predicates'
                    except:
                        # Try rate-based rule
                        rule = self.waf_classic.get_rate_based_rule(RuleId=rule_id)['Rule']
                        rule_type = 'RATE_BASED'
                        predicates_key = 'MatchPredicates'

                    rule_analysis = {
                        'rule_id': rule_id,
                        'name': rule['Name'],
                        'type': rule_type,
                        'action': rule_ref['Action']['Type'],
                        'priority': rule_ref['Priority'],
                        'predicates': []
                    }

                    if rule_type == 'RATE_BASED':
                        rule_analysis['rate_limit'] = rule['RateLimit']
                        rule_analysis['rate_key'] = rule['RateKey']

                    # Analyze predicates
                    for predicate in rule.get(predicates_key, []):
                        pred_analysis = self._analyze_predicate(predicate)
                        rule_analysis['predicates'].append(pred_analysis)

                        # Collect prerequisites
                        if pred_analysis['type'] == 'IPMatch':
                            if pred_analysis['classic_id'] not in [ip['classic_id'] for ip in analysis['prerequisites']['ipsets']]:
                                analysis['prerequisites']['ipsets'].append({
                                    'classic_id': pred_analysis['classic_id'],
                                    'name': pred_analysis.get('name', 'Unknown')
                                })
                        elif pred_analysis['type'] == 'RegexMatch':
                            if pred_analysis['classic_id'] not in [rps['classic_id'] for rps in analysis['prerequisites']['regex_pattern_sets']]:
                                analysis['prerequisites']['regex_pattern_sets'].append({
                                    'classic_id': pred_analysis['classic_id'],
                                    'name': pred_analysis.get('name', 'Unknown')
                                })

                    analysis['rules'].append(rule_analysis)

                except Exception as e:
                    analysis['migration_notes'].append(f"Failed to analyze rule {rule_id}: {str(e)}")

            return analysis

        except Exception as e:
            raise Exception(f"Failed to analyze RuleGroup {rulegroup_id}: {str(e)}")

    def _analyze_predicate(self, predicate: dict) -> dict:
        """Analyze Classic predicate and map to v2 statement"""
        pred_type = predicate['Type']
        pred_id = predicate['DataId']

        analysis = {
            'type': pred_type,
            'negated': predicate['Negated'],
            'data_id': pred_id,
            'classic_id': pred_id,  # Add classic_id for consistency
            'v2_statement': None
        }

        try:
            if pred_type == 'IPMatch':
                ip_set = self.waf_classic.get_ip_set(IPSetId=pred_id)['IPSet']
                analysis['name'] = ip_set['Name']  # Add name for prerequisites

                # Handle empty IPSet
                if not ip_set['IPSetDescriptors']:
                    # Empty IPSet - will create empty IPv4 IPSet
                    ipv4_name = f"{self._generate_v2_name_for_analysis('ipset', ipset_id, ip_set['Name'])}_v4"
                    analysis['v2_statement'] = {
                        'IPSetReferenceStatement': {
                            'ARN': f'arn:aws:wafv2:*:*:*/ipset/{ipv4_name}/*'
                        }
                    }
                    analysis['empty_ipset'] = True
                else:
                    # Check if IPSet contains both IPv4 and IPv6
                    has_ipv4 = any(':' not in desc['Value'] for desc in ip_set['IPSetDescriptors'])
                    has_ipv6 = any(':' in desc['Value'] for desc in ip_set['IPSetDescriptors'])

                    if has_ipv4 and has_ipv6:
                        # Will need to split into two statements
                        ipv4_name = f"{self._generate_v2_name_for_analysis('ipset', ipset_id, ip_set['Name'])}_v4"
                        ipv6_name = f"{self._generate_v2_name_for_analysis('ipset', ipset_id, ip_set['Name'])}_v6"
                        analysis['v2_statement'] = {
                            'OrStatement': {
                                'Statements': [
                                    {
                                        'IPSetReferenceStatement': {
                                            'ARN': f'arn:aws:wafv2:*:*:*/ipset/{ipv4_name}/*'
                                        }
                                    },
                                    {
                                        'IPSetReferenceStatement': {
                                            'ARN': f'arn:aws:wafv2:*:*:*/ipset/{ipv6_name}/*'
                                        }
                                    }
                                ]
                            }
                        }
                        analysis['split_ipset'] = True
                    elif has_ipv6:
                        ipv6_name = f"{self._generate_v2_name_for_analysis('ipset', ipset_id, ip_set['Name'])}_v6"
                        analysis['v2_statement'] = {
                            'IPSetReferenceStatement': {
                                'ARN': f'arn:aws:wafv2:*:*:*/ipset/{ipv6_name}/*'
                            }
                        }
                    else:
                        ipv4_name = f"{self._generate_v2_name_for_analysis('ipset', ipset_id, ip_set['Name'])}_v4"
                        analysis['v2_statement'] = {
                            'IPSetReferenceStatement': {
                                'ARN': f'arn:aws:wafv2:*:*:*/ipset/{ipv4_name}/*'
                            }
                        }

            elif pred_type == 'ByteMatch':
                byte_match = self.waf_classic.get_byte_match_set(ByteMatchSetId=pred_id)['ByteMatchSet']

                # Handle multiple ByteMatchTuples - create OrStatement if multiple
                tuples = byte_match['ByteMatchTuples']
                if len(tuples) == 1:
                    tuple_data = tuples[0]
                    analysis['v2_statement'] = {
                        'ByteMatchStatement': {
                            'SearchString': tuple_data['TargetString'],
                            'FieldToMatch': self._map_field_to_match(tuple_data['FieldToMatch']),
                            'TextTransformations': self._map_text_transformations([tuple_data['TextTransformation']]),
                            'PositionalConstraint': tuple_data['PositionalConstraint']
                        }
                    }
                else:
                    # Multiple tuples - create OrStatement
                    statements = []
                    for tuple_data in tuples:
                        statements.append({
                            'ByteMatchStatement': {
                                'SearchString': tuple_data['TargetString'],
                                'FieldToMatch': self._map_field_to_match(tuple_data['FieldToMatch']),
                                'TextTransformations': self._map_text_transformations([tuple_data['TextTransformation']]),
                                'PositionalConstraint': tuple_data['PositionalConstraint']
                            }
                        })
                    analysis['v2_statement'] = self._create_safe_or_statement(statements)
                    # Skip if no valid statements
                    if analysis["v2_statement"] is None:
                        analysis["error"] = "No valid statements found"
                        return analysis

            elif pred_type == 'GeoMatch':
                geo_match = self.waf_classic.get_geo_match_set(GeoMatchSetId=pred_id)['GeoMatchSet']
                countries = [constraint['Value'] for constraint in geo_match['GeoMatchConstraints']]
                analysis['v2_statement'] = {
                    'GeoMatchStatement': {
                        'CountryCodes': countries
                    }
                }

            elif pred_type == 'RegexMatch':
                # Get RegexMatchSet first
                regex_match_set_id = pred_id
                try:
                    regex_match = self.waf_classic.get_regex_match_set(RegexMatchSetId=regex_match_set_id)['RegexMatchSet']

                    # Extract RegexPatternSet ID from the first tuple
                    if regex_match.get('RegexMatchTuples'):
                        first_tuple = regex_match['RegexMatchTuples'][0]
                        regex_pattern_set_id = first_tuple['RegexPatternSetId']

                        # Now get the actual RegexPatternSet
                        regex_set = self.waf_classic.get_regex_pattern_set(RegexPatternSetId=regex_pattern_set_id)['RegexPatternSet']
                        analysis['name'] = regex_set['Name']  # Add name for prerequisites
                        analysis['classic_id'] = regex_pattern_set_id  # Use RegexPatternSet ID, not RegexMatchSet ID
                        regex_name = self.dependency_graph.generate_v2_name('regex', regex_pattern_set_id, regex_set['Name'])

                        # Handle multiple RegexMatchTuples
                        tuples = regex_match['RegexMatchTuples']
                        if len(tuples) == 1:
                            tuple_data = tuples[0]
                            analysis['v2_statement'] = {
                                'RegexPatternSetReferenceStatement': {
                                    'ARN': f'arn:aws:wafv2:*:*:*/regexpatternset/{regex_name}/*',
                                    'FieldToMatch': self._map_field_to_match(tuple_data['FieldToMatch']),
                                    'TextTransformations': self._map_text_transformations([tuple_data['TextTransformation']])
                                }
                            }
                        else:
                            # Multiple tuples - create OrStatement
                            statements = []
                            for tuple_data in tuples:
                                statements.append({
                                    'RegexPatternSetReferenceStatement': {
                                        'ARN': f'arn:aws:wafv2:*:*:*/regexpatternset/{regex_name}/*',
                                        'FieldToMatch': self._map_field_to_match(tuple_data['FieldToMatch']),
                                        'TextTransformations': self._map_text_transformations([tuple_data['TextTransformation']])
                                    }
                                })
                            analysis['v2_statement'] = self._create_safe_or_statement(statements)
                    # Skip if no valid statements
                    if analysis["v2_statement"] is None:
                        analysis["error"] = "No valid statements found"
                        return analysis

                        # Store the RegexPatternSet ID for prerequisites (not the RegexMatchSet ID)
                        analysis['data_id'] = regex_pattern_set_id
                        analysis['resource_name'] = regex_set['Name']
                    else:
                        analysis['error'] = 'RegexMatchSet has no tuples'

                except Exception as e:
                    analysis['error'] = f'Failed to process RegexMatchSet: {str(e)}'

            elif pred_type == 'SqlInjectionMatch':
                sqli_match = self.waf_classic.get_sql_injection_match_set(SqlInjectionMatchSetId=pred_id)['SqlInjectionMatchSet']

                # Handle multiple SqlInjectionMatchTuples
                tuples = sqli_match['SqlInjectionMatchTuples']
                if len(tuples) == 1:
                    tuple_data = tuples[0]
                    analysis['v2_statement'] = {
                        'SqliMatchStatement': {
                            'FieldToMatch': self._map_field_to_match(tuple_data['FieldToMatch']),
                            'TextTransformations': self._map_text_transformations([tuple_data['TextTransformation']])
                        }
                    }
                else:
                    # Multiple tuples - create OrStatement
                    statements = []
                    for tuple_data in tuples:
                        statements.append({
                            'SqliMatchStatement': {
                                'FieldToMatch': self._map_field_to_match(tuple_data['FieldToMatch']),
                                'TextTransformations': self._map_text_transformations([tuple_data['TextTransformation']])
                            }
                        })
                    analysis['v2_statement'] = self._create_safe_or_statement(statements)
                    # Skip if no valid statements
                    if analysis["v2_statement"] is None:
                        analysis["error"] = "No valid statements found"
                        return analysis

            elif pred_type == 'XssMatch':
                xss_match = self.waf_classic.get_xss_match_set(XssMatchSetId=pred_id)['XssMatchSet']

                # Handle multiple XssMatchTuples
                tuples = xss_match['XssMatchTuples']
                if len(tuples) == 1:
                    tuple_data = tuples[0]
                    analysis['v2_statement'] = {
                        'XssMatchStatement': {
                            'FieldToMatch': self._map_field_to_match(tuple_data['FieldToMatch']),
                            'TextTransformations': self._map_text_transformations([tuple_data['TextTransformation']])
                        }
                    }
                else:
                    # Multiple tuples - create OrStatement
                    statements = []
                    for tuple_data in tuples:
                        statements.append({
                            'XssMatchStatement': {
                                'FieldToMatch': self._map_field_to_match(tuple_data['FieldToMatch']),
                                'TextTransformations': self._map_text_transformations([tuple_data['TextTransformation']])
                            }
                        })
                    analysis['v2_statement'] = self._create_safe_or_statement(statements)
                    # Skip if no valid statements
                    if analysis["v2_statement"] is None:
                        analysis["error"] = "No valid statements found"
                        return analysis

            elif pred_type == 'SizeConstraint':
                size_constraint_set = self.waf_classic.get_size_constraint_set(SizeConstraintSetId=pred_id)['SizeConstraintSet']

                # Handle multiple SizeConstraintTuples
                tuples = size_constraint_set['SizeConstraints']
                if len(tuples) == 1:
                    tuple_data = tuples[0]
                    analysis['v2_statement'] = {
                        'SizeConstraintStatement': {
                            'FieldToMatch': self._map_field_to_match(tuple_data['FieldToMatch']),
                            'ComparisonOperator': tuple_data['ComparisonOperator'],
                            'Size': tuple_data['Size'],
                            'TextTransformations': self._map_text_transformations([tuple_data['TextTransformation']])
                        }
                    }
                else:
                    # Multiple tuples - create OrStatement
                    statements = []
                    for tuple_data in tuples:
                        statements.append({
                            'SizeConstraintStatement': {
                                'FieldToMatch': self._map_field_to_match(tuple_data['FieldToMatch']),
                                'ComparisonOperator': tuple_data['ComparisonOperator'],
                                'Size': tuple_data['Size'],
                                'TextTransformations': self._map_text_transformations([tuple_data['TextTransformation']])
                            }
                        })
                    analysis['v2_statement'] = self._create_safe_or_statement(statements)
                    # Skip if no valid statements
                    if analysis["v2_statement"] is None:
                        analysis["error"] = "No valid statements found"
                        return analysis

                analysis['resource_name'] = size_constraint_set['Name']

        except Exception as e:
            analysis['error'] = str(e)

        return analysis

    def _generate_v2_rule_group_reference(self, rule_group: dict, rule_ref: dict) -> dict:
        """Generate v2 rule group reference statement"""
        rule_id = rule_ref.get('RuleId', 'unknown')

        # Generate proper v2 RuleGroup name using the same logic as migration
        v2_rulegroup_name = self._generate_v2_name_for_analysis('rulegroup', rule_id, rule_group['Name'])

        # Build RuleGroupReferenceStatement
        rg_statement = {
            'ARN': f"arn:aws:wafv2:*:*:*/rulegroup/{v2_rulegroup_name}/*"
        }

        # Handle ExcludedRules if present - apply same naming pattern
        if 'ExcludedRules' in rule_ref and rule_ref['ExcludedRules']:
            excluded_rules_v2 = []
            for excluded_rule in rule_ref['ExcludedRules']:
                excluded_rule_id = excluded_rule['RuleId']
                try:
                    # Get the original rule name from the RuleGroup
                    original_rule = self.waf_classic.get_rule(RuleId=excluded_rule_id)['Rule']
                    # Apply same naming pattern: original name + rule ID suffix
                    v2_rule_name = self._generate_unique_rule_name(original_rule['Name'], excluded_rule_id)
                    excluded_rules_v2.append({'Name': v2_rule_name})
                except Exception:
                    # If we can't get the rule, use the ID with suffix pattern
                    v2_rule_name = self._generate_unique_rule_name(f"Rule-{excluded_rule_id}", excluded_rule_id)
                    excluded_rules_v2.append({'Name': v2_rule_name})

            rg_statement['ExcludedRules'] = excluded_rules_v2

        # For GROUP rules: OverrideAction → no Action in v2, only OverrideAction
        override_action_type = rule_ref['OverrideAction']['Type']
        v2_override_action = None
        if override_action_type == 'NONE':
            v2_override_action = {'None': {}}
        elif override_action_type == 'COUNT':
            v2_override_action = {'Count': {}}

        v2_rule = {
            'Name': self._generate_v2_name_for_analysis('rule', rule_id, f"{rule_group['Name']}-ref"),
            'Priority': rule_ref['Priority'],
            'Statement': {
                'RuleGroupReferenceStatement': rg_statement
            },
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': f"{rule_group['Name']}-ref"
            }
        }

        # Add OverrideAction only (no Action field for GROUP rules)
        if v2_override_action is not None:
            v2_rule['OverrideAction'] = v2_override_action

        return v2_rule

    def _generate_v2_rule(self, rule_analysis: dict) -> dict:
        """Generate v2 rule from Classic rule analysis"""
        rule_type = rule_analysis['type']

        # For REGULAR and RATE_BASED rules: use Action, no OverrideAction
        if rule_type in ['REGULAR', 'RATE_BASED']:
            action_type = rule_analysis['action']
            v2_action = self._map_action_type(action_type)
            v2_override_action = None
        # For GROUP rules: use OverrideAction, no Action
        elif rule_type == 'RuleGroup':
            v2_action = None
            override_action_type = rule_analysis['action']
            if override_action_type == 'NONE':
                v2_override_action = {'None': {}}
            elif override_action_type == 'COUNT':
                v2_override_action = {'Count': {}}
            else:
                v2_override_action = {'None': {}}  # Default fallback
        else:
            # Unknown rule type
            return None

        # Build base rule structure
        v2_rule = {
            'Name': self._generate_v2_name_for_analysis('rule', rule_analysis['rule_id'], rule_analysis['name']),
            'Priority': rule_analysis['priority'],
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': self._generate_v2_name_for_analysis('rule', rule_analysis['rule_id'], rule_analysis['name'])
            }
        }

        # Add Action or OverrideAction based on rule type (exclude None values)
        if v2_action is not None:
            v2_rule['Action'] = v2_action
        if v2_override_action is not None:
            v2_rule['OverrideAction'] = v2_override_action

        # Generate statement based on rule type
        if rule_type == 'RATE_BASED':
            # Rate-based rule
            v2_rule['Statement'] = {
                'RateBasedStatement': {
                    'Limit': rule_analysis['rate_limit'],
                    'AggregateKeyType': rule_analysis['rate_key']
                }
            }

            # Add scope-down statement if predicates exist
            if rule_analysis.get('predicates'):
                if len(rule_analysis['predicates']) == 1:
                    v2_rule['Statement']['RateBasedStatement']['ScopeDownStatement'] = rule_analysis['predicates'][0]['v2_statement']
                else:
                    v2_rule['Statement']['RateBasedStatement']['ScopeDownStatement'] = {
                        'AndStatement': {
                            'Statements': [pred['v2_statement'] for pred in rule_analysis['predicates']]
                        }
                    }

        elif rule_type == 'REGULAR':
            # Regular rule
            if not rule_analysis.get('predicates'):
                return None

            if len(rule_analysis['predicates']) == 1:
                v2_rule['Statement'] = rule_analysis['predicates'][0]['v2_statement']
            else:
                v2_rule['Statement'] = {
                    'AndStatement': {
                        'Statements': [pred['v2_statement'] for pred in rule_analysis['predicates']]
                    }
                }

        elif rule_type == 'RuleGroup':
            # For RuleGroup, return the pre-generated v2_equivalent
            return rule_analysis.get('v2_equivalent')

        return v2_rule
        """Generate WAF v2 rule from Classic rule analysis"""
        statements = []

        for pred in rule_analysis['predicates']:
            if pred['v2_statement']:
                stmt = pred['v2_statement']
                if pred['negated']:
                    stmt = {'NotStatement': {'Statement': stmt}}
                statements.append(stmt)

        # Handle RateBasedRule
        if rule_analysis.get('type') == 'RATE_BASED':
            rate_statement = {
                'RateBasedStatement': {
                    'Limit': rule_analysis['rate_limit'],
                    'AggregateKeyType': rule_analysis['rate_key']
                }
            }

            # Add scope down statement if there are predicates
            if statements:
                if len(statements) == 1:
                    rate_statement['RateBasedStatement']['ScopeDownStatement'] = statements[0]
                else:
                    rate_statement['RateBasedStatement']['ScopeDownStatement'] = {
                        'AndStatement': {'Statements': statements}
                    }

            statement = rate_statement
        else:
            # Regular rule - combine multiple statements with AND
            if len(statements) == 1:
                statement = statements[0]
            elif len(statements) > 1:
                statement = {'AndStatement': {'Statements': statements}}
            else:
                statement = {'ByteMatchStatement': {
                    'SearchString': 'placeholder',
                    'FieldToMatch': {'Body': {}},
                    'TextTransformations': [{'Priority': 0, 'Type': 'NONE'}],
                    'PositionalConstraint': 'CONTAINS'
                }}

        return {
            'Name': self._generate_unique_rule_name(rule_analysis['name'], rule_analysis.get('rule_id', 'unknown')),
            'Priority': rule_analysis['priority'],
            'Statement': statement,
            'Action': self._map_action_type(rule_analysis['action']),
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': rule_analysis['name']  # Keep original name for metrics
            }
        }



    def list_classic_rulegroups(self) -> List[dict]:
        """List all Classic RuleGroups"""
        try:
            response = self.waf_classic.list_rule_groups()
            rulegroups = []

            for rg in response['RuleGroups']:
                try:
                    detail = self.waf_classic.get_rule_group(RuleGroupId=rg['RuleGroupId'])['RuleGroup']
                    activated_rules_response = self.waf_classic.list_activated_rules_in_rule_group(RuleGroupId=rg['RuleGroupId'])
                    activated_rules = activated_rules_response.get('ActivatedRules', [])
                    
                    rulegroups.append({
                        'id': rg['RuleGroupId'],
                        'name': rg['Name'],
                        'rule_count': len(activated_rules),
                        'metric_name': detail.get('MetricName', '')
                    })
                except Exception as e:
                    rulegroups.append({
                        'id': rg['RuleGroupId'],
                        'name': rg['Name'],
                        'error': str(e)
                    })

            return rulegroups
        except Exception as e:
            raise Exception(f"Failed to list rule groups: {str(e)}")

    def migrate_filtered_webacls(self, webacl_ids: List[str], dry_run: bool = False) -> dict:
        """Migrate specific WebACLs using the all migration logic"""
        # Get all WebACLs and filter to only the requested ones
        all_webacls = self.list_classic_webacls()
        filtered_webacls = [w for w in all_webacls if w['id'] in webacl_ids]
        
        if not filtered_webacls:
            return {'success': False, 'error': 'No matching WebACLs found'}
        
        # Temporarily replace the list method to return only filtered WebACLs
        original_list = self.list_classic_webacls
        self.list_classic_webacls = lambda: filtered_webacls
        
        try:
            result = self.migrate_all_webacls(dry_run=dry_run)
            return result
        finally:
            # Restore original method
            self.list_classic_webacls = original_list

    def migrate_filtered_rulegroups(self, rulegroup_ids: List[str], dry_run: bool = False) -> dict:
        """Migrate specific RuleGroups using the all migration logic"""
        # Get all RuleGroups and filter to only the requested ones
        all_rulegroups = self.list_classic_rulegroups()
        filtered_rulegroups = [rg for rg in all_rulegroups if rg['id'] in rulegroup_ids]
        
        if not filtered_rulegroups:
            return {'success': False, 'error': 'No matching RuleGroups found'}
        
        # Temporarily replace the list method to return only filtered RuleGroups
        original_list = self.list_classic_rulegroups
        self.list_classic_rulegroups = lambda: filtered_rulegroups
        
        try:
            result = self.migrate_all_rulegroups(dry_run=dry_run)
            return result
        finally:
            # Restore original method
            self.list_classic_rulegroups = original_list

    def migrate_all_webacls(self, dry_run: bool = False) -> dict:
        """Migrate all WebACLs in the region"""
        try:
            webacls = self.list_classic_webacls()
            webacl_ids = [acl['id'] for acl in webacls]
            
            if not webacl_ids:
                return {'success': False, 'error': 'No WebACLs found in region'}
            
            print(f"SEARCH: Found {len(webacl_ids)} WebACLs to migrate in region {self.region_config.display_name}")
            for i, acl in enumerate(webacls, 1):
                print(f"  {i}. {acl['name']} (ID: {acl['id']})")
            print()
            
            if dry_run:
                print("SEARCH: DRY RUN - No resources will be created")
                return {'success': True, 'dry_run': True, 'webacl_count': len(webacl_ids)}
            
            results = {'webacls': [], 'shared_resources': [], 'success': True, 'summary': {}}
            successful_migrations = 0
            failed_migrations = 0
            
            for i, webacl_id in enumerate(webacl_ids, 1):
                webacl_name = next((acl['name'] for acl in webacls if acl['id'] == webacl_id), f'WebACL-{webacl_id}')
                print(f"INFO: [{i}/{len(webacl_ids)}] Migrating WebACL: {webacl_name}")
                print(f"    Classic ID: {webacl_id}")
                
                try:
                    result = self.execute_streamlined_migration(webacl_id)
                    
                    if result.get('success'):
                        v2_arn = result.get('webacl', {}).get('webacl_arn', 'N/A')
                        v2_name = result.get('webacl', {}).get('webacl_name', 'N/A')
                        print(f"    SUCCESS: {v2_name}")
                        print(f"    LOCATION: v2 ARN: {v2_arn}")
                        successful_migrations += 1
                        
                        results['webacls'].append({
                            'classic_id': webacl_id,
                            'classic_name': webacl_name,
                            'status': 'SUCCESS',
                            'v2_arn': v2_arn,
                            'v2_name': v2_name
                        })
                    else:
                        error_msg = result.get('error', 'Migration failed - no specific error details available')
                        print(f"    FAILED: {error_msg}")
                        failed_migrations += 1
                        results['success'] = False
                        
                        results['webacls'].append({
                            'classic_id': webacl_id,
                            'classic_name': webacl_name,
                            'status': 'FAILED',
                            'error': error_msg
                        })
                        
                except Exception as e:
                    print(f"    FAILED: {str(e)}")
                    failed_migrations += 1
                    results['success'] = False
                    
                    results['webacls'].append({
                        'classic_id': webacl_id,
                        'classic_name': webacl_name,
                        'status': 'FAILED',
                        'error': str(e)
                    })
                
                print()
            
            # Migration completed - summary removed
            
            results['summary'] = {
                'total': len(webacl_ids),
                'successful': successful_migrations,
                'failed': failed_migrations
            }
            
        except Exception as e:
            # Even on exception, try to generate report with whatever data we have
            results = {'webacls': [], 'summary': {'total': 0, 'successful': 0, 'failed': 0}}
            
        # Generate migration table and CSV only if not suppressed
        if not getattr(self, '_suppress_individual_reports', False):
            self._generate_migration_report(results.get('rulegroups', []), 'RuleGroup')
            self._generate_migration_report(results.get('webacls', []), 'WebACL')
        
        return results

    def migrate_all_rulegroups(self, dry_run: bool = False) -> dict:
        """Migrate all RuleGroups in the region"""
        try:
            rulegroups = self.list_classic_rulegroups()
            valid_rulegroups = [rg for rg in rulegroups if 'error' not in rg]
            
            if not valid_rulegroups:
                return {'success': False, 'error': 'No valid RuleGroups found in region'}
            
            print(f"SEARCH: Found {len(valid_rulegroups)} RuleGroups to migrate in region {self.region_config.display_name}")
            for i, rg in enumerate(valid_rulegroups, 1):
                print(f"  {i}. {rg['name']} (Rules: {rg.get('rule_count', 0)}) - ID: {rg['id']}")
            print()
            
            if dry_run:
                print("SEARCH: DRY RUN - No resources will be created")
                return {'success': True, 'dry_run': True, 'rulegroup_count': len(valid_rulegroups)}
            
            results = {'rulegroups': [], 'success': True, 'summary': {}}
            successful_migrations = 0
            failed_migrations = 0
            
            for i, rg in enumerate(valid_rulegroups, 1):
                print(f"INFO: [{i}/{len(valid_rulegroups)}] Migrating RuleGroup: {rg['name']}")
                print(f"    Classic ID: {rg['id']}")
                print(f"    Internal Rules: {rg.get('rule_count', 0)}")
                
                try:
                    result = self.migrate_rulegroup(rg['id'], dry_run=False)
                    
                    if result.get('success'):
                        v2_arn = result.get('v2_arn', 'N/A')
                        v2_name = result.get('v2_name', 'N/A')
                        rules_migrated = result.get('rules_migrated', 0)
                        rules_reused = result.get('rules_reused', 0)
                        rules_created = result.get('rules_created', 0)
                        
                        print(f"    SUCCESS: SUCCESS: {v2_name}")
                        print(f"    LOCATION: v2 ARN: {v2_arn}")
                        print(f"    REPORT: Total Rules: {rules_migrated}")
                        
                        # Show reuse information if any
                        if rules_reused > 0:
                            print(f"    REUSED:  Reused: {rules_reused} rules")
                        if rules_created > 0:
                            print(f"    Enhanced Created: {rules_created} rules")
                        
                        successful_migrations += 1
                        
                        results['rulegroups'].append({
                            'classic_id': rg['id'],
                            'classic_name': rg['name'],
                            'status': 'SUCCESS',
                            'v2_arn': v2_arn,
                            'v2_name': v2_name,
                            'rules_migrated': rules_migrated
                        })
                    else:
                        error_msg = result.get('error', 'Migration failed - no specific error details available')
                        print(f"    FAILED: {error_msg}")
                        failed_migrations += 1
                        results['success'] = False
                        
                        results['rulegroups'].append({
                            'classic_id': rg['id'],
                            'classic_name': rg['name'],
                            'status': 'FAILED',
                            'error': error_msg
                        })
                        
                except Exception as e:
                    print(f"    FAILED: {str(e)}")
                    failed_migrations += 1
                    results['success'] = False
                    
                    results['rulegroups'].append({
                        'classic_id': rg['id'],
                        'classic_name': rg['name'],
                        'status': 'FAILED',
                        'error': str(e)
                    })
                
                print()
            
            results['summary'] = {
                'total': len(valid_rulegroups),
                'successful': successful_migrations,
                'failed': failed_migrations
            }
            
        except Exception as e:
            # Even on exception, try to generate report with whatever data we have
            results = {'rulegroups': [], 'summary': {'total': 0, 'successful': 0, 'failed': 0}}
            
        # Generate migration table and CSV only if not suppressed
        if not getattr(self, '_suppress_individual_reports', False):
            self._generate_migration_report(results.get('rulegroups', []), 'RuleGroup')
            self._generate_migration_report(results.get('webacls', []), 'WebACL')
        
        return results

# Internal helper functions (not exposed as CLI commands)
def list_webacls_multi_region(regions=None, all_regions=False):
    """List WebACLs across multiple regions"""
    if all_regions:
        regions = WAFRegionManager.list_supported_regions()
    elif not regions:
        regions = ['us-east-1']
    
    all_webacls = {}
    for region in regions:
        try:
            migrator = WAFMigrator(region=region)
            webacls = migrator.list_classic_webacls()
            if webacls:
                all_webacls[region] = webacls
        except Exception as e:
            error_msg = str(e)
            if "UnrecognizedClientException" in error_msg or "security token" in error_msg:
                print(f"WARNING: No access to region {region} - credentials may not be valid for this region")
            elif "InvalidUserID.NotFound" in error_msg:
                print(f"WARNING: Region {region} not accessible with current credentials")
            else:
                print(f"ERROR: Failed to list WebACLs in region {region}: {error_msg}")
    
    return all_webacls

def list_rulegroups_multi_region(regions=None, all_regions=False):
    """List RuleGroups across multiple regions"""
    if all_regions:
        regions = WAFRegionManager.list_supported_regions()
    elif not regions:
        regions = ['us-east-1']
    
    all_rulegroups = {}
    for region in regions:
        try:
            migrator = WAFMigrator(region=region)
            rulegroups = migrator.list_classic_rulegroups()
            if rulegroups:
                all_rulegroups[region] = rulegroups
        except Exception as e:
            error_msg = str(e)
            if "UnrecognizedClientException" in error_msg or "security token" in error_msg:
                print(f"WARNING: No access to region {region} - credentials may not be valid for this region")
            elif "InvalidUserID.NotFound" in error_msg:
                print(f"WARNING: Region {region} not accessible with current credentials")
            else:
                print(f"ERROR: Failed to list RuleGroups in region {region}: {error_msg}")
    
    return all_rulegroups

def search_webacls_multi_region(webacl_ids, regions=None, all_regions=False):
    """Search for WebACLs by IDs across multiple regions"""
    if all_regions:
        regions = WAFRegionManager.list_supported_regions()
    elif not regions:
        regions = ['us-east-1']
    
    found_webacls = {}
    for region in regions:
        try:
            migrator = WAFMigrator(region=region)
            region_webacls = migrator.list_classic_webacls()
            
            for webacl_id in webacl_ids:
                for webacl in region_webacls:
                    if webacl['id'] == webacl_id:
                        if region not in found_webacls:
                            found_webacls[region] = []
                        found_webacls[region].append(webacl)
        except Exception as e:
            print(f"ERROR: Failed to search WebACLs in region {region}: {str(e)}")
    
    return found_webacls

def search_rulegroups_multi_region(rulegroup_ids, regions=None, all_regions=False):
    """Search for RuleGroups by IDs across multiple regions"""
    if all_regions:
        regions = WAFRegionManager.list_supported_regions()
    elif not regions:
        regions = ['us-east-1']
    
    found_rulegroups = {}
    for region in regions:
        try:
            migrator = WAFMigrator(region=region)
            region_rulegroups = migrator.list_classic_rulegroups()
            
            for rulegroup_id in rulegroup_ids:
                for rulegroup in region_rulegroups:
                    if rulegroup['id'] == rulegroup_id:
                        if region not in found_rulegroups:
                            found_rulegroups[region] = []
                        found_rulegroups[region].append(rulegroup)
        except Exception as e:
            error_msg = str(e)
            if "UnrecognizedClientException" in error_msg or "security token" in error_msg:
                print(f"WARNING: No access to region {region} - credentials may not be valid for this region")
            elif "InvalidUserID.NotFound" in error_msg:
                print(f"WARNING: Region {region} not accessible with current credentials")
            else:
                print(f"ERROR: Failed to search RuleGroups in region {region}: {error_msg}")
    
    return found_rulegroups

# Global cumulative tracking for multi-region migrations
_global_cumulative_webacl_migrations = []
_global_cumulative_rulegroup_migrations = []
_global_suppress_all_reports = False

def _add_to_global_cumulative_webacl_migrations(migrations):
    """Add WebACL migrations to global cumulative tracking"""
    global _global_cumulative_webacl_migrations
    _global_cumulative_webacl_migrations.extend(migrations)

def _add_to_global_cumulative_rulegroup_migrations(migrations):
    """Add RuleGroup migrations to global cumulative tracking"""
    global _global_cumulative_rulegroup_migrations
    _global_cumulative_rulegroup_migrations.extend(migrations)

def _generate_final_cumulative_reports():
    """Generate final cumulative reports for entire multi-region run"""
    global _global_cumulative_webacl_migrations, _global_cumulative_rulegroup_migrations, _global_suppress_all_reports
    
    if not _global_cumulative_webacl_migrations and not _global_cumulative_rulegroup_migrations:
        return
    
    print("\n" + "=" * 80)
    print("FINAL CUMULATIVE MIGRATION SUMMARY - ENTIRE RUN")
    print("=" * 80)
    
    # Create a temporary migrator instance for report generation
    if _global_cumulative_rulegroup_migrations or _global_cumulative_webacl_migrations:
        # Use the region from the first migration or default to us-east-1
        sample_region = 'us-east-1'
        if _global_cumulative_rulegroup_migrations:
            # Try to extract region from first RuleGroup migration, but since we don't store it, use default
            pass
        elif _global_cumulative_webacl_migrations:
            # Try to extract region from first WebACL migration, but since we don't store it, use default  
            pass
        
        temp_migrator = WAFMigrator(region=sample_region)
        temp_migrator._suppress_individual_reports = False  # Allow final report generation
        
        if _global_cumulative_rulegroup_migrations:
            temp_migrator._generate_migration_report(_global_cumulative_rulegroup_migrations, 'RuleGroup')
        
        if _global_cumulative_webacl_migrations:
            temp_migrator._generate_migration_report(_global_cumulative_webacl_migrations, 'WebACL')
    
    # Clear global data
    _global_cumulative_webacl_migrations.clear()
    _global_cumulative_rulegroup_migrations.clear()
    _global_suppress_all_reports = False

def _enable_global_cumulative_reporting():
    """Enable global cumulative reporting mode"""
    global _global_suppress_all_reports
    _global_suppress_all_reports = True

# Helper functions for new command structure
def analyze_webacls_in_region(migrator, region, webacl_ids):
    """Analyze specific WebACLs in a region"""
    for webacl_id in webacl_ids:
        try:
            analysis = migrator.analyze_and_plan(webacl_id)
            migrator.print_migration_report(analysis)
            
            # Include logging analysis
            classic_webacl = migrator.waf_classic.get_web_acl(WebACLId=webacl_id)
            classic_arn = classic_webacl['WebACL']['WebACLArn']
            classic_logging = migrator.get_classic_logging_configuration(classic_arn)
            
            print("\nLOGGING CONFIGURATION ANALYSIS")
            print("-" * 40)
            if classic_logging:
                destinations = classic_logging.get('LogDestinationConfigs', [])
                redacted_fields = classic_logging.get('RedactedFields', [])
                print(f"SUCCESS: Logging: ENABLED")
                print(f"  Destinations: {len(destinations)}")
                for i, dest in enumerate(destinations):
                    print(f"    {i+1}. {dest}")
                if redacted_fields:
                    print(f"  Redacted fields: {len(redacted_fields)}")
                print("  → Available for migration to WAFv2")
            else:
                print("ERROR: Logging: NOT CONFIGURED")
                print("  → No logging configuration to migrate")
        except Exception as e:
            print(f"ERROR: Failed to analyze WebACL {webacl_id}: {str(e)}")
        print()

def migrate_webacls_in_region(migrator, region, webacl_ids, migrate_logging=False):
    """Migrate specific WebACLs in a region"""
    # Suppress individual reports for each WebACL
    migrator._suppress_individual_reports = True
    
    all_migrations = []
    
    for webacl_id in webacl_ids:
        try:
            # Get WebACL details
            try:
                webacl = migrator.waf_classic.get_web_acl(WebACLId=webacl_id)['WebACL']
                webacl_name = webacl['Name']
            except:
                webacl_name = f'WebACL-{webacl_id}'
            
            # Migrate the WebACL
            if migrate_logging:
                result = migrator.migrate_webacl_with_logging(webacl_id, migrate_logging=True)
            else:
                result = migrator.migrate_filtered_webacls([webacl_id])
            
            if result.get('success'):
                print(f"SUCCESS: WebACL {webacl_id} migrated successfully")
                # Extract WebACL info from result
                webacls = result.get('webacls', [])
                if webacls and len(webacls) > 0:
                    all_migrations.append({
                        'classic_id': webacl_id,
                        'classic_name': webacl_name,
                        'status': 'SUCCESS',
                        'v2_arn': webacls[0].get('v2_arn', 'N/A'),
                        'v2_name': webacls[0].get('v2_name', 'N/A'),
                        'region': region
                    })
                else:
                    all_migrations.append({
                        'classic_id': webacl_id,
                        'classic_name': webacl_name,
                        'status': 'SUCCESS',
                        'v2_arn': 'N/A',
                        'v2_name': 'N/A',
                        'region': region
                    })
            else:
                print(f"FAILED: WebACL {webacl_id} migration failed")
                # Clean up error message - remove "Migration failed:" prefix if present
                error_msg = result.get('error', 'Migration failed - no specific error details available')
                if error_msg.startswith('Migration failed: '):
                    error_msg = error_msg[18:]  # Remove "Migration failed: " prefix
                all_migrations.append({
                    'classic_id': webacl_id,
                    'classic_name': webacl_name,
                    'status': 'FAILED',
                    'error': error_msg,
                    'region': region
                })
        except Exception as e:
            print(f"ERROR: Failed to migrate WebACL {webacl_id}: {str(e)}")
            all_migrations.append({
                'classic_id': webacl_id,
                'classic_name': f'WebACL-{webacl_id}',
                'status': 'FAILED',
                'error': str(e),
                'region': region
            })
        print()
    
    # Add to global cumulative tracking
    _add_to_global_cumulative_webacl_migrations(all_migrations)

def analyze_rulegroups_in_region(migrator, region, rulegroup_ids):
    """Analyze specific RuleGroups in a region"""
    for rulegroup_id in rulegroup_ids:
        try:
            analysis = migrator.analyze_rulegroup(rulegroup_id)
            migrator.print_rulegroup_analysis_report(analysis)
        except Exception as e:
            print(f"ERROR: Failed to analyze RuleGroup {rulegroup_id}: {str(e)}")
        print()

def migrate_rulegroups_in_region(migrator, region, rulegroup_ids):
    """Migrate specific RuleGroups in a region"""
    # Suppress individual reports for each RuleGroup
    migrator._suppress_individual_reports = True
    
    all_migrations = []
    
    for rulegroup_id in rulegroup_ids:
        try:
            # Get RuleGroup details
            try:
                rulegroup = migrator.waf_classic.get_rule_group(RuleGroupId=rulegroup_id)['RuleGroup']
                rulegroup_name = rulegroup['Name']
            except:
                rulegroup_name = f'RuleGroup-{rulegroup_id}'
            
            # Migrate the RuleGroup
            result = migrator.migrate_rulegroup(rulegroup_id)
            
            if result.get('success'):
                print(f"SUCCESS: RuleGroup {rulegroup_id} migrated successfully")
                all_migrations.append({
                    'classic_id': rulegroup_id,
                    'classic_name': rulegroup_name,
                    'status': 'SUCCESS',
                    'v2_arn': result.get('v2_arn', 'N/A'),
                    'v2_name': result.get('v2_name', 'N/A'),
                    'region': region
                })
            else:
                print(f"FAILED: RuleGroup {rulegroup_id} migration failed")
                # Clean up error message - remove "Migration failed:" prefix if present
                error_msg = result.get('error', 'Migration failed - no specific error details available')
                if error_msg.startswith('Migration failed: '):
                    error_msg = error_msg[18:]  # Remove "Migration failed: " prefix
                all_migrations.append({
                    'classic_id': rulegroup_id,
                    'classic_name': rulegroup_name,
                    'status': 'FAILED',
                    'error': error_msg,
                    'region': region
                })
        except Exception as e:
            print(f"ERROR: Failed to migrate RuleGroup {rulegroup_id}: {str(e)}")
            all_migrations.append({
                'classic_id': rulegroup_id,
                'classic_name': f'RuleGroup-{rulegroup_id}',
                'status': 'FAILED',
                'error': str(e),
                'region': region
            })
        print()
    
    # Add to global cumulative tracking
    _add_to_global_cumulative_rulegroup_migrations(all_migrations)

def process_webacl_csv_analysis(csv_file, migrator):
    """Process WebACL CSV file for analysis - headers: id,region"""
    import csv
    try:
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                webacl_id = row['webacl_id']
                region = row['region']
                marked = row['mark_for_migration'] 
                print(f"--- Analyzing WebACL {webacl_id} in {region} ---")
                if marked != 'MIGRATE':
                    print("SKIPPING: WebACL not marked for migration")
                    print()
                    continue

                try:
                    region_migrator = WAFMigrator(region=region)
                    analyze_webacls_in_region(region_migrator, region, [webacl_id])
                except Exception as e:
                    print(f"ERROR: Failed to analyze WebACL {webacl_id} in {region}: {str(e)}")
                print()
    except Exception as e:
        print(f"ERROR: Failed to process CSV file {csv_file}: {str(e)}")

def process_webacl_csv_migration(csv_file, migrator, migrate_logging=False):
    """Process WebACL CSV file for migration - headers: id,region"""
    import csv
    try:
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                webacl_id = row['webacl_id']
                region = row['region']
                marked = row['mark_for_migration'] 
                print(f"--- Migrating WebACL {webacl_id} in {region} ---")
                if marked != 'MIGRATE':
                    print("SKIPPING: WebACL not marked for migration")
                    print()
                    continue
                
                if migrate_logging:
                    print("INFO: Logging migration enabled")
                
                try:
                    region_migrator = WAFMigrator(region=region)
                    migrate_webacls_in_region(region_migrator, region, [webacl_id], migrate_logging)
                except Exception as e:
                    print(f"ERROR: Failed to migrate WebACL {webacl_id} in {region}: {str(e)}")
                print()
    except Exception as e:
        print(f"ERROR: Failed to process CSV file {csv_file}: {str(e)}")

def process_rulegroup_csv_analysis(csv_file, migrator):
    """Process RuleGroup CSV file for analysis - headers: id,region"""
    import csv
    try:
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                rulegroup_id = row['rulegroup_id']
                region = row['region']
                marked = row['mark_for_migration']
                print(f"--- Analyzing RuleGroup {rulegroup_id} in {region} ---")
                if marked != 'MIGRATE':
                    print("SKIPPING: Rulegroup not marked for migration")
                    print()
                    continue
                
                try:
                    region_migrator = WAFMigrator(region=region)
                    analyze_rulegroups_in_region(region_migrator, region, [rulegroup_id])
                except Exception as e:
                    print(f"ERROR: Failed to analyze RuleGroup {rulegroup_id} in {region}: {str(e)}")
                print()
    except Exception as e:
        print(f"ERROR: Failed to process CSV file {csv_file}: {str(e)}")

def process_rulegroup_csv_migration(csv_file, migrator):
    """Process RuleGroup CSV file for migration - headers: id,region"""
    import csv
    try:
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                rulegroup_id = row['rulegroup_id']
                region = row['region']
                marked = row['mark_for_migration']
                print(f"--- Migrating RuleGroup {rulegroup_id} in {region} ---")
                if marked != 'MIGRATE':
                    print("SKIPPING: Rulegroup not marked for migration")
                    print()
                    continue

                try:
                    region_migrator = WAFMigrator(region=region)
                    migrate_rulegroups_in_region(region_migrator, region, [rulegroup_id])
                except Exception as e:
                    print(f"ERROR: Failed to migrate RuleGroup {rulegroup_id} in {region}: {str(e)}")
                print()
    except Exception as e:
        print(f"ERROR: Failed to process CSV file {csv_file}: {str(e)}")

def export_webacls_for_migration(webacl_ids=None, all_webacls=False, regions=None, all_regions=False,filename=None):
    """Export WebACLs to CSV for migration planning"""
    print("=== WebACL Export for Migration ===")
    
    # Use same region logic as existing migration functions
    if all_regions:
        region_list = WAFRegionManager.list_supported_regions()
    else:
        region_list = regions.split(",") if regions else []
    
    # Get WebACLs data
    if all_webacls:
        webacls_data = list_webacls_multi_region(region_list, all_regions)
    else:
        webacls_data = search_webacls_multi_region(webacl_ids, region_list, all_regions)
    
    if not webacls_data:
        print("No WebACLs found to export")
        return
    
    # Convert to flat list for CSV export
    flat_webacls = []
    for region, webacls in webacls_data.items():
        for webacl in webacls:
            webacl['region'] = region
            flat_webacls.append(webacl)
    
    # Export to CSV with migration mark column
    csv_filename = export_webacls_to_csv(flat_webacls, filename, 'mark_for_migration')
    print(f"Exported {len(flat_webacls)} WebACLs to: {csv_filename}")

def export_rulegroups_for_migration(rulegroup_ids=None, all_rulegroups=False, regions=None, all_regions=False, filename=None):
    """Export RuleGroups to CSV for migration planning"""
    print("=== RuleGroup Export for Migration ===")
    
    # Use same region logic as existing migration functions
    if all_regions:
        region_list = WAFRegionManager.list_supported_regions()
    else:
        region_list = regions.split(",") if regions else []
    
    # Get RuleGroups data
    if all_rulegroups:
        rulegroups_data = list_rulegroups_multi_region(region_list, all_regions)
    else:
        rulegroups_data = search_rulegroups_multi_region(rulegroup_ids, region_list, all_regions)
    
    if not rulegroups_data:
        print("No RuleGroups found to export")
        return
    
    # Convert to flat list for CSV export
    flat_rulegroups = []
    for region, rulegroups in rulegroups_data.items():
        for rulegroup in rulegroups:
            rulegroup['region'] = region
            flat_rulegroups.append(rulegroup)
    
    # Export to CSV with migration mark column
    csv_filename = export_rulegroups_to_csv(flat_rulegroups, filename, 'mark_for_migration')
    print(f"Exported {len(flat_rulegroups)} RuleGroups to: {csv_filename}")

def main():
    # Check AWS credentials first
    if not check_aws_credentials():
        print("ERROR: AWS credentials not found or not working!")
        print()
        print("Options:")
        print("1. Run: ./waf-classic-migrate.sh --setup-credentials")
        print("2. Run: aws configure")
        print("3. Set environment variables:")
        print("   export AWS_ACCESS_KEY_ID='your-access-key'")
        print("   export AWS_SECRET_ACCESS_KEY='your-secret-key'")
        print("   export AWS_DEFAULT_REGION='us-east-1'")
        return

    parser = argparse.ArgumentParser(description='WAF Classic to v2 Migration Tool')
    parser.add_argument('command', choices=[
        'migrate-webacl', 'migrate-rulegroup', 'export-webacl', 'export-rulegroup'
    ], help='Command to run')
    
    # Resource selection
    parser.add_argument('--webacl-ids', help='Comma-separated WebACL IDs')
    parser.add_argument('--rulegroup-ids', help='Comma-separated RuleGroup IDs')
    parser.add_argument('--all-webacls', action='store_true', help='Process all WebACLs')
    parser.add_argument('--all-rulegroups', action='store_true', help='Process all RuleGroups')
    parser.add_argument('--csv-file', nargs='+', help='CSV file(s) with resource information')
    
    # Region selection
    parser.add_argument('--regions', help='Comma-separated regions')
    parser.add_argument('--all-regions', action='store_true', help='Process all supported regions')
        
    # Action flags
    parser.add_argument('--analyze', action='store_true', help='Only analyze resources without migrating')
    parser.add_argument('--migrate-logging', action='store_true', help='Migrate logging configuration for WebACLs')

    args = parser.parse_args()

    # Validate exact command combinations
    if args.command == 'migrate-webacl':
        valid_combinations = [
            # Specific WebACL IDs with regions
            (bool(args.webacl_ids), bool(args.regions), not bool(args.all_regions), not bool(args.all_webacls), not bool(args.csv_file)),
            # All WebACLs with regions  
            (bool(args.all_webacls), bool(args.regions), not bool(args.all_regions), not bool(args.webacl_ids), not bool(args.csv_file)),
            # All WebACLs with all regions
            (bool(args.all_webacls), bool(args.all_regions), not bool(args.regions), not bool(args.webacl_ids), not bool(args.csv_file)),
            # CSV files
            (bool(args.csv_file), not bool(args.regions), not bool(args.all_regions), not bool(args.webacl_ids), not bool(args.all_webacls))
        ]
        
        current_combination = (
            bool(args.webacl_ids), 
            bool(args.regions) or bool(args.all_regions) or bool(args.csv_file),
            not bool(args.rulegroup_ids) and not bool(args.all_rulegroups)
        )
        
        if not any(all(combo) for combo in valid_combinations):
            print("ERROR: Invalid argument combination for migrate-webacl")
            print("Valid combinations:")
            print("  --webacl-ids <ids> --regions <regions> [--analyze] [--migrate-logging]")
            print("  --all-webacls --regions <regions> [--analyze] [--migrate-logging]") 
            print("  --all-webacls --all-regions [--analyze] [--migrate-logging]")
            print("  --csv-file <files> [--analyze] [--migrate-logging]")
            return
            
    elif args.command == 'migrate-rulegroup':
        valid_combinations = [
            # Specific RuleGroup IDs with regions
            (bool(args.rulegroup_ids), bool(args.regions), not bool(args.all_regions), not bool(args.all_rulegroups), not bool(args.csv_file)),
            # All RuleGroups with regions
            (bool(args.all_rulegroups), bool(args.regions), not bool(args.all_regions), not bool(args.rulegroup_ids), not bool(args.csv_file)),
            # All RuleGroups with all regions
            (bool(args.all_rulegroups), bool(args.all_regions), not bool(args.regions), not bool(args.rulegroup_ids), not bool(args.csv_file)),
            # CSV files
            (bool(args.csv_file), not bool(args.regions), not bool(args.all_regions), not bool(args.rulegroup_ids), not bool(args.all_rulegroups))
        ]
        
        if not any(all(combo) for combo in valid_combinations):
            print("ERROR: Invalid argument combination for migrate-rulegroup")
            print("Valid combinations:")
            print("  --rulegroup-ids <ids> --regions <regions> [--analyze]")
            print("  --all-rulegroups --regions <regions> [--analyze]")
            print("  --all-rulegroups --all-regions [--analyze]") 
            print("  --csv-file <files> [--analyze]")
            return
            
    elif args.command == 'export-webacl':
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
            
    elif args.command == 'export-rulegroup':
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

    if args.command == 'migrate-webacl':
        handle_migrate_webacl(args)
    elif args.command == 'migrate-rulegroup':
        handle_migrate_rulegroup(args)
    elif args.command == 'export-webacl':
        handle_export_webacl(args)
    elif args.command == 'export-rulegroup':
        handle_export_rulegroup(args)
    else:
        print(f"Unknown command: {args.command}")

def handle_export_webacl(args):
    """Handle export-webacl command"""
    export_webacls_for_migration(
        webacl_ids=args.webacl_ids,
        all_webacls=args.all_webacls,
        regions=args.regions,
        all_regions=args.all_regions,
        filename=None
    )

def handle_export_rulegroup(args):
    """Handle export-rulegroup command"""
    export_rulegroups_for_migration(
        rulegroup_ids=args.rulegroup_ids,
        all_rulegroups=args.all_rulegroups,
        regions=args.regions,
        all_regions=args.all_regions,
        filename=None
    )

def handle_migrate_webacl(args):
    """Handle migrate-webacl command with all its variations"""
    
    # Enable global cumulative reporting mode if not in analyze mode
    if not args.analyze:
        _enable_global_cumulative_reporting()
    
    # Determine regions to process
    if args.all_regions:
        regions = WAFRegionManager.list_supported_regions()
    else:
        regions = args.regions.split(",") if args.regions else []
    
    # CSV file processing
    if args.csv_file:
        for csv_file in args.csv_file:
            print(f"=== Processing CSV file: {csv_file} ===")
            if args.analyze:
                print("INFO: Analysis mode - no resources will be created")
                process_webacl_csv_analysis(csv_file, None)
            else:
                print("INFO: Migration mode")
                process_webacl_csv_migration(csv_file, None, args.migrate_logging)
        # Generate final cumulative report after processing all CSV files
        if not args.analyze:
            _generate_final_cumulative_reports()
        return
    
    # All WebACLs processing
    if args.all_webacls:
        print(f"=== Processing all WebACLs ===")
        # Use internal helper to get all WebACLs across regions
        all_webacls = list_webacls_multi_region(regions, args.all_regions)
        
        if not all_webacls:
            print("INFO: No WebACLs found in specified regions")
            return
        
        for region, webacls in all_webacls.items():
            print(f"\n--- Region: {region} ({len(webacls)} WebACLs) ---")
            webacl_ids = [w['id'] for w in webacls]
            
            try:
                region_migrator = WAFMigrator(region=region)
                if args.analyze:
                    print("INFO: Analysis mode - no resources will be created")
                    # Pass the webacls directly to avoid re-listing
                    for webacl_id in webacl_ids:
                        analysis = region_migrator.analyze_and_plan(webacl_id)
                        region_migrator.print_migration_report(analysis)
                else:
                    print("INFO: Migration mode")
                    migrate_webacls_in_region(region_migrator, region, webacl_ids, args.migrate_logging)
            except Exception as e:
                print(f"ERROR: Failed to process region {region}: {str(e)}")
        
        # Generate final cumulative report after processing all regions
        if not args.analyze:
            _generate_final_cumulative_reports()
        return
    
    # Specific WebACL IDs processing
    if args.webacl_ids:
        print(f"=== Processing specific WebACLs ===")
        # Split comma-separated WebACL IDs
        webacl_ids = args.webacl_ids.split(',')
        # Use internal helper to find WebACLs across regions
        found_webacls = search_webacls_multi_region(webacl_ids, regions, args.all_regions)
        
        if not found_webacls:
            print("ERROR: No specified WebACLs found in any region")
            return
        
        for region, webacls in found_webacls.items():
            print(f"\n--- Region: {region} ({len(webacls)} WebACLs found) ---")
            webacl_ids = [w['id'] for w in webacls]
            
            try:
                region_migrator = WAFMigrator(region=region)
                if args.analyze:
                    print("INFO: Analysis mode - no resources will be created")
                    analyze_webacls_in_region(region_migrator, region, webacl_ids)
                else:
                    print("INFO: Migration mode")
                    migrate_webacls_in_region(region_migrator, region, webacl_ids, args.migrate_logging)
            except Exception as e:
                print(f"ERROR: Failed to process region {region}: {str(e)}")

        # Generate final cumulative report after processing all regions
        if not args.analyze:
            _generate_final_cumulative_reports()
        return
    
    print("ERROR: Must specify --webacl-ids, --all-webacls, or --csv-file")

def handle_migrate_rulegroup(args):
    """Handle migrate-rulegroup command with all its variations"""
    
    # Enable global cumulative reporting mode if not in analyze mode
    if not args.analyze:
        _enable_global_cumulative_reporting()
    
    # Determine regions to process
    if args.all_regions:
        regions = WAFRegionManager.list_supported_regions()
    else:
        regions = args.regions.split(",") if args.regions else []
    
    # CSV file processing
    if args.csv_file:
        for csv_file in args.csv_file:
            print(f"=== Processing CSV file: {csv_file} ===")
            if args.analyze:
                print("INFO: Analysis mode - no resources will be created")
                process_rulegroup_csv_analysis(csv_file, None)
            else:
                print("INFO: Migration mode")
                process_rulegroup_csv_migration(csv_file, None)
        # Generate final cumulative report after processing all CSV files
        if not args.analyze:
            _generate_final_cumulative_reports()
        return
    
    # All RuleGroups processing
    if args.all_rulegroups:
        print(f"=== Processing all RuleGroups ===")
        # Use internal helper to get all RuleGroups across regions
        all_rulegroups = list_rulegroups_multi_region(regions, args.all_regions)
        
        if not all_rulegroups:
            print("INFO: No RuleGroups found in specified regions")
            return
        
        for region, rulegroups in all_rulegroups.items():
            print(f"\n--- Region: {region} ({len(rulegroups)} RuleGroups) ---")
            rulegroup_ids = [r['id'] for r in rulegroups]
            
            try:
                region_migrator = WAFMigrator(region=region)
                if args.analyze:
                    print("INFO: Analysis mode - no resources will be created")
                    analyze_rulegroups_in_region(region_migrator, region, rulegroup_ids)
                else:
                    print("INFO: Migration mode")
                    migrate_rulegroups_in_region(region_migrator, region, rulegroup_ids)
            except Exception as e:
                print(f"ERROR: Failed to process region {region}: {str(e)}")
        
        # Generate final cumulative report after processing all regions
        if not args.analyze:
            _generate_final_cumulative_reports()
        return
    
    # Specific RuleGroup IDs processing
    if args.rulegroup_ids:
        print(f"=== Processing specific RuleGroups ===")
        # Split comma-separated RuleGroup IDs
        rulegroup_ids = args.rulegroup_ids.split(',')
        # Use internal helper to find RuleGroups across regions
        found_rulegroups = search_rulegroups_multi_region(rulegroup_ids, regions, args.all_regions)
        
        if not found_rulegroups:
            print("ERROR: No specified RuleGroups found in any region")
            return
        
        for region, rulegroups in found_rulegroups.items():
            print(f"\n--- Region: {region} ({len(rulegroups)} RuleGroups found) ---")
            rulegroup_ids = [r['id'] for r in rulegroups]
            
            try:
                region_migrator = WAFMigrator(region=region)
                if args.analyze:
                    print("INFO: Analysis mode - no resources will be created")
                    analyze_rulegroups_in_region(region_migrator, region, rulegroup_ids)
                else:
                    print("INFO: Migration mode")
                    migrate_rulegroups_in_region(region_migrator, region, rulegroup_ids)
            except Exception as e:
                print(f"ERROR: Failed to process region {region}: {str(e)}")
        
        # Generate final cumulative report after processing all regions
        if not args.analyze:
            _generate_final_cumulative_reports()
        return
    
    print("ERROR: Must specify --rulegroup-ids, --all-rulegroups, or --csv-file")

if __name__ == '__main__':
    main()
