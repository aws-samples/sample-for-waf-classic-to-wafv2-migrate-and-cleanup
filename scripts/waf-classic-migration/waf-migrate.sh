#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# WAF Classic to v2 Migration Tool - Interactive Shell

export PYTHONWARNINGS="ignore"

# Script directory and helper paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CREDENTIALS_HELPER="$SCRIPT_DIR/../common/aws_credentials_helper.py"

# Function to check AWS credentials
check_credentials() {
    if python3 -c "import boto3; boto3.client('sts').get_caller_identity()" 2>/dev/null; then
        return 0  # Credentials work
    else
        return 1  # No credentials or they don't work
    fi
}

# Function to setup credentials interactively
setup_credentials() {
    echo
    echo "==============================================="
    echo "AWS Credentials Setup"
    echo "==============================================="
    echo
    if [ -f "$CREDENTIALS_HELPER" ]; then
        python3 "$CREDENTIALS_HELPER"
    else
        echo "Credentials helper not found. Please run 'aws configure' manually."
    fi
    echo
}

# Check for credential setup arguments
if [ "$1" = "--setup-credentials" ]; then
    setup_credentials
    exit 0
fi

if [ "$1" = "--check-credentials" ]; then
    echo
    echo "==============================================="
    echo "Checking AWS Credentials"
    echo "==============================================="
    echo
    if check_credentials; then
        echo "AWS credentials are configured and working"
    else
        echo "AWS credentials not found or not working"
        echo
        echo "Run: $0 --setup-credentials"
    fi
    exit 0
fi

# Check credentials before starting main tool
if ! check_credentials; then
    echo
    echo "==============================================="
    echo "AWS Credentials Required"
    echo "==============================================="
    echo
    echo "AWS credentials not found or not working!"
    echo
    echo "Options:"
    echo "1. Run: $0 --setup-credentials"
    echo "2. Run: aws configure"
    echo "3. Set environment variables"
    echo
    read -p "Would you like to set up credentials now? (y/N): " response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        setup_credentials
        echo "Please run the tool again after setting up credentials."
        exit 0
    else
        echo "Exiting. Set up credentials and try again."
        exit 1
    fi
fi

# Region selection
select_region() {
    echo
    echo "=== Region Selection ==="
    echo "Select region(s) - enter numbers separated by commas (e.g., 1,3,5):"
    echo "Or you can select all the 33 regions by typing \"all regions\""
    echo
    echo "Special:"
    echo "  1) cloudfront     - CloudFront (Global)"
    echo
    echo "US Regions:"
    echo "  2) us-east-1      - US East (N. Virginia)"
    echo "  3) us-east-2      - US East (Ohio)"
    echo "  4) us-west-1      - US West (N. California)"
    echo "  5) us-west-2      - US West (Oregon)"
    echo
    echo "US Government:"
    echo "  6) us-gov-east-1  - AWS GovCloud (US-East)"
    echo "  7) us-gov-west-1  - AWS GovCloud (US-West)"
    echo
    echo "Europe:"
    echo "  8) eu-west-1      - Europe (Ireland)"
    echo "  9) eu-west-2      - Europe (London)"
    echo " 10) eu-west-3      - Europe (Paris)"
    echo " 11) eu-central-1   - Europe (Frankfurt)"
    echo " 12) eu-central-2   - Europe (Zurich)"
    echo " 13) eu-north-1     - Europe (Stockholm)"
    echo " 14) eu-south-1     - Europe (Milan)"
    echo " 15) eu-south-2     - Europe (Spain)"
    echo
    echo "Asia Pacific:"
    echo " 16) ap-northeast-1 - Asia Pacific (Tokyo)"
    echo " 17) ap-northeast-2 - Asia Pacific (Seoul)"
    echo " 18) ap-northeast-3 - Asia Pacific (Osaka)"
    echo " 19) ap-southeast-1 - Asia Pacific (Singapore)"
    echo " 20) ap-southeast-2 - Asia Pacific (Sydney)"
    echo " 21) ap-southeast-3 - Asia Pacific (Jakarta)"
    echo " 22) ap-southeast-4 - Asia Pacific (Melbourne)"
    echo " 23) ap-south-1     - Asia Pacific (Mumbai)"
    echo " 24) ap-south-2     - Asia Pacific (Hyderabad)"
    echo " 25) ap-east-1      - Asia Pacific (Hong Kong)"
    echo
    echo "Other:"
    echo " 26) me-south-1     - Middle East (Bahrain)"
    echo " 27) me-central-1   - Middle East (UAE)"
    echo " 28) af-south-1     - Africa (Cape Town)"
    echo " 29) il-central-1   - Israel (Tel Aviv)"
    echo " 30) ca-central-1   - Canada (Central)"
    echo " 31) sa-east-1      - South America (São Paulo)"
    echo " 32) cn-north-1     - China (Beijing)"
    echo " 33) cn-northwest-1 - China (Ningxia)"
    echo
    echo " all regions) Selects all the 33 regions"
    echo
    echo " b) Back to setup"
    echo " q) Quit"
    echo
    read -p "Region numbers: " region_choices
    echo
    
    if [ "$region_choices" = "b" ] || [ "$region_choices" = "B" ]; then
        return
    fi
    
    if [ "$region_choices" = "q" ] || [ "$region_choices" = "Q" ]; then
        echo "Goodbye!"
        exit 0
    fi
    
    if [ "$region_choices" = "all regions" ] || [ "$region_choices" = "ALL REGIONs" ]; then
        SELECTED_REGIONS="all-regions"
        REGION="us-east-1"  # Use us-east-1 as default for initial processing
        return
    fi
    
    # Convert numbers to region names
    SELECTED_REGIONS=""
    IFS=',' read -ra REGION_CHOICES <<< "$region_choices"
    for choice in "${REGION_CHOICES[@]}"; do
        choice=$(echo "$choice" | xargs)  # trim whitespace
        case $choice in
            1) SELECTED_REGIONS="$SELECTED_REGIONS cloudfront" ;;
            2) SELECTED_REGIONS="$SELECTED_REGIONS us-east-1" ;;
            3) SELECTED_REGIONS="$SELECTED_REGIONS us-east-2" ;;
            4) SELECTED_REGIONS="$SELECTED_REGIONS us-west-1" ;;
            5) SELECTED_REGIONS="$SELECTED_REGIONS us-west-2" ;;
            6) SELECTED_REGIONS="$SELECTED_REGIONS us-gov-east-1" ;;
            7) SELECTED_REGIONS="$SELECTED_REGIONS us-gov-west-1" ;;
            8) SELECTED_REGIONS="$SELECTED_REGIONS eu-west-1" ;;
            9) SELECTED_REGIONS="$SELECTED_REGIONS eu-west-2" ;;
            10) SELECTED_REGIONS="$SELECTED_REGIONS eu-west-3" ;;
            11) SELECTED_REGIONS="$SELECTED_REGIONS eu-central-1" ;;
            12) SELECTED_REGIONS="$SELECTED_REGIONS eu-central-2" ;;
            13) SELECTED_REGIONS="$SELECTED_REGIONS eu-north-1" ;;
            14) SELECTED_REGIONS="$SELECTED_REGIONS eu-south-1" ;;
            15) SELECTED_REGIONS="$SELECTED_REGIONS eu-south-2" ;;
            16) SELECTED_REGIONS="$SELECTED_REGIONS ap-northeast-1" ;;
            17) SELECTED_REGIONS="$SELECTED_REGIONS ap-northeast-2" ;;
            18) SELECTED_REGIONS="$SELECTED_REGIONS ap-northeast-3" ;;
            19) SELECTED_REGIONS="$SELECTED_REGIONS ap-southeast-1" ;;
            20) SELECTED_REGIONS="$SELECTED_REGIONS ap-southeast-2" ;;
            21) SELECTED_REGIONS="$SELECTED_REGIONS ap-southeast-3" ;;
            22) SELECTED_REGIONS="$SELECTED_REGIONS ap-southeast-4" ;;
            23) SELECTED_REGIONS="$SELECTED_REGIONS ap-south-1" ;;
            24) SELECTED_REGIONS="$SELECTED_REGIONS ap-south-2" ;;
            25) SELECTED_REGIONS="$SELECTED_REGIONS ap-east-1" ;;
            26) SELECTED_REGIONS="$SELECTED_REGIONS me-south-1" ;;
            27) SELECTED_REGIONS="$SELECTED_REGIONS me-central-1" ;;
            28) SELECTED_REGIONS="$SELECTED_REGIONS af-south-1" ;;
            29) SELECTED_REGIONS="$SELECTED_REGIONS il-central-1" ;;
            30) SELECTED_REGIONS="$SELECTED_REGIONS ca-central-1" ;;
            31) SELECTED_REGIONS="$SELECTED_REGIONS sa-east-1" ;;
            32) SELECTED_REGIONS="$SELECTED_REGIONS cn-north-1" ;;
            33) SELECTED_REGIONS="$SELECTED_REGIONS cn-northwest-1" ;;
            *) echo "Invalid choice: $choice"; select_region; return ;;
        esac
    done
    
    if [ -z "$SELECTED_REGIONS" ]; then
        echo "No valid regions selected."
        select_region
        return
    fi
    
    REGION=$(echo $SELECTED_REGIONS | awk '{print $1}')  # Use first region for initial processing
}

webacl_region_menu() {
    select_region
    if [ -n "$SELECTED_REGIONS" ]; then
        if [ "$SELECTED_REGIONS" = "all-regions" ]; then
            # Handle all regions case
            REGION_DISPLAY="all regions"
            SELECTED_REGIONS_CMD="--all-regions"
        else
            # Store human-readable format
            REGION_DISPLAY="$SELECTED_REGIONS"
            # Convert to CLI format - replace spaces with commas for the --regions parameter
            REGION_LIST=$(echo $SELECTED_REGIONS | tr ' ' ',')
            SELECTED_REGIONS_CMD="--regions $REGION_LIST"
        fi
        webacl_selection_menu
    fi
}

webacl_selection_menu() {
    while true; do
        echo "=== WebACL Selection ==="
        echo "Regions: $REGION_DISPLAY"
        echo
        
        # Display available WebACLs
        echo "Available WebACLs in selected regions:"
        if [ "$SELECTED_REGIONS_CMD" = "--all-regions" ]; then
            python3 "$SCRIPT_DIR/../common/list_waf_resources.py" webacls "all-regions"
        else
            REGION_LIST=$(echo $SELECTED_REGIONS_CMD | sed 's/--regions //')
            python3 "$SCRIPT_DIR/../common/list_waf_resources.py" webacls "$REGION_LIST"
        fi
        echo
        
        echo "Select WebACLs:"
        echo
        echo "  a) All WebACLs in selected regions"
        echo "  s) Specific WebACLs by number (e.g., 1,3,5)"
        echo "  b) Back to region selection"
        echo "  q) Quit"
        echo
        read -p "Choice: " choice
        echo
        
        case $choice in
            a|A)
                WEBACL_SELECTION="--all-webacls"
                webacl_action_menu
                ;;
            s|S)
                echo
                read -p "Enter WebACL numbers (comma-separated, e.g., 1,2,3): " webacl_numbers
                if [[ -z "$webacl_numbers" ]]; then
                    echo "No WebACL numbers specified. Press Enter to continue..."
                    read
                    continue
                fi
                
                # Convert numbers to actual WebACL IDs and regions
                if [ "$SELECTED_REGIONS_CMD" = "--all-regions" ]; then
                    WEBACL_MAP=$(python3 "$SCRIPT_DIR/../common/list_waf_resources.py" webacls "all-regions" map)
                else
                    REGION_LIST=$(echo $SELECTED_REGIONS_CMD | sed 's/--regions //')
                    WEBACL_MAP=$(python3 "$SCRIPT_DIR/../common/list_waf_resources.py" webacls "$REGION_LIST" map)
                fi
                
                # Parse the selected numbers and build ID list and region list
                WEBACL_IDS=""
                WEBACL_REGIONS=""
                IFS=',' read -ra NUMBERS <<< "$webacl_numbers"
                for num in "${NUMBERS[@]}"; do
                    num=$(echo "$num" | xargs)  # trim whitespace
                    MAPPING=$(echo "$WEBACL_MAP" | grep "^$num:")
                    if [[ -n "$MAPPING" ]]; then
                        WEBACL_ID=$(echo "$MAPPING" | cut -d':' -f2)
                        WEBACL_REGION=$(echo "$MAPPING" | cut -d':' -f3)
                        if [[ -z "$WEBACL_IDS" ]]; then
                            WEBACL_IDS="$WEBACL_ID"
                        else
                            WEBACL_IDS="$WEBACL_IDS,$WEBACL_ID"
                        fi
                        # Collect unique regions
                        if [[ -z "$WEBACL_REGIONS" ]]; then
                            WEBACL_REGIONS="$WEBACL_REGION"
                        elif [[ "$WEBACL_REGIONS" != *"$WEBACL_REGION"* ]]; then
                            WEBACL_REGIONS="$WEBACL_REGIONS $WEBACL_REGION"
                        fi
                    else
                        echo "Warning: WebACL number $num not found, skipping..."
                    fi
                done
                
                if [[ -z "$WEBACL_IDS" ]]; then
                    echo "No valid WebACL numbers found. Press Enter to continue..."
                    read
                    continue
                fi
                
                WEBACL_SELECTION="--webacl-ids $WEBACL_IDS"
                # Convert space-separated regions to comma-separated for CLI
                REGION_LIST=$(echo $WEBACL_REGIONS | tr ' ' ',')
                SELECTED_REGIONS_CMD="--regions $REGION_LIST"
                webacl_action_menu
                ;;
            b|B) return ;;
            q|Q) echo "Goodbye!"; exit 0 ;;
            *) echo "Invalid choice. Press Enter to continue..."; read ;;
        esac
    done
}

webacl_action_menu() {
    while true; do
        echo "=== WebACL Action Selection ==="
        echo "Regions: $REGION_DISPLAY"
        echo
        echo "  a) Analyze WebACLs"
        echo "  m) Migrate WebACLs"
        echo "  b) Back to WebACL selection"
        echo "  q) Quit"
        echo
        read -p "Choice: " action
            echo
        
        case $action in
            a|A)
                echo
                echo "=== Analyzing WebACLs ==="
                python3 waf-migrator.py migrate-webacl $WEBACL_SELECTION $SELECTED_REGIONS_CMD --analyze
                echo
                echo "Analysis complete. Press Enter to continue..."
                read
                ;;
            m|M)
                echo
                echo "Do you want to migrate logging configuration?"
                echo "  y) Yes, migrate with logging"
                echo "  n) No, migrate without logging"
                echo
                read -p "Choice: " logging_choice
                    echo
                
                echo
                echo "=== Migrating WebACLs ==="
                if [[ "$logging_choice" =~ ^[Yy]$ ]]; then
                    python3 waf-migrator.py migrate-webacl $WEBACL_SELECTION $SELECTED_REGIONS_CMD --migrate-logging
                else
                    python3 waf-migrator.py migrate-webacl $WEBACL_SELECTION $SELECTED_REGIONS_CMD
                fi
                echo
                echo "Migration complete. Press Enter to continue..."
                read
                ;;
            b|B) return ;;
            q|Q) echo "Goodbye!"; exit 0 ;;
            *) echo "Invalid choice. Press Enter to continue..."; read ;;
        esac
    done
}

rulegroup_region_menu() {
    select_region
    if [ -n "$SELECTED_REGIONS" ]; then
        if [ "$SELECTED_REGIONS" = "all-regions" ]; then
            # Handle all regions case
            REGION_DISPLAY="all regions"
            SELECTED_REGIONS_CMD="--all-regions"
        else
            # Store human-readable format
            REGION_DISPLAY="$SELECTED_REGIONS"
            # Convert to CLI format - replace spaces with commas for the --regions parameter
            REGION_LIST=$(echo $SELECTED_REGIONS | tr ' ' ',')
            SELECTED_REGIONS_CMD="--regions $REGION_LIST"
        fi
        rulegroup_selection_menu
    fi
}

rulegroup_selection_menu() {
    while true; do
        echo "=== RuleGroup Selection ==="
        echo "Regions: $REGION_DISPLAY"
        echo
        
        # Display available RuleGroups
        echo "Available RuleGroups in selected regions:"
        if [ "$SELECTED_REGIONS_CMD" = "--all-regions" ]; then
            python3 "$SCRIPT_DIR/../common/list_waf_resources.py" rulegroups "all-regions"
        else
            REGION_LIST=$(echo $SELECTED_REGIONS_CMD | sed 's/--regions //')
            python3 "$SCRIPT_DIR/../common/list_waf_resources.py" rulegroups "$REGION_LIST"
        fi
        echo
        
        echo "Select RuleGroups:"
        echo
        echo "  a) All RuleGroups in selected regions"
        echo "  s) Specific RuleGroups by number (e.g., 1,3,5)"
        echo "  b) Back to region selection"
        echo "  q) Quit"
        echo
        read -p "Choice: " choice
        echo
        
        case $choice in
            a|A)
                RULEGROUP_SELECTION="--all-rulegroups"
                RULEGROUP_DISPLAY="all RuleGroups"
                rulegroup_action_menu
                ;;
            s|S)
                echo
                read -p "Enter RuleGroup numbers (comma-separated, e.g., 1,2,3): " rulegroup_numbers
                if [[ -z "$rulegroup_numbers" ]]; then
                    echo "No RuleGroup numbers specified. Press Enter to continue..."
                    read
                    continue
                fi
                
                # Convert numbers to actual RuleGroup IDs and regions
                if [ "$SELECTED_REGIONS_CMD" = "--all-regions" ]; then
                    RULEGROUP_MAP=$(python3 "$SCRIPT_DIR/../common/list_waf_resources.py" rulegroups "all-regions" map)
                else
                    REGION_LIST=$(echo $SELECTED_REGIONS_CMD | sed 's/--regions //')
                    RULEGROUP_MAP=$(python3 "$SCRIPT_DIR/../common/list_waf_resources.py" rulegroups "$REGION_LIST" map)
                fi
                
                # Parse the selected numbers and build ID list and region list
                RULEGROUP_IDS=""
                RULEGROUP_REGIONS=""
                IFS=',' read -ra NUMBERS <<< "$rulegroup_numbers"
                for num in "${NUMBERS[@]}"; do
                    num=$(echo "$num" | xargs)  # trim whitespace
                    MAPPING=$(echo "$RULEGROUP_MAP" | grep "^$num:")
                    if [[ -n "$MAPPING" ]]; then
                        RULEGROUP_ID=$(echo "$MAPPING" | cut -d':' -f2)
                        RULEGROUP_REGION=$(echo "$MAPPING" | cut -d':' -f3)
                        if [[ -z "$RULEGROUP_IDS" ]]; then
                            RULEGROUP_IDS="$RULEGROUP_ID"
                        else
                            RULEGROUP_IDS="$RULEGROUP_IDS,$RULEGROUP_ID"
                        fi
                        # Collect unique regions
                        if [[ -z "$RULEGROUP_REGIONS" ]]; then
                            RULEGROUP_REGIONS="$RULEGROUP_REGION"
                        elif [[ "$RULEGROUP_REGIONS" != *"$RULEGROUP_REGION"* ]]; then
                            RULEGROUP_REGIONS="$RULEGROUP_REGIONS $RULEGROUP_REGION"
                        fi
                    else
                        echo "Warning: RuleGroup number $num not found, skipping..."
                    fi
                done
                
                if [[ -z "$RULEGROUP_IDS" ]]; then
                    echo "No valid RuleGroup numbers found. Press Enter to continue..."
                    read
                    continue
                fi
                
                RULEGROUP_SELECTION="--rulegroup-ids $RULEGROUP_IDS"
                # Convert space-separated regions to comma-separated for CLI
                REGION_LIST=$(echo $RULEGROUP_REGIONS | tr ' ' ',')
                SELECTED_REGIONS_CMD="--regions $REGION_LIST"
                RULEGROUP_DISPLAY="Selected RuleGroups: $rulegroup_numbers"
                rulegroup_action_menu
                ;;
            b|B) return ;;
            q|Q) echo "Goodbye!"; exit 0 ;;
            *) echo "Invalid choice. Press Enter to continue..."; read ;;
        esac
    done
}

rulegroup_action_menu() {
    while true; do
        echo "=== RuleGroup Action Selection ==="
        echo "Regions: $REGION_DISPLAY"
        echo "RuleGroups: $RULEGROUP_DISPLAY"
        echo
        echo "  a) Analyze RuleGroups"
        echo "  m) Migrate RuleGroups"
        echo "  b) Back to RuleGroup selection"
        echo "  q) Quit"
        echo
        read -p "Choice: " action
            echo
        
        case $action in
            a|A)
                echo
                echo "=== Analyzing RuleGroups ==="
                python3 waf-migrator.py migrate-rulegroup $RULEGROUP_SELECTION $SELECTED_REGIONS_CMD --analyze
                echo
                echo "Analysis complete. Press Enter to continue..."
                read
                ;;
            m|M)
                echo
                echo "=== Migrating RuleGroups ==="
                python3 waf-migrator.py migrate-rulegroup $RULEGROUP_SELECTION $SELECTED_REGIONS_CMD
                echo
                echo "Migration complete. Press Enter to continue..."
                read
                ;;
            b|B) return ;;
            q|Q) echo "Goodbye!"; exit 0 ;;
            *) echo "Invalid choice. Press Enter to continue..."; read ;;
        esac
    done
}

# Export WebACL menu
export_webacl_menu() {
    echo "==============================================="
    echo "    Export WebACLs to CSV"
    echo "==============================================="
    echo
    select_regions_for_webacl_export "--all-webacls"
}

# Export RuleGroup menu
export_rulegroup_menu() {
    echo "==============================================="
    echo "    Export RuleGroups to CSV"
    echo "==============================================="
    echo
    select_regions_for_rulegroup_export "--all-rulegroups"
}

# Region selection for WebACL export
select_regions_for_webacl_export() {
    local base_args="$1"
    
    select_region
    if [ -n "$SELECTED_REGIONS" ]; then
        if [ "$SELECTED_REGIONS" = "all-regions" ]; then
            echo "Exporting all WebACLs from all regions..."
            python3 waf-migrator.py export-webacl $base_args --all-regions
        else
            # Convert space-separated to comma-separated
            REGION_LIST=$(echo $SELECTED_REGIONS | tr ' ' ',')
            echo "Exporting all WebACLs from regions: $REGION_LIST"
            python3 waf-migrator.py export-webacl $base_args --regions "$REGION_LIST"
        fi
        echo
        echo "Export complete. CSV file includes 'mark_for_migration' column set to 'MIGRATE'."
        echo "Press Enter to continue..."
        read
    fi
}

# Region selection for RuleGroup export
select_regions_for_rulegroup_export() {
    local base_args="$1"
    
    select_region
    if [ -n "$SELECTED_REGIONS" ]; then
        if [ "$SELECTED_REGIONS" = "all-regions" ]; then
            echo "Exporting all RuleGroups from all regions..."
            python3 waf-migrator.py export-rulegroup $base_args --all-regions
        else
            # Convert space-separated to comma-separated
            REGION_LIST=$(echo $SELECTED_REGIONS | tr ' ' ',')
            echo "Exporting all RuleGroups from regions: $REGION_LIST"
            python3 waf-migrator.py export-rulegroup $base_args --regions "$REGION_LIST"
        fi
        echo
        echo "Export complete. CSV file includes 'mark_for_migration' column set to 'MIGRATE'."
        echo "Press Enter to continue..."
        read
    fi
}

# Import CSV functions
import_webacl_csv() {
    echo "==============================================="
    echo "    Import WebACLs from CSV"
    echo "==============================================="
    echo
    echo "Note: Only resources with 'mark_for_migration' = 'MIGRATE' will be processed"
    echo
    echo "Enter CSV file path:"
    read -p "CSV file: " csv_file
    
    if [ ! -f "$csv_file" ]; then
        echo "ERROR: File not found: $csv_file"
        echo "Press Enter to continue..."
        read
        return
    fi
    
    echo
    echo "Select action:"
    echo "  1) Analyze only (safe preview)"
    echo "  2) Migrate marked resources"
    echo "  b) Back"
    echo "  q) Quit"
    echo
    read -p "Choice: " choice
    
    case $choice in
        1)
            echo "Analyzing WebACLs from CSV..."
            python3 waf-migrator.py migrate-webacl --csv-file "$csv_file" --analyze
            ;;
        2)
            echo "Migrating marked WebACLs..."
            read -p "Include logging configuration? (y/n): " logging
            if [ "$logging" = "y" ] || [ "$logging" = "Y" ]; then
                python3 waf-migrator.py migrate-webacl --csv-file "$csv_file" --migrate-logging
            else
                python3 waf-migrator.py migrate-webacl --csv-file "$csv_file"
            fi
            ;;
        b|B) return ;;
        q|Q) echo "Goodbye!"; exit 0 ;;
        *) echo "Invalid choice. Press Enter to continue..."; read ;;
    esac
    
    echo
    echo "Operation complete. Press Enter to continue..."
    read
}

import_rulegroup_csv() {
    echo "==============================================="
    echo "    Import RuleGroups from CSV"
    echo "==============================================="
    echo
    echo "Note: Only resources with 'mark_for_migration' = 'MIGRATE' will be processed"
    echo
    echo "Enter CSV file path:"
    read -p "CSV file: " csv_file
    
    if [ ! -f "$csv_file" ]; then
        echo "ERROR: File not found: $csv_file"
        echo "Press Enter to continue..."
        read
        return
    fi
    
    echo
    echo "Select action:"
    echo "  1) Analyze only (safe preview)"
    echo "  2) Migrate marked resources"
    echo "  b) Back"
    echo "  q) Quit"
    echo
    read -p "Choice: " choice
    
    case $choice in
        1)
            echo "Analyzing RuleGroups from CSV..."
            python3 waf-migrator.py migrate-rulegroup --csv-file "$csv_file" --analyze
            ;;
        2)
            echo "Migrating marked RuleGroups..."
            python3 waf-migrator.py migrate-rulegroup --csv-file "$csv_file"
            ;;
        b|B) return ;;
        q|Q) echo "Goodbye!"; exit 0 ;;
        *) echo "Invalid choice. Press Enter to continue..."; read ;;

    esac
    
    echo
    echo "Operation complete. Press Enter to continue..."
    read
}


main_menu() {
    while true; do
        echo "==============================================="
        echo "    AWS WAF Classic to WAFv2 Migration Tool"
        echo "==============================================="
        echo
        echo "Manual (Select resources manually):"
        echo "  1) Migrate WebACLs"
        echo "  2) Migrate RuleGroups"
        echo
        echo "Export to CSV (Generate CSV files for planning):"
        echo "  3) Export WebACLs"
        echo "  4) Export RuleGroups"
        echo
        echo "Import from CSV (Migrate resources from CSV file):"
        echo "  5) Import WebACLs"
        echo "  6) Import RuleGroups"
        echo
        echo "  q) Quit"
        echo
        read -p "Choice: " choice
        echo
        
        case $choice in
            1) webacl_region_menu ;;
            2) rulegroup_region_menu ;;
            3) export_webacl_menu ;;
            4) export_rulegroup_menu ;;
            5) import_webacl_csv ;;
            6) import_rulegroup_csv ;;
            q|Q) echo "Goodbye!"; exit 0 ;;
            *) echo "Invalid choice. Press Enter to continue..."; read ;;
        esac
    done
}


# Main entry point
cd "$SCRIPT_DIR"
main_menu
