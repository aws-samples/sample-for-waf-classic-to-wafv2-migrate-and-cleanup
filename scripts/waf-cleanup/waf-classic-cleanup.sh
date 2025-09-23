#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# WAF Classic (v1) Cleanup Tool - Interactive Shell

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
        REGION_DISPLAY="all regions"
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

    REGION_DISPLAY="$SELECTED_REGIONS"
    REGION=$(echo $SELECTED_REGIONS | awk '{print $1}')  # Use first region for initial processing
}

# Manual WebACL cleanup
manual_webacl_cleanup() {
    select_region
    if [ $? -ne 0 ]; then
        return
    fi
    
    # Convert regions for CLI
    if [ "$SELECTED_REGIONS" = "all-regions" ]; then
        REGION_CMD="--all-regions"
    else
        REGION_LIST=$(echo $SELECTED_REGIONS | tr ' ' ',')
        REGION_CMD="--regions $REGION_LIST"
    fi
    
    while true; do
        echo
        echo "==============================================="
        echo "    Manual WebACL Cleanup"
        echo "==============================================="
        echo "Regions: $REGION_DISPLAY"
        echo
        
        # List available WebACLs
        echo "Available WebACLs:"
        if [ "$SELECTED_REGIONS" = "all-regions" ]; then
            python3 "$SCRIPT_DIR/../common/list_waf_resources.py" webacls "all-regions"
        else
            python3 "$SCRIPT_DIR/../common/list_waf_resources.py" webacls "$REGION_LIST"
        fi
        echo
        
        echo "Select WebACLs:"
        echo "  a) All WebACLs"
        echo "  s) Specific WebACLs by number (e.g., 1,3,5)"
        echo "  b) Back"
        echo "  q) Quit"
        echo
        read -p "Choice: " choice
        
        case $choice in
            a|A)
                WEBACL_CMD="--all-webacls"
                manual_webacl_action "$REGION_CMD" "$WEBACL_CMD"
                ;;
            s|S)
                echo
                read -p "Enter WebACL numbers (comma-separated): " webacl_numbers
                if [[ -n "$webacl_numbers" ]]; then
                    # Convert numbers to IDs
                    if [ "$SELECTED_REGIONS" = "all-regions" ]; then
                        WEBACL_MAP=$(python3 "$SCRIPT_DIR/../common/list_waf_resources.py" webacls "all-regions" map)
                    else
                        WEBACL_MAP=$(python3 "$SCRIPT_DIR/../common/list_waf_resources.py" webacls "$REGION_LIST" map)
                    fi
                    
                    WEBACL_IDS=""
                    IFS=',' read -ra NUMBERS <<< "$webacl_numbers"
                    for num in "${NUMBERS[@]}"; do
                        num=$(echo "$num" | xargs)
                        MAPPING=$(echo "$WEBACL_MAP" | grep "^$num:")
                        if [[ -n "$MAPPING" ]]; then
                            WEBACL_ID=$(echo "$MAPPING" | cut -d':' -f2)
                            if [[ -z "$WEBACL_IDS" ]]; then
                                WEBACL_IDS="$WEBACL_ID"
                            else
                                WEBACL_IDS="$WEBACL_IDS,$WEBACL_ID"
                            fi
                        fi
                    done
                    
                    if [[ -n "$WEBACL_IDS" ]]; then
                        WEBACL_CMD="--webacl-ids $WEBACL_IDS"
                        manual_webacl_action "$REGION_CMD" "$WEBACL_CMD"
                    fi
                fi
                ;;
            b|B) return ;;
            q|Q) echo "Goodbye!"; exit 0 ;;
        esac
    done
}

# Manual WebACL action menu
manual_webacl_action() {
    local region_cmd="$1"
    local webacl_cmd="$2"
    
    while true; do
        echo
        echo "Select action:"
        echo "  1) Analyze"
        echo "  2) Delete"
        echo "  b) Back"
        echo "  q) Quit"
        echo
        read -p "Choice: " choice
        
        case $choice in
            1)
                echo
                echo "=== Analyzing WebACLs ==="
                python3 waf-classic-cleanup.py $webacl_cmd $region_cmd --analyze
                echo
                echo "Press Enter to continue..."
                read
                ;;
            2)
                echo
                echo "WARNING: This will DELETE the selected WebACLs!"
                echo
                echo "=== Deleting WebACLs ==="
                python3 waf-classic-cleanup.py $webacl_cmd $region_cmd
                echo
                echo "Press Enter to continue..."
                read
                ;;
            b|B) return ;;
            q|Q) echo "Goodbye!"; exit 0 ;;
        esac
    done
}

# Manual RuleGroup cleanup
manual_rulegroup_cleanup() {
    select_region
    if [ $? -ne 0 ]; then
        return
    fi
    
    # Convert regions for CLI
    if [ "$SELECTED_REGIONS" = "all-regions" ]; then
        REGION_CMD="--all-regions"
    else
        REGION_LIST=$(echo $SELECTED_REGIONS | tr ' ' ',')
        REGION_CMD="--regions $REGION_LIST"
    fi
    
    while true; do
        echo
        echo "==============================================="
        echo "    Manual RuleGroup Cleanup"
        echo "==============================================="
        echo "Regions: $REGION_DISPLAY"
        echo
        
        # List available RuleGroups
        echo "Available RuleGroups:"
        if [ "$SELECTED_REGIONS" = "all-regions" ]; then
            python3 "$SCRIPT_DIR/../common/list_waf_resources.py" rulegroups "all-regions"
        else
            python3 "$SCRIPT_DIR/../common/list_waf_resources.py" rulegroups "$REGION_LIST"
        fi
        echo
        
        echo "Select RuleGroups:"
        echo "  a) All RuleGroups"
        echo "  s) Specific RuleGroups by number (e.g., 1,3,5)"
        echo "  b) Back"
        echo "  q) Quit"
        echo
        read -p "Choice: " choice
        
        case $choice in
            a|A)
                RULEGROUP_CMD="--all-rulegroups"
                manual_rulegroup_action "$REGION_CMD" "$RULEGROUP_CMD"
                ;;
            s|S)
                echo
                read -p "Enter RuleGroup numbers (comma-separated): " rulegroup_numbers
                if [[ -n "$rulegroup_numbers" ]]; then
                    # Convert numbers to IDs
                    if [ "$SELECTED_REGIONS" = "all-regions" ]; then
                        RULEGROUP_MAP=$(python3 "$SCRIPT_DIR/../common/list_waf_resources.py" rulegroups "all-regions" map)
                    else
                        RULEGROUP_MAP=$(python3 "$SCRIPT_DIR/../common/list_waf_resources.py" rulegroups "$REGION_LIST" map)
                    fi
                    
                    RULEGROUP_IDS=""
                    IFS=',' read -ra NUMBERS <<< "$rulegroup_numbers"
                    for num in "${NUMBERS[@]}"; do
                        num=$(echo "$num" | xargs)
                        MAPPING=$(echo "$RULEGROUP_MAP" | grep "^$num:")
                        if [[ -n "$MAPPING" ]]; then
                            RULEGROUP_ID=$(echo "$MAPPING" | cut -d':' -f2)
                            if [[ -z "$RULEGROUP_IDS" ]]; then
                                RULEGROUP_IDS="$RULEGROUP_ID"
                            else
                                RULEGROUP_IDS="$RULEGROUP_IDS,$RULEGROUP_ID"
                            fi
                        fi
                    done
                    
                    if [[ -n "$RULEGROUP_IDS" ]]; then
                        RULEGROUP_CMD="--rulegroup-ids $RULEGROUP_IDS"
                        manual_rulegroup_action "$REGION_CMD" "$RULEGROUP_CMD"
                    fi
                fi
                ;;
            b|B) return ;;
            q|Q) echo "Goodbye!"; exit 0 ;;
        esac
    done
}

# Manual RuleGroup action menu
manual_rulegroup_action() {
    local region_cmd="$1"
    local rulegroup_cmd="$2"
    
    while true; do
        echo
        echo "Select action:"
        echo "  1) Analyze"
        echo "  2) Delete"
        echo "  b) Back"
        echo "  q) Quit"
        echo
        read -p "Choice: " choice
        
        case $choice in
            1)
                echo
                echo "=== Analyzing RuleGroups ==="
                python3 waf-classic-cleanup.py $rulegroup_cmd $region_cmd --analyze
                echo
                echo "Press Enter to continue..."
                read
                ;;
            2)
                echo
                echo "WARNING: This will DELETE the selected RuleGroups!"
                echo
                echo "=== Deleting RuleGroups ==="
                python3 waf-classic-cleanup.py $rulegroup_cmd $region_cmd
                echo
                echo "Press Enter to continue..."
                read
                ;;
            b|B) return ;;
            q|Q) echo "Goodbye!"; exit 0 ;;
        esac
    done
}

# Manual Rule cleanup
manual_rule_cleanup() {
    select_region
    if [ $? -ne 0 ]; then
        return
    fi
    
    # Convert regions for CLI
    if [ "$SELECTED_REGIONS" = "all-regions" ]; then
        REGION_CMD="--all-regions"
    else
        REGION_LIST=$(echo $SELECTED_REGIONS | tr ' ' ',')
        REGION_CMD="--regions $REGION_LIST"
    fi
    
    while true; do
        echo
        echo "==============================================="
        echo "    Manual Rule Cleanup"
        echo "==============================================="
        echo "Regions: $REGION_DISPLAY"
        echo
        
        # List available Rules
        echo "Available Rules:"
        if [ "$SELECTED_REGIONS" = "all-regions" ]; then
            python3 "$SCRIPT_DIR/../common/list_waf_resources.py" rules "all-regions"
        else
            python3 "$SCRIPT_DIR/../common/list_waf_resources.py" rules "$REGION_LIST"
        fi
        echo
        
        echo "Select Rules:"
        echo "  a) All Rules"
        echo "  s) Specific Rules by number (e.g., 1,3,5)"
        echo "  b) Back"
        echo "  q) Quit"
        echo
        read -p "Choice: " choice
        
        case $choice in
            a|A)
                RULE_CMD="--all-rules"
                manual_rule_action "$REGION_CMD" "$RULE_CMD"
                ;;
            s|S)
                echo
                read -p "Enter Rule numbers (comma-separated): " rule_numbers
                if [[ -n "$rule_numbers" ]]; then
                    # Convert numbers to IDs
                    if [ "$SELECTED_REGIONS" = "all-regions" ]; then
                        RULE_MAP=$(python3 "$SCRIPT_DIR/../common/list_waf_resources.py" rules "all-regions" map)
                    else
                        RULE_MAP=$(python3 "$SCRIPT_DIR/../common/list_waf_resources.py" rules "$REGION_LIST" map)
                    fi
                    
                    RULE_IDS=""
                    IFS=',' read -ra NUMBERS <<< "$rule_numbers"
                    for num in "${NUMBERS[@]}"; do
                        num=$(echo "$num" | xargs)
                        MAPPING=$(echo "$RULE_MAP" | grep "^$num:")
                        if [[ -n "$MAPPING" ]]; then
                            RULE_ID=$(echo "$MAPPING" | cut -d':' -f2)
                            if [[ -z "$RULE_IDS" ]]; then
                                RULE_IDS="$RULE_ID"
                            else
                                RULE_IDS="$RULE_IDS,$RULE_ID"
                            fi
                        fi
                    done
                    
                    if [[ -n "$RULE_IDS" ]]; then
                        RULE_CMD="--rule-ids $RULE_IDS"
                        manual_rule_action "$REGION_CMD" "$RULE_CMD"
                    fi
                fi
                ;;
            b|B) return ;;
            q|Q) echo "Goodbye!"; exit 0 ;;
        esac
    done
}

# Manual Rule action menu
manual_rule_action() {
    local region_cmd="$1"
    local rule_cmd="$2"
    
    while true; do
        echo
        echo "Select action:"
        echo "  1) Analyze"
        echo "  2) Delete"
        echo "  b) Back"
        echo "  q) Quit"
        echo
        read -p "Choice: " choice
        
        case $choice in
            1)
                echo
                echo "=== Analyzing Rules ==="
                python3 waf-classic-cleanup.py $rule_cmd $region_cmd --analyze
                echo
                echo "Press Enter to continue..."
                read
                ;;
            2)
                echo
                echo "WARNING: This will DELETE the selected Rules!"
                echo
                echo "=== Deleting Rules ==="
                python3 waf-classic-cleanup.py $rule_cmd $region_cmd
                echo
                echo "Press Enter to continue..."
                read
                ;;
            b|B) return ;;
            q|Q) echo "Goodbye!"; exit 0 ;;
        esac
    done
}

# Manual Condition cleanup
manual_condition_cleanup() {
    select_region
    if [ $? -ne 0 ]; then
        return
    fi
    
    # Convert regions for CLI
    if [ "$SELECTED_REGIONS" = "all-regions" ]; then
        REGION_CMD="--all-regions"
    else
        REGION_LIST=$(echo $SELECTED_REGIONS | tr ' ' ',')
        REGION_CMD="--regions $REGION_LIST"
    fi
    
    while true; do
        echo
        echo "==============================================="
        echo "    Manual Condition Cleanup"
        echo "==============================================="
        echo "Regions: $REGION_DISPLAY"
        echo
        
        # List available Conditions
        echo "Available Conditions:"
        if [ "$SELECTED_REGIONS" = "all-regions" ]; then
            python3 "$SCRIPT_DIR/../common/list_waf_resources.py" conditions "all-regions"
        else
            python3 "$SCRIPT_DIR/../common/list_waf_resources.py" conditions "$REGION_LIST"
        fi
        echo
        
        echo "Select Conditions:"
        echo "  a) All Conditions"
        echo "  s) Specific Conditions by number (e.g., 1,3,5)"
        echo "  b) Back"
        echo "  q) Quit"
        echo
        read -p "Choice: " choice
        
        case $choice in
            a|A)
                CONDITION_CMD="--all-conditions"
                manual_condition_action "$REGION_CMD" "$CONDITION_CMD"
                ;;
            s|S)
                echo
                read -p "Enter Condition numbers (comma-separated): " condition_numbers
                if [[ -n "$condition_numbers" ]]; then
                    # Convert numbers to IDs
                    if [ "$SELECTED_REGIONS" = "all-regions" ]; then
                        CONDITION_MAP=$(python3 "$SCRIPT_DIR/../common/list_waf_resources.py" conditions "all-regions" map)
                    else
                        CONDITION_MAP=$(python3 "$SCRIPT_DIR/../common/list_waf_resources.py" conditions "$REGION_LIST" map)
                    fi
                    
                    CONDITION_IDS=""
                    IFS=',' read -ra NUMBERS <<< "$condition_numbers"
                    for num in "${NUMBERS[@]}"; do
                        num=$(echo "$num" | xargs)
                        MAPPING=$(echo "$CONDITION_MAP" | grep "^$num:")
                        if [[ -n "$MAPPING" ]]; then
                            CONDITION_ID=$(echo "$MAPPING" | cut -d':' -f2)
                            if [[ -z "$CONDITION_IDS" ]]; then
                                CONDITION_IDS="$CONDITION_ID"
                            else
                                CONDITION_IDS="$CONDITION_IDS,$CONDITION_ID"
                            fi
                        fi
                    done
                    
                    if [[ -n "$CONDITION_IDS" ]]; then
                        CONDITION_CMD="--condition-ids $CONDITION_IDS"
                        manual_condition_action "$REGION_CMD" "$CONDITION_CMD"
                    fi
                fi
                ;;
            b|B) return ;;
            q|Q) echo "Goodbye!"; exit 0 ;;
        esac
    done
}

# Manual Condition action menu
manual_condition_action() {
    local region_cmd="$1"
    local condition_cmd="$2"
    
    while true; do
        echo
        echo "Select action:"
        echo "  1) Analyze"
        echo "  2) Delete"
        echo "  b) Back"
        echo "  q) Quit"
        echo
        read -p "Choice: " choice
        
        case $choice in
            1)
                echo
                echo "=== Analyzing Conditions ==="
                python3 waf-classic-cleanup.py $condition_cmd $region_cmd --analyze
                echo
                echo "Press Enter to continue..."
                read
                ;;
            2)
                echo
                echo "WARNING: This will DELETE the selected Conditions!"
                echo
                echo "=== Deleting Conditions ==="
                python3 waf-classic-cleanup.py $condition_cmd $region_cmd
                echo
                echo "Press Enter to continue..."
                read
                ;;
            b|B) return ;;
            q|Q) echo "Goodbye!"; exit 0 ;;
        esac
    done
}

# Export WebACL to CSV
export_webacl_csv() {
    select_region
    if [ $? -ne 0 ]; then
        return
    fi
    
    # Convert regions for CLI
    if [ "$SELECTED_REGIONS" = "all-regions" ]; then
        REGION_CMD="--all-regions"
    else
        REGION_LIST=$(echo $SELECTED_REGIONS | tr ' ' ',')
        REGION_CMD="--regions $REGION_LIST"
    fi
    
    echo
    echo "==============================================="
    echo "    Export WebACLs to CSV"
    echo "==============================================="
    echo "Regions: $REGION_DISPLAY"
    echo
    echo "Exporting all WebACLs..."
    python3 waf-classic-cleanup.py export-webacl --all-webacls $REGION_CMD
    echo
    echo "Export complete. CSV file includes 'mark_for_deletion' column set to 'DELETE'."
    echo "Press Enter to continue..."
    read
}

# Export RuleGroup to CSV
export_rulegroup_csv() {
    select_region
    if [ $? -ne 0 ]; then
        return
    fi
    
    # Convert regions for CLI
    if [ "$SELECTED_REGIONS" = "all-regions" ]; then
        REGION_CMD="--all-regions"
    else
        REGION_LIST=$(echo $SELECTED_REGIONS | tr ' ' ',')
        REGION_CMD="--regions $REGION_LIST"
    fi
    
    echo
    echo "==============================================="
    echo "    Export RuleGroups to CSV"
    echo "==============================================="
    echo "Regions: $REGION_DISPLAY"
    echo
    echo "Exporting all RuleGroups..."
    python3 waf-classic-cleanup.py export-rulegroup --all-rulegroups $REGION_CMD
    echo
    echo "Export complete. CSV file includes 'mark_for_deletion' column set to 'DELETE'."
    echo "Press Enter to continue..."
    read
}

# Export Rule to CSV
export_rule_csv() {
    select_region
    if [ $? -ne 0 ]; then
        return
    fi
    
    # Convert regions for CLI
    if [ "$SELECTED_REGIONS" = "all-regions" ]; then
        REGION_CMD="--all-regions"
    else
        REGION_LIST=$(echo $SELECTED_REGIONS | tr ' ' ',')
        REGION_CMD="--regions $REGION_LIST"
    fi
    
    echo
    echo "==============================================="
    echo "    Export Rules to CSV"
    echo "==============================================="
    echo "Regions: $REGION_DISPLAY"
    echo
    echo "Exporting all Rules..."
    python3 waf-classic-cleanup.py export-rule --all-rules $REGION_CMD
    echo
    echo "Export complete. CSV file includes 'mark_for_deletion' column set to 'DELETE'."
    echo "Press Enter to continue..."
    read
}

# Export Condition to CSV
export_condition_csv() {
    select_region
    if [ $? -ne 0 ]; then
        return
    fi
    
    # Convert regions for CLI
    if [ "$SELECTED_REGIONS" = "all-regions" ]; then
        REGION_CMD="--all-regions"
    else
        REGION_LIST=$(echo $SELECTED_REGIONS | tr ' ' ',')
        REGION_CMD="--regions $REGION_LIST"
    fi
    
    echo
    echo "==============================================="
    echo "    Export Conditions to CSV"
    echo "==============================================="
    echo "Regions: $REGION_DISPLAY"
    echo
    echo "Exporting all Conditions..."
    python3 waf-classic-cleanup.py export-condition --all-conditions $REGION_CMD
    echo
    echo "Export complete. CSV file includes 'mark_for_deletion' column set to 'DELETE'."
    echo "Press Enter to continue..."
    read
}

# Import WebACL from CSV
import_webacl_csv() {
    echo
    echo "==============================================="
    echo "    Import WebACLs from CSV"
    echo "==============================================="
    echo
    echo "Note: Only resources with 'mark_for_deletion' = 'DELETE' will be processed"
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
    echo "  2) Delete marked resources"
    echo "  b) Back"
    echo "  q) Quit"
    echo
    read -p "Choice: " choice
    
    case $choice in
        1)
            echo
            echo "=== Analyzing WebACLs from CSV ==="
            python3 waf-classic-cleanup.py --csv-file "$csv_file" --resource-type webacls --analyze
            echo
            echo "Press Enter to continue..."
            read
            ;;
        2)
            echo
            echo "WARNING: This will DELETE the marked WebACLs!"
            echo
            echo "=== Deleting WebACLs from CSV ==="
            python3 waf-classic-cleanup.py --csv-file "$csv_file" --resource-type webacls
            echo
            echo "Press Enter to continue..."
            read
            ;;
        b|B) return ;;
        q|Q) echo "Goodbye!"; exit 0 ;;
    esac
}

# Import RuleGroup from CSV
import_rulegroup_csv() {
    echo
    echo "==============================================="
    echo "    Import RuleGroups from CSV"
    echo "==============================================="
    echo
    echo "Note: Only resources with 'mark_for_deletion' = 'DELETE' will be processed"
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
    echo "  2) Delete marked resources"
    echo "  b) Back"
    echo "  q) Quit"
    echo
    read -p "Choice: " choice
    
    case $choice in
        1)
            echo
            echo "=== Analyzing RuleGroups from CSV ==="
            python3 waf-classic-cleanup.py --csv-file "$csv_file" --resource-type rulegroups --analyze
            echo
            echo "Press Enter to continue..."
            read
            ;;
        2)
            echo
            echo "WARNING: This will DELETE the marked RuleGroups!"
            echo
            echo "=== Deleting RuleGroups from CSV ==="
            python3 waf-classic-cleanup.py --csv-file "$csv_file" --resource-type rulegroups
            echo
            echo "Press Enter to continue..."
            read
            ;;
        b|B) return ;;
        q|Q) echo "Goodbye!"; exit 0 ;;
    esac
}

# Import Rule from CSV
import_rule_csv() {
    echo
    echo "==============================================="
    echo "    Import Rules from CSV"
    echo "==============================================="
    echo
    echo "Note: Only resources with 'mark_for_deletion' = 'DELETE' will be processed"
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
    echo "  2) Delete marked resources"
    echo "  b) Back"
    echo "  q) Quit"
    echo
    read -p "Choice: " choice
    
    case $choice in
        1)
            echo
            echo "=== Analyzing Rules from CSV ==="
            python3 waf-classic-cleanup.py --csv-file "$csv_file" --resource-type rules --analyze
            echo
            echo "Press Enter to continue..."
            read
            ;;
        2)
            echo
            echo "WARNING: This will DELETE the marked Rules!"
            echo
            echo "=== Deleting Rules from CSV ==="
            python3 waf-classic-cleanup.py --csv-file "$csv_file" --resource-type rules
            echo
            echo "Press Enter to continue..."
            read
            ;;
        b|B) return ;;
        q|Q) echo "Goodbye!"; exit 0 ;;
    esac
}

# Import Condition from CSV
import_condition_csv() {
    echo
    echo "==============================================="
    echo "    Import Conditions from CSV"
    echo "==============================================="
    echo
    echo "Note: Only resources with 'mark_for_deletion' = 'DELETE' will be processed"
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
    echo "  2) Delete marked resources"
    echo "  b) Back"
    echo "  q) Quit"
    echo
    read -p "Choice: " choice
    
    case $choice in
        1)
            echo
            echo "=== Analyzing Conditions from CSV ==="
            python3 waf-classic-cleanup.py --csv-file "$csv_file" --resource-type conditions --analyze
            echo
            echo "Press Enter to continue..."
            read
            ;;
        2)
            echo
            echo "WARNING: This will DELETE the marked Conditions!"
            echo
            echo "=== Deleting Conditions from CSV ==="
            python3 waf-classic-cleanup.py --csv-file "$csv_file" --resource-type conditions
            echo
            echo "Press Enter to continue..."
            read
            ;;
        b|B) return ;;
        q|Q) echo "Goodbye!"; exit 0 ;;
    esac
}

# Delete All Resources function
delete_all_resources() {
    select_region
    if [ $? -ne 0 ]; then
        return
    fi
    
    # Convert regions for CLI
    if [ "$SELECTED_REGIONS" = "all-regions" ]; then
        REGION_CMD="--all-regions"
    else
        REGION_LIST=$(echo $SELECTED_REGIONS | tr ' ' ',')
        REGION_CMD="--regions $REGION_LIST"
    fi
    
    echo
    echo "==============================================="
    echo "    DELETE ALL RESOURCES"
    echo "==============================================="
    echo "Regions: $REGION_DISPLAY"
    echo
    echo "WARNING: This operation will DELETE ALL WAF Classic resources in the selected region(s)!"
    echo
    echo "This includes:"
    echo "  • ALL WebACLs"
    echo "  • ALL RuleGroups"
    echo "  • ALL Rules"
    echo "  • ALL Conditions (IPSets, ByteMatchSets, etc.)"
    echo
    echo "Resources will be deleted in the following order:"
    echo "  1. WebACLs (to remove dependencies)"
    echo "  2. RuleGroups"
    echo "  3. Rules"
    echo "  4. Conditions"
    echo
    echo "This operation CANNOT be undone!"
    echo
    echo "To confirm, type 'DELETE ALL' (case sensitive):"
    read -p "> " confirmation
    
    if [ "$confirmation" != "DELETE ALL" ]; then
        echo
        echo "Operation cancelled."
        echo "Press Enter to continue..."
        read
        return
    fi
    
    echo
    echo "=== DELETING ALL RESOURCES ==="
    echo
    python3 waf-classic-cleanup.py --delete-all $REGION_CMD
    echo
    echo "Delete operation complete."
    echo "Press Enter to continue..."
    read
}

# Main menu
main_menu() {
    while true; do
        echo
        echo "==============================================="
        echo "    AWS WAF Classic Cleanup Tool"
        echo "==============================================="
        echo
        echo "Manual (Select resources manually):"
        echo "  1) Cleanup WebACLs"
        echo "  2) Cleanup RuleGroups"
        echo "  3) Cleanup Rules"
        echo "  4) Cleanup Conditions"
        echo
        echo "Export to CSV (Generate CSV files for planning):"
        echo "  5) Export WebACLs"
        echo "  6) Export RuleGroups"
        echo "  7) Export Rules"
        echo "  8) Export Conditions"
        echo
        echo "Import from CSV (Cleanup resources from CSV file):"
        echo "  9) Import WebACLs"
        echo " 10) Import RuleGroups"
        echo " 11) Import Rules"
        echo " 12) Import Conditions"
        echo
        echo "Bulk Operations:"
        echo " 13) DELETE ALL RESOURCES (CAUTION)"
        echo
        echo "  q) Quit"
        echo
        read -p "Choice: " choice
        echo
        
        case $choice in
            1) manual_webacl_cleanup ;;
            2) manual_rulegroup_cleanup ;;
            3) manual_rule_cleanup ;;
            4) manual_condition_cleanup ;;
            5) export_webacl_csv ;;
            6) export_rulegroup_csv ;;
            7) export_rule_csv ;;
            8) export_condition_csv ;;
            9) import_webacl_csv ;;
            10) import_rulegroup_csv ;;
            11) import_rule_csv ;;
            12) import_condition_csv ;;
            13) delete_all_resources ;;
            q|Q) echo "Goodbye!"; exit 0 ;;
            *) echo "Invalid choice. Press Enter to continue..."; read ;;
        esac
    done
}

# Main entry point
cd "$SCRIPT_DIR"
main_menu
