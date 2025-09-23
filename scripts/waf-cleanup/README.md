# WAF Classic WebACL Cleanup Tool

An interactive CLI tool for managing AWS WAF Classic WebACLs across multiple regions. This tool helps identify unused WebACLs and provides safe cleanup options with CSV export/import capabilities.

## Features

- **List all WAF Classic WebACLs/RuleGroups/Rules/Conditions** in your AWS account (both regional and global)
- **Multi-region support** - run against single region, multiple regions, or all supported regions
- 🔗 **Check associations** with:
  - Application Load Balancers (ALBs)
  - API Gateway REST APIs
  - CloudFront Distributions (only when 'cloudfront' pseudo-region is included)
- **Identify unassociated WebACLs** that may be safe to delete
- **CSV export/import** for bulk operations and audit trails
- **Interactive cleanup** with confirmation prompts
- **Safety features** to prevent accidental deletions
- **Global and Regional support** - handles both regional WebACLs and global WebACLs for CloudFront

## Supported Regions

WAF Classic is supported in the following 32 AWS regions, plus a special "cloudfront" pseudo-region:

- **US Regions:** us-east-1, us-east-2, us-west-1, us-west-2
- **US Government Regions:** us-gov-east-1, us-gov-west-1
- **Europe Regions:** eu-west-1, eu-west-2, eu-west-3, eu-central-1, eu-central-2, eu-north-1, eu-south-1, eu-south-2
- **Asia Pacific Regions:** ap-northeast-1, ap-northeast-2, ap-northeast-3, ap-southeast-1, ap-southeast-2, ap-southeast-3, ap-southeast-4, ap-south-1, ap-south-2, ap-east-1
- **Middle East Regions:** me-south-1, me-central-1
- **Africa Regions:** af-south-1
- **Israel Regions:** il-central-1
- **Canada Regions:** ca-central-1
- **South America Regions:** sa-east-1
- **China Regions:** cn-north-1, cn-northwest-1
- **Special Pseudo-Region:** cloudfront (for global WebACLs and CloudFront associations)


**Special Considerations:**
- **China Regions (cn-north-1, cn-northwest-1):** Require special AWS credentials and may have different access patterns
- **GovCloud Regions (us-gov-east-1, us-gov-west-1):** Require GovCloud-specific AWS credentials
- **CloudFront Pseudo-Region:** Use "cloudfront" to include global WebACLs and CloudFront distribution associations
- **Newer Regions:** Some regions may have limited WAF Classic usage as AWS encourages migration to WAF v2

## Prerequisites

- Python 3.6 or higher
- AWS CLI configured with appropriate credentials
- Required AWS permissions (see below)

## Installation

1. **Install Python dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```

2. **Make the script executable:**
   ```bash
   chmod +x waf-classic-cleanup.py
   chmod +x waf-classic-cleanup.sh
   cd ../common && chmod +x aws_credentials_helper.py
   ```

3. **Set up AWS credentials (if not already configured):**
   ```bash
   ./waf-classic-cleanup.sh --setup-credentials
   ```

## Usage

### Basic Usage

```bash
# Interactive shell wrapper (recommended)
./waf-classic-cleanup.sh

# Direct Python usage examples:

# Analyze all WebACLs in a single region
python3 waf-classic-cleanup.py --all-webacls --regions us-east-1 --analyze

# Analyze all resources across all regions
python3 waf-classic-cleanup.py --all-webacls --all-regions --analyze

# Delete specific WebACLs
python3 waf-classic-cleanup.py --webacl-ids WEBACL_ID1,WEBACL_ID2 --regions us-east-1

# Delete all WebACLs in multiple regions
python3 waf-classic-cleanup.py --all-webacls --regions us-east-1,us-west-2

# Export WebACLs to CSV
python3 waf-classic-cleanup.py export-webacl --all-webacls --regions us-east-1

# Import and delete WebACLs from CSV
python3 waf-classic-cleanup.py --csv-file webacls.csv --resource-type webacls

# Delete all resources (WebACLs, RuleGroups, Rules, Conditions)
python3 waf-classic-cleanup.py --delete-all --all-regions

# RuleGroups operations
python3 waf-classic-cleanup.py --all-rulegroups --regions us-east-1 --analyze
python3 waf-classic-cleanup.py export-rulegroup --all-rulegroups --regions us-east-1

# Rules operations  
python3 waf-classic-cleanup.py --all-rules --regions us-east-1 --analyze
python3 waf-classic-cleanup.py export-rule --all-rules --regions us-east-1

# Conditions operations
python3 waf-classic-cleanup.py --all-conditions --regions us-east-1 --analyze
python3 waf-classic-cleanup.py export-condition --all-conditions --regions us-east-1
```

**Note:** When using `--all-regions`, the tool will attempt to access WAF services in all supported regions. Ensure your credentials have the necessary permissions across all target regions.

**Note** It is advised to delete your Webacls and Rulegroups and then use the delete all option to delete the remaining rules and conditions as they will be in huge number. 

## AWS Credentials Management

The tool includes an integrated credential management system to help you set up and manage AWS credentials easily.

### Credential Setup Options

```bash
# Interactive credential setup
./waf-classic-cleanup.sh --setup-credentials

# Check current credential status
./waf-classic-cleanup.sh --check-credentials

# Run the credential helper directly
python3 aws_credentials_helper.py
```

### Credential Helper Features

The integrated credential helper provides:

1. **Setup new credentials** - Interactive setup for first-time users
2. **Update existing credentials** - Modify existing credential files
3. **Environment variable guidance** - Instructions for environment-based setup
4. **Status checking** - View current credential configuration
5. **Credential testing** - Verify credentials work with AWS
6. **Profile support** - Set up multiple AWS profiles

### Automatic Credential Checking

The `./waf-classic-cleanup.sh` wrapper automatically:
- Checks if credentials are configured before running
- Offers to set up credentials if none are found
- Validates credentials work with AWS
- Provides helpful error messages and setup guidance

## Cross-Account Access Setup

To use the tool across multiple AWS accounts, you need to set up cross-account IAM roles.

### 1. Create IAM Role in Target Account

In each target account, create an IAM role with the required WAF permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "waf-regional:ListWebACLs",
                "waf-regional:GetWebACL",
                "waf-regional:GetWebACLForResource",
                "waf-regional:DeleteWebACL",
                "waf-regional:GetChangeToken",
                "waf:ListWebACLs",
                "waf:GetWebACL",
                "waf:DeleteWebACL",
                "waf:GetChangeToken",
                "elbv2:DescribeLoadBalancers",
                "apigateway:GET",
                "apigateway:GetRestApis",
                "apigateway:GetStages",
                "cloudfront:ListDistributions",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

### 2. Configure Trust Relationship

Set up the trust relationship to allow your management account to assume the role:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::MANAGEMENT-ACCOUNT-ID:root"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "optional-external-id"
                }
            }
        }
    ]
}
```

### 3. Grant AssumeRole Permission in Management Account

In your management account, ensure your user/role has permission to assume the cross-account role:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::*:role/CrossAccountWAFRole"
        }
    ]
}
```

## Required AWS Permissions

Your AWS credentials need the following permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "waf-regional:ListWebACLs",
                "waf-regional:GetWebACL",
                "waf-regional:GetWebACLForResource",
                "waf-regional:DeleteWebACL",
                "waf-regional:GetChangeToken",
                "waf:ListWebACLs",
                "waf:GetWebACL",
                "waf:DeleteWebACL",
                "waf:GetChangeToken",
                "elbv2:DescribeLoadBalancers",
                "apigateway:GET",
                "apigateway:GetRestApis",
                "apigateway:GetStages",
                "cloudfront:ListDistributions",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

### Identity and Access
```bash
# Get current AWS identity
aws sts get-caller-identity
```

**Notes:**
- Replace `<PLACEHOLDER_VALUES>` with actual resource IDs, ARNs, and tokens
- Change tokens must be obtained fresh for each WAF modification operation
- Use `--region us-east-1` for global WAF resources (CloudFront)
- For regional resources, use the appropriate region parameter
- Always check for associations before deleting resources
- Resources must be deleted in dependency order: WebACLs → RuleGroups → Rules → Conditions

## How It Works

1. **Discovery Phase:**
   - Lists all WAF Classic WebACLs/RuleGroup/Rule/Conditions in the specified region(s) (regional)
   - Lists all global WAF Classic WebACLs/RuleGroup/Rule/Conditions (for CloudFront) - only when 'cloudfront' pseudo-region is included
   - Retrieves detailed information for each WebACLs/RuleGroup/Rule/Conditions across all target regions

2. **Association Check:**
   - Scans all Application Load Balancers for WAF associations in each target region
   - Checks API Gateway REST APIs for WAF associations in each target region
   - Checks CloudFront distributions for WAF associations (only when 'cloudfront' pseudo-region is included)
   - Maps which WebACLs are actively protecting resources

3. **Analysis & Display:**
   - Shows associated WebACLs/RuleGroup/Rule/Conditions with their protected resources, including region information
   - Clearly distinguishes between regional and global WebACLs/RuleGroup/Rule/Conditions
   - Identifies unassociated WebACLs that may be candidates for cleanup
   - Displays detailed information including rules count and default actions

4. **Interactive Cleanup:**
   - Offers multiple cleanup and export options:
     - Delete all WebACLs/RuleGroup/Rule/Conditions
     - Delete specific WebACLs/RuleGroup/Rule/Conditions
     - Export all WebACLs/RuleGroup/Rule/Conditions to CSV
     - Delete WebACLs/RuleGroup/Rule/Conditions from CSV file
   - Handles both regional and global Resource deletions appropriately
   - Provides detailed feedback on deletion success/failure

## Region-Specific Behavior

The tool behaves differently depending on the AWS regions you specify:

## CSV Export/Import Workflow

### Export Workflow:
1. Run the tool with your desired regions
2. Choose to Export WebACLs/RuleGroup/Rule/Conditions after selecting the regions
3. Review the generated CSV file and use it to import WebACLs/RuleGroup/Rule/Conditions for deletion
4. Mark Resource for deletion by setting `mark_for_deletion` column to `DELETE`, any other word apart from `DELETE` will skip the resource from deletion

### CSV Format Examples:

### WebACL CSV Format:
```csv
webacl_name,webacl_id,region,scope,account_id,default_action,rules_count,associated_resources,resource_identifiers,mark_for_deletion
MyWebACL,12345678-1234-1234-1234-123456789012,us-east-1,regional,123456789012,ALLOW,3,None,None,DELETE
```

### RuleGroup CSV Format:
```csv
rulegroup_name,rulegroup_id,region,scope,account_id,rules_count,associated_resources,resource_identifiers,mark_for_deletion
MyRuleGroup,87654321-4321-4321-4321-210987654321,us-east-1,regional,123456789012,2,WebACL1,webacl-id-123,DELETE
```

### Rule CSV Format:
```csv
rule_name,rule_id,region,scope,account_id,conditions_count,associated_resources,resource_identifiers,mark_for_deletion
MyRule,11111111-2222-3333-4444-555555555555,us-east-1,regional,123456789012,1,RuleGroup1,rulegroup-id-456,DELETE
```

### Condition CSV Format:
```csv
condition_name,condition_id,condition_type,region,scope,account_id,associated_resources,resource_identifiers,mark_for_deletion
MyIPSet,99999999-8888-7777-6666-555555555555,IPSet,us-east-1,regional,123456789012,Rule1,rule-id-789,DELETE
```

**CSV Column Descriptions:**

**WebACL Columns:**
- `webacl_name`: Name of the WebACL
- `webacl_id`: Unique identifier of the WebACL
- `region`: AWS region (or 'cloudfront' for global WebACLs)
- `scope`: Either 'regional' or 'global'
- `account_id`: AWS account ID
- `default_action`: Default action of the WebACL (ALLOW/BLOCK)
- `rules_count`: Number of rules in the WebACL
- `associated_resources`: Human-readable list of associated resources
- `resource_identifiers`: ARNs or IDs of associated resources
- `mark_for_deletion`: Mark with 'DELETE' to delete (case-sensitive)

**RuleGroup Columns:**
- `rulegroup_name`: Name of the RuleGroup
- `rulegroup_id`: Unique identifier of the RuleGroup
- `region`: AWS region (or 'cloudfront' for global RuleGroups)
- `scope`: Either 'regional' or 'global'
- `account_id`: AWS account ID
- `rules_count`: Number of rules in the RuleGroup
- `associated_resources`: WebACLs using this RuleGroup
- `resource_identifiers`: WebACL IDs that reference this RuleGroup
- `mark_for_deletion`: Mark with 'DELETE' to delete (case-sensitive)

**Rule Columns:**
- `rule_name`: Name of the Rule
- `rule_id`: Unique identifier of the Rule
- `region`: AWS region (or 'cloudfront' for global Rules)
- `scope`: Either 'regional' or 'global'
- `account_id`: AWS account ID
- `conditions_count`: Number of conditions in the Rule
- `associated_resources`: RuleGroups/WebACLs using this Rule
- `resource_identifiers`: IDs of resources that reference this Rule
- `mark_for_deletion`: Mark with 'DELETE' to delete (case-sensitive)

**Condition Columns:**
- `condition_name`: Name of the Condition (IP Set, Byte Match Set, etc.)
- `condition_id`: Unique identifier of the Condition
- `condition_type`: Type of condition (IPSet, ByteMatchSet, SqlInjectionMatchSet, XssMatchSet, etc.)
- `region`: AWS region (or 'cloudfront' for global Conditions)
- `scope`: Either 'regional' or 'global'
- `account_id`: AWS account ID
- `associated_resources`: Rules using this Condition
- `resource_identifiers`: Rule IDs that reference this Condition
- `mark_for_deletion`: Mark with 'DELETE' to delete (case-sensitive)

A sample CSV file (`sample_webacls.csv`) is included in the repository for reference.

### Import Workflow:
1. Prepare your CSV file with resource marked for deletion with the word 'DELETE'
2. Run: `python3 waf-classic-cleanup.py --csv-file your_file_path.csv --resource-type webacls`
3. The tool will skip discovery and directly process deletions
4. Confirm the deletion when prompted
5. --resource-type can be webacls, rulegroups, rules, conditions

## Safety Features

- **Confirmation Required:** All deletions require explicit confirmation when we try to delete all resources
- **Detailed Information:** Use analyze to see what is safe to delete before deleting
- **Error Handling:** Gracefully handles API errors and permission issues
- **Association Verification:** Double-checks associations and references before marking resource as unused
- **Scope Awareness:** Properly handles both regional and global WebACL deletions
- **Multi-region Safety:** Clearly identifies which region each resource belongs to
- **CSV Audit Trail:** Export functionality provides audit trails for compliance


## Limitations

- Only works with WAF Classic (not WAFv2)
- Cannot delete Resources that still contain active references (AWS limitation)
- Cannot delete MarketPlace/Partner Managed Rules and it's references
- Global WebACLs and CloudFront associations are only checked when 'cloudfront' pseudo-region is included
- When using `--all-regions`, the operation may take longer due to the number of API calls across all 32 regions plus CloudFront
- Need to follow the deletion flow WebACL -> RuleGroup -> Rule and Conditions to delete resources with less hicups 
- China regions (cn-north-1, cn-northwest-1) and GovCloud regions (us-gov-east-1, us-gov-west-1) require special AWS credentials and may not be accessible with standard AWS accounts

## Troubleshooting

### Common Issues

1. **"WAFNonEmptyEntityException"**
   - The WebACL contains rules and cannot be deleted
   - Remove all rules from the WebACL first, then retry

2. **"WAFReferencedItemException"**
   - The WebACL is still associated with a resource
   - Check for associations that might have been missed

3. **"UnrecognizedClientException"**
   - Dont have permissions in the given region

4. **"ExpiredTokenException"**
   - If you do have permission then a quick refresh of credentials should fix this, this means the credential token got expired 

5. **"AccessDenied"**
   - Insufficient AWS permissions
   - Ensure your credentials have the required permissions listed above
   - When using multi-region operations, ensure permissions exist in all target regions

6. **"No credentials found"**
   - AWS credentials not configured
   - Run `./waf-classic-cleanup.sh --setup-credentials` for interactive setup
   - Or run `aws configure` or set up AWS credentials manually

7. **"Invalid regions specified"**
   - One or more regions in your `--regions` list are not supported by WAF Classic
   - Use `--all-regions` to see all supported regions, or check the error message for valid regions

8. **CSV import issues**
   - Ensure the CSV file exists and has the correct format
   - Check that the `mark_for_deletion` column contains non-empty values for WebACLs you want to delete
   - Verify that WebACL IDs in the CSV still exist and haven't been deleted already

### Debug Mode

For additional debugging information, you can modify the script to enable boto3 debug logging:

```python
import logging
boto3.set_stream_logger('', logging.DEBUG)
```

## License

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0

## Support

This is sample code provided for educational and demonstration purposes. For production use:
- Review and test thoroughly in your environment
- Understand the impact of deleting WAF resources
- Have proper backup and recovery procedures
- Always prioritize security and availability

**Remember: This tool deletes resources permanently. Use with extreme caution.**

---

**Last Updated**: September 17, 2025
