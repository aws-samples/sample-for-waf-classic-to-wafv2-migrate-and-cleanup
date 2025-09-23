# Common Utilities used by both migration and cleanup tools

## AWS Credentials Setup for WAF Tools

## Overview
The WAF tools include built-in credential management to help you set up and manage AWS credentials easily. Both the WAF migration tool and WAF cleanup tool share the same credential management system.

## Quick Setup

### Interactive Credential Setup
```bash
# Setup credentials through migration tool
cd scripts/waf-migration
./waf-migrate.sh --setup-credentials

# Setup credentials through cleanup tool  
cd scripts/waf-cleanup
./waf-classic-cleanup.sh --setup-credentials

# Direct credential helper (from project root)
python3 scripts/common/aws_credentials_helper.py
```

## Setup Options

### 1. Interactive Setup (Recommended)
Both tools will automatically prompt you to set up credentials if none are found:
```bash
# From waf-migration directory
./waf-migrate.sh

# From waf-cleanup directory  
./waf-classic-cleanup.sh

# If no credentials found, you'll be prompted to set them up
```

### 2. Check Existing Credentials
```bash
# Check credentials through migration tool
./waf-migrate.sh --check-credentials

# Check credentials through cleanup tool
./waf-classic-cleanup.sh --check-credentials
```

### 3. Manual AWS CLI Setup
```bash
aws configure
```

### 4. Environment Variables
```bash
export AWS_ACCESS_KEY_ID='your-access-key-id'
export AWS_SECRET_ACCESS_KEY='your-secret-access-key'
export AWS_DEFAULT_REGION='us-east-1'
```

### 5. IAM Roles
For EC2 instances or Lambda functions, attach appropriate IAM roles.

## Required Permissions

### Classic WAF (waf-classic) Permissions
Required for both migration and cleanup tools. Includes both global (`waf`) and regional (`waf-regional`) services:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "waf:GetWebACL",
                "waf:GetRule",
                "waf:GetRateBasedRule",
                "waf:GetIPSet",
                "waf:GetByteMatchSet",
                "waf:GetSqlInjectionMatchSet",
                "waf:GetXssMatchSet",
                "waf:GetSizeConstraintSet",
                "waf:GetGeoMatchSet",
                "waf:GetRegexMatchSet",
                "waf:GetRegexPatternSet",
                "waf:GetRuleGroup",
                "waf:ListWebACLs",
                "waf:ListRules",
                "waf:ListRateBasedRules",
                "waf:ListRuleGroups",
                "waf:ListIPSets",
                "waf:ListByteMatchSets",
                "waf:ListSqlInjectionMatchSets",
                "waf:ListXssMatchSets",
                "waf:ListSizeConstraintSets",
                "waf:ListGeoMatchSets",
                "waf:ListRegexMatchSets",
                "waf:ListRegexPatternSets",
                "waf:ListActivatedRulesInRuleGroup",
                "waf:GetWebACLForResource",
                "waf:GetChangeToken",
                "waf:UpdateWebACL",
                "waf:UpdateRule",
                "waf:UpdateRateBasedRule",
                "waf:UpdateRuleGroup",
                "waf:UpdateIPSet",
                "waf:UpdateByteMatchSet",
                "waf:UpdateSqlInjectionMatchSet",
                "waf:UpdateXssMatchSet",
                "waf:UpdateSizeConstraintSet",
                "waf:UpdateGeoMatchSet",
                "waf:UpdateRegexMatchSet",
                "waf:DeleteWebACL",
                "waf:DeleteRule",
                "waf:DeleteRateBasedRule",
                "waf:DeleteRuleGroup",
                "waf:DeleteIPSet",
                "waf:DeleteByteMatchSet",
                "waf:DeleteSqlInjectionMatchSet",
                "waf:DeleteXssMatchSet",
                "waf:DeleteSizeConstraintSet",
                "waf:DeleteGeoMatchSet",
                "waf:DeleteRegexMatchSet",
                "waf-regional:GetWebACL",
                "waf-regional:GetRule",
                "waf-regional:GetRateBasedRule",
                "waf-regional:GetIPSet",
                "waf-regional:GetByteMatchSet",
                "waf-regional:GetSqlInjectionMatchSet",
                "waf-regional:GetXssMatchSet",
                "waf-regional:GetSizeConstraintSet",
                "waf-regional:GetGeoMatchSet",
                "waf-regional:GetRegexMatchSet",
                "waf-regional:GetRegexPatternSet",
                "waf-regional:GetRuleGroup",
                "waf-regional:ListWebACLs",
                "waf-regional:ListRules",
                "waf-regional:ListRateBasedRules",
                "waf-regional:ListRuleGroups",
                "waf-regional:ListIPSets",
                "waf-regional:ListByteMatchSets",
                "waf-regional:ListSqlInjectionMatchSets",
                "waf-regional:ListXssMatchSets",
                "waf-regional:ListSizeConstraintSets",
                "waf-regional:ListGeoMatchSets",
                "waf-regional:ListRegexMatchSets",
                "waf-regional:ListRegexPatternSets",
                "waf-regional:ListActivatedRulesInRuleGroup",
                "waf-regional:GetWebACLForResource",
                "waf-regional:GetChangeToken",
                "waf-regional:UpdateWebACL",
                "waf-regional:UpdateRule",
                "waf-regional:UpdateRateBasedRule",
                "waf-regional:UpdateRuleGroup",
                "waf-regional:UpdateIPSet",
                "waf-regional:UpdateByteMatchSet",
                "waf-regional:UpdateSqlInjectionMatchSet",
                "waf-regional:UpdateXssMatchSet",
                "waf-regional:UpdateSizeConstraintSet",
                "waf-regional:UpdateGeoMatchSet",
                "waf-regional:UpdateRegexMatchSet",
                "waf-regional:DeleteWebACL",
                "waf-regional:DeleteRule",
                "waf-regional:DeleteRateBasedRule",
                "waf-regional:DeleteRuleGroup",
                "waf-regional:DeleteIPSet",
                "waf-regional:DeleteByteMatchSet",
                "waf-regional:DeleteSqlInjectionMatchSet",
                "waf-regional:DeleteXssMatchSet",
                "waf-regional:DeleteSizeConstraintSet",
                "waf-regional:DeleteGeoMatchSet",
                "waf-regional:DeleteRegexMatchSet",
                "waf:GetLoggingConfiguration",
                "waf:ListLoggingConfigurations",
                "waf-regional:GetLoggingConfiguration",
                "waf-regional:ListLoggingConfigurations"
            ],
            "Resource": "*"
        }
    ]
}
```

### WAF v2 Permissions (for migration tool)
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "wafv2:CreateWebACL",
                "wafv2:CreateIPSet",
                "wafv2:CreateRegexPatternSet",
                "wafv2:CreateRuleGroup",
                "wafv2:CheckCapacity",
                "wafv2:ListIPSets",
                "wafv2:ListRegexPatternSets",
                "wafv2:ListRuleGroups",
                "wafv2:ListWebACLs",
                "wafv2:GetIPSet",
                "wafv2:GetRegexPatternSet",
                "wafv2:GetRuleGroup",
                "wafv2:GetWebACL",
                "wafv2:GetLoggingConfiguration",
                "wafv2:PutLoggingConfiguration",
                "wafv2:ListLoggingConfigurations"
            ],
            "Resource": "*"
        }
    ]
}
```

### IAM Permissions (for logging migration)
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetRole",
                "iam:CreateServiceLinkedRole"
            ],
            "Resource": [
                "arn:aws:iam::*:role/aws-service-role/wafv2.amazonaws.com/AWSServiceRoleForWAFV2Logging"
            ]
        }
    ]
}
                "wafv2:DeleteRuleGroup"
            ],
            "Resource": "*"
        }
    ]
}
```

### Additional Permissions (for association checking)
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "elbv2:DescribeLoadBalancers",
                "cloudfront:ListDistributions",
                "cloudfront:GetDistribution"
            ],
            "Resource": "*"
        }
    ]
}
```

### Limited Access Scenarios

#### CloudFront Only Access
If you only manage CloudFront WebACLs, you need only:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "waf:*",
                "wafv2:*",
                "cloudfront:ListDistributions",
                "cloudfront:GetDistribution"
            ],
            "Resource": "*"
        }
    ]
}
```

#### Regional Only Access  
If you only manage ALB/API Gateway WebACLs, you need only:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "waf-regional:*",
                "wafv2:*",
                "elbv2:DescribeLoadBalancers"
            ],
            "Resource": "*"
        }
    ]
}
```

### Complete IAM Policy Example
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "waf:*",
                "waf-regional:*",
                "wafv2:*",
                "elbv2:DescribeLoadBalancers",
                "cloudfront:ListDistributions",
                "cloudfront:GetDistribution"
            ],
            "Resource": "*"
        }
    ]
}
```

## Credential Helper Features

The `aws_credentials_helper.py` provides:

1. **Interactive Setup**: Guided credential configuration with secure file creation
2. **Credential Testing**: Verify credentials work with AWS using STS GetCallerIdentity
3. **Status Checking**: Show current credential configuration and detection
4. **Profile Management**: Support for multiple AWS profiles
5. **Environment Variables**: Instructions and guidance for env var setup
6. **Update Mode**: Modify existing credential configurations

### Available Commands
```bash
# Interactive menu with all options
python3 scripts/common/aws_credentials_helper.py

# Through shell wrappers
./waf-migrate.sh --setup-credentials    # Setup new credentials
./waf-migrate.sh --check-credentials    # Test existing credentials
./waf-classic-cleanup.sh --setup-credentials  # Setup new credentials  
./waf-classic-cleanup.sh --check-credentials  # Test existing credentials
```

## Troubleshooting

### Common Issues

**"No credentials found"**
- Run credential setup through either tool:
  - `./waf-migrate.sh --setup-credentials`
  - `./waf-classic-cleanup.sh --setup-credentials`
- Or use `aws configure`
- Or set environment variables

**"Access Denied"**
- Check IAM permissions (see Required Permissions section above)
- Verify credentials are for correct AWS account
- Ensure permissions exist in target regions

**"Region not supported"**
- Ensure you're using a supported AWS region
- For CloudFront WebACLs, use `--region cloudfront`
- China regions (cn-north-1, cn-northwest-1) and GovCloud regions require special credentials

### Testing Credentials
```bash
# Test through the tools
./waf-migrate.sh --check-credentials
./waf-classic-cleanup.sh --check-credentials

# Test manually with AWS CLI
aws sts get-caller-identity

# Test through credential helper directly
python3 scripts/common/aws_credentials_helper.py
```

## Security Best Practices

1. **Never commit credentials** to version control
2. **Use IAM roles** when possible (EC2, Lambda, etc.)
3. **Rotate credentials** regularly
4. **Use least privilege** permissions
5. **Store credentials securely** in `~/.aws/credentials`

## Files Created

The credential setup creates:
- `~/.aws/credentials` - AWS access keys
- `~/.aws/config` - AWS configuration (region, output format)

Both files are created with secure permissions (600).

## WAFRegionConfig
- Region-specific configuration and validation
- Support for both regional and global (CloudFront) resources

## list_waf_resources.py

Command-line utility for listing WAF resources:

```bash
# List WebACLs in specific regions
python3 list_waf_resources.py webacls us-east-1,eu-west-1

# List RuleGroups in all regions
python3 list_waf_resources.py rulegroups all-regions

# Get mapping format for shell scripts
python3 list_waf_resources.py webacls us-east-1 map
```

### Supported Resource Types
- `webacls` - Web Application Firewall Access Control Lists
- `rulegroups` - Rule Groups
- `rules` - Individual Rules
- `conditions` - Rule Conditions

## aws_credentials_helper.py

Interactive AWS credentials setup utility:

- Guides users through AWS credential configuration
- Validates credential functionality
- Supports multiple credential methods (AWS CLI, environment variables, IAM roles)

## Usage in Tools

These utilities are imported and used by:
- **waf-migrator.py** - For migration operations
- **waf-classic-cleanup.py** - For cleanup operations
- **waf-migrate.sh** - For interactive resource listing
- **waf-classic-cleanup.sh** - For interactive resource listing

## Design Principles

- **Reusability** - Single implementation used by multiple tools
- **Consistency** - Uniform behavior across migration and cleanup
- **Error Handling** - Graceful handling of AWS API errors
- **Multi-region Support** - Consistent comma-separated region format
- **Modularity** - Clean separation of concerns

## License

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0

---

**Last Updated**: September 17, 2025
