# AWS WAF Tools Collection

A comprehensive suite of tools for managing AWS WAF Classic resources, including migration to WAF v2 and cleanup operations across multiple AWS regions.

## Quick Start

### Prerequisites
- Python 3.6 or later
- AWS credentials configured (interactive setup available)

### Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Make scripts executable
chmod +x scripts/waf-migration/waf-migrate.sh
chmod +x scripts/waf-cleanup/waf-classic-cleanup.sh
```

### AWS Credentials Setup
Both tools include interactive credential management:
```bash
# Setup through migration tool
./scripts/waf-migration/waf-migrate.sh --setup-credentials

# Setup through cleanup tool
./scripts/waf-cleanup/waf-classic-cleanup.sh --setup-credentials

# Or use the shared helper directly
python3 scripts/common/aws_credentials_helper.py
```

## Tools Overview

### WAF Migration Tool
**Location**: `scripts/waf-migration/`
**Script**: `./scripts/waf-migration/waf-migrate.sh`

Migrates AWS WAF Classic WebACLs to equivalent WAF v2 WebACLs with complete automation.

**Key Features:**
- Complete end-to-end migration of WebACLs, IPSets, RegexPatternSets, and RuleGroups
- Support for all 33 AWS regions plus CloudFront (Global)
- Interactive interface with numbered menus
- Deterministic naming and resource reuse
- IPv4/IPv6 automatic splitting for mixed IPSets
- Capacity validation and dependency management

### WAF Cleanup Tool
**Location**: `scripts/waf-cleanup/`
**Script**: `./scripts/waf-cleanup/waf-classic-cleanup.sh`

Safely removes AWS WAF Classic resources with dependency checking and confirmation prompts.

**Key Features:**
- Interactive cleanup with dependency validation
- Multi-region support (all 33 regions + CloudFront)
- Association checking with ALBs, API Gateway, and CloudFront
- CSV export/import for bulk operations
- Cross-account support with role assumption
- Safety checks and confirmation prompts

## Supported Regions

Both tools support all AWS regions where WAF Classic is available:

**US Regions:** us-east-1, us-east-2, us-west-1, us-west-2  
**US Government:** us-gov-east-1, us-gov-west-1  
**Europe:** eu-west-1, eu-west-2, eu-west-3, eu-central-1, eu-central-2, eu-north-1, eu-south-1, eu-south-2  
**Asia Pacific:** ap-northeast-1, ap-northeast-2, ap-northeast-3, ap-southeast-1, ap-southeast-2, ap-southeast-3, ap-southeast-4, ap-south-1, ap-south-2, ap-east-1  
**Middle East:** me-south-1, me-central-1  
**Africa:** af-south-1  
**Israel:** il-central-1  
**Canada:** ca-central-1  
**South America:** sa-east-1  
**China:** cn-north-1, cn-northwest-1  
**Special:** cloudfront (Global WAF for CloudFront distributions)

## Common Components

### AWS Credentials Helper
**Location**: `scripts/common/aws_credentials_helper.py`

Shared credential management system used by both tools:
- Interactive credential setup and validation
- Support for multiple AWS profiles
- Environment variable configuration
- Credential testing and status checking

### Credentials Setup Documentation
**Location**: `scripts/common/CREDENTIALS_SETUP.md`

Comprehensive guide for AWS credential configuration including:
- Required IAM permissions for both Classic WAF and WAF v2
- Multiple setup methods (interactive, AWS CLI, environment variables, IAM roles)
- Security best practices and troubleshooting

## Safety Features

- **Confirmation Required**: All destructive operations require explicit confirmation
- **Dependency Validation**: Checks for resource associations before deletion
- **Capacity Validation**: Migration tool validates WAF v2 capacity limits
- **Error Handling**: Comprehensive error handling with detailed messages
- **Audit Trails**: CSV export provides audit trails for compliance
- **Rollback Information**: Migration tool provides rollback guidance

## Troubleshooting

### Common Issues

**"No credentials found"**
- Run `./waf-migrate.sh --setup-credentials` or `./waf-classic-cleanup.sh --setup-credentials`

**"Access Denied"**
- Verify IAM permissions match the requirements above
- Check if you're using the correct AWS account

**"WAFNonEmptyEntityException"**
- WebACL contains rules and cannot be deleted
- Remove rules first or use the cleanup tool's dependency analysis

**"Region not supported"**
- Ensure you're using a supported AWS region
- For CloudFront, use `--region cloudfront`

## Important Notes

- **Sample Code**: These are sample tools for demonstration purposes
- **Production Use**: Review and test thoroughly before using in production
- **One-Way Migration**: Migration from Classic to v2 is one-way (no automated rollback)
- **Manual Association**: After migration, manually associate v2 WebACLs with resources
- **Testing Required**: Always test migrated WebACLs to ensure identical behavior

## Support

For issues or questions:
1. Check the tool-specific README files for detailed documentation
2. Review error messages for specific guidance
3. Verify AWS permissions and credentials
4. Test with simple resources first
5. Use interactive mode for the best experience

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing to this project.

## License

This project is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file for details.

