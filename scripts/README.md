# AWS WAF Classic Tools

This repository contains tools for managing AWS WAF Classic (v1) resources, including migration to WAF v2 and cleanup operations.

## Components

### WAF Migration Tool (`scripts/waf-migration/`)
Tools for migrating AWS WAF Classic resources to WAF v2.

- **waf-migrator.py** - Core migration engine
- **waf-migrate.sh** - Interactive shell interface

### WAF Cleanup Tool (`scripts/waf-cleanup/`)
Tools for cleaning up AWS WAF Classic resources.

- **wafv1-cleanup.py** - Core cleanup engine
- **wafv1-cleanup.sh** - Interactive shell interface

### Common Utilities (`scripts/common/`)
Shared utilities and configurations used by both tools.

### Tests (`scripts/tests/`)
Covers comprehensive tests for both migation and cleanup.

## Prerequisites

- Python 3.6 or later
- AWS CLI configured with appropriate permissions
- Boto3 library

## Installation

1. Clone this repository
2. Ensure Python 3.6+ is installed
3. Install required dependencies:
   ```bash
   pip install boto3
   ```

## Quick Start

### Migration Tool
```bash
cd scripts/waf-migration
./waf-migrate.sh
```

### Cleanup Tool
```bash
cd scripts/waf-cleanup
./wafv1-cleanup.sh
```

## AWS Permissions Required

The tools require the following AWS permissions:
- WAF Classic read/write permissions
- WAF v2 read/write permissions (for migration)
- CloudFront read permissions (for global resources)
- Application Load Balancer read permissions (for regional resources)

## License

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0

## Support

This is sample code provided for migrating and cleanup WAFv1 Classic. For production use, please review and test thoroughly in your environment.

---

**Last Updated**: September 17, 2025
