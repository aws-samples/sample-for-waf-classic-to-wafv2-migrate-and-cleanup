#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""
WAF Region Configuration Management
Handles mapping between user regions and AWS WAF service endpoints

This module provides region configuration for WAF Classic to v2 migration.
"""

from dataclasses import dataclass
from typing import Dict, List

@dataclass
class WAFRegionConfig:
    user_region: str           # 'cloudfront', 'us-east-1', etc.
    classic_service: str       # 'waf' or 'waf-regional'
    classic_endpoint: str      # actual AWS region
    v2_endpoint: str          # actual AWS region
    v2_scope: str             # 'CLOUDFRONT' or 'REGIONAL'
    display_name: str         # for UI/reporting

class WAFRegionManager:
    """Manages WAF region configurations and service mappings"""

    REGION_MAPPINGS = {
        # Special Pseudo-Region
        'cloudfront': WAFRegionConfig(
            user_region='cloudfront',
            classic_service='waf',
            classic_endpoint='us-east-1',
            v2_endpoint='us-east-1',
            v2_scope='CLOUDFRONT',
            display_name='CloudFront (Global)'
        ),

        # US Regions
        'us-east-1': WAFRegionConfig(
            user_region='us-east-1',
            classic_service='waf-regional',
            classic_endpoint='us-east-1',
            v2_endpoint='us-east-1',
            v2_scope='REGIONAL',
            display_name='US East (N. Virginia)'
        ),
        'us-east-2': WAFRegionConfig(
            user_region='us-east-2',
            classic_service='waf-regional',
            classic_endpoint='us-east-2',
            v2_endpoint='us-east-2',
            v2_scope='REGIONAL',
            display_name='US East (Ohio)'
        ),
        'us-west-1': WAFRegionConfig(
            user_region='us-west-1',
            classic_service='waf-regional',
            classic_endpoint='us-west-1',
            v2_endpoint='us-west-1',
            v2_scope='REGIONAL',
            display_name='US West (N. California)'
        ),
        'us-west-2': WAFRegionConfig(
            user_region='us-west-2',
            classic_service='waf-regional',
            classic_endpoint='us-west-2',
            v2_endpoint='us-west-2',
            v2_scope='REGIONAL',
            display_name='US West (Oregon)'
        ),

        # US Government Regions
        'us-gov-east-1': WAFRegionConfig(
            user_region='us-gov-east-1',
            classic_service='waf-regional',
            classic_endpoint='us-gov-east-1',
            v2_endpoint='us-gov-east-1',
            v2_scope='REGIONAL',
            display_name='AWS GovCloud (US-East)'
        ),
        'us-gov-west-1': WAFRegionConfig(
            user_region='us-gov-west-1',
            classic_service='waf-regional',
            classic_endpoint='us-gov-west-1',
            v2_endpoint='us-gov-west-1',
            v2_scope='REGIONAL',
            display_name='AWS GovCloud (US-West)'
        ),

        # Europe Regions
        'eu-west-1': WAFRegionConfig(
            user_region='eu-west-1',
            classic_service='waf-regional',
            classic_endpoint='eu-west-1',
            v2_endpoint='eu-west-1',
            v2_scope='REGIONAL',
            display_name='Europe (Ireland)'
        ),
        'eu-west-2': WAFRegionConfig(
            user_region='eu-west-2',
            classic_service='waf-regional',
            classic_endpoint='eu-west-2',
            v2_endpoint='eu-west-2',
            v2_scope='REGIONAL',
            display_name='Europe (London)'
        ),
        'eu-west-3': WAFRegionConfig(
            user_region='eu-west-3',
            classic_service='waf-regional',
            classic_endpoint='eu-west-3',
            v2_endpoint='eu-west-3',
            v2_scope='REGIONAL',
            display_name='Europe (Paris)'
        ),
        'eu-central-1': WAFRegionConfig(
            user_region='eu-central-1',
            classic_service='waf-regional',
            classic_endpoint='eu-central-1',
            v2_endpoint='eu-central-1',
            v2_scope='REGIONAL',
            display_name='Europe (Frankfurt)'
        ),
        'eu-central-2': WAFRegionConfig(
            user_region='eu-central-2',
            classic_service='waf-regional',
            classic_endpoint='eu-central-2',
            v2_endpoint='eu-central-2',
            v2_scope='REGIONAL',
            display_name='Europe (Zurich)'
        ),
        'eu-north-1': WAFRegionConfig(
            user_region='eu-north-1',
            classic_service='waf-regional',
            classic_endpoint='eu-north-1',
            v2_endpoint='eu-north-1',
            v2_scope='REGIONAL',
            display_name='Europe (Stockholm)'
        ),
        'eu-south-1': WAFRegionConfig(
            user_region='eu-south-1',
            classic_service='waf-regional',
            classic_endpoint='eu-south-1',
            v2_endpoint='eu-south-1',
            v2_scope='REGIONAL',
            display_name='Europe (Milan)'
        ),
        'eu-south-2': WAFRegionConfig(
            user_region='eu-south-2',
            classic_service='waf-regional',
            classic_endpoint='eu-south-2',
            v2_endpoint='eu-south-2',
            v2_scope='REGIONAL',
            display_name='Europe (Spain)'
        ),

        # Asia Pacific Regions
        'ap-northeast-1': WAFRegionConfig(
            user_region='ap-northeast-1',
            classic_service='waf-regional',
            classic_endpoint='ap-northeast-1',
            v2_endpoint='ap-northeast-1',
            v2_scope='REGIONAL',
            display_name='Asia Pacific (Tokyo)'
        ),
        'ap-northeast-2': WAFRegionConfig(
            user_region='ap-northeast-2',
            classic_service='waf-regional',
            classic_endpoint='ap-northeast-2',
            v2_endpoint='ap-northeast-2',
            v2_scope='REGIONAL',
            display_name='Asia Pacific (Seoul)'
        ),
        'ap-northeast-3': WAFRegionConfig(
            user_region='ap-northeast-3',
            classic_service='waf-regional',
            classic_endpoint='ap-northeast-3',
            v2_endpoint='ap-northeast-3',
            v2_scope='REGIONAL',
            display_name='Asia Pacific (Osaka)'
        ),
        'ap-southeast-1': WAFRegionConfig(
            user_region='ap-southeast-1',
            classic_service='waf-regional',
            classic_endpoint='ap-southeast-1',
            v2_endpoint='ap-southeast-1',
            v2_scope='REGIONAL',
            display_name='Asia Pacific (Singapore)'
        ),
        'ap-southeast-2': WAFRegionConfig(
            user_region='ap-southeast-2',
            classic_service='waf-regional',
            classic_endpoint='ap-southeast-2',
            v2_endpoint='ap-southeast-2',
            v2_scope='REGIONAL',
            display_name='Asia Pacific (Sydney)'
        ),
        'ap-southeast-3': WAFRegionConfig(
            user_region='ap-southeast-3',
            classic_service='waf-regional',
            classic_endpoint='ap-southeast-3',
            v2_endpoint='ap-southeast-3',
            v2_scope='REGIONAL',
            display_name='Asia Pacific (Jakarta)'
        ),
        'ap-southeast-4': WAFRegionConfig(
            user_region='ap-southeast-4',
            classic_service='waf-regional',
            classic_endpoint='ap-southeast-4',
            v2_endpoint='ap-southeast-4',
            v2_scope='REGIONAL',
            display_name='Asia Pacific (Melbourne)'
        ),
        'ap-south-1': WAFRegionConfig(
            user_region='ap-south-1',
            classic_service='waf-regional',
            classic_endpoint='ap-south-1',
            v2_endpoint='ap-south-1',
            v2_scope='REGIONAL',
            display_name='Asia Pacific (Mumbai)'
        ),
        'ap-south-2': WAFRegionConfig(
            user_region='ap-south-2',
            classic_service='waf-regional',
            classic_endpoint='ap-south-2',
            v2_endpoint='ap-south-2',
            v2_scope='REGIONAL',
            display_name='Asia Pacific (Hyderabad)'
        ),
        'ap-east-1': WAFRegionConfig(
            user_region='ap-east-1',
            classic_service='waf-regional',
            classic_endpoint='ap-east-1',
            v2_endpoint='ap-east-1',
            v2_scope='REGIONAL',
            display_name='Asia Pacific (Hong Kong)'
        ),

        # Middle East Regions
        'me-south-1': WAFRegionConfig(
            user_region='me-south-1',
            classic_service='waf-regional',
            classic_endpoint='me-south-1',
            v2_endpoint='me-south-1',
            v2_scope='REGIONAL',
            display_name='Middle East (Bahrain)'
        ),
        'me-central-1': WAFRegionConfig(
            user_region='me-central-1',
            classic_service='waf-regional',
            classic_endpoint='me-central-1',
            v2_endpoint='me-central-1',
            v2_scope='REGIONAL',
            display_name='Middle East (UAE)'
        ),

        # Africa Regions
        'af-south-1': WAFRegionConfig(
            user_region='af-south-1',
            classic_service='waf-regional',
            classic_endpoint='af-south-1',
            v2_endpoint='af-south-1',
            v2_scope='REGIONAL',
            display_name='Africa (Cape Town)'
        ),

        # Israel Regions
        'il-central-1': WAFRegionConfig(
            user_region='il-central-1',
            classic_service='waf-regional',
            classic_endpoint='il-central-1',
            v2_endpoint='il-central-1',
            v2_scope='REGIONAL',
            display_name='Israel (Tel Aviv)'
        ),

        # Canada Regions
        'ca-central-1': WAFRegionConfig(
            user_region='ca-central-1',
            classic_service='waf-regional',
            classic_endpoint='ca-central-1',
            v2_endpoint='ca-central-1',
            v2_scope='REGIONAL',
            display_name='Canada (Central)'
        ),

        # South America Regions
        'sa-east-1': WAFRegionConfig(
            user_region='sa-east-1',
            classic_service='waf-regional',
            classic_endpoint='sa-east-1',
            v2_endpoint='sa-east-1',
            v2_scope='REGIONAL',
            display_name='South America (São Paulo)'
        ),

        # China Regions
        'cn-north-1': WAFRegionConfig(
            user_region='cn-north-1',
            classic_service='waf-regional',
            classic_endpoint='cn-north-1',
            v2_endpoint='cn-north-1',
            v2_scope='REGIONAL',
            display_name='China (Beijing)'
        ),
        'cn-northwest-1': WAFRegionConfig(
            user_region='cn-northwest-1',
            classic_service='waf-regional',
            classic_endpoint='cn-northwest-1',
            v2_endpoint='cn-northwest-1',
            v2_scope='REGIONAL',
            display_name='China (Ningxia)'
        )
    }

    @classmethod
    def get_config(cls, user_region: str) -> WAFRegionConfig:
        """Get region configuration for user-specified region"""
        return cls.REGION_MAPPINGS.get(user_region)

    @classmethod
    def list_supported_regions(cls) -> List[str]:
        """Get list of all supported regions"""
        return list(cls.REGION_MAPPINGS.keys())

    @classmethod
    def get_display_regions(cls) -> List[tuple]:
        """Get list of (region, display_name) tuples for UI"""
        return [(region, config.display_name) for region, config in cls.REGION_MAPPINGS.items()]

    @classmethod
    def validate_region(cls, user_region: str) -> bool:
        """Validate if region is supported"""
        return user_region in cls.REGION_MAPPINGS
