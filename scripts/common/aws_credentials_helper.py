#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""
AWS Credentials Helper for WAF Tools

This unified script helps you set up, update, and manage AWS credentials
for WAF migration and cleanup tools.
"""

import os
import sys
from pathlib import Path

def create_aws_directory():
    """Create AWS config directory if it doesn't exist."""
    aws_dir = Path.home() / '.aws'
    aws_dir.mkdir(exist_ok=True)
    return aws_dir

def check_existing_credentials():
    """Check if credentials already exist and return status."""
    aws_dir = Path.home() / '.aws'
    credentials_file = aws_dir / 'credentials'

    has_file = credentials_file.exists()
    has_env = all(os.getenv(var) for var in ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'])

    return {
        'has_file': has_file,
        'has_env': has_env,
        'credentials_file': credentials_file,
        'has_any': has_file or has_env
    }

def setup_credentials_file(update_mode=False):
    """Interactive setup for AWS credentials file."""
    aws_dir = create_aws_directory()
    credentials_file = aws_dir / 'credentials'

    action = "Update" if update_mode else "Setup"
    print(f"Secure AWS Credentials {action}")
    print("=" * 50)

    if not update_mode:
        print("You need AWS Access Key ID and Secret Access Key.")
        print("You can get these from the AWS Console > IAM > Users > Security credentials")
        print()

    # Get credentials from user
    access_key = input("Enter your AWS Access Key ID: ").strip()
    if not access_key:
        print("ERROR: Access Key ID is required!")
        return False

    secret_key = input("Enter your AWS Secret Access Key: ").strip()
    if not secret_key:
        print("ERROR: Secret Access Key is required!")
        return False

    region = input("Enter your default region (default: us-east-1): ").strip() or "us-east-1"

    # Optionally set up profile
    profile_name = "default"
    if update_mode:
        custom_profile = input("Enter profile name (default: default): ").strip()
        if custom_profile:
            profile_name = custom_profile

    # Write credentials file
    credentials_content = f"""[{profile_name}]
aws_access_key_id = {access_key}
aws_secret_access_key = {secret_key}
"""

    # If updating and file exists, we might want to preserve other profiles
    if update_mode and credentials_file.exists():
        try:
            with open(credentials_file, 'r') as f:
                existing_content = f.read()

            # Simple approach: if it's not the default profile, append
            if profile_name != "default" and f"[{profile_name}]" not in existing_content:
                credentials_content = existing_content.rstrip() + "\n\n" + credentials_content
            elif profile_name == "default":
                # Replace default profile
                lines = existing_content.split('\n')
                new_lines = []
                skip_default = False

                for line in lines:
                    if line.strip() == "[default]":
                        skip_default = True
                        continue
                    elif line.startswith('[') and line != "[default]":
                        skip_default = False

                    if not skip_default:
                        new_lines.append(line)

                # Add new default profile
                if new_lines and new_lines[-1].strip():
                    new_lines.append("")
                credentials_content = '\n'.join(new_lines).rstrip() + "\n\n" + credentials_content
        except Exception as e:
            print(f"WARNING:  Warning: Could not preserve existing profiles: {e}")

    with open(credentials_file, 'w') as f:
        f.write(credentials_content)

    # Set proper permissions
    os.chmod(credentials_file, 0o600)

    # Write config file
    config_file = aws_dir / 'config'
    config_content = f"""[profile {profile_name}]
region = {region}
output = json
""" if profile_name != "default" else f"""[default]
region = {region}
output = json
"""

    # Handle config file similar to credentials
    if update_mode and config_file.exists():
        try:
            with open(config_file, 'r') as f:
                existing_config = f.read()

            config_section = f"[profile {profile_name}]" if profile_name != "default" else "[default]"
            if config_section not in existing_config:
                config_content = existing_config.rstrip() + "\n\n" + config_content
        except Exception as e:
            print(f"WARNING:  Warning: Could not preserve existing config: {e}")

    with open(config_file, 'w') as f:
        f.write(config_content)

    print(f"SUCCESS: AWS credentials saved to {credentials_file}")
    print(f"SUCCESS: AWS config saved to {config_file}")
    if profile_name != "default":
        print(f"Note: To use this profile, run: ./waf-cleanup --profile {profile_name}")
    return True

def show_environment_setup():
    """Show how to set up environment variables."""
    print("\nGlobal Environment Variables Setup")
    print("=" * 50)
    print("You can set credentials using environment variables:")
    print()
    print("# For current session:")
    print("export AWS_ACCESS_KEY_ID='your-access-key-id'")
    print("export AWS_SECRET_ACCESS_KEY='your-secret-access-key'")
    print("export AWS_DEFAULT_REGION='us-east-1'")
    print()
    print("# For permanent setup, add to your shell profile:")
    print("echo 'export AWS_ACCESS_KEY_ID=\"your-access-key-id\"' >> ~/.bashrc")
    print("echo 'export AWS_SECRET_ACCESS_KEY=\"your-secret-access-key\"' >> ~/.bashrc")
    print("echo 'export AWS_DEFAULT_REGION=\"us-east-1\"' >> ~/.bashrc")
    print()
    print("Then run: source ~/.bashrc")

def show_status():
    """Show current credential status."""
    print("Statistics: AWS Credentials Status")
    print("=" * 50)

    cred_status = check_existing_credentials()

    if cred_status['has_file']:
        print(f"SUCCESS: Credentials file: {cred_status['credentials_file']}")
        try:
            with open(cred_status['credentials_file'], 'r') as f:
                content = f.read()
                profiles = [line.strip('[]') for line in content.split('\n') if line.startswith('[')]
                if profiles:
                    print(f"   Profiles: {', '.join(profiles)}")
        except Exception:
            pass
    else:
        print("ERROR: No credentials file found")

    if cred_status['has_env']:
        print("SUCCESS: Environment variables set:")
        print(f"   AWS_ACCESS_KEY_ID: {os.getenv('AWS_ACCESS_KEY_ID', 'Not set')[:10]}...")
        print(f"   AWS_SECRET_ACCESS_KEY: {'*' * 10}")
        print(f"   AWS_DEFAULT_REGION: {os.getenv('AWS_DEFAULT_REGION', 'Not set')}")
    else:
        print("ERROR: No environment variables set")

    if not cred_status['has_any']:
        print("\nWARNING:  No AWS credentials found!")
        print("   Run this script to set up credentials.")

def test_credentials():
    """Test if credentials work by making a simple AWS call."""
    print("🧪 Testing AWS Credentials")
    print("=" * 50)

    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError

        # Try to get caller identity
        sts = boto3.client('sts')
        response = sts.get_caller_identity()

        print("SUCCESS: Credentials are working!")
        print(f"   Account ID: {response.get('Account', 'Unknown')}")
        print(f"   User ARN: {response.get('Arn', 'Unknown')}")
        return True

    except NoCredentialsError:
        print("ERROR: No credentials found!")
        return False
    except ClientError as e:
        print(f"ERROR: Credential error: {e}")
        return False
    except ImportError:
        print("ERROR: boto3 not installed. Run: pip3 install boto3")
        return False
    except Exception as e:
        print(f"ERROR: Unexpected error: {e}")
        return False

def main():
    """Main interactive menu."""
    print("Starting AWS Credentials Helper for WAF Tools")
    print()

    # Check current status
    cred_status = check_existing_credentials()

    if cred_status['has_any']:
        print("SUCCESS: AWS credentials detected!")
    else:
        print("WARNING:  No AWS credentials found.")

    print("\nWhat would you like to do?")
    print("1. Set up new credentials")
    print("2. Update existing credentials")
    print("3. Show environment variable setup")
    print("4. Show credential status")
    print("5. Test credentials")
    print("6. Exit")

    choice = input("\nEnter your choice (1-6): ").strip()

    if choice == '1':
        if setup_credentials_file(update_mode=False):
            print("\nComplete Setup complete! You can now run the WAF tools.")
            if input("\nTest credentials now? (Y/n): ").strip().lower() != 'n':
                test_credentials()
        else:
            print("\nERROR: Setup failed. Please try again.")

    elif choice == '2':
        if setup_credentials_file(update_mode=True):
            print("\nComplete Update complete!")
            if input("\nTest credentials now? (Y/n): ").strip().lower() != 'n':
                test_credentials()
        else:
            print("\nERROR: Update failed. Please try again.")

    elif choice == '3':
        show_environment_setup()

    elif choice == '4':
        show_status()

    elif choice == '5':
        test_credentials()

    elif choice == '6':
        print("Welcome Goodbye!")

    else:
        print("ERROR: Invalid choice.")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nWelcome Cancelled by user.")
    except Exception as e:
        print(f"\nERROR: Unexpected error: {e}")
        sys.exit(1)
