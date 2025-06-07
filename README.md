# Vault Proxy Management Script

A comprehensive macOS script for managing HashiCorp Vault AppRoles and Vault Proxy setup with enhanced security features.

## Overview

This script provides end-to-end management of Vault AppRoles and Proxy configuration, featuring role-specific credential isolation, tmpfs-based secure storage, and automated service management via launchd.

## Features

- **Complete AppRole Management**: Create AppRoles with policies, credentials, and configuration
- **Role-Specific Security**: Each AppRole gets isolated tmpfs directories and named credential files
- **Memory-Only Storage**: Credentials stored in tmpfs (never written to disk)
- **Automatic Service Management**: launchd integration for persistent proxy service
- **Interactive Role Selection**: Choose between multiple configured roles at startup
- **Backward Compatibility**: Supports both new role-specific and legacy generic configurations

## Prerequisites

- macOS (tested on macOS 10.14+)
- HashiCorp Vault CLI installed (`/usr/local/bin/vault`)
- Vault server accessible and authenticated
- `sudo` access (required for tmpfs mounting)

## Installation

```bash
# Clone or download the script
chmod +x vpmgmt.sh

# Set environment variables
export VAULT_ADDR="https://your-vault-server:8200"
export VAULT_TOKEN="your-vault-token"
```

## Quick Start

### New AppRole Setup (Recommended)

```bash
# 1. Initial setup
./vpmgmt.sh --setup

# 2. Create new AppRole and credentials
./vpmgmt.sh --create-approle
# Enter AppRole name: myapp

# 3. Start the proxy service
./vpmgmt.sh --start
# Select role if multiple available

# 4. Optional: Clean up secret-id for security
./vpmgmt.sh --cleanup
```

### Existing AppRole Setup

```bash
# 1. Initial setup
./vpmgmt.sh --setup

# 2. Configure existing credentials
./vpmgmt.sh --existing-credentials
# Enter role name and credentials

# 3. Start the proxy service
./vpmgmt.sh --start
```

## Command Reference

### Setup Commands

| Command | Description |
|---------|-------------|
| `--setup` | Initialize tmpfs, proxy config, and launchd service |
| `--create-approle` | Create new AppRole with policy and store credentials |
| `--existing-credentials` | Store existing AppRole credentials manually |

### Service Management

| Command | Description |
|---------|-------------|
| `--start` | Start the Vault proxy service |
| `--stop` | Stop the Vault proxy service |
| `--status` | Show comprehensive status of all components |

### Cleanup Commands

| Command | Description |
|---------|-------------|
| `--cleanup` | Remove credentials from tmpfs (interactive) |
| `--cleanup-all` | Full cleanup: stop service, remove all files and mounts |

### Information

| Command | Description |
|---------|-------------|
| `--help`, `-h` | Show detailed help and usage information |

## File Structure

### Credential Storage

```
/tmp/vault-secrets-ROLENAME/
├── role-id-ROLENAME      # AppRole Role ID
├── secret-id-ROLENAME    # AppRole Secret ID
└── token                 # Auto-generated Vault token
```

### Configuration Files

```
~/.config/.vault/
└── proxy.hcl            # Vault Proxy configuration

~/Library/LaunchAgents/
└── com.hashicorp.vault-proxy.plist  # macOS service definition
```

### Log Files

```
/tmp/
├── vault-proxy.log       # Proxy service logs
└── vault-proxy-error.log # Proxy service error logs
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_ADDR` | `http://127.0.0.1:8200` | Vault server address |
| `VAULT_TOKEN` | `dev-only-token` | Vault authentication token |
| `TOKEN_TTL` | `1h` | AppRole token time-to-live |
| `TOKEN_MAX_TTL` | `4h` | AppRole token maximum TTL |

## Security Features

### Memory-Only Storage
- **tmpfs**: All credentials stored in memory-based filesystem
- **No Disk Writes**: Credentials never written to persistent storage
- **Automatic Cleanup**: Credentials lost on system reboot

### Role Isolation
- **Separate Directories**: Each role gets isolated tmpfs mount
- **Named Files**: Credentials include role name in filename
- **Permission Control**: Restrictive file permissions (600)

### Service Security
- **User-Level Service**: Runs as current user, not root
- **Automatic Restart**: launchd ensures service availability
- **Log Separation**: Dedicated log files for monitoring

## Workflow Examples

### Development Workflow

```bash
# Setup development environment
export VAULT_ADDR="http://localhost:8200"
export VAULT_TOKEN="dev-root-token"

# Create AppRole for development
./vpmgmt.sh --setup
./vpmgmt.sh --create-approle  # Enter: "dev-app"
./vpmgmt.sh --start

# Your application can now use: http://127.0.0.1:8007
# Clean up when done
./vpmgmt.sh --cleanup-all
```

### Production Workflow

```bash
# Setup with production Vault
export VAULT_ADDR="https://vault.company.com:8200"
export VAULT_TOKEN="s.xxxxxxxxx"
export TOKEN_TTL="4h"
export TOKEN_MAX_TTL="24h"

# Create production AppRole
./vpmgmt.sh --setup
./vpmgmt.sh --create-approle  # Enter: "prod-webapp"
./vpmgmt.sh --start

# Remove secret-id for security
./vpmgmt.sh --cleanup  # Remove secret-id, keep role-id
```

### Multi-Role Environment

```bash
# Create multiple AppRoles
./vpmgmt.sh --create-approle  # Enter: "frontend"
./vpmgmt.sh --create-approle  # Enter: "backend"
./vpmgmt.sh --create-approle  # Enter: "database"

# Start with interactive role selection
./vpmgmt.sh --start
# Multiple credential sets found:
#   1. frontend (/tmp/vault-secrets-frontend)
#   2. backend (/tmp/vault-secrets-backend) 
#   3. database (/tmp/vault-secrets-database)
# Select credentials to use (1-3): 2

# Check status of all roles
./vpmgmt.sh --status
```

## Troubleshooting

### Common Issues

#### Service Won't Start
```bash
# Check logs
tail -f /tmp/vault-proxy-error.log

# Verify Vault connectivity
vault status

# Check credentials
./vpmgmt.sh --status
```

#### Load Error (Input/output error)
This is often a permissions issue but the service may still start successfully:
```bash
# Check if service actually started
./vpmgmt.sh --status

# Test proxy endpoint
curl -s http://127.0.0.1:8007/v1/sys/health
```

#### Vault Binary Not Found
```bash
# Check vault installation
which vault

# Update plist if vault is in different location
# Edit: ~/Library/LaunchAgents/com.hashicorp.vault-proxy.plist
```

### Debug Commands

```bash
# Manual proxy start for debugging
vault proxy -config ~/.config/.vault/proxy.hcl

# Check launchd service
launchctl list | grep vault-proxy

# Manual authentication test
vault write auth/approle/login \
    role_id="$(cat /tmp/vault-secrets-ROLENAME/role-id-ROLENAME)" \
    secret_id="$(cat /tmp/vault-secrets-ROLENAME/secret-id-ROLENAME)"
```

## Application Integration

### Using the Proxy

Once the proxy is running, configure your applications to use:
- **Vault Address**: `http://127.0.0.1:8007`
- **Authentication**: Automatic (proxy handles it)

### Example Application Code

```bash
# Instead of authenticating directly to Vault
# Use the local proxy endpoint
export VAULT_ADDR="http://127.0.0.1:8007"

# Read secrets through the proxy
vault kv get secret/myapp/config
```

## Advanced Configuration

### Custom Policies

The script creates basic policies. To customize:

1. Edit the policy in `create_policy()` function
2. Or create policies manually in Vault
3. Update AppRole to use custom policies

### Custom Proxy Configuration

Edit `~/.config/.vault/proxy.hcl` to customize:
- Listener address/port
- Additional sinks
- Logging levels
- Cache settings

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with appropriate tests
4. Submit a pull request

## License

This script is provided as-is for educational and operational use. Please review and test thoroughly before production use.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review Vault proxy documentation
3. Enable debug logging for detailed diagnostics
