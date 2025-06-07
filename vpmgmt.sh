#!/bin/bash

# Developed by Jason Rahm with Anthropic Claude 4 on June 6, 2025

set -euo pipefail

# Configuration
export VAULT_ADDR=${VAULT_ADDR:-'http://127.0.0.1:8200'}
export VAULT_TOKEN=${VAULT_TOKEN:-'dev-only-token'}

echo "Using VAULT_ADDR: $VAULT_ADDR"
echo "Using VAULT_TOKEN: ${VAULT_TOKEN:0:10}..." # Only show first 10 chars for security

BASE_TMPFS_DIR="/tmp/vault-secrets"
VAULT_CONFIG_DIR="$HOME/.config/.vault"
SERVICE_NAME="com.hashicorp.vault-proxy"
PLIST_PATH="$HOME/Library/LaunchAgents/${SERVICE_NAME}.plist"

# Global variable to store current role name and tmpfs directory
CURRENT_ROLE_NAME=""
CURRENT_TMPFS_DIR=""

# AppRole configuration
TOKEN_TTL="${TOKEN_TTL:-1h}"
TOKEN_MAX_TTL="${TOKEN_MAX_TTL:-4h}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Function to set current role and tmpfs directory
set_current_role() {
    local role_name=$1
    CURRENT_ROLE_NAME="$role_name"
    CURRENT_TMPFS_DIR="$BASE_TMPFS_DIR-$role_name"
}

# Function to check if vault is available and authenticated
check_vault() {
    if ! command -v vault &> /dev/null; then
        log_error "Vault CLI is not installed or not in PATH"
        exit 1
    fi

    if ! vault status &> /dev/null; then
        log_error "Cannot connect to Vault server. Check VAULT_ADDR and ensure Vault is running."
        exit 1
    fi

    if ! vault token lookup &> /dev/null; then
        log_error "Not authenticated to Vault. Please set VAULT_TOKEN or run 'vault auth'"
        exit 1
    fi

    log_info "Vault connection verified"
}

# Function to create tmpfs mount for a specific role
create_role_tmpfs() {
    local role_name=$1
    local tmpfs_dir="$BASE_TMPFS_DIR-$role_name"

    log_info "Creating role-specific tmpfs mount at $tmpfs_dir"

    # Create directory if it doesn't exist
    mkdir -p "$tmpfs_dir"

    # Check if already mounted
    if mount | grep -q "$tmpfs_dir"; then
        log_warn "tmpfs already mounted at $tmpfs_dir"
        return 0
    fi

    # Mount tmpfs
    sudo mount_tmpfs "$tmpfs_dir"
    sudo chown "$(whoami):staff" "$tmpfs_dir"
    chmod 700 "$tmpfs_dir"

    log_info "tmpfs mounted successfully at $tmpfs_dir"
}

# Function to create base tmpfs mount (for backward compatibility)
create_tmpfs() {
    log_info "Creating base tmpfs mount at $BASE_TMPFS_DIR"

    # Create directory if it doesn't exist
    mkdir -p "$BASE_TMPFS_DIR"

    # Check if already mounted
    if mount | grep -q "$BASE_TMPFS_DIR"; then
        log_warn "tmpfs already mounted at $BASE_TMPFS_DIR"
        return 0
    fi

    # Mount tmpfs
    sudo mount_tmpfs "$BASE_TMPFS_DIR"
    sudo chown "$(whoami):staff" "$BASE_TMPFS_DIR"
    chmod 700 "$BASE_TMPFS_DIR"

    log_info "tmpfs mounted successfully"
}

# Function to enable AppRole auth method if not already enabled
enable_approle() {
    if vault auth list | grep -q "approle/"; then
        log_info "AppRole auth method is already enabled"
    else
        log_info "Enabling AppRole auth method..."
        vault auth enable approle
        log_info "AppRole auth method enabled"
    fi
}

# Function to create a basic policy for the AppRole
create_policy() {
    local role_name=$1
    local policy_name="${role_name}-policy"

    log_info "Creating policy: $policy_name"

    cat > "/tmp/${policy_name}.hcl" << EOF
# Allow the agent to renew its own token
path "auth/token/renew-self" {
  capabilities = ["update"]
}

# Allow the agent to lookup its own token
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# Allow the agent to authenticate via AppRole
path "auth/approle/login" {
  capabilities = ["create", "update"]
}

# Example: Allow access to specific secrets (customize as needed)
path "secret/data/${role_name}/*" {
  capabilities = ["read"]
}

path "secret/metadata/${role_name}/*" {
  capabilities = ["read"]
}
EOF

    vault policy write "$policy_name" "/tmp/${policy_name}.hcl"
    rm "/tmp/${policy_name}.hcl"
    log_info "Policy created: $policy_name"

    echo "$policy_name"  # Return policy name
}

# Function to create the AppRole
create_approle() {
    local role_name=$1
    local policy_name=$2

    log_info "Creating AppRole: $role_name"

    vault write "auth/approle/role/$role_name" \
        token_policies="$policy_name" \
        token_ttl="$TOKEN_TTL" \
        token_max_ttl="$TOKEN_MAX_TTL" \
        bind_secret_id=true

    log_info "AppRole created: $role_name"
}

# Function to get and store AppRole credentials
store_approle_credentials() {
    local role_name=$1
    local tmpfs_dir="$BASE_TMPFS_DIR-$role_name"

    log_header "Storing AppRole Credentials"

    # Ensure tmpfs is available
    if [[ ! -d "$tmpfs_dir" ]]; then
        log_error "tmpfs directory $tmpfs_dir does not exist. Creating it now..."
        create_role_tmpfs "$role_name"
    fi

    # Get Role ID
    log_info "Retrieving Role ID..."
    local role_id
    role_id=$(vault read -field=role_id "auth/approle/role/$role_name/role-id")

    # Generate Secret ID
    log_info "Generating Secret ID..."
    local secret_id
    secret_id=$(vault write -field=secret_id -f "auth/approle/role/$role_name/secret-id")

    # Store credentials in tmpfs
    log_info "Storing credentials in tmpfs: $tmpfs_dir"
    echo "$role_id" > "$tmpfs_dir/role-id-$role_name"
    echo "$secret_id" > "$tmpfs_dir/secret-id-$role_name"
    chmod 600 "$tmpfs_dir/role-id-$role_name" "$tmpfs_dir/secret-id-$role_name"

    log_info "Credentials stored securely in tmpfs"
}

# Function to create complete AppRole setup
setup_approle() {
    local role_name

    echo -n "Enter AppRole name: "
    read -r role_name

    if [[ -z "$role_name" ]]; then
        log_error "Role name cannot be empty"
        exit 1
    fi

    # Set current role for global use
    set_current_role "$role_name"

    log_header "Creating Complete AppRole Setup: $role_name"

    check_vault
    enable_approle
    create_role_tmpfs "$role_name"

    local policy_name
    policy_name=$(create_policy "$role_name")
    create_approle "$role_name" "$policy_name"
    store_approle_credentials "$role_name"

    log_info "AppRole setup completed successfully!"

    echo
    log_header "AppRole Information"
    echo -e "${BLUE}Role Name:${NC} $role_name"
    echo -e "${BLUE}Policy:${NC} $policy_name"
    echo -e "${BLUE}Credentials stored in:${NC} $CURRENT_TMPFS_DIR"
    echo

    cat << EOF
${YELLOW}Usage Examples:${NC}
# Test authentication:
vault write auth/approle/login \\
    role_id="\$(cat $CURRENT_TMPFS_DIR/role-id-$role_name)" \\
    secret_id="\$(cat $CURRENT_TMPFS_DIR/secret-id-$role_name)"

# Use in Vault Agent/Proxy config:
role_id_file_path = "$CURRENT_TMPFS_DIR/role-id-$role_name"
secret_id_file_path = "$CURRENT_TMPFS_DIR/secret-id-$role_name"
EOF

    log_warn "Important Security Notes:"
    echo "- Credentials are stored in tmpfs (memory) and will be lost on reboot"
    echo "- This provides enhanced security as secrets are never written to disk"
    echo "- The Secret ID should be rotated regularly for security"
    echo "- Review and customize the policy according to your security requirements"
}

# Function to create vault proxy configuration
create_vault_config() {
    local role_name="${1:-}"
    local tmpfs_dir

    if [[ -n "$role_name" ]]; then
        tmpfs_dir="$BASE_TMPFS_DIR-$role_name"
        log_info "Creating Vault proxy configuration for role: $role_name"
    else
        tmpfs_dir="$BASE_TMPFS_DIR"
        log_info "Creating Vault proxy configuration (generic)"
    fi

    mkdir -p "$VAULT_CONFIG_DIR"

    cat > "$VAULT_CONFIG_DIR/proxy.hcl" << EOF
# Vault Proxy Configuration
vault {
  address = "$VAULT_ADDR"
  retry {
    num_retries = 5
  }
}

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path = "$tmpfs_dir/role-id-${role_name:-default}"
      secret_id_file_path = "$tmpfs_dir/secret-id-${role_name:-default}"
    }
  }

  sink "file" {
    config = {
      path = "$tmpfs_dir/token"
    }
  }
}

api_proxy {
  use_auto_auth_token = true
}

listener "tcp" {
  address = "127.0.0.1:8007"
  tls_disable = true
}

log_level = "info"
pid_file = "/tmp/vault-proxy.pid"
EOF

    log_info "Vault proxy configuration created at $VAULT_CONFIG_DIR/proxy.hcl"
    log_info "Configuration uses VAULT_ADDR: $VAULT_ADDR"
    if [[ -n "$role_name" ]]; then
        log_info "Configuration uses role-specific tmpfs: $tmpfs_dir"
    fi
}

# Function to create launchd plist
create_launchd_service() {
    log_info "Creating launchd service"

    # Create LaunchAgents directory if it doesn't exist
    mkdir -p "$HOME/Library/LaunchAgents"

    cat > "$PLIST_PATH" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${SERVICE_NAME}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/vault</string>
        <string>proxy</string>
        <string>-config</string>
        <string>${VAULT_CONFIG_DIR}/proxy.hcl</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/vault-proxy.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/vault-proxy-error.log</string>
    <key>WorkingDirectory</key>
    <string>${HOME}</string>
</dict>
</plist>
EOF

    log_info "Launchd service created at $PLIST_PATH"
}

# Function to setup existing credentials (manual entry)
setup_existing_credentials() {
    local role_name

    echo -n "Enter role name for these credentials: "
    read -r role_name

    if [[ -z "$role_name" ]]; then
        log_error "Role name cannot be empty"
        exit 1
    fi

    # Set current role for global use
    set_current_role "$role_name"
    local tmpfs_dir="$CURRENT_TMPFS_DIR"

    log_info "Setting up existing vault credentials for role: $role_name"

    # Create role-specific tmpfs if it doesn't exist
    if [[ ! -d "$tmpfs_dir" ]]; then
        create_role_tmpfs "$role_name"
    fi

    # Prompt for role ID
    echo -n "Enter Role ID: "
    read -r role_id
    echo "$role_id" > "$tmpfs_dir/role-id-$role_name"
    chmod 600 "$tmpfs_dir/role-id-$role_name"

    # Prompt for secret ID
    echo -n "Enter Secret ID: "
    read -rs secret_id  # -s for silent input
    echo
    echo "$secret_id" > "$tmpfs_dir/secret-id-$role_name"
    chmod 600 "$tmpfs_dir/secret-id-$role_name"

    log_info "Credentials stored in role-specific tmpfs: $tmpfs_dir"

    # Update proxy configuration to use this role's credentials
    create_vault_config "$role_name"
}

# Function to start the service
start_service() {
    log_info "Starting Vault proxy service"

    # Find all available role credentials
    local available_roles=()
    local role_dirs=()

    # Check base directory for generic files (backward compatibility)
    if [[ -f "$BASE_TMPFS_DIR/role-id" && -f "$BASE_TMPFS_DIR/secret-id" ]]; then
        available_roles+=("generic")
        role_dirs+=("$BASE_TMPFS_DIR")
    fi

    # Check for role-specific directories and files
    for dir in "$BASE_TMPFS_DIR"-*; do
        if [[ -d "$dir" ]]; then
            # Use a safer approach to handle potentially empty arrays
            local role_files=()
            while IFS= read -r -d '' file; do
                role_files+=("$file")
            done < <(find "$dir" -name "role-id-*" -print0 2>/dev/null)

            for file in "${role_files[@]+"${role_files[@]}"}"; do
                local role_name="${file##*/role-id-}"
                if [[ -f "$dir/secret-id-$role_name" ]]; then
                    available_roles+=("$role_name")
                    role_dirs+=("$dir")
                fi
            done
        fi
    done

    if [[ ${#available_roles[@]} -eq 0 ]]; then
        log_error "No credentials found in any tmpfs directory."
        log_error "Run '--create-approle' or '--existing-credentials' first."
        exit 1
    fi

    # If multiple roles available, let user choose
    local selected_role
    local selected_dir

    if [[ ${#available_roles[@]} -eq 1 ]]; then
        selected_role="${available_roles[0]}"
        selected_dir="${role_dirs[0]}"
        log_info "Using credentials for role: $selected_role"
    else
        echo "Multiple credential sets found:"
        for i in "${!available_roles[@]}"; do
            echo "  $((i+1)). ${available_roles[i]} (${role_dirs[i]})"
        done
        echo -n "Select credentials to use (1-${#available_roles[@]}): "
        read -r choice

        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le ${#available_roles[@]} ]]; then
            selected_role="${available_roles[$((choice-1))]}"
            selected_dir="${role_dirs[$((choice-1))]}"
            log_info "Using credentials for role: $selected_role"
        else
            log_error "Invalid selection"
            exit 1
        fi
    fi

    # Update proxy configuration to use selected credentials
    if [[ "$selected_role" == "generic" ]]; then
        create_vault_config  # Use generic config
    else
        create_vault_config "$selected_role"  # Use role-specific config
    fi

    log_info "Using credentials from: $selected_dir"

    # Stop any existing service first
    if launchctl list | grep -q "$SERVICE_NAME"; then
        log_warn "Service already running, stopping it first..."
        launchctl unload "$PLIST_PATH" 2>/dev/null || true
        sleep 1
    fi

    # Load the service
    log_info "Loading Vault proxy service..."
    if ! launchctl load "$PLIST_PATH" 2>/dev/null; then
        log_warn "Standard load failed, trying bootstrap method..."
        if ! launchctl bootstrap gui/$(id -u) "$PLIST_PATH" 2>/dev/null; then
            log_error "Failed to load service with both methods"
            log_error "Check that the vault binary is at /usr/local/bin/vault"
            log_error "Or check logs at /tmp/vault-proxy-error.log for details"
            # Don't exit here, let's check if it actually started
        fi
    fi

    # Wait a moment and check status
    sleep 3
    if launchctl list | grep -q "$SERVICE_NAME"; then
        log_info "Vault proxy service started successfully"
        log_info "Proxy available at: http://127.0.0.1:8007"
        log_info "Logs available at: /tmp/vault-proxy.log"
        log_info "Error logs at: /tmp/vault-proxy-error.log"

        # Test the proxy endpoint
        sleep 2
        if curl -s http://127.0.0.1:8007/v1/sys/health >/dev/null 2>&1; then
            log_info "Proxy endpoint is responding correctly"
        else
            log_warn "Proxy endpoint not yet responding - check logs if issues persist"
        fi
    else
        log_error "Failed to start Vault proxy service"
        log_error "Check logs at /tmp/vault-proxy-error.log for details"
        log_error "Common issues:"
        log_error "  - Vault binary not found at /usr/local/bin/vault"
        log_error "  - Invalid credentials"
        log_error "  - Vault server not accessible"
        exit 1
    fi
}

# Function to stop the service
stop_service() {
    log_info "Stopping Vault proxy service"

    if launchctl list | grep -q "$SERVICE_NAME"; then
        launchctl unload "$PLIST_PATH"
        log_info "Vault proxy service stopped"
    else
        log_warn "Vault proxy service is not running"
    fi
}

# Function to cleanup credentials
cleanup_credentials() {
    log_info "Cleaning up credentials"

    # Find all tmpfs directories
    local tmpfs_dirs=()

    if [[ -d "$BASE_TMPFS_DIR" ]]; then
        tmpfs_dirs+=("$BASE_TMPFS_DIR")
    fi

    for dir in "$BASE_TMPFS_DIR"-*; do
        if [[ -d "$dir" ]]; then
            tmpfs_dirs+=("$dir")
        fi
    done

    if [[ ${#tmpfs_dirs[@]} -eq 0 ]]; then
        log_warn "No tmpfs directories found"
        return
    fi

    # If multiple directories exist, let user choose
    if [[ ${#tmpfs_dirs[@]} -gt 1 ]]; then
        echo "Multiple credential directories found:"
        for i in "${!tmpfs_dirs[@]}"; do
            echo "  $((i+1)). ${tmpfs_dirs[i]}"
        done
        echo -n "Select directory to clean up (1-${#tmpfs_dirs[@]}, or 'all'): "
        read -r choice

        if [[ "$choice" == "all" ]]; then
            for dir in "${tmpfs_dirs[@]}"; do
                cleanup_single_dir "$dir"
            done
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le ${#tmpfs_dirs[@]} ]]; then
            cleanup_single_dir "${tmpfs_dirs[$((choice-1))]}"
        else
            log_error "Invalid selection"
            exit 1
        fi
    else
        cleanup_single_dir "${tmpfs_dirs[0]}"
    fi
}

# Helper function to cleanup a single directory
cleanup_single_dir() {
    local dir=$1
    log_info "Cleaning up credentials in: $dir"

    # Clean up role-specific files
    local secret_files=($(find "$dir" -name "secret-id-*" 2>/dev/null))
    for file in "${secret_files[@]}"; do
        rm -f "$file"
        log_info "Secret ID removed: $file"
    done

    # Clean up generic secret-id for backward compatibility
    if [[ -f "$dir/secret-id" ]]; then
        rm -f "$dir/secret-id"
        log_info "Generic Secret ID removed from $dir"
    fi

    if [[ -f "$dir/token" ]]; then
        rm -f "$dir/token"
        log_info "Cached token removed from $dir"
    fi

    # Handle role-id files
    local role_files=($(find "$dir" -name "role-id-*" 2>/dev/null))
    local has_role_files=false

    if [[ ${#role_files[@]} -gt 0 ]] || [[ -f "$dir/role-id" ]]; then
        has_role_files=true
    fi

    if [[ "$has_role_files" == true ]]; then
        echo -n "Remove role ID files from $dir as well? (y/N): "
        read -r remove_role_id
        if [[ "$remove_role_id" =~ ^[Yy]$ ]]; then
            for file in "${role_files[@]}"; do
                rm -f "$file"
                log_info "Role ID removed: $file"
            done
            # Clean up generic role-id for backward compatibility
            if [[ -f "$dir/role-id" ]]; then
                rm -f "$dir/role-id"
                log_info "Generic Role ID removed from $dir"
            fi
        fi
    fi
}

# Function to cleanup everything
cleanup_all() {
    log_info "Performing full cleanup"

    # Stop service if running
    stop_service

    # Remove credentials from all tmpfs directories
    local tmpfs_dirs=()

    if [[ -d "$BASE_TMPFS_DIR" ]]; then
        tmpfs_dirs+=("$BASE_TMPFS_DIR")
    fi

    for dir in "$BASE_TMPFS_DIR"-*; do
        if [[ -d "$dir" ]]; then
            tmpfs_dirs+=("$dir")
        fi
    done

    for dir in "${tmpfs_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            log_info "Removing credentials from: $dir"
            rm -rf "$dir"/*
        fi
    done

    # Unmount all tmpfs directories
    for dir in "${tmpfs_dirs[@]}"; do
        if mount | grep -q "$dir"; then
            log_info "Unmounting tmpfs: $dir"
            sudo umount "$dir"
        fi
    done

    # Remove service
    if [[ -f "$PLIST_PATH" ]]; then
        rm -f "$PLIST_PATH"
        log_info "Launchd service removed"
    fi

    log_info "Full cleanup completed"
}

# Function to show status
show_status() {
    echo "=== Vault Proxy Status ==="

    # Find all tmpfs directories
    local tmpfs_dirs=()

    if [[ -d "$BASE_TMPFS_DIR" ]]; then
        tmpfs_dirs+=("$BASE_TMPFS_DIR")
    fi

    for dir in "$BASE_TMPFS_DIR"-*; do
        if [[ -d "$dir" ]]; then
            tmpfs_dirs+=("$dir")
        fi
    done

    # Check tmpfs mounts
    if [[ ${#tmpfs_dirs[@]} -eq 0 ]]; then
        echo -e "tmpfs: ${RED}no directories found${NC}"
    else
        for dir in "${tmpfs_dirs[@]}"; do
            local role_name
            if [[ "$dir" == "$BASE_TMPFS_DIR" ]]; then
                role_name="(base)"
            else
                role_name="(${dir#$BASE_TMPFS_DIR-})"
            fi

            if mount | grep -q "$dir"; then
                echo -e "tmpfs $role_name: ${GREEN}mounted${NC} at $dir"
            else
                echo -e "tmpfs $role_name: ${RED}not mounted${NC} at $dir"
            fi

            # Check credentials in this directory
            local role_files=($(find "$dir" -name "role-id-*" 2>/dev/null))
            local secret_files=($(find "$dir" -name "secret-id-*" 2>/dev/null))

            if [[ ${#role_files[@]} -gt 0 ]] || [[ -f "$dir/role-id" ]]; then
                echo -e "  Role ID: ${GREEN}present${NC}"
                if [[ ${#role_files[@]} -gt 0 ]]; then
                    for file in "${role_files[@]}"; do
                        local role_name="${file##*/role-id-}"
                        echo -e "    - role-id-$role_name"
                    done
                fi
                if [[ -f "$dir/role-id" ]]; then
                    echo -e "    - role-id (generic)"
                fi
            else
                echo -e "  Role ID: ${RED}missing${NC}"
            fi

            if [[ ${#secret_files[@]} -gt 0 ]] || [[ -f "$dir/secret-id" ]]; then
                echo -e "  Secret ID: ${GREEN}present${NC}"
                if [[ ${#secret_files[@]} -gt 0 ]]; then
                    for file in "${secret_files[@]}"; do
                        local role_name="${file##*/secret-id-}"
                        echo -e "    - secret-id-$role_name"
                    done
                fi
                if [[ -f "$dir/secret-id" ]]; then
                    echo -e "    - secret-id (generic)"
                fi
            else
                echo -e "  Secret ID: ${RED}missing${NC}"
            fi

            if [[ -f "$dir/token" ]]; then
                echo -e "  Vault Token: ${GREEN}present${NC}"
            else
                echo -e "  Vault Token: ${RED}missing${NC}"
            fi
        done
    fi

    # Check service
    if launchctl list | grep -q "$SERVICE_NAME"; then
        echo -e "Service: ${GREEN}running${NC}"
    else
        echo -e "Service: ${RED}not running${NC}"
    fi

    # Check proxy endpoint
    if curl -s http://127.0.0.1:8007/v1/sys/health >/dev/null 2>&1; then
        echo -e "Proxy Endpoint: ${GREEN}accessible${NC}"
    else
        echo -e "Proxy Endpoint: ${RED}not accessible${NC}"
    fi
}

# Function to show help
show_help() {
    cat << EOF
Vault Proxy Management Script for macOS

This script provides complete management of HashiCorp Vault AppRoles and Proxy setup.

Usage: $0 [OPTION]

Setup Options:
  --setup             Initial setup (tmpfs, config, service)
  --create-approle    Create new AppRole and store credentials
  --existing-credentials  Store existing AppRole credentials

Service Management:
  --start             Start the vault proxy service
  --stop              Stop the vault proxy service
  --status            Show current status

Cleanup Options:
  --cleanup           Remove credentials from tmpfs
  --cleanup-all       Full cleanup (stop service, remove everything)

Information:
  --help, -h          Show this help message

Environment Variables:
  VAULT_ADDR          Vault server address (default: http://127.0.0.1:8200)
  VAULT_TOKEN         Vault authentication token
  TOKEN_TTL           AppRole token TTL (default: 1h)
  TOKEN_MAX_TTL       AppRole token max TTL (default: 4h)

Typical Workflows:

New AppRole Setup:
  1. $0 --setup
  2. $0 --create-approle
  3. $0 --start
  4. $0 --cleanup (optional, to remove secret-id after successful start)

Existing AppRole Setup:
  1. $0 --setup
  2. $0 --existing-credentials
  3. $0 --start

Security Features:
  - Credentials stored in role-specific tmpfs directories (memory-only, never written to disk)
  - Role-specific directories: /tmp/vault-secrets-ROLENAME/
  - Restrictive file permissions (600)
  - Automatic credential cleanup options
  - Separate secret-id rotation support

Service Details:
  - Proxy runs on: http://127.0.0.1:8007
  - Logs: /tmp/vault-proxy.log
  - Error logs: /tmp/vault-proxy-error.log
  - Service name: $SERVICE_NAME

Credential Storage:
  - Each AppRole gets its own tmpfs directory
  - Format: /tmp/vault-secrets-ROLENAME/
  - Files: role-id, secret-id, token (auto-generated)
  - Base directory: /tmp/vault-secrets (for backward compatibility)
EOF
}

# Main script logic
case "${1:-}" in
    "--setup")
        create_tmpfs
        create_vault_config
        create_launchd_service
        log_info "Setup complete! Next steps:"
        log_info "1. Run '$0 --create-approle' to create new AppRole"
        log_info "   OR '$0 --existing-credentials' to use existing credentials"
        log_info "2. Run '$0 --start' to start the service"
        ;;
    "--create-approle")
        setup_approle
        # After creating AppRole, update proxy config to use the role-specific path
        if [[ -n "$CURRENT_ROLE_NAME" ]]; then
            create_vault_config "$CURRENT_ROLE_NAME"
            log_info "Proxy configuration updated for role: $CURRENT_ROLE_NAME"
        fi
        ;;
    "--existing-credentials")
        setup_existing_credentials
        ;;
    "--start")
        start_service
        ;;
    "--stop")
        stop_service
        ;;
    "--cleanup")
        cleanup_credentials
        ;;
    "--cleanup-all")
        cleanup_all
        ;;
    "--status")
        show_status
        ;;
    "--help"|"-h"|"")
        show_help
        ;;
    *)
        log_error "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac
