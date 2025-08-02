#!/bin/bash

# SSH Tools Plugin - Main Logic Script
# Handles SSH key generation, exchange, and management operations

set -e

# Constants
SSH_KEY_TYPE="ed25519"
SSH_KEY_PATH="/root/.ssh/id_${SSH_KEY_TYPE}"
SSH_PUB_KEY_PATH="${SSH_KEY_PATH}.pub"
PLUGIN_DATA_DIR="/boot/config/plugins/ssh-tools"
EXCHANGED_KEYS_FILE="${PLUGIN_DATA_DIR}/exchanged_keys.txt"

# Helper functions
error_exit() {
    echo "Error: $1" >&2
    exit 1
}

debug_log() {
    echo "DEBUG: $1" >&2
}

log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Ensure plugin data directory exists
ensure_data_dir() {
    if [[ ! -d "$PLUGIN_DATA_DIR" ]]; then
        mkdir -p "$PLUGIN_DATA_DIR"
        debug_log "Created plugin data directory: $PLUGIN_DATA_DIR"
    fi
    
    # Ensure exchanged keys file exists
    if [[ ! -f "$EXCHANGED_KEYS_FILE" ]]; then
        touch "$EXCHANGED_KEYS_FILE"
        debug_log "Created exchanged keys tracking file: $EXCHANGED_KEYS_FILE"
    fi
    
    # Set proper permissions
    chmod 644 "$EXCHANGED_KEYS_FILE" 2>/dev/null || true
}

# Validate environment
validate_environment() {
    if [[ -z "$OPERATION" ]]; then
        error_exit "No operation specified"
    fi
    
    debug_log "Operation: $OPERATION"
    ensure_data_dir
}

# Check if SSH key exists and generate if needed
check_or_generate_ssh_key() {
    if [[ ! -f "$SSH_KEY_PATH" ]]; then
        log_info "Generating new ${SSH_KEY_TYPE} SSH key..."
        ssh-keygen -t "$SSH_KEY_TYPE" -f "$SSH_KEY_PATH" -N "" -C "unraid-ssh-tools-$(hostname)"
        log_info "SSH key generated successfully"
        return 0
    else
        debug_log "SSH key already exists at $SSH_KEY_PATH"
        return 0  # Return success - existing key is fine
    fi
}

# Get SSH key status information
get_key_status() {
    if [[ -f "$SSH_KEY_PATH" ]] && [[ -f "$SSH_PUB_KEY_PATH" ]]; then
        local fingerprint=$(ssh-keygen -lf "$SSH_PUB_KEY_PATH" 2>/dev/null | awk '{print $2}')
        echo "SSH key exists - Fingerprint: $fingerprint"
    else
        echo "No SSH key found - will be generated when needed"
    fi
}

# Test SSH connection (with password authentication)
test_ssh_connection() {
    local host="$1"
    local username="$2"
    local password="$3"
    
    log_info "Testing SSH connection to ${username}@${host}..."
    
    # Use sshpass for password authentication (installed as dependency)
    if sshpass -p "$password" ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o BatchMode=no "${username}@${host}" "echo 'Connection test successful'" 2>/dev/null; then
        log_info "Connection test to ${username}@${host} succeeded"
        return 0
    else
        log_info "Connection test to ${username}@${host} failed - check credentials"
        return 1
    fi
}

# Exchange SSH keys with remote host
exchange_ssh_keys() {
    local host="$1"
    local username="$2"
    local password="$3"
    
    log_info "Starting SSH key exchange with ${username}@${host}..."
    
    # Ensure SSH key exists
    check_or_generate_ssh_key
    log_info "Using SSH key: $SSH_PUB_KEY_PATH"
    
    # Check if keys are already exchanged
    if ssh -o BatchMode=yes -o ConnectTimeout=5 "${username}@${host}" true 2>/dev/null; then
        log_info "SSH keys already exchanged with ${username}@${host}"
        log_info "Adding existing exchange to tracking list..."
        
        # Record the existing exchange (rediscovery feature)
        echo "$(date '+%Y-%m-%d %H:%M:%S') ${username}@${host}" >> "$EXCHANGED_KEYS_FILE"
        debug_log "Exchange recorded: $(tail -1 "$EXCHANGED_KEYS_FILE" 2>/dev/null || echo 'Failed to read tracking file')"
        
        log_info "Existing SSH key exchange added to tracking list successfully!"
        return 0
    fi
    
    # Test connection first
    if ! test_ssh_connection "$host" "$username" "$password"; then
        error_exit "Cannot connect to ${username}@${host} with provided credentials"
    fi
    
    # Exchange keys using ssh-copy-id with sshpass (the proven Unraid method)
    log_info "Exchanging SSH keys with ${username}@${host}..."
    
    # Use sshpass with ssh-copy-id (sshpass installed as plugin dependency)
    if sshpass -p "$password" ssh-copy-id -f -o StrictHostKeyChecking=no -i "$SSH_PUB_KEY_PATH" "${username}@${host}" 2>&1; then
        log_info "SSH key successfully copied to ${username}@${host}"
    else
        error_exit "Failed to copy SSH key to ${username}@${host}"
    fi
    
    # Update known_hosts to fix Unraid-specific issue
    log_info "Updating known_hosts file..."
    
    # Fix permissions on known_hosts file first
    if [[ -f ~/.ssh/known_hosts ]]; then
        chmod 644 ~/.ssh/known_hosts 2>/dev/null || true
        # Remove any existing entries for this host to prevent duplicates
        ssh-keygen -R "$host" 2>/dev/null || true
    fi
    
    # Add the host key using ssh-keyscan (your proven method)
    ssh-keyscan -H "$host" >> ~/.ssh/known_hosts 2>/dev/null || true
    
    # Set proper permissions
    chmod 600 ~/.ssh/known_hosts 2>/dev/null || true
    
    # Verify the key exchange worked
    log_info "Verifying passwordless SSH connection..."
    if ssh -o BatchMode=yes -o ConnectTimeout=5 "${username}@${host}" true 2>/dev/null; then
        log_info "SSH key exchange completed successfully!"
        
        # Record the successful exchange
        log_info "Recording successful exchange in tracking file..."
        echo "$(date '+%Y-%m-%d %H:%M:%S') ${username}@${host}" >> "$EXCHANGED_KEYS_FILE"
        
        # Debug: Confirm what was written
        debug_log "Exchange recorded: $(tail -1 "$EXCHANGED_KEYS_FILE" 2>/dev/null || echo 'Failed to read tracking file')"
        
        return 0
    else
        error_exit "SSH key exchange failed - cannot connect without password"
    fi
}

# Test a single SSH connection (key-based)
test_single_ssh_connection() {
    local host="$1"
    
    log_info "Testing SSH connection to $host..."
    
    if ssh -o BatchMode=yes -o ConnectTimeout=5 root@"$host" "echo 'SSH connection successful'" 2>/dev/null; then
        log_info "SSH connection to $host successful (key-based authentication)"
    else
        log_info "SSH connection to $host failed (no key-based access)"
    fi
}

# List exchanged SSH keys
list_exchanged_keys() {
    if [[ -f "$EXCHANGED_KEYS_FILE" ]]; then
        echo "<h4>Successfully Exchanged Keys:</h4>"
        
        # Debug: Show file contents
        debug_log "Exchanged keys file contents:"
        debug_log "$(cat "$EXCHANGED_KEYS_FILE" 2>/dev/null || echo 'Failed to read file')"
        debug_log "Line count: $(wc -l < "$EXCHANGED_KEYS_FILE" 2>/dev/null || echo '0')"
        
        if [[ -s "$EXCHANGED_KEYS_FILE" ]]; then
            echo "<div style='margin-bottom: 15px;'>"
            
            while IFS= read -r line; do
                if [[ -n "$line" ]]; then
                    # Parse the line: "YYYY-MM-DD HH:MM:SS user@host"
                    timestamp=$(echo "$line" | awk '{print $1, $2}')
                    connection=$(echo "$line" | awk '{print $3}')
                    username=$(echo "$connection" | cut -d'@' -f1)
                    hostname=$(echo "$connection" | cut -d'@' -f2)
                    
                    # Debug logging
                    debug_log "Processing line: $line"
                    debug_log "Parsed - timestamp: $timestamp, connection: $connection, username: $username, hostname: $hostname"
                    
                    # Test if connection is still active
                    status_color="#28a745"
                    status_text="✓ Active"
                    if ! ssh -o BatchMode=yes -o ConnectTimeout=3 "${connection}" true 2>/dev/null; then
                        status_color="#dc3545"
                        status_text="✗ Inactive"
                    fi
                    
                    echo "<div style='margin-bottom: 10px; padding: 12px; border: 1px solid #ddd; border-radius: 5px; background: #f8f9fa;'>"
                    echo "  <div style='display: flex; justify-content: space-between; align-items: center;'>"
                    echo "    <div>"
                    echo "      <strong style='color: #333;'>$hostname</strong>"
                    echo "      <span style='color: #666; margin-left: 10px;'>User: $username</span>"
                    echo "      <div style='font-size: 11px; color: #888; margin-top: 2px;'>Exchanged: $timestamp</div>"
                    echo "    </div>"
                    echo "    <div style='color: $status_color; font-weight: bold; font-size: 12px;'>$status_text</div>"
                    echo "  </div>"
                    echo "</div>"
                fi
            done < "$EXCHANGED_KEYS_FILE"
            
            echo "</div>"
        else
            echo "<div style='color: #666; font-style: italic; text-align: center; padding: 20px; border: 1px dashed #ccc; border-radius: 5px;'>"
            echo "No SSH keys have been exchanged yet.<br>Use the 'Exchange SSH Keys' tab to add your first connection."
            echo "</div>"
        fi
    else
        echo "<div style='color: #666; font-style: italic; text-align: center; padding: 20px; border: 1px dashed #ccc; border-radius: 5px;'>"
        echo "No SSH keys have been exchanged yet.<br>Use the 'Exchange SSH Keys' tab to add your first connection."
        echo "</div>"
    fi
}

# Test all previously exchanged connections
test_all_connections() {
    if [[ ! -f "$EXCHANGED_KEYS_FILE" ]] || [[ ! -s "$EXCHANGED_KEYS_FILE" ]]; then
        log_info "No exchanged keys to test"
        return 0
    fi
    
    log_info "Testing all exchanged SSH connections..."
    
    local success_count=0
    local total_count=0
    
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            # Extract host from the line (format: "YYYY-MM-DD HH:MM:SS user@host")
            local host_info=$(echo "$line" | awk '{print $3}')
            local host=$(echo "$host_info" | cut -d'@' -f2)
            local username=$(echo "$host_info" | cut -d'@' -f1)
            
            ((total_count++))
            
            if ssh -o BatchMode=yes -o ConnectTimeout=5 "${username}@${host}" true 2>/dev/null; then
                log_info "✓ Connection to ${username}@${host} successful"
                ((success_count++))
            else
                log_info "✗ Connection to ${username}@${host} failed"
            fi
        fi
    done < "$EXCHANGED_KEYS_FILE"
    
    log_info "Connection test complete: $success_count/$total_count connections successful"
}

# Scan network for SSH services
scan_for_ssh() {
    local network="$1"
    
    log_info "Scanning $network for SSH services..."
    
    # Use nmap if available, otherwise use basic network scanning
    if command -v nmap >/dev/null 2>&1; then
        nmap -p 22 --open "$network" 2>/dev/null | grep -E "(Nmap scan report|22/tcp)" | sed 's/Nmap scan report for //' | awk '/report/{host=$0} /22\/tcp/{print host " - SSH open"}'
    else
        # Basic ping sweep for the network (simplified)
        log_info "nmap not available, performing basic network scan..."
        
        # Extract network base (assuming /24)
        local base=$(echo "$network" | cut -d'.' -f1-3)
        local tested=0
        local found=0
        
        for i in {1..254}; do
            local ip="${base}.${i}"
            if timeout 2 bash -c "</dev/tcp/${ip}/22" 2>/dev/null; then
                log_info "✓ SSH service found on $ip"
                ((found++))
            fi
            ((tested++))
            
            # Progress indicator every 50 hosts
            if ((tested % 50 == 0)); then
                log_info "Scanned $tested hosts, found $found SSH services so far..."
            fi
        done
        
        log_info "Network scan complete: found $found SSH services out of $tested hosts"
    fi
}

# Main logic dispatcher
process_operation() {
    local operation="$1"
    
    case "$operation" in
        "check_key_status")
            get_key_status
            ;;
        "test_connection")
            if [[ -z "$REMOTE_HOST" ]] || [[ -z "$REMOTE_USERNAME" ]] || [[ -z "$REMOTE_PASSWORD" ]]; then
                error_exit "Missing required parameters for connection test"
            fi
            test_ssh_connection "$REMOTE_HOST" "$REMOTE_USERNAME" "$REMOTE_PASSWORD"
            ;;
        "exchange_keys")
            if [[ -z "$REMOTE_HOST" ]] || [[ -z "$REMOTE_USERNAME" ]] || [[ -z "$REMOTE_PASSWORD" ]]; then
                error_exit "Missing required parameters for key exchange"
            fi
            exchange_ssh_keys "$REMOTE_HOST" "$REMOTE_USERNAME" "$REMOTE_PASSWORD"
            ;;
        "test_single_connection")
            if [[ -z "$TEST_HOST" ]]; then
                error_exit "Missing host parameter for connection test"
            fi
            test_single_ssh_connection "$TEST_HOST"
            ;;
        "list_exchanged_keys")
            list_exchanged_keys
            ;;
        "test_all_connections")
            test_all_connections
            ;;
        "scan_ssh")
            if [[ -z "$SCAN_NETWORK" ]]; then
                error_exit "Missing network parameter for SSH scan"
            fi
            scan_for_ssh "$SCAN_NETWORK"
            ;;
        *)
            error_exit "Unknown operation: $operation"
            ;;
    esac
}

# Main execution
main() {
    validate_environment
    process_operation "$OPERATION"
}

# Execute main function
main "$@"
