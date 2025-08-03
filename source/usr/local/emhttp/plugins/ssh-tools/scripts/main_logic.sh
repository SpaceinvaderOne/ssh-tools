#!/bin/bash

# SSH Tools Plugin - Main Logic Script
# Handles SSH key generation, exchange, and management operations

# set -e  # Temporarily disabled to prevent script from exiting on errors

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
    
    # debug_log "Operation: $OPERATION" # Removed - corrupts HTML output
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

# Get SSH key status information (user-friendly)
get_key_status() {
    if [[ -f "$SSH_KEY_PATH" ]] && [[ -f "$SSH_PUB_KEY_PATH" ]]; then
        echo "✓ SSH key ready for exchanges"
    else
        echo "⚠ No SSH key found - will generate automatically"
    fi
}

# Test SSH connection (with password authentication)
test_ssh_connection() {
    local host="$1"
    local username="$2"
    local password="$3"
    local port="${4:-22}"  # Default to port 22 if not specified
    
    log_info "Testing SSH connection to ${username}@${host}:${port}..."
    
    # First test basic connectivity to the port
    if ! timeout 5 bash -c "</dev/tcp/${host}/${port}" 2>/dev/null; then
        log_info "Cannot reach ${host}:${port} - port may be closed or host unreachable"
        return 1
    fi
    
    # Use sshpass for password authentication (installed as dependency)
    # Try with explicit port format and additional SSH options for non-standard ports
    if sshpass -p "$password" ssh -p "$port" -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o BatchMode=no -o UserKnownHostsFile=/dev/null "${username}@${host}" "echo 'Connection test successful'" 2>/dev/null; then
        log_info "Connection test to ${username}@${host}:${port} succeeded"
        return 0
    else
        # Try alternative SSH syntax for troubleshooting
        log_info "Primary connection failed, testing with verbose output..."
        debug_log "Attempting connection with debug info..."
        
        # Capture error output for debugging
        local ssh_error
        ssh_error=$(sshpass -p "$password" ssh -v -p "$port" -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o BatchMode=no -o UserKnownHostsFile=/dev/null "${username}@${host}" "echo 'test'" 2>&1 | head -10)
        debug_log "SSH debug output: $ssh_error"
        
        log_info "Connection test to ${username}@${host}:${port} failed - check credentials and SSH service"
        return 1
    fi
}

# Exchange SSH keys with remote host
exchange_ssh_keys() {
    local host="$1"
    local username="$2"
    local password="$3"
    local port="${4:-22}"  # Default to port 22 if not specified
    
    log_info "Starting SSH key exchange with ${username}@${host}:${port}..."
    
    # Ensure SSH key exists
    check_or_generate_ssh_key
    log_info "Using SSH key: $SSH_PUB_KEY_PATH"
    
    # Check if keys are already exchanged
    if ssh -p "$port" -o BatchMode=yes -o ConnectTimeout=5 "${username}@${host}" true 2>/dev/null; then
        log_info "SSH keys already exchanged with ${username}@${host}:${port}"
        log_info "Adding existing exchange to tracking list..."
        
        # Record the existing exchange (rediscovery feature) - always include port
        echo "$(date '+%Y-%m-%d %H:%M:%S') ${username}@${host}:${port}" >> "$EXCHANGED_KEYS_FILE"
        log_info "Exchange recorded to: $EXCHANGED_KEYS_FILE"
        log_info "File now contains: $(wc -l < "$EXCHANGED_KEYS_FILE") lines"
        
        log_info "Existing SSH key exchange added to tracking list successfully!"
        return 0
    fi
    
    # Test connection first
    if ! test_ssh_connection "$host" "$username" "$password" "$port"; then
        error_exit "Cannot connect to ${username}@${host}:${port} with provided credentials"
    fi
    
    # Exchange keys using ssh-copy-id with sshpass (the proven Unraid method)
    log_info "Exchanging SSH keys with ${username}@${host}:${port}..."
    
    # Use sshpass with ssh-copy-id (sshpass installed as plugin dependency)
    if sshpass -p "$password" ssh-copy-id -p "$port" -f -o StrictHostKeyChecking=no -i "$SSH_PUB_KEY_PATH" "${username}@${host}" 2>&1; then
        log_info "SSH key successfully copied to ${username}@${host}:${port}"
    else
        error_exit "Failed to copy SSH key to ${username}@${host}:${port}"
    fi
    
    # Update known_hosts to fix Unraid-specific issue
    log_info "Updating known_hosts file..."
    
    # Fix permissions on known_hosts file first
    if [[ -f ~/.ssh/known_hosts ]]; then
        chmod 644 ~/.ssh/known_hosts 2>/dev/null || true
        # Remove any existing entries for this host to prevent duplicates
        ssh-keygen -R "$host" 2>/dev/null || true
        # Also remove entries with port specification
        ssh-keygen -R "[$host]:$port" 2>/dev/null || true
    fi
    
    # Add the host key using ssh-keyscan with port (your proven method)
    ssh-keyscan -p "$port" -H "$host" >> ~/.ssh/known_hosts 2>/dev/null || true
    
    # Set proper permissions
    chmod 600 ~/.ssh/known_hosts 2>/dev/null || true
    
    # Verify the key exchange worked
    log_info "Verifying passwordless SSH connection..."
    if ssh -p "$port" -o BatchMode=yes -o ConnectTimeout=5 "${username}@${host}" true 2>/dev/null; then
        log_info "SSH key exchange completed successfully!"
        
        # Record the successful exchange - always include port
        log_info "Recording successful exchange in tracking file..."
        echo "$(date '+%Y-%m-%d %H:%M:%S') ${username}@${host}:${port}" >> "$EXCHANGED_KEYS_FILE"
        log_info "Exchange recorded to: $EXCHANGED_KEYS_FILE"
        log_info "File now contains: $(wc -l < "$EXCHANGED_KEYS_FILE") lines"
        
        return 0
    else
        error_exit "SSH key exchange failed - cannot connect without password"
    fi
}

# Test a single SSH connection (key-based)
test_single_ssh_connection() {
    local host="$1"
    local port="${2:-22}"  # Default to port 22 if not specified
    local username="${3:-${TEST_USERNAME:-root}}"  # Use provided username or default to root
    
    # Parse host:port format if provided as single parameter
    if [[ "$host" == *":"* ]]; then
        port=$(echo "$host" | cut -d':' -f2)
        host=$(echo "$host" | cut -d':' -f1)
    fi
    
    local display_host="$host"
    if [[ "$port" != "22" ]]; then
        display_host="${host}:${port}"
    fi
    
    log_info "Testing SSH connection to ${username}@$display_host..."
    
    if ssh -p "$port" -o BatchMode=yes -o ConnectTimeout=5 "${username}@${host}" "echo 'SSH connection successful'" 2>/dev/null; then
        log_info "SSH connection to ${username}@$display_host successful (key-based authentication)"
    else
        log_info "SSH connection to ${username}@$display_host failed (no key-based access)"
    fi
}

# List exchanged SSH keys
list_exchanged_keys() {
    if [[ -f "$EXCHANGED_KEYS_FILE" ]]; then
        echo "<h4>Successfully Exchanged Keys:</h4>"
        
        # Debug removed - was corrupting HTML output
        
        if [[ -s "$EXCHANGED_KEYS_FILE" ]]; then
            echo "<div style='margin-bottom: 15px;'>"
            
            entry_count=0
            while IFS= read -r line; do
                if [[ -n "$line" ]]; then
                    ((entry_count++))
                    # Parse the line: "YYYY-MM-DD HH:MM:SS user@host:port"
                    timestamp=$(echo "$line" | awk '{print $1, $2}')
                    connection=$(echo "$line" | awk '{print $3}')
                    username=$(echo "$connection" | cut -d'@' -f1)
                    host_with_port=$(echo "$connection" | cut -d'@' -f2)
                    
                    # Split hostname and port (format: hostname:port or just hostname)
                    if [[ "$host_with_port" == *":"* ]]; then
                        hostname=$(echo "$host_with_port" | cut -d':' -f1)
                        port=$(echo "$host_with_port" | cut -d':' -f2)
                    else
                        hostname="$host_with_port"
                        port="22"
                    fi
                    
                    # Debug removed - was corrupting HTML output
                    
                    # Test if connection is still active (temporarily disabled for debugging)
                    status_color="#28a745"
                    status_text="✓ Active"
                    # if ! ssh -o BatchMode=yes -o ConnectTimeout=3 "${connection}" true 2>/dev/null; then
                    #     status_color="#dc3545"
                    #     status_text="✗ Inactive"
                    # fi
                    
                    # Display hostname with port if non-standard
                    display_host="$hostname"
                    if [[ "$port" != "22" ]]; then
                        display_host="${hostname}:${port}"
                    fi
                    
                    # Generate unique ID for this exchanged key (using entry count)
                    local key_id="exchanged_key_${entry_count}"
                    
                    echo "<div style='margin-bottom: 10px; padding: 12px; border: 1px solid #ddd; border-radius: 5px; background: #f8f9fa;'>"
                    echo "  <div style='display: flex; justify-content: space-between; align-items: center;'>"
                    echo "    <div>"
                    echo "      <strong style='color: #333;'>$display_host</strong>"
                    echo "      <span style='color: #666; margin-left: 10px;'>User: $username</span>"
                    echo "      <div style='font-size: 11px; color: #888; margin-top: 2px;'>Exchanged: $timestamp</div>"
                    echo "    </div>"
                    echo "    <div style='display: flex; align-items: center; gap: 15px;'>"
                    echo "      <div style='color: $status_color; font-weight: bold; font-size: 12px;'>$status_text</div>"
                    echo "      <button onclick=\"revokeExchangedKey('$key_id', '$display_host', '$hostname', '$username', '$port', $entry_count)\" style='background: #dc3545; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; font-size: 11px;' title='Revoke SSH access'>Revoke Access</button>"
                    echo "    </div>"
                    echo "  </div>"
                    echo "</div>"
                fi
            done < "$EXCHANGED_KEYS_FILE"
            
            # Debug removed - was corrupting HTML output
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
            # Extract connection info from the line (format: "YYYY-MM-DD HH:MM:SS user@host:port")
            local host_info=$(echo "$line" | awk '{print $3}')
            local username=$(echo "$host_info" | cut -d'@' -f1)
            local host_with_port=$(echo "$host_info" | cut -d'@' -f2)
            
            # Split hostname and port (format: hostname:port or just hostname)
            local host
            local port
            if [[ "$host_with_port" == *":"* ]]; then
                host=$(echo "$host_with_port" | cut -d':' -f1)
                port=$(echo "$host_with_port" | cut -d':' -f2)
            else
                host="$host_with_port"
                port="22"
            fi
            
            ((total_count++))
            
            # Use port in SSH connection test
            if ssh -p "$port" -o BatchMode=yes -o ConnectTimeout=5 "${username}@${host}" true 2>/dev/null; then
                local display_host="$host"
                if [[ "$port" != "22" ]]; then
                    display_host="${host}:${port}"
                fi
                log_info "✓ Connection to ${username}@${display_host} successful"
                ((success_count++))
            else
                local display_host="$host"
                if [[ "$port" != "22" ]]; then
                    display_host="${host}:${port}"
                fi
                log_info "✗ Connection to ${username}@${display_host} failed"
            fi
        fi
    done < "$EXCHANGED_KEYS_FILE"
    
    log_info "Connection test complete: $success_count/$total_count connections successful"
}

# Scan network for SSH services
scan_for_ssh() {
    local network="$1"
    local ports="${2:-22}"  # Default to port 22, but allow comma-separated list
    
    log_info "Scanning $network for SSH services on ports: $ports..."
    
    # Use nmap if available, otherwise use basic network scanning
    if command -v nmap >/dev/null 2>&1; then
        nmap -p "$ports" --open "$network" 2>/dev/null | grep -E "(Nmap scan report|[0-9]+/tcp)" | sed 's/Nmap scan report for //' | awk '/report/{host=$0} /\/tcp/{port=$1; print host " - SSH open on port " port}'
    else
        # Basic ping sweep for the network (simplified)
        log_info "nmap not available, performing basic network scan..."
        
        # Convert comma-separated ports to array
        IFS=',' read -ra PORT_ARRAY <<< "$ports"
        
        # Extract network base (assuming /24)
        local base=$(echo "$network" | cut -d'.' -f1-3)
        local tested=0
        local found=0
        
        for i in {1..254}; do
            local ip="${base}.${i}"
            
            # Test each port
            for port in "${PORT_ARRAY[@]}"; do
                port=$(echo "$port" | tr -d ' ')  # Remove whitespace
                if timeout 2 bash -c "</dev/tcp/${ip}/${port}" 2>/dev/null; then
                    if [[ "$port" == "22" ]]; then
                        log_info "✓ SSH service found on $ip (standard port)"
                    else
                        log_info "✓ SSH service found on $ip:$port (non-standard port)"
                    fi
                    ((found++))
                fi
            done
            
            ((tested++))
            
            # Progress indicator every 50 hosts
            if ((tested % 50 == 0)); then
                log_info "Scanned $tested hosts, found $found SSH services so far..."
            fi
        done
        
        log_info "Network scan complete: found $found SSH services out of $tested hosts"
    fi
}

# Backup authorized_keys file before modifications
backup_authorized_keys() {
    local auth_keys_file="/root/.ssh/authorized_keys"
    local backup_file="/root/.ssh/authorized_keys.backup.$(date +%Y%m%d_%H%M%S)"
    
    if [[ -f "$auth_keys_file" ]]; then
        cp "$auth_keys_file" "$backup_file" 2>/dev/null || true
        debug_log "Backed up authorized_keys to $backup_file"
        return 0
    else
        debug_log "No authorized_keys file to backup"
        return 1
    fi
}

# List authorized SSH keys that can connect to this server
list_authorized_keys() {
    local auth_keys_file="/root/.ssh/authorized_keys"
    
    if [[ ! -f "$auth_keys_file" ]]; then
        echo "<h4>Authorized SSH Keys:</h4>"
        echo "<div style='color: #666; font-style: italic; text-align: center; padding: 20px; border: 1px dashed #ccc; border-radius: 5px;'>"
        echo "No authorized keys found.<br>No external machines are currently authorized to connect to this server."
        echo "</div>"
        return 0
    fi
    
    echo "<h4>Authorized SSH Keys:</h4>"
    echo "<div style='margin-bottom: 15px;'>"
    
    local entry_count=0
    local line_number=0
    
    while IFS= read -r line; do
        ((line_number++))
        
        # Skip empty lines and comments
        if [[ -z "$line" ]] || [[ "$line" =~ ^[[:space:]]*# ]]; then
            continue
        fi
        
        ((entry_count++))
        
        # Parse SSH key format: keytype key comment
        local key_type=$(echo "$line" | awk '{print $1}')
        local key_data=$(echo "$line" | awk '{print $2}')
        local key_comment=$(echo "$line" | awk '{for(i=3; i<=NF; i++) printf "%s ", $i}' | sed 's/[[:space:]]*$//')
        
        # Extract user and hostname from comment (user@hostname format)
        local user_info=""
        local hostname=""
        
        if [[ "$key_comment" =~ (.+)@(.+) ]]; then
            user_info="${BASH_REMATCH[1]}"
            hostname="${BASH_REMATCH[2]}"
        elif [[ -n "$key_comment" ]]; then
            # If no @ symbol, use entire comment as hostname
            hostname="$key_comment"
            user_info="unknown"
        else
            hostname="Unknown Host"
            user_info="unknown"
        fi
        
        # Test connectivity to determine active/inactive status
        local status_color="#28a745"
        local status_text="✓ Active"
        
        if [[ "$hostname" != "Unknown Host" ]] && [[ "$hostname" != *"localhost"* ]]; then
            # Try to ping the hostname (quick test)
            if ! ping -c 1 -W 2 "$hostname" >/dev/null 2>&1; then
                status_color="#dc3545"
                status_text="✗ Inactive"
            fi
        else
            status_color="#ffc107"
            status_text="? Unknown"
        fi
        
        # Generate unique ID for this key (using line number)
        local key_id="auth_key_${line_number}"
        
        echo "<div style='margin-bottom: 10px; padding: 12px; border: 1px solid #ddd; border-radius: 5px; background: #f8f9fa;'>"
        echo "  <div style='display: flex; justify-content: space-between; align-items: center;'>"
        echo "    <div>"
        echo "      <strong style='color: #333;'>$hostname</strong>"
        if [[ "$user_info" != "unknown" ]]; then
            echo "      <span style='color: #666; margin-left: 10px;'>User: $user_info</span>"
        fi
        echo "      <div style='font-size: 11px; color: #888; margin-top: 2px;'>Key Type: $key_type</div>"
        echo "    </div>"
        echo "    <div style='display: flex; align-items: center; gap: 15px;'>"
        echo "      <div style='color: $status_color; font-weight: bold; font-size: 12px;'>$status_text</div>"
        echo "      <button onclick='deleteAuthorizedKey(\"$key_id\", \"$hostname\", $line_number)' style='background: #dc3545; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; font-size: 11px;' title='Remove authorized key'>Remove</button>"
        echo "    </div>"
        echo "  </div>"
        echo "</div>"
        
    done < "$auth_keys_file"
    
    if [[ $entry_count -eq 0 ]]; then
        echo "<div style='color: #666; font-style: italic; text-align: center; padding: 20px; border: 1px dashed #ccc; border-radius: 5px;'>"
        echo "No valid authorized keys found.<br>The authorized_keys file exists but contains no valid entries."
        echo "</div>"
    fi
    
    echo "</div>"
}

# Remove a specific authorized key by line number
remove_authorized_key() {
    local line_number="$1"
    
    if [[ -z "$line_number" ]] || ! [[ "$line_number" =~ ^[0-9]+$ ]]; then
        error_exit "Invalid line number for key removal"
    fi
    
    local auth_keys_file="/root/.ssh/authorized_keys"
    
    if [[ ! -f "$auth_keys_file" ]]; then
        error_exit "No authorized_keys file found"
    fi
    
    # Create backup before modification
    backup_authorized_keys
    
    # Count total lines in file
    local total_lines=$(wc -l < "$auth_keys_file")
    
    if [[ $line_number -gt $total_lines ]]; then
        error_exit "Line number $line_number exceeds file length ($total_lines lines)"
    fi
    
    # Create temporary file without the specified line
    local temp_file=$(mktemp)
    
    # Copy all lines except the one to be removed
    sed "${line_number}d" "$auth_keys_file" > "$temp_file"
    
    # Verify the operation succeeded
    if [[ $? -eq 0 ]] && [[ -f "$temp_file" ]]; then
        # Replace original file
        mv "$temp_file" "$auth_keys_file"
        
        # Set proper permissions
        chmod 600 "$auth_keys_file" 2>/dev/null || true
        
        log_info "Successfully removed authorized key at line $line_number"
        log_info "Backup created before modification"
        
        return 0
    else
        # Cleanup temp file if something went wrong
        rm -f "$temp_file" 2>/dev/null || true
        error_exit "Failed to remove authorized key - file not modified"
    fi
}

# Revoke SSH access (remove our public key from remote server)
revoke_ssh_access_full() {
    local host="$1"
    local username="$2"
    local port="$3"
    local line_number="$4"
    
    log_info "Starting full SSH access revocation for ${username}@${host}:${port}..."
    
    # Get our public key's base64 material for reliable matching
    local our_key_material
    if [[ -f "$SSH_PUB_KEY_PATH" ]]; then
        our_key_material=$(cat "$SSH_PUB_KEY_PATH" | awk '{print $2}')
        log_info "Using public key: $SSH_PUB_KEY_PATH"
        log_info "Key material: ${our_key_material:0:20}...${our_key_material: -20}"
    else
        error_exit "Local public key not found at $SSH_PUB_KEY_PATH"
    fi
    
    # Test connection first
    if ! ssh -p "$port" -o BatchMode=yes -o ConnectTimeout=5 "${username}@${host}" true 2>/dev/null; then
        error_exit "Cannot connect to ${username}@${host}:${port} - server may be offline"
    fi
    
    log_info "Connected successfully, removing public key from remote authorized_keys..."
    
    # Create enhanced remote script with permission testing and base64 matching
    local remote_script=$(cat << 'EOF'
# Enhanced remote script for safe SSH key removal
AUTH_KEYS_FILE="$HOME/.ssh/authorized_keys"
OUR_KEY_MATERIAL="$1"

# Exit codes: 1=general error, 2=permission error, 3=key not found

# Check if authorized_keys file exists
if [[ ! -f "$AUTH_KEYS_FILE" ]]; then
    echo "PERMISSION_ERROR: No authorized_keys file found"
    exit 2
fi

# Comprehensive permission testing before any operations
echo "Testing file permissions..."

# Test 1: Check if authorized_keys is writable
if [[ ! -w "$AUTH_KEYS_FILE" ]]; then
    echo "PERMISSION_ERROR: Cannot write to authorized_keys file"
    exit 2
fi

# Test 2: Check if .ssh directory is writable (for temp files)
if ! touch "$HOME/.ssh/.write_test" 2>/dev/null; then
    echo "PERMISSION_ERROR: Cannot write to .ssh directory"
    exit 2
fi
rm -f "$HOME/.ssh/.write_test" 2>/dev/null

# Test 3: Test atomic operation capability
if ! touch "${AUTH_KEYS_FILE}.tmp_test" 2>/dev/null; then
    echo "PERMISSION_ERROR: Cannot create temporary files for atomic operations"
    exit 2
fi
rm -f "${AUTH_KEYS_FILE}.tmp_test" 2>/dev/null

echo "Permission tests passed - proceeding with key removal"

# Check if our key material is present before attempting removal
if ! grep -F -q "$OUR_KEY_MATERIAL" "$AUTH_KEYS_FILE"; then
    echo "KEY_NOT_FOUND: Key material not found in authorized_keys"
    exit 3
fi

echo "Key found - creating backup and removing key"

# Create timestamped backup
if ! cp "$AUTH_KEYS_FILE" "${AUTH_KEYS_FILE}.backup.$(date +%Y%m%d_%H%M%S)" 2>/dev/null; then
    echo "PERMISSION_ERROR: Cannot create backup file"
    exit 2
fi

# Enhanced atomic removal with better error handling
echo "DEBUG: Attempting to create temporary file: ${AUTH_KEYS_FILE}.tmp"
echo "DEBUG: Current working directory: $(pwd)"
echo "DEBUG: Home directory: $HOME"
echo "DEBUG: User: $(whoami)"
echo "DEBUG: Auth keys file: $AUTH_KEYS_FILE"
echo "DEBUG: File exists: $(test -f "$AUTH_KEYS_FILE" && echo "yes" || echo "no")"
echo "DEBUG: File readable: $(test -r "$AUTH_KEYS_FILE" && echo "yes" || echo "no")"
echo "DEBUG: Directory writable: $(test -w "$(dirname "$AUTH_KEYS_FILE")" && echo "yes" || echo "no")"

# Test if we can create a simple temp file first
if ! touch "${AUTH_KEYS_FILE}.test_tmp" 2>/dev/null; then
    echo "ERROR: Cannot create test temporary file in SSH directory"
    echo "DEBUG: Directory permissions: $(ls -ld "$(dirname "$AUTH_KEYS_FILE")" 2>/dev/null || echo "cannot check")"
    exit 1
fi
rm -f "${AUTH_KEYS_FILE}.test_tmp" 2>/dev/null || true
echo "DEBUG: Temporary file creation test passed"

# Try the actual grep operation with detailed error reporting
echo "DEBUG: Running grep command to remove key material"
if grep -F -v "$OUR_KEY_MATERIAL" "$AUTH_KEYS_FILE" > "${AUTH_KEYS_FILE}.tmp" 2>&1; then
    echo "DEBUG: Grep command succeeded, checking results"
    
    # Verify the temporary file was created and has content
    if [[ ! -f "${AUTH_KEYS_FILE}.tmp" ]]; then
        echo "ERROR: Temporary file was not created despite successful grep"
        exit 1
    fi
    
    echo "DEBUG: Temporary file created successfully"
    echo "DEBUG: Original file lines: $(wc -l < "$AUTH_KEYS_FILE" 2>/dev/null || echo "unknown")"
    echo "DEBUG: Temp file lines: $(wc -l < "${AUTH_KEYS_FILE}.tmp" 2>/dev/null || echo "unknown")"
    
    # Verify the key was actually removed
    if grep -F -q "$OUR_KEY_MATERIAL" "${AUTH_KEYS_FILE}.tmp"; then
        echo "ERROR: Key still present after removal attempt"
        echo "DEBUG: Key material found in temp file - removal failed"
        rm -f "${AUTH_KEYS_FILE}.tmp" 2>/dev/null || true
        exit 1
    fi
    
    echo "DEBUG: Key successfully removed from temp file, performing atomic move"
    
    # Atomic move and set permissions
    if mv "${AUTH_KEYS_FILE}.tmp" "$AUTH_KEYS_FILE"; then
        chmod 600 "$AUTH_KEYS_FILE" 2>/dev/null || true
        chmod 700 "$HOME/.ssh" 2>/dev/null || true
        echo "Successfully removed SSH key from authorized_keys"
        echo "Key removal verified and file permissions secured"
    else
        echo "ERROR: Failed to replace authorized_keys file with temp file"
        rm -f "${AUTH_KEYS_FILE}.tmp" 2>/dev/null || true
        exit 1
    fi
else
    grep_exit_code=$?
    echo "ERROR: Grep command failed with exit code: $grep_exit_code"
    echo "DEBUG: Failed to create temporary file for key removal"
    echo "DEBUG: This could be due to file system permissions, disk space, or file locks"
    rm -f "${AUTH_KEYS_FILE}.tmp" 2>/dev/null || true
    exit 1
fi
EOF
)
    
    # Execute the enhanced remote script with proper error handling
    local ssh_output
    local ssh_exit_code
    
    ssh_output=$(ssh -p "$port" -o BatchMode=yes -o ConnectTimeout=10 "${username}@${host}" "bash -s '$our_key_material'" <<< "$remote_script" 2>&1)
    ssh_exit_code=$?
    
    log_info "Remote script output: $ssh_output"
    
    case $ssh_exit_code in
        0)
            log_info "Successfully removed public key from remote server"
            # Remove from local tracking file
            revoke_ssh_access_local "$line_number"
            log_info "Full SSH access revocation completed successfully"
            return 0
            ;;
        2)
            log_info "Permission error on remote server: $ssh_output"
            error_exit "PERMISSION_ERROR: $ssh_output"
            ;;
        3)
            log_info "Key not found on remote server: $ssh_output"
            error_exit "KEY_NOT_FOUND: $ssh_output"
            ;;
        *)
            log_info "Remote script failed with exit code $ssh_exit_code: $ssh_output"
            error_exit "Failed to remove public key from remote server: $ssh_output"
            ;;
    esac
}

# Remove SSH connection from local tracking only
revoke_ssh_access_local() {
    local line_number="$1"
    
    if [[ -z "$line_number" ]] || ! [[ "$line_number" =~ ^[0-9]+$ ]]; then
        error_exit "Invalid line number for local revocation"
    fi
    
    if [[ ! -f "$EXCHANGED_KEYS_FILE" ]]; then
        error_exit "No exchanged keys file found"
    fi
    
    log_info "Removing entry from local tracking list..."
    
    # Create backup of exchanged keys file
    local backup_file="${EXCHANGED_KEYS_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    cp "$EXCHANGED_KEYS_FILE" "$backup_file" 2>/dev/null || true
    
    # Count total lines in file
    local total_lines=$(wc -l < "$EXCHANGED_KEYS_FILE")
    
    if [[ $line_number -gt $total_lines ]]; then
        error_exit "Line number $line_number exceeds file length ($total_lines lines)"
    fi
    
    # Create temporary file without the specified line
    local temp_file=$(mktemp)
    
    # Copy all lines except the one to be removed
    sed "${line_number}d" "$EXCHANGED_KEYS_FILE" > "$temp_file"
    
    # Verify the operation succeeded
    if [[ $? -eq 0 ]] && [[ -f "$temp_file" ]]; then
        # Replace original file
        mv "$temp_file" "$EXCHANGED_KEYS_FILE"
        
        # Set proper permissions
        chmod 644 "$EXCHANGED_KEYS_FILE" 2>/dev/null || true
        
        log_info "Successfully removed entry from tracking list"
        log_info "Backup created: $backup_file"
        
        return 0
    else
        # Cleanup temp file if something went wrong
        rm -f "$temp_file" 2>/dev/null || true
        error_exit "Failed to remove entry from tracking list"
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
            test_ssh_connection "$REMOTE_HOST" "$REMOTE_USERNAME" "$REMOTE_PASSWORD" "$REMOTE_PORT"
            ;;
        "exchange_keys")
            if [[ -z "$REMOTE_HOST" ]] || [[ -z "$REMOTE_USERNAME" ]] || [[ -z "$REMOTE_PASSWORD" ]]; then
                error_exit "Missing required parameters for key exchange"
            fi
            exchange_ssh_keys "$REMOTE_HOST" "$REMOTE_USERNAME" "$REMOTE_PASSWORD" "$REMOTE_PORT"
            ;;
        "test_single_connection")
            if [[ -z "$TEST_HOST" ]]; then
                error_exit "Missing host parameter for connection test"
            fi
            test_single_ssh_connection "$TEST_HOST" "" "$TEST_USERNAME"
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
        "list_authorized_keys")
            list_authorized_keys
            ;;
        "remove_authorized_key")
            if [[ -z "$KEY_LINE_NUMBER" ]]; then
                error_exit "Missing line number parameter for key removal"
            fi
            remove_authorized_key "$KEY_LINE_NUMBER"
            ;;
        "revoke_exchanged_key")
            if [[ -z "$KEY_LINE_NUMBER" ]]; then
                error_exit "Missing line number parameter for key revocation"
            fi
            if [[ -z "$REVOKE_TYPE" ]]; then
                error_exit "Missing revoke type parameter"
            fi
            
            if [[ "$REVOKE_TYPE" == "full" ]]; then
                if [[ -z "$REMOTE_HOST" ]] || [[ -z "$REMOTE_USERNAME" ]]; then
                    error_exit "Missing required parameters for full revocation"
                fi
                revoke_ssh_access_full "$REMOTE_HOST" "$REMOTE_USERNAME" "$REMOTE_PORT" "$KEY_LINE_NUMBER"
            elif [[ "$REVOKE_TYPE" == "local_only" ]]; then
                revoke_ssh_access_local "$KEY_LINE_NUMBER"
            else
                error_exit "Invalid revoke type: $REVOKE_TYPE"
            fi
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
