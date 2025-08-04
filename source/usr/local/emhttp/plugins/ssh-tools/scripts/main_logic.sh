#!/bin/bash

# SSH Tools Plugin - Main Logic Script
# Handles SSH key generation, exchange, and management operations

# set -e  # Temporarily disabled to prevent script from exiting on errors

# Constants
SSH_KEY_TYPE="ed25519"
GLOBAL_SSH_KEY_PATH="/root/.ssh/id_${SSH_KEY_TYPE}"  # Keep for system compatibility
GLOBAL_SSH_PUB_KEY_PATH="${GLOBAL_SSH_KEY_PATH}.pub"
PLUGIN_DATA_DIR="/boot/config/plugins/ssh-tools"
CONNECTIONS_REGISTRY="/root/.ssh/ssh-tools-connections.json"

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

# Initialize connections registry with clean JSON structure
initialize_connections_registry() {
    if [[ ! -f "$CONNECTIONS_REGISTRY" ]]; then
        cat > "$CONNECTIONS_REGISTRY" << EOF
{
  "version": "2.0",
  "created": "$(date -Iseconds)",
  "last_updated": "$(date -Iseconds)",
  "connections": []
}
EOF
        chmod 644 "$CONNECTIONS_REGISTRY" 2>/dev/null || true
        debug_log "Created connections registry: $CONNECTIONS_REGISTRY"
    fi
}

# Ensure plugin data directory exists
ensure_data_dir() {
    if [[ ! -d "$PLUGIN_DATA_DIR" ]]; then
        mkdir -p "$PLUGIN_DATA_DIR"
        debug_log "Created plugin data directory: $PLUGIN_DATA_DIR"
    fi
    
    # Initialize JSON connections registry
    initialize_connections_registry
}

# Validate environment
validate_environment() {
    if [[ -z "$OPERATION" ]]; then
        error_exit "No operation specified"
    fi
    
    # debug_log "Operation: $OPERATION" # Removed - corrupts HTML output
    ensure_data_dir
}

# Resolve hostname from IP or validate hostname
resolve_hostname() {
    local host="$1"
    local resolved_name=""
    
    # Try reverse DNS lookup for IP addresses
    if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        resolved_name=$(nslookup "$host" 2>/dev/null | grep "name =" | head -1 | awk '{print $4}' | sed 's/\.$//') 2>/dev/null || true
        # If reverse lookup failed or returned IP, use IP as identifier
        if [[ -z "$resolved_name" ]] || [[ "$resolved_name" == "$host" ]]; then
            resolved_name=""
        fi
    else
        # For hostnames, validate they resolve
        if nslookup "$host" >/dev/null 2>&1; then
            resolved_name="$host"
        fi
    fi
    
    echo "$resolved_name"
}

# Create safe filename from hostname or IP
create_safe_identifier() {
    local host="$1"
    local identifier=""
    
    # Try to get hostname first
    local hostname=$(resolve_hostname "$host")
    
    if [[ -n "$hostname" ]]; then
        # Use hostname, make it filesystem-safe
        identifier=$(echo "$hostname" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9.-]/-/g' | sed 's/--*/-/g' | sed 's/^-\|-$//g')
        # Limit length
        if [[ ${#identifier} -gt 20 ]]; then
            identifier="${identifier:0:20}"
        fi
    fi
    
    # Fallback to IP with dashes if hostname not available or too complex
    if [[ -z "$identifier" ]] || [[ ${#identifier} -lt 3 ]]; then
        identifier=$(echo "$host" | sed 's/\./-/g' | sed 's/[^a-z0-9-]/-/g')
    fi
    
    echo "$identifier"
}

# Generate PAIR- formatted key filename
generate_pair_key_name() {
    local host="$1"
    local username="$2"
    local port="$3"
    
    local identifier=$(create_safe_identifier "$host")
    local port_suffix="p${port}"
    
    echo "PAIR-${identifier}-${username}-${port_suffix}_ed25519"
}

# Check for key name collisions and add suffix if needed
get_unique_key_name() {
    local base_name="$1"
    local key_path="/root/.ssh/${base_name}"
    
    # If no collision, return original name
    if [[ ! -f "$key_path" ]] && [[ ! -f "${key_path}.pub" ]]; then
        echo "$base_name"
        return 0
    fi
    
    # Handle collision with numbered suffix
    local counter=2
    while [[ -f "/root/.ssh/${base_name%_ed25519}-${counter}_ed25519" ]] || [[ -f "/root/.ssh/${base_name%_ed25519}-${counter}_ed25519.pub" ]]; do
        ((counter++))
    done
    
    echo "${base_name%_ed25519}-${counter}_ed25519"
}

# Generate individual SSH key with enhanced PAIR- naming
generate_connection_key() {
    local conn_id="$1"
    local host="$2"
    local username="$3"
    local port="$4"
    
    # Generate descriptive key name
    local base_key_name=$(generate_pair_key_name "$host" "$username" "$port")
    local unique_key_name=$(get_unique_key_name "$base_key_name")
    
    local private_key="/root/.ssh/${unique_key_name}"
    local public_key="${private_key}.pub"
    
    if [[ ! -f "$private_key" ]]; then
        # Enhanced comment with hostname resolution
        local hostname=$(resolve_hostname "$host")
        local comment_host="$host"
        if [[ -n "$hostname" ]] && [[ "$hostname" != "$host" ]]; then
            comment_host="${hostname}(${host})"
        fi
        
        # Generate key silently (no output that corrupts return value)
        ssh-keygen -t "$SSH_KEY_TYPE" -f "$private_key" -N "" \
            -C "PAIR-${username}@${comment_host}:${port}-created:$(date +%Y%m%d%H%M%S)" >/dev/null 2>&1
        
        # Set proper permissions
        chmod 600 "$private_key" 2>/dev/null || true
        chmod 644 "$public_key" 2>/dev/null || true
        
        # Return the path (no debug output in functions that return values)
        echo "$private_key"
        return 0
    else
        # Return existing key path (no debug output)
        echo "$private_key"
        return 0
    fi
}

# Generate unique connection ID
generate_connection_id() {
    echo "conn-$(date +%Y%m%d%H%M%S)-$$"
}

# Add connection to JSON registry
add_connection_to_registry() {
    local conn_id="$1"
    local host="$2"
    local username="$3"
    local port="$4"
    local private_key="$5"  # Now passed as parameter from generate_connection_key
    local public_key="${private_key}.pub"
    local timestamp="$(date -Iseconds)"
    
    # Check if jq is available
    if ! command -v jq >/dev/null 2>&1; then
        error_exit "jq is required but not installed"
    fi
    
    # Create temporary file for atomic update
    local temp_file="/tmp/connections_update.json"
    
    # Add new connection to registry
    jq --arg id "$conn_id" \
       --arg host "$host" \
       --arg username "$username" \
       --arg port "$port" \
       --arg private_key "$private_key" \
       --arg public_key "$public_key" \
       --arg created "$timestamp" \
       --arg last_updated "$timestamp" \
       '.last_updated = $last_updated | .connections += [{
         "id": $id,
         "host": $host,
         "username": $username,
         "port": ($port | tonumber),
         "private_key": $private_key,
         "public_key": $public_key,
         "created": $created,
         "last_tested": null,
         "last_successful": null,
         "status": "active"
       }]' "$CONNECTIONS_REGISTRY" > "$temp_file"
    
    if [[ $? -eq 0 ]]; then
        mv "$temp_file" "$CONNECTIONS_REGISTRY"
        chmod 644 "$CONNECTIONS_REGISTRY" 2>/dev/null || true
        debug_log "Added connection $conn_id to registry"
        return 0
    else
        rm -f "$temp_file" 2>/dev/null || true
        error_exit "Failed to update connections registry"
    fi
}

# Update connection test result in JSON registry
update_connection_test_result() {
    local conn_id="$1"
    local result="$2"  # "success" or "failed"
    local timestamp="$(date -Iseconds)"
    
    if ! command -v jq >/dev/null 2>&1; then
        debug_log "jq not available - skipping test result update"
        return 0
    fi
    
    local temp_file="/tmp/connections_test_update.json"
    
    if [[ "$result" == "success" ]]; then
        # Update both last_tested and last_successful
        jq --arg id "$conn_id" \
           --arg timestamp "$timestamp" \
           '.last_updated = $timestamp | 
            (.connections[] | select(.id == $id)) |= 
            (.last_tested = $timestamp | .last_successful = $timestamp | .status = "active")' \
           "$CONNECTIONS_REGISTRY" > "$temp_file"
    else
        # Update only last_tested
        jq --arg id "$conn_id" \
           --arg timestamp "$timestamp" \
           '.last_updated = $timestamp | 
            (.connections[] | select(.id == $id)) |= 
            (.last_tested = $timestamp | .status = "inactive")' \
           "$CONNECTIONS_REGISTRY" > "$temp_file"
    fi
    
    if [[ $? -eq 0 ]]; then
        mv "$temp_file" "$CONNECTIONS_REGISTRY"
        chmod 644 "$CONNECTIONS_REGISTRY" 2>/dev/null || true
        debug_log "Updated test result for connection $conn_id: $result"
    else
        rm -f "$temp_file" 2>/dev/null || true
        debug_log "Failed to update test result for connection $conn_id"
    fi
}

# Get SSH key status information (system global key for display)
get_key_status() {
    if [[ -f "$GLOBAL_SSH_KEY_PATH" ]] && [[ -f "$GLOBAL_SSH_PUB_KEY_PATH" ]]; then
        echo "✓ System SSH key available - individual keys generated per connection"
    else
        echo "ℹ Individual SSH keys will be generated automatically for each connection"
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

# Exchange SSH keys with remote host using individual key pairs
exchange_ssh_keys() {
    local host="$1"
    local username="$2"
    local password="$3"
    local port="${4:-22}"  # Default to port 22 if not specified
    
    log_info "Starting SSH key exchange with ${username}@${host}:${port}..."
    
    # Generate unique connection ID
    local conn_id=$(generate_connection_id)
    log_info "Generated connection ID: $conn_id"
    
    # Generate individual SSH key for this connection
    local private_key=$(generate_connection_key "$conn_id" "$host" "$username" "$port")
    local public_key="${private_key}.pub"
    
    # Extract the key name for user feedback
    local key_name=$(basename "$private_key")
    log_info "Generated individual SSH key: $key_name"
    log_info "Using individual SSH key: $public_key"
    
    # Test connection first with password
    if ! test_ssh_connection "$host" "$username" "$password" "$port"; then
        # Clean up generated key on connection failure
        rm -f "$private_key" "$public_key" 2>/dev/null || true
        error_exit "Cannot connect to ${username}@${host}:${port} with provided credentials"
    fi
    
    # Exchange keys using ssh-copy-id with sshpass (the proven Unraid method)
    log_info "Exchanging individual SSH key with ${username}@${host}:${port}..."
    
    # Use sshpass with ssh-copy-id (sshpass installed as plugin dependency)
    if sshpass -p "$password" ssh-copy-id -p "$port" -f -o StrictHostKeyChecking=no -i "$public_key" "${username}@${host}" 2>&1; then
        log_info "Individual SSH key successfully copied to ${username}@${host}:${port}"
    else
        # Clean up generated key on exchange failure
        rm -f "$private_key" "$public_key" 2>/dev/null || true
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
    
    # Verify the key exchange worked using individual key
    log_info "Verifying passwordless SSH connection with individual key..."
    if ssh -i "$private_key" -p "$port" -o BatchMode=yes -o ConnectTimeout=5 "${username}@${host}" true 2>/dev/null; then
        log_info "SSH key exchange completed successfully!"
        
        # Add connection to JSON registry with individual key path
        add_connection_to_registry "$conn_id" "$host" "$username" "$port" "$private_key"
        
        # Update test result as successful
        update_connection_test_result "$conn_id" "success"
        
        log_info "Connection recorded in registry with ID: $conn_id"
        return 0
    else
        # Clean up generated key on verification failure
        rm -f "$private_key" "$public_key" 2>/dev/null || true
        error_exit "SSH key exchange failed - cannot connect without password using individual key"
    fi
}

# Test a single SSH connection (for specific connections or general testing)
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
    
    # First check if this is a tracked connection with individual key
    local found_connection=""
    if [[ -f "$CONNECTIONS_REGISTRY" ]] && command -v jq >/dev/null 2>&1; then
        found_connection=$(jq -r --arg host "$host" --arg username "$username" --arg port "$port" \
            '.connections[] | select(.host == $host and .username == $username and (.port | tostring) == $port) | .private_key' \
            "$CONNECTIONS_REGISTRY" 2>/dev/null)
    fi
    
    # Test with individual key if available
    if [[ -n "$found_connection" ]] && [[ "$found_connection" != "null" ]] && [[ -f "$found_connection" ]]; then
        if ssh -i "$found_connection" -p "$port" -o BatchMode=yes -o ConnectTimeout=5 "${username}@${host}" "echo 'SSH connection successful'" 2>/dev/null; then
            log_info "SSH connection to ${username}@$display_host successful (using individual key)"
            
            # Update connection status in registry
            local conn_id=$(jq -r --arg host "$host" --arg username "$username" --arg port "$port" \
                '.connections[] | select(.host == $host and .username == $username and (.port | tostring) == $port) | .id' \
                "$CONNECTIONS_REGISTRY" 2>/dev/null)
            if [[ -n "$conn_id" ]] && [[ "$conn_id" != "null" ]]; then
                update_connection_test_result "$conn_id" "success"
            fi
            return 0
        else
            log_info "SSH connection to ${username}@$display_host failed (individual key authentication failed)"
            
            # Update connection status in registry
            local conn_id=$(jq -r --arg host "$host" --arg username "$username" --arg port "$port" \
                '.connections[] | select(.host == $host and .username == $username and (.port | tostring) == $port) | .id' \
                "$CONNECTIONS_REGISTRY" 2>/dev/null)
            if [[ -n "$conn_id" ]] && [[ "$conn_id" != "null" ]]; then
                update_connection_test_result "$conn_id" "failed"
            fi
            return 1
        fi
    else
        # Try with global key or no key (general testing)
        if ssh -p "$port" -o BatchMode=yes -o ConnectTimeout=5 "${username}@${host}" "echo 'SSH connection successful'" 2>/dev/null; then
            log_info "SSH connection to ${username}@$display_host successful (key-based authentication)"
            return 0
        else
            log_info "SSH connection to ${username}@$display_host failed (no key-based access)"
            return 1
        fi
    fi
}

# List exchanged SSH keys from JSON registry
list_exchanged_keys() {
    if [[ ! -f "$CONNECTIONS_REGISTRY" ]]; then
        echo "<div style='color: #666; font-style: italic; text-align: center; padding: 20px; border: 1px dashed #ccc; border-radius: 5px;'>"
        echo "No SSH keys have been exchanged yet.<br>Use the 'Exchange Keys' tab to add your first connection."
        echo "</div>"
        return 0
    fi
    
    # Check if jq is available
    if ! command -v jq >/dev/null 2>&1; then
        echo "<div style='color: #dc3545; text-align: center; padding: 20px; border: 1px solid #dc3545; border-radius: 5px;'>"
        echo "Error: jq is required to display connections.<br>Please install jq to use this feature."
        echo "</div>"
        return 1
    fi
    
    # Get connection count
    local connection_count=$(jq '.connections | length' "$CONNECTIONS_REGISTRY" 2>/dev/null || echo "0")
    
    if [[ "$connection_count" -eq 0 ]]; then
        echo "<div style='color: #666; font-style: italic; text-align: center; padding: 20px; border: 1px dashed #ccc; border-radius: 5px;'>"
        echo "No SSH keys have been exchanged yet.<br>Use the 'Exchange Keys' tab to add your first connection."
        echo "</div>"
        return 0
    fi
    
    echo "<h4>Successfully Exchanged Keys:</h4>"
    echo "<div style='margin-bottom: 15px;'>"
    
    # Process each connection using jq
    local connections_json=$(jq -c '.connections[]' "$CONNECTIONS_REGISTRY" 2>/dev/null)
    
    if [[ -n "$connections_json" ]]; then
        echo "$connections_json" | while IFS= read -r connection; do
            # Extract connection details
            local conn_id=$(echo "$connection" | jq -r '.id')
            local host=$(echo "$connection" | jq -r '.host')
            local username=$(echo "$connection" | jq -r '.username')
            local port=$(echo "$connection" | jq -r '.port')
            local created=$(echo "$connection" | jq -r '.created')
            local last_tested=$(echo "$connection" | jq -r '.last_tested')
            local last_successful=$(echo "$connection" | jq -r '.last_successful')
            local status=$(echo "$connection" | jq -r '.status')
            
            # Format timestamps for display
            local created_display=""
            if [[ "$created" != "null" ]]; then
                created_display=$(date -d "$created" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$created")
            fi
            
            local last_tested_display=""
            if [[ "$last_tested" != "null" ]]; then
                last_tested_display=$(date -d "$last_tested" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$last_tested")
            fi
            
            # Display hostname with port if non-standard
            local display_host="$host"
            if [[ "$port" != "22" ]]; then
                display_host="${host}:${port}"
            fi
            
            # Determine status color and text
            local status_color="#666"
            local status_text="Unknown"
            
            if [[ "$status" == "active" ]]; then
                status_color="#28a745"
                status_text="✓ Active"
            elif [[ "$status" == "inactive" ]]; then
                status_color="#dc3545"
                status_text="✗ Inactive"
            fi
            
            # Add last tested info if available
            local status_detail=""
            if [[ "$last_tested_display" != "" ]]; then
                status_detail="<div style='font-size: 10px; color: #888;'>Last tested: $last_tested_display</div>"
            fi
            
            echo "<div style='margin-bottom: 10px; padding: 12px; border: 1px solid #ddd; border-radius: 5px; background: #f8f9fa;'>"
            echo "  <div style='display: flex; justify-content: space-between; align-items: center;'>"
            echo "    <div>"
            echo "      <strong style='color: #333;'>$display_host</strong>"
            echo "      <span style='color: #666; margin-left: 10px;'>User: $username</span>"
            echo "      <div style='font-size: 11px; color: #888; margin-top: 2px;'>Created: $created_display</div>"
            echo "      $status_detail"
            echo "    </div>"
            echo "    <div style='display: flex; align-items: center; gap: 15px;'>"
            echo "      <div style='color: $status_color; font-weight: bold; font-size: 12px;'>$status_text</div>"
            echo "      <button onclick=\"revokeExchangedKey('$conn_id', '$display_host', '$host', '$username', '$port', '1')\" style='background: #dc3545; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; font-size: 11px;' title='Revoke SSH access'>Revoke Access</button>"
            echo "    </div>"
            echo "  </div>"
            echo "</div>"
        done
    fi
    
    echo "</div>"
}

# Test all previously exchanged connections using individual keys
test_all_connections() {
    if [[ ! -f "$CONNECTIONS_REGISTRY" ]]; then
        log_info "No connections registry found - no connections to test"
        return 0
    fi
    
    if ! command -v jq >/dev/null 2>&1; then
        log_info "jq not available - cannot test connections"
        return 1
    fi
    
    local connection_count=$(jq '.connections | length' "$CONNECTIONS_REGISTRY" 2>/dev/null || echo "0")
    
    if [[ "$connection_count" -eq 0 ]]; then
        log_info "No exchanged keys to test"
        return 0
    fi
    
    log_info "Testing all exchanged SSH connections using individual keys..."
    
    local success_count=0
    local total_count=0
    
    # Get all connections from JSON registry
    local connections_json=$(jq -c '.connections[]' "$CONNECTIONS_REGISTRY" 2>/dev/null)
    
    if [[ -n "$connections_json" ]]; then
        echo "$connections_json" | while IFS= read -r connection; do
            # Extract connection details
            local conn_id=$(echo "$connection" | jq -r '.id')
            local host=$(echo "$connection" | jq -r '.host')
            local username=$(echo "$connection" | jq -r '.username')
            local port=$(echo "$connection" | jq -r '.port')
            local private_key=$(echo "$connection" | jq -r '.private_key')
            
            ((total_count++))
            
            # Display hostname with port if non-standard
            local display_host="$host"
            if [[ "$port" != "22" ]]; then
                display_host="${host}:${port}"
            fi
            
            # Test connection using individual key
            if [[ -f "$private_key" ]] && ssh -i "$private_key" -p "$port" -o BatchMode=yes -o ConnectTimeout=5 "${username}@${host}" true 2>/dev/null; then
                log_info "✓ Connection to ${username}@${display_host} successful (using individual key)"
                ((success_count++))
                # Update connection status in registry
                update_connection_test_result "$conn_id" "success"
            else
                log_info "✗ Connection to ${username}@${display_host} failed"
                # Update connection status in registry
                update_connection_test_result "$conn_id" "failed"
                
                # Check if key file exists
                if [[ ! -f "$private_key" ]]; then
                    log_info "  ⚠ Individual key file missing: $private_key"
                fi
            fi
        done
        
        log_info "Connection test complete: $success_count/$total_count connections successful"
    else
        log_info "No connections found in registry"
    fi
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
echo "DEBUG: Key material length: ${#OUR_KEY_MATERIAL}"
echo "DEBUG: Key material starts with: ${OUR_KEY_MATERIAL:0:30}..."
echo "DEBUG: Key material ends with: ...${OUR_KEY_MATERIAL: -30}"
echo "DEBUG: Authorized keys file content:"
cat -n "$AUTH_KEYS_FILE" | head -5
echo "DEBUG: Grep test - looking for key in file:"
if grep -F -q "$OUR_KEY_MATERIAL" "$AUTH_KEYS_FILE"; then
    echo "DEBUG: Key material FOUND in authorized_keys"
else
    echo "DEBUG: Key material NOT FOUND in authorized_keys"
fi
echo "DEBUG: Now attempting removal with grep -F -v"
# Note: grep -v returns exit code 1 when output is empty (all lines removed), which is valid
grep -F -v "$OUR_KEY_MATERIAL" "$AUTH_KEYS_FILE" > "${AUTH_KEYS_FILE}.tmp" 2>&1
grep_exit_code=$?
echo "DEBUG: Grep -v exit code: $grep_exit_code"

# Exit codes: 0=success with output, 1=no output (empty file), 2=error
if [[ $grep_exit_code -eq 0 ]] || [[ $grep_exit_code -eq 1 ]]; then
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
    # Only true errors (exit code 2 or higher)
    echo "ERROR: Grep command failed with exit code: $grep_exit_code"
    echo "DEBUG: This indicates a true error (not empty output)"
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
            if [[ -z "$CONNECTION_ID" ]]; then
                error_exit "Missing connection ID parameter for key revocation"
            fi
            if [[ -z "$REVOKE_TYPE" ]]; then
                error_exit "Missing revoke type parameter"
            fi
            
            if [[ "$REVOKE_TYPE" == "full" ]]; then
                if [[ -z "$REMOTE_HOST" ]] || [[ -z "$REMOTE_USERNAME" ]]; then
                    error_exit "Missing required parameters for full revocation"
                fi
                revoke_connection_full "$CONNECTION_ID" "$REMOTE_HOST" "$REMOTE_USERNAME" "$REMOTE_PORT"
            elif [[ "$REVOKE_TYPE" == "local_only" ]]; then
                revoke_connection_local "$CONNECTION_ID"
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
# New revocation system for individual SSH keys
revoke_connection_full() {
    local conn_id="$1"
    local host="$2"
    local username="$3"
    local port="$4"
    
    log_info "Starting full connection revocation for ${username}@${host}:${port} (connection: $conn_id)..."
    
    # Get connection details from registry
    if [[ ! -f "$CONNECTIONS_REGISTRY" ]] || ! command -v jq >/dev/null 2>&1; then
        error_exit "Cannot access connections registry - jq required"
    fi
    
    local connection_data=$(jq -r --arg id "$conn_id" '.connections[] | select(.id == $id)' "$CONNECTIONS_REGISTRY" 2>/dev/null)
    
    if [[ -z "$connection_data" ]] || [[ "$connection_data" == "null" ]]; then
        error_exit "Connection $conn_id not found in registry"
    fi
    
    local private_key=$(echo "$connection_data" | jq -r '.private_key')
    local public_key=$(echo "$connection_data" | jq -r '.public_key')
    
    if [[ ! -f "$private_key" ]] || [[ ! -f "$public_key" ]]; then
        log_info "⚠ Individual key files not found - performing local cleanup only"
        revoke_connection_local "$conn_id"
        return $?
    fi
    
    # Get our public key's base64 material for reliable matching
    local our_key_material=$(cat "$public_key" | awk '{print $2}')
    log_info "Using individual public key: $public_key"
    log_info "Key material: ${our_key_material:0:20}...${our_key_material: -20}"
    
    # Test connection first using individual key
    if ! ssh -i "$private_key" -p "$port" -o BatchMode=yes -o ConnectTimeout=5 "${username}@${host}" true 2>/dev/null; then
        log_info "⚠ Cannot connect to ${username}@${host}:${port} using individual key - server may be offline"
        log_info "Performing local cleanup only..."
        revoke_connection_local "$conn_id"
        return $?
    fi
    
    log_info "Connected successfully, removing individual public key from remote authorized_keys..."
    
    # Create remote script for individual key removal
    local remote_script=$(cat << 'EOF'
AUTH_KEYS_FILE="$HOME/.ssh/authorized_keys"
OUR_KEY_MATERIAL="$1"

# Check if authorized_keys file exists
if [[ ! -f "$AUTH_KEYS_FILE" ]]; then
    echo "KEY_NOT_FOUND: No authorized_keys file found"
    exit 3
fi

# Check if our key material is present with literal string matching
if ! grep -F -q "$OUR_KEY_MATERIAL" "$AUTH_KEYS_FILE"; then
    echo "KEY_NOT_FOUND: Key material not found in authorized_keys"
    exit 3
fi

# Create backup
cp "$AUTH_KEYS_FILE" "${AUTH_KEYS_FILE}.backup.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true

# Remove key with literal string matching and proper exit code handling
grep -F -v "$OUR_KEY_MATERIAL" "$AUTH_KEYS_FILE" > "${AUTH_KEYS_FILE}.tmp" 2>&1
grep_exit_code=$?

# Exit codes: 0=success with output, 1=no output (empty file), 2=error
if [[ $grep_exit_code -eq 0 ]] || [[ $grep_exit_code -eq 1 ]]; then
    mv "${AUTH_KEYS_FILE}.tmp" "$AUTH_KEYS_FILE"
    chmod 600 "$AUTH_KEYS_FILE" 2>/dev/null || true
    echo "Successfully removed SSH key from authorized_keys"
else
    echo "ERROR: Grep command failed with exit code: $grep_exit_code"
    exit 1
fi
EOF
)
    
    # Execute remote script using individual key
    local ssh_output
    ssh_output=$(ssh -i "$private_key" -p "$port" -o BatchMode=yes -o ConnectTimeout=10 "${username}@${host}" "bash -s '$our_key_material'" <<< "$remote_script" 2>&1)
    local ssh_exit_code=$?
    
    log_info "Remote script output: $ssh_output"
    
    if [[ $ssh_exit_code -eq 0 ]]; then
        log_info "Successfully removed individual key from remote server"
        # Now perform local cleanup
        revoke_connection_local "$conn_id"
        return 0
    else
        # Handle specific error types
        if [[ "$ssh_output" == *"PERMISSION_ERROR:"* ]]; then
            echo "PERMISSION_ERROR: $ssh_output"
            exit 2
        elif [[ "$ssh_output" == *"KEY_NOT_FOUND:"* ]]; then
            echo "KEY_NOT_FOUND: $ssh_output"  
            # Still perform local cleanup for missing keys
            revoke_connection_local "$conn_id"
            exit 3
        else
            log_info "Remote key removal failed, performing local cleanup..."
            revoke_connection_local "$conn_id"
            return 1
        fi
    fi
}

# Local revocation for individual connection
revoke_connection_local() {
    local conn_id="$1"
    
    log_info "Performing local cleanup for connection: $conn_id"
    
    if [[ ! -f "$CONNECTIONS_REGISTRY" ]] || ! command -v jq >/dev/null 2>&1; then
        error_exit "Cannot access connections registry - jq required"
    fi
    
    # Get connection details
    local connection_data=$(jq -r --arg id "$conn_id" '.connections[] | select(.id == $id)' "$CONNECTIONS_REGISTRY" 2>/dev/null)
    
    if [[ -z "$connection_data" ]] || [[ "$connection_data" == "null" ]]; then
        error_exit "Connection $conn_id not found in registry"
    fi
    
    local private_key=$(echo "$connection_data" | jq -r '.private_key')
    local public_key=$(echo "$connection_data" | jq -r '.public_key')
    
    # Remove individual key files
    if [[ -f "$private_key" ]]; then
        rm -f "$private_key"
        log_info "Removed individual private key: $private_key"
    fi
    
    if [[ -f "$public_key" ]]; then
        rm -f "$public_key"
        log_info "Removed individual public key: $public_key"
    fi
    
    # Remove connection from JSON registry
    local temp_file="/tmp/connections_revoke.json"
    jq --arg id "$conn_id" \
       '.last_updated = now | .connections = (.connections | map(select(.id != $id)))' \
       "$CONNECTIONS_REGISTRY" > "$temp_file"
    
    if [[ $? -eq 0 ]]; then
        mv "$temp_file" "$CONNECTIONS_REGISTRY"
        chmod 644 "$CONNECTIONS_REGISTRY" 2>/dev/null || true
        log_info "Removed connection $conn_id from registry"
        log_info "Local cleanup completed successfully"
        return 0
    else
        rm -f "$temp_file" 2>/dev/null || true
        error_exit "Failed to update connections registry"
    fi
}

main() {
    validate_environment
    process_operation "$OPERATION"
}

# Execute main function
main "$@"
