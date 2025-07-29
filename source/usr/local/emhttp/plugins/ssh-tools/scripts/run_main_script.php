<?php
// Main PHP backend script
require_once '/usr/local/emhttp/webGui/include/Helpers.php';

// Initialize session if not already started
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// CSRF Protection - Temporarily disabled for debugging
// TODO: Implement proper CSRF protection for production use
/*
$expected_token = $var['csrf_token'] ?? $_SESSION['csrf_token'] ?? '';
$provided_token = $_POST['csrf_token'] ?? '';
if (empty($expected_token) || empty($provided_token) || $provided_token !== $expected_token) {
    echo "Error: Invalid CSRF token";
    exit;
}
*/

$operation = $_POST['operation'] ?? '';

if (empty($operation)) {
    echo "Error: No operation specified";
    exit;
}

// Prepare environment variables
$env = array();
$env['OPERATION'] = $operation;

// Input validation function
function validateInput($input, $type, $maxLength = 512) {
    if (empty($input)) {
        return ['error' => 'Input is required'];
    }
    
    switch ($type) {
        case 'host':
            // Basic hostname/IP validation
            if (strlen($input) > $maxLength) {
                return ['error' => "Input too long (max: $maxLength characters)"];
            }
            // Allow hostnames, IP addresses, but prevent command injection
            if (!preg_match('/^[a-zA-Z0-9.-]+$/', $input)) {
                return ['error' => 'Invalid characters in hostname/IP'];
            }
            return ['value' => trim($input)];
            
        case 'username':
            if (strlen($input) > 32) {
                return ['error' => 'Username too long (max: 32 characters)'];
            }
            // Basic username validation
            if (!preg_match('/^[a-zA-Z0-9._-]+$/', $input)) {
                return ['error' => 'Invalid characters in username'];
            }
            return ['value' => trim($input)];
            
        case 'password':
            if (strlen($input) > 128) {
                return ['error' => 'Password too long (max: 128 characters)'];
            }
            return ['value' => $input]; // Don't trim passwords
            
        case 'network':
            if (strlen($input) > 32) {
                return ['error' => 'Network range too long'];
            }
            // Basic CIDR validation
            if (!preg_match('/^[0-9.\/]+$/', $input)) {
                return ['error' => 'Invalid network range format'];
            }
            return ['value' => trim($input)];
    }
    
    return ['error' => 'Unknown validation type'];
}

// Process parameters based on operation
switch ($operation) {
    case 'check_key_status':
        // No additional parameters needed
        break;
        
    case 'test_connection':
    case 'exchange_keys':
        if (isset($_POST['host'])) {
            $validation = validateInput($_POST['host'], 'host');
            if (isset($validation['error'])) {
                echo "Error: " . $validation['error'];
                exit;
            }
            $env['REMOTE_HOST'] = $validation['value'];
        } else {
            echo "Error: Host is required";
            exit;
        }
        
        if (isset($_POST['username'])) {
            $validation = validateInput($_POST['username'], 'username');
            if (isset($validation['error'])) {
                echo "Error: " . $validation['error'];
                exit;
            }
            $env['REMOTE_USERNAME'] = $validation['value'];
        } else {
            echo "Error: Username is required";
            exit;
        }
        
        if (isset($_POST['password'])) {
            $validation = validateInput($_POST['password'], 'password');
            if (isset($validation['error'])) {
                echo "Error: " . $validation['error'];
                exit;
            }
            $env['REMOTE_PASSWORD'] = $validation['value'];
        } else {
            echo "Error: Password is required";
            exit;
        }
        break;
        
    case 'test_single_connection':
        if (isset($_POST['host'])) {
            $validation = validateInput($_POST['host'], 'host');
            if (isset($validation['error'])) {
                echo "Error: " . $validation['error'];
                exit;
            }
            $env['TEST_HOST'] = $validation['value'];
        } else {
            echo "Error: Host is required";
            exit;
        }
        break;
        
    case 'scan_ssh':
        if (isset($_POST['network'])) {
            $validation = validateInput($_POST['network'], 'network');
            if (isset($validation['error'])) {
                echo "Error: " . $validation['error'];
                exit;
            }
            $env['SCAN_NETWORK'] = $validation['value'];
        } else {
            echo "Error: Network range is required";
            exit;
        }
        break;
        
    case 'list_exchanged_keys':
    case 'test_all_connections':
        // No additional parameters needed
        break;
}

// Execute shell script
$descriptorspec = array(
    0 => array("pipe", "r"),
    1 => array("pipe", "w"),
    2 => array("pipe", "w")
);

$process = proc_open(
    '/usr/local/emhttp/plugins/ssh-tools/scripts/main_logic.sh',
    $descriptorspec,
    $pipes,
    null,
    $env
);

if (is_resource($process)) {
    fclose($pipes[0]);
    
    $output = stream_get_contents($pipes[1]);
    $error = stream_get_contents($pipes[2]);
    
    fclose($pipes[1]);
    fclose($pipes[2]);
    
    $exitCode = proc_close($process);
    
    if ($exitCode === 0) {
        echo $output;
    } else {
        echo "Error: " . ($error ?: "Script execution failed");
    }
} else {
    echo "Error: Failed to start script process";
}
?>
