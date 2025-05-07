<#
.SYNOPSIS
Detection script for OneStart.ai and DBar remnants.

.DESCRIPTION
Checks for processes, files, registry entries, or scheduled tasks
associated with OneStart.ai or DBar. Exits with 1 if found, 0 if not found.

.OUTPUTS
Exits with code 1 if OneStart/DBar signs are detected, 0 otherwise.

.NOTES
Designed to run in the System context via Intune Proactive Remediations.
#>

# Initialize exit code: 0 means no issue found (compliant)
$script:ExitCode = 0

# --- Detection Logic ---

# 1. Check for running processes
$process_names = @("OneStart*", "onestart.ai*", "onestartbar*", "onestartupdate*", "DBar*")
try {
    $running_processes = Get-Process -Name $process_names -ErrorAction SilentlyContinue
    if ($running_processes) {
        Write-Verbose "Detected processes: $($running_processes.Name -join ', ')" # Log for troubleshooting
        $script:ExitCode = 1 # Issue detected
    }
} catch {
    Write-Warning "Error checking processes: $($_.Exception.Message)"
    # Continue checking other items even if this fails
}

# Exit early if process found, no need to check further for detection
if ($script:ExitCode -eq 1) { exit $script:ExitCode }

# 2. Check for common installation/data folders
# Note: Checking all user profiles might be slow. Focus on Program Files/Data or specific known persistent locations.
# For simplicity and speed in detection, let's check a few key locations.
$detection_paths = @(
    "C:\Program Files\OneStart*",
    "C:\Program Files (x86)\OneStart*",
    "C:\ProgramData\OneStart*",
    "C:\Users\*\AppData\Roaming\OneStart", # Check presence in any user profile
    "C:\Users\*\AppData\Local\OneStart.ai", # Check presence in any user profile
    # CORRECTED: Removed trailing comma from the line below
    "C:\Users\*\AppData\Local\OneStartBar" # Potential OneStart variation - Check presence in any user profile
    # Add specific DBar paths here if necessary for detection
)

foreach ($dpath in $detection_paths) {
    try {
        # Using Get-ChildItem to handle wildcards and check existence efficiently
        if (Get-ChildItem -Path $dpath -ErrorAction SilentlyContinue) {
            Write-Verbose "Detected folder pattern: '$dpath'" # Log for troubleshooting
            $script:ExitCode = 1 # Issue detected
            break # Found evidence, no need to check other paths
        }
    } catch {
        Write-Warning "Error checking path '$dpath': $($_.Exception.Message)"
        # Continue checking other items even if this fails
    }
}

# Exit early if folder found
if ($script:ExitCode -eq 1) { exit $script:ExitCode }


# 3. Check for persistent registry keys (HKLM Run, Uninstall, main keys)
$detection_reg_paths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\OneStart*",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\DBar*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\OneStart*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\DBar*",
    "HKLM:\Software\OneStart.ai",
    "HKLM:\Software\OneStartBar",
    "HKLM:\Software\DBar",
    "HKLM:\Software\WOW6432Node\OneStart.ai",
    "HKLM:\Software\WOW6432Node\OneStartBar",
    "HKLM:\Software\WOW6432Node\DBar",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OneStart*",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\DBar*",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\OneStart*",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\DBar*",
    # Include the specific GUID key if it's a strong indicator of presence
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\Currentversion\Uninstall\{31F4B209-D4E1-41E0-A34F-35EFF7117AE8}"
)

foreach ($dregpath in $detection_reg_paths) {
     try {
        # Using Test-Path for direct keys, or Get-ChildItem for wildcard paths
        if ($dregpath.Contains("*")) {
             if (Get-ChildItem -Path $dregpath -ErrorAction SilentlyContinue) {
                 Write-Verbose "Detected registry pattern: '$dregpath'" # Log
                 $script:ExitCode = 1 # Issue detected
                 break # Found evidence
             }
        } elseif (Test-Path $dregpath) {
             Write-Verbose "Detected registry key: '$dregpath'" # Log
             $script:ExitCode = 1 # Issue detected
             break # Found evidence
        }
    } catch {
        Write-Warning "Error checking registry path '$dregpath': $($_.Exception.Message)"
        # Continue checking other items
    }
}

# Exit early if registry key found
if ($script:ExitCode -eq 1) { exit $script:ExitCode }


# 4. Check for scheduled tasks
$detection_task_names = @("OneStart*", "DBar*")
try {
    $found_tasks = Get-ScheduledTask -TaskName $detection_task_names -ErrorAction SilentlyContinue
    if ($found_tasks) {
        Write-Verbose "Detected scheduled task(s): $($found_tasks.TaskName -join ', ')" # Log
        $script:ExitCode = 1 # Issue detected
    }
} catch {
    Write-Warning "Error checking scheduled tasks: $($_.Exception.Message)"
    # Continue checking other items
}

# Exit early if task found
if ($script:ExitCode -eq 1) { exit $script:ExitCode }


# --- Final Output ---
# If we reached here, no significant traces were found. Exit code remains 0.
exit $script:ExitCode