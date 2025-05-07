<#
.SYNOPSIS
Script to remove OneStart.ai, DBar, and known related components.

.DESCRIPTION
This script attempts to remove OneStart.ai and DBar processes, files, folders,
registry entries (per-user and system-wide), and scheduled tasks.
It includes checks for common installation paths, registry locations,
and potential process/task names associated with this type of software,
including a specific known uninstall registry key.

.NOTES
- Run this script with Administrator privileges for full removal capabilities.
- This script uses -Force and -Recurse and can delete data irreversibly.
- Complete removal of stubborn PUPs may require additional steps like
  using dedicated security software or manual browser cleanup.
- This script is provided as-is and without warranty. Use at your own risk.
- A prompt has been added at the end to prevent the window from closing immediately.
#>

# Requires Administrator privileges for system-wide removal (HKLM, Program Files, Scheduled Tasks)
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges to remove all components. Please re-run as Administrator."
    # Optionally exit if not admin
    # Exit
}

Write-Host "Starting OneStart.ai and DBar removal process..."

#region Stop Processes
Write-Host "`n--- Checking and stopping OneStart/DBar processes ---"

# find running processes with "OneStart", "DBar", or known aliases in them
# ADDED "DBar" to the list of process names to check
$process_names = @("OneStart", "onestart.ai", "onestartbar", "onestartupdate", "DBar")

# Paths where OneStart or DBar might legitimately run from (to avoid stopping unrelated processes with similar names)
# Updated user paths to include both Local and Roaming AppData for OneStart/DBar
$all_valid_paths = @(
    "C:\Users\*\AppData\Local\OneStart.ai\*",
    "C:\Users\*\AppData\Roaming\OneStart\*", # Added Roaming path from your DBar snippet
    "C:\Program Files*\OneStart*",
    "C:\ProgramData\OneStart*"
    # Add more specific DBar paths here if DBar is known to install outside OneStart folders (e.g., "C:\Program Files*\DBar*", "C:\Users\*\AppData\Roaming\DBar\*")
)

foreach ($proc in $process_names){
    Write-Host "Searching for process name: '$proc'"
	# Using wildcard in Get-Process name search for robustness
    $OL_processes = Get-Process -Name "$proc*" -ErrorAction SilentlyContinue | Where-Object {
        # Check if the process path matches any of the known valid paths (user or system)
        $path = $_.Path
        $path_match = $false
        if ($path) { # Ensure path is not null/empty
            foreach ($vpath in $all_valid_paths) {
                if ($path -like $vpath) {
                    $path_match = true
                    break
                }
            }
        }
        $path_match
    }

	if ($OL_processes.Count -eq 0){
		Write-Output "No '$proc' processes matching known paths were found."
	}else {
		Write-Output "Found the following processes potentially related to '$proc' at known paths:"
        $OL_processes | Select-Object Name, Id, Path | Format-Table -AutoSize
		foreach ($process in $OL_processes){
            Write-Host "Attempting to stop process $($process.Name) (ID: $($process.Id)) at path $($process.Path)..."
			try {
                Stop-Process $process -Force -ErrorAction Stop
				Write-Output "Successfully stopped process $($process.Name)."
			}
            catch {
                Write-Warning "Could not stop process $($process.Name). Error: $($_.Exception.Message)"
            }
		}
	}
}

Start-Sleep -Seconds 2 # Give processes a moment to terminate
#endregion

#region Remove Files and Folders
Write-Host "`n--- Removing OneStart/DBar files and folders ---"

# Common AppData paths (per user)
# Ensure paths cover both Local and Roaming for OneStart and potential DBar variations
$user_file_paths = @(
    "\AppData\Roaming\OneStart\",
    "\AppData\Local\OneStart.ai\",
    "\AppData\Local\OneStartBar\" # Potential OneStart variation - CORRECTED: Removed trailing comma
    # Add specific DBar user paths here if DBar is known to install outside OneStart folders (e.g., "\AppData\Roaming\DBar\", "\AppData\Local\DBar\")
)

# Common System paths (requires Admin)
$system_file_paths = @(
    "C:\Program Files\OneStart*",
    "C:\Program Files (x86)\OneStart*",
    "C:\ProgramData\OneStart*"
    # Add specific DBar system paths here if DBar is known to install outside OneStart folders (e.g., "C:\Program Files\DBar*", "C:\ProgramData\DBar\")
)

# Iterate through users for AppData directories
Write-Host "Checking user profiles for AppData folders..."
foreach ($folder in (Get-ChildItem C:\Users -ErrorAction SilentlyContinue)) {
    if ($folder.PSBase.Name -eq "Public") { continue } # Skip Public user profile for AppData checks
	foreach ($fpath in $user_file_paths) {
		$path = Join-Path -Path $folder.FullName -ChildPath $fpath
		# Write-Verbose "Checking path: $path" # Use Write-Verbose for less clutter, or keep Write-Output for debugging
		if (Test-Path $path) {
            Write-Host "Found path: $path - Attempting removal..."
			try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                if (-not (Test-Path $path)) {
                    Write-Output "$path has been successfully deleted."
                } else {
                    Write-Warning "$path could not be deleted after removal attempt."
                }
            }
            catch {
                 Write-Warning "Error removing path '$path': $($_.Exception.Message)"
            }
		} else {
			# Write-Verbose "$path does not exist." # Use Write-Verbose
            Write-Output "$path does not exist." # Keep for showing checks
		}
	}
}

# Check system-wide paths (requires Admin)
Write-Host "Checking system-wide folders..."
foreach ($fpath in $system_file_paths) {
    # Using Get-ChildItem with -ErrorAction SilentlyContinue and wildcards
    $items_to_remove = Get-ChildItem -Path $fpath -ErrorAction SilentlyContinue
    if ($items_to_remove) {
        foreach ($item in $items_to_remove) {
            Write-Host "Found system path: $($item.FullName) - Attempting removal..."
            try {
                Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                if (-not (Test-Path $item.FullName)) {
                    Write-Output "$($item.FullName) has been successfully deleted."
                } else {
                    Write-Warning "$($item.FullName) could not be deleted after removal attempt."
                }
            }
            catch {
                Write-Warning "Error removing system path '$($item.FullName)': $($_.Exception.Message)"
            }
        }
    } else {
        Write-Output "No items found matching '$fpath'."
    }
}
#endregion

#region Remove Registry Keys and Properties
Write-Host "`n--- Removing OneStart/DBar registry entries ---"

# Common registry key paths (main keys)
# Added HKLM keys, WOW6432Node, Uninstall checks, AND the specific GUID key
$reg_keys_to_remove = @(
    "\software\OneStart.ai",
    "\software\OneStartBar", # Potential variation
    "\software\DBar", # Potential DBar key (per user)
    "HKLM:\Software\OneStart.ai",
    "HKLM:\Software\OneStartBar", # Potential variation
    "HKLM:\Software\DBar", # Potential DBar key (system-wide)
    "HKLM:\Software\WOW6432Node\OneStart.ai",
    "HKLM:\Software\WOW6432Node\OneStartBar", # Potential variation
    "HKLM:\Software\WOW6432Node\DBar", # Potential DBar key (32-bit)
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OneStart*", # Check uninstall entries
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\OneStart*", # Check 32-bit uninstall entries
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\DBar*", # Check for DBar uninstall entries
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\DBar*", # Check for 32-bit DBar uninstall entries
    # ADDED the specific uninstall key GUID path
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\Currentversion\Uninstall\{31F4B209-D4E1-41E0-A34F-35EFF7117AE8}"
)

# Iterate through users for per-user registry keys
Write-Host "Checking user profiles for registry keys..."
foreach ($registry_hive in (Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue)) {
    # Check default user or other non-standard hives if necessary, but primarily focus on SIDs
    if ($registry_hive.PSBase.Name -like "S-1-5-21-*") { # Filter for typical user SIDs
        $user_sid_path = $registry_hive.PSPath
        # Specify suffixes for HKU iteration, including potential DBar per-user key
        foreach ($regpath_suffix in @("\software\OneStart.ai", "\software\OneStartBar", "\software\DBar")) {
             $path = $user_sid_path + $regpath_suffix
             # Write-Verbose "Checking registry path: $path"
            if (Test-Path $path) {
                Write-Host "Found registry key: $path - Attempting removal..."
                try {
                    Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                    if (-not (Test-Path $path)) {
                         Write-Output "$path has been successfully removed."
                    } else {
                         Write-Warning "$path could not be removed after attempt."
                    }
                }
                catch {
                    Write-Warning "Error removing registry key '$path': $($_.Exception.Message)"
                }
            } else {
                 # Write-Verbose "$path does not exist."
                 Write-Output "$path does not exist."
            }
        }
    }
}

# Check system-wide registry keys (requires Admin)
Write-Host "Checking system-wide registry keys..."
foreach ($regpath in $reg_keys_to_remove) {
    # Use Get-ChildItem for paths with wildcards like Uninstall entries or if the exact key name might vary slightly
    # Handle paths that are simple hive\key or hive\key\subkey without wildcards directly if Test-Path is sufficient
    # The GUID path is treated as an exact path here
    if ($regpath -like "*\*" -or $regpath.Contains("*")) { # Check if path includes hive AND potentially wildcards
         $items_to_remove = Get-ChildItem -Path $regpath -ErrorAction SilentlyContinue
         if ($items_to_remove) {
             foreach ($item in $items_to_remove) {
                 Write-Host "Found registry key: $($item.PSPath) - Attempting removal..."
                 try {
                     Remove-Item -Path $item.PSPath -Recurse -Force -ErrorAction Stop
                      if (-not (Test-Path $item.PSPath)) {
                         Write-Output "$($item.PSPath) has been successfully removed."
                     } else {
                         Write-Warning "$($item.PSPath) could not be removed after attempt."
                     }
                 }
                 catch {
                     Write-Warning "Error removing registry key '$($item.PSPath)': $($_.Exception.Message)"
                 }
             }
         } else {
              Write-Output "No registry keys found matching '$regpath'."
         }
    } elseif (Test-Path $regpath) { # Handle specific paths without wildcards already checked by Get-ChildItem
         Write-Host "Found registry key: $regpath - Attempting removal..."
         try {
             Remove-Item -Path $regpath -Recurse -Force -ErrorAction Stop
              if (-not (Test-Path $regpath)) {
                 Write-Output "$regpath has been successfully removed."
             } else {
                 Write-Warning "$regpath could not be removed after attempt."
             }
         }
         catch {
             Write-Warning "Error removing registry key '$regpath': $($_.Exception.Message)"
         }
    } else {
         Write-Output "Registry key '$regpath' does not exist."
    }
}


# Registry Run Keys (Startup entries)
Write-Host "Checking Run registry keys for startup entries..."
# Added HKLM run keys
$run_key_paths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", # HKCU links to current user in HKEY_USERS
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" # 32-bit run key
    # Add other startup keys like RunOnce if necessary after research
)

# Added "DBar" property name to the list of properties to check for removal
$reg_properties_to_remove = @("OneStartBar", "OneStartBarUpdate", "OneStartUpdate", "OneStart", "DBar")

foreach($run_path in $run_key_paths){
    if (test-path $run_path){
        Write-Host "Checking run key path: $run_path"
        try {
            $reg_key = Get-Item $run_path -ErrorAction Stop
            # Use wildcard search for properties potentially related to OneStart or DBar
            $prop_values = $reg_key.GetValueNames() | Where-Object { $_ -like "OneStart*" -or $_ -like "DBar*" }

            if ($prop_values){
                 Write-Host "Found potential OneStart/DBar startup properties: $($prop_values -join ', ')"
                foreach ($prop_value in $prop_values) {
                    # Add a more specific check here if needed, but wildcards above are likely sufficient
                    # if ($reg_properties_to_remove -contains $prop_value) { # More explicit check
                        Write-Host "Attempting to remove property '$prop_value' from '$run_path'..."
                        try {
                             Remove-ItemProperty -Path $run_path -Name $prop_value -ErrorAction Stop
                            Write-Output "$run_path\$prop_value registry property value has been successfully removed."
                        }
                        catch {
                            Write-Warning "Error removing registry property '$prop_value' from '$run_path': $($_.Exception.Message)"
                        }
                    #}
                }
            } else {
                 Write-Output "No OneStart/DBar related properties found in '$run_path'."
            }
        }
        catch {
            Write-Warning "Error accessing run key path '$run_path': $($_.Exception.Message)"
        }
    } else {
        Write-Output "Run key path '$run_path' does not exist."
    }
}
#endregion

#region Remove Scheduled Tasks
Write-Host "`n--- Removing OneStart/DBar scheduled tasks ---"

# Added potential aliases for task names, including DBar if known
$schtasknames = @("OneStart Chromium", "OneStart Updater", "OneStart Maintenance", "OneStart Cleanup", "OneStart*", "DBar*") # Added wildcard search for DBar tasks

$removed_task_count = 0

# find onestart/dbar related scheduled tasks and unregister them
foreach ($taskname_pattern in $schtasknames){
    Write-Host "Searching for scheduled tasks matching '$taskname_pattern'..."
	$clear_tasks = Get-ScheduledTask -TaskName $taskname_pattern -ErrorAction SilentlyContinue

	if ($clear_tasks){
        Write-Output "Found the following tasks matching '$taskname_pattern':"
        $clear_tasks | Select-Object TaskName, TaskPath | Format-Table -AutoSize
		foreach ($task in $clear_tasks) {
            Write-Host "Attempting to unregister task '$($task.TaskName)' in path '$($task.TaskPath)'..."
            try {
                Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
                Write-Output "Scheduled task '$($task.TaskName)' has been successfully removed."
                $removed_task_count++
            }
            catch {
                Write-Warning "Could not remove scheduled task '$($task.TaskName)'. Error: $($_.Exception.Message)"
            }
		}
	} else {
        Write-Output "No scheduled tasks found matching '$taskname_pattern'."
    }
}

if ($removed_task_count -eq 0){
	Write-Output "No OneStart or DBar scheduled tasks were found or removed."
} else {
    Write-Output "$removed_task_count scheduled task(s) related to OneStart/DBar were removed."
}
#endregion

Write-Host "`n--- Removal process complete ---"
Write-Host "Manual steps may still be required, especially for browser extensions."
Write-Host "Consider running a reputable anti-malware scan."

#region Keep Window Open
# Added to keep the PowerShell window open after execution finishes
Read-Host -Prompt "Press Enter to exit"
#endregion