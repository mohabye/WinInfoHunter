# Prompt user for the directory to save the files
$savePath = Read-Host -Prompt "Enter the full path where you want to save the output files (e.g., C:\Reports)"
if (-not (Test-Path -Path $savePath)) {
    Write-Host "The path provided does not exist. Please create the directory or provide a valid path."
    exit
}

# Create file paths for each data type
$autorunFile = Join-Path -Path $savePath -ChildPath "AutorunEntries.csv"
$diskInfoFile = Join-Path -Path $savePath -ChildPath "DiskInfo.csv"
$envVariablesFile = Join-Path -Path $savePath -ChildPath "EnvironmentVariables.csv"
$eventLogsFile = Join-Path -Path $savePath -ChildPath "EventLogs.csv"
$installedSoftwareFile = Join-Path -Path $savePath -ChildPath "InstalledSoftware.csv"
$logonSessionsFile = Join-Path -Path $savePath -ChildPath "LogonSessions.csv"
$networkDrivesFile = Join-Path -Path $savePath -ChildPath "NetworkDrives.csv"
$runningProcessesFile = Join-Path -Path $savePath -ChildPath "RunningProcesses.csv"
$tempFilesFile = Join-Path -Path $savePath -ChildPath "TempFiles.csv"
$unsignedDllsFile = Join-Path -Path $savePath -ChildPath "UnsignedDLLs.csv"
$loggedInUserFile = Join-Path -Path $savePath -ChildPath "LoggedInUser.csv"
$localGroupsFile = Join-Path -Path $savePath -ChildPath "LocalGroups.csv"
$localAccountsFile = Join-Path -Path $savePath -ChildPath "LocalUserAccounts.csv"
$networkConfigFile = Join-Path -Path $savePath -ChildPath "NetworkConfiguration.csv"
$networkConnectionsFile = Join-Path -Path $savePath -ChildPath "NetworkConnections.csv"
$schedTasksFile = Join-Path -Path $savePath -ChildPath "ScheduledTasks.csv"
$systemInfoFile = Join-Path -Path $savePath -ChildPath "SystemInfo.csv"
$wmiScriptsFile = Join-Path -Path $savePath -ChildPath "WMIScripts.csv"

# Function to get Autorun Entries
function Get-AutorunEntries {
    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User
}

# Function to get Disk Info
function Get-DiskInfo {
    Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, DriveType, FreeSpace, Size, VolumeName
}

# Function to get Environment Variables
function Get-EnvironmentVariables {
    Get-ChildItem Env: | Select-Object Name, Value
}

# Function to get the last 100 Event Logs
function Get-EventLogs {
    Get-EventLog -LogName System -Newest 100 | Select-Object TimeGenerated, EntryType, Source, EventID, Message
}

# Function to get Installed Software
function Get-InstalledSoftware {
    Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
}

# Function to get Logon Sessions
function Get-LogonSessions {
    Get-WmiObject -Class Win32_LogonSession | Select-Object LogonId, StartTime, LogonType
}

# Function to get Mapped Network Drives
function Get-NetworkDrives {
    Get-WmiObject -Class Win32_MappedLogicalDisk | Select-Object DeviceID, ProviderName, LocalName
}

# Function to get Running Processes
function Get-RunningProcesses {
    Get-Process | Select-Object Name, Id, CPU, MemoryUsage
}

# Function to get Files in Temp Folder
function Get-TempFiles {
    Get-ChildItem -Path $env:TEMP -Recurse | Select-Object FullName, Length
}

# Function to get Unsigned DLLs
function Get-UnsignedDLLs {
    $dlls = Get-ChildItem -Path $env:SystemRoot\System32 -Recurse -Filter *.dll -ErrorAction SilentlyContinue
    $unsignedDlls = @()
    foreach ($dll in $dlls) {
        try {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($dll.FullName)
            if (!$cert.Verify()) {
                $unsignedDlls += [PSCustomObject]@{FullName = $dll.FullName}
            }
        } catch {
            # Handle exceptions for files that are not valid certificates
            $unsignedDlls += [PSCustomObject]@{FullName = $dll.FullName}
        }
    }
    $unsignedDlls
}

# Function to get Logged-in User
function Get-LoggedInUser {
    Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName
}

# Function to get Local Groups
function Get-LocalGroups {
    Get-LocalGroup | Select-Object Name, Description
}

# Function to get Local User Accounts
function Get-LocalUserAccounts {
    Get-LocalUser | Select-Object Name, Enabled, LastLogon
}

# Function to get Network Configuration
function Get-NetworkConfiguration {
    Get-NetIPAddress | Select-Object IPAddress, InterfaceAlias, AddressFamily, PrefixLength
}

# Function to get Network Connections
function Get-NetworkConnections {
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
}

# Function to get Scheduled Tasks with AT Command
function Get-ScheduledTasks {
    schtasks /query /fo LIST /v | Select-String -Pattern "TaskName|Next Run Time|Status" | Out-File -FilePath $schedTasksFile
}

# Function to get System Information
function Get-SystemInfo {
    Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, Name, NumberOfLogicalProcessors, TotalPhysicalMemory
}

# Function to get WMI Scripts run in the last 24 hours
function Get-WMIScripts {
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; StartTime=(Get-Date).AddDays(-1)} | Select-Object TimeCreated, Message
}

# Gather all data
$autorunEntries = Get-AutorunEntries
$diskInfo = Get-DiskInfo
$envVariables = Get-EnvironmentVariables
$eventLogs = Get-EventLogs
$installedSoftware = Get-InstalledSoftware
$logonSessions = Get-LogonSessions
$networkDrives = Get-NetworkDrives
$runningProcesses = Get-RunningProcesses
$tempFiles = Get-TempFiles
$unsignedDlls = Get-UnsignedDLLs
$loggedInUser = Get-LoggedInUser
$localGroups = Get-LocalGroups
$localAccounts = Get-LocalUserAccounts
$networkConfig = Get-NetworkConfiguration
$networkConnections = Get-NetworkConnections
$schedTasks = Get-ScheduledTasks
$systemInfo = Get-SystemInfo
$wmiScripts = Get-WMIScripts

# Export data to CSV files
$autorunEntries | Export-Csv -Path $autorunFile -NoTypeInformation
$diskInfo | Export-Csv -Path $diskInfoFile -NoTypeInformation
$envVariables | Export-Csv -Path $envVariablesFile -NoTypeInformation
$eventLogs | Export-Csv -Path $eventLogsFile -NoTypeInformation
$installedSoftware | Export-Csv -Path $installedSoftwareFile -NoTypeInformation
$logonSessions | Export-Csv -Path $logonSessionsFile -NoTypeInformation
$networkDrives | Export-Csv -Path $networkDrivesFile -NoTypeInformation
$runningProcesses | Export-Csv -Path $runningProcessesFile -NoTypeInformation
$tempFiles | Export-Csv -Path $tempFilesFile -NoTypeInformation
$unsignedDlls | Export-Csv -Path $unsignedDllsFile -NoTypeInformation
$loggedInUser | Export-Csv -Path $loggedInUserFile -NoTypeInformation
$localGroups | Export-Csv -Path $localGroupsFile -NoTypeInformation
$localAccounts | Export-Csv -Path $localAccountsFile -NoTypeInformation
$networkConfig | Export-Csv -Path $networkConfigFile -NoTypeInformation
$networkConnections | Export-Csv -Path $networkConnectionsFile -NoTypeInformation
$schedTasks | Export-Csv -Path $schedTasksFile -NoTypeInformation
$systemInfo | Export-Csv -Path $systemInfoFile -NoTypeInformation
$wmiScripts | Export-Csv -Path $wmiScriptsFile -NoTypeInformation

Write-Host "Data collection completed. Files saved in $savePath"

