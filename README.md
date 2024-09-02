# WinInfoHunter

## Overview

`WinInfoHunter` is a PowerShell script designed to gather a comprehensive set of system information from a Windows machine. It collects data related to autorun entries, disk information, environment variables, event logs, installed software, and more. The script allows users to specify the location where the collected data should be saved and outputs each type of information into separate CSV files.

## Features

- **Autorun Entries**: Lists applications set to run automatically at system startup.
- **Disk Info**: Provides details about disk drives, including free space and total size.
- **Environment Variables**: Retrieves system environment variables.
- **Event Logs**: Collects the latest 100 system event logs.
- **Installed Software**: Lists software installed on the machine.
- **Logon Sessions**: Details of user logon sessions.
- **Mapped Network Drives**: Lists network drives currently mapped on the system.
- **Running Processes**: Displays all currently running processes.
- **Temp Files**: Lists files present in the temporary folder.
- **Unsigned DLLs/Software/Processes**: Identifies unsigned files in system directories.
- **Logged In User**: Shows the currently logged-in user.
- **Local Groups**: Lists local user groups on the machine.
- **Local User Accounts**: Retrieves local user account details.
- **Network Configuration**: Provides network configuration details.
- **Network Connections**: Lists active network connections.
- **Scheduled Tasks**: Shows tasks scheduled with the AT command.
- **System Information**: General system details.
- **WMI Scripts**: Lists WMI scripts run in the last 24 hours.

![image](https://github.com/user-attachments/assets/32550cba-ffea-4a61-850b-b63a4010ede1)


## Installation

Ensure you have PowerShell installed. For PowerShell 5.1 or higher, the `ImportExcel` module is required to export data to CSV. If you don’t have this module installed, you can install it using:

```powershell
Install-Module -Name ImportExcel -Scope CurrentUser


