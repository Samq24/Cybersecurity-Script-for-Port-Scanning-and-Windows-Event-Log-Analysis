# Cybersecurity Project

This project is designed to perform security scans on a Windows machine using a Python script. The script utilizes the `nmap` library to scan ports on a specified IP address and analyzes system logs for events related to potential attacks.

## How the Script Works

### 1. Define Objectives
The script starts by defining the scan objectives, including a target IP address and a range of ports to scan. These objectives can be configured within the `define_objectives()` function.

### 2. Port Scanning with Nmap
The script uses the `nmap` library to conduct a port scan on the specified IP address and port range. Detailed information about open ports is collected and displayed in the console.

### 3. Windows Event Log Analysis
An analysis of the system logs is performed to identify events that may indicate potential attacks. The script searches for patterns related to the keywords "attack,intrusion,compromised security,unauthorized access,network attack,malware,denial of service,compromised account" using regular expressions.

### 4. Alert Notification
If a potential attack is detected in the system logs, an alert is displayed using a Windows message box, thanks to the `notify_alerts` function.

### 5. Nmap Scan Results
Finally, detailed results of the port scan performed with `nmap` are displayed, highlighting the status, service, and version of each port.

## How to Use the Script

1. Clone the repository to your local machine.
2. Open a terminal and navigate to the project directory.
3. Run the Python script using the command `python script_name.py`.
4. **IMPORTANT:** Ensure to run the script with administrator privileges. You can do this by opening a terminal as an administrator.

## Requirements

- Python 3.x
- `nmap` library

## Important Notes

- This script is designed for Windows systems and may not be fully compatible with other operating systems.
- Ensure you have the necessary permissions to conduct scans and access system logs.
