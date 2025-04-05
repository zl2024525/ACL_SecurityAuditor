# ACL_SecurityAuditor: Advanced Access Control List Security Auditor
ACL_SecurityAuditor is a Python-based tool designed to perform in-depth security audits on Access Control Lists (ACLs). By analyzing ACL configurations from network devices, it identifies potential security vulnerabilities and misconfigurations. The tool is particularly useful for network administrators, security analysts, and organizations aiming to enhance the security posture of their network infrastructure. It supports both Cisco and Huawei devices' specific ACL syntax, making it versatile for different networking environments.

## Installation
- The tool requires Python 3.x
- tkinter, sqlite3, re, os, time, matplotlib

## Usage
### GUI Interaction
- **Upload File Path:** Enter the path to the directory with ACL configuration files in the "Upload File Path" entry field, or click the "Upload" button to select a directory using a file dialog.
- **Initiate Detection**
- **View Results:** Detection results are displayed in the large text box in the main window.
- **Export Results**
- **View History**

### Behind the Scenes Process
- **File Preprocessing:** When detection starts, the tool reads each ACL configuration file in the selected directory and determines whether it is from a Cisco or Huawei device based on specific keywords.
- **Rule Detection:** For each ACL in the file, the tool applies a set of rules to detect security vulnerabilities, including prohibited rules, broad rules, conflict rules, and coverage rules.
- **Result Aggregation:** After analyzing all ACLs in all files, the tool aggregates the results. It calculates the total number of valid ACLs, total number of security risks, and breaks down risks into different categories (prohibited, broad, conflict, etc.).
- **Data Visualization:** The tool generates a pie chart to visually represent the ratio of regular ACLs to security vulnerabilities, providing a quick overview of the overall security state of the audited ACLs.

## Key Features
### Rule-Based Vulnerability Detection

**Prohibited Rule Detection**
- The tool flags rules allowing traffic from any source, to any destination, using any protocol (e.g., "permit ip any any any").
- It also detects rules permitting UDP traffic (less secure than TCP) and those allowing traffic on risky ports like 135, 139, 445, 21, 23, etc., which are frequently targeted in network attacks.

**Broad Rule Detection**
- Rules allowing traffic from any source or to any destination, or those specifying a wide IP address range (e.g., "source 192.168.0.0" in a permit statement), are identified.
- Rules without a specific port in a permit statement are also considered broad and detected.

### Conflict and Coverage Analysis

**Conflict Rule Detection**
- The tool checks for the co-existence of allow and deny rules for the same address and port (e.g., "permit tcp 192.168.1.1 10.0.0.1 eq 80" and "deny tcp 192.168.1.1 10.0.0.1 eq 80").
- It also detects conflicts in source or destination IP addresses when other parameters like protocol and port match.

**Coverage Rule Detection**

Rules where one IP address range covers another in a permit statement are identified. For example, if there are "permit tcp 192.168.0.0 0.0.255.255" and "permit tcp 192.168.1.0 0.0.0.255" rules, the relevant coverage relationship is detected.

### Device-Specific Support
**Cisco and Huawei ACL Compatibility**
- The tool automatically detects whether the input ACL configuration is from a Cisco or Huawei device.
- For Cisco devices, it parses configurations starting with "ip access-list", and for Huawei devices, those starting with "acl".
