# Converting Sigma Rules to  SIEMs.

## Introduction

Sigma is an open-source, SIEM-agnostic rule format that enables security professionals to write standardized threat detection rules in YAML. These rules can be converted into query languages for various Security Information and Event Management (SIEM) systems, such as Splunk, Elastic (Elasticsearch/OpenSearch), Microsoft Sentinel, and QRadar. This guide provides a clear, step-by-step process for converting any Sigma rule to these popular SIEM platforms, ensuring efficient deployment of detection logic across diverse environments.

## Key Points

- **Purpose**: Sigma rules allow you to write detection logic once and convert it for use in multiple SIEMs, saving time and reducing errors.
- **Tool**: The `sigma-cli` tool, built on the `pySigma` library, is the primary method for converting rules to SIEM-specific query languages.
- **Supported SIEMs**: This guide covers Splunk, Elastic, Microsoft Sentinel, and QRadar, which are among the most widely used SIEM platforms.
- **Customization**: Field mappings may need adjustment based on your SIEM’s log schema to ensure accurate conversions.
- **Testing**: Always test converted queries to verify functionality and tune for false positives.

## Prerequisites

Before converting Sigma rules, ensure you have:
- **Python 3.9+**: Required to run `sigma-cli`.
- **sigma-cli**: Install via pip:
  ```bash
  pip install sigmatools
  ```
- **Sigma Rules**: Obtain rules from the [SigmaHQ repository](https://github.com/SigmaHQ/sigma) or write your own in YAML format.
- **Log Sources**: Verify that your SIEM ingests the necessary logs (e.g., Sysmon, Windows Event Logs).
- **Configuration Files**: Download the Sigma repository for backend-specific configuration files (`tools/config/`).

## Step-by-Step Conversion Process

### Step 1: Obtain or Create a Sigma Rule
Sigma rules are YAML files that define detection logic. Ensure your rule includes key components like `title`, `logsource`, `detection`, and `fields`. Save the rule as `your_rule.yml`.

### Step 2: Identify Your SIEM
Choose the target SIEM (e.g., Splunk, Elastic, Microsoft Sentinel, QRadar) and note its query language (e.g., SPL for Splunk, KQL for Sentinel).

### Step 3: Convert the Rule Using sigma-cli
Use the `sigma convert` command with the appropriate backend (`-t`) and configuration file (`-c`). Configuration files map Sigma fields to SIEM-specific fields.

### Step 4: Test and Deploy
Run the converted query in your SIEM, verify results, tune for false positives, and deploy as an alert or correlation rule.

## Conversion Examples

Below is an example Sigma conversion  its converted queries for each SIEM:


**Splunk Conversion**:
```bash
sigma convert -t splunk -c tools/config/splunk-windows.yml your_rule.yml
```
**Output**:
```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 process="*\\powershell.exe" ("-EncodedCommand" OR "-WindowStyle Hidden")
| fields CommandLine, ParentImage
```

**Elastic (KQL) Conversion**:
```bash
sigma convert -t es-qs -c tools/config/ecs-windows.yml your_rule.yml
```
**Output**:
```kql
event.category:process AND process.executable:*\\powershell.exe AND process.command_line:("-EncodedCommand" OR "-WindowStyle Hidden")
```

**Microsoft Sentinel (KQL) Conversion**:
```bash
sigma convert -t azure -c tools/config/microsoft-sentinel.yml your_rule.yml
```
**Output**:
```kql
SysmonEvent
| where EventID == 1
| where Process endswith "\\powershell.exe"
| where CommandLine contains "-EncodedCommand" or CommandLine contains "-WindowStyle Hidden"
| project CommandLine, ParentProcess
```

**QRadar (AQL) Conversion**:
```bash
sigma convert -t qradar -c tools/config/qradar.yml your_rule.yml
```
**Output**:
```aql
SELECT * FROM events WHERE
LOWER(PROCESS) LIKE '%\\powershell.exe'
AND (PROCESS_COMMANDLINE LIKE '%-EncodedCommand%' OR PROCESS_COMMANDLINE LIKE '%-WindowStyle Hidden%')
```

---

# Comprehensive Guide to Converting Sigma Rules to Popular SIEMs

## Introduction to Sigma

Sigma is an open-source, vendor-neutral format for defining threat detection rules in YAML. Developed by Florian Roth and Thomas Patzke in 2017, Sigma addresses the challenge of varying log schemas and query languages across SIEM platforms. By providing a standardized format, Sigma enables security teams to write detection rules once and convert them for use in multiple SIEMs, such as Splunk, Elastic, Microsoft Sentinel, and QRadar. This guide details the process of converting any Sigma rule to these platforms, leveraging the `sigma-cli` tool and configuration files.

## Why Use Sigma?

- **Portability**: Write rules once and deploy across multiple SIEMs.
- **Community-Driven**: Benefit from a global community contributing rules and updates.
- **Human-Readable**: YAML format is easy to read and modify.
- **Standardization**: Aligns with MITRE ATT&CK for consistent threat mapping.

## Prerequisites

To convert Sigma rules, you need:
- **Python 3.9+**: Required for `sigma-cli`. Install from [python.org](https://www.python.org/downloads/).
- **sigma-cli**: Install via pip:
  ```bash
  pip install sigmatools
  ```
- **Sigma Rules**: Source from the [SigmaHQ repository](https://github.com/SigmaHQ/sigma) or create custom rules.
- **Log Sources**: Ensure your SIEM ingests relevant logs (e.g., Sysmon Event ID 1 for process creation, Event ID 13 for registry events).
- **Configuration Files**: Download from the Sigma repository (`tools/config/`) for field mappings.

## Understanding Sigma Rules

A Sigma rule consists of several key components, as shown in the example below:

```yaml
title: Suspicious PowerShell Command Execution
id: 123e4567-e89b-12d3-a456-426614174000
description: Detects PowerShell executions with suspicious parameters.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-WindowStyle Hidden'
  condition: selection
fields:
  - CommandLine
  - ParentImage
falsepositives:
  - Legitimate administrative scripts
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

**Key Components**:
- **title**: Descriptive name of the rule.
- **id**: Unique UUID for identification.
- **logsource**: Specifies the log source (e.g., `process_creation`, `windows`).
- **detection**: Defines the logic using fields and conditions.
- **fields**: Lists fields to include in query output.
- **falsepositives**: Notes potential legitimate activities that may trigger the rule.
- **level**: Severity (e.g., `high`, `medium`).
- **tags**: MITRE ATT&CK references.

## Conversion Process

The `sigma-cli` tool, built on the `pySigma` library, converts Sigma rules into SIEM-specific query languages. Each SIEM requires a specific backend and configuration file to map Sigma fields to the SIEM’s schema.

### Step 1: Install sigma-cli
Install the tool using pip:
```bash
pip install sigmatools
```

### Step 2: Obtain Configuration Files
Clone the Sigma repository to access configuration files:
```bash
git clone https://github.com/SigmaHQ/sigma.git
cd sigma
```

Configuration files are located in `tools/config/`. Common files include:
- `splunk-windows.yml` for Splunk.
- `ecs-windows.yml` for Elastic (ECS fields).
- `microsoft-sentinel.yml` for Microsoft Sentinel.
- `qradar.yml` for QRadar.

### Step 3: Convert Rules for Specific SIEMs

Below are detailed instructions for converting Sigma rules to the four most popular SIEMs.

#### Splunk
- **Query Language**: Search Processing Language (SPL).
- **Backend**: `-t splunk`.
- **Config File**: `tools/config/splunk-windows.yml`.
- **Command**:
  ```bash
  sigma convert -t splunk -c tools/config/splunk-windows.yml your_rule.yml
  ```
- **Example Output** (for the PowerShell rule):
  ```spl
  source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 process="*\\powershell.exe" ("-EncodedCommand" OR "-WindowStyle Hidden")
  | fields CommandLine, ParentImage
  ```
- **Notes**:
  - Adjust the `source` to match your Splunk index (e.g., `index=sysmon`).
  - Map fields like `Image` to `process` and `CommandLine` to `command_line` in the config file if needed.
  - Test in Splunk’s Search interface.

#### Elastic (Elasticsearch/OpenSearch)
- **Query Language**: Kibana Query Language (KQL) or Query DSL.
- **Backend**: `-t es-qs` (KQL) or `-t es-dsl` (Query DSL).
- **Config File**: `tools/config/ecs-windows.yml`.
- **Command**:
  ```bash
  sigma convert -t es-qs -c tools/config/ecs-windows.yml your_rule.yml
  ```
- **Example Output (KQL)**:
  ```kql
  event.category:process AND process.executable:*\\powershell.exe AND process.command_line:("-EncodedCommand" OR "-WindowStyle Hidden")
  ```
- **Notes**:
  - Use Elastic Common Schema (ECS) fields (e.g., `process.executable`, `process.command_line`).
  - Elastic is case-sensitive; ensure string matches align with your data.
  - Test in Kibana’s KQL search bar or Dev Tools (for DSL).

#### Microsoft Sentinel
- **Query Language**: Kusto Query Language (KQL).
- **Backend**: `-t azure`.
- **Config File**: `tools/config/microsoft-sentinel.yml`.
- **Command**:
  ```bash
  sigma convert -t azure -c tools/config/microsoft-sentinel.yml your_rule.yml
  ```
- **Example Output**:
  ```kql
  SysmonEvent
  | where EventID == 1
  | where Process endswith "\\powershell.exe"
  | where CommandLine contains "-EncodedCommand" or CommandLine contains "-WindowStyle Hidden"
  | project CommandLine, ParentProcess
  ```
- **Notes**:
  - Use `SysmonEvent` or `SecurityEvent` tables based on your log source.
  - Map fields like `Image` to `Process` or `NewProcessName` for SecurityEvent logs.
  - Test in Sentinel’s Logs section.

#### QRadar
- **Query Language**: Ariel Query Language (AQL).
- **Backend**: `-t qradar`.
- **Config File**: `tools/config/qradar.yml`.
- **Command**:
  ```bash
  sigma convert -t qradar -c tools/config/qradar.yml your_rule.yml
  ```
- **Example Output**:
  ```aql
  SELECT * FROM events WHERE
  LOWER(PROCESS) LIKE '%\\powershell.exe'
  AND (PROCESS_COMMANDLINE LIKE '%-EncodedCommand%' OR PROCESS_COMMANDLINE LIKE '%-WindowStyle Hidden%')
  ```
- **Notes**:
  - Map fields like `Image` to `PROCESS` and `CommandLine` to `PROCESS_COMMANDLINE`.
  - QRadar is case-sensitive; `LOWER()` is used for consistency.
  - Test in QRadar’s Log Activity tab.

### Step 4: Test and Tune Queries
- **Verify Log Sources**: Ensure your SIEM ingests the required logs (e.g., Sysmon Event ID 1 for process creation).
- **Check Field Mappings**: Update the configuration file if your SIEM uses custom field names (e.g., `process_command_line` instead of `CommandLine`).
- **Reduce False Positives**: Use the `falsepositives` section of the Sigma rule to guide exclusions (e.g., `NOT command_line="*sccm*"` for administrative scripts).
- **Performance**: Limit query scope with time ranges (e.g., `earliest=-24h` in Splunk) or specific filters (e.g., `EventType: SetValue` for registry events).

### Step 5: Deploy Queries
Deploy the converted queries as alerts or correlation rules:
- **Splunk**: Save as a scheduled search or alert.
- **Elastic**: Create a detection rule in Kibana.
- **Microsoft Sentinel**: Set up an analytic rule.
- **QRadar**: Create a custom rule or event rule.

## Common SIEM Backends and Configurations

| SIEM              | Backend       | Config File                     | Query Language | Notes                                      |
|-------------------|---------------|---------------------------------|----------------|--------------------------------------------|
| Splunk            | `-t splunk`   | `splunk-windows.yml`           | SPL            | Adjust `source` to match index.            |
| Elastic           | `-t es-qs`    | `ecs-windows.yml`              | KQL            | Use ECS fields; case-sensitive.            |
| Microsoft Sentinel| `-t azure`    | `microsoft-sentinel.yml`       | KQL            | Use `SysmonEvent` or `SecurityEvent`.      |
| QRadar            | `-t qradar`   | `qradar.yml`                   | AQL            | Case-sensitive; use `LOWER()` for strings. |

## Advanced Considerations

- **Field Mapping**: If your SIEM uses non-standard field names, modify the configuration file to map Sigma fields (e.g., `Image` to `process.executable`).
- **Log Source Availability**:
  - **Process Creation**: Requires Sysmon Event ID 1 or Windows Event ID 4688.
  - **Network Connections**: Requires Sysmon Event ID 3 or network monitoring (e.g., Zeek).
  - **Registry Events**: Requires Sysmon Event ID 13 or Windows Event ID 4657.
- **Threat Intelligence**: For rules involving IPs, integrate with a threat intelligence feed for dynamic updates.
- **Case Sensitivity**: Splunk and Sentinel are case-insensitive, but Elastic and QRadar may require case handling (e.g., add case variations or use `LOWER()`).
- **Performance Optimization**: Use specific filters and time ranges to reduce query load.
- **Automation**: Consider integrating `sigma-cli` into CI/CD pipelines for automated rule conversion and deployment.

## Troubleshooting

- **Field Errors**: If fields are missing, verify your SIEM’s log schema and update the configuration file.
- **No Results**: Ensure the required log sources are enabled and ingested.
- **False Positives**: Add exclusions based on the `falsepositives` section of the rule.
- **Syntax Issues**: Validate the Sigma rule with `sigma check your_rule.yml` before conversion.

## Resources

- **Sigma Documentation**: [sigmahq.io/docs](https://sigmahq.io/docs/)
- **Sigma GitHub Repository**: [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- **Community Support**: Join discussions on GitHub or the Sigma Slack channel.
- **Exabeam Blog**: [Automating Sigma Rule Conversion](https://www.exabeam.com/blog/security-operations-center/seamless-security-automating-sigma-rule-conversion-with-generative-ai/)
- **SOC Prime Blog**: [Sigma Rules Guide](https://socprime.com/blog/sigma-rules-the-beginners-guide/)

## Conclusion

Converting Sigma rules to SIEM-specific query languages streamlines threat detection across diverse platforms. By using `sigma-cli` and the appropriate configuration files, you can efficiently translate rules for Splunk, Elastic, Microsoft Sentinel, and QRadar. Regular testing and tuning ensure accurate detections with minimal false positives. Leverage the Sigma community and resources to stay updated on best practices and new backends.
