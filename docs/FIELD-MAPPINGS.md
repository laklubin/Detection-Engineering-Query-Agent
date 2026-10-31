<!-- GENERATED FILE — run `npm run docs` to regenerate. Do not edit by hand. -->

# Supported SIEM field mappings

DetectionForge AI never invents a vendor field name. Every logical field below is resolved through a documented registry entry. Where a platform has no documented mapping for a telemetry family, the adapter emits a `<<MAPPING_REQUIRED:field>>` placeholder, records the gap, and marks that platform output **Mapping Required** — it does not guess a plausible column name.

## Legend

| Symbol | Meaning |
| --- | --- |
| `field` | Documented vendor field used directly in generated queries |
| — | No documented mapping; output is marked Mapping Required |
| ⚠ | A mapping exists but carries a caveat; the caveat is shown in the UI and exports |

## Platforms

| Platform | Query language | Standalone query deployable? |
| --- | --- | --- |
| Splunk Enterprise Security | SPL | Yes |
| Microsoft Sentinel | KQL | Yes |
| IBM QRadar | AQL | No — proprietary rule configuration also required |
| Elastic Security | EQL / ES\|QL | Yes |
| Securonix | Spotter Query Language | No — proprietary rule configuration also required |
| FortiSIEM | Event Search / Rule Expression | No — proprietary rule configuration also required |
| Sigma | Sigma YAML | Yes |

## Telemetry source scopes

The search scope applied per telemetry family.

### `windows_security`

| Platform | Scope |
| --- | --- |
| Splunk Enterprise Security | `index=wineventlog sourcetype=WinEventLog:Security` |
| Microsoft Sentinel | `SecurityEvent` ⚠ If the workspace uses the Azure Monitor Agent security data connector the table may be `SecurityEvent`; Defender XDR deployments use `DeviceEvents`. |
| IBM QRadar | `logsourcetype = 'Microsoft Windows Security Event Log'` ⚠ Confirm the exact log source type string in Admin > Log Sources. |
| Elastic Security | `logs-windows.*,winlogbeat-*` |
| Securonix | `rg_functionality = "Microsoft Windows"` |
| FortiSIEM | `eventType CONTAIN "Win-Security"` |
| Sigma | `{"product":"windows","service":"security"}` |

### `windows_sysmon`

| Platform | Scope |
| --- | --- |
| Splunk Enterprise Security | `index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| Microsoft Sentinel | `Event` ⚠ Sysmon arrives in the generic `Event` table via the legacy MMA custom-log path or in `DeviceProcessEvents` when Defender XDR is deployed. Confirm which table is populated before use. |
| IBM QRadar | `logsourcetype = 'Microsoft Windows Sysmon'` |
| Elastic Security | `logs-windows.sysmon_operational-*` |
| Securonix | `rg_functionality = "Endpoint Management Systems"` |
| FortiSIEM | `eventType CONTAIN "Win-Sysmon"` |
| Sigma | `{"product":"windows","service":"sysmon"}` |

### `windows_powershell`

| Platform | Scope |
| --- | --- |
| Splunk Enterprise Security | `index=powershell sourcetype=XmlWinEventLog:Microsoft-Windows-PowerShell/Operational` |
| Microsoft Sentinel | `Event` ⚠ Script-block events require the PowerShell Operational channel to be collected; parse `EventData` XML to reach ScriptBlockText. |
| IBM QRadar | — ⚠ PowerShell operational events need a dedicated log source and custom properties. |
| Elastic Security | `logs-windows.powershell_operational-*` |
| Securonix | — ⚠ Requires a Windows PowerShell connector with script-block parsing. |
| FortiSIEM | `eventType CONTAIN "Win-PowerShell"` |
| Sigma | `{"product":"windows","service":"powershell","definition":"Script block logging (4104) must be enabled"}` |

### `edr_process`

| Platform | Scope |
| --- | --- |
| Splunk Enterprise Security | `index=edr` ⚠ Index and sourcetype depend on the EDR technology add-on in use. |
| Microsoft Sentinel | `DeviceProcessEvents` |
| IBM QRadar | — ⚠ EDR telemetry normally reaches QRadar through a vendor DSM; confirm QIDs. |
| Elastic Security | `logs-endpoint.events.process-*` |
| Securonix | `rg_functionality = "Endpoint Management Systems"` |
| FortiSIEM | — ⚠ Requires the vendor-specific FortiSIEM integration; event types vary. |
| Sigma | `{"category":"process_creation","product":"windows"}` |

### `linux_auditd`

| Platform | Scope |
| --- | --- |
| Splunk Enterprise Security | `index=linux sourcetype=linux_audit` |
| Microsoft Sentinel | `Syslog` ⚠ auditd via Syslog is unparsed text; a custom table or DCR transform is normally required. |
| IBM QRadar | `logsourcetype = 'Linux OS'` |
| Elastic Security | `logs-auditd.*` |
| Securonix | `rg_functionality = "Unix / Linux"` |
| FortiSIEM | `eventType CONTAIN "Linux"` |
| Sigma | `{"product":"linux","service":"auditd"}` |

### `identity_signin`

| Platform | Scope |
| --- | --- |
| Splunk Enterprise Security | `index=identity` ⚠ Depends on the identity TA (Microsoft Entra ID / Okta) in use. |
| Microsoft Sentinel | `SigninLogs` |
| IBM QRadar | — ⚠ Cloud identity sources require the relevant DSM and often a custom property set. |
| Elastic Security | `logs-azure.signinlogs-*,logs-okta.system-*` |
| Securonix | `rg_functionality = "Identity and Access Management"` |
| FortiSIEM | — ⚠ Cloud identity integrations vary; confirm the event types created by the parser. |
| Sigma | `{"product":"azure","service":"signinlogs"}` ⚠ For Okta use `product: okta, service: oktaxx` per the Sigma taxonomy for that source. |

### `cloud_audit`

| Platform | Scope |
| --- | --- |
| Splunk Enterprise Security | `index=cloud` ⚠ AWS data lands in the index configured by Splunk Add-on for AWS. |
| Microsoft Sentinel | `AuditLogs` ⚠ Entra audit uses `AuditLogs`; Azure resource activity uses `AzureActivity`; AWS uses `AWSCloudTrail`. |
| IBM QRadar | — ⚠ Cloud audit sources require the relevant DSM; confirm QID coverage. |
| Elastic Security | `logs-aws.cloudtrail-*,logs-gcp.audit-*` |
| Securonix | `rg_functionality = "Cloud Infrastructure"` |
| FortiSIEM | — ⚠ Cloud connector dependent. |
| Sigma | `{"product":"aws","service":"cloudtrail"}` ⚠ Change `product`/`service` to match the cloud provider actually in scope. |

### `network_flow`

| Platform | Scope |
| --- | --- |
| Splunk Enterprise Security | `index=network` |
| Microsoft Sentinel | `VMConnection` ⚠ Table depends on the flow source (AzureNetworkAnalytics_CL, AWSVPCFlow, VMConnection). |
| IBM QRadar | `flow data (use the `flows` AQL source)` ⚠ Flow queries must select FROM flows, not events; column names differ. |
| Elastic Security | `logs-network_traffic.flow-*,logs-aws.vpcflow-*` |
| Securonix | `rg_functionality = "Network Devices"` |
| FortiSIEM | `eventType CONTAIN "NetFlow"` |
| Sigma | `{"category":"network_connection","product":"windows"}` ⚠ Sigma network taxonomy is endpoint oriented; flow-only sources may have no clean category. |

### `dns`

| Platform | Scope |
| --- | --- |
| Splunk Enterprise Security | `index=dns sourcetype=stream:dns` |
| Microsoft Sentinel | `DnsEvents` |
| IBM QRadar | — ⚠ DNS analytics typically needs a custom property set on the resolver log source. |
| Elastic Security | `logs-network_traffic.dns-*,logs-*.dns-*` |
| Securonix | `rg_functionality = "DNS"` |
| FortiSIEM | `eventType CONTAIN "DNS"` |
| Sigma | `{"category":"dns_query","product":"windows"}` |

### `web_proxy`

| Platform | Scope |
| --- | --- |
| Splunk Enterprise Security | `index=proxy` |
| Microsoft Sentinel | `CommonSecurityLog` ⚠ CEF-based proxies land in CommonSecurityLog; native connectors may use a custom table. |
| IBM QRadar | `logsourcetype = 'Zscaler NSS'` |
| Elastic Security | `logs-zscaler_zia.*,logs-*.web-*` |
| Securonix | `rg_functionality = "Web Proxy"` |
| FortiSIEM | `eventType CONTAIN "Proxy"` |
| Sigma | `{"category":"proxy"}` |

### `firewall`

| Platform | Scope |
| --- | --- |
| Splunk Enterprise Security | `index=firewall` |
| Microsoft Sentinel | `CommonSecurityLog` ⚠ Palo Alto/Fortinet via CEF land in CommonSecurityLog; AMA-native connectors may differ. |
| IBM QRadar | `logsourcetype IN ('Palo Alto PA Series', 'Fortinet FortiGate Security Gateway')` |
| Elastic Security | `logs-panw.panos-*,logs-fortinet_fortigate.log-*` |
| Securonix | `rg_functionality = "Firewalls"` |
| FortiSIEM | `eventType CONTAIN "FortiGate"` |
| Sigma | `{"category":"firewall"}` |

### `email_security`

| Platform | Scope |
| --- | --- |
| Splunk Enterprise Security | `index=email` |
| Microsoft Sentinel | `EmailEvents` ⚠ `EmailEvents` requires Defender for Office 365; Proofpoint uses a custom table. |
| IBM QRadar | — ⚠ Email security sources need the vendor DSM plus custom properties. |
| Elastic Security | `logs-proofpoint_tap.*,logs-o365.*` |
| Securonix | `rg_functionality = "Email / Messaging"` |
| FortiSIEM | — ⚠ Email security integration dependent. |
| Sigma | `{"category":"email"}` ⚠ No stable Sigma category for third-party email gateways; treat as definition-scoped. |

### `generic`

| Platform | Scope |
| --- | --- |
| Splunk Enterprise Security | — ⚠ No telemetry family selected — index and sourcetype must be supplied by the engineer. |
| Microsoft Sentinel | — ⚠ No telemetry family selected — the target table must be supplied by the engineer. |
| IBM QRadar | — ⚠ No telemetry family selected — the log source type must be supplied by the engineer. |
| Elastic Security | — ⚠ No telemetry family selected — the index pattern must be supplied by the engineer. |
| Securonix | — ⚠ No telemetry family selected — the resource group must be supplied by the engineer. |
| FortiSIEM | — ⚠ No telemetry family selected — the event type scope must be supplied by the engineer. |
| Sigma | — ⚠ No telemetry family selected — the logsource block must be supplied by the engineer. |

## Logical field registry

Mappings are shown per telemetry family because the same logical field resolves to different vendor columns depending on the source table (for example, a process command line in Windows Security auditing versus a Defender XDR device table).

### Telemetry family: `windows_security`

| Logical field | Splunk Enterprise Security | Microsoft Sentinel | IBM QRadar | Elastic Security | Securonix | FortiSIEM | Sigma |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `auth.app` | `app` | `AppDisplayName` | — | `event.provider` | `applicationname` | — | — |
| `auth.mfa_result` | — | `MfaDetail` | — | — | — | — | — |
| `cloud.account_id` | `aws_account_id` | `AADTenantId` | — | `cloud.account.id` | `tenantid` | — | — |
| `cloud.event_name` | `eventName` | `OperationName` | — | `event.action` | `eventname` | — | `eventName` |
| `destination.domain` | `dest_host` | `RemoteUrl` | — | `destination.domain` | `destinationhostname` | `destName` | `DestinationHostname` |
| `destination.ip` | `dest_ip` | `RemoteIP` | `destinationip` | `destination.ip` | `destinationaddress` | `destIpAddr` | `DestinationIp` |
| `destination.port` | `dest_port` | `RemotePort` | `destinationport` | `destination.port` | `destinationport` | `destIpPort` | `DestinationPort` |
| `dns.question.name` | `query` | `Name` ⚠ | — | `dns.question.name` | `destinationhostname` | `dnsQuery` | `QueryName` |
| `email.sender` | `src_user` | `SenderFromAddress` | — | `email.from.address` | `sourceusername` | — | — |
| `email.subject` | `subject` | `Subject` | — | `email.subject` | `transactionstring1` | — | — |
| `event.code` | `EventCode` | `EventID` | — | `winlog.event_id` | — | `eventType` ⚠ | `EventID` |
| `event.outcome` | `action` | — | — | `event.outcome` | `eventoutcome` | — | — |
| `file.hash.sha256` | `file_hash` | `SHA256` | — | `file.hash.sha256` | `filehash` | — | `Hashes` |
| `file.path` | `file_path` | `FolderPath` | — | `file.path` | `filepath` | `fileName` | `TargetFilename` |
| `host.name` | `host` | `Computer` | — | `host.name` | `devicehostname` | `hostName` | `ComputerName` |
| `logon.type` | `Logon_Type` | `LogonType` | — | `winlog.event_data.LogonType` | — | — | `LogonType` |
| `network.bytes_out` | `bytes_out` | — | `sourcebytes` | `source.bytes` | `bytesout` | `sentBytes` | — |
| `network.protocol` | `protocol` | — | `protocolid` ⚠ | `network.protocol` | `transportprotocol` | `ipProto` | `Protocol` |
| `powershell.script_block` | `ScriptBlockText` | `ScriptBlockText` ⚠ | — | `powershell.file.script_block_text` | — | — | `ScriptBlockText` |
| `process.command_line` | `Process_Command_Line` ⚠ | `CommandLine` | — | `process.command_line` | — | `command` ⚠ | `CommandLine` |
| `process.executable` | `process_path` | `NewProcessName` | — | `process.executable` | — | — | `Image` |
| `process.name` | `process_name` | `NewProcessName` ⚠ | — | `process.name` | `destinationprocessname` | `procName` | `Image` |
| `process.parent.command_line` | `parent_process` | — | — | `process.parent.command_line` | — | — | `ParentCommandLine` |
| `process.parent.name` | `parent_process_name` | `ParentProcessName` | — | `process.parent.name` | `sourceprocessname` | — | `ParentImage` |
| `process.pid` | `process_id` | `NewProcessId` | — | `process.pid` | — | — | `ProcessId` |
| `registry.path` | `registry_path` | `RegistryKey` | — | `registry.path` | — | — | `TargetObject` |
| `source.ip` | `src_ip` | `IpAddress` | `sourceip` | `source.ip` | `sourceaddress` | `srcIpAddr` | `SourceIp` |
| `url.full` | `url` | `RequestURL` | — | `url.full` | `requesturl` | `httpUrl` | `url` |
| `user.domain` | `user_domain` | `TargetDomainName` | — | `user.domain` | — | — | `TargetDomainName` |
| `user.name` | `user` | `TargetUserName` | `username` | `user.name` | `accountname` | `user` | `TargetUserName` |
| `user_agent.original` | `http_user_agent` | `UserAgent` | — | `user_agent.original` | `useragent` | — | — |

### Telemetry family: `windows_sysmon`

| Logical field | Splunk Enterprise Security | Microsoft Sentinel | IBM QRadar | Elastic Security | Securonix | FortiSIEM | Sigma |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `auth.app` | `app` | `AppDisplayName` | — | `event.provider` | `applicationname` | — | — |
| `auth.mfa_result` | — | `MfaDetail` | — | — | — | — | — |
| `cloud.account_id` | `aws_account_id` | `AADTenantId` | — | `cloud.account.id` | `tenantid` | — | — |
| `cloud.event_name` | `eventName` | `OperationName` | — | `event.action` | `eventname` | — | `eventName` |
| `destination.domain` | `dest_host` | `RemoteUrl` | — | `destination.domain` | `destinationhostname` | `destName` | `DestinationHostname` |
| `destination.ip` | `dest_ip` | `DestinationIp` | `destinationip` | `destination.ip` | `destinationaddress` | `destIpAddr` | `DestinationIp` |
| `destination.port` | `dest_port` | `DestinationPort` | `destinationport` | `destination.port` | `destinationport` | `destIpPort` | `DestinationPort` |
| `dns.question.name` | `query` | `Name` ⚠ | — | `dns.question.name` | `destinationhostname` | `dnsQuery` | `QueryName` |
| `email.sender` | `src_user` | `SenderFromAddress` | — | `email.from.address` | `sourceusername` | — | — |
| `email.subject` | `subject` | `Subject` | — | `email.subject` | `transactionstring1` | — | — |
| `event.code` | `EventCode` | `EventID` | — | `winlog.event_id` | — | `eventType` ⚠ | `EventID` |
| `event.outcome` | `action` | — | — | `event.outcome` | `eventoutcome` | — | — |
| `file.hash.sha256` | `file_hash` | `SHA256` | — | `file.hash.sha256` | `filehash` | — | `Hashes` |
| `file.path` | `file_path` | `FolderPath` | — | `file.path` | `filepath` | `fileName` | `TargetFilename` |
| `host.name` | `host` | `Computer` | — | `host.name` | `devicehostname` | `hostName` | `ComputerName` |
| `logon.type` | `Logon_Type` | `LogonType` | — | `winlog.event_data.LogonType` | — | — | `LogonType` |
| `network.bytes_out` | `bytes_out` | — | `sourcebytes` | `source.bytes` | `bytesout` | `sentBytes` | — |
| `network.protocol` | `protocol` | — | `protocolid` ⚠ | `network.protocol` | `transportprotocol` | `ipProto` | `Protocol` |
| `powershell.script_block` | `ScriptBlockText` | `ScriptBlockText` ⚠ | — | `powershell.file.script_block_text` | — | — | `ScriptBlockText` |
| `process.command_line` | `CommandLine` ⚠ | `CommandLine` | — | `process.command_line` | — | `command` ⚠ | `CommandLine` |
| `process.executable` | `process_path` | `NewProcessName` | — | `process.executable` | — | — | `Image` |
| `process.name` | `process_name` | `Image` ⚠ | — | `process.name` | `destinationprocessname` | `procName` | `Image` |
| `process.parent.command_line` | `parent_process` | — | — | `process.parent.command_line` | — | — | `ParentCommandLine` |
| `process.parent.name` | `parent_process_name` | `ParentImage` | — | `process.parent.name` | `sourceprocessname` | — | `ParentImage` |
| `process.pid` | `process_id` | `NewProcessId` | — | `process.pid` | — | — | `ProcessId` |
| `registry.path` | `registry_path` | `RegistryKey` | — | `registry.path` | — | — | `TargetObject` |
| `source.ip` | `src_ip` | `IpAddress` | `sourceip` | `source.ip` | `sourceaddress` | `srcIpAddr` | `SourceIp` |
| `url.full` | `url` | `RequestURL` | — | `url.full` | `requesturl` | `httpUrl` | `url` |
| `user.domain` | `user_domain` | `TargetDomainName` | — | `user.domain` | — | — | `TargetDomainName` |
| `user.name` | `user` | `User` | `username` | `user.name` | `accountname` | `user` | `User` |
| `user_agent.original` | `http_user_agent` | `UserAgent` | — | `user_agent.original` | `useragent` | — | — |

### Telemetry family: `windows_powershell`

| Logical field | Splunk Enterprise Security | Microsoft Sentinel | IBM QRadar | Elastic Security | Securonix | FortiSIEM | Sigma |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `auth.app` | `app` | `AppDisplayName` | — | `event.provider` | `applicationname` | — | — |
| `auth.mfa_result` | — | `MfaDetail` | — | — | — | — | — |
| `cloud.account_id` | `aws_account_id` | `AADTenantId` | — | `cloud.account.id` | `tenantid` | — | — |
| `cloud.event_name` | `eventName` | `OperationName` | — | `event.action` | `eventname` | — | `eventName` |
| `destination.domain` | `dest_host` | `RemoteUrl` | — | `destination.domain` | `destinationhostname` | `destName` | `DestinationHostname` |
| `destination.ip` | `dest_ip` | `RemoteIP` | `destinationip` | `destination.ip` | `destinationaddress` | `destIpAddr` | `DestinationIp` |
| `destination.port` | `dest_port` | `RemotePort` | `destinationport` | `destination.port` | `destinationport` | `destIpPort` | `DestinationPort` |
| `dns.question.name` | `query` | `Name` ⚠ | — | `dns.question.name` | `destinationhostname` | `dnsQuery` | `QueryName` |
| `email.sender` | `src_user` | `SenderFromAddress` | — | `email.from.address` | `sourceusername` | — | — |
| `email.subject` | `subject` | `Subject` | — | `email.subject` | `transactionstring1` | — | — |
| `event.code` | `EventCode` | `EventID` | — | `winlog.event_id` | — | `eventType` ⚠ | `EventID` |
| `event.outcome` | `action` | — | — | `event.outcome` | `eventoutcome` | — | — |
| `file.hash.sha256` | `file_hash` | `SHA256` | — | `file.hash.sha256` | `filehash` | — | `Hashes` |
| `file.path` | `file_path` | `FolderPath` | — | `file.path` | `filepath` | `fileName` | `TargetFilename` |
| `host.name` | `host` | `Computer` | — | `host.name` | `devicehostname` | `hostName` | `ComputerName` |
| `logon.type` | `Logon_Type` | `LogonType` | — | `winlog.event_data.LogonType` | — | — | `LogonType` |
| `network.bytes_out` | `bytes_out` | — | `sourcebytes` | `source.bytes` | `bytesout` | `sentBytes` | — |
| `network.protocol` | `protocol` | — | `protocolid` ⚠ | `network.protocol` | `transportprotocol` | `ipProto` | `Protocol` |
| `powershell.script_block` | `ScriptBlockText` | `ScriptBlockText` ⚠ | — | `powershell.file.script_block_text` | — | — | `ScriptBlockText` |
| `process.command_line` | `CommandLine` ⚠ | `CommandLine` | — | `process.command_line` | — | `command` ⚠ | `CommandLine` |
| `process.executable` | `process_path` | `NewProcessName` | — | `process.executable` | — | — | `Image` |
| `process.name` | `process_name` | `NewProcessName` ⚠ | — | `process.name` | `destinationprocessname` | `procName` | `Image` |
| `process.parent.command_line` | `parent_process` | — | — | `process.parent.command_line` | — | — | `ParentCommandLine` |
| `process.parent.name` | `parent_process_name` | `ParentProcessName` | — | `process.parent.name` | `sourceprocessname` | — | `ParentImage` |
| `process.pid` | `process_id` | `NewProcessId` | — | `process.pid` | — | — | `ProcessId` |
| `registry.path` | `registry_path` | `RegistryKey` | — | `registry.path` | — | — | `TargetObject` |
| `source.ip` | `src_ip` | `IpAddress` | `sourceip` | `source.ip` | `sourceaddress` | `srcIpAddr` | `SourceIp` |
| `url.full` | `url` | `RequestURL` | — | `url.full` | `requesturl` | `httpUrl` | `url` |
| `user.domain` | `user_domain` | `TargetDomainName` | — | `user.domain` | — | — | `TargetDomainName` |
| `user.name` | `user` | `TargetUserName` | `username` | `user.name` | `accountname` | `user` | `TargetUserName` |
| `user_agent.original` | `http_user_agent` | `UserAgent` | — | `user_agent.original` | `useragent` | — | — |

### Telemetry family: `edr_process`

| Logical field | Splunk Enterprise Security | Microsoft Sentinel | IBM QRadar | Elastic Security | Securonix | FortiSIEM | Sigma |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `auth.app` | `app` | `AppDisplayName` | — | `event.provider` | `applicationname` | — | — |
| `auth.mfa_result` | — | `MfaDetail` | — | — | — | — | — |
| `cloud.account_id` | `aws_account_id` | `AADTenantId` | — | `cloud.account.id` | `tenantid` | — | — |
| `cloud.event_name` | `eventName` | `OperationName` | — | `event.action` | `eventname` | — | `eventName` |
| `destination.domain` | `dest_host` | `RemoteUrl` | — | `destination.domain` | `destinationhostname` | `destName` | `DestinationHostname` |
| `destination.ip` | `dest_ip` | `RemoteIP` | `destinationip` | `destination.ip` | `destinationaddress` | `destIpAddr` | `DestinationIp` |
| `destination.port` | `dest_port` | `RemotePort` | `destinationport` | `destination.port` | `destinationport` | `destIpPort` | `DestinationPort` |
| `dns.question.name` | `query` | `Name` ⚠ | — | `dns.question.name` | `destinationhostname` | `dnsQuery` | `QueryName` |
| `email.sender` | `src_user` | `SenderFromAddress` | — | `email.from.address` | `sourceusername` | — | — |
| `email.subject` | `subject` | `Subject` | — | `email.subject` | `transactionstring1` | — | — |
| `event.code` | `EventCode` | `ActionType` | — | `event.code` | — | `eventType` ⚠ | `EventType` |
| `event.outcome` | `action` | — | — | `event.outcome` | `eventoutcome` | — | — |
| `file.hash.sha256` | `file_hash` | `SHA256` | — | `file.hash.sha256` | `filehash` | — | `Hashes` |
| `file.path` | `file_path` | `FolderPath` | — | `file.path` | `filepath` | `fileName` | `TargetFilename` |
| `host.name` | `host` | `DeviceName` | — | `host.name` | `devicehostname` | `hostName` | `ComputerName` |
| `logon.type` | `Logon_Type` | `LogonType` | — | `winlog.event_data.LogonType` | — | — | `LogonType` |
| `network.bytes_out` | `bytes_out` | — | `sourcebytes` | `source.bytes` | `bytesout` | `sentBytes` | — |
| `network.protocol` | `protocol` | — | `protocolid` ⚠ | `network.protocol` | `transportprotocol` | `ipProto` | `Protocol` |
| `powershell.script_block` | `ScriptBlockText` | `ScriptBlockText` ⚠ | — | `powershell.file.script_block_text` | — | — | `ScriptBlockText` |
| `process.command_line` | `process` ⚠ | `ProcessCommandLine` | — | `process.command_line` | — | `command` ⚠ | `CommandLine` |
| `process.executable` | `process_path` | `FolderPath` | — | `process.executable` | — | — | `Image` |
| `process.name` | `process_name` | `FileName` ⚠ | — | `process.name` | `destinationprocessname` | `procName` | `Image` |
| `process.parent.command_line` | `parent_process` | `InitiatingProcessCommandLine` ⚠ | — | `process.parent.command_line` | — | — | `ParentCommandLine` |
| `process.parent.name` | `parent_process_name` | `InitiatingProcessFileName` | — | `process.parent.name` | `sourceprocessname` | — | `ParentImage` |
| `process.pid` | `process_id` | `ProcessId` | — | `process.pid` | — | — | `ProcessId` |
| `registry.path` | `registry_path` | `RegistryKey` | — | `registry.path` | — | — | `TargetObject` |
| `source.ip` | `src_ip` | `LocalIP` | `sourceip` | `source.ip` | `sourceaddress` | `srcIpAddr` | `SourceIp` |
| `url.full` | `url` | `RequestURL` | — | `url.full` | `requesturl` | `httpUrl` | `url` |
| `user.domain` | `user_domain` | `TargetDomainName` | — | `user.domain` | — | — | `TargetDomainName` |
| `user.name` | `user` | `AccountName` | `username` | `user.name` | `accountname` | `user` | `User` |
| `user_agent.original` | `http_user_agent` | `UserAgent` | — | `user_agent.original` | `useragent` | — | — |

### Telemetry family: `linux_auditd`

| Logical field | Splunk Enterprise Security | Microsoft Sentinel | IBM QRadar | Elastic Security | Securonix | FortiSIEM | Sigma |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `auth.app` | `app` | `AppDisplayName` | — | `event.provider` | `applicationname` | — | — |
| `auth.mfa_result` | — | `MfaDetail` | — | — | — | — | — |
| `cloud.account_id` | `aws_account_id` | `AADTenantId` | — | `cloud.account.id` | `tenantid` | — | — |
| `cloud.event_name` | `eventName` | `OperationName` | — | `event.action` | `eventname` | — | `eventName` |
| `destination.domain` | `dest_host` | `RemoteUrl` | — | `destination.domain` | `destinationhostname` | `destName` | `DestinationHostname` |
| `destination.ip` | `dest_ip` | `RemoteIP` | `destinationip` | `destination.ip` | `destinationaddress` | `destIpAddr` | `DestinationIp` |
| `destination.port` | `dest_port` | `RemotePort` | `destinationport` | `destination.port` | `destinationport` | `destIpPort` | `DestinationPort` |
| `dns.question.name` | `query` | `Name` ⚠ | — | `dns.question.name` | `destinationhostname` | `dnsQuery` | `QueryName` |
| `email.sender` | `src_user` | `SenderFromAddress` | — | `email.from.address` | `sourceusername` | — | — |
| `email.subject` | `subject` | `Subject` | — | `email.subject` | `transactionstring1` | — | — |
| `event.code` | `EventCode` | `EventID` | — | `event.code` | — | `eventType` ⚠ | `EventID` |
| `event.outcome` | `action` | — | — | `event.outcome` | `eventoutcome` | — | — |
| `file.hash.sha256` | `file_hash` | `SHA256` | — | `file.hash.sha256` | `filehash` | — | `Hashes` |
| `file.path` | `file_path` | `FolderPath` | — | `file.path` | `filepath` | `fileName` | `TargetFilename` |
| `host.name` | `host` | `Computer` | — | `host.name` | `devicehostname` | `hostName` | `ComputerName` |
| `logon.type` | `Logon_Type` | `LogonType` | — | `winlog.event_data.LogonType` | — | — | `LogonType` |
| `network.bytes_out` | `bytes_out` | — | `sourcebytes` | `source.bytes` | `bytesout` | `sentBytes` | — |
| `network.protocol` | `protocol` | — | `protocolid` ⚠ | `network.protocol` | `transportprotocol` | `ipProto` | `Protocol` |
| `powershell.script_block` | `ScriptBlockText` | `ScriptBlockText` ⚠ | — | `powershell.file.script_block_text` | — | — | `ScriptBlockText` |
| `process.command_line` | `CommandLine` ⚠ | `CommandLine` | — | `process.command_line` | — | `command` ⚠ | `CommandLine` |
| `process.executable` | `process_path` | `NewProcessName` | — | `process.executable` | — | — | `Image` |
| `process.name` | `process_name` | `NewProcessName` ⚠ | — | `process.name` | `destinationprocessname` | `procName` | `Image` |
| `process.parent.command_line` | `parent_process` | — | — | `process.parent.command_line` | — | — | `ParentCommandLine` |
| `process.parent.name` | `parent_process_name` | `ParentProcessName` | — | `process.parent.name` | `sourceprocessname` | — | `ParentImage` |
| `process.pid` | `process_id` | `NewProcessId` | — | `process.pid` | — | — | `ProcessId` |
| `registry.path` | `registry_path` | `RegistryKey` | — | `registry.path` | — | — | `TargetObject` |
| `source.ip` | `src_ip` | `IpAddress` | `sourceip` | `source.ip` | `sourceaddress` | `srcIpAddr` | `SourceIp` |
| `url.full` | `url` | `RequestURL` | — | `url.full` | `requesturl` | `httpUrl` | `url` |
| `user.domain` | `user_domain` | `TargetDomainName` | — | `user.domain` | — | — | `TargetDomainName` |
| `user.name` | `user` | `TargetUserName` | `username` | `user.name` | `accountname` | `user` | `auid` |
| `user_agent.original` | `http_user_agent` | `UserAgent` | — | `user_agent.original` | `useragent` | — | — |

### Telemetry family: `identity_signin`

| Logical field | Splunk Enterprise Security | Microsoft Sentinel | IBM QRadar | Elastic Security | Securonix | FortiSIEM | Sigma |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `auth.app` | `app` | `AppDisplayName` | — | `event.provider` | `applicationname` | — | — |
| `auth.mfa_result` | — | `MfaDetail` | — | — | — | — | — |
| `cloud.account_id` | `aws_account_id` | `AADTenantId` | — | `cloud.account.id` | `tenantid` | — | — |
| `cloud.event_name` | `eventName` | `OperationName` | — | `event.action` | `eventname` | — | `eventName` |
| `destination.domain` | `dest_host` | `RemoteUrl` | — | `destination.domain` | `destinationhostname` | `destName` | `DestinationHostname` |
| `destination.ip` | `dest_ip` | `RemoteIP` | `destinationip` | `destination.ip` | `destinationaddress` | `destIpAddr` | `DestinationIp` |
| `destination.port` | `dest_port` | `RemotePort` | `destinationport` | `destination.port` | `destinationport` | `destIpPort` | `DestinationPort` |
| `dns.question.name` | `query` | `Name` ⚠ | — | `dns.question.name` | `destinationhostname` | `dnsQuery` | `QueryName` |
| `email.sender` | `src_user` | `SenderFromAddress` | — | `email.from.address` | `sourceusername` | — | — |
| `email.subject` | `subject` | `Subject` | — | `email.subject` | `transactionstring1` | — | — |
| `event.code` | `EventCode` | `EventID` | — | `event.code` | — | `eventType` ⚠ | `EventID` |
| `event.outcome` | `action` | `ResultType` ⚠ | — | `event.outcome` | `eventoutcome` | — | — |
| `file.hash.sha256` | `file_hash` | `SHA256` | — | `file.hash.sha256` | `filehash` | — | `Hashes` |
| `file.path` | `file_path` | `FolderPath` | — | `file.path` | `filepath` | `fileName` | `TargetFilename` |
| `host.name` | `host` | `DeviceDetail` | — | `host.name` | `devicehostname` | `hostName` | `ComputerName` |
| `logon.type` | `Logon_Type` | `LogonType` | — | `winlog.event_data.LogonType` | — | — | `LogonType` |
| `network.bytes_out` | `bytes_out` | — | `sourcebytes` | `source.bytes` | `bytesout` | `sentBytes` | — |
| `network.protocol` | `protocol` | — | `protocolid` ⚠ | `network.protocol` | `transportprotocol` | `ipProto` | `Protocol` |
| `powershell.script_block` | `ScriptBlockText` | `ScriptBlockText` ⚠ | — | `powershell.file.script_block_text` | — | — | `ScriptBlockText` |
| `process.command_line` | `CommandLine` ⚠ | `CommandLine` | — | `process.command_line` | — | `command` ⚠ | `CommandLine` |
| `process.executable` | `process_path` | `NewProcessName` | — | `process.executable` | — | — | `Image` |
| `process.name` | `process_name` | `NewProcessName` ⚠ | — | `process.name` | `destinationprocessname` | `procName` | `Image` |
| `process.parent.command_line` | `parent_process` | — | — | `process.parent.command_line` | — | — | `ParentCommandLine` |
| `process.parent.name` | `parent_process_name` | `ParentProcessName` | — | `process.parent.name` | `sourceprocessname` | — | `ParentImage` |
| `process.pid` | `process_id` | `NewProcessId` | — | `process.pid` | — | — | `ProcessId` |
| `registry.path` | `registry_path` | `RegistryKey` | — | `registry.path` | — | — | `TargetObject` |
| `source.ip` | `src_ip` | `IPAddress` | `sourceip` | `source.ip` | `sourceaddress` | `srcIpAddr` | `IpAddress` |
| `url.full` | `url` | `RequestURL` | — | `url.full` | `requesturl` | `httpUrl` | `url` |
| `user.domain` | `user_domain` | `TargetDomainName` | — | `user.domain` | — | — | `TargetDomainName` |
| `user.name` | `user` | `UserPrincipalName` | `username` | `user.name` | `accountname` | `user` | `UserPrincipalName` |
| `user_agent.original` | `http_user_agent` | `UserAgent` | — | `user_agent.original` | `useragent` | — | — |

### Telemetry family: `cloud_audit`

| Logical field | Splunk Enterprise Security | Microsoft Sentinel | IBM QRadar | Elastic Security | Securonix | FortiSIEM | Sigma |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `auth.app` | `app` | `AppDisplayName` | — | `event.provider` | `applicationname` | — | — |
| `auth.mfa_result` | — | `MfaDetail` | — | — | — | — | — |
| `cloud.account_id` | `aws_account_id` | `AADTenantId` | — | `cloud.account.id` | `tenantid` | — | — |
| `cloud.event_name` | `eventName` | `OperationName` | — | `event.action` | `eventname` | — | `eventName` |
| `destination.domain` | `dest_host` | `RemoteUrl` | — | `destination.domain` | `destinationhostname` | `destName` | `DestinationHostname` |
| `destination.ip` | `dest_ip` | `RemoteIP` | `destinationip` | `destination.ip` | `destinationaddress` | `destIpAddr` | `DestinationIp` |
| `destination.port` | `dest_port` | `RemotePort` | `destinationport` | `destination.port` | `destinationport` | `destIpPort` | `DestinationPort` |
| `dns.question.name` | `query` | `Name` ⚠ | — | `dns.question.name` | `destinationhostname` | `dnsQuery` | `QueryName` |
| `email.sender` | `src_user` | `SenderFromAddress` | — | `email.from.address` | `sourceusername` | — | — |
| `email.subject` | `subject` | `Subject` | — | `email.subject` | `transactionstring1` | — | — |
| `event.code` | `EventCode` | `EventID` | — | `event.code` | — | `eventType` ⚠ | `EventID` |
| `event.outcome` | `action` | `Result` ⚠ | — | `event.outcome` | `eventoutcome` | — | — |
| `file.hash.sha256` | `file_hash` | `SHA256` | — | `file.hash.sha256` | `filehash` | — | `Hashes` |
| `file.path` | `file_path` | `FolderPath` | — | `file.path` | `filepath` | `fileName` | `TargetFilename` |
| `host.name` | `host` | `Computer` | — | `host.name` | `devicehostname` | `hostName` | `ComputerName` |
| `logon.type` | `Logon_Type` | `LogonType` | — | `winlog.event_data.LogonType` | — | — | `LogonType` |
| `network.bytes_out` | `bytes_out` | — | `sourcebytes` | `source.bytes` | `bytesout` | `sentBytes` | — |
| `network.protocol` | `protocol` | — | `protocolid` ⚠ | `network.protocol` | `transportprotocol` | `ipProto` | `Protocol` |
| `powershell.script_block` | `ScriptBlockText` | `ScriptBlockText` ⚠ | — | `powershell.file.script_block_text` | — | — | `ScriptBlockText` |
| `process.command_line` | `CommandLine` ⚠ | `CommandLine` | — | `process.command_line` | — | `command` ⚠ | `CommandLine` |
| `process.executable` | `process_path` | `NewProcessName` | — | `process.executable` | — | — | `Image` |
| `process.name` | `process_name` | `NewProcessName` ⚠ | — | `process.name` | `destinationprocessname` | `procName` | `Image` |
| `process.parent.command_line` | `parent_process` | — | — | `process.parent.command_line` | — | — | `ParentCommandLine` |
| `process.parent.name` | `parent_process_name` | `ParentProcessName` | — | `process.parent.name` | `sourceprocessname` | — | `ParentImage` |
| `process.pid` | `process_id` | `NewProcessId` | — | `process.pid` | — | — | `ProcessId` |
| `registry.path` | `registry_path` | `RegistryKey` | — | `registry.path` | — | — | `TargetObject` |
| `source.ip` | `src_ip` | `CallerIpAddress` | `sourceip` | `source.ip` | `sourceaddress` | `srcIpAddr` | `SourceIp` |
| `url.full` | `url` | `RequestURL` | — | `url.full` | `requesturl` | `httpUrl` | `url` |
| `user.domain` | `user_domain` | `TargetDomainName` | — | `user.domain` | — | — | `TargetDomainName` |
| `user.name` | `user` | `InitiatedBy` | `username` | `user.name` | `accountname` | `user` | `TargetUserName` |
| `user_agent.original` | `http_user_agent` | `UserAgent` | — | `user_agent.original` | `useragent` | — | — |

### Telemetry family: `network_flow`

| Logical field | Splunk Enterprise Security | Microsoft Sentinel | IBM QRadar | Elastic Security | Securonix | FortiSIEM | Sigma |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `auth.app` | `app` | `AppDisplayName` | — | `event.provider` | `applicationname` | — | — |
| `auth.mfa_result` | — | `MfaDetail` | — | — | — | — | — |
| `cloud.account_id` | `aws_account_id` | `AADTenantId` | — | `cloud.account.id` | `tenantid` | — | — |
| `cloud.event_name` | `eventName` | `OperationName` | — | `event.action` | `eventname` | — | `eventName` |
| `destination.domain` | `dest_host` | `RemoteUrl` | — | `destination.domain` | `destinationhostname` | `destName` | `DestinationHostname` |
| `destination.ip` | `dest_ip` | `RemoteIP` | `destinationip` | `destination.ip` | `destinationaddress` | `destIpAddr` | `DestinationIp` |
| `destination.port` | `dest_port` | `RemotePort` | `destinationport` | `destination.port` | `destinationport` | `destIpPort` | `DestinationPort` |
| `dns.question.name` | `query` | `Name` ⚠ | — | `dns.question.name` | `destinationhostname` | `dnsQuery` | `QueryName` |
| `email.sender` | `src_user` | `SenderFromAddress` | — | `email.from.address` | `sourceusername` | — | — |
| `email.subject` | `subject` | `Subject` | — | `email.subject` | `transactionstring1` | — | — |
| `event.code` | `EventCode` | `EventID` | — | `event.code` | — | `eventType` ⚠ | `EventID` |
| `event.outcome` | `action` | — | — | `event.outcome` | `eventoutcome` | — | — |
| `file.hash.sha256` | `file_hash` | `SHA256` | — | `file.hash.sha256` | `filehash` | — | `Hashes` |
| `file.path` | `file_path` | `FolderPath` | — | `file.path` | `filepath` | `fileName` | `TargetFilename` |
| `host.name` | `host` | `Computer` | — | `host.name` | `devicehostname` | `hostName` | `ComputerName` |
| `logon.type` | `Logon_Type` | `LogonType` | — | `winlog.event_data.LogonType` | — | — | `LogonType` |
| `network.bytes_out` | `bytes_out` | `OutboundBytes` ⚠ | `sourcebytes` | `source.bytes` | `bytesout` | `sentBytes` | — |
| `network.protocol` | `protocol` | — | `protocolid` ⚠ | `network.protocol` | `transportprotocol` | `ipProto` | `Protocol` |
| `powershell.script_block` | `ScriptBlockText` | `ScriptBlockText` ⚠ | — | `powershell.file.script_block_text` | — | — | `ScriptBlockText` |
| `process.command_line` | `CommandLine` ⚠ | `CommandLine` | — | `process.command_line` | — | `command` ⚠ | `CommandLine` |
| `process.executable` | `process_path` | `NewProcessName` | — | `process.executable` | — | — | `Image` |
| `process.name` | `process_name` | `NewProcessName` ⚠ | — | `process.name` | `destinationprocessname` | `procName` | `Image` |
| `process.parent.command_line` | `parent_process` | — | — | `process.parent.command_line` | — | — | `ParentCommandLine` |
| `process.parent.name` | `parent_process_name` | `ParentProcessName` | — | `process.parent.name` | `sourceprocessname` | — | `ParentImage` |
| `process.pid` | `process_id` | `NewProcessId` | — | `process.pid` | — | — | `ProcessId` |
| `registry.path` | `registry_path` | `RegistryKey` | — | `registry.path` | — | — | `TargetObject` |
| `source.ip` | `src_ip` | `IpAddress` | `sourceip` | `source.ip` | `sourceaddress` | `srcIpAddr` | `SourceIp` |
| `url.full` | `url` | `RequestURL` | — | `url.full` | `requesturl` | `httpUrl` | `url` |
| `user.domain` | `user_domain` | `TargetDomainName` | — | `user.domain` | — | — | `TargetDomainName` |
| `user.name` | `user` | `TargetUserName` | `username` | `user.name` | `accountname` | `user` | `TargetUserName` |
| `user_agent.original` | `http_user_agent` | `UserAgent` | — | `user_agent.original` | `useragent` | — | — |

### Telemetry family: `dns`

| Logical field | Splunk Enterprise Security | Microsoft Sentinel | IBM QRadar | Elastic Security | Securonix | FortiSIEM | Sigma |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `auth.app` | `app` | `AppDisplayName` | — | `event.provider` | `applicationname` | — | — |
| `auth.mfa_result` | — | `MfaDetail` | — | — | — | — | — |
| `cloud.account_id` | `aws_account_id` | `AADTenantId` | — | `cloud.account.id` | `tenantid` | — | — |
| `cloud.event_name` | `eventName` | `OperationName` | — | `event.action` | `eventname` | — | `eventName` |
| `destination.domain` | `dest_host` | `RemoteUrl` | — | `destination.domain` | `destinationhostname` | `destName` | `DestinationHostname` |
| `destination.ip` | `dest_ip` | `RemoteIP` | `destinationip` | `destination.ip` | `destinationaddress` | `destIpAddr` | `DestinationIp` |
| `destination.port` | `dest_port` | `RemotePort` | `destinationport` | `destination.port` | `destinationport` | `destIpPort` | `DestinationPort` |
| `dns.question.name` | `query` | `Name` ⚠ | — | `dns.question.name` | `destinationhostname` | `dnsQuery` | `QueryName` |
| `email.sender` | `src_user` | `SenderFromAddress` | — | `email.from.address` | `sourceusername` | — | — |
| `email.subject` | `subject` | `Subject` | — | `email.subject` | `transactionstring1` | — | — |
| `event.code` | `EventCode` | `EventID` | — | `event.code` | — | `eventType` ⚠ | `EventID` |
| `event.outcome` | `action` | — | — | `event.outcome` | `eventoutcome` | — | — |
| `file.hash.sha256` | `file_hash` | `SHA256` | — | `file.hash.sha256` | `filehash` | — | `Hashes` |
| `file.path` | `file_path` | `FolderPath` | — | `file.path` | `filepath` | `fileName` | `TargetFilename` |
| `host.name` | `host` | `Computer` | — | `host.name` | `devicehostname` | `hostName` | `ComputerName` |
| `logon.type` | `Logon_Type` | `LogonType` | — | `winlog.event_data.LogonType` | — | — | `LogonType` |
| `network.bytes_out` | `bytes_out` | — | `sourcebytes` | `source.bytes` | `bytesout` | `sentBytes` | — |
| `network.protocol` | `protocol` | — | `protocolid` ⚠ | `network.protocol` | `transportprotocol` | `ipProto` | `Protocol` |
| `powershell.script_block` | `ScriptBlockText` | `ScriptBlockText` ⚠ | — | `powershell.file.script_block_text` | — | — | `ScriptBlockText` |
| `process.command_line` | `CommandLine` ⚠ | `CommandLine` | — | `process.command_line` | — | `command` ⚠ | `CommandLine` |
| `process.executable` | `process_path` | `NewProcessName` | — | `process.executable` | — | — | `Image` |
| `process.name` | `process_name` | `NewProcessName` ⚠ | — | `process.name` | `destinationprocessname` | `procName` | `Image` |
| `process.parent.command_line` | `parent_process` | — | — | `process.parent.command_line` | — | — | `ParentCommandLine` |
| `process.parent.name` | `parent_process_name` | `ParentProcessName` | — | `process.parent.name` | `sourceprocessname` | — | `ParentImage` |
| `process.pid` | `process_id` | `NewProcessId` | — | `process.pid` | — | — | `ProcessId` |
| `registry.path` | `registry_path` | `RegistryKey` | — | `registry.path` | — | — | `TargetObject` |
| `source.ip` | `src_ip` | `IpAddress` | `sourceip` | `source.ip` | `sourceaddress` | `srcIpAddr` | `SourceIp` |
| `url.full` | `url` | `RequestURL` | — | `url.full` | `requesturl` | `httpUrl` | `url` |
| `user.domain` | `user_domain` | `TargetDomainName` | — | `user.domain` | — | — | `TargetDomainName` |
| `user.name` | `user` | `TargetUserName` | `username` | `user.name` | `accountname` | `user` | `TargetUserName` |
| `user_agent.original` | `http_user_agent` | `UserAgent` | — | `user_agent.original` | `useragent` | — | — |

### Telemetry family: `web_proxy`

| Logical field | Splunk Enterprise Security | Microsoft Sentinel | IBM QRadar | Elastic Security | Securonix | FortiSIEM | Sigma |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `auth.app` | `app` | `AppDisplayName` | — | `event.provider` | `applicationname` | — | — |
| `auth.mfa_result` | — | `MfaDetail` | — | — | — | — | — |
| `cloud.account_id` | `aws_account_id` | `AADTenantId` | — | `cloud.account.id` | `tenantid` | — | — |
| `cloud.event_name` | `eventName` | `OperationName` | — | `event.action` | `eventname` | — | `eventName` |
| `destination.domain` | `dest_host` | `RemoteUrl` | — | `destination.domain` | `destinationhostname` | `destName` | `DestinationHostname` |
| `destination.ip` | `dest_ip` | `RemoteIP` | `destinationip` | `destination.ip` | `destinationaddress` | `destIpAddr` | `DestinationIp` |
| `destination.port` | `dest_port` | `RemotePort` | `destinationport` | `destination.port` | `destinationport` | `destIpPort` | `DestinationPort` |
| `dns.question.name` | `query` | `Name` ⚠ | — | `dns.question.name` | `destinationhostname` | `dnsQuery` | `QueryName` |
| `email.sender` | `src_user` | `SenderFromAddress` | — | `email.from.address` | `sourceusername` | — | — |
| `email.subject` | `subject` | `Subject` | — | `email.subject` | `transactionstring1` | — | — |
| `event.code` | `EventCode` | `EventID` | — | `event.code` | — | `eventType` ⚠ | `EventID` |
| `event.outcome` | `action` | — | — | `event.outcome` | `eventoutcome` | — | — |
| `file.hash.sha256` | `file_hash` | `SHA256` | — | `file.hash.sha256` | `filehash` | — | `Hashes` |
| `file.path` | `file_path` | `FolderPath` | — | `file.path` | `filepath` | `fileName` | `TargetFilename` |
| `host.name` | `host` | `Computer` | — | `host.name` | `devicehostname` | `hostName` | `ComputerName` |
| `logon.type` | `Logon_Type` | `LogonType` | — | `winlog.event_data.LogonType` | — | — | `LogonType` |
| `network.bytes_out` | `bytes_out` | — | `sourcebytes` | `source.bytes` | `bytesout` | `sentBytes` | — |
| `network.protocol` | `protocol` | — | `protocolid` ⚠ | `network.protocol` | `transportprotocol` | `ipProto` | `Protocol` |
| `powershell.script_block` | `ScriptBlockText` | `ScriptBlockText` ⚠ | — | `powershell.file.script_block_text` | — | — | `ScriptBlockText` |
| `process.command_line` | `CommandLine` ⚠ | `CommandLine` | — | `process.command_line` | — | `command` ⚠ | `CommandLine` |
| `process.executable` | `process_path` | `NewProcessName` | — | `process.executable` | — | — | `Image` |
| `process.name` | `process_name` | `NewProcessName` ⚠ | — | `process.name` | `destinationprocessname` | `procName` | `Image` |
| `process.parent.command_line` | `parent_process` | — | — | `process.parent.command_line` | — | — | `ParentCommandLine` |
| `process.parent.name` | `parent_process_name` | `ParentProcessName` | — | `process.parent.name` | `sourceprocessname` | — | `ParentImage` |
| `process.pid` | `process_id` | `NewProcessId` | — | `process.pid` | — | — | `ProcessId` |
| `registry.path` | `registry_path` | `RegistryKey` | — | `registry.path` | — | — | `TargetObject` |
| `source.ip` | `src_ip` | `IpAddress` | `sourceip` | `source.ip` | `sourceaddress` | `srcIpAddr` | `SourceIp` |
| `url.full` | `url` | `RequestURL` | — | `url.full` | `requesturl` | `httpUrl` | `url` |
| `user.domain` | `user_domain` | `TargetDomainName` | — | `user.domain` | — | — | `TargetDomainName` |
| `user.name` | `user` | `TargetUserName` | `username` | `user.name` | `accountname` | `user` | `TargetUserName` |
| `user_agent.original` | `http_user_agent` | `UserAgent` | — | `user_agent.original` | `useragent` | — | — |

### Telemetry family: `firewall`

| Logical field | Splunk Enterprise Security | Microsoft Sentinel | IBM QRadar | Elastic Security | Securonix | FortiSIEM | Sigma |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `auth.app` | `app` | `AppDisplayName` | — | `event.provider` | `applicationname` | — | — |
| `auth.mfa_result` | — | `MfaDetail` | — | — | — | — | — |
| `cloud.account_id` | `aws_account_id` | `AADTenantId` | — | `cloud.account.id` | `tenantid` | — | — |
| `cloud.event_name` | `eventName` | `OperationName` | — | `event.action` | `eventname` | — | `eventName` |
| `destination.domain` | `dest_host` | `RemoteUrl` | — | `destination.domain` | `destinationhostname` | `destName` | `DestinationHostname` |
| `destination.ip` | `dest_ip` | `RemoteIP` | `destinationip` | `destination.ip` | `destinationaddress` | `destIpAddr` | `DestinationIp` |
| `destination.port` | `dest_port` | `RemotePort` | `destinationport` | `destination.port` | `destinationport` | `destIpPort` | `DestinationPort` |
| `dns.question.name` | `query` | `Name` ⚠ | — | `dns.question.name` | `destinationhostname` | `dnsQuery` | `QueryName` |
| `email.sender` | `src_user` | `SenderFromAddress` | — | `email.from.address` | `sourceusername` | — | — |
| `email.subject` | `subject` | `Subject` | — | `email.subject` | `transactionstring1` | — | — |
| `event.code` | `EventCode` | `EventID` | — | `event.code` | — | `eventType` ⚠ | `EventID` |
| `event.outcome` | `action` | — | — | `event.outcome` | `eventoutcome` | — | — |
| `file.hash.sha256` | `file_hash` | `SHA256` | — | `file.hash.sha256` | `filehash` | — | `Hashes` |
| `file.path` | `file_path` | `FolderPath` | — | `file.path` | `filepath` | `fileName` | `TargetFilename` |
| `host.name` | `host` | `Computer` | — | `host.name` | `devicehostname` | `hostName` | `ComputerName` |
| `logon.type` | `Logon_Type` | `LogonType` | — | `winlog.event_data.LogonType` | — | — | `LogonType` |
| `network.bytes_out` | `bytes_out` | `SentBytes` ⚠ | `sourcebytes` | `source.bytes` | `bytesout` | `sentBytes` | — |
| `network.protocol` | `protocol` | — | `protocolid` ⚠ | `network.protocol` | `transportprotocol` | `ipProto` | `Protocol` |
| `powershell.script_block` | `ScriptBlockText` | `ScriptBlockText` ⚠ | — | `powershell.file.script_block_text` | — | — | `ScriptBlockText` |
| `process.command_line` | `CommandLine` ⚠ | `CommandLine` | — | `process.command_line` | — | `command` ⚠ | `CommandLine` |
| `process.executable` | `process_path` | `NewProcessName` | — | `process.executable` | — | — | `Image` |
| `process.name` | `process_name` | `NewProcessName` ⚠ | — | `process.name` | `destinationprocessname` | `procName` | `Image` |
| `process.parent.command_line` | `parent_process` | — | — | `process.parent.command_line` | — | — | `ParentCommandLine` |
| `process.parent.name` | `parent_process_name` | `ParentProcessName` | — | `process.parent.name` | `sourceprocessname` | — | `ParentImage` |
| `process.pid` | `process_id` | `NewProcessId` | — | `process.pid` | — | — | `ProcessId` |
| `registry.path` | `registry_path` | `RegistryKey` | — | `registry.path` | — | — | `TargetObject` |
| `source.ip` | `src_ip` | `IpAddress` | `sourceip` | `source.ip` | `sourceaddress` | `srcIpAddr` | `SourceIp` |
| `url.full` | `url` | `RequestURL` | — | `url.full` | `requesturl` | `httpUrl` | `url` |
| `user.domain` | `user_domain` | `TargetDomainName` | — | `user.domain` | — | — | `TargetDomainName` |
| `user.name` | `user` | `TargetUserName` | `username` | `user.name` | `accountname` | `user` | `TargetUserName` |
| `user_agent.original` | `http_user_agent` | `UserAgent` | — | `user_agent.original` | `useragent` | — | — |

### Telemetry family: `email_security`

| Logical field | Splunk Enterprise Security | Microsoft Sentinel | IBM QRadar | Elastic Security | Securonix | FortiSIEM | Sigma |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `auth.app` | `app` | `AppDisplayName` | — | `event.provider` | `applicationname` | — | — |
| `auth.mfa_result` | — | `MfaDetail` | — | — | — | — | — |
| `cloud.account_id` | `aws_account_id` | `AADTenantId` | — | `cloud.account.id` | `tenantid` | — | — |
| `cloud.event_name` | `eventName` | `OperationName` | — | `event.action` | `eventname` | — | `eventName` |
| `destination.domain` | `dest_host` | `RemoteUrl` | — | `destination.domain` | `destinationhostname` | `destName` | `DestinationHostname` |
| `destination.ip` | `dest_ip` | `RemoteIP` | `destinationip` | `destination.ip` | `destinationaddress` | `destIpAddr` | `DestinationIp` |
| `destination.port` | `dest_port` | `RemotePort` | `destinationport` | `destination.port` | `destinationport` | `destIpPort` | `DestinationPort` |
| `dns.question.name` | `query` | `Name` ⚠ | — | `dns.question.name` | `destinationhostname` | `dnsQuery` | `QueryName` |
| `email.sender` | `src_user` | `SenderFromAddress` | — | `email.from.address` | `sourceusername` | — | — |
| `email.subject` | `subject` | `Subject` | — | `email.subject` | `transactionstring1` | — | — |
| `event.code` | `EventCode` | `EventID` | — | `event.code` | — | `eventType` ⚠ | `EventID` |
| `event.outcome` | `action` | — | — | `event.outcome` | `eventoutcome` | — | — |
| `file.hash.sha256` | `file_hash` | `SHA256` | — | `file.hash.sha256` | `filehash` | — | `Hashes` |
| `file.path` | `file_path` | `FolderPath` | — | `file.path` | `filepath` | `fileName` | `TargetFilename` |
| `host.name` | `host` | `Computer` | — | `host.name` | `devicehostname` | `hostName` | `ComputerName` |
| `logon.type` | `Logon_Type` | `LogonType` | — | `winlog.event_data.LogonType` | — | — | `LogonType` |
| `network.bytes_out` | `bytes_out` | — | `sourcebytes` | `source.bytes` | `bytesout` | `sentBytes` | — |
| `network.protocol` | `protocol` | — | `protocolid` ⚠ | `network.protocol` | `transportprotocol` | `ipProto` | `Protocol` |
| `powershell.script_block` | `ScriptBlockText` | `ScriptBlockText` ⚠ | — | `powershell.file.script_block_text` | — | — | `ScriptBlockText` |
| `process.command_line` | `CommandLine` ⚠ | `CommandLine` | — | `process.command_line` | — | `command` ⚠ | `CommandLine` |
| `process.executable` | `process_path` | `NewProcessName` | — | `process.executable` | — | — | `Image` |
| `process.name` | `process_name` | `NewProcessName` ⚠ | — | `process.name` | `destinationprocessname` | `procName` | `Image` |
| `process.parent.command_line` | `parent_process` | — | — | `process.parent.command_line` | — | — | `ParentCommandLine` |
| `process.parent.name` | `parent_process_name` | `ParentProcessName` | — | `process.parent.name` | `sourceprocessname` | — | `ParentImage` |
| `process.pid` | `process_id` | `NewProcessId` | — | `process.pid` | — | — | `ProcessId` |
| `registry.path` | `registry_path` | `RegistryKey` | — | `registry.path` | — | — | `TargetObject` |
| `source.ip` | `src_ip` | `IpAddress` | `sourceip` | `source.ip` | `sourceaddress` | `srcIpAddr` | `SourceIp` |
| `url.full` | `url` | `RequestURL` | — | `url.full` | `requesturl` | `httpUrl` | `url` |
| `user.domain` | `user_domain` | `TargetDomainName` | — | `user.domain` | — | — | `TargetDomainName` |
| `user.name` | `user` | `TargetUserName` | `username` | `user.name` | `accountname` | `user` | `TargetUserName` |
| `user_agent.original` | `http_user_agent` | `UserAgent` | — | `user_agent.original` | `useragent` | — | — |

## Field definitions

| Logical field | Meaning |
| --- | --- |
| `auth.app` | Application or client used to authenticate. |
| `auth.mfa_result` | Multi-factor authentication outcome or requirement. |
| `cloud.account_id` | Account, subscription or project identifier. |
| `cloud.event_name` | Provider API operation name (e.g. AssumeRole, Add member to role). |
| `destination.domain` | Resolved hostname of the destination. |
| `destination.ip` | Target network address. |
| `destination.port` | Target transport port. |
| `dns.question.name` | Queried domain name. |
| `email.sender` | Envelope or header sender address. |
| `email.subject` | Message subject line. |
| `event.code` | Numeric or string event identifier emitted by the log source. |
| `event.outcome` | success / failure outcome of the audited action. |
| `file.hash.sha256` | SHA256 hash of the file or process image. |
| `file.path` | Full path of the file touched by the event. |
| `host.name` | Hostname of the asset generating the event. |
| `logon.type` | Windows logon type (2 interactive, 3 network, 10 RemoteInteractive...). |
| `network.bytes_out` | Outbound byte volume for the flow or session. |
| `network.protocol` | Application or transport protocol. |
| `powershell.script_block` | Deobfuscated script block content (Event ID 4104). |
| `process.command_line` | Full command line, including arguments. |
| `process.executable` | Full path to the process executable. |
| `process.name` | Image file name of the executing process. |
| `process.parent.command_line` | Command line of the parent process. |
| `process.parent.name` | Image name of the parent process. |
| `process.pid` | Operating-system process identifier. |
| `registry.path` | Windows registry key or value path. |
| `source.ip` | Originating network address. |
| `url.full` | Full requested URL. |
| `user.domain` | Domain or tenant of the principal. |
| `user.name` | Security principal associated with the event. |
| `user_agent.original` | Raw HTTP user-agent string. |

## Allowlisted log sources

| Log source id | Name | Vendor | Telemetry family |
| --- | --- | --- | --- |
| `windows_security_events` | Windows Security Events | microsoft | `windows_security` |
| `windows_sysmon` | Windows Sysmon | microsoft | `windows_sysmon` |
| `windows_powershell_operational` | Windows PowerShell Operational / Script Block | microsoft | `windows_powershell` |
| `defender_endpoint` | Microsoft Defender for Endpoint (Advanced Hunting) | microsoft | `edr_process` |
| `entra_id_signin` | Microsoft Entra ID Sign-in Logs | microsoft | `identity_signin` |
| `entra_id_audit` | Microsoft Entra ID Audit Logs | microsoft | `cloud_audit` |
| `linux_auditd` | Linux auditd | linux | `linux_auditd` |
| `linux_syslog` | Linux Syslog / Secure | linux | `generic` |
| `crowdstrike_fdr` | CrowdStrike Falcon Data Replicator | crowdstrike | `edr_process` |
| `sentinelone_deep_visibility` | SentinelOne Deep Visibility | sentinelone | `edr_process` |
| `panos_traffic` | Palo Alto PAN-OS Traffic Logs | palo_alto | `firewall` |
| `fortigate_traffic` | FortiGate Traffic / UTM Logs | fortinet | `firewall` |
| `cisco_asa` | Cisco ASA / Firepower | cisco | `firewall` |
| `okta_system_log` | Okta System Log | okta | `identity_signin` |
| `aws_cloudtrail` | AWS CloudTrail | aws | `cloud_audit` |
| `aws_vpc_flow` | AWS VPC Flow Logs | aws | `network_flow` |
| `gcp_audit` | Google Cloud Audit Logs | gcp | `cloud_audit` |
| `zscaler_web_proxy` | Zscaler Internet Access (Web Proxy) | zscaler | `web_proxy` |
| `proofpoint_email` | Proofpoint Email Security | proofpoint | `email_security` |
| `zeek_conn` | Zeek conn.log (Network Flow) | generic_network | `network_flow` |
| `dns_resolver` | DNS Resolver / Query Logs | generic_network | `dns` |

## Adding a mapping

1. Add or extend the entry in `packages/core/src/mappings/fields.ts`.
2. Add a caveat in `notes` if the field needs parser, data-model or extraction work.
3. Add a test in `packages/core/tests/adapters.test.ts`.
4. Run `npm run docs` so this file is regenerated, then commit both changes.
