/**
 * Telemetry-source mapping registry.
 *
 * Where `fields.ts` maps logical fields to vendor columns, this module maps a
 * telemetry family to the vendor-specific *scope* of a search: the Splunk index
 * or data model, the Sentinel table, the Elastic index pattern, the Sigma
 * logsource block, and so on.
 *
 * Same honesty rule applies: an undocumented combination yields `null` and the
 * adapter emits a "Mapping Required" marker rather than a guessed table name.
 */

import type { PlatformId } from '../constants.js';
import type { TelemetryFamily } from '../catalog.js';

export interface SigmaLogSource {
  readonly product?: string;
  readonly service?: string;
  readonly category?: string;
  readonly definition?: string;
}

export interface SourceScope {
  /** Splunk search prefix, e.g. `index=wineventlog sourcetype=XmlWinEventLog`. */
  readonly splunk: string | null;
  /** Microsoft Sentinel table name. */
  readonly sentinel: string | null;
  /** QRadar scoping hint used in the AQL WHERE clause. */
  readonly qradar: string | null;
  /** Elastic index pattern. */
  readonly elastic: string | null;
  /** Securonix Spotter resource-group functionality scope. */
  readonly securonix: string | null;
  /** FortiSIEM event-type scope. */
  readonly fortisiem: string | null;
  /** Sigma logsource block. */
  readonly sigma: SigmaLogSource | null;
  /** Caveats shown to the engineer. */
  readonly notes?: Partial<Record<PlatformId, string>>;
}

const SCOPES: Readonly<Record<TelemetryFamily, SourceScope>> = {
  windows_security: {
    splunk: 'index=wineventlog sourcetype=WinEventLog:Security',
    sentinel: 'SecurityEvent',
    qradar: "logsourcetype = 'Microsoft Windows Security Event Log'",
    elastic: 'logs-windows.*,winlogbeat-*',
    securonix: 'rg_functionality = "Microsoft Windows"',
    fortisiem: 'eventType CONTAIN "Win-Security"',
    sigma: { product: 'windows', service: 'security' },
    notes: {
      sentinel:
        'If the workspace uses the Azure Monitor Agent security data connector the ' +
        'table may be `SecurityEvent`; Defender XDR deployments use `DeviceEvents`.',
      qradar: 'Confirm the exact log source type string in Admin > Log Sources.',
    },
  },
  windows_sysmon: {
    splunk: 'index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
    sentinel: 'Event',
    qradar: "logsourcetype = 'Microsoft Windows Sysmon'",
    elastic: 'logs-windows.sysmon_operational-*',
    securonix: 'rg_functionality = "Endpoint Management Systems"',
    fortisiem: 'eventType CONTAIN "Win-Sysmon"',
    sigma: { product: 'windows', service: 'sysmon' },
    notes: {
      sentinel:
        'Sysmon arrives in the generic `Event` table via the legacy MMA custom-log ' +
        'path or in `DeviceProcessEvents` when Defender XDR is deployed. Confirm ' +
        'which table is populated before use.',
    },
  },
  windows_powershell: {
    splunk: 'index=powershell sourcetype=XmlWinEventLog:Microsoft-Windows-PowerShell/Operational',
    sentinel: 'Event',
    qradar: null,
    elastic: 'logs-windows.powershell_operational-*',
    securonix: null,
    fortisiem: 'eventType CONTAIN "Win-PowerShell"',
    sigma: { product: 'windows', service: 'powershell', definition: 'Script block logging (4104) must be enabled' },
    notes: {
      sentinel:
        'Script-block events require the PowerShell Operational channel to be ' +
        'collected; parse `EventData` XML to reach ScriptBlockText.',
      qradar: 'PowerShell operational events need a dedicated log source and custom properties.',
      securonix: 'Requires a Windows PowerShell connector with script-block parsing.',
    },
  },
  edr_process: {
    splunk: 'index=edr',
    sentinel: 'DeviceProcessEvents',
    qradar: null,
    elastic: 'logs-endpoint.events.process-*',
    securonix: 'rg_functionality = "Endpoint Management Systems"',
    fortisiem: null,
    sigma: { category: 'process_creation', product: 'windows' },
    notes: {
      splunk: 'Index and sourcetype depend on the EDR technology add-on in use.',
      qradar: 'EDR telemetry normally reaches QRadar through a vendor DSM; confirm QIDs.',
      fortisiem: 'Requires the vendor-specific FortiSIEM integration; event types vary.',
    },
  },
  linux_auditd: {
    splunk: 'index=linux sourcetype=linux_audit',
    sentinel: 'Syslog',
    qradar: "logsourcetype = 'Linux OS'",
    elastic: 'logs-auditd.*',
    securonix: 'rg_functionality = "Unix / Linux"',
    fortisiem: 'eventType CONTAIN "Linux"',
    sigma: { product: 'linux', service: 'auditd' },
    notes: {
      sentinel: 'auditd via Syslog is unparsed text; a custom table or DCR transform is normally required.',
    },
  },
  identity_signin: {
    splunk: 'index=identity',
    sentinel: 'SigninLogs',
    qradar: null,
    elastic: 'logs-azure.signinlogs-*,logs-okta.system-*',
    securonix: 'rg_functionality = "Identity and Access Management"',
    fortisiem: null,
    sigma: { product: 'azure', service: 'signinlogs' },
    notes: {
      splunk: 'Depends on the identity TA (Microsoft Entra ID / Okta) in use.',
      qradar: 'Cloud identity sources require the relevant DSM and often a custom property set.',
      fortisiem: 'Cloud identity integrations vary; confirm the event types created by the parser.',
      sigma: 'For Okta use `product: okta, service: oktaxx` per the Sigma taxonomy for that source.',
    },
  },
  cloud_audit: {
    splunk: 'index=cloud',
    sentinel: 'AuditLogs',
    qradar: null,
    elastic: 'logs-aws.cloudtrail-*,logs-gcp.audit-*',
    securonix: 'rg_functionality = "Cloud Infrastructure"',
    fortisiem: null,
    sigma: { product: 'aws', service: 'cloudtrail' },
    notes: {
      sentinel: 'Entra audit uses `AuditLogs`; Azure resource activity uses `AzureActivity`; AWS uses `AWSCloudTrail`.',
      splunk: 'AWS data lands in the index configured by Splunk Add-on for AWS.',
      qradar: 'Cloud audit sources require the relevant DSM; confirm QID coverage.',
      fortisiem: 'Cloud connector dependent.',
      sigma: 'Change `product`/`service` to match the cloud provider actually in scope.',
    },
  },
  network_flow: {
    splunk: 'index=network',
    sentinel: 'VMConnection',
    qradar: 'flow data (use the `flows` AQL source)',
    elastic: 'logs-network_traffic.flow-*,logs-aws.vpcflow-*',
    securonix: 'rg_functionality = "Network Devices"',
    fortisiem: 'eventType CONTAIN "NetFlow"',
    sigma: { category: 'network_connection', product: 'windows' },
    notes: {
      sentinel: 'Table depends on the flow source (AzureNetworkAnalytics_CL, AWSVPCFlow, VMConnection).',
      qradar: 'Flow queries must select FROM flows, not events; column names differ.',
      sigma: 'Sigma network taxonomy is endpoint oriented; flow-only sources may have no clean category.',
    },
  },
  dns: {
    splunk: 'index=dns sourcetype=stream:dns',
    sentinel: 'DnsEvents',
    qradar: null,
    elastic: 'logs-network_traffic.dns-*,logs-*.dns-*',
    securonix: 'rg_functionality = "DNS"',
    fortisiem: 'eventType CONTAIN "DNS"',
    sigma: { category: 'dns_query', product: 'windows' },
    notes: { qradar: 'DNS analytics typically needs a custom property set on the resolver log source.' },
  },
  web_proxy: {
    splunk: 'index=proxy',
    sentinel: 'CommonSecurityLog',
    qradar: "logsourcetype = 'Zscaler NSS'",
    elastic: 'logs-zscaler_zia.*,logs-*.web-*',
    securonix: 'rg_functionality = "Web Proxy"',
    fortisiem: 'eventType CONTAIN "Proxy"',
    sigma: { category: 'proxy' },
    notes: { sentinel: 'CEF-based proxies land in CommonSecurityLog; native connectors may use a custom table.' },
  },
  firewall: {
    splunk: 'index=firewall',
    sentinel: 'CommonSecurityLog',
    qradar: "logsourcetype IN ('Palo Alto PA Series', 'Fortinet FortiGate Security Gateway')",
    elastic: 'logs-panw.panos-*,logs-fortinet_fortigate.log-*',
    securonix: 'rg_functionality = "Firewalls"',
    fortisiem: 'eventType CONTAIN "FortiGate"',
    sigma: { category: 'firewall' },
    notes: {
      sentinel: 'Palo Alto/Fortinet via CEF land in CommonSecurityLog; AMA-native connectors may differ.',
    },
  },
  email_security: {
    splunk: 'index=email',
    sentinel: 'EmailEvents',
    qradar: null,
    elastic: 'logs-proofpoint_tap.*,logs-o365.*',
    securonix: 'rg_functionality = "Email / Messaging"',
    fortisiem: null,
    sigma: { category: 'email' },
    notes: {
      sentinel: '`EmailEvents` requires Defender for Office 365; Proofpoint uses a custom table.',
      qradar: 'Email security sources need the vendor DSM plus custom properties.',
      fortisiem: 'Email security integration dependent.',
      sigma: 'No stable Sigma category for third-party email gateways; treat as definition-scoped.',
    },
  },
  generic: {
    splunk: null,
    sentinel: null,
    qradar: null,
    elastic: null,
    securonix: null,
    fortisiem: null,
    sigma: null,
    notes: {
      splunk: 'No telemetry family selected — index and sourcetype must be supplied by the engineer.',
      sentinel: 'No telemetry family selected — the target table must be supplied by the engineer.',
      qradar: 'No telemetry family selected — the log source type must be supplied by the engineer.',
      elastic: 'No telemetry family selected — the index pattern must be supplied by the engineer.',
      securonix: 'No telemetry family selected — the resource group must be supplied by the engineer.',
      fortisiem: 'No telemetry family selected — the event type scope must be supplied by the engineer.',
      sigma: 'No telemetry family selected — the logsource block must be supplied by the engineer.',
    },
  },
};

export function sourceScope(telemetry: TelemetryFamily): SourceScope {
  return SCOPES[telemetry];
}

export function scopeNote(telemetry: TelemetryFamily, platform: PlatformId): string | undefined {
  return SCOPES[telemetry].notes?.[platform];
}
