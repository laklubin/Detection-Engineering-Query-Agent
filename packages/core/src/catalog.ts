/**
 * Vendor and log-source catalogue.
 *
 * This is an ALLOWLIST. The API accepts only vendor ids and log-source ids that
 * appear here; free-text vendor/log-source values are rejected by the schema.
 * That removes an entire class of injection vectors and guarantees that the
 * detection specification only ever references telemetry we have documented.
 */

export interface VendorDescriptor {
  readonly id: string;
  readonly name: string;
  readonly description: string;
}

export const VENDORS: readonly VendorDescriptor[] = [
  { id: 'microsoft', name: 'Microsoft', description: 'Windows, Entra ID, Defender XDR, Microsoft 365' },
  { id: 'linux', name: 'Linux / Unix', description: 'auditd, syslog, osquery, Falco' },
  { id: 'crowdstrike', name: 'CrowdStrike', description: 'Falcon EDR telemetry' },
  { id: 'sentinelone', name: 'SentinelOne', description: 'Singularity Deep Visibility' },
  { id: 'palo_alto', name: 'Palo Alto Networks', description: 'PAN-OS, Cortex XDR, GlobalProtect' },
  { id: 'fortinet', name: 'Fortinet', description: 'FortiGate, FortiEDR, FortiAuthenticator' },
  { id: 'cisco', name: 'Cisco', description: 'ASA, Firepower, Umbrella, Duo' },
  { id: 'okta', name: 'Okta', description: 'Identity and SSO system logs' },
  { id: 'aws', name: 'Amazon Web Services', description: 'CloudTrail, GuardDuty, VPC Flow Logs' },
  { id: 'gcp', name: 'Google Cloud', description: 'Cloud Audit Logs, VPC Flow Logs' },
  { id: 'zscaler', name: 'Zscaler', description: 'ZIA web proxy, ZPA access logs' },
  { id: 'proofpoint', name: 'Proofpoint', description: 'Email security and URL defence' },
  { id: 'generic_network', name: 'Generic Network', description: 'Zeek, NetFlow, DNS, firewall' },
  { id: 'multi_vendor', name: 'Multi-vendor / Not sure', description: 'Let the agent ask a clarifying question' },
] as const;

export const VENDOR_IDS = VENDORS.map((v) => v.id);

export interface LogSourceDescriptor {
  readonly id: string;
  readonly name: string;
  readonly vendorId: string;
  /** Canonical telemetry family used by the field-mapping registry. */
  readonly telemetry: TelemetryFamily;
  /** Free-text search keywords for the searchable dropdown. */
  readonly keywords: readonly string[];
}

export const TELEMETRY_FAMILIES = [
  'windows_security',
  'windows_sysmon',
  'windows_powershell',
  'edr_process',
  'linux_auditd',
  'identity_signin',
  'cloud_audit',
  'network_flow',
  'dns',
  'web_proxy',
  'firewall',
  'email_security',
  'generic',
] as const;

export type TelemetryFamily = (typeof TELEMETRY_FAMILIES)[number];

export const LOG_SOURCES: readonly LogSourceDescriptor[] = [
  {
    id: 'windows_security_events',
    name: 'Windows Security Events',
    vendorId: 'microsoft',
    telemetry: 'windows_security',
    keywords: ['4624', '4625', '4688', 'logon', 'audit', 'eventlog', 'wineventlog'],
  },
  {
    id: 'windows_sysmon',
    name: 'Windows Sysmon',
    vendorId: 'microsoft',
    telemetry: 'windows_sysmon',
    keywords: ['sysmon', 'process creation', 'event id 1', 'event id 3', 'network connect'],
  },
  {
    id: 'windows_powershell_operational',
    name: 'Windows PowerShell Operational / Script Block',
    vendorId: 'microsoft',
    telemetry: 'windows_powershell',
    keywords: ['4104', 'script block', 'powershell', 'module logging'],
  },
  {
    id: 'defender_endpoint',
    name: 'Microsoft Defender for Endpoint (Advanced Hunting)',
    vendorId: 'microsoft',
    telemetry: 'edr_process',
    keywords: ['mde', 'deviceprocessevents', 'devicenetworkevents', 'xdr', 'edr'],
  },
  {
    id: 'entra_id_signin',
    name: 'Microsoft Entra ID Sign-in Logs',
    vendorId: 'microsoft',
    telemetry: 'identity_signin',
    keywords: ['azure ad', 'aad', 'signinlogs', 'conditional access', 'mfa'],
  },
  {
    id: 'entra_id_audit',
    name: 'Microsoft Entra ID Audit Logs',
    vendorId: 'microsoft',
    telemetry: 'cloud_audit',
    keywords: ['azure ad audit', 'directory', 'role assignment', 'auditlogs'],
  },
  {
    id: 'linux_auditd',
    name: 'Linux auditd',
    vendorId: 'linux',
    telemetry: 'linux_auditd',
    keywords: ['auditd', 'execve', 'syscall', 'selinux'],
  },
  {
    id: 'linux_syslog',
    name: 'Linux Syslog / Secure',
    vendorId: 'linux',
    telemetry: 'generic',
    keywords: ['syslog', 'sshd', 'var log secure', 'pam'],
  },
  {
    id: 'crowdstrike_fdr',
    name: 'CrowdStrike Falcon Data Replicator',
    vendorId: 'crowdstrike',
    telemetry: 'edr_process',
    keywords: ['fdr', 'falcon', 'processrollup2', 'edr'],
  },
  {
    id: 'sentinelone_deep_visibility',
    name: 'SentinelOne Deep Visibility',
    vendorId: 'sentinelone',
    telemetry: 'edr_process',
    keywords: ['s1', 'deep visibility', 'edr', 'singularity'],
  },
  {
    id: 'panos_traffic',
    name: 'Palo Alto PAN-OS Traffic Logs',
    vendorId: 'palo_alto',
    telemetry: 'firewall',
    keywords: ['pan-os', 'traffic', 'threat', 'firewall', 'globalprotect'],
  },
  {
    id: 'fortigate_traffic',
    name: 'FortiGate Traffic / UTM Logs',
    vendorId: 'fortinet',
    telemetry: 'firewall',
    keywords: ['fortigate', 'fortios', 'utm', 'webfilter', 'firewall'],
  },
  {
    id: 'cisco_asa',
    name: 'Cisco ASA / Firepower',
    vendorId: 'cisco',
    telemetry: 'firewall',
    keywords: ['asa', 'firepower', 'vpn', 'firewall'],
  },
  {
    id: 'okta_system_log',
    name: 'Okta System Log',
    vendorId: 'okta',
    telemetry: 'identity_signin',
    keywords: ['okta', 'sso', 'mfa', 'user.authentication'],
  },
  {
    id: 'aws_cloudtrail',
    name: 'AWS CloudTrail',
    vendorId: 'aws',
    telemetry: 'cloud_audit',
    keywords: ['cloudtrail', 'iam', 'sts', 'assumerole', 'aws api'],
  },
  {
    id: 'aws_vpc_flow',
    name: 'AWS VPC Flow Logs',
    vendorId: 'aws',
    telemetry: 'network_flow',
    keywords: ['vpc', 'flow', 'netflow', 'aws network'],
  },
  {
    id: 'gcp_audit',
    name: 'Google Cloud Audit Logs',
    vendorId: 'gcp',
    telemetry: 'cloud_audit',
    keywords: ['gcp', 'stackdriver', 'admin activity', 'cloud audit'],
  },
  {
    id: 'zscaler_web_proxy',
    name: 'Zscaler Internet Access (Web Proxy)',
    vendorId: 'zscaler',
    telemetry: 'web_proxy',
    keywords: ['zscaler', 'zia', 'proxy', 'url', 'web'],
  },
  {
    id: 'proofpoint_email',
    name: 'Proofpoint Email Security',
    vendorId: 'proofpoint',
    telemetry: 'email_security',
    keywords: ['proofpoint', 'email', 'tap', 'message', 'phishing'],
  },
  {
    id: 'zeek_conn',
    name: 'Zeek conn.log (Network Flow)',
    vendorId: 'generic_network',
    telemetry: 'network_flow',
    keywords: ['zeek', 'bro', 'conn', 'flow', 'netflow'],
  },
  {
    id: 'dns_resolver',
    name: 'DNS Resolver / Query Logs',
    vendorId: 'generic_network',
    telemetry: 'dns',
    keywords: ['dns', 'query', 'resolver', 'umbrella', 'passivedns'],
  },
] as const;

export const LOG_SOURCE_IDS = LOG_SOURCES.map((s) => s.id);

export function findLogSource(id: string): LogSourceDescriptor | undefined {
  return LOG_SOURCES.find((s) => s.id === id);
}

export function findVendor(id: string): VendorDescriptor | undefined {
  return VENDORS.find((v) => v.id === id);
}

export function logSourcesForVendor(vendorId: string): readonly LogSourceDescriptor[] {
  if (vendorId === 'multi_vendor') return LOG_SOURCES;
  return LOG_SOURCES.filter((s) => s.vendorId === vendorId);
}
