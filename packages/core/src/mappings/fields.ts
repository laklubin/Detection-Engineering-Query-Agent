/**
 * Field-mapping registry.
 *
 * DESIGN RULE: this registry is the ONLY place a logical field name becomes a
 * vendor field name. A logical field that has no documented mapping for a given
 * platform/telemetry combination resolves to `status: 'mapping_required'` and the
 * adapters surface that honestly instead of inventing a plausible column name.
 *
 * Mappings are intentionally conservative. Where a platform requires a custom
 * event property, data-model acceleration, or parser-dependent attribute, the
 * entry carries a note describing exactly what the engineer must confirm.
 */

import type { PlatformId } from '../constants.js';
import type { TelemetryFamily } from '../catalog.js';

export type MappingStatus = 'mapped' | 'mapping_required';

export interface ResolvedField {
  readonly logical: string;
  readonly platform: PlatformId;
  readonly telemetry: TelemetryFamily;
  /** Vendor field name, or null when no documented mapping exists. */
  readonly physical: string | null;
  readonly status: MappingStatus;
  readonly note?: string;
}

interface FieldMapEntry {
  readonly label: string;
  readonly description: string;
  /** Mapping used when the telemetry family has no specific override. */
  readonly defaults: Partial<Record<PlatformId, string>>;
  readonly overrides?: Partial<Record<TelemetryFamily, Partial<Record<PlatformId, string>>>>;
  /** Caveats surfaced to the engineer alongside the resolved field. */
  readonly notes?: Partial<Record<PlatformId, string>>;
}

const QRADAR_CUSTOM_PROPERTY_NOTE =
  'Requires a QRadar custom event property (regex/JSON extraction) to exist on the ' +
  'log source before this reference resolves.';
const SECURONIX_CUSTOM_NOTE =
  'Securonix normalisation is import-connector dependent; confirm the policy field ' +
  'in Spotter before promoting the query.';
const SENTINEL_SYSMON_NOTE =
  'Sysmon reaches Sentinel either as Defender XDR device tables or as rows in the ' +
  'generic `Event` table, where this value lives inside the EventData XML. Extract ' +
  'it with parse_xml()/extract() (or target a Sysmon-specific custom table) before ' +
  'filtering on it.';
const FORTISIEM_PARSER_NOTE =
  'FortiSIEM event attribute availability depends on the active parser for the ' +
  'device type; confirm the attribute name in Analytics > Event Attributes.';

const REGISTRY: Readonly<Record<string, FieldMapEntry>> = {
  // -- Event identity -------------------------------------------------------
  'event.code': {
    label: 'Event ID / code',
    description: 'Numeric or string event identifier emitted by the log source.',
    defaults: {
      splunk: 'EventCode',
      sentinel: 'EventID',
      elastic: 'event.code',
      sigma: 'EventID',
      fortisiem: 'eventType',
    },
    overrides: {
      windows_sysmon: { elastic: 'winlog.event_id', splunk: 'EventCode', sigma: 'EventID' },
      windows_security: { elastic: 'winlog.event_id' },
      windows_powershell: { elastic: 'winlog.event_id' },
      edr_process: { sentinel: 'ActionType', sigma: 'EventType' },
    },
    notes: {
      qradar:
        'Use the QRadar QID or category rather than a raw event id: `qid` / ' +
        '`category` are the supported discriminators in AQL.',
      securonix: SECURONIX_CUSTOM_NOTE,
      fortisiem: FORTISIEM_PARSER_NOTE,
    },
  },
  'event.outcome': {
    label: 'Event outcome',
    description: 'success / failure outcome of the audited action.',
    defaults: {
      splunk: 'action',
      elastic: 'event.outcome',
      securonix: 'eventoutcome',
    },
    overrides: {
      identity_signin: { sentinel: 'ResultType', elastic: 'event.outcome' },
      cloud_audit: { sentinel: 'Result', elastic: 'event.outcome' },
    },
    notes: {
      sentinel:
        'Windows SecurityEvent encodes outcome in the EventID (4624 vs 4625) rather ' +
        'than a dedicated outcome column.',
      qradar: 'Outcome is encoded in the QID mapping; filter on `qid` or `category`.',
      sigma: 'Sigma expresses outcome through the selected EventID / category.',
      fortisiem: FORTISIEM_PARSER_NOTE,
    },
  },

  // -- Host / user ----------------------------------------------------------
  'host.name': {
    label: 'Host name',
    description: 'Hostname of the asset generating the event.',
    defaults: {
      splunk: 'host',
      sentinel: 'Computer',
      elastic: 'host.name',
      sigma: 'ComputerName',
      securonix: 'devicehostname',
      fortisiem: 'hostName',
    },
    overrides: {
      edr_process: { sentinel: 'DeviceName' },
      identity_signin: { sentinel: 'DeviceDetail' },
    },
    notes: {
      qradar:
        'AQL exposes the log source rather than a normalised hostname: use ' +
        '`LOGSOURCENAME(logsourceid)` or a custom property.',
    },
  },
  'user.name': {
    label: 'User / account name',
    description: 'Security principal associated with the event.',
    defaults: {
      splunk: 'user',
      sentinel: 'TargetUserName',
      qradar: 'username',
      elastic: 'user.name',
      sigma: 'TargetUserName',
      securonix: 'accountname',
      fortisiem: 'user',
    },
    overrides: {
      edr_process: { sentinel: 'AccountName', sigma: 'User' },
      identity_signin: { sentinel: 'UserPrincipalName', elastic: 'user.name', sigma: 'UserPrincipalName' },
      cloud_audit: { sentinel: 'InitiatedBy', elastic: 'user.name' },
      windows_sysmon: { sigma: 'User', sentinel: 'User' },
      linux_auditd: { sigma: 'auid', elastic: 'user.name' },
    },
  },
  'user.domain': {
    label: 'User domain',
    description: 'Domain or tenant of the principal.',
    defaults: {
      splunk: 'user_domain',
      sentinel: 'TargetDomainName',
      elastic: 'user.domain',
      sigma: 'TargetDomainName',
    },
    notes: {
      qradar: QRADAR_CUSTOM_PROPERTY_NOTE,
      securonix: SECURONIX_CUSTOM_NOTE,
      fortisiem: FORTISIEM_PARSER_NOTE,
    },
  },
  'logon.type': {
    label: 'Logon type',
    description: 'Windows logon type (2 interactive, 3 network, 10 RemoteInteractive...).',
    defaults: {
      splunk: 'Logon_Type',
      sentinel: 'LogonType',
      elastic: 'winlog.event_data.LogonType',
      sigma: 'LogonType',
    },
    notes: {
      qradar: QRADAR_CUSTOM_PROPERTY_NOTE,
      securonix: SECURONIX_CUSTOM_NOTE,
      fortisiem: FORTISIEM_PARSER_NOTE,
    },
  },

  // -- Process --------------------------------------------------------------
  'process.name': {
    label: 'Process name',
    description: 'Image file name of the executing process.',
    defaults: {
      splunk: 'process_name',
      sentinel: 'NewProcessName',
      elastic: 'process.name',
      sigma: 'Image',
      securonix: 'destinationprocessname',
      fortisiem: 'procName',
    },
    overrides: {
      edr_process: { sentinel: 'FileName', sigma: 'Image' },
      windows_sysmon: { sentinel: 'Image' },
    },
    notes: { qradar: QRADAR_CUSTOM_PROPERTY_NOTE, sentinel: SENTINEL_SYSMON_NOTE },
  },
  'process.executable': {
    label: 'Process image path',
    description: 'Full path to the process executable.',
    defaults: {
      splunk: 'process_path',
      sentinel: 'NewProcessName',
      elastic: 'process.executable',
      sigma: 'Image',
    },
    overrides: {
      edr_process: { sentinel: 'FolderPath' },
    },
    notes: {
      qradar: QRADAR_CUSTOM_PROPERTY_NOTE,
      securonix: SECURONIX_CUSTOM_NOTE,
      fortisiem: FORTISIEM_PARSER_NOTE,
    },
  },
  'process.command_line': {
    label: 'Process command line',
    description: 'Full command line, including arguments.',
    defaults: {
      splunk: 'CommandLine',
      sentinel: 'CommandLine',
      elastic: 'process.command_line',
      sigma: 'CommandLine',
      fortisiem: 'command',
    },
    overrides: {
      edr_process: { sentinel: 'ProcessCommandLine', splunk: 'process' },
      windows_security: { splunk: 'Process_Command_Line' },
      windows_sysmon: { sentinel: 'CommandLine' },
    },
    notes: {
      qradar:
        'Command line is not a normalised AQL column. ' + QRADAR_CUSTOM_PROPERTY_NOTE,
      securonix: SECURONIX_CUSTOM_NOTE,
      fortisiem: FORTISIEM_PARSER_NOTE,
      splunk:
        'Requires Windows TA process-creation auditing (4688 with command line) or ' +
        'Sysmon Event ID 1.',
    },
  },
  'process.parent.name': {
    label: 'Parent process name',
    description: 'Image name of the parent process.',
    defaults: {
      splunk: 'parent_process_name',
      sentinel: 'ParentProcessName',
      elastic: 'process.parent.name',
      sigma: 'ParentImage',
      securonix: 'sourceprocessname',
    },
    overrides: {
      edr_process: { sentinel: 'InitiatingProcessFileName' },
      windows_sysmon: { sentinel: 'ParentImage' },
    },
    notes: { qradar: QRADAR_CUSTOM_PROPERTY_NOTE, fortisiem: FORTISIEM_PARSER_NOTE },
  },
  'process.parent.command_line': {
    label: 'Parent command line',
    description: 'Command line of the parent process.',
    defaults: {
      splunk: 'parent_process',
      elastic: 'process.parent.command_line',
      sigma: 'ParentCommandLine',
    },
    overrides: {
      edr_process: { sentinel: 'InitiatingProcessCommandLine' },
    },
    notes: {
      sentinel: 'Not available on the Windows SecurityEvent table; requires Defender XDR or Sysmon.',
      qradar: QRADAR_CUSTOM_PROPERTY_NOTE,
      securonix: SECURONIX_CUSTOM_NOTE,
      fortisiem: FORTISIEM_PARSER_NOTE,
    },
  },
  'process.pid': {
    label: 'Process ID',
    description: 'Operating-system process identifier.',
    defaults: {
      splunk: 'process_id',
      sentinel: 'NewProcessId',
      elastic: 'process.pid',
      sigma: 'ProcessId',
    },
    overrides: { edr_process: { sentinel: 'ProcessId' } },
    notes: { qradar: QRADAR_CUSTOM_PROPERTY_NOTE, securonix: SECURONIX_CUSTOM_NOTE },
  },
  'powershell.script_block': {
    label: 'PowerShell script block text',
    description: 'Deobfuscated script block content (Event ID 4104).',
    defaults: {
      splunk: 'ScriptBlockText',
      sentinel: 'ScriptBlockText',
      elastic: 'powershell.file.script_block_text',
      sigma: 'ScriptBlockText',
    },
    notes: {
      sentinel:
        'Available via the Event XML of the PowerShell Operational channel; extract ' +
        'with `parse_xml()` / `extract()` before filtering.',
      qradar: QRADAR_CUSTOM_PROPERTY_NOTE,
      securonix: SECURONIX_CUSTOM_NOTE,
      fortisiem: FORTISIEM_PARSER_NOTE,
    },
  },

  // -- Network --------------------------------------------------------------
  'source.ip': {
    label: 'Source IP address',
    description: 'Originating network address.',
    defaults: {
      splunk: 'src_ip',
      sentinel: 'IpAddress',
      qradar: 'sourceip',
      elastic: 'source.ip',
      sigma: 'SourceIp',
      securonix: 'sourceaddress',
      fortisiem: 'srcIpAddr',
    },
    overrides: {
      identity_signin: { sentinel: 'IPAddress', sigma: 'IpAddress' },
      cloud_audit: { sentinel: 'CallerIpAddress', elastic: 'source.ip' },
      edr_process: { sentinel: 'LocalIP' },
    },
  },
  'destination.ip': {
    label: 'Destination IP address',
    description: 'Target network address.',
    defaults: {
      splunk: 'dest_ip',
      sentinel: 'RemoteIP',
      qradar: 'destinationip',
      elastic: 'destination.ip',
      sigma: 'DestinationIp',
      securonix: 'destinationaddress',
      fortisiem: 'destIpAddr',
    },
    overrides: {
      windows_sysmon: { sentinel: 'DestinationIp', sigma: 'DestinationIp' },
    },
  },
  'destination.port': {
    label: 'Destination port',
    description: 'Target transport port.',
    defaults: {
      splunk: 'dest_port',
      sentinel: 'RemotePort',
      qradar: 'destinationport',
      elastic: 'destination.port',
      sigma: 'DestinationPort',
      securonix: 'destinationport',
      fortisiem: 'destIpPort',
    },
    overrides: {
      windows_sysmon: { sentinel: 'DestinationPort', sigma: 'DestinationPort' },
    },
  },
  'destination.domain': {
    label: 'Destination domain / hostname',
    description: 'Resolved hostname of the destination.',
    defaults: {
      splunk: 'dest_host',
      sentinel: 'RemoteUrl',
      elastic: 'destination.domain',
      sigma: 'DestinationHostname',
      securonix: 'destinationhostname',
      fortisiem: 'destName',
    },
    notes: { qradar: QRADAR_CUSTOM_PROPERTY_NOTE },
  },
  'network.bytes_out': {
    label: 'Bytes sent',
    description: 'Outbound byte volume for the flow or session.',
    defaults: {
      splunk: 'bytes_out',
      elastic: 'source.bytes',
      qradar: 'sourcebytes',
      fortisiem: 'sentBytes',
      securonix: 'bytesout',
    },
    overrides: { firewall: { sentinel: 'SentBytes' }, network_flow: { sentinel: 'OutboundBytes' } },
    notes: {
      sentinel: 'Column name depends on the firewall/flow table in use — confirm in your workspace schema.',
      sigma: 'Sigma has no standard byte-volume taxonomy field for all products.',
    },
  },
  'network.protocol': {
    label: 'Protocol',
    description: 'Application or transport protocol.',
    defaults: {
      splunk: 'protocol',
      elastic: 'network.protocol',
      qradar: 'protocolid',
      sigma: 'Protocol',
      fortisiem: 'ipProto',
      securonix: 'transportprotocol',
    },
    notes: {
      qradar: 'AQL exposes the numeric protocol id; use `PROTOCOLNAME(protocolid)` for names.',
      sentinel: 'Protocol column varies by table (Protocol / L7Protocol) — confirm in schema.',
    },
  },
  'dns.question.name': {
    label: 'DNS query name',
    description: 'Queried domain name.',
    defaults: {
      splunk: 'query',
      sentinel: 'Name',
      elastic: 'dns.question.name',
      sigma: 'QueryName',
      securonix: 'destinationhostname',
      fortisiem: 'dnsQuery',
    },
    notes: {
      qradar: QRADAR_CUSTOM_PROPERTY_NOTE,
      sentinel: 'Table-dependent (DnsEvents.Name vs DeviceNetworkEvents.RemoteUrl).',
    },
  },
  'url.full': {
    label: 'URL',
    description: 'Full requested URL.',
    defaults: {
      splunk: 'url',
      sentinel: 'RequestURL',
      elastic: 'url.full',
      sigma: 'url',
      securonix: 'requesturl',
      fortisiem: 'httpUrl',
    },
    notes: { qradar: QRADAR_CUSTOM_PROPERTY_NOTE },
  },
  'user_agent.original': {
    label: 'User agent',
    description: 'Raw HTTP user-agent string.',
    defaults: {
      splunk: 'http_user_agent',
      sentinel: 'UserAgent',
      elastic: 'user_agent.original',
      securonix: 'useragent',
    },
    notes: {
      qradar: QRADAR_CUSTOM_PROPERTY_NOTE,
      sigma: 'Field name varies by product taxonomy (`c-useragent`, `UserAgent`).',
      fortisiem: FORTISIEM_PARSER_NOTE,
    },
  },

  // -- File / registry ------------------------------------------------------
  'file.path': {
    label: 'File path',
    description: 'Full path of the file touched by the event.',
    defaults: {
      splunk: 'file_path',
      sentinel: 'FolderPath',
      elastic: 'file.path',
      sigma: 'TargetFilename',
      securonix: 'filepath',
      fortisiem: 'fileName',
    },
    notes: { qradar: QRADAR_CUSTOM_PROPERTY_NOTE },
  },
  'file.hash.sha256': {
    label: 'File SHA256',
    description: 'SHA256 hash of the file or process image.',
    defaults: {
      splunk: 'file_hash',
      sentinel: 'SHA256',
      elastic: 'file.hash.sha256',
      sigma: 'Hashes',
      securonix: 'filehash',
    },
    notes: { qradar: QRADAR_CUSTOM_PROPERTY_NOTE, fortisiem: FORTISIEM_PARSER_NOTE },
  },
  'registry.path': {
    label: 'Registry key path',
    description: 'Windows registry key or value path.',
    defaults: {
      splunk: 'registry_path',
      sentinel: 'RegistryKey',
      elastic: 'registry.path',
      sigma: 'TargetObject',
    },
    notes: {
      qradar: QRADAR_CUSTOM_PROPERTY_NOTE,
      securonix: SECURONIX_CUSTOM_NOTE,
      fortisiem: FORTISIEM_PARSER_NOTE,
    },
  },

  // -- Cloud / identity -----------------------------------------------------
  'cloud.event_name': {
    label: 'Cloud API action',
    description: 'Provider API operation name (e.g. AssumeRole, Add member to role).',
    defaults: {
      splunk: 'eventName',
      sentinel: 'OperationName',
      elastic: 'event.action',
      sigma: 'eventName',
      securonix: 'eventname',
    },
    notes: { qradar: QRADAR_CUSTOM_PROPERTY_NOTE, fortisiem: FORTISIEM_PARSER_NOTE },
  },
  'cloud.account_id': {
    label: 'Cloud account / tenant id',
    description: 'Account, subscription or project identifier.',
    defaults: {
      splunk: 'aws_account_id',
      sentinel: 'AADTenantId',
      elastic: 'cloud.account.id',
      securonix: 'tenantid',
    },
    notes: {
      qradar: QRADAR_CUSTOM_PROPERTY_NOTE,
      sigma: 'Provider-specific; no stable Sigma taxonomy field.',
      fortisiem: FORTISIEM_PARSER_NOTE,
    },
  },
  'auth.app': {
    label: 'Application / client',
    description: 'Application or client used to authenticate.',
    defaults: {
      sentinel: 'AppDisplayName',
      elastic: 'event.provider',
      splunk: 'app',
      securonix: 'applicationname',
    },
    notes: {
      qradar: QRADAR_CUSTOM_PROPERTY_NOTE,
      sigma: 'Provider-specific field name.',
      fortisiem: FORTISIEM_PARSER_NOTE,
    },
  },
  'auth.mfa_result': {
    label: 'MFA result',
    description: 'Multi-factor authentication outcome or requirement.',
    defaults: {
      sentinel: 'MfaDetail',
    },
    notes: {
      splunk: 'Vendor-specific; depends on the identity TA field extractions.',
      qradar: QRADAR_CUSTOM_PROPERTY_NOTE,
      elastic: 'No stable ECS field; use the integration-specific field.',
      sigma: 'Provider-specific field name.',
      securonix: SECURONIX_CUSTOM_NOTE,
      fortisiem: FORTISIEM_PARSER_NOTE,
    },
  },

  // -- Email ----------------------------------------------------------------
  'email.sender': {
    label: 'Email sender',
    description: 'Envelope or header sender address.',
    defaults: {
      splunk: 'src_user',
      sentinel: 'SenderFromAddress',
      elastic: 'email.from.address',
      securonix: 'sourceusername',
    },
    notes: { qradar: QRADAR_CUSTOM_PROPERTY_NOTE, sigma: 'Product-specific.', fortisiem: FORTISIEM_PARSER_NOTE },
  },
  'email.subject': {
    label: 'Email subject',
    description: 'Message subject line.',
    defaults: {
      splunk: 'subject',
      sentinel: 'Subject',
      elastic: 'email.subject',
      securonix: 'transactionstring1',
    },
    notes: { qradar: QRADAR_CUSTOM_PROPERTY_NOTE, sigma: 'Product-specific.', fortisiem: FORTISIEM_PARSER_NOTE },
  },
};

export const LOGICAL_FIELDS = Object.keys(REGISTRY).sort();

export function isKnownLogicalField(logical: string): boolean {
  return Object.hasOwn(REGISTRY, logical);
}

export function describeLogicalField(logical: string): { label: string; description: string } | undefined {
  const entry = REGISTRY[logical];
  if (!entry) return undefined;
  return { label: entry.label, description: entry.description };
}

/**
 * Resolve a logical field to a vendor field name.
 *
 * Returns `status: 'mapping_required'` — never a guessed name — when the
 * platform has no documented mapping for the field.
 */
export function resolveField(
  logical: string,
  platform: PlatformId,
  telemetry: TelemetryFamily,
): ResolvedField {
  const entry = REGISTRY[logical];
  if (!entry) {
    return {
      logical,
      platform,
      telemetry,
      physical: null,
      status: 'mapping_required',
      note:
        `"${logical}" is not present in the DetectionForge field registry. ` +
        'Add a documented mapping before deploying a query that references it.',
    };
  }

  const override = entry.overrides?.[telemetry]?.[platform];
  const physical = override ?? entry.defaults[platform] ?? null;
  const note = entry.notes?.[platform];

  if (physical === null) {
    return {
      logical,
      platform,
      telemetry,
      physical: null,
      status: 'mapping_required',
      note:
        note ??
        `No documented ${platform} mapping for "${logical}" on ${telemetry} telemetry. ` +
          'Confirm the vendor field name in your deployment before use.',
    };
  }

  return note
    ? { logical, platform, telemetry, physical, status: 'mapped', note }
    : { logical, platform, telemetry, physical, status: 'mapped' };
}

/** Resolve many fields at once, preserving input order. */
export function resolveFields(
  logicals: readonly string[],
  platform: PlatformId,
  telemetry: TelemetryFamily,
): ResolvedField[] {
  return logicals.map((l) => resolveField(l, platform, telemetry));
}
