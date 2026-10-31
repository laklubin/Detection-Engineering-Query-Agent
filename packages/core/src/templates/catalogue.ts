/**
 * Detection template catalogue.
 *
 * Every entry is a human-authored detection-engineering pattern: real MITRE
 * mappings, realistic thresholds, concrete false positives and tuning actions.
 * They are parameterised by telemetry family so the same pattern renders
 * correctly against Windows Security auditing, Sysmon, an EDR table, Entra ID
 * sign-ins, cloud audit logs or network telemetry.
 */

import type { TelemetryFamily } from '../catalog.js';
import type { DetectionTemplate, TemplateContext } from './types.js';

/** Pick the first compatible telemetry, preferring what the user selected. */
function resolveTelemetry(ctx: TemplateContext, supported: readonly TelemetryFamily[]): TelemetryFamily {
  if (supported.includes(ctx.telemetry)) return ctx.telemetry;
  return supported[0] as TelemetryFamily;
}

function base(ctx: TemplateContext, slug: string) {
  return {
    slug,
    vendorId: ctx.vendorId,
    logSourceIds: ctx.logSourceIds.length > 0 ? ctx.logSourceIds : ['windows_security_events'],
  };
}

export const TEMPLATES: readonly DetectionTemplate[] = [
  // -------------------------------------------------------------------------
  {
    id: 'failed-then-successful-auth',
    title: 'Repeated Authentication Failures Followed by a Successful Sign-in',
    example: 'Detect multiple failed logins followed by a successful authentication',
    keywords: [
      'failed login', 'failed logins', 'failed logon', 'failed logons', 'failed authentication',
      'then successful', 'followed by successful', 'successful authentication', 'successful login',
      'brute force', 'bruteforce', 'password guessing', 'account takeover', '4625', '4624',
      'credential stuffing', 'login failure',
    ],
    telemetry: ['windows_security', 'identity_signin', 'generic'],
    build(ctx) {
      const telemetry = resolveTelemetry(ctx, this.telemetry);
      const windows = telemetry === 'windows_security';
      const failure = windows
        ? [
            { field: 'event.code', operator: 'equals', value: 4625, rationale: 'Windows logon failure.' },
            { field: 'logon.type', operator: 'in', value: [3, 8, 10], rationale: 'Logon types that carry a source address.' },
            { field: 'user.name', operator: 'not_contains', value: '$', rationale: 'Exclude machine accounts.' },
          ]
        : [
            { field: 'event.outcome', operator: 'not_equals', value: 0, rationale: 'Non-zero result code is a failed sign-in.' },
            { field: 'user.name', operator: 'exists' },
          ];
      const success = windows
        ? [
            { field: 'event.code', operator: 'equals', value: 4624, rationale: 'Windows logon success.' },
            { field: 'logon.type', operator: 'in', value: [3, 8, 10] },
          ]
        : [
            { field: 'event.outcome', operator: 'equals', value: 0, rationale: 'Successful sign-in.' },
            { field: 'user.name', operator: 'exists' },
          ];

      return {
        ...base(ctx, 'failed-then-successful-auth'),
        name: this.title,
        objective:
          'Detect an account that accumulates a burst of failed authentications and then authenticates ' +
          'successfully from the same source address inside the same window, which indicates a likely ' +
          'successful password-guessing attempt rather than an ordinary mistyped password.',
        attackScenario:
          'An adversary with a list of valid usernames tries a small set of common passwords. When a guess ' +
          'lands, the failure burst is immediately followed by a success from the same source. Alerting on ' +
          'the failures alone is noisy; pairing them with the success raises the fidelity sharply because ' +
          'ordinary users who mistype a password rarely produce ten failures first.',
        requiredEventFields: windows
          ? ['event.code', 'user.name', 'source.ip', 'logon.type', 'host.name']
          : ['event.outcome', 'user.name', 'source.ip', 'auth.app'],
        mappingAssumptions: windows
          ? [
              'Audit Logon is enabled so both 4625 and 4624 are collected from domain controllers and member servers.',
              'source.ip is populated for network logons; console logons carry no source address and are excluded by the logon-type filter.',
            ]
          : ['Sign-in logs include a result code and the originating IP address.'],
        mitre: [
          { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1110.003', techniqueName: 'Brute Force: Password Spraying' },
          { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078', techniqueName: 'Valid Accounts' },
        ],
        stages: [
          { id: 'failures', name: 'Burst of failed authentications', description: 'Repeated authentication failures for one account from one source.', telemetry, conditionLogic: 'all', conditions: failure },
          { id: 'success', name: 'Successful authentication from the same source', description: 'A success for the same account and source address.', telemetry, conditionLogic: 'all', conditions: success },
        ],
        correlation: {
          type: 'sequence', groupBy: ['user.name', 'source.ip'], timeWindowSeconds: 900,
          ordered: true, eventThreshold: 10,
          description: 'At least ten failures followed by a success for the same account and source within fifteen minutes.',
        },
        severity: 'high',
        falsePositives: [
          'Expired or cached credentials on a mobile device producing a failure burst, then a success once the user updates the password.',
          'Service accounts with stale credentials in scheduled tasks or application pools.',
          'VPN concentrators and NAT gateways presenting one source address for many users, which inflates per-source counts.',
          'Authorised penetration tests and red-team exercises.',
        ],
        tuning: [
          'Exclude known NAT and VPN egress ranges from source.ip, or group by user.name alone for those ranges.',
          'Allow-list service accounts by user.name once credential hygiene is confirmed, each with an owner and a review date.',
          'Set the threshold from the 95th percentile of per-account daily failures in your own environment rather than using 10 unchanged.',
          'Suppress for 60 minutes per account and source pair to prevent alert storms.',
        ],
        validationRecommendations: [
          'In a lab, produce ten deliberate failures for a test account from one host, then authenticate successfully, and confirm the correlation fires.',
          'Confirm both the failure and success events are collected from domain controllers, not only member servers.',
          'Run the logic over 30 days of history to size alert volume before enabling notification.',
        ],
      };
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'password-spray',
    title: 'Password Spraying: One Source Against Many Accounts',
    example: 'Detect password spraying against many accounts from a single source',
    keywords: [
      'password spray', 'password spraying', 'spray', 'many accounts', 'multiple accounts',
      'distinct users', 'many users', 'single source', 'account enumeration', 'user enumeration',
    ],
    telemetry: ['windows_security', 'identity_signin', 'generic'],
    build(ctx) {
      const telemetry = resolveTelemetry(ctx, this.telemetry);
      const windows = telemetry === 'windows_security';
      return {
        ...base(ctx, 'password-spray-single-source'),
        name: this.title,
        objective:
          'Detect a single source address producing authentication failures against an unusually large number ' +
          'of distinct accounts in a short window, the signature of a low-and-slow password spray.',
        attackScenario:
          'Rather than many passwords against one account, which triggers lockout, the adversary tries one or ' +
          'two very common passwords against hundreds of accounts. Each account sees only one or two failures, ' +
          'so per-account thresholds never fire. The distinguishing signal is the breadth of distinct accounts ' +
          'touched by a single source.',
        requiredEventFields: windows
          ? ['event.code', 'user.name', 'source.ip', 'logon.type']
          : ['event.outcome', 'user.name', 'source.ip', 'auth.app'],
        mappingAssumptions: [
          'Authentication failures are collected centrally from every authentication point, not a subset.',
          'source.ip is populated and is not rewritten to a single proxy address for all users.',
        ],
        mitre: [
          { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1110.003', techniqueName: 'Brute Force: Password Spraying' },
        ],
        stages: [
          {
            id: 'failures-many-accounts',
            name: 'Authentication failures across many accounts',
            description: 'Failures from one source address spanning many distinct accounts.',
            telemetry,
            conditionLogic: 'all',
            conditions: windows
              ? [
                  { field: 'event.code', operator: 'equals', value: 4625 },
                  { field: 'logon.type', operator: 'in', value: [3, 10] },
                  { field: 'user.name', operator: 'not_contains', value: '$' },
                ]
              : [
                  { field: 'event.outcome', operator: 'not_equals', value: 0 },
                  { field: 'user.name', operator: 'exists' },
                ],
          },
        ],
        correlation: {
          type: 'threshold', groupBy: ['source.ip'], timeWindowSeconds: 1800,
          eventThreshold: 30, distinctThreshold: 15, thresholdField: 'user.name', ordered: false,
          description: 'At least 30 failures against 15 or more distinct accounts from one source in thirty minutes.',
        },
        severity: 'high',
        falsePositives: [
          'A misconfigured application or sync agent retrying with stale credentials for many users.',
          'NAT egress or a VPN concentrator aggregating many legitimate users behind one address.',
          'Vulnerability scanners and authenticated scanning appliances.',
        ],
        tuning: [
          'Exclude known NAT and proxy egress addresses, or pivot to user agent and application for those ranges.',
          'Baseline distinct-account counts per source over 30 days and set the threshold above the observed 99th percentile.',
          'Separate internal from internet-facing sources and apply a lower threshold to the latter.',
        ],
        validationRecommendations: [
          'Replay 30 synthetic failures across 15 lab accounts from one host and confirm the threshold fires once.',
          'Verify the distinct-count field resolves correctly on your platform; several platforms need a custom property for it.',
        ],
      };
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'suspicious-powershell',
    title: 'Suspicious PowerShell Execution',
    example: 'Detect suspicious PowerShell execution with an encoded command',
    keywords: [
      'powershell', 'pwsh', 'encoded command', 'encodedcommand', 'script block', 'scriptblock',
      'obfuscated', 'obfuscation', 'downloadstring', 'invoke-expression', 'iex', 'living off the land',
      'lolbin', '4104', 'base64',
    ],
    telemetry: ['windows_sysmon', 'windows_security', 'edr_process', 'windows_powershell'],
    build(ctx) {
      const telemetry = resolveTelemetry(ctx, this.telemetry);
      return {
        ...base(ctx, 'suspicious-powershell-execution'),
        name: this.title,
        objective:
          'Detect PowerShell started with encoded, hidden or download-oriented arguments, which is the common ' +
          'staging step for script-based loaders.',
        attackScenario:
          'After initial access the adversary launches PowerShell with an encoded command, a hidden window and ' +
          'a bypassed execution policy, then pulls the next stage into memory with a download cradle. Each of ' +
          'those arguments is individually legitimate in places, so the detection looks for the argument ' +
          'patterns that administrators rarely combine.',
        requiredEventFields: ['process.name', 'process.command_line', 'process.parent.name', 'user.name', 'host.name'],
        mappingAssumptions: [
          'Command-line capture is enabled: Sysmon Event ID 1, Windows 4688 with command line, or an EDR process table.',
          'Script-block logging (Event ID 4104) gives better coverage of in-memory execution than command line alone.',
        ],
        mitre: [
          { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1059.001', techniqueName: 'Command and Scripting Interpreter: PowerShell' },
          { tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1027', techniqueName: 'Obfuscated Files or Information' },
        ],
        stages: [
          {
            id: 'suspicious-arguments',
            name: 'PowerShell launched with suspicious arguments',
            description: 'A PowerShell host process starts with obfuscation or download-cradle arguments.',
            telemetry,
            conditionLogic: 'all',
            conditions: [
              { field: 'process.name', operator: 'in', value: ['powershell.exe', 'pwsh.exe', 'powershell_ise.exe'], rationale: 'Scope to the PowerShell host binaries.' },
              {
                field: 'process.command_line', operator: 'regex',
                value: '(-enc(odedcommand)?|-e\\s|-w\\s*hidden|-windowstyle\\s*hidden|-nop|-noprofile|-ep\\s*bypass|-executionpolicy\\s*bypass|downloadstring|downloadfile|invoke-webrequest|iwr\\s|frombase64string|iex\\s|invoke-expression)',
                rationale: 'Obfuscation and download-cradle argument patterns seen in loaders.',
              },
            ],
          },
        ],
        correlation: {
          type: 'threshold', groupBy: ['host.name', 'user.name'], timeWindowSeconds: 600,
          eventThreshold: 1, ordered: false,
          description: 'Any single matching execution is worth triage; grouping limits duplicate alerts per host and user.',
        },
        severity: 'high',
        falsePositives: [
          'Configuration-management tooling (SCCM, Intune, Ansible, Chocolatey) running PowerShell with -NoProfile and downloading packages.',
          'Software deployment and patching agents fetching payloads over HTTPS.',
          'Developer and administrator workstations where encoded commands are used interactively or by build tooling.',
        ],
        tuning: [
          'Allow-list process.parent.name for verified management agents such as ccmexec.exe or intunemanagementextension.exe, after confirming parentage.',
          'Treat -NoProfile alone as benign; require it to co-occur with encoding or a download cradle.',
          'Exclude signed vendor scripts by path once the signing chain has been verified.',
        ],
        validationRecommendations: [
          'Reproduce safely with the Atomic Red Team test for T1059.001 encoded commands in an isolated lab.',
          'Confirm the command line is actually captured: 4688 without command-line auditing will not match.',
          'Measure a seven-day historical hit rate before enabling notification.',
        ],
      };
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'execution-then-egress',
    title: 'Suspicious Script Execution Followed by External Network Egress',
    example: 'Detect script execution followed by external network communication',
    keywords: [
      'followed by network', 'then network', 'external network', 'network communication', 'callback',
      'beacon', 'command and control', 'c2', 'egress', 'outbound connection', 'phones home',
      'execution followed by',
    ],
    telemetry: ['windows_sysmon', 'edr_process'],
    build(ctx) {
      const telemetry = resolveTelemetry(ctx, this.telemetry);
      return {
        ...base(ctx, 'execution-then-external-egress'),
        name: this.title,
        objective:
          'Detect a script interpreter launched with suspicious arguments that is followed, on the same host ' +
          'and by the same account, by an outbound connection to a public address within a short window.',
        attackScenario:
          'A loader runs, then contacts operator infrastructure to retrieve the next stage or register the ' +
          'beacon. Correlating the execution with the subsequent egress cuts the false-positive rate sharply ' +
          'compared with alerting on interpreter arguments alone.',
        requiredEventFields: ['process.name', 'process.command_line', 'user.name', 'host.name', 'destination.ip', 'destination.port'],
        mappingAssumptions: [
          'Process-creation and network-connection telemetry are collected from the same endpoints and share a host and user key.',
          'Private address space is RFC1918 plus the organisation CGNAT range; adjust the exclusion to your addressing plan.',
        ],
        mitre: [
          { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter' },
          { tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1071.001', techniqueName: 'Application Layer Protocol: Web Protocols' },
        ],
        stages: [
          {
            id: 'suspicious-execution', name: 'Interpreter launched with suspicious arguments',
            description: 'A scripting interpreter starts with obfuscation or download arguments.',
            telemetry, conditionLogic: 'all',
            conditions: [
              { field: 'process.name', operator: 'in', value: ['powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe'] },
              { field: 'process.command_line', operator: 'regex', value: '(-enc(odedcommand)?|-w\\s*hidden|-nop|downloadstring|downloadfile|invoke-webrequest|frombase64string|http[s]?:)' },
            ],
          },
          {
            id: 'external-egress', name: 'Outbound connection to a public address',
            description: 'The same account on the same host opens an outbound connection to a non-private address.',
            telemetry, conditionLogic: 'all',
            conditions: [
              { field: 'destination.port', operator: 'in', value: [80, 443, 8080, 8443, 53, 4444, 8888] },
              {
                field: 'destination.ip', operator: 'not_regex',
                value: '^(10\\.|127\\.|169\\.254\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.|::1$|fe80:|fc00:|fd)',
                rationale: 'Exclude RFC1918, loopback, link-local, CGNAT and IPv6 private ranges.',
              },
            ],
          },
        ],
        correlation: {
          type: 'sequence', groupBy: ['host.name', 'user.name'], timeWindowSeconds: 300, ordered: true,
          description: 'The egress must follow the execution on the same host and account within five minutes.',
        },
        severity: 'high',
        falsePositives: [
          'Management agents that run a script and then fetch packages from a vendor endpoint.',
          'Developer tooling that downloads dependencies during a build.',
          'Telemetry agents that use rundll32 or mshta as part of normal operation on legacy systems.',
        ],
        tuning: [
          'Allow-list destination.domain for signed vendor update endpoints rather than destination.ip, which rotates.',
          'Exclude automation service accounts by user.name and review the exclusion list quarterly.',
          'Widen the window to 120 seconds if browser-driven activity produces excessive matches.',
        ],
        validationRecommendations: [
          'Reproduce both stages in a lab and confirm the group-by fields populate on each.',
          'Verify that network-connection telemetry carries the initiating account, not only the host.',
        ],
      };
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'credential-dumping',
    title: 'Credential Dumping: LSASS Process Access',
    example: 'Detect LSASS credential dumping with procdump or comsvcs',
    keywords: [
      'lsass', 'credential dump', 'credential dumping', 'mimikatz', 'procdump', 'comsvcs',
      'memory dump', 'dump lsass', 'credential theft', 'secretsdump',
    ],
    telemetry: ['windows_sysmon', 'edr_process'],
    build(ctx) {
      const telemetry = resolveTelemetry(ctx, this.telemetry);
      return {
        ...base(ctx, 'lsass-credential-dumping'),
        name: this.title,
        objective:
          'Detect a process reading or dumping the memory of LSASS, the step that yields plaintext or hashed ' +
          'credentials for lateral movement.',
        attackScenario:
          'Having gained local administrator rights, the adversary dumps LSASS memory with a signed utility ' +
          'such as procdump or comsvcs.dll, or with a purpose-built tool, then extracts credentials offline. ' +
          'Using a signed binary makes the action look routine, so the detection keys on the target and the ' +
          'argument pattern rather than on the tool name.',
        requiredEventFields: ['process.name', 'process.command_line', 'process.parent.name', 'user.name', 'host.name'],
        mappingAssumptions: [
          'Sysmon Event ID 10 (ProcessAccess) or an equivalent EDR access event is collected; command-line-only telemetry misses direct API access.',
          'Granted-access masks are available where the platform supports them, which reduces noise considerably.',
        ],
        mitre: [
          { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1003.001', techniqueName: 'OS Credential Dumping: LSASS Memory' },
        ],
        stages: [
          {
            id: 'lsass-access', name: 'Process targets LSASS memory',
            description: 'A command line references LSASS alongside a dump or memory-read verb.',
            telemetry, conditionLogic: 'all',
            conditions: [
              { field: 'process.command_line', operator: 'contains', value: 'lsass', rationale: 'The target process.' },
              {
                field: 'process.command_line', operator: 'regex',
                value: '(procdump|comsvcs|minidump|-ma\\s|createdump|rundll32.*comsvcs|dump.*lsass|lsass.*dmp)',
                rationale: 'Dump utilities and the MiniDump export commonly used against LSASS.',
              },
            ],
          },
        ],
        correlation: {
          type: 'threshold', groupBy: ['host.name', 'user.name'], timeWindowSeconds: 600, eventThreshold: 1, ordered: false,
          description: 'Any single occurrence warrants immediate triage.',
        },
        severity: 'critical',
        falsePositives: [
          'Endpoint protection and DLP products that legitimately open LSASS for inspection.',
          'Crash-dump and performance-diagnostic tooling run by support staff during an incident.',
          'Authorised red-team exercises.',
        ],
        tuning: [
          'Allow-list the specific signed security products in your estate by process.executable path, not by file name.',
          'Where granted-access masks are available, restrict to masks that permit memory reads rather than alerting on any handle.',
          'Require the acting account not to be a known support account, or route those matches to a lower-severity queue.',
        ],
        validationRecommendations: [
          'Run the Atomic Red Team test for T1003.001 in an isolated lab and confirm the event is produced and collected.',
          'Confirm the relevant Sysmon or EDR access event is enabled; many default configurations omit it.',
        ],
      };
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'persistence-autorun',
    title: 'Persistence via Registry Run Key or Scheduled Task',
    example: 'Detect persistence via a registry run key or a scheduled task',
    keywords: [
      'persistence', 'run key', 'runkey', 'autorun', 'auto start', 'autostart', 'startup',
      'scheduled task', 'schtasks', 'registry', 'survive reboot', 'boot persistence',
    ],
    telemetry: ['windows_sysmon', 'windows_security', 'edr_process'],
    build(ctx) {
      const telemetry = resolveTelemetry(ctx, this.telemetry);
      return {
        ...base(ctx, 'persistence-autorun-or-task'),
        name: this.title,
        objective:
          'Detect a new autostart entry being created through a registry Run key or a scheduled task that ' +
          'points at a writable or unusual location.',
        attackScenario:
          'To survive reboot the adversary writes a Run key or registers a scheduled task pointing at a payload ' +
          'in a user-writable directory. Legitimate software does this too, so the detection focuses on the ' +
          'combination of autostart creation with a path under a temporary or user-writable directory.',
        requiredEventFields: ['process.name', 'process.command_line', 'process.parent.name', 'user.name', 'host.name', 'registry.path'],
        mappingAssumptions: [
          'Registry-modification telemetry (Sysmon Event ID 12/13) or scheduled-task creation auditing (4698) is collected.',
          'Command-line capture is enabled so schtasks arguments are visible.',
        ],
        mitre: [
          { tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1547.001', techniqueName: 'Boot or Logon Autostart Execution: Registry Run Keys' },
          { tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1053.005', techniqueName: 'Scheduled Task/Job: Scheduled Task' },
        ],
        stages: [
          {
            id: 'autostart-created', name: 'Autostart entry created',
            description: 'A Run key is written or a scheduled task is registered pointing at a writable path.',
            telemetry, conditionLogic: 'all',
            conditions: [
              {
                field: 'process.command_line', operator: 'regex',
                value: '(currentversion\\\\\\\\run|schtasks.*\\/create|new-scheduledtask|register-scheduledtask|reg\\s+add.*run)',
                rationale: 'Run-key writes and scheduled-task registration.',
              },
              {
                field: 'process.command_line', operator: 'regex',
                value: '(\\\\\\\\appdata\\\\\\\\|\\\\\\\\temp\\\\\\\\|\\\\\\\\users\\\\\\\\public\\\\\\\\|\\\\\\\\programdata\\\\\\\\|%temp%|%appdata%)',
                rationale: 'Payload located in a user-writable directory, which legitimate installers rarely use for autostart.',
              },
            ],
          },
        ],
        correlation: {
          type: 'threshold', groupBy: ['host.name', 'user.name'], timeWindowSeconds: 3600, eventThreshold: 1, ordered: false,
          description: 'Any autostart creation pointing at a writable path is worth triage.',
        },
        severity: 'high',
        falsePositives: [
          'Per-user application installers that legitimately stage in AppData, such as some chat and browser updaters.',
          'Software-deployment tooling that registers maintenance tasks from a staging directory.',
          'Developer tooling creating local scheduled tasks.',
        ],
        tuning: [
          'Allow-list known per-user updaters by the full executable path and verify the signature before doing so.',
          'Exclude deployment agents by process.parent.name after confirming the parent chain.',
          'Split into two rules if one of the two patterns dominates your alert volume.',
        ],
        validationRecommendations: [
          'Create a benign Run key pointing at a file in %TEMP% in a lab and confirm the rule fires.',
          'Confirm registry or task-creation auditing is actually enabled; it is off by default in many builds.',
        ],
      };
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'defense-evasion-tampering',
    title: 'Security Tooling Tampering or Disablement',
    example: 'Detect attempts to disable Defender or clear the Windows event log',
    keywords: [
      'disable antivirus', 'disable defender', 'tamper', 'tampering', 'evade', 'evasion',
      'disable logging', 'clear log', 'clear event log', 'wevtutil', 'stop service', 'unload sysmon',
      'disable edr', 'turn off', 'defender exclusion',
    ],
    telemetry: ['windows_sysmon', 'windows_security', 'edr_process'],
    build(ctx) {
      const telemetry = resolveTelemetry(ctx, this.telemetry);
      return {
        ...base(ctx, 'security-tooling-tampering'),
        name: this.title,
        objective:
          'Detect attempts to disable endpoint protection, add broad exclusions, stop security services or ' +
          'clear event logs — actions that precede or conceal the rest of an intrusion.',
        attackScenario:
          'Before deploying a payload the adversary adds a Defender exclusion for the staging directory, stops ' +
          'the telemetry service, or clears the event log afterwards to frustrate investigation. These actions ' +
          'are rare for ordinary users and highly indicative when performed outside a change window.',
        requiredEventFields: ['process.name', 'process.command_line', 'process.parent.name', 'user.name', 'host.name'],
        mappingAssumptions: [
          'Command-line capture is enabled so the arguments to these utilities are visible.',
          'Event ID 1102 (audit log cleared) is collected where log clearing is in scope.',
        ],
        mitre: [
          { tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1562.001', techniqueName: 'Impair Defenses: Disable or Modify Tools' },
          { tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1070.001', techniqueName: 'Indicator Removal: Clear Windows Event Logs' },
        ],
        stages: [
          {
            id: 'tampering-command', name: 'Security control tampered with',
            description: 'A command disables protection, adds an exclusion, stops a security service or clears a log.',
            telemetry, conditionLogic: 'any',
            conditions: [
              { field: 'process.command_line', operator: 'regex', value: '(set-mppreference.*(disablerealtimemonitoring|disableioavprotection)|add-mppreference.*exclusionpath)', rationale: 'Defender disablement or exclusion.' },
              { field: 'process.command_line', operator: 'regex', value: '(wevtutil\\s+cl|clear-eventlog|wevtutil\\s+sl.*\\/e:false)', rationale: 'Event log clearing or disablement.' },
              { field: 'process.command_line', operator: 'regex', value: '(net\\s+stop\\s+(sense|windefend|sysmon)|sc\\s+(stop|delete|config)\\s+(sense|windefend|sysmon))', rationale: 'Security service stopped, deleted or reconfigured.' },
              { field: 'process.command_line', operator: 'regex', value: '(fltmc.*unload|bcdedit.*safeboot|vssadmin\\s+delete\\s+shadows)', rationale: 'Driver unload, safe-boot abuse or shadow-copy deletion.' },
            ],
          },
        ],
        correlation: {
          type: 'threshold', groupBy: ['host.name', 'user.name'], timeWindowSeconds: 900, eventThreshold: 1, ordered: false,
          description: 'Any match is high signal; grouping suppresses duplicates from a single session.',
        },
        severity: 'critical',
        falsePositives: [
          'Sanctioned maintenance where an administrator disables protection during troubleshooting.',
          'Imaging and provisioning workflows that configure exclusions as part of a build.',
          'Backup software removing old shadow copies as part of normal retention.',
        ],
        tuning: [
          'Correlate against your change-management window and downgrade matches that fall inside it.',
          'Allow-list the provisioning service account, but alert if the same command runs under any other account.',
          'Split shadow-copy deletion into its own rule if backup software dominates the volume.',
        ],
        validationRecommendations: [
          'Add and then remove a harmless Defender exclusion in a lab and confirm the rule fires.',
          'Verify 1102 is collected if log clearing is in scope; it is written to the Security channel itself.',
        ],
      };
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'dns-beaconing',
    title: 'DNS Beaconing or Tunnelling Indicators',
    example: 'Detect DNS tunnelling and beaconing in resolver logs',
    keywords: [
      'dns', 'dns tunnel', 'dns tunnelling', 'dns tunneling', 'nxdomain', 'dga', 'domain generation',
      'beacon', 'beaconing', 'long domain', 'txt record', 'dns exfil', 'dns query',
    ],
    telemetry: ['dns', 'network_flow', 'generic'],
    build(ctx) {
      const telemetry = resolveTelemetry(ctx, this.telemetry);
      return {
        ...base(ctx, 'dns-beaconing-indicators'),
        name: this.title,
        objective:
          'Detect a host issuing an abnormally high number of distinct subdomain lookups under a small number ' +
          'of parent domains, the pattern produced by DNS tunnelling and by domain-generation beacons.',
        attackScenario:
          'DNS is permitted outbound almost everywhere, so it is used both as a covert channel and as a ' +
          'resilient beacon. Tunnelling encodes data into long, unique subdomain labels; DGA beacons resolve ' +
          'many algorithmically generated names until one answers. Both produce a volume of distinct names ' +
          'from a single host that ordinary browsing does not.',
        requiredEventFields: ['dns.question.name', 'host.name', 'source.ip'],
        mappingAssumptions: [
          'Resolver query logs are collected with the full queried name, not just the resolved address.',
          'Internal resolvers are the collection point; endpoint-side logs alone will miss hosts using an external resolver.',
        ],
        mitre: [
          { tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1071.004', techniqueName: 'Application Layer Protocol: DNS' },
          { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1048', techniqueName: 'Exfiltration Over Alternative Protocol' },
        ],
        stages: [
          {
            id: 'high-volume-unique-names', name: 'High volume of distinct lookups',
            description: 'One source issues many distinct DNS names in a short window.',
            telemetry, conditionLogic: 'all',
            conditions: [
              { field: 'dns.question.name', operator: 'exists' },
              { field: 'dns.question.name', operator: 'not_endswith', value: '.arpa', rationale: 'Exclude reverse lookups.' },
            ],
          },
        ],
        correlation: {
          type: 'threshold', groupBy: ['source.ip'], timeWindowSeconds: 3600,
          eventThreshold: 500, distinctThreshold: 200, thresholdField: 'dns.question.name', ordered: false,
          description: 'At least 500 queries covering 200 or more distinct names from one source in an hour.',
        },
        severity: 'medium',
        falsePositives: [
          'Content delivery networks and advertising technology, which legitimately generate many unique hostnames.',
          'Security products performing reputation lookups that encode data into the query name.',
          'Mail servers and spam filters doing high-volume blocklist lookups.',
        ],
        tuning: [
          'Exclude known CDN and reputation-service parent domains, and keep that list under review.',
          'Baseline distinct-name counts per host over 30 days and set the threshold above the 99th percentile.',
          'Add a label-length or entropy check where the platform supports it; that separates tunnelling from ordinary CDN noise far better than volume alone.',
        ],
        validationRecommendations: [
          'Generate a controlled burst of unique subdomain lookups to a domain you own and confirm the threshold fires.',
          'Confirm resolver logs capture the full query name; some configurations truncate it.',
        ],
      };
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'data-exfiltration-volume',
    title: 'Large Outbound Data Transfer to an External Destination',
    example: 'Detect large outbound data exfiltration to an external host',
    keywords: [
      'exfiltration', 'exfil', 'data transfer', 'large upload', 'data loss', 'upload volume',
      'bytes out', 'outbound volume', 'staging', 'data theft',
    ],
    telemetry: ['network_flow', 'firewall', 'web_proxy'],
    build(ctx) {
      const telemetry = resolveTelemetry(ctx, this.telemetry);
      return {
        ...base(ctx, 'large-outbound-transfer'),
        name: this.title,
        objective:
          'Detect a host sending an unusually large volume of data to a single external destination in a short ' +
          'window, the network signature of bulk collection being moved out.',
        attackScenario:
          'After staging data the adversary moves it to an external host or cloud storage endpoint. The volume ' +
          'is the signal: the destination is often a legitimate service, so blocking by reputation alone does ' +
          'not catch it. A per-destination byte threshold inside a short window separates bulk transfer from ' +
          'ordinary browsing.',
        requiredEventFields: ['source.ip', 'destination.ip', 'destination.port', 'network.bytes_out'],
        mappingAssumptions: [
          'Flow or session records include a byte count for the client-to-server direction.',
          'Long sessions are either closed or periodically re-logged; otherwise byte totals arrive only at session end and delay detection.',
        ],
        mitre: [
          { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1041', techniqueName: 'Exfiltration Over C2 Channel' },
          { tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1567', techniqueName: 'Exfiltration Over Web Service' },
        ],
        stages: [
          {
            id: 'bulk-outbound', name: 'Bulk outbound session to a public address',
            description: 'Outbound sessions to a non-private destination carrying substantial volume.',
            telemetry, conditionLogic: 'all',
            conditions: [
              { field: 'network.bytes_out', operator: 'gt', value: 10_000_000, rationale: 'Individual sessions above roughly 10 MB outbound.' },
              {
                field: 'destination.ip', operator: 'not_regex',
                value: '^(10\\.|127\\.|169\\.254\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|::1$|fe80:|fc00:|fd)',
                rationale: 'External destinations only.',
              },
            ],
          },
        ],
        correlation: {
          type: 'threshold', groupBy: ['source.ip', 'destination.ip'], timeWindowSeconds: 3600,
          eventThreshold: 5, ordered: false,
          description: 'Five or more bulk sessions between the same pair within an hour.',
        },
        severity: 'medium',
        falsePositives: [
          'Sanctioned cloud backup, file sync and software distribution.',
          'Video conferencing and screen sharing, which sustain high outbound volume.',
          'Developers pushing large artefacts to a build or container registry.',
        ],
        tuning: [
          'Allow-list sanctioned backup and sync destinations by domain rather than by address.',
          'Baseline per-host outbound volume and alert on deviation from that host rather than on a flat threshold.',
          'Exclude conferencing ports and known media endpoints, or apply a higher threshold to them.',
        ],
        validationRecommendations: [
          'Transfer a controlled 50 MB file to a destination you own and confirm the byte field populates as expected.',
          'Verify the direction of the byte counter; several products report client-to-server under a differently named field.',
        ],
      };
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'cloud-privilege-escalation',
    title: 'Cloud Identity Privilege Escalation',
    example: 'Detect cloud privilege escalation through an IAM role assignment',
    keywords: [
      'privilege escalation', 'privilege', 'role assignment', 'admin role', 'global admin',
      'iam', 'assumerole', 'attachpolicy', 'added to group', 'elevated', 'owner role',
      'cloudtrail', 'policy change', 'escalate',
    ],
    telemetry: ['cloud_audit', 'identity_signin'],
    build(ctx) {
      const telemetry = resolveTelemetry(ctx, this.telemetry);
      return {
        ...base(ctx, 'cloud-privilege-escalation'),
        name: this.title,
        objective:
          'Detect an identity granting itself or another principal a privileged role, or attaching a broad ' +
          'policy, in the cloud control plane.',
        attackScenario:
          'With a foothold on a low-privilege identity the adversary escalates in the control plane rather than ' +
          'on a host: attaching an administrator policy, adding a principal to a privileged directory role, or ' +
          'creating access keys for a more privileged user. These are rare, high-consequence actions and are ' +
          'well suited to detection because the control plane logs them reliably.',
        requiredEventFields: ['cloud.event_name', 'user.name', 'source.ip', 'cloud.account_id'],
        mappingAssumptions: [
          'Control-plane audit logging is enabled for every account, subscription or project in scope, not just production.',
          'Operation names differ per provider; the pattern below must be aligned with the provider actually in use.',
        ],
        mitre: [
          { tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1098', techniqueName: 'Account Manipulation' },
          { tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1098.003', techniqueName: 'Account Manipulation: Additional Cloud Roles' },
        ],
        stages: [
          {
            id: 'privileged-grant', name: 'Privileged role or policy granted',
            description: 'A control-plane operation grants elevated rights to a principal.',
            telemetry, conditionLogic: 'any',
            conditions: [
              { field: 'cloud.event_name', operator: 'regex', value: '(AttachUserPolicy|AttachRolePolicy|PutUserPolicy|CreateAccessKey|CreateLoginProfile|UpdateAssumeRolePolicy)', rationale: 'AWS IAM escalation primitives.' },
              { field: 'cloud.event_name', operator: 'regex', value: '(Add member to role|Add eligible member to role|Update role definition|Add owner to application)', rationale: 'Entra ID directory role escalation.' },
              { field: 'cloud.event_name', operator: 'regex', value: '(SetIamPolicy|CreateServiceAccountKey)', rationale: 'Google Cloud IAM escalation primitives.' },
            ],
          },
        ],
        correlation: {
          type: 'threshold', groupBy: ['user.name', 'cloud.account_id'], timeWindowSeconds: 3600, eventThreshold: 1, ordered: false,
          description: 'Any privileged grant is worth triage; grouping suppresses duplicates from a single change.',
        },
        severity: 'high',
        falsePositives: [
          'Infrastructure-as-code pipelines that legitimately manage IAM, which will match constantly if not excluded.',
          'Identity-governance tooling performing scheduled access reviews and just-in-time elevation.',
          'Planned onboarding of a new administrator.',
        ],
        tuning: [
          'Exclude the Terraform, CloudFormation or deployment service principals by user.name, and alert loudly if the same action comes from any other identity.',
          'Treat just-in-time elevation as expected when it correlates with an approved request id, and alert when it does not.',
          'Raise severity when the acting identity has never performed an IAM operation before.',
        ],
        validationRecommendations: [
          'Perform a reversible role assignment in a non-production tenant and confirm the operation name matches the pattern exactly.',
          'Confirm audit logs are collected from every account in scope, not only the production one.',
        ],
      };
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'impossible-travel',
    title: 'Improbable Travel or Legacy Authentication Sign-in',
    example: 'Detect impossible travel and legacy authentication sign-ins',
    keywords: [
      'impossible travel', 'improbable travel', 'unusual location', 'geo', 'different country',
      'legacy auth', 'legacy authentication', 'mfa bypass', 'conditional access', 'sign-in',
      'signin', 'anomalous login', 'suspicious sign in',
    ],
    telemetry: ['identity_signin', 'cloud_audit'],
    build(ctx) {
      const telemetry = resolveTelemetry(ctx, this.telemetry);
      return {
        ...base(ctx, 'anomalous-identity-signin'),
        name: this.title,
        objective:
          'Detect successful sign-ins from a client that bypasses modern authentication, or from more distinct ' +
          'source addresses than a single user plausibly has in one window.',
        attackScenario:
          'An adversary with stolen credentials authenticates through a legacy protocol endpoint that cannot ' +
          'enforce MFA, or signs in from infrastructure far from the user while the real user is still active. ' +
          'Both show up as a successful sign-in with properties the genuine user does not normally produce.',
        requiredEventFields: ['user.name', 'source.ip', 'auth.app', 'event.outcome'],
        mappingAssumptions: [
          'Sign-in logs include the client application and the originating address.',
          'Geolocation enrichment is applied downstream where true travel-time analysis is required; this rule approximates it with distinct source counts.',
        ],
        mitre: [
          { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078.004', techniqueName: 'Valid Accounts: Cloud Accounts' },
          { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1621', techniqueName: 'Multi-Factor Authentication Request Generation' },
        ],
        stages: [
          {
            id: 'successful-signin', name: 'Successful sign-in',
            description: 'A successful authentication, used as the base population for the anomaly.',
            telemetry, conditionLogic: 'all',
            conditions: [
              { field: 'event.outcome', operator: 'equals', value: 0, rationale: 'Successful sign-in.' },
              { field: 'user.name', operator: 'exists' },
              { field: 'source.ip', operator: 'exists' },
            ],
          },
        ],
        correlation: {
          type: 'threshold', groupBy: ['user.name'], timeWindowSeconds: 3600,
          eventThreshold: 2, distinctThreshold: 3, thresholdField: 'source.ip', ordered: false,
          description: 'One account authenticating successfully from three or more distinct addresses inside an hour.',
        },
        severity: 'medium',
        falsePositives: [
          'Users on mobile networks whose address changes as they move between cells.',
          'Corporate VPN split tunnelling producing both the office and the home address.',
          'Cloud-hosted mail clients that connect from a provider address pool.',
        ],
        tuning: [
          'Exclude corporate VPN and office egress ranges so only genuinely distinct locations count.',
          'Raise the distinct threshold for roles that travel, and lower it for service accounts, which should be static.',
          'Where the platform supplies a risk score or named location, prefer those over a raw distinct-address count.',
        ],
        validationRecommendations: [
          'Authenticate as a test account from two different networks and confirm both addresses appear as distinct.',
          'Confirm the sign-in result field uses the value your platform assigns to success before relying on it.',
        ],
      };
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'web-shell',
    title: 'Web Shell Written to a Web-Served Directory',
    example: 'Detect a malicious web shell dropped on an IIS web server',
    keywords: [
      'web shell', 'webshell', 'aspx', 'jsp', 'php shell', 'iis', 'apache', 'tomcat',
      'w3wp', 'server compromise', 'web server', 'dropped file',
    ],
    telemetry: ['windows_sysmon', 'edr_process', 'linux_auditd'],
    build(ctx) {
      const telemetry = resolveTelemetry(ctx, this.telemetry);
      const windows = telemetry !== 'linux_auditd';
      return {
        ...base(ctx, 'web-shell-dropped'),
        name: this.title,
        objective:
          'Detect a web server process writing an executable script into a directory it serves, or spawning a ' +
          'command interpreter — the two reliable signals of a web shell.',
        attackScenario:
          'After exploiting a web application the adversary writes a small script into the web root to obtain ' +
          'persistent command execution. The strongest signal is the parent-child relationship: a web server ' +
          'worker process has no legitimate reason to spawn a shell.',
        requiredEventFields: ['process.name', 'process.parent.name', 'process.command_line', 'host.name', 'user.name', 'file.path'],
        mappingAssumptions: [
          'Process-creation telemetry includes the parent process name.',
          'The set of web-root paths below must be adjusted to your own deployment layout.',
        ],
        mitre: [
          { tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1505.003', techniqueName: 'Server Software Component: Web Shell' },
        ],
        stages: [
          {
            id: 'webserver-spawns-shell', name: 'Web server process spawns an interpreter',
            description: 'A web server worker launches a command shell or scripting interpreter.',
            telemetry, conditionLogic: 'all',
            conditions: windows
              ? [
                  { field: 'process.parent.name', operator: 'in', value: ['w3wp.exe', 'httpd.exe', 'tomcat.exe', 'nginx.exe', 'php-cgi.exe'], rationale: 'Web server worker processes.' },
                  { field: 'process.name', operator: 'in', value: ['cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe'], rationale: 'Interpreters a web worker should never launch.' },
                ]
              : [
                  { field: 'process.parent.name', operator: 'in', value: ['httpd', 'nginx', 'php-fpm', 'apache2', 'java'], rationale: 'Web server worker processes.' },
                  { field: 'process.name', operator: 'in', value: ['sh', 'bash', 'dash', 'python', 'perl'], rationale: 'Interpreters a web worker should never launch.' },
                ],
          },
        ],
        correlation: {
          type: 'threshold', groupBy: ['host.name'], timeWindowSeconds: 900, eventThreshold: 1, ordered: false,
          description: 'Any occurrence warrants immediate triage.',
        },
        severity: 'critical',
        falsePositives: [
          'Web applications that legitimately shell out, for example to run a report generator or image converter.',
          'Deployment and maintenance scripts executed through the web stack during a release.',
          'Monitoring plugins that invoke a shell for health checks.',
        ],
        tuning: [
          'Enumerate the applications that legitimately shell out and allow-list the specific child command line, not the parent.',
          'Exclude the release window, or require the acting account not to be the deployment account.',
          'Where available, add a file-write condition for script extensions under the web root to catch the drop as well as the execution.',
        ],
        validationRecommendations: [
          'In a lab, have a test page execute a harmless command and confirm the parent-child pair is recorded.',
          'Confirm the parent process name is populated; some collection paths omit it.',
        ],
      };
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'lateral-movement-remote-exec',
    title: 'Lateral Movement via Remote Service or Admin Share',
    example: 'Detect lateral movement using psexec or WMI remote execution',
    keywords: [
      'lateral movement', 'lateral', 'psexec', 'remote execution', 'wmi', 'wmic', 'admin share',
      'admin$', 'smb', 'remote service', 'pass the hash', 'wsman', 'winrm', 'pivot',
    ],
    telemetry: ['windows_security', 'windows_sysmon', 'edr_process'],
    build(ctx) {
      const telemetry = resolveTelemetry(ctx, this.telemetry);
      return {
        ...base(ctx, 'lateral-movement-remote-exec'),
        name: this.title,
        objective:
          'Detect remote command execution against another host through service creation, WMI or WinRM, the ' +
          'standard mechanisms for moving laterally with stolen credentials.',
        attackScenario:
          'Holding valid credentials, the adversary executes commands on a second host by creating a service ' +
          'over the admin share, invoking WMI process creation, or opening a WinRM session. Administrators use ' +
          'these tools too, so the detection depends on knowing which accounts and sources are expected.',
        requiredEventFields: ['process.name', 'process.command_line', 'process.parent.name', 'user.name', 'host.name', 'source.ip'],
        mappingAssumptions: [
          'Command-line capture is enabled so remote-execution arguments are visible.',
          'Service-creation auditing (7045 or 4697) is collected where service-based execution is in scope.',
        ],
        mitre: [
          { tacticId: 'TA0008', tacticName: 'Lateral Movement', techniqueId: 'T1021.002', techniqueName: 'Remote Services: SMB/Windows Admin Shares' },
          { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1047', techniqueName: 'Windows Management Instrumentation' },
        ],
        stages: [
          {
            id: 'remote-exec-command', name: 'Remote execution invoked',
            description: 'A command performs remote execution against another host.',
            telemetry, conditionLogic: 'any',
            conditions: [
              { field: 'process.command_line', operator: 'regex', value: '(psexec|paexec|\\\\\\\\admin\\$|\\\\\\\\c\\$)', rationale: 'Service-based remote execution over an admin share.' },
              { field: 'process.command_line', operator: 'regex', value: '(wmic\\s+\\/node:|invoke-wmimethod|invoke-cimmethod.*create)', rationale: 'WMI remote process creation.' },
              { field: 'process.command_line', operator: 'regex', value: '(invoke-command\\s+-computername|enter-pssession|winrs\\s+-r)', rationale: 'WinRM remote session or command.' },
            ],
          },
        ],
        correlation: {
          type: 'threshold', groupBy: ['user.name', 'host.name'], timeWindowSeconds: 1800, eventThreshold: 1, ordered: false,
          description: 'Any remote-execution invocation outside the expected administrative set is worth triage.',
        },
        severity: 'high',
        falsePositives: [
          'Administrators and jump hosts performing routine remote management.',
          'Configuration-management and patching tooling that uses WMI or WinRM by design.',
          'Monitoring systems polling remote hosts.',
        ],
        tuning: [
          'Allow-list the designated administrative source hosts and service accounts, then alert on anything outside that set.',
          'Exclude the management platform by process.parent.name after confirming the parent chain.',
          'Raise severity when the source host is a workstation rather than a jump host.',
        ],
        validationRecommendations: [
          'Run a benign remote command from a lab jump host and confirm both the source and target are identifiable in the event.',
          'Confirm service-creation auditing is enabled if service-based execution is in scope.',
        ],
      };
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'ransomware-precursor',
    title: 'Ransomware Precursor: Shadow Copy Deletion and Mass File Modification',
    example: 'Detect ransomware deleting shadow copies before encryption',
    keywords: [
      'ransomware', 'encrypt', 'encryption', 'shadow copy', 'vssadmin', 'mass file',
      'file rename', 'extension change', 'recovery disabled', 'bcdedit', 'crypto locker',
    ],
    telemetry: ['windows_sysmon', 'edr_process', 'windows_security'],
    build(ctx) {
      const telemetry = resolveTelemetry(ctx, this.telemetry);
      return {
        ...base(ctx, 'ransomware-precursor'),
        name: this.title,
        objective:
          'Detect the destruction of recovery options — shadow copies, backup catalogues and boot recovery — ' +
          'which immediately precedes encryption in almost every ransomware deployment.',
        attackScenario:
          'Before encrypting, the operator removes the victim\'s ability to recover: deleting volume shadow ' +
          'copies, clearing the backup catalogue and disabling Windows recovery. This happens minutes before ' +
          'encryption, which makes it the last useful opportunity to intervene automatically.',
        requiredEventFields: ['process.name', 'process.command_line', 'process.parent.name', 'user.name', 'host.name'],
        mappingAssumptions: [
          'Command-line capture is enabled; these actions are only distinguishable by their arguments.',
          'The detection targets the precursor, not the encryption itself, so response must be fast to be useful.',
        ],
        mitre: [
          { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1490', techniqueName: 'Inhibit System Recovery' },
          { tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1486', techniqueName: 'Data Encrypted for Impact' },
        ],
        stages: [
          {
            id: 'recovery-destruction', name: 'Recovery options destroyed',
            description: 'Shadow copies, backup catalogue or boot recovery are removed or disabled.',
            telemetry, conditionLogic: 'any',
            conditions: [
              { field: 'process.command_line', operator: 'regex', value: '(vssadmin.*delete\\s+shadows|wmic.*shadowcopy.*delete|win32_shadowcopy.*delete)', rationale: 'Volume shadow copy deletion.' },
              { field: 'process.command_line', operator: 'regex', value: '(wbadmin.*delete\\s+(catalog|systemstatebackup))', rationale: 'Backup catalogue deletion.' },
              { field: 'process.command_line', operator: 'regex', value: '(bcdedit.*(recoveryenabled\\s+no|bootstatuspolicy\\s+ignoreallfailures))', rationale: 'Windows recovery disabled.' },
            ],
          },
        ],
        correlation: {
          type: 'threshold', groupBy: ['host.name'], timeWindowSeconds: 600, eventThreshold: 1, ordered: false,
          description: 'A single occurrence should trigger immediate automated containment, not a queued alert.',
        },
        severity: 'critical',
        falsePositives: [
          'Backup software pruning old shadow copies as part of its normal retention policy.',
          'Disk-imaging and migration tooling during a planned rebuild.',
          'Administrators reclaiming disk space on a storage-constrained server.',
        ],
        tuning: [
          'Allow-list the backup product by full executable path and verify its signature; do not allow-list by file name.',
          'Keep this rule at the highest severity even after tuning — the cost of a missed detection is total.',
          'Pair with an automated containment action rather than a notification, because the window to act is minutes.',
        ],
        validationRecommendations: [
          'Run vssadmin list shadows in a lab first to confirm the process and command line are captured, then test the delete variant on a disposable host.',
          'Verify end-to-end alerting latency; a rule that fires twenty minutes later provides no value here.',
        ],
      };
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'phishing-email',
    title: 'Suspicious Inbound Email with Risky Attachment or Link',
    example: 'Detect a phishing email campaign with a credential-harvesting lure',
    keywords: [
      'phishing', 'phish', 'email', 'attachment', 'malicious link', 'spoof', 'business email compromise',
      'bec', 'sender', 'subject', 'mail', 'lure',
    ],
    telemetry: ['email_security'],
    build(ctx) {
      const telemetry = resolveTelemetry(ctx, this.telemetry);
      return {
        ...base(ctx, 'suspicious-inbound-email'),
        name: this.title,
        objective:
          'Detect inbound mail carrying an executable or script attachment, or a subject consistent with a ' +
          'credential-harvesting lure, delivered to multiple recipients in a short window.',
        attackScenario:
          'A campaign lands in many mailboxes at once with a common lure and an attachment type that no ' +
          'ordinary business correspondence uses. Detecting the campaign shape — same sender or subject across ' +
          'several recipients — is far more reliable than judging any single message.',
        requiredEventFields: ['email.sender', 'email.subject', 'user.name'],
        mappingAssumptions: [
          'The mail gateway logs sender, subject and recipient for every delivered message, not just blocked ones.',
          'Attachment names or types are available; otherwise only the subject heuristic applies.',
        ],
        mitre: [
          { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1566.001', techniqueName: 'Phishing: Spearphishing Attachment' },
          { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1566.002', techniqueName: 'Phishing: Spearphishing Link' },
        ],
        stages: [
          {
            id: 'risky-message', name: 'Message with a risky lure',
            description: 'Inbound mail whose subject matches a common credential-harvesting lure.',
            telemetry, conditionLogic: 'all',
            conditions: [
              { field: 'email.sender', operator: 'exists' },
              {
                field: 'email.subject', operator: 'regex',
                value: '(password\\s*(expir|reset)|verify\\s+your\\s+account|unusual\\s+sign|action\\s+required|invoice\\s+attached|payment\\s+remittance|mailbox\\s+(full|quota)|docu[\\s-]?sign|shared\\s+a\\s+file\\s+with\\s+you)',
                rationale: 'Lure phrasing repeatedly observed in credential-harvesting campaigns.',
              },
            ],
          },
        ],
        correlation: {
          type: 'threshold', groupBy: ['email.sender'], timeWindowSeconds: 3600,
          eventThreshold: 5, distinctThreshold: 5, thresholdField: 'user.name', ordered: false,
          description: 'One sender reaching five or more distinct recipients with a matching lure inside an hour.',
        },
        severity: 'medium',
        falsePositives: [
          'Legitimate bulk mail from service providers, which uses exactly this phrasing.',
          'Internal IT notifications about password expiry and mailbox quota.',
          'Genuine invoice and remittance traffic in finance teams.',
        ],
        tuning: [
          'Allow-list authenticated internal senders and verified bulk-mail providers by domain with DMARC alignment confirmed.',
          'Require the sender domain to be external and failing DMARC before alerting, which removes most of the volume.',
          'Maintain the lure list from your own confirmed phishing reports rather than from a generic list.',
        ],
        validationRecommendations: [
          'Send a benign test message matching the subject pattern from an external test domain to five mailboxes.',
          'Confirm the gateway logs delivered mail, not only blocked mail; otherwise this rule sees nothing.',
        ],
      };
    },
  },

  // -------------------------------------------------------------------------
  {
    id: 'linux-suspicious-execution',
    title: 'Linux Suspicious Shell Execution and Download Cradle',
    example: 'Detect a Linux host piping a curl download straight into bash',
    keywords: [
      'linux', 'unix', 'bash', 'shell', 'curl', 'wget', 'auditd', 'reverse shell',
      'chmod', 'cron', 'etc/passwd', 'sudo',
    ],
    telemetry: ['linux_auditd', 'generic'],
    build(ctx) {
      const telemetry = resolveTelemetry(ctx, this.telemetry);
      return {
        ...base(ctx, 'linux-suspicious-execution'),
        name: this.title,
        objective:
          'Detect a Linux host downloading a file and immediately making it executable or piping it straight ' +
          'into a shell, the standard staging pattern on Unix systems.',
        attackScenario:
          'Following exploitation the adversary retrieves a payload with curl or wget and executes it in one ' +
          'step, often piping the response directly into bash so nothing durable touches disk. The combination ' +
          'of a download utility with immediate execution is the signal.',
        requiredEventFields: ['process.name', 'process.command_line', 'user.name', 'host.name'],
        mappingAssumptions: [
          'auditd execve records are collected with full command-line arguments, which requires an explicit audit rule.',
          'Argument truncation is disabled; auditd splits long command lines by default and can hide the pattern.',
        ],
        mitre: [
          { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1059.004', techniqueName: 'Command and Scripting Interpreter: Unix Shell' },
          { tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1105', techniqueName: 'Ingress Tool Transfer' },
        ],
        stages: [
          {
            id: 'download-and-execute', name: 'Download piped to a shell or marked executable',
            description: 'A download utility is combined with immediate execution.',
            telemetry, conditionLogic: 'all',
            conditions: [
              { field: 'process.command_line', operator: 'regex', value: '(curl|wget|fetch)\\s', rationale: 'Download utility invoked.' },
              { field: 'process.command_line', operator: 'regex', value: '(\\|\\s*(ba)?sh|\\|\\s*python|chmod\\s+\\+?x|;\\s*\\.\\/)', rationale: 'Immediate execution of what was downloaded.' },
            ],
          },
        ],
        correlation: {
          type: 'threshold', groupBy: ['host.name', 'user.name'], timeWindowSeconds: 900, eventThreshold: 1, ordered: false,
          description: 'Any single occurrence outside a build context is worth triage.',
        },
        severity: 'high',
        falsePositives: [
          'Container image builds and CI jobs, which use this pattern constantly and legitimately.',
          'Package installers and bootstrap scripts for developer tooling.',
          'Configuration-management runs that fetch and execute remote scripts by design.',
        ],
        tuning: [
          'Exclude build agents and CI runners entirely by host, rather than trying to tune the pattern on them.',
          'Allow-list the configuration-management service account, and alert when the same pattern runs under an interactive user.',
          'Restrict to production hosts first, where this pattern should be rare.',
        ],
        validationRecommendations: [
          'Run a benign curl piped to a shell on a lab host and confirm the full command line is recorded by auditd.',
          'Verify the audit rule for execve exists; without it there is nothing to match.',
        ],
      };
    },
  },
];
