/**
 * Demo-mode fixtures.
 *
 * Used ONLY when the backend has no Hugging Face token configured. They are
 * synthetic, non-sensitive, and are injected at the *model-output* layer, so
 * demo responses travel through exactly the same validation, adapter and
 * structural-check pipeline as live responses.
 *
 * Demo responses are always labelled `mode: "demo"` in the API payload and the
 * UI renders a prominent banner. Fabricated output is never presented as live
 * AI generation.
 */

import type { ModelResponse } from '../schemas.js';

export const DEMO_MODEL_RESPONSE: ModelResponse = {
  status: 'ok',
  useCases: [
    {
      slug: 'powershell-exec-then-egress',
      name: 'Suspicious PowerShell Execution Followed by External Network Egress',
      objective:
        'Detect a PowerShell process launched with encoded, hidden or download-oriented ' +
        'arguments that is followed, on the same host and by the same account, by an ' +
        'outbound connection to a non-RFC1918 destination within a short window.',
      attackScenario:
        'After initial access through a malicious document or script, the adversary uses ' +
        'PowerShell to stage a loader with obfuscated arguments (encoded command, hidden ' +
        'window, download cradle). The loader then contacts an operator-controlled host to ' +
        'retrieve the next-stage implant or to register the beacon. Correlating the ' +
        'execution with the subsequent egress materially reduces the false-positive rate ' +
        'compared with alerting on PowerShell arguments alone.',
      vendorId: 'microsoft',
      logSourceIds: ['windows_sysmon', 'windows_security_events'],
      requiredEventFields: [
        'process.name',
        'process.command_line',
        'process.parent.name',
        'user.name',
        'host.name',
        'destination.ip',
        'destination.port',
      ],
      mappingAssumptions: [
        'Sysmon Event ID 1 (process creation) and Event ID 3 (network connection) are ' +
          'collected from the same endpoints, or 4688 command-line auditing is enabled.',
        'Private address space is defined as RFC1918 plus the organisation CGNAT range; ' +
          'adjust the exclusion list to your addressing plan.',
      ],
      mitre: [
        {
          tacticId: 'TA0002',
          tacticName: 'Execution',
          techniqueId: 'T1059.001',
          techniqueName: 'Command and Scripting Interpreter: PowerShell',
        },
        {
          tacticId: 'TA0011',
          tacticName: 'Command and Control',
          techniqueId: 'T1071.001',
          techniqueName: 'Application Layer Protocol: Web Protocols',
        },
      ],
      stages: [
        {
          id: 'suspicious-powershell',
          name: 'PowerShell launched with suspicious arguments',
          description:
            'PowerShell or pwsh starts with encoded command, hidden window, bypassed ' +
            'execution policy, or an in-memory download expression.',
          telemetry: 'windows_sysmon',
          conditionLogic: 'all',
          conditions: [
            {
              field: 'process.name',
              operator: 'in',
              value: ['powershell.exe', 'pwsh.exe', 'powershell_ise.exe'],
              rationale: 'Scope the stage to the PowerShell host binaries.',
            },
            {
              field: 'process.command_line',
              operator: 'regex',
              value:
                '(-enc(odedcommand)?|-e\\s|-w\\s*hidden|-windowstyle\\s*hidden|-nop|-noprofile|-ep\\s*bypass|downloadstring|downloadfile|invoke-webrequest|iwr\\s|frombase64string|iex\\s)',
              rationale:
                'Obfuscation and download-cradle argument patterns commonly seen in loaders.',
            },
          ],
        },
        {
          id: 'external-egress',
          name: 'Outbound connection to an external destination',
          description:
            'The same account on the same host opens an outbound connection to a public ' +
            'address on a common web or alternate C2 port.',
          telemetry: 'windows_sysmon',
          conditionLogic: 'all',
          conditions: [
            {
              field: 'destination.port',
              operator: 'in',
              value: [80, 443, 8080, 8443, 53, 4444, 8888],
              rationale: 'Web ports plus frequently abused alternates.',
            },
            {
              field: 'destination.ip',
              operator: 'not_regex',
              value:
                '^(10\\.|127\\.|169\\.254\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.|::1$|fe80:|fc00:|fd)',
              rationale:
                'Exclude RFC1918, loopback, link-local, CGNAT and IPv6 private ranges so ' +
                'only genuinely external destinations match.',
            },
          ],
        },
      ],
      correlation: {
        type: 'sequence',
        groupBy: ['host.name', 'user.name'],
        timeWindowSeconds: 300,
        ordered: true,
        description:
          'Stage 2 must follow stage 1 on the same host and account within five minutes, ' +
          'which matches observed loader-to-callback latency while limiting unrelated ' +
          'coincidental browsing activity.',
      },
      severity: 'high',
      falsePositives: [
        'Configuration-management tooling (SCCM, Intune, Ansible, Chocolatey) that runs ' +
          'PowerShell with -NoProfile and then downloads packages.',
        'Software-deployment and patching agents that fetch payloads over HTTPS.',
        'Developer and administrator workstations where encoded commands are used ' +
          'interactively or by build tooling.',
        'Security tooling and vulnerability scanners that execute PowerShell collectors.',
      ],
      tuning: [
        'Allow-list process.parent.name for known management agents (ccmexec.exe, ' +
          'ansible-connection, intunemanagementextension.exe) after verifying parentage.',
        'Allow-list destination.domain for signed vendor update endpoints rather than ' +
          'allow-listing destination.ip, which rotates.',
        'Exclude service accounts used by automation via user.name, and review the ' +
          'exclusion list quarterly.',
        'Raise the window to 120 seconds if the environment produces excessive matches ' +
          'from browser-driven activity.',
      ],
      validationRecommendations: [
        'Reproduce stage 1 safely with Atomic Red Team T1059.001 test for encoded ' +
          'commands in an isolated lab, and confirm Sysmon Event ID 1 captures the ' +
          'command line.',
        'Reproduce stage 2 with a benign HTTPS request from the same session and confirm ' +
          'Sysmon Event ID 3 records the destination.',
        'Verify the correlation fires end to end and that the group-by fields populate on ' +
          'both stages.',
        'Measure a 7-day historical hit rate before enabling notification, and record the ' +
          'baseline in the detection backlog.',
      ],
    },
    {
      slug: 'password-spray-then-success',
      name: 'Repeated Authentication Failures Followed by Successful Sign-in',
      objective:
        'Detect an account that accumulates a burst of failed authentications and then ' +
        'authenticates successfully from the same source address within the same window, ' +
        'indicating a likely successful password-guessing or spray attempt.',
      attackScenario:
        'An adversary with a list of valid usernames attempts a small number of common ' +
        'passwords against many accounts, or many passwords against one account. When a ' +
        'guess succeeds the failure burst is immediately followed by a successful logon ' +
        'from the same source. Alerting on the failure burst alone is noisy; pairing it ' +
        'with the success provides high-confidence evidence of account compromise.',
      vendorId: 'microsoft',
      logSourceIds: ['windows_security_events'],
      requiredEventFields: ['event.code', 'user.name', 'source.ip', 'logon.type', 'host.name'],
      mappingAssumptions: [
        'Audit Logon events are enabled so that both 4625 (failure) and 4624 (success) ' +
          'are collected from domain controllers and member servers.',
        'source.ip is populated for network logons; interactive console logons will not ' +
          'carry a source address and are excluded by the logon-type filter.',
      ],
      mitre: [
        {
          tacticId: 'TA0006',
          tacticName: 'Credential Access',
          techniqueId: 'T1110.003',
          techniqueName: 'Brute Force: Password Spraying',
        },
        {
          tacticId: 'TA0001',
          tacticName: 'Initial Access',
          techniqueId: 'T1078',
          techniqueName: 'Valid Accounts',
        },
      ],
      stages: [
        {
          id: 'failed-logons',
          name: 'Burst of failed logons',
          description: 'Multiple 4625 failures for the same account from the same source address.',
          telemetry: 'windows_security',
          conditionLogic: 'all',
          conditions: [
            { field: 'event.code', operator: 'equals', value: 4625, rationale: 'Windows logon failure.' },
            {
              field: 'logon.type',
              operator: 'in',
              value: [3, 8, 10],
              rationale: 'Network, network-cleartext and RemoteInteractive logons carry a source address.',
            },
            {
              field: 'user.name',
              operator: 'not_contains',
              value: '$',
              rationale: 'Exclude machine accounts, which end with a dollar sign.',
            },
          ],
        },
        {
          id: 'successful-logon',
          name: 'Successful logon from the same source',
          description: 'A 4624 success for the same account and source address.',
          telemetry: 'windows_security',
          conditionLogic: 'all',
          conditions: [
            { field: 'event.code', operator: 'equals', value: 4624, rationale: 'Windows logon success.' },
            { field: 'logon.type', operator: 'in', value: [3, 8, 10] },
          ],
        },
      ],
      correlation: {
        type: 'sequence',
        groupBy: ['user.name', 'source.ip'],
        timeWindowSeconds: 900,
        ordered: true,
        eventThreshold: 10,
        description:
          'At least ten failures followed by a success for the same account and source ' +
          'address inside fifteen minutes.',
      },
      severity: 'high',
      falsePositives: [
        'Expired passwords or cached credentials on mobile devices producing failure ' +
          'bursts followed by a successful sign-in after the user updates the password.',
        'Service accounts with stale credentials in scheduled tasks or application pools.',
        'Load balancers and VPN concentrators that present one source address for many ' +
          'users, inflating per-source counts.',
        'Penetration tests and authorised red-team exercises.',
      ],
      tuning: [
        'Exclude known NAT egress and VPN concentrator addresses from source.ip, or group ' +
          'by user.name only for those ranges.',
        'Allow-list service accounts by user.name once credential hygiene is confirmed, ' +
          'and track each exclusion with an owner and review date.',
        'Tune the threshold from the 95th percentile of per-account daily failures in your ' +
          'own environment rather than using 10 unchanged.',
        'Suppress for 60 minutes per account/source pair to prevent alert storms.',
      ],
      validationRecommendations: [
        'In a lab, generate ten deliberate authentication failures for a test account from ' +
          'one host, then authenticate successfully, and confirm the correlation fires.',
        'Confirm 4625 and 4624 are both collected from domain controllers, not only from ' +
          'member servers.',
        'Validate that logon.type values present in your telemetry match the filter.',
        'Run the logic over 30 days of history to size the alert volume before enabling ' +
          'notification.',
      ],
    },
  ],
};

/** Fixture used by tests and the sample-output documentation. */
export const DEMO_CLARIFICATION_RESPONSE: ModelResponse = {
  status: 'needs_clarification',
  clarifyingQuestion:
    'Which log source should this detection use — Windows Security Events, Sysmon, or an EDR process table?',
  useCases: [],
};
