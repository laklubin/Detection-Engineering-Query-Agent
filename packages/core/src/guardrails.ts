/**
 * Scope and safety guardrails.
 *
 * These checks run in backend application logic BEFORE an inference request is
 * constructed. A rejected request is never forwarded to Hugging Face. The
 * system prompt repeats the policy, but the system prompt is defence in depth,
 * not the control itself.
 *
 * Design note on false positives: security engineers legitimately describe
 * attacker behaviour ("detect ransomware canary-file encryption", "alert on EDR
 * tampering"). The classifier therefore evaluates the *requested action*, not
 * the mere presence of adversarial vocabulary: an authoring verb pointed at an
 * offensive artefact is blocked, while the same vocabulary inside detection
 * framing is allowed.
 */

import { OFF_TOPIC_REJECTION_MESSAGE } from './constants.js';

export const GUARDRAIL_CATEGORIES = [
  'prompt_injection',
  'secret_extraction',
  'policy_override',
  'offensive_tooling',
  'software_development',
  'no_detection_intent',
] as const;
export type GuardrailCategory = (typeof GUARDRAIL_CATEGORIES)[number];

export interface GuardrailPass {
  readonly allowed: true;
  /** Detection-intent signals observed, for observability only. */
  readonly signals: readonly string[];
}

export interface GuardrailBlock {
  readonly allowed: false;
  readonly category: GuardrailCategory;
  /** Verbatim user-facing message. Never templated or reworded. */
  readonly userMessage: typeof OFF_TOPIC_REJECTION_MESSAGE;
  /** Internal rule id for metrics. Not shown to the user. */
  readonly rule: string;
}

export type GuardrailResult = GuardrailPass | GuardrailBlock;

/**
 * Canonical form used for pattern matching: lowercase, punctuation collapsed to
 * single spaces. Defeats spacing/punctuation obfuscation such as
 * "i.g.n.o.r.e   previous,,, instructions".
 */
export function canonicalise(text: string): string {
  return text
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
}

interface Rule {
  readonly id: string;
  readonly category: GuardrailCategory;
  readonly pattern: RegExp;
}

/**
 * Unconditional blocks. These phrasings have no legitimate detection-engineering
 * reading, so no defensive-framing exemption applies.
 */
const HARD_RULES: readonly Rule[] = [
  // --- prompt injection / instruction override ---------------------------
  { id: 'inj.ignore_instructions', category: 'prompt_injection', pattern: /\b(?:ignore|disregard|forget|override|bypass|skip)\s+(?:all\s+|any\s+|the\s+|your\s+|my\s+|previous\s+|prior\s+|above\s+|earlier\s+|preceding\s+){0,3}(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions|guideline|guidelines|constraint|constraints|context|system)\b/ },
  { id: 'inj.new_persona', category: 'prompt_injection', pattern: /\byou\s+are\s+(?:now|no\s+longer)\b|\bact\s+as\s+(?:if\s+you\s+are\s+)?(?:an?\s+)?(?:unrestricted|uncensored|unfiltered|jailbroken|different|evil|dan)\b|\bdeveloper\s+mode\b|\bjailbreak\b|\bdo\s+anything\s+now\b/ },
  { id: 'inj.reveal_prompt', category: 'prompt_injection', pattern: /\b(?:reveal|show|print|output|repeat|disclose|dump|leak|echo|display)\b(?:\s+\w+){0,4}\s+(?:system\s+prompt|system\s+message|initial\s+instructions|hidden\s+instructions|developer\s+instructions|instructions\s+above|prompt\s+above|your\s+instructions|your\s+prompt|your\s+rules|your\s+configuration)\b/ },
  { id: 'inj.role_markup', category: 'prompt_injection', pattern: /\b(?:begin|end)\s+(?:of\s+)?system\b|\bim\s+start\b|\bim\s+end\b|\b(?:system|assistant)\s*:\s*you\s+(?:must|will|should)\b/ },
  { id: 'inj.pretend_authority', category: 'prompt_injection', pattern: /\b(?:as|i\s+am)\s+(?:the\s+)?(?:developer|administrator|admin|owner|author)\s+(?:of\s+)?(?:this\s+)?(?:app|application|system|platform|agent)\b(?:\s+\w+){0,6}\s+(?:you\s+(?:must|will|can|should)|disable|turn\s+off|remove)\b/ },

  // --- secret / token extraction -----------------------------------------
  { id: 'sec.reveal_token', category: 'secret_extraction', pattern: /\b(?:reveal|show|print|give|tell|send|expose|leak|dump|output|display|what\s+is|whats)\b(?:\s+\w+){0,5}\s+(?:api\s*key|api\s*token|access\s*token|auth\s*token|bearer\s*token|secret\s*key|hf\s*token|hugging\s*face\s*token|private\s*key|credential|credentials|password|env\s*var|environment\s*variable)\b/ },
  { id: 'sec.token_name', category: 'secret_extraction', pattern: /\bhf\s*token\b(?:\s+\w+){0,4}\s*(?:value|please|here|now)\b|\bprocess\s+env\b|\bdotenv\b|\bcat\s+env\b|\bprint\s+env\b/ },
  { id: 'sec.exfil_backend', category: 'secret_extraction', pattern: /\b(?:send|post|forward|upload|transmit|exfiltrate)\b(?:\s+\w+){0,4}\s+(?:token|secret|key|credential|credentials)\b(?:\s+\w+){0,4}\s+(?:to|at)\b/ },

  // --- policy / product-guardrail tampering ------------------------------
  { id: 'pol.change_policy', category: 'policy_override', pattern: /\b(?:change|modify|update|relax|disable|turn\s+off|remove|drop|lift|raise|increase|bypass|circumvent)\b(?:\s+\w+){0,4}\s+(?:security\s+policy|safety\s+policy|guardrail|guardrails|content\s+filter|restriction|restrictions|limitation|limitations|use\s+case\s+limit|rate\s+limit|sanitisation|sanitization|validation)\b/ },
  { id: 'pol.notice_removal', category: 'policy_override', pattern: /\b(?:remove|hide|delete|suppress|omit|do\s+not\s+(?:show|display|include)|dont\s+(?:show|display|include))\b(?:\s+\w+){0,5}\s+(?:commercial|contact|notice|disclaimer|footer|lubin)\b/ },
  { id: 'pol.more_than_two', category: 'policy_override', pattern: /\b(?:generate|give|produce|create|return|output)\b(?:\s+\w+){0,3}\s+(?:more\s+than\s+(?:two|2)|(?:[3-9]|\d\d+)\s+(?:use\s*cases?|usecases?|detections?))\b|\bignore\s+the\s+(?:two|2)\s+use\s*case\s+limit\b|\bunlimited\s+use\s*cases?\b/ },
];

/** Authoring verbs that indicate the user wants an artefact built. */
const AUTHORING_VERB =
  /\b(?:write|create|build|develop|generate|produce|make|code|implement|craft|design|script|program|compile|deploy|launch|execute|run)\b/gi;

/** Offensive artefacts. An authoring verb aimed at these is prohibited. */
const OFFENSIVE_OBJECT =
  /\b(?:ransomware|malware|virus|worm|trojan|keylogger|key\s*logger|rootkit|bootkit|botnet|spyware|infostealer|stealer|exploit|exploits|0\s*day|zero\s*day|payload|payloads|shellcode|reverse\s*shell|bind\s*shell|web\s*shell|webshell|backdoor|implant|c2|command\s+and\s+control|beacon|dropper|loader|wiper|cryptolocker|crypter|packer|phishing\s+(?:kit|page|site|email|template)|credential\s+harvester|password\s+cracker|brute\s*forcer|ddos|dos\s+attack|denial\s+of\s+service|port\s*scanner|vulnerability\s+scanner|privilege\s+escalation\s+(?:tool|exploit|script)|lateral\s+movement\s+(?:tool|script)|data\s+exfiltration\s+(?:tool|script)|anti\s*forensics|log\s+(?:wiper|cleaner))\b/i;

/** Non-security software artefacts. */
const SOFTWARE_OBJECT =
  /\b(?:python\s+(?:program|script|app|application|code|function|class)|javascript\s+(?:program|app|code|function)|java\s+(?:program|application|class)|c\s*\+\+\s+program|go\s+program|rust\s+program|bash\s+script|shell\s+script|powershell\s+script|web\s*site|website|web\s+page|webpage|html\s+page|landing\s+page|react\s+(?:app|component|website)|vue\s+(?:app|component)|angular\s+app|mobile\s+app|android\s+app|ios\s+app|rest\s+api|crud\s+app|todo\s+app|game|chatbot|calculator|spreadsheet|resume|cv|cover\s+letter|blog\s+post|poem|song|story|essay|recipe|business\s+plan|sql\s+(?:database|schema|table)|docker\s*file|kubernetes\s+manifest|terraform\s+(?:module|config)|ci\s+pipeline|unit\s+tests?\s+for\s+my)\b/i;

/**
 * Detection-engineering framing. Presence of one of these inside the clause
 * flips an otherwise offensive-looking phrase into a legitimate defensive ask.
 */
const DEFENSIVE_MARKER =
  /\b(?:detect|detects|detecting|detection|detections|alert|alerts|alerting|rule|rules|ruleset|query|queries|search|sigma|spl|kql|aql|eql|esql|spotter|siem|soc|hunt|hunts|hunting|threat\s*hunt|identify|identifies|monitor|monitors|monitoring|flag|flags|correlate|correlation|use\s*case|usecase|signature|signatures|analytic|analytics|telemetry|log\s*source|logsource|event\s*id|baseline|anomaly|triage|notable|offense|indicator|ioc|mitre|att&ck|attack|technique|tactic)\b/i;

/** Positive detection-intent signals required for a request to proceed. */
const DETECTION_SIGNALS: readonly { id: string; pattern: RegExp }[] = [
  { id: 'detect_verb', pattern: /\b(?:detect|detects|detection|detecting|alert|alerting|identify|monitor|monitoring|flag|surface|spot|catch|hunt|hunting|triage|investigate)\b/i },
  { id: 'rule_artifact', pattern: /\b(?:rule|rules|query|queries|search|use\s*case|usecase|signature|analytic|analytics|correlation|notable|offense|dashboard|sigma|spl|kql|aql|eql|esql|yara|spotter)\b/i },
  { id: 'siem_platform', pattern: /\b(?:siem|splunk|sentinel|qradar|elastic|elasticsearch|securonix|fortisiem|chronicle|sumo\s*logic|exabeam|arcsight|soc|xdr|edr)\b/i },
  { id: 'telemetry', pattern: /\b(?:log|logs|logging|logins?|logons?|authentication|authenticate[sd]?|event|events|event\s*id|telemetry|sysmon|auditd|cloudtrail|sign\s*-?\s*ins?|firewall|proxy|dns|netflow|edr|winlog|eventlog|syslog|network|traffic|connections?|egress|endpoints?|hosts?|workstations?|servers?|process(?:es)?|command\s*line)\b/i },
  {
    id: 'threat_behaviour',
    pattern:
      /\b(?:suspicious|malicious|anomalous|unauthori[sz]ed|lateral\s+movement|lateral|privilege\s+escalation|persistence|exfiltration|exfil|command\s+and\s+control|brute\s*force|password\s+spray(?:ing)?|credential\s+(?:access|dumping|theft)|credentials?|phishing|ransomware|beacon(?:ing)?|living\s+off\s+the\s+land|impossible\s+travel|improbable\s+travel|failed\s+log(?:in|on)s?|account\s+lockouts?|lockouts?|mfa\s+fatigue|token\s+theft|dll\s+(?:injection|side\s*loading)|process\s+injection|defense\s+evasion|tamper(?:ing)?|web\s*shells?|shadow\s+cop(?:y|ies)|scheduled\s+tasks?|run\s+keys?|autoruns?|encoded\s+command|obfuscat(?:ed|ion)|malware|trojan|backdoors?|rootkits?|keyloggers?|spyware|droppers?|tunnel(?:ling|ing)?|intrusion|compromise[ds]?)\b/i,
  },
  { id: 'mitre', pattern: /\b(?:mitre|att&ck|attack)\b|\bT\d{4}(?:\.\d{3})?\b/i },
];

/** Split text into clause-sized windows for contextual evaluation. */
function clauseAt(text: string, index: number): string {
  const tail = text.slice(index, index + 160);
  const boundary = tail.search(/[.;!?\n]/);
  return boundary === -1 ? tail : tail.slice(0, boundary + 1);
}

function findObjectRequest(
  text: string,
  objectPattern: RegExp,
): { verb: string; clause: string } | null {
  AUTHORING_VERB.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = AUTHORING_VERB.exec(text)) !== null) {
    const clause = clauseAt(text, match.index);
    if (!objectPattern.test(clause)) continue;
    if (DEFENSIVE_MARKER.test(clause)) continue;
    return { verb: match[0], clause };
  }
  return null;
}

export interface GuardrailInput {
  /** Already-sanitised requirement text. */
  readonly requirement: string;
  /** True when the user picked an allowlisted vendor. */
  readonly hasVendor: boolean;
  /** True when the user picked an allowlisted log source. */
  readonly hasLogSource: boolean;
}

function block(category: GuardrailCategory, rule: string): GuardrailBlock {
  return { allowed: false, category, userMessage: OFF_TOPIC_REJECTION_MESSAGE, rule };
}

/**
 * Classify a sanitised requirement. Pure function — no I/O, no model call.
 */
export function evaluateGuardrails(input: GuardrailInput): GuardrailResult {
  const canon = canonicalise(input.requirement);

  // 1. Unconditional blocks -------------------------------------------------
  for (const rule of HARD_RULES) {
    if (rule.pattern.test(canon)) {
      return block(rule.category, rule.id);
    }
  }

  // 2. Offensive artefact authoring ----------------------------------------
  const offensive = findObjectRequest(input.requirement, OFFENSIVE_OBJECT);
  if (offensive) {
    return block('offensive_tooling', 'off.authoring_request');
  }
  // Explicit evasion/weaponisation asks without any defensive framing.
  if (
    /\b(?:evade|bypass|defeat|disable|tamper\s+with|turn\s+off|uninstall|kill)\b(?:\s+\w+){0,4}\s+(?:detection|edr|av|antivirus|defender|siem|logging|audit|monitoring|sysmon)\b/i.test(
      canon,
    ) &&
    !DEFENSIVE_MARKER.test(input.requirement)
  ) {
    return block('offensive_tooling', 'off.evasion_request');
  }

  // 3. General software development ----------------------------------------
  const software = findObjectRequest(input.requirement, SOFTWARE_OBJECT);
  if (software) {
    return block('software_development', 'dev.authoring_request');
  }

  // 4. Positive detection intent ------------------------------------------
  const signals = DETECTION_SIGNALS.filter((s) => s.pattern.test(input.requirement)).map((s) => s.id);
  const selectorContext = input.hasVendor && input.hasLogSource;
  // A selector pair plus any single signal is enough; free text needs two.
  const required = selectorContext ? 1 : 2;
  if (signals.length < required) {
    return block('no_detection_intent', 'intent.insufficient_signal');
  }

  return { allowed: true, signals };
}

/**
 * Secondary guardrail applied to MODEL OUTPUT before rendering. Model text is
 * untrusted: if it echoes injected instructions or anything credential-shaped,
 * the response is discarded rather than displayed.
 */
export function evaluateModelOutputSafety(serialised: string): GuardrailResult {
  const canon = canonicalise(serialised);
  for (const rule of HARD_RULES) {
    if (rule.category === 'no_detection_intent') continue;
    if (rule.pattern.test(canon)) {
      return block(rule.category, `model.${rule.id}`);
    }
  }
  if (/\bhf_[A-Za-z0-9]{16,}\b|-----BEGIN[A-Z ]*PRIVATE KEY-----|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\./.test(serialised)) {
    return block('secret_extraction', 'model.credential_shaped_output');
  }
  return { allowed: true, signals: [] };
}
