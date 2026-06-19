// Shared vocabulary + types for the AI Attack Surface operator page.
// The chip set is the single source of truth (§3): one mapping drives chip
// labels, colors, and OWASP-LLM links across the grid and the detail view.

export type ChipKey =
  | 'prompt-injection'
  | 'jailbreak'
  | 'system-prompt-leak'
  | 'data-disclosure'
  | 'encoding-bypass'
  | 'toxicity'
  | 'bias'
  | 'hallucination'

export interface ChipMeta {
  label: string
  color: string
  owasp: string
  definition: string
}

export const ATTACK_CHIPS: Record<ChipKey, ChipMeta> = {
  'prompt-injection': { label: 'Prompt Injection', color: '#ef4444', owasp: 'LLM01', definition: 'Make the model follow attacker instructions' },
  jailbreak: { label: 'Jailbreak', color: '#f97316', owasp: 'LLM01', definition: 'Bypass safety rules (DAN, crescendo, skeleton key)' },
  'system-prompt-leak': { label: 'System Prompt Leak', color: '#a855f7', owasp: 'LLM07', definition: 'Extract the hidden system prompt' },
  'data-disclosure': { label: 'Data Disclosure', color: '#3b82f6', owasp: 'LLM02', definition: 'Leak secrets / training data / PII' },
  'encoding-bypass': { label: 'Encoding Bypass', color: '#92400e', owasp: 'LLM01', definition: 'Smuggle payloads via base64/rot13/unicode' },
  toxicity: { label: 'Toxicity / Harmful', color: '#eab308', owasp: 'safety', definition: 'Force toxic or harmful output' },
  bias: { label: 'Bias / Stereotypes', color: '#22c55e', owasp: 'safety', definition: 'Surface discriminatory behavior' },
  hallucination: { label: 'Hallucination', color: '#9ca3af', owasp: 'LLM09', definition: 'Confident false answers / misinformation' },
}

export interface ProbeOption {
  id: string        // garak probe family
  label: string
  chip: ChipKey
}

export interface ToolCard {
  id: string
  name: string
  license: string
  style: string         // single-shot / multi-turn / scan / eval
  purpose: string
  requires: string      // surface needed (chat / tool-call / vector-db)
  chips: ChipKey[]
  probes: ProbeOption[]
  available: boolean    // false => greyed (adapter not shipped yet)
}

export const GARAK_CARD: ToolCard = {
  id: 'garak',
  name: 'garak',
  license: 'Apache-2.0',
  style: 'single-shot',
  purpose: 'Broad LLM vulnerability scanner',
  requires: 'chat',
  chips: ['prompt-injection', 'jailbreak', 'system-prompt-leak', 'encoding-bypass', 'data-disclosure', 'toxicity'],
  probes: [
    { id: 'promptinject', label: 'Prompt Injection (promptinject)', chip: 'prompt-injection' },
    { id: 'dan', label: 'Jailbreak (dan)', chip: 'jailbreak' },
    { id: 'encoding', label: 'Encoding Bypass (encoding)', chip: 'encoding-bypass' },
    { id: 'leakreplay', label: 'Data / Leak Replay (leakreplay)', chip: 'data-disclosure' },
  ],
  available: true,
}

// Future tools — shown greyed until their adapter ships (Steps 6-8).
export const FUTURE_CARDS: ToolCard[] = [
  { id: 'pyrit', name: 'PyRIT', license: 'MIT', style: 'multi-turn', purpose: 'Bounded multi-turn jailbreaks', requires: 'chat', chips: ['jailbreak', 'prompt-injection', 'system-prompt-leak'], probes: [], available: false },
  { id: 'giskard', name: 'giskard', license: 'Apache-2.0', style: 'scan', purpose: 'Quality + safety scan', requires: 'chat', chips: ['hallucination', 'bias', 'prompt-injection', 'toxicity', 'data-disclosure'], probes: [], available: false },
  { id: 'promptfoo', name: 'promptfoo', license: 'MIT', style: 'eval', purpose: 'Red-team eval + ASR', requires: 'chat', chips: ['prompt-injection', 'jailbreak', 'data-disclosure', 'toxicity'], probes: [], available: false },
]

export const ALL_CARDS: ToolCard[] = [GARAK_CARD, ...FUTURE_CARDS]

export interface AiTarget {
  baseUrl: string
  path: string
  method: string
  interfaceType: string | null
  modelFamily: string | null
  modelIds: string[]
  supportsTools: boolean | null
  streaming: boolean | null
}

export interface AiFinding {
  id: string
  source: string
  name: string
  severity: string
  type: string
  owaspLlmId: string | null
  asr: number | null
  trials: number | null
  payloadClass: string | null
  oracleKind: string | null
  atlasTechnique: string | null
  probePackVersion: string | null
  transcriptRef: string | null
  evidence: string | null
  description: string | null
  targetType: string | null
  target: string | null
  endpointPath: string | null
}

export type AiAttackStatus = 'idle' | 'starting' | 'running' | 'completed' | 'error' | 'stopping'

export interface AiAttackRunState {
  project_id: string
  run_id: string
  tool: string
  status: AiAttackStatus
  current_phase?: string | null
  phase_number?: number | null
  total_phases?: number
  error?: string | null
}
