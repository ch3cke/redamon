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

// PyRIT (Step 6) — bounded multi-turn. Its "probes" are the attack strategies;
// they flow through the same `probes` field garak uses.
export const PYRIT_CARD: ToolCard = {
  id: 'pyrit',
  name: 'PyRIT',
  license: 'MIT',
  style: 'multi-turn',
  purpose: 'Bounded multi-turn jailbreaks',
  requires: 'chat',
  chips: ['jailbreak', 'prompt-injection', 'system-prompt-leak'],
  probes: [
    { id: 'crescendo', label: 'Crescendo (gradual escalation)', chip: 'jailbreak' },
    { id: 'skeleton_key', label: 'Skeleton Key (safety override)', chip: 'jailbreak' },
  ],
  available: true,
}

// Future tools — shown greyed until their adapter ships (Steps 7-8).
export const FUTURE_CARDS: ToolCard[] = [
  { id: 'giskard', name: 'giskard', license: 'Apache-2.0', style: 'scan', purpose: 'Quality + safety scan', requires: 'chat', chips: ['hallucination', 'bias', 'prompt-injection', 'toxicity', 'data-disclosure'], probes: [], available: false },
  { id: 'promptfoo', name: 'promptfoo', license: 'MIT', style: 'eval', purpose: 'Red-team eval + ASR', requires: 'chat', chips: ['prompt-injection', 'jailbreak', 'data-disclosure', 'toxicity'], probes: [], available: false },
]

export const ALL_CARDS: ToolCard[] = [GARAK_CARD, PYRIT_CARD, ...FUTURE_CARDS]
// Tools whose detail view + launch are wired in the UI.
export const ACTIVE_CARDS: ToolCard[] = ALL_CARDS.filter((c) => c.available)

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

// --- Target authentication (shared across all tools) ---------------------- //
// Three UI modes resolve to the {api_key, auth_header, auth_scheme} the backend
// applies. Reusable by every tool's detail view (PyRIT/giskard/promptfoo).
export type AuthMode = 'none' | 'bearer' | 'custom'

export interface AuthConfig {
  mode: AuthMode
  bearerToken?: string   // bearer mode
  headerName?: string    // custom mode (e.g. x-api-key, api-key, X-Authorization)
  headerValue?: string   // custom mode key value
}

export interface ResolvedAuth {
  api_key: string
  auth_header: string
  auth_scheme: string
}

export function resolveAuth(a: AuthConfig): ResolvedAuth {
  if (a.mode === 'bearer') {
    return { api_key: a.bearerToken || '', auth_header: 'Authorization', auth_scheme: 'Bearer' }
  }
  if (a.mode === 'custom') {
    return { api_key: a.headerValue || '', auth_header: (a.headerName || '').trim(), auth_scheme: '' }
  }
  return { api_key: '', auth_header: '', auth_scheme: '' }
}

// --- Custom (off-graph) target -------------------------------------------- //
// Attack an arbitrary URL not discovered by recon. Shared across tools.
export interface CustomTarget {
  baseUrl: string
  path: string
  method: string
  interfaceType: string   // llm-chat / llm-completion (drives the request shape)
  model: string
}

/** Split a full URL into {baseUrl, path}. Returns null if unparseable. */
export function splitUrl(raw: string): { baseUrl: string; path: string } | null {
  try {
    const u = new URL(raw.trim())
    const baseUrl = `${u.protocol}//${u.host}`
    const path = (u.pathname || '/') + (u.search || '')
    return { baseUrl, path }
  } catch {
    return null
  }
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
