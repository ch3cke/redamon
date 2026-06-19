/**
 * Render tests for the AI Attack Surface page. The provider + hook are mocked
 * so we assert the rendering logic (card grid, chips, greying, findings table).
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'

// vitest config has no globals:true, so RTL's auto-cleanup never registers —
// unmount between tests so renders don't accumulate in the DOM.
afterEach(cleanup)

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ projectId: 'p1' }) }))

const hookState = {
  targets: [] as unknown[],
  findings: [] as unknown[],
  run: null as unknown,
  logs: [] as unknown[],
  phase: { name: null, num: null },
  launching: false,
  loadingTargets: false,
  error: null,
  loadTargets: vi.fn(),
  loadFindings: vi.fn(),
  launch: vi.fn(),
  stop: vi.fn(),
}
vi.mock('@/hooks/useAiAttackSurface', () => ({ useAiAttackSurface: () => hookState }))

const AiAttackSurfacePage = (await import('./page')).default

beforeEach(() => {
  hookState.targets = []
  hookState.findings = []
  hookState.run = null
  hookState.logs = []
})

describe('AI Attack Surface page', () => {
  test('renders the title and the four tool cards', () => {
    render(<AiAttackSurfacePage />)
    expect(screen.getByText('AI Attack Surface')).toBeTruthy()
    expect(screen.getByText('garak')).toBeTruthy()
    expect(screen.getByText('PyRIT')).toBeTruthy()
    expect(screen.getByText('giskard')).toBeTruthy()
    expect(screen.getByText('promptfoo')).toBeTruthy()
  })

  test('renders the shared chip vocabulary in the filter bar', () => {
    render(<AiAttackSurfacePage />)
    expect(screen.getAllByText('Prompt Injection').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Jailbreak').length).toBeGreaterThan(0)
    // Hallucination appears in the filter bar AND the giskard card chips.
    expect(screen.getAllByText('Hallucination').length).toBeGreaterThan(0)
  })

  test('shows discovered count from targets', () => {
    hookState.targets = [{ baseUrl: 'http://h', path: '/c' }]
    render(<AiAttackSurfacePage />)
    expect(screen.getByText(/1 LLM endpoint\(s\) discovered/)).toBeTruthy()
  })

  test('renders findings table rows with ASR percentage', () => {
    hookState.findings = [{
      id: 'aiatk_1', source: 'garak', owaspLlmId: 'LLM01', payloadClass: 'garak-dan',
      target: 'http://h', endpointPath: '/v1/chat/completions', asr: 1.0, trials: 1,
      severity: 'high', evidence: 'dan.Dan_11_0/dan.DAN hits=1/1',
    }]
    render(<AiAttackSurfacePage />)
    expect(screen.getByText('Findings (1)')).toBeTruthy()
    expect(screen.getByText('garak-dan')).toBeTruthy()
    expect(screen.getByText('100%')).toBeTruthy()
    expect(screen.getByText('LLM01')).toBeTruthy()
  })

  test('garak Configure stays enabled with no endpoint (custom targets allowed)', () => {
    render(<AiAttackSurfacePage />)   // targets = [] by default
    const btn = screen.getAllByText('Configure')[0] as HTMLButtonElement
    expect(btn.disabled).toBe(false)
  })

  test('opening garak with no endpoints still shows the custom-target form + auth', () => {
    render(<AiAttackSurfacePage />)
    fireEvent.click(screen.getAllByText('Configure')[0])
    expect(screen.getByText(/Attack a URL not in the graph/)).toBeTruthy()
    expect(screen.getByText('Target authentication')).toBeTruthy()
    expect(screen.getByText('Bearer token')).toBeTruthy()
  })

  test('opening garak (with a target) shows the four-block detail + the target row', () => {
    hookState.targets = [{ baseUrl: 'http://h:8000', path: '/v1/chat/completions', method: 'POST', interfaceType: 'llm-chat', modelFamily: 'qwen' }]
    render(<AiAttackSurfacePage />)
    fireEvent.click(screen.getAllByText('Configure')[0])   // garak is first
    expect(screen.getByText('1. Targets')).toBeTruthy()
    expect(screen.getByText('2. Probes')).toBeTruthy()
    expect(screen.getByText('3. Run bounds')).toBeTruthy()
    expect(screen.getByText('http://h:8000/v1/chat/completions')).toBeTruthy()
  })

  test('opening PyRIT shows the multi-turn strategy block + Max turns', () => {
    render(<AiAttackSurfacePage />)
    // garak + pyrit both have a Configure button; pyrit is the second.
    fireEvent.click(screen.getAllByText('Configure')[1])
    expect(screen.getByText('PyRIT — configure run')).toBeTruthy()
    expect(screen.getByText('2. Attack strategies')).toBeTruthy()
    expect(screen.getByText(/Crescendo/)).toBeTruthy()
    expect(screen.getByText('Max turns')).toBeTruthy()
    expect(screen.getByText('Launch PyRIT')).toBeTruthy()
  })
})
