'use client'

import { useEffect, useMemo, useState } from 'react'
import { AlertTriangle, Loader2, Play, ShieldAlert, Square, Terminal } from 'lucide-react'
import { useProject } from '@/providers/ProjectProvider'
import { useAiAttackSurface } from '@/hooks/useAiAttackSurface'
import {
  ALL_CARDS, ATTACK_CHIPS, GARAK_CARD,
  type ChipKey, type ToolCard,
} from '@/lib/aiAttackSurface'
import styles from './page.module.css'

function Chip({ chip, dim }: { chip: ChipKey; dim?: boolean }) {
  const m = ATTACK_CHIPS[chip]
  return (
    <span className={styles.chip} title={`${m.definition} (${m.owasp})`}
          style={{ borderColor: m.color, color: m.color, opacity: dim ? 0.35 : 1 }}>
      {m.label}
    </span>
  )
}

function sevColor(sev: string): string {
  return { critical: '#dc2626', high: '#ef4444', medium: '#f59e0b', low: '#3b82f6', info: '#9ca3af' }[sev] || '#9ca3af'
}

export default function AiAttackSurfacePage() {
  const { projectId } = useProject()
  const s = useAiAttackSurface(projectId)
  const [filter, setFilter] = useState<ChipKey | null>(null)
  const [openTool, setOpenTool] = useState<string | null>(null)

  // garak detail-view state
  const [selectedTargets, setSelectedTargets] = useState<Set<string>>(new Set())
  const [selectedProbes, setSelectedProbes] = useState<Set<string>>(new Set(['dan']))
  const [trials, setTrials] = useState(1)
  const [asrThreshold, setAsrThreshold] = useState(0.3)
  const [judgeModel, setJudgeModel] = useState('qwen2.5:7b')
  const [roeConfirmed, setRoeConfirmed] = useState(false)

  useEffect(() => {
    if (projectId) {
      s.loadTargets()
      s.loadFindings()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId])

  const hasChat = s.targets.length > 0
  const targetKey = (t: { baseUrl: string; path: string }) => `${t.baseUrl}|${t.path}`

  const cards = useMemo<ToolCard[]>(
    () => (filter ? ALL_CARDS.filter((c) => c.chips.includes(filter)) : ALL_CARDS),
    [filter],
  )

  const toggle = (set: Set<string>, key: string, apply: (s: Set<string>) => void) => {
    const next = new Set(set)
    next.has(key) ? next.delete(key) : next.add(key)
    apply(next)
  }

  const launchGarak = async () => {
    const chosen = s.targets.filter((t) => selectedTargets.has(targetKey(t)))
    await s.launch({
      tool: 'garak',
      targets: chosen.map((t) => ({ baseurl: t.baseUrl, path: t.path, method: t.method })),
      bounds: { trials, asr_threshold: asrThreshold, judge_model: judgeModel },
      roe_confirmed: roeConfirmed,
      probes: Array.from(selectedProbes),
    })
  }

  const running = s.run?.status === 'running' || s.run?.status === 'starting'
  const canLaunch = selectedTargets.size > 0 && selectedProbes.size > 0 && roeConfirmed && !s.launching && !running

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1 className={styles.title}><ShieldAlert size={22} /> AI Attack Surface</h1>
          <p className={styles.subtitle}>
            Deterministic offensive testing of the AI surface recon discovered.
            <span className={styles.discovered}> {s.targets.length} LLM endpoint(s) discovered</span>
          </p>
        </div>
      </div>

      {/* Filter bar — the shared chip vocabulary */}
      <div className={styles.filterBar}>
        <span className={styles.filterLabel}>Filter by attack:</span>
        {(Object.keys(ATTACK_CHIPS) as ChipKey[]).map((k) => (
          <button key={k} type="button"
                  className={`${styles.filterChip} ${filter === k ? styles.filterChipActive : ''}`}
                  style={{ borderColor: ATTACK_CHIPS[k].color, color: ATTACK_CHIPS[k].color }}
                  onClick={() => setFilter(filter === k ? null : k)}>
            {ATTACK_CHIPS[k].label}
          </button>
        ))}
      </div>

      {/* Card grid */}
      <div className={styles.grid}>
        {cards.map((card) => {
          const greyed = !card.available || !hasChat
          return (
            <div key={card.id} className={`${styles.card} ${greyed ? styles.cardGreyed : ''}`}>
              <div className={styles.cardChips}>
                {card.chips.map((c) => <Chip key={c} chip={c} dim={filter ? c !== filter : false} />)}
              </div>
              <div className={styles.cardName}>{card.name}
                <span className={styles.cardStyle}>{card.style}</span>
              </div>
              <div className={styles.cardPurpose}>{card.purpose}</div>
              <div className={styles.cardMeta}>
                <span className={styles.requires}>
                  Requires: {card.requires}{!hasChat && card.available ? ' (none found)' : ''}
                </span>
                <span className={styles.license}>{card.license}</span>
              </div>
              <div className={styles.cardActions}>
                {!card.available && <span className={styles.soon}>coming soon</span>}
                {card.available && (
                  <button type="button" className={styles.launchBtn} disabled={greyed}
                          onClick={() => setOpenTool(openTool === card.id ? null : card.id)}>
                    {openTool === card.id ? 'Close' : 'Configure'}
                  </button>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {/* garak detail view (four blocks) */}
      {openTool === 'garak' && (
        <div className={styles.detail}>
          <h2 className={styles.detailTitle}>garak — configure run</h2>

          {/* 1. Targets */}
          <section className={styles.block}>
            <h3 className={styles.blockTitle}>1. Targets</h3>
            {s.loadingTargets && <p className={styles.muted}>Loading…</p>}
            {!s.loadingTargets && s.targets.length === 0 && (
              <p className={styles.muted}>No llm-chat/completion endpoints in this project. Run AI Surface Recon first.</p>
            )}
            {s.targets.map((t) => {
              const k = targetKey(t)
              return (
                <label key={k} className={styles.row}>
                  <input type="checkbox" checked={selectedTargets.has(k)}
                         onChange={() => toggle(selectedTargets, k, setSelectedTargets)} />
                  <span className={styles.rowMain}>{t.baseUrl}{t.path}</span>
                  <span className={styles.rowCtx}>{t.interfaceType}{t.modelFamily ? ` · ${t.modelFamily}` : ''}</span>
                </label>
              )
            })}
          </section>

          {/* 2. Probes */}
          <section className={styles.block}>
            <h3 className={styles.blockTitle}>2. Probes</h3>
            <div className={styles.probeRow}>
              {GARAK_CARD.probes.map((p) => (
                <label key={p.id} className={styles.probe}>
                  <input type="checkbox" checked={selectedProbes.has(p.id)}
                         onChange={() => toggle(selectedProbes, p.id, setSelectedProbes)} />
                  {p.label}
                </label>
              ))}
            </div>
            <p className={styles.hint}>Whole families can be slow on CPU; start with one (e.g. dan) to validate.</p>
          </section>

          {/* 3. Run bounds */}
          <section className={styles.block}>
            <h3 className={styles.blockTitle}>3. Run bounds</h3>
            <div className={styles.boundsRow}>
              <label>Generations<input type="number" min={1} value={trials}
                     onChange={(e) => setTrials(parseInt(e.target.value) || 1)} /></label>
              <label>ASR ≥<input type="number" min={0} max={1} step={0.05} value={asrThreshold}
                     onChange={(e) => setAsrThreshold(parseFloat(e.target.value) || 0)} /></label>
              <label>Judge<input type="text" value={judgeModel}
                     onChange={(e) => setJudgeModel(e.target.value)} /></label>
            </div>
            <label className={styles.roe}>
              <input type="checkbox" checked={roeConfirmed} onChange={(e) => setRoeConfirmed(e.target.checked)} />
              <AlertTriangle size={14} /> I confirm this is an authorized, in-scope target (RoE).
            </label>
            <div className={styles.launchRow}>
              <button type="button" className={styles.primary} disabled={!canLaunch} onClick={launchGarak}>
                {s.launching ? <Loader2 size={14} className={styles.spin} /> : <Play size={14} />} Launch garak
              </button>
              {running && (
                <button type="button" className={styles.stop} onClick={s.stop}>
                  <Square size={14} /> Stop
                </button>
              )}
              {s.error && <span className={styles.err}>{s.error}</span>}
            </div>
          </section>

          {/* 4. Output */}
          <section className={styles.block}>
            <h3 className={styles.blockTitle}><Terminal size={14} /> 4. Output</h3>
            {s.run && (
              <div className={styles.status}>
                Status: <strong>{s.run.status}</strong>
                {s.phase.name && <> · Phase {s.phase.num}/4: {s.phase.name}</>}
              </div>
            )}
            {s.logs.length > 0 && (
              <pre className={styles.logs}>
                {s.logs.map((l, i) => (
                  <div key={i} className={styles[`log_${l.level}`] || styles.log_info}>{l.log}</div>
                ))}
              </pre>
            )}
          </section>
        </div>
      )}

      {/* Findings table */}
      <div className={styles.findings}>
        <h2 className={styles.detailTitle}>Findings ({s.findings.length})</h2>
        {s.findings.length === 0 && <p className={styles.muted}>No AI Attack Surface findings yet.</p>}
        {s.findings.length > 0 && (
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Tool</th><th>OWASP</th><th>Attack</th><th>Target</th>
                <th>ASR</th><th>Trials</th><th>Severity</th><th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {s.findings.map((f) => (
                <tr key={f.id}>
                  <td>{f.source}</td>
                  <td>{f.owaspLlmId}</td>
                  <td>{f.payloadClass}</td>
                  <td className={styles.tgt}>{f.target}{f.endpointPath || ''}</td>
                  <td><strong>{f.asr != null ? `${Math.round(f.asr * 100)}%` : '—'}</strong></td>
                  <td>{f.trials ?? '—'}</td>
                  <td><span className={styles.sevDot} style={{ background: sevColor(f.severity) }} />{f.severity}</td>
                  <td className={styles.ev}>{f.evidence}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
