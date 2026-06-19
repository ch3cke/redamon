'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import type { AiAttackRunState, AiFinding, AiTarget } from '@/lib/aiAttackSurface'

export interface AiAttackLogLine {
  log: string
  phase?: string | null
  phaseNumber?: number | null
  isPhaseStart?: boolean
  level: string
  timestamp: string
}

export interface LaunchPayload {
  tool: string
  targets: { baseurl: string; path: string; method?: string }[]
  bounds: { trials?: number; asr_threshold?: number; judge_model?: string; max_turns?: number }
  roe_confirmed: boolean
  dry_run?: boolean
  probes?: string[]
  target_model?: string
}

export function useAiAttackSurface(projectId: string | null) {
  const [targets, setTargets] = useState<AiTarget[]>([])
  const [findings, setFindings] = useState<AiFinding[]>([])
  const [run, setRun] = useState<AiAttackRunState | null>(null)
  const [logs, setLogs] = useState<AiAttackLogLine[]>([])
  const [phase, setPhase] = useState<{ name: string | null; num: number | null }>({ name: null, num: null })
  const [launching, setLaunching] = useState(false)
  const [loadingTargets, setLoadingTargets] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const esRef = useRef<EventSource | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const stopStream = useCallback(() => {
    esRef.current?.close()
    esRef.current = null
    if (pollRef.current) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
  }, [])

  const loadTargets = useCallback(async () => {
    if (!projectId) return
    setLoadingTargets(true)
    try {
      const r = await fetch(`/api/ai-attack-surface/${projectId}/targets`)
      const d = await r.json()
      setTargets(d.targets || [])
    } catch {
      setTargets([])
    } finally {
      setLoadingTargets(false)
    }
  }, [projectId])

  const loadFindings = useCallback(async () => {
    if (!projectId) return
    try {
      const r = await fetch(`/api/ai-attack-surface/${projectId}/findings`)
      const d = await r.json()
      setFindings(d.findings || [])
    } catch {
      /* soft */
    }
  }, [projectId])

  const pollStatus = useCallback(async (runId: string) => {
    if (!projectId) return
    try {
      const r = await fetch(`/api/ai-attack-surface/${projectId}/${runId}/status`)
      const d: AiAttackRunState = await r.json()
      setRun(d)
      if (d.status === 'completed' || d.status === 'error') {
        stopStream()
        loadFindings()
      }
    } catch {
      /* soft */
    }
  }, [projectId, stopStream, loadFindings])

  const launch = useCallback(async (payload: LaunchPayload): Promise<AiAttackRunState | null> => {
    if (!projectId) return null
    setLaunching(true)
    setError(null)
    setLogs([])
    setFindings([])
    setPhase({ name: null, num: null })
    stopStream()
    try {
      const r = await fetch(`/api/ai-attack-surface/${projectId}/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      const d = await r.json()
      if (!r.ok) throw new Error(d.error || 'Failed to launch')
      setRun(d)
      const runId = d.run_id

      const es = new EventSource(`/api/ai-attack-surface/${projectId}/${runId}/logs`)
      esRef.current = es
      es.addEventListener('log', (ev: MessageEvent) => {
        try {
          const data = JSON.parse(ev.data) as AiAttackLogLine
          setLogs((prev) => [...prev, data])
          if (data.isPhaseStart && data.phase) {
            setPhase({ name: data.phase, num: data.phaseNumber ?? null })
          }
        } catch {
          /* ignore malformed line */
        }
      })
      es.onerror = () => {
        es.close()
      }

      pollRef.current = setInterval(() => pollStatus(runId), 3000)
      return d
    } catch (e) {
      const m = e instanceof Error ? e.message : 'Launch failed'
      setError(m)
      return null
    } finally {
      setLaunching(false)
    }
  }, [projectId, pollStatus, stopStream])

  const stop = useCallback(async () => {
    if (!projectId || !run?.run_id) return
    try {
      await fetch(`/api/ai-attack-surface/${projectId}/${run.run_id}/stop`, { method: 'POST' })
    } catch {
      /* soft */
    }
    stopStream()
    pollStatus(run.run_id)
  }, [projectId, run, stopStream, pollStatus])

  useEffect(() => () => stopStream(), [stopStream])

  return {
    targets, findings, run, logs, phase, launching, loadingTargets, error,
    loadTargets, loadFindings, launch, stop,
  }
}
