/**
 * Invariants for the AI Attack Surface shared vocabulary.
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import {
  ALL_CARDS, ATTACK_CHIPS, FUTURE_CARDS, GARAK_CARD, PYRIT_CARD,
  resolveAuth, splitUrl,
  type ChipKey,
} from './aiAttackSurface'

const CHIP_KEYS = Object.keys(ATTACK_CHIPS) as ChipKey[]

describe('ATTACK_CHIPS', () => {
  test('has 8 chips, each fully specified', () => {
    expect(CHIP_KEYS).toHaveLength(8)
    for (const k of CHIP_KEYS) {
      const c = ATTACK_CHIPS[k]
      expect(c.label).toBeTruthy()
      expect(c.color).toMatch(/^#[0-9a-f]{6}$/i)
      expect(c.owasp).toBeTruthy()
      expect(c.definition).toBeTruthy()
    }
  })
})

describe('cards', () => {
  test('every card chip is a known chip key', () => {
    for (const card of ALL_CARDS) {
      for (const chip of card.chips) {
        expect(CHIP_KEYS).toContain(chip)
      }
    }
  })

  test('garak probes map to known chip keys', () => {
    for (const p of GARAK_CARD.probes) {
      expect(CHIP_KEYS).toContain(p.chip)
      expect(p.id).toBeTruthy()
    }
  })

  test('garak + pyrit are available; giskard/promptfoo are greyed (future)', () => {
    expect(GARAK_CARD.available).toBe(true)
    expect(PYRIT_CARD.available).toBe(true)
    expect(FUTURE_CARDS.every((c) => !c.available)).toBe(true)
    expect(ALL_CARDS).toHaveLength(4)
    expect(ALL_CARDS[0]).toBe(GARAK_CARD)
    expect(PYRIT_CARD.probes.map((p) => p.id)).toEqual(['crescendo', 'skeleton_key'])
  })

  test('garak probe families match the documented MVP set', () => {
    const ids = GARAK_CARD.probes.map((p) => p.id).sort()
    expect(ids).toEqual(['dan', 'encoding', 'leakreplay', 'promptinject'])
  })

  test('card ids are unique', () => {
    const ids = ALL_CARDS.map((c) => c.id)
    expect(new Set(ids).size).toBe(ids.length)
  })
})

describe('resolveAuth (shared, reused by all tools)', () => {
  test('none -> no header', () => {
    expect(resolveAuth({ mode: 'none' })).toEqual({ api_key: '', auth_header: '', auth_scheme: '' })
  })
  test('bearer -> Authorization + Bearer scheme', () => {
    expect(resolveAuth({ mode: 'bearer', bearerToken: 'sk-1' }))
      .toEqual({ api_key: 'sk-1', auth_header: 'Authorization', auth_scheme: 'Bearer' })
  })
  test('custom -> named header, no scheme', () => {
    expect(resolveAuth({ mode: 'custom', headerName: 'x-api-key', headerValue: 'k' }))
      .toEqual({ api_key: 'k', auth_header: 'x-api-key', auth_scheme: '' })
  })
})

describe('splitUrl (custom target parsing)', () => {
  test('splits host and path+query', () => {
    expect(splitUrl('https://api.example.com:8443/v1/chat/completions?x=1'))
      .toEqual({ baseUrl: 'https://api.example.com:8443', path: '/v1/chat/completions?x=1' })
  })
  test('bare host -> root path', () => {
    expect(splitUrl('http://h:11434')).toEqual({ baseUrl: 'http://h:11434', path: '/' })
  })
  test('garbage -> null', () => {
    expect(splitUrl('not a url')).toBeNull()
  })
})
