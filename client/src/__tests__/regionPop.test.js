/**
 * regionPop.test.js — unit tests for region-aware PoP selection (Phase-0).
 *
 * Covers:
 *   • Known region returns the mapped PoP (eu → eu.relay.vulos.app)
 *   • Unknown region falls back to defaultPop
 *   • Undefined/falsy region falls back to defaultPop
 *   • No region + no default → undefined (pure same-origin / no-op path)
 *   • Case-insensitivity (EU → eu.relay.vulos.app)
 *   • REGION_POP_MAP is exported and contains the eu entry
 */

import { describe, it, expect } from 'vitest'
import { REGION_POP_MAP, selectPop } from '../regionPop.js'

describe('REGION_POP_MAP', () => {
  it('exports an object with an eu entry', () => {
    expect(typeof REGION_POP_MAP).toBe('object')
    expect(REGION_POP_MAP.eu).toBe('eu.relay.vulos.app')
  })
})

describe('selectPop', () => {
  it('returns the mapped PoP for a known region', () => {
    expect(selectPop('eu')).toBe('eu.relay.vulos.app')
  })

  it('returns the mapped PoP for a known region ignoring case', () => {
    expect(selectPop('EU')).toBe('eu.relay.vulos.app')
    expect(selectPop('Eu')).toBe('eu.relay.vulos.app')
  })

  it('returns defaultPop for an unknown region', () => {
    expect(selectPop('us', 'relay.vulos.app')).toBe('relay.vulos.app')
    expect(selectPop('ap', 'relay.vulos.app')).toBe('relay.vulos.app')
  })

  it('returns undefined for an unknown region with no default', () => {
    expect(selectPop('us')).toBeUndefined()
  })

  it('returns defaultPop when region is undefined', () => {
    expect(selectPop(undefined, 'relay.vulos.app')).toBe('relay.vulos.app')
  })

  it('returns defaultPop when region is an empty string', () => {
    expect(selectPop('', 'relay.vulos.app')).toBe('relay.vulos.app')
  })

  it('returns undefined when both region and defaultPop are omitted', () => {
    expect(selectPop()).toBeUndefined()
  })

  it('region match takes precedence over defaultPop', () => {
    expect(selectPop('eu', 'relay.vulos.app')).toBe('eu.relay.vulos.app')
  })
})
