/**
 * ice.test.js — fetchIce fallback posture (audit LOW — third-party reach-out).
 *
 * Default: no third-party STUN. When the host endpoint is unreachable or empty,
 * the fallback is an empty list unless the operator opts into a public STUN
 * server via host injection or build env.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { fetchIce, resolveStunFallback, GOOGLE_STUN_FALLBACK } from '../call/ice.js'

beforeEach(() => {
  globalThis.window = globalThis.window || {}
  delete window.__VULOS_ENDPOINTS__
})

afterEach(() => {
  vi.restoreAllMocks()
  delete window.__VULOS_ENDPOINTS__
})

describe('fetchIce', () => {
  it('returns server-provided ICE servers when present', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({
      ok: true,
      json: async () => ({ iceServers: [{ urls: ['turn:host:3478'] }] }),
    })))
    const servers = await fetchIce('/api/turn/credentials')
    expect(servers).toEqual([{ urls: ['turn:host:3478'] }])
  })

  it('falls back to an EMPTY list by default (no third-party reach-out)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('endpoint down') }))
    const servers = await fetchIce('/api/turn/credentials')
    expect(servers).toEqual([])
  })

  it('honours an explicit fallbackIceServers list', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ iceServers: [] }) })))
    const servers = await fetchIce('/api/turn/credentials', {
      fallbackIceServers: GOOGLE_STUN_FALLBACK,
    })
    expect(servers).toEqual(GOOGLE_STUN_FALLBACK)
  })
})

describe('resolveStunFallback', () => {
  it('defaults to an empty list', () => {
    expect(resolveStunFallback()).toEqual([])
  })

  it('opts into Google STUN via window.__VULOS_ENDPOINTS__.googleStunFallback', () => {
    window.__VULOS_ENDPOINTS__ = { googleStunFallback: true }
    expect(resolveStunFallback()).toEqual(GOOGLE_STUN_FALLBACK)
  })

  it('uses a custom injected iceServersFallback list', () => {
    const custom = [{ urls: ['stun:stun.myco.example:3478'] }]
    window.__VULOS_ENDPOINTS__ = { iceServersFallback: custom }
    expect(resolveStunFallback()).toEqual(custom)
  })
})
