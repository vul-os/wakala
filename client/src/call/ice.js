// ice.js — shared ICE-server fetch helper with STUN fallback.
//
// Both the OS fabric path (/api/peering/ice → body.ice_servers) and
// the call/TURN path (/api/turn/credentials → body.iceServers) implement
// the same fetch-with-fallback pattern. This helper centralises it so the
// fallback STUN address is defined once.
//
// Usage:
//   const servers = await fetchIce('/api/turn/credentials', {
//     responseKey: 'iceServers',        // key inside the JSON response body
//     fetchOptions: { credentials: 'include' },
//   })
//
// On any fetch error, non-ok response, or empty array the helper falls back to
//   [{ urls: ['stun:stun.l.google.com:19302'] }]

const STUN_FALLBACK = [{ urls: ['stun:stun.l.google.com:19302'] }]

/**
 * Fetch ICE servers from a relay/TURN endpoint with a STUN fallback.
 *
 * @param {string} endpoint      - URL path to GET (e.g. '/api/turn/credentials')
 * @param {object} [opts]
 * @param {string} [opts.responseKey='iceServers']  - key in the JSON body that holds the array
 * @param {object} [opts.fetchOptions={}]           - extra options forwarded to fetch()
 * @returns {Promise<Array>}     - ICE server objects; never empty
 */
export async function fetchIce(endpoint, { responseKey = 'iceServers', fetchOptions = {} } = {}) {
  try {
    const r = await fetch(endpoint, fetchOptions)
    if (r.ok) {
      const body = await r.json()
      const servers = body[responseKey]
      if (Array.isArray(servers) && servers.length) return servers
    }
  } catch { /* ignore — fall through to STUN */ }
  return STUN_FALLBACK
}
