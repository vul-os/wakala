<script lang="ts">
  import { client } from '../lib/api';
  import type { KeysDto, RotateResponse } from '../lib/types';
  import { shortHex } from '../lib/format';

  let keys = $state<KeysDto | null>(null);
  let loading = $state(true);
  let rotating = $state(false);
  let lastRotation = $state<RotateResponse | null>(null);
  let confirmOpen = $state(false);

  $effect(() => {
    (async () => {
      keys = await client.getKeys();
      loading = false;
    })();
  });

  async function rotate() {
    rotating = true;
    try {
      const res = await client.rotateKeys();
      lastRotation = res;
      keys = await client.getKeys();
      confirmOpen = false;
    } finally {
      rotating = false;
    }
  }
</script>

<div class="page">
  <div class="page-head">
    <span class="kicker">Keys</span>
    <h1>Signing identity</h1>
    <p class="lede">The operator's accountable identity (CONTRACT §2.1). Rotating generates a fresh key and re-signs the descriptor — the outgoing key is kept in history, never dropped.</p>
  </div>

  {#if loading || !keys}
    <p class="loading">Loading…</p>
  {:else}
    <div class="layout">
      <section class="panel">
        <div class="panel-header">
          <div>
            <span class="panel-kicker">Active</span>
            <h2>Current public key</h2>
          </div>
          <div class="stamp stamp-signed" aria-hidden="true">Live<br/>key</div>
        </div>
        <div class="panel-body">
          <code class="pubkey">{keys.public_key_hex}</code>

          {#if lastRotation}
            <div class="note">
              <span aria-hidden="true">◈</span>
              <span>
                Rotated from <code class="hex">{shortHex(lastRotation.old_public_key_hex)}</code> to
                <code class="hex">{shortHex(lastRotation.new_public_key_hex)}</code> — the descriptor was
                re-signed under the new key in the same operation.
              </span>
            </div>
          {/if}

          {#if !confirmOpen}
            <button type="button" class="btn btn-danger-outline" onclick={() => (confirmOpen = true)}>
              Rotate key →
            </button>
          {:else}
            <div class="confirm-box">
              <p>
                This generates a brand-new signing key, makes it current immediately, and re-signs the
                descriptor. The old key is <strong>not</strong> destroyed — it moves to history below so
                anything that referenced it stays traceable.
              </p>
              <div class="confirm-actions">
                <button type="button" class="btn" onclick={() => (confirmOpen = false)}>Cancel</button>
                <button type="button" class="btn btn-danger-outline" disabled={rotating} onclick={rotate}>
                  {rotating ? 'Rotating…' : 'Confirm rotation'}
                </button>
              </div>
            </div>
          {/if}
        </div>
      </section>

      <section class="panel">
        <div class="panel-header">
          <div>
            <span class="panel-kicker">Never cleared</span>
            <h2>Rotation history</h2>
          </div>
        </div>
        <div class="panel-body">
          {#if keys.history_hex.length === 0}
            <p class="empty">No rotations yet — this is the identity the coordinator started with.</p>
          {:else}
            <ol class="history">
              {#each keys.history_hex as h, i (h)}
                <li>
                  <span class="idx">{i + 1}</span>
                  <code class="hex">{h}</code>
                  <span class="tag">retired</span>
                </li>
              {/each}
            </ol>
          {/if}
          <div class="note">
            <span aria-hidden="true">◈</span>
            <span>Rotation re-signs the descriptor only — a tariff already attached keeps its own signature under the previous key. Re-sign the tariff separately (Pricing) if you want it under the new key too.</span>
          </div>
        </div>
      </section>
    </div>
  {/if}
</div>

<style>
  .page {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }
  .kicker {
    font-family: var(--font-mono);
    font-size: 0.72rem;
    font-weight: 500;
    letter-spacing: 0.02em;
    color: var(--text-muted);
  }
  h1 {
    font-size: 1.9rem;
    margin: 0.2rem 0 0.35rem;
  }
  .lede {
    color: var(--text-secondary);
    margin: 0;
    max-width: 68ch;
  }
  .loading,
  .empty {
    color: var(--text-tertiary);
    font-family: var(--font-mono);
    font-size: 0.85rem;
  }
  .layout {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
    gap: 1.1rem;
    align-items: start;
  }
  @media (max-width: 980px) {
    .layout {
      grid-template-columns: 1fr;
    }
  }
  .pubkey {
    display: block;
    font-size: 0.86rem;
    line-height: 1.6;
    word-break: break-all;
    background: var(--bg-base);
    border: 1px solid var(--border-default);
    border-radius: 8px;
    padding: 0.8rem 1rem;
    margin-bottom: 1rem;
    color: var(--accent);
  }
  .confirm-box {
    margin-top: 0.9rem;
    border: 1px dashed var(--status-danger);
    background: var(--status-danger-soft);
    border-radius: 9px;
    padding: 0.9rem 1rem;
  }
  .confirm-box p {
    margin: 0 0 0.8rem;
    font-size: 0.82rem;
    color: var(--text-primary);
    line-height: 1.5;
  }
  .confirm-actions {
    display: flex;
    gap: 0.6rem;
  }
  .history {
    list-style: none;
    margin: 0 0 1rem;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.55rem;
  }
  .history li {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    font-size: 0.8rem;
    background: var(--bg-base);
    border: 1px solid var(--border-default);
    border-radius: 7px;
    padding: 0.5rem 0.7rem;
  }
  .history .idx {
    font-family: var(--font-mono);
    color: var(--text-tertiary);
    width: 1.2rem;
  }
  .history code {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text-secondary);
  }
  .tag {
    font-family: var(--font-mono);
    font-size: 0.64rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-tertiary);
    border: 1px solid var(--border-strong);
    border-radius: 999px;
    padding: 0.15rem 0.5rem;
  }
</style>
