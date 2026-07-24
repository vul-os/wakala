<script lang="ts">
  import { client, ApiError } from '../lib/api';
  import type { TariffDto, ResourceKind } from '../lib/types';
  import { RESOURCE_KINDS } from '../lib/types';
  import { kindLabel, kindRecommendedPrice, kindNaturalUnitLabel, shortHex } from '../lib/format';

  let tariff = $state<TariffDto | null>(null);
  let loading = $state(true);

  let currency = $state('USD');
  let prices = $state<Record<ResourceKind, number>>({
    bytes_forwarded: 0,
    connections: 0,
    messages: 0,
    compute_seconds: 0,
  });
  let freeAllowance = $state<Record<ResourceKind, number>>({
    bytes_forwarded: 0,
    connections: 0,
    messages: 0,
    compute_seconds: 0,
  });
  let periodDays = $state(30);

  let saving = $state(false);
  let errorMsg = $state<string | null>(null);
  let published = $state(false);

  const RECOMMENDED: Record<ResourceKind, { microUsd: number; basis: string }> = {
    bytes_forwarded: { microUsd: 5, basis: 'Hetzner Cloud egress overage (~$1.2/TB) + margin' },
    connections: { microUsd: 35, basis: 'Vultr LB connection overhead, cost-plus ~3×' },
    messages: { microUsd: 12, basis: 'Amortized broker CPU + storage per message' },
    compute_seconds: { microUsd: 13, basis: 'Vultr/Hetzner shared-vCPU core-hour, cost-plus' },
  };

  $effect(() => {
    (async () => {
      const t = await client.getTariff();
      tariff = t;
      if (t) {
        currency = t.schedule.currency;
        for (const k of RESOURCE_KINDS) {
          prices[k] = t.schedule.prices[k] ?? 0;
          freeAllowance[k] = t.schedule.free_allowance[k] ?? 0;
        }
        periodDays = t.schedule.period_seconds ? Math.round(t.schedule.period_seconds / 86400) : 30;
      }
      loading = false;
    })();
  });

  function applyRecommended() {
    for (const k of RESOURCE_KINDS) prices[k] = RECOMMENDED[k].microUsd;
  }

  async function publish() {
    errorMsg = null;
    saving = true;
    published = false;
    try {
      const res = await client.putTariff({
        currency,
        prices: { ...prices },
        free_allowance: { ...freeAllowance },
        period_seconds: periodDays * 86400,
      });
      tariff = res;
      published = true;
    } catch (e) {
      errorMsg = e instanceof ApiError ? e.message : 'Could not publish the tariff.';
    } finally {
      saving = false;
    }
  }
</script>

<div class="page">
  <div class="page-head">
    <span class="kicker">03 · Pricing</span>
    <h1>Tariff schedule</h1>
    <p class="lede">Priced in an existing currency, never a protocol token (DIRECTION §5) — this UI has no field for one, on purpose.</p>
  </div>

  {#if loading}
    <p class="loading">Loading…</p>
  {:else}
    <section class="panel recommend-panel">
      <div class="panel-header">
        <div>
          <span class="panel-kicker">Reference only</span>
          <h2>Recommended USD pricing</h2>
        </div>
        <button type="button" class="btn btn-ghost" onclick={applyRecommended}>Apply to draft below →</button>
      </div>
      <div class="panel-body">
        <p class="disclaimer">
          <strong>These are recommendations, not a default you're bound to.</strong> Cost-plus estimates over
          common self-host targets (Hetzner, Vultr) at a modest margin — set your own numbers below; nothing
          in the protocol ranks or steers on price (CONTRACT §2.1, no price-rank field exists).
        </p>
        <div class="scroll-x">
          <table class="ledger">
            <thead>
              <tr>
                <th>Resource kind</th>
                <th>Recommended</th>
                <th>Basis</th>
              </tr>
            </thead>
            <tbody>
              {#each RESOURCE_KINDS as k (k)}
                <tr>
                  <td>{kindLabel(k)}</td>
                  <td class="mono price-cell">{kindRecommendedPrice(k, RECOMMENDED[k].microUsd)} / {kindNaturalUnitLabel(k)}</td>
                  <td class="basis">{RECOMMENDED[k].basis}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <div class="layout">
      <section class="panel">
        <div class="panel-header">
          <div>
            <span class="panel-kicker">Draft</span>
            <h2>Your tariff</h2>
          </div>
        </div>
        <div class="panel-body">
          <div class="field">
            <label for="currency">Currency / asset</label>
            <input id="currency" type="text" bind:value={currency} placeholder="USD" />
            <p class="field-hint">Any existing currency or asset string — USD, USDC, EUR. Never a Ephor-minted token.</p>
          </div>

          <div class="field">
            <label for="period">Billing period (days)</label>
            <input id="period" type="number" min="1" bind:value={periodDays} />
          </div>

          <div class="scroll-x">
            <table class="ledger price-table">
              <thead>
                <tr>
                  <th>Kind</th>
                  <th>Price (µ{currency}/unit)</th>
                  <th>≈ per {`{natural unit}`}</th>
                  <th>Free allowance</th>
                </tr>
              </thead>
              <tbody>
                {#each RESOURCE_KINDS as k (k)}
                  <tr>
                    <td>{kindLabel(k)}</td>
                    <td><input type="number" min="0" bind:value={prices[k]} aria-label={`Price for ${kindLabel(k)}`} /></td>
                    <td class="mono computed">{kindRecommendedPrice(k, prices[k])} / {kindNaturalUnitLabel(k)}</td>
                    <td><input type="number" min="0" bind:value={freeAllowance[k]} aria-label={`Free allowance for ${kindLabel(k)}`} /></td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>

          {#if errorMsg}
            <div class="note note-danger" role="alert">
              <span aria-hidden="true">✕</span>
              <span>{errorMsg}</span>
            </div>
          {/if}

          <button type="button" class="btn btn-primary" disabled={saving} onclick={publish}>
            {saving ? 'Signing…' : 'Sign & publish tariff'}
          </button>
          {#if published}<span class="published-flag">Published — attached to the descriptor.</span>{/if}
        </div>
      </section>

      <section class="panel">
        <div class="panel-header">
          <div>
            <span class="panel-kicker">Live</span>
            <h2>Currently signed</h2>
          </div>
          {#if tariff}<div class="stamp stamp-signed" aria-hidden="true">Signed<br/>&amp; live</div>{/if}
        </div>
        <div class="panel-body">
          {#if tariff}
            <dl>
              <dt>Currency</dt><dd>{tariff.schedule.currency}</dd>
              <dt>Signer</dt><dd class="hex">{shortHex(tariff.identity_hex)}</dd>
              <dt>Signature</dt><dd class="hex">{shortHex(tariff.sig_hex)}</dd>
              <dt>Period</dt><dd>{tariff.schedule.period_seconds ? `${Math.round(tariff.schedule.period_seconds / 86400)} days` : 'unset'}</dd>
            </dl>
            <div class="scroll-x">
              <table class="ledger">
                <thead><tr><th>Kind</th><th>Price</th><th>Free allowance</th></tr></thead>
                <tbody>
                  {#each RESOURCE_KINDS as k (k)}
                    <tr>
                      <td>{kindLabel(k)}</td>
                      <td class="mono">{kindRecommendedPrice(k, tariff.schedule.prices[k] ?? 0)} / {kindNaturalUnitLabel(k)}</td>
                      <td class="mono">{tariff.schedule.free_allowance[k] ?? 0}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {:else}
            <p class="loading">Not metered yet — no tariff has been signed for this coordinator.</p>
          {/if}
        </div>
      </section>
    </div>

    <div class="note">
      <span aria-hidden="true">◈</span>
      <span><strong>No token, ever.</strong> KOTVA mints none (CONTRACT §6, DIRECTION §5). A field to configure one doesn't exist in this form — the admin API rejects an attempt on the wire, too.</span>
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
    font-size: 0.7rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--accent);
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
  .loading {
    color: var(--text-tertiary);
    font-family: var(--font-mono);
  }
  .disclaimer {
    font-size: 0.84rem;
    color: var(--text-secondary);
    margin: 0 0 1rem;
    max-width: 72ch;
  }
  .price-cell {
    color: var(--accent);
    font-weight: 600;
  }
  .basis {
    color: var(--text-tertiary);
    font-size: 0.78rem;
  }
  .layout {
    display: grid;
    grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr);
    gap: 1.1rem;
    align-items: start;
  }
  @media (max-width: 980px) {
    .layout {
      grid-template-columns: 1fr;
    }
  }
  .price-table input {
    min-width: 5.5rem;
  }
  .computed {
    color: var(--text-tertiary);
    font-size: 0.78rem;
  }
  .btn-primary {
    margin-top: 0.6rem;
  }
  .published-flag {
    display: block;
    margin-top: 0.6rem;
    font-size: 0.78rem;
    color: var(--status-success);
    font-family: var(--font-mono);
  }
  dl {
    display: grid;
    grid-template-columns: 6.5rem 1fr;
    row-gap: 0.55rem;
    column-gap: 0.6rem;
    margin: 0 0 1rem;
    font-size: 0.84rem;
  }
  dt {
    font-family: var(--font-mono);
    font-size: 0.66rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-tertiary);
    align-self: center;
  }
  dd {
    margin: 0;
    min-width: 0;
    word-break: break-all;
  }
</style>
