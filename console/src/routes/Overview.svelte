<script lang="ts">
  import { client, IS_MOCK } from '../lib/api';
  import type { ReportDto, ReceiptsResponse, PrepaidAccount, SignedDescriptorDto } from '../lib/types';
  import VisibilityBadge from '../lib/components/VisibilityBadge.svelte';
  import ConformanceStrip from '../lib/components/ConformanceStrip.svelte';
  import StatCard from '../lib/components/StatCard.svelte';
  import { ledgerMoney, kindQuantity, kindLabel, integer } from '../lib/format';
  import { router } from '../lib/router.svelte';
  import type { ResourceKind } from '../lib/types';
  import { RESOURCE_KINDS } from '../lib/types';

  let descriptor = $state<SignedDescriptorDto | null>(null);
  let conformance = $state<ReportDto | null>(null);
  let receipts = $state<ReceiptsResponse | null>(null);
  let accounts = $state<PrepaidAccount[]>([]);
  let loading = $state(true);

  const UPTIME_SINCE = new Date('2026-06-11T08:00:00Z');
  const now = new Date('2026-07-23T14:00:00Z');
  const uptimeMs = now.getTime() - UPTIME_SINCE.getTime();
  const uptimeDays = Math.floor(uptimeMs / 86_400_000);
  const uptimeHours = Math.floor((uptimeMs % 86_400_000) / 3_600_000);

  $effect(() => {
    (async () => {
      loading = true;
      const [d, c, r, a] = await Promise.all([
        client.getDescriptor(),
        client.getConformance(),
        client.getReceipts(),
        client.getPrepaidAccounts(),
      ]);
      descriptor = d;
      conformance = c;
      receipts = r;
      accounts = a;
      loading = false;
    })();
  });

  let usageTotals = $derived.by(() => {
    const totals: Partial<Record<ResourceKind, number>> = {};
    for (const r of receipts?.receipts ?? []) {
      totals[r.kind] = (totals[r.kind] ?? 0) + r.metered_units;
    }
    return totals;
  });

  let totalBalance = $derived(accounts.reduce((sum, a) => sum + a.balance_minor, 0));
  let lowBalanceCount = $derived(accounts.filter((a) => a.balance_minor < a.low_balance_threshold_minor).length);
  let currency = $derived(accounts[0]?.currency ?? 'USD');
</script>

<div class="page">
  <div class="page-head">
    <div>
      <span class="kicker">01 · Overview</span>
      <h1>Bridge deck</h1>
      <p class="lede">The coordinator's declared posture and the numbers an operator checks first.</p>
    </div>
  </div>

  {#if loading || !descriptor || !conformance}
    <p class="loading">Reading the current signed descriptor…</p>
  {:else}
    <div class="grid-top">
      <section class="panel visibility-panel">
        <div class="panel-header">
          <div>
            <span class="panel-kicker">Kind · {descriptor.kind}</span>
            <h2>Declared content-visibility</h2>
          </div>
          <button class="btn btn-ghost" type="button" onclick={() => router.go('descriptor')}>Edit descriptor →</button>
        </div>
        <div class="panel-body">
          <VisibilityBadge visibility={descriptor.visibility} />
        </div>
      </section>

      <section class="panel conformance-panel">
        <div class="panel-header">
          <div>
            <span class="panel-kicker">COORD-1..8</span>
            <h2>Conformance</h2>
          </div>
          <span class="pill" class:pill-pass={conformance.is_conformant} class:pill-violation={!conformance.is_conformant}>
            {conformance.is_conformant ? 'No violations' : 'Violations found'}
          </span>
        </div>
        <div class="panel-body">
          <ConformanceStrip report={conformance} />
          <p class="strip-note">Amber lights are <strong>behavioral</strong> — decidable only against real traffic, not a violation. Hover a light for its clause.</p>
        </div>
      </section>
    </div>

    <div class="stat-grid">
      {#each RESOURCE_KINDS as k (k)}
        <StatCard
          label={kindLabel(k)}
          value={kindQuantity(k, usageTotals[k] ?? 0).split(' ')[0]}
          unit={kindQuantity(k, usageTotals[k] ?? 0).split(' ').slice(1).join(' ')}
          hint="metered this period, all payers"
        />
      {/each}
    </div>

    <div class="stat-grid stat-grid-secondary">
      <StatCard
        label="Prepaid balance"
        value={ledgerMoney(totalBalance, currency)}
        accent="brass"
        hint={lowBalanceCount > 0 ? `${lowBalanceCount} payer${lowBalanceCount > 1 ? 's' : ''} below top-up threshold` : 'all payers above threshold'}
      />
      <StatCard
        label="Receipts issued"
        value={integer(receipts?.receipts.length ?? 0)}
        accent="teal"
        hint="signed usage receipts on file"
      />
      <StatCard
        label="Uptime"
        value={`${uptimeDays}d ${uptimeHours}h`}
        hint="in-memory store — resets on restart"
      />
      <StatCard
        label="Operator key"
        value={descriptor.identity_hex.slice(0, 10) + '…'}
        hint="current signing identity"
      />
    </div>

    <div class="footer-notes">
      <div class="note">
        <span aria-hidden="true">◈</span>
        <span>{descriptor.note}</span>
      </div>
      {#if IS_MOCK}
        <div class="note note-caution">
          <span aria-hidden="true">⚑</span>
          <span><strong>Demo data.</strong> This build is reading fixture data (VITE_MOCK=1), not a live <code>ephor-admin</code> instance. See <code>console/README.md</code> to point it at a real coordinator.</span>
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .page {
    display: flex;
    flex-direction: column;
    gap: 1.6rem;
  }

  .page-head {
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    gap: 1rem;
    flex-wrap: wrap;
  }

  .kicker {
    font-family: var(--font-mono);
    font-size: 0.7rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--accent);
  }

  h1 {
    font-size: 2.1rem;
    margin: 0.2rem 0 0.35rem;
  }

  .lede {
    color: var(--text-secondary);
    margin: 0;
    max-width: 46ch;
  }

  .loading {
    color: var(--text-tertiary);
    font-family: var(--font-mono);
    font-size: 0.85rem;
  }

  .grid-top {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1.35fr);
    gap: 1.1rem;
    align-items: stretch;
  }

  @media (max-width: 980px) {
    .grid-top {
      grid-template-columns: 1fr;
    }
  }

  .strip-note {
    margin: 0.9rem 0 0;
    font-size: 0.76rem;
    color: var(--text-tertiary);
    line-height: 1.5;
  }

  .stat-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 1rem;
  }

  @media (max-width: 760px) {
    .stat-grid {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }

  .footer-notes {
    display: flex;
    flex-direction: column;
    gap: 0.7rem;
  }

  .footer-notes .note span[aria-hidden] {
    color: var(--accent);
  }
</style>
