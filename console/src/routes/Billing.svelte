<script lang="ts">
  import { client, ApiError } from '../lib/api';
  import type { PrepaidAccount, ReceiptDto, TopUp, UsageDto, ResourceKind } from '../lib/types';
  import { RESOURCE_KINDS } from '../lib/types';
  import { ledgerMoney, kindLabel, kindQuantity, shortHex, formatDate, money } from '../lib/format';

  let accounts = $state<PrepaidAccount[]>([]);
  let selectedPayer = $state<string>('');
  let usage = $state<UsageDto | null>(null);
  let receipts = $state<ReceiptDto[]>([]);
  let auditCaveat = $state('');
  let topups = $state<TopUp[]>([]);
  let loading = $state(true);

  let topUpOpen = $state(false);
  let topUpAmount = $state(50);
  let topUpRail = $state<'stablecoin' | 'card'>('stablecoin');
  let topUpBusy = $state(false);

  let runningBilling = $state(false);
  let runError = $state<string | null>(null);

  let selectedAccount = $derived(accounts.find((a) => a.payer_hex === selectedPayer) ?? null);

  $effect(() => {
    (async () => {
      const a = await client.getPrepaidAccounts();
      accounts = a;
      selectedPayer = a[0]?.payer_hex ?? '';
      loading = false;
    })();
  });

  async function loadPayerData(payerHex: string) {
    if (!payerHex) return;
    const [u, r, t] = await Promise.all([
      client.getUsage(payerHex),
      client.getReceiptsForPayer(payerHex),
      client.getTopUps(payerHex),
    ]);
    usage = u;
    receipts = r.receipts;
    auditCaveat = r.one_directional_audit_caveat;
    topups = t;
  }

  $effect(() => {
    if (selectedPayer) loadPayerData(selectedPayer);
  });

  async function doTopUp() {
    if (!selectedAccount) return;
    topUpBusy = true;
    try {
      await client.topUp(selectedAccount.payer_hex, Math.round(topUpAmount * 1_000_000), topUpRail);
      accounts = await client.getPrepaidAccounts();
      topups = await client.getTopUps(selectedAccount.payer_hex);
      topUpOpen = false;
    } finally {
      topUpBusy = false;
    }
  }

  async function runBilling() {
    if (!selectedAccount) return;
    runError = null;
    runningBilling = true;
    try {
      await client.runBilling(selectedAccount.payer_hex);
      await loadPayerData(selectedAccount.payer_hex);
    } catch (e) {
      runError = e instanceof ApiError ? e.message : 'Could not run the billing period.';
    } finally {
      runningBilling = false;
    }
  }

  async function toggleMonthlyCard() {
    if (!selectedAccount) return;
    const next = !selectedAccount.monthly_card_enabled;
    await client.setMonthlyCard(next);
    accounts = await client.getPrepaidAccounts();
  }

  let hasUsage = $derived(usage ? RESOURCE_KINDS.some((k) => (usage!.usage[k] ?? 0) > 0) : false);
</script>

<div class="page">
  <div class="page-head">
    <span class="kicker">Billing</span>
    <h1>Prepaid ledger</h1>
    <p class="lede">Payers fund a balance up front; usage debits it. No invoicing float, no credit risk to the operator by default.</p>
  </div>

  {#if loading}
    <p class="loading">Loading…</p>
  {:else}
    <div class="payer-row">
      <label for="payer" class="payer-label">Payer</label>
      <select id="payer" bind:value={selectedPayer} class="payer-select">
        {#each accounts as a (a.payer_hex)}
          <option value={a.payer_hex}>{a.payer_label} — {shortHex(a.payer_hex, 6, 4)}</option>
        {/each}
      </select>
    </div>

    {#if selectedAccount}
      <div class="grid-top">
        <section class="panel balance-panel">
          <div class="panel-header">
            <div>
              <span class="panel-kicker">Prepaid — patala rails</span>
              <h2>Credit balance</h2>
            </div>
          </div>
          <div class="panel-body balance-body">
            <div class="balance-value" class:low={selectedAccount.balance_minor < selectedAccount.low_balance_threshold_minor}>
              {ledgerMoney(selectedAccount.balance_minor, selectedAccount.currency)}
            </div>
            {#if selectedAccount.balance_minor < selectedAccount.low_balance_threshold_minor}
              <p class="low-flag">Below the {ledgerMoney(selectedAccount.low_balance_threshold_minor, selectedAccount.currency)} top-up threshold.</p>
            {/if}

            <button type="button" class="btn btn-primary" onclick={() => (topUpOpen = !topUpOpen)}>
              {topUpOpen ? 'Cancel' : 'Top up →'}
            </button>

            {#if topUpOpen}
              <div class="topup-form">
                <div class="field">
                  <label for="amount">Amount ({selectedAccount.currency})</label>
                  <input id="amount" type="number" min="1" step="1" bind:value={topUpAmount} />
                </div>
                <div class="field">
                  <span class="rail-label">Rail</span>
                  <div class="rail-choice">
                    <label class="rail-opt" class:active={topUpRail === 'stablecoin'}>
                      <input type="radio" name="rail" value="stablecoin" bind:group={topUpRail} />
                      Stablecoin (USDC)
                    </label>
                    <label class="rail-opt" class:active={topUpRail === 'card'}>
                      <input type="radio" name="rail" value="card" bind:group={topUpRail} />
                      Card (patala-hyperswitch)
                    </label>
                  </div>
                </div>
                <button type="button" class="btn btn-primary" disabled={topUpBusy} onclick={doTopUp}>
                  {topUpBusy ? 'Processing…' : `Confirm top-up`}
                </button>
              </div>
            {/if}

            {#if topups.length}
              <div class="topup-history">
                <span class="panel-kicker">Recent top-ups</span>
                <ul>
                  {#each topups.slice(0, 4) as t (t.id)}
                    <li>
                      <span class="mono">+{money(t.amount_minor, t.currency)}</span>
                      <span class="topup-detail">{t.detail}</span>
                      <span class="topup-date">{formatDate(t.at)}</span>
                    </li>
                  {/each}
                </ul>
              </div>
            {/if}
          </div>
        </section>

        <section class="panel usage-panel">
          <div class="panel-header">
            <div>
              <span class="panel-kicker">Current period</span>
              <h2>Metered usage</h2>
            </div>
            <button type="button" class="btn btn-ghost" disabled={runningBilling || !hasUsage} onclick={runBilling}>
              {runningBilling ? 'Billing…' : 'Run billing period →'}
            </button>
          </div>
          <div class="panel-body">
            {#if runError}
              <div class="note note-danger" role="alert"><span aria-hidden="true">✕</span><span>{runError}</span></div>
            {/if}
            {#if usage && hasUsage}
              <div class="scroll-x">
                <table class="ledger">
                  <thead><tr><th>Resource</th><th class="num">Metered</th></tr></thead>
                  <tbody>
                    {#each RESOURCE_KINDS as k (k)}
                      {#if (usage.usage[k] ?? 0) > 0}
                        <tr><td>{kindLabel(k)}</td><td class="mono num">{kindQuantity(k, usage.usage[k] ?? 0)}</td></tr>
                      {/if}
                    {/each}
                  </tbody>
                </table>
              </div>
            {:else}
              <p class="empty">Meter reset — nothing accrued yet this period.</p>
            {/if}

            <div class="settings-block">
              <div class="settings-row">
                <div class="settings-head">
                  <span class="settings-title">Monthly card (postpaid)</span>
                  <button
                    type="button"
                    class="switch"
                    class:on={selectedAccount.monthly_card_enabled}
                    onclick={toggleMonthlyCard}
                    aria-pressed={selectedAccount.monthly_card_enabled}
                    aria-label="Toggle monthly card postpaid fallback"
                  >
                    <span class="knob"></span>
                  </button>
                </div>
                <p class="settings-desc">Optional fallback via patala-hyperswitch — bills a card at period close instead of debiting prepaid balance. Secondary to prepaid; off unless the operator opts a payer in.</p>
              </div>
            </div>
          </div>
        </section>
      </div>

      <section class="panel receipts-panel">
        <div class="panel-header">
          <div>
            <span class="panel-kicker">Signed usage receipts</span>
            <h2>Receipts for {selectedAccount.payer_label}</h2>
          </div>
        </div>
        <div class="panel-body">
          <div class="note note-caution audit-note">
            <span aria-hidden="true">⚑</span>
            <span><strong>One-directional audit.</strong> {auditCaveat}</span>
          </div>
          {#if receipts.length}
            <div class="scroll-x">
              <table class="ledger">
                <thead>
                  <tr><th>#</th><th>Kind</th><th class="num">Metered</th><th class="num">Billed</th><th class="num">Amount</th><th>Verifies</th><th>Signer</th></tr>
                </thead>
                <tbody>
                  {#each receipts as r (r.sequence + r.kind)}
                    <tr>
                      <td class="mono">{r.sequence}</td>
                      <td>{kindLabel(r.kind)}</td>
                      <td class="mono num">{kindQuantity(r.kind, r.metered_units)}</td>
                      <td class="mono num">{kindQuantity(r.kind, r.billed_units)}</td>
                      <td class="mono num">{money(r.amount, r.currency)}</td>
                      <td>
                        <span class="pill" class:pill-pass={r.verifies} class:pill-violation={!r.verifies}>
                          {r.verifies ? 'signature ok' : 'invalid'}
                        </span>
                      </td>
                      <td class="hex">{shortHex(r.identity_hex, 6, 4)}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {:else}
            <p class="empty">No receipts issued for this payer yet.</p>
          {/if}
        </div>
      </section>
    {/if}
  {/if}
</div>

<style>
  .page {
    display: flex;
    flex-direction: column;
    gap: 1.4rem;
  }
  .kicker {
    font-family: var(--font-sans);
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.02em;
    color: var(--text-tertiary);
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
  .payer-row {
    display: flex;
    align-items: center;
    gap: 0.7rem;
  }
  .payer-label {
    margin: 0;
  }
  .payer-select {
    max-width: 24rem;
  }
  .grid-top {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1.3fr);
    gap: 1.1rem;
    align-items: start;
  }
  @media (max-width: 980px) {
    .grid-top {
      grid-template-columns: 1fr;
    }
  }
  .balance-body {
    display: flex;
    flex-direction: column;
    gap: 0.7rem;
  }
  .balance-value {
    font-family: var(--font-sans);
    font-size: 2rem;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: -0.01em;
    font-variant-numeric: tabular-nums;
  }
  .balance-value.low {
    color: var(--status-danger);
  }
  .low-flag {
    margin: -0.4rem 0 0;
    font-size: 0.78rem;
    color: var(--status-danger);
  }
  .topup-form {
    border-top: 1px dashed var(--border-default);
    padding-top: 0.9rem;
    margin-top: 0.3rem;
    display: flex;
    flex-direction: column;
    gap: 0.7rem;
  }
  .rail-label {
    font-size: 0.78rem;
    font-weight: 600;
    color: var(--text-secondary);
    display: block;
    margin-bottom: 0.35rem;
  }
  .rail-choice {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }
  .rail-opt {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    border: 1px solid var(--border-strong);
    border-radius: 7px;
    padding: 0.55rem 0.7rem;
    font-size: 0.82rem;
    font-weight: 500;
    color: var(--text-secondary);
    cursor: pointer;
  }
  .rail-opt.active {
    border-color: var(--accent);
    color: var(--text-primary);
    background: var(--accent-soft);
  }
  .rail-opt input {
    width: auto;
  }
  .topup-history {
    border-top: 1px dashed var(--border-default);
    padding-top: 0.8rem;
    margin-top: 0.2rem;
  }
  .topup-history ul {
    list-style: none;
    margin: 0.5rem 0 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .topup-history li {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 0.5rem;
    font-size: 0.78rem;
  }
  .topup-history .mono {
    color: var(--status-success);
    font-weight: 600;
  }
  .topup-detail {
    color: var(--text-secondary);
  }
  .topup-date {
    color: var(--text-tertiary);
    margin-left: auto;
  }
  .settings-block {
    border-top: 1px dashed var(--border-default);
    margin-top: 1.1rem;
    padding-top: 1rem;
  }
  .settings-row {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 1rem;
  }
  .settings-title {
    font-weight: 600;
    font-size: 0.86rem;
  }
  .settings-desc {
    margin: 0.25rem 0 0;
    font-size: 0.76rem;
    color: var(--text-tertiary);
    max-width: 40ch;
  }
  .switch {
    flex-shrink: 0;
    width: 2.6rem;
    height: 1.5rem;
    border-radius: 999px;
    background: var(--bg-base);
    border: 1px solid var(--border-strong);
    padding: 0.15rem;
    display: flex;
    cursor: pointer;
  }
  .switch.on {
    background: color-mix(in srgb, var(--accent) 45%, var(--bg-base));
    justify-content: flex-end;
  }
  .knob {
    width: 1.1rem;
    height: 1.1rem;
    border-radius: 50%;
    background: var(--bg-elevated);
    box-shadow: var(--shadow-sm);
  }
  .audit-note {
    margin-bottom: 1rem;
  }
</style>
