<script lang="ts">
  import { client } from '../lib/api';
  import type { ReportDto, FindingDto } from '../lib/types';

  let report = $state<ReportDto | null>(null);
  let loading = $state(true);

  $effect(() => {
    (async () => {
      report = await client.getConformance();
      loading = false;
    })();
  });

  const ROWS: { id: string; title: string; summary: string }[] = [
    { id: 'COORD-1', title: 'Signed, discovery-only descriptor', summary: 'No global score, no price rank, no stake field — structurally, by the type.' },
    { id: 'COORD-2', title: 'Zero lock-in', summary: 'Switching operator is a config change: no data migration, no identity change.' },
    { id: 'COORD-3', title: 'Self-host backstop', summary: 'Anyone meeting the kind\'s requirement can run it themselves — or the one disclosed scarce-reachability exception.' },
    { id: 'COORD-4', title: 'Declared content-visibility', summary: 'Exactly one class + level declared; a declared-level blind claim must be shown unverified, never verified.' },
    { id: 'COORD-5', title: 'No silent downgrade', summary: 'Declaring terminating is the disclosure required; claiming blind while operating terminating is the violation.' },
    { id: 'COORD-6', title: 'Authorize, never classify', summary: 'Gates delivery-path traffic on sender identity + rate only, or sits on no delivery path at all.' },
    { id: 'COORD-7', title: 'Signed receipts if metered', summary: 'Metering without payer-facing signed receipts is a violation.' },
    { id: 'COORD-8', title: 'No token; existing-asset settlement', summary: 'Stakes/settles only in existing assets — minting a protocol token is forbidden.' },
  ];

  function findingFor(id: string, r: ReportDto | null): FindingDto | undefined {
    return r?.findings.find((f) => f.id === id);
  }
</script>

<div class="page">
  <div class="page-head">
    <span class="kicker">06 · Conformance</span>
    <h1>COORD-1..8 checklist</h1>
    <p class="lede">Every coordinator kind inherits the same eight clauses (CONTRACT §7). Some are decidable from the descriptor; others are marked <strong>behavioral</strong> — honestly deferred to a runtime test, never falsely passed.</p>
  </div>

  {#if loading || !report}
    <p class="loading">Running the self-check…</p>
  {:else}
    <div class="summary-bar panel">
      <div class="summary-left">
        <span class="pill" class:pill-pass={report.is_conformant} class:pill-violation={!report.is_conformant}>
          {report.is_conformant ? 'Conformant — no violations' : 'Non-conformant'}
        </span>
        <span class="summary-kind">kind: {report.kind}</span>
      </div>
      <div class="counts">
        <span><span class="light-dot pass-dot" aria-hidden="true"></span> {report.findings.filter((f) => f.outcome === 'pass').length} pass</span>
        <span><span class="light-dot behavioral-dot" aria-hidden="true"></span> {report.findings.filter((f) => f.outcome === 'behavioral').length} behavioral</span>
        <span><span class="light-dot violation-dot" aria-hidden="true"></span> {report.findings.filter((f) => f.outcome === 'violation').length} violation</span>
      </div>
    </div>

    <div class="rows">
      {#each ROWS as row (row.id)}
        {@const f = findingFor(row.id, report)}
        <article class="finding panel" class:pass={f?.outcome === 'pass'} class:behavioral={f?.outcome === 'behavioral'} class:violation={f?.outcome === 'violation'}>
          <div class="finding-badge">
            <span class="light-dot" aria-hidden="true"></span>
            <span class="fid">{row.id}</span>
            <span class="fclause">{f?.clause}</span>
          </div>
          <div class="finding-body">
            <h3>{row.title}</h3>
            <p class="summary">{row.summary}</p>
            {#if f?.detail}
              <p class="detail"><span class="detail-label">{f.outcome}:</span> {f.detail}</p>
            {/if}
          </div>
          <span class="outcome-pill pill" class:pill-pass={f?.outcome === 'pass'} class:pill-behavioral={f?.outcome === 'behavioral'} class:pill-violation={f?.outcome === 'violation'}>
            {f?.outcome}
          </span>
        </article>
      {/each}
    </div>
  {/if}
</div>

<style>
  .page {
    display: flex;
    flex-direction: column;
    gap: 1.4rem;
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
    max-width: 72ch;
  }
  .loading {
    color: var(--text-tertiary);
    font-family: var(--font-mono);
    font-size: 0.85rem;
  }
  .summary-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 0.8rem;
    padding: 1rem 1.3rem;
  }
  .summary-left {
    display: flex;
    align-items: center;
    gap: 0.8rem;
  }
  .summary-kind {
    font-family: var(--font-mono);
    font-size: 0.78rem;
    color: var(--text-tertiary);
  }
  .counts {
    display: flex;
    gap: 1rem;
    font-size: 0.78rem;
    color: var(--text-secondary);
    font-family: var(--font-mono);
  }
  .counts span {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
  }
  .pass-dot {
    color: var(--status-success);
  }
  .behavioral-dot {
    color: var(--status-warning);
  }
  .violation-dot {
    color: var(--status-danger);
  }
  .rows {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .finding {
    display: grid;
    grid-template-columns: 6rem 1fr auto;
    align-items: start;
    gap: 1rem;
    padding: 1rem 1.3rem;
    border-left: 4px solid var(--border-default);
  }
  .finding.pass {
    border-left-color: var(--status-success);
  }
  .finding.behavioral {
    border-left-color: var(--status-warning);
  }
  .finding.violation {
    border-left-color: var(--status-danger);
  }
  @media (max-width: 700px) {
    .finding {
      grid-template-columns: 1fr;
    }
  }
  .finding-badge {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }
  .finding.pass .finding-badge {
    color: var(--status-success);
  }
  .finding.behavioral .finding-badge {
    color: var(--status-warning);
  }
  .finding.violation .finding-badge {
    color: var(--status-danger);
  }
  .fid {
    font-family: var(--font-mono);
    font-weight: 700;
    font-size: 0.82rem;
    color: var(--text-primary);
  }
  .fclause {
    font-family: var(--font-mono);
    font-size: 0.7rem;
    color: var(--text-tertiary);
  }
  .finding-body h3 {
    font-size: 0.98rem;
    margin-bottom: 0.3rem;
  }
  .summary {
    margin: 0;
    font-size: 0.82rem;
    color: var(--text-secondary);
    line-height: 1.5;
  }
  .detail {
    margin: 0.5rem 0 0;
    font-size: 0.78rem;
    color: var(--text-primary);
    background: var(--bg-base);
    border-radius: 6px;
    padding: 0.5rem 0.7rem;
    line-height: 1.5;
  }
  .detail-label {
    text-transform: uppercase;
    font-family: var(--font-mono);
    font-size: 0.66rem;
    letter-spacing: 0.06em;
    color: var(--text-tertiary);
    margin-right: 0.3rem;
  }
  .outcome-pill {
    text-transform: uppercase;
    align-self: start;
  }
</style>
