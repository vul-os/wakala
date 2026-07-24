<script module lang="ts">
  // Exported so other views (e.g. the Overview summary card) can reuse the same clause titles
  // instead of re-declaring them — the single source of truth for what COORD-1..8 stand for.
  export const CLAUSE_TITLE: Record<string, string> = {
    'COORD-1': 'Signed, discovery-only descriptor',
    'COORD-2': 'Zero lock-in',
    'COORD-3': 'Self-host backstop',
    'COORD-4': 'Declared content-visibility',
    'COORD-5': 'No silent downgrade',
    'COORD-6': 'Authorize, never classify',
    'COORD-7': 'Signed receipts if metered',
    'COORD-8': 'No token; existing-asset settlement',
  };
</script>

<script lang="ts">
  import type { ReportDto } from '../types';

  let { report }: { report: ReportDto } = $props();
</script>

<div class="strip" role="list" aria-label="COORD-1..8 conformance status">
  {#each report.findings as f (f.id)}
    <div class="light" role="listitem" class:pass={f.outcome === 'pass'} class:behavioral={f.outcome === 'behavioral'} class:violation={f.outcome === 'violation'}>
      <span class="dot light-dot" aria-hidden="true"></span>
      <div class="label">
        <span class="id">{f.id}</span>
        <span class="clause">{f.clause}</span>
      </div>
      <div class="tooltip">
        <strong>{CLAUSE_TITLE[f.id] ?? f.id}</strong>
        <span class="outcome-word">{f.outcome}</span>
        {#if f.detail}<p>{f.detail}</p>{/if}
      </div>
    </div>
  {/each}
</div>

<style>
  .strip {
    display: grid;
    grid-template-columns: repeat(8, minmax(0, 1fr));
    gap: 0.5rem;
  }

  @media (max-width: 760px) {
    .strip {
      grid-template-columns: repeat(4, minmax(0, 1fr));
    }
  }

  .light {
    position: relative;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.4rem;
    padding: 0.7rem 0.4rem;
    border-radius: 9px;
    background: var(--bg-elevated);
    border: 1px solid var(--border-default);
    cursor: default;
  }

  .light.pass {
    color: var(--status-success);
  }
  .light.behavioral {
    color: var(--status-warning);
  }
  .light.violation {
    color: var(--status-danger);
  }

  .label {
    display: flex;
    flex-direction: column;
    align-items: center;
    line-height: 1.2;
  }

  .id {
    font-family: var(--font-mono);
    font-size: 0.68rem;
    font-weight: 700;
    color: var(--text-primary);
  }

  .clause {
    font-family: var(--font-mono);
    font-size: 0.62rem;
    color: var(--text-tertiary);
  }

  .tooltip {
    position: absolute;
    bottom: calc(100% + 0.5rem);
    left: 50%;
    transform: translateX(-50%) translateY(4px);
    width: 15rem;
    background: var(--text-primary);
    color: var(--bg-base);
    border-radius: 8px;
    padding: 0.6rem 0.75rem;
    font-size: 0.72rem;
    line-height: 1.4;
    opacity: 0;
    pointer-events: none;
    transition: opacity 0.15s ease, transform 0.15s ease;
    z-index: 20;
    box-shadow: var(--shadow-lg);
  }

  .tooltip strong {
    display: block;
    color: var(--bg-base);
    font-family: var(--font-mono);
  }

  .tooltip .outcome-word {
    display: inline-block;
    text-transform: uppercase;
    font-family: var(--font-mono);
    font-size: 0.62rem;
    letter-spacing: 0.08em;
    opacity: 0.75;
    margin-top: 0.15rem;
  }

  .tooltip p {
    margin: 0.35rem 0 0;
    opacity: 0.9;
  }

  .light:hover .tooltip,
  .light:focus-within .tooltip {
    opacity: 1;
    transform: translateX(-50%) translateY(0);
  }
</style>
