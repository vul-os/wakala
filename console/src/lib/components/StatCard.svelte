<script lang="ts">
  let {
    label,
    value,
    unit = '',
    hint = '',
    accent = 'ink',
  }: {
    label: string;
    value: string;
    unit?: string;
    hint?: string;
    accent?: 'ink' | 'teal' | 'bronze';
  } = $props();
</script>

<div class="stat panel">
  <span class="label">{label}</span>
  <div class="value-row">
    <span class="value" class:teal={accent === 'teal'} class:bronze={accent === 'bronze'}>{value}</span>
    {#if unit}<span class="unit">{unit}</span>{/if}
  </div>
  {#if hint}<span class="hint">{hint}</span>{/if}
</div>

<style>
  .stat {
    padding: 1.1rem 1.3rem 1.2rem;
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    min-width: 0;
  }

  .label {
    font-family: var(--font-mono);
    font-size: 0.66rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--text-tertiary);
  }

  .value-row {
    display: flex;
    align-items: baseline;
    gap: 0.4rem;
  }

  .value {
    font-family: var(--font-sans);
    font-size: 1.9rem;
    font-weight: 600;
    color: var(--text-primary);
    line-height: 1;
    letter-spacing: -0.01em;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .value.teal {
    color: var(--accent);
  }
  .value.bronze {
    color: var(--accent);
  }

  .unit {
    font-size: 0.78rem;
    color: var(--text-tertiary);
    font-family: var(--font-mono);
  }

  .hint {
    font-size: 0.74rem;
    color: var(--text-secondary);
  }
</style>
