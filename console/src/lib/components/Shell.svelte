<script lang="ts">
  import type { Snippet } from 'svelte';
  import { router, type Route } from '../router.svelte';
  import { theme } from '../theme.svelte';
  import { IS_MOCK } from '../api';

  let { children }: { children: Snippet } = $props();

  const NAV: { id: Route; num: string; label: string }[] = [
    { id: 'overview', num: '01', label: 'Overview' },
    { id: 'descriptor', num: '02', label: 'Descriptor' },
    { id: 'tariff', num: '03', label: 'Pricing' },
    { id: 'billing', num: '04', label: 'Billing' },
    { id: 'keys', num: '05', label: 'Keys' },
    { id: 'conformance', num: '06', label: 'Conformance' },
  ];
</script>

<div class="shell">
  <a href="#main" class="skip-link">Skip to content</a>

  <aside class="nav">
    <div class="brandblock">
      <div class="mark" aria-hidden="true">
        <svg viewBox="0 0 48 48" fill="none">
          <rect x="0" y="0" width="48" height="48" rx="11" fill="url(#g)"/>
          <path d="M12 15l7 18 6-10 6 10 7-18" stroke="#fff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
          <circle cx="24" cy="23" r="4.6" fill="none" stroke="#14B8A6" stroke-width="1.6"/>
          <defs>
            <linearGradient id="g" x1="0" y1="0" x2="48" y2="48" gradientUnits="userSpaceOnUse">
              <stop offset="0" stop-color="#FFC24B"/>
              <stop offset=".55" stop-color="#FF8A3D"/>
              <stop offset="1" stop-color="#E8543D"/>
            </linearGradient>
          </defs>
        </svg>
      </div>
      <div class="wordblock">
        <span class="word">Wakala</span>
        <span class="sub">Operator Console</span>
      </div>
    </div>

    <nav aria-label="Console sections">
      <ol class="manifest">
        {#each NAV as item (item.id)}
          <li>
            <button
              type="button"
              class="navitem"
              class:active={router.current === item.id}
              onclick={() => router.go(item.id)}
              aria-current={router.current === item.id ? 'page' : undefined}
            >
              <span class="num">{item.num}</span>
              <span class="lbl">{item.label}</span>
            </button>
          </li>
        {/each}
      </ol>
    </nav>

    <div class="nav-foot">
      {#if IS_MOCK}
        <span class="mode-badge" title="This build is running on fixture data, not a live wakala-admin — see console/README.md">
          <span class="light-dot" aria-hidden="true"></span> Demo data
        </span>
      {/if}
      <p class="foot-note">Binds operator-local by default (127.0.0.1:8090). Bearer-token gated, fail-closed.</p>
    </div>
  </aside>

  <div class="content-col">
    <header class="topbar">
      <div class="crumbs">
        <span class="crumb-kicker">Coordinator control plane</span>
      </div>
      <button type="button" class="theme-toggle" onclick={() => theme.toggle()} aria-label="Toggle day/night theme">
        <span class="track" class:night={theme.resolved() === 'dark'}>
          <span class="thumb">
            {#if theme.resolved() === 'dark'}
              <svg viewBox="0 0 24 24" fill="none"><path d="M20 14.5A8.5 8.5 0 119.5 4a7 7 0 1010.5 10.5z" fill="currentColor"/></svg>
            {:else}
              <svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="4.5" fill="currentColor"/><path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>
            {/if}
          </span>
        </span>
        <span class="tlabel">{theme.resolved() === 'dark' ? 'Night' : 'Day'}</span>
      </button>
    </header>

    <main id="main" tabindex="-1">
      {@render children()}
    </main>
  </div>
</div>

<style>
  .skip-link {
    position: absolute;
    left: -999px;
    top: 0;
    background: var(--ink);
    color: var(--bg);
    padding: 0.6rem 1rem;
    z-index: 100;
  }
  .skip-link:focus {
    left: 0.5rem;
    top: 0.5rem;
  }

  .shell {
    display: grid;
    grid-template-columns: 15.5rem 1fr;
    min-height: 100vh;
  }

  @media (max-width: 900px) {
    .shell {
      grid-template-columns: 1fr;
    }
    .nav {
      position: static;
      height: auto;
    }
  }

  .nav {
    background: var(--surface);
    border-right: 1px solid var(--rule);
    display: flex;
    flex-direction: column;
    padding: 1.4rem 1.1rem;
    position: sticky;
    top: 0;
    height: 100vh;
  }

  .brandblock {
    display: flex;
    align-items: center;
    gap: 0.7rem;
    padding: 0 0.3rem;
    margin-bottom: 1.6rem;
  }

  .mark svg {
    width: 2.3rem;
    height: 2.3rem;
    display: block;
  }

  .wordblock {
    display: flex;
    flex-direction: column;
    line-height: 1.15;
  }

  .word {
    font-family: var(--font-display);
    font-weight: 700;
    font-size: 1.15rem;
  }

  .sub {
    font-family: var(--font-mono);
    font-size: 0.62rem;
    letter-spacing: 0.09em;
    text-transform: uppercase;
    color: var(--ink-faint);
  }

  .manifest {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    border-top: 1px dashed var(--rule);
    border-bottom: 1px dashed var(--rule);
    padding: 0.5rem 0;
  }

  .navitem {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 0.65rem;
    padding: 0.55rem 0.6rem;
    border-radius: 7px;
    border: none;
    background: transparent;
    color: var(--ink-soft);
    font-size: 0.87rem;
    font-weight: 600;
    text-align: left;
    cursor: pointer;
  }

  .navitem:hover {
    background: var(--bg-deep);
    color: var(--ink);
  }

  .navitem.active {
    background: linear-gradient(90deg, color-mix(in srgb, var(--brass-2) 18%, transparent), transparent);
    color: var(--ink);
    box-shadow: inset 3px 0 0 var(--brass-3);
  }

  .num {
    font-family: var(--font-mono);
    font-size: 0.68rem;
    color: var(--ink-faint);
    width: 1.3rem;
  }

  .navitem.active .num {
    color: var(--brass-3);
  }

  .nav-foot {
    margin-top: auto;
    padding-top: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }

  .mode-badge {
    align-self: flex-start;
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    font-family: var(--font-mono);
    font-size: 0.68rem;
    color: var(--teal);
    background: var(--teal-soft);
    border: 1px solid color-mix(in srgb, var(--teal) 40%, transparent);
    padding: 0.3rem 0.6rem;
    border-radius: 999px;
  }

  .foot-note {
    font-size: 0.68rem;
    color: var(--ink-faint);
    line-height: 1.5;
    margin: 0;
  }

  .content-col {
    min-width: 0;
    display: flex;
    flex-direction: column;
  }

  .topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1.1rem 1.8rem;
    border-bottom: 1px solid var(--rule);
    background: color-mix(in srgb, var(--bg) 82%, transparent);
    backdrop-filter: blur(6px);
    position: sticky;
    top: 0;
    z-index: 10;
  }

  .crumb-kicker {
    font-family: var(--font-mono);
    font-size: 0.68rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--ink-faint);
  }

  .theme-toggle {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    background: none;
    border: none;
    cursor: pointer;
    color: var(--ink-soft);
  }

  .track {
    width: 2.5rem;
    height: 1.4rem;
    border-radius: 999px;
    background: var(--bg-deep);
    border: 1px solid var(--rule-strong);
    display: flex;
    align-items: center;
    padding: 0.12rem;
    transition: background 0.2s ease;
  }

  .track.night {
    background: color-mix(in srgb, var(--teal) 30%, var(--bg-deep));
    justify-content: flex-end;
  }

  .thumb {
    width: 1.05rem;
    height: 1.05rem;
    border-radius: 50%;
    background: var(--surface-raised);
    color: var(--brass-3);
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 1px 3px hsl(var(--shadow) / 0.3);
  }

  .track.night .thumb {
    color: var(--teal);
  }

  .thumb svg {
    width: 0.7rem;
    height: 0.7rem;
  }

  .tlabel {
    font-family: var(--font-mono);
    font-size: 0.72rem;
  }

  main {
    padding: 1.8rem;
    max-width: 78rem;
    width: 100%;
    margin: 0 auto;
  }

  @media (max-width: 640px) {
    main {
      padding: 1.1rem;
    }
    .topbar {
      padding: 0.9rem 1.1rem;
    }
  }
</style>
