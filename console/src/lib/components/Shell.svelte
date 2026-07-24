<script lang="ts">
  import type { Snippet } from 'svelte';
  import { router, type Route } from '../router.svelte';
  import { theme } from '../theme.svelte';
  import { IS_MOCK } from '../api';

  let { children }: { children: Snippet } = $props();

  // Mobile: the sidebar collapses to a slide-in drawer behind a hamburger.
  let drawerOpen = $state(false);

  function go(id: Route) {
    router.go(id);
    drawerOpen = false; // dismiss the drawer after navigating on mobile
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') drawerOpen = false;
  }

  // Grouped like the Vulos OS settings rail: plain labels under small muted
  // section headers, no leading numbers.
  const NAV_GROUPS: { heading: string; items: { id: Route; label: string }[] }[] = [
    {
      heading: 'Posture',
      items: [
        { id: 'overview', label: 'Overview' },
        { id: 'descriptor', label: 'Descriptor' },
        { id: 'conformance', label: 'Conformance' },
      ],
    },
    {
      heading: 'Billing',
      items: [
        { id: 'tariff', label: 'Pricing' },
        { id: 'billing', label: 'Ledger' },
      ],
    },
    {
      heading: 'Identity',
      items: [{ id: 'keys', label: 'Keys' }],
    },
  ];
</script>

<svelte:window onkeydown={onKeydown} />

<div class="shell" class:drawer-open={drawerOpen}>
  <a href="#main" class="skip-link">Skip to content</a>

  <!-- scrim behind the mobile drawer -->
  <button
    type="button"
    class="scrim"
    aria-label="Close menu"
    tabindex={drawerOpen ? 0 : -1}
    onclick={() => (drawerOpen = false)}
  ></button>

  <aside class="nav" class:open={drawerOpen}>
    <div class="brandblock">
      <div class="mark" aria-hidden="true">
        <!-- Ephor mark: a comma drawn so it reads as a lowercase "e" — the
             product's initial (brand/logo-mark.svg). The bowl and crossbar
             form the e; its lower terminal continues into the comma's tail. -->
        <svg viewBox="0 0 128 128" fill="none">
          <rect x="0" y="0" width="128" height="128" rx="28" fill="url(#g)"/>
          <g fill="none" stroke="#C89A56" stroke-width="15" stroke-linecap="round" stroke-linejoin="round">
            <path d="M40 60 H83"/>
            <path d="M83 60 A29 29 0 1 0 72 86"/>
            <path d="M72 86 Q 80 104 58 112"/>
          </g>
          <defs>
            <linearGradient id="g" x1="0" y1="0" x2="128" y2="128" gradientUnits="userSpaceOnUse">
              <stop offset="0" stop-color="#14171f"/>
              <stop offset="1" stop-color="#08090c"/>
            </linearGradient>
          </defs>
        </svg>
      </div>
      <div class="wordblock">
        <span class="word">Ephor</span>
        <span class="sub">Operator Console</span>
      </div>
    </div>

    <nav aria-label="Console sections">
      {#each NAV_GROUPS as group (group.heading)}
        <p class="nav-heading">{group.heading}</p>
        <ul class="navlist">
          {#each group.items as item (item.id)}
            <li>
              <button
                type="button"
                class="navitem"
                class:active={router.current === item.id}
                onclick={() => go(item.id)}
                aria-current={router.current === item.id ? 'page' : undefined}
              >
                <span class="lbl">{item.label}</span>
              </button>
            </li>
          {/each}
        </ul>
      {/each}
    </nav>

    <div class="nav-foot">
      {#if IS_MOCK}
        <span class="mode-badge" title="This build is running on fixture data, not a live ephor-admin — see console/README.md">
          <span class="light-dot" aria-hidden="true"></span> Demo data
        </span>
      {/if}
      <p class="foot-note">Binds operator-local by default (127.0.0.1:8090). Bearer-token gated, fail-closed.</p>
    </div>
  </aside>

  <div class="content-col">
    <header class="topbar">
      <div class="crumbs">
        <button
          type="button"
          class="hamburger"
          aria-label="Open menu"
          aria-expanded={drawerOpen}
          onclick={() => (drawerOpen = true)}
        >
          <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M3 6h18M3 12h18M3 18h18" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
        </button>
        <span class="crumb-kicker">Coordinator control plane</span>
      </div>
      <button type="button" class="theme-toggle" onclick={() => theme.toggle()} aria-label="Toggle light/dark theme">
        <span class="track" class:dark={theme.resolved() === 'dark'}>
          <span class="thumb">
            {#if theme.resolved() === 'dark'}
              <svg viewBox="0 0 24 24" fill="none"><path d="M20 14.5A8.5 8.5 0 119.5 4a7 7 0 1010.5 10.5z" fill="currentColor"/></svg>
            {:else}
              <svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="4.5" fill="currentColor"/><path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>
            {/if}
          </span>
        </span>
        <span class="tlabel">{theme.resolved() === 'dark' ? 'Dark' : 'Light'}</span>
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
    background: var(--text-primary);
    color: var(--bg-base);
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

  .nav {
    background: var(--bg-surface);
    border-right: 1px solid var(--border-default);
    display: flex;
    flex-direction: column;
    padding: 1.4rem 1.1rem;
    position: sticky;
    top: 0;
    height: 100vh;
  }

  /* Scrim is inert on desktop; only the mobile drawer reveals it. */
  .scrim {
    display: none;
    border: none;
    padding: 0;
  }

  /* ── Mobile: single column; the sidebar becomes a slide-in drawer ── */
  @media (max-width: 900px) {
    .shell {
      grid-template-columns: 1fr;
    }
    .nav {
      position: fixed;
      top: 0;
      left: 0;
      bottom: 0;
      z-index: 60;
      width: 16rem;
      max-width: 82vw;
      height: 100dvh;
      transform: translateX(-100%);
      transition: transform 0.24s cubic-bezier(0.22, 1, 0.36, 1);
      box-shadow: var(--shadow-lg);
      overflow-y: auto;
    }
    .nav.open {
      transform: translateX(0);
    }
    .scrim {
      display: block;
      position: fixed;
      inset: 0;
      z-index: 50;
      background: rgba(0, 0, 0, 0.55);
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.24s ease;
      cursor: default;
    }
    .shell.drawer-open .scrim {
      opacity: 1;
      pointer-events: auto;
    }
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
    font-family: var(--font-mono);
    font-weight: 700;
    font-size: 1.1rem;
    letter-spacing: -0.02em;
  }

  .sub {
    font-family: var(--font-mono);
    font-size: 0.66rem;
    letter-spacing: 0.02em;
    color: var(--text-muted);
  }

  .nav-heading {
    font-family: var(--font-mono);
    font-size: 0.66rem;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-muted);
    margin: 1.1rem 0 0.35rem;
    padding: 0 0.6rem;
  }
  .nav-heading:first-of-type {
    margin-top: 0.2rem;
  }

  .navlist {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
  }

  .navitem {
    width: 100%;
    display: flex;
    align-items: center;
    padding: 0.45rem 0.6rem;
    border-radius: 7px;
    border: none;
    background: transparent;
    color: var(--text-secondary);
    font-size: 0.87rem;
    font-weight: 500;
    text-align: left;
    cursor: pointer;
  }

  .navitem:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .navitem.active {
    background: color-mix(in srgb, var(--accent) 12%, transparent);
    color: var(--text-primary);
    font-weight: 600;
    box-shadow: inset 2px 0 0 var(--accent);
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
    font-size: 0.72rem;
    font-weight: 500;
    color: var(--accent);
    background: var(--accent-soft);
    border: 1px solid color-mix(in srgb, var(--accent) 40%, transparent);
    padding: 0.25rem 0.6rem;
    border-radius: 999px;
  }

  .foot-note {
    font-size: 0.68rem;
    color: var(--text-tertiary);
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
    padding: 1rem 1.8rem;
    border-bottom: 1px solid var(--border-default);
    background: var(--nav-scrim);
    backdrop-filter: blur(6px);
    position: sticky;
    top: 0;
    z-index: 10;
  }

  .crumbs {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    min-width: 0;
  }

  .crumb-kicker {
    font-family: var(--font-mono);
    font-size: 0.75rem;
    font-weight: 500;
    letter-spacing: 0.02em;
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  /* Hamburger: hidden on desktop, shown when the sidebar is a drawer. */
  .hamburger {
    display: none;
    align-items: center;
    justify-content: center;
    width: 2.1rem;
    height: 2.1rem;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-sm);
    background: var(--bg-elevated);
    color: var(--text-secondary);
    cursor: pointer;
    flex-shrink: 0;
  }
  .hamburger svg {
    width: 1.1rem;
    height: 1.1rem;
  }
  .hamburger:hover {
    color: var(--text-primary);
    border-color: var(--border-emphasis);
  }
  @media (max-width: 900px) {
    .hamburger {
      display: inline-flex;
    }
  }

  .theme-toggle {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    background: none;
    border: none;
    cursor: pointer;
    color: var(--text-secondary);
  }

  .track {
    width: 2.5rem;
    height: 1.4rem;
    border-radius: 999px;
    background: var(--bg-base);
    border: 1px solid var(--border-strong);
    display: flex;
    align-items: center;
    padding: 0.12rem;
    transition: background 0.2s ease;
  }

  .track.dark {
    background: color-mix(in srgb, var(--accent) 30%, var(--bg-base));
    justify-content: flex-end;
  }

  .thumb {
    width: 1.05rem;
    height: 1.05rem;
    border-radius: 50%;
    background: var(--bg-elevated);
    color: var(--accent);
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: var(--shadow-sm);
  }

  .track.dark .thumb {
    color: var(--accent);
  }

  .thumb svg {
    width: 0.7rem;
    height: 0.7rem;
  }

  .tlabel {
    font-family: var(--font-mono);
    font-size: 0.78rem;
    color: var(--text-secondary);
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
