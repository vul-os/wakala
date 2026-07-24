<script lang="ts">
  import { client, ApiError } from '../lib/api';
  import type { SignedDescriptorDto, VisibilityClass, AssuranceLevel, OperatorPolicy } from '../lib/types';
  import { COORDINATOR_KINDS } from '../lib/types';
  import VisibilityBadge from '../lib/components/VisibilityBadge.svelte';
  import { isDowngrade } from '../lib/visibility';
  import { shortHex } from '../lib/format';

  let descriptor = $state<SignedDescriptorDto | null>(null);
  let loading = $state(true);

  let kind = $state<SignedDescriptorDto['kind']>('reachability-adapter');
  let visClass = $state<VisibilityClass>('blind-routing');
  let visLevel = $state<AssuranceLevel>('declared');
  let policy = $state<OperatorPolicy>({ region: '', capabilities: [], contact: '', notes: '' });
  let capabilitiesText = $state('');

  let confirmDowngrade = $state(false);
  let saving = $state(false);
  let errorMsg = $state<string | null>(null);
  let justPublished = $state(false);

  $effect(() => {
    (async () => {
      const d = await client.getDescriptor();
      descriptor = d;
      kind = d.kind;
      visClass = d.visibility.class;
      visLevel = d.visibility.level;
      policy = { ...d.policy };
      capabilitiesText = d.policy.capabilities.join(', ');
      loading = false;
    })();
  });

  let pendingVisibility = $derived({ class: visClass, level: visLevel });
  let wouldDowngrade = $derived(descriptor ? isDowngrade(descriptor.visibility, pendingVisibility) : false);

  async function publish() {
    if (!descriptor) return;
    errorMsg = null;
    saving = true;
    justPublished = false;
    try {
      const body = {
        kind,
        visibility: pendingVisibility,
        policy: {
          region: policy.region || null,
          capabilities: capabilitiesText
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean),
          contact: policy.contact || null,
          notes: policy.notes || null,
        },
        confirm_downgrade: confirmDowngrade,
      };
      const res = await client.putDescriptor(body);
      descriptor = res.descriptor;
      confirmDowngrade = false;
      justPublished = true;
    } catch (e) {
      errorMsg = e instanceof ApiError ? e.message : 'Could not publish the descriptor.';
    } finally {
      saving = false;
    }
  }
</script>

<div class="page">
  <div class="page-head">
    <span class="kicker">Descriptor</span>
    <h1>Operator policy &amp; declared visibility</h1>
    <p class="lede">The signed, discovery-only artifact this coordinator publishes about itself (CONTRACT §2.1). No score, no price rank, no stake field — the type has none.</p>
  </div>

  {#if loading || !descriptor}
    <p class="loading">Loading…</p>
  {:else}
    <div class="layout">
      <section class="panel">
        <div class="panel-header">
          <div>
            <span class="panel-kicker">Draft</span>
            <h2>Edit &amp; sign</h2>
          </div>
        </div>
        <div class="panel-body">
          <div class="field">
            <label for="kind">Coordinator kind</label>
            <select id="kind" bind:value={kind}>
              {#each COORDINATOR_KINDS as k (k)}
                <option value={k}>{k}</option>
              {/each}
            </select>
          </div>

          <div class="two-col">
            <div class="field">
              <label for="vclass">Visibility class</label>
              <select id="vclass" bind:value={visClass}>
                <option value="blind">blind</option>
                <option value="blind-routing">blind-routing</option>
                <option value="terminating">terminating</option>
              </select>
            </div>
            <div class="field">
              <label for="vlevel">Assurance level</label>
              <select id="vlevel" bind:value={visLevel}>
                <option value="structural">structural</option>
                <option value="attested">attested</option>
                <option value="declared">declared</option>
              </select>
            </div>
          </div>

          <div class="preview">
            <VisibilityBadge visibility={pendingVisibility} size="sm" />
          </div>

          {#if wouldDowngrade}
            <div class="note note-danger">
              <span aria-hidden="true">⚠</span>
              <span>
                <strong>This is a visibility downgrade.</strong> Moving from
                <code>{descriptor.visibility.class} / {descriptor.visibility.level}</code> to
                <code>{visClass} / {visLevel}</code> weakens the declared claim (CONTRACT §3.2 — no
                <em>silent</em> downgrade). A real, intentional switch is legitimate as long as it's disclosed:
                <label class="checkline">
                  <input type="checkbox" bind:checked={confirmDowngrade} />
                  I am intentionally disclosing this downgrade
                </label>
              </span>
            </div>
          {/if}

          <div class="field">
            <label for="region">Region</label>
            <input id="region" type="text" bind:value={policy.region} placeholder="eu-west" />
          </div>

          <div class="field">
            <label for="caps">Capabilities (comma-separated)</label>
            <input id="caps" type="text" bind:value={capabilitiesText} placeholder="reachability-adapter, sni-passthrough" />
          </div>

          <div class="field">
            <label for="contact">Contact</label>
            <input id="contact" type="text" bind:value={policy.contact} placeholder="ops@example.org" />
          </div>

          <div class="field">
            <label for="notes">Notes</label>
            <textarea id="notes" rows="3" bind:value={policy.notes} placeholder="Free-text operator note."></textarea>
          </div>

          {#if errorMsg}
            <div class="note note-danger" role="alert">
              <span aria-hidden="true">✕</span>
              <span>{errorMsg}</span>
            </div>
          {/if}

          <button
            type="button"
            class="btn btn-primary"
            disabled={saving || (wouldDowngrade && !confirmDowngrade)}
            onclick={publish}
          >
            {saving ? 'Signing…' : 'Sign & publish'}
          </button>
          {#if justPublished}
            <span class="published-flag">Published — re-signed under the current key.</span>
          {/if}
        </div>
      </section>

      <section class="panel">
        <div class="panel-header">
          <div>
            <span class="panel-kicker">Live</span>
            <h2>Currently published</h2>
          </div>
          <div class="stamp stamp-signed" aria-hidden="true">Signed<br/>&amp; live</div>
        </div>
        <div class="panel-body published">
          <dl>
            <dt>Kind</dt>
            <dd>{descriptor.kind}</dd>
            <dt>Visibility</dt>
            <dd><VisibilityBadge visibility={descriptor.visibility} size="sm" /></dd>
            <dt>Identity (pubkey)</dt>
            <dd class="hex">{shortHex(descriptor.identity_hex, 12, 8)}</dd>
            <dt>Signature</dt>
            <dd class="hex">{shortHex(descriptor.sig_hex, 12, 8)}</dd>
            <dt>Deterministic CBOR</dt>
            <dd class="hex">{shortHex(descriptor.det_cbor_hex, 12, 8)}</dd>
            <dt>Policy — region</dt>
            <dd>{descriptor.policy.region ?? '—'}</dd>
            <dt>Policy — capabilities</dt>
            <dd>{descriptor.policy.capabilities.length ? descriptor.policy.capabilities.join(', ') : '—'}</dd>
            <dt>Policy — contact</dt>
            <dd>{descriptor.policy.contact ?? '—'}</dd>
            <dt>Policy — notes</dt>
            <dd class="notes">{descriptor.policy.notes ?? '—'}</dd>
          </dl>
          <div class="note">
            <span aria-hidden="true">◈</span>
            <span>{descriptor.note}</span>
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
  .loading {
    color: var(--text-tertiary);
    font-family: var(--font-mono);
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
  .two-col {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.8rem;
  }
  .preview {
    margin: 0.9rem 0 1.1rem;
  }
  .checkline {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    margin-top: 0.5rem;
    font-weight: 600;
    color: var(--text-primary);
    font-size: 0.78rem;
  }
  .checkline input {
    width: auto;
  }
  .btn-primary {
    margin-top: 0.4rem;
  }
  .published-flag {
    display: block;
    margin-top: 0.6rem;
    font-size: 0.78rem;
    color: var(--status-success);
    font-family: var(--font-mono);
  }
  .published dl {
    display: grid;
    grid-template-columns: 9.5rem 1fr;
    row-gap: 0.65rem;
    column-gap: 0.8rem;
    margin: 0 0 1.1rem;
  }
  .published dt {
    font-family: var(--font-mono);
    font-size: 0.68rem;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-tertiary);
    align-self: center;
  }
  .published dd {
    margin: 0;
    font-size: 0.86rem;
    min-width: 0;
  }
  .published dd.notes {
    color: var(--text-secondary);
  }
</style>
