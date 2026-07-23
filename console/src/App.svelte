<script lang="ts">
  import Shell from './lib/components/Shell.svelte';
  import { router } from './lib/router.svelte';
  import Overview from './routes/Overview.svelte';
  import Descriptor from './routes/Descriptor.svelte';
  import Tariff from './routes/Tariff.svelte';
  import Billing from './routes/Billing.svelte';
  import Keys from './routes/Keys.svelte';
  import Conformance from './routes/Conformance.svelte';
</script>

<Shell>
  {#if router.current === 'overview'}
    <Overview />
  {:else if router.current === 'descriptor'}
    <Descriptor />
  {:else if router.current === 'tariff'}
    <Tariff />
  {:else if router.current === 'billing'}
    <Billing />
  {:else if router.current === 'keys'}
    <Keys />
  {:else if router.current === 'conformance'}
    <Conformance />
  {/if}
</Shell>
