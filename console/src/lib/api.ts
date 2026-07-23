// Typed client for the `admin` crate's HTTP API (crates/admin/src/lib.rs).
//
// Two implementations share one interface: `RealAdminClient` calls a live `wakala-admin`
// instance; `MockAdminClient` serves realistic in-memory fixtures so the console runs
// standalone (VITE_MOCK=1, the default for this build — see console/README.md). The rest
// of the app talks only to `AdminClient` and never knows which backend it got.

import type {
  DescriptorPutRequest,
  DescriptorPutResponse,
  KeysDto,
  PrepaidAccount,
  QuotaPolicy,
  ReceiptDto,
  ReceiptsResponse,
  ReportDto,
  ResourceKind,
  RotateResponse,
  SignedDescriptorDto,
  TariffDto,
  TariffScheduleDto,
  TopUp,
  UsageDto,
} from './types';

export interface AdminClient {
  getDescriptor(): Promise<SignedDescriptorDto>;
  putDescriptor(body: DescriptorPutRequest): Promise<DescriptorPutResponse>;
  getTariff(): Promise<TariffDto | null>;
  putTariff(body: TariffScheduleDto): Promise<TariffDto>;
  getUsage(payerHex: string): Promise<UsageDto>;
  getReceipts(): Promise<ReceiptsResponse>;
  getReceiptsForPayer(payerHex: string): Promise<ReceiptsResponse>;
  runBilling(payerHex: string): Promise<ReceiptsResponse>;
  getQuota(): Promise<QuotaPolicy>;
  putQuota(body: QuotaPolicy): Promise<QuotaPolicy>;
  getKeys(): Promise<KeysDto>;
  rotateKeys(): Promise<RotateResponse>;
  getConformance(): Promise<ReportDto>;
  // Console-only prepaid/patala surface — not part of the admin HTTP API, modeled here so
  // the Billing view has something real to render (CONTRACT §6 leaves settlement to an
  // operator-supplied rail; this is that rail's UI, not a protocol requirement).
  getPrepaidAccounts(): Promise<PrepaidAccount[]>;
  getTopUps(payerHex: string): Promise<TopUp[]>;
  topUp(payerHex: string, amountMinor: number, rail: 'stablecoin' | 'card'): Promise<TopUp>;
  setMonthlyCard(enabled: boolean): Promise<void>;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

/** Talks to a real `wakala-admin` instance (see crates/admin). */
export class RealAdminClient implements AdminClient {
  constructor(
    private baseUrl: string,
    private token: string,
  ) {}

  private async req<T>(path: string, init?: RequestInit): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${this.token}`,
        ...(init?.headers ?? {}),
      },
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({ error: res.statusText }));
      throw new ApiError(res.status, body.error ?? res.statusText);
    }
    if (res.status === 204) return undefined as T;
    return res.json();
  }

  getDescriptor() {
    return this.req<SignedDescriptorDto>('/descriptor');
  }
  putDescriptor(body: DescriptorPutRequest) {
    return this.req<DescriptorPutResponse>('/descriptor', {
      method: 'PUT',
      body: JSON.stringify(body),
    });
  }
  getTariff() {
    return this.req<TariffDto | null>('/tariff');
  }
  putTariff(body: TariffScheduleDto) {
    return this.req<TariffDto>('/tariff', { method: 'PUT', body: JSON.stringify(body) });
  }
  getUsage(payerHex: string) {
    return this.req<UsageDto>(`/usage/${payerHex}`);
  }
  getReceipts() {
    return this.req<ReceiptsResponse>('/receipts');
  }
  getReceiptsForPayer(payerHex: string) {
    return this.req<ReceiptsResponse>(`/receipts/${payerHex}`);
  }
  runBilling(payerHex: string) {
    return this.req<ReceiptsResponse>(`/billing/run/${payerHex}`, { method: 'POST' });
  }
  getQuota() {
    return this.req<QuotaPolicy>('/quota');
  }
  putQuota(body: QuotaPolicy) {
    return this.req<QuotaPolicy>('/quota', { method: 'PUT', body: JSON.stringify(body) });
  }
  getKeys() {
    return this.req<KeysDto>('/keys');
  }
  rotateKeys() {
    return this.req<RotateResponse>('/keys/rotate', { method: 'POST' });
  }
  getConformance() {
    return this.req<ReportDto>('/conformance');
  }
  // The real admin API has no prepaid/patala surface (CONTRACT §6 leaves settlement to an
  // operator-supplied rail) — a real deployment wires these three to whatever rail it runs.
  // Wired here to the same-origin `/patala/*` convention so an operator can stand up that
  // proxy without forking this client.
  getPrepaidAccounts() {
    return this.req<PrepaidAccount[]>('/patala/accounts');
  }
  getTopUps(payerHex: string) {
    return this.req<TopUp[]>(`/patala/topups/${payerHex}`);
  }
  topUp(payerHex: string, amountMinor: number, rail: 'stablecoin' | 'card') {
    return this.req<TopUp>(`/patala/topups/${payerHex}`, {
      method: 'POST',
      body: JSON.stringify({ amount_minor: amountMinor, rail }),
    });
  }
  setMonthlyCard(enabled: boolean) {
    return this.req<void>('/patala/monthly-card', {
      method: 'PUT',
      body: JSON.stringify({ enabled }),
    });
  }
}

// ---------------------------------------------------------------------------------------
// Mock fixtures — a believable single-operator demo posture.
//
// Kind: `reachability-adapter` declaring `blind-routing` at `declared` assurance — the
// exact "bare adapter-zone vanity" example broker-economics' own tests use (REACH-1a):
// it lets the UI demonstrate the §3.4 "declared, not verified" duty on a claim that is
// genuinely still in the blind family, rather than only on the trivial terminating case.
// ---------------------------------------------------------------------------------------

import type { CoordinatorKind, VisibilityClass, AssuranceLevel } from './types';

const MOCK_IDENTITY_HEX =
  'b47a1c9de3f8025671cdb4a90f3e2c8815a6d4b7f0912e3ac5d78b4109fce62';
const MOCK_IDENTITY_HEX_OLD =
  '4f1e9a02c7b356d8ea41902cf6b7d3a15908e6c4b21a7f0398de562179ca4bb';

const MOCK_KIND: CoordinatorKind = 'reachability-adapter';
const MOCK_VIS_CLASS: VisibilityClass = 'blind-routing';
const MOCK_VIS_LEVEL: AssuranceLevel = 'declared';

const PAYER_A = 'c1a2b3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff0';
const PAYER_B = '02fd91ee7c6b5a493827160f5e4d3c2b1a09f8e7d6c5b4a392817060504a3c2';
const PAYER_C = '77aa66bb55cc44dd33ee22ff11009988776655443322110099887766554433';

function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v));
}

function fakeSig(seed: string): string {
  // Deterministic-looking 64-byte hex, cosmetic only — never a real signature.
  let s = '';
  let x = 0;
  for (let i = 0; i < seed.length; i++) x = (x * 31 + seed.charCodeAt(i)) >>> 0;
  for (let i = 0; i < 128; i++) {
    x = (x * 1103515245 + 12345) >>> 0;
    s += (x % 16).toString(16);
  }
  return s;
}

const TARIFF_SCHEDULE: TariffScheduleDto = {
  currency: 'USD',
  // Integer minor-units-of-USD (micro-USD, 1e-6 USD) per metered unit — see console/README.md
  // for the exact per-kind conversion the Pricing view displays.
  prices: {
    bytes_forwarded: 6, // micro-USD / MiB forwarded
    connections: 40, // micro-USD / connection
    messages: 15, // micro-USD / message
    compute_seconds: 14, // micro-USD / compute-second
  },
  free_allowance: {
    bytes_forwarded: 5_000, // 5,000 MiB (~4.9 GiB) free per period
    connections: 500,
    messages: 2_000,
    compute_seconds: 0,
  },
  period_seconds: 2_592_000, // 30 days
};

const DESCRIPTOR_POLICY = {
  region: 'eu-west',
  capabilities: ['reachability-adapter', 'sni-passthrough', 'own-domain-cert'],
  contact: 'ops@harborline.example',
  notes:
    'Public reachable ingress for self-hosted boxes. SNI-passthrough profile; operator does not hold the origin TLS key for adapter-zone vanity names.',
};

function mockTariffDto(): TariffDto {
  return {
    identity_hex: MOCK_IDENTITY_HEX,
    schedule: clone(TARIFF_SCHEDULE),
    sig_hex: fakeSig('tariff' + MOCK_IDENTITY_HEX),
  };
}

function mockDescriptorDto(identityHex = MOCK_IDENTITY_HEX): SignedDescriptorDto {
  return {
    kind: MOCK_KIND,
    identity_hex: identityHex,
    visibility: { class: MOCK_VIS_CLASS, level: MOCK_VIS_LEVEL },
    policy: clone(DESCRIPTOR_POLICY),
    tariff: mockTariffDto(),
    sig_hex: fakeSig('descriptor' + identityHex),
    det_cbor_hex: fakeSig('cbor' + identityHex) + fakeSig('cbor2' + identityHex),
    note:
      'discovery-only, self-asserted (CONTRACT §2.1): carries no global reputation score, no price ranking, and no stake field by construction',
  };
}

function mockConformanceReport(): ReportDto {
  return {
    kind: MOCK_KIND,
    is_conformant: true,
    findings: [
      {
        id: 'COORD-1',
        clause: '§2.1',
        outcome: 'behavioral',
        detail: 'verify descriptor signature once kotva-core is pinned',
      },
      { id: 'COORD-2', clause: '§2.2', outcome: 'pass' },
      { id: 'COORD-3', clause: '§2.3', outcome: 'pass' },
      {
        id: 'COORD-4',
        clause: '§2.4/§3',
        outcome: 'behavioral',
        detail:
          'declared-level blind-routing / declared claim: client MUST surface it as unverified, not verified (§3.4)',
      },
      {
        id: 'COORD-5',
        clause: '§3.2',
        outcome: 'behavioral',
        detail: 'assert observed TLS behavior matches the declared visibility class',
      },
      { id: 'COORD-6', clause: '§4', outcome: 'pass' },
      { id: 'COORD-7', clause: '§6', outcome: 'pass' },
      { id: 'COORD-8', clause: '§6', outcome: 'pass' },
    ],
  };
}

interface MockReceiptSeed {
  payer: string;
  kind: ResourceKind;
  metered: number;
  billed: number;
  amount: number;
  sequence: number;
}

const RECEIPT_SEEDS: MockReceiptSeed[] = [
  { payer: PAYER_A, kind: 'bytes_forwarded', metered: 2_411_000, billed: 2_406_000, amount: 14_436_000, sequence: 41 },
  { payer: PAYER_A, kind: 'connections', metered: 156_200, billed: 155_700, amount: 6_228_000, sequence: 42 },
  { payer: PAYER_A, kind: 'messages', metered: 947_300, billed: 945_300, amount: 14_179_500, sequence: 43 },
  { payer: PAYER_A, kind: 'compute_seconds', metered: 270_400, billed: 270_400, amount: 3_785_600, sequence: 44 },
  { payer: PAYER_B, kind: 'bytes_forwarded', metered: 612_000, billed: 607_000, amount: 3_642_000, sequence: 17 },
  { payer: PAYER_B, kind: 'messages', metered: 118_400, billed: 116_400, amount: 1_746_000, sequence: 18 },
  { payer: PAYER_C, kind: 'connections', metered: 8_900, billed: 8_400, amount: 336_000, sequence: 5 },
  { payer: PAYER_C, kind: 'compute_seconds', metered: 41_200, billed: 41_200, amount: 576_800, sequence: 6 },
];

function receiptFromSeed(s: MockReceiptSeed): ReceiptDto {
  return {
    identity_hex: MOCK_IDENTITY_HEX,
    sig_hex: fakeSig(`receipt-${s.payer}-${s.kind}-${s.sequence}`),
    payer_hex: s.payer,
    kind: s.kind,
    metered_units: s.metered,
    billed_units: s.billed,
    amount: s.amount,
    currency: 'USD',
    sequence: s.sequence,
    verifies: true,
  };
}

const AUDIT_CAVEAT =
  "a signed usage receipt proves the operator's key produced this claim; it does NOT prove the claim is true, and it cannot prove every chargeable operation was receipted at all — the one-directional audit (CONTRACT §6, R-6). Disclosed, not hidden.";

const PREPAID_ACCOUNTS: PrepaidAccount[] = [
  {
    payer_hex: PAYER_A,
    payer_label: 'Northwind Delivery Co.',
    balance_minor: 612_400_000, // $612.40 — comfortably above its ~$39/period usage
    currency: 'USD',
    low_balance_threshold_minor: 100_000_000, // $100
    monthly_card_enabled: false,
  },
  {
    payer_hex: PAYER_B,
    payer_label: 'Sable & Finch Studio',
    balance_minor: 18_190_000, // $18.19 — below its own threshold, a live low-balance example
    currency: 'USD',
    low_balance_threshold_minor: 20_000_000, // $20
    monthly_card_enabled: true,
  },
  {
    payer_hex: PAYER_C,
    payer_label: 'Ridge Line Freight',
    balance_minor: 511_200_000, // $511.20
    currency: 'USD',
    low_balance_threshold_minor: 50_000_000, // $50
    monthly_card_enabled: false,
  },
];

const TOPUPS: Record<string, TopUp[]> = {
  [PAYER_A]: [
    { id: 'tu_9f3a', at: '2026-07-18T09:14:00Z', amount_minor: 5_000_000, currency: 'USD', rail: 'stablecoin', detail: 'USDC — patala rail, 0xa1…4c2' },
    { id: 'tu_8b21', at: '2026-06-21T16:02:00Z', amount_minor: 5_000_000, currency: 'USD', rail: 'card', detail: 'patala-hyperswitch — Visa •••• 4417' },
  ],
  [PAYER_B]: [
    { id: 'tu_7c10', at: '2026-07-20T11:47:00Z', amount_minor: 1_000_000, currency: 'USD', rail: 'card', detail: 'patala-hyperswitch — Mastercard •••• 9012' },
  ],
  [PAYER_C]: [
    { id: 'tu_6a55', at: '2026-07-10T08:30:00Z', amount_minor: 3_000_000, currency: 'USD', rail: 'stablecoin', detail: 'USDC — patala rail, 0xd4…91f' },
  ],
};

const USAGE_BY_PAYER: Record<string, Partial<Record<ResourceKind, number>>> = {
  [PAYER_A]: { bytes_forwarded: 812_400, connections: 41_200, messages: 260_100, compute_seconds: 74_000 },
  [PAYER_B]: { bytes_forwarded: 194_300, connections: 9_800, messages: 38_900, compute_seconds: 0 },
  [PAYER_C]: { bytes_forwarded: 0, connections: 2_100, messages: 0, compute_seconds: 11_400 },
};

/** In-memory mock backend — realistic fixtures, real interactivity (PUT/rotate/run actually
 * mutate this module's state), no network. Used when `VITE_MOCK=1` (this build's default). */
export class MockAdminClient implements AdminClient {
  private descriptor: SignedDescriptorDto = mockDescriptorDto();
  private history: string[] = [MOCK_IDENTITY_HEX_OLD];
  private tariff: TariffDto | null = mockTariffDto();
  private quota: QuotaPolicy = {
    requests_per_minute: 600,
    max_connections: 2_000,
    daily_byte_quota: 500_000_000_000,
    notes: 'Baseline profile for a single mid-size adapter-zone box; raise before onboarding a high-fanout tenant.',
  };
  private receipts: ReceiptDto[] = RECEIPT_SEEDS.map(receiptFromSeed);
  private accounts: PrepaidAccount[] = clone(PREPAID_ACCOUNTS);
  private topups: Record<string, TopUp[]> = clone(TOPUPS);
  private latency: number;

  constructor(latencyMs = 220) {
    this.latency = latencyMs;
  }

  private async wait<T>(v: T): Promise<T> {
    await new Promise((r) => setTimeout(r, this.latency));
    return clone(v);
  }

  async getDescriptor() {
    return this.wait(this.descriptor);
  }

  async putDescriptor(body: DescriptorPutRequest): Promise<DescriptorPutResponse> {
    const currentRank = visRank(this.descriptor.visibility);
    const nextRank = visRank(body.visibility);
    const isDowngrade =
      nextRank.classRank > currentRank.classRank ||
      (nextRank.classRank === currentRank.classRank && nextRank.levelRank > currentRank.levelRank);
    if (isDowngrade && !body.confirm_downgrade) {
      throw new ApiError(
        409,
        `declaring ${body.visibility.class} / ${body.visibility.level} after ${this.descriptor.visibility.class} / ${this.descriptor.visibility.level} is a visibility downgrade (CONTRACT §3.2: no silent downgrade); resubmit with "confirm_downgrade": true to disclose it explicitly`,
      );
    }
    this.descriptor = {
      ...this.descriptor,
      kind: body.kind,
      visibility: body.visibility,
      policy: body.policy,
      sig_hex: fakeSig('descriptor' + Date.now()),
    };
    await new Promise((r) => setTimeout(r, this.latency));
    return clone({ descriptor: this.descriptor, conformance: this.recompute() });
  }

  private recompute(): ReportDto {
    const report = mockConformanceReport();
    report.kind = this.descriptor.kind;
    const v = this.descriptor.visibility;
    const idx = report.findings.findIndex((f) => f.id === 'COORD-4');
    if (idx >= 0) {
      const mustWarn = v.class !== 'terminating' && v.level === 'declared';
      report.findings[idx] = mustWarn
        ? {
            id: 'COORD-4',
            clause: '§2.4/§3',
            outcome: 'behavioral',
            detail: `declared-level ${v.class} / ${v.level} claim: client MUST surface it as unverified, not verified (§3.4)`,
          }
        : { id: 'COORD-4', clause: '§2.4/§3', outcome: 'pass' };
    }
    report.is_conformant = !report.findings.some((f) => f.outcome === 'violation');
    return report;
  }

  async getTariff() {
    return this.wait(this.tariff);
  }

  async putTariff(body: TariffScheduleDto): Promise<TariffDto> {
    if (body.token != null) {
      throw new ApiError(
        400,
        'no protocol token: KOTVA mints none, ever (CONTRACT §6, DIRECTION §5) — price in an existing currency/asset ("currency") instead, and drop the "token" field',
      );
    }
    this.tariff = {
      identity_hex: this.descriptor.identity_hex,
      schedule: body,
      sig_hex: fakeSig('tariff' + Date.now()),
    };
    this.descriptor = { ...this.descriptor, tariff: this.tariff };
    await new Promise((r) => setTimeout(r, this.latency));
    return clone(this.tariff);
  }

  async getUsage(payerHex: string): Promise<UsageDto> {
    return this.wait({ payer_hex: payerHex, usage: USAGE_BY_PAYER[payerHex] ?? {} });
  }

  async getReceipts(): Promise<ReceiptsResponse> {
    return this.wait({ receipts: this.receipts, one_directional_audit_caveat: AUDIT_CAVEAT });
  }

  async getReceiptsForPayer(payerHex: string): Promise<ReceiptsResponse> {
    return this.wait({
      receipts: this.receipts.filter((r) => r.payer_hex === payerHex),
      one_directional_audit_caveat: AUDIT_CAVEAT,
    });
  }

  async runBilling(payerHex: string): Promise<ReceiptsResponse> {
    if (!this.tariff) {
      throw new ApiError(409, 'no tariff configured; PUT /tariff first');
    }
    const usage = USAGE_BY_PAYER[payerHex] ?? {};
    const issued: ReceiptDto[] = [];
    let seq = this.receipts.filter((r) => r.payer_hex === payerHex).length + 1;
    for (const [kind, units] of Object.entries(usage) as [ResourceKind, number][]) {
      if (!units) continue;
      const price = this.tariff.schedule.prices[kind] ?? 0;
      const free = this.tariff.schedule.free_allowance[kind] ?? 0;
      const billedUnits = Math.max(0, units - free);
      const amount = billedUnits * price;
      const receipt: ReceiptDto = {
        identity_hex: this.descriptor.identity_hex,
        sig_hex: fakeSig(`run-${payerHex}-${kind}-${Date.now()}`),
        payer_hex: payerHex,
        kind,
        metered_units: units,
        billed_units: billedUnits,
        amount,
        currency: this.tariff.schedule.currency,
        sequence: seq++,
        verifies: true,
      };
      issued.push(receipt);
      this.receipts.push(receipt);
    }
    USAGE_BY_PAYER[payerHex] = {};
    await new Promise((r) => setTimeout(r, this.latency));
    return clone({ receipts: issued, one_directional_audit_caveat: AUDIT_CAVEAT });
  }

  async getQuota() {
    return this.wait(this.quota);
  }

  async putQuota(body: QuotaPolicy) {
    this.quota = body;
    return this.wait(this.quota);
  }

  async getKeys(): Promise<KeysDto> {
    return this.wait({ public_key_hex: this.descriptor.identity_hex, history_hex: this.history });
  }

  async rotateKeys(): Promise<RotateResponse> {
    const oldPub = this.descriptor.identity_hex;
    const newPub = fakeSig('rotated' + Date.now()).slice(0, 64);
    this.history = [...this.history, oldPub];
    this.descriptor = { ...this.descriptor, identity_hex: newPub, sig_hex: fakeSig('descriptor' + newPub) };
    await new Promise((r) => setTimeout(r, this.latency));
    return clone({ old_public_key_hex: oldPub, new_public_key_hex: newPub, descriptor: this.descriptor });
  }

  async getConformance(): Promise<ReportDto> {
    return this.wait(this.recompute());
  }

  async getPrepaidAccounts() {
    return this.wait(this.accounts);
  }

  async getTopUps(payerHex: string) {
    return this.wait(this.topups[payerHex] ?? []);
  }

  async topUp(payerHex: string, amountMinor: number, rail: 'stablecoin' | 'card'): Promise<TopUp> {
    const account = this.accounts.find((a) => a.payer_hex === payerHex);
    if (!account) throw new ApiError(404, 'unknown payer');
    account.balance_minor += amountMinor;
    const entry: TopUp = {
      id: 'tu_' + Math.random().toString(16).slice(2, 6),
      at: new Date().toISOString(),
      amount_minor: amountMinor,
      currency: account.currency,
      rail,
      detail:
        rail === 'stablecoin'
          ? 'USDC — patala rail'
          : 'patala-hyperswitch — card on file',
    };
    this.topups[payerHex] = [entry, ...(this.topups[payerHex] ?? [])];
    await new Promise((r) => setTimeout(r, this.latency));
    return clone(entry);
  }

  async setMonthlyCard(enabled: boolean): Promise<void> {
    for (const a of this.accounts) a.monthly_card_enabled = enabled;
    await new Promise((r) => setTimeout(r, this.latency));
  }
}

function visRank(v: { class: VisibilityClass; level: AssuranceLevel }) {
  const classRank = { blind: 0, 'blind-routing': 1, terminating: 2 }[v.class];
  const levelRank = { structural: 0, attested: 1, declared: 2 }[v.level];
  return { classRank, levelRank };
}

export const DEFAULT_PAYER_HEX = PAYER_A;
export const MOCK_PAYERS = [PAYER_A, PAYER_B, PAYER_C];

// ---------------------------------------------------------------------------------------
// Client factory
// ---------------------------------------------------------------------------------------

export function createClient(): AdminClient {
  const isMock = import.meta.env.VITE_MOCK !== '0';
  if (isMock) return new MockAdminClient();
  const base = import.meta.env.VITE_API_BASE ?? 'http://127.0.0.1:8090';
  const token = localStorage.getItem('wakala:admin-token') ?? import.meta.env.VITE_ADMIN_TOKEN ?? '';
  return new RealAdminClient(base, token);
}

export const IS_MOCK = import.meta.env.VITE_MOCK !== '0';

/** Singleton client the whole app shares — one mock backend instance so state (a signed
 * descriptor, an issued receipt, a rotated key) stays consistent across views/navigation. */
export const client: AdminClient = createClient();
