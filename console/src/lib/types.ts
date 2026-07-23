// Wire types mirrored from crates/admin/src/*.rs — kept 1:1 with the Rust DTOs so this
// client never drifts from the real HTTP surface. See each field's source file in the
// comment above the block.

// broker-economics/src/visibility.rs
export type VisibilityClass = 'blind' | 'blind-routing' | 'terminating';
export type AssuranceLevel = 'structural' | 'attested' | 'declared';

export interface VisibilityDto {
  class: VisibilityClass;
  level: AssuranceLevel;
}

// broker-economics/src/kinds.rs
export type CoordinatorKind =
  | 'gateway'
  | 'relay'
  | 'media-relay'
  | 'reachability-adapter'
  | 'indexer'
  | 'labeler'
  | 'matcher'
  | 'compute'
  | 'arbiter'
  | 'oracle'
  | 'custodial-escrow';

export const COORDINATOR_KINDS: CoordinatorKind[] = [
  'gateway',
  'relay',
  'media-relay',
  'reachability-adapter',
  'indexer',
  'labeler',
  'matcher',
  'compute',
  'arbiter',
  'oracle',
  'custodial-escrow',
];

// admin/src/policy.rs
export interface OperatorPolicy {
  region?: string | null;
  capabilities: string[];
  contact?: string | null;
  notes?: string | null;
}

// broker-billing/src/meter.rs
export type ResourceKind = 'bytes_forwarded' | 'connections' | 'messages' | 'compute_seconds';

export const RESOURCE_KINDS: ResourceKind[] = [
  'bytes_forwarded',
  'connections',
  'messages',
  'compute_seconds',
];

// admin/src/tariff.rs
export interface TariffScheduleDto {
  currency: string;
  prices: Partial<Record<ResourceKind, number>>;
  free_allowance: Partial<Record<ResourceKind, number>>;
  period_seconds?: number | null;
  token?: unknown; // MUST stay absent — carried only so a client attempt to set one is rejected
}

export interface TariffDto {
  identity_hex: string;
  schedule: TariffScheduleDto;
  sig_hex: string;
}

// admin/src/descriptor.rs
export interface SignedDescriptorDto {
  kind: CoordinatorKind;
  identity_hex: string;
  visibility: VisibilityDto;
  policy: OperatorPolicy;
  tariff: TariffDto | null;
  sig_hex: string;
  det_cbor_hex: string;
  note: string;
}

export interface DescriptorPutRequest {
  kind: CoordinatorKind;
  visibility: VisibilityDto;
  policy: OperatorPolicy;
  confirm_downgrade: boolean;
}

export interface DescriptorPutResponse {
  descriptor: SignedDescriptorDto;
  conformance: ReportDto;
}

// admin/src/conformance.rs
export type Outcome = 'pass' | 'violation' | 'behavioral';

export interface FindingDto {
  id: string;
  clause: string;
  outcome: Outcome;
  detail?: string | null;
}

export interface ReportDto {
  kind: CoordinatorKind;
  is_conformant: boolean;
  findings: FindingDto[];
}

// admin/src/billing.rs
export interface UsageDto {
  payer_hex: string;
  usage: Partial<Record<ResourceKind, number>>;
}

export interface ReceiptDto {
  identity_hex: string;
  sig_hex: string;
  payer_hex: string;
  kind: ResourceKind;
  metered_units: number;
  billed_units: number;
  amount: number;
  currency: string;
  sequence: number;
  verifies: boolean;
}

export interface ReceiptsResponse {
  receipts: ReceiptDto[];
  one_directional_audit_caveat: string;
}

// admin/src/quota.rs
export interface QuotaPolicy {
  requests_per_minute?: number | null;
  max_connections?: number | null;
  daily_byte_quota?: number | null;
  notes?: string | null;
}

// admin/src/keys.rs
export interface KeysDto {
  public_key_hex: string;
  history_hex: string[];
}

export interface RotateResponse {
  old_public_key_hex: string;
  new_public_key_hex: string;
  descriptor: SignedDescriptorDto;
}

// --- console-only, not part of the admin API: prepaid billing state (patala rails) ---
export interface PrepaidAccount {
  payer_hex: string;
  payer_label: string;
  balance_minor: number; // integer, minor units of `currency`
  currency: string;
  low_balance_threshold_minor: number;
  monthly_card_enabled: boolean;
}

export interface TopUp {
  id: string;
  at: string; // ISO timestamp
  amount_minor: number;
  currency: string;
  rail: 'stablecoin' | 'card';
  detail: string;
}
