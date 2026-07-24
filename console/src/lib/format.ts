import type { ResourceKind } from './types';

/** Format an integer amount of minor currency units (e.g. micro-USD, or cents) as money. */
export function money(amountMinor: number, currency: string, minorPerUnit = 1_000_000): string {
  const value = amountMinor / minorPerUnit;
  try {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: currency === 'USDC' ? 'USD' : currency,
      minimumFractionDigits: value !== 0 && Math.abs(value) < 1 ? 4 : 2,
      maximumFractionDigits: value !== 0 && Math.abs(value) < 1 ? 4 : 2,
    }).format(value);
  } catch {
    return `${value.toFixed(4)} ${currency}`;
  }
}

/** Prepaid-ledger amounts are stored in cents-equivalent minor units (1e-6 currency). */
export function ledgerMoney(amountMinor: number, currency: string): string {
  return money(amountMinor, currency, 1_000_000);
}

export function compactNumber(n: number): string {
  return new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 }).format(n);
}

export function integer(n: number): string {
  return new Intl.NumberFormat('en-US').format(n);
}

const KIND_LABEL: Record<ResourceKind, string> = {
  bytes_forwarded: 'Data forwarded',
  connections: 'Connections',
  messages: 'Messages',
  compute_seconds: 'Compute time',
};

const KIND_UNIT: Record<ResourceKind, string> = {
  bytes_forwarded: 'MiB',
  connections: 'conn.',
  messages: 'msgs',
  compute_seconds: 'sec',
};

export function kindLabel(k: ResourceKind): string {
  return KIND_LABEL[k] ?? k;
}

export function kindUnit(k: ResourceKind): string {
  return KIND_UNIT[k] ?? '';
}

/** Human-friendly rendering of a raw metered quantity, per resource kind. Every branch routes
 * its whole-number case through `integer()` so thousands separators are consistent with the
 * count-style kinds (connections/messages) below — no bare `toFixed` on a value that can run
 * into four+ digits. */
export function kindQuantity(k: ResourceKind, units: number): string {
  if (k === 'bytes_forwarded') {
    const gib = units / 1024;
    if (gib >= 1) return gib >= 100 ? `${integer(Math.round(gib))} GiB` : `${gib.toFixed(2)} GiB`;
    return `${integer(units)} MiB`;
  }
  if (k === 'compute_seconds') {
    const hours = units / 3600;
    if (hours >= 1) return hours >= 100 ? `${integer(Math.round(hours))} hr` : `${hours.toFixed(1)} hr`;
    return `${integer(units)} sec`;
  }
  return `${integer(units)} ${KIND_UNIT[k]}`;
}

/** Recommended $/natural-unit price for the Pricing view, derived from a per-metered-unit
 * micro-USD price (see api.ts's mock schedule / an operator's real one). */
export function kindRecommendedPrice(k: ResourceKind, microUsdPerUnit: number): string {
  const perNatural: Record<ResourceKind, number> = {
    bytes_forwarded: microUsdPerUnit * 1024, // -> $/GiB
    connections: microUsdPerUnit * 1000, // -> $/1k connections
    messages: microUsdPerUnit * 1000, // -> $/1k messages
    compute_seconds: microUsdPerUnit * 3600, // -> $/compute-hour
  };
  const dollars = perNatural[k] / 1_000_000;
  return `$${dollars.toFixed(dollars < 0.01 ? 4 : dollars < 1 ? 3 : 2)}`;
}

const NATURAL_UNIT_LABEL: Record<ResourceKind, string> = {
  bytes_forwarded: 'GiB forwarded',
  connections: '1,000 connections',
  messages: '1,000 messages',
  compute_seconds: 'compute-hour',
};

export function kindNaturalUnitLabel(k: ResourceKind): string {
  return NATURAL_UNIT_LABEL[k];
}

export function shortHex(hex: string, lead = 8, trail = 6): string {
  if (hex.length <= lead + trail + 1) return hex;
  return `${hex.slice(0, lead)}…${hex.slice(-trail)}`;
}

export function formatDate(iso: string): string {
  const d = new Date(iso);
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(d);
}
