// tptech-backend/src/modules/valuation/valuation.helpers.ts
import { Prisma } from "@prisma/client";

/* =========================
   Helpers
========================= */

export function toNum(v: any, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

export function assertFinitePositive(n: number, msg: string) {
  if (!Number.isFinite(n) || n <= 0) {
    const err: any = new Error(msg);
    err.status = 400;
    throw err;
  }
}

export function toRefValue(v: any) {
  if (v === undefined || v === null || v === "") return undefined;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) {
    const err: any = new Error("Valor de referencia inválido.");
    err.status = 400;
    throw err;
  }
  return n;
}

export function clampTake(v: any, fallback = 80) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(1, Math.min(200, Math.trunc(n)));
}

export function dec(v: any, fallback = 0) {
  const n = Number(v);
  if (!Number.isFinite(n)) return new Prisma.Decimal(fallback);
  return new Prisma.Decimal(n);
}

export function decOrNull(v: any) {
  if (v === undefined || v === null || v === "") return null;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) return null;
  return new Prisma.Decimal(n);
}

export function assertNonEmpty(s: any, msg: string) {
  const v = String(s ?? "").trim();
  if (!v) {
    const err: any = new Error(msg);
    err.status = 400;
    throw err;
  }
  return v;
}

/**
 * purity: asumimos convención 0..1 (ej: 18k = 0.750)
 */
export function assertPurity(p: any) {
  const n = Number(p);
  if (!Number.isFinite(n) || n <= 0 || n > 1) {
    const err: any = new Error("Pureza/Ley inválida. Usá un valor entre 0 y 1 (ej: 0.750).");
    err.status = 400;
    throw err;
  }
  return n;
}

/**
 * factors: deben ser > 0
 */
export function assertFactor(v: any, name: string) {
  if (v === undefined) return undefined;
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) {
    const err: any = new Error(`${name} inválido. Debe ser mayor a 0.`);
    err.status = 400;
    throw err;
  }
  return n;
}

/**
 * suggested price
 * referenceValue (base currency per gram) * purity
 */
export function computeSuggested(referenceValue: Prisma.Decimal, purity: Prisma.Decimal) {
  return referenceValue.mul(purity);
}

/**
 * final price
 * suggested * factor
 */
export function computeFinal(
  suggested: Prisma.Decimal,
  factor: Prisma.Decimal,
  override: Prisma.Decimal | null
) {
  if (override !== null) return override;
  return suggested.mul(factor);
}

export function hasOverride(v: any) {
  return v !== null && v !== undefined;
}

/* =========================
   Historial profesional
========================= */

/** Redondeo “de almacenamiento” para Decimal(18,6) */
export function round6(n: any) {
  const x = Number(n);
  if (!Number.isFinite(x)) return NaN;
  return Math.round(x * 1_000_000) / 1_000_000;
}

/** Compara dos números redondeados a 6 decimales */
export function same6(a: any, b: any) {
  const ra = round6(a);
  const rb = round6(b);
  if (!Number.isFinite(ra) || !Number.isFinite(rb)) return false;
  return ra === rb;
}

/* =========================
   Conversión FX
========================= */

export function convertPrice(price: number, rate: number | null | undefined) {
  const p = Number(price);
  const r = Number(rate);

  if (!Number.isFinite(p)) return null;
  if (!Number.isFinite(r) || r <= 0) return null;

  return round6(p * r);
}