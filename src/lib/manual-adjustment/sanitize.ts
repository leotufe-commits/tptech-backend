// src/lib/manual-adjustment/sanitize.ts
// =============================================================================
// Sanitizer puro de la intención del operador (`manualAdjustment`).
//
// Compartido entre:
//   · sales.controller (valida el body del request).
//   · sales.service    (defensa en profundidad: revalida al persistir DRAFT
//                       y al consumir el DRAFT en confirm).
//
// Reglas (POLICY §R-Rounding-1 capa 17 + CLAUDE.md §Etapa A/C):
//   · Scope DEBE ser "UNIFIED" o "BREAKDOWN". Otros → 400.
//   · UNIFIED: requiere amount con |amount| > EPS_MONEY → normalizado a
//     { scope, amount, reason }.
//   · BREAKDOWN: metals[] + monetaryAmount opcionales. Cada metal acepta
//     targetGrams (≥0) y/o deltaGrams (cualquier signo). Entries sin
//     instrucción útil se descartan silenciosamente.
//   · Si todo el ajuste resulta vacío → `null` (no se persiste).
//   · Trim de `reason`; vacío → null.
//
// El gate "BREAKDOWN solo cuando documento opera en modo BREAKDOWN" NO
// vive acá — el sanitizer no tiene contexto del documento. Lo aplica el
// service cuando ya resolvió el balanceMode.
// =============================================================================

import type {
  ManualAdjustmentInput,
  ManualAdjustmentMetalInput,
} from "./types.js";

export const MANUAL_ADJUSTMENT_EPS_MONEY = 0.005;
export const MANUAL_ADJUSTMENT_EPS_GRAMS = 0.0001;

function err400(message: string): never {
  const e: any = new Error(message);
  e.status = 400;
  throw e;
}

function sanitizeReason(raw: any): string | null {
  if (typeof raw !== "string") return null;
  const t = raw.trim();
  return t.length > 0 ? t : null;
}

function sanitizeMetalEntries(
  raw: any,
  context: string,
): ManualAdjustmentMetalInput[] {
  if (raw == null) return [];
  if (!Array.isArray(raw)) {
    err400(`${context}.breakdown.metals: debe ser arreglo.`);
  }
  const out: ManualAdjustmentMetalInput[] = [];
  (raw as any[]).forEach((entry, idx) => {
    if (entry == null || typeof entry !== "object") {
      err400(`${context}.breakdown.metals[${idx}]: debe ser objeto.`);
    }
    const path = `${context}.breakdown.metals[${idx}]`;

    let metalParentId: string | null = null;
    if (typeof entry.metalParentId === "string" && entry.metalParentId.trim().length > 0) {
      metalParentId = entry.metalParentId.trim();
    } else if (entry.metalParentId !== undefined && entry.metalParentId !== null) {
      err400(`${path}.metalParentId: debe ser string o null.`);
    }

    const metalParentName =
      typeof entry.metalParentName === "string" ? entry.metalParentName.trim() : undefined;

    let targetGrams: number | undefined;
    if (entry.targetGrams !== undefined && entry.targetGrams !== null) {
      const tg = Number(entry.targetGrams);
      if (!Number.isFinite(tg)) err400(`${path}.targetGrams: debe ser número finito.`);
      if (tg < 0)               err400(`${path}.targetGrams: no puede ser negativo.`);
      targetGrams = tg;
    }

    let deltaGrams: number | undefined;
    if (entry.deltaGrams !== undefined && entry.deltaGrams !== null) {
      const dg = Number(entry.deltaGrams);
      if (!Number.isFinite(dg)) err400(`${path}.deltaGrams: debe ser número finito.`);
      deltaGrams = dg;
    }

    const hasTarget = typeof targetGrams === "number";
    const hasDelta  = typeof deltaGrams === "number" && Math.abs(deltaGrams) > MANUAL_ADJUSTMENT_EPS_GRAMS;
    if (!hasTarget && !hasDelta) return;

    out.push({
      metalParentId,
      metalParentName,
      ...(hasTarget ? { targetGrams: targetGrams as number } : {}),
      ...(hasDelta  ? { deltaGrams:  deltaGrams  as number } : {}),
      reason: sanitizeReason(entry.reason),
    });
  });
  return out;
}

export function sanitizeManualAdjustmentInput(
  raw: any,
  context: string = "manualAdjustment",
): ManualAdjustmentInput | null {
  if (raw == null) return null;
  if (typeof raw !== "object") err400(`${context}: debe ser objeto.`);

  const scopeRaw = raw.scope;
  if (scopeRaw !== undefined && scopeRaw !== null && scopeRaw !== "UNIFIED" && scopeRaw !== "BREAKDOWN") {
    err400(
      `${context}.scope: solo "UNIFIED" o "BREAKDOWN" están soportados. ` +
      `Recibido: ${JSON.stringify(scopeRaw)}.`,
    );
  }

  const reason = sanitizeReason(raw.reason);

  if (scopeRaw === "BREAKDOWN") {
    const breakdownRoot = raw.breakdown && typeof raw.breakdown === "object" ? raw.breakdown : raw;
    const metals = sanitizeMetalEntries(breakdownRoot.metals, context);

    let monetaryAmount: number | undefined;
    const rawMonetary = breakdownRoot.monetaryAmount;
    if (rawMonetary !== undefined && rawMonetary !== null) {
      const n = Number(rawMonetary);
      if (!Number.isFinite(n)) {
        err400(`${context}.breakdown.monetaryAmount: debe ser número finito.`);
      }
      if (Math.abs(n) > MANUAL_ADJUSTMENT_EPS_MONEY) monetaryAmount = n;
    }

    if (metals.length === 0 && monetaryAmount === undefined) return null;

    return {
      scope:  "BREAKDOWN",
      metals,
      ...(monetaryAmount !== undefined ? { monetaryAmount } : {}),
      reason,
    };
  }

  // UNIFIED (default cuando viene unified.amount sin scope).
  const amountRaw =
    typeof raw.amount === "number"
      ? raw.amount
      : typeof raw.unified?.amount === "number"
        ? raw.unified.amount
        : null;

  if (amountRaw == null || !Number.isFinite(amountRaw)) return null;
  if (Math.abs(amountRaw) <= MANUAL_ADJUSTMENT_EPS_MONEY) return null;

  return {
    scope:  "UNIFIED",
    amount: amountRaw,
    reason,
  };
}
