// src/lib/manual-adjustment/buildSnapshot.ts
// =============================================================================
// Manual Adjustment — helper PURO para armar el snapshot + computar finalTotal.
//
// Etapa A — UNIFIED — implementado.
// Etapa C — BREAKDOWN — implementado (solo manual). Ver POLICY §R-Rounding-1
// capa 17 y §R-Rounding-13 para la separación con redondeo físico futuro.
//
// Sin DB, sin async, sin matemática del motor. Determinístico — mismo input →
// mismo output. Imprescindible para preview/confirm parity.
//
// ── Definición canónica (POLICY §R-Rounding-1) ─────────────────────────────
//
// UNIFIED:
//   Ajuste global sobre el total del comprobante (no distingue dominios).
//
// BREAKDOWN:
//   Ajuste sobre el saldo desglosado del documento. Dominios DISJUNTOS:
//     a) Cada metal padre en GRAMOS.
//     b) Bucket HECHURA / SALDO MONETARIO = todo lo no-metal-padre
//        (hechura + productos + servicios + impuestos + envío + descuentos +
//        cupones + canal + forma de pago + redondeos monetarios).
//
//   Principio "no mezclar":
//     · Ajustes de gramos viven SOLO en su metal padre.
//     · Ajustes monetarios viven SOLO en el bucket hechura/saldo.
//
//   Equivalencia monetaria de ajustes en metales padre (regla crítica —
//   paralelo al redondeo BREAKDOWN):
//     · `monetaryEquivalent` = deltaGrams × metalPricePerGram.
//     · SÍ impacta Sale.total, totals.metalMonetaryEquivalent y
//       totals.totalMonetaryAdjustment.
//     · NO mueve el valor a breakdown.monetary.amount (hechura).
//     · NO convierte el ajuste físico en "ajuste monetario de hechura".
//     · El ajuste físico sigue perteneciendo al metal padre.
//     · Resultado: dos dominios PARALELOS (METAL + HECHURA/SALDO) que
//       consolidan financieramente en `totalMonetaryAdjustment` sin
//       mezclarse conceptualmente.
//
// ── Contrato universal del snapshot (rige siempre) ─────────────────────────
//   Sale.total = max(0, Sale.engineTotal + snapshot.totals.totalMonetaryAdjustment)
//
//   UNIFIED:
//     totals.monetaryAdjustment      = unified.amount efectivo
//     totals.metalMonetaryEquivalent = 0
//     totals.totalMonetaryAdjustment = monetaryAdjustment
//
//   BREAKDOWN:
//     totals.monetaryAdjustment      = breakdown.monetary.amount efectivo
//                                    = ajuste solo sobre hechura/saldo
//     totals.metalMonetaryEquivalent = Σ breakdown.metals[].monetaryEquivalent
//                                    = equivalente $ del delta físico de gramos
//     totals.totalMonetaryAdjustment = monetaryAdjustment + metalMonetaryEquivalent
//                                    = consolidado financiero (clamp Sale.total)
// =============================================================================

import type {
  ManualAdjustmentInput,
  ManualAdjustmentInputBreakdown,
  ManualAdjustmentSnapshot,
  ManualAdjustmentSnapshotMetalEntry,
  ManualAdjustmentSnapshotMonetaryLayer,
  ManualAdjustmentSnapshotTotals,
  ManualAdjustmentPreview,
  ManualAdjustmentAudit,
  ManualAdjustmentBreakdownContext,
  ManualAdjustmentMetalContextItem,
} from "./types.js";
import { traceDocument } from "../pricing-engine/pricing-trace.js";

const EPS_MONEY = 0.005;
const EPS_GRAMS = 0.0001;
const round2 = (n: number): number => Math.round(n * 100) / 100;
const round4Grams = (n: number): number => Math.round(n * 10000) / 10000;

/**
 * Construye el snapshot + finalTotal a partir del engineTotal del motor y la
 * intención del operador.
 *
 *   · UNIFIED  — capa única, opcionalmente `breakdownContext = null`.
 *   · BREAKDOWN — necesita `breakdownContext` con metales + monetaryHechura.
 *
 * Reglas (ambos scopes):
 *   · `finalTotal` NUNCA es negativo (clamp a 0).
 *   · Si el clamp recorta el delta, el snapshot refleja el delta EFECTIVO
 *     (postAmount - preAmount) en lugar del tipeado.
 *   · Si el input no propone movimiento significativo (EPS-money y EPS-gramos),
 *     se devuelve `snapshot=null` y `finalTotal=engineTotal`.
 *   · Para BREAKDOWN sin contexto válido → snapshot=null (caller no proveyó
 *     metales / monetaryHechura; el preview debe seguir respondiendo).
 *   · El motor NO se llama desde acá — passthrough numérico puro.
 */
export function buildManualAdjustmentSnapshot(args: {
  engineTotal: number;
  input:       ManualAdjustmentInput | null | undefined;
  audit:       ManualAdjustmentAudit | null;
  /** Contexto BREAKDOWN. Requerido si input.scope === "BREAKDOWN".
   *  Si está ausente y el input es BREAKDOWN, el helper devuelve snapshot=null
   *  (no inventa metales). */
  breakdownContext?: ManualAdjustmentBreakdownContext | null;
}): ManualAdjustmentPreview {
  const engineTotal = round2(Number(args.engineTotal) || 0);
  const input = args.input ?? null;

  const result = (() => {
    if (input == null) {
      return passthrough(engineTotal);
    }
    if (input.scope !== "UNIFIED" && input.scope !== "BREAKDOWN") {
      return passthrough(engineTotal);
    }
    if (input.scope === "UNIFIED") {
      return buildUnified(engineTotal, input.amount, args.audit, input.reason ?? null);
    }
    if (!args.breakdownContext) {
      return passthrough(engineTotal);
    }
    return buildBreakdown(
      engineTotal,
      input,
      args.breakdownContext,
      args.audit,
      input.reason ?? null,
    );
  })();

  // ── pricing-trace L14 (ajuste manual) + L15 (final total) ────────────────
  // No altera lógica — solo emite eventos si PRICING_TRACE está activo.
  traceDocument("L14_MANUAL_ADJUSTMENT", {
    applied:                 result.snapshot != null,
    scope:                   result.snapshot?.scope ?? null,
    monetaryAdjustment:      result.snapshot?.totals.monetaryAdjustment      ?? 0,
    metalMonetaryEquivalent: result.snapshot?.totals.metalMonetaryEquivalent ?? 0,
    totalMonetaryAdjustment: result.snapshot?.totals.totalMonetaryAdjustment ?? 0,
    unified: result.snapshot?.unified
      ? {
          preAmount:  result.snapshot.unified.preAmount,
          postAmount: result.snapshot.unified.postAmount,
          amount:     result.snapshot.unified.amount,
        }
      : null,
    breakdown: result.snapshot?.breakdown
      ? {
          metals: result.snapshot.breakdown.metals.map((m) => ({
            metalParentName:   m.metalParentName,
            preGrams:          m.preGrams,
            postGrams:         m.postGrams,
            deltaGrams:        m.deltaGrams,
            metalPricePerGram: m.metalPricePerGram,
            monetaryEquivalent: m.monetaryEquivalent,
          })),
          monetary: {
            preAmount:  result.snapshot.breakdown.monetary.preAmount,
            amount:     result.snapshot.breakdown.monetary.amount,
            postAmount: result.snapshot.breakdown.monetary.postAmount,
          },
        }
      : null,
  });
  traceDocument("L15_FINAL_TOTAL", {
    engineTotal: result.engineTotal,
    delta:       round2(result.finalTotal - result.engineTotal),
    finalTotal:  result.finalTotal,
    clampedToZero: result.finalTotal === 0
      && (result.engineTotal + (result.snapshot?.totals.totalMonetaryAdjustment ?? 0)) < 0,
  });

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers internos
// ─────────────────────────────────────────────────────────────────────────────

function passthrough(engineTotal: number): ManualAdjustmentPreview {
  return { snapshot: null, engineTotal, finalTotal: engineTotal };
}

function buildAudit(
  audit: ManualAdjustmentAudit | null,
  reason: string | null,
): ManualAdjustmentAudit {
  if (audit) {
    // Si el caller ya armó audit, lo respetamos. Si el input traía reason
    // y el audit no, lo propagamos.
    if (audit.reason == null && reason != null) {
      return { ...audit, reason };
    }
    return audit;
  }
  return {
    appliedBy: null,
    appliedAt: new Date().toISOString(),
    reason,
  };
}

function buildUnified(
  engineTotal: number,
  requestedAmount: number,
  audit: ManualAdjustmentAudit | null,
  reason: string | null,
): ManualAdjustmentPreview {
  if (!Number.isFinite(requestedAmount) || Math.abs(requestedAmount) <= EPS_MONEY) {
    return passthrough(engineTotal);
  }

  // Clamp defensivo: finalTotal no puede ser negativo.
  const naive       = round2(engineTotal + requestedAmount);
  const finalTotal  = Math.max(0, naive);
  const effective   = round2(finalTotal - engineTotal);

  const totals: ManualAdjustmentSnapshotTotals = {
    monetaryAdjustment:      effective,
    metalMonetaryEquivalent: 0,
    totalMonetaryAdjustment: effective,
  };

  const snapshot: ManualAdjustmentSnapshot = {
    scope: "UNIFIED",
    unified: {
      preAmount:  engineTotal,
      postAmount: finalTotal,
      amount:     effective,
    },
    totals,
    audit: buildAudit(audit, reason),
  };

  return { snapshot, engineTotal, finalTotal };
}

function buildBreakdown(
  engineTotal: number,
  input: ManualAdjustmentInputBreakdown,
  ctx:   ManualAdjustmentBreakdownContext,
  audit: ManualAdjustmentAudit | null,
  reason: string | null,
): ManualAdjustmentPreview {
  // 1) Resolver metals: matchear input vs context por metalParentId/nombre.
  const metalsSnapshot: ManualAdjustmentSnapshotMetalEntry[] = [];
  const inputMetals = Array.isArray(input.metals) ? input.metals : [];

  for (const ctxItem of ctx.metals) {
    const inputItem = findInputMetalMatch(inputMetals, ctxItem);
    if (!inputItem) continue;

    const preGrams = round4Grams(Number(ctxItem.gramsPure) || 0);
    let postGrams = preGrams;
    if (typeof inputItem.targetGrams === "number" && Number.isFinite(inputItem.targetGrams)) {
      postGrams = Math.max(0, round4Grams(inputItem.targetGrams));
    } else if (typeof inputItem.deltaGrams === "number" && Number.isFinite(inputItem.deltaGrams)) {
      postGrams = Math.max(0, round4Grams(preGrams + inputItem.deltaGrams));
    } else {
      continue; // sin instrucción significativa
    }

    const deltaGrams = round4Grams(postGrams - preGrams);
    if (Math.abs(deltaGrams) <= EPS_GRAMS) continue;

    const price = typeof ctxItem.metalPricePerGram === "number" && Number.isFinite(ctxItem.metalPricePerGram)
      ? ctxItem.metalPricePerGram
      : 0;
    const monetaryEquivalent = round2(deltaGrams * price);

    metalsSnapshot.push({
      metalParentId:      ctxItem.metalParentId,
      metalParentName:    inputItem.metalParentName ?? ctxItem.metalParentName,
      preGrams,
      postGrams,
      deltaGrams,
      metalPricePerGram:  price,
      monetaryEquivalent,
    });
  }

  // 2) Resolver capa monetaria (hechura).
  const monetaryPre = round2(Number(ctx.monetaryHechura.preAmount) || 0);
  const rawMonetary = typeof input.monetaryAmount === "number" && Number.isFinite(input.monetaryAmount)
    ? input.monetaryAmount
    : 0;
  const hasMonetary = Math.abs(rawMonetary) > EPS_MONEY;
  const monetaryLayer: ManualAdjustmentSnapshotMonetaryLayer = {
    preAmount:  monetaryPre,
    amount:     hasMonetary ? round2(rawMonetary) : 0,
    postAmount: hasMonetary ? round2(monetaryPre + rawMonetary) : monetaryPre,
  };

  const metalsImpact = round2(
    metalsSnapshot.reduce((acc, m) => acc + m.monetaryEquivalent, 0),
  );

  // Si no hay ningún movimiento significativo (ni gramos ni hechura) → null.
  if (metalsSnapshot.length === 0 && !hasMonetary) {
    return passthrough(engineTotal);
  }

  // 3) Calcular total efectivo + clamp 0.
  const proposedTotalDelta = round2(monetaryLayer.amount + metalsImpact);
  const naiveFinalTotal    = round2(engineTotal + proposedTotalDelta);
  const finalTotal         = Math.max(0, naiveFinalTotal);

  // Si el clamp recortó, ajustamos SOLO el bucket monetario (hechura/saldo)
  // para que refleje el delta EFECTIVO. Los gramos NO se recortan — el
  // operador pidió un ajuste físico sobre un metal padre, y ese ajuste
  // sigue perteneciendo al metal (principio "no mezclar" POLICY §R-Rounding-1).
  // Lo que se recorta es el monetario, que es el dominio que el clamp
  // legítimamente puede modificar para llevar `Sale.total` a 0.
  let monetaryEffective = monetaryLayer.amount;
  if (finalTotal !== naiveFinalTotal) {
    const totalEffective = round2(finalTotal - engineTotal);
    monetaryEffective    = round2(totalEffective - metalsImpact);
    monetaryLayer.amount     = monetaryEffective;
    monetaryLayer.postAmount = round2(monetaryLayer.preAmount + monetaryEffective);
  }

  const totals: ManualAdjustmentSnapshotTotals = {
    monetaryAdjustment:      monetaryEffective,
    metalMonetaryEquivalent: metalsImpact,
    totalMonetaryAdjustment: round2(monetaryEffective + metalsImpact),
  };

  const snapshot: ManualAdjustmentSnapshot = {
    scope: "BREAKDOWN",
    breakdown: {
      metals:   metalsSnapshot,
      monetary: monetaryLayer,
    },
    totals,
    audit: buildAudit(audit, reason),
  };

  return { snapshot, engineTotal, finalTotal };
}

/** Match input metal vs context metal:
 *  · Si ambos tienen `metalParentId` no-null y coinciden → match.
 *  · Si input tiene `metalParentId === null` y nombre, comparamos por nombre
 *    case-insensitive trimmed.
 *  · Si no, no hay match — el caller decide qué hacer (acá lo descartamos). */
function findInputMetalMatch(
  inputs: import("./types.js").ManualAdjustmentMetalInput[],
  ctxItem: ManualAdjustmentMetalContextItem,
): import("./types.js").ManualAdjustmentMetalInput | null {
  for (const it of inputs) {
    if (it.metalParentId && ctxItem.metalParentId && it.metalParentId === ctxItem.metalParentId) {
      return it;
    }
    if (
      it.metalParentId == null &&
      ctxItem.metalParentId == null &&
      typeof it.metalParentName === "string" &&
      it.metalParentName.trim().toLowerCase() === ctxItem.metalParentName.trim().toLowerCase()
    ) {
      return it;
    }
  }
  return null;
}
