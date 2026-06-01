// src/lib/document-physical-rounding-apply.ts
// =============================================================================
// Etapa D3 — Orquestador de capa 16: aplica el redondeo automático físico de
// gramos por metal padre al `documentTotals` y al `balanceBreakdown` ya
// construidos por el motor.
//
// Estrategia (POLICY §R-Rounding-13):
//   1. `loadDocumentRoundingConfig` (D2) suprime el redondeo metal monetario
//      (capa 15.metal) cuando `metalDomain=PHYSICAL`. El motor produce un
//      `documentRoundingApplied.breakdown.metal` con delta=0.
//   2. Sales.service construye `balanceBreakdown` (existente).
//   3. ESTE HELPER corre la capa 16:
//        · Llama `roundDocumentMetalGrams` (D1) con los metales del
//          balance + la config resuelta (D2).
//        · Muta `documentTotals.total` sumando el `metalMonetaryEquivalent`.
//        · Muta `documentTotals.documentRoundingApplied`:
//            - Agrega `metalDomain = "PHYSICAL"`.
//            - Reemplaza `breakdown.metal` por `null` (anti doble redondeo).
//            - Agrega `breakdown.metalPhysical = { metals[], metalMonetaryEquivalent, fallback }`.
//            - Agrega bloque universal `totals = { monetaryRoundingAdjustment,
//              metalMonetaryEquivalent, totalRoundingAdjustment }`.
//        · Muta `balanceBreakdown.metals[i].gramsPure / gramsOriginal /
//          valuationMonetary` para que el ajuste manual posterior lea
//          `preGrams = postGrams del redondeo automático`.
//
// Si `metalDomain=MONETARY`: el helper igual agrega el contrato `totals`
// universal con `metalMonetaryEquivalent=0`. No toca el resto.
//
// Determinístico, sin DB, sin async. Mantiene la regla "no se mezclan
// dominios": el delta del metal físico viaja en `metalMonetaryEquivalent`
// y NO entra al bucket monetario (`breakdown.monetary.amount` / hechura).
// =============================================================================

import type { DocumentRoundingPolicy } from "./document-rounding.js";
import {
  roundDocumentMetalGrams,
  type RoundDocumentMetalGramsResult,
} from "./document-physical-rounding.js";

/** Subset mínimo de `documentTotals` que la capa 16 muta. Tipado al ras
 *  para no acoplar a `SaleDocumentTotals` (cuyo shape vive en el motor). */
export interface PhysicalRoundingDocumentTotalsLike {
  total:                  number;
  documentRoundingApplied?: any | null;
  metalSaleSubtotal?:     number;
}

/** Subset mínimo de `balanceBreakdown.metals[i]` que la capa 16 actualiza. */
export interface PhysicalRoundingBalanceMetalLike {
  metalParentId:      string | null;
  metalParentName:    string;
  gramsPure:          number;
  gramsOriginal?:     number;
  purity?:            number | null;
  quotePriceSnapshot?: number | null;
  valuationMonetary?: number | null;
}

/** Subset mínimo del balance que mutamos. */
export interface PhysicalRoundingBalanceLike {
  metals: PhysicalRoundingBalanceMetalLike[];
}

const round2 = (n: number): number => Math.round(n * 100) / 100;
const round4 = (n: number): number => Math.round(n * 10000) / 10000;

/**
 * Aplica capa 16 al documentTotals y balanceBreakdown. Llamado por
 * sales.service después de `buildSaleBalanceBreakdown`, antes de emitir
 * `engineTotal`. Tras la mutación, `documentTotals.total` ya refleja el
 * delta físico y el snapshot lo audita.
 *
 * @returns el resultado del helper D1 (útil para tests y trazas).
 */
export function applyDocumentPhysicalRounding(args: {
  documentTotals:   PhysicalRoundingDocumentTotalsLike;
  balanceBreakdown: PhysicalRoundingBalanceLike;
  policy:           DocumentRoundingPolicy;
}): RoundDocumentMetalGramsResult | null {
  const { documentTotals, balanceBreakdown, policy } = args;

  // ── Bloque universal `totals` — back-compat.
  // `monetaryRoundingAdjustment` = delta $ de capa 15 (hechura + unified +
  // metal $ en MONETARY). Debe capturarse ANTES de mutar `totalAdjustment`
  // con el delta de capa 16, sino contaríamos doble.
  const ensureTotalsBlock = (monetaryAdj: number, metalEq: number): void => {
    const dra = documentTotals.documentRoundingApplied;
    if (!dra) return;
    dra.totals = {
      monetaryRoundingAdjustment: round2(monetaryAdj),
      metalMonetaryEquivalent:    round2(metalEq),
      totalRoundingAdjustment:    round2(monetaryAdj + metalEq),
    };
  };

  // ── Path MONETARY (back-compat) ─────────────────────────────────────────
  // Cuando el dominio es monetario, no corremos D1. Igual sembramos el
  // contrato `totals` universal con metalMonetaryEquivalent=0 si hay snapshot.
  if (policy.metalDomain !== "PHYSICAL" || !policy.physical.enabled) {
    const monetaryAdj = round2(Number(documentTotals.documentRoundingApplied?.totalAdjustment ?? 0));
    ensureTotalsBlock(monetaryAdj, 0);
    return null;
  }

  // ── Path PHYSICAL ───────────────────────────────────────────────────────
  // 1. Tomar metales del balance + config + correr D1.
  const helperInput = {
    metals: balanceBreakdown.metals.map((m) => ({
      metalParentId:    m.metalParentId,
      metalParentName:  m.metalParentName,
      grams:            m.gramsPure,
      metalPricePerGram:
        typeof m.quotePriceSnapshot === "number" && Number.isFinite(m.quotePriceSnapshot)
          ? m.quotePriceSnapshot
          : null,
    })),
    configByMetalParentId: policy.physical.configByMetalParentId,
    fallbackConfig:        policy.physical.fallbackConfig,
  };
  const result = roundDocumentMetalGrams(helperInput);

  // 2. Mutar balanceBreakdown.metals[i] con los gramos post-redondeo.
  //    El ajuste manual BREAKDOWN posterior (Etapa C) leerá `gramsPure` del
  //    balance ⇒ verá automáticamente el postGrams como preGrams del ajuste.
  for (const entry of result.metals) {
    const target = balanceBreakdown.metals.find((m) =>
      (m.metalParentId != null && entry.metalParentId != null && m.metalParentId === entry.metalParentId) ||
      (m.metalParentId == null && entry.metalParentId == null && m.metalParentName === entry.metalParentName)
    );
    if (!target) continue;
    if (entry.fallback != null) continue; // fallback → no mutamos (preserva originales)
    target.gramsPure = entry.postGrams;
    if (typeof target.purity === "number" && target.purity > 0 && target.gramsOriginal != null) {
      target.gramsOriginal = round4(entry.postGrams / target.purity);
    }
    if (typeof target.quotePriceSnapshot === "number" && Number.isFinite(target.quotePriceSnapshot)) {
      target.valuationMonetary = round2(entry.postGrams * target.quotePriceSnapshot);
    }
  }

  // 3. Mutar documentTotals.total (+ metalSaleSubtotal si existía).
  const metalEq = result.metalMonetaryEquivalent;
  documentTotals.total = round2(Math.max(0, documentTotals.total + metalEq));
  if (typeof documentTotals.metalSaleSubtotal === "number") {
    documentTotals.metalSaleSubtotal = round2(documentTotals.metalSaleSubtotal + metalEq);
  }

  // 4. Mutar documentRoundingApplied:
  //      · breakdown.metal (monetario) → null  (anti doble redondeo).
  //      · breakdown.metalPhysical → snapshot de capa 16.
  //      · metalDomain → "PHYSICAL".
  //      · totalAdjustment → suma con metalEq.
  //      · totals → bloque universal con desglose por dominio.
  const dra = documentTotals.documentRoundingApplied;
  if (dra) {
    // Capturar monetary $ ANTES de mutar totalAdjustment con capa 16.
    const monetaryAdj = round2(Number(dra.totalAdjustment ?? 0));
    if (dra.breakdown) {
      // Limpieza metal $ — el motor lo emitió en NONE (forzado por loader),
      // pero igual lo borramos para que el snapshot sea quirúrgicamente claro.
      dra.breakdown.metal = null;
      dra.breakdown.metalDomain = "PHYSICAL";
      dra.breakdown.metalPhysical = {
        metals: result.metals,
        metalMonetaryEquivalent: result.metalMonetaryEquivalent,
        ...(result.fallback ? { fallback: result.fallback } : { fallback: null }),
      };
      dra.breakdown.combinedAdjustment = round2(
        Number(dra.breakdown.combinedAdjustment ?? 0) + metalEq,
      );
    }
    dra.totalAdjustment = round2(monetaryAdj + metalEq);
    ensureTotalsBlock(monetaryAdj, metalEq);
  } else if (Math.abs(metalEq) > 0.005 || result.metals.length > 0) {
    // Sin snapshot previo (motor pasó por NO_BREAKDOWN_DATA, etc.) pero
    // capa 16 produjo algo: armamos un snapshot mínimo.
    documentTotals.documentRoundingApplied = {
      source:        "TENANT_POLICY",
      scope:         "BREAKDOWN",
      applyOn:       "DOC_TOTAL",
      totalAdjustment: round2(metalEq),
      breakdown: {
        metal:         null,
        hechura:       null,
        metalDomain:   "PHYSICAL",
        metalPhysical: {
          metals: result.metals,
          metalMonetaryEquivalent: result.metalMonetaryEquivalent,
          ...(result.fallback ? { fallback: result.fallback } : { fallback: null }),
        },
        combinedAdjustment: round2(metalEq),
      },
      totals: {
        monetaryRoundingAdjustment: 0,
        metalMonetaryEquivalent: round2(metalEq),
        totalRoundingAdjustment: round2(metalEq),
      },
    };
  }

  return result;
}
