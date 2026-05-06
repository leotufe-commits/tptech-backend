// src/lib/pricing-composition.ts
// ============================================================================
// Helpers de armado del bloque `composition` (metal / hechura / taxes) que se
// expone en los responses de pricing preview de articles y de sales.
//
// VIVE FUERA del directorio `pricing-engine/` a propósito: no toca el motor
// de cálculo, sólo lee `SalePriceResult.costOverrideContext` y `taxBreakdown`
// para armar la estructura de display compartida entre los dos endpoints.
//
// Antes de Fase 2A.7 esta lógica vivía únicamente dentro de
// `articles.controller.ts` (líneas ~1257-1296) y `sales/preview` no la
// exponía. Al extraerla acá, ambos endpoints producen exactamente el mismo
// shape sin duplicar lógica.
// ============================================================================

import { prisma } from "./prisma.js";
import type { SalePriceResult } from "./pricing-engine/pricing-engine.js";

// ---------------------------------------------------------------------------
// Tipos exportados
// ---------------------------------------------------------------------------

export type MetalVariantInfo = {
  purity:      number | null;
  purityLabel: string | null;
  metalName:   string | null;
};

export type CompositionMetalBlock = {
  originalGrams:     number | null;
  appliedGrams:      number | null;
  gramsManual:       boolean;
  originalMermaPct:  number | null;
  appliedMermaPct:   number | null;
  mermaManual:       boolean;
  originalVariantId: string | null;
  appliedVariantId:  string | null;
  variantManual:     boolean;
  purity:            number | null;
  purityLabel:       string | null;
  metalName:         string | null;
};

export type CompositionHechuraBlock = {
  originalAmount: number | null;
  appliedAmount:  number | null;
  manual:         boolean;
  appliesTo:      string | null;
};

export type CompositionTaxItem = {
  id:        string;
  name:      string;
  code:      string;
  rate:      number | null;
  appliesTo: string;
  taxAmount: number;
  manual:    boolean;
};

export type Composition = {
  metal:   CompositionMetalBlock | null;
  hechura: CompositionHechuraBlock | null;
  taxes:   CompositionTaxItem[];
};

// ---------------------------------------------------------------------------
// Métodos públicos
// ---------------------------------------------------------------------------

const EMPTY_METAL_VARIANT_INFO: MetalVariantInfo = {
  purity:      null,
  purityLabel: null,
  metalName:   null,
};

/**
 * Devuelve `purity / purityLabel / metalName` desde el modelo `MetalVariant`.
 * El motor no necesita la pureza para calcular precios — esta info es sólo
 * para mostrar en la composición.
 *
 * Si `metalVariantId` es `null` o no existe en DB, devuelve un objeto con
 * los tres campos en `null`.
 */
export async function fetchMetalVariantInfo(
  metalVariantId: string | null,
): Promise<MetalVariantInfo> {
  if (!metalVariantId) return EMPTY_METAL_VARIANT_INFO;

  const mv = await prisma.metalVariant.findUnique({
    where:  { id: metalVariantId },
    select: {
      purity: true,
      name:   true,
      metal:  { select: { name: true } },
    },
  });
  if (!mv) return EMPTY_METAL_VARIANT_INFO;

  const purityNum = mv.purity != null ? parseFloat(mv.purity.toString()) : null;
  let label: string | null = null;
  if (purityNum != null && purityNum > 0) {
    // Heurística: si parece quilatage (0 < p ≤ 1) → multiplicar × 24 y "k".
    if (purityNum <= 1) {
      const k = Math.round(purityNum * 24);
      label = `${k}k`;
    } else {
      // Ya viene en quilates u otra unidad → mostrar como número entero.
      label = `${Math.round(purityNum)}k`;
    }
  } else {
    label = mv.name;
  }
  return {
    purity:      purityNum,
    purityLabel: label,
    metalName:   mv.metal?.name ?? null,
  };
}

/**
 * Resuelve cuál `metalVariantId` usar para `fetchMetalVariantInfo`. Idéntica
 * heurística a la del controller original (`articles.controller.ts:1147-1150`):
 * primero el aplicado, luego el original. Devuelve `null` si no hay ninguno.
 */
export function resolveMetalVariantIdFromResult(
  result: SalePriceResult | null | undefined,
): string | null {
  return (
    result?.costOverrideContext?.metalVariant?.appliedId ??
    result?.costOverrideContext?.metalVariant?.originalId ??
    null
  );
}

/**
 * Arma el bloque `composition` que aparece en los responses de preview.
 * Mismo shape que devolvía `articles.controller.ts:1257-1296` antes de la
 * extracción.
 *
 * El argumento `mvi` es el resultado de `fetchMetalVariantInfo`. Se pasa por
 * separado para que el caller controle cuándo hace la query (típicamente una
 * vez por línea, ya cacheable si hace falta optimizar).
 */
export function buildComposition(
  result: SalePriceResult,
  mvi: MetalVariantInfo,
): Composition {
  const ctx = result.costOverrideContext;

  const metal: CompositionMetalBlock | null =
    ctx?.grams || ctx?.mermaPercent || ctx?.metalVariant
      ? {
          originalGrams:     ctx?.grams?.original ?? null,
          appliedGrams:      ctx?.grams?.applied  ?? null,
          gramsManual:       !!ctx?.grams?.manual,
          originalMermaPct:  ctx?.mermaPercent?.original ?? null,
          appliedMermaPct:   ctx?.mermaPercent?.applied  ?? null,
          mermaManual:       !!ctx?.mermaPercent?.manual,
          originalVariantId: ctx?.metalVariant?.originalId ?? null,
          appliedVariantId:  ctx?.metalVariant?.appliedId  ?? null,
          variantManual:     !!ctx?.metalVariant?.manual,
          purity:            mvi.purity,
          purityLabel:       mvi.purityLabel,
          metalName:         mvi.metalName,
        }
      : null;

  const hechura: CompositionHechuraBlock | null = ctx?.hechura
    ? {
        originalAmount: ctx.hechura.original,
        appliedAmount:  ctx.hechura.applied,
        manual:         !!ctx.hechura.manual,
        appliesTo:      null,
      }
    : null;

  const taxes: CompositionTaxItem[] = (result.taxBreakdown ?? []).map((t) => ({
    id:        t.taxId,
    name:      t.name,
    code:      t.code,
    rate:      t.rate != null ? Number(t.rate) : null,
    appliesTo: t.applyOn,
    taxAmount: Number(t.taxAmount ?? 0),
    manual:    t.taxId === "OVERRIDE_MANUAL",
  }));

  return { metal, hechura, taxes };
}

/**
 * `appliedMermaPercent` plano — atajo para callers que no necesitan toda la
 * `composition`. Lee del mismo lugar (`costOverrideContext.mermaPercent.applied`).
 */
export function getAppliedMermaPercent(result: SalePriceResult | null | undefined): number | null {
  return result?.costOverrideContext?.mermaPercent?.applied ?? null;
}
