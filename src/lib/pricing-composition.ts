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
import type { SalePriceResult, PricingStep } from "./pricing-engine/pricing-engine.js";

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

/**
 * FASE F1.3 G4.1 — bloque per-item para PRODUCT y SERVICE.
 *
 * Cada cost line de tipo PRODUCT o SERVICE se expone como un item separado
 * (no se bucketean en hechura como hacía el motor por convención interna).
 * Permite a la UI mostrar cada componente del costo con su trazabilidad
 * completa (catalog ref, cantidad, ajuste per-línea, impacto stock).
 *
 * Campos opcionales (`null` o ausentes) cuando el motor no los expone:
 *   · `costLineId`, `catalogItemId`, `affectsStock` — requieren extensión
 *     del motor (commit G4.1.2). Hoy quedan null por compatibilidad.
 *   · `catalogItemCode` / `catalogItemName` — vienen del catálogo
 *     pre-cargado por el caller (Map opcional pasado a buildComposition).
 *
 * POLICY R4.5 — la UI lee passthrough; cero cálculo monetario derivado.
 */
export type CompositionItemBlock = {
  /** ArticleCostLine.id — null hasta que el motor lo exponga en step.meta. */
  costLineId:       string | null;
  /** Article.id referenciado (PRODUCT/SERVICE apuntan a otro artículo). */
  catalogItemId:    string | null;
  /** Código del catálogo (ej "PIEDRA-Z01"). Ya viene en step.meta.lineCode. */
  catalogItemCode:  string | null;
  /** Nombre legible (ej "Zafiro 0.5ct"). Resuelto desde catalog map o
   *  fallback a step.meta.lineLabel. */
  catalogItemName:  string | null;
  /** Cantidad del componente (ej. 2 piedras). */
  quantity:         number;
  /** Valor unitario en moneda del componente. */
  unitValue:        number;
  /** Total del item = quantity × unitValue (lo computa el motor en step.value). */
  totalValue:       number;
  /** Moneda original del componente (null = moneda base del tenant). */
  currencyId:       string | null;
  /** Tipo de ajuste per-línea ("BONUS" o "SURCHARGE"), si lo hay. */
  lineAdjKind:      "BONUS" | "SURCHARGE" | null;
  /** Tipo del valor del ajuste ("PERCENTAGE" o "FIXED_AMOUNT"). */
  lineAdjType:      "PERCENTAGE" | "FIXED_AMOUNT" | null;
  /** Valor configurado del ajuste (ej. 10 cuando es PERCENTAGE 10%). */
  lineAdjValue:     number | null;
  /** Monto absoluto del ajuste — null hasta que el motor lo exponga
   *  explícitamente (G4.1.2). Mientras tanto, la UI puede derivarlo
   *  como display-only si lo necesita (no es cálculo monetario crítico). */
  lineAdjAmount:    number | null;
  /** Si esta cost line descuenta stock al confirmar venta (PRODUCT/SERVICE).
   *  Default false — null hasta que el motor lo exponga (G4.1.2). */
  affectsStock:     boolean | null;
};

export type Composition = {
  metal:   CompositionMetalBlock | null;
  hechura: CompositionHechuraBlock | null;
  /** F1.3 G4.1 — array de cost lines de tipo PRODUCT (insumos / productos
   *  externos). Vacío cuando el artículo no tiene PRODUCT lines. La UI
   *  rendereiza un bloque por item (no bucketean en hechura). */
  products: CompositionItemBlock[];
  /** F1.3 G4.1 — array de cost lines de tipo SERVICE (servicios externos).
   *  Mismo tratamiento que products. */
  services: CompositionItemBlock[];
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
 * F1.3 G4.1.3 — internal — query batch failure-safe por catalogItemIds.
 *
 * Centraliza el patrón de:
 *   1. Set dedupe (no se valida acá; el caller pasa el Set ya dedupeado).
 *   2. Single query Prisma con filtros multi-tenancy + soft-delete.
 *   3. Failure-safety: si Prisma throws, devuelve Map vacío + log warning.
 *
 * Reusada por `buildCatalogItemsMapForSteps` (post-engine) y
 * `buildCatalogItemsMapForCostLines` (pre-engine, para sales/preview que
 * conoce los catalogItemIds desde la precarga de articleData).
 */
async function loadCatalogItemsByIds(
  jewelryId: string,
  ids: Set<string>,
): Promise<Map<string, { code: string; name: string }>> {
  const empty = new Map<string, { code: string; name: string }>();
  if (!jewelryId || ids.size === 0) return empty;

  try {
    const items = await prisma.article.findMany({
      where:  { jewelryId, id: { in: [...ids] }, deletedAt: null },
      select: { id: true, code: true, name: true },
    });
    const map = new Map<string, { code: string; name: string }>();
    for (const a of items) {
      map.set(a.id, { code: a.code ?? "", name: a.name ?? "" });
    }
    return map;
  } catch (err) {
    // Failure-safety: NO romper composition por catalog lookup fallido.
    // Los items renderean igual con fallback meta.lineCode/lineLabel.
    // eslint-disable-next-line no-console
    console.warn(
      "[pricing-composition] catalog lookup falló; usando fallback meta.lineCode/lineLabel:",
      err,
    );
    return empty;
  }
}

/**
 * F1.3 G4.1.3 — pre-carga el catalog info (code/name) para los PRODUCT/SERVICE
 * referenciados en los steps de un resultado de pricing. UNA SOLA query
 * batch — evita N+1 cuando el artículo tiene múltiples cost lines.
 *
 * Variante para 1 artículo (post-engine). Para sales/preview con N líneas,
 * usar `buildCatalogItemsMapForCostLines` que dedupea GLOBAL antes del engine.
 *
 * IMPORTANTE — cuándo llamar:
 *   · UNA vez por request (post-engine, pre-buildComposition).
 *   · NO llamar per-línea, per-step, ni dentro de buildComposition.
 */
export async function buildCatalogItemsMapForSteps(
  jewelryId: string,
  steps: PricingStep[] | null | undefined,
): Promise<Map<string, { code: string; name: string }>> {
  if (!Array.isArray(steps) || steps.length === 0) {
    return new Map<string, { code: string; name: string }>();
  }
  const ids = new Set<string>();
  for (const s of steps) {
    if (!s) continue;
    if (s.key !== "COST_LINES_PRODUCT" && s.key !== "COST_LINES_SERVICE") continue;
    if (s.status !== "ok") continue;
    const id = (s.meta as any)?.catalogItemId;
    if (typeof id === "string" && id.length > 0) ids.add(id);
  }
  return loadCatalogItemsByIds(jewelryId, ids);
}

/**
 * F1.3 G4.1.4 — variante para sales/preview con N líneas del documento.
 *
 * Recibe arrays de cost lines (del articleData precargado por previewSale)
 * y dedupea catalogItemIds GLOBALMENTE antes de la query batch única.
 *
 * IMPORTANTE — cuándo llamar:
 *   · UNA vez por request, ANTES del engine loop (en paralelo con otras
 *     precargas via Promise.all).
 *   · NO per-línea, NO dentro del loop, NO dentro de buildComposition.
 *
 * Performance: query count = 1 incluso con 100 líneas y catalogItemIds
 * repetidos. Verificado por test específico de benchmark.
 *
 * Failure-safety: si Prisma falla, Map vacío (fallback a meta.lineCode/Label).
 *
 * @param jewelryId             Tenant scope obligatorio.
 * @param costLinesByArticle    Array de arrays de cost lines (típicamente
 *                              `articleData.map(a => a.costComposition ?? [])`).
 *                              Solo se inspecciona el campo `catalogItemId`.
 */
export async function buildCatalogItemsMapForCostLines(
  jewelryId: string,
  costLinesByArticle: Array<Array<{ catalogItemId?: string | null }>> | null | undefined,
): Promise<Map<string, { code: string; name: string }>> {
  if (!Array.isArray(costLinesByArticle) || costLinesByArticle.length === 0) {
    return new Map<string, { code: string; name: string }>();
  }
  const ids = new Set<string>();
  for (const lines of costLinesByArticle) {
    if (!Array.isArray(lines)) continue;
    for (const cl of lines) {
      const id = cl?.catalogItemId;
      if (typeof id === "string" && id.length > 0) ids.add(id);
    }
  }
  return loadCatalogItemsByIds(jewelryId, ids);
}

/**
 * F1.3 G4.1.1 — extrae bloques `products[]` o `services[]` desde
 * `result.steps[]` filtrando por la key correspondiente.
 *
 * El motor cost ya emite un step `COST_LINES_PRODUCT` / `COST_LINES_SERVICE`
 * por cada cost line de ese tipo. Este helper los mapea al shape display
 * sin recálculo monetario (POLICY R4.5).
 *
 * `catalogItems` es un Map opcional pre-cargado por el caller (1 query
 * batch, evita N+1) que asocia `catalogItemId` → `{ code, name }` del
 * artículo referenciado. Sin este map, el item queda con `catalogItemCode`
 * tomado de `step.meta.lineCode` (lo que el motor ya emite) y
 * `catalogItemName` derivado del label.
 *
 * Campos no expuestos hoy en step.meta (`costLineId`, `catalogItemId`,
 * `affectsStock`, `lineAdjAmount`) quedan null. Commit G4.1.2 extenderá el
 * motor para emitirlos. Mientras tanto, los items SE renderean con la info
 * disponible — la UI no se rompe.
 *
 * TODO Frontend: si products/services > 3 items, evaluar colapsado del
 * panel para evitar saturación visual.
 */
export function extractCompositionItems(
  steps: PricingStep[] | null | undefined,
  targetKey: "COST_LINES_PRODUCT" | "COST_LINES_SERVICE",
  catalogItems?: Map<string, { code: string; name: string }>,
): CompositionItemBlock[] {
  if (!Array.isArray(steps) || steps.length === 0) return [];

  return steps
    .filter(s => s && s.key === targetKey && s.status === "ok")
    .map(s => {
      const meta = (s.meta ?? {}) as Record<string, unknown>;
      const catalogId = (meta.catalogItemId ?? null) as string | null;
      const catalogInfo = catalogId ? catalogItems?.get(catalogId) : null;

      const lineCodeFromMeta = typeof meta.lineCode === "string" && meta.lineCode.length > 0
        ? meta.lineCode
        : null;
      const lineLabelFromMeta = typeof meta.lineLabel === "string" && meta.lineLabel.length > 0
        ? meta.lineLabel
        : null;
      const fallbackLabel = typeof s.label === "string" && s.label.length > 0
        ? s.label
        : null;

      const adjKindRaw = typeof meta.lineAdjKind === "string" && meta.lineAdjKind.length > 0
        ? meta.lineAdjKind
        : null;
      const adjKind: "BONUS" | "SURCHARGE" | null =
        adjKindRaw === "BONUS" || adjKindRaw === "SURCHARGE" ? adjKindRaw : null;
      const adjTypeRaw = typeof meta.lineAdjType === "string" && meta.lineAdjType.length > 0
        ? meta.lineAdjType
        : null;
      const adjType: "PERCENTAGE" | "FIXED_AMOUNT" | null =
        adjTypeRaw === "PERCENTAGE" || adjTypeRaw === "FIXED_AMOUNT" ? adjTypeRaw : null;

      // step.value ya es qty × unitValue (post conversión moneda + ajuste)
      // — lo provee el motor cost. Cero recálculo acá.
      const totalValue = s.value != null ? Number(s.value) : 0;
      const qty       = meta.qty       != null ? Number(meta.qty)       : 0;
      const unitValue = meta.unitValue != null ? Number(meta.unitValue) : 0;

      return {
        costLineId:       (meta.costLineId ?? null) as string | null,
        catalogItemId:    catalogId,
        catalogItemCode:  catalogInfo?.code ?? lineCodeFromMeta,
        catalogItemName:  catalogInfo?.name ?? lineLabelFromMeta ?? fallbackLabel,
        quantity:         Number.isFinite(qty)       ? qty       : 0,
        unitValue:        Number.isFinite(unitValue) ? unitValue : 0,
        totalValue:       Number.isFinite(totalValue) ? totalValue : 0,
        currencyId:       (meta.currencyId ?? null) as string | null,
        lineAdjKind:      adjKind,
        lineAdjType:      adjType,
        lineAdjValue:     meta.lineAdjValue != null ? Number(meta.lineAdjValue) : null,
        lineAdjAmount:    meta.lineAdjAmount != null ? Number(meta.lineAdjAmount) : null,
        affectsStock:     typeof meta.affectsStock === "boolean" ? meta.affectsStock : null,
      };
    });
}

/**
 * Arma el bloque `composition` que aparece en los responses de preview.
 * Mismo shape que devolvía `articles.controller.ts:1257-1296` antes de la
 * extracción.
 *
 * El argumento `mvi` es el resultado de `fetchMetalVariantInfo`. Se pasa por
 * separado para que el caller controle cuándo hace la query (típicamente una
 * vez por línea, ya cacheable si hace falta optimizar).
 *
 * F1.3 G4.1.1 — agrega `products[]` y `services[]` extraídos de
 * `result.steps[]`. Por defecto vacíos; cuando el caller pasa `catalogItems`
 * map pre-cargado, los items incluyen `catalogItemCode` / `catalogItemName`
 * resueltos. Sin map, caen al `lineCode` / `lineLabel` que ya emite el motor.
 */
export function buildComposition(
  result: SalePriceResult,
  mvi: MetalVariantInfo,
  catalogItems?: Map<string, { code: string; name: string }>,
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

  // F1.3 G4.1.1 — extraer products/services desde steps[] del motor.
  // Cero recálculo monetario; passthrough estructural de step.value/meta.
  const products = extractCompositionItems(result.steps, "COST_LINES_PRODUCT", catalogItems);
  const services = extractCompositionItems(result.steps, "COST_LINES_SERVICE", catalogItems);

  return { metal, hechura, products, services, taxes };
}

/**
 * `appliedMermaPercent` plano — atajo para callers que no necesitan toda la
 * `composition`. Lee del mismo lugar (`costOverrideContext.mermaPercent.applied`).
 */
export function getAppliedMermaPercent(result: SalePriceResult | null | undefined): number | null {
  return result?.costOverrideContext?.mermaPercent?.applied ?? null;
}
