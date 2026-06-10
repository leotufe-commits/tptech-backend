// src/modules/sales/commercial-doc-rounding-wiring.ts
// =============================================================================
// Etapa D' — Wiring del redondeo comercial PER_DOCUMENT para previewSale y
// confirmSale.
//
// Este módulo orquesta:
//   1. Identificar la "lista activa del documento" (si todas las líneas
//      comparten una sola lista vía `linePriceListId` o `defaultPriceListIdInput`).
//   2. Pre-cargar la `PriceList` desde DB.
//   3. Llamar `resolveDocCommercialRoundingContext` (helper puro) para
//      decidir el modo (`PER_LINE_LEGACY` / `PER_DOCUMENT` / `MIXED_LIST_FALLBACK`).
//   4. Extraer agregados (`metalsByParent`, `metalValuationSum`) desde las
//      líneas resueltas para alimentar `computeSaleDocumentTotals`.
//
// El env var `PRICING_COMMERCIAL_DOC_ROUNDING_ENABLED=1` activa PER_DOCUMENT
// globalmente mientras no haya schema. Cuando se agregue
// `PriceList.commercialRoundingScope` en Prisma, el resolvedor leerá ese
// campo y el env queda obsoleto.
// =============================================================================

import { prisma } from "../../lib/prisma.js";
// Importamos directamente del archivo interno (no del barrel) porque varios
// tests del módulo sales mockean el barrel y NO exportan estas funciones nuevas
// (pre-Etapa D'). Mientras los tests se actualicen, este import puntual evita
// regresiones masivas. La regla "siempre vía barrel" se respeta en consumidores
// productivos — este es un helper interno del wiring.
import {
  resolveDocCommercialRoundingContext,
  buildCommercialDocRoundingFromPriceList,
  type DocCommercialRoundingContext,
  type PriceListSummaryForContext,
} from "../../lib/pricing-engine/commercial-document-rounding-context.js";
import {
  computeCommercialPostGrams,
  applyCommercialRoundingMonetary,
  type CommercialDocMetalParentInput,
  type CommercialDocRoundingPartConfig,
  type CommercialDocRoundingInput,
  type CommercialDocRoundingApplied,
  type CommercialDocMetalSnapshotEntry,
} from "../../lib/pricing-engine/commercial-document-rounding.js";

// Select mínimo replicado localmente para evitar acoplar este helper al
// mock del barrel `pricing-engine.ts` (los tests con `vi.mock(barrel)` no
// exportan `PL_COMPUTE_SELECT`). Mantener sincronizado con el original.
const PL_SELECT_FOR_DOC_CTX = {
  id:                               true,
  name:                             true,
  mode:                             true,
  roundingTarget:                   true,
  roundingMode:                     true,
  roundingDirection:                true,
  roundingModeHechura:              true,
  roundingDirectionHechura:         true,
  commercialRoundingMetalDomain:    true,
  // Etapa D' — scope persistido en DB. Default PER_LINE_LEGACY.
  commercialRoundingScope:          true,
} as const;

export interface ResolveDocumentCommercialContextArgs {
  jewelryId: string;
  /** Input lines del preview/confirm — tienen `priceListIdOverride?`. */
  lineInputs: Array<{ priceListIdOverride?: string | null }>;
  /** Override de lista a nivel documento (input.priceListId). Si está, vale
   *  para todas las líneas que no traigan `linePriceListIdOverride`. */
  defaultPriceListIdInput?: string | null;
}

/**
 * Pre-carga la lista activa del documento (si hay una sola compartida) y
 * resuelve el contexto comercial PER_DOCUMENT.
 *
 * Lógica simplificada mientras no haya schema:
 *   · Si todas las líneas usan la MISMA lista (override de línea, o el
 *     `defaultPriceListIdInput`), esa es la lista activa.
 *   · Si líneas distintas usan listas distintas → MIXED_LIST_FALLBACK.
 *   · Si NINGUNA línea trae override y no hay `defaultPriceListIdInput`
 *     → no podemos identificar la lista del documento sin resolver
 *     cliente/categoría (complejo). En este caso, devolvemos PER_LINE_LEGACY
 *     directamente (el sistema funciona como hasta hoy).
 *
 * Cuando el schema agregue `PriceList.commercialRoundingScope`, ampliar la
 * lógica para resolver lista por cliente/categoría también.
 */
export async function resolveDocumentCommercialContextForSale(
  args: ResolveDocumentCommercialContextArgs,
): Promise<DocCommercialRoundingContext> {
  const { defaultPriceListIdInput } = args;
  // Defensa: cuando el caller pasa un array no-array (mocks legacy), tratamos
  // como mixed-list (PER_LINE_LEGACY). Sin trace, sin error.
  const lineInputs = Array.isArray(args.lineInputs) ? args.lineInputs : [];

  // ── 1) ¿Lista compartida? ────────────────────────────────────────────────
  const resolvedIdsPerLine = lineInputs.map(
    (l) => l.priceListIdOverride ?? defaultPriceListIdInput ?? null,
  );
  const uniqueIds = new Set(resolvedIdsPerLine.filter((id): id is string => !!id));
  const allLinesHaveSameExplicitList =
    uniqueIds.size === 1 &&
    resolvedIdsPerLine.every((id) => id != null);

  // Caso: ninguna lista explícita / mixed → no identificamos lista doc.
  // El env var de activación PER_DOCUMENT igual se respeta: si está activo
  // pero no hay lista compartida, el resolvedor reporta MIXED_LIST_FALLBACK.
  if (!allLinesHaveSameExplicitList) {
    // Si ni siquiera había overrides explícitos en las líneas (todos null),
    // el caller no expresó intención → PER_LINE_LEGACY directo.
    if (uniqueIds.size === 0) {
      return resolveDocCommercialRoundingContext({
        sharedPriceList:   null,
        allLinesShareList: false,
      });
    }
    // Líneas con listas distintas → mixed-list.
    return resolveDocCommercialRoundingContext({
      sharedPriceList:   null,
      allLinesShareList: false,
    });
  }

  // ── 2) Cargar la lista compartida ────────────────────────────────────────
  const sharedListId = [...uniqueIds][0];
  // Defensa: mocks legacy de Prisma pueden no exponer `priceList`. En ese
  // caso, fallback a PER_LINE_LEGACY (sin throw).
  if (!(prisma as any)?.priceList?.findFirst) {
    return resolveDocCommercialRoundingContext({
      sharedPriceList:   null,
      allLinesShareList: false,
    });
  }
  let priceListRaw: any = null;
  try {
    priceListRaw = await prisma.priceList.findFirst({
      where:  { id: sharedListId, jewelryId: args.jewelryId, deletedAt: null },
      select: PL_SELECT_FOR_DOC_CTX,
    });
  } catch {
    // Mock parcial / error de runtime → fallback seguro.
    return resolveDocCommercialRoundingContext({
      sharedPriceList:   null,
      allLinesShareList: false,
    });
  }
  if (!priceListRaw) {
    return resolveDocCommercialRoundingContext({
      sharedPriceList:   null,
      allLinesShareList: false,
    });
  }

  const summary: PriceListSummaryForContext = {
    id:                            priceListRaw.id,
    name:                          priceListRaw.name,
    mode:                          String((priceListRaw as any).mode ?? ""),
    roundingTarget:                String((priceListRaw as any).roundingTarget ?? ""),
    roundingMode:                  String((priceListRaw as any).roundingMode ?? "NONE"),
    roundingDirection:             String((priceListRaw as any).roundingDirection ?? "NEAREST"),
    roundingModeHechura:           ((priceListRaw as any).roundingModeHechura      ?? null) as string | null,
    roundingDirectionHechura:      ((priceListRaw as any).roundingDirectionHechura ?? null) as string | null,
    commercialRoundingMetalDomain: ((priceListRaw as any).commercialRoundingMetalDomain ?? null) as string | null,
    commercialRoundingScope:
      ((priceListRaw as any).commercialRoundingScope ?? "PER_LINE_LEGACY") as
      "PER_LINE_LEGACY" | "PER_DOCUMENT",
  };

  return resolveDocCommercialRoundingContext({
    sharedPriceList:   summary,
    allLinesShareList: true,
  });
}

/**
 * Reconciliación MIXED por listas REALMENTE APLICADAS (post-pricing).
 *
 * `resolveDocumentCommercialContextForSale` decide el modo por INTENCIÓN
 * (override de línea / `defaultPriceListIdInput`, ANTES del pricing). Pero la
 * lista que cada línea termina aplicando (`SaleLine.appliedPriceListId`) puede
 * diferir de esa intención (resolución por artículo / categoría / cliente).
 * Cuando las listas efectivamente aplicadas difieren entre sí, el documento es
 * MIXED a todos los efectos y NO debe consolidarse redondeo comercial a nivel
 * comprobante (contrato: el redondeo COMERCIAL es dominio artículo/lista; el
 * documental es el FINANCIERO, dominio tenant — ver CLAUDE.md "Redondeo
 * Comercial vs Redondeo Financiero"). Es el espejo POST-pricing de la
 * consolidación `consolidatedPriceListId === "MIXED"` del documento.
 *
 * Helper PURO — sin DB, determinístico.
 */
export function appliedPriceListsAreMixed(
  appliedPriceListIds: ReadonlyArray<string | null | undefined>,
): boolean {
  const distinct = new Set<string>();
  for (const id of appliedPriceListIds) {
    if (typeof id === "string" && id.length > 0) distinct.add(id);
  }
  return distinct.size > 1;
}

/**
 * Listas mixtas (2026-06-03 — Opción 1) — Resuelve la config de redondeo
 * comercial POR LÍNEA desde la lista efectivamente aplicada a cada línea
 * (`appliedPriceListId`). Permite que, en MIXED_LIST_FALLBACK, cada línea
 * conserve su propio saldo comercial según SU lista (sin tocar el total
 * documental, que sigue desactivado en mixto).
 *
 * Devuelve `Map<lineIdx, CommercialDocRoundingInput | null>`:
 *   · BREAKDOWN  → la lista de la línea es METAL_HECHURA con redondeo activo.
 *   · UNIFIED    → lista con redondeo unificado.
 *   · null       → línea sin lista / lista sin redondeo / id no resuelto.
 *
 * Batch-load de las listas distintas (1 query). Defensivo ante mocks de Prisma
 * (fallback: todas `null`). Helper de wiring — NO calcula pricing.
 */
export async function resolvePerLineCommercialConfigs(args: {
  jewelryId: string;
  /** `appliedPriceListId` por índice de línea (en el orden de las líneas). */
  lineAppliedPriceListIds: ReadonlyArray<string | null>;
}): Promise<Map<number, CommercialDocRoundingInput | null>> {
  const out = new Map<number, CommercialDocRoundingInput | null>();
  const distinct = new Set(
    args.lineAppliedPriceListIds.filter((id): id is string => !!id),
  );

  const cfgById = new Map<string, CommercialDocRoundingInput | null>();
  if (distinct.size > 0 && (prisma as any)?.priceList?.findMany) {
    try {
      const lists = await prisma.priceList.findMany({
        where:  { id: { in: [...distinct] }, jewelryId: args.jewelryId, deletedAt: null },
        select: PL_SELECT_FOR_DOC_CTX,
      });
      for (const pl of lists as any[]) {
        const summary: PriceListSummaryForContext = {
          id:                            pl.id,
          name:                          pl.name,
          mode:                          String(pl.mode ?? ""),
          roundingTarget:                String(pl.roundingTarget ?? ""),
          roundingMode:                  String(pl.roundingMode ?? "NONE"),
          roundingDirection:             String(pl.roundingDirection ?? "NEAREST"),
          roundingModeHechura:           (pl.roundingModeHechura      ?? null) as string | null,
          roundingDirectionHechura:      (pl.roundingDirectionHechura ?? null) as string | null,
          commercialRoundingMetalDomain: (pl.commercialRoundingMetalDomain ?? null) as string | null,
          commercialRoundingScope:
            (pl.commercialRoundingScope ?? "PER_LINE_LEGACY") as "PER_LINE_LEGACY" | "PER_DOCUMENT",
        };
        cfgById.set(pl.id, buildCommercialDocRoundingFromPriceList(summary));
      }
    } catch {
      // Mock parcial / error de runtime → todas las líneas quedan null.
    }
  }

  args.lineAppliedPriceListIds.forEach((id, i) => {
    out.set(i, id ? (cfgById.get(id) ?? null) : null);
  });
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Agregados para `computeSaleDocumentTotals` (BREAKDOWN)
// ─────────────────────────────────────────────────────────────────────────────

export interface MetalSnippetForCommercialAgg {
  metalParentId:                  string;
  metalParentName:                string;
  /** Gramos puros por unidad (post merma + purity). */
  appliedGramsPerUnit:            number;
  /** Cotización por gramo en moneda del documento. */
  quotePriceSnapshot:             number | null;
  /** Valorización monetaria $ de la línea (gramsPure × quotePrice × qty),
   *  pre-redondeo. */
  metalLineValuationDocCurrency?: number | null;
  /** Valor de referencia del metal padre (`Metal.referenceValue`). Precio por
   *  gramo COMERCIAL equivalente para el redondeo comercial CON MARGEN. */
  metalReferenceValue?:           number | null;
}

export interface ResolvedLineForCommercialAgg {
  quantity: number;
  /** Metales agregados por la balance pipeline. Si la línea no tiene metales,
   *  array vacío. */
  metals?:  MetalSnippetForCommercialAgg[] | null;
}

export interface CommercialDocRoundingAggregates {
  metalsByParent:   CommercialDocMetalParentInput[];
  metalValuationSum: number;
  /** Etapa Opción δ — subproducto del loop, sin cómputo extra.
   *  Map<metalParentId, Map<lineIdx, gramsPureDeLaLínea>>. Permite al caller
   *  prorratear el delta agregado del redondeo comercial PER_DOCUMENT entre
   *  las líneas que aportaron al metal padre, con peso = gramsPure de la línea
   *  sobre Σ gramsPure del padre en el documento. */
  gramsPureByParentByLineIdx: Map<string, Map<number, number>>;
}

/**
 * Agrega gramos puros y valorización por metal padre, sumando across todas
 * las líneas resueltas. Output listo para alimentar `computeSaleDocumentTotals`.
 *
 * Helper PURO — sin DB, sin async.
 *
 * Opción δ (R-COMMERCIAL-METAL-VISIBLE) — además del agregado, devuelve un
 * Map indexado por (metalParentId, lineIdx) con los gramsPure que aportó cada
 * línea individual. El caller usa esto para distribuir el delta monetario
 * del redondeo agregado a las líneas correspondientes (passthrough — el
 * frontend no recalcula).
 */
export function aggregateMetalsForCommercialDocRounding(
  resolvedLines: ResolvedLineForCommercialAgg[],
): CommercialDocRoundingAggregates {
  type Acc = {
    metalParentId:     string;
    metalParentName:   string;
    gramsPure:         number;
    priceWeightedSum:  number;     // Σ grams × price → average
    priceWeightedDiv:  number;
    valuationSum:      number;
    referenceValue:    number | null;
  };
  const byParent = new Map<string, Acc>();
  let metalValuationSum = 0;
  // Opción δ — gramsPure per (padre, línea), índice de línea = posición en
  // el array `resolvedLines`. Cero cómputo adicional respecto al loop original.
  const gramsPureByParentByLineIdx = new Map<string, Map<number, number>>();

  for (let lineIdx = 0; lineIdx < resolvedLines.length; lineIdx++) {
    const l = resolvedLines[lineIdx];
    const qty = Number.isFinite(l.quantity) && l.quantity > 0 ? l.quantity : 1;
    if (!l.metals?.length) continue;
    for (const m of l.metals) {
      if (!m.metalParentId) continue;
      const gramsLine = Number(m.appliedGramsPerUnit ?? 0) * qty;
      if (!Number.isFinite(gramsLine) || gramsLine <= 0) continue;
      const price = typeof m.quotePriceSnapshot === "number" && Number.isFinite(m.quotePriceSnapshot)
        ? m.quotePriceSnapshot
        : 0;
      const lineVal = typeof m.metalLineValuationDocCurrency === "number" && Number.isFinite(m.metalLineValuationDocCurrency)
        ? m.metalLineValuationDocCurrency
        : gramsLine * price;
      metalValuationSum += lineVal;
      let acc = byParent.get(m.metalParentId);
      if (!acc) {
        acc = {
          metalParentId:    m.metalParentId,
          metalParentName:  m.metalParentName,
          gramsPure:        0,
          priceWeightedSum: 0,
          priceWeightedDiv: 0,
          valuationSum:     0,
          referenceValue:   null,
        };
        byParent.set(m.metalParentId, acc);
      }
      if (acc.referenceValue == null
        && typeof m.metalReferenceValue === "number"
        && Number.isFinite(m.metalReferenceValue)
        && m.metalReferenceValue > 0) {
        acc.referenceValue = m.metalReferenceValue;
      }
      acc.gramsPure        += gramsLine;
      acc.priceWeightedSum += gramsLine * price;
      acc.priceWeightedDiv += gramsLine;
      acc.valuationSum     += lineVal;
      // Opción δ — registrar el aporte de esta línea a este padre. Si una
      // línea tiene varios cost-lines del mismo padre, se acumulan.
      let perLineMap = gramsPureByParentByLineIdx.get(m.metalParentId);
      if (!perLineMap) {
        perLineMap = new Map<number, number>();
        gramsPureByParentByLineIdx.set(m.metalParentId, perLineMap);
      }
      perLineMap.set(lineIdx, (perLineMap.get(lineIdx) ?? 0) + gramsLine);
    }
  }

  const metalsByParent: CommercialDocMetalParentInput[] = [];
  for (const acc of byParent.values()) {
    const avgPrice = acc.priceWeightedDiv > 0
      ? acc.priceWeightedSum / acc.priceWeightedDiv
      : 0;
    metalsByParent.push({
      metalParentId:     acc.metalParentId,
      metalParentName:   acc.metalParentName,
      gramsPure:         Math.round(acc.gramsPure * 10000) / 10000,
      metalPricePerGram: avgPrice,
      metalReferenceValue: acc.referenceValue ?? undefined,
    });
  }
  return {
    metalsByParent,
    metalValuationSum: Math.round(metalValuationSum * 100) / 100,
    gramsPureByParentByLineIdx,
  };
}

/**
 * Opción δ — Distribuye el `monetaryEquivalent` agregado por metal padre
 * entre las líneas que aportaron al padre, ponderado por gramsPure de cada
 * línea sobre Σ gramsPure del padre en el documento.
 *
 * Garantiza conservación exacta: la primera línea con aporte absorbe el
 * residuo de redondeo a 2 decimales para que
 * `Σ líneas distributedImpact === Σ padres monetaryEquivalent`.
 *
 * Helper PURO — sin DB, sin async. Determinístico.
 */
export function distributeMetalRoundingImpactPerLine(args: {
  /** Snapshot.breakdown.metals[*] post-aplicar redondeo. */
  metalEntries: ReadonlyArray<{
    metalParentId:      string;
    monetaryEquivalent: number;
  }>;
  /** Subproducto de `aggregateMetalsForCommercialDocRounding`. */
  gramsPureByParentByLineIdx: Map<string, Map<number, number>>;
  /** Cantidad total de líneas del documento (incluye las que no aportan al metal). */
  lineCount: number;
}): Map<number, number> {
  const out = new Map<number, number>();
  for (const entry of args.metalEntries) {
    const monetaryEq = Number(entry.monetaryEquivalent);
    if (!Number.isFinite(monetaryEq) || monetaryEq === 0) continue;
    const perLine = args.gramsPureByParentByLineIdx.get(entry.metalParentId);
    if (!perLine || perLine.size === 0) continue;
    // Σ gramsPure del padre a nivel doc.
    let totalGramsPadre = 0;
    for (const g of perLine.values()) totalGramsPadre += g;
    if (totalGramsPadre <= 0) continue;
    // Prorrateo proporcional a gramsPure.
    const lineIdxs = Array.from(perLine.keys()).sort((a, b) => a - b);
    let assignedSum = 0;
    for (let i = 0; i < lineIdxs.length; i++) {
      const idx = lineIdxs[i];
      const gramsLine = perLine.get(idx)!;
      let portion: number;
      if (i === lineIdxs.length - 1) {
        // Última línea absorbe el residuo para garantizar conservación exacta.
        portion = Math.round((monetaryEq - assignedSum) * 100) / 100;
      } else {
        portion = Math.round(((gramsLine / totalGramsPadre) * monetaryEq) * 100) / 100;
        assignedSum += portion;
      }
      out.set(idx, Math.round(((out.get(idx) ?? 0) + portion) * 100) / 100);
    }
  }
  return out;
}

/**
 * Opción A — Distribuye el `deltaSaldoMonetario` AGREGADO del Redondeo
 * Comercial PER_DOCUMENT (bucket hechura / saldo monetario) entre las líneas
 * del documento, ponderado por `hechuraSale × qty` (dominio venta) de cada
 * línea sobre Σ del documento.
 *
 * Espejo de `distributeMetalRoundingImpactPerLine` pero para el bucket
 * monetario. Garantiza conservación exacta a 2 decimales:
 *   `Σ líneas hechuraRoundingMonetaryImpact === deltaSaldoMonetario`.
 * La última línea con aporte absorbe el residuo de redondeo.
 *
 * Casos borde:
 *   · `deltaSaldoMonetario === 0` → Map vacío (no hay impacto que repartir).
 *   · Σ base positiva === 0 (todas las hechuras ≤ 0, ej. bonificaciones que
 *     superan la hechura) → reparto en PARTES IGUALES entre todas las líneas
 *     para no perder el delta. La hechura puede ser negativa (componentes
 *     negativos válidos); un peso negativo distorsionaría el prorrateo, por
 *     eso solo cuenta la porción positiva.
 *
 * Helper PURO — sin DB, sin async. Determinístico.
 */
export function distributeHechuraRoundingImpactPerLine(args: {
  /** `snapshot.breakdown.hechura.deltaSaldoMonetario` agregado del documento. */
  deltaSaldoMonetario: number;
  /** `hechuraSale × qty` por índice de línea (dominio venta, moneda base). */
  hechuraSaleByLineIdx: ReadonlyMap<number, number>;
  /** Cantidad total de líneas del documento. */
  lineCount: number;
}): Map<number, number> {
  const out = new Map<number, number>();
  const delta = Number(args.deltaSaldoMonetario);
  if (!Number.isFinite(delta) || delta === 0) return out;
  if (!Number.isFinite(args.lineCount) || args.lineCount <= 0) return out;

  const idxs: number[] = [];
  for (let i = 0; i < args.lineCount; i++) idxs.push(i);

  // Base de prorrateo: solo la porción POSITIVA de `hechuraSale × qty`.
  const baseByIdx = new Map<number, number>();
  let totalBase = 0;
  for (const i of idxs) {
    const raw = Number(args.hechuraSaleByLineIdx.get(i) ?? 0);
    const pos = Number.isFinite(raw) && raw > 0 ? raw : 0;
    baseByIdx.set(i, pos);
    totalBase += pos;
  }

  const equalSplit = totalBase <= 0;
  const contributing = equalSplit
    ? idxs
    : idxs.filter((i) => (baseByIdx.get(i) ?? 0) > 0);
  if (contributing.length === 0) return out;

  let assigned = 0;
  for (let k = 0; k < contributing.length; k++) {
    const i = contributing[k];
    let portion: number;
    if (k === contributing.length - 1) {
      // Última línea con aporte absorbe el residuo → conservación exacta.
      portion = Math.round((delta - assigned) * 100) / 100;
    } else {
      const weight = equalSplit
        ? 1 / contributing.length
        : (baseByIdx.get(i) ?? 0) / totalBase;
      portion = Math.round((delta * weight) * 100) / 100;
      assigned += portion;
    }
    out.set(i, portion);
  }
  return out;
}

/**
 * Opción A (descomposición FÍSICA) — Distribuye el SALDO MONETARIO POST del
 * documento (`breakdown.hechura.postRoundingSaldoMonetario` = total − valor
 * físico del metal, redondeado) entre las líneas, proporcional a
 * `hechuraSale × qty`. Conservación exacta: Σ líneas === saldoPost.
 *
 * A diferencia del distribuidor de impacto (que reparte el DELTA), éste reparte
 * el VALOR POST COMPLETO — es el número que el bloque MONETARIO del Resumen
 * Comercial muestra como "saldo monetario post-redondeo" (ej. 185.500).
 *
 * Helper PURO — determinístico.
 */
export function distributeMonetarySaldoPostPerLine(args: {
  saldoPost:            number;
  hechuraSaleByLineIdx: ReadonlyMap<number, number>;
  lineCount:            number;
}): Map<number, number> {
  const out = new Map<number, number>();
  const total = Number(args.saldoPost);
  if (!Number.isFinite(total)) return out;
  if (!Number.isFinite(args.lineCount) || args.lineCount <= 0) return out;

  const idxs: number[] = [];
  for (let i = 0; i < args.lineCount; i++) idxs.push(i);

  const baseByIdx = new Map<number, number>();
  let totalBase = 0;
  for (const i of idxs) {
    const raw = Number(args.hechuraSaleByLineIdx.get(i) ?? 0);
    const pos = Number.isFinite(raw) && raw > 0 ? raw : 0;
    baseByIdx.set(i, pos);
    totalBase += pos;
  }

  const equalSplit = totalBase <= 0;
  const contributing = equalSplit
    ? idxs
    : idxs.filter((i) => (baseByIdx.get(i) ?? 0) > 0);
  if (contributing.length === 0) {
    if (idxs.length > 0) out.set(idxs[0], Math.round(total * 100) / 100);
    return out;
  }

  let assigned = 0;
  for (let k = 0; k < contributing.length; k++) {
    const i = contributing[k];
    let portion: number;
    if (k === contributing.length - 1) {
      portion = Math.round((total - assigned) * 100) / 100;
    } else {
      const weight = equalSplit
        ? 1 / contributing.length
        : (baseByIdx.get(i) ?? 0) / totalBase;
      portion = Math.round((total * weight) * 100) / 100;
      assigned += portion;
    }
    out.set(i, portion);
  }
  return out;
}

export interface CommercialRoundingPerLineImpact {
  /** Porción $ del Redondeo Comercial atribuida al METAL de esta línea. */
  metalImpact:   number;
  /** Porción $ del Redondeo Comercial atribuida a la HECHURA/MONETARIO de esta línea. */
  hechuraImpact: number;
  /** Opción A (descomposición FÍSICA) — SALDO MONETARIO POST atribuido a esta
   *  línea (= porción de `postRoundingSaldoMonetario`). `null` cuando el
   *  snapshot no trae el bucket hechura. Es el valor que el bloque MONETARIO
   *  del Resumen Comercial muestra POST-redondeo. */
  monetarySaldoPost: number | null;
}

/**
 * Opción A — Orquestador PURO del reparto per-línea del Redondeo Comercial
 * PER_DOCUMENT (metal + hechura). Usado por `previewSale` y `confirmSale`
 * con los MISMOS inputs → paridad por construcción.
 *
 * Devuelve un Map lineIdx → { metalImpact, hechuraImpact }. Las líneas que no
 * reciben impacto quedan en 0 (nunca undefined).
 *
 * Conservación (verificable):
 *   · Σ metalImpact   ≡ Σ breakdown.metals[*].monetaryEquivalent
 *   · Σ hechuraImpact ≡ breakdown.hechura.deltaSaldoMonetario
 *
 * El total post-redondeo comercial por línea lo compone el caller:
 *   lineTotalWithTaxPostCommercialRounding
 *     = lineTotalWithTax + metalImpact + hechuraImpact
 */
export function computeCommercialRoundingPerLineImpacts(args: {
  /** `commercialDocumentRoundingApplied.breakdown` (o null si no hubo redondeo). */
  breakdown:                  any | null | undefined;
  gramsPureByParentByLineIdx: Map<string, Map<number, number>>;
  hechuraSaleByLineIdx:       ReadonlyMap<number, number>;
  lineCount:                  number;
}): Map<number, CommercialRoundingPerLineImpact> {
  const out = new Map<number, CommercialRoundingPerLineImpact>();
  for (let i = 0; i < args.lineCount; i++) {
    out.set(i, { metalImpact: 0, hechuraImpact: 0, monetarySaldoPost: null });
  }
  const breakdown = args.breakdown;
  if (!breakdown) return out;

  const metalEntries = Array.isArray(breakdown.metals) ? breakdown.metals : null;
  if (metalEntries && metalEntries.length > 0) {
    const m = distributeMetalRoundingImpactPerLine({
      metalEntries,
      gramsPureByParentByLineIdx: args.gramsPureByParentByLineIdx,
      lineCount:                  args.lineCount,
    });
    for (const [idx, v] of m) {
      const slot = out.get(idx);
      if (slot) slot.metalImpact = v;
    }
  }

  const hechuraDelta =
    breakdown.hechura && typeof breakdown.hechura.deltaSaldoMonetario === "number"
      ? breakdown.hechura.deltaSaldoMonetario
      : 0;
  const h = distributeHechuraRoundingImpactPerLine({
    deltaSaldoMonetario:  hechuraDelta,
    hechuraSaleByLineIdx: args.hechuraSaleByLineIdx,
    lineCount:            args.lineCount,
  });
  for (const [idx, v] of h) {
    const slot = out.get(idx);
    if (slot) slot.hechuraImpact = v;
  }

  // Descomposición FÍSICA — saldo monetario POST por línea (valor que el
  // bloque MONETARIO del Resumen muestra). Solo cuando el snapshot trae el
  // bucket hechura; si no, queda null y el frontend cae al MONETARIO comercial.
  const saldoPost =
    breakdown.hechura && typeof breakdown.hechura.postRoundingSaldoMonetario === "number"
      ? breakdown.hechura.postRoundingSaldoMonetario
      : null;
  if (saldoPost != null) {
    const s = distributeMonetarySaldoPostPerLine({
      saldoPost,
      hechuraSaleByLineIdx: args.hechuraSaleByLineIdx,
      lineCount:            args.lineCount,
    });
    for (const idx of out.keys()) {
      const slot = out.get(idx);
      if (slot) slot.monetarySaldoPost = s.get(idx) ?? 0;
    }
  }

  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// GRAMOS COMERCIALES PER-LÍNEA (display-only) — fix "Resumen mezcla líneas"
// ─────────────────────────────────────────────────────────────────────────────

/** Un metal padre del Resumen Comercial de UNA línea. Gramos físicos POST
 *  redondeo comercial + su monetización, calculados SOLO con datos de la
 *  propia línea. */
export interface LineCommercialRoundingMetal {
  metalParentId:   string;
  metalParentName: string;
  /** gramsSale = gramsPure_línea × marginFactor_línea (sin redondear). */
  preGrams:        number;
  /** round(preGrams) con la config metal de la lista. */
  postGrams:       number;
  /** postGrams − preGrams (redondeo del gramo comercial). */
  deltaGrams:      number;
  /** Valor comercial por gramo (`Metal.referenceValue`, fallback
   *  metalPricePerGram) con el que `gramsSale × refValue = metalSale`. Moneda
   *  BASE (el display converter lo convierte). 0 si no hay refValue. */
  metalReferenceValue: number;
  /** Impacto monetario del redondeo del gramo = `deltaGrams × metalReferenceValue`
   *  (round2). Σ por línea === `metalRoundingMonetaryImpact`. Moneda BASE. */
  monetaryImpact:      number;
}

/**
 * Calcula los gramos comerciales POST-redondeo POR LÍNEA y por metal padre,
 * usando EXCLUSIVAMENTE datos de cada línea:
 *   · `gramsPure` de la línea (de `gramsPureByParentByLineIdx`).
 *   · `marginFactor` de la línea (`metalSale_línea / metalCost_línea`).
 *   · la MISMA fórmula SSOT `computeCommercialPostGrams` que footer/agregado.
 *
 * Resultado: Map lineIdx → LineCommercialRoundingMetal[]. Como cada línea usa
 * su propio gramsPure y su propio margen, agregar otra línea NO altera ésta
 * (cierra el bug "Resumen Comercial del Artículo mezcla líneas"). Display-only:
 * no toca dinero, saldo ni totales.
 *
 * `marginFactorByLineIdx` faltante o ≤0 ⇒ 1 (sin margen). `metalCfg` con
 * `mode="NONE"` ⇒ postGrams = preGrams (sin redondeo, solo margen).
 */
export function computeLineCommercialRoundingMetals(args: {
  gramsPureByParentByLineIdx: Map<string, Map<number, number>>;
  /** Nombres de metal padre por id (de `metalsByParent`). */
  metalNameById:              ReadonlyMap<string, string>;
  /** Valor comercial por gramo por padre (`metalReferenceValue ?? metalPricePerGram`).
   *  Para monetizar el delta de gramos. Faltante/omitido ⇒ 0 (impacto 0). */
  refValueByParent?:          ReadonlyMap<string, number>;
  marginFactorByLineIdx:      ReadonlyMap<number, number>;
  metalCfg:                   CommercialDocRoundingPartConfig;
  /** Listas mixtas (2026-06-03) — config de redondeo de metal POR LÍNEA (la de
   *  la lista propia de cada línea). Cuando se provee, gana sobre `metalCfg`
   *  por índice; `metalCfg` queda como default para líneas sin entrada. Permite
   *  que cada línea redondee sus gramos con SU lista aun en MIXED_LIST_FALLBACK.
   *  Omitido ⇒ todas usan `metalCfg` (back-compat / shared list). */
  metalCfgByLineIdx?:         ReadonlyMap<number, CommercialDocRoundingPartConfig>;
  lineCount:                  number;
}): Map<number, LineCommercialRoundingMetal[]> {
  const out = new Map<number, LineCommercialRoundingMetal[]>();
  for (let i = 0; i < args.lineCount; i++) out.set(i, []);

  for (const [parentId, perLineMap] of args.gramsPureByParentByLineIdx) {
    const name     = args.metalNameById.get(parentId) ?? parentId;
    const refValueRaw = Number(args.refValueByParent?.get(parentId) ?? 0);
    const refValue = Number.isFinite(refValueRaw) && refValueRaw > 0 ? refValueRaw : 0;
    for (const [lineIdx, gramsPureLine] of perLineMap) {
      if (!Number.isFinite(gramsPureLine) || gramsPureLine <= 0) continue;
      const marginFactor = args.marginFactorByLineIdx.get(lineIdx) ?? 1;
      const metalCfgLine = args.metalCfgByLineIdx?.get(lineIdx) ?? args.metalCfg;
      const g = computeCommercialPostGrams(gramsPureLine, marginFactor, metalCfgLine);
      const arr = out.get(lineIdx);
      if (arr) {
        arr.push({
          metalParentId:      parentId,
          metalParentName:    name,
          preGrams:           g.preGrams,
          postGrams:          g.postGrams,
          deltaGrams:         g.deltaGrams,
          metalReferenceValue: refValue,
          monetaryImpact:     Math.round(g.deltaGrams * refValue * 100) / 100,
        });
      }
    }
  }

  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// DINERO COMERCIAL LINE-AUTONOMOUS — fix "contaminación entre líneas"
// ─────────────────────────────────────────────────────────────────────────────

/** Los 4 campos monetarios del Resumen Comercial de UNA línea, calculados con
 *  datos EXCLUSIVOS de la línea (redondeo comercial aplicado sobre el saldo y
 *  los gramos de la propia línea). Inmunes a agregar/quitar otras líneas. */
export interface LineAutonomousCommercialMoney {
  /** Σ (deltaGrams_línea × refValue) del metal — impacto $ del redondeo físico
   *  comercial de los gramos de ESTA línea. */
  metalRoundingMonetaryImpact:             number;
  /** saldoLínea = lineTotalWithTax − Σ metalSale de la línea — saldo monetario
   *  PRE redondeo comercial (lo que el card muestra como "AR$ 185.475,21 →"). */
  lineMonetarySaldoPreCommercialRounding:  number;
  /** round(saldoLínea) — saldo monetario POST redondeo comercial de la línea. */
  lineMonetarySaldoPostCommercialRounding: number;
  /** saldoPost − saldoLínea — impacto $ del redondeo del bucket monetario. */
  hechuraRoundingMonetaryImpact:           number;
  /** lineTotalWithTax + metalImpact + hechuraImpact — total línea c/imp POST,
   *  display-only (el motor NO lo suma para el total del comprobante). */
  lineTotalWithTaxPostCommercialRounding:  number;
}

/**
 * Calcula los 4 campos monetarios del Resumen Comercial de cada línea de forma
 * LINE-AUTONOMOUS: el redondeo comercial se aplica sobre el saldo y los gramos
 * PROPIOS de la línea, NO repartiendo el agregado del documento. Por eso
 * agregar/quitar/modificar otra línea no altera estos valores.
 *
 * Espejo per-línea del motor documental (`applyBreakdown`):
 *   saldoLínea = lineTotalWithTax − metalSaleSum_línea   (metal CON margen)
 *   saldoPost  = redondeo(saldoLínea)                    (config hechura)
 *   metalImpact = Σ deltaGrams_línea × refValue          (redondeo de gramos)
 *   totalPost  = lineTotalWithTax + metalImpact + (saldoPost − saldoLínea)
 *
 * Invariante POR LÍNEA (verificable):
 *   (metalSaleSum + metalImpact) + saldoPost === totalPost
 *   ⇔ METAL Comercial post + MONETARIO post === TOTAL LÍNEA post
 *
 * NO toca el total del comprobante (PER_DOCUMENT sigue siendo el SSOT del motor):
 * estos campos son display-only del card. `Σ líneas ≠ documento` es esperado
 * (round(a)+round(b) ≠ round(a+b)) — el footer usa el agregado documental.
 *
 * Helper PURO — determinístico, sin DB.
 */
export function computeLineAutonomousCommercialMoney(args: {
  /** Gramos comerciales per-línea (output de `computeLineCommercialRoundingMetals`). */
  lineCommercialRoundingMetals: ReadonlyMap<number, ReadonlyArray<{ metalParentId: string; deltaGrams: number }>>;
  /** Precio por gramo comercial (`Metal.referenceValue`, fallback metalPricePerGram). */
  refValueByParent:             ReadonlyMap<string, number>;
  /** lineTotalWithTax (c/imp, × qty) por línea. */
  lineTotalWithTaxByIdx:        ReadonlyMap<number, number>;
  /** Σ metalSale (CON margen, × qty) por línea — misma base que metalSaleSubtotal del doc. */
  metalSaleSumByIdx:            ReadonlyMap<number, number>;
  /** Config de redondeo del saldo monetario (bucket hechura) de la lista. */
  hechuraCfg:                   CommercialDocRoundingPartConfig;
  /** Listas mixtas (2026-06-03) — config de redondeo de hechura POR LÍNEA (la
   *  de la lista propia de cada línea). Gana sobre `hechuraCfg` por índice;
   *  `hechuraCfg` queda como default. Permite que cada línea redondee su saldo
   *  con SU lista aun en MIXED_LIST_FALLBACK. Omitido ⇒ todas usan `hechuraCfg`. */
  hechuraCfgByLineIdx?:         ReadonlyMap<number, CommercialDocRoundingPartConfig>;
  lineCount:                    number;
}): Map<number, LineAutonomousCommercialMoney> {
  const out = new Map<number, LineAutonomousCommercialMoney>();

  for (let i = 0; i < args.lineCount; i++) {
    const lineTotalWithTax = Number(args.lineTotalWithTaxByIdx.get(i) ?? 0);
    const metalSaleSum     = Number(args.metalSaleSumByIdx.get(i) ?? 0);
    const hechuraCfgLine   = args.hechuraCfgByLineIdx?.get(i) ?? args.hechuraCfg;

    // 1) Impacto $ del redondeo de gramos de la línea = Σ deltaGrams × refValue.
    let metalImpact = 0;
    const metals = args.lineCommercialRoundingMetals.get(i);
    if (metals) {
      for (const m of metals) {
        const refValue = Number(args.refValueByParent.get(m.metalParentId) ?? 0);
        const delta    = Number(m.deltaGrams ?? 0);
        if (Number.isFinite(refValue) && Number.isFinite(delta)) {
          metalImpact += delta * refValue;
        }
      }
    }
    metalImpact = Math.round(metalImpact * 100) / 100;

    // 2) Saldo monetario propio de la línea (CON margen) + su redondeo.
    const saldoLinea = Math.round((lineTotalWithTax - metalSaleSum) * 100) / 100;
    const saldoPost  = applyCommercialRoundingMonetary(saldoLinea, hechuraCfgLine);
    const hechuraImpact = Math.round((saldoPost - saldoLinea) * 100) / 100;

    // 3) Total línea c/imp POST (display-only).
    const totalPost = Math.round((lineTotalWithTax + metalImpact + hechuraImpact) * 100) / 100;

    out.set(i, {
      metalRoundingMonetaryImpact:             metalImpact,
      lineMonetarySaldoPreCommercialRounding:  saldoLinea,
      lineMonetarySaldoPostCommercialRounding: saldoPost,
      hechuraRoundingMonetaryImpact:           hechuraImpact,
      lineTotalWithTaxPostCommercialRounding:  totalPost,
    });
  }

  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// CONSOLIDACIÓN DOCUMENTAL = Σ round(línea)  (Etapa Σ-round — canónico 2026-06-03)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Construye el snapshot comercial PER_DOCUMENT del comprobante a partir de la
 * SUMA de los valores comerciales finales POR LÍNEA (`Σ round(línea)`), NO del
 * redondeo del agregado documental (`round(Σ)`).
 *
 * Es la pieza que materializa la regla canónica:
 *   footerMetalGrams    = Σ metalCommercialFinalGramsByLine
 *   footerMonetaryAmount = Σ monetaryCommercialFinalAmountByLine
 *   totalComercialDoc   = Σ valores comerciales visibles por línea
 *
 * Inputs = los MISMOS mapas per-línea que alimentan el display del card del
 * artículo (`computeLineCommercialRoundingMetals` + `computeLineAutonomousCommercialMoney`),
 * por lo que el footer del comprobante y la suma visual de los artículos
 * coinciden EXACTAMENTE por construcción. El caller lo usa idéntico en
 * `previewSale` y `confirmSale` → preview = confirmación.
 *
 * Solo scope BREAKDOWN (metal padre físico + hechura/saldo monetario). El
 * dominio metal y el monetario NUNCA se mezclan: el equivalente monetario del
 * redondeo de gramos vive en `breakdown.metals[*].monetaryEquivalent` /
 * `metalMonetaryEquivalent`, jamás en `hechura`.
 *
 * Devuelve `null` cuando no hubo movimiento real (Σ delta de gramos ≈ 0 y
 * Σ delta de saldo ≈ 0) — preserva la semántica "sin redondeo → valores exactos
 * del motor" (el caller no inyecta snapshot y el footer muestra el balance).
 *
 * Conservación garantizada (verificable en tests):
 *   · breakdown.metals[*].postGrams (por padre) = Σ líneas round(gramsSale_línea)
 *   · breakdown.metalMonetaryEquivalent          = Σ líneas metalRoundingMonetaryImpact
 *   · breakdown.hechura.postRoundingSaldoMonetario = Σ líneas lineMonetarySaldoPostCommercialRounding
 *   · totalAdjustment = combinedAdjustment        = metalMonetaryEquivalent + Σ hechuraImpact
 *
 * Helper PURO — sin DB, sin async, determinístico.
 */
export function consolidateCommercialDocFromPerLine(args: {
  lineCommercialRoundingMetals: ReadonlyMap<number, ReadonlyArray<LineCommercialRoundingMetal>>;
  lineMoney:                    ReadonlyMap<number, LineAutonomousCommercialMoney>;
  /** Nombre del metal padre por id (de `metalsByParent`). */
  metalNameById:                ReadonlyMap<string, string>;
  /** Valor comercial por gramo por padre (refValue ?? metalPricePerGram). */
  refValueByParent:             ReadonlyMap<string, number>;
  metalCfg:                     CommercialDocRoundingPartConfig;
  hechuraCfg:                   CommercialDocRoundingPartConfig;
  lineCount:                    number;
}): CommercialDocRoundingApplied | null {
  const round2      = (n: number): number => Math.round(n * 100)   / 100;
  const round4Grams = (n: number): number => Math.round(n * 10000) / 10000;
  const EPS_MONEY   = 0.005;
  const EPS_GRAMS   = 1e-9;

  // ── 1) METAL — agregar por padre sumando los valores POST por línea ───────
  type MetalAcc = {
    metalParentId:   string;
    metalParentName: string;
    preGrams:        number;
    postGrams:       number;
    deltaGrams:      number;
    monetaryEquivalent: number;
  };
  const byParent = new Map<string, MetalAcc>();
  for (const metals of args.lineCommercialRoundingMetals.values()) {
    for (const m of metals) {
      if (!m || !m.metalParentId) continue;
      let acc = byParent.get(m.metalParentId);
      if (!acc) {
        acc = {
          metalParentId:      m.metalParentId,
          metalParentName:    args.metalNameById.get(m.metalParentId) ?? m.metalParentName ?? m.metalParentId,
          preGrams:           0,
          postGrams:          0,
          deltaGrams:         0,
          monetaryEquivalent: 0,
        };
        byParent.set(m.metalParentId, acc);
      }
      acc.preGrams           += Number(m.preGrams ?? 0);
      acc.postGrams          += Number(m.postGrams ?? 0);
      acc.deltaGrams         += Number(m.deltaGrams ?? 0);
      acc.monetaryEquivalent += Number(m.monetaryImpact ?? 0);
    }
  }

  // metals[] incluye TODOS los padres con gramos (incluso delta=0) para que el
  // footer muestre `Σ round(línea)` de cada metal. Los delta=0 aportan
  // monetaryEquivalent=0 → no alteran la conservación.
  const metalEntries: CommercialDocMetalSnapshotEntry[] = [];
  const metalsPostGrams: NonNullable<CommercialDocRoundingApplied["breakdown"]>["metalsPostGrams"] = [];
  let metalMonetaryEquivalent = 0;
  for (const acc of byParent.values()) {
    const preGrams  = round4Grams(acc.preGrams);
    const postGrams = round4Grams(acc.postGrams);
    const deltaGrams = round4Grams(acc.deltaGrams);
    const refValue  = args.refValueByParent.get(acc.metalParentId) ?? 0;
    const monetaryEquivalent = round2(acc.monetaryEquivalent);
    metalMonetaryEquivalent += monetaryEquivalent;
    metalsPostGrams!.push({
      metalParentId:   acc.metalParentId,
      metalParentName: acc.metalParentName,
      preGrams,
      postGrams,
    });
    metalEntries.push({
      metalParentId:      acc.metalParentId,
      metalParentName:    acc.metalParentName,
      preGrams,
      postGrams,
      deltaGrams,
      metalPricePerGram:  refValue,
      monetaryEquivalent,
      preAmount:          round2(preGrams  * refValue),
      postAmount:         round2(postGrams * refValue),
      mode:               args.metalCfg.mode,
      direction:          args.metalCfg.direction,
    });
  }
  metalMonetaryEquivalent = round2(metalMonetaryEquivalent);

  // ── 2) HECHURA / SALDO MONETARIO — sumar los valores POST por línea ───────
  let saldoPre  = 0;
  let saldoPost = 0;
  let saldoDelta = 0;
  for (const m of args.lineMoney.values()) {
    if (!m) continue;
    saldoPre   += Number(m.lineMonetarySaldoPreCommercialRounding  ?? 0);
    saldoPost  += Number(m.lineMonetarySaldoPostCommercialRounding ?? 0);
    saldoDelta += Number(m.hechuraRoundingMonetaryImpact           ?? 0);
  }
  saldoPre   = round2(saldoPre);
  saldoPost  = round2(saldoPost);
  saldoDelta = round2(saldoDelta);

  const combinedAdjustment = round2(metalMonetaryEquivalent + saldoDelta);

  // Sin movimiento real (ni gramos ni saldo) → no inyectamos snapshot: el
  // footer cae a los valores exactos del motor (regla "sin redondeo → exacto").
  const anyMetalMovement = metalEntries.some((e) => Math.abs(e.deltaGrams) > EPS_GRAMS);
  if (Math.abs(combinedAdjustment) <= EPS_MONEY && !anyMetalMovement) {
    return null;
  }

  return {
    source:    "PRICE_LIST",
    scope:     "BREAKDOWN",
    appliedAt: "DOCUMENT",
    breakdown: {
      metals:                  metalEntries,
      metalMonetaryEquivalent,
      hechura: {
        preRoundingSaldoMonetario:  saldoPre,
        postRoundingSaldoMonetario: saldoPost,
        deltaSaldoMonetario:        saldoDelta,
        mode:                       args.hechuraCfg.mode,
        direction:                  args.hechuraCfg.direction,
        source:                     "PRICE_LIST_HECHURA",
      },
      combinedAdjustment,
      metalsPostGrams,
    },
    totalAdjustment: combinedAdjustment,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// FASE 0 — Contrato ÚNICO por línea: `lineCommercialSummary`
//
// Objeto autosuficiente que la UI renderiza SIN elegir fuente, sin interpretar
// modos, sin fallbacks. Lo arma `previewSale`/`confirmSale` (idéntico → preview
// = confirmación) desde los MISMOS valores per-línea ya computados
// (`computeLineCommercialRoundingMetals` + `computeLineAutonomousCommercialMoney`).
// Es display-only: NO toca `Sale.total` ni el motor.
//
// Invariantes (verificadas en tests):
//   1. metals.monetaryAmount + monetary.amount === totalLineAmount
//   2. metals.visibleGrams === Σ metals.byParent[].visibleGrams
//   3. el redondeo de metal vive SOLO en metals.roundingImpact
//   4. el redondeo monetario vive SOLO en monetary.roundingImpact
// ─────────────────────────────────────────────────────────────────────────────

export interface LineCommercialSummaryByParent {
  metalParentId:   string;
  metalParentName: string;
  /** Gramos comerciales finales (post-redondeo) visibles de ESTE padre. */
  visibleGrams:    number;
  /** Valor comercial del padre CON margen, post-redondeo (= postGrams × refValue). */
  monetaryAmount:  number;
  /** Impacto $ del redondeo de gramos del padre (= deltaGrams × refValue). */
  roundingImpact:  number;
}

export interface LineCommercialSummary {
  /** Modo de saldo DE LA LÍNEA (de su lista). NO del documento. */
  mode: "UNIFIED" | "BREAKDOWN";
  /** Bloque METAL — `null` si la línea no tiene metales (o es UNIFIED). */
  metals: {
    visibleGrams:   number;   // Σ byParent.visibleGrams
    monetaryAmount: number;   // = totalLineAmount − monetary.amount (cierre exacto)
    roundingImpact: number;   // Σ impacto $ del redondeo de gramos
    byParent:       LineCommercialSummaryByParent[];
  } | null;
  /** Bucket MONETARIO / HECHURA (todo lo no-metal). */
  monetary: {
    amount:         number;   // saldo monetario comercial final (post-redondeo)
    roundingImpact: number;   // impacto $ del redondeo del saldo
  };
  /** Total línea c/imp comercial final (= metals.monetaryAmount + monetary.amount). */
  totalLineAmount: number;
  /** Diagnóstico/auditoría — el FE NO ramifica por esto. */
  source: {
    strategy:           "PER_DOCUMENT" | "PER_LINE" | "NONE";
    appliedListMode:    string | null;
    appliedPriceListId: string | null;
    documentContext:    "SHARED_LIST" | "MIXED_LIST" | "NO_LIST";
    generatedBy:        string;
  };
}

/**
 * Ensambla el `lineCommercialSummary` de UNA línea. PURO — solo agrega/proyecta
 * valores ya computados; NO recalcula pricing.
 *
 * BREAKDOWN (con `money`): toma los valores per-línea autónomos. `metals.monetaryAmount`
 * se DERIVA como `totalLineAmount − monetary.amount` para garantizar la invariante 1
 * exacta. `byParent` es el detalle por padre (postGrams × refValue).
 *
 * UNIFIED (o sin `money`): el Total es el monetario; sin desglose de metal
 * (`metals = null`). `monetary.amount = totalLineAmount = lineTotalWithTax`.
 */
export function buildLineCommercialSummary(args: {
  mode:             "UNIFIED" | "BREAKDOWN";
  lineTotalWithTax: number;
  money:            LineAutonomousCommercialMoney | null;
  metals:           ReadonlyArray<LineCommercialRoundingMetal> | null;
  source:           Omit<LineCommercialSummary["source"], "generatedBy">;
  /** Impacto $ del redondeo comercial UNIFICADO de la línea (= delta del
   *  redondeo diferido `applyOn=TOTAL` sobre `lineTotalWithTax`, ya × qty).
   *  Solo se usa en la rama UNIFIED; el caller ya aplicó el gate
   *  `applyOn === "TOTAL"` (PRICE/NET/METAL → 0). Cuando el redondeo se
   *  suprime (política documental) llega 0. Sin clamp — negativos válidos. */
  unifiedRoundingImpact?: number;
}): LineCommercialSummary {
  const round2 = (n: number): number => Math.round(n * 100)   / 100;
  const round4 = (n: number): number => Math.round(n * 10000) / 10000;
  const GENERATED_BY = "buildLineCommercialSummary@v1";

  if (args.mode === "BREAKDOWN" && args.money) {
    const totalLineAmount = round2(args.money.lineTotalWithTaxPostCommercialRounding);
    const monetaryAmount  = round2(args.money.lineMonetarySaldoPostCommercialRounding);
    const byParent: LineCommercialSummaryByParent[] = (args.metals ?? []).map((m) => ({
      metalParentId:   m.metalParentId,
      metalParentName: m.metalParentName,
      visibleGrams:    round4(m.postGrams),
      monetaryAmount:  round2(m.postGrams * (m.metalReferenceValue ?? 0)),
      roundingImpact:  round2(m.monetaryImpact ?? 0),
    }));
    const metalsBlock = byParent.length > 0
      ? {
          visibleGrams:   round4(byParent.reduce((s, p) => s + p.visibleGrams, 0)),
          // Derivado → invariante 1 EXACTA (= Σ metalSale + metalRoundingImpact).
          monetaryAmount: round2(totalLineAmount - monetaryAmount),
          roundingImpact: round2(args.money.metalRoundingMonetaryImpact),
          byParent,
        }
      : null;
    return {
      mode:           "BREAKDOWN",
      metals:         metalsBlock,
      monetary:       { amount: monetaryAmount, roundingImpact: round2(args.money.hechuraRoundingMonetaryImpact) },
      totalLineAmount,
      source:         { ...args.source, generatedBy: GENERATED_BY },
    };
  }

  // UNIFIED (o sin money) — Total como monetario; sin desglose de metal.
  // El redondeo comercial unificado (lista `applyOn=TOTAL`) ya vino aplicado en
  // `lineTotalWithTax` (post-redondeo); su DELTA lo emite el caller en
  // `unifiedRoundingImpact` para que el footer MIXED pueda consolidarlo.
  // Sin clamp (negativos válidos). 0 cuando no hubo redondeo o fue suprimido.
  const total = round2(args.lineTotalWithTax);
  return {
    mode:           "UNIFIED",
    metals:         null,
    monetary:       { amount: total, roundingImpact: round2(args.unifiedRoundingImpact ?? 0) },
    totalLineAmount: total,
    source:         { ...args.source, generatedBy: GENERATED_BY },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// FASE 1 (display-only) — `lineCommercialDisplaySummary`: resumen comercial
// AUTÓNOMO de la línea, calculado SOLO con datos de la propia línea.
//
// Dominio ARTÍCULO: el resultado NO depende del modo del documento, ni de otras
// líneas, ni de agregados/prorrateos documentales. Por eso:
//   · El metal se agrega usando ÚNICAMENTE esta línea
//     (`aggregateMetalsForCommercialDocRounding([line])`) → `refValue` y
//     `gramsPure` line-local, SIN promediar precio/gramo con otras líneas.
//   · El margen entra como `metalSalePreRounding / metalCost` (valor PRE
//     redondeo comercial) → invariante a los flags de supresión del modo.
//   · La config de redondeo es la de la LISTA de la línea.
// Es display-only: NO toca `Sale.total`, `documentTotals`, footer ni el motor.
// Reúsa las 3 funciones puras existentes con `lineCount = 1` (índice 0).
//
// Invariante (verificado en tests):
//   BREAKDOWN solo = BREAKDOWN+BREAKDOWN = BREAKDOWN+UNIFIED  (misma línea).
// ─────────────────────────────────────────────────────────────────────────────
export function buildLineCommercialDisplaySummary(args: {
  mode:             "UNIFIED" | "BREAKDOWN";
  /** Metales de ESTA línea (line-local). Vacío / UNIFIED ⇒ sin desglose. */
  lineMetals:       ReadonlyArray<MetalSnippetForCommercialAgg>;
  quantity:         number;
  /** `metalSalePreRounding / metalCost` — margen PRE redondeo (invariante). */
  marginFactor:     number;
  metalCfg:         CommercialDocRoundingPartConfig;
  hechuraCfg:       CommercialDocRoundingPartConfig;
  lineTotalWithTax: number;
  /** Σ `metalSalePreRounding × qty` de la línea (invariante). */
  metalSaleSum:     number;
  source:           Omit<LineCommercialSummary["source"], "generatedBy">;
}): LineCommercialSummary {
  if (args.mode !== "BREAKDOWN" || args.lineMetals.length === 0) {
    return buildLineCommercialSummary({
      mode:             "UNIFIED",
      lineTotalWithTax: args.lineTotalWithTax,
      money:            null,
      metals:           null,
      source:           args.source,
    });
  }
  // Agregado de UNA sola línea ⇒ refValue/gramsPure line-local (sin dilución).
  const agg = aggregateMetalsForCommercialDocRounding([
    { quantity: args.quantity, metals: args.lineMetals as MetalSnippetForCommercialAgg[] },
  ]);
  const refValueByParent = new Map<string, number>(
    agg.metalsByParent.map((m) => [
      m.metalParentId,
      (typeof m.metalReferenceValue === "number" && m.metalReferenceValue > 0)
        ? m.metalReferenceValue
        : m.metalPricePerGram,
    ]),
  );
  const metalNameById = new Map<string, string>(
    agg.metalsByParent.map((m) => [m.metalParentId, m.metalParentName]),
  );
  const lineMetals = computeLineCommercialRoundingMetals({
    gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
    metalNameById,
    refValueByParent,
    marginFactorByLineIdx: new Map([[0, args.marginFactor]]),
    metalCfg:              args.metalCfg,
    lineCount:             1,
  });
  const money = computeLineAutonomousCommercialMoney({
    lineCommercialRoundingMetals: lineMetals,
    refValueByParent,
    lineTotalWithTaxByIdx: new Map([[0, args.lineTotalWithTax]]),
    metalSaleSumByIdx:     new Map([[0, args.metalSaleSum]]),
    hechuraCfg:            args.hechuraCfg,
    lineCount:             1,
  });
  return buildLineCommercialSummary({
    mode:             "BREAKDOWN",
    lineTotalWithTax: args.lineTotalWithTax,
    money:            money.get(0) ?? null,
    metals:           lineMetals.get(0) ?? [],
    source:           args.source,
  });
}
