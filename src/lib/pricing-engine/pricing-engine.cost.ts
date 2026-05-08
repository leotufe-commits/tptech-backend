// src/lib/pricing-engine/pricing-engine.cost.ts
// Motor de cálculo de costo de artículo con trazabilidad por pasos.
//
// Único modo: COST_LINES → ArticleCostLine (arquitectura final)

import { Prisma } from "@prisma/client";
import { prisma } from "../prisma.js";
import type {
  ArticleCostInput,
  BatchCostContext,
  CostLineInput,
  CostResult,
  PricingStep,
} from "./pricing-engine.types.js";
import {
  getBaseCurrencyId,
  getExchangeRate,
} from "./pricing-engine.currency.js";

// ---------------------------------------------------------------------------
// applyAdjustment — aplica bonus/recargo sobre un valor base
// ---------------------------------------------------------------------------

export function applyAdjustment(
  base: Prisma.Decimal,
  kind?: string | null,
  adjType?: string | null,
  adjRaw?: any
): Prisma.Decimal {
  if (!kind || kind === "" || adjRaw == null) return base;
  const absVal = new Prisma.Decimal(Math.abs(Number(adjRaw)).toString());
  const adjAmount =
    adjType === "PERCENTAGE" ? base.mul(absVal.div(100)) : absVal;
  return kind === "SURCHARGE" ? base.add(adjAmount) : base.sub(adjAmount);
}

// ---------------------------------------------------------------------------
// modoCostLines — COST_LINES (nueva arquitectura)
// FIX 1: si no hay cotización para alguna línea → marca partial pero continúa
// ---------------------------------------------------------------------------

async function modoCostLines(
  jewelryId: string,
  lines: CostLineInput[],
  steps: PricingStep[],
  entityMermaMap: Map<string, number> = new Map(),
  ctx?: BatchCostContext,
  /** F1.4 G5 #11-A — overrides per costLineId. Map<costLineId, sanitized
   *  override>. El motor aplica `effective*` SOLO a cost lines cuyo `id`
   *  está en el map. Cero mutación del input. */
  costLineOverrideMap?: Map<string, import("./pricing-engine.types.js").CostLineOverride>,
): Promise<{
  value: Prisma.Decimal | null;
  partial: boolean;
  metalCost: Prisma.Decimal;
  hechuraCost: Prisma.Decimal;
  totalGrams: Prisma.Decimal;
  metalGramsWithMerma: Prisma.Decimal;
  /** Sprint 3 — Pureza efectiva si todas las líneas METAL usan la misma
   *  variante con purity definida. null si hay heterogeneidad o no hay metal. */
  metalPurity: Prisma.Decimal | null;
}> {
  // Moneda base: desde contexto o query
  const baseCurrencyId = ctx?.baseCurrencyId ?? await getBaseCurrencyId(jewelryId);
  if (!baseCurrencyId) {
    steps.push({
      key: "COST_LINES_BASE_CURRENCY",
      label: "Moneda base del tenant",
      status: "missing",
      value: null,
      message: "No se encontró moneda base configurada",
    });
    return { value: null, partial: true, metalCost: new Prisma.Decimal(0), hechuraCost: new Prisma.Decimal(0), totalGrams: new Prisma.Decimal(0), metalGramsWithMerma: new Prisma.Decimal(0), metalPurity: null };
  }

  let total = new Prisma.Decimal(0);
  let metalTotal = new Prisma.Decimal(0);
  let hechuraTotal = new Prisma.Decimal(0);
  let gramsTotal = new Prisma.Decimal(0);
  let gramsWithMermaTotal = new Prisma.Decimal(0);
  let hasAllPrices = true;

  // saleFactor + cotizaciones de metal. Con ctx: desde el mapa pre-cargado.
  // Sin ctx: batch query (evita N+1 en el loop).
  // quote.price = finalSalePrice = suggestedPrice × saleFactor.
  // Base correcta: suggestedPrice = quote.price / saleFactor.
  let metalVariantSaleFactors: Map<string, Prisma.Decimal>;
  let metalQuoteMap: Map<string, { price: Prisma.Decimal }>;
  // Sprint 3 — purity por variantId (Decimal 0-1). null cuando la variante
  // no tiene purity definida.
  let metalVariantPurities: Map<string, Prisma.Decimal | null>;

  if (ctx) {
    // Sin queries: extraer desde contexto pre-cargado
    metalVariantSaleFactors = new Map(
      [...ctx.metalVariantData.entries()].map(([k, v]) => [k, v.saleFactor])
    );
    metalQuoteMap = new Map(
      [...ctx.metalVariantData.entries()].map(([k, v]) => [k, { price: v.price }])
    );
    metalVariantPurities = new Map(
      [...ctx.metalVariantData.entries()].map(([k, v]) => [k, v.purity ?? null])
    );
  } else {
    // Batch fetch para artículo individual (evita N+1 en el loop)
    metalVariantSaleFactors = new Map<string, Prisma.Decimal>();
    metalQuoteMap = new Map<string, { price: Prisma.Decimal }>();
    metalVariantPurities = new Map<string, Prisma.Decimal | null>();
    const metalVariantIds = [...new Set(
      lines.filter(l => l.type === "METAL" && l.metalVariantId).map(l => l.metalVariantId as string)
    )];
    if (metalVariantIds.length > 0) {
      const [variantRows, quoteRows] = await Promise.all([
        prisma.metalVariant.findMany({
          where: { id: { in: metalVariantIds } },
          select: { id: true, saleFactor: true, purity: true },
        }),
        prisma.metalQuote.findMany({
          where: { variantId: { in: metalVariantIds }, currencyId: baseCurrencyId },
          orderBy: { effectiveAt: "desc" },
          select: { variantId: true, price: true },
        }),
      ]);
      for (const v of variantRows) {
        metalVariantSaleFactors.set(v.id, new Prisma.Decimal(v.saleFactor?.toString() ?? "1"));
        metalVariantPurities.set(
          v.id,
          v.purity != null ? new Prisma.Decimal(v.purity.toString()) : null,
        );
      }
      for (const q of quoteRows) {
        if (!metalQuoteMap.has(q.variantId)) metalQuoteMap.set(q.variantId, { price: q.price });
      }
    }
  }
  // Sprint 3 — purity efectiva del documento. Si todas las líneas METAL usan
  // variantes con la misma purity definida, lo exponemos para que la capa
  // pricelist calcule pureGramsBase. Si hay heterogeneidad (mezcla 18K/22K,
  // o alguna variante sin purity), null. POLICY.md §8.
  let observedPurity: Prisma.Decimal | null = null;
  let purityHeterogeneous = false;
  let metalLinesSeen = 0;

  for (const line of lines) {
    // F1.4 G5 #11-A — override per costLineId (cero mutación de `line`).
    // Lookup O(1). Cuando hay match, los `effective*` reemplazan los
    // valores originales sin mutar el objeto.
    const ov = (costLineOverrideMap && typeof line.id === "string" && line.id.length > 0)
      ? costLineOverrideMap.get(line.id)
      : undefined;
    const effectiveQtyRaw = ov?.quantityOverride != null
      ? ov.quantityOverride
      : line.quantity;
    const qty = new Prisma.Decimal(effectiveQtyRaw?.toString() ?? "0");

    if (line.type === "METAL") {
      if (!line.metalVariantId) {
        hasAllPrices = false;
        steps.push({
          key: "COST_LINES_METAL",
          label: "Línea de costo (METAL)",
          status: "missing",
          value: null,
          message: "Línea de metal sin metalVariantId",
        });
        continue;
      }

      const quote = metalQuoteMap.get(line.metalVariantId);

      if (!quote) {
        hasAllPrices = false;
        steps.push({
          key: "COST_LINES_METAL",
          label: "Cotización de metal",
          status: "missing",
          value: null,
          message: `Sin cotización para variante ${line.metalVariantId}`,
          meta: { metalVariantId: line.metalVariantId },
        });
        continue;
      }

      // Sprint 3 — registrar purity de esta línea para resolver `metalPurity`
      // del documento al final del loop.
      metalLinesSeen += 1;
      const linePurity = metalVariantPurities.get(line.metalVariantId) ?? null;
      if (linePurity == null) {
        purityHeterogeneous = true;
      } else if (observedPurity == null) {
        observedPurity = linePurity;
      } else if (!observedPurity.equals(linePurity)) {
        purityHeterogeneous = true;
      }

      // F1.4 G5 #11-A — merma efectiva con prioridad explícita:
      //   1) costLineOverride.mermaPercentOverride (del array por costLineId)
      //   2) entity merma override (config legacy global por variante)
      //   3) merma de la línea (config artículo)
      //   4) 0 (sin merma)
      const lineOverrideMerma = ov?.mermaPercentOverride;
      const entityMerma = line.metalVariantId ? entityMermaMap.get(line.metalVariantId) : undefined;
      const effectiveMerma = lineOverrideMerma != null
        ? lineOverrideMerma
        : (entityMerma != null ? entityMerma : (line.mermaPercent ?? 0));
      const mermaSource =
        lineOverrideMerma != null ? "costLineOverride"
        : (entityMerma != null     ? "entity"
        :                            "line");
      const mermaFactor = new Prisma.Decimal(1).add(
        new Prisma.Decimal(effectiveMerma.toString()).div(100)
      );

      // Usar suggestedPrice = quote.price / saleFactor como base del costo.
      // quote.price almacena finalSalePrice = suggestedPrice × saleFactor. Si el saleFactor
      // fue usado también como mermaPercent (práctica habitual), multiplicar por mermaFactor
      // sobre finalSalePrice duplicaría ese factor. Al dividir primero por saleFactor obtenemos
      // la base "sin factor" y aplicamos la merma una sola vez. Con saleFactor=1 el resultado
      // es idéntico al comportamiento anterior.
      const saleFactor = metalVariantSaleFactors.get(line.metalVariantId) ?? new Prisma.Decimal(1);
      const suggestedPrice = saleFactor.gt(0)
        ? new Prisma.Decimal(quote.price.toString()).div(saleFactor)
        : new Prisma.Decimal(quote.price.toString());

      const gramsWithMerma = qty.mul(mermaFactor);
      const baseLineCost = gramsWithMerma.mul(suggestedPrice);
      // Ajuste por línea ignorado para METAL (solo aplica a HECHURA/PRODUCT/SERVICE)
      const lineCost = baseLineCost.lt(0) ? new Prisma.Decimal(0) : baseLineCost;
      total = total.add(lineCost);
      metalTotal = metalTotal.add(lineCost);
      gramsTotal = gramsTotal.add(qty);
      gramsWithMermaTotal = gramsWithMermaTotal.add(gramsWithMerma);

      steps.push({
        key: "COST_LINES_METAL",
        label: "Línea de metal",
        status: "ok",
        value: lineCost,
        meta: {
          variantId: line.metalVariantId, qty: qty.toString(), merma: effectiveMerma, mermaSource,
          // quotePrice expone el precio base (suggestedPrice) sobre el que se aplica la merma,
          // no el finalSalePrice. Esto permite que la fórmula del simulador sea coherente.
          quotePrice: suggestedPrice.toFixed(6),
          // F1.3 G4.x #9-A — costLineId estable, persistente, snapshot-safe.
          // Idéntico al patrón emitido para HECHURA/PRODUCT/SERVICE en el ELSE
          // de abajo (línea 319). Necesario para `composition.metals[]` poder
          // referenciar cada cost line individualmente sin depender del orden.
          ...(line.id ? { costLineId: line.id } : {}),
        },
      });
    } else {
      // FASE 2 — `catalogVariantId` se acepta en el tipo y se persiste en
      // `ArticleCostLine`, pero NO altera el costo del componente: el motor
      // sigue usando `qty × unitValue` (el `unitValue` viene poblado desde el
      // costo del padre referenciado al armar la composición). El `variantId`
      // se usa exclusivamente para descontar stock de la variante correcta
      // en confirmSale (ver sales.service.ts). Si en el futuro se necesita
      // recomputar el costo del componente con `weightOverride` de la
      // variante, se hace acá leyendo `line.catalogVariantId`.
      // F1.4 G5 #11-A — unitValue efectivo (override per costLineId gana).
      const effectiveUnitValueRaw = ov?.unitValueOverride != null
        ? ov.unitValueOverride
        : line.unitValue;
      const unitVal = new Prisma.Decimal(effectiveUnitValueRaw?.toString() ?? "0");
      let lineValue = qty.mul(unitVal);

      let conversionMeta: Record<string, string> | undefined;
      if (line.currencyId && line.currencyId !== baseCurrencyId) {
        // Tasa desde contexto pre-cargado (batch) o query individual
        const rateInfo = ctx
          ? ctx.rateMap.get(line.currencyId) ?? null
          : await getExchangeRate(line.currencyId);
        if (!rateInfo) {
          hasAllPrices = false;
          steps.push({
            key: "COST_LINES_CURRENCY",
            label: "Conversión de moneda (línea de costo)",
            status: "missing",
            value: null,
            message: `Sin tasa para moneda ${line.currencyId}`,
          });
          continue;
        }
        conversionMeta = {
          originalAmount:  lineValue.toString(),
          fromCurrencyId:  line.currencyId,
          currencyCode:    rateInfo.code,
          currencySymbol:  rateInfo.symbol,
          rate:            rateInfo.rate.toString(),
        };
        lineValue = lineValue.mul(rateInfo.rate);
      }

      // F1.3 G4.1.2 — capturar valor PRE-ajuste para computar el monto
      // absoluto del adjustment (passthrough — el frontend NO recalcula).
      // Convención de signo (alineada con ComponentSaleAdjustment.amount,
      // types.ts:164-165): positivo cuando el adjustment REDUCE el valor
      // (BONUS), negativo cuando lo AUMENTA (SURCHARGE).
      const preAdjValue = lineValue;
      // F1.4 G5 #11-A — adjustment efectivo aplicando override per costLineId.
      //   · undefined  → mantener original.
      //   · null       → LIMPIAR (sin bonif/recargo, equivale a kind="").
      //   · valor      → reemplazar.
      // Si el override tiene adjustmentKind=null, los 3 campos se limpian
      // (resolveEffectiveAdjustment ya garantiza eso).
      let effAdjKind:  unknown = line.lineAdjKind;
      let effAdjType:  unknown = line.lineAdjType;
      let effAdjValue: unknown = line.lineAdjValue;
      if (ov && (
        ov.adjustmentKind  !== undefined ||
        ov.adjustmentType  !== undefined ||
        ov.adjustmentValue !== undefined
      )) {
        if (ov.adjustmentKind === null) {
          effAdjKind = null;
          effAdjType = null;
          effAdjValue = null;
        } else {
          if (ov.adjustmentKind  !== undefined) effAdjKind  = ov.adjustmentKind;
          if (ov.adjustmentType  !== undefined) effAdjType  = ov.adjustmentType;
          if (ov.adjustmentValue !== undefined) effAdjValue = ov.adjustmentValue;
        }
      }
      // Ajuste por línea (bonificación / recargo) — usa los efectivos.
      lineValue = applyAdjustment(
        lineValue,
        effAdjKind  as Parameters<typeof applyAdjustment>[1],
        effAdjType  as Parameters<typeof applyAdjustment>[2],
        effAdjValue as Parameters<typeof applyAdjustment>[3],
      );
      if (lineValue.lt(0)) lineValue = new Prisma.Decimal(0);

      total = total.add(lineValue);
      // Regla del sistema: todo lo que NO es metal es "hechura" para cálculo de márgenes.
      // Esto incluye: HECHURA, PRODUCT, SERVICE, MANUAL.
      hechuraTotal = hechuraTotal.add(lineValue);

      // F1.3 G4.1.2 — monto absoluto del ajuste, computado por el motor.
      // Solo se incluye en meta cuando hubo adjustment (kind no vacío);
      // así el frontend evita derivarlo y respeta el redondeo del motor.
      const hasAdjustment = !!effAdjKind && effAdjKind !== "";
      let lineAdjAmountStr: string | null = null;
      if (hasAdjustment) {
        // delta = pre - post. Positivo = reducción (BONUS); negativo = aumento (SURCHARGE).
        const delta = preAdjValue.sub(lineValue);
        lineAdjAmountStr = delta.toString();
      }

      // Obtener código del artículo referenciado (solo para PRODUCT/SERVICE)
      const refCode: string | null =
        line.lineCode?.trim() ||
        (line as any).catalogItem?.sku?.trim() ||
        (line as any).catalogItem?.code?.trim() ||
        null;
      const lineLabel = line.label?.trim() || null;

      steps.push({
        key: `COST_LINES_${line.type}`,
        label: lineLabel || `Línea de costo (${line.type})`,
        status: "ok",
        value: lineValue,
        meta: {
          // Cantidad y valor unitario (en moneda original si hay conversión, en base si no)
          // — usados por el frontend para mostrar la fórmula "qty × unitValue = value".
          qty:        qty.toString(),
          unitValue:  unitVal.toString(),
          ...(conversionMeta ?? {}),
          ...(lineLabel ? { lineLabel }  : {}),
          ...(refCode   ? { lineCode: refCode } : {}),
          ...(effAdjKind && effAdjKind !== ""
            ? { lineAdjKind: effAdjKind, lineAdjType: effAdjType, lineAdjValue: effAdjValue }
            : {}),
          // F1.3 G4.1.2 — campos nuevos para trazabilidad UI:
          //   · costLineId — estable, persistente, snapshot-safe (NO orden/índice)
          //   · catalogItemId — solo para PRODUCT/SERVICE (ref a otro Article)
          //   · affectsStock — solo si está definido en la línea (semánticamente
          //     sensible: undefined ≠ false, ver doc CostLineInput.affectsStock)
          //   · lineAdjAmount — monto absoluto del ajuste (computado por motor,
          //     ya respetando precisión Decimal). Solo cuando hasAdjustment.
          ...(line.id            ? { costLineId:    line.id }            : {}),
          ...(line.catalogItemId ? { catalogItemId: line.catalogItemId } : {}),
          ...(typeof line.affectsStock === "boolean"
            ? { affectsStock: line.affectsStock }
            : {}),
          ...(lineAdjAmountStr != null ? { lineAdjAmount: lineAdjAmountStr } : {}),
        },
      });
    }
  }

  // Sprint 3 — purity efectiva: solo la exponemos si hay al menos una línea
  // METAL y todas comparten la misma purity. Cualquier variante sin purity o
  // con purity distinta neutraliza el campo (null).
  const metalPurity: Prisma.Decimal | null =
    metalLinesSeen > 0 && !purityHeterogeneous && observedPurity != null
      ? observedPurity
      : null;

  return { value: total, partial: !hasAllPrices, metalCost: metalTotal, hechuraCost: hechuraTotal, totalGrams: gramsTotal, metalGramsWithMerma: gramsWithMermaTotal, metalPurity };
}

// ---------------------------------------------------------------------------
// calculateCostFromLines — API pública canónica para costo desde composición
//
// Único punto de entrada para cálculo de costo. Procesa líneas de tipo
// METAL, HECHURA, PRODUCT, SERVICE y MANUAL. Artículos sin líneas devuelven
// { value: null, partial: true }.
//
// Parámetros:
//   jewelryId  — tenant ID (para cotizaciones de metal y moneda base)
//   lines      — líneas de composición de costo (ArticleCostLine)
//   adjustment — ajuste global sobre el total de líneas (opcional)
//   ctx        — contexto pre-cargado para cálculo en batch (sin N+1 queries)
// ---------------------------------------------------------------------------

export async function calculateCostFromLines(
  jewelryId: string,
  lines: CostLineInput[],
  adjustment?: {
    kind?:  string | null;
    type?:  string | null;
    value?: any;
  },
  ctx?: BatchCostContext,
  /** F1.4 G5 #11-A — overrides per costLineId. Cuando se pasa, el motor
   *  aplica los `effective*` correspondientes vía Map<id, override>.
   *  Cero mutación del input `lines`. */
  costLineOverrides?: ReadonlyArray<import("./pricing-engine.types.js").CostLineOverride>,
): Promise<CostResult> {
  const steps: PricingStep[] = [];

  if (!lines || lines.length === 0) {
    steps.push({
      key:     "COST_LINES_EMPTY",
      label:   "Sin líneas de costo",
      status:  "missing",
      value:   null,
      message: "No se proporcionaron líneas de costo",
    });
    return { value: null, mode: "COST_LINES", partial: true, steps };
  }

  // F1.4 G5 #11-A — construir Map<costLineId, override sanitizado>.
  // Los warnings van al `debugWarnings` del CostResult — NO a steps[].
  const { buildCostLineOverrideMap } = await import("./pricing-engine.cost-line-overrides.js");
  const { map: ovMap, applied: ovApplied, warnings: ovWarnings } =
    Array.isArray(costLineOverrides) && costLineOverrides.length > 0
      ? buildCostLineOverrideMap(costLineOverrides, lines)
      : { map: new Map(), applied: [], warnings: [] };

  const linesResult = await modoCostLines(jewelryId, lines, steps, new Map(), ctx, ovMap);

  if (linesResult.value === null) {
    return {
      value: null, mode: "COST_LINES", partial: true, steps,
      // Mantener trazabilidad de overrides incluso cuando no hay valor.
      ...(ovApplied.length > 0 ? { costLineOverridesApplied: ovApplied } : {}),
      ...(ovWarnings.length > 0 ? { debugWarnings: ovWarnings } : {}),
    };
  }

  const adjusted = applyAdjustment(
    linesResult.value,
    adjustment?.kind,
    adjustment?.type,
    adjustment?.value,
  );

  steps.push({
    key:    "COST_LINES_FINAL",
    label:  "Total líneas de costo (con ajuste)",
    status: linesResult.partial ? "partial" : "ok",
    value:  adjusted,
    meta: {
      adjustmentKind:  adjustment?.kind  ?? null,
      adjustmentType:  adjustment?.type  ?? null,
      adjustmentValue: adjustment?.value != null ? String(adjustment.value) : null,
      sumLines:        linesResult.value.toString(),
    },
  });

  const adjFactor = linesResult.value.gt(0)
    ? adjusted.div(linesResult.value)
    : new Prisma.Decimal(1);

  return {
    value:               adjusted,
    mode:                "COST_LINES",
    partial:             linesResult.partial,
    steps,
    metalCost:           linesResult.metalCost.mul(adjFactor),
    hechuraCost:         linesResult.hechuraCost.mul(adjFactor),
    totalGrams:          linesResult.totalGrams,
    metalGramsWithMerma: linesResult.metalGramsWithMerma,
    // Sprint 3 — POLICY.md §8 — alimenta pureGramsBase en el motor de venta.
    metalPurity:         linesResult.metalPurity,
    // F1.4 G5 #11-A — trazabilidad de overrides aplicados + warnings.
    ...(ovApplied.length > 0 ? { costLineOverridesApplied: ovApplied } : {}),
    ...(ovWarnings.length > 0 ? { debugWarnings: ovWarnings } : {}),
  };
}

// ---------------------------------------------------------------------------
// enrichCostMetalSteps — agrega metalName/variantName/variantSku/purity a cada
// step COST_LINES_METAL. Llamado desde resolveFinalSalePrice y buildPriceBreakdown.
// ---------------------------------------------------------------------------

export async function enrichCostMetalSteps(steps: PricingStep[]): Promise<void> {
  const variantIds: string[] = [];
  for (const step of steps) {
    if (step.key !== "COST_LINES_METAL" || !step.meta) continue;
    const vId = String(step.meta.variantId ?? "");
    if (vId) variantIds.push(vId);
  }
  if (variantIds.length === 0) return;

  const variantRows = await prisma.metalVariant.findMany({
    where: { id: { in: variantIds } },
    select: {
      id:        true,
      name:      true,
      sku:       true,
      purity:    true,
      saleFactor: true,
      metalId:   true,
      metal: { select: { name: true, symbol: true } },
    },
  });

  type VariantInfo = {
    purity:      number | null;
    saleFactor:  number;
    metalId:     string;
    variantName: string;
    variantSku:  string;
    metalName:   string | null;
    metalSymbol: string | null;
  };
  const variantMap = new Map<string, VariantInfo>();
  for (const row of variantRows) {
    variantMap.set(row.id, {
      purity:      row.purity      != null ? parseFloat(row.purity.toString())      : null,
      saleFactor:  row.saleFactor  != null ? parseFloat(row.saleFactor.toString())  : 1,
      metalId:     row.metalId,
      variantName: row.name,
      variantSku:  row.sku,
      metalName:   row.metal?.name   ?? null,
      metalSymbol: row.metal?.symbol ?? null,
    });
  }

  for (const step of steps) {
    if (step.key !== "COST_LINES_METAL" || !step.meta) continue;
    const vId = String(step.meta.variantId ?? "");
    const v = variantMap.get(vId);
    if (!v) continue;
    const gramsOriginal: number | null =
      step.meta.qty != null ? parseFloat(String(step.meta.qty)) : null;
    const rawMerma  = step.meta.merma != null ? parseFloat(String(step.meta.merma)) : 0;
    const mermaMul  = 1 + rawMerma / 100;
    const gramsFineEquivalent: number | null =
      gramsOriginal != null && v.purity != null
        ? parseFloat((gramsOriginal * v.purity * mermaMul).toFixed(6))
        : null;
    step.meta = {
      ...step.meta,
      metalId:     v.metalId,
      variantName: v.variantName,
      variantSku:  v.variantSku,
      ...(v.metalName          && { metalName:   v.metalName }),
      ...(v.metalSymbol        && { metalSymbol: v.metalSymbol }),
      ...(v.purity      != null && { purity: v.purity }),
      ...(v.saleFactor  !== 1   && { saleFactor: v.saleFactor }),
      ...(gramsOriginal != null && { gramsOriginal }),
      ...(gramsFineEquivalent != null && { gramsFineEquivalent }),
    };
  }
}

// ---------------------------------------------------------------------------
// buildBatchCostContext — pre-carga todos los datos necesarios para un batch
// de artículos sin queries dentro del loop (evita N+1 en listArticles)
// ---------------------------------------------------------------------------

export async function buildBatchCostContext(
  jewelryId: string,
  articles: ArticleCostInput[]
): Promise<BatchCostContext> {
  // Recolectar todos los variantIds y currencyIds únicos del batch
  const variantIdSet = new Set<string>();
  const currencyIdSet = new Set<string>();

  for (const a of articles) {
    for (const l of (a.costComposition ?? [])) {
      if (l.type === "METAL" && l.metalVariantId) variantIdSet.add(l.metalVariantId);
      if (l.currencyId) currencyIdSet.add(l.currencyId);
    }
  }

  const variantIds    = [...variantIdSet];
  const currencyIds   = [...currencyIdSet];

  // Query paralela: jewelry, metalVariant, metalQuote, currencyRate
  const [jewelry, baseCurrencyRow, variantRows, rateRows] = await Promise.all([
    prisma.jewelry.findUnique({
      where: { id: jewelryId },
      select: { defaultMermaPercent: true },
    }),
    prisma.currency.findFirst({
      where: { jewelryId, isBase: true, deletedAt: null },
      select: { id: true },
    }),
    variantIds.length > 0
      ? prisma.metalVariant.findMany({
          where: { id: { in: variantIds } },
          select: { id: true, saleFactor: true, purity: true },
        })
      : Promise.resolve([]),
    currencyIds.length > 0
      ? prisma.currencyRate.findMany({
          where: { currencyId: { in: currencyIds } },
          orderBy: { createdAt: "desc" },
          select: {
            currencyId: true,
            rate: true,
            currency: { select: { code: true, symbol: true } },
          },
        })
      : Promise.resolve([]),
  ]);

  const baseCurrencyId = baseCurrencyRow?.id ?? "";

  // metalVariant saleFactor map
  const saleFactorMap = new Map<string, Prisma.Decimal>();
  // Sprint 3 — purity por variantId (Decimal 0-1 o null).
  const purityMap = new Map<string, Prisma.Decimal | null>();
  for (const v of variantRows) {
    saleFactorMap.set(v.id, new Prisma.Decimal(v.saleFactor?.toString() ?? "1"));
    purityMap.set(
      v.id,
      (v as any).purity != null ? new Prisma.Decimal((v as any).purity.toString()) : null,
    );
  }

  // metalQuote por variante en moneda base (query separada, necesita baseCurrencyId)
  let quoteRows: { variantId: string; price: Prisma.Decimal }[] = [];
  if (variantIds.length > 0 && baseCurrencyId) {
    quoteRows = await prisma.metalQuote.findMany({
      where: { variantId: { in: variantIds }, currencyId: baseCurrencyId },
      orderBy: { effectiveAt: "desc" },
      select: { variantId: true, price: true },
    });
  }

  // Construir metalVariantData: variantId → { price, saleFactor, purity }
  const metalVariantData = new Map<string, { price: Prisma.Decimal; saleFactor: Prisma.Decimal; purity: Prisma.Decimal | null }>();
  for (const q of quoteRows) {
    if (!metalVariantData.has(q.variantId)) {
      metalVariantData.set(q.variantId, {
        price:      new Prisma.Decimal(q.price.toString()),
        saleFactor: saleFactorMap.get(q.variantId) ?? new Prisma.Decimal(1),
        purity:     purityMap.get(q.variantId) ?? null,
      });
    }
  }
  // Rellenar variantes sin cotización (para que saleFactorMap esté completa)
  for (const v of variantRows) {
    if (!metalVariantData.has(v.id)) {
      metalVariantData.set(v.id, {
        price:      new Prisma.Decimal(0),
        saleFactor: saleFactorMap.get(v.id) ?? new Prisma.Decimal(1),
        purity:     purityMap.get(v.id) ?? null,
      });
    }
  }

  // rateMap: currencyId → { rate, code, symbol } (solo la tasa más reciente por moneda)
  const rateMap = new Map<string, { rate: Prisma.Decimal; code: string; symbol: string }>();
  for (const r of rateRows) {
    if (!rateMap.has(r.currencyId)) {
      rateMap.set(r.currencyId, {
        rate:   new Prisma.Decimal(r.rate.toString()),
        code:   r.currency.code,
        symbol: r.currency.symbol,
      });
    }
  }

  return {
    baseCurrencyId,
    defaultMermaPercent: jewelry?.defaultMermaPercent ?? 0,
    metalVariantData,
    rateMap,
    // Cache lazy de metales por artículo (FASE 3 — scope METALS).
    // Empieza vacío porque `ArticleCostInput` no incluye `id`; se popula
    // on-demand desde `getArticleMetalVariantIds(...,ctx)` o vía
    // `loadArticleMetalVariantsBatch` antes del loop.
    articleMetalVariantsMap: new Map<string, string[]>(),
  };
}

// ---------------------------------------------------------------------------
// resolveVariantAwareWeight — resuelve el peso final respetando el override de variante
// ---------------------------------------------------------------------------
//
// Regla (prioridad mayor → menor):
//   1. variant.weightOverride != null → usarlo (incluyendo 0, que es válido)
//   2. article.weight != null         → usarlo como fallback legacy
//   3. null                           → sin peso disponible
//
// Notas:
// - La comparación es != null (no "falsy"), por lo que 0 se trata como peso válido.
// - El caller puede pasar cualquier tipo numérico; la función normaliza a Decimal.
// - Esta función es pura: sin efectos secundarios ni queries.

export function resolveVariantAwareWeight(
  articleWeight: any,
  variantWeightOverride?: any
): Prisma.Decimal | null {
  if (variantWeightOverride != null) {
    return new Prisma.Decimal(variantWeightOverride.toString());
  }
  if (articleWeight != null) {
    return new Prisma.Decimal(articleWeight.toString());
  }
  return null;
}

// ---------------------------------------------------------------------------
// getArticleMetalVariantIds — set de variantes de metal del artículo
// ---------------------------------------------------------------------------
//
// Retorna los `metalVariantId` distintos presentes en la composición de costo
// del artículo (líneas tipo METAL). Usado por la evaluación de scope METALS
// en promociones, cupones y descuentos por cantidad.
//
// v1: NO se propagan metales desde componentes de combos comerciales — solo
// la composición DIRECTA del articleId pedido. Si el ctx ya pre-cargó el set,
// se devuelve sin nueva query.

export async function getArticleMetalVariantIds(
  jewelryId: string,
  articleId: string,
  ctx?: BatchCostContext
): Promise<string[]> {
  if (ctx?.articleMetalVariantsMap?.has(articleId)) {
    return ctx.articleMetalVariantsMap.get(articleId)!;
  }
  // Defensa contra mocks parciales de prisma en tests: si el cliente no
  // expone `articleCostLine`, devolvemos []. En producción siempre existe.
  if (!(prisma as any).articleCostLine?.findMany) return [];
  const lines = await prisma.articleCostLine.findMany({
    where: { jewelryId, articleId, type: "METAL", metalVariantId: { not: null } },
    select: { metalVariantId: true },
  });
  const ids = [...new Set(
    lines.map(l => l.metalVariantId).filter((v): v is string => !!v)
  )];
  if (ctx?.articleMetalVariantsMap) {
    ctx.articleMetalVariantsMap.set(articleId, ids);
  }
  return ids;
}

// ---------------------------------------------------------------------------
// loadArticleMetalVariantsBatch — versión batch (1 query para N artículos)
// ---------------------------------------------------------------------------
// Útil cuando se procesa una lista grande de artículos (listados, ventas con
// muchas líneas). El consumidor puede pasar el resultado a `BatchCostContext`
// vía `articleMetalVariantsMap` para evitar `getArticleMetalVariantIds` lazy
// dentro del loop.

export async function loadArticleMetalVariantsBatch(
  jewelryId: string,
  articleIds: string[]
): Promise<Map<string, string[]>> {
  const out = new Map<string, string[]>();
  if (articleIds.length === 0) return out;
  const lines = await prisma.articleCostLine.findMany({
    where: { jewelryId, articleId: { in: articleIds }, type: "METAL", metalVariantId: { not: null } },
    select: { articleId: true, metalVariantId: true },
  });
  for (const id of articleIds) out.set(id, []);
  for (const l of lines) {
    if (!l.metalVariantId) continue;
    const arr = out.get(l.articleId) ?? [];
    if (!arr.includes(l.metalVariantId)) arr.push(l.metalVariantId);
    out.set(l.articleId, arr);
  }
  return out;
}
