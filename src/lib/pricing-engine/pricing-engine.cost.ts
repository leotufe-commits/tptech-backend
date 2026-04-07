// src/lib/pricing-engine/pricing-engine.cost.ts
// Motor de cálculo de costo de artículo con trazabilidad por pasos.
//
// Modos (en orden de prioridad):
//   COST_LINES          → ArticleCostLine (nueva arquitectura)
//                         FIX 1: si falla → cae a MANUAL en vez de abortar
//   MANUAL              → manualBaseCost (o legacy costPrice)
//   MULTIPLIER          → multiplierQuantity × multiplierValue
//   METAL_MERMA_HECHURA → composiciones metálicas + merma + hechura
//                         FIX 2: hechura PER_GRAM usa gramos CON merma

import { Prisma } from "@prisma/client";
import { prisma } from "../prisma.js";
import type {
  ArticleCostInput,
  CostLineInput,
  CostResult,
  PriceBreakdown,
  PriceBreakdownAdjustment,
  PriceBreakdownMetalItem,
  PricingStep,
} from "./pricing-engine.types.js";
import {
  getBaseCurrencyId,
  getExchangeRate,
  normalizeToBaseCurrency,
} from "./pricing-engine.currency.js";

// ---------------------------------------------------------------------------
// applyAdjustment — aplica bonus/recargo sobre un valor base
// ---------------------------------------------------------------------------

function applyAdjustment(
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
  steps: PricingStep[]
): Promise<{ value: Prisma.Decimal | null; partial: boolean; metalCost: Prisma.Decimal; hechuraCost: Prisma.Decimal; totalGrams: Prisma.Decimal }> {
  const baseCurrencyId = await getBaseCurrencyId(jewelryId);
  if (!baseCurrencyId) {
    steps.push({
      key: "COST_LINES_BASE_CURRENCY",
      label: "Moneda base del tenant",
      status: "missing",
      value: null,
      message: "No se encontró moneda base configurada",
    });
    return { value: null, partial: true, metalCost: new Prisma.Decimal(0), hechuraCost: new Prisma.Decimal(0), totalGrams: new Prisma.Decimal(0) };
  }

  let total = new Prisma.Decimal(0);
  let metalTotal = new Prisma.Decimal(0);
  let hechuraTotal = new Prisma.Decimal(0);
  let gramsTotal = new Prisma.Decimal(0);
  let hasAllPrices = true;

  for (const line of lines) {
    const qty = new Prisma.Decimal(line.quantity?.toString() ?? "0");

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

      const quote = await prisma.metalQuote.findFirst({
        where: { variantId: line.metalVariantId, currencyId: baseCurrencyId },
        orderBy: { effectiveAt: "desc" },
        select: { price: true },
      });

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

      const mermaFactor = new Prisma.Decimal(1).add(
        new Prisma.Decimal(line.mermaPercent?.toString() ?? "0").div(100)
      );
      const baseLineCost = qty.mul(mermaFactor).mul(new Prisma.Decimal(quote.price.toString()));
      // Ajuste por línea ignorado para METAL (solo aplica a HECHURA/PRODUCT/SERVICE)
      const lineCost = baseLineCost.lt(0) ? new Prisma.Decimal(0) : baseLineCost;
      total = total.add(lineCost);
      metalTotal = metalTotal.add(lineCost);
      gramsTotal = gramsTotal.add(qty);

      steps.push({
        key: "COST_LINES_METAL",
        label: "Línea de metal",
        status: "ok",
        value: lineCost,
        meta: {
          variantId: line.metalVariantId, qty: qty.toString(), merma: line.mermaPercent, quotePrice: quote.price.toString(),
        },
      });
    } else {
      const unitVal = new Prisma.Decimal(line.unitValue?.toString() ?? "0");
      let lineValue = qty.mul(unitVal);

      let conversionMeta: Record<string, string> | undefined;
      if (line.currencyId && line.currencyId !== baseCurrencyId) {
        const rateInfo = await getExchangeRate(line.currencyId);
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

      // Ajuste por línea (bonificación / recargo)
      lineValue = applyAdjustment(lineValue, line.lineAdjKind, line.lineAdjType, line.lineAdjValue);
      if (lineValue.lt(0)) lineValue = new Prisma.Decimal(0);

      total = total.add(lineValue);
      // Regla del sistema: todo lo que NO es metal es "hechura" para cálculo de márgenes.
      // Esto incluye: HECHURA, PRODUCT, SERVICE, MANUAL.
      hechuraTotal = hechuraTotal.add(lineValue);

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
          ...(conversionMeta ?? {}),
          ...(lineLabel ? { lineLabel }  : {}),
          ...(refCode   ? { lineCode: refCode } : {}),
          ...(line.lineAdjKind && line.lineAdjKind !== "" ? { lineAdjKind: line.lineAdjKind, lineAdjType: line.lineAdjType, lineAdjValue: line.lineAdjValue } : {}),
        },
      });
    }
  }

  return { value: total, partial: !hasAllPrices, metalCost: metalTotal, hechuraCost: hechuraTotal, totalGrams: gramsTotal };
}

// ---------------------------------------------------------------------------
// modoManual — MANUAL
// ---------------------------------------------------------------------------

async function modoManual(
  jewelryId: string,
  article: ArticleCostInput,
  steps: PricingStep[]
): Promise<Prisma.Decimal | null> {
  let val: Prisma.Decimal | null = null;

  if (article.manualBaseCost != null) {
    val = new Prisma.Decimal(article.manualBaseCost.toString());

    // Convertir a base ANTES de aplicar ajuste (FIX: conversión primero)
    if (article.manualCurrencyId) {
      const baseCurrencyId = await getBaseCurrencyId(jewelryId);
      if (baseCurrencyId && article.manualCurrencyId !== baseCurrencyId) {
        const converted = await normalizeToBaseCurrency({
          rawValue: val,
          currencyId: article.manualCurrencyId,
          baseCurrencyId,
          stepKey: "MANUAL_CURRENCY",
          stepLabel: "Conversión de moneda (costo manual)",
          steps,
        });
        if (converted === null) return null;
        val = converted;
      }
    }

    // Aplicar ajuste sobre el valor ya convertido
    val = applyAdjustment(
      val,
      article.manualAdjustmentKind,
      article.manualAdjustmentType,
      article.manualAdjustmentValue
    );

    steps.push({
      key: "MANUAL_BASE_COST",
      label: "Costo manual (base)",
      status: "ok",
      value: val,
      meta: {
        manualBaseCost: article.manualBaseCost?.toString(),
        adjustmentKind: article.manualAdjustmentKind,
      },
    });
  } else if (article.costPrice != null) {
    // Fallback legacy: costPrice ya incluye ajuste
    val = new Prisma.Decimal(article.costPrice.toString());
    steps.push({
      key: "MANUAL_COST_PRICE",
      label: "Costo manual (legacy costPrice)",
      status: "ok",
      value: val,
    });
  } else {
    steps.push({
      key: "MANUAL_COST_PRICE",
      label: "Costo manual",
      status: "missing",
      value: null,
      message: "No hay costPrice ni manualBaseCost configurado",
    });
    return null;
  }

  return val;
}

// ---------------------------------------------------------------------------
// modoMultiplier — MULTIPLIER
// ---------------------------------------------------------------------------

async function modoMultiplier(
  jewelryId: string,
  article: ArticleCostInput,
  steps: PricingStep[]
): Promise<Prisma.Decimal | null> {
  if (article.multiplierValue == null || article.multiplierQuantity == null) {
    steps.push({
      key: "MULTIPLIER",
      label: "Modo multiplicador",
      status: "missing",
      value: null,
      message: "Faltan multiplierValue o multiplierQuantity",
    });
    return null;
  }

  let base = new Prisma.Decimal(article.multiplierQuantity.toString())
    .mul(new Prisma.Decimal(article.multiplierValue.toString()));

  if (article.multiplierCurrencyId) {
    const baseCurrencyId = await getBaseCurrencyId(jewelryId);
    if (baseCurrencyId && article.multiplierCurrencyId !== baseCurrencyId) {
      const converted = await normalizeToBaseCurrency({
        rawValue: base,
        currencyId: article.multiplierCurrencyId,
        baseCurrencyId,
        stepKey: "MULTIPLIER_CURRENCY",
        stepLabel: "Conversión de moneda (multiplicador)",
        steps,
      });
      if (converted === null) return null;
      base = converted;
    }
  }

  const result = applyAdjustment(
    base,
    article.manualAdjustmentKind,
    article.manualAdjustmentType,
    article.manualAdjustmentValue
  );

  steps.push({
    key: "MULTIPLIER",
    label: "Modo multiplicador",
    status: "ok",
    value: result,
    meta: {
      qty: article.multiplierQuantity?.toString(),
      value: article.multiplierValue?.toString(),
      base: article.multiplierBase,
    },
  });

  return result;
}

// ---------------------------------------------------------------------------
// modoMetalMermaHechura — METAL_MERMA_HECHURA
// FIX 2: hechura PER_GRAM usa gramos CON merma
// ---------------------------------------------------------------------------

async function modoMetalMermaHechura(
  jewelryId: string,
  article: ArticleCostInput,
  steps: PricingStep[]
): Promise<{ value: Prisma.Decimal | null; metalCost: Prisma.Decimal; hechuraCost: Prisma.Decimal; totalGrams: Prisma.Decimal; partial: boolean }> {
  const compositions = article.compositions ?? [];
  if (compositions.length === 0) {
    steps.push({
      key: "METAL_MERMA_HECHURA",
      label: "Composición metálica",
      status: "missing",
      value: null,
      message: "No hay composiciones metálicas configuradas",
    });
    return { value: null, metalCost: new Prisma.Decimal(0), hechuraCost: new Prisma.Decimal(0), totalGrams: new Prisma.Decimal(0), partial: true };
  }

  const baseCurrencyId = await getBaseCurrencyId(jewelryId);
  if (!baseCurrencyId) {
    steps.push({
      key: "METAL_MERMA_BASE_CURRENCY",
      label: "Moneda base del tenant",
      status: "missing",
      value: null,
      message: "No se encontró moneda base configurada",
    });
    return { value: null, metalCost: new Prisma.Decimal(0), hechuraCost: new Prisma.Decimal(0), totalGrams: new Prisma.Decimal(0), partial: true };
  }

  // Merma efectiva: artículo → categoría → jewelry → 0
  const jewelry = await prisma.jewelry.findUnique({
    where: { id: jewelryId },
    select: { defaultMermaPercent: true },
  });
  const rawMerma =
    article.mermaPercent ??
    article.category?.mermaPercent ??
    jewelry?.defaultMermaPercent ??
    0;
  const mermaFactor = new Prisma.Decimal(1).add(
    new Prisma.Decimal(rawMerma.toString()).div(100)
  );

  let metalCost = new Prisma.Decimal(0);
  let totalBaseGrams = new Prisma.Decimal(0);
  let totalGramsWithMerma = new Prisma.Decimal(0);
  let hasAllPrices = true;

  for (const comp of compositions) {
    const quote = await prisma.metalQuote.findFirst({
      where: { variantId: comp.variantId, currencyId: baseCurrencyId },
      orderBy: { effectiveAt: "desc" },
      select: { price: true },
    });
    if (!quote) {
      hasAllPrices = false;
      steps.push({
        key: "METAL_QUOTE",
        label: "Cotización de metal",
        status: "missing",
        value: null,
        message: `Sin cotización para variante ${comp.variantId}`,
        meta: { variantId: comp.variantId },
      });
      continue;
    }

    const grams = new Prisma.Decimal(comp.grams.toString());
    const gramsConMerma = grams.mul(mermaFactor);
    const lineCost = gramsConMerma.mul(new Prisma.Decimal(quote.price.toString()));
    metalCost = metalCost.add(lineCost);
    totalBaseGrams = totalBaseGrams.add(grams);
    totalGramsWithMerma = totalGramsWithMerma.add(gramsConMerma);

    steps.push({
      key: "METAL_QUOTE",
      label: "Cotización de metal",
      status: "ok",
      value: lineCost,
      meta: {
        variantId: comp.variantId,
        grams: grams.toString(),
        gramsConMerma: gramsConMerma.toString(),
        price: quote.price.toString(),
        merma: rawMerma,
      },
    });
  }

  // Hechura
  let hechura = new Prisma.Decimal(0);
  if (article.hechuraPrice != null) {
    const hp = new Prisma.Decimal(article.hechuraPrice.toString());
    if (article.hechuraPriceMode === "PER_GRAM") {
      // FIX 2: usar gramos CON merma (consistente con metalCost)
      hechura = hp.mul(totalGramsWithMerma);
    } else {
      hechura = hp;
    }
    steps.push({
      key: "HECHURA",
      label: "Hechura",
      status: "ok",
      value: hechura,
      meta: {
        mode: article.hechuraPriceMode,
        price: article.hechuraPrice?.toString(),
        gramsWithMerma: totalGramsWithMerma.toString(),
      },
    });
  }

  const base = metalCost.add(hechura);
  const result = applyAdjustment(
    base,
    article.manualAdjustmentKind,
    article.manualAdjustmentType,
    article.manualAdjustmentValue
  );

  steps.push({
    key: "METAL_MERMA_HECHURA_TOTAL",
    label: "Total metal + merma + hechura",
    status: hasAllPrices ? "ok" : "partial",
    value: result,
    meta: { metalCost: metalCost.toString(), hechura: hechura.toString(), merma: rawMerma },
  });

  return {
    value: result,
    metalCost,
    hechuraCost: hechura,
    totalGrams: totalBaseGrams,
    partial: !hasAllPrices,
  };
}

// ---------------------------------------------------------------------------
// resolveArticleCost — función principal del motor de costo
// ---------------------------------------------------------------------------

export async function resolveArticleCost(
  jewelryId: string,
  article: ArticleCostInput
): Promise<CostResult> {
  const steps: PricingStep[] = [];
  let base: CostResult;

  // ── COST_LINES (prioridad máxima) ─────────────────────────────────────────
  if (article.costComposition && article.costComposition.length > 0) {
    const linesResult = await modoCostLines(jewelryId, article.costComposition, steps);

    if (linesResult.value !== null) {
      const adjusted = applyAdjustment(
        linesResult.value,
        article.manualAdjustmentKind,
        article.manualAdjustmentType,
        article.manualAdjustmentValue
      );
      steps.push({
        key: "COST_LINES_FINAL",
        label: "Total líneas de costo (con ajuste)",
        status: linesResult.partial ? "partial" : "ok",
        value: adjusted,
        meta: {
          adjustmentKind:  article.manualAdjustmentKind  ?? null,
          adjustmentType:  article.manualAdjustmentType  ?? null,
          adjustmentValue: article.manualAdjustmentValue != null ? String(article.manualAdjustmentValue) : null,
          sumLines:        linesResult.value.toString(),
        },
      });
      // Distribuir el ajuste global proporcionalmente entre metal y hechura
      // para que costResult.hechuraCost siempre sea consistente con costResult.value.
      const adjFactor = linesResult.value.gt(0)
        ? adjusted.div(linesResult.value)
        : new Prisma.Decimal(1);
      base = {
        value: adjusted,
        mode: "COST_LINES",
        partial: linesResult.partial,
        steps,
        metalCost:   linesResult.metalCost.mul(adjFactor),
        hechuraCost: linesResult.hechuraCost.mul(adjFactor),
        totalGrams: linesResult.totalGrams,
      };
    } else {
      // FIX 1: COST_LINES falló → cae a MANUAL si hay datos disponibles
      steps.push({
        key: "COST_LINES_FALLBACK",
        label: "COST_LINES sin datos → intenta MANUAL",
        status: "skipped",
        value: null,
        message: "Sin cotizaciones o moneda base; se intenta modo MANUAL",
      });

      if (article.manualBaseCost != null || article.costPrice != null) {
        const manualVal = await modoManual(jewelryId, article, steps);
        base = {
          value: manualVal,
          mode: "COST_LINES→MANUAL",
          partial: manualVal === null,
          steps,
        };
      } else {
        base = { value: null, mode: "COST_LINES", partial: true, steps };
      }
    }
  } else {
    const mode = article.costCalculationMode ?? "MANUAL";

    // ── MANUAL ────────────────────────────────────────────────────────────────
    if (mode === "MANUAL") {
      const val = await modoManual(jewelryId, article, steps);
      base = {
        value: val,
        mode: "MANUAL",
        partial: val === null,
        steps,
      };

    // ── MULTIPLIER ────────────────────────────────────────────────────────────
    } else if (mode === "MULTIPLIER") {
      const val = await modoMultiplier(jewelryId, article, steps);
      base = {
        value: val,
        mode: "MULTIPLIER",
        partial: val === null,
        steps,
      };

    // ── METAL_MERMA_HECHURA ───────────────────────────────────────────────────
    } else if (mode === "METAL_MERMA_HECHURA") {
      const result = await modoMetalMermaHechura(jewelryId, article, steps);
      base = {
        value: result.value,
        mode: "METAL_MERMA_HECHURA",
        partial: result.partial || result.value === null,
        steps,
        metalCost: result.metalCost,
        hechuraCost: result.hechuraCost,
        totalGrams: result.totalGrams,
      };

    } else {
      steps.push({
        key: "UNKNOWN_MODE",
        label: "Modo de cálculo",
        status: "missing",
        value: null,
        message: `Modo desconocido: ${mode}`,
      });
      base = { value: null, mode, partial: false, steps };
    }
  }

  // ── Adjuntar breakdown Metal/Hechura cuando hay valor ─────────────────────
  if (base.value !== null) {
    const breakdown = await buildPriceBreakdown(article, base);
    return { ...base, breakdown };
  }
  return base;
}

// ---------------------------------------------------------------------------
// buildPriceBreakdown — construye el desglose Metal/Hechura desde CostResult
// ---------------------------------------------------------------------------

export async function buildPriceBreakdown(
  article: ArticleCostInput,
  costResult: CostResult
): Promise<PriceBreakdown | null> {
  if (costResult.value === null) return null;

  const unified   = parseFloat(costResult.value.toString());
  const metalTotal = costResult.metalCost  ? parseFloat(costResult.metalCost.toString())  : 0;
  const hechuraBase = costResult.hechuraCost ? parseFloat(costResult.hechuraCost.toString()) : 0;

  // ── Metal items desde steps ──────────────────────────────────────────────
  const metalItems: PriceBreakdownMetalItem[] = [];
  const variantIds: string[] = [];

  for (const step of costResult.steps) {
    if (step.status !== "ok" || step.value == null) continue;
    const m = step.meta ?? {};
    if (step.key === "COST_LINES_METAL") {
      const vid = (m.variantId as string | null) ?? null;
      if (vid) variantIds.push(vid);
      metalItems.push({
        variantId:    vid,
        gramsOriginal: m.qty   ? parseFloat(String(m.qty))        : null,
        unitValue:    m.quotePrice ? parseFloat(String(m.quotePrice)) : null,
        totalValue:   parseFloat(step.value.toString()),
      });
    } else if (step.key === "METAL_QUOTE") {
      const vid = (m.variantId as string | null) ?? null;
      if (vid) variantIds.push(vid);
      metalItems.push({
        variantId:    vid,
        gramsOriginal: m.grams ? parseFloat(String(m.grams)) : null,
        unitValue:    m.price  ? parseFloat(String(m.price)) : null,
        totalValue:   parseFloat(step.value.toString()),
      });
    }
  }

  // Enriquecer con pureza, metalId, variantName y metalName desde MetalVariant (batch)
  if (variantIds.length > 0) {
    const variantMap = new Map<string, { purity: number | null; metalId: string; variantName: string; metalName: string | null; metalSymbol: string | null }>();
    const variantRows = await prisma.metalVariant.findMany({
      where: { id: { in: variantIds } },
      select: { id: true, name: true, purity: true, metalId: true, metal: { select: { id: true, name: true, symbol: true } } },
    });
    for (const row of variantRows) {
      variantMap.set(row.id, {
        purity:       row.purity != null ? parseFloat(row.purity.toString()) : null,
        metalId:      row.metalId,
        variantName:  row.name,
        metalName:    (row as any).metal?.name   ?? null,
        metalSymbol:  (row as any).metal?.symbol ?? null,
      });
    }
    for (const item of metalItems) {
      if (!item.variantId) continue;
      const v = variantMap.get(item.variantId);
      if (!v) continue;
      item.metalId = v.metalId;
      if (v.purity != null) {
        item.purity = v.purity;
        item.gramsPure = item.gramsOriginal != null ? parseFloat((item.gramsOriginal * v.purity).toFixed(6)) : null;
        item.gramsFineEquivalent = item.gramsPure;
      }
    }
    // Enriquecer steps de metal con purity, gramsOriginal, gramsFineEquivalent, metalId, variantName, metalName
    for (const step of costResult.steps) {
      if ((step.key !== "COST_LINES_METAL" && step.key !== "METAL_QUOTE") || !step.meta) continue;
      const vId = String(step.meta.variantId ?? "");
      const v = variantMap.get(vId);
      if (!v) continue;
      const gramsOriginal: number | null = step.key === "METAL_QUOTE"
        ? (step.meta.grams != null ? parseFloat(String(step.meta.grams)) : null)
        : (step.meta.qty   != null ? parseFloat(String(step.meta.qty))   : null);
      const gramsFineEquivalent: number | null =
        gramsOriginal != null && v.purity != null
          ? parseFloat((gramsOriginal * v.purity).toFixed(6))
          : null;
      step.meta = {
        ...step.meta,
        ...(v.metalId                   && { metalId: v.metalId }),
        ...(v.variantName               && { variantName: v.variantName }),
        ...(v.metalName                 && { metalName: v.metalName }),
        ...(v.metalSymbol               && { metalSymbol: v.metalSymbol }),
        ...(v.purity             != null && { purity: v.purity }),
        ...(gramsOriginal        != null && { gramsOriginal }),
        ...(gramsFineEquivalent  != null && { gramsFineEquivalent }),
      };
    }
  }

  // ── Hechura adjustments (bonificación / recargo aplicado al total) ────────
  const adjustments: PriceBreakdownAdjustment[] = [];
  const adjKind = article.manualAdjustmentKind;
  if (adjKind && adjKind !== "") {
    // El ajuste impacta en la diferencia entre (metal + hechuraBase) y el total
    const baseBeforeAdj = metalTotal + hechuraBase;
    const adjAmount = unified - baseBeforeAdj;
    if (Math.abs(adjAmount) > 0.001) {
      adjustments.push({
        type:   adjKind === "BONUS" ? "BONUS" : "SURCHARGE",
        label:  adjKind === "BONUS" ? "Bonificación" : "Recargo",
        amount: adjAmount,
      });
    }
  }

  // ── Para modo MANUAL: extraer base y ajuste desde steps ──────────────────
  if (metalTotal === 0 && metalItems.length === 0) {
    // Todo es hechura; si hay ajuste, base es el valor antes del ajuste
    const baseCostStep = costResult.steps.find(
      s => s.key === "MANUAL_BASE_COST" && s.status === "ok" && s.value != null
    );
    if (baseCostStep?.meta?.manualBaseCost != null && adjustments.length === 0) {
      const rawBase = parseFloat(String(baseCostStep.meta.manualBaseCost));
      const adjAmt  = unified - rawBase;
      if (Math.abs(adjAmt) > 0.001) {
        adjustments.push({
          type:   adjAmt < 0 ? "BONUS" : "SURCHARGE",
          label:  adjAmt < 0 ? "Bonificación" : "Recargo",
          amount: adjAmt,
        });
      }
    }
  }

  const hechuraTotal = unified - metalTotal;

  return {
    mode: costResult.mode,
    metal: {
      items: metalItems,
      total: metalTotal,
    },
    hechura: {
      base: hechuraBase > 0 ? hechuraBase : (metalTotal === 0 ? unified : hechuraTotal),
      adjustments,
      total: hechuraTotal,
    },
    totals: {
      metal:   metalTotal,
      hechura: hechuraTotal,
      unified,
    },
  };
}
