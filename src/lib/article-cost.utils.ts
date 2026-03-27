// src/lib/article-cost.utils.ts
// Cálculo oficial de costo de artículo.
// Reutilizable desde pricing (POS), ventas (confirm snapshot) y artículos (detalle).
//
// Modes (en orden de prioridad):
//   COST_LINES          → ArticleCostLine (nueva arquitectura)
//   MANUAL              → costPrice almacenado directamente
//   MULTIPLIER          → multiplierQuantity × multiplierValue
//   METAL_MERMA_HECHURA → composiciones metálicas + merma + hechura

import { Prisma } from "@prisma/client";
import { prisma } from "./prisma.js";
import type { CostBreakdown } from "./pricing.utils.js";

// ---------------------------------------------------------------------------
// Tipos públicos
// ---------------------------------------------------------------------------

export type ArticleCostInput = {
  costCalculationMode:    string;
  costPrice:              any;
  manualCurrencyId?:      string | null;
  manualBaseCost?:        any;
  manualAdjustmentKind?:  string | null;
  manualAdjustmentType?:  string | null;
  manualAdjustmentValue?: any;
  multiplierBase:          string | null;
  multiplierValue:         any;
  multiplierQuantity:      any;
  multiplierCurrencyId?:   string | null;
  hechuraPrice:           any;
  hechuraPriceMode:       string;
  mermaPercent:           any;
  compositions?: Array<{ variantId: string; grams: any; isBase: boolean }>;
  category?:     { mermaPercent?: any } | null;
  costComposition?: Array<{
    type:           string;
    quantity:       any;
    unitValue:      any;
    currencyId:     string | null;
    mermaPercent:   any;
    metalVariantId: string | null;
  }>;
};

export type CostResult = CostBreakdown & { mode: string; partial: boolean };

/**
 * Prisma select shape que garantiza todos los campos necesarios para computeCostPrice().
 * Usar en cualquier query que luego llame a computeCostPrice().
 */
export const ARTICLE_COST_SELECT = {
  costCalculationMode:    true,
  costPrice:              true,
  manualCurrencyId:       true,
  manualBaseCost:         true,
  manualAdjustmentKind:   true,
  manualAdjustmentType:   true,
  manualAdjustmentValue:  true,
  multiplierBase:          true,
  multiplierValue:         true,
  multiplierQuantity:      true,
  multiplierCurrencyId:    true,
  hechuraPrice:        true,
  hechuraPriceMode:    true,
  mermaPercent:        true,
  category:        { select: { mermaPercent: true } },
  costComposition: {
    select: {
      type:           true,
      quantity:       true,
      unitValue:      true,
      currencyId:     true,
      mermaPercent:   true,
      metalVariantId: true,
    },
  },
  compositions: {
    select: { variantId: true, grams: true, isBase: true },
  },
} as const;

// ---------------------------------------------------------------------------
// applyAdjustment — aplica bonus/recargo sobre un valor base
// ---------------------------------------------------------------------------

/**
 * Aplica el ajuste (bonus o recargo) de los campos manualAdjustment* sobre `base`.
 * Se usa en todos los modos de cálculo para garantizar comportamiento uniforme:
 *   costo_final = base + ajuste  (luego applyTaxes se encarga de los impuestos)
 */
function applyAdjustment(
  base:    Prisma.Decimal,
  kind?:   string | null,
  adjType?: string | null,
  adjRaw?:  any,
): Prisma.Decimal {
  if (!kind || kind === "" || adjRaw == null) return base;
  const absVal    = new Prisma.Decimal(Math.abs(Number(adjRaw)).toString());
  const adjAmount = adjType === "PERCENTAGE" ? base.mul(absVal.div(100)) : absVal;
  return kind === "SURCHARGE" ? base.add(adjAmount) : base.sub(adjAmount);
}

// ---------------------------------------------------------------------------
// computeCostFromLines — modo COST_LINES (nueva arquitectura)
// ---------------------------------------------------------------------------

async function computeCostFromLines(
  jewelryId: string,
  lines: Array<{
    type:           string;
    quantity:       any;
    unitValue:      any;
    currencyId:     string | null;
    mermaPercent:   any;
    metalVariantId: string | null;
  }>
): Promise<CostResult> {
  const mode = "COST_LINES";

  const baseCurrency = await prisma.currency.findFirst({
    where: { jewelryId, isBase: true, deletedAt: null },
    select: { id: true },
  });
  if (!baseCurrency) return { value: null, mode, partial: true };

  let total        = new Prisma.Decimal(0);
  let metalTotal   = new Prisma.Decimal(0);
  let hechuraTotal = new Prisma.Decimal(0);
  let gramsTotal   = new Prisma.Decimal(0);
  let hasAllPrices = true;

  for (const line of lines) {
    const qty = new Prisma.Decimal(line.quantity?.toString() ?? "0");

    if (line.type === "METAL") {
      if (!line.metalVariantId) { hasAllPrices = false; continue; }
      const quote = await prisma.metalQuote.findFirst({
        where: { variantId: line.metalVariantId, currencyId: baseCurrency.id },
        orderBy: { effectiveAt: "desc" },
        select: { price: true },
      });
      if (!quote) { hasAllPrices = false; continue; }
      const mermaFactor = new Prisma.Decimal(1).add(
        new Prisma.Decimal(line.mermaPercent?.toString() ?? "0").div(100)
      );
      const lineCost = qty.mul(mermaFactor).mul(new Prisma.Decimal(quote.price.toString()));
      total      = total.add(lineCost);
      metalTotal = metalTotal.add(lineCost);
      gramsTotal = gramsTotal.add(qty);
    } else {
      const unitVal  = new Prisma.Decimal(line.unitValue?.toString() ?? "0");
      let lineValue  = qty.mul(unitVal);

      if (line.currencyId && line.currencyId !== baseCurrency.id) {
        const rate = await prisma.currencyRate.findFirst({
          where: { currencyId: line.currencyId },
          orderBy: { createdAt: "desc" },
          select: { rate: true },
        });
        if (!rate) { hasAllPrices = false; continue; }
        lineValue = lineValue.mul(new Prisma.Decimal(rate.rate.toString()));
      }
      total = total.add(lineValue);
      if (line.type === "HECHURA") hechuraTotal = hechuraTotal.add(lineValue);
    }
  }

  return {
    value:       total,
    mode,
    partial:     !hasAllPrices,
    metalCost:   metalTotal,
    hechuraCost: hechuraTotal,
    totalGrams:  gramsTotal,
  };
}

// ---------------------------------------------------------------------------
// computeCostPrice — función oficial de costo (exportada)
// ---------------------------------------------------------------------------

export async function computeCostPrice(
  jewelryId: string,
  article: ArticleCostInput
): Promise<CostResult> {
  // ── COST_LINES: nueva arquitectura (tiene precedencia sobre costCalculationMode) ─
  if (article.costComposition && article.costComposition.length > 0) {
    const linesResult = await computeCostFromLines(jewelryId, article.costComposition);
    if (linesResult.value == null) return linesResult;
    return {
      ...linesResult,
      value: applyAdjustment(
        linesResult.value,
        article.manualAdjustmentKind,
        article.manualAdjustmentType,
        article.manualAdjustmentValue,
      ),
    };
  }

  const mode = article.costCalculationMode ?? "MANUAL";

  // ── MANUAL ────────────────────────────────────────────────────────────────
  if (mode === "MANUAL") {
    let val: Prisma.Decimal | null = null;

    if (article.manualBaseCost != null) {
      // Fuente primaria: reconstruir desde manualBaseCost + ajuste.
      // Mismo criterio que computeManualFinalCost() en el frontend.
      val = new Prisma.Decimal(article.manualBaseCost.toString());
      const kind    = article.manualAdjustmentKind  ?? "";
      const adjType = article.manualAdjustmentType  ?? "";
      const adjRaw  = article.manualAdjustmentValue;
      if (kind !== "" && adjRaw != null) {
        const absVal    = new Prisma.Decimal(Math.abs(Number(adjRaw)).toString());
        const adjAmount = adjType === "PERCENTAGE"
          ? val.mul(absVal.div(100))
          : absVal;
        val = kind === "SURCHARGE"
          ? val.add(adjAmount)
          : val.sub(adjAmount);
      }
    } else if (article.costPrice != null) {
      // Fallback: artículos legacy que solo tienen costPrice almacenado.
      // El ajuste ya está incluido en costPrice (guardado por el frontend).
      val = new Prisma.Decimal(article.costPrice.toString());
    } else {
      return { value: null, mode, partial: true };
    }

    // Convertir a moneda base si el costo fue ingresado en moneda extranjera.
    // Mismo criterio que batchComputeCosts() en articles.service.ts.
    if (article.manualCurrencyId) {
      const baseCurrency = await prisma.currency.findFirst({
        where: { jewelryId, isBase: true, deletedAt: null },
        select: { id: true },
      });
      if (baseCurrency && article.manualCurrencyId !== baseCurrency.id) {
        const rate = await prisma.currencyRate.findFirst({
          where: { currencyId: article.manualCurrencyId },
          orderBy: { createdAt: "desc" },
          select: { rate: true },
        });
        if (!rate) return { value: null, mode, partial: true };
        val = val.mul(new Prisma.Decimal(rate.rate.toString()));
      }
    }

    return { value: val, mode, partial: false };
  }

  // ── MULTIPLIER ────────────────────────────────────────────────────────────
  if (mode === "MULTIPLIER") {
    if (article.multiplierValue == null || article.multiplierQuantity == null) {
      return { value: null, mode, partial: true };
    }
    let base = new Prisma.Decimal(article.multiplierQuantity.toString())
      .mul(new Prisma.Decimal(article.multiplierValue.toString()));

    // Convertir a moneda base si el valor fue ingresado en moneda extranjera.
    if (article.multiplierCurrencyId) {
      const baseCurrency = await prisma.currency.findFirst({
        where: { jewelryId, isBase: true, deletedAt: null },
        select: { id: true },
      });
      if (baseCurrency && article.multiplierCurrencyId !== baseCurrency.id) {
        const rate = await prisma.currencyRate.findFirst({
          where: { currencyId: article.multiplierCurrencyId },
          orderBy: { createdAt: "desc" },
          select: { rate: true },
        });
        if (!rate) return { value: null, mode, partial: true };
        base = base.mul(new Prisma.Decimal(rate.rate.toString()));
      }
    }

    return {
      value: applyAdjustment(base, article.manualAdjustmentKind, article.manualAdjustmentType, article.manualAdjustmentValue),
      mode,
      partial: false,
    };
  }

  // ── METAL_MERMA_HECHURA ───────────────────────────────────────────────────
  if (mode === "METAL_MERMA_HECHURA") {
    const compositions = article.compositions ?? [];
    if (compositions.length === 0) {
      return { value: null, mode, partial: true };
    }

    const baseCurrency = await prisma.currency.findFirst({
      where: { jewelryId, isBase: true, deletedAt: null },
      select: { id: true },
    });
    if (!baseCurrency) return { value: null, mode, partial: true };

    // Merma efectiva: artículo → categoría → jewelry → 0
    const jewelry = await prisma.jewelry.findUnique({
      where: { id: jewelryId },
      select: { defaultMermaPercent: true },
    });
    const rawMerma = article.mermaPercent
      ?? article.category?.mermaPercent
      ?? jewelry?.defaultMermaPercent
      ?? 0;
    const mermaFactor = new Prisma.Decimal(1).add(
      new Prisma.Decimal(rawMerma.toString()).div(100)
    );

    let metalCost      = new Prisma.Decimal(0);
    let totalBaseGrams = new Prisma.Decimal(0);
    let hasAllPrices   = true;

    for (const comp of compositions) {
      const quote = await prisma.metalQuote.findFirst({
        where: { variantId: comp.variantId, currencyId: baseCurrency.id },
        orderBy: { effectiveAt: "desc" },
        select: { price: true },
      });
      if (!quote) { hasAllPrices = false; continue; }

      const grams        = new Prisma.Decimal(comp.grams.toString());
      const gramsConMerma = grams.mul(mermaFactor);
      metalCost           = metalCost.add(gramsConMerma.mul(new Prisma.Decimal(quote.price.toString())));
      totalBaseGrams      = totalBaseGrams.add(grams);
    }

    let hechura = new Prisma.Decimal(0);
    if (article.hechuraPrice != null) {
      const hp = new Prisma.Decimal(article.hechuraPrice.toString());
      hechura = article.hechuraPriceMode === "PER_GRAM"
        ? hp.mul(totalBaseGrams)   // sobre gramos originales (sin merma)
        : hp;
    }

    const base = metalCost.add(hechura);
    return {
      value: applyAdjustment(base, article.manualAdjustmentKind, article.manualAdjustmentType, article.manualAdjustmentValue),
      mode,
      partial:     !hasAllPrices,
      metalCost,
      hechuraCost: hechura,
      totalGrams:  totalBaseGrams,
    };
  }

  return { value: null, mode, partial: false };
}
