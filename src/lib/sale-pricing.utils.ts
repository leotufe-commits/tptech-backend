// src/lib/sale-pricing.utils.ts
// Motor de resolución de precio de venta en contexto de venta (POS / cotización).
//
// Flujo:
//   BASE → QUANTITY_DISCOUNT → PROMOTION → COSTO_REAL → MARGEN
//
// Precio base (en orden):
//   1. variant.priceOverride    — override explícito de variante
//   2. Lista de precios         — resolvePriceList + applyPriceList
//   3. MANUAL_OVERRIDE          — Article.useManualSalePrice=true && salePrice != null
//   4. MANUAL_FALLBACK          — Article.salePrice (sin lista ni override)
//
// Descuento por cantidad:
//   Se aplica SIEMPRE sobre el precio base, sin importar de dónde viene.
//
// Promoción:
//   Se aplica SIEMPRE al final (sobre precio base ± descuento por cantidad).
//
// Costo real y margen:
//   Se calcula con computeCostPrice() del motor oficial (article-cost.utils.ts).
//   No hay estimaciones simplificadas: si no hay datos suficientes → costPartial: true.

import { Prisma } from "@prisma/client";
import { prisma } from "./prisma.js";
import { resolvePriceList, applyPriceList } from "./pricing.utils.js";
import type { CostBreakdown } from "./pricing.utils.js";
import { computeCostPrice } from "./article-cost.utils.js";

// ---------------------------------------------------------------------------
// Tipos
// ---------------------------------------------------------------------------

/** Fuente del precio BASE (qué determinó el precio antes de descuentos). */
export type BasePriceSource =
  | "VARIANT_OVERRIDE"  // variant.priceOverride
  | "PRICE_LIST"        // lista de precios
  | "MANUAL_OVERRIDE"   // article.useManualSalePrice=true && salePrice
  | "MANUAL_FALLBACK"   // article.salePrice sin override ni lista
  | "NONE";

/**
 * Fuente efectiva del precio final (backward-compat con SaleLine.priceSource).
 * Refleja la última capa que modificó el precio.
 */
export type SalePriceSource =
  | "VARIANT_OVERRIDE"
  | "PRICE_LIST"
  | "MANUAL_OVERRIDE"
  | "MANUAL_FALLBACK"
  | "QUANTITY_DISCOUNT"  // qty discount aplicado (sin promo)
  | "PROMOTION"          // promoción aplicada (siempre la última)
  | "NONE";

export type SalePriceResult = {
  /** Precio final (después de todos los descuentos). */
  unitPrice: string | null;
  /** Precio base, antes de descuentos por cantidad y promoción. */
  basePrice: string | null;
  /** Descuento por cantidad (null si no aplica). */
  quantityDiscountAmount: string | null;
  /** Descuento por promoción (null si no aplica). */
  promotionDiscountAmount: string | null;
  /** Total descontado (qty + promo). */
  discountAmount: string | null;

  /**
   * Fuente efectiva final — la última capa que modificó el precio.
   * Usado en SaleLine.priceSource para retrocompatibilidad.
   */
  priceSource: SalePriceSource;
  /** Fuente del precio BASE (antes de descuentos). */
  baseSource: BasePriceSource;

  appliedPriceListId: string | null;
  appliedPriceListName: string | null;
  appliedPromotionId: string | null;
  appliedPromotionName: string | null;
  appliedDiscountId: string | null;
  /** true si el precio base es parcial (e.g. lista sin datos de costo suficientes). */
  partial: boolean;

  /** Costo unitario real calculado con el motor oficial. Null si no disponible. */
  unitCost: string | null;
  /** Margen unitario = unitPrice − unitCost. Null si sin costo. */
  unitMargin: string | null;
  /** Margen % sobre el precio de venta final. Null si sin costo. */
  marginPercent: string | null;
  /** true cuando el costo no pudo resolverse completamente (faltan cotizaciones, etc.). */
  costPartial: boolean;
  /** Modo de cálculo de costo: MANUAL | MULTIPLIER | METAL_MERMA_HECHURA | COST_LINES | NONE */
  costMode: string;
};

type SalePriceOpts = {
  articleId:   string;
  variantId?:  string | null;
  clientId?:   string | null;
  categoryId?: string | null;  // si no se envía, se resuelve desde el artículo
  quantity?:   number | string;
};

// ---------------------------------------------------------------------------
// Helpers internos
// ---------------------------------------------------------------------------

function isPromotionValid(p: {
  validFrom: Date | null;
  validTo:   Date | null;
  isActive:  boolean;
  deletedAt: Date | null;
}): boolean {
  if (!p.isActive || p.deletedAt) return false;
  const now = new Date();
  if (p.validFrom && p.validFrom > now) return false;
  if (p.validTo   && p.validTo   < now) return false;
  return true;
}

function applyDiscount(
  base: Prisma.Decimal,
  type: string,
  value: Prisma.Decimal
): { final: Prisma.Decimal; discountAmount: Prisma.Decimal } {
  const D = Prisma.Decimal;
  let discountAmount: Prisma.Decimal;

  if (type === "PERCENTAGE") {
    discountAmount = base.mul(value).div(100);
  } else {
    // FIXED — nunca descuenta más que el precio base
    discountAmount = D.min(value, base);
  }

  const final = base.sub(discountAmount);
  return {
    final: final.lessThan(0) ? new D(0) : final,
    discountAmount,
  };
}

function noPrice(): SalePriceResult {
  return {
    unitPrice:               null,
    basePrice:               null,
    quantityDiscountAmount:  null,
    promotionDiscountAmount: null,
    discountAmount:          null,
    priceSource:             "NONE",
    baseSource:              "NONE",
    appliedPriceListId:      null,
    appliedPriceListName:    null,
    appliedPromotionId:      null,
    appliedPromotionName:    null,
    appliedDiscountId:       null,
    partial:                 true,
    unitCost:                null,
    unitMargin:              null,
    marginPercent:           null,
    costPartial:             true,
    costMode:                "NONE",
  };
}

// ---------------------------------------------------------------------------
// resolveQuantityDiscount — mejor tier para la cantidad dada
// ---------------------------------------------------------------------------
async function resolveQuantityDiscount(
  jewelryId: string,
  articleId: string,
  variantId: string | null,
  quantity: Prisma.Decimal,
  categoryId?: string | null,
  brand?: string | null,
) {
  const rules = await prisma.quantityDiscount.findMany({
    where: {
      jewelryId,
      isActive: true,
      deletedAt: null,
      OR: [
        { variantId: variantId ?? null, articleId },
        { variantId: null, articleId },
        ...(categoryId ? [{ categoryId, articleId: null }] : []),
        ...(brand ? [{ brand, articleId: null }] : []),
        { articleId: null, categoryId: null, brand: null },
      ],
    },
    select: {
      id: true,
      articleId: true,
      variantId: true,
      categoryId: true,
      brand: true,
      tiers: {
        select: { minQty: true, type: true, value: true },
        orderBy: { minQty: "desc" },
      },
    },
  });

  // Specificity priority: variant > article > category > brand > global
  function scopePriority(r: typeof rules[0]): number {
    if (r.variantId)  return 0;
    if (r.articleId)  return 1;
    if (r.categoryId) return 2;
    if (r.brand)      return 3;
    return 4;
  }

  const sorted = [...rules].sort((a, b) => scopePriority(a) - scopePriority(b));

  for (const rule of sorted) {
    const tier = rule.tiers.find((t) =>
      new Prisma.Decimal(t.minQty.toString()).lte(quantity)
    );
    if (tier) {
      return { id: rule.id, type: tier.type, value: tier.value };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// resolveSalePrice — motor principal
// ---------------------------------------------------------------------------
export async function resolveSalePrice(
  jewelryId: string,
  opts: SalePriceOpts
): Promise<SalePriceResult> {
  const D = Prisma.Decimal;
  const qty = new D(String(opts.quantity ?? 1));

  // ── Cargar artículo con todos los campos necesarios (precio + costo) ──────
  const article = await prisma.article.findFirst({
    where: { id: opts.articleId, jewelryId, deletedAt: null },
    select: {
      // Precio
      categoryId:          true,
      brand:               true,
      salePrice:           true,
      useManualSalePrice:  true,
      // Costo — todos los campos para computeCostPrice()
      costCalculationMode:   true,
      costPrice:             true,
      manualCurrencyId:      true,
      manualBaseCost:        true,
      manualAdjustmentKind:  true,
      manualAdjustmentType:  true,
      manualAdjustmentValue: true,
      multiplierBase:        true,
      multiplierValue:       true,
      multiplierQuantity:    true,
      hechuraPrice:          true,
      hechuraPriceMode:      true,
      mermaPercent:          true,
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
      compositions: { select: { variantId: true, grams: true, isBase: true } },
    },
  });

  if (!article) return noPrice();

  // ── Cargar variante (si aplica) ────────────────────────────────────────
  let variantPriceOverride: Prisma.Decimal | null = null;
  if (opts.variantId) {
    const variant = await prisma.articleVariant.findFirst({
      where: { id: opts.variantId, articleId: opts.articleId, deletedAt: null },
      select: { priceOverride: true },
    });
    if (variant?.priceOverride != null) {
      variantPriceOverride = new D(variant.priceOverride.toString());
    }
  }

  const categoryId = opts.categoryId ?? article.categoryId ?? undefined;

  // ── Cargar promoción activa (se usará al final) ────────────────────────
  // Precedencia: variante exacta > artículo > categoría > marca > todos (scope=ALL)
  const promotionCandidates = await prisma.promotion.findMany({
    where: {
      jewelryId,
      isActive: true,
      deletedAt: null,
      OR: [
        // Scope ALL — aplica a todos los artículos
        { scope: "ALL" },
        // Scope ARTICLE — tiene una entrada junction para este artículo
        { scope: "ARTICLE", articles: { some: { articleId: opts.articleId } } },
        // Scope VARIANT — tiene una entrada junction para esta variante
        ...(opts.variantId
          ? [{ scope: "VARIANT" as const, variants: { some: { variantId: opts.variantId } } }]
          : []),
        // Scope CATEGORY — tiene una entrada junction para la categoría del artículo
        ...(article.categoryId
          ? [{ scope: "CATEGORY" as const, categories: { some: { categoryId: article.categoryId } } }]
          : []),
        // Scope BRAND — tiene una entrada junction para la marca del artículo
        ...(article.brand
          ? [{ scope: "BRAND" as const, brands: { some: { brand: article.brand } } }]
          : []),
      ],
    },
    select: {
      id: true, name: true, type: true, value: true,
      scope: true,
      validFrom: true, validTo: true, isActive: true, deletedAt: true,
      priority: true,
    },
    orderBy: [{ priority: "asc" }, { createdAt: "asc" } as any],
  });
  const activePromo = promotionCandidates.find(isPromotionValid) ?? null;

  // ── Pre-calcular costo real (necesario para listas de precios y margen) ─
  const costResult = await computeCostPrice(jewelryId, article as any);

  // Si computeCostPrice no devolvió totalGrams (MANUAL/MULTIPLIER) pero el artículo
  // tiene composiciones, inyectarlo para que COST_PER_GRAM price lists funcionen.
  if (
    (costResult as any).totalGrams == null &&
    article.compositions &&
    article.compositions.length > 0
  ) {
    (costResult as any).totalGrams = article.compositions.reduce(
      (acc, c) => acc.add(new D(c.grams.toString())),
      new D(0)
    );
  }

  // ── PASO 1: Resolver precio base ───────────────────────────────────────
  let basePrice:  Prisma.Decimal | null = null;
  let baseSource: BasePriceSource = "NONE";
  let appliedPriceListId:   string | null = null;
  let appliedPriceListName: string | null = null;
  let partial = false;

  // 1a. variant.priceOverride (mayor prioridad)
  if (variantPriceOverride != null) {
    basePrice  = variantPriceOverride;
    baseSource = "VARIANT_OVERRIDE";
  }

  // 1b. Lista de precios
  if (basePrice == null) {
    const resolved = await resolvePriceList(jewelryId, { clientId: opts.clientId, categoryId });
    if (resolved) {
      const priceResult = applyPriceList(resolved.priceList, costResult);
      if (priceResult.value != null) {
        basePrice            = priceResult.value;
        baseSource           = "PRICE_LIST";
        appliedPriceListId   = resolved.priceList.id;
        appliedPriceListName = resolved.priceList.name;
        partial              = priceResult.partial;
      }
    }
  }

  // 1c. Manual override (useManualSalePrice=true)
  if (basePrice == null && article.useManualSalePrice && article.salePrice != null) {
    basePrice  = new D(article.salePrice.toString());
    baseSource = "MANUAL_OVERRIDE";
  }

  // 1d. Fallback: salePrice manual
  if (basePrice == null && article.salePrice != null) {
    basePrice  = new D(article.salePrice.toString());
    baseSource = "MANUAL_FALLBACK";
  }

  if (basePrice == null) return noPrice();

  // ── PASO 2: Descuento por cantidad (sobre precio base) ─────────────────
  let priceAfterQty       = basePrice;
  let qtyDiscountAmount:  Prisma.Decimal | null = null;
  let appliedDiscountId:  string | null = null;

  const qtyDiscount = await resolveQuantityDiscount(
    jewelryId,
    opts.articleId,
    opts.variantId ?? null,
    qty,
    article.categoryId,
    article.brand,
  );

  if (qtyDiscount) {
    const { final, discountAmount } = applyDiscount(
      basePrice,
      qtyDiscount.type,
      new D(qtyDiscount.value.toString())
    );
    priceAfterQty     = final;
    qtyDiscountAmount = discountAmount;
    appliedDiscountId = qtyDiscount.id;
  }

  // ── PASO 3: Promoción (siempre al final) ───────────────────────────────
  let finalPrice:          Prisma.Decimal = priceAfterQty;
  let promoDiscountAmount: Prisma.Decimal | null = null;
  let appliedPromotionId:  string | null = null;
  let appliedPromotionName: string | null = null;

  if (activePromo) {
    const { final, discountAmount } = applyDiscount(
      priceAfterQty,
      activePromo.type,
      new D(activePromo.value.toString())
    );
    finalPrice            = final;
    promoDiscountAmount   = discountAmount;
    appliedPromotionId    = activePromo.id;
    appliedPromotionName  = activePromo.name;
  }

  // ── Calcular descuento total ───────────────────────────────────────────
  const totalDiscount = (qtyDiscountAmount ?? new D(0)).add(promoDiscountAmount ?? new D(0));
  const hasDiscount   = totalDiscount.greaterThan(0);

  // ── Determinar fuente efectiva final (para SaleLine.priceSource) ───────
  let priceSource: SalePriceSource;
  if (activePromo && appliedPromotionId) {
    priceSource = "PROMOTION";
  } else if (qtyDiscount && appliedDiscountId) {
    priceSource = "QUANTITY_DISCOUNT";
  } else {
    priceSource = baseSource as SalePriceSource;
  }

  // ── PASO 4: Margen con costo ya calculado ─────────────────────────────
  let unitCost:     string | null = null;
  let unitMargin:   string | null = null;
  let marginPercent: string | null = null;
  const costPartial = costResult.partial;
  const costMode    = costResult.mode;

  if (costResult.value != null) {
    const cost   = costResult.value;
    const margin = finalPrice.sub(cost);
    unitCost      = cost.toFixed(4);
    unitMargin    = margin.toFixed(4);
    marginPercent = finalPrice.gt(0)
      ? margin.div(finalPrice).mul(100).toFixed(4)
      : new D(0).toFixed(4);
  }

  return {
    unitPrice:               finalPrice.toFixed(4),
    basePrice:               basePrice.toFixed(4),
    quantityDiscountAmount:  qtyDiscountAmount   ? qtyDiscountAmount.toFixed(4)   : null,
    promotionDiscountAmount: promoDiscountAmount ? promoDiscountAmount.toFixed(4) : null,
    discountAmount:          hasDiscount ? totalDiscount.toFixed(4) : null,
    priceSource,
    baseSource,
    appliedPriceListId,
    appliedPriceListName,
    appliedPromotionId,
    appliedPromotionName,
    appliedDiscountId,
    partial,
    unitCost,
    unitMargin,
    marginPercent,
    costPartial,
    costMode,
  };
}
