// src/lib/pricing-engine/pricing-engine.sale.ts
// Motor de resolución de precio de venta con trazabilidad por pasos.
//
// Flujo:
//   COSTO_REAL → BASE_PRICE → DESCUENTO_CANTIDAD → PROMOCION → MARGEN
//
// Precio base (en orden):
//   1. variant.priceOverride    — override explícito de variante
//   2. Lista de precios         — resolvePriceList + applyPriceList
//   3. MANUAL_OVERRIDE          — Article.useManualSalePrice=true && salePrice
//   4. MANUAL_FALLBACK          — Article.salePrice
//
// FIX 3: multiplierCurrencyId incluido en el select del artículo.

import { Prisma } from "@prisma/client";
import { prisma } from "../prisma.js";
import { resolvePriceList, resolvePriceListById, applyPriceList, applyRounding, type MetalHechuraDetail } from "../pricing.utils.js";
import { resolveArticleCost } from "./pricing-engine.cost.js";
import type {
  SalePriceResult,
  SalePriceOpts,
  PricingStep,
  PricingAlert,
  PricingPolicyResult,
  TaxBreakdownItem,
  PriceBreakdown,
} from "./pricing-engine.types.js";

// ---------------------------------------------------------------------------
// Política de precios — configuración y fallbacks
// ---------------------------------------------------------------------------

interface PricingPolicyConfig {
  lowMarginWarningPercent: number;
  lowMarginBlockPercent: number | null;
  blockLossSale: boolean;
  blockZeroOrNegativePrice: boolean;
  blockPartialData: boolean;
}

const PRICING_DEFAULTS: PricingPolicyConfig = {
  lowMarginWarningPercent:  15,
  lowMarginBlockPercent:    null,
  blockLossSale:            false,
  blockZeroOrNegativePrice: false,
  blockPartialData:         false,
};

function toNum(v: any): number | null {
  if (v == null) return null;
  const n = parseFloat(v.toString());
  return Number.isFinite(n) ? n : null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isPromotionValid(p: {
  validFrom: Date | null;
  validTo: Date | null;
  isActive: boolean;
  deletedAt: Date | null;
}): boolean {
  if (!p.isActive || p.deletedAt) return false;
  const now = new Date();
  if (p.validFrom && p.validFrom > now) return false;
  if (p.validTo && p.validTo < now) return false;
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
    discountAmount = D.min(value, base);
  }

  const final = base.sub(discountAmount);
  return {
    final: final.lessThan(0) ? new D(0) : final,
    discountAmount,
  };
}

// Resuelve la base sobre la que se aplica un descuento según applyOn.
// Devuelve { base, rest, estimated }:
//   base = componente sobre el que se calcula el descuento
//   rest = lo que queda intacto (para reconstruir el precio final)
//   estimated = true si se usó proporción de costo en vez de desglose exacto
function resolveDiscountBase(
  applyOn: string,
  basePrice: Prisma.Decimal,
  metalHechuraBreakdown: MetalHechuraDetail | null,
  costBreakdown: PriceBreakdown | null,
): { base: Prisma.Decimal; rest: Prisma.Decimal; estimated: boolean } {
  const D = Prisma.Decimal;
  const fp = parseFloat(basePrice.toString());

  let costMetal: number | null = null;
  let costHechura: number | null = null;
  let costTotal: number | null = null;
  if (costBreakdown) {
    costMetal   = (costBreakdown as any).metalCost   ?? null;
    costHechura = (costBreakdown as any).hechuraCost ?? null;
    costTotal   = (costBreakdown as any).totalCost   ?? null;
  }

  switch (applyOn) {
    case "METAL": {
      if (metalHechuraBreakdown) {
        const metal = new D(metalHechuraBreakdown.metalSale.toFixed(6));
        const rest  = new D(metalHechuraBreakdown.hechuraSale.toFixed(6));
        return { base: metal, rest, estimated: false };
      }
      if (costMetal != null && costTotal != null && costTotal > 0) {
        const metal = new D((fp * costMetal / costTotal).toFixed(6));
        return { base: metal, rest: basePrice.sub(metal), estimated: true };
      }
      return { base: basePrice, rest: new D(0), estimated: true };
    }
    case "HECHURA": {
      if (metalHechuraBreakdown) {
        const hechura = new D(metalHechuraBreakdown.hechuraSale.toFixed(6));
        const rest    = new D(metalHechuraBreakdown.metalSale.toFixed(6));
        return { base: hechura, rest, estimated: false };
      }
      if (costHechura != null && costTotal != null && costTotal > 0) {
        const hechura = new D((fp * costHechura / costTotal).toFixed(6));
        return { base: hechura, rest: basePrice.sub(hechura), estimated: true };
      }
      return { base: basePrice, rest: new D(0), estimated: true };
    }
    case "METAL_Y_HECHURA":
    case "TOTAL":
    default:
      return { base: basePrice, rest: new D(0), estimated: false };
  }
}

// Aplica un descuento respetando applyOn (base específica + componentes restantes).
function applyDiscountWithApplyOn(
  basePrice: Prisma.Decimal,
  type: string,
  value: Prisma.Decimal,
  applyOn: string,
  metalHechuraBreakdown: MetalHechuraDetail | null,
  costBreakdown: PriceBreakdown | null,
): { final: Prisma.Decimal; discountAmount: Prisma.Decimal; discountBase: number; discountBaseEstimated: boolean } {
  const { base, rest, estimated } = resolveDiscountBase(applyOn, basePrice, metalHechuraBreakdown, costBreakdown);
  const { final: discountedBase, discountAmount } = applyDiscount(base, type, value);
  const raw = discountedBase.add(rest);
  return {
    final:                raw.lessThan(0) ? new Prisma.Decimal(0) : raw,
    discountAmount,
    discountBase:         parseFloat(base.toString()),
    discountBaseEstimated: estimated,
  };
}

function noPrice(): Omit<SalePriceResult, "alerts" | "policy"> {
  return {
    unitPrice: null,
    basePrice: null,
    quantityDiscountAmount: null,
    promotionDiscountAmount: null,
    discountAmount: new Prisma.Decimal(0),
    priceSource: "NONE",
    baseSource: "NONE",
    taxAmount: new Prisma.Decimal(0),
    taxBreakdown: [],
    totalWithTax: null,
    unitCost: null,
    unitMargin: null,
    marginPercent: null,
    costPartial: true,
    costMode: "NONE",
    partial: true,
    appliedPriceListId: null,
    appliedPriceListName: null,
    appliedPromotionId: null,
    appliedPromotionName: null,
    appliedDiscountId: null,
    stackingMode: "NONE",
    taxExemptByEntity: false,
    steps: [],
  };
}

/** Completa un resultado parcial con alerts + policy calculadas. */
function finalize(
  base: Omit<SalePriceResult, "alerts" | "policy">,
  config: PricingPolicyConfig
): SalePriceResult {
  const alerts = buildAlerts(base, config.lowMarginWarningPercent);
  const policy = buildPolicy(alerts, base.unitPrice, base.marginPercent, config);
  return { ...base, alerts, policy };
}

// ---------------------------------------------------------------------------
// buildAlerts — genera alertas de negocio sobre el resultado del motor
// ---------------------------------------------------------------------------

function buildAlerts(
  result: Omit<SalePriceResult, "alerts" | "policy">,
  warningPercent: number
): PricingAlert[] {
  const alerts: PricingAlert[] = [];
  const D = Prisma.Decimal;

  // ZERO_OR_NEGATIVE_PRICE — precio final es cero o negativo
  if (result.unitPrice != null && result.unitPrice.lte(0)) {
    alerts.push({
      code: "ZERO_OR_NEGATIVE_PRICE",
      level: "error",
      message: "El precio de venta resultante es cero o negativo.",
    });
  }

  // LOSS_SALE — se vende por debajo del costo
  if (
    result.unitCost != null &&
    result.unitPrice != null &&
    result.unitPrice.gt(0) &&
    result.unitPrice.lte(result.unitCost)
  ) {
    alerts.push({
      code: "LOSS_SALE",
      level: "error",
      message: `Venta a pérdida: el precio (${result.unitPrice.toFixed(2)}) es menor o igual al costo (${result.unitCost.toFixed(2)}).`,
    });
  }

  // LOW_MARGIN — margen por debajo del umbral de alerta, pero no negativo
  if (
    result.marginPercent != null &&
    result.marginPercent.gte(0) &&
    result.marginPercent.lt(new D(warningPercent)) &&
    result.unitPrice != null &&
    result.unitPrice.gt(0)
  ) {
    alerts.push({
      code: "LOW_MARGIN",
      level: "warning",
      message: `Margen bajo: ${result.marginPercent.toFixed(1)}% (mínimo recomendado: ${warningPercent}%).`,
    });
  }

  // COST_UNRESOLVED — no se pudo calcular el costo
  if (result.unitCost == null) {
    alerts.push({
      code: "COST_UNRESOLVED",
      level: "warning",
      message: "No se pudo resolver el costo del artículo. El margen no está disponible.",
    });
  }

  // PARTIAL_DATA — datos incompletos (costo parcial o precio parcial)
  if (result.partial || result.costPartial) {
    alerts.push({
      code: "PARTIAL_DATA",
      level: "warning",
      message: result.partial
        ? "El precio es estimado porque faltan datos (cotizaciones, listas o composiciones)."
        : "El costo es aproximado porque falta información (cotizaciones de metal u otros).",
    });
  }

  // Ordenar: errores primero, luego warnings, luego info
  const levelOrder: Record<PricingAlert["level"], number> = { error: 0, warning: 1, info: 2 };
  return alerts.sort((a, b) => levelOrder[a.level] - levelOrder[b.level]);
}

// ---------------------------------------------------------------------------
// buildPolicy — evalúa si la venta puede confirmarse según política del tenant
// ---------------------------------------------------------------------------

function buildPolicy(
  alerts: PricingAlert[],
  unitPrice: Prisma.Decimal | null,
  marginPercent: Prisma.Decimal | null,
  config: PricingPolicyConfig
): PricingPolicyResult {
  const D = Prisma.Decimal;
  const blockingAlerts: string[] = [];
  const alertCodes = new Set(alerts.map(a => a.code));

  // Sin precio en absoluto → siempre bloquea
  if (unitPrice == null) {
    return { canConfirm: false, blockingAlerts: ["PARTIAL_DATA"] };
  }

  // ZERO_OR_NEGATIVE_PRICE
  if (config.blockZeroOrNegativePrice && alertCodes.has("ZERO_OR_NEGATIVE_PRICE")) {
    blockingAlerts.push("ZERO_OR_NEGATIVE_PRICE");
  }

  // LOSS_SALE
  if (config.blockLossSale && alertCodes.has("LOSS_SALE")) {
    blockingAlerts.push("LOSS_SALE");
  }

  // PARTIAL_DATA
  if (config.blockPartialData && alertCodes.has("PARTIAL_DATA")) {
    blockingAlerts.push("PARTIAL_DATA");
  }

  // LOW_MARGIN block — chequeo independiente contra umbral de bloqueo
  if (
    config.lowMarginBlockPercent != null &&
    marginPercent != null &&
    unitPrice.gt(0) &&
    marginPercent.lt(new D(config.lowMarginBlockPercent))
  ) {
    if (!blockingAlerts.includes("LOW_MARGIN")) {
      blockingAlerts.push("LOW_MARGIN");
    }
  }

  return {
    canConfirm: blockingAlerts.length === 0,
    blockingAlerts,
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
  groupId?: string | null,
  categoryTotal?: Prisma.Decimal,
  brandTotal?: Prisma.Decimal,
  groupTotal?: Prisma.Decimal,
  allowedIds?: string[]
) {
  const rules = await prisma.quantityDiscount.findMany({
    where: {
      jewelryId,
      isActive: true,
      deletedAt: null,
      ...(allowedIds && allowedIds.length > 0 ? { id: { in: allowedIds } } : {}),
      OR: [
        { variantId: variantId ?? null, articleId },
        { variantId: null, articleId },
        ...(categoryId ? [{ categoryId, articleId: null, groupId: null }] : []),
        ...(brand ? [{ brand, articleId: null, groupId: null }] : []),
        ...(groupId ? [{ groupId, articleId: null }] : []),
        { articleId: null, categoryId: null, brand: null, groupId: null },
      ],
    },
    select: {
      id: true,
      articleId: true,
      variantId: true,
      categoryId: true,
      brand: true,
      groupId: true,
      group:    { select: { id: true, name: true } },
      category: { select: { id: true, name: true } },
      isStackable: true,
      evaluationMode: true,
      applyOn: true,
      tiers: {
        select: { minQty: true, type: true, value: true },
        orderBy: { minQty: "desc" },
      },
    },
  });

  function scopePriority(r: (typeof rules)[0]): number {
    if (r.variantId)  return 0;
    if (r.articleId)  return 1;
    if (r.categoryId) return 2;
    if (r.brand)      return 3;
    if (r.groupId)    return 4;
    return 5;
  }

  const sorted = [...rules].sort((a, b) => scopePriority(a) - scopePriority(b));

  for (const rule of sorted) {
    // Determinar la cantidad efectiva según el modo de evaluación
    let effectiveQty = quantity;
    if (rule.evaluationMode === "CATEGORY_TOTAL" && categoryTotal != null) {
      effectiveQty = categoryTotal;
    } else if (rule.evaluationMode === "BRAND_TOTAL" && brandTotal != null) {
      effectiveQty = brandTotal;
    } else if (rule.evaluationMode === "GROUP_TOTAL" && groupTotal != null) {
      effectiveQty = groupTotal;
    }

    const tier = rule.tiers.find((t) =>
      new Prisma.Decimal(t.minQty.toString()).lte(effectiveQty)
    );
    if (tier) {
      return {
        id: rule.id,
        type: tier.type,
        value: tier.value,
        isStackable: rule.isStackable,
        evaluationMode: rule.evaluationMode,
        applyOn: rule.applyOn as string,
        effectiveQty,
        scopeLabel: rule.group?.name
          ?? (rule as any).category?.name
          ?? rule.brand
          ?? null,
        scopeType: rule.groupId   ? "GROUP"
          : rule.categoryId       ? "CATEGORY"
          : rule.brand            ? "BRAND"
          : rule.articleId        ? "ARTICLE"
          : rule.variantId        ? "VARIANT"
          : "GENERAL",
      };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// computeLineTaxes — calcula impuestos para una línea de venta
// Exportado para reutilizar en confirmSale (sales.service.ts)
// ---------------------------------------------------------------------------

// Tipo mínimo de EntityTaxOverride para computeLineTaxes (evita import circular)
type TaxOverrideInput = {
  taxId: string;
  overrideMode: string;  // "INHERIT" | "EXEMPT" | "CUSTOM_RATE"
  applyOn: string | null;
  isActive: boolean;
};

export async function computeLineTaxes(
  jewelryId: string,
  taxIds: string[],
  finalPrice: Prisma.Decimal,
  basePrice: Prisma.Decimal,
  metalHechuraBreakdown: { metalSale: number; hechuraSale: number } | null,
  costBreakdown: PriceBreakdown | null,
  entityApplyOnOverride?: string | null,
  entityTaxOverrides?: TaxOverrideInput[] | null,
): Promise<{ taxBreakdown: TaxBreakdownItem[]; taxAmount: Prisma.Decimal }> {
  const D = Prisma.Decimal;
  if (!taxIds.length) return { taxBreakdown: [], taxAmount: new D(0) };

  const now = new Date();
  const taxes = await prisma.tax.findMany({
    where: { id: { in: taxIds }, jewelryId, isActive: true, deletedAt: null, appliesOnSale: true },
    select: {
      id: true, name: true, code: true, taxType: true,
      calculationType: true, applyOn: true,
      rate: true, fixedAmount: true, validFrom: true, validTo: true,
    },
  });

  const activeTaxes = taxes.filter(t => {
    if (t.validFrom && t.validFrom > now) return false;
    if (t.validTo   && t.validTo   < now) return false;
    return true;
  });

  // Índice rápido de overrides activos por taxId
  const overrideByTaxId = new Map<string, TaxOverrideInput>();
  if (entityTaxOverrides) {
    for (const ov of entityTaxOverrides) {
      if (ov.isActive) overrideByTaxId.set(ov.taxId, ov);
    }
  }

  // Componentes de costo para estimar base METAL/HECHURA cuando no hay metalHechuraBreakdown
  const costMetal  = costBreakdown?.totals.metal   ?? null;
  const costHechura= costBreakdown?.totals.hechura ?? null;
  const costTotal  = costBreakdown?.totals.unified ?? null;

  const fp = toNum(finalPrice) ?? 0;
  const bp = toNum(basePrice)  ?? fp;

  function resolveBase(applyOn: string): { base: number; estimated: boolean } {
    switch (applyOn) {
      case "TOTAL":
      case "SUBTOTAL_AFTER_DISCOUNT":
        return { base: fp, estimated: false };
      case "SUBTOTAL_BEFORE_DISCOUNT":
        return { base: bp, estimated: false };
      case "METAL": {
        if (metalHechuraBreakdown) return { base: metalHechuraBreakdown.metalSale, estimated: false };
        if (costMetal != null && costTotal != null && costTotal > 0)
          return { base: fp * costMetal / costTotal, estimated: true };
        return { base: fp, estimated: true };
      }
      case "HECHURA": {
        if (metalHechuraBreakdown) return { base: metalHechuraBreakdown.hechuraSale, estimated: false };
        if (costHechura != null && costTotal != null && costTotal > 0)
          return { base: fp * costHechura / costTotal, estimated: true };
        return { base: fp, estimated: true };
      }
      case "METAL_Y_HECHURA":
        // En joyería metal+hechura = total del artículo
        return { base: fp, estimated: false };
      default:
        return { base: fp, estimated: true };
    }
  }

  const taxBreakdown: TaxBreakdownItem[] = [];
  let totalTax = new D(0);

  for (const t of activeTaxes) {
    // ── Prioridad de override ────────────────────────────────────────────────
    // 1. Override puntual activo para este impuesto
    // 2. Override global de la entidad (entityApplyOnOverride)
    // 3. Base del Tax

    const individualOverride = overrideByTaxId.get(t.id);

    // Si el override puntual es EXEMPT → saltear este impuesto por completo
    if (individualOverride && individualOverride.overrideMode === "EXEMPT") {
      continue;
    }

    let effectiveApplyOn: string;
    let entityOverrideSource: "INDIVIDUAL" | "GLOBAL" | undefined;

    if (individualOverride && individualOverride.applyOn != null) {
      // Override puntual con applyOn propio
      effectiveApplyOn = individualOverride.applyOn;
      entityOverrideSource = "INDIVIDUAL";
    } else if (entityApplyOnOverride != null) {
      // Override global de la entidad
      effectiveApplyOn = entityApplyOnOverride;
      entityOverrideSource = "GLOBAL";
    } else {
      // Sin override → heredar del Tax
      effectiveApplyOn = t.applyOn;
      entityOverrideSource = undefined;
    }

    const overriddenByEntity = entityOverrideSource != null;
    const { base, estimated } = resolveBase(effectiveApplyOn);
    const baseD = new D(base.toFixed(6));
    const rate  = t.rate        != null ? parseFloat(t.rate.toString())        : null;
    const fixed = t.fixedAmount != null ? parseFloat(t.fixedAmount.toString()) : null;

    let taxAmt = 0;
    if (t.calculationType === "PERCENTAGE" && rate != null) {
      taxAmt = parseFloat(baseD.mul(rate).div(100).toFixed(6));
    } else if (t.calculationType === "FIXED_AMOUNT" && fixed != null) {
      taxAmt = fixed;
    } else if (t.calculationType === "PERCENTAGE_PLUS_FIXED") {
      const pct = rate  != null ? parseFloat(baseD.mul(rate).div(100).toFixed(6)) : 0;
      const fxa = fixed ?? 0;
      taxAmt = pct + fxa;
    }

    taxBreakdown.push({
      taxId:                    t.id,
      name:                     t.name,
      code:                     t.code,
      taxType:                  t.taxType,
      calculationType:          t.calculationType,
      applyOn:                  effectiveApplyOn,
      applyOnOverriddenByEntity: overriddenByEntity || undefined,
      entityOverrideSource,
      base,
      baseEstimated:            estimated,
      rate,
      fixedAmount:              fixed,
      taxAmount:                taxAmt,
    });

    totalTax = totalTax.add(new D(taxAmt.toFixed(6)));
  }

  return { taxBreakdown, taxAmount: totalTax };
}

// ---------------------------------------------------------------------------
// resolveFinalSalePrice — motor principal con trazabilidad
// ---------------------------------------------------------------------------

export async function resolveFinalSalePrice(
  jewelryId: string,
  opts: SalePriceOpts
): Promise<SalePriceResult> {
  const D = Prisma.Decimal;
  const steps: PricingStep[] = [];
  const qty = new D(String(opts.quantity ?? 1));

  // ── Cargar configuración de política de precios del tenant ────────────────
  const jewelryConfig = await prisma.jewelry.findUnique({
    where: { id: jewelryId },
    select: {
      pricingLowMarginWarningPercent:  true,
      pricingLowMarginBlockPercent:    true,
      pricingBlockLossSale:            true,
      pricingBlockZeroOrNegativePrice: true,
      pricingBlockPartialData:         true,
    },
  });
  const policyConfig: PricingPolicyConfig = {
    lowMarginWarningPercent:  toNum(jewelryConfig?.pricingLowMarginWarningPercent)  ?? PRICING_DEFAULTS.lowMarginWarningPercent,
    lowMarginBlockPercent:    toNum(jewelryConfig?.pricingLowMarginBlockPercent)    ?? PRICING_DEFAULTS.lowMarginBlockPercent,
    blockLossSale:            jewelryConfig?.pricingBlockLossSale            ?? PRICING_DEFAULTS.blockLossSale,
    blockZeroOrNegativePrice: jewelryConfig?.pricingBlockZeroOrNegativePrice ?? PRICING_DEFAULTS.blockZeroOrNegativePrice,
    blockPartialData:         jewelryConfig?.pricingBlockPartialData         ?? PRICING_DEFAULTS.blockPartialData,
  };

  // ── FIX 3: Cargar artículo con multiplierCurrencyId incluido ─────────────
  const article = await prisma.article.findFirst({
    where: { id: opts.articleId, jewelryId, deletedAt: null },
    select: {
      // Precio
      categoryId: true,
      brand: true,
      groupId: true,
      salePrice: true,
      useManualSalePrice: true,
      // Costo — todos los campos para resolveArticleCost()
      costCalculationMode: true,
      costPrice: true,
      manualCurrencyId: true,
      manualBaseCost: true,
      manualAdjustmentKind: true,
      manualAdjustmentType: true,
      manualAdjustmentValue: true,
      multiplierBase: true,
      multiplierValue: true,
      multiplierQuantity: true,
      multiplierCurrencyId: true,  // FIX 3: campo faltante en versión anterior
      hechuraPrice: true,
      hechuraPriceMode: true,
      mermaPercent: true,
      category: { select: { mermaPercent: true } },
      costComposition: {
        select: {
          type: true,
          label: true,
          quantity: true,
          unitValue: true,
          currencyId: true,
          mermaPercent: true,
          metalVariantId: true,
          lineAdjKind:  true,
          lineAdjType:  true,
          lineAdjValue: true,
          catalogItem: { select: { code: true, sku: true } },
        },
      },
      compositions: { select: { variantId: true, grams: true, isBase: true } },
      manualTaxIds: true,
    },
  });

  if (!article) {
    steps.push({
      key: "ARTICLE_LOAD",
      label: "Carga del artículo",
      status: "missing",
      value: null,
      message: `Artículo ${opts.articleId} no encontrado`,
    });
    return finalize({ ...noPrice(), steps }, policyConfig);
  }

  steps.push({
    key: "ARTICLE_LOAD",
    label: "Carga del artículo",
    status: "ok",
    value: null,
    meta: { articleId: opts.articleId, categoryId: article.categoryId },
  });

  // ── Cargar variante ────────────────────────────────────────────────────
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

  // ── Calcular costo real (motor nuevo) ──────────────────────────────────
  const costResult = await resolveArticleCost(jewelryId, article as any);

  // Inyectar totalGrams desde composiciones si el motor no lo devolvió
  if (
    costResult.totalGrams == null &&
    article.compositions &&
    article.compositions.length > 0
  ) {
    costResult.totalGrams = article.compositions.reduce(
      (acc, c) => acc.add(new D(c.grams.toString())),
      new D(0)
    );
  }

  // Agregar pasos del costo al trace
  steps.push(...costResult.steps);

  steps.push({
    key: "COSTO_REAL",
    label: "Costo real del artículo",
    status: costResult.partial ? "partial" : costResult.value != null ? "ok" : "missing",
    value: costResult.value,
    meta: { mode: costResult.mode, partial: costResult.partial },
  });

  // ── Cargar promoción activa ────────────────────────────────────────────
  const promotionCandidates = await prisma.promotion.findMany({
    where: {
      jewelryId,
      isActive: true,
      deletedAt: null,
      OR: [
        { scope: "ALL" },
        { scope: "ARTICLE", articles: { some: { articleId: opts.articleId } } },
        ...(opts.variantId
          ? [{ scope: "VARIANT" as const, variants: { some: { variantId: opts.variantId } } }]
          : []),
        ...(article.categoryId
          ? [{ scope: "CATEGORY" as const, categories: { some: { categoryId: article.categoryId } } }]
          : []),
        ...(article.brand
          ? [{ scope: "BRAND" as const, brands: { some: { brand: article.brand } } }]
          : []),
        ...(article.groupId
          ? [{ scope: "GROUP" as const, groups: { some: { groupId: article.groupId } } }]
          : []),
      ],
    },
    select: {
      id: true,
      name: true,
      type: true,
      value: true,
      scope: true,
      validFrom: true,
      validTo: true,
      isActive: true,
      deletedAt: true,
      priority: true,
      isStackable: true,
      applyOn: true,
    },
    orderBy: [{ priority: "asc" }, { createdAt: "asc" } as any],
  });
  const activePromo = promotionCandidates.find(isPromotionValid) ?? null;

  // ── PASO 1: Resolver precio base ────────────────────────────────────────
  let basePrice: Prisma.Decimal | null = null;
  let priceSource: SalePriceResult["priceSource"] = "NONE";
  let appliedPriceListId: string | null = null;
  let appliedPriceListName: string | null = null;
  let partial = false;
  let metalHechuraBreakdown: MetalHechuraDetail | null = null;
  // Redondeo diferido: cuando roundingApplyOn = "NET" o "TOTAL"
  let deferredRounding: { mode: string; direction: string; applyOn: "NET" | "TOTAL" } | null = null;

  // 1a. variant.priceOverride
  if (variantPriceOverride != null) {
    basePrice = variantPriceOverride;
    priceSource = "PRICE_LIST"; // compatibilidad: VARIANT_OVERRIDE no existe en el tipo legacy
    steps.push({
      key: "VARIANT_OVERRIDE",
      label: "Override de variante",
      status: "ok",
      value: basePrice,
      meta: { variantId: opts.variantId },
    });
  }

  // 1b. Lista de precios
  if (basePrice == null) {
    const resolved = opts.priceListIdOverride
      ? await resolvePriceListById(jewelryId, opts.priceListIdOverride)
      : await resolvePriceList(jewelryId, { clientId: opts.clientId, categoryId });

    if (resolved) {
      const priceResult = applyPriceList(resolved.priceList, costResult);
      if (priceResult.value != null) {
        basePrice = priceResult.value;
        priceSource = "PRICE_LIST";
        appliedPriceListId = resolved.priceList.id;
        appliedPriceListName = resolved.priceList.name;
        partial = priceResult.partial;
        metalHechuraBreakdown = priceResult.metalHechuraDetail ?? null;
        // Capturar redondeo diferido (NET o TOTAL)
        if (priceResult.roundingDeferred) deferredRounding = priceResult.roundingDeferred;

        // Si el redondeo cambió el valor → mostrar el valor pre-redondeo en PRICE_LIST
        const priceListDisplayValue = priceResult.preRounding ?? priceResult.value;

        steps.push({
          key: "PRICE_LIST",
          label: `Lista de precios: ${resolved.priceList.name}`,
          status: priceResult.partial ? "partial" : "ok",
          value: priceListDisplayValue,
          meta: {
            source: resolved.source,
            mode: resolved.priceList.mode,
            priceListId: resolved.priceList.id,
            ...(priceResult.metalHechuraDetail ? { metalHechuraDetail: priceResult.metalHechuraDetail } : {}),
          },
        });

        // Paso de redondeo (solo cuando el redondeo modificó el valor — modo PRICE)
        if (priceResult.preRounding != null) {
          steps.push({
            key: "ROUNDING",
            label: "Redondeo",
            status: "ok",
            value: priceResult.value,
            meta: {
              preRounding:  priceResult.preRounding.toString(),
              mode:         priceResult.roundingMode,
              direction:    priceResult.roundingDirection,
              applyOn:      "PRICE",
            },
          });
        }
      } else {
        steps.push({
          key: "PRICE_LIST",
          label: `Lista de precios: ${resolved.priceList.name}`,
          status: "missing",
          value: null,
          message: "Lista encontrada pero sin datos de costo suficientes",
          meta: { priceListId: resolved.priceList.id, mode: resolved.priceList.mode },
        });
      }
    } else {
      steps.push({
        key: "PRICE_LIST",
        label: "Lista de precios",
        status: "skipped",
        value: null,
        message: "No hay lista de precios activa",
      });
    }
  }

  // 1c. Manual override
  if (basePrice == null && article.useManualSalePrice && article.salePrice != null) {
    basePrice = new D(article.salePrice.toString());
    priceSource = "MANUAL_OVERRIDE";
    steps.push({
      key: "MANUAL_OVERRIDE",
      label: "Precio manual (override activado)",
      status: "ok",
      value: basePrice,
    });
  }

  // 1d. Fallback salePrice
  if (basePrice == null && article.salePrice != null) {
    basePrice = new D(article.salePrice.toString());
    priceSource = "MANUAL_FALLBACK";
    steps.push({
      key: "MANUAL_FALLBACK",
      label: "Precio de venta (fallback)",
      status: "ok",
      value: basePrice,
    });
  }

  if (basePrice == null) {
    steps.push({
      key: "BASE_PRICE",
      label: "Precio base",
      status: "missing",
      value: null,
      message: "No se pudo determinar precio base",
    });
    return finalize({ ...noPrice(), steps }, policyConfig);
  }

  // Capturar baseSource antes de que priceSource pueda cambiar por descuentos
  const baseSource: SalePriceResult["priceSource"] = priceSource;

  // ── PASO 2 + 3: Descuento por cantidad y Promoción (con acumulabilidad) ─
  const qtyDiscount = await resolveQuantityDiscount(
    jewelryId,
    opts.articleId,
    opts.variantId ?? null,
    qty,
    article.categoryId,
    article.brand,
    (article as any).groupId ?? null,
    opts.categoryTotal != null ? new D(opts.categoryTotal.toString()) : undefined,
    opts.brandTotal    != null ? new D(opts.brandTotal.toString())    : undefined,
    opts.groupTotal    != null ? new D(opts.groupTotal.toString())    : undefined,
    opts.quantityDiscountIds,
  );

  let finalPrice: Prisma.Decimal = basePrice;
  let qtyDiscountAmount: Prisma.Decimal | null = null;
  let promoDiscountAmount: Prisma.Decimal | null = null;
  let appliedDiscountId: string | null = null;
  let appliedPromotionId: string | null = null;
  let appliedPromotionName: string | null = null;
  let stackingMode: SalePriceResult["stackingMode"] = "NONE";

  if (qtyDiscount && activePromo) {
    // Ambos aplican → decidir si acumular o elegir el mejor
    const bothStackable = qtyDiscount.isStackable && activePromo.isStackable;

    if (bothStackable) {
      // CHAINED: QD primero, luego Promo sobre el precio resultante
      stackingMode = "CHAINED";
      const qdApplied = applyDiscountWithApplyOn(
        basePrice, qtyDiscount.type, new D(qtyDiscount.value.toString()),
        qtyDiscount.applyOn, metalHechuraBreakdown, costResult.breakdown ?? null,
      );
      qtyDiscountAmount = qdApplied.discountAmount;
      appliedDiscountId = qtyDiscount.id;

      // En modo CHAINED la promo aplica sobre el precio post-QD (como TOTAL)
      const promoApplied = applyDiscountWithApplyOn(
        qdApplied.final, activePromo.type, new D(activePromo.value.toString()),
        activePromo.applyOn as string, null, null,
      );
      finalPrice = promoApplied.final;
      promoDiscountAmount = promoApplied.discountAmount;
      appliedPromotionId = activePromo.id;
      appliedPromotionName = activePromo.name;
      priceSource = "PROMOTION";

      steps.push({
        key: "QUANTITY_DISCOUNT",
        label: "Descuento por cantidad",
        status: "ok",
        value: qdApplied.final,
        meta: {
          discountId:            qtyDiscount.id,
          type:                  qtyDiscount.type,
          value:                 qtyDiscount.value.toString(),
          discountAmount:        qdApplied.discountAmount.toString(),
          applyOn:               qtyDiscount.applyOn,
          discountBase:          qdApplied.discountBase,
          discountBaseEstimated: qdApplied.discountBaseEstimated,
          quantity:              qty.toString(),
          evaluationMode:        qtyDiscount.evaluationMode,
          effectiveQty:          qtyDiscount.effectiveQty.toString(),
          scopeType:             qtyDiscount.scopeType,
          scopeLabel:            qtyDiscount.scopeLabel,
          stackable:             true,
        },
      });
      steps.push({
        key: "PROMOTION",
        label: `Promoción: ${activePromo.name}`,
        status: "ok",
        value: promoApplied.final,
        meta: {
          promoId:               activePromo.id,
          type:                  activePromo.type,
          value:                 activePromo.value.toString(),
          discountAmount:        promoApplied.discountAmount.toString(),
          applyOn:               activePromo.applyOn,
          discountBase:          promoApplied.discountBase,
          discountBaseEstimated: promoApplied.discountBaseEstimated,
          scope:                 activePromo.scope,
          stackable:             true,
        },
      });
    } else {
      // BEST_OF: comparar desde basePrice, aplicar solo el que da menor precio
      const qdResult = applyDiscountWithApplyOn(
        basePrice, qtyDiscount.type, new D(qtyDiscount.value.toString()),
        qtyDiscount.applyOn, metalHechuraBreakdown, costResult.breakdown ?? null,
      );
      const promoResult = applyDiscountWithApplyOn(
        basePrice, activePromo.type, new D(activePromo.value.toString()),
        activePromo.applyOn as string, metalHechuraBreakdown, costResult.breakdown ?? null,
      );
      const qdWins = qdResult.final.lte(promoResult.final);

      if (qdWins) {
        stackingMode = "BEST_OF_QD";
        finalPrice = qdResult.final;
        qtyDiscountAmount = qdResult.discountAmount;
        appliedDiscountId = qtyDiscount.id;
        priceSource = "QUANTITY_DISCOUNT";

        steps.push({
          key: "QUANTITY_DISCOUNT",
          label: "Descuento por cantidad",
          status: "ok",
          value: qdResult.final,
          meta: {
            discountId:            qtyDiscount.id,
            type:                  qtyDiscount.type,
            value:                 qtyDiscount.value.toString(),
            discountAmount:        qdResult.discountAmount.toString(),
            applyOn:               qtyDiscount.applyOn,
            discountBase:          qdResult.discountBase,
            discountBaseEstimated: qdResult.discountBaseEstimated,
            quantity:              qty.toString(),
            evaluationMode:        qtyDiscount.evaluationMode,
            effectiveQty:          qtyDiscount.effectiveQty.toString(),
            scopeType:             qtyDiscount.scopeType,
            scopeLabel:            qtyDiscount.scopeLabel,
            stackable:             false,
          },
        });
        steps.push({
          key: "PROMOTION",
          label: `Promoción: ${activePromo.name}`,
          status: "skipped",
          value: null,
          message: "Descartada: el descuento por cantidad ofrece mejor precio",
          meta: {
            promoId:         activePromo.id,
            stackable:       false,
            competing:       true,
            competingResult: promoResult.final.toString(),
          },
        });
      } else {
        stackingMode = "BEST_OF_PROMO";
        finalPrice = promoResult.final;
        promoDiscountAmount = promoResult.discountAmount;
        appliedPromotionId = activePromo.id;
        appliedPromotionName = activePromo.name;
        priceSource = "PROMOTION";

        steps.push({
          key: "QUANTITY_DISCOUNT",
          label: "Descuento por cantidad",
          status: "skipped",
          value: null,
          message: "Descartado: la promoción ofrece mejor precio",
          meta: {
            discountId:      qtyDiscount.id,
            evaluationMode:  qtyDiscount.evaluationMode,
            effectiveQty:    qtyDiscount.effectiveQty.toString(),
            stackable:       false,
            competing:       true,
            competingResult: qdResult.final.toString(),
          },
        });
        steps.push({
          key: "PROMOTION",
          label: `Promoción: ${activePromo.name}`,
          status: "ok",
          value: promoResult.final,
          meta: {
            promoId:               activePromo.id,
            type:                  activePromo.type,
            value:                 activePromo.value.toString(),
            discountAmount:        promoResult.discountAmount.toString(),
            applyOn:               activePromo.applyOn,
            discountBase:          promoResult.discountBase,
            discountBaseEstimated: promoResult.discountBaseEstimated,
            scope:                 activePromo.scope,
            stackable:             false,
          },
        });
      }
    }
  } else if (qtyDiscount) {
    // Solo descuento por cantidad
    const qdApplied = applyDiscountWithApplyOn(
      basePrice, qtyDiscount.type, new D(qtyDiscount.value.toString()),
      qtyDiscount.applyOn, metalHechuraBreakdown, costResult.breakdown ?? null,
    );
    finalPrice = qdApplied.final;
    qtyDiscountAmount = qdApplied.discountAmount;
    appliedDiscountId = qtyDiscount.id;
    priceSource = "QUANTITY_DISCOUNT";

    steps.push({
      key: "QUANTITY_DISCOUNT",
      label: "Descuento por cantidad",
      status: "ok",
      value: qdApplied.final,
      meta: {
        discountId:            qtyDiscount.id,
        type:                  qtyDiscount.type,
        value:                 qtyDiscount.value.toString(),
        discountAmount:        qdApplied.discountAmount.toString(),
        applyOn:               qtyDiscount.applyOn,
        discountBase:          qdApplied.discountBase,
        discountBaseEstimated: qdApplied.discountBaseEstimated,
        quantity:              qty.toString(),
        evaluationMode:        qtyDiscount.evaluationMode,
        effectiveQty:          qtyDiscount.effectiveQty.toString(),
        scopeType:             qtyDiscount.scopeType,
        scopeLabel:            qtyDiscount.scopeLabel,
      },
    });
    steps.push({
      key: "PROMOTION",
      label: "Promoción",
      status: "skipped",
      value: null,
      message: "Sin promoción activa",
    });
  } else if (activePromo) {
    // Solo promoción
    const promoApplied = applyDiscountWithApplyOn(
      basePrice, activePromo.type, new D(activePromo.value.toString()),
      activePromo.applyOn as string, metalHechuraBreakdown, costResult.breakdown ?? null,
    );
    finalPrice = promoApplied.final;
    promoDiscountAmount = promoApplied.discountAmount;
    appliedPromotionId = activePromo.id;
    appliedPromotionName = activePromo.name;
    priceSource = "PROMOTION";

    steps.push({
      key: "QUANTITY_DISCOUNT",
      label: "Descuento por cantidad",
      status: "skipped",
      value: null,
      message: "Sin descuento por cantidad aplicable",
    });
    steps.push({
      key: "PROMOTION",
      label: `Promoción: ${activePromo.name}`,
      status: "ok",
      value: promoApplied.final,
      meta: {
        promoId:               activePromo.id,
        type:                  activePromo.type,
        value:                 activePromo.value.toString(),
        discountAmount:        promoApplied.discountAmount.toString(),
        applyOn:               activePromo.applyOn,
        discountBase:          promoApplied.discountBase,
        discountBaseEstimated: promoApplied.discountBaseEstimated,
        scope:                 activePromo.scope,
      },
    });
  } else {
    // Ninguno aplica
    steps.push({
      key: "QUANTITY_DISCOUNT",
      label: "Descuento por cantidad",
      status: "skipped",
      value: null,
      message: "Sin descuento por cantidad aplicable",
    });
    steps.push({
      key: "PROMOTION",
      label: "Promoción",
      status: "skipped",
      value: null,
      message: "Sin promoción activa",
    });
  }

  const totalDiscount = (qtyDiscountAmount ?? new D(0)).add(promoDiscountAmount ?? new D(0));

  // ── PASO 4b: Cargar entidad + condición comercial propia ───────────────────
  // Leemos todos los campos de la entidad de una sola vez (se reutilizan en PASO 5 — impuestos)
  let entityTaxExempt = false;
  let entityTaxApplyOnOverride: string | null = null;
  let entityTaxOverrides: Array<{ taxId: string; overrideMode: string; applyOn: string | null; isActive: boolean }> | null = null;

  if (opts.clientId) {
    const clientEnt = await prisma.commercialEntity.findFirst({
      where: { id: opts.clientId, jewelryId, deletedAt: null },
      select: {
        taxExempt: true,
        taxApplyOnOverride: true,
        commercialRuleType: true,
        commercialValueType: true,
        commercialValue: true,
        commercialApplyOn: true,
        taxOverrides: {
          where: { isActive: true },
          select: { taxId: true, overrideMode: true, applyOn: true, isActive: true },
        },
      },
    });

    entityTaxExempt          = clientEnt?.taxExempt ?? false;
    entityTaxApplyOnOverride = clientEnt?.taxApplyOnOverride ?? null;
    entityTaxOverrides       = (clientEnt?.taxOverrides ?? null) as typeof entityTaxOverrides;

    const ruleType      = clientEnt?.commercialRuleType   ?? null;
    const valueType     = clientEnt?.commercialValueType  ?? null;
    const rawValue      = clientEnt?.commercialValue != null
      ? parseFloat(clientEnt.commercialValue.toString())
      : null;
    const effectiveApplyOn = clientEnt?.commercialApplyOn ?? "TOTAL";

    const canApply = ruleType != null && valueType != null && rawValue != null && rawValue > 0;

    if (canApply) {
      const ruleValue = new D(String(rawValue));

      if (ruleType === "DISCOUNT" || ruleType === "BONUS") {
        const applied = applyDiscountWithApplyOn(
          finalPrice, valueType, ruleValue, effectiveApplyOn,
          metalHechuraBreakdown ?? null, costResult.breakdown ?? null,
        );
        finalPrice = applied.final;
        steps.push({
          key:    "ENTITY_COMMERCIAL_RULE",
          label:  "Condición comercial",
          status: "ok",
          value:  applied.discountAmount,
          meta: {
            ruleType,
            valueType,
            value:                 String(rawValue),
            applyOn:               effectiveApplyOn,
            discountBase:          applied.discountBase,
            discountBaseEstimated: applied.discountBaseEstimated,
            discountAmount:        applied.discountAmount.toString(),
          },
        });
      } else if (ruleType === "SURCHARGE") {
        const { base, estimated } = resolveDiscountBase(
          effectiveApplyOn, finalPrice, metalHechuraBreakdown ?? null, costResult.breakdown ?? null,
        );
        const baseD = new D(base.toFixed(6));
        const surchargeAmt: Prisma.Decimal = valueType === "PERCENTAGE"
          ? baseD.mul(ruleValue).div(100)
          : ruleValue;
        finalPrice = finalPrice.add(surchargeAmt);
        steps.push({
          key:    "ENTITY_COMMERCIAL_RULE",
          label:  "Condición comercial",
          status: "ok",
          value:  surchargeAmt,
          meta: {
            ruleType,
            valueType,
            value:                  String(rawValue),
            applyOn:                effectiveApplyOn,
            surchargeBase:          parseFloat(base.toString()),
            surchargeBaseEstimated: estimated,
            surchargeAmount:        surchargeAmt.toString(),
          },
        });
      }
    }
  }

  // ── REDONDEO DIFERIDO NET: sobre precio neto (después de descuentos, antes de impuestos) ──
  if (deferredRounding?.applyOn === "NET") {
    const before = finalPrice;
    finalPrice = applyRounding(finalPrice, deferredRounding.mode, deferredRounding.direction);
    if (!finalPrice.equals(before)) {
      steps.push({
        key:    "ROUNDING",
        label:  "Redondeo",
        status: "ok",
        value:  finalPrice,
        meta: {
          preRounding: before.toString(),
          mode:        deferredRounding.mode,
          direction:   deferredRounding.direction,
          applyOn:     "NET",
        },
      });
    }
  }

  // ── PASO 4: Costo y margen ──────────────────────────────────────────────
  let unitCost: Prisma.Decimal | null = null;
  let unitMargin: Prisma.Decimal | null = null;
  let marginPercent: Prisma.Decimal | null = null;

  if (costResult.value != null) {
    unitCost = costResult.value;
    unitMargin = finalPrice.sub(unitCost);
    marginPercent = finalPrice.gt(0)
      ? unitMargin.div(finalPrice).mul(100)
      : new D(0);

    steps.push({
      key: "MARGIN",
      label: "Margen sobre precio",
      status: "ok",
      value: marginPercent,
      meta: {
        unitCost: unitCost.toString(),
        unitMargin: unitMargin.toString(),
        finalPrice: finalPrice.toString(),
      },
    });
  }

  steps.push({
    key: "PRECIO_FINAL",
    label: "Precio final",
    status: "ok",
    value: finalPrice,
    meta: {
      source: priceSource,
      discountTotal: totalDiscount.toString(),
    },
  });

  // ── PASO 5: Impuestos ──────────────────────────────────────────────────────
  // entityTaxExempt y entityTaxApplyOnOverride ya se cargaron en PASO 4b

  const taxIds: string[] = entityTaxExempt ? [] : ((article as any).manualTaxIds ?? []);
  const { taxBreakdown, taxAmount } = await computeLineTaxes(
    jewelryId,
    taxIds,
    finalPrice,
    basePrice,
    metalHechuraBreakdown ?? null,
    costResult.breakdown ?? null,
    entityTaxApplyOnOverride,
    entityTaxOverrides,
  );
  let totalWithTax = finalPrice.add(taxAmount);

  steps.push({
    key: "TAX",
    label: "Impuestos",
    status: entityTaxExempt ? "skipped" : taxBreakdown.length > 0 ? "ok" : "skipped",
    value: taxBreakdown.length > 0 ? taxAmount : null,
    message: entityTaxExempt ? "Entidad exenta de impuestos" : undefined,
    meta: {
      items: taxBreakdown,
      totalWithTax: totalWithTax.toString(),
      exemptByEntity: entityTaxExempt,
    },
  });

  // ── REDONDEO DIFERIDO TOTAL: sobre el total con impuestos ─────────────────
  if (deferredRounding?.applyOn === "TOTAL") {
    const before = totalWithTax;
    totalWithTax = applyRounding(totalWithTax, deferredRounding.mode, deferredRounding.direction);
    if (!totalWithTax.equals(before)) {
      steps.push({
        key:    "ROUNDING",
        label:  "Redondeo",
        status: "ok",
        value:  totalWithTax,
        meta: {
          preRounding: before.toString(),
          mode:        deferredRounding.mode,
          direction:   deferredRounding.direction,
          applyOn:     "TOTAL",
        },
      });
    }
  }

  const base: Omit<SalePriceResult, "alerts" | "policy"> = {
    unitPrice: finalPrice,
    basePrice,
    quantityDiscountAmount: qtyDiscountAmount,
    promotionDiscountAmount: promoDiscountAmount,
    discountAmount: totalDiscount,
    priceSource,
    baseSource,
    unitCost,
    unitMargin,
    marginPercent,
    costPartial: costResult.partial,
    costMode: costResult.mode,
    partial,
    appliedPriceListId,
    appliedPriceListName,
    appliedPromotionId,
    appliedPromotionName,
    appliedDiscountId,
    stackingMode,
    steps,
    metalHechuraBreakdown,
    taxAmount,
    taxBreakdown,
    totalWithTax,
    taxExemptByEntity: entityTaxExempt,
  };

  return finalize(base, policyConfig);
}

// ---------------------------------------------------------------------------
// evaluatePricingPolicy — chequeo rápido de política para confirmación de venta
// ---------------------------------------------------------------------------

export interface LinePolicyBlock {
  articleId: string;
  variantId: string | null;
  blockingAlerts: string[];
}

export async function evaluatePricingPolicy(
  jewelryId: string,
  lines: Array<{ articleId: string; variantId: string | null; unitPrice: any }>
): Promise<LinePolicyBlock[]> {
  const D = Prisma.Decimal;

  // Cargar config del tenant
  const jewelryConfig = await prisma.jewelry.findUnique({
    where: { id: jewelryId },
    select: {
      pricingLowMarginBlockPercent:    true,
      pricingBlockLossSale:            true,
      pricingBlockZeroOrNegativePrice: true,
      pricingBlockPartialData:         true,
    },
  });
  const config = {
    lowMarginBlockPercent:    toNum(jewelryConfig?.pricingLowMarginBlockPercent)    ?? PRICING_DEFAULTS.lowMarginBlockPercent,
    blockLossSale:            jewelryConfig?.pricingBlockLossSale            ?? PRICING_DEFAULTS.blockLossSale,
    blockZeroOrNegativePrice: jewelryConfig?.pricingBlockZeroOrNegativePrice ?? PRICING_DEFAULTS.blockZeroOrNegativePrice,
    blockPartialData:         jewelryConfig?.pricingBlockPartialData         ?? PRICING_DEFAULTS.blockPartialData,
  };

  // Fast exit: sin reglas de bloqueo activas
  const anyBlock = config.blockLossSale || config.blockZeroOrNegativePrice ||
    config.blockPartialData || config.lowMarginBlockPercent != null;
  if (!anyBlock) return [];

  const results: LinePolicyBlock[] = [];

  for (const line of lines) {
    const blocking: string[] = [];
    const unitPrice = new D(String(line.unitPrice ?? 0));

    // ZERO_OR_NEGATIVE_PRICE
    if (config.blockZeroOrNegativePrice && unitPrice.lte(0)) {
      blocking.push("ZERO_OR_NEGATIVE_PRICE");
    }

    // Reglas basadas en costo (LOSS_SALE, LOW_MARGIN, PARTIAL_DATA)
    if (config.blockLossSale || config.lowMarginBlockPercent != null || config.blockPartialData) {
      const artCost = await prisma.article.findFirst({
        where: { id: line.articleId, jewelryId, deletedAt: null },
        select: {
          costCalculationMode: true,
          costPrice: true,
          manualCurrencyId: true,
          manualBaseCost: true,
          manualAdjustmentKind: true,
          manualAdjustmentType: true,
          manualAdjustmentValue: true,
          multiplierBase: true,
          multiplierValue: true,
          multiplierQuantity: true,
          multiplierCurrencyId: true,
          hechuraPrice: true,
          hechuraPriceMode: true,
          mermaPercent: true,
          category: { select: { mermaPercent: true } },
          costComposition: {
            select: {
              type: true, label: true,
              quantity: true, unitValue: true, currencyId: true, mermaPercent: true, metalVariantId: true,
              lineAdjKind: true, lineAdjType: true, lineAdjValue: true,
              catalogItem: { select: { code: true, sku: true } },
            },
          },
          compositions: { select: { variantId: true, grams: true, isBase: true } },
        },
      });

      if (artCost) {
        const costResult = await resolveArticleCost(jewelryId, artCost as any);

        if (costResult.value != null) {
          if (config.blockLossSale && unitPrice.gt(0) && unitPrice.lte(costResult.value)) {
            blocking.push("LOSS_SALE");
          }
          if (config.lowMarginBlockPercent != null && unitPrice.gt(0)) {
            const margin = unitPrice.sub(costResult.value).div(unitPrice).mul(100);
            if (margin.lt(new D(config.lowMarginBlockPercent))) {
              blocking.push("LOW_MARGIN");
            }
          }
        } else if (config.blockPartialData) {
          blocking.push("PARTIAL_DATA");
        }
      }
    }

    if (blocking.length > 0) {
      results.push({ articleId: line.articleId, variantId: line.variantId ?? null, blockingAlerts: blocking });
    }
  }

  return results;
}
