// src/lib/pricing-engine/pricing-engine.sale.ts
// Motor de resolución de precio de venta con trazabilidad por pasos.
//
// Flujo:
//   COSTO_REAL → BASE_PRICE → DESCUENTO_CANTIDAD → PROMOCION → MARGEN
//
// Precio base (en orden):
//   1. Lista de precios         — resolvePriceList + applyPriceList
//   2. MANUAL_OVERRIDE          — Article.useManualSalePrice=true && salePrice
//   3. MANUAL_FALLBACK          — Article.salePrice
//
// REGLA: Las variantes no tienen precio propio (priceOverride eliminado).
// El precio es siempre del artículo padre; las variantes solo afectan
// el costo vía weightOverride.
//
// FIX 3: multiplierCurrencyId incluido en el select del artículo.

import { Prisma } from "@prisma/client";
import { prisma } from "../prisma.js";
import { resolvePriceList, resolvePriceListById, applyPriceList, applyRounding, type MetalHechuraDetail } from "./pricing-engine.pricelist.js";
import { calculateCostFromLines, enrichCostMetalSteps, buildBatchCostContext, getArticleMetalVariantIds } from "./pricing-engine.cost.js";
import type {
  SalePriceResult,
  SalePriceOpts,
  PriceSource,
  PricingStep,
  PricingAlert,
  PricingPolicyResult,
  TaxBreakdownItem,
  PriceBreakdown,
  MetalHechuraBreakdownSource,
  ArticleCostInput,
  BatchCostContext,
  PricingLineSnapshot,
  ComponentAdjustmentKind,
  ComponentSaleAdjustment,
  ComponentSaleBreakdown,
  ComponentSaleDetail,
} from "./pricing-engine.types.js";
import { PRICING_LINE_SNAPSHOT_VERSION } from "./pricing-engine.types.js";

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

export function isPromotionValid(p: {
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

  // Bugfix: leer la forma canónica del PriceBreakdown (`totals.{metal,hechura,unified}`).
  // La versión vieja accedía a `metalCost`/`hechuraCost`/`totalCost` planos —
  // campos que NUNCA existieron en este shape — así que la rama de estimación
  // por proporción de costo nunca se activaba y los descuentos applyOn=METAL|HECHURA
  // sin metalHechuraBreakdown se aplicaban al precio completo.
  let costMetal: number | null = null;
  let costHechura: number | null = null;
  let costTotal: number | null = null;
  if (costBreakdown?.totals) {
    costMetal   = costBreakdown.totals.metal   ?? null;
    costHechura = costBreakdown.totals.hechura ?? null;
    costTotal   = costBreakdown.totals.unified ?? null;
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
    customerDiscountAmount: null,
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
    appliedPriceListMode: null,
    appliedPromotionId: null,
    appliedPromotionName: null,
    appliedDiscountId: null,
    stackingMode: "NONE",
    taxExemptByEntity: false,
    appliedRounding: null,
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
  allowedIds?: string[],
  articleMetalVariantIds?: string[]
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
      metalVariantIds: true,
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

  // FASE 3: filtro adicional por variantes de metal. Una regla con
  // `metalVariantIds` no vacío solo aplica si el artículo contiene al menos
  // una de esas variantes. Reglas con array vacío no se ven afectadas.
  const articleMetalSet = new Set(articleMetalVariantIds ?? []);
  const metalFilteredRules = rules.filter((r) => {
    if (!r.metalVariantIds || r.metalVariantIds.length === 0) return true;
    return r.metalVariantIds.some((id) => articleMetalSet.has(id));
  });

  function scopePriority(r: (typeof rules)[0]): number {
    if (r.variantId)  return 0;
    if (r.articleId)  return 1;
    if (r.categoryId) return 2;
    if (r.brand)      return 3;
    if (r.groupId)    return 4;
    return 5;
  }

  const sorted = [...metalFilteredRules].sort((a, b) => scopePriority(a) - scopePriority(b));

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

/**
 * Override manual de la línea (línea-nivel, no entidad). Reemplaza por
 * completo el cálculo de impuestos del backend con un único item sintético.
 * Permite que el usuario edite manualmente el impuesto desde la UI sin
 * romper la regla de "una sola fuente de verdad".
 *
 * `appliesTo` define la base imponible del item sintético. Si no se pasa,
 * se asume "TOTAL" (sobre el precio neto unitario completo).
 */
export type LineTaxManualOverride = {
  mode: "PERCENT" | "AMOUNT";
  value: number;
  appliesTo?: "METAL" | "HECHURA" | "PRODUCT" | "SERVICE" | "TOTAL";
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
  manualOverride?: LineTaxManualOverride | null,
): Promise<{ taxBreakdown: TaxBreakdownItem[]; taxAmount: Prisma.Decimal }> {
  const D = Prisma.Decimal;

  // Override manual de la línea — reemplaza TODO el cálculo. La base
  // depende de `appliesTo`: TOTAL = finalPrice; METAL/HECHURA = porción
  // correspondiente del breakdown; PRODUCT/SERVICE = aproximación por
  // proporción de costo.
  if (manualOverride && Number.isFinite(manualOverride.value) && manualOverride.value >= 0) {
    const fp = toNum(finalPrice) ?? 0;
    const applyOn = manualOverride.appliesTo ?? "TOTAL";
    const costMetal   = costBreakdown?.totals.metal   ?? null;
    const costHechura = costBreakdown?.totals.hechura ?? null;
    const costTotal   = costBreakdown?.totals.unified ?? null;
    let base = fp;
    let estimated = false;
    if (applyOn === "METAL") {
      if (metalHechuraBreakdown) base = metalHechuraBreakdown.metalSale;
      else if (costMetal != null && costTotal && costTotal > 0) { base = fp * costMetal / costTotal; estimated = true; }
      else estimated = true;
    } else if (applyOn === "HECHURA") {
      if (metalHechuraBreakdown) base = metalHechuraBreakdown.hechuraSale;
      else if (costHechura != null && costTotal && costTotal > 0) { base = fp * costHechura / costTotal; estimated = true; }
      else estimated = true;
    } else if (applyOn === "PRODUCT" || applyOn === "SERVICE") {
      // No hay decomposición Producto/Servicio en el motor — caemos a fp y
      // marcamos como estimado para que la UI sepa que es aproximación.
      estimated = true;
    }
    const value = manualOverride.value;
    const mode  = manualOverride.mode;
    const taxAmt = mode === "PERCENT"
      ? parseFloat(new D(base).mul(value).div(100).toFixed(6))
      : value;
    const item: TaxBreakdownItem = {
      taxId:                     "OVERRIDE_MANUAL",
      name:                      mode === "PERCENT" ? `Impuesto manual ${value}%` : "Impuesto manual",
      code:                      "MANUAL_OVERRIDE",
      taxType:                   "OVERRIDE",
      calculationType:           mode === "PERCENT" ? "PERCENTAGE" : "FIXED_AMOUNT",
      applyOn,
      applyOnOverriddenByEntity: true,
      entityOverrideSource:      "INDIVIDUAL",
      base,
      baseEstimated:             estimated,
      rate:                      mode === "PERCENT" ? value : null,
      fixedAmount:               mode === "AMOUNT"  ? value : null,
      taxAmount:                 taxAmt,
    };
    return { taxBreakdown: [item], taxAmount: new D(taxAmt.toFixed(6)) };
  }

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
// applyTaxesFromMap — versión sync para batch (listados de artículos)
//
// Dada una base y una colección pre-cargada de impuestos indexada por id,
// devuelve la base + la suma de impuestos aplicados. Se usa en endpoints
// de listado donde los impuestos se cargan UNA vez para N artículos,
// evitando 1 query por fila.
//
// Delega el cálculo unitario de cada impuesto en la misma aritmética que
// computeLineTaxes (PERCENTAGE, FIXED_AMOUNT, PERCENTAGE_PLUS_FIXED).
// ---------------------------------------------------------------------------
export function applyTaxesFromMap(
  base: Prisma.Decimal,
  taxIds: string[],
  taxMap: Map<string, { rate: Prisma.Decimal; fixedAmount: Prisma.Decimal; calculationType: string }>,
): Prisma.Decimal {
  let total = base;
  for (const tid of taxIds) {
    const tax = taxMap.get(tid);
    if (!tax) continue;
    if (tax.calculationType === "PERCENTAGE") {
      total = total.add(base.mul(tax.rate.div(100)));
    } else if (tax.calculationType === "FIXED_AMOUNT") {
      total = total.add(tax.fixedAmount);
    } else if (tax.calculationType === "PERCENTAGE_PLUS_FIXED") {
      total = total.add(base.mul(tax.rate.div(100))).add(tax.fixedAmount);
    }
  }
  return total;
}

// ---------------------------------------------------------------------------
// computePurchaseTaxes — impuestos de compra sobre el costo de un artículo
//
// Lee el costo base y los manualTaxIds del artículo, filtra los impuestos
// por contexto de COMPRA (appliesOnPurchase=true, isRecoverable=false) y
// devuelve un breakdown + total. Usado por getPricingPreview para que el
// detalle del artículo muestre el costo con impuestos no-recuperables.
//
// Los impuestos de compra recuperables (ej: IVA crédito fiscal) se exluyen
// porque no forman parte del costo comercial real.
// ---------------------------------------------------------------------------
export type PurchaseTaxBreakdownItem = {
  taxId:           string;
  name:            string;
  calculationType: string;
  rate:            number | null;
  fixedAmount:     number | null;
  taxAmount:       number;
};

export type PurchaseTaxResult = {
  costBase:         string | null;  // costo sin impuestos (formateado)
  costTaxAmount:    string | null;  // suma de impuestos de compra
  costWithTax:      string | null;  // costBase + costTaxAmount
  costTaxBreakdown: PurchaseTaxBreakdownItem[];
};

export async function computePurchaseTaxes(
  jewelryId: string,
  articleId: string,
  costBaseDecimal: Prisma.Decimal | null,
): Promise<PurchaseTaxResult> {
  const empty: PurchaseTaxResult = {
    costBase:         costBaseDecimal != null ? costBaseDecimal.toFixed(4) : null,
    costTaxAmount:    null,
    costWithTax:      costBaseDecimal != null ? costBaseDecimal.toFixed(4) : null,
    costTaxBreakdown: [],
  };

  if (costBaseDecimal == null) return empty;

  const art = await prisma.article.findFirst({
    where: { id: articleId, jewelryId, deletedAt: null },
    select: { manualTaxIds: true },
  });
  if (!art || !art.manualTaxIds?.length) return empty;

  const taxes = await prisma.tax.findMany({
    where: {
      jewelryId,
      id:                { in: art.manualTaxIds },
      deletedAt:         null,
      appliesOnPurchase: true,
      isRecoverable:     false,
    },
    select: { id: true, name: true, rate: true, fixedAmount: true, calculationType: true },
  });
  if (!taxes.length) return empty;

  const breakdown: PurchaseTaxBreakdownItem[] = [];
  let totalTax = new Prisma.Decimal(0);

  for (const t of taxes) {
    const rate     = new Prisma.Decimal((t.rate ?? 0).toString());
    const fixedAmt = new Prisma.Decimal((t.fixedAmount ?? 0).toString());
    let   taxAmt   = new Prisma.Decimal(0);

    if (t.calculationType === "PERCENTAGE") {
      taxAmt = costBaseDecimal.mul(rate.div(100));
    } else if (t.calculationType === "FIXED_AMOUNT") {
      taxAmt = fixedAmt;
    } else if (t.calculationType === "PERCENTAGE_PLUS_FIXED") {
      taxAmt = costBaseDecimal.mul(rate.div(100)).add(fixedAmt);
    }

    totalTax = totalTax.add(taxAmt);
    breakdown.push({
      taxId:           t.id,
      name:            t.name,
      calculationType: t.calculationType,
      rate:            t.rate != null ? t.rate.toNumber() : null,
      fixedAmount:     t.fixedAmount != null ? t.fixedAmount.toNumber() : null,
      taxAmount:       taxAmt.toNumber(),
    });
  }

  const costWithTax = costBaseDecimal.add(totalTax);

  return {
    costBase:         costBaseDecimal.toFixed(4),
    costTaxAmount:    totalTax.gt(0) ? totalTax.toFixed(4) : null,
    costWithTax:      costWithTax.toFixed(4),
    costTaxBreakdown: breakdown,
  };
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

  const article = await prisma.article.findFirst({
    where: { id: opts.articleId, jewelryId, deletedAt: null },
    select: {
      // Precio
      categoryId: true,
      brand: true,
      salePrice: true,
      useManualSalePrice: true,
      // Combo comercial: campos para resolver precio desde componentes
      commercialMode: true,
      comboAdjustmentKind: true,
      comboAdjustmentValue: true,
      // Costo
      manualAdjustmentKind: true,
      manualAdjustmentType: true,
      manualAdjustmentValue: true,
      costComposition: {
        select: {
          type: true,
          label: true,
          quantity: true,
          unitValue: true,
          currencyId: true,
          mermaPercent: true,
          metalVariantId: true,
          catalogItemId: true,        // necesario para resolver precio de cada componente
          affectsStock: true,
          lineAdjKind:  true,
          lineAdjType:  true,
          lineAdjValue: true,
          catalogItem: { select: { id: true, code: true, sku: true, name: true } },
        },
      },
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

  // ── Cargar variante (weightOverride — groupId vive en ArticleGroupItem) ──
  // Resolución de grupo (para PROMOTION/QUANTITY_DISCOUNT/COUPON con scope GROUP):
  //   1) si la variante está asignada a un grupo (itemType=VARIANT) → ese grupo
  //   2) si no, fallback al grupo asignado al artículo padre (itemType=ARTICLE)
  // Sin este fallback, las promos/descuentos/cupones por GRUPO no aplicaban
  // cuando el artículo estaba asignado a nivel de ARTICLE en vez de VARIANT.
  let variantWeightOverride: Prisma.Decimal | null = null;
  let variantGroupId: string | null = null;
  if (opts.variantId) {
    const [variant, variantGroupItem, articleGroupItem] = await Promise.all([
      prisma.articleVariant.findFirst({
        where: { id: opts.variantId, articleId: opts.articleId, deletedAt: null },
        select: { weightOverride: true },
      }),
      prisma.articleGroupItem.findFirst({
        where: { variantId: opts.variantId },
        select: { groupId: true },
      }),
      prisma.articleGroupItem.findFirst({
        where: { articleId: opts.articleId, itemType: "ARTICLE" },
        select: { groupId: true },
      }),
    ]);
    if (variant?.weightOverride != null) {
      variantWeightOverride = new D(variant.weightOverride.toString());
    }
    variantGroupId = variantGroupItem?.groupId ?? articleGroupItem?.groupId ?? null;
  } else {
    const articleGroupItem = await prisma.articleGroupItem.findFirst({
      where: { articleId: opts.articleId, itemType: "ARTICLE" },
      select: { groupId: true },
    });
    variantGroupId = articleGroupItem?.groupId ?? null;
  }

  const categoryId = opts.categoryId ?? article.categoryId ?? undefined;

  // ── Calcular costo real (motor del artículo padre) ─────────────────────
  // NO se pasa clientId: el costo es estable e independiente del cliente.
  // La merma de entidad se aplica más abajo, solo en el cálculo del precio.
  // Líneas de costo: las reales del artículo + las inyectadas por simulación (ej. envío "what-if")
  const baseLines: any[] = (article as any).costComposition ?? [];

  // ── OVERRIDES DE COMPOSICIÓN A NIVEL LÍNEA (Fase 2) ─────────────────────
  // CRÍTICO: estos overrides actúan SOLO sobre una copia en memoria. La
  // ficha del artículo en DB no se modifica. Cada override es opcional.
  //
  // Se capturan los valores ORIGINALES antes de mutar para que la UI pueda
  // mostrar "Original X / Usado Y" sin tener que cargar el artículo otra
  // vez.
  const overrideContext: NonNullable<SalePriceResult["costOverrideContext"]> = {};

  // Encontramos la primera línea METAL y la primera HECHURA. La gran mayoría
  // de los artículos tienen una de cada — si hay varias, los overrides
  // aplican solo a la primera (decisión de UX simple para esta fase).
  const metalIdx   = baseLines.findIndex((l: any) => l?.type === "METAL");
  const hechuraIdx = baseLines.findIndex((l: any) => l?.type === "HECHURA");
  const metalLine   = metalIdx   >= 0 ? baseLines[metalIdx]   : null;
  const hechuraLine = hechuraIdx >= 0 ? baseLines[hechuraIdx] : null;

  // Originales (antes de mutar) — necesarios para el response.
  const originalGrams       = metalLine?.quantity != null
    ? parseFloat(String(metalLine.quantity))
    : null;
  const originalMermaPct    = metalLine?.mermaPercent != null
    ? parseFloat(String(metalLine.mermaPercent))
    : null;
  const originalMetalVariantId = metalLine?.metalVariantId ?? null;
  const originalHechuraAmount  = hechuraLine
    ? parseFloat(String(hechuraLine.quantity ?? 0)) * parseFloat(String(hechuraLine.unitValue ?? 0))
    : null;

  // Construimos una copia mutable de las líneas. Solo clonamos los objetos
  // que vamos a tocar; los demás los referenciamos tal cual.
  let workLines: any[] = baseLines;

  function ensureClone(): any[] {
    if (workLines === baseLines) workLines = baseLines.map((l) => ({ ...l }));
    return workLines;
  }

  // gramsOverride → quantity de la línea METAL.
  if (
    opts.gramsOverride != null &&
    Number.isFinite(opts.gramsOverride) &&
    opts.gramsOverride >= 0 &&
    metalIdx >= 0
  ) {
    const ws = ensureClone();
    ws[metalIdx] = { ...ws[metalIdx], quantity: opts.gramsOverride };
    overrideContext.grams = {
      original: originalGrams,
      applied:  opts.gramsOverride,
      manual:   true,
    };
  } else if (originalGrams != null) {
    overrideContext.grams = {
      original: originalGrams,
      applied:  originalGrams,
      manual:   false,
    };
  }

  // mermaPercentOverride → mermaPercent de la línea METAL.
  if (
    opts.mermaPercentOverride != null &&
    Number.isFinite(opts.mermaPercentOverride) &&
    opts.mermaPercentOverride >= 0 &&
    metalIdx >= 0
  ) {
    const ws = ensureClone();
    ws[metalIdx] = { ...ws[metalIdx], mermaPercent: opts.mermaPercentOverride };
    overrideContext.mermaPercent = {
      original: originalMermaPct,
      applied:  opts.mermaPercentOverride,
      manual:   true,
    };
  } else if (originalMermaPct != null) {
    overrideContext.mermaPercent = {
      original: originalMermaPct,
      applied:  originalMermaPct,
      manual:   false,
    };
  }

  // metalVariantIdOverride → metalVariantId de la línea METAL. El motor
  // resuelve la cotización vigente automáticamente desde ese id.
  if (
    opts.metalVariantIdOverride != null &&
    typeof opts.metalVariantIdOverride === "string" &&
    opts.metalVariantIdOverride.length > 0 &&
    metalIdx >= 0
  ) {
    const ws = ensureClone();
    ws[metalIdx] = { ...ws[metalIdx], metalVariantId: opts.metalVariantIdOverride };
    overrideContext.metalVariant = {
      originalId: originalMetalVariantId,
      appliedId:  opts.metalVariantIdOverride,
      manual:     true,
    };
  } else if (originalMetalVariantId != null) {
    overrideContext.metalVariant = {
      originalId: originalMetalVariantId,
      appliedId:  originalMetalVariantId,
      manual:     false,
    };
  }

  // hechuraOverrideAmount → quantity=1, unitValue=monto en la línea HECHURA.
  if (
    opts.hechuraOverrideAmount != null &&
    Number.isFinite(opts.hechuraOverrideAmount) &&
    opts.hechuraOverrideAmount >= 0 &&
    hechuraIdx >= 0
  ) {
    const ws = ensureClone();
    ws[hechuraIdx] = {
      ...ws[hechuraIdx],
      quantity:  1,
      unitValue: opts.hechuraOverrideAmount,
    };
    overrideContext.hechura = {
      original: originalHechuraAmount,
      applied:  opts.hechuraOverrideAmount,
      manual:   true,
    };
  } else if (originalHechuraAmount != null) {
    overrideContext.hechura = {
      original: originalHechuraAmount,
      applied:  originalHechuraAmount,
      manual:   false,
    };
  }

  const composedLines = opts.extraCostLines && opts.extraCostLines.length > 0
    ? [...workLines, ...opts.extraCostLines]
    : workLines;
  const costResult = await calculateCostFromLines(
    jewelryId,
    composedLines,
    {
      kind:  (article as any).manualAdjustmentKind,
      type:  (article as any).manualAdjustmentType,
      value: (article as any).manualAdjustmentValue,
    },
  );

  // Resolver totalGrams: variant.weightOverride tiene prioridad
  if (variantWeightOverride != null) {
    costResult.totalGrams = variantWeightOverride;
  }

  // Enriquecer steps COST_LINES_METAL con metalName/variantName/variantSku
  // para que el simulador pueda mostrar el metal y variante correctamente.
  await enrichCostMetalSteps(costResult.steps);

  // ── COMBO COMERCIAL — costo derivado de los componentes ─────────────────
  // El combo NO tiene costo manual: lo hereda recursivamente de sus componentes.
  //   comboCost = Σ (componentResult.unitCost × quantity_i)
  // Sobreescribimos costResult.value (y otros campos) con ese valor para que
  // el flujo posterior (PRICE_LIST / MANUAL_OVERRIDE / MANUAL_FALLBACK / MARGIN)
  // resuelva el precio del combo a partir del costo derivado.
  // El precio NO se calcula en este branch — lo aplica el flujo estándar como
  // cualquier artículo. Si el combo no tiene lista ni salePrice manual → precio = null.
  let comboCostStep: any = null;
  if (article.commercialMode === "COMBO_COMMERCIAL") {
    const comboCtx = opts._comboContext ?? { depth: 0, visited: new Set<string>() };
    const MAX_DEPTH = 5;

    if (comboCtx.depth >= MAX_DEPTH) {
      comboCostStep = {
        key: "COMBO_COST",
        label: "Costo del combo",
        status: "missing",
        value: null,
        message: `Profundidad máxima de combos alcanzada (${MAX_DEPTH}).`,
      };
      costResult.value = null;
      costResult.partial = true;
    } else if (comboCtx.visited.has(opts.articleId)) {
      comboCostStep = {
        key: "COMBO_COST",
        label: "Costo del combo",
        status: "missing",
        value: null,
        message: "Ciclo detectado entre combos.",
      };
      costResult.value = null;
      costResult.partial = true;
    } else {
      const childCtx = {
        depth: comboCtx.depth + 1,
        visited: new Set<string>([...comboCtx.visited, opts.articleId]),
      };

      const componentLines = ((article as any).costComposition ?? []).filter(
        (l: any) => (l.type === "PRODUCT" || l.type === "SERVICE") && l.catalogItemId,
      );

      let comboCost = new Prisma.Decimal(0);
      // FASE 1 — acumulamos costos por componente (metal vs hechura) para que
      // el combo tenga `metalCost`/`hechuraCost` y pueda armar
      // `metalHechuraBreakdown` con `source = "COMBO_COMPONENTS"`.
      let comboMetalCost   = new Prisma.Decimal(0);
      let comboHechuraCost = new Prisma.Decimal(0);
      let comboPartial = false;
      const componentsDetail: Array<{
        articleId: string;
        code: string | null;
        name: string | null;
        quantity: number;
        unitCost: number | null;       // costo unitario del componente
        lineCost: number;              // unitCost × quantity
        // Trazabilidad opcional del precio del componente (informativo, no se usa en cálculo)
        unitPrice?: number | null;
        priceSource?: string | null;
      }> = [];
      const missingComponents: Array<{ articleId: string; reason: string }> = [];

      for (const line of componentLines) {
        const componentId = line.catalogItemId as string;
        const qty = parseFloat(String(line.quantity ?? 0));
        if (!Number.isFinite(qty) || qty <= 0) continue;

        let componentResult: SalePriceResult | null = null;
        try {
          componentResult = await resolveFinalSalePrice(jewelryId, {
            articleId: componentId,
            quantity:  1,
            _comboContext: childCtx,
          });
        } catch {
          missingComponents.push({ articleId: componentId, reason: "Error al resolver el componente." });
        }

        const compCost = componentResult?.unitCost != null
          ? new Prisma.Decimal(String(componentResult.unitCost))
          : null;

        if (compCost == null) {
          comboPartial = true;
          missingComponents.push({
            articleId: componentId,
            reason: "Componente sin costo resuelto.",
          });
          componentsDetail.push({
            articleId: componentId,
            code: line.catalogItem?.code ?? null,
            name: line.catalogItem?.name ?? null,
            quantity: qty,
            unitCost: null,
            lineCost: 0,
            unitPrice: componentResult?.unitPrice != null ? parseFloat(componentResult.unitPrice.toString()) : null,
            priceSource: (componentResult as any)?.priceSource ?? null,
          });
          continue;
        }

        const lineCost = compCost.mul(qty);
        comboCost = comboCost.add(lineCost);
        // FASE 1 — propagar metalCost/hechuraCost desde el breakdown del
        // componente. Si el componente no tiene breakdown (ej. componente
        // partial), atribuimos su costo a hechura (todo a hechura es la
        // aproximación más segura para componentes service-like).
        const compMHB = componentResult?.metalHechuraBreakdown ?? null;
        if (compMHB) {
          comboMetalCost   = comboMetalCost.add(  new Prisma.Decimal(String(compMHB.metalCost   ?? 0)).mul(qty));
          comboHechuraCost = comboHechuraCost.add(new Prisma.Decimal(String(compMHB.hechuraCost ?? 0)).mul(qty));
        } else {
          // Sin breakdown del componente — todo a hechura.
          comboHechuraCost = comboHechuraCost.add(lineCost);
        }
        componentsDetail.push({
          articleId: componentId,
          code: line.catalogItem?.code ?? null,
          name: line.catalogItem?.name ?? null,
          quantity: qty,
          unitCost: parseFloat(compCost.toString()),
          lineCost: parseFloat(lineCost.toString()),
          unitPrice: componentResult?.unitPrice != null ? parseFloat(componentResult.unitPrice.toString()) : null,
          priceSource: (componentResult as any)?.priceSource ?? null,
        });
      }

      // Sobreescribir el costo del motor con el del combo derivado.
      // costResult ya viene calculado con calculateCostFromLines (que sumó unitValues
      // de las líneas — típicamente 0 en combos). Lo reemplazamos por comboCost real.
      costResult.value = comboCost;
      costResult.partial = comboPartial;
      // FASE 1 — exponemos el costo desglosado del combo para que
      // `deriveMetalHechuraBreakdown` pueda armar el breakdown con
      // `source = "COMBO_COMPONENTS"`.
      costResult.metalCost   = comboMetalCost;
      costResult.hechuraCost = comboHechuraCost;
      // El "modo" lo marcamos como COMBO para trazabilidad
      (costResult as any).mode = "COMBO";

      comboCostStep = {
        key: "COMBO_COST",
        label: "Costo del combo (suma de componentes)",
        status: comboPartial ? "partial" : "ok",
        value: comboCost,
        meta: {
          totalCost: parseFloat(comboCost.toString()),
          components: componentsDetail,
          ...(missingComponents.length > 0 ? { missingComponents } : {}),
        },
      };
    }
  }

  // Agregar pasos del costo al trace
  steps.push(...costResult.steps);
  if (comboCostStep) steps.push(comboCostStep);

  steps.push({
    key: "COSTO_REAL",
    label: "Costo real del artículo",
    status: costResult.partial ? "partial" : costResult.value != null ? "ok" : "missing",
    value: costResult.value,
    meta: { mode: costResult.mode, partial: costResult.partial },
  });

  // ── Entity merma override — solo afecta VENTA, no el costo ────────────
  // Se re-calcula la parte de metal del costo usando la merma del cliente,
  // y ese valor ajustado se pasa a applyPriceList en lugar del costo puro.
  // El costResult (puro) sigue sin modificarse — es lo que se muestra en Costo.
  let saleCostInput: typeof costResult = costResult;

  if (opts.clientId && costResult.metalCost != null && costResult.metalCost.gt(new Prisma.Decimal(0))) {
    const entityOverrides = await prisma.entityMermaOverride.findMany({
      where: { entityId: opts.clientId, isActive: true, deletedAt: null },
      select: { variantId: true, mermaPercent: true },
    });

    if (entityOverrides.length > 0) {
      const D = Prisma.Decimal;
      const overrideMap = new Map<string, number>();
      for (const o of entityOverrides) {
        overrideMap.set(o.variantId, Number(o.mermaPercent));
      }

      // Re-computar metalCost usando merma del cliente (a partir de los steps del costo puro)
      const metalSteps = costResult.steps.filter(
        (s: PricingStep) =>
          (s.key === "METAL_QUOTE" || s.key === "COST_LINES_METAL") && s.status === "ok"
      );

      let newMetalCost = new D(0);
      let newMetalGramsWithMerma = new D(0);

      for (const step of metalSteps) {
        const m = (step.meta ?? {}) as Record<string, unknown>;
        const variantId  = String(m.variantId ?? "");
        const entityMerma = overrideMap.get(variantId);
        const grams = new D(String(m.grams ?? m.qty ?? "0"));
        const price = new D(String(m.price ?? m.quotePrice ?? "0"));

        if (entityMerma != null) {
          // Re-computar con la merma del cliente
          const mermaFactor = new D(1).add(new D(entityMerma.toString()).div(100));
          const gramsWithMerma = grams.mul(mermaFactor);
          newMetalCost = newMetalCost.add(gramsWithMerma.mul(price));
          newMetalGramsWithMerma = newMetalGramsWithMerma.add(gramsWithMerma);
        } else {
          // Sin override para esta variante: usar el valor original del step
          newMetalCost = newMetalCost.add(new D(String(step.value ?? "0")));
          // Recuperar gramos con merma originales del metadata del step
          const origGramsWithMerma = m.gramsConMerma != null
            ? new D(String(m.gramsConMerma))
            : m.merma != null
              ? grams.mul(new D(1).add(new D(String(m.merma)).div(100)))
              : grams;
          newMetalGramsWithMerma = newMetalGramsWithMerma.add(origGramsWithMerma);
        }
      }

      // Si COST_LINES tuvo un ajuste global, propagar ese factor al nuevo metalCost
      // (los gramos no llevan ajuste monetario)
      const stepsMetalSum = metalSteps.reduce(
        (acc: Prisma.Decimal, s: PricingStep) => acc.add(new D(String(s.value ?? "0"))),
        new D(0)
      );
      if (stepsMetalSum.gt(new D("0.0001"))) {
        const adjFactor = costResult.metalCost.div(stepsMetalSum);
        newMetalCost = newMetalCost.mul(adjFactor);
      }

      if (!newMetalCost.eq(costResult.metalCost)) {
        const delta = newMetalCost.sub(costResult.metalCost);
        saleCostInput = {
          ...costResult,
          metalCost: newMetalCost,
          value: costResult.value != null ? costResult.value.add(delta) : costResult.value,
          metalGramsWithMerma: newMetalGramsWithMerma,
        };

        steps.push({
          key: "ENTITY_MERMA_SALE_ADJ",
          label: "Ajuste de merma por cliente (venta)",
          status: "ok",
          value: delta,
          meta: {
            clientId: opts.clientId,
            variants: entityOverrides.map(o => ({
              variantId: o.variantId,
              mermaPercent: Number(o.mermaPercent),
            })),
          },
        });
      }
    }
  }

  // ── Cost breakdown unificado para resolveDiscountBase y tracker ─────────
  // `resolveDiscountBase` con applyOn=METAL|HECHURA lee el desglose de costo
  // para estimar la porción del precio cuando NO hay metalHechuraBreakdown.
  // Necesita una shape canónica: `breakdown.totals.{metal,hechura,unified}`.
  //
  // Modos COST_LINES la traen naturalmente. Modos legacy (METAL_MERMA_HECHURA,
  // MULTIPLIER, MANUAL con composición) populan `metalCost`/`hechuraCost`
  // directos en CostResult pero no arman `breakdown`. Para ese caso
  // sintetizamos uno aquí, usando los valores de `saleCostInput` (que ya
  // refleja el override de merma por cliente, si aplicó).
  //
  // Si ninguna fuente provee desglose, queda null y los descuentos
  // applyOn=METAL|HECHURA caerán al modo `estimated=true` sobre basePrice
  // completo, igual que antes.
  const effectiveCostBreakdown: PriceBreakdown | null = (() => {
    const cb: PriceBreakdown | null = saleCostInput.breakdown ?? costResult.breakdown ?? null;
    if (cb?.totals && cb.totals.unified > 0) return cb;
    const mc = saleCostInput.metalCost   ?? costResult.metalCost   ?? null;
    const hc = saleCostInput.hechuraCost ?? costResult.hechuraCost ?? null;
    if (mc != null && hc != null) {
      const m = parseFloat(mc.toString());
      const h = parseFloat(hc.toString());
      const u = m + h;
      if (u > 0) {
        return {
          mode:    saleCostInput.mode,
          metal:   { items: [], total: m },
          hechura: { base: h, adjustments: [], total: h },
          totals:  { metal: m, hechura: h, unified: u },
        };
      }
    }
    return cb;
  })();

  // ── Cargar promoción activa ────────────────────────────────────────────
  // FASE 3: para evaluar scope METALS necesitamos el set de variantes de
  // metal del artículo (composición de costo directa). Una query liviana
  // por artículo. Combos comerciales NO heredan metales en v1.
  // Si en el futuro `resolveFinalSalePrice` recibe un `BatchCostContext`,
  // este helper soporta cache vía `ctx.articleMetalVariantsMap`.
  const articleMetalVariantIds = await getArticleMetalVariantIds(jewelryId, opts.articleId);

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
        ...(variantGroupId
          ? [{ scope: "GROUP" as const, groups: { some: { groupId: variantGroupId } } }]
          : []),
        ...(articleMetalVariantIds.length > 0
          ? [{ scope: "METALS" as const, metalVariants: { some: { metalVariantId: { in: articleMetalVariantIds } } } }]
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
  let appliedPriceListMode: string | null = null;
  let partial = false;
  let metalHechuraBreakdown: MetalHechuraDetail | null = null;
  // ── Tracker per-componente (Metal/Hechura) ─────────────────────────────
  // Cada vez que se aplica un descuento con applyOn=METAL|HECHURA se imputa
  // al componente correspondiente. TOTAL/PRODUCT/SERVICE no se trackean.
  //
  // La base por componente proviene, en orden de preferencia:
  //   1. metalHechuraBreakdown.metalSale/hechuraSale  (lista METAL_HECHURA — exacto)
  //   2. proporción de costo: basePrice × costMetal/costTotal              (estimado)
  //
  // Mientras `componentBaseMetal`/`componentBaseHechura` sean null, el
  // tracker es no-op. Estos valores se setean recién post-PRICE_LIST,
  // cuando ya conocemos basePrice y/o el desglose Metal/Hechura.
  let componentBaseMetal:    number | null = null;
  let componentBaseHechura:  number | null = null;
  let componentBaseEstimated = false;
  let componentBaseSource: "breakdown" | "cost-estimate" | "none" = "none";
  const componentMetalAdjs: ComponentSaleAdjustment[] = [];
  const componentHechuraAdjs: ComponentSaleAdjustment[] = [];
  function trackComponentAdjustment(
    applyOn: string,
    kind: ComponentAdjustmentKind,
    label: string,
    amount: number,
    extras?: {
      base?:       number | null;
      percentage?: number | null;
      valueType?:  string | null;
      source?:     string | null;
    },
  ) {
    if (componentBaseMetal == null || componentBaseHechura == null) return;
    if (!Number.isFinite(amount) || Math.abs(amount) < 0.0001) return;
    const adj: ComponentSaleAdjustment = {
      kind,
      label,
      amount,
      applyOn: applyOn === "METAL" ? "METAL" : "HECHURA",
      base:       extras?.base       ?? null,
      percentage: extras?.percentage ?? null,
      valueType:  extras?.valueType  ?? null,
      source:     extras?.source     ?? null,
    };
    if (applyOn === "METAL") {
      componentMetalAdjs.push(adj);
    } else if (applyOn === "HECHURA") {
      componentHechuraAdjs.push(adj);
    }
  }

  // Redondeo diferido: cuando roundingApplyOn = "NET" o "TOTAL"
  let deferredRounding: { mode: string; direction: string; applyOn: "NET" | "TOTAL" } | null = null;

  // Redondeo efectivamente aplicado a este preview (para exponerlo al frontend
  // sin que tenga que reconstruirlo desde `steps[]`). Se popula en el sitio
  // donde el redondeo realmente cambió el valor.
  let appliedRounding: SalePriceResult["appliedRounding"] = null;


  // 1. Lista de precios (las variantes no tienen precio propio — VARIANT_OVERRIDE eliminado)
  if (basePrice == null) {
    const resolved = opts.priceListIdOverride
      ? await resolvePriceListById(jewelryId, opts.priceListIdOverride)
      : await resolvePriceList(jewelryId, { clientId: opts.clientId, categoryId });

    if (resolved) {
      // saleCostInput tiene metalCost ajustado con merma de entidad (si aplica).
      // costResult (puro) ya fue trackeado arriba como COSTO_REAL.
      const priceResult = applyPriceList(resolved.priceList, saleCostInput);
      if (priceResult.value != null) {
        basePrice = priceResult.value;
        priceSource = "PRICE_LIST";
        appliedPriceListId = resolved.priceList.id;
        appliedPriceListName = resolved.priceList.name;
        appliedPriceListMode = (resolved.priceList as any).mode ?? null;
        partial = priceResult.partial;
        metalHechuraBreakdown = priceResult.metalHechuraDetail ?? null;
        // Capturar redondeo diferido (NET o TOTAL).
        // Cuando el tenant tiene política de redondeo a nivel comprobante
        // activa, el caller pasa `suppressListDeferredRounding = true` para
        // evitar doble redondeo: la lista delega y `computeSaleDocumentTotals`
        // redondea una sola vez sobre el `total` final.
        if (priceResult.roundingDeferred && !opts.suppressListDeferredRounding) {
          deferredRounding = priceResult.roundingDeferred;
        }

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
          appliedRounding = {
            applyOn:      "PRICE",
            mode:         priceResult.roundingMode as string,
            direction:    priceResult.roundingDirection as string,
            preRounding:  priceResult.preRounding,
            postRounding: priceResult.value,
            priceListId:   resolved.priceList.id,
            priceListName: resolved.priceList.name,
          };
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

  // ── Bases por componente para tracker ──────────────────────────────────
  // Se calcula UNA vez, post-basePrice. Cadena de fuentes en orden de
  // preferencia (de más exacta a más estimada):
  //
  //   1. metalHechuraBreakdown.{metalSale,hechuraSale}
  //      → lista activa en modo METAL_HECHURA (exacto, post-margen propio).
  //
  //   2. costBreakdown.totals.{metal,hechura,unified}
  //      → modo COST_LINES con composición Metal+Hechura. Estimamos la
  //        base de venta por proporción del costo: fp × cm/ct y fp × ch/ct.
  //
  //   3. costResult.metalCost / costResult.hechuraCost (campos directos).
  //      → modos legacy (METAL_MERMA_HECHURA, MULTIPLIER, etc.) que populan
  //        costMetal/costHechura sin armar `breakdown.totals`. Misma fórmula
  //        de proporción que (2).
  //
  // Si ninguna fuente tiene metal/hechura > 0, el tracker queda no-op y
  // `componentSaleBreakdown` será null al final.
  if (metalHechuraBreakdown) {
    componentBaseMetal     = metalHechuraBreakdown.metalSale;
    componentBaseHechura   = metalHechuraBreakdown.hechuraSale;
    componentBaseSource    = "breakdown";
    componentBaseEstimated = false;
  } else if (effectiveCostBreakdown?.totals && effectiveCostBreakdown.totals.unified > 0) {
    // Reusamos la misma shape canónica que `resolveDiscountBase` consume,
    // así el tracker y el cálculo del descuento ven exactamente la misma
    // proporción Metal/Hechura.
    const fp = parseFloat(basePrice.toString());
    const cm = effectiveCostBreakdown.totals.metal;
    const ch = effectiveCostBreakdown.totals.hechura;
    const ct = effectiveCostBreakdown.totals.unified;
    if (fp > 0 && (cm > 0 || ch > 0)) {
      componentBaseMetal     = fp * cm / ct;
      componentBaseHechura   = fp * ch / ct;
      componentBaseSource    = "cost-estimate";
      componentBaseEstimated = true;
    }
  }

  // Capturar baseSource antes de que priceSource pueda cambiar por descuentos
  const baseSource: SalePriceResult["priceSource"] = priceSource;

  // ── OVERRIDE MANUAL DE PRECIO (línea-nivel) ─────────────────────────────
  // Si el operador fijó un precio manual desde la UI, pisa el unitPrice y
  // saltamos descuentos por cantidad y promociones (el precio manual ES el
  // precio final neto). Mantenemos `basePrice` para que la UI muestre la
  // lista original.
  let manualPriceApplied = false;
  if (
    opts.manualPriceOverride != null &&
    Number.isFinite(opts.manualPriceOverride) &&
    opts.manualPriceOverride >= 0
  ) {
    manualPriceApplied = true;
    priceSource = "MANUAL_OVERRIDE";
    steps.push({
      key: "MANUAL_PRICE_OVERRIDE",
      label: "Precio manual",
      status: "ok",
      value: new D(opts.manualPriceOverride),
      message: "Precio neto unitario fijado por el operador",
    });
  }

  // ── PASO 2 + 3: Descuento por cantidad y Promoción (con acumulabilidad) ─
  const qtyDiscount = await resolveQuantityDiscount(
    jewelryId,
    opts.articleId,
    opts.variantId ?? null,
    qty,
    article.categoryId,
    article.brand,
    variantGroupId,
    opts.categoryTotal != null ? new D(opts.categoryTotal.toString()) : undefined,
    opts.brandTotal    != null ? new D(opts.brandTotal.toString())    : undefined,
    opts.groupTotal    != null ? new D(opts.groupTotal.toString())    : undefined,
    opts.quantityDiscountIds,
    articleMetalVariantIds,
  );

  let finalPrice: Prisma.Decimal = basePrice;
  let qtyDiscountAmount: Prisma.Decimal | null = null;
  let promoDiscountAmount: Prisma.Decimal | null = null;
  let appliedDiscountId: string | null = null;
  let appliedPromotionId: string | null = null;
  let appliedPromotionName: string | null = null;
  let stackingMode: SalePriceResult["stackingMode"] = "NONE";

  // Si hay precio manual, salteamos qty discount + promotion + manualDiscount
  // (el operador fijó el precio final neto; cualquier descuento adicional
  // sería confuso). El bloque `if (qtyDiscount && activePromo) { ... }` y
  // los siguientes se saltan via este flag y caen al final con
  // finalPrice = manualPriceOverride.
  if (manualPriceApplied) {
    finalPrice = new D(opts.manualPriceOverride!);
    // Descuento informativo: la diferencia entre lista y precio manual.
    if (basePrice && basePrice.greaterThan(finalPrice)) {
      qtyDiscountAmount = basePrice.minus(finalPrice);
    }
  } else if (qtyDiscount && activePromo) {
    // Ambos aplican → decidir si acumular o elegir el mejor
    const bothStackable = qtyDiscount.isStackable && activePromo.isStackable;

    if (bothStackable) {
      // CHAINED: QD primero, luego Promo sobre el precio resultante
      stackingMode = "CHAINED";
      const qdApplied = applyDiscountWithApplyOn(
        basePrice, qtyDiscount.type, new D(qtyDiscount.value.toString()),
        qtyDiscount.applyOn, metalHechuraBreakdown, effectiveCostBreakdown,
      );
      qtyDiscountAmount = qdApplied.discountAmount;
      appliedDiscountId = qtyDiscount.id;
      trackComponentAdjustment(
        qtyDiscount.applyOn, "QUANTITY_DISCOUNT",
        "Descuento por cantidad", qdApplied.discountAmount.toNumber(),
        {
          base:       qdApplied.discountBase,
          percentage: qtyDiscount.type === "PERCENTAGE"
            ? parseFloat(qtyDiscount.value.toString()) : null,
          valueType:  qtyDiscount.type,
          source:     "GENERAL",
        },
      );

      // En modo CHAINED la promo aplica sobre el precio post-QD (como TOTAL,
      // breakdowns null) → no se rola al desglose por componente aunque el
      // applyOn semántico sea METAL/HECHURA.
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
        qtyDiscount.applyOn, metalHechuraBreakdown, effectiveCostBreakdown,
      );
      const promoResult = applyDiscountWithApplyOn(
        basePrice, activePromo.type, new D(activePromo.value.toString()),
        activePromo.applyOn as string, metalHechuraBreakdown, effectiveCostBreakdown,
      );
      const qdWins = qdResult.final.lte(promoResult.final);

      if (qdWins) {
        stackingMode = "BEST_OF_QD";
        finalPrice = qdResult.final;
        qtyDiscountAmount = qdResult.discountAmount;
        appliedDiscountId = qtyDiscount.id;
        priceSource = "QUANTITY_DISCOUNT";
        trackComponentAdjustment(
          qtyDiscount.applyOn, "QUANTITY_DISCOUNT",
          "Descuento por cantidad", qdResult.discountAmount.toNumber(),
          {
            base:       qdResult.discountBase,
            percentage: qtyDiscount.type === "PERCENTAGE"
              ? parseFloat(qtyDiscount.value.toString()) : null,
            valueType:  qtyDiscount.type,
            source:     "GENERAL",
          },
        );

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
        trackComponentAdjustment(
          activePromo.applyOn as string, "PROMOTION",
          `Promoción: ${activePromo.name}`, promoResult.discountAmount.toNumber(),
          {
            base:       promoResult.discountBase,
            percentage: activePromo.type === "PERCENTAGE"
              ? parseFloat(activePromo.value.toString()) : null,
            valueType:  activePromo.type,
            source:     "GENERAL",
          },
        );

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
      qtyDiscount.applyOn, metalHechuraBreakdown, effectiveCostBreakdown,
    );
    finalPrice = qdApplied.final;
    qtyDiscountAmount = qdApplied.discountAmount;
    appliedDiscountId = qtyDiscount.id;
    priceSource = "QUANTITY_DISCOUNT";
    trackComponentAdjustment(
      qtyDiscount.applyOn, "QUANTITY_DISCOUNT",
      "Descuento por cantidad", qdApplied.discountAmount.toNumber(),
      {
        base:       qdApplied.discountBase,
        percentage: qtyDiscount.type === "PERCENTAGE"
          ? parseFloat(qtyDiscount.value.toString()) : null,
        valueType:  qtyDiscount.type,
        source:     "GENERAL",
      },
    );

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
      activePromo.applyOn as string, metalHechuraBreakdown, effectiveCostBreakdown,
    );
    finalPrice = promoApplied.final;
    promoDiscountAmount = promoApplied.discountAmount;
    appliedPromotionId = activePromo.id;
    appliedPromotionName = activePromo.name;
    priceSource = "PROMOTION";
    trackComponentAdjustment(
      activePromo.applyOn as string, "PROMOTION",
      `Promoción: ${activePromo.name}`, promoApplied.discountAmount.toNumber(),
      {
        base:       promoApplied.discountBase,
        percentage: activePromo.type === "PERCENTAGE"
          ? parseFloat(activePromo.value.toString()) : null,
        valueType:  activePromo.type,
        source:     "GENERAL",
      },
    );

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

  // Sprint 3 — POLICY.md §8 — acumulador de descuento de cliente (capa 5).
  // Solo suma DISCOUNT/BONUS de la rule comercial. NO incluye SURCHARGE
  // (recargo), descuentos por cantidad/promo (otras capas) ni manuales
  // (capa posterior). Si queda en 0 → null al exponerlo.
  let customerDiscountAccumulator = new D(0);

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
          metalHechuraBreakdown ?? null, effectiveCostBreakdown,
        );
        finalPrice = applied.final;
        // Sprint 3 — POLICY.md §8 — acumular el monto independientemente del
        // applyOn (TOTAL / METAL / HECHURA / etc.) para que el snapshot lo
        // exponga como campo singular.
        customerDiscountAccumulator = customerDiscountAccumulator.add(applied.discountAmount);
        trackComponentAdjustment(
          effectiveApplyOn, "ENTITY_RULE",
          ruleType === "BONUS" ? "Bonificación cliente" : "Descuento cliente",
          applied.discountAmount.toNumber(),
          {
            base:       applied.discountBase,
            percentage: valueType === "PERCENTAGE" ? rawValue : null,
            valueType,
            source:     "CLIENT",
          },
        );
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
          effectiveApplyOn, finalPrice, metalHechuraBreakdown ?? null, effectiveCostBreakdown,
        );
        const baseD = new D(base.toFixed(6));
        const surchargeAmt: Prisma.Decimal = valueType === "PERCENTAGE"
          ? baseD.mul(ruleValue).div(100)
          : ruleValue;
        finalPrice = finalPrice.add(surchargeAmt);
        // Recargo cliente — convención del tracker: amount positivo = reduce.
        // Acá el ajuste aumenta el precio, así que lo registramos con monto negativo.
        trackComponentAdjustment(
          effectiveApplyOn, "ENTITY_RULE",
          "Recargo cliente", -surchargeAmt.toNumber(),
          {
            base:       parseFloat(base.toString()),
            percentage: valueType === "PERCENTAGE" ? rawValue : null,
            valueType,
            source:     "CLIENT",
          },
        );
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

  // ── OVERRIDE MANUAL DE DESCUENTO ────────────────────────────────────────
  // Se aplica DESPUÉS de qty/promo/entityCommercialRule y ANTES del redondeo.
  // Reemplaza qty + promo (cuando no hay manualPrice).
  //
  // Convivencia con `manualPriceOverride`:
  //   · Sin manualPrice: la base del descuento es `basePrice` (precio de
  //     lista). Reemplaza qty + promo.
  //   · CON manualPrice: la base del descuento es el `finalPrice` actual
  //     (= el manualPrice). Esto permite encadenar manualPrice + manualDiscount
  //     (ej. precio 100k → -10% bonificación → 90k → +10% IVA → 99k). Sin
  //     este encadenamiento el operador no podía componer overrides
  //     comerciales — el manual price desactivaba el descuento manual.
  //
  // `appliesTo` define la base sobre la que se calcula el descuento:
  //   · TOTAL   (default): sobre la base elegida arriba (basePrice o finalPrice).
  //   · METAL   / HECHURA: sobre la porción metal/hechura del costo
  //                        (proporción de la base). Si no hay
  //                        decomposición disponible, cae a TOTAL.
  //   · PRODUCT / SERVICE: idem (estimación por costo, fallback TOTAL).
  if (
    opts.manualDiscountOverride &&
    Number.isFinite(opts.manualDiscountOverride.value) &&
    opts.manualDiscountOverride.value >= 0
  ) {
    const od = opts.manualDiscountOverride;
    const applyOn = od.appliesTo ?? "TOTAL";
    // Base de cálculo según haya o no manualPrice. Mantener back-compat
    // del comportamiento legacy cuando NO hay manualPrice (descuento sobre
    // lista, reemplaza qty/promo).
    const discountStartingBase: Prisma.Decimal = manualPriceApplied ? finalPrice : basePrice;
    const costMetal   = effectiveCostBreakdown?.totals.metal   ?? null;
    const costHechura = effectiveCostBreakdown?.totals.hechura ?? null;
    const costTotal   = effectiveCostBreakdown?.totals.unified ?? null;
    let discBase: Prisma.Decimal = discountStartingBase;
    if ((applyOn === "METAL" || applyOn === "HECHURA") && costTotal && costTotal > 0) {
      const portion =
        applyOn === "METAL"   ? (costMetal   ?? 0) / costTotal :
        applyOn === "HECHURA" ? (costHechura ?? 0) / costTotal :
        1;
      if (portion > 0 && portion <= 1) {
        discBase = discountStartingBase.mul(portion);
      }
    }
    const discAmount = od.mode === "PERCENT"
      ? discBase.mul(od.value).div(100)
      : new D(od.value);
    const newFinal = discountStartingBase.minus(discAmount);
    finalPrice = newFinal.lessThan(0) ? new D(0) : newFinal;
    qtyDiscountAmount   = discAmount;
    promoDiscountAmount = null;
    appliedDiscountId   = null;
    appliedPromotionId  = null;
    appliedPromotionName = null;
    stackingMode = "NONE";
    trackComponentAdjustment(
      applyOn, "MANUAL_DISCOUNT",
      "Bonificación manual", discAmount.toNumber(),
      {
        base:       parseFloat(discBase.toString()),
        percentage: od.mode === "PERCENT" ? od.value : null,
        valueType:  od.mode === "PERCENT" ? "PERCENTAGE" : "FIXED_AMOUNT",
        source:     "GENERAL",
      },
    );
    priceSource = "MANUAL_OVERRIDE";
    steps.push({
      key:    "MANUAL_DISCOUNT_OVERRIDE",
      label:  "Bonificación manual",
      status: "ok",
      value:  newFinal,
      meta: {
        mode:           od.mode,
        value:          od.value,
        appliesTo:      applyOn,
        discountAmount: discAmount.toString(),
        discountBase:   discBase.toString(),
      },
    });
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
      appliedRounding = {
        applyOn:      "NET",
        mode:         deferredRounding.mode,
        direction:    deferredRounding.direction,
        preRounding:  before,
        postRounding: finalPrice,
        priceListId:   appliedPriceListId,
        priceListName: appliedPriceListName,
      };
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
    effectiveCostBreakdown,
    entityTaxApplyOnOverride,
    entityTaxOverrides,
    // Override manual de la línea — si vino, reemplaza el cálculo entero
    // (excepto cuando el cliente está exento, que prevalece).
    entityTaxExempt ? null : (opts.taxOverride ?? null),
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
      appliedRounding = {
        applyOn:      "TOTAL",
        mode:         deferredRounding.mode,
        direction:    deferredRounding.direction,
        preRounding:  before,
        postRounding: totalWithTax,
        priceListId:   appliedPriceListId,
        priceListName: appliedPriceListName,
      };
    }
  }

  // ── Construcción del componentSaleBreakdown ─────────────────────────────
  // Se popula cuando hay base por componente disponible (sea exacta desde
  // metalHechuraBreakdown, sea estimada por proporción de costo).
  // El `final` por componente = `base` − Σ ajustes (positivos = reducen).
  // Se clampa a 0 para evitar finales negativos por redondeos acumulados.
  let componentSaleBreakdown: ComponentSaleDetail | null = null;
  if (componentBaseMetal != null && componentBaseHechura != null) {
    // F1.3 G4.3 — Decimal-safe end-to-end. Acumulamos los amounts en Decimal
    // y partimos los ajustes en dos buckets: manual vs no-manual. Luego:
    //   final                 = base − Σ all
    //   salePreManualDiscount = base − Σ non-manual   (= final + Σ manual)
    // Sin parseFloat / Number / toFixed intermedios — solo `.toNumber()`
    // final al asignar al campo `number`.
    const buildBreakdown = (
      baseValue: number,
      adjs:      ComponentSaleAdjustment[],
    ): ComponentSaleBreakdown => {
      const baseD = new D(String(baseValue));
      let allSum: Prisma.Decimal     = new D(0);
      let nonManualSum: Prisma.Decimal = new D(0);
      for (const a of adjs) {
        const amtD = new D(String(a.amount));
        allSum = allSum.plus(amtD);
        if (a.kind !== "MANUAL_DISCOUNT") {
          nonManualSum = nonManualSum.plus(amtD);
        }
      }
      const finalD = baseD.minus(allSum);
      const preD   = baseD.minus(nonManualSum);
      // Clamp ≥ 0 en Decimal para evitar finales negativos por redondeos
      // acumulados, sin coerción JS.
      const zero = new D(0);
      return {
        base:                  baseValue,
        adjustments:           adjs,
        final:                 (finalD.lessThan(zero) ? zero : finalD).toNumber(),
        salePreManualDiscount: (preD.lessThan(zero)   ? zero : preD).toNumber(),
      };
    };
    componentSaleBreakdown = {
      metal:   buildBreakdown(componentBaseMetal,   componentMetalAdjs),
      hechura: buildBreakdown(componentBaseHechura, componentHechuraAdjs),
    };
  }
  // `componentBaseSource` y `componentBaseEstimated` quedan disponibles si
  // en el futuro queremos exponer el origen al frontend (etiqueta "estimado").
  void componentBaseSource;
  void componentBaseEstimated;

  // ── FASE 1 — `metalHechuraBreakdown` universal ──────────────────────────
  // Pasamos el breakdown actual (puede venir exacto del paso PRICE_LIST
  // METAL_HECHURA) por el helper para que SIEMPRE quede etiquetado con
  // `source` y `*Estimated`. Cuando vino null y el costo tiene desglose,
  // el helper lo deriva por proporción de costo.
  metalHechuraBreakdown = deriveMetalHechuraBreakdown({
    metalCost:      costResult.metalCost   != null ? parseFloat(costResult.metalCost.toString())   : 0,
    hechuraCost:    costResult.hechuraCost != null ? parseFloat(costResult.hechuraCost.toString()) : 0,
    costTotal:      costResult.value       != null ? parseFloat(costResult.value.toString())       : null,
    basePrice:      basePrice              != null ? parseFloat(basePrice.toString())              : null,
    priceSource:    priceSource as PriceSource,
    commercialMode: (article as any)?.commercialMode ?? null,
    // FASE 5 — gramos del metal con merma desde el cost-engine. El helper
    // los usa para derivar `metalGramsSale` y `metalPricePerGram` también
    // en modos derivados (MARGIN_TOTAL, COMBO, etc.). Sin esto, el card
    // metal del Comparador caía a "—" porque solo el branch METAL_HECHURA
    // exacto poblaba esos campos.
    // FASE 5.1 — gramos puros con merma (qty × pureza × (1+merma/100)).
    // Sumamos `gramsFineEquivalent` de los steps `COST_LINES_METAL` que
    // `enrichCostMetalSteps` ya enriqueció con la pureza de cada variante.
    // Es el mismo valor que el simulador usa en `totalEquivGr` para el
    // header del card metal. Fallback a `metalGramsWithMerma` (sin pureza)
    // sólo cuando la pureza no está disponible — caso edge.
    metalGramsBase: (() => {
      const fineSum = (costResult.steps as any[])
        .filter(s => s?.key === "COST_LINES_METAL" && s?.meta?.gramsFineEquivalent != null)
        .reduce((sum, s) => sum + parseFloat(String(s.meta.gramsFineEquivalent)), 0);
      if (fineSum > 0) return parseFloat(fineSum.toFixed(6));
      return costResult.metalGramsWithMerma != null
        ? parseFloat(costResult.metalGramsWithMerma.toString())
        : null;
    })(),
    // FASE 5.2 — `metalSaleFinal` post-descuentos por componente. Cuando
    // hay descuentos imputados a METAL (ENTITY_RULE / promoción con
    // applyOn=METAL / etc.), `componentSaleBreakdown.metal.final` < `metalSale`.
    // El helper usa este valor para `metalGramsSale` y refleja la
    // realidad post-descuentos en el header del card metal.
    metalSaleFinal:   componentSaleBreakdown?.metal?.final   ?? null,
    hechuraSaleFinal: componentSaleBreakdown?.hechura?.final ?? null,
    exactBreakdown: metalHechuraBreakdown
      ? {
          metalSale:         metalHechuraBreakdown.metalSale,
          hechuraSale:       metalHechuraBreakdown.hechuraSale,
          metalMarginPct:    metalHechuraBreakdown.metalMarginPct,
          hechuraMarginPct:  metalHechuraBreakdown.hechuraMarginPct,
          metalGramsBase:    metalHechuraBreakdown.metalGramsBase    ?? null,
          metalGramsSale:    metalHechuraBreakdown.metalGramsSale    ?? null,
          metalPricePerGram: metalHechuraBreakdown.metalPricePerGram ?? null,
          // Sprint 3 — POLICY.md §8 — propagar gramos puros del breakdown
          // de la lista al resultado del motor.
          pureGramsBase:     metalHechuraBreakdown.pureGramsBase     ?? null,
          pureGramsSale:     metalHechuraBreakdown.pureGramsSale     ?? null,
        }
      : null,
  }) as typeof metalHechuraBreakdown;

  const base: Omit<SalePriceResult, "alerts" | "policy"> = {
    unitPrice: finalPrice,
    basePrice,
    quantityDiscountAmount: qtyDiscountAmount,
    promotionDiscountAmount: promoDiscountAmount,
    // Sprint 3 — POLICY.md §8 — solo exponemos cuando hubo descuento real;
    // cero o sin rule → null para que el frontend muestre "—".
    customerDiscountAmount: customerDiscountAccumulator.gt(0) ? customerDiscountAccumulator : null,
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
    appliedPriceListMode,
    appliedPromotionId,
    appliedPromotionName,
    appliedDiscountId,
    stackingMode,
    steps,
    metalHechuraBreakdown,
    componentSaleBreakdown,
    taxAmount,
    taxBreakdown,
    totalWithTax,
    taxExemptByEntity: entityTaxExempt,
    appliedRounding,
    costOverrideContext: Object.keys(overrideContext).length > 0 ? overrideContext : undefined,
  };

  return finalize(base, policyConfig);
}

// ---------------------------------------------------------------------------
// deriveMetalHechuraBreakdown — FASE 1 del refactor BREAKDOWN
// ---------------------------------------------------------------------------
// Helper puro (sin DB, sin Decimal) que decide cómo poblar
// `SalePriceResult.metalHechuraBreakdown` para que sea fuente única backend
// en TODOS los modos de lista. Garantía:
//
//   |metalSale + hechuraSale − basePrice| ≤ 0.01
//
// Reglas (en orden de prioridad):
//   1. `exactBreakdown` viene del PRICE_LIST METAL_HECHURA → `source = "METAL_HECHURA"`,
//      `*Estimated = false`. El motor confiable, no se altera nada.
//   2. `commercialMode = "COMBO_COMMERCIAL"` → `source = "COMBO_COMPONENTS"`.
//      El branch combo del motor agregó `metalCost`/`hechuraCost` desde los
//      componentes; acá se proporciona `metalSale`/`hechuraSale` por
//      proporción de costo.
//   3. `metalCost ≈ 0 && hechuraCost > 0` → `source = "SERVICE_AS_HECHURA"`,
//      `metalSale = 0`, `hechuraSale = basePrice`. Útil para artículos
//      tipo SERVICE o composiciones puras de hechura.
//   4. Precio manual sin costo (`priceSource ∈ {MANUAL_OVERRIDE, MANUAL_FALLBACK}`
//      y `costTotal ≈ 0`) → `source = "MANUAL_AS_HECHURA"`, todo a hechura.
//   5. `costTotal > 0` → `source = "PROPORTIONAL_COST"`, factor = basePrice/costTotal.
//   6. Cualquier otro caso → `null` (motor deja `partial = true`).
//
// Es PURA: tests unitarios la cubren sin necesidad de mocks de Prisma.
// ---------------------------------------------------------------------------

/** Shape exacto cuando el motor lo recibe del PRICE_LIST METAL_HECHURA. */
export type MetalHechuraExactDetail = {
  metalSale:         number;
  hechuraSale:       number;
  metalMarginPct:    number;
  hechuraMarginPct:  number;
  metalGramsBase?:    number | null;
  metalGramsSale?:    number | null;
  metalPricePerGram?: number | null;
  /** Sprint 3 — Gramos puros (post purity) base y de venta. POLICY.md §8. */
  pureGramsBase?:     number | null;
  pureGramsSale?:     number | null;
};

export interface DeriveMetalHechuraInput {
  /** Costo del metal (devuelve `costResult.metalCost`). */
  metalCost:       number;
  /** Costo de hechura/PRODUCT/SERVICE/MANUAL. */
  hechuraCost:     number;
  /** `costResult.value`. Cuando `0` o `null` no hay proporción posible. */
  costTotal:       number | null;
  /** `basePrice` post lista de precios, pre descuentos comerciales. */
  basePrice:       number | null;
  /** `priceSource` del motor (PRICE_LIST / MANUAL_OVERRIDE / etc.). */
  priceSource:     PriceSource;
  /** `article.commercialMode` — usado para detectar combos. */
  commercialMode:  string | null;
  /** Cuando viene exacto del paso PRICE_LIST METAL_HECHURA. Si está poblado,
   *  se usa tal cual y se etiqueta como `source = "METAL_HECHURA"`. */
  exactBreakdown?: MetalHechuraExactDetail | null;
  /**
   * Gramos del metal con merma aplicada (`costResult.metalGramsWithMerma`).
   * Cuando viene poblado y `metalCost > 0`, el helper deriva
   * `metalGramsSale` y `metalPricePerGram` también en los modos derivados
   * (MARGIN_TOTAL / PROPORTIONAL_COST / COMBO). Esto permite que la UI
   * muestre "X gr de venta" en el header del card metal sin importar el
   * modo de la lista.
   */
  metalGramsBase?: number | null;
  /**
   * Precio FINAL del metal después de descuentos por componente
   * (`componentSaleBreakdown.metal.final`). Cuando viene y difiere del
   * `metalSale` pre-descuento, el helper recalcula `metalGramsSale` con
   * este valor: `metalGramsSale = metalGramsBase × metalSaleFinal/metalCost`.
   * Es lo que la UI debe mostrar como "gramos de venta" reflejando
   * descuentos imputados al componente metal (ENTITY_RULE / promociones
   * con applyOn=METAL / etc.).
   */
  metalSaleFinal?: number | null;
  /** Análogo para hechura. */
  hechuraSaleFinal?: number | null;
}

export type MetalHechuraBreakdownResult = NonNullable<SalePriceResult["metalHechuraBreakdown"]>;

export function deriveMetalHechuraBreakdown(
  input: DeriveMetalHechuraInput,
): MetalHechuraBreakdownResult | null {
  const { metalCost, hechuraCost, costTotal, basePrice, priceSource, commercialMode, exactBreakdown } = input;

  // 1) Caso exacto: lista METAL_HECHURA con desglose por componente.
  if (exactBreakdown) {
    // Para los gramos preferimos `input.metalGramsBase` si viene poblado
    // (suma de `gramsFineEquivalent` = qty × pureza × merma). El campo
    // `exactBreakdown.metalGramsBase` (qty × merma sin pureza) queda como
    // fallback para casos legacy. Esto alinea el header del card metal del
    // Comparador con el `totalEquivGr` que usa el Simulador.
    const fineGramsBase    = input.metalGramsBase != null && input.metalGramsBase > 0
      ? input.metalGramsBase
      : (exactBreakdown.metalGramsBase ?? null);
    // El factor de venta usa `metalSaleFinal` (post-descuentos por
    // componente) cuando viene y difiere del `metalSale` exacto. Si no,
    // usa el `metalSale` original.
    const exactSaleEffective =
      input.metalSaleFinal != null && Math.abs(input.metalSaleFinal - exactBreakdown.metalSale) > 0.005
        ? input.metalSaleFinal
        : exactBreakdown.metalSale;
    let exactGramsSale:    number | null = exactBreakdown.metalGramsSale    ?? null;
    let exactPricePerGram: number | null = exactBreakdown.metalPricePerGram ?? null;
    if (fineGramsBase != null && fineGramsBase > 0 && metalCost > 0) {
      exactPricePerGram = parseFloat((metalCost / fineGramsBase).toFixed(6));
      exactGramsSale    = parseFloat((fineGramsBase * (exactSaleEffective / metalCost)).toFixed(6));
    }
    return {
      metalCost,
      hechuraCost,
      metalSale:         exactBreakdown.metalSale,
      hechuraSale:       exactBreakdown.hechuraSale,
      metalMarginPct:    exactBreakdown.metalMarginPct,
      hechuraMarginPct:  exactBreakdown.hechuraMarginPct,
      metalGramsBase:    fineGramsBase,
      metalGramsSale:    exactGramsSale,
      metalPricePerGram: exactPricePerGram,
      // Sprint 3 — POLICY.md §8 — passthrough de gramos puros del breakdown
      // de la lista. Si la lista no los emitió (purity heterogénea o ausente),
      // quedan null y el frontend muestra "—" (R4.4).
      pureGramsBase:     exactBreakdown.pureGramsBase ?? null,
      pureGramsSale:     exactBreakdown.pureGramsSale ?? null,
      metalSaleEstimated:   false,
      hechuraSaleEstimated: false,
      source:               "METAL_HECHURA",
    };
  }

  // Sin precio base no se puede derivar nada útil.
  if (basePrice == null) return null;

  const ε = 0.001;
  const ct = costTotal ?? 0;
  // Suma de componentes — denominador ideal del factor proporcional. Garantiza
  // que `metalSale + hechuraSale = basePrice` exacto, aun cuando el cost-engine
  // reporta `cost.value` con ajustes que difieren de `metalCost + hechuraCost`.
  const componentSum = metalCost + hechuraCost;

  let source: MetalHechuraBreakdownSource;
  let metalSaleD:   number;
  let hechuraSaleD: number;

  if (commercialMode === "COMBO_COMMERCIAL") {
    // 2) Combo: requiere componentSum > 0 (acumulado por el branch combo).
    //    Si la suma es 0, no se puede derivar.
    if (componentSum <= ε) return null;
    source = "COMBO_COMPONENTS";
    const factor = basePrice / componentSum;
    metalSaleD   = metalCost   * factor;
    hechuraSaleD = hechuraCost * factor;
  } else if (metalCost < ε && hechuraCost > ε) {
    // 3) Servicio o artículo sin metal.
    source = "SERVICE_AS_HECHURA";
    metalSaleD   = 0;
    hechuraSaleD = basePrice;
  } else if (
    (priceSource === "MANUAL_OVERRIDE" || priceSource === "MANUAL_FALLBACK") &&
    componentSum <= ε
  ) {
    // 4) Manual sin desglose útil.
    source = "MANUAL_AS_HECHURA";
    metalSaleD   = 0;
    hechuraSaleD = basePrice;
  } else if (componentSum > ε) {
    // 5) Proporción de costo. Funciona para MARGIN_TOTAL / COST_PER_GRAM /
    //    MANUAL con costo desglosado.
    source = "PROPORTIONAL_COST";
    const factor = basePrice / componentSum;
    metalSaleD   = metalCost   * factor;
    hechuraSaleD = hechuraCost * factor;
  } else if (ct > ε) {
    // 6) Hay cost.value pero sin desglose por componente (caso edge:
    //    cost-engine reportó un total sin separar metal/hechura). Tratamos
    //    todo como hechura — es la aproximación más segura.
    source = "MANUAL_AS_HECHURA";
    metalSaleD   = 0;
    hechuraSaleD = basePrice;
  } else {
    // 7) No se puede armar.
    return null;
  }

  // Gramos derivados — sólo cuando el cost-engine reporta gramos del metal
  // con merma. Permite que la UI muestre "X gr de venta" en el header del
  // card metal en modos derivados (MARGIN_TOTAL, COMBO, etc.).
  // Cuando `metalSaleFinal` viene poblado (post-descuentos por componente),
  // se usa para el factor — los gramos venta reflejan la realidad
  // post-descuentos.
  let metalGramsSale:    number | null = null;
  let metalPricePerGram: number | null = null;
  if (input.metalGramsBase != null && input.metalGramsBase > ε && metalCost > ε) {
    metalPricePerGram = parseFloat((metalCost / input.metalGramsBase).toFixed(6));
    const saleForGrams = input.metalSaleFinal != null && Math.abs(input.metalSaleFinal - metalSaleD) > 0.005
      ? input.metalSaleFinal
      : metalSaleD;
    metalGramsSale = parseFloat((input.metalGramsBase * (saleForGrams / metalCost)).toFixed(6));
  }

  return {
    metalCost,
    hechuraCost,
    metalSale:    parseFloat(metalSaleD.toFixed(6)),
    hechuraSale:  parseFloat(hechuraSaleD.toFixed(6)),
    // En modos derivados no hay un margen explícito por componente. La UI
    // que lo necesite puede inferirlo del costo total y `basePrice`.
    metalMarginPct:    0,
    hechuraMarginPct:  0,
    metalGramsBase:    input.metalGramsBase ?? null,
    metalGramsSale,
    metalPricePerGram,
    metalSaleEstimated:   true,
    hechuraSaleEstimated: true,
    source,
  };
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

  // Pre-cargar todos los artículos en una sola query batch (evita N+1)
  const needsCostCheck = config.blockLossSale || config.lowMarginBlockPercent != null || config.blockPartialData;
  type ArtCostRow = ArticleCostInput & { id: string };
  let articleMap = new Map<string, ArtCostRow>();
  let batchCtx: BatchCostContext | undefined;

  if (needsCostCheck && lines.length > 0) {
    const articleIds = [...new Set(lines.map(l => l.articleId))];
    const articles = await prisma.article.findMany({
      where: { id: { in: articleIds }, jewelryId, deletedAt: null },
      select: {
        id: true,
        manualAdjustmentKind: true,
        manualAdjustmentType: true,
        manualAdjustmentValue: true,
        costComposition: {
          select: {
            type: true, label: true,
            quantity: true, unitValue: true, currencyId: true, mermaPercent: true, metalVariantId: true,
            lineAdjKind: true, lineAdjType: true, lineAdjValue: true,
            catalogItem: { select: { code: true, sku: true } },
          },
        },
      },
    });
    articleMap = new Map(articles.map(a => [a.id, a as ArtCostRow]));
    batchCtx = await buildBatchCostContext(jewelryId, articles as ArticleCostInput[]);
  }

  for (const line of lines) {
    const blocking: string[] = [];
    const unitPrice = new D(String(line.unitPrice ?? 0));

    // ZERO_OR_NEGATIVE_PRICE
    if (config.blockZeroOrNegativePrice && unitPrice.lte(0)) {
      blocking.push("ZERO_OR_NEGATIVE_PRICE");
    }

    // Reglas basadas en costo (LOSS_SALE, LOW_MARGIN, PARTIAL_DATA)
    if (needsCostCheck) {
      const artCost = articleMap.get(line.articleId);

      if (artCost) {
        const costResult = await calculateCostFromLines(
          jewelryId,
          artCost.costComposition ?? [],
          {
            kind:  artCost.manualAdjustmentKind,
            type:  artCost.manualAdjustmentType,
            value: artCost.manualAdjustmentValue,
          },
          batchCtx,
        );

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

// ---------------------------------------------------------------------------
// buildPricingSnapshot — congela el resultado del motor en un objeto serializable
//
// Por qué:
//   SalePriceResult contiene Prisma.Decimal y estructuras internas que no
//   se pueden guardar en JSON directamente (PrismaJSON fields). Esta función
//   convierte el resultado a un objeto plano con solo los campos necesarios
//   para reconstruir la lógica de precio histórica.
//
// Uso:
//   const snap = buildPricingSnapshot(result);
//   await tx.saleLine.update({ data: { pricingSnapshot: snap as any } });
// ---------------------------------------------------------------------------

export function buildPricingSnapshot(result: SalePriceResult): PricingLineSnapshot {
  const mhb = result.metalHechuraBreakdown ?? null;
  return {
    snapshotVersion: PRICING_LINE_SNAPSHOT_VERSION,

    unitPrice:      result.unitPrice?.toNumber()     ?? null,
    basePrice:      result.basePrice?.toNumber()     ?? null,
    quantityDiscountAmount:  result.quantityDiscountAmount?.toNumber()  ?? null,
    promotionDiscountAmount: result.promotionDiscountAmount?.toNumber() ?? null,
    // Sprint 3 — POLICY.md §8 — capa 5 implementada. El motor lo expone
    // sumando solo DISCOUNT/BONUS de la rule comercial (no SURCHARGE,
    // no qty/promo/manual). Si no hubo regla aplicable, queda null.
    customerDiscountAmount:  result.customerDiscountAmount?.toNumber() ?? null,
    discountAmount: result.discountAmount.toNumber(),
    taxAmount:      result.taxAmount.toNumber(),
    totalWithTax:   result.totalWithTax?.toNumber()  ?? null,

    priceSource: result.priceSource as string,
    baseSource:  result.baseSource  as string,

    unitCost:      result.unitCost?.toNumber()      ?? null,
    unitMargin:    result.unitMargin?.toNumber()    ?? null,
    marginPercent: result.marginPercent?.toNumber() ?? null,
    costPartial:   result.costPartial,
    costMode:      result.costMode,

    partial:              result.partial,
    appliedPriceListId:   result.appliedPriceListId,
    appliedPriceListName: result.appliedPriceListName,
    appliedPriceListMode: result.appliedPriceListMode,
    appliedPromotionId:   result.appliedPromotionId,
    appliedPromotionName: result.appliedPromotionName,
    appliedDiscountId:    result.appliedDiscountId,

    metalHechuraBreakdown: mhb
      ? {
          metalCost:      mhb.metalCost,
          metalSale:      mhb.metalSale,
          hechuraCost:    mhb.hechuraCost,
          hechuraSale:    mhb.hechuraSale,
          metalGramsBase: mhb.metalGramsBase ?? null,
          metalGramsSale: mhb.metalGramsSale ?? null,
          // Sprint 1: motor todavía no propaga purity → null. Cuando se
          // implemente, calcular pureGramsBase = metalGramsBase × purity y
          // pureGramsSale = pureGramsBase × (1 + metalMarginPct/100).
          pureGramsBase:  mhb.pureGramsBase  ?? null,
          pureGramsSale:  mhb.pureGramsSale  ?? null,
          source:         mhb.source,
        }
      : null,

    costOverrideContext: result.costOverrideContext,

    resolvedAt: new Date().toISOString(),
  };
}
