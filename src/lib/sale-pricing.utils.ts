// src/lib/sale-pricing.utils.ts
// ── DEPRECATED ENTRYPOINT ────────────────────────────────────────────────────
// Usar src/lib/pricing-engine/ como fuente de verdad.
// Este archivo es un wrapper de compatibilidad que mantiene la API pública
// original (resolveSalePrice + SalePriceResult con strings) para no romper
// importadores existentes.
//
// La lógica real está en:
//   src/lib/pricing-engine/pricing-engine.sale.ts
//
// NOTA: SalePriceResult aquí usa string (legacy) en vez de Prisma.Decimal.
// Para nuevos consumidores, importar SalePriceResult directamente del motor.
//
// NO agregar lógica de negocio aquí. Todo cambio debe ir al motor.
// ─────────────────────────────────────────────────────────────────────────────

import { Prisma } from "@prisma/client";
import { resolveFinalSalePrice } from "./pricing-engine/pricing-engine.js";

// ---------------------------------------------------------------------------
// Tipos públicos (re-exportados para backward-compat)
// ---------------------------------------------------------------------------

/** Fuente del precio BASE (qué determinó el precio antes de descuentos). */
export type BasePriceSource =
  | "VARIANT_OVERRIDE"
  | "PRICE_LIST"
  | "MANUAL_OVERRIDE"
  | "MANUAL_FALLBACK"
  | "NONE";

/**
 * Fuente efectiva del precio final.
 * Refleja la última capa que modificó el precio.
 */
export type SalePriceSource =
  | "VARIANT_OVERRIDE"
  | "PRICE_LIST"
  | "MANUAL_OVERRIDE"
  | "MANUAL_FALLBACK"
  | "QUANTITY_DISCOUNT"
  | "PROMOTION"
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
  /** Fuente efectiva final — la última capa que modificó el precio. */
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
  categoryId?: string | null;
  quantity?:   number | string;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fmt(v: Prisma.Decimal | null | undefined): string | null {
  return v != null ? v.toFixed(4) : null;
}

function fmtTotal(v: Prisma.Decimal): string | null {
  return v.greaterThan(0) ? v.toFixed(4) : null;
}

// ---------------------------------------------------------------------------
// resolveSalePrice — wrapper sobre el motor centralizado
// ---------------------------------------------------------------------------

export async function resolveSalePrice(
  jewelryId: string,
  opts: SalePriceOpts
): Promise<SalePriceResult> {
  const result = await resolveFinalSalePrice(jewelryId, {
    articleId:  opts.articleId,
    variantId:  opts.variantId,
    clientId:   opts.clientId,
    categoryId: opts.categoryId,
    quantity:   typeof opts.quantity === "string"
      ? parseFloat(opts.quantity) || 1
      : (opts.quantity ?? 1),
  });

  // Convertir Decimal → string (formato heredado que el frontend espera)
  return {
    unitPrice:               fmt(result.unitPrice),
    basePrice:               fmt(result.basePrice),
    quantityDiscountAmount:  fmt(result.quantityDiscountAmount),
    promotionDiscountAmount: fmt(result.promotionDiscountAmount),
    discountAmount:          fmtTotal(result.discountAmount),
    priceSource:             result.priceSource as SalePriceSource,
    baseSource:              result.baseSource as BasePriceSource,
    appliedPriceListId:      result.appliedPriceListId,
    appliedPriceListName:    result.appliedPriceListName,
    appliedPromotionId:      result.appliedPromotionId,
    appliedPromotionName:    result.appliedPromotionName,
    appliedDiscountId:       result.appliedDiscountId,
    partial:                 result.partial,
    unitCost:                fmt(result.unitCost),
    unitMargin:              fmt(result.unitMargin),
    marginPercent:           fmt(result.marginPercent),
    costPartial:             result.costPartial,
    costMode:                result.costMode,
  };
}
