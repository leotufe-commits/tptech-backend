// src/lib/pricing-engine/pricing-engine.types.ts
// Tipos compartidos del motor de cálculo de costos y precios de TPTech.

import { Prisma } from "@prisma/client";

// ---------------------------------------------------------------------------
// PricingStep — trazabilidad de cada paso del cálculo
// ---------------------------------------------------------------------------

export type PricingStepStatus = "ok" | "partial" | "missing" | "skipped";

export interface PricingStep {
  /** Identificador corto del paso (e.g. "COST_LINES", "METAL_QUOTE", "PRICE_LIST") */
  key: string;
  /** Descripción legible del paso */
  label: string;
  /** Estado del paso */
  status: PricingStepStatus;
  /** Valor calculado en este paso (en moneda base), null si no disponible */
  value: Prisma.Decimal | null;
  /** Mensaje informativo o de error */
  message?: string;
  /** Datos extra (e.g. nombre de lista, fuente, etc.) */
  meta?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// PriceBreakdown — desglose Metal / Hechura del costo de artículo
// ---------------------------------------------------------------------------

export interface PriceBreakdownMetalItem {
  /** ID del metal padre (para agrupar en cuenta corriente) */
  metalId?: string | null;
  /** ID de la variante metálica */
  variantId?: string | null;
  /** Gramos originales (sin merma) */
  gramsOriginal?: number | null;
  /** Pureza de la variante (0–1). Null si no disponible. */
  purity?: number | null;
  /** Gramos puros = gramsOriginal × purity */
  gramsPure?: number | null;
  /** Equivalente en gramos finos = gramsOriginal × purity (alias canónico de gramsPure, persiste en breakdownSnapshot) */
  gramsFineEquivalent?: number | null;
  /** Cotización por gramo en moneda base */
  unitValue?: number | null;
  /** Costo total de esta línea metálica */
  totalValue: number;
}

export interface PriceBreakdownAdjustment {
  /** Tipo de ajuste */
  type: "BONUS" | "SURCHARGE" | "OTHER";
  /** Descripción legible */
  label: string;
  /** Monto del ajuste (positivo = recargo, negativo = bonificación) */
  amount: number;
}

export interface PriceBreakdown {
  /** Modo de cálculo que generó este desglose */
  mode: string;
  metal: {
    /** Componentes metálicos individuales */
    items: PriceBreakdownMetalItem[];
    /** Total metal en moneda base */
    total: number;
  };
  hechura: {
    /** Hechura base (antes de ajustes) */
    base: number;
    /** Ajustes imputados a hechura (impuestos, bonificaciones, recargos) */
    adjustments: PriceBreakdownAdjustment[];
    /** Total hechura = base + sum(adjustments) */
    total: number;
  };
  totals: {
    metal: number;
    hechura: number;
    /** = metal + hechura */
    unified: number;
  };
}

// ---------------------------------------------------------------------------
// CostResult — resultado del cálculo de costo de artículo
// ---------------------------------------------------------------------------

export interface CostResult {
  /** Costo final en moneda base. null si no se pudo calcular. */
  value: Prisma.Decimal | null;
  /** Modo de cálculo que se utilizó */
  mode: string;
  /** true si el resultado es aproximado por falta de datos (cotizaciones, etc.) */
  partial: boolean;
  /** Pasos del cálculo (para depuración / UI) */
  steps: PricingStep[];
  // Desglose opcional (disponible en modos METAL_MERMA_HECHURA y COST_LINES)
  metalCost?: Prisma.Decimal | null;
  hechuraCost?: Prisma.Decimal | null;
  totalGrams?: Prisma.Decimal | null;
  /** Desglose Metal/Hechura estructurado. Disponible cuando value != null. */
  breakdown?: PriceBreakdown | null;
}

// ---------------------------------------------------------------------------
// TaxBreakdownItem — resultado del cálculo de un impuesto individual
// ---------------------------------------------------------------------------

export interface TaxBreakdownItem {
  taxId: string;
  name: string;
  code: string;
  taxType: string;
  calculationType: string;
  /** Base de aplicación del impuesto (puede ser la del Tax o la del override de entidad) */
  applyOn: string;
  /** true cuando la base de aplicación fue sobreescrita por la configuración de la entidad */
  applyOnOverriddenByEntity?: boolean;
  /**
   * Fuente del override de base de aplicación:
   * - "INDIVIDUAL": un EntityTaxOverride puntual para este impuesto
   * - "GLOBAL": el taxApplyOnOverride global de la entidad
   * - undefined: sin override (se heredó del Tax base)
   */
  entityOverrideSource?: "INDIVIDUAL" | "GLOBAL";
  /** Base monetaria sobre la que se calculó el impuesto */
  base: number;
  /** true si la base fue estimada (p.ej. metal sin lista METAL_HECHURA) */
  baseEstimated: boolean;
  /** Tasa porcentual (para PERCENTAGE y PERCENTAGE_PLUS_FIXED) */
  rate: number | null;
  /** Monto fijo (para FIXED_AMOUNT y PERCENTAGE_PLUS_FIXED) */
  fixedAmount: number | null;
  /** Monto final de este impuesto */
  taxAmount: number;
}

// ---------------------------------------------------------------------------
// SalePriceResult — resultado completo del motor de precio de venta
// ---------------------------------------------------------------------------

export type PriceSource =
  | "PROMOTION"
  | "MANUAL_OVERRIDE"
  | "QUANTITY_DISCOUNT"
  | "PRICE_LIST"
  | "MANUAL_FALLBACK"
  | "NONE";

export interface SalePriceResult {
  // ── Precios ──────────────────────────────────────────────────────────────
  /** Precio unitario final (en moneda base) */
  unitPrice: Prisma.Decimal | null;
  /** Precio base antes de descuentos (de lista o fallback) */
  basePrice: Prisma.Decimal | null;
  /** Descuento aplicado por cantidad (null si no aplica) */
  quantityDiscountAmount: Prisma.Decimal | null;
  /** Descuento aplicado por promoción (null si no aplica) */
  promotionDiscountAmount: Prisma.Decimal | null;
  /** Monto total descontado (qty + promo) */
  discountAmount: Prisma.Decimal;

  // ── Fuente del precio ─────────────────────────────────────────────────────
  /** Fuente efectiva final (última capa que modificó el precio) */
  priceSource: PriceSource;
  /** Fuente del precio BASE antes de descuentos */
  baseSource: PriceSource;

  // ── Costo y margen ────────────────────────────────────────────────────────
  /** Costo unitario real (motor de costo). Null si no disponible. */
  unitCost: Prisma.Decimal | null;
  /** Margen unitario = unitPrice − unitCost. Null si sin costo. */
  unitMargin: Prisma.Decimal | null;
  /** Margen % sobre precio final. Null si sin costo. */
  marginPercent: Prisma.Decimal | null;
  /** true cuando el costo no pudo resolverse completamente */
  costPartial: boolean;
  /** Modo de cálculo de costo: MANUAL | MULTIPLIER | METAL_MERMA_HECHURA | COST_LINES | NONE */
  costMode: string;

  // ── Metadatos ─────────────────────────────────────────────────────────────
  /** true si algún precio es aproximado (lista sin datos suficientes) */
  partial: boolean;
  appliedPriceListId: string | null;
  appliedPriceListName: string | null;
  appliedPromotionId: string | null;
  appliedPromotionName: string | null;
  appliedDiscountId: string | null;
  /** Pasos del cálculo (para depuración / UI) */
  steps: PricingStep[];
  /** Alertas de negocio generadas por el motor (errores + advertencias) */
  alerts: PricingAlert[];
  /** Evaluación de la política de confirmación de venta */
  policy: PricingPolicyResult;
  /**
   * Modo de resolución cuando coexisten descuento por cantidad y promoción:
   * - CHAINED:       ambos acumulables → se encadenaron (QD primero, luego Promo)
   * - BEST_OF_QD:    no acumulables → ganó descuento por cantidad (menor precio)
   * - BEST_OF_PROMO: no acumulables → ganó la promoción (menor precio)
   * - NONE:          solo uno o ninguno aplicó, sin conflicto
   */
  stackingMode: "CHAINED" | "BEST_OF_QD" | "BEST_OF_PROMO" | "NONE";
  /**
   * Desglose Metal/Hechura del precio de venta.
   * Solo disponible cuando la lista activa usa mode=METAL_HECHURA y el costo
   * tiene metalCost + hechuraCost resueltos.
   */
  metalHechuraBreakdown?: {
    metalCost:        number;
    metalSale:        number;
    metalMarginPct:   number;
    hechuraCost:      number;
    hechuraSale:      number;
    hechuraMarginPct: number;
  } | null;

  // ── Impuestos ─────────────────────────────────────────────────────────────
  /** Suma total de todos los impuestos aplicados (en moneda base) */
  taxAmount: Prisma.Decimal;
  /** Desglose por impuesto individual */
  taxBreakdown: TaxBreakdownItem[];
  /** Precio unitario + impuestos. null si no hay precio. */
  totalWithTax: Prisma.Decimal | null;
  /** true cuando la entidad (cliente/proveedor) tiene taxExempt=true → impuestos omitidos */
  taxExemptByEntity: boolean;
}

// ---------------------------------------------------------------------------
// PricingAlert — alertas de negocio generadas por el motor
// ---------------------------------------------------------------------------

export type PricingAlertLevel = "info" | "warning" | "error";

export interface PricingAlert {
  /** Código de la alerta (e.g. "LOSS_SALE", "LOW_MARGIN") */
  code: string;
  /** Nivel de severidad */
  level: PricingAlertLevel;
  /** Mensaje legible en español */
  message: string;
}

// ---------------------------------------------------------------------------
// PricingPolicyResult — evaluación de política de confirmación de venta
// ---------------------------------------------------------------------------

export interface PricingPolicyResult {
  /** true si la venta puede confirmarse según la política del tenant */
  canConfirm: boolean;
  /** Códigos de alertas que están bloqueando la confirmación */
  blockingAlerts: string[];
}

// ---------------------------------------------------------------------------
// Tipos de entrada del motor de costo
// ---------------------------------------------------------------------------

export interface CostLineInput {
  type: string;           // "METAL" | "HECHURA" | "PRODUCT" | "SERVICE" | "MANUAL"
  /** Descripción/nombre de la línea ingresado por el usuario */
  label?: string | null;
  /** Código del artículo referenciado (catalogItem.code), solo para PRODUCT/SERVICE */
  lineCode?: string | null;
  quantity: any;
  unitValue: any;
  currencyId: string | null;
  mermaPercent: any;
  metalVariantId: string | null;
  /** Ajuste por línea: "" | "BONUS" | "SURCHARGE" */
  lineAdjKind?: string | null;
  /** Tipo de valor del ajuste: "" | "PERCENTAGE" | "FIXED_AMOUNT" */
  lineAdjType?: string | null;
  /** Valor del ajuste (porcentaje o monto fijo) */
  lineAdjValue?: any;
}

export interface CompositionInput {
  variantId: string;
  grams: any;
  isBase: boolean;
}

export interface ArticleCostInput {
  costCalculationMode: string;
  costPrice: any;
  manualCurrencyId?: string | null;
  manualBaseCost?: any;
  manualAdjustmentKind?: string | null;
  manualAdjustmentType?: string | null;
  manualAdjustmentValue?: any;
  multiplierBase: string | null;
  multiplierValue: any;
  multiplierQuantity: any;
  multiplierCurrencyId?: string | null;
  hechuraPrice: any;
  hechuraPriceMode: string;
  mermaPercent: any;
  compositions?: CompositionInput[];
  category?: { mermaPercent?: any } | null;
  costComposition?: CostLineInput[];
}

// ---------------------------------------------------------------------------
// CheckoutResult — capa de pago sobre el precio comercial
// ---------------------------------------------------------------------------

export interface CheckoutStep {
  /** Código del paso (e.g. "CHECKOUT_BASE", "PAYMENT_ADJUSTMENT") */
  code: string;
  /** Descripción legible */
  label: string;
  /** Fórmula legible para mostrar en UI (e.g. "1000 × 5% = 50") */
  formula: string;
  /** Monto resultante de este paso */
  amount: number;
  /** Código de moneda (e.g. "ARS") */
  currencyCode: string;
}

export interface CheckoutResult {
  /** Precio comercial base (unitPrice × quantity) */
  baseAmount: number;
  /** Ajuste por forma de pago (positivo = recargo, negativo = descuento) */
  paymentAdjustment: number;
  /** Total final = baseAmount + paymentAdjustment */
  finalAmount: number;
  /** Cantidad de cuotas (si aplica) */
  installments?: number;
  /** Monto por cuota (si aplica) */
  installmentAmount?: number;
  /** Pasos del cálculo para trazabilidad / UI */
  steps: CheckoutStep[];
}

export interface CheckoutPaymentMethod {
  /** Tipo de ajuste por forma de pago */
  adjustmentType: "PERCENTAGE" | "FIXED";
  /** Valor del ajuste (positivo = recargo, negativo = descuento) */
  adjustmentValue: number;
  /** Nombre del medio de pago (para mostrar en steps) */
  name?: string;
}

export interface CheckoutInstallments {
  /** Cantidad de cuotas (debe ser ≥ 1) */
  quantity: number;
  /** Descripción del plan (para mostrar en steps, opcional) */
  label?: string;
}

export interface CheckoutOpts {
  /** Precio unitario final del motor comercial */
  unitPrice: number;
  /** Cantidad de artículos */
  quantity?: number;
  /** Código de moneda base para mostrar en steps */
  currencyCode?: string;
  /** Forma de pago con su ajuste */
  paymentMethod?: CheckoutPaymentMethod;
  /** Plan de cuotas */
  installments?: CheckoutInstallments;
}

// ---------------------------------------------------------------------------
// Tipos de entrada del motor de venta
// ---------------------------------------------------------------------------

export interface SalePriceOpts {
  articleId: string;
  variantId?: string | null;
  clientId?: string | null;
  categoryId?: string | null;
  quantity?: number;
  /** Si se indica, fuerza el uso de esa lista en lugar de resolver la cadena normal. Solo para simulación. */
  priceListIdOverride?: string | null;
  /**
   * Cantidad total de artículos de la misma categoría en el comprobante.
   * Usado cuando un QuantityDiscount tiene evaluationMode = CATEGORY_TOTAL.
   * Si no se provee, cae a quantity (comportamiento LINE).
   */
  categoryTotal?: number;
  /**
   * Cantidad total de artículos de la misma marca en el comprobante.
   * Usado cuando un QuantityDiscount tiene evaluationMode = BRAND_TOTAL.
   * Si no se provee, cae a quantity (comportamiento LINE).
   */
  brandTotal?: number;
  /**
   * Cantidad total de artículos del mismo grupo en el comprobante.
   * Usado cuando un QuantityDiscount tiene evaluationMode = GROUP_TOTAL.
   * Si no se provee, cae a quantity (comportamiento LINE).
   */
  groupTotal?: number;
  /**
   * Solo para simulación: restringe qué descuentos por cantidad considera el motor.
   * Si no se provee, el motor usa todos los aplicables (comportamiento normal).
   */
  quantityDiscountIds?: string[];
}
