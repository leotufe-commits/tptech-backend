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
  /** Gramos de metal incluidos en metalCost, ya con merma aplicada (qty × mermaFactor).
   *  Permite derivar pricePerGram = metalCost / metalGramsWithMerma en el lado de venta. */
  metalGramsWithMerma?: Prisma.Decimal | null;
  /** Sprint 3 — Pureza efectiva del metal (Decimal 0-1, ej: 0.750 para 18K).
   *  null si hay múltiples variantes con purity distinta o si no hay metal.
   *  Alimenta `pureGramsBase` en el `metalHechuraBreakdown`. POLICY.md §8. */
  metalPurity?: Prisma.Decimal | null;
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
// ComponentSaleBreakdown — desglose Metal/Hechura post-descuentos por componente
// ---------------------------------------------------------------------------

/** Tipo de la capa que generó este ajuste sobre el componente. */
export type ComponentAdjustmentKind =
  | "QUANTITY_DISCOUNT"
  | "PROMOTION"
  | "ENTITY_RULE"
  | "MANUAL_DISCOUNT";

/** Un ajuste imputado a un componente (METAL o HECHURA). `amount` es positivo
 *  cuando reduce el precio (descuento/bonificación) y negativo cuando lo
 *  aumenta (recargo). */
export interface ComponentSaleAdjustment {
  kind:    ComponentAdjustmentKind;
  /** Etiqueta legible para mostrar en la UI (ej. "Promoción Verano",
   *  "Desc. ×3 u.", "Cliente Mayorista"). */
  label:   string;
  /** Monto del ajuste en moneda base. Convención: positivo = reduce precio. */
  amount:  number;
  /** Componente al que se aplica el ajuste. */
  applyOn: "METAL" | "HECHURA";
  // ── Metadata para la UI (opcional) ─────────────────────────────────────
  // Permiten que el frontend muestre la fórmula "Base × % = monto" sin
  // tener que reconstruirla desde otros campos. Se popula cuando el motor
  // tiene la información (descuentos PERCENTAGE) y queda `null` cuando no
  // aplica (descuento fijo, ajuste manual sin base, etc.).
  /** Base monetaria sobre la que se calculó el ajuste (porción del precio
   *  imputada al componente, en moneda base). */
  base?:       number | null;
  /** Porcentaje aplicado, sólo cuando `valueType === "PERCENTAGE"`. */
  percentage?: number | null;
  /** Tipo de valor del ajuste tal como vino del motor. */
  valueType?:  "PERCENTAGE" | "FIXED_AMOUNT" | string | null;
  /** Origen de negocio del ajuste. Útil para etiquetar en UI:
   *   - "CLIENT":  condición comercial de la entidad cliente.
   *   - "GENERAL": regla global del tenant (qty discount, promoción, manual).
   *  No es exhaustivo; puede crecer en el futuro. */
  source?:     "CLIENT" | "GENERAL" | string | null;
}

/** Desglose de un componente: precio base (post-lista, pre-descuento), lista
 *  de ajustes que lo afectan y precio final (post-descuentos). */
export interface ComponentSaleBreakdown {
  base:        number;
  adjustments: ComponentSaleAdjustment[];
  final:       number;
}

export interface ComponentSaleDetail {
  metal:   ComponentSaleBreakdown;
  hechura: ComponentSaleBreakdown;
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
  // FASE 1.1 G1 — línea MANUAL sin articleId (ítem libre / servicio puntual).
  // El motor todavía la procesa fuera del flow normal en sales.service.ts:2349
  // y devuelve un snapshot sintético con priceSource="MANUAL_LINE". Está en el
  // union para que TypeScript no obligue el cast `as any` (POLICY §3 R3.6).
  | "MANUAL_LINE"
  | "NONE";

/**
 * Origen del `metalHechuraBreakdown` (FASE 1 del refactor BREAKDOWN).
 * Permite a la UI distinguir cuándo los componentes son exactos vs derivados.
 */
export type MetalHechuraBreakdownSource =
  /** Lista en modo `METAL_HECHURA` con costo desglosado — exacto. */
  | "METAL_HECHURA"
  /** MARGIN_TOTAL / COST_PER_GRAM / MANUAL con costo desglosado — derivado
   *  por proporción `metalCost / hechuraCost`. */
  | "PROPORTIONAL_COST"
  /** Precio manual sin costo útil (cost.value = 0 o null) — todo a hechura. */
  | "MANUAL_AS_HECHURA"
  /** Artículo sin metal (`metalCost = 0`, `hechuraCost > 0`) — todo a hechura. */
  | "SERVICE_AS_HECHURA"
  /** Combo comercial — sumado de los `metalHechuraBreakdown` de cada
   *  componente. */
  | "COMBO_COMPONENTS"
  /** No se pudo armar el breakdown (datos faltantes). El motor deja
   *  `metalHechuraBreakdown = null` y marca `partial = true`. */
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
  /**
   * Sprint 3 — Descuento por regla comercial del cliente / categoría /
   * canal-jerárquico (capa 5 del orden inmutable). null cuando no hay
   * regla aplicada de tipo DISCOUNT/BONUS.
   *
   * Alcance EXCLUSIVO de este campo:
   *   - Incluye SOLO descuentos comerciales de la capa 5 (rule del cliente
   *     con `ruleType ∈ {DISCOUNT, BONUS}`), independientemente del
   *     `applyOn` (TOTAL, METAL, HECHURA, METAL_Y_HECHURA, etc.).
   *   - NO incluye `quantityDiscountAmount` (capa 4 — descuento por cantidad).
   *   - NO incluye `promotionDiscountAmount` (capa 3 — promociones).
   *   - NO incluye SURCHARGES (recargos del cliente; convención: el campo
   *     es de descuento, no monto neto).
   *   - NO incluye descuentos manuales (`manualDiscountOverride` se aplica
   *     en una capa posterior y queda fuera).
   *
   * POLICY.md §8 — campo persistible para que el frontend lo lea sin derivar.
   */
  customerDiscountAmount: Prisma.Decimal | null;
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
  /** Modo de cálculo de costo: COST_LINES | NONE */
  costMode: string;

  // ── Metadatos ─────────────────────────────────────────────────────────────
  /** true si algún precio es aproximado (lista sin datos suficientes) */
  partial: boolean;
  appliedPriceListId: string | null;
  appliedPriceListName: string | null;
  /** Modo de la lista efectivamente aplicada ("METAL_HECHURA", "MARGIN_TOTAL",
   *  etc.). Permite a la UI ramificar el render entre desglose por componente
   *  y margen unificado. `null` cuando no se resolvió lista (precio manual o
   *  fallback). */
  appliedPriceListMode: string | null;
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
   *
   * FASE 1 — fuente única backend: el motor lo popula SIEMPRE que haya
   * `costResult.metalCost` y `costResult.hechuraCost` resueltos, sea cual
   * sea el modo de lista. Cuando la lista no expone `metalSale`/`hechuraSale`
   * exactos (todo modo distinto a `METAL_HECHURA`), el motor los deriva por
   * proporción de costo y marca `*Estimated = true`.
   *
   * Garantía:
   *   |metalSale + hechuraSale − basePrice| ≤ 0.01
   * Si no se puede armar (cost null, basePrice null), el campo queda `null`
   * y `partial = true`.
   */
  metalHechuraBreakdown?: {
    metalCost:         number;
    metalSale:         number;
    metalMarginPct:    number;
    hechuraCost:       number;
    hechuraSale:       number;
    hechuraMarginPct:  number;
    /** Gramos con merma usados en el costo del metal (base real antes del margen) */
    metalGramsBase?:    number | null;
    /** Gramos de venta = metalGramsBase × (1 + metalMarginPct/100) */
    metalGramsSale?:    number | null;
    /** Precio por gramo base = metalCost / metalGramsBase */
    metalPricePerGram?: number | null;
    /** Gramos puros base = metalGramsBase × purity. null si purity no disponible
     *  (en Sprint 1 el motor todavía no propaga purity → siempre null). */
    pureGramsBase?:     number | null;
    /** Gramos puros de venta = pureGramsBase × (1 + metalMarginPct/100).
     *  null si pureGramsBase null. POLICY.md §8 — campo persistible. */
    pureGramsSale?:     number | null;
    /** FASE 1 — `true` cuando `metalSale` se derivó por proporción de costo
     *  (no surge directo del paso PRICE_LIST METAL_HECHURA). */
    metalSaleEstimated?:   boolean;
    /** FASE 1 — análogo para hechura. */
    hechuraSaleEstimated?: boolean;
    /** FASE 1 — trazabilidad de cómo se llegó al breakdown. La UI puede
     *  ramificar el render según este valor. */
    source?: MetalHechuraBreakdownSource;
  } | null;

  /**
   * Desglose por componente con descuentos imputados.
   *
   * Mismo origen que `metalHechuraBreakdown` (sólo se popula cuando hay
   * desglose Metal/Hechura), pero rola los descuentos `applyOn = METAL | HECHURA`
   * sobre el componente correspondiente. Permite a la UI mostrar el card
   * "Hechura" con base, lista de ajustes y subtotal final, sin re-calcular.
   *
   * Importante: los descuentos con `applyOn = TOTAL | PRODUCT | SERVICE | METAL_Y_HECHURA`
   * NO entran en este desglose (son a nivel total y se muestran fuera del
   * card por componente).
   *
   * `null` cuando no hay desglose Metal/Hechura disponible (lista en modo
   * MARGIN_TOTAL, precio manual, fallback, etc.).
   */
  componentSaleBreakdown?: ComponentSaleDetail | null;

  // ── Impuestos ─────────────────────────────────────────────────────────────
  /** Suma total de todos los impuestos aplicados (en moneda base) */
  taxAmount: Prisma.Decimal;
  /** Desglose por impuesto individual */
  taxBreakdown: TaxBreakdownItem[];
  /** Precio unitario + impuestos. null si no hay precio. */
  totalWithTax: Prisma.Decimal | null;
  /** true cuando la entidad (cliente/proveedor) tiene taxExempt=true → impuestos omitidos */
  taxExemptByEntity: boolean;

  /**
   * Redondeo efectivamente aplicado por la lista de precios.
   *
   * Se popula SOLO cuando `applyRounding` modificó el valor (preRounding ≠
   * postRounding). El motor lo expone para que la UI pueda mostrar
   * "Redondeo por lista: …" sin tener que reconstruir la información a
   * partir de `steps[].meta`. Cuando la lista no tiene redondeo activo o
   * cuando el redondeo no cambió el valor, el campo es `null`.
   *
   *  - applyOn=PRICE: rondea el `basePrice` (antes de descuentos).
   *  - applyOn=NET:   rondea el `unitPrice` final (post descuentos, pre tax).
   *  - applyOn=TOTAL: rondea el `totalWithTax` por unidad.
   */
  appliedRounding: {
    applyOn:      "PRICE" | "NET" | "TOTAL";
    mode:         string;
    direction:    string;
    preRounding:  Prisma.Decimal;
    postRounding: Prisma.Decimal;
    priceListId:   string | null;
    priceListName: string | null;
  } | null;

  /**
   * Contexto de overrides de composición de costo aplicados a este preview.
   * Sirve para que la UI muestre "Original X / Usado en factura Y" sin
   * volver a consultar el artículo. Cada campo es opcional — solo se
   * popula si tiene un valor original o un override aplicado distinto.
   *
   * IMPORTANTE: estos valores NO se persisten en `Article` ni en
   * `ArticleCostLine`. Son solo del preview de la línea actual.
   */
  costOverrideContext?: {
    grams?: {
      original: number | null;
      applied:  number | null;
      manual:   boolean;
    };
    mermaPercent?: {
      original: number | null;
      applied:  number | null;
      manual:   boolean;
    };
    metalVariant?: {
      originalId: string | null;
      appliedId:  string | null;
      manual:     boolean;
    };
    hechura?: {
      original: number | null;
      applied:  number | null;
      manual:   boolean;
    };
  };
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
// BatchCostContext — contexto pre-cargado para cálculo en batch (sin N+1)
// ---------------------------------------------------------------------------

export interface BatchCostContext {
  /** Moneda base del tenant */
  baseCurrencyId: string;
  /** Merma por defecto de la joyería (fallback cuando el artículo no tiene una) */
  defaultMermaPercent: any;
  /**
   * variantId → { price: finalSalePrice, saleFactor, purity }
   * Cargado en batch antes del loop; evita N queries de metalQuote + metalVariant.
   * Sprint 3 — `purity` opcional (Decimal 0-1) para alimentar pureGramsBase
   * en el breakdown del precio de venta. POLICY.md §8.
   */
  metalVariantData: Map<string, { price: Prisma.Decimal; saleFactor: Prisma.Decimal; purity?: Prisma.Decimal | null }>;
  /**
   * currencyId → { rate, code, symbol }
   * Tasas de cambio pre-cargadas para conversión de moneda sin queries en loop.
   */
  rateMap: Map<string, { rate: Prisma.Decimal; code: string; symbol: string }>;
  /**
   * articleId → set de `metalVariantId` presentes en su composición de costo
   * (líneas tipo METAL con `metalVariantId` poblado). Usado por la evaluación
   * de scope METALS en promociones, cupones y descuentos por cantidad.
   * v1: NO se propagan metales desde componentes de combos comerciales.
   */
  articleMetalVariantsMap: Map<string, string[]>;
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
  /** Moneda del valor unitario; null = moneda base del tenant */
  currencyId?: string | null;
  /** Merma en porcentaje; solo relevante para type=METAL */
  mermaPercent?: any;
  /** ID de variante metálica; solo para type=METAL */
  metalVariantId?: string | null;
  /**
   * FASE 2: variante específica del componente referenciado (PRODUCT/SERVICE).
   * Si está presente, su `articleId` debe coincidir con `catalogItemId`. Hoy
   * el motor de costo solo lo usa para resolver `weightOverride` cuando aplica;
   * el resto del cálculo se sigue derivando del padre.
   */
  catalogVariantId?: string | null;
  /** Ajuste por línea: "" | "BONUS" | "SURCHARGE" */
  lineAdjKind?: string | null;
  /** Tipo de valor del ajuste: "" | "PERCENTAGE" | "FIXED_AMOUNT" */
  lineAdjType?: string | null;
  /** Valor del ajuste (porcentaje o monto fijo) */
  lineAdjValue?: any;
}

export interface ArticleCostInput {
  /** Líneas de composición de costo. Única fuente de verdad del costo. */
  costComposition: CostLineInput[];

  // ── Ajuste global sobre el total de COST_LINES ───────────────────────────
  manualAdjustmentKind?: string | null;   // "BONUS" | "SURCHARGE"
  manualAdjustmentType?: string | null;   // "PERCENTAGE" | "FIXED_AMOUNT"
  manualAdjustmentValue?: any;
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
  /**
   * Solo para simulación: líneas de costo extra inyectadas al cálculo (no persisten).
   * Útil para "what-if" de envío/logística sin modificar el artículo.
   * Se concatenan después de las líneas reales del artículo.
   */
  extraCostLines?: CostLineInput[];
  /**
   * Override manual del impuesto a nivel línea. Reemplaza por completo el
   * cálculo de impuestos del motor con un único item sintético. La UI lo usa
   * cuando el operador edita manualmente el impuesto desde la línea.
   *   - mode "PERCENT" + value 21 → IVA 21% sobre el precio neto.
   *   - mode "AMOUNT" + value 100 → impuesto fijo de 100 sobre el precio neto.
   *   - appliesTo opcional: define la base imponible del item sintético.
   *     Default "TOTAL". Mismas opciones que `applyOn` del Tax model.
   */
  taxOverride?: {
    mode: "PERCENT" | "AMOUNT";
    value: number;
    appliesTo?: "METAL" | "HECHURA" | "PRODUCT" | "SERVICE" | "TOTAL";
  } | null;
  /**
   * Override manual del precio neto unitario (sin impuestos). Pisa el
   * resultado del paso PRICE_LIST y desactiva descuentos por cantidad y
   * promociones (porque el operador fijó el precio explícitamente). El
   * `priceSource` resultante es "MANUAL_OVERRIDE".
   *
   * Útil cuando el vendedor negocia un precio puntual con el cliente sin
   * tocar la lista ni la configuración del artículo.
   */
  manualPriceOverride?: number | null;
  /**
   * Override manual del descuento aplicado sobre el precio de lista.
   * Reemplaza qty discount + promotion con un único monto manual.
   *   - mode "PERCENT" + value 15 → 15% sobre `basePrice`.
   *   - mode "AMOUNT"  + value 100 → 100 unitario sobre `basePrice`.
   *
   * Si convive con `manualPriceOverride`, gana el manualPrice (porque ese
   * ya define el unitPrice final, no hace falta un descuento separado).
   */
  manualDiscountOverride?: {
    mode: "PERCENT" | "AMOUNT";
    value: number;
    /**
     * Define sobre qué porción del basePrice se aplica el descuento. Default
     * "TOTAL" (descuento sobre el precio completo). METAL / HECHURA /
     * PRODUCT / SERVICE descuentan solo de la porción correspondiente.
     */
    appliesTo?: "METAL" | "HECHURA" | "PRODUCT" | "SERVICE" | "TOTAL";
  } | null;

  // ─────────────────────────────────────────────────────────────────────
  // Overrides de COMPOSICIÓN DE COSTO a nivel línea (Fase 2).
  //
  // REGLA CRÍTICA: estos overrides NO modifican el artículo en DB. El motor
  // hace una COPIA en memoria de la `costComposition` original, le aplica
  // los overrides, y calcula sobre la copia. La ficha del artículo queda
  // intacta. Cada override es individual y opcional.
  // ─────────────────────────────────────────────────────────────────────

  /**
   * Pisa los gramos (`quantity`) de la línea METAL del artículo. La ficha
   * sigue diciendo 2g; el motor calcula con el valor del override.
   */
  gramsOverride?: number | null;

  /**
   * Pisa el `mermaPercent` de la línea METAL. Si la línea no tenía merma,
   * se la agregamos. La merma global del tenant / artículo no se modifica.
   */
  mermaPercentOverride?: number | null;

  /**
   * Pisa el `metalVariantId` de la línea METAL. El motor toma la cotización
   * vigente del nuevo metal y recalcula. Si el id no existe → ignora el
   * override.
   */
  metalVariantIdOverride?: string | null;

  /**
   * Pisa el monto unitario de la línea HECHURA. Setea `quantity=1` y
   * `unitValue=hechuraOverrideAmount`. La hechura del artículo no se
   * modifica.
   */
  hechuraOverrideAmount?: number | null;
  /**
   * Uso INTERNO del motor — no debe ser provisto por callers externos.
   * Cuando un combo comercial resuelve el precio de sus componentes invoca
   * recursivamente resolveFinalSalePrice. Este campo lleva el contexto para
   * detectar ciclos / limitar profundidad y evitar pricing infinito.
   */
  _comboContext?: { depth: number; visited: Set<string> };

  /**
   * Anti doble redondeo a nivel comprobante.
   *
   * Cuando el tenant tiene `documentRoundingEnabled = true`, el caller
   * (sales.service) pasa `true` aquí para que el motor IGNORE el redondeo
   * diferido (`roundingApplyOn = NET | TOTAL`) que la lista de precios
   * pudiera tener configurado. El redondeo se aplica una sola vez, a nivel
   * documento, en `computeSaleDocumentTotals`.
   *
   * El redondeo `roundingApplyOn = PRICE` de la lista NO se afecta — ese
   * actúa sobre el precio de lista antes de descuentos y no compite con el
   * redondeo doc.
   */
  suppressListDeferredRounding?: boolean;
}

// ---------------------------------------------------------------------------
// CostSnapshot — costo congelado al confirmar un documento de compra
//
// Propósito:
//   Versión simplificada de PricingLineSnapshot orientada a flujos de costo
//   (compras, recepciones, órdenes de compra). No incluye datos de precio de
//   venta ni de descuentos/promociones comerciales.
//
// Uso típico:
//   const snap = buildCostSnapshot(costResult);
//   await tx.purchaseLine.update({ data: { pricingSnapshot: snap as any } });
// ---------------------------------------------------------------------------

export interface CostSnapshot {
  /** Costo unitario en moneda base. null si no se pudo calcular. */
  unitCost:    number | null;
  /** Modo de cálculo del costo (COST_LINES | NONE | ...) */
  costMode:    string;
  /** true cuando el costo es aproximado por falta de datos (cotizaciones, etc.) */
  costPartial: boolean;
  /** Timestamp ISO-8601 del momento en que se congeló el costo */
  resolvedAt:  string;
}

// ---------------------------------------------------------------------------
// PricingLineSnapshot — precio congelado al confirmar un documento
//
// Propósito:
//   Guardar una foto serializable del resultado del motor en el momento exacto
//   en que se confirma una venta, presupuesto, compra u otro documento. Permite
//   reconstruir la lógica de precios histórica sin depender de datos actuales.
//
// Uso típico:
//   const snap = buildPricingSnapshot(await resolveFinalSalePrice(opts));
//   await tx.saleLine.update({ data: { pricingSnapshot: snap as any } });
// ---------------------------------------------------------------------------

export interface PricingLineSnapshot {
  // ── Versión del shape ─────────────────────────────────────────────────────
  /** Versión del shape del snapshot. Snapshots <2 no tienen los campos nuevos
   *  (quantity/promotion/customerDiscountAmount, metalHechuraBreakdown,
   *  costOverrideContext). Bump al agregar/cambiar campos. POLICY.md §2.5. */
  snapshotVersion?: number;

  // ── Precios en moneda base ────────────────────────────────────────────────
  unitPrice:      number | null;
  basePrice:      number | null;
  /** Descuento por cantidad (capa 4). null si no aplica. */
  quantityDiscountAmount?:  number | null;
  /** Descuento por promoción (capa 3). null si no aplica. */
  promotionDiscountAmount?: number | null;
  /** Descuento por cliente / categoría / canal-jerárquico (capa 5).
   *  En Sprint 1 SIEMPRE null — la capa todavía no se computa en el motor.
   *  Cuando exista, viajará acá como campo singular para que el frontend NO
   *  la derive (POLICY.md §7). */
  customerDiscountAmount?:  number | null;
  discountAmount: number;
  taxAmount:      number;
  totalWithTax:   number | null;

  // ── Fuente del precio ─────────────────────────────────────────────────────
  priceSource: string;
  baseSource:  string;

  // ── Costo y margen al momento del snapshot ────────────────────────────────
  unitCost:      number | null;
  unitMargin:    number | null;
  marginPercent: number | null;
  costPartial:   boolean;
  costMode:      string;

  // ── Metadatos de resolución ───────────────────────────────────────────────
  partial:              boolean;
  appliedPriceListId:   string | null;
  appliedPriceListName: string | null;
  /** Modo de la lista aplicada — congelado en el snapshot para que la UI
   *  futura reproduzca el render correcto sin re-pegarle al motor.
   *  Opcional para preservar compat con snapshots viejos pre-fix. */
  appliedPriceListMode?: string | null;
  appliedPromotionId:   string | null;
  appliedPromotionName: string | null;
  appliedDiscountId:    string | null;

  // ── Desglose metal/hechura congelado ──────────────────────────────────────
  /** Snapshot del desglose metal/hechura. Optional para back-compat con
   *  snapshots viejos. Los sub-campos son optionals para que tipos derivados
   *  (DocumentLineSnapshot) puedan extender sin conflicto. POLICY.md §8. */
  metalHechuraBreakdown?: {
    metalCost:       number;
    metalSale:       number;
    hechuraCost:     number;
    hechuraSale:     number;
    metalGramsBase:  number | null;
    metalGramsSale?: number | null;
    /** Sprint 1: null hasta que el motor propague purity. */
    pureGramsBase?:  number | null;
    pureGramsSale?:  number | null;
    source?:         string;
  } | null;

  // ── Overrides de composición de costo aplicados ───────────────────────────
  /** Overrides aplicados al preview de la línea. Ya existe en
   *  SalePriceResult; acá se persiste para reproducibilidad. POLICY.md §8. */
  costOverrideContext?: {
    grams?:        { original: number | null; applied: number | null; manual: boolean };
    mermaPercent?: { original: number | null; applied: number | null; manual: boolean };
    metalVariant?: { originalId: string | null; appliedId: string | null; manual: boolean };
    hechura?:      { original: number | null; applied: number | null; manual: boolean };
  };

  // ── Timestamp ISO-8601 del momento en que se congeló el precio ────────────
  resolvedAt: string;
}

/** Versión actual del shape de PricingLineSnapshot. Bump al agregar campos
 *  o cambiar semántica. POLICY.md §2.5 / §9.4.
 *
 *  v2 (Sprint 1) — agrega snapshotVersion, qty/promo/customerDiscountAmount
 *                  (este último siempre null), metalHechuraBreakdown,
 *                  costOverrideContext.
 *  v3 (Sprint 3) — populi customerDiscountAmount cuando hay rule de cliente
 *                  DISCOUNT/BONUS; populi pureGramsBase/pureGramsSale en
 *                  metalHechuraBreakdown cuando hay purity única. Snapshots
 *                  v2 siguen siendo legibles (campos nuevos quedan null). */
export const PRICING_LINE_SNAPSHOT_VERSION = 3;
