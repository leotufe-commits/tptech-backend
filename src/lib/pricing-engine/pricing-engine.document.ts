// src/lib/pricing-engine/pricing-engine.document.ts
// ============================================================================
// buildDocumentPricingSnapshot — arma el DocumentPricingSnapshot que viaja a
// cabecera de Receipt y a cada ReceiptLine.
//
// Esta función NO calcula precios, costos, impuestos ni descuentos: recibe
// todos los valores ya resueltos por el motor (vía resolveFinalSalePrice +
// computeLineTaxes + applySalesChannelAdjustment + applyCouponAdjustment) y
// los serializa en la estructura canónica definida en
// src/modules/ARCHITECTURE-RECEIPTS-PAYMENTS.md §2.3.
//
// Inmutable: el output se guarda tal cual en Receipt.pricingSnapshot y en cada
// ReceiptLine.pricingSnapshot. Nunca se muta después.
// ============================================================================

import { Prisma } from "@prisma/client";
import type { PricingLineSnapshot } from "./pricing-engine.types.js";
import {
  applySalesChannelAdjustment,
  type ChannelAdjustmentInput,
  type ChannelAdjustmentResult,
} from "./pricing-engine.channel.js";
import {
  applyCouponAdjustment,
  type CouponInput,
  type CouponAdjustmentResult,
} from "./pricing-engine.coupon.js";
import { applyRounding } from "./pricing-engine.pricelist.js";

type D = Prisma.Decimal;

const toNum = (v: D | number | string | null | undefined): number => {
  if (v == null) return 0;
  if (typeof v === "number") return v;
  if (typeof v === "string") return parseFloat(v) || 0;
  return parseFloat(v.toString()) || 0;
};

// ─────────────────────────────────────────────────────────────────────────────
// Tipos del input (entrada del builder)
// ─────────────────────────────────────────────────────────────────────────────

export interface BuildSnapshotInput {
  currency: SnapshotCurrency;
  issuer:   SnapshotIssuer;
  counterparty: SnapshotCounterparty | null;
  channel:      SnapshotChannel | null;
  coupon:       SnapshotCoupon | null;
  promotion:    SnapshotPromotion | null;
  quantityDiscount: SnapshotQuantityDiscount | null;
  paymentMethod:    SnapshotPaymentMethod | null;
  rounding:         SnapshotRounding;
  taxBreakdown:     SnapshotTaxBreakdownItem[];
  totals:           SnapshotTotals;
  cost:             SnapshotCost;
  lines:            DocumentLineInput[];
}

export interface SnapshotCurrency {
  id:               string;
  currencyCode:     string;
  symbol:           string;
  currencyRate:     number;   // a moneda base del tenant
  baseCurrencyCode: string;
}

export interface SnapshotIssuer {
  jewelryId:    string;
  name:         string;
  cuit:         string;
  ivaCondition: string;
}

export interface SnapshotCounterparty {
  entityId:     string | null;
  kind:         "CLIENT" | "SUPPLIER";
  displayName:  string;
  docType:      string;
  docNumber:    string;
  ivaCondition: string;
}

export interface SnapshotChannel {
  id:                string;
  name:              string;
  adjustmentPercent: number | null;
  adjustmentAmount:  number;
}

export interface SnapshotCoupon {
  id:             string;
  code:           string;
  name:           string;
  discountType:   "FIXED" | "PERCENTAGE";
  discountValue:  number;
  discountAmount: number;
}

export interface SnapshotPromotion {
  id:       string;
  name:     string;
  type:     "FIXED" | "PERCENTAGE";
  value:    number;
  priority: number;
}

export interface SnapshotQuantityDiscount {
  id:   string;
  name: string;
  tier: number;
}

export interface SnapshotPaymentMethod {
  id:               string;
  name:             string;
  type:             string;  // CASH | CARD | TRANSFER | METAL | CHECK | OTHER
  surchargePercent: number | null;
  installmentsQty:  number;
  installmentsPlan: { id: string; name: string } | null;
  surchargeAmount:  number;
}

export interface SnapshotRounding {
  source:    "PRICE_LIST" | "TENANT_POLICY" | "MANUAL" | "NONE";
  appliedOn: "LINE" | "NET" | "TOTAL" | "METAL" | "HECHURA" | "NONE";
  mode:      "INTEGER" | "DECIMAL_1" | "DECIMAL_2" | "TEN" | "HUNDRED" | "NONE";
  direction: "UP" | "DOWN" | "NEAREST" | "NONE";
  adjustment: number;
}

export interface SnapshotTaxBreakdownItem {
  taxId:           string;
  name:            string;
  code:            string;
  taxType:         string;
  calculationType: "PERCENTAGE" | "FIXED_AMOUNT" | "PERCENTAGE_PLUS_FIXED";
  applyOn:         string;
  rate:            number | null;
  fixedAmount:     number | null;
  baseAmount:      number;
  taxAmount:       number;
  baseEstimated:   boolean;
  overriddenByEntity: boolean;
}

export interface SnapshotTotals {
  subtotal:               number;
  channelAmount:          number;
  couponAmount:           number;
  quantityDiscountAmount: number;
  promotionAmount:        number;
  paymentSurcharge:       number;
  discountAmount:         number;
  taxAmount:              number;
  roundingAdjustment:     number;
  total:                  number;
  totalBase:              number;
}

export interface SnapshotCost {
  totalCost:     number | null;
  totalMargin:   number | null;
  marginPercent: number | null;
  costPartial:   boolean;
}

export interface DocumentLineInput {
  // Identidad
  itemKind:  "ARTICLE_SIMPLE" | "ARTICLE_VARIANT" | "SERVICE" | "COMBO";
  articleId: string;
  variantId: string | null;
  code:      string;
  sku:       string;
  barcode:   string;
  name:      string;
  sortOrder: number;

  // PricingLineSnapshot ya computado por el motor
  linePricing: PricingLineSnapshot;

  // Valores resueltos por el caller
  quantity:         number;
  subtotal:         number;   // unitPrice × quantity
  discountLine:     number;   // descuento aplicado a la línea
  lineTotal:        number;   // subtotal - discountLine
  lineTaxAmount:    number;
  lineTotalWithTax: number;
  totalCost:        number | null;
  totalMargin:      number | null;

  taxBreakdown: SnapshotTaxBreakdownItem[];

  metalHechuraBreakdown?: {
    metalCost:       number;
    metalSale:       number;
    hechuraCost:     number;
    hechuraSale:     number;
    metalGramsBase:  number | null;
    /** Gramos de venta = metalGramsBase × (1 + metalMarginPct/100). null si N/A. */
    metalGramsSale?: number | null;
    /** Gramos puros base = metalGramsBase × purity. Sprint 1: null hasta que
     *  el motor propague purity. POLICY.md §8. */
    pureGramsBase?:  number | null;
    /** Gramos puros de venta = pureGramsBase × (1 + metalMarginPct/100). null
     *  si pureGramsBase null. */
    pureGramsSale?:  number | null;
  } | null;

  comboComponents?: Array<{
    articleId:    string;
    code:         string;
    name:         string;
    quantity:     number;
    unitCost:     number | null;
    affectsStock: boolean;
  }>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Tipos del output (lo que se persiste)
// ─────────────────────────────────────────────────────────────────────────────

export interface DocumentPricingSnapshot {
  version:          number;
  resolvedAt:       string;
  currency:         SnapshotCurrency;
  issuer:           SnapshotIssuer;
  counterparty:     SnapshotCounterparty | null;
  channel:          SnapshotChannel | null;
  coupon:           SnapshotCoupon | null;
  promotion:        SnapshotPromotion | null;
  quantityDiscount: SnapshotQuantityDiscount | null;
  paymentMethod:    SnapshotPaymentMethod | null;
  rounding:         SnapshotRounding;
  taxBreakdown:     SnapshotTaxBreakdownItem[];
  totals:           SnapshotTotals;
  cost:             SnapshotCost;
  lines:            DocumentLineSnapshot[];
}

export interface DocumentLineSnapshot extends PricingLineSnapshot {
  itemKind:  "ARTICLE_SIMPLE" | "ARTICLE_VARIANT" | "SERVICE" | "COMBO";
  articleId: string;
  variantId: string | null;
  code:      string;
  sku:       string;
  barcode:   string;
  name:      string;
  sortOrder: number;

  quantity:         number;
  subtotal:         number;
  discountLine:     number;
  lineTotal:        number;
  lineTaxAmount:    number;
  lineTotalWithTax: number;
  totalCost:        number | null;
  totalMargin:      number | null;

  taxBreakdown: SnapshotTaxBreakdownItem[];

  metalHechuraBreakdown?: {
    metalCost:       number;
    metalSale:       number;
    hechuraCost:     number;
    hechuraSale:     number;
    metalGramsBase:  number | null;
    metalGramsSale?: number | null;
    pureGramsBase?:  number | null;
    pureGramsSale?:  number | null;
  } | null;

  comboComponents?: Array<{
    articleId:    string;
    code:         string;
    name:         string;
    quantity:     number;
    unitCost:     number | null;
    affectsStock: boolean;
  }>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Builder
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Versión actual del shape de DocumentPricingSnapshot.
 *
 * v1 → shape original (pre Sprint 1).
 * v2 → agrega metalGramsSale/pureGramsBase/pureGramsSale al breakdown por
 *       línea (POLICY.md §8). Snapshots v1 son compatibles vía optionals.
 */
export const DOCUMENT_SNAPSHOT_VERSION = 2;

/**
 * Construye un DocumentPricingSnapshot a partir de valores ya resueltos por
 * el motor de precios. Esta función NO hace cálculo: copia + serializa.
 *
 * El `resolvedAt` se setea al momento de la llamada — después de eso el
 * snapshot es inmutable y se puede guardar tal cual en la DB.
 */
export function buildDocumentPricingSnapshot(input: BuildSnapshotInput): DocumentPricingSnapshot {
  const resolvedAt = new Date().toISOString();

  const lines: DocumentLineSnapshot[] = input.lines.map((l) => ({
    ...l.linePricing,
    itemKind:  l.itemKind,
    articleId: l.articleId,
    variantId: l.variantId,
    code:      l.code,
    sku:       l.sku,
    barcode:   l.barcode,
    name:      l.name,
    sortOrder: l.sortOrder,

    quantity:         toNum(l.quantity),
    subtotal:         toNum(l.subtotal),
    discountLine:     toNum(l.discountLine),
    lineTotal:        toNum(l.lineTotal),
    lineTaxAmount:    toNum(l.lineTaxAmount),
    lineTotalWithTax: toNum(l.lineTotalWithTax),
    totalCost:        l.totalCost   != null ? toNum(l.totalCost)   : null,
    totalMargin:      l.totalMargin != null ? toNum(l.totalMargin) : null,

    taxBreakdown: l.taxBreakdown,

    ...(l.metalHechuraBreakdown
      ? { metalHechuraBreakdown: l.metalHechuraBreakdown }
      : {}),
    ...(l.comboComponents && l.comboComponents.length > 0
      ? { comboComponents: l.comboComponents }
      : {}),
  }));

  return {
    version:          DOCUMENT_SNAPSHOT_VERSION,
    resolvedAt,
    currency:         input.currency,
    issuer:           input.issuer,
    counterparty:     input.counterparty,
    channel:          input.channel,
    coupon:           input.coupon,
    promotion:        input.promotion,
    quantityDiscount: input.quantityDiscount,
    paymentMethod:    input.paymentMethod,
    rounding:         input.rounding,
    taxBreakdown:     input.taxBreakdown,
    totals:           input.totals,
    cost:             input.cost,
    lines,
  };
}

// ============================================================================
// computeSaleDocumentTotals — fuente única de verdad de los totales del
// documento de venta.
//
// Por qué existe (Fase 3):
//   Antes confirmSale() calculaba el total a mano:
//     newTotal = round(couponAdj.finalAmount + saleTaxTotal)
//   y dispersaba la lógica de canal+cupón en varios lugares. Eso hacía que
//   simulador y factura pudieran divergir y que `Sale.discountAmount`
//   guardara solo el descuento del cupón (no del canal ni de las líneas).
//
//   Esta función recibe las líneas YA RESUELTAS por el motor (con sus
//   pricingSnapshot) y los inputs comerciales del documento, y devuelve un
//   único objeto `SaleDocumentTotals` con todos los importes del comprobante
//   y un `sourceTrace` para depuración.
//
// Capa pura — no toca DB, no llama al motor de líneas. Es la última fase del
// pricing pipeline: orquesta lo que ya está calculado.
// ============================================================================

export interface SaleDocumentTotalsLineInput {
  /** Cantidad de la línea. */
  quantity:      number;
  /** Precio de lista por unidad (pre-descuento). Si la línea no tiene
   *  basePrice (ej. legacy), pasar el unitPrice como basePrice. */
  basePrice:     number;
  /** Precio final por unidad (post-descuento de línea). */
  unitPrice:     number;
  /** Total de la línea YA REDONDEADO. Normalmente `qty × unitPrice`. */
  lineTotal:     number;
  /** Suma de impuestos de la línea (qty × taxUnit). */
  lineTaxAmount: number;

  // ── FASE 2 — Breakdown Metal/Hechura por línea ──────────────────────────
  // Opcionales para back-compat. Cuando vienen, `computeSaleDocumentTotals`
  // los agrega a nivel documento (`metalCostSubtotal`, etc.).
  // Vienen ESCALADOS a per-línea (× quantity), igual que `lineTotal`.
  // Si ninguna línea los provee, los agregados doc-level quedan en 0 y
  // `breakdownEstimated = false`.
  /** Costo del metal × cantidad. */
  metalCost?:            number;
  /** Costo de hechura/PRODUCT/SERVICE × cantidad. */
  hechuraCost?:          number;
  /** Precio de venta del metal × cantidad (pre-descuentos comerciales). */
  metalSale?:            number;
  /** Precio de venta de hechura × cantidad. */
  hechuraSale?:          number;
  /** `true` si la línea reporta `metalSaleEstimated=true` (derivado por
   *  proporción de costo, no exacto del modo METAL_HECHURA). */
  metalSaleEstimated?:   boolean;
  /** Análogo para hechura. */
  hechuraSaleEstimated?: boolean;
}

export interface SaleDocumentTotalsInput {
  lines:   SaleDocumentTotalsLineInput[];
  channel: ChannelAdjustmentInput | null;
  coupon:  CouponInput            | null;
  /** Recargo / descuento por medio de pago. Fase 3: confirmSale aún no lo
   *  computa, pasar 0. TODO Fase 4: integrar resolveCheckoutPrice. */
  paymentAdjustmentAmount?: number;
  /** Costo de envío. Fase 3: confirmSale aún no lo computa, pasar 0.
   *  TODO Fase 4: integrar el shipping del frontend a este input. */
  shippingAmount?: number;
  /** Descuento global a nivel documento. Fase 3: confirmSale aún no lo
   *  computa, pasar 0. TODO Fase 4: integrar el descuento global del frontend. */
  globalDiscountAmount?: number;
  /** Ajuste de redondeo (ej. desde la lista). Fase 3: pasar 0 si no aplica.
   *  Cuando `documentRounding` está activo, este campo se sobrescribe con el
   *  delta calculado por la política UNIFIED del tenant. */
  roundingAdjustment?: number;
  /**
   * Política de redondeo a nivel comprobante (modo UNIFIED).
   *
   * Cuando viene poblada y `mode !== "NONE"`, `computeSaleDocumentTotals`
   * aplica `applyRounding` sobre el `total` final (post-pago, post-envío),
   * sustituye `roundingAdjustment` por el delta calculado y popula
   * `roundingInfo` con `source = "TENANT_POLICY"` y `applyOn = "DOC_TOTAL"`.
   *
   * Reglas (rule-set TPTech):
   *   - Solo afecta el `total` final. NO toca líneas, impuestos ni base.
   *   - NO se prorratea sobre las líneas: el delta queda en cabecera.
   *   - Si `mode === "NONE"`, se ignora (comportamiento legacy).
   *   - El caller (sales.service) es responsable de evitar doble redondeo
   *     desactivando los `roundingApplyOn = NET | TOTAL` de las listas
   *     cuando esta política está activa.
   */
  documentRounding?: DocumentRoundingInput | null;
}

/**
 * Política de redondeo aplicada sobre el `total` final del documento.
 * Modo UNIFIED: redondea el monto total del comprobante según `mode` y
 * `direction`. No tiene variantes BREAKDOWN — esa decisión queda fuera
 * de este módulo hasta que el motor exponga metal/hechura confiable en
 * todos los modos de lista.
 */
export interface DocumentRoundingInput {
  mode:      "NONE" | "INTEGER" | "DECIMAL_1" | "DECIMAL_2" | "TEN" | "HUNDRED";
  direction: "NEAREST" | "UP" | "DOWN";
}

export interface SaleDocumentTotals {
  /** Σ basePrice × quantity. Suma de líneas a precio de lista. */
  subtotalBeforeDiscounts: number;
  /** Σ (basePrice − unitPrice) × quantity. Total de descuentos por línea
   *  (promoción + descuento por cantidad + manual override). */
  lineDiscountAmount: number;
  /** Σ lineTotal. Subtotal con descuentos de línea aplicados. */
  subtotalAfterLineDiscounts: number;
  /** Ajuste por canal (positivo = recargo, negativo = descuento). */
  channelAdjustmentAmount: number;
  /** Descuento del cupón (siempre ≥ 0). */
  couponDiscountAmount: number;
  /** Recargo / descuento por forma de pago. Fase 3 = 0. */
  paymentAdjustmentAmount: number;
  /** Costo de envío. Fase 3 = 0. */
  shippingAmount: number;
  /** Descuento global a nivel documento. Fase 3 = 0. */
  globalDiscountAmount: number;
  /** Base imponible: subtotalAfterLineDiscounts + canal − cupón + pago − global. */
  taxableBase: number;
  /** Σ lineTaxAmount. Suma de impuestos por línea. */
  taxAmount: number;
  /**
   * Ajuste de redondeo agregado a nivel documento.
   *
   * `computeSaleDocumentTotals` recibe este valor como input (default 0) y
   * lo expone tal cual; `previewSale` lo SOBREESCRIBE con la suma de los
   * `unitAdjustment × qty` reportados por las líneas con redondeo aplicado
   * por la lista de precios. Es un campo de DISPLAY: las líneas ya tienen
   * el redondeo absorbido en `lineTotal`/`lineTotalWithTax`, así que
   * `total` no se vuelve a ajustar con este número.
   */
  roundingAdjustment: number;
  /**
   * Metadata del redondeo aplicado al documento. `null` cuando no hubo
   * redondeo. Dos fuentes posibles:
   *   - `PRICE_LIST`: agregado de líneas con `appliedRounding` propio
   *     (display delta — el motor ya absorbió el delta en `lineTotal`).
   *     Se popula en `previewSale` (no en `computeSaleDocumentTotals`).
   *   - `TENANT_POLICY`: redondeo del comprobante (modo UNIFIED) calculado
   *     por `computeSaleDocumentTotals` cuando `documentRounding` está
   *     activo. El delta sí afecta el `total` final.
   */
  roundingInfo?: {
    source:        "PRICE_LIST" | "TENANT_POLICY";
    priceListId:   string | null;
    priceListName: string | null;
    applyOn:       string;
    mode:          string;
    direction:     string;
  } | null;
  /**
   * Resultado del redondeo a nivel comprobante (modo UNIFIED). `null` cuando
   * la política no estaba activa o cuando el delta fue 0. El caller puede
   * usar este objeto para popular el `SnapshotRounding` del documento con
   * `source = "TENANT_POLICY"` y `applyOn = "DOC_TOTAL"`.
   */
  documentRoundingApplied?: {
    source:       "TENANT_POLICY";
    applyOn:      "DOC_TOTAL";
    mode:         string;
    direction:    string;
    preRounding:  number;
    postRounding: number;
    adjustment:   number;
  } | null;
  /** taxableBase + envío. */
  totalBeforeTax: number;
  /** Total final del comprobante = totalBeforeTax + impuestos + redondeo,
   *  nunca negativo. */
  total: number;
  /** Total = totalBeforeTax + impuestos sin redondeo extra (alias). */
  totalWithTax: number;

  // ── Compatibilidad legacy ────────────────────────────────────────────────
  /**
   * `Sale.discountAmount` históricamente guardó SOLO el descuento del cupón.
   * Hasta que se haga la migración para que represente todos los descuentos
   * del documento, este campo sigue siendo lo que persiste el caller en esa
   * columna.
   *
   * legacy: Sale.discountAmount currently stores coupon discount only.
   * TODO Fase 7 / migración: pasar a `documentDiscountAmount = lineDiscountAmount +
   * |channelAdjustmentAmount<0| + couponDiscountAmount + globalDiscountAmount`.
   */
  legacyCouponOnlyDiscount: number;

  // ── Resultados intermedios (Fase 6) ──────────────────────────────────────
  /**
   * `ChannelAdjustmentResult` ya resuelto. Se expone para que `previewSale` y
   * `confirmSale` no tengan que invocar `applySalesChannelAdjustment` por
   * segunda vez para construir el snapshot del canal.
   */
  channelResult: ChannelAdjustmentResult;
  /**
   * `CouponAdjustmentResult` ya resuelto. Mismo motivo que `channelResult`.
   */
  couponResult:  CouponAdjustmentResult;

  /** Trazabilidad paso por paso para depuración / UI. */
  sourceTrace: SaleDocumentTotalsTraceStep[];

  // ── FASE 2 — Agregados Metal/Hechura a nivel documento ──────────────────
  // Suman los campos homónimos de `SaleDocumentTotalsLineInput`. Cuando
  // ninguna línea los provee, todos quedan en `0` y `breakdownEstimated`
  // en `false`. Estos valores NO afectan ningún total existente — son
  // agregados informativos / base para futuras pantallas de balance.
  /** Σ `line.metalCost` (per-línea, ya × qty). */
  metalCostSubtotal:    number;
  /** Σ `line.hechuraCost`. */
  hechuraCostSubtotal:  number;
  /** Σ `line.metalSale` (per-línea, pre-descuentos doc). */
  metalSaleSubtotal:    number;
  /** Σ `line.hechuraSale`. */
  hechuraSaleSubtotal:  number;
  /** `true` si al menos una línea reporta `metalSaleEstimated=true` o
   *  `hechuraSaleEstimated=true`. La UI lo usa para mostrar badge
   *  "estimado" cuando alguna línea no tiene desglose exacto. */
  breakdownEstimated:   boolean;
}

export interface SaleDocumentTotalsTraceStep {
  step:   string;       // "SUBTOTAL_BEFORE_DISCOUNTS" | "LINE_DISCOUNTS" | ...
  amount: number;
  note?:  string;
}

const round2 = (n: number): number => Math.round(n * 100) / 100;

/**
 * Calcula los totales del documento de venta a partir de líneas resueltas y
 * ajustes comerciales. Capa pura: no consulta DB ni recalcula precios de
 * línea. Las líneas deben venir con sus precios y descuentos ya aplicados.
 */
export function computeSaleDocumentTotals(
  input: SaleDocumentTotalsInput,
): SaleDocumentTotals {
  // ── Agregados por línea ──────────────────────────────────────────────────
  let subtotalBeforeDiscounts   = 0;
  let lineDiscountAmount        = 0;
  let subtotalAfterLineDiscounts = 0;
  let lineTaxTotal              = 0;
  // FASE 2 — agregados Metal/Hechura. Suman los campos opcionales de cada
  // línea. Si NINGUNA línea los provee, los subtotales quedan en 0 y
  // `breakdownEstimated = false` (comportamiento legacy intacto).
  let metalCostSubtotal    = 0;
  let hechuraCostSubtotal  = 0;
  let metalSaleSubtotal    = 0;
  let hechuraSaleSubtotal  = 0;
  let breakdownEstimated   = false;
  for (const l of input.lines) {
    const baseQty   = (l.basePrice ?? l.unitPrice) * l.quantity;
    subtotalBeforeDiscounts    += baseQty;
    lineDiscountAmount         += baseQty - l.lineTotal;
    subtotalAfterLineDiscounts += l.lineTotal;
    lineTaxTotal               += l.lineTaxAmount;
    metalCostSubtotal          += Number(l.metalCost   ?? 0);
    hechuraCostSubtotal        += Number(l.hechuraCost ?? 0);
    metalSaleSubtotal          += Number(l.metalSale   ?? 0);
    hechuraSaleSubtotal        += Number(l.hechuraSale ?? 0);
    if (l.metalSaleEstimated   === true) breakdownEstimated = true;
    if (l.hechuraSaleEstimated === true) breakdownEstimated = true;
  }
  subtotalBeforeDiscounts    = round2(subtotalBeforeDiscounts);
  lineDiscountAmount         = Math.max(0, round2(lineDiscountAmount));
  subtotalAfterLineDiscounts = round2(subtotalAfterLineDiscounts);
  metalCostSubtotal          = round2(metalCostSubtotal);
  hechuraCostSubtotal        = round2(hechuraCostSubtotal);
  metalSaleSubtotal          = round2(metalSaleSubtotal);
  hechuraSaleSubtotal        = round2(hechuraSaleSubtotal);

  // ── Canal de venta ───────────────────────────────────────────────────────
  // Aplica sobre el subtotal post-descuentos de línea.
  const channelResult = applySalesChannelAdjustment(
    subtotalAfterLineDiscounts,
    input.channel,
  );
  const channelAdjustmentAmount = round2(channelResult.channelAmount);

  // ── Cupón ────────────────────────────────────────────────────────────────
  // Aplica sobre el resultado del canal.
  const couponResult = applyCouponAdjustment(
    channelResult.finalAmount,
    input.coupon,
  );
  const couponDiscountAmount = round2(couponResult.discountAmount);

  // ── Otros ajustes (Fase 4) ──────────────────────────────────────────────
  const paymentAdjustmentAmount = round2(input.paymentAdjustmentAmount ?? 0);
  const shippingAmount          = round2(input.shippingAmount          ?? 0);
  const globalDiscountAmount    = round2(input.globalDiscountAmount    ?? 0);
  // Cuando la política doc está activa, el `roundingAdjustment` del caller
  // se DESCARTA: la política es la única fuente de verdad del redondeo y
  // sobreescribe este campo con el delta real calculado al final.
  const docRoundingActive = !!(input.documentRounding && input.documentRounding.mode && input.documentRounding.mode !== "NONE");
  let   roundingAdjustment      = docRoundingActive
    ? 0
    : round2(input.roundingAdjustment ?? 0);

  // ── Base imponible y total ──────────────────────────────────────────────
  //
  // BUG FIX (post Fase 2.1.b): el orden correcto debe igualar al de
  // `articles/pricing-preview` (referencia única del Simulador).
  //
  //   1. subtotal neto (post canal/cupón/globalDiscount, SIN payment ni shipping)
  //   2. impuestos                  ← se calculan sobre el neto
  //   3. total con impuestos
  //   4. forma de pago (checkout)   ← se aplica DESPUÉS de impuestos
  //   5. envío
  //   6. redondeo final
  //
  // Antes acá `taxableBase` incluía `paymentAdjustmentAmount`, lo que
  // contaminaba el subtotal neto y hacía que la fila "Subtotal neto antes
  // de impuestos" del Comparador divergiera de articles exactamente por el
  // monto del recargo de pago.
  //
  // Nota: el `total` final no cambia con este movimiento — payment solo se
  // mueve de un sumando intermedio a otro. Solo cambia la semántica de
  // `taxableBase`, `totalBeforeTax` y `totalWithTax`.
  const taxableBase = round2(
    subtotalAfterLineDiscounts +
    channelAdjustmentAmount -
    couponDiscountAmount -
    globalDiscountAmount,
  );

  const taxAmount      = round2(lineTaxTotal);
  const totalBeforeTax = round2(taxableBase + shippingAmount);
  const totalWithTax   = round2(totalBeforeTax + taxAmount);
  // Pago + redondeo se suman al total final, después de impuestos.
  let total            = Math.max(
    0,
    round2(totalWithTax + paymentAdjustmentAmount + roundingAdjustment),
  );

  // ── Redondeo por comprobante (modo UNIFIED) ──────────────────────────────
  // Se aplica al final, después de pago/envío/redondeo previo. Sobrescribe
  // `roundingAdjustment` con el delta real producido por la política. NO
  // toca líneas, impuestos, ni base imponible.
  let documentRoundingApplied: SaleDocumentTotals["documentRoundingApplied"] = null;
  if (
    input.documentRounding &&
    input.documentRounding.mode &&
    input.documentRounding.mode !== "NONE"
  ) {
    const before = total;
    const rounded = applyRounding(
      new Prisma.Decimal(before.toString()),
      input.documentRounding.mode,
      input.documentRounding.direction,
    ).toNumber();
    const newTotal = Math.max(0, round2(rounded));
    const delta    = round2(newTotal - before);
    total = newTotal;
    if (delta !== 0) {
      // El delta del redondeo doc REEMPLAZA el roundingAdjustment previo
      // (no se acumula con el redondeo de lista, que ya fue absorbido en
      // `lineTotal` cuando applyOn=PRICE; los modos NET/TOTAL deben venir
      // suprimidos por el caller cuando esta política está activa).
      roundingAdjustment = delta;
      documentRoundingApplied = {
        source:       "TENANT_POLICY",
        applyOn:      "DOC_TOTAL",
        mode:         input.documentRounding.mode,
        direction:    input.documentRounding.direction,
        preRounding:  before,
        postRounding: total,
        adjustment:   delta,
      };
    }
    // delta === 0 → el total ya estaba en el modo. No reportamos
    // `documentRoundingApplied` para evitar redondeo "fantasma" en la UI.
  }

  const sourceTrace: SaleDocumentTotalsTraceStep[] = [
    { step: "SUBTOTAL_BEFORE_DISCOUNTS",    amount: subtotalBeforeDiscounts },
    { step: "LINE_DISCOUNTS",               amount: -lineDiscountAmount },
    { step: "SUBTOTAL_AFTER_LINE_DISCOUNTS",amount: subtotalAfterLineDiscounts },
    { step: "CHANNEL",                      amount: channelAdjustmentAmount, note: input.channel?.name },
    { step: "COUPON",                       amount: -couponDiscountAmount,   note: input.coupon?.code },
    { step: "GLOBAL_DISCOUNT",              amount: -globalDiscountAmount },
    { step: "TAXABLE_BASE",                 amount: taxableBase },
    { step: "SHIPPING",                     amount: shippingAmount },
    { step: "TAX",                          amount: taxAmount },
    { step: "PAYMENT",                      amount: paymentAdjustmentAmount },
    { step: "ROUNDING",                     amount: roundingAdjustment, note: documentRoundingApplied ? `${documentRoundingApplied.mode} ${documentRoundingApplied.direction}` : undefined },
    { step: "TOTAL",                        amount: total },
  ];

  return {
    subtotalBeforeDiscounts,
    lineDiscountAmount,
    subtotalAfterLineDiscounts,
    channelAdjustmentAmount,
    couponDiscountAmount,
    paymentAdjustmentAmount,
    shippingAmount,
    globalDiscountAmount,
    taxableBase,
    taxAmount,
    roundingAdjustment,
    totalBeforeTax,
    totalWithTax,
    total,
    legacyCouponOnlyDiscount: couponDiscountAmount,
    channelResult,
    couponResult,
    sourceTrace,
    documentRoundingApplied,
    // FASE 2 — Agregados Metal/Hechura
    metalCostSubtotal,
    hechuraCostSubtotal,
    metalSaleSubtotal,
    hechuraSaleSubtotal,
    breakdownEstimated,
  };
}
