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
import type {
  PricingLineSnapshot,
  BalanceMode,
  BalanceModeSource,
  DocumentBalanceBreakdown,
} from "./pricing-engine.types.js";
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
import { traceDocument } from "./pricing-trace.js";
import {
  applyCommercialDocumentRounding,
  type CommercialDocRoundingInput,
  type CommercialDocRoundingApplied,
  type CommercialDocMetalParentInput,
} from "./commercial-document-rounding.js";

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

  // ── Snapshot v3 — Balance Mode (POLICY.md §11) ──────────────────────────
  // Todos opcionales: callers actuales que NO los pasen siguen funcionando.
  // Cuando no vienen, el builder genera un breakdown UNIFIED implícito
  // derivado de `totals.total` y `totals.totalBase`. NO se ejecuta lógica
  // del motor para construirlo — sólo passthrough de los totales ya resueltos.
  /** Modo de balance resuelto (R11.4). Si no se provee → "UNIFIED". */
  balanceMode?:       BalanceMode;
  /** De dónde salió el modo (auditoría). Si no se provee → "FALLBACK_UNIFIED". */
  balanceModeSource?: BalanceModeSource;
  /** Breakdown canónico ya construido (ej. por `buildDocumentBalanceBreakdown`).
   *  Si no se provee, el builder lo arma como UNIFIED implícito con
   *  `monetary.amount = totals.total`. */
  balanceBreakdown?:  DocumentBalanceBreakdown;
  /** Trazabilidad inversa: documento origen que produjo este snapshot.
   *  Útil cuando el snapshot vive en un movimiento de cuenta corriente y
   *  el visor quiere linkear de vuelta a la Sale/Purchase/etc. */
  sourceDocument?:    SnapshotSourceDocument | null;
}

/** Documento origen del snapshot. Trazabilidad para visores de cuenta
 *  corriente. Opcional — la mayoría de callers no lo necesitan. */
export interface SnapshotSourceDocument {
  /** Tipo de documento origen. Strings libres para no acoplarnos a un enum
   *  de DB; los conocidos son SALE / PURCHASE / CROSS_SETTLEMENT. */
  kind:    "SALE" | "PURCHASE" | "CROSS_SETTLEMENT" | string;
  id:      string;
  number?: string | null;
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

  // ── v3 (Snapshot v3 — Balance Mode) ─────────────────────────────────────
  /** Modo de balance del documento (R11.4). UNIFIED / BREAKDOWN. Siempre
   *  presente en v3+; en lecturas legacy v2 → asumir UNIFIED. */
  balanceMode:       BalanceMode;
  /** Origen del modo: documento / cliente / lista / tenant / fallback. */
  balanceModeSource: BalanceModeSource;
  /** Breakdown canónico (metals + monetaryBalance). En UNIFIED, `metals=[]`
   *  y `monetaryBalance.amount = totals.total`. */
  balanceBreakdown:  DocumentBalanceBreakdown;
  /** Trazabilidad opcional al documento origen (Sale/Purchase/etc.). */
  sourceDocument?:   SnapshotSourceDocument | null;
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
 * v3 → agrega `balanceMode`, `balanceModeSource`, `balanceBreakdown` y
 *       `sourceDocument` opcional (POLICY.md §11 — Balance Mode). Las
 *       lecturas de snapshots v2/legacy se traducen a UNIFIED implícito vía
 *       `readBalanceBreakdown` (`pricing-engine.balance.ts`).
 */
export const DOCUMENT_SNAPSHOT_VERSION = 3;

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

  // ── v3 — Balance Mode passthrough con defaults seguros ──────────────────
  // Si el caller NO provee balanceMode/balanceBreakdown, defaultamos a
  // UNIFIED con un breakdown derivado de los totales ya resueltos. NO se
  // recalcula nada: es el mismo número que `totals.total`/`totals.totalBase`
  // expuesto bajo el shape canónico de balance. Esto preserva la promesa
  // "cero runtime change" frente a callers actuales.
  const balanceMode: BalanceMode = input.balanceMode ?? "UNIFIED";
  const balanceModeSource: BalanceModeSource =
    input.balanceModeSource ?? "FALLBACK_UNIFIED";
  const currencyRateSnap =
    Number.isFinite(input.currency.currencyRate) && input.currency.currencyRate > 0
      ? input.currency.currencyRate
      : 1;
  const balanceBreakdown: DocumentBalanceBreakdown =
    input.balanceBreakdown ?? {
      metals: [],
      monetaryBalance: {
        amount:       toNum(input.totals.total),
        currencyCode: input.currency.currencyCode,
        currencyRate: currencyRateSnap,
        amountBase:   toNum(input.totals.totalBase),
      },
    };

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
    balanceMode,
    balanceModeSource,
    balanceBreakdown,
    ...(input.sourceDocument !== undefined
      ? { sourceDocument: input.sourceDocument }
      : {}),
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

  /**
   * Etapa fiscal (POLICY §Tax.3) — porción del `lineTaxAmount` que NO debe
   * escalar con descuentos de documento. Suma de impuestos `FIXED_AMOUNT`
   * + la parte fija de impuestos `PERCENTAGE_PLUS_FIXED`. Default 0 → todo
   * el `lineTaxAmount` escala (back-compat con callers pre POLICY §Tax).
   *
   * Si `lineTaxAmountFixed > lineTaxAmount`, el motor lo clampa al
   * `lineTaxAmount` reportado (defensivo; nunca lo "infla").
   */
  lineTaxAmountFixed?:   number;
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

  // ── Etapa D' — Redondeo Comercial PER_DOCUMENT (POLICY §R-Rounding-15) ──
  /**
   * Configuración del redondeo comercial PER_DOCUMENT. Se aplica entre el
   * cálculo del `taxAmount` (con §Tax.4 aplicado) y la suma de
   * `shipping + payment + financialRounding`.
   *
   * Posición canónica:
   *   ... → Canal → Cupón → Bonif. Global → Taxable Base → Impuestos
   *      → [REDONDEO COMERCIAL PER_DOCUMENT] ← acá
   *      → Envío → Forma de Pago → Redondeo Financiero
   *
   * Cuando viene `null`/omitido, la capa no se ejecuta (back-compat total
   * con callers que no lo conocen).
   *
   * El caller (sales.service) es responsable de:
   *   · Resolver la "lista activa del documento" — si las líneas no
   *     comparten lista, NO pasar este campo y emitir un snapshot con
   *     `fallback: "NO_SHARED_LIST"` por separado.
   *   · Suprimir el PER_LINE legacy de hechura (`applyPriceList:442`)
   *     cuando la lista tiene `commercialRoundingScope === "PER_DOCUMENT"`.
   */
  commercialDocumentRounding?: CommercialDocRoundingInput | null;
  /**
   * Metales agregados por padre a nivel documento (Σ líneas gramsPure × qty).
   * Solo necesario cuando `commercialDocumentRounding?.scope === "BREAKDOWN"`
   * y `metal.mode !== "NONE"`.
   */
  metalsByParentForCommercialRounding?: CommercialDocMetalParentInput[];
  /**
   * Σ líneas (gramsPure × quotePrice) — valorización física del metal a
   * nivel documento. Solo se usa cuando `commercialDocumentRounding?.scope
   * === "BREAKDOWN"` para derivar el saldo monetario:
   *   saldoMonetario = totalComercialPostTax − metalValuationSum
   * Default 0 (sin metal).
   */
  metalValuationSumForCommercialRounding?: number;
}

/**
 * Política de redondeo aplicada al documento. Etapa 1B soporta 3 scopes:
 *
 *   · UNIFIED   → redondea solo el `total` final (legacy / default).
 *   · BREAKDOWN → redondea por separado los subtotales `metalSale` y
 *                 `hechuraSale` agregados a nivel documento; el delta
 *                 combinado se refleja en el `total`.
 *   · BOTH      → cascada controlada — BREAKDOWN primero, UNIFIED al
 *                 final sobre el total ya ajustado. Si el delta UNIFIED
 *                 es cero después del BREAKDOWN, el snapshot no reporta
 *                 una capa UNIFIED extra (guard anti doble-redondeo).
 *
 * Back-compat (Etapa 1A): un caller que pase `{ mode, direction }` sin
 * `scope` ni `breakdown` se comporta exactamente como UNIFIED, idéntico
 * al motor pre Etapa 1B.
 */
export type DocumentRoundingScope = "UNIFIED" | "BREAKDOWN" | "BOTH";

export type DocumentRoundingMode =
  | "NONE" | "INTEGER" | "DECIMAL_1" | "DECIMAL_2" | "TEN" | "HUNDRED";

export type DocumentRoundingDirection = "NEAREST" | "UP" | "DOWN";

export interface DocumentRoundingPartConfig {
  mode:      DocumentRoundingMode;
  direction: DocumentRoundingDirection;
}

export interface DocumentRoundingInput {
  /** Scope efectivo. Default UNIFIED si se omite (back-compat). */
  scope?: DocumentRoundingScope;
  /** Config UNIFIED. Se usa cuando scope = UNIFIED o BOTH. */
  mode:      DocumentRoundingMode;
  direction: DocumentRoundingDirection;
  /** Config BREAKDOWN. Requerida cuando scope = BREAKDOWN o BOTH. */
  breakdown?: {
    metal:   DocumentRoundingPartConfig;
    hechura: DocumentRoundingPartConfig;
  };
}

/**
 * Capa atómica de redondeo aplicada al documento. Una instancia por
 * componente efectivamente redondeado (metal, hechura, unified).
 * `adjustment = postRounding − preRounding` y puede ser negativa.
 */
export interface DocumentRoundingLayerResult {
  applyOn:      "DOC_TOTAL" | "DOC_METAL" | "DOC_HECHURA";
  mode:         DocumentRoundingMode;
  direction:    DocumentRoundingDirection;
  preRounding:  number;
  postRounding: number;
  adjustment:   number;
}

/**
 * Resultado completo del redondeo a nivel comprobante. Se persiste en
 * `Sale.documentRoundingSnapshot` al confirmar y se expone en
 * `SaleDocumentTotals.documentRoundingApplied` durante el preview.
 *
 * `fallback`:
 *   · `NO_BREAKDOWN_DATA` → scope BREAKDOWN/BOTH solicitado pero las
 *     líneas no aportaron `metalSale`/`hechuraSale` → BREAKDOWN se omite.
 *     Si el scope era BOTH, el UNIFIED sigue aplicándose.
 *   · `ZERO_DELTA` → todas las capas dieron delta 0 → el bloque
 *     `documentRoundingApplied` no se expone (evita "redondeo fantasma").
 */
export interface DocumentRoundingApplied {
  source:  "TENANT_POLICY";
  scope:   DocumentRoundingScope;
  applyOn: "DOC_TOTAL";
  unified?: DocumentRoundingLayerResult;
  breakdown?: {
    metal:              DocumentRoundingLayerResult;
    hechura:            DocumentRoundingLayerResult;
    combinedAdjustment: number;
  };
  totalAdjustment: number;
  fallback?: "NO_BREAKDOWN_DATA" | null;
}

/**
 * Resultado del scaling fiscal aplicado a `taxAmount` cuando hay descuentos
 * de cabecera (canal, cupón, global). POLICY §Tax.4 — §Tax.6.
 *
 * Si `scalingApplied = false`, el documento no tuvo descuentos de cabecera y
 * `scaledTaxAmount === originalTaxAmount`. En ese caso el caller puede
 * omitir persistir este bloque (es ruido) — o persistirlo para auditoría
 * exhaustiva.
 */
export interface TaxScalingResult {
  /** `taxableBase / subtotalAfterLineDiscounts`, en [0, 1]. */
  effectiveSaleRatio:         number;
  /** `1 − effectiveSaleRatio`, en [0, 1]. */
  effectiveDiscountRatio:     number;
  /** Subtotal post descuentos línea — denominador del ratio. */
  subtotalAfterLineDiscounts: number;
  /** Base imponible post-descuentos doc (canal+cupón+global). */
  taxableBase:                number;
  /** Σ `lineTaxAmount` pre-scaling. */
  originalTaxAmount:          number;
  /** Σ (`lineTaxAmount − lineTaxAmountFixed`) — porción porcentual. */
  scalableTaxAmount:          number;
  /** Σ `lineTaxAmountFixed` — porción que NO escala (POLICY §Tax.3). */
  fixedTaxAmount:             number;
  /** `round2(scalableTaxAmount × effectiveSaleRatio)` — porcentual post-scaling. */
  scaledScalableTax:          number;
  /** `scaledScalableTax + fixedTaxAmount` — equivalente al `taxAmount` final. */
  scaledTaxAmount:            number;
  /** `false` cuando `effectiveSaleRatio === 1` (no hubo descuento doc). */
  scalingApplied:             boolean;
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
  /**
   * Impuestos efectivos del documento (post-scaling fiscal — POLICY §Tax.4).
   *
   * Hasta Etapa Tax: era `round2(Σ lineTaxAmount)` sin considerar descuentos
   * de cabecera (canal, cupón, global), lo que producía IVA "fantasma" cuando
   * `taxableBase < subtotalAfterLineDiscounts`.
   *
   * Ahora: `scaledScalableTax + fixedTaxAmount`. Ver `taxScaling` para el
   * detalle del scaling aplicado.
   */
  taxAmount: number;
  /**
   * Detalle del scaling fiscal. Siempre poblado; con `scalingApplied=false`
   * cuando `effectiveSaleRatio === 1` (no hubo descuento de cabecera).
   * El caller (sales.service) lo persiste en `Sale.documentFiscalSnapshot`.
   */
  taxScaling: TaxScalingResult;
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
   * Resultado del redondeo a nivel comprobante. `null` cuando la política
   * no estaba activa o cuando todas las capas dieron delta 0.
   *
   * Etapa 1B: el shape es discriminado por `scope`. Para UNIFIED reporta
   * `unified`. Para BREAKDOWN reporta `breakdown` (metal + hechura) y
   * `unified` queda undefined. Para BOTH reporta ambos en cascada.
   *
   * El caller (sales.service) congela este objeto en
   * `Sale.documentRoundingSnapshot` al confirmar para que el documento
   * sea auto-suficiente (no depende de Receipt).
   */
  documentRoundingApplied?: DocumentRoundingApplied | null;

  // ── Etapa D' — Redondeo Comercial PER_DOCUMENT (POLICY §R-Rounding-15) ──
  /**
   * Snapshot del redondeo comercial PER_DOCUMENT. `null` cuando la capa no
   * actuó (config NONE sin movimiento o no se pasó `commercialDocumentRounding`
   * en el input). Incluye `fallback` cuando hay caso informativo
   * (ALL_NONE, NO_METALS_BREAKDOWN_DATA).
   *
   * El caller (sales.service) puede inyectar adicionalmente un snapshot con
   * `fallback: "NO_SHARED_LIST"` cuando detecta mixed-list y no llama a la
   * capa — ese caso NO sale desde este campo (se persiste por separado en
   * `Sale.commercialDocumentRoundingSnapshot`).
   */
  commercialDocumentRoundingApplied?: CommercialDocRoundingApplied | null;
  /** Total comercial post-tax ANTES del redondeo comercial PER_DOCUMENT
   *  (= `taxableBase + taxAmount`). Auditable. */
  totalComercialPreCommercialRounding: number;
  /** Total comercial DESPUÉS del redondeo comercial PER_DOCUMENT
   *  (= `totalComercialPreCommercialRounding + commercialDocumentRoundingApplied.totalAdjustment`).
   *  Cuando la capa no actuó, igual al pre. */
  totalComercialPostCommercialRounding: number;

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
 * Una política `DocumentRoundingInput` está activa cuando al menos uno de
 * sus componentes efectivos tiene `mode !== "NONE"`. UNIFIED se chequea con
 * `mode` raíz; BREAKDOWN con los modos de metal/hechura. Mantener este
 * helper centralizado evita que cada caller reinvente la condición.
 */
function isDocumentRoundingActive(input: DocumentRoundingInput): boolean {
  const scope = input.scope ?? "UNIFIED";
  const unifiedActive = !!input.mode && input.mode !== "NONE";
  const breakdownActive =
    !!input.breakdown &&
    (
      (input.breakdown.metal.mode   && input.breakdown.metal.mode   !== "NONE") ||
      (input.breakdown.hechura.mode && input.breakdown.hechura.mode !== "NONE")
    );
  if (scope === "UNIFIED")   return unifiedActive;
  if (scope === "BREAKDOWN") return breakdownActive;
  // BOTH
  return unifiedActive || breakdownActive;
}

/**
 * Resumen textual para el `sourceTrace.ROUNDING.note`. Devuelve un string
 * legible que identifica las capas que efectivamente movieron el total
 * (UNIFIED, BREAKDOWN o ambos en cascada).
 */
function roundingTraceNote(applied: DocumentRoundingApplied): string {
  const parts: string[] = [];
  if (applied.breakdown) {
    parts.push(`BREAKDOWN(${applied.breakdown.metal.mode}/${applied.breakdown.hechura.mode})`);
  }
  if (applied.unified) {
    parts.push(`UNIFIED(${applied.unified.mode} ${applied.unified.direction})`);
  }
  if (applied.fallback) {
    parts.push(`fallback=${applied.fallback}`);
  }
  return parts.join(" + ") || applied.scope;
}

/**
 * Aplica `applyRounding` sobre un monto y devuelve la capa completa
 * (pre, post, delta). Si el modo es NONE o el delta es 0, devuelve una
 * capa con `adjustment = 0` — el caller decide si la reporta.
 */
function applyRoundingLayer(
  amount:  number,
  cfg:     DocumentRoundingPartConfig,
  applyOn: DocumentRoundingLayerResult["applyOn"],
): DocumentRoundingLayerResult {
  if (!cfg.mode || cfg.mode === "NONE") {
    return {
      applyOn,
      mode:         cfg.mode,
      direction:    cfg.direction,
      preRounding:  amount,
      postRounding: amount,
      adjustment:   0,
    };
  }
  const post = round2(
    applyRounding(new Prisma.Decimal(amount.toString()), cfg.mode, cfg.direction).toNumber(),
  );
  return {
    applyOn,
    mode:         cfg.mode,
    direction:    cfg.direction,
    preRounding:  amount,
    postRounding: post,
    adjustment:   round2(post - amount),
  };
}

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
  // POLICY §Tax.3 — porción de `lineTaxAmount` que NO debe escalar con
  // descuentos de cabecera. Default 0 → todo el tax escala (back-compat
  // con callers que no separen FIXED de PERCENTAGE).
  let lineTaxFixedTotal         = 0;
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
    // Clampamos lineTaxAmountFixed a [0, lineTaxAmount] — defensivo contra
    // callers que reporten un fijo mayor que el tax total (que sería un bug
    // del caller pero no debe inflar nuestro `taxAmount`).
    const lineFixed             = Math.max(0, Math.min(Number(l.lineTaxAmountFixed ?? 0), l.lineTaxAmount));
    lineTaxFixedTotal          += lineFixed;
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
  traceDocument("L06_CHANNEL", {
    pre:        subtotalAfterLineDiscounts,
    delta:      channelAdjustmentAmount,
    post:       round2(subtotalAfterLineDiscounts + channelAdjustmentAmount),
    channelId:   input.channel?.id   ?? null,
    channelName: input.channel?.name ?? null,
  });

  // ── Cupón ────────────────────────────────────────────────────────────────
  // Aplica sobre el resultado del canal.
  const couponResult = applyCouponAdjustment(
    channelResult.finalAmount,
    input.coupon,
  );
  const couponDiscountAmount = round2(couponResult.discountAmount);
  traceDocument("L07_COUPON", {
    pre:        channelResult.finalAmount,
    delta:      -couponDiscountAmount,
    post:       round2(channelResult.finalAmount - couponDiscountAmount),
    couponId:   input.coupon?.id   ?? null,
    couponCode: input.coupon?.code ?? null,
  });

  // ── Otros ajustes (Fase 4) ──────────────────────────────────────────────
  const paymentAdjustmentAmount = round2(input.paymentAdjustmentAmount ?? 0);
  const shippingAmount          = round2(input.shippingAmount          ?? 0);
  const globalDiscountAmount    = round2(input.globalDiscountAmount    ?? 0);
  traceDocument("L08_GLOBAL_DISCOUNT", {
    amount: globalDiscountAmount,
  });
  traceDocument("L09_SHIPPING", {
    amount: shippingAmount,
  });
  traceDocument("L10_PAYMENT", {
    amount: paymentAdjustmentAmount,
  });
  // Cuando la política doc está activa, el `roundingAdjustment` del caller
  // se DESCARTA: la política es la única fuente de verdad del redondeo y
  // sobreescribe este campo con el delta real calculado al final. Usa el
  // helper que considera UNIFIED/BREAKDOWN/BOTH.
  const docRoundingActive = !!(input.documentRounding && isDocumentRoundingActive(input.documentRounding));
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

  // ── Scaling fiscal del taxAmount (POLICY §Tax.4) ───────────────────────────
  //
  // Modelo fiscal oficial: si los descuentos de cabecera (canal, cupón,
  // global) bajan la `taxableBase`, el `taxAmount` PERCENTAGE debe escalar
  // proporcionalmente. Los impuestos FIXED_AMOUNT (percepciones, sellados,
  // cargos fijos) NO escalan — el caller los reporta vía
  // `lineTaxAmountFixed` y se preservan tal cual.
  //
  // Fórmula:
  //   effectiveSaleRatio = max(0, taxableBase) / subtotalAfterLineDiscounts
  //   scaledScalableTax  = round2(scalableTax × effectiveSaleRatio)
  //   taxAmount          = round2(scaledScalableTax + fixedTaxAmount)
  //
  // Back-compat: cuando no hay descuentos de cabecera, `effectiveSaleRatio = 1`
  // y `taxAmount === round2(lineTaxTotal)` exactamente como antes.
  const originalTaxAmount   = round2(lineTaxTotal);
  const fixedTaxAmount      = round2(lineTaxFixedTotal);
  const scalableTaxAmount   = round2(Math.max(0, originalTaxAmount - fixedTaxAmount));
  const effectiveSaleRatio  = subtotalAfterLineDiscounts > 0
    ? Math.max(0, taxableBase) / subtotalAfterLineDiscounts
    : 0;
  const effectiveDiscountRatio = round2(1 - effectiveSaleRatio);
  const scaledScalableTax   = round2(scalableTaxAmount * effectiveSaleRatio);
  const taxAmount           = round2(scaledScalableTax + fixedTaxAmount);
  const scalingApplied      = effectiveSaleRatio < 1;

  const taxScaling: TaxScalingResult = {
    effectiveSaleRatio:         round2(effectiveSaleRatio),
    effectiveDiscountRatio,
    subtotalAfterLineDiscounts,
    taxableBase,
    originalTaxAmount,
    scalableTaxAmount,
    fixedTaxAmount,
    scaledScalableTax,
    scaledTaxAmount:            taxAmount,
    scalingApplied,
  };

  // ── Etapa D' — Redondeo Comercial PER_DOCUMENT (POLICY §R-Rounding-15) ──
  // Posición canónica: post-tax (con §Tax.4 aplicado), pre-shipping/payment.
  // Actúa sobre `totalComercialPostTax = taxableBase + taxAmount` — NO
  // incluye shipping ni payment. El delta se suma al total final.
  //
  // Mantenemos `totalBeforeTax` y `totalWithTax` con los valores legacy
  // (sumas conmutativas) para no romper consumidores que los leen.
  const totalComercialPreCommercialRounding = round2(taxableBase + taxAmount);
  let commercialDocumentRoundingApplied: CommercialDocRoundingApplied | null = null;
  let totalComercialPostCommercialRounding = totalComercialPreCommercialRounding;
  if (input.commercialDocumentRounding) {
    const commercialResult = applyCommercialDocumentRounding({
      totalComercialPostTax: totalComercialPreCommercialRounding,
      metalValuationSum:     input.metalValuationSumForCommercialRounding ?? 0,
      // CONTRATO CANÓNICO — el saldo comercial DESGLOSADO = total − Σ metalSale
      // (metal COMERCIAL con margen), NO la valoración física. Usamos el
      // subtotal de metalSale ya agregado de las líneas.
      metalSaleSum:          metalSaleSubtotal,
      // Factor de margen del metal (= Σ metalSale / Σ metalCost). Base ÚNICA
      // del redondeo físico COMERCIAL de los gramos (regla final — Paso 2):
      //   gramsSale = gramsPure × factor;  postGrams = round(gramsSale).
      // Alimenta a la vez los gramos del card (`metalsPostGrams`), el footer
      // (`metals[]`) y el impacto monetario (`deltaGrams × refValue`) → el
      // delta del metal entra en `totalPostCommercial`. NO altera el saldo
      // hechura (que sigue siendo `total − Σ metalSale`). Factor 1 ⇒ sin
      // margen (back-compat).
      metalCommercialMarginFactor: metalCostSubtotal > 0
        ? metalSaleSubtotal / metalCostSubtotal
        : 1,
      metalsByParent:        input.metalsByParentForCommercialRounding,
      config:                input.commercialDocumentRounding,
    });
    commercialDocumentRoundingApplied   = commercialResult.applied;
    totalComercialPostCommercialRounding = commercialResult.totalPostCommercial;
  }
  const commercialDelta = round2(
    totalComercialPostCommercialRounding - totalComercialPreCommercialRounding,
  );

  // L05B — trazabilidad de la capa comercial.
  traceDocument("L05B_COMMERCIAL_DOC_ROUNDING", {
    applied:                 commercialDocumentRoundingApplied != null,
    scope:                   commercialDocumentRoundingApplied?.scope ?? null,
    pre:                     totalComercialPreCommercialRounding,
    post:                    totalComercialPostCommercialRounding,
    delta:                   commercialDelta,
    fallback:                commercialDocumentRoundingApplied?.fallback ?? null,
    unified:                 commercialDocumentRoundingApplied?.unified ?? null,
    breakdown:               commercialDocumentRoundingApplied?.breakdown
      ? {
          metalMonetaryEquivalent: commercialDocumentRoundingApplied.breakdown.metalMonetaryEquivalent,
          metalsCount:             commercialDocumentRoundingApplied.breakdown.metals.length,
          hechura:                 commercialDocumentRoundingApplied.breakdown.hechura,
          combinedAdjustment:      commercialDocumentRoundingApplied.breakdown.combinedAdjustment,
        }
      : null,
  });

  const totalBeforeTax = round2(taxableBase + shippingAmount);
  const totalWithTax   = round2(totalBeforeTax + taxAmount);
  // Pago + envío + redondeo legacy + delta comercial → total final.
  // Aritméticamente: total = totalWithTax + payment + roundingAdjustment + commercialDelta.
  // (Sin la capa nueva, `commercialDelta = 0` y el resultado es idéntico al legacy.)
  let total            = Math.max(
    0,
    round2(totalWithTax + paymentAdjustmentAmount + roundingAdjustment + commercialDelta),
  );
  traceDocument("L11_TOTAL_BEFORE_FIN_ROUND", {
    subtotalAfterLineDiscounts,
    channel:        channelAdjustmentAmount,
    coupon:         -couponDiscountAmount,
    globalDiscount: -globalDiscountAmount,
    taxableBase,
    tax:            taxAmount,
    commercialDelta,                                      // ← nuevo
    totalComercialPostCommercialRounding,                 // ← nuevo
    shipping:       shippingAmount,
    payment:        paymentAdjustmentAmount,
    totalBeforeRounding: total,
  });

  // ── Redondeo por comprobante (Etapa 1B — UNIFIED / BREAKDOWN / BOTH) ─────
  // Se aplica al final, después de pago/envío/redondeo previo. Sobrescribe
  // `roundingAdjustment` con el delta real producido por la política. NO
  // toca líneas individuales, impuestos por línea ni base imponible.
  //
  // Orden de capas:
  //   1. BREAKDOWN (si scope = BREAKDOWN o BOTH y hay datos metal/hechura)
  //   2. UNIFIED   (si scope = UNIFIED o BOTH)
  // El delta de cada capa se suma al `total` final. El reporte del snapshot
  // refleja qué capas efectivamente movieron el número (delta != 0) y deja
  // constancia del fallback si no había datos para BREAKDOWN.
  let documentRoundingApplied: DocumentRoundingApplied | null = null;
  if (input.documentRounding && isDocumentRoundingActive(input.documentRounding)) {
    const scope: DocumentRoundingScope = input.documentRounding.scope ?? "UNIFIED";
    const wantsBreakdown = scope === "BREAKDOWN" || scope === "BOTH";
    const wantsUnified   = scope === "UNIFIED"   || scope === "BOTH";

    // Datos disponibles para BREAKDOWN: hace falta que al menos un componente
    // tenga monto > 0. Si los subtotales son 0, el BREAKDOWN no tiene sobre
    // qué actuar — se reporta `fallback = NO_BREAKDOWN_DATA` y, en BOTH, el
    // UNIFIED sigue aplicándose normalmente.
    const breakdownDataPresent =
      wantsBreakdown && (metalSaleSubtotal > 0 || hechuraSaleSubtotal > 0);

    let breakdownLayer: DocumentRoundingApplied["breakdown"] | undefined;
    let unifiedLayer:   DocumentRoundingLayerResult         | undefined;
    let fallback:       DocumentRoundingApplied["fallback"] = null;
    let combinedDelta = 0;

    if (wantsBreakdown && !breakdownDataPresent) {
      fallback = "NO_BREAKDOWN_DATA";
    }

    if (breakdownDataPresent && input.documentRounding.breakdown) {
      const metalCfg   = input.documentRounding.breakdown.metal;
      const hechuraCfg = input.documentRounding.breakdown.hechura;
      const metalLayer   = applyRoundingLayer(metalSaleSubtotal,   metalCfg,   "DOC_METAL");
      const hechuraLayer = applyRoundingLayer(hechuraSaleSubtotal, hechuraCfg, "DOC_HECHURA");
      const breakdownDelta = round2(metalLayer.adjustment + hechuraLayer.adjustment);
      combinedDelta += breakdownDelta;
      total = Math.max(0, round2(total + breakdownDelta));
      breakdownLayer = {
        metal:              metalLayer,
        hechura:            hechuraLayer,
        combinedAdjustment: breakdownDelta,
      };
    }

    if (wantsUnified) {
      const unifiedCfg: DocumentRoundingPartConfig = {
        mode:      input.documentRounding.mode,
        direction: input.documentRounding.direction,
      };
      const layer = applyRoundingLayer(total, unifiedCfg, "DOC_TOTAL");
      if (layer.adjustment !== 0) {
        combinedDelta += layer.adjustment;
        total = Math.max(0, round2(layer.postRounding));
        unifiedLayer = layer;
      }
      // delta === 0 → en BOTH evitamos reportar UNIFIED para no inflar la UI
      // con una capa "fantasma" (guard anti doble-redondeo visual).
    }

    if (combinedDelta !== 0 || fallback) {
      // El delta combinado REEMPLAZA `roundingAdjustment` (la política doc
      // es la única autoridad cuando está activa; el redondeo de listas
      // con applyOn=NET|TOTAL viene suprimido por el caller).
      roundingAdjustment = round2(combinedDelta);
      documentRoundingApplied = {
        source:  "TENANT_POLICY",
        scope,
        applyOn: "DOC_TOTAL",
        totalAdjustment: roundingAdjustment,
        ...(unifiedLayer   ? { unified:   unifiedLayer }   : {}),
        ...(breakdownLayer ? { breakdown: breakdownLayer } : {}),
        ...(fallback       ? { fallback }                  : {}),
      };
    }
    // combinedDelta === 0 sin fallback → el total ya estaba en los modos
    // pedidos. No reportamos `documentRoundingApplied` para evitar
    // redondeo "fantasma" en la UI (consistente con el comportamiento
    // pre Etapa 1B).
  }

  // ── pricing-trace L12 (redondeo financiero) + L13 (engineTotal) ─────────
  {
    const dra: any = documentRoundingApplied;
    traceDocument("L12_FINANCIAL_ROUNDING", {
      applied:    !!dra,
      scope:      dra?.scope     ?? null,
      delta:      dra?.totalAdjustment ?? 0,
      unified: dra?.unified
        ? {
            pre:       dra.unified.preRounding,
            post:      dra.unified.postRounding,
            delta:     dra.unified.adjustment,
            mode:      dra.unified.mode,
            direction: dra.unified.direction,
          }
        : null,
      breakdown: dra?.breakdown
        ? {
            metal: {
              pre:       dra.breakdown.metal.preRounding,
              post:      dra.breakdown.metal.postRounding,
              delta:     dra.breakdown.metal.adjustment,
              mode:      dra.breakdown.metal.mode,
              direction: dra.breakdown.metal.direction,
            },
            hechura: {
              pre:       dra.breakdown.hechura.preRounding,
              post:      dra.breakdown.hechura.postRounding,
              delta:     dra.breakdown.hechura.adjustment,
              mode:      dra.breakdown.hechura.mode,
              direction: dra.breakdown.hechura.direction,
            },
            combinedAdjustment: dra.breakdown.combinedAdjustment,
          }
        : null,
      fallback:   dra?.fallback ?? null,
    });
    traceDocument("L13_ENGINE_TOTAL", {
      engineTotal: total,
    });
  }

  const roundingNote: string | undefined = documentRoundingApplied
    ? roundingTraceNote(documentRoundingApplied)
    : undefined;

  const sourceTrace: SaleDocumentTotalsTraceStep[] = [
    { step: "SUBTOTAL_BEFORE_DISCOUNTS",    amount: subtotalBeforeDiscounts },
    { step: "LINE_DISCOUNTS",               amount: -lineDiscountAmount },
    { step: "SUBTOTAL_AFTER_LINE_DISCOUNTS",amount: subtotalAfterLineDiscounts },
    { step: "CHANNEL",                      amount: channelAdjustmentAmount, note: input.channel?.name },
    { step: "COUPON",                       amount: -couponDiscountAmount,   note: input.coupon?.code },
    { step: "GLOBAL_DISCOUNT",              amount: -globalDiscountAmount },
    { step: "TAXABLE_BASE",                 amount: taxableBase },
    { step: "SHIPPING",                     amount: shippingAmount },
    // POLICY §Tax.4 — trace del scaling fiscal. Solo aparece cuando hubo
    // descuento de cabecera (ratio < 1). Para back-compat con consumers que
    // buscan `TAX` directo, ese step se mantiene con el valor final escalado.
    ...(scalingApplied
      ? [
          { step: "TAX_ORIGINAL", amount: originalTaxAmount, note: `ratio=${effectiveSaleRatio.toFixed(4)}` },
          { step: "TAX_FIXED",    amount: fixedTaxAmount },
          { step: "TAX_SCALED",   amount: scaledScalableTax },
        ]
      : []),
    { step: "TAX",                          amount: taxAmount },
    { step: "PAYMENT",                      amount: paymentAdjustmentAmount },
    // Etapa 1B — Capas de redondeo del documento (orden: BREAKDOWN → UNIFIED).
    ...(documentRoundingApplied?.breakdown
      ? [
          { step: "ROUNDING_BREAKDOWN_METAL",   amount: documentRoundingApplied.breakdown.metal.adjustment,   note: `${documentRoundingApplied.breakdown.metal.mode} ${documentRoundingApplied.breakdown.metal.direction}` },
          { step: "ROUNDING_BREAKDOWN_HECHURA", amount: documentRoundingApplied.breakdown.hechura.adjustment, note: `${documentRoundingApplied.breakdown.hechura.mode} ${documentRoundingApplied.breakdown.hechura.direction}` },
        ]
      : []),
    ...(documentRoundingApplied?.unified
      ? [{ step: "ROUNDING_UNIFIED", amount: documentRoundingApplied.unified.adjustment, note: `${documentRoundingApplied.unified.mode} ${documentRoundingApplied.unified.direction}` }]
      : []),
    { step: "ROUNDING",                     amount: roundingAdjustment, note: roundingNote },
    // Etapa D' — Redondeo Comercial PER_DOCUMENT (entre TAX y SHIPPING).
    ...(commercialDocumentRoundingApplied && commercialDocumentRoundingApplied.totalAdjustment !== 0
      ? [{
          step:   "COMMERCIAL_DOC_ROUNDING",
          amount: commercialDocumentRoundingApplied.totalAdjustment,
          note:   `${commercialDocumentRoundingApplied.scope}${commercialDocumentRoundingApplied.fallback ? ` fallback=${commercialDocumentRoundingApplied.fallback}` : ""}`,
        }]
      : []),
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
    taxScaling,
    roundingAdjustment,
    totalBeforeTax,
    totalWithTax,
    total,
    legacyCouponOnlyDiscount: couponDiscountAmount,
    channelResult,
    couponResult,
    sourceTrace,
    documentRoundingApplied,
    // Etapa D' — Redondeo Comercial PER_DOCUMENT
    commercialDocumentRoundingApplied,
    totalComercialPreCommercialRounding,
    totalComercialPostCommercialRounding,
    // FASE 2 — Agregados Metal/Hechura
    metalCostSubtotal,
    hechuraCostSubtotal,
    metalSaleSubtotal,
    hechuraSaleSubtotal,
    breakdownEstimated,
  };
}
