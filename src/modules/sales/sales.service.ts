import { prisma } from "../../lib/prisma.js";
import { Prisma } from "@prisma/client";
// Etapa 2 — PDF unico canonico para Factura. Toda generacion de PDF
// (descarga / impresion / adjunto mail / draft) pasa por el provider
// `saleInvoicePdfProvider`. Antes este archivo conocia los renderers
// (`renderInvoicePdf` / `renderInvoicePdfFromHtml`), el selector de
// motor (`renderInvoicePdfBuffer`) y el adapter `pdfSale`/`pdfJewelry`;
// todo eso se movio al provider para garantizar UN SOLO PUNTO de
// generacion que comparten descarga, impresion y mail.
import { renderFromPersisted as renderSaleInvoicePdfFromPersisted } from "../../lib/saleInvoicePdfProvider.js";
// 1.D — Envio de la factura por mail. Reusamos `sendMail` (que ya soporta
// attachments tras 1.C) y `generateSalePdf` para NO duplicar el PDF.
import { sendMail } from "../../lib/mail.service.js";
// E2 — Log documental del envío. Inmutable, sin propagar errores.
import { createDocumentEmailLog } from "../../lib/document-email-log.js";
// Etapa 1 (mail sender real) — SSOT del header de mail por tenant.
// Resuelve `From` (con nombre de joyería) + `Reply-To` (campo dedicado
// con fallback al email legacy). Reutilizable por presupuestos / ordenes
// / notas de credito / remitos en etapas futuras.
import { resolveTenantMailContext } from "../../lib/tenantMailContext.js";
import {
  buildManualAdjustmentSnapshot,
  type ManualAdjustmentSnapshot,
  type ManualAdjustmentPreview,
  type ManualAdjustmentBreakdownContext,
} from "../../lib/manual-adjustment/index.js";
import {
  calculateCostFromLines,
  // Etapa C/D — bugfix balanceBreakdown.metals vacío en previewSale.
  // `enrichCostMetalSteps` resuelve `metalId` y `purity` en cada step
  // `COST_LINES_METAL` consultando `MetalVariant` por id. Sin esto, los
  // steps que `calculateCostFromLines` produce quedan crudos
  // (sólo `variantId`) y `extractMetalItemsFromSteps` los descarta —
  // dejando `balanceBreakdown.metals=[]` aunque la línea SÍ tenga metal.
  enrichCostMetalSteps,
  buildBatchCostContext,
  buildBalanceBreakdownFromPrice,
  evaluatePricingPolicy,
  resolveFinalSalePrice,
  buildPricingSnapshot,
  computeLineTaxes,
  sumFixedTaxComponent,
  applySalesChannelAdjustment,
  applyCouponAdjustment,
  computeSaleDocumentTotals,
  type CostLineInput,
  type ArticleCostInput,
  type BatchCostContext,
  type PricingLineSnapshot,
  type CheckoutResult,
  type ChannelAdjustmentInput,
  type CouponInput,
  type ChannelAdjustmentResult,
  type CouponAdjustmentResult,
  type SaleDocumentTotalsLineInput,
  type SaleDocumentTotals,
  type DocumentRoundingInput,
  // FASE 2 — helper puro para armar el breakdown Metal/Hechura por línea
  // en confirmSale (que recalcula costo pero NO llama al motor entero).
  deriveMetalHechuraBreakdown,
  type PriceSource,
  // Fase 2A.7 — `sales/preview` ahora expone también costo de compra por línea
  // para tener paridad con `articles/pricing-preview`.
  computePurchaseTaxes,
  type PurchaseTaxBreakdownItem,
  type ComponentSaleDetail,
  // Sprint 3 — capa 10 del orden inmutable: resolución oficial del envío.
  resolveShippingAmount,
  // F1.4 G5 #11-A — override per costLineId (Fase 1 plumbing HTTP).
  type CostLineOverride,
  // T55 (Fase 3B.5) — Balance Mode runtime: tipo del breakdown canónico que
  // el preview/confirm exponen + el snapshot v3 persiste.
  type DocumentBalanceBreakdown,
  type BalanceMode,
  // R6 fix passthrough — el motor emite `alerts[]` por línea junto con
  // `policy`, pero el adapter del preview no las propagaba al DTO. Sin
  // ellas el frontend nunca puede derivar el commercialLevel WARNING (su
  // único disparador no-bloqueante es `alerts: [{code:"LOW_MARGIN",...}]`).
  type PricingAlert,
} from "../../lib/pricing-engine/pricing-engine.js";
// pricing-trace — diagnostic dev-only (gated por env PRICING_TRACE).
// No altera comportamiento productivo.
import {
  runWithTrace,
  resolvePricingTraceMode,
  traceDocument,
} from "../../lib/pricing-engine/pricing-trace.js";
// Etapa D' — Wiring del redondeo comercial PER_DOCUMENT.
import {
  resolveDocumentCommercialContextForSale,
  aggregateMetalsForCommercialDocRounding,
  computeCommercialRoundingPerLineImpacts,
  computeLineCommercialRoundingMetals,
  computeLineAutonomousCommercialMoney,
  type LineCommercialRoundingMetal,
} from "./commercial-doc-rounding-wiring.js";
// Importamos directamente del archivo interno (no del barrel) para no romper
// los tests del módulo sales que mockean el barrel sin esta función nueva.
import { assertCommercialDocRoundingConsistency } from "../../lib/pricing-engine/commercial-document-rounding-context.js";
// Fase 3B.5 — resolución + construcción del Balance Mode del documento.
import {
  resolveSaleBalanceMode,
  buildSaleBalanceBreakdown,
  buildDocumentMonetaryComponentsFromTotals,
  extractMetalItemsFromSteps,
  type SaleLineForBalance,
} from "./balance-mode-runtime.js";
// Helper compartido entre articles y sales para armar el bloque
// `composition` (metal/hechura/taxes). Vive fuera del motor.
import {
  buildComposition,
  buildCatalogItemsMapForCostLines,
  fetchMetalVariantInfo,
  fetchMetalVariantInfoMap,
  resolveMetalVariantIdFromResult,
  getAppliedMermaPercent,
} from "../../lib/pricing-composition.js";
// Multimoneda en preview (Fase MM). Conversión SOLO en visualización del
// preview — confirmSale persiste en moneda base.
import {
  getCurrencyDisplayContext,
  buildResponseCurrencyMetadata,
  convertSalesPreviewResponseInPlace,
  convertSalesPreviewInputInPlace,
} from "../../lib/pricing-currency-display.js";
import { getBaseCurrencyId } from "../../lib/pricing-engine/pricing-engine.currency.js";
import type { EntitySnapshot, SellerSnapshot, IssuerSnapshot, CurrencySnapshot } from "../../lib/document-snapshot.types.js";
import { calculateLineCommission } from "../../lib/seller-commission.js";
import { getCheckoutPreview } from "../payments/payments.service.js";
import { validateCoupon } from "../coupons/coupons.service.js";
import { applyMovementImpact, reverseMovementImpact } from "../../lib/stock-engine.js";
import { onSaleConfirmed, onSaleCancelled } from "../../lib/document-hooks/sale.hook.js";
import { loadDocumentRoundingConfig } from "../../lib/document-rounding.js";
import { applyDocumentPhysicalRounding } from "../../lib/document-physical-rounding-apply.js";

// ─── Helpers ────────────────────────────────────────────────────────────────
function err(msg: string, status = 400): never {
  const e: any = new Error(msg);
  e.status = status;
  throw e;
}

// La política de redondeo a nivel comprobante vive en `src/lib/document-rounding.ts`
// porque también la usa el Simulador de Artículos (articles.controller). Acá la
// importamos sin envoltorios extra.
//
// Reglas (resumen — ver el helper para el detalle):
//   · Cuando la política está apagada (modo NONE o disabled) → política inerte.
//   · Cuando está activa:
//       - `suppressListDeferredRounding = true` → el motor ignora el redondeo
//         diferido (NET/TOTAL) de las listas (anti doble redondeo).
//       - `documentRounding = { mode, direction }` → se pasa a
//         `computeSaleDocumentTotals` para redondear el total del comprobante.

async function nextSaleCode(jewelryId: string): Promise<string> {
  const last = await prisma.sale.findFirst({
    where: { jewelryId },
    orderBy: { createdAt: "desc" },
    select: { code: true },
  });
  let n = 1;
  if (last?.code) {
    const m = last.code.match(/(\d+)$/);
    if (m) n = parseInt(m[1], 10) + 1;
  }
  return `VTA-${String(n).padStart(4, "0")}`;
}

// ─── Comisión: factor de descuentos canal + cupón (legacy) ──────────────────
// Calcula `(subtotal post canal+cupón) / subtotal` para que la base de
// comisión `*_AFTER_DISCOUNTS` refleje el descuento global. Es lógica
// paralela al motor — el motor no expone esta noción todavía.
//
// TODO Fase 4: cuando computeSaleDocumentTotals() persista en el snapshot del
// documento, mover la base de comisión a leer ese snapshot y borrar este
// helper. Mientras tanto se mantiene aislado para no contaminar el cálculo
// del total del documento.
async function computeLineDiscountFactorForCommission(
  jewelryId: string,
  sale: {
    subtotal:  any;
    couponId:  string | null;
    channel?:  { id: string; name: string; adjustmentType: string; adjustmentValue: any } | null;
    seller?:   { commissionBase?: string | null } | null;
  },
): Promise<number> {
  const sellerCommBase = sale.seller?.commissionBase;
  if (
    sellerCommBase !== "TOTAL_AFTER_DISCOUNTS" &&
    sellerCommBase !== "HECHURA_AFTER_DISCOUNTS"
  ) {
    return 1;
  }
  const subForFactor = parseFloat(sale.subtotal.toString());
  if (!Number.isFinite(subForFactor) || subForFactor <= 0) return 1;

  const chInputF: ChannelAdjustmentInput | null = sale.channel
    ? {
        id:              sale.channel.id,
        name:            sale.channel.name,
        adjustmentType:  sale.channel.adjustmentType as "PERCENTAGE" | "FIXED",
        adjustmentValue: parseFloat(sale.channel.adjustmentValue.toString()),
      }
    : null;
  const chAdjF = applySalesChannelAdjustment(subForFactor, chInputF);
  let adjTotalF = chAdjF.finalAmount;

  if (sale.couponId) {
    const cpRowF = await prisma.coupon.findFirst({
      where: { id: sale.couponId, jewelryId, deletedAt: null, isActive: true },
      select: {
        id: true, code: true, name: true,
        discountType: true, discountValue: true,
        validFrom: true, validTo: true,
      },
    });
    const nowF = new Date();
    if (
      cpRowF &&
      (!cpRowF.validFrom || nowF >= cpRowF.validFrom) &&
      (!cpRowF.validTo   || nowF <= cpRowF.validTo)
    ) {
      adjTotalF = applyCouponAdjustment(chAdjF.finalAmount, {
        id:            cpRowF.id,
        code:          cpRowF.code,
        name:          cpRowF.name,
        discountType:  cpRowF.discountType as "PERCENTAGE" | "FIXED_AMOUNT",
        discountValue: parseFloat(cpRowF.discountValue.toString()),
      } as CouponInput).finalAmount;
    }
  }
  return adjTotalF / subForFactor;
}

// ─── Types ───────────────────────────────────────────────────────────────────
//
// Fase 1 hizo que `unitPrice`, `discountPct`, `priceSource`, `appliedPriceListId`
// `appliedPromotionId` y `appliedDiscountId` dejen de ser fuente de verdad —
// el motor recalcula desde `articleId/variantId/quantity/clientId`.
//
// Se mantienen en el shape solo por **compatibilidad legacy** con clientes
// viejos que siguen mandándolos. `resolveDraftSaleLinesPricing` los acepta
// como `legacyClientUnitPrice` / `legacyClientDiscountPct` (fallback solo si
// el motor no resuelve nada — ver `legacyClientUnitPrice` en ese helper).
//
// TODO Fase 7 / breaking change: dejar de aceptar estos campos y exigir solo
// `{ articleId, variantId, quantity, manualPriceOverride?, manualDiscountOverride?, taxOverride? }`.
/** Override de aplicación ("appliesTo") para descuentos/impuestos de línea.
 *  Mismo dominio que el motor (`SalePreviewLineInput`); persiste en DRAFT
 *  para reaplicarse en cada recompute. */
export type SaleLineAppliesTo =
  | "TOTAL" | "METAL" | "HECHURA" | "METAL_Y_HECHURA"
  | "SUBTOTAL_AFTER_DISCOUNT" | "SUBTOTAL_BEFORE_DISCOUNT"
  | "PRODUCT" | "SERVICE";

export type SaleLineManualDiscountOverride = {
  mode:      "PERCENT" | "AMOUNT";
  value:     number;
  appliesTo?: SaleLineAppliesTo;
  kind?:     "BONUS" | "SURCHARGE";
};

export type SaleLineTaxOverride = {
  mode:      "PERCENT" | "AMOUNT";
  value:     number;
  appliesTo?: SaleLineAppliesTo;
};

export type CreateSaleLineInput = {
  articleId: string;
  variantId?: string | null;
  quantity: number;
  /** @deprecated legacy — el motor recalcula. Se ignora salvo fallback. */
  unitPrice: number;
  /** @deprecated legacy — el motor recalcula. Se ignora salvo fallback. */
  discountPct?: number;
  /** @deprecated legacy — el motor lo emite, no lo lee. */
  priceSource?: string;
  /** @deprecated legacy — el motor lo emite, no lo lee. */
  appliedPriceListId?: string | null;
  /** @deprecated legacy — el motor lo emite, no lo lee. */
  appliedPromotionId?: string | null;
  /** @deprecated legacy — el motor lo emite, no lo lee. */
  appliedDiscountId?: string | null;

  // ── Fase 1.5 — overrides de composición que viajan a DRAFT ───────────────
  // Aplican sobre la composición de costo de esta línea (no tocan el
  // artículo maestro). El motor los recibe en `resolveDraftSaleLinesPricing`
  // y los serializa en `pricingSnapshot.costLineOverridesApplied`. Eso
  // garantiza que `confirmSale` pueda recomputar costo / margen con los
  // mismos overrides → preview ↔ draft ↔ confirm ↔ recompute paritarios.
  /** Legacy — pisa los gramos del primer METAL. */
  gramsOverride?:          number | null;
  /** Legacy — pisa el % de merma del primer METAL. */
  mermaPercentOverride?:   number | null;
  /** Legacy — cambia la variante del primer METAL (recotiza). */
  metalVariantIdOverride?: string | null;
  /** Legacy — pisa el monto unitario del primer HECHURA. */
  hechuraOverrideAmount?:  number | null;
  /**
   * F1.4 G5 #11-A — overrides per costLineId. Pisa los legacy cuando hay
   * match por id. El motor unifica vía `unifyCostLineOverrides`.
   */
  costLineOverrides?: CostLineOverride[];

  // ── Etapa 4 (cierre limitación Etapa 3) — overrides comerciales DRAFT ────
  // Inputs del operador que el motor aplica al resolver el snapshot. Persisten
  // en SaleLine para que reabrir un DRAFT no pierda el override.
  /** Precio manual unitario. Pisa el resultado de la lista. */
  manualPriceOverride?: number | null;
  /** Ajuste manual de descuento/recargo. */
  manualDiscountOverride?: SaleLineManualDiscountOverride | null;
  /** Impuesto manual de línea. */
  taxOverride?: SaleLineTaxOverride | null;
  /** Override de SOLO la base del descuento del cliente, INDEPENDIENTE
   *  del valor (el motor recalcula sobre esta base). */
  manualDiscountAppliesToOverride?: SaleLineAppliesTo | null;
  /** Override de SOLO la base del impuesto heredado. */
  manualTaxAppliesToOverride?: SaleLineAppliesTo | null;
  /** Override de lista de precios a nivel línea. Precedencia sobre la
   *  lista global del documento. */
  priceListIdOverride?: string | null;
};

export type CreateSaleInput = {
  clientId?: string | null;
  sellerId?: string | null;
  warehouseId?: string | null;
  notes?: string;
  channelId?: string | null;
  couponCode?: string | null;
  /** Etapa C16 — paridad preview ↔ persist (fix drift C15).
   *  Lista del documento. Acepta cualquier `PriceList.id` del tenant.
   *  Si la línea trae su propio `priceListIdOverride`, ese gana; sin
   *  override, las líneas heredan esta lista del documento. Si esta también
   *  es `null` o ausente, el motor cae a la jerarquía legacy
   *  (cliente → favorita → default). Mismo contrato que `PreviewSaleInput.priceListId`. */
  priceListId?: string | null;
  lines: CreateSaleLineInput[];
  /** Fase 4.2 — Override manual del Balance Mode del documento
   *  (POLICY.md §11 R11.4). Persiste en `Sale.balanceModeOverride`.
   *  Si viene `null` o ausente → resolución automática (entity → list →
   *  tenant → fallback UNIFIED). Si viene `"UNIFIED" | "BREAKDOWN"` →
   *  pisa la jerarquía y `balanceModeSource` queda `DOCUMENT_OVERRIDE`
   *  al confirmar. */
  balanceModeOverride?: "UNIFIED" | "BREAKDOWN" | null;

  // ── Etapa 1.1 — ajustes a nivel documento (paridad preview ↔ confirm) ────
  // Estos cinco campos persisten en `Sale` para que `confirmSale` pueda
  // reaplicar la MISMA lógica que `previewSale` al pasar por
  // `computeSaleDocumentTotals`. Aceptamos shape rico (`shipping`,
  // `globalDiscount` objeto) o monto plano por compatibilidad con preview.
  /** Costo de envío del documento — monto ya resuelto. Prevalece si `shipping`
   *  no viene. */
  shippingAmount?: number | null;
  /** Envío crudo: el backend lo resuelve vía `resolveShippingAmount`
   *  (POLICY.md §5) y persiste el monto resuelto en `Sale.shippingAmount`. */
  shipping?: {
    mode:    "FIXED" | "BY_WEIGHT" | "FREE";
    value?:  number | null;
    weight?: number | null;
  } | null;
  /** Descuento global del documento — shape rico. El backend persiste
   *  `globalDiscountType` + `globalDiscountValue` y resuelve el monto en
   *  cada cómputo contra el subtotal post-descuentos de línea. */
  globalDiscount?: { type: "PERCENT" | "AMOUNT"; value: number } | null;
  /** Descuento global como monto plano (compat legacy). Se convierte a
   *  `{ type: "AMOUNT", value }` al persistir. Ignorado si `globalDiscount`
   *  viene con un valor válido. */
  globalDiscountAmount?: number | null;
  /** Forma de pago seleccionada en el draft — afecta el `paymentAdjustment`
   *  del documento. FK a `PaymentMethod`. */
  paymentMethodId?: string | null;
  /** Cantidad de cuotas elegidas (≥ 1). Requiere `paymentMethodId`. El motor
   *  consulta `PaymentInstallmentPlan` y computa el ajuste por interés. */
  paymentInstallments?: number | null;
  /** Etapa A — Ajuste manual UNIFIED del comprobante (POLICY §R-Rounding-1
   *  capa 17). Persiste en `Sale.manualAdjustmentInput` mientras la venta
   *  está en DRAFT; se consume y se vacía al confirmar (`confirmSale` arma
   *  el `Sale.manualAdjustmentSnapshot` inmutable).
   *
   *  Reglas oficiales:
   *    · Etapa A: SOLO scope=UNIFIED. BREAKDOWN del ajuste manual no soportado.
   *    · `amount=0` o `null` → equivale a "sin ajuste" (Sale.manualAdjustmentInput
   *      queda en `null`). Decisión documentada en CLAUDE.md §Etapa A.
   *    · El sanitizer del controller rechaza con 400 cualquier scope distinto
   *      de UNIFIED. Acá asumimos input ya sanitizado, pero
   *      `persistManualAdjustmentInputForDraft` revalida defensivamente. */
  manualAdjustment?: import("../../lib/manual-adjustment/index.js").ManualAdjustmentInput | null;
};

export type AddPaymentInput = {
  paymentMethodId?: string | null;
  amount: number;
  installments?: number;
  reference?: string;
};

// ─── Select shapes ────────────────────────────────────────────────────────────
const SALE_LIST_SELECT = {
  id: true,
  code: true,
  status: true,
  saleDate: true,
  subtotal: true,
  discountAmount: true,
  taxAmount: true,
  total: true,
  paidAmount: true,
  notes: true,
  confirmedAt: true,
  cancelledAt: true,
  createdAt: true,
  client: { select: { id: true, displayName: true, code: true } },
  seller: { select: { id: true, firstName: true, lastName: true, displayName: true } },
  warehouse: { select: { id: true, name: true, code: true } },
  createdBy: { select: { id: true, name: true, firstName: true, lastName: true } },
  _count: { select: { lines: true } },
} satisfies Prisma.SaleSelect;

const SALE_DETAIL_SELECT = {
  ...SALE_LIST_SELECT,
  clientSnapshot: true,
  cancelNote: true,
  confirmedById: true,
  cancelledById: true,
  // ── Etapa C16.3 — paridad rehidratación DRAFT ─────────────────────────
  // El draft debe re-correr el preview con el MISMO contexto persistido al
  // guardar; sin estos campos el preview reabierto pierde canal/cupón y
  // los totales divergen del pre-save (audit C16.2 post — síntoma del
  // operador: total cambia al reabrir). `paymentMethodId` y
  // `paymentInstallments` ya estaban más abajo (Etapa 1.1) — completamos
  // canal + cupón para cerrar el gap.
  channelId: true,
  couponId:  true,
  coupon:    { select: { id: true, code: true } },
  // Fase 4.2 — Balance Mode (POLICY.md §11). Persistencia draft + hidratación
  // al cargar la venta. `balanceModeOverride` viaja entre create/update.
  // `balanceMode` y `balanceModeSource` solo se setean al confirmar (R11.1).
  balanceModeOverride: true,
  balanceMode:         true,
  balanceModeSource:   true,
  // Etapa 1.1 — ajustes a nivel documento (paridad preview ↔ confirm).
  shippingAmount:      true,
  globalDiscountType:  true,
  globalDiscountValue: true,
  paymentMethodId:     true,
  paymentInstallments: true,
  // Etapa A — Manual Adjustment. `manualAdjustmentInput` viaja en DRAFT
  // y se vacía al confirmar; `manualAdjustmentSnapshot` queda inmutable
  // tras el confirm; `engineTotal` permite reconstruir el pre-ajuste.
  manualAdjustmentInput:    true,
  manualAdjustmentSnapshot: true,
  engineTotal:              true,
  lines: {
    orderBy: { sortOrder: "asc" as const },
    select: {
      id: true,
      articleId: true,
      variantId: true,
      articleName: true,
      variantName: true,
      sku: true,
      barcode: true,
      quantity: true,
      unitPrice: true,
      discountPct: true,
      lineTotal: true,
      priceSource: true,
      appliedPriceListId: true,
      appliedPromotionId: true,
      appliedDiscountId: true,
      unitCost: true,
      totalCost: true,
      unitMargin: true,
      totalMargin: true,
      marginPercent: true,
      breakdownSnapshot: true,
      sortOrder: true,
      // Etapa 4 — overrides comerciales persistidos en DRAFT. Permiten al
      // frontend rehidratar pricingMeta.manualPrice/manualDiscount/taxOverride
      // + los flags manualOverrides.{price/discount/tax} al reabrir.
      manualPriceOverride:             true,
      manualDiscountOverride:          true,
      taxOverride:                     true,
      manualDiscountAppliesToOverride: true,
      manualTaxAppliesToOverride:      true,
      priceListIdOverride:             true,
      article: { select: { id: true, code: true, name: true, mainImageUrl: true } },
      variant: { select: { id: true, code: true, name: true } },
    },
  },
  payments: {
    orderBy: { createdAt: "asc" as const },
    select: {
      id: true,
      paymentMethodId: true,
      paymentMethodName: true,
      amount: true,
      installments: true,
      reference: true,
      paidAt: true,
      createdAt: true,
      paymentMethod: { select: { id: true, name: true, type: true } },
    },
  },
  // 1.A — Receipts emitidos al confirmar la venta. `Receipt.code` es la
  // numeracion oficial del comprobante (formato `<prefix>-<pos>-<n>`,
  // ej. "A-0001-00000001") generada atomicamente por `ReceiptSeries` en
  // `sale.hook.ts`. El frontend usa este code como "Factura N°" en el
  // header del modal y como nombre del PDF descargado.
  receipts: {
    orderBy: { issuedAt: "asc" as const },
    select: {
      id:        true,
      code:      true,
      type:      true,
      direction: true,
      status:    true,
      issueDate: true,
      issuedAt:  true,
    },
  },
} satisfies Prisma.SaleSelect;

// ─── List ────────────────────────────────────────────────────────────────────
export async function listSales(
  jewelryId: string,
  opts: {
    skip?: number;
    take?: number;
    status?: string;
    clientId?: string;
    sellerId?: string;
    q?: string;
    dateFrom?: string;
    dateTo?: string;
  }
) {
  const { skip = 0, take = 50, status, clientId, sellerId, q, dateFrom, dateTo } = opts;

  const where: Prisma.SaleWhereInput = {
    jewelryId,
    ...(status && { status: status as any }),
    ...(clientId && { clientId }),
    ...(sellerId && { sellerId }),
    ...(dateFrom || dateTo
      ? {
          saleDate: {
            ...(dateFrom && { gte: new Date(dateFrom) }),
            ...(dateTo && { lte: new Date(dateTo) }),
          },
        }
      : {}),
    ...(q
      ? {
          OR: [
            { code: { contains: q, mode: "insensitive" } },
            { client: { displayName: { contains: q, mode: "insensitive" } } },
            { notes: { contains: q, mode: "insensitive" } },
          ],
        }
      : {}),
  };

  const [data, total] = await Promise.all([
    prisma.sale.findMany({
      where,
      select: SALE_LIST_SELECT,
      orderBy: { saleDate: "desc" },
      skip,
      take,
    }),
    prisma.sale.count({ where }),
  ]);

  return { data, total, skip, take };
}

// ─── Get one ─────────────────────────────────────────────────────────────────
export async function getSale(id: string, jewelryId: string) {
  const sale = await prisma.sale.findFirst({
    where: { id, jewelryId },
    select: SALE_DETAIL_SELECT,
  });
  if (!sale) err("Venta no encontrada.", 404);

  // Aggregate cost/margin totals across lines (null when no line has cost data)
  const lines = (sale as any).lines as Array<{
    lineTotal: any; totalCost: any; totalMargin: any; marginPercent: any;
  }>;
  const linesWithCost = lines.filter((l) => l.totalCost != null);
  let saleTotals: {
    revenue: string; cost: string; margin: string; marginPercent: string; linesWithoutCost: number;
  } | null = null;

  if (linesWithCost.length > 0) {
    let revenue = new Prisma.Decimal(0);
    let cost    = new Prisma.Decimal(0);
    for (const l of lines) {
      revenue = revenue.add(new Prisma.Decimal(l.lineTotal?.toString() ?? "0"));
      if (l.totalCost != null) cost = cost.add(new Prisma.Decimal(l.totalCost.toString()));
    }
    const margin        = revenue.sub(cost);
    const marginPct     = revenue.gt(0) ? margin.div(revenue).mul(100) : new Prisma.Decimal(0);
    saleTotals = {
      revenue:       revenue.toFixed(2),
      cost:          cost.toFixed(2),
      margin:        margin.toFixed(2),
      marginPercent: marginPct.toFixed(4),
      linesWithoutCost: lines.length - linesWithCost.length,
    };
  }

  return { ...sale, saleTotals };
}

// ─── Create (DRAFT) ──────────────────────────────────────────────────────────

// ── Helper Manual Adjustment (DRAFT) ──────────────────────────────────────
// Defensa en profundidad: reutilizamos el sanitizer canónico (compartido
// con el controller) que soporta scope "UNIFIED" (Etapa A) y "BREAKDOWN"
// (Etapa C). Reglas en `lib/manual-adjustment/sanitize.ts`.
//
// El gate adicional "BREAKDOWN solo cuando el documento opera en modo
// BREAKDOWN" NO se aplica acá — vive en el caller (previewSale/confirmSale)
// que resolvió el balanceMode del documento.
import { sanitizeManualAdjustmentInput as sanitizeManualAdjustmentInputForDraft } from "../../lib/manual-adjustment/index.js";

/**
 * Etapa C — adapter `DocumentBalanceBreakdown → ManualAdjustmentBreakdownContext`.
 *
 * El helper `buildManualAdjustmentSnapshot` es PURO y necesita conocer:
 *   · `monetaryHechura.preAmount` = saldo monetario pre-ajuste (el motor lo
 *     emite en `balanceBreakdown.monetaryBalance.amount`).
 *   · `metals[]` con `gramsPure` y `metalPricePerGram` por metal padre.
 *
 * En modo UNIFIED, `metals=[]` y `monetaryBalance.amount === documentTotals.total`.
 * El helper igualmente recibe el contexto: si el input es UNIFIED lo ignora.
 *
 * Cero matemática comercial — solo selecciona campos del breakdown ya
 * normalizado por `pricing-engine.balance.ts`.
 */
function buildManualAdjustmentBreakdownContext(
  balanceBreakdown: DocumentBalanceBreakdown,
): ManualAdjustmentBreakdownContext {
  return {
    monetaryHechura: {
      preAmount: Number(balanceBreakdown.monetaryBalance?.amount ?? 0) || 0,
    },
    metals: (balanceBreakdown.metals ?? []).map((m: any) => ({
      metalParentId:     m.metalParentId ?? null,
      metalParentName:   String(m.metalParentName ?? ""),
      gramsPure:         Number(m.gramsPure ?? 0) || 0,
      metalPricePerGram: typeof m.quotePriceSnapshot === "number" && Number.isFinite(m.quotePriceSnapshot)
        ? m.quotePriceSnapshot
        : null,
    })),
  };
}

// ── Helper Etapa 1.1: ajustes a nivel documento ────────────────────────────
// Sanitiza y resuelve los 5 campos que persisten en `Sale` para garantizar
// paridad preview ↔ confirm. Mismo orden de precedencia que `previewSale`:
//   · `shipping` crudo > `shippingAmount` plano > 0.
//   · `globalDiscount {type,value}` > `globalDiscountAmount` (→ AMOUNT) > 0.
//   · `paymentMethodId`: solo se persiste si pertenece al tenant y está
//     activo; en caso contrario, queda en null silenciosamente (mismo
//     comportamiento que el preview, que falla al checkout sin payment).
//   · `paymentInstallments`: clamp a entero ≥ 1; sin paymentMethodId → null.
//
// El helper devuelve solo lo que va al `data` de Prisma — los campos
// undefined se omiten para no pisar valores existentes en update().
type SaleDocumentAdjustmentsInput = Pick<
  CreateSaleInput,
  "shipping" | "shippingAmount" | "globalDiscount" | "globalDiscountAmount"
  | "paymentMethodId" | "paymentInstallments"
>;

interface SaleDocumentAdjustmentsPersistShape {
  shippingAmount:      number | null;
  globalDiscountType:  "PERCENT" | "AMOUNT" | null;
  globalDiscountValue: number | null;
  paymentMethodId:     string | null;
  paymentInstallments: number | null;
}

async function sanitizeSaleDocumentAdjustments(
  jewelryId: string,
  body: SaleDocumentAdjustmentsInput,
): Promise<SaleDocumentAdjustmentsPersistShape> {
  // ── Shipping ───────────────────────────────────────────────────────────
  let shippingAmount: number | null = null;
  if (body.shipping !== undefined && body.shipping !== null) {
    const resolved = resolveShippingAmount(body.shipping);
    shippingAmount = resolved ? resolved.amount : null;
  } else if (body.shippingAmount != null) {
    const n = Number(body.shippingAmount);
    shippingAmount = Number.isFinite(n) && n >= 0
      ? Math.round(n * 100) / 100
      : null;
  }

  // ── Global discount ────────────────────────────────────────────────────
  let globalDiscountType:  "PERCENT" | "AMOUNT" | null = null;
  let globalDiscountValue: number | null               = null;
  if (
    body.globalDiscount &&
    (body.globalDiscount.type === "PERCENT" || body.globalDiscount.type === "AMOUNT") &&
    Number.isFinite(body.globalDiscount.value) &&
    body.globalDiscount.value > 0
  ) {
    globalDiscountType  = body.globalDiscount.type;
    globalDiscountValue = body.globalDiscount.value;
  } else if (body.globalDiscountAmount != null) {
    const n = Number(body.globalDiscountAmount);
    if (Number.isFinite(n) && n > 0) {
      globalDiscountType  = "AMOUNT";
      globalDiscountValue = n;
    }
  }

  // ── Payment method + installments ──────────────────────────────────────
  let paymentMethodId:     string | null = null;
  let paymentInstallments: number | null = null;
  if (body.paymentMethodId) {
    const pm = await prisma.paymentMethod.findFirst({
      where: { id: body.paymentMethodId, jewelryId, deletedAt: null, isActive: true },
      select: { id: true },
    });
    if (pm) {
      paymentMethodId = pm.id;
      const raw = body.paymentInstallments != null
        ? parseInt(String(body.paymentInstallments), 10)
        : 1;
      paymentInstallments = Number.isFinite(raw) && raw >= 1
        ? Math.min(999, Math.trunc(raw))
        : 1;
    }
    // Si el paymentMethod no es válido, silenciosamente cae a null — mismo
    // criterio que `previewSale` cuando el checkout no resuelve.
  }

  return {
    shippingAmount,
    globalDiscountType,
    globalDiscountValue,
    paymentMethodId,
    paymentInstallments,
  };
}

export async function createSale(
  jewelryId: string,
  userId: string,
  body: CreateSaleInput
) {
  if (!body.lines?.length) err("La venta debe tener al menos una línea.");

  // Validate articles exist and belong to tenant
  const articleIds = [...new Set(body.lines.map((l) => l.articleId))];
  const articles = await prisma.article.findMany({
    where: { id: { in: articleIds }, jewelryId, deletedAt: null },
    select: {
      id: true,
      name: true,
      code: true,
      sku: true,
      barcode: true,
      salePrice: true,
      _count: { select: { variants: { where: { deletedAt: null, isActive: true } } } },
    },
  });
  const articleMap = new Map(articles.map((a) => [a.id, a]));

  const variantIds = body.lines
    .filter((l) => l.variantId)
    .map((l) => l.variantId!);
  const variants =
    variantIds.length > 0
      ? await prisma.articleVariant.findMany({
          where: { id: { in: variantIds }, jewelryId, deletedAt: null, isActive: true },
          select: { id: true, name: true, sku: true, barcode: true },
        })
      : [];
  const variantMap = new Map(variants.map((v) => [v.id, v]));

  // Validate each line
  for (const line of body.lines) {
    if (!articleMap.has(line.articleId))
      err(`Artículo ${line.articleId} no encontrado.`);
    const art = articleMap.get(line.articleId)!;

    // variantId es obligatorio si el artículo tiene variantes activas
    const activeVariantCount = (art as any)._count?.variants ?? 0;
    if (activeVariantCount > 0 && !line.variantId)
      err(`El artículo "${art.name}" tiene variantes. Especificá la variante en cada línea.`);

    if (line.variantId && !variantMap.has(line.variantId))
      err(`Variante "${line.variantId}" no encontrada, inactiva o no pertenece al artículo "${art.name}".`);
    if (line.quantity <= 0) err("La cantidad debe ser mayor a 0.");
    if (line.unitPrice < 0) err("El precio unitario no puede ser negativo.");
  }

  // Validate channel
  if (body.channelId) {
    const ch = await prisma.salesChannel.findFirst({
      where: { id: body.channelId, jewelryId, deletedAt: null, isActive: true },
      select: { id: true },
    });
    if (!ch) err("Canal de venta no encontrado o inactivo.");
  }

  // Resolve couponCode → couponId (existence only, redemption deferred to confirm)
  let resolvedCouponId: string | null = null;
  if (body.couponCode) {
    const couponExist = await prisma.coupon.findFirst({
      where: { jewelryId, code: body.couponCode.trim().toUpperCase(), deletedAt: null, isActive: true },
      select: { id: true },
    });
    if (!couponExist) err("Cupón no encontrado o inactivo.");
    resolvedCouponId = couponExist!.id;
  }

  const code = await nextSaleCode(jewelryId);

  // ── Resolución de precio por línea — fuente única de verdad ────────────────
  // El cliente puede mandar `unitPrice` y `discountPct` por compatibilidad,
  // pero NO los usamos como fuente principal. El motor recalcula desde
  // articleId/variantId/quantity/clientId. Si el motor no resuelve, el helper
  // hace fallback al legacy con log.
  const resolved = await resolveDraftSaleLinesPricing(
    jewelryId,
    body.lines.map((line) => ({
      articleId: line.articleId,
      variantId: line.variantId ?? null,
      quantity:  line.quantity,
      legacyClientUnitPrice:   line.unitPrice,
      legacyClientDiscountPct: line.discountPct,
      // Fase 1.5 — los overrides viajan al snapshot persistido para que
      // confirm/recompute mantengan paridad con preview.
      gramsOverride:          line.gramsOverride          ?? null,
      mermaPercentOverride:   line.mermaPercentOverride   ?? null,
      metalVariantIdOverride: line.metalVariantIdOverride ?? null,
      hechuraOverrideAmount:  line.hechuraOverrideAmount  ?? null,
      costLineOverrides:      line.costLineOverrides,
      manualDiscountAppliesToOverride: line.manualDiscountAppliesToOverride ?? null,
      manualTaxAppliesToOverride:      line.manualTaxAppliesToOverride      ?? null,
      // Etapa 4 — overrides comerciales del operador.
      manualPriceOverride:    line.manualPriceOverride    ?? null,
      manualDiscountOverride: line.manualDiscountOverride ?? null,
      taxOverride:            line.taxOverride            ?? null,
      priceListIdOverride:    line.priceListIdOverride    ?? null,
    })),
    {
      clientId:    body.clientId ?? null,
      // Etapa C16 — propagación de la lista global del documento al motor
      // por línea. Sin esto se pierde el cambio del combo global (drift C15).
      priceListId: body.priceListId ?? null,
    },
  );

  // ── Armar payload de líneas a persistir ──────────────────────────────────
  // Mantenemos `subtotal = suma de lineTotal` para la grilla de líneas, pero
  // los totales del DOCUMENTO (canal/cupón/IVA/envío/payment/ajuste manual)
  // ahora vienen del motor del PREVIEW vía `computeDraftTotalsFromBody`, para
  // que el listado de Facturas (lee `Sale.total`) coincida con el card "Total
  // del comprobante" del editor (lee `previewResult.finalTotal`). Sin esta
  // alineación, el DRAFT en DB persistía `total = subtotal` (sin descuentos
  // doc), divergiendo del número que vio el operador.
  let subtotal = 0;
  const linesData = body.lines.map((line, idx) => {
    const r   = resolved[idx];
    const art = articleMap.get(line.articleId)!;
    const vnt = line.variantId ? variantMap.get(line.variantId) : undefined;
    subtotal += r.lineTotal;

    return {
      jewelryId,
      articleId:   line.articleId,
      variantId:   line.variantId ?? null,
      articleName: art.name,
      variantName: vnt?.name ?? "",
      sku:         vnt?.sku || art.sku,
      barcode:     vnt?.barcode || art.barcode || "",
      quantity:    line.quantity,
      unitPrice:   r.unitPrice,
      discountPct: r.discountPct,
      lineTotal:   r.lineTotal,
      priceSource:        r.priceSource,
      appliedPriceListId: r.appliedPriceListId,
      appliedPromotionId: r.appliedPromotionId,
      appliedDiscountId:  r.appliedDiscountId,
      pricingSnapshot:    r.pricingSnapshot as any,
      sortOrder: idx,
      // Etapa 4 — persistir overrides comerciales del operador.
      manualPriceOverride:             line.manualPriceOverride    ?? null,
      manualDiscountOverride:          (line.manualDiscountOverride ?? null) as Prisma.InputJsonValue,
      taxOverride:                     (line.taxOverride            ?? null) as Prisma.InputJsonValue,
      manualDiscountAppliesToOverride: line.manualDiscountAppliesToOverride ?? null,
      manualTaxAppliesToOverride:      line.manualTaxAppliesToOverride      ?? null,
      priceListIdOverride:             line.priceListIdOverride    ?? null,
    };
  });

  // Fase 4.2 — `balanceModeOverride` opcional. Sanitizamos: solo UNIFIED/
  // BREAKDOWN se persisten; cualquier otro valor (inválido) → null.
  const balanceModeOverride =
    body.balanceModeOverride === "UNIFIED" || body.balanceModeOverride === "BREAKDOWN"
      ? body.balanceModeOverride
      : null;

  // Etapa 1.1 — ajustes a nivel documento. Persistimos siempre los 5 campos
  // (en null si no se enviaron) para que `confirmSale` los reaplique 1:1.
  const adjustments = await sanitizeSaleDocumentAdjustments(jewelryId, body);

  // Etapa A — Manual Adjustment. Sanitiza la intención del operador y la
  // persiste en `Sale.manualAdjustmentInput`. Si `amount=0`/ausente → `null`.
  // Scope distinto de UNIFIED → 400 lanzado por el sanitizer.
  const manualAdjustmentForDraft = sanitizeManualAdjustmentInputForDraft(
    body.manualAdjustment,
    "sales.create.manualAdjustment",
  );

  const sale = await prisma.sale.create({
    data: {
      jewelryId,
      code,
      status: "DRAFT",
      clientId: body.clientId ?? null,
      sellerId: body.sellerId ?? null,
      warehouseId: body.warehouseId ?? null,
      channelId: body.channelId ?? null,
      couponId: resolvedCouponId,
      notes: body.notes ?? "",
      // Placeholder inicial: el siguiente paso (`syncDraftDocumentTotals`)
      // sobrescribe con los totales del motor del PREVIEW (paridad con
      // el card "Total del comprobante" del editor).
      subtotal,
      discountAmount: 0,
      taxAmount: 0,
      total: subtotal,
      paidAmount: 0,
      createdById: userId || null,
      lines: { create: linesData },
      ...(balanceModeOverride != null && { balanceModeOverride }),
      shippingAmount:      adjustments.shippingAmount,
      globalDiscountType:  adjustments.globalDiscountType,
      globalDiscountValue: adjustments.globalDiscountValue,
      paymentMethodId:     adjustments.paymentMethodId,
      paymentInstallments: adjustments.paymentInstallments,
      // Etapa A — intención del operador. `null` => sin ajuste.
      manualAdjustmentInput: manualAdjustmentForDraft
        ? (manualAdjustmentForDraft as unknown as Prisma.InputJsonValue)
        : Prisma.JsonNull,
    } as any,
    select: SALE_DETAIL_SELECT,
  });

  // Alineación DRAFT ↔ "Total del comprobante": tras crear, sincronizamos los
  // totales con el motor del PREVIEW (capa única de cálculo). Garantiza que
  // el listado de Facturas (lee `Sale.total`) muestre el MISMO importe que
  // el card del editor (lee `previewResult.finalTotal`).
  //
  // Etapa 2.2 — Manejo del 400 funcional: a partir de la 2.3, syncDraftDocumentTotals
  // RELANZA los errores 400 del motor (gate scope BREAKDOWN+UNIFIED, sanitizer, etc.)
  // en vez de tragarlos. Si eso ocurre acá, la Sale ya fue persistida → quedaría
  // huérfana con totales placeholder y el operador vería un error sin nada limpiado.
  // Hacemos rollback explícito (delete + cascade a SaleLine) antes de relanzar.
  // Para errores no-400 (técnicos), syncDraftDocumentTotals los sigue tragando
  // internamente y devuelve `detail` → no entra a este catch.
  let synced: any;
  try {
    synced = await syncDraftDocumentTotals(sale.id, jewelryId, sale);
  } catch (syncErr) {
    if ((syncErr as any)?.status === 400) {
      try {
        await prisma.sale.delete({ where: { id: sale.id } });
      } catch (rollbackErr) {
        console.warn(
          `[sales.createSale] rollback de draft ${sale.id} falló tras 400 del sync: ${(rollbackErr as any)?.message ?? rollbackErr}`,
        );
      }
    }
    throw syncErr;
  }
  return synced ?? sale;
}

// ─── Update lines / metadata (DRAFT only) ────────────────────────────────────
export async function updateSale(
  id: string,
  jewelryId: string,
  body: Partial<CreateSaleInput> & { notes?: string }
) {
  // Etapa 2.2 — Capturamos `manualAdjustmentInput` previo para poder revertir si
  // el sync interno tira 400 (gate scope BREAKDOWN+UNIFIED). Sin esto el draft
  // queda en loop: el input persistido es exactamente lo que el motor rechaza,
  // y cualquier nuevo sync vuelve a tirar 400 sin manera de salir.
  const sale = await prisma.sale.findFirst({
    where: { id, jewelryId },
    select: { id: true, status: true, clientId: true, manualAdjustmentInput: true },
  });
  if (!sale) err("Venta no encontrada.", 404);
  const previousManualAdjustmentInput = (sale as any).manualAdjustmentInput ?? null;
  if (sale.status !== "DRAFT") err("Solo se pueden editar ventas en estado BORRADOR.");

  const updateData: any = {};
  if (body.clientId !== undefined) updateData.clientId = body.clientId;
  if (body.sellerId !== undefined) updateData.sellerId = body.sellerId;
  if (body.warehouseId !== undefined) updateData.warehouseId = body.warehouseId;
  if (body.notes !== undefined) updateData.notes = body.notes;
  // Fase 4.2 — `balanceModeOverride` opcional. `undefined` = no tocar el campo
  // (preserva el valor actual). `null` = volver a resolución automática.
  // Cualquier valor distinto de UNIFIED/BREAKDOWN se sanitiza a `null` (no
  // se conserva el campo a medio inválido).
  if (body.balanceModeOverride !== undefined) {
    updateData.balanceModeOverride =
      body.balanceModeOverride === "UNIFIED" || body.balanceModeOverride === "BREAKDOWN"
        ? body.balanceModeOverride
        : null;
  }

  // Etapa A — Manual Adjustment. Patrón "undefined = no tocar" igual que el
  // balance mode override. `null` o `{amount:0}` → limpiar (Prisma.JsonNull).
  // Scope distinto de UNIFIED → 400.
  if (body.manualAdjustment !== undefined) {
    const cleaned = sanitizeManualAdjustmentInputForDraft(
      body.manualAdjustment,
      "sales.update.manualAdjustment",
    );
    updateData.manualAdjustmentInput = cleaned
      ? (cleaned as unknown as Prisma.InputJsonValue)
      : Prisma.JsonNull;
  }

  // Etapa 1.1 — ajustes a nivel documento. Patrón "undefined = no tocar":
  // solo persistimos las claves que el body trajo. Si el body no menciona
  // un campo, conservamos el valor actual de la Sale.
  const adjustmentKeyHit =
       body.shipping             !== undefined
    || body.shippingAmount       !== undefined
    || body.globalDiscount       !== undefined
    || body.globalDiscountAmount !== undefined
    || body.paymentMethodId      !== undefined
    || body.paymentInstallments  !== undefined;
  if (adjustmentKeyHit) {
    const adj = await sanitizeSaleDocumentAdjustments(jewelryId, body);
    if (body.shipping !== undefined || body.shippingAmount !== undefined) {
      updateData.shippingAmount = adj.shippingAmount;
    }
    if (body.globalDiscount !== undefined || body.globalDiscountAmount !== undefined) {
      updateData.globalDiscountType  = adj.globalDiscountType;
      updateData.globalDiscountValue = adj.globalDiscountValue;
    }
    if (body.paymentMethodId !== undefined) {
      updateData.paymentMethodId     = adj.paymentMethodId;
      updateData.paymentInstallments = adj.paymentInstallments;
    } else if (body.paymentInstallments !== undefined) {
      // Solo viene installments sin tocar el método. Persistimos el valor
      // saneado tal cual: si la sale ya tenía paymentMethodId, el motor en
      // confirm lo usa; si no, getCheckoutPreview no se invoca y el campo
      // queda inocuo (matemáticamente neutral).
      if (body.paymentInstallments == null) {
        updateData.paymentInstallments = null;
      } else {
        const raw = parseInt(String(body.paymentInstallments), 10);
        updateData.paymentInstallments = Number.isFinite(raw) && raw >= 1
          ? Math.min(999, Math.trunc(raw))
          : null;
      }
    }
  }

  if (body.lines) {
    // Re-calculate lines
    const articleIds = [...new Set(body.lines.map((l) => l.articleId))];
    const articles = await prisma.article.findMany({
      where: { id: { in: articleIds }, jewelryId, deletedAt: null },
      select: {
        id: true,
        name: true,
        sku: true,
        barcode: true,
        _count: { select: { variants: { where: { deletedAt: null, isActive: true } } } },
      },
    });
    const articleMap = new Map(articles.map((a) => [a.id, a]));

    const variantIds = body.lines.filter((l) => l.variantId).map((l) => l.variantId!);
    const variants = variantIds.length > 0
      ? await prisma.articleVariant.findMany({
          where: { id: { in: variantIds }, jewelryId, deletedAt: null, isActive: true },
          select: { id: true, name: true, sku: true, barcode: true },
        })
      : [];
    const variantMap = new Map(variants.map((v) => [v.id, v]));

    // Validate variantId required when article has active variants
    for (const line of body.lines) {
      const art = articleMap.get(line.articleId);
      const activeVariantCount = (art as any)?._count?.variants ?? 0;
      if (activeVariantCount > 0 && !line.variantId)
        err(`El artículo "${art?.name ?? line.articleId}" tiene variantes. Especificá la variante en cada línea.`);
      if (line.variantId && !variantMap.has(line.variantId))
        err(`Variante "${line.variantId}" no encontrada, inactiva o no pertenece al artículo.`);
    }

    // ── Resolución de precio por línea — fuente única de verdad ──────────
    // Para `clientId` usamos el del body si vino, si no el de la venta actual.
    const effectiveClientId =
      body.clientId !== undefined ? body.clientId : (sale as any).clientId ?? null;
    const resolved = await resolveDraftSaleLinesPricing(
      jewelryId,
      body.lines.map((line) => ({
        articleId: line.articleId,
        variantId: line.variantId ?? null,
        quantity:  line.quantity,
        legacyClientUnitPrice:   line.unitPrice,
        legacyClientDiscountPct: line.discountPct,
        // Fase 1.5 — paridad con createSale: los overrides viajan a draft.
        gramsOverride:          line.gramsOverride          ?? null,
        mermaPercentOverride:   line.mermaPercentOverride   ?? null,
        metalVariantIdOverride: line.metalVariantIdOverride ?? null,
        hechuraOverrideAmount:  line.hechuraOverrideAmount  ?? null,
        costLineOverrides:      line.costLineOverrides,
        manualDiscountAppliesToOverride: line.manualDiscountAppliesToOverride ?? null,
        manualTaxAppliesToOverride:      line.manualTaxAppliesToOverride      ?? null,
        // Etapa 4 — overrides comerciales.
        manualPriceOverride:    line.manualPriceOverride    ?? null,
        manualDiscountOverride: line.manualDiscountOverride ?? null,
        taxOverride:            line.taxOverride            ?? null,
        priceListIdOverride:    line.priceListIdOverride    ?? null,
      })),
      {
        clientId: effectiveClientId,
        // Etapa C16 — propagación de la lista global del documento al motor
        // por línea. Mismo patrón que createSale. Sin esto, al editar una
        // venta DRAFT el cambio del combo global se perdía.
        priceListId: body.priceListId ?? null,
      },
    );

    let subtotal = 0;
    const linesData = body.lines.map((line, idx) => {
      const r   = resolved[idx];
      const art = articleMap.get(line.articleId)!;
      const vnt = line.variantId ? variantMap.get(line.variantId) : undefined;
      subtotal += r.lineTotal;
      return {
        jewelryId,
        articleId:   line.articleId,
        variantId:   line.variantId ?? null,
        articleName: art?.name ?? "",
        variantName: vnt?.name ?? "",
        sku:         vnt?.sku || art?.sku || "",
        barcode:     vnt?.barcode || art?.barcode || "",
        quantity:    line.quantity,
        unitPrice:   r.unitPrice,
        discountPct: r.discountPct,
        lineTotal:   r.lineTotal,
        priceSource:        r.priceSource,
        appliedPriceListId: r.appliedPriceListId,
        appliedPromotionId: r.appliedPromotionId,
        appliedDiscountId:  r.appliedDiscountId,
        pricingSnapshot:    r.pricingSnapshot as any,
        sortOrder: idx,
        // Etapa 4 — persistir overrides comerciales.
        manualPriceOverride:             line.manualPriceOverride    ?? null,
        manualDiscountOverride:          (line.manualDiscountOverride ?? null) as Prisma.InputJsonValue,
        taxOverride:                     (line.taxOverride            ?? null) as Prisma.InputJsonValue,
        manualDiscountAppliesToOverride: line.manualDiscountAppliesToOverride ?? null,
        manualTaxAppliesToOverride:      line.manualTaxAppliesToOverride      ?? null,
        priceListIdOverride:             line.priceListIdOverride    ?? null,
      };
    });

    updateData.subtotal = subtotal;
    updateData.total = subtotal;
    updateData.lines = { deleteMany: { saleId: id }, create: linesData };
  }

  await prisma.sale.update({ where: { id }, data: updateData });
  // Misma sync que createSale: tras el update, recomputamos `subtotal /
  // discountAmount / taxAmount / total` desde el motor del PREVIEW para que
  // el listado de Facturas siga alineado con el card "Total del comprobante".
  //
  // Etapa 2.2 — Si el sync tira 400 (gate funcional), revertimos el
  // `manualAdjustmentInput` al valor previo para evitar dejar el draft en loop.
  // El operador ve el 400 y puede corregir desde un estado consistente.
  // Errores no-400 los traga internamente el sync (devuelve detail).
  let synced: any;
  try {
    synced = await syncDraftDocumentTotals(id, jewelryId);
  } catch (syncErr) {
    if (
      (syncErr as any)?.status === 400 &&
      updateData.manualAdjustmentInput !== undefined
    ) {
      try {
        await prisma.sale.update({
          where: { id },
          data: {
            manualAdjustmentInput: previousManualAdjustmentInput == null
              ? Prisma.JsonNull
              : (previousManualAdjustmentInput as unknown as Prisma.InputJsonValue),
          } as any,
        });
      } catch (rollbackErr) {
        console.warn(
          `[sales.updateSale] revert de manualAdjustmentInput falló tras 400 del sync para ${id}: ${(rollbackErr as any)?.message ?? rollbackErr}`,
        );
      }
    }
    throw syncErr;
  }
  return synced ?? getSale(id, jewelryId);
}

// ─── Sync de totales DRAFT con el motor del PREVIEW ──────────────────────────
//
// Mata la divergencia entre lo que ve el operador en el card "Total del
// comprobante" y lo que muestra el listado de Facturas. Se invoca al final
// de `createSale` y `updateSale` cuando la venta queda en DRAFT.
//
// Flujo:
//   1. Lee la Sale persistida (líneas + ajustes doc-level + manualAdjustment).
//   2. Si NO está en DRAFT → devuelve el detalle tal cual (CONFIRMED es
//      inmutable; sus totales ya vienen del confirmSale).
//   3. Compone un `SalePreviewInput` reproduciendo exactamente el shape que
//      enviaría el frontend al endpoint de preview.
//   4. Llama `previewSale(jewelryId, input)` — fuente única de verdad.
//   5. Persiste los totales del motor en `Sale` mediante un único update.
//
// Failure-safe: si el preview falla por cualquier razón (lista borrada, etc.)
// el documento sigue persistido con los totales placeholder anteriores. El
// listado queda con el número viejo, pero confirmSale sigue funcionando.
export async function syncDraftDocumentTotals(
  saleId: string,
  jewelryId: string,
  presetDetail?: any,
) {
  // Failure-safe: si algo del pipeline rompe (mocks de tests, lista borrada,
  // datos inconsistentes), devolvemos el detail sin alinear totales en lugar
  // de tirar el endpoint. El comprobante sigue en DB y `confirmSale` igual
  // recalcula desde el motor.
  let detail: any = presetDetail ?? null;
  if (!detail) {
    try {
      detail = await getSale(saleId, jewelryId);
    } catch (e) {
      console.warn(
        `[sales.syncDraftDocumentTotals] getSale falló para ${saleId}: ${(e as any)?.message ?? e}`,
      );
      return null;
    }
  }
  if (!detail || detail.status !== "DRAFT") return detail;

  // ── Compone SalePreviewInput desde la persistencia ────────────────────────
  const lines = (detail.lines ?? []) as Array<any>;
  if (lines.length === 0) return detail; // sin líneas no hay motor que correr.

  // Derivar priceListId doc-level: si todas las líneas comparten el mismo
  // `appliedPriceListId` y ninguna tiene `priceListIdOverride` propio, ése
  // es el global. Mismo criterio que el frontend usa para rehidratar.
  let derivedDocPriceListId: string | null = null;
  const linePriceListIds = new Set(
    lines.map((l) => l.priceListIdOverride ?? l.appliedPriceListId ?? null),
  );
  const linesHaveExplicitOverride = lines.some(
    (l) => l.priceListIdOverride != null,
  );
  if (!linesHaveExplicitOverride && linePriceListIds.size === 1) {
    const only = [...linePriceListIds][0];
    if (only) derivedDocPriceListId = only;
  }

  // globalDiscount — reconstruir desde los campos persistidos.
  const gdType  = detail.globalDiscountType ?? null;
  const gdValue =
    detail.globalDiscountValue != null
      ? Number(detail.globalDiscountValue.toString())
      : null;
  const globalDiscount =
    (gdType === "PERCENT" || gdType === "AMOUNT") &&
    gdValue != null &&
    Number.isFinite(gdValue) &&
    gdValue > 0
      ? { type: gdType as "PERCENT" | "AMOUNT", value: gdValue }
      : null;

  // shippingAmount — número plano (el motor lo trata como ya resuelto).
  const shippingAmount =
    detail.shippingAmount != null
      ? Number(detail.shippingAmount.toString())
      : undefined;

  const previewInput: SalePreviewInput = {
    lines: lines.map((l) => ({
      type: "ARTICLE" as const,
      articleId: l.articleId,
      variantId: l.variantId ?? null,
      quantity:  Number(l.quantity?.toString?.() ?? l.quantity ?? 0),
      manualPriceOverride:
        l.manualPriceOverride != null
          ? Number(l.manualPriceOverride.toString())
          : null,
      manualDiscountOverride:          l.manualDiscountOverride ?? null,
      taxOverride:                     l.taxOverride ?? null,
      manualDiscountAppliesToOverride: l.manualDiscountAppliesToOverride ?? null,
      manualTaxAppliesToOverride:      l.manualTaxAppliesToOverride ?? null,
      priceListIdOverride:             l.priceListIdOverride ?? null,
    })),
    clientId:        detail.client?.id ?? null,
    paymentMethodId: detail.paymentMethodId ?? null,
    installmentsQty:
      detail.paymentInstallments != null
        ? Number(detail.paymentInstallments)
        : 0,
    channelId:       detail.channelId ?? null,
    couponCode:      detail.coupon?.code ?? null,
    shippingAmount,
    globalDiscount,
    priceListId:     derivedDocPriceListId,
    balanceModeOverride:
      detail.balanceModeOverride === "UNIFIED" ||
      detail.balanceModeOverride === "BREAKDOWN"
        ? detail.balanceModeOverride
        : null,
    manualAdjustment: detail.manualAdjustmentInput ?? null,
  };

  // Llamamos al motor — fuente única de verdad.
  //
  // Etapa 2.3 — Política failure-safe diferenciada:
  //   · Errores FUNCIONALES (err.status === 400) — gate de scope BREAKDOWN vs
  //     balanceMode UNIFIED, sanitizer rechazando shape inválido, etc. → RELANZAR.
  //     Antes se tragaban silenciosamente y la Sale persistía con totales placeholder
  //     mientras el frontend creía que había guardado. Ahora el 400 propaga al caller
  //     (createSale/updateSale) que lo retorna al frontend → toast de error visible,
  //     cero "guardar borrador no parece guardar".
  //   · Errores TÉCNICOS inesperados (lista borrada, mocks parciales en tests,
  //     timeout, etc.) → seguir tragando + warning de audit. El documento queda
  //     con los totales placeholder; confirmSale igual recalcula desde cero.
  //
  // Caveat operativo conocido: en tests unitarios con fixtures incompletos
  // (ej. `articleCostMap` mockeado sin `costComposition`), el preview interno
  // puede crashear con error técnico (`Cannot read properties of undefined`).
  // El swallow se dispara y el draft persiste con totales placeholder — eso es
  // SOLO test theater: en producción los datos siempre vienen completos desde
  // el SALE_DETAIL_SELECT. No es bug. Si aparece en logs de producción, es
  // señal genuina de corrupción de datos y hay que investigar el caller, no
  // este try/catch.
  let result: any;
  try {
    result = await previewSale(jewelryId, previewInput);
  } catch (e) {
    if ((e as any)?.status === 400) {
      console.warn(
        `[sales.syncDraftDocumentTotals] previewSale 400 (funcional, RELANZADO) ${saleId}: ${(e as any)?.message ?? e}`,
      );
      throw e;
    }
    console.warn(
      `[sales.syncDraftDocumentTotals] previewSale falló (técnico, tragado) ${saleId}: ${(e as any)?.message ?? e}`,
    );
    return detail;
  }

  // POLICY §R-Rounding-1 — `Sale.total` debe ser `finalTotal` (engineTotal
  // + manualAdjustment.totals.totalMonetaryAdjustment, clamp ≥ 0). Lo mismo
  // que persiste `confirmSale`. Si `finalTotal` no viene (preview viejo),
  // fallback a `documentTotals.total`.
  const dt = result?.documentTotals ?? {};
  const finalTotal =
    typeof result?.finalTotal === "number"
      ? result.finalTotal
      : (typeof dt.total === "number" ? dt.total : 0);

  // ── Etapa 2.1 — Persistencia COMPLETA de snapshots en draft (paridad con confirm) ──
  // Antes solo se persistían 4 campos planos (subtotal/discount/tax/total). Reabrir
  // un draft mostraba `Sale.total` correcto pero no traía documentRoundingSnapshot
  // ni manualAdjustmentSnapshot → el frontend no podía renderizar redondeos sin
  // correr OTRO preview. Ahora persistimos el set completo que `confirmSale` escribe
  // (sales.service confirmSale §"5. Actualizar venta") → mismo input al reabrir
  // produce mismo display, sin re-preview.
  //
  // Campos JSON usan `Prisma.JsonNull` cuando son null (Prisma 7 requiere distinguir
  // JSON null de SQL null).
  const documentRoundingSnapshotForDraft =
    result?.documentRoundingSnapshot ?? null;
  const manualAdjustmentSnapshotForDraft =
    result?.manualAdjustmentSnapshot ?? null;
  // engineTotal: total del motor PRE ajuste manual. En confirm es `documentTotals.total`
  // (capa 16 ya aplicada). Acá es `dt.total` del preview interno — misma fuente.
  const engineTotalForDraft =
    typeof result?.engineTotal === "number"
      ? result.engineTotal
      : (typeof dt.total === "number" ? dt.total : 0);

  try {
    await prisma.sale.update({
      where: { id: saleId },
      data: {
        subtotal:       typeof dt.subtotalAfterLineDiscounts === "number"
                          ? dt.subtotalAfterLineDiscounts
                          : (typeof result?.subtotal === "number" ? result.subtotal : 0),
        discountAmount: typeof dt.legacyCouponOnlyDiscount === "number"
                          ? dt.legacyCouponOnlyDiscount
                          : 0,
        taxAmount:      typeof dt.taxAmount === "number" ? dt.taxAmount : 0,
        total:          finalTotal,
        // ── Etapa 2.1 — Paridad con confirm ────────────────────────────────
        engineTotal:    engineTotalForDraft,
        documentRoundingSnapshot: documentRoundingSnapshotForDraft
          ? (documentRoundingSnapshotForDraft as unknown as Prisma.InputJsonValue)
          : Prisma.JsonNull,
        manualAdjustmentSnapshot: manualAdjustmentSnapshotForDraft
          ? (manualAdjustmentSnapshotForDraft as unknown as Prisma.InputJsonValue)
          : Prisma.JsonNull,
        // Balance mode resuelto por el motor — `Sale.balanceMode` queda alineado
        // con lo que verá el operador al reabrir el draft.
        ...(result?.balanceMode       != null && { balanceMode:       result.balanceMode }),
        ...(result?.balanceModeSource != null && { balanceModeSource: result.balanceModeSource }),
      } as any,
    });
  } catch (e) {
    console.warn(
      `[sales.syncDraftDocumentTotals] sale.update falló para ${saleId}: ${(e as any)?.message ?? e}`,
    );
    return detail;
  }

  try {
    return await getSale(saleId, jewelryId);
  } catch {
    return detail;
  }
}

// ─── Confirm (DRAFT → CONFIRMED, descuenta stock) ────────────────────────────
export async function confirmSale(
  id: string,
  jewelryId: string,
  userId: string
) {
  const { result } = await runWithTrace(
    `confirmSale jewelry=${jewelryId} sale=${id}`,
    () => _confirmSaleImpl(id, jewelryId, userId),
  );
  return result;
}

async function _confirmSaleImpl(
  id: string,
  jewelryId: string,
  userId: string,
) {
  const sale = await prisma.sale.findFirst({
    where: { id, jewelryId },
    select: {
      id: true,
      code: true,
      status: true,
      clientId: true,
      warehouseId: true,
      subtotal: true,
      discountAmount: true,
      taxAmount: true,
      total: true,
      couponId: true,
      // Fase 3B.5 — override manual del documento (POLICY.md §11 R11.4).
      balanceModeOverride: true,
      // Etapa 1.1 — ajustes a nivel documento (paridad preview ↔ confirm).
      shippingAmount:      true,
      globalDiscountType:  true,
      globalDiscountValue: true,
      paymentMethodId:     true,
      paymentInstallments: true,
      // Etapa A — Manual Adjustment. Intención del operador del DRAFT.
      // Sin este `select`, el confirmSale leía siempre `null` y el ajuste
      // del operador se perdía silenciosamente al confirmar.
      manualAdjustmentInput: true,
      client: {
        select: {
          id: true, displayName: true, code: true,
          documentType: true, documentNumber: true, ivaCondition: true,
          email: true, phone: true,
          balanceType: true,
          // Fase 3B.5 — Balance Mode canónico (nuevo campo schema 3B.4).
          balanceMode: true,
          taxExempt: true, taxApplyOnOverride: true,
          taxOverrides: { where: { isActive: true }, select: { taxId: true, overrideMode: true, applyOn: true, isActive: true } },
          addresses: {
            where: { type: "BILLING", deletedAt: null },
            select: { street: true, streetNumber: true, floor: true, apartment: true, city: true, province: true, country: true, postalCode: true },
            take: 1,
          },
        },
      },
      seller: {
        select: { id: true, firstName: true, lastName: true, displayName: true, documentType: true, documentNumber: true, email: true, commissionType: true, commissionValue: true, commissionBase: true },
      },
      channel: {
        select: { id: true, name: true, code: true, adjustmentType: true, adjustmentValue: true },
      },
      lines: {
        select: {
          id: true,
          articleId: true,
          variantId: true,
          quantity: true,
          unitPrice: true,
          discountPct: true,
          lineTotal: true,
          priceSource:        true,
          appliedPriceListId: true,
          appliedPromotionId: true,
          appliedDiscountId:  true,
          // Fase 1 — incluido para detectar líneas legadas sin snapshot.
          pricingSnapshot:    true,
        },
      },
    },
  });

  if (!sale) err("Venta no encontrada.", 404);
  if (sale.status !== "DRAFT") err("La venta ya fue confirmada o anulada.");

  // ── Política de precios — pre-check antes de tocar nada ──────────────────
  const policyBlocks = await evaluatePricingPolicy(jewelryId, sale.lines.map(l => ({
    articleId: l.articleId,
    variantId: l.variantId ?? null,
    unitPrice:  l.unitPrice,
  })));

  if (policyBlocks.length > 0) {
    const allBlockingCodes = [...new Set(policyBlocks.flatMap(b => b.blockingAlerts))];
    const e: any = new Error("La venta no puede confirmarse: hay artículos con alertas de política de precios.");
    e.status = 422;
    e.blockingAlerts = allBlockingCodes;
    throw e;
  }

  // ── Snapshot de costo y margen por línea ──────────────────────────────────
  // Fetch article cost fields for all unique articles in the sale
  const uniqueArticleIds = [...new Set(sale.lines.map((l) => l.articleId))];
  const articleCostData = await prisma.article.findMany({
    where: { id: { in: uniqueArticleIds }, jewelryId },
    select: {
      id: true,
      stockMode: true,                       // necesario para excluir combos (NO_STOCK) del movimiento del padre
      // FASE 2 — necesario para que `deriveMetalHechuraBreakdown` detecte
      // combos comerciales y use `source = "COMBO_COMPONENTS"`.
      commercialMode: true,
      mermaPercent: true,
      manualTaxIds: true,
      manualAdjustmentKind:  true,
      manualAdjustmentType:  true,
      manualAdjustmentValue: true,
      category: { select: { mermaPercent: true } },
      costComposition: {
        select: {
          // Fase 1.5 — `id` requerido para que `calculateCostFromLines` pueda
          // re-aplicar los `costLineOverrides` del snapshot frozen al confirmar
          // (paridad preview ↔ confirm). Sin esto, el motor recibe líneas sin
          // costLineId y el match `unifyCostLineOverrides` falla → overrides
          // ignorados al recomputar costo → margen inconsistente.
          id: true,
          type: true, label: true, quantity: true, quantityUnit: true, unitValue: true, currencyId: true,
          mermaPercent: true, metalVariantId: true, lineAdjKind: true, lineAdjType: true, lineAdjValue: true,
          catalogItemId: true, catalogVariantId: true, affectsStock: true,
        },
      },
    },
  });
  const articleCostMap = new Map(articleCostData.map((a) => [a.id, a]));

  // Batch cost context — evita N+1 en calculateCostFromLines por línea
  const batchCostCtx: BatchCostContext = await buildBatchCostContext(
    jewelryId,
    articleCostData as ArticleCostInput[],
  );

  // Batch fetch nombres de lista de precios y promociones (para pricingSnapshot)
  const priceListIds = [...new Set(sale.lines.map(l => l.appliedPriceListId).filter((id): id is string => !!id))];
  const promotionIds = [...new Set(sale.lines.map(l => l.appliedPromotionId).filter((id): id is string => !!id))];

  const [priceListRows, promotionRows] = await Promise.all([
    priceListIds.length > 0
      ? prisma.priceList.findMany({ where: { id: { in: priceListIds } }, select: { id: true, name: true } })
      : Promise.resolve([]),
    promotionIds.length > 0
      ? prisma.promotion.findMany({ where: { id: { in: promotionIds } }, select: { id: true, name: true } })
      : Promise.resolve([]),
  ]);
  const priceListNameMap = new Map(priceListRows.map(r => [r.id, r.name]));
  const promotionNameMap = new Map(promotionRows.map(r => [r.id, r.name]));

  // Pre-calcular factor de descuentos (canal + cupón) para bases AFTER_DISCOUNTS.
  // Aislado en helper para que no contamine el cálculo del total.
  // TODO Fase 4: derivar la base de comisión del `documentTotals` (subtotal /
  // taxableBase / etc.) en vez de simular acá canal+cupón a mano.
  const lineDiscountFactor = await computeLineDiscountFactorForCommission(
    jewelryId,
    sale as any,
  );

  // Compute cost + tax + commission por línea — SIN escrituras (van en la tx al final)
  type LineResult = {
    lineId:          string;
    lineTaxAmtTotal: number;
    commission:      { base: number | null; amount: number };
    updateData:      Record<string, any> | null;
    breakdownSnapshot: any;
    /** Opción A — steps del motor cost (post enrich) para alimentar
     *  `extractMetalItemsFromSteps` en el balance breakdown. El
     *  `breakdown.metal.items[]` viene vacío en runtime; los steps son
     *  la fuente real. */
    costSteps:       any[] | null;
    lineTotal:       Prisma.Decimal;
    /** Datos para `computeSaleDocumentTotals`. null cuando la línea no
     *  participa del cálculo (ej. artCost no encontrado). */
    documentLine:    SaleDocumentTotalsLineInput | null;
    /** BUG FIX 2026-05-28 — delta del redondeo deferred aplicado por la línea
     *  (post-pre) × qty. Se agrega a `subtotal` doc-level para paridad con
     *  el preview cuando la lista aplica redondeo NET/TOTAL. Opcional porque
     *  el return temprano (artCost no encontrado) no lo emite. */
    appliedRoundingDelta?: number;
  };

  const resolvedAt = new Date().toISOString();

  const lineResults: LineResult[] = await Promise.all(
    sale.lines.map(async (line): Promise<LineResult> => {
      const artCost = articleCostMap.get(line.articleId);
      if (!artCost) {
        return {
          lineId:            line.id,
          lineTaxAmtTotal:   0,
          commission:        { base: null, amount: 0 },
          updateData:        null,
          breakdownSnapshot: null,
          costSteps:         null,
          lineTotal:         new Prisma.Decimal(line.lineTotal.toString()),
          documentLine:      null,
        };
      }

      // ── Fase 2 — Precio: leer snapshot frozen del DRAFT ──────────────────
      // El precio se congela en createSale/updateSale. Acá NUNCA reconstruimos
      // basePrice desde unitPrice/discountPct: usamos el snapshot tal cual.
      // Si la línea es legada, el helper recalcula con el motor.
      const { snapshot: snap } = await getLinePricingSnapshotForConfirm(
        jewelryId,
        line as any,
        { clientId: (sale as any).clientId ?? null },
      );

      // ── Costo: recomputar siempre al confirmar ────────────────────────────
      // El precio queda frozen pero el costo refleja el momento de confirmación
      // (cotizaciones de metal pueden haber cambiado). Margen = unitPrice
      // (frozen) − unitCost (fresh).
      //
      // Fase 1.5 — paridad de overrides en confirm:
      // El snapshot frozen del DRAFT trae `costLineOverridesApplied` (post
      // unify legacy + explicit). Lo reaplicamos al costo fresco para que:
      //   · `unitCost` refleje los mismos overrides que `unitPrice` frozen,
      //   · `unitMargin = unitPrice − unitCost` sea coherente,
      //   · una eventual recompute (sale legada / re-confirm) dé idénticos
      //     totales.
      // Sin esto, el margen se desplazaría al confirmar — sin que el
      // operador haya cambiado nada.
      const frozenCostLineOverrides =
        Array.isArray((snap as any).costLineOverridesApplied)
          ? ((snap as any).costLineOverridesApplied as CostLineOverride[])
          : undefined;
      const costResult = await calculateCostFromLines(
        jewelryId,
        (artCost as any).costComposition as CostLineInput[],
        {
          kind:  (artCost as any).manualAdjustmentKind,
          type:  (artCost as any).manualAdjustmentType,
          value: (artCost as any).manualAdjustmentValue,
        },
        batchCostCtx,
        frozenCostLineOverrides,
      );

      const clientTaxExempt          = (sale.client as any)?.taxExempt ?? false;
      const clientTaxApplyOnOverride = (sale.client as any)?.taxApplyOnOverride ?? null;
      const clientTaxOverrides       = (sale.client as any)?.taxOverrides ?? null;
      const taxIds: string[] = clientTaxExempt ? [] : ((artCost as any).manualTaxIds ?? []);

      // Bases para impuestos — desde el snapshot frozen, NO desde columnas.
      const unitPriceNum = snap.unitPrice ?? 0;
      const basePriceNum = snap.basePrice ?? unitPriceNum;
      const unitPriceDec = new Prisma.Decimal(unitPriceNum);
      const basePriceDec = new Prisma.Decimal(basePriceNum);

      const { taxBreakdown, taxAmount } = await computeLineTaxes(
        jewelryId,
        taxIds,
        unitPriceDec,
        basePriceDec,
        null,
        costResult.breakdown ?? null,
        clientTaxApplyOnOverride,
        clientTaxOverrides,
        // 9º — confirm no recibe override de valor por línea (limitación
        // preexistente; el precio/descuento ya está frozen en el snapshot).
        null,
        // 10º — base ("Aplica a") congelada en el snapshot del DRAFT, para
        // que el impuesto se recompute sobre la MISMA base que el preview
        // (paridad preview↔confirm del override de base).
        (snap as any).manualTaxAppliesTo ?? null,
      );

      const lineTaxAmt = parseFloat(taxAmount.toString());
      const qty        = parseFloat(line.quantity.toString());

      // Costo / margen — del costResult fresco
      const hasCost        = costResult.value != null;
      const qtyDec         = new Prisma.Decimal(line.quantity.toString());
      const lineTotalDec   = new Prisma.Decimal(line.lineTotal.toString());
      const unitCostDec    = hasCost ? new Prisma.Decimal(costResult.value!.toString()) : null;
      const totalCostDec   = unitCostDec ? unitCostDec.mul(qtyDec) : null;
      const totalMarginDec = totalCostDec ? lineTotalDec.sub(totalCostDec) : null;
      const unitMarginDec  = unitCostDec ? unitPriceDec.sub(unitCostDec) : null;
      const marginPercentDec =
        totalMarginDec && lineTotalDec.gt(0)
          ? totalMarginDec.div(lineTotalDec).mul(100)
          : null;

      // Snapshot persistido al confirmar:
      //   - precio (unitPrice/basePrice/discountAmount/priceSource/applied*) → snapshot frozen
      //   - costo (unitCost/unitMargin/marginPercent) → costResult fresco
      //   - impuestos (taxAmount/totalWithTax) → computeLineTaxes recién hecho
      const pricingSnapshotPersisted: PricingLineSnapshot = {
        unitPrice:      unitPriceNum,
        basePrice:      basePriceNum,
        discountAmount: snap.discountAmount ?? Math.max(0, basePriceNum - unitPriceNum),
        taxAmount:      lineTaxAmt,
        totalWithTax:   unitPriceNum + lineTaxAmt,
        priceSource:    snap.priceSource || (line as any).priceSource || "",
        baseSource:     snap.baseSource  || snap.priceSource || (line as any).priceSource || "",
        unitCost:       unitCostDec    ? unitCostDec.toNumber()    : null,
        unitMargin:     unitMarginDec  ? unitMarginDec.toNumber()  : null,
        marginPercent:  marginPercentDec ? marginPercentDec.toNumber() : null,
        costPartial:    costResult.partial,
        costMode:       costResult.mode,
        partial:        snap.partial || costResult.partial,
        appliedPriceListId:   snap.appliedPriceListId   ?? (line as any).appliedPriceListId ?? null,
        appliedPriceListName: snap.appliedPriceListName ?? priceListNameMap.get(snap.appliedPriceListId ?? (line as any).appliedPriceListId ?? "") ?? null,
        appliedPromotionId:   snap.appliedPromotionId   ?? (line as any).appliedPromotionId ?? null,
        appliedPromotionName: snap.appliedPromotionName ?? promotionNameMap.get(snap.appliedPromotionId ?? (line as any).appliedPromotionId ?? "") ?? null,
        appliedDiscountId:    snap.appliedDiscountId    ?? (line as any).appliedDiscountId  ?? null,
        // Fase 1.5 — preservar overrides aplicados en el snapshot CONFIRMED.
        // Tomamos el array que el motor cost devolvió ahora (`costResult`)
        // — si hubo overrides en DRAFT, vuelven a aparecer porque los
        // pasamos arriba a `calculateCostFromLines`. Fallback al snapshot
        // frozen del draft cuando el costResult no expone el campo (modo
        // legacy / sin overrides). Esto cierra paridad preview ↔ confirm.
        ...((costResult as any).costLineOverridesApplied
          && Array.isArray((costResult as any).costLineOverridesApplied)
          && (costResult as any).costLineOverridesApplied.length > 0
            ? { costLineOverridesApplied: (costResult as any).costLineOverridesApplied }
            : (frozenCostLineOverrides && frozenCostLineOverrides.length > 0
                ? { costLineOverridesApplied: frozenCostLineOverrides }
                : {})),
        // Preservar la base ("Aplica a") congelada del DRAFT en el snapshot
        // CONFIRMED — así un re-confirm / recompute reproduce idéntico.
        ...((snap as any).manualTaxAppliesTo != null
          ? { manualTaxAppliesTo: (snap as any).manualTaxAppliesTo }
          : {}),
        resolvedAt,
      };

      const lineComm = calculateLineCommission({
        commissionType:    (sale as any).seller?.commissionType  ?? "NONE",
        commissionValue:   (sale as any).seller?.commissionValue != null ? parseFloat((sale as any).seller.commissionValue.toString()) : null,
        commissionBase:    (sale as any).seller?.commissionBase  ?? "TOTAL",
        lineTotal:         parseFloat(line.lineTotal.toString()),
        breakdownSnapshot: costResult.breakdown ?? null,
        quantity:          qty,
        lineDiscountFactor,
      });

      const updateData: Record<string, any> = {
        taxAmount:              lineTaxAmt > 0 ? taxAmount : null,
        taxSnapshot:            taxBreakdown.length > 0 ? (taxBreakdown as any) : Prisma.JsonNull,
        pricingSnapshot:        pricingSnapshotPersisted as any,
        sellerCommissionBase:   lineComm.base   != null ? lineComm.base   : null,
        sellerCommissionAmount: lineComm.amount  > 0    ? lineComm.amount  : null,
      };
      if (hasCost) {
        updateData.unitCost          = unitCostDec;
        updateData.totalCost         = totalCostDec;
        updateData.unitMargin        = unitMarginDec;
        updateData.totalMargin       = totalMarginDec;
        updateData.marginPercent     = marginPercentDec;
        updateData.breakdownSnapshot = costResult.breakdown ?? null;
      }

      // FASE 2 — armar `metalHechuraBreakdown` per línea para que el motor
      // de documentTotals agregue Metal/Hechura a nivel doc. confirmSale no
      // llama al motor entero por línea (usa snapshot frozen + costResult
      // fresh), así que invocamos `deriveMetalHechuraBreakdown` con los
      // inputs que ya tenemos a mano.
      const mhbForLine = deriveMetalHechuraBreakdown({
        metalCost:   costResult.metalCost   != null ? parseFloat(costResult.metalCost.toString())   : 0,
        hechuraCost: costResult.hechuraCost != null ? parseFloat(costResult.hechuraCost.toString()) : 0,
        costTotal:   costResult.value       != null ? parseFloat(costResult.value.toString())       : null,
        basePrice:   unitPriceNum,
        priceSource: ((snap as any).priceSource ?? "PRICE_LIST") as PriceSource,
        commercialMode: (artCost as any)?.commercialMode ?? null,
        exactBreakdown: null,
      });

      // BUG FIX 2026-05-28 — Delta del rounding deferred TOTAL por línea.
      // El snapshot frozen del DRAFT trae `appliedRounding` cuando la lista
      // aplicó rounding. El motor de línea actualiza `totalWithTax` post-
      // rounding pero NO actualiza `unitPrice`/`unitTaxAmount` (solo para
      // applyOn=TOTAL — los otros applyOn sí actualizan unitPrice). Como
      // `lineTotal = unitPrice × qty` y `lineTaxAmount = unitTaxAmount × qty`,
      // la suma del documento queda pre-rounding solo para applyOn=TOTAL.
      //
      // Filtro CRÍTICO: solo applyOn=TOTAL aporta delta — para PRICE/NET el
      // unitPrice ya está post-rounding y sumarlo otra vez DUPLICA. Idéntica
      // lógica a previewSale para garantizar paridad.
      const ar = (snap as any).appliedRounding ?? null;
      let appliedRoundingDelta = 0;
      if (ar && ar.applyOn === "TOTAL") {
        const pre  = typeof ar.preRounding  === "number"
          ? ar.preRounding
          : ar.preRounding  != null ? parseFloat(String(ar.preRounding))  : 0;
        const post = typeof ar.postRounding === "number"
          ? ar.postRounding
          : ar.postRounding != null ? parseFloat(String(ar.postRounding)) : 0;
        if (Number.isFinite(pre) && Number.isFinite(post)) {
          appliedRoundingDelta = (post - pre) * qty;
        }
      }

      return {
        lineId:          line.id,
        lineTaxAmtTotal: lineTaxAmt * qty,
        commission:      lineComm,
        updateData,
        breakdownSnapshot: hasCost ? (costResult.breakdown ?? null) : null,
        // Opción A — steps del motor (post enrichCostMetalSteps) para alimentar
        // `extractMetalItemsFromSteps`. El breakdown.metal.items[] viene vacío
        // en runtime; los steps son la única fuente real.
        costSteps:         hasCost && Array.isArray(costResult.steps) ? costResult.steps : null,
        lineTotal:         lineTotalDec,
        // BUG FIX 2026-05-28 — paridad preview/confirm para rounding deferred.
        appliedRoundingDelta,
        documentLine: {
          quantity:      qty,
          basePrice:     basePriceNum,
          unitPrice:     unitPriceNum,
          lineTotal:     parseFloat(lineTotalDec.toString()),
          lineTaxAmount: lineTaxAmt * qty,
          // POLICY §Tax.3 — porción FIXED del impuesto, NO escala con
          // descuentos de cabecera. taxBreakdown viene per-unit → × qty.
          lineTaxAmountFixed: sumFixedTaxComponent(taxBreakdown) * qty,
          ...(mhbForLine
            ? {
                metalCost:            Math.round(mhbForLine.metalCost   * qty * 100) / 100,
                hechuraCost:          Math.round(mhbForLine.hechuraCost * qty * 100) / 100,
                metalSale:            Math.round(mhbForLine.metalSale   * qty * 100) / 100,
                hechuraSale:          Math.round(mhbForLine.hechuraSale * qty * 100) / 100,
                metalSaleEstimated:   mhbForLine.metalSaleEstimated   ?? false,
                hechuraSaleEstimated: mhbForLine.hechuraSaleEstimated ?? false,
              }
            : {}),
        },
      };
    })
  );

  const lineCommissions = lineResults.map(r => r.commission);

  // ── Totales del documento — fuente única de verdad (Fase 3) ──────────────
  // Antes acá se calculaba `newTotal = round(coupon.finalAmount + saleTax)`
  // a mano, dispersando la lógica de canal/cupón. Ahora todo pasa por
  // computeSaleDocumentTotals(): recibe líneas resueltas + ajustes y devuelve
  // todos los totales con un sourceTrace. Las llamadas a applySalesChannel /
  // applyCoupon de acá abajo siguen para construir los SNAPSHOTS de canal /
  // cupón que persisten en `Sale.channelSnapshot` / `Sale.couponSnapshot` —
  // esos datos los necesita el comprobante.

  const confirmChannelInput: ChannelAdjustmentInput | null = (sale as any).channel
    ? {
        id:              (sale as any).channel.id,
        name:            (sale as any).channel.name,
        adjustmentType:  (sale as any).channel.adjustmentType as "PERCENTAGE" | "FIXED",
        adjustmentValue: parseFloat((sale as any).channel.adjustmentValue.toString()),
      }
    : null;

  let confirmCouponInput: CouponInput | null = null;
  if ((sale as any).couponId) {
    const couponRow = await prisma.coupon.findFirst({
      where: { id: (sale as any).couponId, jewelryId, deletedAt: null, isActive: true },
      select: { id: true, code: true, name: true, discountType: true, discountValue: true, validFrom: true, validTo: true },
    });
    const now = new Date();
    if (couponRow &&
        (!couponRow.validFrom || now >= couponRow.validFrom) &&
        (!couponRow.validTo   || now <= couponRow.validTo)) {
      confirmCouponInput = {
        id:            couponRow.id,
        code:          couponRow.code,
        name:          couponRow.name,
        discountType:  couponRow.discountType as "PERCENTAGE" | "FIXED_AMOUNT",
        discountValue: parseFloat(couponRow.discountValue.toString()),
      };
    }
  }

  // Líneas para el motor de totales (descarta las que no resolvieron).
  const documentLineInputs: SaleDocumentTotalsLineInput[] = lineResults
    .map(r => r.documentLine)
    .filter((l): l is SaleDocumentTotalsLineInput => l != null);

  // Política de redondeo a nivel comprobante (UNIFIED). Cuando está activa,
  // `computeSaleDocumentTotals` aplica el redondeo final sobre `total` y los
  // snapshots de las líneas (creados con suppressListDeferredRounding=true en
  // createSale/recompute fallback) NO traen redondeo de lista absorbido.
  const docRoundingPolicy = await loadDocumentRoundingConfig(jewelryId);

  // ── Etapa D' — Contexto comercial PER_DOCUMENT (mismo que previewSale) ──
  // Resuelve usando los `priceListIdOverride` persistidos del draft. Si
  // todas las líneas comparten lista, intenta PER_DOCUMENT; si están en
  // mixed-list, fallback NO_SHARED_LIST → comportamiento legacy.
  // Importante: los snapshots de las líneas ya fueron creados respetando
  // el mismo modo en createSale/updateSale (resolveDraftSaleLines wiring),
  // por lo que `computeSaleDocumentTotals` puede agregar la capa nueva
  // sin riesgo de doble redondeo.
  const confirmCommercialDocCtx = await resolveDocumentCommercialContextForSale({
    jewelryId,
    lineInputs: (sale as any).items?.map((it: any) => ({
      priceListIdOverride: it.priceListIdOverride ?? null,
    })) ?? [],
    defaultPriceListIdInput: null,
  });
  assertCommercialDocRoundingConsistency(confirmCommercialDocCtx);
  traceDocument("L00_DOC_COMMERCIAL_CONTEXT", {
    where:                             "confirmSale",
    mode:                              confirmCommercialDocCtx.mode,
    documentActivePriceList:           confirmCommercialDocCtx.documentActivePriceList,
    suppressLineHechuraRounding:       confirmCommercialDocCtx.applyPriceListOptions.suppressLineHechuraRounding       === true,
    suppressLineMetalPhysicalRounding: confirmCommercialDocCtx.applyPriceListOptions.suppressLineMetalPhysicalRounding === true,
    fallback:                          confirmCommercialDocCtx.fallback,
    commercialDocumentRoundingActive:  confirmCommercialDocCtx.commercialDocumentRounding != null,
    commercialDocumentRoundingScope:   confirmCommercialDocCtx.commercialDocumentRounding?.scope ?? null,
  });

  // ── Etapa 1.1 — Ajustes a nivel documento (paridad preview ↔ confirm) ─────
  // Reproducimos el orden y la base que `previewSale` usa para calcular el
  // ajuste por forma de pago, el envío y el descuento global. Sin estos,
  // `computeSaleDocumentTotals` recibe 0 y el total confirmado diverge del
  // total previsualizado. Los inputs vienen del DRAFT persistido en
  // `createSale` / `updateSale` (`sanitizeSaleDocumentAdjustments`).
  const subtotalLineSum = Math.round(
    documentLineInputs.reduce((s, l) => s + (l.lineTotal ?? 0), 0) * 100,
  ) / 100;
  const subtotalLineWithTax = Math.round(
    documentLineInputs.reduce(
      (s, l) => s + ((l.lineTotal ?? 0) + (l.lineTaxAmount ?? 0)),
      0,
    ) * 100,
  ) / 100;

  // Provisional channel + coupon — misma fórmula que `previewSale` antes de
  // computar `paymentBaseAmount` (capa 7 del orden inmutable, POLICY.md §5).
  const confirmProvisionalChannel = applySalesChannelAdjustment(
    subtotalLineSum,
    confirmChannelInput,
  );
  const confirmProvisionalCoupon = applyCouponAdjustment(
    confirmProvisionalChannel.finalAmount,
    confirmCouponInput,
  );
  const confirmChannelAdjustmentAmount = confirmProvisionalChannel.channelAmount ?? 0;
  const confirmCouponDiscountAmount    = (confirmCouponInput && confirmProvisionalCoupon.applied)
    ? (confirmProvisionalCoupon.discountAmount ?? 0)
    : 0;
  const confirmPaymentBaseAmount = Math.max(
    0,
    Math.round(
      (subtotalLineWithTax + confirmChannelAdjustmentAmount - confirmCouponDiscountAmount) * 100,
    ) / 100,
  );

  // Payment adjustment — solo si el DRAFT tiene método de pago elegido.
  const confirmPaymentMethodId     = (sale as any).paymentMethodId ?? null;
  const confirmPaymentInstallments =
    (sale as any).paymentInstallments != null
      ? Number((sale as any).paymentInstallments)
      : 0;
  const confirmCheckoutResult =
    confirmPaymentBaseAmount > 0 &&
    (confirmPaymentMethodId || confirmPaymentInstallments >= 1)
      ? await getCheckoutPreview(
          jewelryId,
          confirmPaymentBaseAmount,
          confirmPaymentMethodId ?? undefined,
          confirmPaymentInstallments || 0,
        )
      : null;
  const confirmPaymentAdjustmentAmount = confirmCheckoutResult
    ? confirmCheckoutResult.finalAmount - confirmPaymentBaseAmount
    : 0;

  // Shipping — ya viene resuelto en el DRAFT (capa 10, POLICY.md §5).
  const confirmShippingAmount =
    (sale as any).shippingAmount != null
      ? parseFloat((sale as any).shippingAmount.toString()) || 0
      : 0;

  // Global discount — recomputado contra el subtotal post-descuentos de
  // línea. Las líneas pueden haber cambiado entre create y confirm; el
  // motor de totales necesita el monto resuelto, no el % crudo.
  const confirmGdType  = (sale as any).globalDiscountType;
  const confirmGdValue =
    (sale as any).globalDiscountValue != null
      ? parseFloat((sale as any).globalDiscountValue.toString())
      : null;
  let confirmGlobalDiscountAmount = 0;
  if (confirmGdValue != null && Number.isFinite(confirmGdValue) && confirmGdValue > 0) {
    if (confirmGdType === "PERCENT") {
      confirmGlobalDiscountAmount = Math.max(
        0,
        Math.round(subtotalLineSum * confirmGdValue) / 100,
      );
    } else if (confirmGdType === "AMOUNT") {
      confirmGlobalDiscountAmount = Math.max(0, confirmGdValue);
    }
  }

  // BUG FIX 2026-05-28 — Agregar el delta del rounding deferred de lista
  // ANTES de invocar el motor del documento. Ver explicación detallada en
  // `previewSale`. Paridad preview/confirm garantizada porque ambos usan
  // la misma fórmula (Σ `appliedRounding.unitAdjustment × qty`).
  const docRoundingAdjustmentPreEngine = Math.round(
    lineResults.reduce((s, lr) => s + ((lr as any).appliedRoundingDelta ?? 0), 0) * 100,
  ) / 100;

  // ── Etapa D' — Agregados para la capa comercial PER_DOCUMENT ───────────
  // FIX paridad preview ↔ confirm (Opción δ, 2026-05-31): la fuente anterior
  // (`lr.balanceMetals`) NUNCA se popula en código real → confirm emitía
  // `metalValuationSum=0` y el snapshot persistido divergía del preview.
  //
  // Reemplazamos por `lr.costSteps` (= `costResult.steps` con overrides
  // YA aplicados — `calculateCostFromLines` recibió `frozenCostLineOverrides`
  // arriba en línea ~1685). Misma fuente canónica que preview, idéntico
  // contrato R-COMMERCIAL-GRAMS-WITH-MERMA.
  //
  // Resuelve nombre del metal padre vía query batch al modelo `Metal` —
  // mismo fallback defensivo (id) si la query falla.
  const confirmCommercialMetalIds = new Set<string>();
  if (confirmCommercialDocCtx.mode === "PER_DOCUMENT" && confirmCommercialDocCtx.commercialDocumentRounding) {
    for (const lr of lineResults as any[]) {
      if (Array.isArray(lr?.costSteps)) {
        for (const m of extractMetalItemsFromSteps(lr.costSteps)) {
          if (m.metalId) confirmCommercialMetalIds.add(m.metalId);
        }
      }
    }
  }
  let confirmCommercialMetalNames = new Map<string, string>();
  const confirmCommercialMetalRefValues = new Map<string, number>();
  if (confirmCommercialMetalIds.size > 0) {
    try {
      const metals = await prisma.metal.findMany({
        where:  { id: { in: Array.from(confirmCommercialMetalIds) }, jewelryId, deletedAt: null },
        select: { id: true, name: true, referenceValue: true },
      });
      confirmCommercialMetalNames = new Map(metals.map((m) => [m.id, m.name]));
      for (const m of metals) {
        const rv = m.referenceValue != null ? Number(m.referenceValue.toString()) : NaN;
        if (Number.isFinite(rv) && rv > 0) confirmCommercialMetalRefValues.set(m.id, rv);
      }
    } catch {
      // Defensa contra mocks legacy / errores de runtime — fallback al id.
    }
  }

  const confirmCommercialAggregates =
    confirmCommercialDocCtx.mode === "PER_DOCUMENT" && confirmCommercialDocCtx.commercialDocumentRounding
      ? aggregateMetalsForCommercialDocRounding(
          (lineResults as any[]).map((lr) => {
            const metalItems = Array.isArray(lr?.costSteps)
              ? extractMetalItemsFromSteps(lr.costSteps)
              : [];
            return {
              quantity: lr?.quantity || 1,
              // R-COMMERCIAL-GRAMS-WITH-MERMA — `appliedGramsPerUnit` debe ser
              // `gramsFineEquivalent` (post pureza + post merma). Items sin
              // ese campo se excluyen + log (mismo contrato que preview).
              metals: metalItems
                .filter((m) => {
                  if (!m.metalId) return false;
                  if (typeof m.gramsFineEquivalent !== "number" || !Number.isFinite(m.gramsFineEquivalent)) {
                    // eslint-disable-next-line no-console
                    console.warn(
                      `[sales/confirm] Item METAL ${m.metalId} sin gramsFineEquivalent — ` +
                      `excluido del agregado comercial (R-COMMERCIAL-GRAMS-WITH-MERMA). ` +
                      `gramsOriginal=${m.gramsOriginal} purity=${m.purity}`,
                    );
                    return false;
                  }
                  return true;
                })
                .map((m) => ({
                  metalParentId:       m.metalId!,
                  metalParentName:     confirmCommercialMetalNames.get(m.metalId!) ?? m.metalId!,
                  appliedGramsPerUnit: m.gramsFineEquivalent as number,
                  quotePriceSnapshot:  m.unitValue ?? null,
                  metalReferenceValue: confirmCommercialMetalRefValues.get(m.metalId!) ?? null,
                })),
            };
          }),
        )
      : { metalsByParent: [], metalValuationSum: 0, gramsPureByParentByLineIdx: new Map<string, Map<number, number>>() };

  const documentTotals = computeSaleDocumentTotals({
    lines:   documentLineInputs,
    channel: confirmChannelInput,
    coupon:  confirmCouponInput,
    // Etapa 1.1 — fuente única: campos persistidos en el DRAFT por
    // `createSale` / `updateSale`. Mismo orden y fórmula que `previewSale`.
    paymentAdjustmentAmount: confirmPaymentAdjustmentAmount,
    shippingAmount:          confirmShippingAmount,
    globalDiscountAmount:    confirmGlobalDiscountAmount,
    roundingAdjustment:      docRoundingAdjustmentPreEngine,
    documentRounding:        docRoundingPolicy.documentRounding,
    // Etapa D' — Redondeo Comercial PER_DOCUMENT.
    commercialDocumentRounding:             confirmCommercialDocCtx.commercialDocumentRounding,
    metalsByParentForCommercialRounding:    confirmCommercialAggregates.metalsByParent,
    metalValuationSumForCommercialRounding: confirmCommercialAggregates.metalValuationSum,
  });

  // ── Opción A — Persistir el TOTAL LÍNEA C/ IMP. post-redondeo comercial +
  // impactos $ por línea en el `pricingSnapshot` (paridad con preview + audit).
  //
  // CRÍTICO anti doble conteo: esto NO altera el total del documento (el motor
  // ya lo computó arriba desde `lineTotal`); solo agrega campos de DISPLAY al
  // snapshot inmutable. Mismos distribuidores e inputs que `previewSale` →
  // paridad por construcción. Conservación:
  //   Σ metalImpact   = Σ breakdown.metals[*].monetaryEquivalent
  //   Σ hechuraImpact = breakdown.hechura.deltaSaldoMonetario
  if (documentTotals.commercialDocumentRoundingApplied) {
    const hechuraSaleByLineIdx = new Map<number, number>();
    for (let i = 0; i < lineResults.length; i++) {
      const dl = (lineResults[i] as any).documentLine;
      hechuraSaleByLineIdx.set(i, dl ? Number(dl.hechuraSale ?? 0) : 0);
    }
    const impactsByLineIdx = computeCommercialRoundingPerLineImpacts({
      breakdown:                  (documentTotals.commercialDocumentRoundingApplied as any)?.breakdown,
      gramsPureByParentByLineIdx: confirmCommercialAggregates.gramsPureByParentByLineIdx,
      hechuraSaleByLineIdx,
      lineCount:                  lineResults.length,
    });
    for (let i = 0; i < lineResults.length; i++) {
      const lr: any = lineResults[i];
      const dl = lr.documentLine;
      if (!lr.updateData || !dl || !lr.updateData.pricingSnapshot) continue;
      const imp = impactsByLineIdx.get(i) ?? { metalImpact: 0, hechuraImpact: 0, monetarySaldoPost: null };
      // Pre lineTotalWithTax con la MISMA fórmula que `previewSale`
      // (lineTotal + lineTaxAmount + delta del rounding deferred de lista).
      const pre = Math.round(
        (Number(dl.lineTotal ?? 0) + Number(dl.lineTaxAmount ?? 0) + Number(lr.appliedRoundingDelta ?? 0)) * 100,
      ) / 100;
      lr.updateData.pricingSnapshot = {
        ...lr.updateData.pricingSnapshot,
        metalRoundingMonetaryImpact:             imp.metalImpact,
        hechuraRoundingMonetaryImpact:           imp.hechuraImpact,
        lineMonetarySaldoPostCommercialRounding: imp.monetarySaldoPost,
        lineTotalWithTaxPostCommercialRounding:  Math.round((pre + imp.metalImpact + imp.hechuraImpact) * 100) / 100,
      };
    }

    // ── Gramos comerciales PER-LÍNEA (paridad con previewSale) ────────────
    // Display-only — mismos inputs que el preview (gramsPure + margen de la
    // PROPIA línea). NO toca dinero/saldo/total. Persistido en el snapshot por
    // línea para que "Ver Factura" muestre los gramos correctos por artículo.
    if (confirmCommercialDocCtx.commercialDocumentRounding?.scope === "BREAKDOWN") {
      const metalCfg = confirmCommercialDocCtx.commercialDocumentRounding.metal;
      const metalNameById = new Map<string, string>(
        confirmCommercialAggregates.metalsByParent.map((m) => [m.metalParentId, m.metalParentName]),
      );
      const marginFactorByLineIdx = new Map<number, number>();
      for (let i = 0; i < lineResults.length; i++) {
        const dl = (lineResults[i] as any).documentLine;
        const cost = dl ? Number(dl.metalCost ?? 0) : 0;
        const sale = dl ? Number(dl.metalSale ?? 0) : 0;
        marginFactorByLineIdx.set(i, cost > 0 ? sale / cost : 1);
      }
      const refValueByParent = new Map<string, number>(
        confirmCommercialAggregates.metalsByParent.map((m) => [
          m.metalParentId,
          (typeof m.metalReferenceValue === "number" && m.metalReferenceValue > 0)
            ? m.metalReferenceValue
            : m.metalPricePerGram,
        ]),
      );
      const lineMetalsByIdx = computeLineCommercialRoundingMetals({
        gramsPureByParentByLineIdx: confirmCommercialAggregates.gramsPureByParentByLineIdx,
        metalNameById,
        refValueByParent,
        marginFactorByLineIdx,
        metalCfg,
        lineCount: lineResults.length,
      });

      // ── Opción B (LINE-AUTONOMOUS) — dinero comercial por línea (paridad) ──
      // Mismos inputs que previewSale: saldo + gramos PROPIOS de cada línea.
      const hechuraCfg = confirmCommercialDocCtx.commercialDocumentRounding.hechura;
      const lineTotalWithTaxByIdx = new Map<number, number>();
      const metalSaleSumByIdx     = new Map<number, number>();
      for (let i = 0; i < lineResults.length; i++) {
        const lr: any = lineResults[i];
        const dl = lr.documentLine;
        // Misma fórmula `pre` que el bloque de impactos (lineTotal + tax + delta).
        const pre = Math.round(
          (Number(dl?.lineTotal ?? 0) + Number(dl?.lineTaxAmount ?? 0) + Number(lr.appliedRoundingDelta ?? 0)) * 100,
        ) / 100;
        lineTotalWithTaxByIdx.set(i, pre);
        // dl.metalSale ya viene × qty (línea 1871) → no re-escalar.
        metalSaleSumByIdx.set(i, dl ? Math.round(Number(dl.metalSale ?? 0) * 100) / 100 : 0);
      }
      const moneyByIdx = computeLineAutonomousCommercialMoney({
        lineCommercialRoundingMetals: lineMetalsByIdx,
        refValueByParent,
        lineTotalWithTaxByIdx,
        metalSaleSumByIdx,
        hechuraCfg,
        lineCount: lineResults.length,
      });

      for (let i = 0; i < lineResults.length; i++) {
        const lr: any = lineResults[i];
        if (!lr.updateData || !lr.updateData.pricingSnapshot) continue;
        const m = moneyByIdx.get(i);
        lr.updateData.pricingSnapshot = {
          ...lr.updateData.pricingSnapshot,
          lineCommercialRoundingMetals: lineMetalsByIdx.get(i) ?? [],
          // Opción B — sobrescribe el dinero distribuido (arriba) por el
          // line-autonomous. Paridad exacta con previewSale.
          ...(m ? {
            metalRoundingMonetaryImpact:             m.metalRoundingMonetaryImpact,
            hechuraRoundingMonetaryImpact:           m.hechuraRoundingMonetaryImpact,
            lineMonetarySaldoPreCommercialRounding:  m.lineMonetarySaldoPreCommercialRounding,
            lineMonetarySaldoPostCommercialRounding: m.lineMonetarySaldoPostCommercialRounding,
            lineTotalWithTaxPostCommercialRounding:  m.lineTotalWithTaxPostCommercialRounding,
          } : {}),
        };
      }
    }
  }

  // Fase 6: `documentTotals` ya expone `channelResult` y `couponResult`
  // calculados por el motor. Antes acá había un doble cómputo redundante.
  const confirmChannelAdj = documentTotals.channelResult;
  const confirmCouponAdj  = documentTotals.couponResult;

  // Aliases legacy: el resto del flujo seguía nombrando estos valores. Los
  // dejamos mapeados al nuevo motor para no diseminar el cambio.
  const saleTaxTotal = documentTotals.taxAmount;
  const newTotal     = documentTotals.total;

  // ── Garantía de fuente única (P1) ─────────────────────────────────────────
  // El motor (documentTotals) es la fuente de verdad. El DRAFT pudo haber
  // quedado con totales obsoletos si el frontend persistió un snapshot stale
  // o si las cotizaciones / impuestos cambiaron entre createSale y confirmSale.
  // Loggeamos divergencia > 0.01 para auditoría — el motor SIEMPRE gana.
  const draftSubtotal = parseFloat((sale as any).subtotal?.toString() ?? "0");
  const draftDiscount = parseFloat((sale as any).discountAmount?.toString() ?? "0");
  const draftTax      = parseFloat((sale as any).taxAmount?.toString() ?? "0");
  const draftTotal    = parseFloat((sale as any).total?.toString() ?? "0");
  const drift = {
    subtotal:       Math.abs(draftSubtotal - documentTotals.subtotalAfterLineDiscounts),
    discountAmount: Math.abs(draftDiscount - documentTotals.legacyCouponOnlyDiscount),
    taxAmount:      Math.abs(draftTax      - documentTotals.taxAmount),
    total:          Math.abs(draftTotal    - documentTotals.total),
  };
  if (drift.subtotal > 0.01 || drift.discountAmount > 0.01 || drift.taxAmount > 0.01 || drift.total > 0.01) {
    console.warn(
      `[sales.confirmSale] Sale ${sale.code} (${id}): totales del DRAFT difieren del motor. ` +
      `DRAFT subtotal=${draftSubtotal} discount=${draftDiscount} tax=${draftTax} total=${draftTotal}; ` +
      `engine subtotal=${documentTotals.subtotalAfterLineDiscounts} discount=${documentTotals.legacyCouponOnlyDiscount} ` +
      `tax=${documentTotals.taxAmount} total=${documentTotals.total}. Persistiendo valores del motor.`,
    );
  }

  // ── Comisión del vendedor: total de la venta ──────────────────────────────
  let sellerCommissionTotal: number | null = null;
  const sellerInfo = (sale as any).seller;
  if (sellerInfo && sellerInfo.commissionType !== "NONE") {
    if (sellerInfo.commissionType === "FIXED_AMOUNT" && sellerInfo.commissionValue != null) {
      sellerCommissionTotal = Math.round(parseFloat(sellerInfo.commissionValue.toString()) * 100) / 100;
    } else if (sellerInfo.commissionType === "PERCENTAGE") {
      const lineSum = lineCommissions.reduce((s, c) => s + c.amount, 0);
      sellerCommissionTotal = Math.round(lineSum * 100) / 100;
    }
  }

  const snapshotAt = new Date().toISOString();

  // ── Snapshots (solo lectura, antes de la tx) ──────────────────────────────
  const clientSnapshot: EntitySnapshot | null = sale.client
    ? {
        id:                 sale.client.id,
        displayName:        sale.client.displayName,
        code:               sale.client.code,
        documentType:       (sale.client as any).documentType ?? "",
        documentNumber:     sale.client.documentNumber,
        ivaCondition:       sale.client.ivaCondition,
        email:              (sale.client as any).email ?? "",
        phone:              (sale.client as any).phone ?? "",
        taxExempt:          sale.client.taxExempt,
        taxApplyOnOverride: (sale.client.taxApplyOnOverride as string | null) ?? null,
        taxOverrides:       sale.client.taxOverrides as EntitySnapshot["taxOverrides"],
        billingAddress:     (sale.client as any).addresses?.[0] ?? null,
        snapshotAt,
      }
    : null;

  const channelSnapshot = (sale as any).channel
    ? { ...(sale as any).channel, snapshotAt }
    : null;

  const couponSnapshot = confirmCouponAdj.applied && confirmCouponAdj.couponId
    ? {
        couponId:              confirmCouponAdj.couponId,
        couponCode:            confirmCouponAdj.couponCode,
        couponName:            confirmCouponAdj.couponName,
        discountType:          confirmCouponAdj.discountType,
        discountValue:         confirmCouponAdj.discountValue,
        appliedDiscountAmount: confirmCouponAdj.discountAmount,
        resolvedAt:            snapshotAt,
      }
    : null;

  const sellerSnapshot: SellerSnapshot | null = (sale as any).seller
    ? {
        id:               (sale as any).seller.id,
        firstName:        (sale as any).seller.firstName,
        lastName:         (sale as any).seller.lastName,
        displayName:      (sale as any).seller.displayName,
        documentType:     (sale as any).seller.documentType ?? "",
        documentNumber:   (sale as any).seller.documentNumber ?? "",
        email:            (sale as any).seller.email ?? "",
        commissionType:   (sale as any).seller.commissionType  ?? "NONE",
        commissionValue:  (sale as any).seller.commissionValue != null
          ? parseFloat((sale as any).seller.commissionValue.toString())
          : null,
        commissionBase:   (sale as any).seller.commissionBase  ?? "TOTAL",
        commissionTotal:  sellerCommissionTotal,
        snapshotAt,
      }
    : null;

  const baseCurrencyId = await getBaseCurrencyId(jewelryId);
  const [currencyRow, jewelry] = await Promise.all([
    baseCurrencyId
      ? prisma.currency.findUnique({
          where: { id: baseCurrencyId },
          select: { id: true, code: true, name: true, symbol: true, isBase: true },
        })
      : Promise.resolve(null),
    prisma.jewelry.findUnique({
      where: { id: jewelryId },
      select: {
        id: true, name: true, legalName: true, cuit: true, ivaCondition: true, email: true,
        street: true, number: true, floor: true, apartment: true,
        city: true, province: true, country: true, postalCode: true, logoUrl: true,
      },
    }),
  ]);

  const currencySnapshot: CurrencySnapshot | null = currencyRow
    ? { id: currencyRow.id, code: currencyRow.code, name: currencyRow.name, symbol: currencyRow.symbol, isBase: currencyRow.isBase, exchangeRate: null, snapshotAt }
    : null;

  const issuerSnapshot: IssuerSnapshot | null = jewelry
    ? {
        id: jewelry.id, name: jewelry.name, legalName: jewelry.legalName,
        cuit: jewelry.cuit, ivaCondition: jewelry.ivaCondition, email: jewelry.email,
        street: jewelry.street, number: jewelry.number, floor: jewelry.floor, apartment: jewelry.apartment,
        city: jewelry.city, province: jewelry.province, country: jewelry.country, postalCode: jewelry.postalCode,
        logoUrl: jewelry.logoUrl, snapshotAt,
      }
    : null;

  // Balance entries usando lineResults (sin re-fetch)
  const clientBalanceType = sale.clientId && sale.client
    ? ((sale.client as any).balanceType as "UNIFIED" | "BREAKDOWN" ?? "UNIFIED")
    : "UNIFIED";
  const balanceEntryData = (sale.clientId && sale.client)
    ? lineResults.map((lr) => {
        const isBreakdown = clientBalanceType === "BREAKDOWN" && lr.breakdownSnapshot != null;
        if (isBreakdown) {
          const bd = buildBalanceBreakdownFromPrice(lr.breakdownSnapshot);
          return { entityId: sale.clientId!, jewelryId, role: "CLIENT" as const, entryType: "INVOICE" as const, amount: new Prisma.Decimal(0), currency: "BASE", documentRef: id, createdBy: userId ?? "", breakdownSnapshot: bd as any };
        }
        return { entityId: sale.clientId!, jewelryId, role: "CLIENT" as const, entryType: "INVOICE" as const, amount: lr.lineTotal, currency: "BASE", documentRef: id, createdBy: userId ?? "", breakdownSnapshot: null };
      })
    : [];

  // ── T55 (Fase 3B.5) — Balance Mode resolución + breakdown ────────────────
  // Mismo flujo que `previewSale`, pero leyendo desde el DRAFT persistido:
  //   · documentOverride  → sale.balanceModeOverride
  //   · entityDefault     → sale.client.balanceMode ?? mapBalanceTypeToMode(balanceType)
  //   · priceListDefault  → única lista consolidada de las líneas (si única)
  //   · tenantDefault     → jewelry.defaultBalanceMode
  // El modo se congela acá y persiste en Sale.balanceMode/balanceModeSource —
  // NUNCA se recalcula después (POLICY.md §11 R11.1, R11.5).
  const confirmDocumentOverride: BalanceMode | null =
    (sale as any).balanceModeOverride === "UNIFIED" ||
    (sale as any).balanceModeOverride === "BREAKDOWN"
      ? (sale as any).balanceModeOverride
      : null;
  // Lista única consolidada (si todas las líneas usan la misma).
  const confirmPriceListIds = new Set(
    sale.lines.map((l) => l.appliedPriceListId).filter((id): id is string => !!id),
  );
  let confirmPriceListDefault: BalanceMode | null = null;
  let confirmPriceListMode:    string       | null = null;
  if (confirmPriceListIds.size === 1) {
    const onlyId = [...confirmPriceListIds][0]!;
    try {
      const pl = await prisma.priceList.findFirst({
        where:  { id: onlyId, jewelryId, deletedAt: null },
        select: { balanceMode: true, mode: true },
      });
      confirmPriceListDefault = (pl?.balanceMode ?? null) as BalanceMode | null;
      confirmPriceListMode    = (pl?.mode        ?? null) as string       | null;
    } catch { /* defensive — tests con prisma parcial */ }
  }
  let confirmTenantDefault: BalanceMode | null = null;
  try {
    const confirmJewelryRow = await prisma.jewelry.findUnique({
      where:  { id: jewelryId },
      select: { defaultBalanceMode: true },
    });
    confirmTenantDefault = (confirmJewelryRow?.defaultBalanceMode ?? null) as BalanceMode | null;
  } catch { /* defensive */ }
  const confirmBalanceResolution = resolveSaleBalanceMode({
    documentOverride:        confirmDocumentOverride,
    entityBalanceMode:       (sale.client as any)?.balanceMode ?? null,
    entityBalanceTypeLegacy: sale.client?.balanceType ?? null,
    priceListDefault:        confirmPriceListDefault,
    priceListMode:           confirmPriceListMode,
    tenantDefault:           confirmTenantDefault,
  });

  // Nombres de metales (sólo si BREAKDOWN). Cargamos en batch desde los
  // STEPS del motor (fuente real — el breakdown.metal.items[] viene vacío) y,
  // como fallback, desde el `breakdownSnapshot` (back-compat con snapshots
  // históricos que pudieran tener items).
  let confirmMetalNames:   Map<string, string> | undefined;
  let confirmVariantNames: Map<string, string> | undefined;
  if (confirmBalanceResolution.mode === "BREAKDOWN") {
    const metalIds   = new Set<string>();
    const variantIds = new Set<string>();
    for (const lr of lineResults) {
      // Fuente primaria: steps `COST_LINES_METAL` con metalId/variantId.
      for (const s of (lr.costSteps ?? [])) {
        if (!s || s.key !== "COST_LINES_METAL" || s.status !== "ok") continue;
        const meta = s.meta ?? {};
        if (typeof meta.metalId   === "string" && meta.metalId)   metalIds.add(meta.metalId);
        if (typeof meta.variantId === "string" && meta.variantId) variantIds.add(meta.variantId);
      }
      // Fallback: breakdown legacy (snapshots viejos).
      const items = lr.breakdownSnapshot?.metal?.items ?? [];
      for (const it of items) {
        if (it.metalId)   metalIds.add(it.metalId);
        if (it.variantId) variantIds.add(it.variantId);
      }
    }
    if (metalIds.size > 0) {
      try {
        const metals = await prisma.metal.findMany({
          where: { id: { in: [...metalIds] }, jewelryId },
          select: { id: true, name: true },
        });
        confirmMetalNames = new Map(metals.map((m) => [m.id, m.name]));
      } catch { /* defensive */ }
    }
    if (variantIds.size > 0) {
      try {
        const variants = await prisma.metalVariant.findMany({
          where: { id: { in: [...variantIds] } },
          select: { id: true, name: true },
        });
        confirmVariantNames = new Map(variants.map((v) => [v.id, v.name]));
      } catch { /* defensive */ }
    }
  }

  // Proyección de líneas + valuación monetaria por línea.
  // Opción A — fuente primaria: STEPS del motor de cost (`lr.costSteps`).
  // Fallback: breakdown legacy (`lr.breakdownSnapshot.metal.items`).
  const confirmLinesForBalance: SaleLineForBalance[] = sale.lines.map((sl) => {
    const lr = lineResults.find((r) => r.lineId === sl.id);
    const bd = lr?.breakdownSnapshot ?? null;
    // metalSale × quantity en moneda BASE (confirmSale persiste en base).
    // Lo derivamos del `bd.totals.metal` (= sum totalValue del metal de la
    // línea — coincide con `metalSale` cuando el motor no aplica
    // descuentos/recargos sobre el metal). Si hace falta paridad exacta
    // con preview ante descuentos, T55 expone metalSale per-line del motor.
    const metalLineValuationDocCurrency =
      typeof bd?.totals?.metal === "number"
        ? Math.round(Number(bd.totals.metal) * Number(sl.quantity) * 100) / 100
        : null;
    const fromSteps = extractMetalItemsFromSteps(lr?.costSteps ?? null);
    const items     = bd?.metal?.items ?? [];
    const metalItems =
      fromSteps.length > 0
        ? fromSteps
        : items.map((it: any) => ({
            metalId:       it.metalId       ?? null,
            variantId:     it.variantId     ?? null,
            gramsOriginal: it.gramsOriginal ?? null,
            purity:        it.purity        ?? null,
            gramsPure:     it.gramsPure     ?? null,
            unitValue:     it.unitValue     ?? null,
          }));
    return {
      lineId:   sl.id,
      quantity: Number(sl.quantity),
      metalItems,
      metalLineValuationDocCurrency,
    };
  });

  // Componentes monetarios doc-level (display-only) — passthrough del motor.
  // Mismo helper que `previewSale` → paridad por construcción.
  // Etapa 1.1: confirm ya recibe `paymentAdjustmentAmount`, `shippingAmount`
  // y `globalDiscountAmount` desde el DRAFT persistido, por lo que los
  // componentes monetarios coinciden 1:1 con los del preview.
  const confirmDocumentMonetaryComponents = buildDocumentMonetaryComponentsFromTotals({
    totals: {
      hechuraSaleSubtotal:     documentTotals.hechuraSaleSubtotal,
      lineDiscountAmount:      documentTotals.lineDiscountAmount,
      channelAdjustmentAmount: documentTotals.channelAdjustmentAmount,
      couponDiscountAmount:    documentTotals.couponDiscountAmount,
      globalDiscountAmount:    documentTotals.globalDiscountAmount,
      paymentAdjustmentAmount: documentTotals.paymentAdjustmentAmount,
      shippingAmount:          documentTotals.shippingAmount,
      taxAmount:                documentTotals.taxAmount,
      roundingAdjustment:      documentTotals.roundingAdjustment,
    },
    channelLabel:  confirmChannelAdj?.channelName ?? null,
    channelSource: confirmChannelAdj?.channelId   ?? null,
    couponLabel:   confirmCouponAdj?.couponName   ?? null,
    couponSource:  confirmCouponAdj?.couponId     ?? null,
  });

  const confirmBalanceBreakdown: DocumentBalanceBreakdown = buildSaleBalanceBreakdown({
    mode:              confirmBalanceResolution.mode,
    documentTotal:     documentTotals.total,
    documentTotalBase: documentTotals.total, // confirm persiste en BASE
    currency: { code: "", rate: 1 },
    lines: confirmLinesForBalance,
    metalNames:   confirmMetalNames,
    variantNames: confirmVariantNames,
    documentMonetaryComponents: confirmDocumentMonetaryComponents,
  });

  // ── Etapa D3 — Capa 16: REDONDEO FÍSICO DE GRAMOS (paridad con preview) ──
  // Misma invocación que en `previewSale`: muta `documentTotals.total` y
  // `confirmBalanceBreakdown.metals[i].gramsPure` para que el ajuste manual
  // (Etapa C) que viene a continuación vea los gramos post-redondeo.
  // Determinismo del helper + helper D1 puro ⇒ paridad preview ↔ confirm.
  applyDocumentPhysicalRounding({
    documentTotals,
    balanceBreakdown: confirmBalanceBreakdown,
    policy: docRoundingPolicy,
  });

  // ── ÚNICA transacción: todas las escrituras juntas ────────────────────────
  // Fase 5: el hook onSaleConfirmed emite Receipt + CurrentAccountMovement
  // dentro de la misma transacción. receipts/accountMovements se propagan en
  // el result de confirmSale para que el endpoint pueda devolver receiptId.
  let hookResult: Awaited<ReturnType<typeof onSaleConfirmed>> = { receipts: [], accountMovements: [] };

  await prisma.$transaction(async (tx) => {
    // 1. Movimiento OUT de stock del artículo padre (si la venta tiene almacén).
    //
    // Guard: las líneas cuyo artículo tiene stockMode=NO_STOCK NO generan movimiento
    // del padre (caso típico: combos comerciales y servicios). El descuento real
    // se hace abajo (1b) sobre los componentes vía componentMovementId.
    let stockMovementId: string | null = null;
    const parentMovementLines = sale.lines.filter(l => {
      const art = articleCostMap.get(l.articleId);
      return art?.stockMode !== "NO_STOCK";
    });
    if (sale.warehouseId && parentMovementLines.length > 0) {
      const movCount = await tx.articleMovement.count({ where: { jewelryId, kind: "OUT" } });
      const movCode  = `AS-${String(movCount + 1).padStart(4, "0")}`;
      const movement = await tx.articleMovement.create({
        data: {
          jewelryId,
          kind:        "OUT",
          status:      "CONFIRMED",
          sourceType:  "SALE",
          code:        movCode,
          note:        `Venta ${sale.code}`,
          effectiveAt: new Date(),
          warehouseId: sale.warehouseId,
          createdById: userId || null,
          lines: {
            create: parentMovementLines.map(l => ({
              jewelryId,
              articleId: l.articleId,
              variantId: l.variantId ?? null,
              quantity:  new Prisma.Decimal(l.quantity.toString()),
            })),
          },
        },
        select: { id: true },
      });
      stockMovementId = movement.id;
      await applyMovementImpact(tx, {
        kind:        "OUT",
        jewelryId,
        warehouseId: sale.warehouseId,
        lines: parentMovementLines.map(l => ({
          articleId: l.articleId,
          variantId: l.variantId ?? null,
          quantity:  new Prisma.Decimal(l.quantity.toString()),
        })),
      });
    }

    // 1b. Movimiento OUT de componentes (PRODUCT/SERVICE con affectsStock=true)
    //
    // FASE 2: el agrupamiento es por (articleId, variantId). Si la línea de
    // costo apunta a una variante específica (`catalogVariantId`), se descuenta
    // de esa variante. Si no, mantiene el comportamiento legacy (descuenta del
    // padre, variantId=null). Dos componentes del mismo padre con variantes
    // distintas generan dos líneas de movimiento separadas.
    let componentMovementId: string | null = null;
    if (sale.warehouseId) {
      type CompLine = { articleId: string; variantId: string | null; qty: Prisma.Decimal };
      const compLines: CompLine[] = [];
      for (const saleLine of sale.lines) {
        const artCost = articleCostMap.get(saleLine.articleId);
        if (!artCost) continue;
        const saleQty = new Prisma.Decimal(saleLine.quantity.toString());
        for (const cl of artCost.costComposition) {
          if (!cl.affectsStock) continue;
          if (cl.type !== "PRODUCT" && cl.type !== "SERVICE") continue;
          if (!cl.catalogItemId) continue;
          const compQty = new Prisma.Decimal(cl.quantity.toString()).mul(saleQty);
          compLines.push({
            articleId: cl.catalogItemId,
            variantId: cl.catalogVariantId ?? null,
            qty:       compQty,
          });
        }
      }
      // Agrupar por (articleId, variantId). Clave compuesta separada con "::"
      // — ningún cuid contiene "::", la separación es inequívoca.
      const compMap = new Map<string, Prisma.Decimal>();
      const KEY_SEP = "::";
      for (const cl of compLines) {
        const key = `${cl.articleId}${KEY_SEP}${cl.variantId ?? ""}`;
        compMap.set(key, (compMap.get(key) ?? new Prisma.Decimal(0)).add(cl.qty));
      }
      const compEntries = [...compMap.entries()].map(([key, qty]) => {
        const [articleId, variantIdRaw] = key.split(KEY_SEP);
        return { articleId, variantId: variantIdRaw || null, qty };
      });
      if (compEntries.length > 0) {
        const compMovCount = await tx.articleMovement.count({ where: { jewelryId, kind: "OUT" } });
        const compMovCode  = `AS-${String(compMovCount + 1).padStart(4, "0")}`;
        const compMov = await tx.articleMovement.create({
          data: {
            jewelryId,
            kind:        "OUT",
            status:      "CONFIRMED",
            sourceType:  "SALE",
            code:        compMovCode,
            note:        `Componentes venta ${sale.code}`,
            effectiveAt: new Date(),
            warehouseId: sale.warehouseId,
            createdById: userId || null,
            lines: {
              create: compEntries.map((e) => ({
                jewelryId,
                articleId: e.articleId,
                variantId: e.variantId,
                quantity:  e.qty,
              })),
            },
          },
          select: { id: true },
        });
        componentMovementId = compMov.id;
        await applyMovementImpact(tx, {
          kind:        "OUT",
          jewelryId,
          warehouseId: sale.warehouseId,
          lines: compEntries.map((e) => ({
            articleId: e.articleId,
            variantId: e.variantId,
            quantity:  e.qty,
          })),
        });
      }
    }

    // 2. Snapshots de costo/impuesto/comisión por línea
    for (const lr of lineResults) {
      if (!lr.updateData) continue;
      await tx.saleLine.update({ where: { id: lr.lineId }, data: lr.updateData as any });
    }

    // 3. Cuenta corriente
    if (balanceEntryData.length > 0) {
      await tx.entityBalanceEntry.createMany({ data: balanceEntryData as any });
    }

    // 4. Cupón
    if (confirmCouponAdj.applied && confirmCouponAdj.couponId) {
      await tx.couponRedemption.create({
        data: { couponId: confirmCouponAdj.couponId, jewelryId, saleId: id, clientId: sale.clientId ?? null, amount: confirmCouponAdj.discountAmount },
      });
    }

    // 5. Actualizar venta — status + totales + snapshots + stockMovementId (todo en un solo update)
    //
    // Fase 3: los totales salen de `documentTotals` (fuente única). El campo
    // `Sale.discountAmount` mantiene su semántica legacy y guarda solo el
    // descuento del cupón (`legacyCouponOnlyDiscount`) hasta que se pueda
    // migrar el schema. El detalle completo (descuentos por línea + canal +
    // cupón) vive en `documentTotals` y, por ahora, se reconstruye al vuelo
    // desde los pricingSnapshot por línea — Fase 4 lo persistirá entero.
    //
    // P1: `subtotal` también se reescribe desde el motor — antes quedaba con
    // el valor del DRAFT, lo que dejaba puerta abierta a que un snapshot stale
    // del frontend persistiera. Ahora viene siempre de documentTotals.
    // Etapa 1B — Snapshot inmutable del redondeo doc aplicado. Se congela
    // acá para que Sale sea auto-suficiente (no depende de Receipt para
    // reproducir el redondeo). El motor devuelve `documentRoundingApplied`
    // ya normalizado con el scope efectivo y todas las capas; le agregamos
    // el flag de supresión de listas para audit.
    const documentRoundingSnapshot = documentTotals.documentRoundingApplied
      ? {
          ...documentTotals.documentRoundingApplied,
          suppressedListDeferredRounding: docRoundingPolicy.suppressListDeferredRounding,
        }
      : null;

    // Etapa Tax (POLICY §Tax.6) — Snapshot fiscal del scaling de impuestos.
    // Solo se persiste si el scaling efectivamente actuó (ratio < 1). Caso
    // contrario, null: la venta no tuvo descuentos de cabecera y el Sale.taxAmount
    // coincide con Σ lineTaxAmount (auditable directo desde SaleLine snapshots).
    //
    // Lectura defensive (`?.`): el motor real siempre puebla `taxScaling` (POLICY
    // §Tax.4), pero mocks de tests pueden devolver `documentTotals` sin el campo
    // — equivalente semántico a `scalingApplied: false`, persistimos null.
    const documentFiscalSnapshot = documentTotals.taxScaling?.scalingApplied
      ? documentTotals.taxScaling
      : null;

    // ── Manual Adjustment (POLICY §R-Rounding-1 capa 17) ──────────────────
    // Etapa A — scope UNIFIED; Etapa C — scope BREAKDOWN.
    // Congelar el override comercial del operador. El `input` viene del
    // DRAFT persistido en `Sale.manualAdjustmentInput`. El helper puro
    // produce el snapshot determinístico (mismo input → mismo output) →
    // garantiza preview/confirm parity.
    //
    // Defensa en profundidad: aunque create/update ya sanea el input, lo
    // revalidamos al consumir. Si por cualquier razón se persistió un shape
    // inválido (ej. legado), tirar 400 antes de armar un snapshot incoherente.
    //
    // Gate scope BREAKDOWN: solo válido cuando el documento confirma en
    // modo BREAKDOWN. Si el operador guardó un draft con scope BREAKDOWN
    // y al confirmar el documento resolvió a UNIFIED (cambio de cliente,
    // lista o tenant default), descartamos el input con un 400 explícito.
    const manualAdjustmentInputDraft = sanitizeManualAdjustmentInputForDraft(
      (sale as any).manualAdjustmentInput ?? null,
      "sales.confirm.manualAdjustmentInput",
    );
    if (
      manualAdjustmentInputDraft?.scope === "BREAKDOWN" &&
      confirmBalanceResolution.mode !== "BREAKDOWN"
    ) {
      const e: any = new Error(
        "manualAdjustmentInput scope=BREAKDOWN no es compatible con un " +
        `documento confirmado en modo "${confirmBalanceResolution.mode}". ` +
        "Volvé a editar el ajuste en la pantalla de Factura.",
      );
      e.status = 400;
      throw e;
    }
    const breakdownContextConfirm = buildManualAdjustmentBreakdownContext(confirmBalanceBreakdown);
    const manualAdjustmentResult = buildManualAdjustmentSnapshot({
      engineTotal: documentTotals.total,
      input:       manualAdjustmentInputDraft,
      audit: {
        appliedBy: userId
          ? { userId, userName: (sale as any).confirmedBy?.name ?? "" }
          : null,
        appliedAt: new Date().toISOString(),
        reason:    manualAdjustmentInputDraft?.reason ?? null,
      },
      breakdownContext: breakdownContextConfirm,
    });
    const manualAdjustmentSnapshot = manualAdjustmentResult.snapshot;
    // POLICY §R-Rounding-1 — `Sale.total` = engineTotal + totals.totalMonetaryAdjustment
    // (clamp ≥ 0). El helper ya devuelve `finalTotal` aplicando esta regla
    // para los dos scopes; lo usamos directamente.
    const finalTotal               = manualAdjustmentResult.finalTotal;

    // ── Etapa UX-Auditable (2026-05-29) — recompute monetary.components ────
    // Igual que en previewSale: el primer call de
    // `buildDocumentMonetaryComponentsFromTotals` corrió ANTES de la capa 16
    // y la capa 17. Ahora reconstruimos para que `confirmBalanceBreakdown.
    // monetaryBalance.components` incluya METAL_MARGIN (cubre la diferencia
    // entre metalCostSubtotal y Σ valuationMonetary) y MANUAL_ADJUSTMENT
    // (capa 17). Resultado: Σ components == saldo monetario canónico
    // (POLICY §R-Rounding-14). Display-only — no afecta total persistido.
    if (
      confirmBalanceBreakdown.monetaryBalance
      && confirmBalanceResolution.mode === "BREAKDOWN"
    ) {
      const metalValuationSumPost = (confirmBalanceBreakdown.metals ?? []).reduce(
        (acc, m) =>
          acc + (typeof m.valuationMonetary === "number" && Number.isFinite(m.valuationMonetary)
            ? m.valuationMonetary
            : 0),
        0,
      );
      const manualAdjMonetary =
        manualAdjustmentSnapshot?.totals?.totalMonetaryAdjustment ?? null;
      confirmBalanceBreakdown.monetaryBalance.components = buildDocumentMonetaryComponentsFromTotals({
        totals: {
          hechuraSaleSubtotal:     documentTotals.hechuraSaleSubtotal,
          lineDiscountAmount:      documentTotals.lineDiscountAmount,
          channelAdjustmentAmount: documentTotals.channelAdjustmentAmount,
          couponDiscountAmount:    documentTotals.couponDiscountAmount,
          globalDiscountAmount:    documentTotals.globalDiscountAmount,
          paymentAdjustmentAmount: documentTotals.paymentAdjustmentAmount,
          shippingAmount:          documentTotals.shippingAmount,
          taxAmount:                documentTotals.taxAmount,
          roundingAdjustment:      documentTotals.roundingAdjustment,
          metalCostSubtotal:       documentTotals.metalCostSubtotal,
        },
        metalValuationSum:             metalValuationSumPost,
        manualAdjustmentMonetaryAmount: manualAdjMonetary,
        channelLabel:  confirmChannelAdj?.channelName ?? null,
        channelSource: confirmChannelAdj?.channelId   ?? null,
        couponLabel:   confirmCouponAdj?.couponName   ?? null,
        couponSource:  confirmCouponAdj?.couponId     ?? null,
      });
    }

    await tx.sale.update({
      where: { id },
      data: {
        status:          "CONFIRMED",
        confirmedAt:     new Date(),
        confirmedById:   userId || null,
        subtotal:        documentTotals.subtotalAfterLineDiscounts,
        taxAmount:       documentTotals.taxAmount,
        discountAmount:  documentTotals.legacyCouponOnlyDiscount,
        // POLICY §R-Rounding-1 — Sale.total ahora es el `finalTotal`:
        //   - sin manualAdjustment → finalTotal === engineTotal (igual que antes).
        //   - con manualAdjustment → finalTotal = engineTotal + delta.
        // PDFs, cuenta corriente y mails leen `Sale.total` → coherente.
        total:           finalTotal,
        // POLICY §R-Rounding-6 — Engine Total (auditoría pre-ajuste manual).
        // Snapshot del total emitido por `computeSaleDocumentTotals`
        // INMEDIATAMENTE después del rounding del motor. Cuando hay
        // ajuste manual, `total` diverge de `engineTotal` por el delta
        // del snapshot.
        engineTotal:     documentTotals.total,
        ...(sellerCommissionTotal != null && { sellerCommissionTotal }),
        ...(stockMovementId       != null && { stockMovementId }),
        ...(componentMovementId   != null && { componentMovementId }),
        clientSnapshot:  clientSnapshot  ?? Prisma.JsonNull,
        sellerSnapshot:  sellerSnapshot  ?? Prisma.JsonNull,
        channelSnapshot: channelSnapshot ?? Prisma.JsonNull,
        couponSnapshot:  couponSnapshot  ?? Prisma.JsonNull,
        currencyId:      currencyRow?.id ?? null,
        currencySnapshot: currencySnapshot ?? Prisma.JsonNull,
        issuerSnapshot:  issuerSnapshot  ?? Prisma.JsonNull,
        // T55 (Fase 3B.5) — Balance Mode congelado (R11.1 inmutable).
        balanceMode:       confirmBalanceResolution.mode,
        balanceModeSource: confirmBalanceResolution.source,
        // Etapa 1B — Document Rounding Snapshot (inmutable).
        documentRoundingSnapshot: documentRoundingSnapshot
          ? (documentRoundingSnapshot as unknown as Prisma.InputJsonValue)
          : Prisma.JsonNull,
        // Etapa D' — Commercial Document Rounding Snapshot (inmutable).
        // Mismo shape que viaja en el response del preview en
        // `documentTotals.commercialDocumentRoundingApplied`. Null cuando la
        // venta operó en PER_LINE_LEGACY o MIXED_LIST_FALLBACK.
        commercialDocumentRoundingSnapshot: documentTotals.commercialDocumentRoundingApplied
          ? (documentTotals.commercialDocumentRoundingApplied as unknown as Prisma.InputJsonValue)
          : Prisma.JsonNull,
        // Etapa Tax (POLICY §Tax.6) — Document Fiscal Snapshot (inmutable).
        documentFiscalSnapshot: documentFiscalSnapshot
          ? (documentFiscalSnapshot as unknown as Prisma.InputJsonValue)
          : Prisma.JsonNull,
        // Etapa Manual Adjustment 1 — Snapshot inmutable del override
        // comercial humano. Null cuando no hubo ajuste.
        manualAdjustmentSnapshot: manualAdjustmentSnapshot
          ? (manualAdjustmentSnapshot as unknown as Prisma.InputJsonValue)
          : Prisma.JsonNull,
        // El input DRAFT ya fue consumido para armar el snapshot — limpiarlo
        // evita confusión en lecturas post-confirm (la fuente de verdad es
        // el snapshot inmutable).
        manualAdjustmentInput: Prisma.JsonNull,
      } as any,
    });

    // 6. Emitir comprobante + cuenta corriente (Fase 5).
    //    El hook corre DENTRO de esta misma transacción — si algo falla,
    //    Postgres revierte el sale.update, el stockMovement y el receipt juntos.
    //    Fase 3B.5: pasamos el balanceBreakdown ya construido para que el
    //    snapshot v3 lo incluya canónicamente. NO se crea AccountMovementMetalEntry
    //    todavía (eso es 3B.6).
    hookResult = await onSaleConfirmed(tx, id, {
      issueInvoice: true,
      issuedById:   userId || null,
      balanceMode:       confirmBalanceResolution.mode,
      balanceModeSource: confirmBalanceResolution.source,
      balanceBreakdown:  confirmBalanceBreakdown,
    });
  });

  const confirmedSale = await getSale(id, jewelryId);
  return {
    ...confirmedSale,
    receipts:         hookResult.receipts,
    accountMovements: hookResult.accountMovements,
  };
}

// ─── Add payment ─────────────────────────────────────────────────────────────
export async function addPayment(
  saleId: string,
  jewelryId: string,
  body: AddPaymentInput
) {
  const sale = await prisma.sale.findFirst({
    where: { id: saleId, jewelryId },
    select: { id: true, status: true, total: true, paidAmount: true },
  });
  if (!sale) err("Venta no encontrada.", 404);
  if (sale.status === "CANCELLED") err("No se puede cobrar una venta anulada.");
  if (sale.status === "DRAFT") err("Confirme la venta antes de registrar pagos.");

  if (body.amount <= 0) err("El monto del pago debe ser mayor a 0.");

  let paymentMethodName = "";
  if (body.paymentMethodId) {
    const pm = await prisma.paymentMethod.findFirst({
      where: { id: body.paymentMethodId, jewelryId, deletedAt: null },
      select: { name: true },
    });
    if (!pm) err("Método de pago no encontrado.");
    paymentMethodName = pm!.name;
  }

  await prisma.salePayment.create({
    data: {
      saleId,
      jewelryId,
      paymentMethodId: body.paymentMethodId ?? null,
      paymentMethodName,
      amount: body.amount,
      installments: body.installments ?? 1,
      reference: body.reference ?? "",
    },
  });

  // Recalculate paidAmount and update status
  const allPayments = await prisma.salePayment.findMany({
    where: { saleId },
    select: { amount: true },
  });
  const newPaid = allPayments.reduce(
    (sum, p) => sum + parseFloat(p.amount.toString()),
    0
  );
  const total = parseFloat(sale.total.toString());
  const newStatus =
    newPaid >= total ? "PAID" : newPaid > 0 ? "PARTIALLY_PAID" : "CONFIRMED";

  await prisma.sale.update({
    where: { id: saleId },
    data: { paidAmount: newPaid, status: newStatus as any },
  });

  // Actualizar comisión TOTAL_AFTER_PAYMENT en el primer pago con factor real del medio de pago
  if (allPayments.length === 1 && body.paymentMethodId) {
    const saleForComm = await prisma.sale.findFirst({
      where: { id: saleId },
      select: {
        total:     true,
        taxAmount: true,
        seller: { select: { commissionType: true, commissionValue: true, commissionBase: true } },
      },
    });
    if (
      saleForComm?.seller?.commissionBase === "TOTAL_AFTER_PAYMENT" &&
      saleForComm.seller.commissionType === "PERCENTAGE" &&
      saleForComm.seller.commissionValue != null
    ) {
      const pmForComm = await prisma.paymentMethod.findFirst({
        where: { id: body.paymentMethodId, jewelryId, deletedAt: null },
        select: { adjustmentType: true, adjustmentValue: true },
      });
      if (pmForComm) {
        const preTaxTotal = parseFloat(saleForComm.total.toString()) - parseFloat(saleForComm.taxAmount.toString());
        let paymentAdj = 0;
        if (pmForComm.adjustmentType === "PERCENTAGE" && pmForComm.adjustmentValue != null) {
          paymentAdj = preTaxTotal * parseFloat(pmForComm.adjustmentValue.toString()) / 100;
        } else if (pmForComm.adjustmentType === "FIXED_AMOUNT" && pmForComm.adjustmentValue != null) {
          paymentAdj = parseFloat(pmForComm.adjustmentValue.toString());
        }
        const totalAfterPayment = preTaxTotal + paymentAdj;
        const pct = parseFloat(saleForComm.seller.commissionValue.toString()) / 100;
        const newComm = Math.round(totalAfterPayment * pct * 100) / 100;
        await prisma.sale.update({
          where: { id: saleId },
          data: { sellerCommissionTotal: newComm } as any,
        });
      }
    }
  }

  return getSale(saleId, jewelryId);
}

// ─── Cancel ──────────────────────────────────────────────────────────────────
export async function cancelSale(
  id: string,
  jewelryId: string,
  userId: string,
  note: string
) {
  const sale = await prisma.sale.findFirst({
    where: { id, jewelryId },
    select: {
      id: true, status: true,
      stockMovementId: true, componentMovementId: true,
      clientId: true,
      // Etapa 1.2 — bloqueo de cancelación si hay cobros aplicados.
      paidAmount: true,
    },
  });

  if (!sale) err("Venta no encontrada.", 404);
  if (sale.status === "CANCELLED") err("La venta ya está anulada.");

  // Etapa 1.2 — Regla 6: rechazar si hay cobros aplicados. La reversa de
  // cobros vendrá con el módulo Cobros; sin esa lógica, anular dejaría
  // pagos huérfanos contra una sale CANCELLED.
  const paidAmount = parseFloat(sale.paidAmount?.toString() ?? "0");
  if (paidAmount > 0) {
    const e: any = new Error(
      "No se puede anular una factura con cobros aplicados. Primero revertí o desvinculá los cobros.",
    );
    e.status = 409;
    e.code   = "SALE_CANCEL_BLOCKED_BY_PAYMENTS";
    throw e;
  }

  const wasConfirmed = sale.status !== "DRAFT";

  return prisma.$transaction(async (tx) => {
    // 1. Revertir movimiento de stock si la venta fue confirmada y tiene movimiento asociado
    if (wasConfirmed && sale.stockMovementId) {
      const movement = await tx.articleMovement.findUnique({
        where:  { id: sale.stockMovementId },
        select: {
          kind:        true,
          warehouseId: true,
          lines: { select: { articleId: true, variantId: true, quantity: true } },
        },
      });
      if (movement) {
        await reverseMovementImpact(tx, {
          kind:        movement.kind as "OUT",
          jewelryId,
          warehouseId: movement.warehouseId ?? undefined,
          lines: movement.lines.map(l => ({
            articleId: l.articleId,
            variantId: l.variantId,
            quantity:  new Prisma.Decimal(l.quantity.toString()),
          })),
        });
        await tx.articleMovement.update({
          where: { id: sale.stockMovementId! },
          data: {
            status:     "VOIDED",
            voidedAt:   new Date(),
            voidedById: userId || null,
            voidedNote: note ? `Venta anulada: ${note}` : "Venta anulada",
          },
        });
      }
    }

    // 1b. Revertir movimiento de componentes si existía
    if (wasConfirmed && sale.componentMovementId) {
      const compMov = await tx.articleMovement.findUnique({
        where:  { id: sale.componentMovementId },
        select: {
          kind:        true,
          warehouseId: true,
          lines: { select: { articleId: true, variantId: true, quantity: true } },
        },
      });
      if (compMov) {
        await reverseMovementImpact(tx, {
          kind:        compMov.kind as "OUT",
          jewelryId,
          warehouseId: compMov.warehouseId ?? undefined,
          lines: compMov.lines.map(l => ({
            articleId: l.articleId,
            variantId: l.variantId,
            quantity:  new Prisma.Decimal(l.quantity.toString()),
          })),
        });
        await tx.articleMovement.update({
          where: { id: sale.componentMovementId! },
          data: {
            status:     "VOIDED",
            voidedAt:   new Date(),
            voidedById: userId || null,
            voidedNote: note ? `Venta anulada: ${note}` : "Venta anulada",
          },
        });
      }
    }

    // 2. Anular balance entries de cuenta corriente del cliente (legacy).
    //    Convive con `CurrentAccountMovement` (Etapa 1.2) hasta la migración
    //    explícita del sistema dual (Etapa 6 en el plan).
    if (wasConfirmed && sale.clientId) {
      await tx.entityBalanceEntry.updateMany({
        where: {
          entityId:    sale.clientId,
          jewelryId,
          documentRef: id,   // documentRef = sale.id (seteado en confirmSale)
          voidedAt:    null, // idempotencia: no reanular las ya anuladas
        },
        data: {
          voidedAt:   new Date(),
          voidedBy:   userId || "",
          voidReason: `Venta cancelada: ${note || "sin nota"}`,
        },
      });
    }

    // 3. Etapa 1.2 — Emitir Nota de Crédito + CurrentAccountMovement CREDIT
    //    reverso. Regla "nada se pisa, todo se encadena":
    //      · Receipt INVOICE original queda intacto.
    //      · CurrentAccountMovement DEBIT original queda intacto.
    //      · NC apunta al original via `correctedReceiptId`.
    //      · Movimiento CREDIT reverso apunta a la NC + sourceDocument SALE_CANCEL.
    //    Solo se invoca para sales CONFIRMED (las DRAFT no tienen Receipt).
    //    Si falla, toda la TX revierte (stock + EntityBalanceEntry + Sale).
    if (wasConfirmed) {
      await onSaleCancelled(tx, id, {
        issuedById: userId || null,
        note:       note ?? "",
      });
    }

    return tx.sale.update({
      where: { id },
      data: {
        status:        "CANCELLED",
        cancelledAt:   new Date(),
        cancelledById: userId || null,
        cancelNote:    note ?? "",
      },
      select: SALE_DETAIL_SELECT,
    });
  });
}

// ─── Caja day summary ─────────────────────────────────────────────────────────
export async function cajaDaySummary(jewelryId: string, date: string) {
  // Parse date: expects "YYYY-MM-DD"
  const d = new Date(date + "T00:00:00");
  if (isNaN(d.getTime())) {
    const e: any = new Error("Fecha inválida. Usar formato YYYY-MM-DD.");
    e.status = 400; throw e;
  }
  const dayStart = new Date(d.getFullYear(), d.getMonth(), d.getDate(), 0, 0, 0, 0);
  const dayEnd   = new Date(d.getFullYear(), d.getMonth(), d.getDate(), 23, 59, 59, 999);

  const payments = await prisma.salePayment.findMany({
    where: {
      jewelryId,
      paidAt: { gte: dayStart, lte: dayEnd },
    },
    select: {
      id: true,
      saleId: true,
      paymentMethodId: true,
      paymentMethodName: true,
      amount: true,
      installments: true,
      reference: true,
      paidAt: true,
      sale: { select: { code: true, status: true, total: true } },
    },
    orderBy: { paidAt: "asc" },
  });

  // Aggregate by payment method
  const methodMap = new Map<string, { paymentMethodId: string | null; paymentMethodName: string; amount: number; count: number }>();
  let totalPaid = 0;

  for (const p of payments) {
    const key = p.paymentMethodName || "Otro";
    const existing = methodMap.get(key);
    const amt = parseFloat(p.amount.toString());
    totalPaid += amt;
    if (existing) {
      existing.amount += amt;
      existing.count += 1;
    } else {
      methodMap.set(key, {
        paymentMethodId: p.paymentMethodId,
        paymentMethodName: key,
        amount: amt,
        count: 1,
      });
    }
  }

  // Sales confirmed or paid on this day (by saleDate)
  const salesOnDay = await prisma.sale.findMany({
    where: {
      jewelryId,
      status: { not: "CANCELLED" },
      saleDate: { gte: dayStart, lte: dayEnd },
    },
    select: { id: true, code: true, status: true, total: true, paidAmount: true },
  });

  const totalSalesAmount = salesOnDay.reduce((s, sale) => s + parseFloat(sale.total.toString()), 0);
  const totalSalesPending = salesOnDay.reduce((s, sale) => {
    const pending = parseFloat(sale.total.toString()) - parseFloat(sale.paidAmount.toString());
    return s + Math.max(0, pending);
  }, 0);

  return {
    date,
    salesCount: salesOnDay.length,
    totalSalesAmount,
    totalPaid,
    totalPending: totalSalesPending,
    paymentsByMethod: Array.from(methodMap.values()),
    payments: payments.map((p) => ({
      id: p.id,
      saleId: p.saleId,
      saleCode: p.sale?.code ?? "",
      saleStatus: p.sale?.status ?? "",
      paymentMethodId: p.paymentMethodId,
      paymentMethodName: p.paymentMethodName || "Otro",
      amount: p.amount,
      installments: p.installments,
      reference: p.reference,
      paidAt: p.paidAt,
    })),
  };
}

// ─── Pricing en DRAFT — fuente única de verdad ───────────────────────────────
// Helper compartido por createSale() y updateSale(). Resuelve cada línea con
// el pricing-engine (mismo camino que previewSale) y devuelve los valores
// listos para persistir en SaleLine, incluido `pricingSnapshot`.
//
// REGLA: el unitPrice y los descuentos del cliente NO son fuente de verdad.
// El motor recalcula desde articleId, variantId, quantity y clientId. Si el
// frontend manda valores legacy, se ignoran como fuente principal y solo se
// loguea una advertencia si difieren del cálculo real.

export type DraftSaleLineInput = {
  articleId: string;
  variantId?: string | null;
  quantity: number;
  /** Solo para compatibilidad: ignorado como fuente principal. */
  legacyClientUnitPrice?: number;
  /** Solo para compatibilidad: ignorado como fuente principal. */
  legacyClientDiscountPct?: number;

  // ── Fase 1.5 — overrides de composición que viajan a DRAFT ───────────────
  // Mismas reglas que `SalePreviewLineInput` y `CreateSaleLineInput`. El
  // motor los aplica al resolver el snapshot persistido para que confirm /
  // recompute mantengan paridad con preview.
  gramsOverride?:          number | null;
  mermaPercentOverride?:   number | null;
  metalVariantIdOverride?: string | null;
  hechuraOverrideAmount?:  number | null;
  costLineOverrides?:      CostLineOverride[];
  /** Override de SOLO la base ("Aplica a") del descuento del cliente,
   *  independiente del valor. Persiste vía snapshot para paridad confirm. */
  manualDiscountAppliesToOverride?: SaleLineAppliesTo | null;
  /** Override de SOLO la base ("Aplica a") del impuesto heredado,
   *  independiente del valor. Persiste en el snapshot para que confirmSale
   *  recompute el impuesto sobre la misma base (paridad preview↔confirm). */
  manualTaxAppliesToOverride?: SaleLineAppliesTo | null;

  // ── Etapa 4 — overrides comerciales DRAFT ────────────────────────────────
  // El motor (`resolveFinalSalePrice`) los recibe directamente; el snapshot
  // congela el resultado. Si el operador reabre el DRAFT, updateSale los
  // vuelve a pasar y el snapshot se recompute igual.
  manualPriceOverride?:    number | null;
  manualDiscountOverride?: SaleLineManualDiscountOverride | null;
  taxOverride?:            SaleLineTaxOverride | null;
  priceListIdOverride?:    string | null;
};

export type DraftSaleLineOpts = {
  clientId?: string | null;
  /** Etapa C16 — fix paridad preview ↔ persist (C15). Lista del documento.
   *  Cada línea sin `priceListIdOverride` la hereda como `priceListIdOverride`
   *  efectivo cuando llama al motor. Sin esto, las líneas sin override caían
   *  a la cadena legacy (cliente → favorita) y se perdía la lista global
   *  elegida por el operador en el combo del documento. */
  priceListId?: string | null;
};

export type DraftSaleLineResolved = {
  articleId:           string;
  variantId:           string | null;
  quantity:            number;
  unitPrice:           number;
  discountPct:         number;
  lineTotal:           number;
  priceSource:         string;
  appliedPriceListId:  string | null;
  appliedPromotionId:  string | null;
  appliedDiscountId:   string | null;
  pricingSnapshot:     PricingLineSnapshot;
};

/**
 * Resuelve el precio de cada línea en DRAFT usando el pricing-engine.
 *
 * Devuelve, por cada línea, los valores que se van a persistir en SaleLine:
 *   - unitPrice / discountPct / lineTotal (esquema actual, sin cambios)
 *   - priceSource / appliedPriceListId / appliedPromotionId / appliedDiscountId
 *   - pricingSnapshot completo (para reconstrucción histórica)
 *
 * NOTA Fase 1: no se computan unitCost / totalCost / margin / breakdownSnapshot
 * / taxAmount / taxSnapshot en DRAFT. Esos siguen viviendo en confirmSale().
 * El `pricingSnapshot` ya trae `unitCost`, `unitMargin`, `marginPercent` desde
 * el motor, así que la información existe (solo no en columnas dedicadas).
 * Mover el resto a DRAFT es trabajo de Fase 2.
 */
export async function resolveDraftSaleLinesPricing(
  jewelryId: string,
  lines: DraftSaleLineInput[],
  opts: DraftSaleLineOpts = {},
): Promise<DraftSaleLineResolved[]> {
  if (!lines.length) return [];

  // Si el tenant tiene política de redondeo a nivel comprobante activa, los
  // snapshots del DRAFT deben construirse SIN el redondeo diferido (NET/TOTAL)
  // de la lista. El redondeo se aplica una sola vez, al confirmar, sobre el
  // total del documento.
  const { suppressListDeferredRounding } = await loadDocumentRoundingConfig(jewelryId);

  // ── Etapa D' — Contexto comercial PER_DOCUMENT para createSale/updateSale ─
  // Se resuelve usando los mismos `priceListIdOverride` de las líneas del
  // input. El draft persistirá los snapshots SIN redondeo per-line si el
  // documento opera en PER_DOCUMENT, garantizando que confirmSale pueda
  // aplicar la capa nueva sin doble.
  const draftCommercialDocCtx = await resolveDocumentCommercialContextForSale({
    jewelryId,
    lineInputs:              lines,
    defaultPriceListIdInput: opts.priceListId ?? null,
  });
  assertCommercialDocRoundingConsistency(draftCommercialDocCtx);

  // ── Precarga de totales por categoría / marca / grupo ────────────────────
  // Se usan cuando un QuantityDiscount evalúa por CATEGORY_TOTAL / BRAND_TOTAL
  // / GROUP_TOTAL. Mismo patrón que previewSale().
  //
  // F1.3 G4.x #5b — además precargamos `costComposition` para poder armar
  // composition (products/services) y persistirla en el snapshot del DRAFT.
  // Sin esto, el snapshot iba sin composition y al confirmar perdíamos
  // paridad preview/persisted.
  const articleIds = [...new Set(lines.map(l => l.articleId))];
  const articleMeta = articleIds.length > 0
    ? await prisma.article.findMany({
        where: { id: { in: articleIds }, jewelryId, deletedAt: null },
        select: {
          id: true, categoryId: true, brand: true,
          costComposition: { select: { catalogItemId: true } },
        },
      })
    : [];
  const metaMap = new Map(articleMeta.map(a => [a.id, a]));

  // F1.3 G4.x #5b — catalogItemsMap GLOBAL (1 query con dedupe cross-líneas).
  // Mismo patrón que previewSale (commit G4.1.4). Failure-safe: catálogo
  // caído → Map vacío y los items renderean con fallback meta.lineCode/Label.
  const catalogItemsMap = await buildCatalogItemsMapForCostLines(
    jewelryId,
    articleMeta.map(a => a.costComposition ?? []),
  );

  const variantIds = lines.map(l => l.variantId).filter(Boolean) as string[];
  const variantGroupItems = variantIds.length > 0
    ? await prisma.articleGroupItem.findMany({
        where: { variantId: { in: variantIds }, itemType: "VARIANT" },
        select: { variantId: true, groupId: true },
      })
    : [];
  const variantGroupMap = new Map(variantGroupItems.map(i => [i.variantId!, i.groupId]));

  const categoryTotals = new Map<string, number>();
  const brandTotals    = new Map<string, number>();
  const groupTotals    = new Map<string, number>();
  for (const line of lines) {
    const m       = metaMap.get(line.articleId);
    const groupId = line.variantId ? variantGroupMap.get(line.variantId) : undefined;
    if (!m) continue;
    if (m.categoryId) categoryTotals.set(m.categoryId, (categoryTotals.get(m.categoryId) ?? 0) + line.quantity);
    if (m.brand)      brandTotals.set(m.brand,          (brandTotals.get(m.brand)          ?? 0) + line.quantity);
    if (groupId)      groupTotals.set(groupId,           (groupTotals.get(groupId)           ?? 0) + line.quantity);
  }

  return Promise.all(
    lines.map(async (line): Promise<DraftSaleLineResolved> => {
      const m       = metaMap.get(line.articleId);
      const lineGid = line.variantId ? variantGroupMap.get(line.variantId) : undefined;

      const result = await resolveFinalSalePrice(jewelryId, {
        articleId: line.articleId,
        variantId: line.variantId ?? null,
        clientId:  opts.clientId ?? undefined,
        quantity:  line.quantity,
        categoryTotal: m?.categoryId ? categoryTotals.get(m.categoryId) : undefined,
        brandTotal:    m?.brand      ? brandTotals.get(m.brand)         : undefined,
        groupTotal:    lineGid       ? groupTotals.get(lineGid)          : undefined,
        // Fase 1.5 — overrides per-line viajan al motor en DRAFT. El
        // snapshot resultante (`buildPricingSnapshot`) preserva
        // `costLineOverridesApplied`, así confirm/recompute pueden
        // reaplicar los mismos overrides sobre el costo fresco y mantener
        // paridad con preview.
        gramsOverride:          line.gramsOverride          ?? null,
        mermaPercentOverride:   line.mermaPercentOverride   ?? null,
        metalVariantIdOverride: line.metalVariantIdOverride ?? null,
        hechuraOverrideAmount:  line.hechuraOverrideAmount  ?? null,
        costLineOverrides:      line.costLineOverrides,
        // Override de SOLO la base del descuento del cliente — afecta el
        // unitPrice congelado en DRAFT (paridad con preview).
        discountAppliesToOverride: line.manualDiscountAppliesToOverride ?? null,
        taxAppliesToOverride:      line.manualTaxAppliesToOverride      ?? null,
        // Etapa 4 — overrides comerciales del operador (precio manual,
        // bonificación manual, impuesto manual, override de lista per-línea).
        manualPriceOverride:    line.manualPriceOverride    ?? null,
        manualDiscountOverride: line.manualDiscountOverride ?? null,
        taxOverride:            line.taxOverride            ?? null,
        // Etapa C16 — fallback paridad preview ↔ persist (fix drift C15).
        // Precedencia: priceListIdOverride por línea > priceListId del doc
        // > null (cae a cadena cliente → favorita en el motor). Mismo
        // patrón que `previewSale` (`sales.service.ts:3790`).
        priceListIdOverride:
          line.priceListIdOverride ?? opts.priceListId ?? null,
        suppressListDeferredRounding,
        // Etapa D' — Propaga los flags PER_DOCUMENT al motor de lista.
        // Cuando PER_LINE_LEGACY, el objeto está vacío y el comportamiento
        // queda intacto.
        applyPriceListOptions: draftCommercialDocCtx.applyPriceListOptions,
      });

      const engineUnitPrice = result.unitPrice != null
        ? parseFloat(result.unitPrice.toString())
        : null;

      // ── Fallback controlado si el motor no pudo resolver el precio ─────
      // Si `engineUnitPrice` es null el motor no tiene datos suficientes
      // (artículo sin lista, sin manual, sin nada). Antes de Fase 1, esa
      // venta se creaba igual con el unitPrice del cliente. Para no romper
      // ese comportamiento, usamos el legacy como fallback con log explícito.
      // TODO Fase 2: decidir si esto debe ser un error duro.
      let unitPrice: number;
      if (engineUnitPrice != null) {
        unitPrice = engineUnitPrice;
        if (
          line.legacyClientUnitPrice != null &&
          Math.abs(line.legacyClientUnitPrice - engineUnitPrice) > 0.01
        ) {
          console.warn(
            `[sales.draftPricing] Cliente envió unitPrice=${line.legacyClientUnitPrice} ` +
            `para articleId=${line.articleId} pero el motor calculó ${engineUnitPrice}. ` +
            `Se usa el motor.`,
          );
        }
      } else {
        unitPrice = line.legacyClientUnitPrice ?? 0;
        console.warn(
          `[sales.draftPricing] Motor no pudo calcular precio para ` +
          `articleId=${line.articleId} (jewelryId=${jewelryId}). ` +
          `Fallback legacy unitPrice=${unitPrice}. ` +
          `TODO Fase 2: convertir en error duro o requerir override explícito.`,
        );
      }

      // ── discountPct: derivado del basePrice del motor ─────────────────
      // Convención del schema: lineTotal = qty × unitPrice × (1 − discPct/100).
      // El motor devuelve `unitPrice` ya con todos los descuentos aplicados,
      // así que persistimos discountPct=0 para evitar doble descuento. La
      // trazabilidad del descuento original vive en pricingSnapshot.basePrice
      // y en pricingSnapshot.discountAmount.
      // TODO Fase 2: evaluar persistir basePrice/discountPct reales para que
      // confirmSale() y reportes lo reconstruyan sin leer el snapshot JSON.
      const discountPct = 0;
      const lineTotal   = Math.round(unitPrice * line.quantity * 100) / 100;

      // F1.3 G4.x #5b — armar composition para persistirla en el snapshot.
      // Failure-safe: si buildComposition falla, snapshot queda con
      // composition=null y la UI degrada a defaults seguros (sin crash).
      let composition: Awaited<ReturnType<typeof buildComposition>> | null = null;
      try {
        // F1.3 G4.x #9-A — además del legacy fetch del primer variantId,
        // batch query de TODAS las variantes referenciadas en steps METAL
        // (uno por cost line). Permite que composition.metals[] traiga
        // metalName/purity per item.
        const metalVariantIdToFetch = resolveMetalVariantIdFromResult(result);
        const metalVariantIdsFromSteps = (result.steps ?? [])
          .filter(s => s?.key === "COST_LINES_METAL" && s?.status === "ok")
          .map(s => (s.meta as any)?.variantId)
          .filter((v): v is string => typeof v === "string" && v.length > 0);
        const [metalVariantInfo, metalVariantInfoMap] = await Promise.all([
          fetchMetalVariantInfo(metalVariantIdToFetch),
          fetchMetalVariantInfoMap(metalVariantIdsFromSteps),
        ]);
        composition = buildComposition(result, metalVariantInfo, catalogItemsMap, metalVariantInfoMap);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(
          `[sales.draftPricing] buildComposition falló para articleId=${line.articleId}; ` +
          `snapshot persistido con composition=null:`,
          err,
        );
      }

      // F17 — paridad preview/confirm. computePurchaseTaxes corre acá también
      // para que el snapshot v7 persistido en DRAFT incluya costBase/
      // costTaxAmount/costWithTax/costTaxBreakdown idénticos a los del
      // preview. La base es `result.unitCost` (post-ajuste global).
      const draftCostTaxResult = await computePurchaseTaxes(
        jewelryId,
        line.articleId,
        result.unitCost ?? null,
      );
      const pricingSnapshot = buildPricingSnapshot(result, {
        composition,
        purchaseTaxes: draftCostTaxResult,
      });
      // Persistir la base ("Aplica a") del impuesto elegida por el operador,
      // para que confirmSale recompute el impuesto sobre la MISMA base
      // (paridad preview↔confirm). El descuento ya quedó congelado en
      // unitPrice (resuelto arriba con discountAppliesToOverride).
      (pricingSnapshot as any).manualTaxAppliesTo =
        line.manualTaxAppliesToOverride ?? null;

      return {
        articleId:           line.articleId,
        variantId:           line.variantId ?? null,
        quantity:            line.quantity,
        unitPrice,
        discountPct,
        lineTotal,
        priceSource:         result.priceSource ?? "",
        appliedPriceListId:  result.appliedPriceListId,
        appliedPromotionId:  result.appliedPromotionId,
        appliedDiscountId:   result.appliedDiscountId,
        pricingSnapshot,
      };
    }),
  );
}

// ─── Pricing en CONFIRM — leer snapshot frozen del DRAFT ────────────────────
// Helper usado por confirmSale(). Lee el `pricingSnapshot` que createSale /
// updateSale dejaron en SaleLine y lo devuelve como única fuente de verdad
// del precio. Así evitamos la reconstrucción inversa
// `basePrice = unitPrice / (1 - discPct/100)` que era incorrecta cuando el
// descuento provenía de promoción / quantityDiscount / manual override.
//
// Si la línea es legada (sin snapshot, ej. ventas creadas antes de Fase 1)
// el helper recalcula con el motor. Eso preserva compatibilidad pero
// **cambia el precio frozen**: la responsabilidad de no perder el precio
// histórico recae en quien creó esa venta vieja sin snapshot.

type LegacySaleLineForSnapshot = {
  id: string;
  articleId: string;
  variantId: string | null;
  quantity: any;       // Decimal
  unitPrice: any;      // Decimal — fallback de último recurso
  discountPct: any;    // Decimal — fallback de último recurso
  pricingSnapshot: any; // Json | null leído de la DB
  priceSource: string;
  appliedPriceListId: string | null;
  appliedPromotionId: string | null;
  appliedDiscountId:  string | null;
};

/**
 * Devuelve true si el snapshot tiene el mínimo necesario para confirmar
 * sin recalcular: `unitPrice` numérico finito y `priceSource` string.
 */
function isUsableConfirmSnapshot(s: any): s is PricingLineSnapshot {
  return (
    !!s &&
    typeof s === "object" &&
    typeof s.unitPrice === "number" &&
    Number.isFinite(s.unitPrice) &&
    typeof s.priceSource === "string"
  );
}

/**
 * Resultado del helper. `recomputed=true` indica que el snapshot original no
 * estaba o no era usable y hubo que recalcular con el motor (línea legada).
 */
type ConfirmSnapshotResolution = {
  snapshot:   PricingLineSnapshot;
  recomputed: boolean;
};

/**
 * Obtiene el `PricingLineSnapshot` para usar al confirmar una venta.
 *
 *   1) Si la línea trae un snapshot válido → se devuelve tal cual.
 *   2) Si no → se recalcula con `resolveFinalSalePrice` (mismo camino que
 *      Simulador / DRAFT) y se loguea warn para diagnóstico.
 *   3) Si el motor tampoco resuelve (artículo sin lista, sin manual, sin
 *      cotización…) → snapshot mínimo desde columnas de la línea, con
 *      `partial=true`. Es el último recurso para no romper ventas viejas.
 *
 * Nota Fase 2: este helper NO consulta articleGroupItem ni precalcula
 * categoryTotal/brandTotal/groupTotal. Si una línea legada usaba un
 * descuento por cantidad con scope CATEGORY/BRAND/GROUP, el recompute
 * cae a comportamiento LINE. Aceptable para legacy; si hace falta más
 * fidelidad, mover a Fase 3.
 */
export async function getLinePricingSnapshotForConfirm(
  jewelryId: string,
  line: LegacySaleLineForSnapshot,
  opts: { clientId: string | null },
): Promise<ConfirmSnapshotResolution> {
  if (isUsableConfirmSnapshot(line.pricingSnapshot)) {
    return { snapshot: line.pricingSnapshot, recomputed: false };
  }

  console.warn(
    `[sales.confirmSale] SaleLine ${line.id} sin pricingSnapshot válido — ` +
    `recalculando con motor. Probablemente fue creada antes de Fase 1.`,
  );

  // Misma regla anti doble redondeo que el DRAFT: si el tenant tiene política
  // doc activa, ignoramos el redondeo diferido de la lista al recomputar.
  const { suppressListDeferredRounding } = await loadDocumentRoundingConfig(jewelryId);

  const result = await resolveFinalSalePrice(jewelryId, {
    articleId: line.articleId,
    variantId: line.variantId ?? null,
    clientId:  opts.clientId ?? undefined,
    quantity:  parseFloat(line.quantity.toString()),
    suppressListDeferredRounding,
  });

  if (result.unitPrice == null) {
    // Último recurso: snapshot mínimo desde columnas. Nunca debería pasar en
    // producción si el DRAFT se creó correctamente.
    console.warn(
      `[sales.confirmSale] Motor no pudo recalcular precio para SaleLine ` +
      `${line.id}. Construyendo snapshot mínimo desde columnas legacy.`,
    );
    const colUnitPrice = parseFloat(line.unitPrice.toString());
    const colDiscPct   = parseFloat(line.discountPct.toString());
    const colBase      = colDiscPct > 0
      ? colUnitPrice / (1 - colDiscPct / 100)
      : colUnitPrice;
    return {
      snapshot: {
        unitPrice:            colUnitPrice,
        basePrice:            colBase,
        discountAmount:       Math.max(0, colBase - colUnitPrice),
        taxAmount:            0,
        totalWithTax:         null,
        priceSource:          line.priceSource || "NONE",
        baseSource:           line.priceSource || "NONE",
        unitCost:             null,
        unitMargin:           null,
        marginPercent:        null,
        costPartial:          true,
        costMode:             "NONE",
        partial:              true,
        appliedPriceListId:   line.appliedPriceListId,
        appliedPriceListName: null,
        appliedPromotionId:   line.appliedPromotionId,
        appliedPromotionName: null,
        appliedDiscountId:    line.appliedDiscountId,
        resolvedAt:           new Date().toISOString(),
      },
      recomputed: true,
    };
  }

  // F17 — para snapshots recomputados en confirm (legacy fallback), también
  // resolvemos costBase/costTaxAmount/costWithTax/costTaxBreakdown para que
  // el snapshot v7 quede consistente.
  const recomputeCostTax = await computePurchaseTaxes(
    jewelryId,
    line.articleId,
    result.unitCost ?? null,
  );
  return {
    snapshot: buildPricingSnapshot(result, { purchaseTaxes: recomputeCostTax }),
    recomputed: true,
  };
}

// ─── Sale Preview ─────────────────────────────────────────────────────────────
// Resuelve precios + checkout sin persistir nada.
// Fuente única de verdad para el total en Ventas.

export type SalePreviewLineInput = {
  /**
   * Tipo de línea. Default: ARTICLE (comportamiento histórico).
   *   · ARTICLE: línea con artículo del catálogo. Requiere `articleId`.
   *   · MANUAL: línea de descripción libre (texto del operador). NO usa
   *     pricing-engine, NO accede al artículo, NO aplica lista/promo/qty.
   *     Solo aplica `manualPriceOverride` (= unitPrice), `manualDiscountOverride`
   *     y `taxOverride` con la misma lógica de % o $ que el motor.
   */
  type?: "ARTICLE" | "MANUAL";
  /** Descripción de la línea. Obligatoria si `type === "MANUAL"`. */
  description?: string;
  /** Id del artículo del catálogo. Obligatorio si `type === "ARTICLE"` (default). */
  articleId?: string;
  variantId?: string | null;
  quantity: number;
  /** Override manual de precio neto unitario (Fase post-6). Si se setea,
   *  el motor usa este valor en lugar de resolver lista/promo/qty discount.
   *  Se traslada directamente a `SalePriceOpts.manualPriceOverride`. */
  manualPriceOverride?: number | null;
  /** Override manual del ajuste comercial por línea (bonif / recargo).
   *  `kind` es opcional: ausente = BONUS (back-compat); SURCHARGE suma. */
  manualDiscountOverride?: {
    mode:      "PERCENT" | "AMOUNT";
    value:     number;
    kind?:     "BONUS" | "SURCHARGE";
    appliesTo?: "TOTAL" | "METAL" | "HECHURA" | "METAL_Y_HECHURA" | "SUBTOTAL_AFTER_DISCOUNT" | "SUBTOTAL_BEFORE_DISCOUNT" | "PRODUCT" | "SERVICE";
  } | null;
  /** Override manual de impuesto por línea. Reemplaza el tax automático. */
  taxOverride?: {
    mode:      "PERCENT" | "AMOUNT";
    value:     number;
    appliesTo?: "TOTAL" | "METAL" | "HECHURA" | "METAL_Y_HECHURA" | "SUBTOTAL_AFTER_DISCOUNT" | "SUBTOTAL_BEFORE_DISCOUNT" | "PRODUCT" | "SERVICE";
  } | null;
  /** Override de SOLO la base ("Aplica a") del descuento heredado del
   *  cliente, independiente del valor. Ver `SalePriceOpts.discountAppliesToOverride`. */
  manualDiscountAppliesToOverride?: "TOTAL" | "METAL" | "HECHURA" | "METAL_Y_HECHURA" | "SUBTOTAL_AFTER_DISCOUNT" | "SUBTOTAL_BEFORE_DISCOUNT" | "PRODUCT" | "SERVICE" | null;
  /** Override de SOLO la base ("Aplica a") del impuesto heredado,
   *  independiente del valor. Ver `SalePriceOpts.taxAppliesToOverride`. */
  manualTaxAppliesToOverride?: "TOTAL" | "METAL" | "HECHURA" | "METAL_Y_HECHURA" | "SUBTOTAL_AFTER_DISCOUNT" | "SUBTOTAL_BEFORE_DISCOUNT" | "PRODUCT" | "SERVICE" | null;
  /** Fase 2A.7 — override de lista de precios a nivel línea. Tiene
   *  precedencia sobre el `priceListId` doc-level. Si ambos vienen vacíos,
   *  el motor resuelve por jerarquía cliente → categoría → favorita. */
  priceListIdOverride?: string | null;
  // ── Fase 3B — overrides de COMPOSICIÓN DE COSTO por línea ───────────────
  // Aplican solo a esta línea (motor trabaja sobre copia en memoria); no
  // modifican la ficha del artículo. El motor ya soporta los 4 desde
  // `SalePriceOpts`; este endpoint los expone para que el frontend los
  // mande directamente sin pasar por `articles/pricing-preview` por línea.
  /** Pisa los gramos de la línea METAL del artículo. */
  gramsOverride?: number | null;
  /** Pisa el % de merma aplicado sobre el metal. */
  mermaPercentOverride?: number | null;
  /** Pisa el `metalVariantId` (cambia la cotización del metal usado). */
  metalVariantIdOverride?: string | null;
  /** Pisa el monto unitario de la línea HECHURA. */
  hechuraOverrideAmount?: number | null;
  /**
   * F1.4 G5 #11-A — overrides per costLineId.
   *
   * Array indexado por `costLineId`. Pisa los overrides legacy cuando
   * hay match (ver `unifyCostLineOverrides`). Permite editar quantity,
   * unitValue, mermaPercent y adjustment de cost lines individuales sin
   * tocar la ficha del artículo.
   *
   * Validaciones (delegadas al motor — `validateCostLineOverride`):
   *   · `costLineId` desconocido → ignorado + debugWarning.
   *   · type mismatch / campos no aplicables → idem.
   *
   * Pase 100% transparente: el controller no valida — el motor sí.
   */
  costLineOverrides?: CostLineOverride[];
};

export type SalePreviewInput = {
  lines: SalePreviewLineInput[];
  clientId?: string | null;
  paymentMethodId?: string | null;
  installmentsQty?: number;
  channelId?: string | null;
  couponCode?: string | null;
  /** Costo de envío del documento (Fase 4 — viene del frontend YA RESUELTO).
   *  Sprint 3: deprecado en favor de `shipping` crudo. Sigue funcionando
   *  como fallback hasta que todos los clientes migren. */
  shippingAmount?: number;
  /** Sprint 3 — input crudo del envío. Si viene, prevalece sobre
   *  `shippingAmount` y el backend resuelve el monto vía
   *  `resolveShippingAmount` (capa 10 del orden inmutable). POLICY.md §5. */
  shipping?: {
    mode:    "FIXED" | "BY_WEIGHT" | "FREE";
    value?:  number | null;
    weight?: number | null;
  } | null;
  /** Descuento global del documento (Fase 4 — viene del frontend, ya
   *  resuelto a monto). Si se pasa `globalDiscount` (objeto), tiene
   *  prioridad y `globalDiscountAmount` se ignora. */
  globalDiscountAmount?: number;
  /** Descuento global del documento sin resolver (Fase 5). El backend
   *  computa el monto contra el subtotal post-descuentos de línea, lo que
   *  evita un feedback loop frontend↔backend cuando el frontend usaba el
   *  subtotal local para resolver el % a monto. */
  globalDiscount?: { type: "PERCENT" | "AMOUNT"; value: number } | null;
  /** Fase 2A.7 — override de lista de precios a nivel documento.
   *  Aplica a todas las líneas que no tengan su propio `priceListIdOverride`. */
  priceListId?: string | null;
  /** Fase MM — moneda en la que se quiere ver el response. Si es null o
   *  coincide con la base, no hay conversión. SOLO afecta el PREVIEW;
   *  `confirmSale` ignora este campo y persiste en moneda base. */
  currencyId?: string | null;
  /** Fase MM ext — cotización manual aplicada en el documento (`draft.fxRate`
   *  del frontend). Cuando viene válida, reemplaza la tasa vigente del
   *  catálogo `CurrencyRate` para la conversión del response. Si no viene,
   *  se usa la última tasa registrada. SOLO afecta el preview. */
  currencyRate?: number | null;
  /** Fase 3B.5 — override manual del Balance Mode del documento
   *  (POLICY.md §11 R11.4). Si viene null o ausente, el backend resuelve
   *  por jerarquía (cliente → lista → tenant). El frontend NO resuelve. */
  balanceModeOverride?: "UNIFIED" | "BREAKDOWN" | null;
  /** Manual Adjustment Etapa 1 — override comercial humano sobre el
   *  `engineTotal`. Capa 17 del pipeline (POLICY §R-Rounding-1).
   *  Etapa 1: solo scope=UNIFIED global del documento.
   *  Backend NO recalcula motor — solo aplica el delta post-rounding. */
  manualAdjustment?: import("../../lib/manual-adjustment/index.js").ManualAdjustmentInput | null;
};

/**
 * Subset serializable de `PricingStep` que viaja al frontend por línea.
 * Solo se exponen los steps relevantes para el pipeline de descuentos (ver
 * whitelist en el mapper). Los campos de `meta` son los útiles para el
 * render del timeline; el motor expone más cosas internamente pero no
 * necesitamos exponerlas todas. */
export type SalePreviewStep = {
  key:     string;
  label:   string;
  status:  "ok" | "partial" | "missing" | "skipped";
  /** Valor resultante per-unidad post-step (precio neto, no precio×qty). */
  value:   number | null;
  message?: string;
  meta?: {
    discountBase?:           number | null;
    discountAmount?:         number | null;
    discountBaseEstimated?:  boolean;
    surchargeBase?:          number | null;
    surchargeAmount?:        number | null;
    surchargeBaseEstimated?: boolean;
    /** Valor configurado de la rule (% o monto fijo según `type`/`valueType`). */
    value?:     number | null;
    type?:      "PERCENTAGE" | "FIXED_AMOUNT" | null;
    valueType?: "PERCENTAGE" | "FIXED_AMOUNT" | null;
    applyOn?:   string | null;
    ruleType?:  "DISCOUNT" | "BONUS" | "SURCHARGE" | null;
    kind?:      "BONUS" | "SURCHARGE" | null;
    mode?:      "PERCENT" | "FIXED" | null;
    promoId?:    string | null;
    discountId?: string | null;
    promoName?:  string | null;
  };
};

/**
 * Línea resuelta del preview. Fase 5: el frontend ya no necesita llamar a
 * `articlesApi.getPricingPreview` por línea — todos los datos para renderizar
 * la línea (precio, impuestos, costo, margen, descuentos detallados,
 * snapshot, metal/hechura) salen de acá.
 */
export type SalePreviewLine = {
  // ── Identidad ────────────────────────────────────────────────────────────
  articleId:            string;
  variantId:            string | null;
  quantity:             number;

  // ── Precio (Fase 4: incluye basePrice y los totales por línea) ───────────
  unitPrice:            number | null;
  basePrice:            number | null;     // precio de lista pre-descuento
  lineSubtotal:         number | null;     // alias de lineTotal — preservado por compat
  lineTotal:            number | null;     // qty × unitPrice (rounded)
  lineDiscount:         number;            // (basePrice − unitPrice) × qty
  unitTaxAmount:        number;            // impuesto unitario (Fase 4)
  /** Sprint 3 — unitario CON impuestos = unitPrice + unitTaxAmount. Permite
   *  al frontend mostrar el unitario con tax sin recalcular. POLICY.md §4 R4.3. */
  unitTotalWithTax:     number | null;
  lineTaxAmount:        number;            // qty × unitTaxAmount
  lineTotalWithTax:     number | null;     // lineTotal + lineTaxAmount

  // ── FASE 1.1 G7 — flags explícitos de overrides aplicados a la línea ───
  /** Subcampos: true si el operador overrideó ese aspecto.
   *  · quantity: siempre false — qty es input directo, no overrideable.
   *  · price:    line.manualPriceOverride != null
   *  · discount: line.manualDiscountOverride != null
   *  · tax:      line.taxOverride != null
   *  POLICY.md §3 R3.4 — distingue los 3 tipos en lugar de inferir desde
   *  priceSource="MANUAL_OVERRIDE" (que solo refleja el override de precio). */
  manualOverridesApplied: {
    quantity: boolean;
    price:    boolean;
    discount: boolean;
    tax:      boolean;
  };

  // ── Detalle de descuentos (Fase 5) ──────────────────────────────────────
  /** Descuento por cantidad por unidad, si aplicó. null si no. */
  quantityDiscountAmount:  number | null;
  /** Descuento de promoción por unidad, si aplicó. null si no. */
  promotionDiscountAmount: number | null;
  /** Sprint 3 — Descuento por regla de cliente (capa 5). Solo DISCOUNT/BONUS;
   *  no incluye qty, promo, surcharge ni manuales. null si no aplica.
   *  POLICY.md §8. */
  customerDiscountAmount:  number | null;

  // ── Metadata explicativa de cálculo POR LÍNEA (display-only).
  //    El motor calcula estos valores y los emite en `steps[].meta` con keys
  //    QUANTITY_DISCOUNT / PROMOTION / ENTITY_COMMERCIAL_RULE. Hasta ahora
  //    el mapper de venta NO los serializaba, lo que dejaba al frontend sin
  //    forma de mostrar "Cálculo: base × valor" sin recalcular. Estos campos
  //    son METADATA pura (no afectan el resultado del motor). POLICY.md
  //    R4.5 / R6 — frontend lector puro de datos del motor.
  /** Base sobre la que se aplicó el descuento por cantidad (per-línea). null
   *  cuando no hay descuento por cantidad o el motor no lo expuso. */
  quantityDiscountBase:      number | null;
  /** Valor configurado del descuento por cantidad (% o monto fijo según
   *  `quantityDiscountValueType`). null cuando no aplica. */
  quantityDiscountValue:     number | null;
  /** `"PERCENTAGE" | "FIXED_AMOUNT" | null` — distingue cómo se aplicó el
   *  descuento por cantidad. */
  quantityDiscountValueType: "PERCENTAGE" | "FIXED_AMOUNT" | null;
  /** Idem para promoción. */
  promotionDiscountBase:      number | null;
  promotionDiscountValue:     number | null;
  promotionDiscountValueType: "PERCENTAGE" | "FIXED_AMOUNT" | null;
  /** Base sobre la que se aplicó la regla del cliente (capa 5). null cuando
   *  no aplica o el motor no la expuso. El `value` y `valueType` ya viajan
   *  en `clientCommercialRules` (a nivel documento). */
  customerDiscountBase:       number | null;

  /**
   * Subset whitelist de `pricing.steps[]` que el motor emitió en orden real
   * de aplicación. Permite al frontend renderizar el "pipeline" de cálculo
   * (Base inicial → Desc. cantidad → Promo → Cliente → Manual) sin derivar
   * orden ni recalcular subtotales.
   *
   *   · Keys whitelisteados:
   *       PRICE_LIST / MANUAL_OVERRIDE / MANUAL_FALLBACK / MANUAL_PRICE_OVERRIDE
   *       → base inicial del pipeline.
   *       QUANTITY_DISCOUNT / PROMOTION / ENTITY_COMMERCIAL_RULE /
   *       MANUAL_DISCOUNT_OVERRIDE → pasos del pipeline.
   *   · `value` y `meta.discount*` son PER-UNIDAD. El frontend multiplica
   *     por qty.
   *   · POLICY R4.5 — passthrough estricto, no modifica el resultado del
   *     motor. */
  pricingSteps?: SalePreviewStep[];

  // ── Trazabilidad ─────────────────────────────────────────────────────────
  priceSource:          string;
  appliedPriceListId:   string | null;
  appliedPriceListName: string | null;
  /** Modo de la lista aplicada (METAL_HECHURA / MARGIN_TOTAL / etc.). */
  appliedPriceListMode?: string | null;
  appliedPromotionId:   string | null;
  appliedPromotionName: string | null;
  appliedDiscountId:    string | null;

  // ── Costo y margen (Fase 5: incluye margen para que la UI no calcule) ───
  unitCost:             number | null;
  unitMargin:           number | null;
  marginPercent:        number | null;
  /** Markup % sobre costo. Provisto por el motor para que el frontend no
   *  recalcule (POLICY R6 — frontend lector puro). Derivable de unitCost/
   *  unitMargin pero no se persiste en pricingSnapshot. Null si sin costo. */
  markupPercent:        number | null;
  costPartial:          boolean;
  costMode:             string;

  // ── Política ─────────────────────────────────────────────────────────────
  policy: {
    canConfirm:     boolean;
    blockingAlerts: string[];
  };

  // ── Alertas de negocio emitidas por el motor para esta línea (passthrough
  //    estricto). Incluye códigos como LOW_MARGIN (warning), LOSS_SALE
  //    (error), COST_UNRESOLVED (warning), PARTIAL_DATA (warning),
  //    ZERO_OR_NEGATIVE_PRICE (error). El frontend las usa para derivar el
  //    commercialLevel visual (`deriveCommercialLevel` en
  //    `tptech-frontend/src/lib/sales/commercialPolicy.ts`). POLICY R6 —
  //    el frontend es lector puro, no recalcula nada.
  alerts: PricingAlert[];

  // ── Impuestos (Fase 4: desglose por línea) ───────────────────────────────
  taxBreakdown:         any[];

  // ── Desglose Metal/Hechura (Fase 5) ─────────────────────────────────────
  /** Solo presente cuando la lista activa usa modo METAL_HECHURA y el costo
   *  resolvió metalCost + hechuraCost. Útil para la UI del editor de líneas. */
  metalHechuraBreakdown: SalePreviewLineMetalHechura | null;

  /** Desglose por componente con descuentos imputados. Mismo dominio que
   *  `metalHechuraBreakdown` pero con `base/adjustments/final` por
   *  componente. Permite que la UI muestre el card "Hechura" con sus
   *  descuentos sin reconstruirlos desde `steps[]`. */
  componentSaleBreakdown: ComponentSaleDetail | null;

  // ── Snapshot completo (Fase 5) ──────────────────────────────────────────
  /** Snapshot serializable equivalente al que el backend persistiría en
   *  SaleLine al crear el DRAFT. Le permite al frontend mostrar exactamente
   *  los mismos datos sin recalcular. */
  pricingSnapshot:      PricingLineSnapshot;

  // ── Redondeo aplicado por la lista de precios ───────────────────────────
  /** Metadata del redondeo aplicado a esta línea. Null si la lista no tenía
   *  redondeo activo o si el redondeo no movió el valor. La UI lo lee para
   *  mostrar "Redondeo por lista: …" sin tocar `pricingSnapshot.steps`. */
  appliedRounding: {
    source:        "PRICE_LIST";
    priceListId:   string | null;
    priceListName: string | null;
    /** "METAL" agregado para el redondeo COMERCIAL PHYSICAL (POLICY §R-Rounding-14).
     *  Cuando applyOn === "METAL", el sub-objeto `physical` lleva el snapshot
     *  canónico por metal padre (preGrams/postGrams/deltaGrams/monetaryEquivalent). */
    applyOn:       "PRICE" | "NET" | "TOTAL" | "METAL";
    mode:          string;
    direction:     string;
    preRounding:   number;     // valor por unidad antes del redondeo
    postRounding:  number;     // valor por unidad después del redondeo
    unitAdjustment: number;    // postRounding − preRounding (per unit)
    /** Solo cuando applyOn === "METAL" — snapshot del redondeo físico por
     *  metal padre. Passthrough del helper `applyCommercialPhysicalRoundingForMetals`. */
    physical?: import("../../lib/commercial-physical-rounding-apply.js").CommercialPhysicalRoundingSnapshot | null;
  } | null;

  // ── Fase 2A.7 — paridad con `articles/pricing-preview` ──────────────────
  /** Bloque metal/hechura/taxes — mismo shape que devuelve el endpoint del
   *  Simulador. Armado por el helper `buildComposition`. */
  composition?: ReturnType<typeof import("../../lib/pricing-composition.js").buildComposition>;
  /** Merma efectivamente aplicada por el motor (de override de entidad o
   *  default del artículo). Atajo de `composition.metal.appliedMermaPct`. */
  appliedMermaPercent?: number | null;
  /** Costo de compra (sin/con/breakdown) — `computePurchaseTaxes`. */
  costBase?:         string | null;
  costTaxAmount?:    string | null;
  costWithTax?:      string | null;
  costTaxBreakdown?: PurchaseTaxBreakdownItem[];
  /** Eco del `priceListIdOverride` recibido en el input para esta línea
   *  (luego de aplicar precedencia: línea > documento). `null` si no se
   *  envió ningún override (motor resolvió por jerarquía). */
  priceListIdOverride?: string | null;

  // ── Etapa D' — Contexto del Redondeo Comercial (CIERRE CONCEPTUAL) ──────
  /** **Vista** del Redondeo Comercial del comprobante para visualización
   *  dentro del card del artículo. Mismo objeto que
   *  `documentTotals.commercialDocumentRoundingApplied` (única fuente
   *  backend), enriquecido con `appliedAt` + `appliedToLineCount`.
   *
   *  IMPORTANTE — naturaleza del campo:
   *    · NO representa un redondeo propio de esta línea.
   *    · NO implica que el cálculo se haya ejecutado sobre esta línea.
   *    · Es una replicación visual: el snapshot del documento se copia
   *      a cada `lines[i]` para que el card de artículo pueda mostrarlo
   *      como cierre de su cadena comercial sin tener que mirar el
   *      response del documento entero.
   *    · El cálculo SIEMPRE se hace a nivel comprobante en
   *      `computeSaleDocumentTotals` (cuando `commercialRoundingScope =
   *      PER_DOCUMENT`). Por eso `appliedAt` SIEMPRE vale `"DOCUMENT"`
   *      en este campo.
   *
   *  Cuando es `null`: la lista del documento opera en PER_LINE_LEGACY o
   *  mixed-list (NO_SHARED_LIST). El card de artículo NO muestra el bloque
   *  PER_DOCUMENT — el redondeo legacy vive en `metalHechuraBreakdown` y
   *  se renderiza por su path histórico.
   *
   *  REGLA DE ORO PERMANENTE:
   *    Si un valor necesario no existe en este snapshot:
   *      · NO calcularlo en frontend.
   *      · NO inferirlo.
   *      · NO reconstruirlo.
   *    El fix correcto es agregarlo al snapshot backend. */
  commercialRoundingContext?: import("../../lib/pricing-engine/pricing-engine.js").CommercialRoundingApplied
    & {
      appliedAt:          "DOCUMENT";
      appliedToLineCount: number;
    }
    | null;

  /** Opción δ (R-COMMERCIAL-METAL-VISIBLE) — Impacto monetario del Redondeo
   *  Comercial PER_DOCUMENT atribuido a ESTA línea, distribuido proporcionalmente
   *  a la fracción de gramos puros que la línea aporta al(los) metal(es) padre
   *  redondeado(s).
   *
   *  Permite al frontend computar el "Metal Visible" del Resumen Comercial
   *  como `metalSale × qty + metalRoundingMonetaryImpact`, garantizando que:
   *
   *    Σ líneas metalRoundingMonetaryImpact === Σ snapshot.breakdown.metals[*].monetaryEquivalent
   *    Metal Visible[i] + Hechura[i] === Total línea c/ imp.[i]
   *
   *  Backend SSOT: el frontend NO recalcula. Cero matemática FE — pura suma
   *  de dos números pre-emitidos por el motor.
   *
   *  `null` cuando: no hay snapshot D' (PER_LINE_LEGACY / mixed-list), no
   *  hubo delta de redondeo (combinedAdjustment=0), o la línea no aporta a
   *  ningún metal redondeado. */
  metalRoundingMonetaryImpact?: number | null;

  /** Opción A — Impacto monetario del Redondeo Comercial PER_DOCUMENT atribuido
   *  al bucket HECHURA / MONETARIO de ESTA línea, distribuido proporcionalmente
   *  a `hechuraSale × qty` que la línea aporta al documento.
   *
   *  Espejo de `metalRoundingMonetaryImpact` para el dominio monetario.
   *  Conservación: Σ líneas hechuraRoundingMonetaryImpact ===
   *  snapshot.breakdown.hechura.deltaSaldoMonetario. `null` igual que el de metal. */
  hechuraRoundingMonetaryImpact?: number | null;

  /** Opción A — TOTAL LÍNEA C/ IMP. POST-redondeo comercial. Campo de DISPLAY
   *  dedicado:
   *    = lineTotalWithTax + metalRoundingMonetaryImpact + hechuraRoundingMonetaryImpact
   *
   *  NO se usa como autoridad del total del documento (eso lo computa
   *  `computeSaleDocumentTotals` desde `lineTotal`); existe para que el frontend
   *  muestre el cierre comercial de la línea cumpliendo por construcción:
   *    METAL Comercial post + MONETARIO Comercial post = TOTAL LÍNEA post.
   *
   *  `lineTotalWithTax` (sin sufijo) permanece PRE-redondeo comercial — es el
   *  que el motor suma para el total del documento (anti doble conteo). Cuando
   *  no hay Redondeo Comercial PER_DOCUMENT, el post === pre. */
  lineTotalWithTaxPostCommercialRounding?: number | null;

  /** Opción A (descomposición FÍSICA) — SALDO MONETARIO POST-redondeo comercial
   *  atribuido a esta línea (porción de breakdown.hechura.postRoundingSaldoMonetario,
   *  = total menos valor físico del metal, redondeado). Es el valor que el bloque
   *  MONETARIO del Resumen Comercial muestra en modo DESGLOSADO (ej. 185.500).
   *  `null` cuando el snapshot no trae el bucket hechura. */
  lineMonetarySaldoPostCommercialRounding?: number | null;

  /** Saldo monetario PRE redondeo comercial de la línea (= lineTotalWithTax −
   *  Σ metalSale). Es el "AR$ 185.475,21 →" que el card muestra antes de la
   *  flecha. Line-autonomous (no cambia al agregar otras líneas). `null` sin
   *  Redondeo Comercial PER_DOCUMENT BREAKDOWN. */
  lineMonetarySaldoPreCommercialRounding?: number | null;

  /** Gramos comerciales POST-redondeo POR LÍNEA y metal padre, calculados con
   *  el `gramsPure` y el margen de ESTA línea (immune a otras líneas). Es la
   *  fuente que el Resumen Comercial del Artículo (card) usa para los gramos
   *  del metal — reemplaza la lectura del agregado del documento
   *  (`commercialRoundingContext.breakdown.metalsPostGrams`) que acumulaba al
   *  sumar varias líneas del mismo metal. Display-only (sin dinero). `null`
   *  cuando no hay Redondeo Comercial PER_DOCUMENT en modo BREAKDOWN. */
  lineCommercialRoundingMetals?: LineCommercialRoundingMetal[] | null;
};

/** Etapa C-comercial / C4-fix — entry per metal padre del snapshot
 *  comercial PHYSICAL. Shape EXACTO de `CommercialPhysicalRoundingSnapshotEntry`
 *  (`tptech-backend/src/lib/commercial-physical-rounding-apply.ts`). Lo
 *  redeclaramos acá inline (sin import al barrel del motor) para que el DTO
 *  del preview sea autocontenido. */
export type SalePreviewLineCommercialPhysicalEntry = {
  metalParentId:      string | null;
  metalParentName:    string;
  preGrams:           number;
  postGrams:          number;
  deltaGrams:         number;
  metalPricePerGram:  number;
  monetaryEquivalent: number;
  mode:               string;
  direction:          string;
  source:             "COMMERCIAL_PHYSICAL_ROUNDING";
  fallback:           null | "NO_METAL_PRICE" | "NO_CONFIG" | "INVALID_GRAMS";
};

export type SalePreviewLineCommercialPhysicalSnapshot = {
  metals:                  SalePreviewLineCommercialPhysicalEntry[];
  metalMonetaryEquivalent: number;
  fallback:                null | "NO_BREAKDOWN_DATA" | "NO_METALS_TO_ROUND";
};

export type SalePreviewLineMetalHechura = {
  metalCost:         number;
  metalSale:         number;
  metalMarginPct:    number;
  hechuraCost:       number;
  hechuraSale:       number;
  hechuraMarginPct:  number;
  metalGramsBase:    number | null;
  metalGramsSale:    number | null;
  metalPricePerGram: number | null;
  // ── Etapa C-comercial / C4-fix (POLICY §R-Rounding-14) ──────────────────
  // Auditoría del redondeo comercial (válida para los dos dominios). Los
  // 4 campos `*PreRounding` / `*RoundingDelta` quedan `null` cuando NO actuó
  // el redondeo (passthrough) — solo viajan cuando hay delta.
  metalSalePreRounding?:    number | null;
  hechuraSalePreRounding?:  number | null;
  metalSaleRoundingDelta?:  number | null;
  hechuraSaleRoundingDelta?:number | null;
  /** Snapshot completo del redondeo COMERCIAL PHYSICAL — paralelo al
   *  `documentRoundingApplied.breakdown.metalPhysical` del financiero.
   *  Solo presente cuando la lista operó en
   *  `commercialRoundingMetalDomain="PHYSICAL"` y había `metalsByParent`
   *  válidos. `null` en MONETARY (legacy). */
  physical?:                SalePreviewLineCommercialPhysicalSnapshot | null;
};

/** Fase 2A.7 — campos del cliente que el preview ahora expone para que el
 *  frontend no tenga que hacer una llamada paralela a `/commercial-entities/:id`
 *  para mostrar reglas comerciales o balanceType. */
export type SalePreviewClientCommercialRules = {
  ruleType:   string | null;
  valueType:  string | null;
  value:      number | null;
  applyOn:    string | null;
};

export type SalePreviewResult = {
  lines:          SalePreviewLine[];
  /** Σ lineTotal — alias de `documentTotals.subtotalAfterLineDiscounts`. */
  subtotal:       number;
  channelResult:  ChannelAdjustmentResult | null;
  couponResult:   CouponAdjustmentResult | null;
  checkoutResult: CheckoutResult | null;
  /** Total final con impuestos. Fase 4: ahora incluye taxes (antes era post
   *  canal/cupón/pago SIN impuestos). */
  total:          number;
  /** Fase 4: totales del documento de la misma fuente que `confirmSale`. */
  documentTotals: SaleDocumentTotals;

  // ── Fase 2A.7 — info doc-level ─────────────────────────────────────────
  /** Tipo de saldo del cliente (UNIFIED / BREAKDOWN). null si no hay cliente. */
  clientBalanceType?:    string | null;
  /** Reglas comerciales del cliente (descuentos/recargos automáticos). */
  clientCommercialRules?: SalePreviewClientCommercialRules | null;
  /**
   * true si el cliente está marcado exento de impuestos (`CommercialEntity
   * .taxExempt`). Metadata READ-ONLY: lo expone para que el frontend pueda
   * distinguir "sin impuesto" de "exento por cliente". NO recalcula nada
   * (el motor ya aplicó la exención por `clientId`). null/false si no hay
   * cliente o no es exento. */
  clientTaxExempt?: boolean;
  /** Eco de `input.priceListId` (lo que el operador eligió a nivel doc). */
  requestedPriceListId?: string | null;
  /** Lista efectivamente aplicada consolidada a nivel documento. Si todas
   *  las líneas usaron la misma → ese id. Si difieren → "MIXED". null si
   *  no hubo lista resuelta (precio manual o sin datos). */
  appliedPriceListId?:   string | null;
  /** Nombre de la lista consolidada. "Múltiples" cuando es "MIXED". */
  appliedPriceListName?: string | null;
  /** true cuando se envió `requestedPriceListId` (o cualquier
   *  `priceListIdOverride` por línea) — independientemente de si el motor
   *  pudo respetarlo. */
  priceListWasOverridden?: boolean;

  // ── Fase 3B.5 — Balance Mode (POLICY.md §11) ───────────────────────────
  /** Modo de balance resuelto en este preview (UNIFIED / BREAKDOWN). El
   *  backend resuelve siempre; el frontend es read-only. */
  balanceMode?: "UNIFIED" | "BREAKDOWN";
  /** De dónde salió el modo: DOCUMENT_OVERRIDE / ENTITY_DEFAULT /
   *  PRICELIST_DEFAULT / TENANT_DEFAULT / FALLBACK_UNIFIED. Auditoría. */
  balanceModeSource?: string;
  /** Breakdown canónico del documento (metals + monetaryBalance). En UNIFIED,
   *  metals=[] y monetary.amount=total. */
  balanceBreakdown?: DocumentBalanceBreakdown;

  // ── Etapa 1.1 (estabilización) — campos canónicos top-level ─────────────
  // Hasta esta etapa, estos 4 campos vivían pegados al responsePayload con
  // cast `as any` (engineTotal/finalTotal/manualAdjustment) o enterrados en
  // `documentTotals.documentRoundingApplied` (documentRoundingSnapshot). El
  // frontend los leía con `(res as any).…` y un cualquier rename rompía sin
  // error de TS. Esta declaración los hace contractuales.
  //
  // Paridad de naming con persistencia en `Sale`:
  //   responsePayload.engineTotal              ↔ Sale.engineTotal
  //   responsePayload.finalTotal               ↔ Sale.total (clamp ≥ 0)
  //   responsePayload.manualAdjustmentSnapshot ↔ Sale.manualAdjustmentSnapshot
  //   responsePayload.documentRoundingSnapshot ↔ Sale.documentRoundingSnapshot
  //
  /** Total del motor INMEDIATAMENTE post-rounding y PRE ajuste manual.
   *  POLICY §R-Rounding-6. Auditoría: cuando hay ajuste, `total` diverge
   *  de `engineTotal` por el delta del snapshot manual. */
  engineTotal?: number;
  /** Total final = engineTotal + manualAdjustmentSnapshot.totals.totalMonetaryAdjustment
   *  (clamp ≥ 0). POLICY §R-Rounding-1. PDF / mail / cuenta corriente leen
   *  `Sale.total` que coincide con este `finalTotal`. */
  finalTotal?: number;
  /** Snapshot inmutable del ajuste manual del operador (UNIFIED o BREAKDOWN).
   *  null cuando no hubo ajuste. Mismo shape que se persiste en
   *  `Sale.manualAdjustmentSnapshot` al confirmar. */
  manualAdjustmentSnapshot?: ManualAdjustmentPreview["snapshot"] | null;
  /** @deprecated Usar `manualAdjustmentSnapshot`. Alias mantenido durante la
   *  migración del frontend (consumers existentes leen `result.manualAdjustment`
   *  con cast `as any`). Es la MISMA referencia que `manualAdjustmentSnapshot`
   *  — el converter de moneda lo conoce solo por este nombre y muta in-place. */
  manualAdjustment?: ManualAdjustmentPreview["snapshot"] | null;
  /** Snapshot del redondeo automático del documento (Etapa 1B + capa 16
   *  PHYSICAL). Mismo shape que se persiste en `Sale.documentRoundingSnapshot`
   *  al confirmar. Es la MISMA referencia que `documentTotals.documentRoundingApplied`
   *  — el converter de moneda lo muta in-place vía ese path. */
  documentRoundingSnapshot?: SaleDocumentTotals["documentRoundingApplied"] | null;
};

export async function previewSale(
  jewelryId: string,
  input: SalePreviewInput,
): Promise<SalePreviewResult> {
  // pricing-trace wrapper. Cuando PRICING_TRACE=off, runWithTrace ejecuta
  // `_previewSaleImpl` directamente sin overhead. Cuando está activo, captura
  // las 15 capas y (opcional) adjunta `_diagnostics` al payload de respuesta.
  const { result, trace } = await runWithTrace(
    `previewSale jewelry=${jewelryId} lines=${input.lines?.length ?? 0}`,
    () => _previewSaleImpl(jewelryId, input),
  );
  if (trace && (resolvePricingTraceMode() === "response" || resolvePricingTraceMode() === "both")) {
    (result as any)._diagnostics = {
      pricingTrace: trace,
    };
  }
  return result;
}

async function _previewSaleImpl(
  jewelryId: string,
  input: SalePreviewInput,
): Promise<SalePreviewResult> {
  const { lines, clientId, paymentMethodId, installmentsQty = 0 } = input;

  // ── Multimoneda (Fase MM) — contexto resuelto AL INICIO ─────────────────
  // El motor trabaja 100% en moneda BASE. El operador tipea los montos
  // (precio/bonif./impuesto/global/envío manuales) en la moneda del
  // documento (display). Convertimos esos INPUTS display→base ACÁ, antes
  // de que el motor los consuma, y al final convertimos el RESPONSE
  // base→display (simetría). Sin esto, una bonif. AMOUNT de "20" (USD) se
  // aplicaba como "20" base (ARS) y volvía como ~US$0,01.
  // `confirmSale` NO pasa por acá (persiste en base) → sin doble conversión.
  const currencyCtx = await getCurrencyDisplayContext(
    jewelryId,
    input.currencyId   ?? null,
    input.currencyRate ?? null,
  );
  if (currencyCtx?.applied) {
    // Mutación in-place de `input` ANTES de cualquier lectura del motor.
    // `lines` (destructurado arriba) es la MISMA referencia → ve los
    // valores ya convertidos. Solo AMOUNT/montos; PERCENT no se toca.
    convertSalesPreviewInputInPlace(input, currencyCtx.rate);
  }

  // ── Política de redondeo a nivel comprobante (UNIFIED) ──────────────────
  // Se carga una sola vez al inicio del preview y se reutiliza para todas
  // las llamadas a resolveFinalSalePrice y para computeSaleDocumentTotals.
  const docRoundingPolicy = await loadDocumentRoundingConfig(jewelryId);

  // ── Etapa D' — Contexto comercial PER_DOCUMENT ──────────────────────────
  // Pre-resuelve la lista activa del documento (si hay una compartida) y
  // decide si vamos PER_LINE_LEGACY (back-compat) o PER_DOCUMENT (capa nueva).
  // Mientras no haya schema, el modo se activa por env
  // PRICING_COMMERCIAL_DOC_ROUNDING_ENABLED=1 (sin tocar comportamiento
  // productivo). Cuando esté el schema, se lee de la lista activa.
  const commercialDocCtx = await resolveDocumentCommercialContextForSale({
    jewelryId,
    lineInputs:             lines,
    defaultPriceListIdInput: input.priceListId ?? null,
  });
  // Fail-fast: si el contexto resultó inconsistente (flags+capa desincronizados
  // → DOBLE redondeo), lanza error explícito antes de tocar nada.
  assertCommercialDocRoundingConsistency(commercialDocCtx);
  traceDocument("L00_DOC_COMMERCIAL_CONTEXT", {
    mode:                              commercialDocCtx.mode,
    documentActivePriceList:           commercialDocCtx.documentActivePriceList,
    suppressLineHechuraRounding:       commercialDocCtx.applyPriceListOptions.suppressLineHechuraRounding       === true,
    suppressLineMetalPhysicalRounding: commercialDocCtx.applyPriceListOptions.suppressLineMetalPhysicalRounding === true,
    fallback:                          commercialDocCtx.fallback,
    commercialDocumentRoundingActive:  commercialDocCtx.commercialDocumentRounding != null,
    commercialDocumentRoundingScope:   commercialDocCtx.commercialDocumentRounding?.scope ?? null,
  });

  // ── Precarga: meta + cost composition + manualTax IDs ───────────────────
  // Fase 4: para que previewSale tenga paridad con confirmSale, necesita el
  // mismo material que confirmSale tiene del artículo: composición de costo
  // (para `calculateCostFromLines`), `manualTaxIds` (para `computeLineTaxes`)
  // y los `manualAdjustment*`. Antes previewSale solo cargaba categoryId/brand.
  // Líneas MANUAL no tienen articleId → quedan fuera de esta precarga; se
  // resuelven más abajo en una rama dedicada (sin pricing-engine).
  const articleIds = [...new Set(
    lines
      .filter((l) => l.type !== "MANUAL" && !!l.articleId)
      .map((l) => l.articleId as string),
  )];
  const articleData = articleIds.length > 0
    ? await prisma.article.findMany({
        where: { id: { in: articleIds }, jewelryId, deletedAt: null },
        select: {
          id: true,
          categoryId: true,
          brand: true,
          mermaPercent: true,
          manualTaxIds: true,
          manualAdjustmentKind:  true,
          manualAdjustmentType:  true,
          manualAdjustmentValue: true,
          category: { select: { mermaPercent: true } },
          costComposition: {
            select: {
              // F1.3 G4.1.2 — `id` necesario para que step.meta.costLineId
              // se propague (trazabilidad estable, snapshot-safe).
              id: true,
              type: true, label: true, quantity: true, quantityUnit: true, unitValue: true, currencyId: true,
              mermaPercent: true, metalVariantId: true, lineAdjKind: true, lineAdjType: true, lineAdjValue: true,
              catalogItemId: true, affectsStock: true,
            },
          },
        },
      })
    : [];
  const articleMap = new Map(articleData.map(a => [a.id, a]));

  // F1.3 G4.1.4 — pre-carga GLOBAL del catalog info (code/name) para los
  // PRODUCT/SERVICE referenciados en TODAS las líneas del documento.
  // Una sola query batch (Set dedupe global), failure-safe (si falla,
  // los items usan fallback meta.lineCode/lineLabel — no rompe preview).
  // Se ejecuta acá (post articleData, pre engine loop) para reutilizar
  // los costComposition ya cargados sin extra fetch.
  const catalogItemsMap = await buildCatalogItemsMapForCostLines(
    jewelryId,
    articleData.map(a => a.costComposition ?? []),
  );

  // Cliente: tax overrides + reglas comerciales + balanceType (Fase 2A.7).
  // El select se extendió para que el preview exponga balanceType y reglas
  // sin que el frontend tenga que pegarle a /commercial-entities/:id.
  const clientRow = clientId
    ? await prisma.commercialEntity.findFirst({
        where: { id: clientId, jewelryId, deletedAt: null },
        select: {
          taxExempt: true,
          taxApplyOnOverride: true,
          taxOverrides: {
            where: { isActive: true },
            select: { taxId: true, overrideMode: true, applyOn: true, isActive: true },
          },
          // Fase 2A.7
          balanceType:         true,
          // Fase 3B.5 — Balance Mode canónico (nuevo campo del schema 3B.4).
          // Tiene prioridad sobre `balanceType` legacy via mapBalanceTypeToMode.
          balanceMode:         true,
          commercialRuleType:  true,
          commercialValueType: true,
          commercialValue:     true,
          commercialApplyOn:   true,
        },
      })
    : null;
  const clientTaxExempt          = clientRow?.taxExempt ?? false;
  const clientTaxApplyOnOverride = clientRow?.taxApplyOnOverride ?? null;
  const clientTaxOverrides       = clientRow?.taxOverrides ?? null;

  // groupId vive en ArticleGroupItem — para QuantityDiscount con scope GROUP
  const variantIds = lines.map(l => l.variantId).filter(Boolean) as string[];
  const variantGroupItems = variantIds.length > 0
    ? await prisma.articleGroupItem.findMany({
        where: { variantId: { in: variantIds }, itemType: "VARIANT" },
        select: { variantId: true, groupId: true },
      })
    : [];
  const variantGroupMap = new Map(variantGroupItems.map(i => [i.variantId!, i.groupId]));

  const categoryTotals = new Map<string, number>();
  const brandTotals    = new Map<string, number>();
  const groupTotals    = new Map<string, number>();
  for (const line of lines) {
    if (!line.articleId) continue;          // líneas MANUAL no aportan totales
    const m       = articleMap.get(line.articleId);
    const groupId = line.variantId ? variantGroupMap.get(line.variantId) : undefined;
    if (!m) continue;
    if (m.categoryId) categoryTotals.set(m.categoryId, (categoryTotals.get(m.categoryId) ?? 0) + line.quantity);
    if (m.brand)      brandTotals.set(m.brand,          (brandTotals.get(m.brand)          ?? 0) + line.quantity);
    if (groupId)      groupTotals.set(groupId,           (groupTotals.get(groupId)           ?? 0) + line.quantity);
  }

  // Batch cost context (evita N+1 en calculateCostFromLines)
  const batchCostCtx: BatchCostContext = await buildBatchCostContext(
    jewelryId,
    articleData as ArticleCostInput[],
  );

  // T55 (Fase 3B.5) — Captura del `costBreakdown` por índice de línea para
  // alimentar `buildSaleBalanceBreakdown` después de `computeSaleDocumentTotals`,
  // sin recomputar el motor de costo y sin contaminar el shape público de
  // `SalePreviewLine`. Cada línea ARTICLE lo escribe acá adentro del map.
  const lineCostBreakdownsByIdx: Map<number, any> = new Map();

  // Opción A (fix balance metals) — Captura paralela de los `steps` del motor
  // de cost por línea. Necesario porque `costResult.breakdown.metal.items[]`
  // NUNCA viene poblado en runtime real (bug arquitectónico); la fuente real
  // de los metales son los steps `COST_LINES_METAL` post `enrichCostMetalSteps`.
  // Ver `extractMetalItemsFromSteps` en balance-mode-runtime.ts.
  const lineCostStepsByIdx: Map<number, any[]> = new Map();

  // FIX (auditoría diff-commercial-rounding-by-quantity) — Map paralelo de los
  // `steps` del MOTOR DE VENTA (`resolveFinalSalePrice`). A diferencia del
  // `calculateCostFromLines` standalone (`lineCostStepsByIdx`), este motor
  // recibe `costLineOverrides` y los aplica → `gramsOriginal` POST-overrides.
  //
  // Origen del bug: el agregado para `aggregateMetalsForCommercialDocRounding`
  // leía `lineCostStepsByIdx` (steps CRUDOS), por lo que el snapshot
  // `commercialDocumentRoundingApplied.breakdown.metals[].preGrams` quedaba
  // congelado en el valor del artículo maestro aunque el operador editara la
  // cantidad/gramos del metal en la grilla.
  //
  // El header METALES, "Composición del costo" y "Resumen comercial" ya
  // consumen indirectamente `pricing.steps` (via `buildComposition` →
  // `composition.metals`), por eso esas vistas SÍ reflejan el override. Esta
  // captura paralela alinea el agregado del Redondeo Comercial con la misma
  // fuente — mismo contrato que `confirmSale` ya respeta vía `balanceMetals`.
  //
  // Cero matemática nueva: passthrough de los mismos steps emitidos por el motor.
  const linePricingStepsByIdx: Map<number, any[]> = new Map();

  // ── Resolver cada línea: precio + costo + impuestos ─────────────────────
  const resolvedLines = await Promise.all(
    lines.map(async (line, __lineIdx): Promise<SalePreviewLine> => {
      // ── Línea MANUAL (texto libre, sin artículo) ──────────────────────
      // Camino mínimo: sin pricing-engine, sin lista, sin promo, sin costo.
      // Solo aplica los 3 overrides comerciales (precio / bonif / impuesto)
      // con la misma semántica de % / $ que el motor para artículos. El
      // documentTotals de abajo sigue funcionando porque se arma desde los
      // campos resueltos acá (basePrice/unitPrice/lineTotal/lineTaxAmount).
      if (line.type === "MANUAL") {
        const round2 = (n: number) => Math.round(n * 100) / 100;
        const qty = Number.isFinite(line.quantity) && line.quantity > 0 ? line.quantity : 1;
        // basePrice = el manual sin descuentos (sirve para mostrar la
        // bonificación como diferencia visual). Si no se mandó manualPrice,
        // queda en 0 — el documento totaliza 0 hasta que el operador lo
        // ingrese.
        const basePriceN = Number(line.manualPriceOverride ?? 0);
        // Aplicar ajuste manual (bonif/recargo).
        let unitPriceN = basePriceN;
        const md = line.manualDiscountOverride ?? null;
        if (md && Number.isFinite(md.value) && md.value >= 0) {
          const adjAmt = md.mode === "PERCENT"
            ? (basePriceN * md.value) / 100
            : md.value;
          unitPriceN = md.kind === "SURCHARGE"
            ? basePriceN + adjAmt
            : Math.max(0, basePriceN - adjAmt);
        }
        // Aplicar impuesto manual sobre unitPrice (post descuento).
        let unitTaxAmountN = 0;
        const tx = line.taxOverride ?? null;
        if (tx && Number.isFinite(tx.value) && tx.value >= 0) {
          unitTaxAmountN = tx.mode === "PERCENT"
            ? (unitPriceN * tx.value) / 100
            : tx.value;
        }
        const lineTotalN        = round2(unitPriceN * qty);
        const lineTaxAmountN    = round2(unitTaxAmountN * qty);
        const lineTotalWithTaxN = round2(lineTotalN + lineTaxAmountN);
        const lineDiscountN     = round2(Math.max(0, (basePriceN - unitPriceN) * qty));
        // Snapshot mínimo para mantener la forma del SalePreviewLine.
        const snap: any = {
          unitPrice:            unitPriceN,
          basePrice:            basePriceN,
          discountAmount:       0,
          taxAmount:            unitTaxAmountN,
          totalWithTax:         round2(unitPriceN + unitTaxAmountN),
          priceSource:          "MANUAL_LINE",
          baseSource:           "MANUAL",
          unitCost:             null,
          unitMargin:           null,
          marginPercent:        null,
          markupPercent:        null,
          costPartial:          true,
          costMode:             "NONE",
          partial:              false,
          appliedPriceListId:   null,
          appliedPriceListName: null,
          appliedPromotionId:   null,
          appliedPromotionName: null,
          appliedDiscountId:    null,
          resolvedAt:           new Date().toISOString(),
        };
        return {
          articleId:            "",
          variantId:            null,
          quantity:             qty,
          unitPrice:            unitPriceN,
          basePrice:            basePriceN,
          lineSubtotal:         lineTotalN,
          lineTotal:            lineTotalN,
          lineDiscount:         lineDiscountN,
          unitTaxAmount:        unitTaxAmountN,
          // Sprint 3 — POLICY.md §4 R4.3.
          unitTotalWithTax:     round2(unitPriceN + unitTaxAmountN),
          lineTaxAmount:        lineTaxAmountN,
          lineTotalWithTax:     lineTotalWithTaxN,
          quantityDiscountAmount:  0,
          promotionDiscountAmount: 0,
          // Sprint 3 — línea manual no tiene capa 5; campo siempre null.
          customerDiscountAmount:  null,
          priceSource:          "MANUAL_LINE",
          appliedPriceListId:   null,
          appliedPriceListName: null,
          appliedPriceListMode: null,
          appliedPromotionId:   null,
          appliedPromotionName: null,
          appliedDiscountId:    null,
          unitCost:             null,
          unitMargin:           null,
          marginPercent:        null,
          markupPercent:        null,
          costPartial:          true,
          costMode:             "NONE",
          policy:               { canConfirm: true, blockingAlerts: [] },
          taxBreakdown:         [],
          metalHechuraBreakdown: null,
          pricingSnapshot:      snap,
        } as unknown as SalePreviewLine;
      }

      // Línea de catálogo: requiere `articleId`.
      if (!line.articleId) {
        throw Object.assign(new Error("Línea sin articleId no es ARTICLE válida."), { status: 400 });
      }
      const art     = articleMap.get(line.articleId);
      const lineGid = line.variantId ? variantGroupMap.get(line.variantId) : undefined;

      // Fase 2A.7 — precedencia de override de lista: línea > documento.
      // Si ninguno viene, el motor resuelve por jerarquía cliente → categoría
      // → favorita.
      const effectivePriceListOverride = line.priceListIdOverride
        ?? input.priceListId
        ?? null;

      // 1) Precio
      const pricing = await resolveFinalSalePrice(jewelryId, {
        articleId: line.articleId,
        variantId: line.variantId ?? null,
        clientId:  clientId ?? undefined,
        quantity:  line.quantity,
        categoryTotal: art?.categoryId ? categoryTotals.get(art.categoryId) : undefined,
        brandTotal:    art?.brand      ? brandTotals.get(art.brand)         : undefined,
        groupTotal:    lineGid         ? groupTotals.get(lineGid)            : undefined,
        // Overrides per-line — Fase 6.5: el frontend los manda cuando el
        // usuario edita manualmente precio / bonificación / impuesto. El
        // motor los aplica como input y devuelve los totales coherentes.
        manualPriceOverride:    line.manualPriceOverride    ?? null,
        manualDiscountOverride: line.manualDiscountOverride ?? null,
        taxOverride:            line.taxOverride            ?? null,
        // Override de SOLO la base ("Aplica a"), independiente del valor.
        discountAppliesToOverride: line.manualDiscountAppliesToOverride ?? null,
        taxAppliesToOverride:      line.manualTaxAppliesToOverride      ?? null,
        // Fase 2A.7 — override de lista por línea (toma precedencia).
        priceListIdOverride:    effectivePriceListOverride,
        // Fase 3B — overrides de composición de costo por línea. El motor
        // ya los respetaba para `articles/pricing-preview`; ahora también
        // viajan en el endpoint `sales/preview` para edición desde Factura.
        gramsOverride:          line.gramsOverride          ?? null,
        mermaPercentOverride:   line.mermaPercentOverride   ?? null,
        metalVariantIdOverride: line.metalVariantIdOverride ?? null,
        hechuraOverrideAmount:  line.hechuraOverrideAmount  ?? null,
        // F1.4 G5 #11-A — overrides per costLineId (Fase 1 plumbing). El
        // motor unifica con los legacy de arriba: explicit gana cuando hay
        // match por costLineId. Validaciones (id desconocido / type
        // mismatch / campo inválido) las hace el motor → debugWarnings.
        costLineOverrides:      line.costLineOverrides,
        // Anti doble redondeo: si el tenant tiene redondeo doc activo, el
        // motor IGNORA el redondeo diferido (NET/TOTAL) de la lista.
        suppressListDeferredRounding: docRoundingPolicy.suppressListDeferredRounding,
        // Etapa D' — Si el documento opera PER_DOCUMENT, suprimimos el
        // redondeo PER_LINE de hechura y/o metal físico en applyPriceList
        // (gate anti-doble). Cuando es PER_LINE_LEGACY, el objeto está
        // vacío y el motor mantiene comportamiento legacy intacto.
        applyPriceListOptions: commercialDocCtx.applyPriceListOptions,
      });

      const n2 = (v: any) =>
        v != null && typeof v === "object" && "toNumber" in v
          ? (v as any).toNumber()
          : v != null ? parseFloat(String(v)) : null;

      const unitPrice = n2(pricing.unitPrice);
      const basePrice = n2(pricing.basePrice);

      // FIX (auditoría diff-commercial-rounding-by-quantity) — capturamos los
      // steps del motor de venta para el agregado del Redondeo Comercial
      // PER_DOCUMENT. Estos steps ya tienen aplicados `costLineOverrides`
      // (incluido `quantityOverride` que el operador edita en la grilla).
      // `enrichCostMetalSteps` ya corrió internamente en `resolveFinalSalePrice`
      // (`pricing-engine.sale.ts:1268`), por lo que `meta.metalId/purity/
      // gramsOriginal` vienen completos. Ver `linePricingStepsByIdx` arriba.
      if (Array.isArray((pricing as any).steps) && (pricing as any).steps.length > 0) {
        linePricingStepsByIdx.set(__lineIdx, (pricing as any).steps as any[]);
      }

      // 2) Costo (para que la base de impuestos pueda usar el desglose
      //    Metal/Hechura cuando aplica, igual que confirmSale).
      let costBreakdown: any = null;
      if (art) {
        const costResult = await calculateCostFromLines(
          jewelryId,
          (art as any).costComposition as CostLineInput[],
          {
            kind:  (art as any).manualAdjustmentKind,
            type:  (art as any).manualAdjustmentType,
            value: (art as any).manualAdjustmentValue,
          },
          batchCostCtx,
        );
        costBreakdown = costResult.breakdown ?? null;
        // T55 (Fase 3B.5) — guarda lateral para el balance breakdown.
        if (costBreakdown) lineCostBreakdownsByIdx.set(__lineIdx, costBreakdown);
        // Opción A — guardamos también los `steps` del motor de cost. Son la
        // fuente real de los metales por variante (con `metalId` resuelto
        // por `enrichCostMetalSteps`). El breakdown.metal.items[] queda
        // como fuente histórica (snapshots viejos que sí lo poblaban).
        //
        // FIX (auditoría Etapa C/D — BREAKDOWN): `calculateCostFromLines`
        // emite los steps `COST_LINES_METAL` SIN `metalId` (solo
        // `variantId`). `enrichCostMetalSteps` resuelve `metalId`/`purity`/
        // `metalName` consultando `MetalVariant` por id. Sin esta llamada
        // `extractMetalItemsFromSteps` descarta cada item por el guard
        // `if (!metalId) continue;`, dejando `balanceBreakdown.metals=[]`
        // aunque la línea sí tenga composición de metal. En el flujo
        // `resolveFinalSalePrice` (`pricing-engine.sale.ts:1268`) este
        // enrich ya corre; acá lo replicamos para los steps del costo
        // standalone que el preview persiste lateralmente.
        if (Array.isArray(costResult.steps) && costResult.steps.length > 0) {
          await enrichCostMetalSteps(costResult.steps);
          lineCostStepsByIdx.set(__lineIdx, costResult.steps);
        }
      }

      // 3) Impuestos por línea — mismo camino que confirmSale
      // Pasar `pricing.metalHechuraBreakdown` (no null literal) para alinear
      // la base imponible con el motor del simulador. Cuando un impuesto
      // tiene `applyOn=METAL` o `applyOn=HECHURA`, `computeLineTaxes` usa
      // `metalHechuraBreakdown.metalSale/hechuraSale` como base; pasar null
      // hace caer al fallback `fp × costPart / costTotal`, que estima sobre
      // proporciones de COSTO (no de precio de venta) y produce divergencia.
      let unitTaxAmount = 0;
      let taxBreakdownArr: any[] = [];
      // Override manual de la línea: si está presente, el operador eligió
      // EXPLÍCITAMENTE un impuesto manual (incluido value=0 con la nueva
      // semántica X=manual 0). Tiene PRIORIDAD sobre la exención del
      // cliente — la exención es un default automático, no un candado.
      // `computeLineTaxes` ya respeta el override sobre `taxIds=[]`; el
      // guard externo debe dejarlo entrar también cuando cliente exento +
      // override. Sin esto, el bloque entero se saltaba para cliente
      // exento y el override del operador NUNCA llegaba al motor.
      const lineHasManualTaxOverride =
        line.taxOverride != null || line.manualTaxAppliesToOverride != null;
      if (unitPrice != null && art && (!clientTaxExempt || lineHasManualTaxOverride)) {
        // Cliente exento + override manual: vaciamos los IVAs heredados
        // del artículo (la exención los cubre) y dejamos que el motor
        // aplique SOLO el override. Sin esto, el motor sumaría el IVA
        // configurado + el override → doble aplicación contraria a la
        // semántica de exención. Cliente NO exento: los IVAs heredados
        // del artículo aplican normalmente (con o sin override; el
        // motor los combina/reemplaza según override).
        const taxIds: string[] = clientTaxExempt
          ? []
          : (((art as any).manualTaxIds ?? []) as string[]);
        // Override manual de impuesto por línea (Factura). Tiene PRIORIDAD
        // absoluta sobre el impuesto heredado del artículo (`manualTaxIds`):
        // `computeLineTaxes` lo resuelve antes de tocar `taxIds`. Por eso el
        // bloque debe ejecutarse también cuando NO hay taxIds heredados pero
        // sí hay override (ej. artículo sin IVA y el operador fija 10%), y
        // cuando hay override 0 explícito (limpiar impuesto). Antes este
        // recompute OMITÍA el 9º argumento → el motor caía al IVA heredado y
        // el override del operador se perdía (bug confirmado por logs).
        const lineTaxOverride   = line.taxOverride ?? null;
        // Override de SOLO la base ("Aplica a") del impuesto heredado.
        // El recompute debe correr también cuando solo cambió la base
        // (sin override de valor) para que el preview recalcule al toque.
        const lineTaxAppliesTo  = line.manualTaxAppliesToOverride ?? null;
        if (taxIds.length > 0 || lineTaxOverride != null || lineTaxAppliesTo != null) {
          const unitPriceDec = new Prisma.Decimal(unitPrice);
          const basePriceDec = new Prisma.Decimal(basePrice ?? unitPrice);
          // Base imponible NETA por componente: usamos los `*SaleFinal`
          // (= componentSaleBreakdown.{metal,hechura}.final) que el motor
          // ya calculó post-bonificación/descuento por componente. Sin
          // esto, "Bonif. Solo metal + Impuesto Solo metal" calculaba el
          // impuesto sobre el metal BRUTO (bug reportado). Fallback al
          // bruto solo si el motor no expuso el neto.
          // Base imponible NETA por componente. Fuente del NETO, en orden:
          //   1. metalHechuraBreakdown.{metal,hechura}SaleFinal (listas
          //      METAL_HECHURA con desglose exacto).
          //   2. componentSaleBreakdown.{metal,hechura}.final — el motor lo
          //      deriva TAMBIÉN para listas UNIFICADA/COST_LINES (proporción),
          //      donde `metalHechuraBreakdown` es null. Sin esto, "Bonif.
          //      Solo metal/hechura + Impuesto Solo metal/hechura" en lista
          //      Unificada caía al estimado por proporción de costo (≈ BRUTO).
          //   3. Bruto solo si el motor no expuso ningún neto.
          const mhRaw = pricing.metalHechuraBreakdown as any;
          const csb   = (pricing as any).componentSaleBreakdown ?? null;
          const netMetal   = mhRaw?.metalSaleFinal   ?? csb?.metal?.final;
          const netHechura = mhRaw?.hechuraSaleFinal ?? csb?.hechura?.final;
          const mhForTax =
            netMetal != null && netHechura != null
              ? {
                  metalSale:   parseFloat(String(netMetal)),
                  hechuraSale: parseFloat(String(netHechura)),
                }
              : pricing.metalHechuraBreakdown
                ? {
                    metalSale:   parseFloat(String(pricing.metalHechuraBreakdown.metalSale)),
                    hechuraSale: parseFloat(String(pricing.metalHechuraBreakdown.hechuraSale)),
                  }
                : null;
          const { taxBreakdown, taxAmount } = await computeLineTaxes(
            jewelryId,
            taxIds,
            unitPriceDec,
            basePriceDec,
            mhForTax,
            costBreakdown,
            clientTaxApplyOnOverride,
            clientTaxOverrides,
            // 9º arg — override manual de la línea. Sin esto el motor
            // ignoraba el override y devolvía el IVA heredado 21%.
            lineTaxOverride,
            // 10º arg — override de SOLO la base ("Aplica a"). Recalcula
            // el impuesto heredado sobre esa base sin tocar la tasa.
            lineTaxAppliesTo,
          );
          unitTaxAmount   = parseFloat(taxAmount.toString());
          // Escalar `base` y `taxAmount` de cada item por la cantidad de la
          // línea para que el breakdown sea coherente con `lineTaxAmount`
          // (que ya es × qty). El motor `computeLineTaxes` devuelve valores
          // per-unit; en una línea de venta debemos exponerlos por-línea
          // para que el frontend (PricingCompare, factura UI) los use sin
          // tener que multiplicar de nuevo. Verificación implícita:
          // `Σ item.taxAmount === unitTaxAmount × qty === lineTaxAmount`.
          const qtyN = parseFloat(String(line.quantity)) || 1;
          const r2   = (n: number) => Math.round(n * 100) / 100;
          taxBreakdownArr = (taxBreakdown as any[]).map((t) => ({
            ...t,
            base:      r2(Number(t.base ?? 0)      * qtyN),
            taxAmount: r2(Number(t.taxAmount ?? 0) * qtyN),
          }));
        }
      }

      const round2 = (n: number) => Math.round(n * 100) / 100;
      // ── PARIDAD preview ↔ confirm (Fix B2) ─────────────────────────────
      //   Construir `lineTotal` y `lineTotalWithTax` con la MISMA fórmula
      //   que `confirmSale` (ver más arriba `totalWithTax = unitPriceNum +
      //   lineTaxAmt`). NO depender de `pricing.totalWithTax` del motor:
      //   el motor lo arma con SUS impuestos (sin overrides de cliente),
      //   mientras que acá `lineTaxAmount` viene de `computeLineTaxes`
      //   re-invocado con overrides. Si los dos diferían, la fórmula
      //   `lineTotal = pricing.totalWithTax × qty − lineTaxAmount`
      //   producía un offset = (pricing.taxAmount × qty − lineTaxAmount).
      //
      //   Trade-off: cuando una lista aplicaba `applyOn=TOTAL` con redondeo
      //   propio, el motor redondeaba `pricing.totalWithTax` y se preservaba
      //   acá. Con este cambio, ese redondeo se reconstruye desde
      //   `unitPrice + lineTaxAmount` y puede diferir en centavos.
      //   POLICY.md §1 R1.2 ya prohíbe la combinación catastrófica (lista
      //   con redondeo + tenant con `documentRoundingEnabled=true`); el
      //   redondeo único pasa al documento (capa 11 del orden inmutable).
      // DEBUG TEMPORAL 2026-05-28 — captura el metalHechuraBreakdown que el
      // motor expone para CADA línea (post-rounding por componente cuando
      // METAL_HECHURA + target=METAL). Si acá hechuraSale viene 59384.06 en
      // lugar de 59400, el bug está EN EL MOTOR. Si viene 59400 acá pero el
      // frontend muestra 59384.06, el bug está EN EL FRONTEND o en el mapping
      // del response. Activar con env TPTECH_DEBUG_ROUNDING=1.
      if (process.env.TPTECH_DEBUG_ROUNDING === "1") {
        // eslint-disable-next-line no-console
        console.log("[SALE_PREVIEW_BREAKDOWN_ROUNDING_DEBUG]", {
          articleId:              line.articleId,
          variantId:              line.variantId ?? null,
          priceListId:            (pricing as any).appliedPriceListId ?? null,
          priceListName:          (pricing as any).appliedPriceListName ?? null,
          quantity:               line.quantity,
          unitPriceFromMotor:     pricing.unitPrice  != null ? Number(pricing.unitPrice)  : null,
          basePriceFromMotor:     pricing.basePrice  != null ? Number(pricing.basePrice)  : null,
          unitTaxAmount,
          metalHechuraBreakdown:  pricing.metalHechuraBreakdown ?? null,
          appliedRounding:        (pricing as any).appliedRounding ?? null,
        });
      }

      const lineTaxAmount    = round2(unitTaxAmount * line.quantity);
      const lineTotal        = unitPrice != null ? round2(unitPrice * line.quantity)         : null;
      // BUG FIX 2026-05-28 — Cuando la lista aplica `appliedRounding` con
      // `applyOn=TOTAL`, el motor redondea `totalWithTax` per-unit pero NO
      // actualiza `unitPrice` ni `unitTaxAmount`. Por lo tanto la suma
      // `lineTotal + lineTaxAmount` queda PRE-rounding. La celda visual
      // "Total línea c/ imp." debe reflejar el monto que el cliente paga
      // (= post-rounding), igual que el hero del comprobante. Sumamos el
      // delta `(postRounding − preRounding) × qty` cuando existe.
      //
      // `lineTotal` y `lineTaxAmount` se mantienen separados (pre-rounding)
      // para no romper consumers de esos campos. La suma del documento
      // se corrige aparte vía `docRoundingAdjustmentPreEngine` que el caller
      // pasa a `computeSaleDocumentTotals` (POLICY §R-Rounding-1 capa 11).
      const ar = (pricing as any).appliedRounding ?? null;
      let lineRoundingDelta = 0;
      if (ar && ar.applyOn === "TOTAL") {
        const pre  = typeof ar.preRounding  === "number"
          ? ar.preRounding
          : ar.preRounding  != null ? parseFloat(String(ar.preRounding))  : 0;
        const post = typeof ar.postRounding === "number"
          ? ar.postRounding
          : ar.postRounding != null ? parseFloat(String(ar.postRounding)) : 0;
        if (Number.isFinite(pre) && Number.isFinite(post)) {
          lineRoundingDelta = (post - pre) * line.quantity;
        }
      }
      const lineTotalWithTax = lineTotal != null
        ? round2(lineTotal + lineTaxAmount + lineRoundingDelta)
        : null;
      const lineDiscount =
        basePrice != null && unitPrice != null
          ? Math.max(0, round2((basePrice - unitPrice) * line.quantity))
          : 0;

      // Etapa C-comercial / C4-fix (POLICY §R-Rounding-14) — agregamos
      // los 5 campos que C3 emite en `metalHechuraDetail` para que viajen
      // hasta el frontend: `physical` (snapshot por metal padre) + 4
      // pares pre/delta de auditoría. Los campos viejos se preservan EXACTOS
      // — cero cambio de contrato para listas legacy MONETARY.
      const mh: SalePreviewLineMetalHechura | null = pricing.metalHechuraBreakdown
        ? {
            metalCost:         pricing.metalHechuraBreakdown.metalCost,
            metalSale:         pricing.metalHechuraBreakdown.metalSale,
            metalMarginPct:    pricing.metalHechuraBreakdown.metalMarginPct,
            hechuraCost:       pricing.metalHechuraBreakdown.hechuraCost,
            hechuraSale:       pricing.metalHechuraBreakdown.hechuraSale,
            hechuraMarginPct:  pricing.metalHechuraBreakdown.hechuraMarginPct,
            metalGramsBase:    pricing.metalHechuraBreakdown.metalGramsBase    ?? null,
            metalGramsSale:    pricing.metalHechuraBreakdown.metalGramsSale    ?? null,
            metalPricePerGram: pricing.metalHechuraBreakdown.metalPricePerGram ?? null,
            // C4-fix — auditoría del redondeo comercial.
            metalSalePreRounding:
              (pricing.metalHechuraBreakdown as any).metalSalePreRounding    ?? null,
            hechuraSalePreRounding:
              (pricing.metalHechuraBreakdown as any).hechuraSalePreRounding  ?? null,
            metalSaleRoundingDelta:
              (pricing.metalHechuraBreakdown as any).metalSaleRoundingDelta  ?? null,
            hechuraSaleRoundingDelta:
              (pricing.metalHechuraBreakdown as any).hechuraSaleRoundingDelta?? null,
            physical:
              (pricing.metalHechuraBreakdown as any).physical                ?? null,
          }
        : null;

      // F1.3 G4.x #5b — composition se arma ANTES del snapshot para que se
      // persista junto con el resto del precio (paridad preview/persisted).
      // Failure-isolation por línea: si buildComposition lanza, esa línea
      // queda con composition=null y el resto del preview sigue.
      // F1.3 G4.x #9-A — además del legacy fetch del primer variantId,
      // batch query de TODAS las variantes referenciadas en steps METAL.
      const metalVariantIdToFetch = resolveMetalVariantIdFromResult(pricing);
      const metalVariantIdsFromSteps = (pricing.steps ?? [])
        .filter(s => s?.key === "COST_LINES_METAL" && s?.status === "ok")
        .map(s => (s.meta as any)?.variantId)
        .filter((v): v is string => typeof v === "string" && v.length > 0);
      const [metalVariantInfo, metalVariantInfoMap] = await Promise.all([
        fetchMetalVariantInfo(metalVariantIdToFetch),
        fetchMetalVariantInfoMap(metalVariantIdsFromSteps),
      ]);
      let composition: Awaited<ReturnType<typeof buildComposition>> | null = null;
      try {
        composition = buildComposition(pricing, metalVariantInfo, catalogItemsMap, metalVariantInfoMap);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(
          `[sales/preview] buildComposition falló para línea articleId=${line.articleId}; ` +
          `composition=null para esta línea, resto del preview sigue:`,
          err,
        );
      }

      // Fase 2A.7 — paridad con `articles/pricing-preview`.
      // 1) Costo de compra por línea (mismo helper que articles).
      // F17 — se calcula ANTES de armar el snapshot para que `buildPricingSnapshot`
      // lo persista en `costBase/costTaxAmount/costWithTax/costTaxBreakdown`
      // (snapshot v7). La base es `pricing.unitCost`, que ya es post-ajuste
      // global del artículo (manualAdjustment* aplicado por el motor).
      const costTaxResult = await computePurchaseTaxes(
        jewelryId,
        line.articleId,
        pricing.unitCost ?? null,
      );

      // Snapshot reusable — lo mismo que createSale persiste en DRAFT.
      // F1.3 G4.x #5b — pasamos `composition` para que viaje en el snapshot
      // (igual al de DRAFT). El motor ya provee componentSaleBreakdown.
      // F17 — pasamos `purchaseTaxes` para persistir costBase/costTaxAmount/
      // costWithTax/costTaxBreakdown en el snapshot v7.
      const pricingSnapshotForLine = buildPricingSnapshot(pricing, {
        composition,
        purchaseTaxes: costTaxResult,
      });
      // El snapshot del motor ya trae `totalWithTax` UNITARIO REDONDEADO
      // (preservando applyRounding cuando la lista aplica `applyOn=TOTAL`).
      // NO pisarlo: antes lo reescribíamos como `unitPrice + unitTaxAmount`
      // y perdíamos el redondeo. Solo sincronizamos `taxAmount` con el
      // cálculo local de previewSale (ya consistente con el motor).
      pricingSnapshotForLine.taxAmount = unitTaxAmount;
      const appliedMermaPercent   = getAppliedMermaPercent(pricing);

      // FASE 1.1 G7 — flags explícitos de qué overrides aplicó el operador a
      // esta línea. POLICY.md §3 R3.4 pide flags por subcampo (price/discount/
      // tax). El frontend antes inferia desde priceSource="MANUAL_OVERRIDE",
      // pero ese flag no distingue entre los 3 tipos.
      // `quantity` queda en `false` siempre — el motor nunca computa qty,
      // es siempre input directo del operador.
      //
      // Frontend desbloqueado:
      //   · Priority 6 — composeDocumentPricingDetail puede mostrar
      //     trazabilidad explícita: "este descuento es manual, no de regla".
      //   · Priority 8 — VentasFacturas / TPDocumentLineAdvancedEditor
      //     pueden destacar visualmente cada subcampo overrideado en lugar
      //     de mostrar un único badge "MANUAL_OVERRIDE".
      const manualOverridesApplied = {
        quantity: false,
        price:    line.manualPriceOverride != null,
        discount: line.manualDiscountOverride != null,
        tax:      line.taxOverride != null,
      };

      return {
        articleId:            line.articleId,
        variantId:            line.variantId ?? null,
        quantity:             line.quantity,
        unitPrice,
        basePrice,
        lineSubtotal:         lineTotal,            // alias compat
        lineTotal,
        lineDiscount,
        unitTaxAmount,
        // Sprint 3 — unitario con impuestos = unitPrice + unitTaxAmount.
        // Frontend deja de derivarlo (POLICY.md §4 R4.3).
        unitTotalWithTax:     unitPrice != null ? round2(unitPrice + unitTaxAmount) : null,
        lineTaxAmount,
        lineTotalWithTax,
        // FASE 1.1 G7 — flags de overrides explícitos.
        manualOverridesApplied,
        quantityDiscountAmount:  n2(pricing.quantityDiscountAmount),
        promotionDiscountAmount: n2(pricing.promotionDiscountAmount),
        // Sprint 3 — POLICY.md §8 — capa 5 expuesta como campo singular.
        customerDiscountAmount:  n2(pricing.customerDiscountAmount),
        // ── Metadata explicativa per-origen ──────────────────────────────
        // Leemos los `steps[]` que el motor ya populó. NO modifica nada del
        // resultado: solo serializa lo que el motor calculó internamente.
        // El frontend usa esto para mostrar "Cálculo: base × valor" sin
        // recalcular nada (POLICY.md R4.5).
        ...(() => {
          const steps = pricing.steps;
          const findMeta = (key: string): Record<string, unknown> | null =>
            Array.isArray(steps)
              ? ((steps.find((s) => s?.key === key)?.meta as Record<string, unknown> | undefined) ?? null)
              : null;
          const toNum = (v: unknown): number | null => {
            if (v == null) return null;
            const n = typeof v === "string" ? Number(v) : (typeof v === "number" ? v : NaN);
            return Number.isFinite(n) ? n : null;
          };
          const toValueType = (v: unknown): "PERCENTAGE" | "FIXED_AMOUNT" | null =>
            v === "PERCENTAGE" || v === "FIXED_AMOUNT" ? v : null;
          const qdMeta    = findMeta("QUANTITY_DISCOUNT");
          const promoMeta = findMeta("PROMOTION");
          const ruleMeta  = findMeta("ENTITY_COMMERCIAL_RULE");
          return {
            quantityDiscountBase:      n2(toNum(qdMeta?.discountBase)),
            quantityDiscountValue:     toNum(qdMeta?.value),
            // Step QUANTITY_DISCOUNT emite `type` (no `valueType`).
            quantityDiscountValueType: toValueType(qdMeta?.type),
            promotionDiscountBase:      n2(toNum(promoMeta?.discountBase)),
            promotionDiscountValue:     toNum(promoMeta?.value),
            promotionDiscountValueType: toValueType(promoMeta?.type),
            // Step ENTITY_COMMERCIAL_RULE emite `valueType` y `discountBase`.
            // El `value` y `applyOn` ya viajan en `clientCommercialRules`.
            customerDiscountBase:       n2(toNum(ruleMeta?.discountBase)),
          };
        })(),
        // Subset whitelist de pricing.steps[] para que el frontend renderice
        // el pipeline en orden real (POLICY R4.5 — passthrough estricto).
        pricingSteps: (() => {
          const steps = pricing.steps;
          if (!Array.isArray(steps)) return undefined;
          const WHITELIST = new Set([
            "PRICE_LIST", "MANUAL_OVERRIDE", "MANUAL_FALLBACK",
            "MANUAL_PRICE_OVERRIDE",
            "QUANTITY_DISCOUNT", "PROMOTION", "ENTITY_COMMERCIAL_RULE",
            "MANUAL_DISCOUNT_OVERRIDE",
          ]);
          const toNum = (v: unknown): number | null => {
            if (v == null) return null;
            const n = typeof v === "string" ? Number(v) : (typeof v === "number" ? v : NaN);
            return Number.isFinite(n) ? n : null;
          };
          const toEnum = <T extends string>(v: unknown, allowed: readonly T[]): T | null =>
            typeof v === "string" && (allowed as readonly string[]).includes(v)
              ? (v as T)
              : null;
          return steps
            .filter((s) => s != null && WHITELIST.has(s.key))
            .map((s): SalePreviewStep => {
              const m = (s.meta ?? {}) as Record<string, unknown>;
              return {
                key:     s.key,
                label:   s.label,
                status:  (s.status as SalePreviewStep["status"]) ?? "ok",
                value:   n2(toNum(s.value as unknown)),
                message: typeof s.message === "string" ? s.message : undefined,
                meta: {
                  discountBase:           n2(toNum(m.discountBase)),
                  discountAmount:         n2(toNum(m.discountAmount)),
                  discountBaseEstimated:  typeof m.discountBaseEstimated === "boolean" ? m.discountBaseEstimated : undefined,
                  surchargeBase:          n2(toNum(m.surchargeBase)),
                  surchargeAmount:        n2(toNum(m.surchargeAmount)),
                  surchargeBaseEstimated: typeof m.surchargeBaseEstimated === "boolean" ? m.surchargeBaseEstimated : undefined,
                  value:                  toNum(m.value),
                  type:                   toEnum(m.type,      ["PERCENTAGE", "FIXED_AMOUNT"] as const),
                  valueType:              toEnum(m.valueType, ["PERCENTAGE", "FIXED_AMOUNT"] as const),
                  applyOn:                typeof m.applyOn === "string" ? m.applyOn : null,
                  ruleType:               toEnum(m.ruleType, ["DISCOUNT", "BONUS", "SURCHARGE"] as const),
                  kind:                   toEnum(m.kind,     ["BONUS", "SURCHARGE"] as const),
                  mode:                   toEnum(m.mode,     ["PERCENT", "FIXED"] as const),
                  promoId:                typeof m.promoId    === "string" ? m.promoId    : null,
                  discountId:             typeof m.discountId === "string" ? m.discountId : null,
                  // PROMOTION ya emite el nombre en el label (`Promoción: X`),
                  // pero igual viajamos un campo dedicado para el frontend.
                  promoName: pricing.appliedPromotionName ?? null,
                },
              };
            });
        })(),
        priceSource:          pricing.priceSource,
        appliedPriceListId:   pricing.appliedPriceListId,
        appliedPriceListName: pricing.appliedPriceListName,
        appliedPriceListMode: pricing.appliedPriceListMode,
        appliedPromotionId:   pricing.appliedPromotionId,
        appliedPromotionName: pricing.appliedPromotionName,
        appliedDiscountId:    pricing.appliedDiscountId,
        unitCost:             n2(pricing.unitCost),
        unitMargin:           n2(pricing.unitMargin),
        marginPercent:        n2(pricing.marginPercent),
        markupPercent:        n2(pricing.markupPercent),
        costPartial:          pricing.costPartial,
        costMode:             pricing.costMode,
        policy:               pricing.policy,
        // R6 fix passthrough — exponer las alertas del motor al frontend.
        // El motor ya las calcula (`buildAlerts` en `pricing-engine.sale.ts`).
        // Sin esta propagación, el frontend recibía `alerts: undefined` y
        // `deriveCommercialLevel` siempre devolvía "OK" — el chip ámbar de
        // WARNING (cuyo único disparador no-bloqueante es LOW_MARGIN en
        // `alerts[]`) era estructuralmente inalcanzable.
        alerts:               pricing.alerts,
        taxBreakdown:         taxBreakdownArr,
        metalHechuraBreakdown: mh,
        componentSaleBreakdown: pricing.componentSaleBreakdown ?? null,
        pricingSnapshot:       pricingSnapshotForLine,
        // Redondeo aplicado por la lista de precios a esta línea (per unit).
        // Lo expone el motor para que la UI no tenga que reconstruirlo.
        appliedRounding: pricing.appliedRounding
          ? {
              source:        "PRICE_LIST" as const,
              priceListId:   pricing.appliedRounding.priceListId,
              priceListName: pricing.appliedRounding.priceListName,
              applyOn:       pricing.appliedRounding.applyOn,
              mode:          pricing.appliedRounding.mode,
              direction:     pricing.appliedRounding.direction,
              preRounding:   parseFloat(pricing.appliedRounding.preRounding.toFixed(4)),
              postRounding:  parseFloat(pricing.appliedRounding.postRounding.toFixed(4)),
              unitAdjustment: parseFloat(
                pricing.appliedRounding.postRounding.minus(pricing.appliedRounding.preRounding).toFixed(4)
              ),
              // Etapa C-comercial — passthrough del snapshot PHYSICAL cuando
              // applyOn === "METAL". Sin esto, el frontend ve `appliedRounding`
              // sin el detalle por metal padre (preGrams/postGrams/etc).
              ...(pricing.appliedRounding.physical != null
                ? { physical: pricing.appliedRounding.physical }
                : {}),
            }
          : null,
        // ── Fase 2A.7 — paridad con articles/pricing-preview ─────────────
        // F1.3 G4.1.4 — `composition ?? undefined` mantiene el contrato del
        // SalePreviewLine type (composition?: Composition) cuando la línea
        // sufrió failure-isolation arriba.
        composition: composition ?? undefined,
        appliedMermaPercent,
        costBase:         costTaxResult.costBase,
        costTaxAmount:    costTaxResult.costTaxAmount,
        costWithTax:      costTaxResult.costWithTax,
        costTaxBreakdown: costTaxResult.costTaxBreakdown,
        priceListIdOverride: effectivePriceListOverride,
      };
    }),
  );


  // ── Canal de venta ────────────────────────────────────────────────────────
  let channelAdjInput: ChannelAdjustmentInput | null = null;
  if (input.channelId) {
    const channelRow = await prisma.salesChannel.findFirst({
      where: { id: input.channelId, jewelryId, deletedAt: null, isActive: true },
      select: { id: true, name: true, adjustmentType: true, adjustmentValue: true },
    });
    if (channelRow) {
      channelAdjInput = {
        id:              channelRow.id,
        name:            channelRow.name,
        adjustmentType:  channelRow.adjustmentType as "PERCENTAGE" | "FIXED",
        adjustmentValue: parseFloat(channelRow.adjustmentValue.toString()),
      };
    }
  }

  // ── Cupón ────────────────────────────────────────────────────────────────
  let couponInputForTotals: CouponInput | null = null;
  let couponInvalidReason: string | undefined;
  let couponInvalidEcho: { id: string; code: string; name: string; type: any } | null = null;
  if (input.couponCode) {
    const validation = await validateCoupon(jewelryId, input.couponCode, { clientId: clientId ?? null });
    if (validation.valid) {
      couponInputForTotals = {
        id:            validation.id,
        code:          validation.code,
        name:          validation.name,
        discountType:  validation.discountType,
        discountValue: validation.discountValue,
      };
    } else {
      couponInvalidReason = validation.reason;
      couponInvalidEcho   = {
        id:   validation.id || "",
        code: input.couponCode.trim().toUpperCase(),
        name: validation.name || "",
        type: (validation.discountType as any) || "PERCENTAGE",
      };
    }
  }

  // ── Forma de pago — calculamos primero sin saber el ajuste para pasarlo
  //    a computeSaleDocumentTotals. El paso de pago sigue aplicándose
  //    DESPUÉS del cupón, sobre couponResult.finalAmount.
  // Lo resolvemos en dos pases: primero canal+cupón con totals=null (placeholder),
  // luego payment, luego totals final.
  //
  // BUG FIX (Fase 2.1.b post-mortem):
  // La forma de pago debe usar EXACTAMENTE la misma base que
  // `articles/pricing-preview` (referencia única). Articles arma:
  //
  //     baseForPayment = (totalWithTax + channelAmount - couponAmount) × qty
  //
  // es decir TOTAL CON IMPUESTOS post-canal/cupón (per-doc). Antes acá
  // pasábamos `provisionalCoupon.finalAmount`, que era subtotal NETO
  // post-canal/cupón SIN impuestos → divergencia ≈ IVA con el Simulador.
  //
  // No tocar el motor: solo armar la base con la misma fórmula y pasarla.
  const provisionalChannel = applySalesChannelAdjustment(
    Math.round(resolvedLines.reduce((s, l) => s + (l.lineTotal ?? 0), 0) * 100) / 100,
    channelAdjInput,
  );
  const provisionalCoupon = applyCouponAdjustment(
    provisionalChannel.finalAmount,
    couponInputForTotals,
  );
  // Base con impuestos: Σ lineTotalWithTax + channelAmount − couponAmount.
  // - `lineTotalWithTax` ya es per-doc por línea (qty × unit + tax).
  // - `channelAdjustmentAmount` y `couponDiscountAmount` per-doc, derivados
  //   del paso provisional de arriba (que aplicó sobre el subtotal neto,
  //   igual que el motor del Simulador).
  const subtotalLineWithTax = Math.round(
    resolvedLines.reduce((s, l) => s + (l.lineTotalWithTax ?? l.lineTotal ?? 0), 0) * 100,
  ) / 100;
  const channelAdjustmentAmount = provisionalChannel.channelAmount ?? 0;
  const couponDiscountAmount    = (couponInputForTotals && provisionalCoupon.applied)
    ? (provisionalCoupon.discountAmount ?? 0)
    : 0;
  const paymentBaseAmount = Math.max(
    0,
    Math.round((subtotalLineWithTax + channelAdjustmentAmount - couponDiscountAmount) * 100) / 100,
  );

  const checkoutResult =
    paymentBaseAmount > 0 && (paymentMethodId || installmentsQty >= 1)
      ? await getCheckoutPreview(
          jewelryId,
          paymentBaseAmount,
          paymentMethodId ?? undefined,
          installmentsQty,
        )
      : null;
  const paymentAdjustmentAmount = checkoutResult
    ? checkoutResult.finalAmount - paymentBaseAmount
    : 0;

  // ── Resolver descuento global ────────────────────────────────────────────
  // Fase 5: si el frontend manda `globalDiscount: { type, value }`, lo
  // resolvemos acá contra el subtotal post-descuentos de línea (lo que rompe
  // el feedback loop FE↔BE). Si manda `globalDiscountAmount`, lo usamos
  // directamente (compat Fase 4).
  const subtotalForGlobalDiscount = Math.round(
    resolvedLines.reduce((s, l) => s + (l.lineTotal ?? 0), 0) * 100,
  ) / 100;
  let resolvedGlobalDiscountAmount = input.globalDiscountAmount ?? 0;
  if (input.globalDiscount && Number.isFinite(input.globalDiscount.value) && input.globalDiscount.value > 0) {
    if (input.globalDiscount.type === "PERCENT") {
      resolvedGlobalDiscountAmount = Math.max(
        0,
        Math.round(subtotalForGlobalDiscount * input.globalDiscount.value) / 100,
      );
    } else if (input.globalDiscount.type === "AMOUNT") {
      resolvedGlobalDiscountAmount = Math.max(0, input.globalDiscount.value);
    }
  }

  // ── Totales del documento — fuente única (Fase 4) ────────────────────────

  // Mismo motor que `confirmSale` usa.
  // FASE 2 — propagamos el breakdown Metal/Hechura por línea (per-unit ×
  // qty) para que el motor agregue `metalCostSubtotal` / `metalSaleSubtotal`
  // / etc. a nivel documento. Cada `l.metalHechuraBreakdown` viene
  // poblado universalmente desde FASE 1.
  // ── Pre-cómputo del delta de rounding deferred TOTAL ──────────────────────
  // BUG FIX 2026-05-28: el motor recibía `roundingAdjustment: 0` siempre, lo
  // que dejaba `documentTotals.total` PRE-rounding cuando la lista tenía
  // `applyOn=TOTAL` (el rounding se aplica a `totalWithTax` por línea pero
  // NO actualiza `unitPrice`/`unitTaxAmount`, por lo que la suma `Σ lineTotal
  // + Σ lineTaxAmount` queda PRE-rounding).
  //
  // Filtro CRÍTICO: solo `applyOn === "TOTAL"` aporta delta acá. Para
  // `applyOn=PRICE` y `applyOn=NET`, el motor SÍ actualiza `unitPrice`
  // (rawPrice/finalPrice quedan post-rounding), entonces `lineTotal =
  // unitPrice × qty` ya incluye el delta — sumar acá lo DUPLICARÍA.
  //
  // Cuando hay política de comprobante (Etapa 1B), el motor descarta este
  // input y aplica el rounding del comprobante (anti doble-rounding ya
  // implementado en `document.ts:730-733`).
  let docRoundingAdjustmentPreEngine = 0;
  for (const l of resolvedLines) {
    const ar = (l as any).appliedRounding;
    if (!ar || ar.applyOn !== "TOTAL") continue;
    docRoundingAdjustmentPreEngine += (ar.unitAdjustment ?? 0) * (l.quantity ?? 1);
  }
  docRoundingAdjustmentPreEngine = Math.round(docRoundingAdjustmentPreEngine * 100) / 100;

  // ── Etapa D' — Agregados para el redondeo comercial PER_DOCUMENT ────────
  // Solo armar cuando la capa nueva va a actuar (PER_DOCUMENT con
  // commercialDocumentRounding != null). En PER_LINE_LEGACY no se usan.
  // Los `metalItems` salen de `lineCostStepsByIdx` (ya enriquecidos con
  // metalId y purity por `enrichCostMetalSteps`).
  //
  // BUG-FIX (Etapa D' cierre) — `metalParentName` legible:
  //   Antes se pasaba `metalParentName: m.metalId` (el id técnico tipo
  //   "cmprg38wr…") porque `extractMetalItemsFromSteps` no expone el nombre.
  //   Fix: query batch a `Metal` para construir `Map<metalId, name>` y
  //   propagar el nombre real (ej. "Oro Fino", "Plata"). Cero matemática
  //   — solo resolución de label. Si la query falla o el metal no existe
  //   (drift histórico), fallback al id como antes para no romper el flujo.
  const commercialMetalIds = new Set<string>();
  if (commercialDocCtx.mode === "PER_DOCUMENT" && commercialDocCtx.commercialDocumentRounding) {
    for (let idx = 0; idx < resolvedLines.length; idx++) {
      const steps = lineCostStepsByIdx.get(idx);
      if (!steps) continue;
      for (const m of extractMetalItemsFromSteps(steps)) {
        if (m.metalId) commercialMetalIds.add(m.metalId);
      }
    }
  }
  let commercialMetalNames = new Map<string, string>();
  const commercialMetalRefValues = new Map<string, number>();
  if (commercialMetalIds.size > 0) {
    try {
      const metals = await prisma.metal.findMany({
        where:  { id: { in: Array.from(commercialMetalIds) }, jewelryId, deletedAt: null },
        select: { id: true, name: true, referenceValue: true },
      });
      commercialMetalNames = new Map(metals.map((m) => [m.id, m.name]));
      for (const m of metals) {
        const rv = m.referenceValue != null ? Number(m.referenceValue.toString()) : NaN;
        if (Number.isFinite(rv) && rv > 0) commercialMetalRefValues.set(m.id, rv);
      }
    } catch {
      // Defensa: si la query falla (mocks legacy / DB sin acceso), seguimos
      // con map vacío → fallback al id como antes.
    }
  }

  const commercialDocAggregates =
    commercialDocCtx.mode === "PER_DOCUMENT" && commercialDocCtx.commercialDocumentRounding
      ? aggregateMetalsForCommercialDocRounding(
          resolvedLines.map((l, idx) => {
            // FIX (auditoría diff-commercial-rounding-by-quantity) — usar los
            // steps del MOTOR DE VENTA (post `costLineOverrides`) como fuente
            // única del agregado. Fallback defensivo a los steps del cálculo
            // standalone de cost (crudos) solo si el motor de venta no
            // emitió steps para esta línea (edge case).
            const steps =
              linePricingStepsByIdx.get(idx)
              ?? lineCostStepsByIdx.get(idx);
            const metalItems = steps ? extractMetalItemsFromSteps(steps) : [];
            return {
              quantity: l.quantity || 1,
              // R-COMMERCIAL-GRAMS-WITH-MERMA (REGLA ABSOLUTA) — el agregado
              // del Redondeo Comercial SOLO acepta items con
              // `gramsFineEquivalent = gramsOriginal × purity × (1 + merma/100)`
              // ya computado por `enrichCostMetalSteps`
              // (`pricing-engine.cost.ts:585-588`). PROHIBIDO aplicar el
              // redondeo sobre `gramsOriginal × purity` sin merma.
              //
              // Si el motor NO emitió `gramsFineEquivalent` para este step
              // (caso anómalo: purity ausente / step legacy / variante sin
              // pureza) descartamos la entry — preferimos no redondear a
              // redondear sin merma. La anomalía se loguea para auditoría.
              metals: metalItems
                .filter((m) => {
                  if (!m.metalId) return false;
                  if (typeof m.gramsFineEquivalent !== "number" || !Number.isFinite(m.gramsFineEquivalent)) {
                    // eslint-disable-next-line no-console
                    console.warn(
                      `[sales/preview] Item METAL ${m.metalId} sin gramsFineEquivalent — ` +
                      `excluido del agregado comercial (R-COMMERCIAL-GRAMS-WITH-MERMA). ` +
                      `gramsOriginal=${m.gramsOriginal} purity=${m.purity}`,
                    );
                    return false;
                  }
                  return true;
                })
                .map((m) => ({
                  metalParentId:       m.metalId!,
                  metalParentName:     commercialMetalNames.get(m.metalId!) ?? m.metalId!,
                  // Passthrough estricto del campo canónico del motor.
                  appliedGramsPerUnit: m.gramsFineEquivalent as number,
                  quotePriceSnapshot:  m.unitValue ?? null,
                  // CON MARGEN — precio por gramo comercial (referenceValue).
                  metalReferenceValue: commercialMetalRefValues.get(m.metalId!) ?? null,
                })),
            };
          }),
        )
      : { metalsByParent: [], metalValuationSum: 0, gramsPureByParentByLineIdx: new Map<string, Map<number, number>>() };

  const documentTotals = computeSaleDocumentTotals({
    lines: resolvedLines.map((l): SaleDocumentTotalsLineInput => {
      const mhb = (l as any).metalHechuraBreakdown ?? null;
      const q   = l.quantity || 1;
      return {
        quantity:      l.quantity,
        basePrice:     l.basePrice ?? l.unitPrice ?? 0,
        unitPrice:     l.unitPrice ?? 0,
        lineTotal:     l.lineTotal ?? 0,
        lineTaxAmount: l.lineTaxAmount,
        // POLICY §Tax.3 — porción FIXED. `l.taxBreakdown` ya viene per-line
        // (× qty) desde el armado del preview (ver línea ~3687), entonces
        // sumamos directo sin multiplicar.
        lineTaxAmountFixed: sumFixedTaxComponent((l as any).taxBreakdown),
        ...(mhb
          ? {
              metalCost:            Math.round(Number(mhb.metalCost   ?? 0) * q * 100) / 100,
              hechuraCost:          Math.round(Number(mhb.hechuraCost ?? 0) * q * 100) / 100,
              metalSale:            Math.round(Number(mhb.metalSale   ?? 0) * q * 100) / 100,
              hechuraSale:          Math.round(Number(mhb.hechuraSale ?? 0) * q * 100) / 100,
              metalSaleEstimated:   mhb.metalSaleEstimated   ?? false,
              hechuraSaleEstimated: mhb.hechuraSaleEstimated ?? false,
            }
          : {}),
      };
    }),
    channel: channelAdjInput,
    coupon:  couponInputForTotals,
    paymentAdjustmentAmount,
    // Sprint 3 — capa 10 del orden inmutable. Si el frontend manda `shipping`
    // crudo, lo resolvemos acá (POLICY.md §5). `shippingAmount` legacy queda
    // como fallback hasta que todos los clientes migren.
    shippingAmount:       input.shipping
      ? (resolveShippingAmount(input.shipping)?.amount ?? 0)
      : (input.shippingAmount ?? 0),
    globalDiscountAmount: resolvedGlobalDiscountAmount,
    // POLICY §R-Rounding-1 capa 11 — delta del rounding deferred de lista.
    // El motor lo aplica al `total` final solo si NO hay política de
    // comprobante activa (docRoundingActive descarta este valor).
    roundingAdjustment:   docRoundingAdjustmentPreEngine,
    documentRounding:     docRoundingPolicy.documentRounding,
    // Etapa D' — Redondeo Comercial PER_DOCUMENT (POLICY §R-Rounding-15).
    // `null` cuando PER_LINE_LEGACY o MIXED_LIST_FALLBACK → la capa no actúa
    // (back-compat total). Cuando PER_DOCUMENT, alimenta la capa nueva.
    commercialDocumentRounding:             commercialDocCtx.commercialDocumentRounding,
    metalsByParentForCommercialRounding:    commercialDocAggregates.metalsByParent,
    metalValuationSumForCommercialRounding: commercialDocAggregates.metalValuationSum,
  });

  // Fase 6: `documentTotals` ya expone `channelResult` y `couponResult` —
  // no más doble cómputo. Solo si el cupón vino inválido, lo emitimos como
  // `applied=false` para que el frontend reciba el motivo.
  const channelResult = documentTotals.channelResult;
  let couponResult: CouponAdjustmentResult = documentTotals.couponResult;
  if (!couponInputForTotals && couponInvalidEcho) {
    couponResult = {
      baseAmount:     channelResult.finalAmount,
      discountAmount: 0,
      finalAmount:    channelResult.finalAmount,
      couponId:       couponInvalidEcho.id,
      couponCode:     couponInvalidEcho.code,
      couponName:     couponInvalidEcho.name,
      discountType:   couponInvalidEcho.type,
      discountValue:  0,
      applied:        false,
      reason:         couponInvalidReason,
    };
  }

  // ── Resumen de redondeo a nivel documento ─────────────────────────────────
  // Suma el `unitAdjustment × qty` de cada línea para que la UI muestre
  // "Redondeo por lista: …" sin tener que recorrer las líneas.
  // Si NINGUNA línea tuvo redondeo aplicado, el campo es null y la UI lo
  // pinta como "Sin redondeo".
  let docRoundingAdjustment = 0;
  let docRoundingInfo: {
    source:        "PRICE_LIST";
    priceListId:   string | null;
    priceListName: string | null;
    applyOn:       string;
    mode:          string;
    direction:     string;
  } | null = null;
  for (const l of resolvedLines) {
    const ar = (l as any).appliedRounding;
    if (!ar) continue;
    docRoundingAdjustment += (ar.unitAdjustment ?? 0) * (l.quantity ?? 1);
    if (!docRoundingInfo) {
      docRoundingInfo = {
        source:        ar.source,
        priceListId:   ar.priceListId,
        priceListName: ar.priceListName,
        applyOn:       ar.applyOn,
        mode:          ar.mode,
        direction:     ar.direction,
      };
    }
  }
  docRoundingAdjustment = Math.round(docRoundingAdjustment * 100) / 100;

  // ── Fase 2A.7 — consolidación doc-level de la lista de precios ─────────
  // Si todas las líneas usaron la misma lista → ese id/nombre. Si difieren →
  // "MIXED" + nombre "Múltiples". Si ninguna resolvió lista → null.
  const distinctAppliedPriceListIds = new Set<string>();
  let firstAppliedName: string | null = null;
  for (const l of resolvedLines) {
    if (l.appliedPriceListId) {
      distinctAppliedPriceListIds.add(l.appliedPriceListId);
      if (!firstAppliedName) firstAppliedName = l.appliedPriceListName ?? null;
    }
  }
  let consolidatedPriceListId:   string | null = null;
  let consolidatedPriceListName: string | null = null;
  if (distinctAppliedPriceListIds.size === 1) {
    consolidatedPriceListId   = [...distinctAppliedPriceListIds][0]!;
    consolidatedPriceListName = firstAppliedName;
  } else if (distinctAppliedPriceListIds.size > 1) {
    consolidatedPriceListId   = "MIXED";
    consolidatedPriceListName = "Múltiples";
  }

  // `priceListWasOverridden`: true si el operador pidió override (a nivel
  // documento o en alguna línea), independientemente de si el motor pudo
  // respetarlo (lista vencida, sin permiso, etc.).
  const lineHasOverride = resolvedLines.some(
    (l) => !!(l as any).priceListIdOverride && (l as any).priceListIdOverride !== input.priceListId,
  );
  const priceListWasOverridden =
    !!input.priceListId || lineHasOverride;

  // `clientCommercialRules` — null si no hay cliente.
  const clientCommercialRules: SalePreviewClientCommercialRules | null = clientRow
    ? {
        ruleType:  clientRow.commercialRuleType  ?? null,
        valueType: clientRow.commercialValueType ?? null,
        value:     clientRow.commercialValue != null
          ? parseFloat(clientRow.commercialValue.toString())
          : null,
        applyOn:   clientRow.commercialApplyOn ?? null,
      }
    : null;

  // ── T55 (Fase 3B.5) — Balance Mode resolución + breakdown ──────────────
  // Resolución R11.4 (POLICY.md §11):
  //   1. documentOverride (input.balanceModeOverride)
  //   2. entityDefault (clientRow.balanceMode ?? legacy balanceType)
  //   3. priceListDefault (PriceList.balanceMode si hay una única lista)
  //   4. tenantDefault (Jewelry.defaultBalanceMode)
  //   5. fallback UNIFIED
  //
  // El frontend NO resuelve — solo manda `balanceModeOverride` si el operador
  // lo seteó. Toda la prioridad se evalúa acá.
  //
  // Para BREAKDOWN: necesitamos el detalle por metal padre. Cargamos los
  // nombres en batch desde Metal + MetalVariant — query única.
  const balanceModeOverrideInput: BalanceMode | null =
    input.balanceModeOverride === "UNIFIED" || input.balanceModeOverride === "BREAKDOWN"
      ? input.balanceModeOverride
      : null;
  // Lista única → leemos su `balanceMode`. Si MIXED o ninguna, queda null.
  // Defensive: tests pueden mockear `prisma` parcialmente y omitir
  // `priceList.findFirst`/`jewelry.findUnique`. En esos casos caemos a null
  // y la resolución termina en FALLBACK_UNIFIED — comportamiento legacy
  // exacto. Runtime real siempre tiene el cliente completo.
  let priceListBalanceModeDefault: BalanceMode | null = null;
  let priceListModeForResolver:    string       | null = null;
  if (
    consolidatedPriceListId &&
    consolidatedPriceListId !== "MIXED"
  ) {
    try {
      const pl = await prisma.priceList.findFirst({
        where:  { id: consolidatedPriceListId, jewelryId, deletedAt: null },
        select: { balanceMode: true, mode: true },
      });
      priceListBalanceModeDefault = (pl?.balanceMode ?? null) as BalanceMode | null;
      priceListModeForResolver    = (pl?.mode        ?? null) as string       | null;
    } catch { /* defensive — tests con prisma parcial */ }
  }
  // Tenant default (Jewelry.defaultBalanceMode). Cargamos sólo el campo.
  let tenantBalanceModeDefault: BalanceMode | null = null;
  try {
    const tenantRow = await prisma.jewelry.findUnique({
      where:  { id: jewelryId },
      select: { defaultBalanceMode: true },
    });
    tenantBalanceModeDefault = (tenantRow?.defaultBalanceMode ?? null) as BalanceMode | null;
  } catch { /* defensive — tests con prisma parcial */ }

  const balanceModeResolution = resolveSaleBalanceMode({
    documentOverride:        balanceModeOverrideInput,
    entityBalanceMode:       (clientRow as any)?.balanceMode ?? null,
    entityBalanceTypeLegacy: clientRow?.balanceType ?? null,
    priceListDefault:        priceListBalanceModeDefault,
    priceListMode:           priceListModeForResolver,
    tenantDefault:           tenantBalanceModeDefault,
  });

  // Mapas de nombres de metal (cargados sólo si BREAKDOWN y hay items).
  let metalNamesMap:   Map<string, string> | undefined;
  let variantNamesMap: Map<string, string> | undefined;
  if (balanceModeResolution.mode === "BREAKDOWN") {
    const metalIds   = new Set<string>();
    const variantIds = new Set<string>();
    // Opción A — recolectar metalIds desde los STEPS (fuente real) y, como
    // back-compat, también desde el breakdown legacy si trajera items.
    for (const steps of lineCostStepsByIdx.values()) {
      for (const s of steps) {
        if (!s || s.key !== "COST_LINES_METAL" || s.status !== "ok") continue;
        const meta = s.meta ?? {};
        if (typeof meta.metalId   === "string" && meta.metalId)   metalIds.add(meta.metalId);
        if (typeof meta.variantId === "string" && meta.variantId) variantIds.add(meta.variantId);
      }
    }
    for (const bd of lineCostBreakdownsByIdx.values()) {
      for (const it of (bd?.metal?.items ?? [])) {
        if (it.metalId)   metalIds.add(it.metalId);
        if (it.variantId) variantIds.add(it.variantId);
      }
    }
    if (metalIds.size > 0) {
      try {
        const metals = await prisma.metal.findMany({
          where: { id: { in: [...metalIds] }, jewelryId },
          select: { id: true, name: true },
        });
        metalNamesMap = new Map(metals.map((m) => [m.id, m.name]));
      } catch { /* defensive */ }
    }
    if (variantIds.size > 0) {
      try {
        const variants = await prisma.metalVariant.findMany({
          where: { id: { in: [...variantIds] } },
          select: { id: true, name: true },
        });
        variantNamesMap = new Map(variants.map((v) => [v.id, v.name]));
      } catch { /* defensive */ }
    }
  }

  // Proyección a `SaleLineForBalance[]`. Cada `resolvedLine` aporta sus
  // items metálicos por unidad (extraídos de `costResult.steps[]`) + la
  // valuación monetaria de la línea (= metalSale × quantity del motor).
  //
  // Opción A (fix balance metals): la fuente canónica de los metales son los
  // STEPS `COST_LINES_METAL` del motor cost (post `enrichCostMetalSteps`).
  // El `breakdown.metal.items[]` queda como fallback histórico — el motor
  // nunca lo popula en runtime, pero snapshots viejos sí lo tienen.
  const linesForBalance: SaleLineForBalance[] = resolvedLines.map(
    (l, idx): SaleLineForBalance => {
      const bd    = lineCostBreakdownsByIdx.get(idx) ?? null;
      const steps = lineCostStepsByIdx.get(idx) ?? null;
      const mh    = (l as any).metalHechuraBreakdown ?? null;
      const qty   = l.quantity || 1;
      // Valuación METAL de la línea en moneda del DOCUMENTO (= metalSale × qty).
      // El motor expone `metalHechuraBreakdown.metalSale` por unidad.
      const metalLineValuationDocCurrency = mh?.metalSale != null
        ? Math.round(Number(mh.metalSale) * qty * 100) / 100
        : null;
      // Fuente primaria: STEPS del motor. Fallback: breakdown legacy (en
      // caso de snapshots históricos cuando algún día se reconstruyan).
      const fromSteps = extractMetalItemsFromSteps(steps);
      const metalItems =
        fromSteps.length > 0
          ? fromSteps
          : (bd?.metal?.items
              ? bd.metal.items.map((it: any) => ({
                  metalId:       it.metalId       ?? null,
                  variantId:     it.variantId     ?? null,
                  gramsOriginal: it.gramsOriginal ?? null,
                  purity:        it.purity        ?? null,
                  gramsPure:     it.gramsPure     ?? null,
                  unitValue:     it.unitValue     ?? null,
                }))
              : undefined);
      return {
        lineId:   (l as any).articleId ?? `idx-${idx}`,
        quantity: qty,
        metalItems,
        metalLineValuationDocCurrency,
      };
    },
  );

  // Construcción del breakdown canónico. `documentTotal`/`documentTotalBase`
  // en MONEDA BASE acá (el response se convierte después con
  // `convertSalesPreviewResponseInPlace`). La moneda del documento la fijamos
  // como BASE por ahora; cuando la conversión final corra, los campos del
  // breakdown se convertirán junto con el resto (si pricing-currency-display
  // los soporta — TODO 3B.7).
  // Componentes monetarios doc-level (display-only) — passthrough del motor.
  // Cero matemática nueva: cada amount sale de un campo de `documentTotals`.
  const documentMonetaryComponents = buildDocumentMonetaryComponentsFromTotals({
    totals: {
      hechuraSaleSubtotal:     documentTotals.hechuraSaleSubtotal,
      lineDiscountAmount:      documentTotals.lineDiscountAmount,
      channelAdjustmentAmount: documentTotals.channelAdjustmentAmount,
      couponDiscountAmount:    documentTotals.couponDiscountAmount,
      globalDiscountAmount:    documentTotals.globalDiscountAmount,
      paymentAdjustmentAmount: documentTotals.paymentAdjustmentAmount,
      shippingAmount:          documentTotals.shippingAmount,
      taxAmount:                documentTotals.taxAmount,
      // `documentTotals.roundingAdjustment` puede venir 0 si el redondeo
      // está absorbido por las líneas; en ese caso usamos `docRoundingAdjustment`
      // (suma de `unitAdjustment × qty` ya calculada arriba).
      roundingAdjustment:      docRoundingPolicy.documentRounding
        ? documentTotals.roundingAdjustment
        : docRoundingAdjustment,
    },
    channelLabel:  channelResult?.channelName ?? null,
    channelSource: channelResult?.channelId   ?? null,
    couponLabel:   couponResult?.couponName   ?? null,
    couponSource:  couponResult?.couponId     ?? null,
  });

  const balanceBreakdown: DocumentBalanceBreakdown = buildSaleBalanceBreakdown({
    mode:              balanceModeResolution.mode,
    documentTotal:     documentTotals.total,
    documentTotalBase: documentTotals.total,
    currency: {
      code: "",     // base — el code real se setea en convert*InPlace si aplica
      rate: 1,
    },
    lines: linesForBalance,
    metalNames:   metalNamesMap,
    variantNames: variantNamesMap,
    documentMonetaryComponents,
  });

  // ── Etapa D3 — Capa 16: REDONDEO FÍSICO DE GRAMOS (POLICY §R-Rounding-13) ─
  // Si el tenant operó `documentRoundingMetalDomain="PHYSICAL"` y hay config
  // válida, el helper:
  //   · Redondea los gramos por metal padre (usa D1).
  //   · Suma el equivalente monetario al `documentTotals.total`.
  //   · Muta `balanceBreakdown.metals[i].gramsPure` con los post-grams para
  //     que el ajuste manual posterior vea `preGrams = postGrams capa 16`.
  //   · Reescribe `documentTotals.documentRoundingApplied` agregando
  //     `breakdown.metalPhysical` + `breakdown.metalDomain="PHYSICAL"` y
  //     limpia `breakdown.metal` (anti doble redondeo).
  //   · Agrega bloque universal `totals` (monetaryRoundingAdjustment +
  //     metalMonetaryEquivalent + totalRoundingAdjustment) — también en
  //     MONETARY como passthrough informativo.
  //
  // Si `metalDomain=MONETARY` o no hay config: comportamiento idéntico al
  // pre-D3 (helper queda en passthrough decorativo).
  applyDocumentPhysicalRounding({
    documentTotals,
    balanceBreakdown,
    policy: docRoundingPolicy,
  });

  // ── Etapa D' (cierre conceptual) — Vista del Redondeo Comercial por línea
  //
  // IMPORTANTE — naturaleza del campo (ver JSDoc de
  // `SalePreviewLine.commercialRoundingContext`):
  //   · NO es un redondeo PROPIO de la línea.
  //   · NO implica que el cálculo se haya ejecutado sobre esta línea.
  //   · Es una REPLICACIÓN VISUAL del snapshot del documento (calculado UNA
  //     sola vez a nivel comprobante por `computeSaleDocumentTotals`) para
  //     que el card del artículo lo muestre como cierre de su cadena
  //     comercial sin tener que mirar el response del documento entero.
  //
  // Permite al card (`PricingStepsBreakdown.RoundingTaxSection`) renderizar
  // el bloque sin que el frontend tenga que contar líneas ni inferir el
  // scope. Passthrough puro — cero matemática nueva.
  //
  // REGLA DE ORO: backend calcula, frontend renderiza. El conteo
  // `appliedToLineCount` lo hace el backend; el frontend SOLO lee.
  if (documentTotals.commercialDocumentRoundingApplied) {
    const ctxBase = documentTotals.commercialDocumentRoundingApplied;
    const ctx = {
      ...ctxBase,
      appliedAt:          "DOCUMENT" as const,
      appliedToLineCount: resolvedLines.length,
    };
    for (const line of resolvedLines) {
      (line as any).commercialRoundingContext = ctx;
    }

    // ── Opción A (R-COMMERCIAL-METAL-VISIBLE + MONETARIO POST) ────────────
    // Distribución del impacto $ del redondeo PER_DOCUMENT a cada línea:
    //   · METAL   → proporcional a gramsPure aportado por la línea.
    //   · HECHURA → proporcional a `hechuraSale × qty` aportado por la línea.
    // Conservación exacta a 2 decimales:
    //   Σ metalImpact   = Σ breakdown.metals[*].monetaryEquivalent
    //   Σ hechuraImpact = breakdown.hechura.deltaSaldoMonetario
    //
    // Con eso el backend compone el TOTAL LÍNEA C/ IMP. POST-redondeo comercial
    // (campo NUEVO, NO muta `lineTotalWithTax` para no romper el total del
    // documento que lo suma — anti doble conteo):
    //   lineTotalWithTaxPostCommercialRounding
    //     = lineTotalWithTax + metalImpact + hechuraImpact
    //
    // El frontend renderiza (cero matemática FE):
    //   METAL Comercial post     = Σ metalSale + metalImpact
    //   MONETARIO Comercial post = totalPost − METAL Comercial post
    //   TOTAL LÍNEA post         = lineTotalWithTaxPostCommercialRounding
    const hechuraSaleByLineIdx = new Map<number, number>();
    for (let i = 0; i < resolvedLines.length; i++) {
      const mhb = (resolvedLines[i] as any).metalHechuraBreakdown ?? null;
      const q   = resolvedLines[i].quantity || 1;
      hechuraSaleByLineIdx.set(
        i,
        mhb ? Math.round(Number(mhb.hechuraSale ?? 0) * q * 100) / 100 : 0,
      );
    }
    const impactsByLineIdx = computeCommercialRoundingPerLineImpacts({
      breakdown:                  (ctxBase as any)?.breakdown,
      gramsPureByParentByLineIdx: commercialDocAggregates.gramsPureByParentByLineIdx,
      hechuraSaleByLineIdx,
      lineCount:                  resolvedLines.length,
    });
    for (let i = 0; i < resolvedLines.length; i++) {
      const imp = impactsByLineIdx.get(i) ?? { metalImpact: 0, hechuraImpact: 0, monetarySaldoPost: null };
      (resolvedLines[i] as any).metalRoundingMonetaryImpact   = imp.metalImpact;
      (resolvedLines[i] as any).hechuraRoundingMonetaryImpact = imp.hechuraImpact;
      // Descomposición FÍSICA — saldo monetario POST por línea (lo que muestra
      // el bloque MONETARIO del Resumen: ej. 185.500). `null` ⇒ FE cae al
      // MONETARIO comercial (hechura con margen).
      (resolvedLines[i] as any).lineMonetarySaldoPostCommercialRounding = imp.monetarySaldoPost;
      const pre = resolvedLines[i].lineTotalWithTax;
      (resolvedLines[i] as any).lineTotalWithTaxPostCommercialRounding =
        typeof pre === "number" && Number.isFinite(pre)
          ? Math.round((pre + imp.metalImpact + imp.hechuraImpact) * 100) / 100
          : pre;
    }

    // ── Gramos comerciales PER-LÍNEA (fix "Resumen mezcla líneas") ─────────
    // El card del artículo debe mostrar SOLO los gramos de SU línea. Antes leía
    // `commercialRoundingContext.breakdown.metalsPostGrams` (agregado del
    // documento) → al sumar una 2.ª línea, la 1.ª mostraba el total acumulado.
    // Acá calculamos los gramos POST por línea con la MISMA fórmula SSOT pero
    // con el gramsPure y el margen de cada línea (immune a otras líneas).
    // Display-only: NO toca dinero/saldo/total (esos campos quedan intactos).
    if (commercialDocCtx.commercialDocumentRounding?.scope === "BREAKDOWN") {
      const metalCfg = commercialDocCtx.commercialDocumentRounding.metal;
      const metalNameById = new Map<string, string>(
        commercialDocAggregates.metalsByParent.map((m) => [m.metalParentId, m.metalParentName]),
      );
      // Factor de margen de la PROPIA línea = metalSale_línea / metalCost_línea.
      const marginFactorByLineIdx = new Map<number, number>();
      for (let i = 0; i < resolvedLines.length; i++) {
        const mhb = (resolvedLines[i] as any).metalHechuraBreakdown ?? null;
        const cost = mhb ? Number(mhb.metalCost ?? 0) : 0;
        const sale = mhb ? Number(mhb.metalSale ?? 0) : 0;
        marginFactorByLineIdx.set(i, cost > 0 ? sale / cost : 1);
      }
      // Valor comercial por gramo por padre (para monetizar el delta de gramos).
      const refValueByParent = new Map<string, number>(
        commercialDocAggregates.metalsByParent.map((m) => [
          m.metalParentId,
          (typeof m.metalReferenceValue === "number" && m.metalReferenceValue > 0)
            ? m.metalReferenceValue
            : m.metalPricePerGram,
        ]),
      );
      const lineMetalsByIdx = computeLineCommercialRoundingMetals({
        gramsPureByParentByLineIdx: commercialDocAggregates.gramsPureByParentByLineIdx,
        metalNameById,
        refValueByParent,
        marginFactorByLineIdx,
        metalCfg,
        lineCount: resolvedLines.length,
      });
      for (let i = 0; i < resolvedLines.length; i++) {
        (resolvedLines[i] as any).lineCommercialRoundingMetals = lineMetalsByIdx.get(i) ?? [];
      }

      // ── Opción B (LINE-AUTONOMOUS) — dinero comercial POR LÍNEA ──────────
      // Reemplaza el reparto del agregado del documento por el redondeo del
      // saldo/gramos PROPIOS de cada línea → agregar/quitar otra línea NO
      // altera estos 4 campos. El total del comprobante sigue siendo
      // PER_DOCUMENT (el motor NO suma estos campos; son display del card).
      const hechuraCfg = commercialDocCtx.commercialDocumentRounding.hechura;
      const lineTotalWithTaxByIdx = new Map<number, number>();
      const metalSaleSumByIdx     = new Map<number, number>();
      for (let i = 0; i < resolvedLines.length; i++) {
        const mhb = (resolvedLines[i] as any).metalHechuraBreakdown ?? null;
        const q   = resolvedLines[i].quantity || 1;
        const ltw = resolvedLines[i].lineTotalWithTax;
        lineTotalWithTaxByIdx.set(i, typeof ltw === "number" && Number.isFinite(ltw) ? ltw : 0);
        // metalSaleSum = misma base que `metalSaleSubtotal` del documento
        // (mhb.metalSale per-unit × qty, round2) → invariante del card exacto.
        metalSaleSumByIdx.set(i, mhb ? Math.round(Number(mhb.metalSale ?? 0) * q * 100) / 100 : 0);
      }
      const moneyByIdx = computeLineAutonomousCommercialMoney({
        lineCommercialRoundingMetals: lineMetalsByIdx,
        refValueByParent,
        lineTotalWithTaxByIdx,
        metalSaleSumByIdx,
        hechuraCfg,
        lineCount: resolvedLines.length,
      });
      for (let i = 0; i < resolvedLines.length; i++) {
        const m = moneyByIdx.get(i);
        if (!m) continue;
        (resolvedLines[i] as any).metalRoundingMonetaryImpact             = m.metalRoundingMonetaryImpact;
        (resolvedLines[i] as any).hechuraRoundingMonetaryImpact           = m.hechuraRoundingMonetaryImpact;
        (resolvedLines[i] as any).lineMonetarySaldoPreCommercialRounding  = m.lineMonetarySaldoPreCommercialRounding;
        (resolvedLines[i] as any).lineMonetarySaldoPostCommercialRounding = m.lineMonetarySaldoPostCommercialRounding;
        (resolvedLines[i] as any).lineTotalWithTaxPostCommercialRounding  = m.lineTotalWithTaxPostCommercialRounding;
      }
    } else {
      for (const line of resolvedLines) {
        (line as any).lineCommercialRoundingMetals = null;
      }
    }
  } else {
    // Sin Redondeo Comercial PER_DOCUMENT → el post ES el pre (no hay impacto).
    for (const line of resolvedLines) {
      (line as any).commercialRoundingContext              = null;
      (line as any).metalRoundingMonetaryImpact            = null;
      (line as any).hechuraRoundingMonetaryImpact          = null;
      (line as any).lineMonetarySaldoPreCommercialRounding  = null;
      (line as any).lineMonetarySaldoPostCommercialRounding = null;
      (line as any).lineTotalWithTaxPostCommercialRounding = line.lineTotalWithTax ?? null;
      (line as any).lineCommercialRoundingMetals           = null;
    }
  }

  // Armado del response — todo en moneda BASE del tenant. La conversión a la
  // moneda elegida (Fase MM) se aplica al final con `convertSalesPreviewResponseInPlace`.
  const responsePayload: SalePreviewResult & Record<string, unknown> = {
    lines:           resolvedLines,
    subtotal:        documentTotals.subtotalAfterLineDiscounts,
    channelResult,
    couponResult,
    checkoutResult,
    total:           documentTotals.total,
    // ── Fase 3B.5 — Balance Mode (POLICY.md §11) ────────────────────────
    balanceMode:       balanceModeResolution.mode,
    balanceModeSource: balanceModeResolution.source,
    balanceBreakdown,
    documentTotals: {
      ...documentTotals,
      // Cuando la política doc está activa, el motor ya popula
      // `roundingAdjustment` con el delta real del redondeo a nivel
      // comprobante; preservamos ese valor y reportamos `roundingInfo`
      // como TENANT_POLICY (DOC_TOTAL).
      // Cuando NO está activa, las líneas pudieron haber absorbido el
      // redondeo de la lista (NET/TOTAL). Pisamos `roundingAdjustment`
      // con el agregado de `unitAdjustment × qty` para que el frontend
      // lo vea como display delta — el `total` no cambia.
      roundingAdjustment: docRoundingPolicy.documentRounding
        ? documentTotals.roundingAdjustment
        : docRoundingAdjustment,
      roundingInfo: documentTotals.documentRoundingApplied
        ? (() => {
            // Etapa 1B — el shape cambió a discriminated union por scope.
            // Para mantener compat con consumers existentes del preview que
            // leen `mode`/`direction` planos, derivamos esos campos de la
            // capa que efectivamente actuó. Prioridad: unified (cierre
            // comercial final) > metal > hechura. Las pantallas que entiendan
            // el scope nuevo pueden leer `documentTotals.documentRoundingApplied`
            // directamente para el detalle por capa.
            const applied = documentTotals.documentRoundingApplied;
            const primary =
              applied.unified ??
              applied.breakdown?.metal ??
              applied.breakdown?.hechura;
            return {
              source:        "TENANT_POLICY" as const,
              priceListId:   null,
              priceListName: null,
              applyOn:       primary?.applyOn   ?? applied.applyOn,
              mode:          primary?.mode      ?? "NONE",
              direction:     primary?.direction ?? "NEAREST",
              // Campo nuevo opcional — los consumers viejos lo ignoran.
              scope:         applied.scope,
            };
          })()
        : docRoundingInfo,
    },
    // ── Fase 2A.7 — info doc-level ───────────────────────────────────────
    clientBalanceType:     clientRow?.balanceType ?? null,
    clientCommercialRules,
    // Metadata READ-ONLY (ya computado en PASO 4b, no recalcula): permite al
    // frontend mostrar "Exento cliente" vs "sin impuesto".
    clientTaxExempt,
    requestedPriceListId:  input.priceListId ?? null,
    appliedPriceListId:    consolidatedPriceListId,
    appliedPriceListName:  consolidatedPriceListName,
    priceListWasOverridden,
  };

  // ── Manual Adjustment (POLICY §R-Rounding-1 capa 17) ──────────────────
  // Etapa A — scope UNIFIED: amount global sobre engineTotal.
  // Etapa C — scope BREAKDOWN: ajuste por metal en gramos + hechura.
  // Helper puro: combina engineTotal + intención + (si BREAKDOWN) contexto
  // de metales/hechura → snapshot + finalTotal.
  // Cero matemática del motor; cero recálculo de impuestos.
  //
  // Gate de scope BREAKDOWN: solo válido cuando el documento opera en modo
  // BREAKDOWN. Si llega scope BREAKDOWN con balanceMode=UNIFIED, 400.
  if (input.manualAdjustment?.scope === "BREAKDOWN" && balanceModeResolution.mode !== "BREAKDOWN") {
    const e: any = new Error(
      "manualAdjustment scope=BREAKDOWN requiere que el documento opere en " +
      "modo BREAKDOWN (Balance Mode). El modo resuelto para este preview es " +
      `"${balanceModeResolution.mode}".`,
    );
    e.status = 400;
    throw e;
  }
  const breakdownContextPreview = buildManualAdjustmentBreakdownContext(balanceBreakdown);
  const manualAdjustmentPreview: ManualAdjustmentPreview = buildManualAdjustmentSnapshot({
    engineTotal: documentTotals.total,
    input:       input.manualAdjustment ?? null,
    audit: {
      appliedBy: null,
      appliedAt: new Date().toISOString(),
      reason:    input.manualAdjustment?.reason ?? null,
    },
    breakdownContext: breakdownContextPreview,
  });

  // ── Etapa 1.1/1.2 — Campos canónicos top-level (ver tipo SalePreviewResult) ──
  // Reference aliasing: `manualAdjustment` y `manualAdjustmentSnapshot` apuntan
  // al MISMO objeto snapshot, y `documentRoundingSnapshot` apunta al MISMO
  // objeto que `documentTotals.documentRoundingApplied`. El converter de moneda
  // (`convertSalesPreviewResponseInPlace`) muta cada objeto in-place una sola
  // vez por su path conocido → cero doble conversión, cero cambios al converter.
  //
  // Paridad con confirmSale: el snapshot persistido en `Sale.documentRoundingSnapshot`
  // (sales.service confirmSale §"Etapa 1B") incluye el flag de audit
  // `suppressedListDeferredRounding`. Para que preview/draft/confirm devuelvan
  // shape idéntico, lo agregamos in-place acá. Mutación segura: el spread
  // `documentTotals: { ...documentTotals }` del responsePayload es shallow → la
  // subreferencia `documentRoundingApplied` es la misma, una sola mutación
  // alcanza ambos paths (enterrado y alias top-level).
  if (documentTotals.documentRoundingApplied) {
    (documentTotals.documentRoundingApplied as any).suppressedListDeferredRounding =
      docRoundingPolicy.suppressListDeferredRounding;
  }

  responsePayload.engineTotal              = manualAdjustmentPreview.engineTotal;
  responsePayload.finalTotal               = manualAdjustmentPreview.finalTotal;
  responsePayload.manualAdjustmentSnapshot = manualAdjustmentPreview.snapshot;
  responsePayload.manualAdjustment         = manualAdjustmentPreview.snapshot; // alias @deprecated
  responsePayload.documentRoundingSnapshot = documentTotals.documentRoundingApplied ?? null;

  // ── Etapa UX-Auditable (2026-05-29) — recomputar monetary.components ─────
  // El primer call de `buildDocumentMonetaryComponentsFromTotals` corrió ANTES
  // de la capa 16 (rounding físico) y de la capa 17 (ajuste manual), por
  // necesidad de orden del pipeline. Ahora que ya están disponibles:
  //   · metalValuationSum del balance (post-capa 16, gramsPure puede haber
  //     sido mutado por applyDocumentPhysicalRounding)
  //   · manualAdjustmentSnapshot.totals.totalMonetaryAdjustment (capa 17)
  // reconstruimos la lista de components con METAL_MARGIN + MANUAL_ADJUSTMENT
  // y pisamos `balanceBreakdown.monetaryBalance.components`. Esto cierra la
  // auditabilidad: Σ components == (total − Σ valuationMonetary) = saldo
  // monetario canónico (POLICY §R-Rounding-14).
  if (balanceBreakdown.monetaryBalance && balanceModeResolution.mode === "BREAKDOWN") {
    const metalValuationSumPost = (balanceBreakdown.metals ?? []).reduce(
      (acc, m) =>
        acc + (typeof m.valuationMonetary === "number" && Number.isFinite(m.valuationMonetary)
          ? m.valuationMonetary
          : 0),
      0,
    );
    const manualAdjMonetary =
      manualAdjustmentPreview.snapshot?.totals?.totalMonetaryAdjustment ?? null;
    balanceBreakdown.monetaryBalance.components = buildDocumentMonetaryComponentsFromTotals({
      totals: {
        hechuraSaleSubtotal:     documentTotals.hechuraSaleSubtotal,
        lineDiscountAmount:      documentTotals.lineDiscountAmount,
        channelAdjustmentAmount: documentTotals.channelAdjustmentAmount,
        couponDiscountAmount:    documentTotals.couponDiscountAmount,
        globalDiscountAmount:    documentTotals.globalDiscountAmount,
        paymentAdjustmentAmount: documentTotals.paymentAdjustmentAmount,
        shippingAmount:          documentTotals.shippingAmount,
        taxAmount:                documentTotals.taxAmount,
        roundingAdjustment:      docRoundingPolicy.documentRounding
          ? documentTotals.roundingAdjustment
          : docRoundingAdjustment,
        metalCostSubtotal:       documentTotals.metalCostSubtotal,
      },
      metalValuationSum:             metalValuationSumPost,
      manualAdjustmentMonetaryAmount: manualAdjMonetary,
      channelLabel:  channelResult?.channelName ?? null,
      channelSource: channelResult?.channelId   ?? null,
      couponLabel:   couponResult?.couponName   ?? null,
      couponSource:  couponResult?.couponId     ?? null,
    });
  }

  // ── Multimoneda (Fase MM) — conversión del RESPONSE base→display ─────────
  // Reusa el MISMO `currencyCtx` resuelto al inicio (no se vuelve a pedir):
  // input se convirtió display→base arriba, acá el response base→display.
  // Simetría exacta con la misma tasa. confirmSale NUNCA pasa por acá.
  if (currencyCtx?.applied) {
    convertSalesPreviewResponseInPlace(responsePayload, currencyCtx.rate);
  }
  if (currencyCtx) {
    Object.assign(responsePayload, buildResponseCurrencyMetadata(currencyCtx));
  }

  return responsePayload;
}

// =============================================================================
// PDF del comprobante — disponible para cualquier estado.
//
// Pivot funcional: ya NO bloqueamos por DRAFT / CANCELLED. La diferencia
// se hace VISUALMENTE en el PDF (watermark BORRADOR / ANULADA).
//
// Etapa 2 — Esta funcion es ahora un wrapper delgado sobre el provider
// canonico (`saleInvoicePdfProvider.renderFromPersisted`). El controller
// `sales.controller.downloadPdf` la sigue llamando con su firma actual
// para mantener back-compat de tests y rutas. Internamente, el render
// es el mismo punto unico que usa el adjunto del mail — garantizado por
// `sendSaleByEmail` mas abajo que tambien llama al provider.
// =============================================================================
export async function generateSalePdf(id: string, jewelryId: string): Promise<{ buffer: Buffer; filename: string }> {
  const sale = await getSale(id, jewelryId) as any;
  const { buffer, filename } = await renderSaleInvoicePdfFromPersisted({ sale, jewelryId });
  return { buffer, filename };
}

// =============================================================================
// Etapa 2 — Las funciones internas que armaban el PDF a partir del Sale
// persistido (`generateSalePdfFromLoadedSale`, `renderInvoicePdfBuffer`,
// `toN`) se movieron al provider canonico `saleInvoicePdfProvider.ts`.
// Buscalas alli — son las que componen `pdfSale`, eligen motor HTML vs
// pdfkit y resuelven filename adaptive por status. Esto garantiza que
// descarga, impresion y adjunto de mail compartan render byte-equivalente.
// =============================================================================

// =============================================================================
// 1.D — Envio de la factura por mail.
// =============================================================================

export interface SendSaleByEmailInput {
  to:      string;
  subject: string;
  message: string;
}

export async function sendSaleByEmail(
  id:           string,
  jewelryId:    string,
  input:        SendSaleByEmailInput,
  sentByUserId?: string | null,
): Promise<{ messagedRecipient: string; filename: string }> {
  // Pivot funcional: NO bloqueamos por estado ni por ausencia de receipt.
  const sale = await getSale(id, jewelryId) as any;

  // Etapa 2 — PDF unico canonico. El adjunto del mail usa el MISMO
  // provider que la descarga (`renderFromPersisted`). Garantia
  // byte-equivalente: si el operador descarga el PDF y despues lo
  // manda por mail, ambos archivos son identicos (mismo template, mismo
  // motor, mismo adapter, mismo filename).
  const { buffer, filename } = await renderSaleInvoicePdfFromPersisted({ sale, jewelryId });

  // Etapa 1 — SSOT del header de mail por tenant.
  // Lee `emailSenderName`, `emailReplyTo`, `email` (legacy fallback) y
  // `emailEnabled` de una sola query. Compone `From` ("Joyería X <addr>")
  // y `Reply-To` con la cadena correcta. Reutilizable por todos los
  // documentos en etapas futuras (presupuestos / ordenes / NC / remitos).
  const mailCtx = await resolveTenantMailContext(jewelryId);

  const html = `<pre style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.5;white-space:pre-wrap;margin:0;">${escapeHtmlForMail(input.message)}</pre>`;

  // E2 — envoltura para capturar messageId y errores del provider,
  // luego persistir el log documental. El log NUNCA rompe el envío
  // (createDocumentEmailLog traga errores internamente).
  let mailResult: { messageId: string | null } = { messageId: null };
  let sendError:  Error | null = null;
  try {
    mailResult = await sendMail({
      to:      input.to,
      subject: input.subject,
      html,
      text:    input.message,
      // `from` puede ser undefined (sin sender name ni MAIL_FROM) — en ese
      // caso `mail.service` cae a su default interno. Lo pasamos siempre
      // para que el provider use el header compuesto cuando hay nombre
      // de joyeria configurado ("Joyería Pérez <no-reply@tptech.local>").
      from:    mailCtx.from,
      replyTo: mailCtx.replyTo,
      attachments: [
        { filename, content: buffer, contentType: "application/pdf" },
      ],
    });
  } catch (err) {
    sendError = err instanceof Error ? err : new Error(String(err));
  }

  // E2 — Log documental inmutable. status SENT u FAILED segun el
  // resultado del provider. saleId queda como documentId Y como
  // saleId anchor para el index del historial.
  await createDocumentEmailLog({
    jewelryId,
    documentKind:       "SALE_INVOICE",
    documentId:         id,
    saleId:             id,
    recipientEmail:     input.to,
    subjectSnapshot:    input.subject,
    bodySnapshot:       input.message,
    attachmentFilename: filename,
    provider:           "postmark",
    providerMessageId:  mailResult.messageId,
    status:             sendError ? "FAILED" : "SENT",
    sentByUserId:       sentByUserId ?? null,
  });

  // Si el provider tiró, propagamos DESPUÉS del log para que el
  // operador vea el toast de error pero la auditoría quede registrada.
  if (sendError) throw sendError;

  return { messagedRecipient: input.to, filename };
}

function escapeHtmlForMail(s: string): string {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
