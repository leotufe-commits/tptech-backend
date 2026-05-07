import { prisma } from "../../lib/prisma.js";
import { Prisma } from "@prisma/client";
import {
  calculateCostFromLines,
  buildBatchCostContext,
  buildBalanceBreakdownFromPrice,
  evaluatePricingPolicy,
  resolveFinalSalePrice,
  buildPricingSnapshot,
  computeLineTaxes,
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
} from "../../lib/pricing-engine/pricing-engine.js";
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
} from "../../lib/pricing-currency-display.js";
import { getBaseCurrencyId } from "../../lib/pricing-engine/pricing-engine.currency.js";
import type { EntitySnapshot, SellerSnapshot, IssuerSnapshot, CurrencySnapshot } from "../../lib/document-snapshot.types.js";
import { calculateLineCommission } from "../../lib/seller-commission.js";
import { getCheckoutPreview } from "../payments/payments.service.js";
import { validateCoupon } from "../coupons/coupons.service.js";
import { applyMovementImpact, reverseMovementImpact } from "../../lib/stock-engine.js";
import { onSaleConfirmed } from "../../lib/document-hooks/sale.hook.js";
import { loadDocumentRoundingConfig } from "../../lib/document-rounding.js";

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
};

export type CreateSaleInput = {
  clientId?: string | null;
  sellerId?: string | null;
  warehouseId?: string | null;
  notes?: string;
  channelId?: string | null;
  couponCode?: string | null;
  lines: CreateSaleLineInput[];
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
    })),
    { clientId: body.clientId ?? null },
  );

  // ── Armar payload de líneas a persistir ──────────────────────────────────
  // Mantenemos `subtotal = suma de lineTotal` (comportamiento previo).
  // Los totales reales (canal, cupón, impuestos) se siguen calculando en
  // confirmSale(); en DRAFT se mantienen en 0 como antes.
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
    };
  });

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
      subtotal,
      discountAmount: 0,
      taxAmount: 0,
      total: subtotal,
      paidAmount: 0,
      createdById: userId || null,
      lines: { create: linesData },
    },
    select: SALE_DETAIL_SELECT,
  });

  return sale;
}

// ─── Update lines / metadata (DRAFT only) ────────────────────────────────────
export async function updateSale(
  id: string,
  jewelryId: string,
  body: Partial<CreateSaleInput> & { notes?: string }
) {
  const sale = await prisma.sale.findFirst({ where: { id, jewelryId }, select: { id: true, status: true, clientId: true } });
  if (!sale) err("Venta no encontrada.", 404);
  if (sale.status !== "DRAFT") err("Solo se pueden editar ventas en estado BORRADOR.");

  const updateData: any = {};
  if (body.clientId !== undefined) updateData.clientId = body.clientId;
  if (body.sellerId !== undefined) updateData.sellerId = body.sellerId;
  if (body.warehouseId !== undefined) updateData.warehouseId = body.warehouseId;
  if (body.notes !== undefined) updateData.notes = body.notes;

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
      })),
      { clientId: effectiveClientId },
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
      };
    });

    updateData.subtotal = subtotal;
    updateData.total = subtotal;
    updateData.lines = { deleteMany: { saleId: id }, create: linesData };
  }

  await prisma.sale.update({ where: { id }, data: updateData });
  return getSale(id, jewelryId);
}

// ─── Confirm (DRAFT → CONFIRMED, descuenta stock) ────────────────────────────
export async function confirmSale(
  id: string,
  jewelryId: string,
  userId: string
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
      client: {
        select: {
          id: true, displayName: true, code: true,
          documentType: true, documentNumber: true, ivaCondition: true,
          email: true, phone: true,
          balanceType: true, taxExempt: true, taxApplyOnOverride: true,
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
          type: true, label: true, quantity: true, unitValue: true, currencyId: true,
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
    lineTotal:       Prisma.Decimal;
    /** Datos para `computeSaleDocumentTotals`. null cuando la línea no
     *  participa del cálculo (ej. artCost no encontrado). */
    documentLine:    SaleDocumentTotalsLineInput | null;
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
      const costResult = await calculateCostFromLines(
        jewelryId,
        (artCost as any).costComposition as CostLineInput[],
        {
          kind:  (artCost as any).manualAdjustmentKind,
          type:  (artCost as any).manualAdjustmentType,
          value: (artCost as any).manualAdjustmentValue,
        },
        batchCostCtx,
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

      return {
        lineId:          line.id,
        lineTaxAmtTotal: lineTaxAmt * qty,
        commission:      lineComm,
        updateData,
        breakdownSnapshot: hasCost ? (costResult.breakdown ?? null) : null,
        lineTotal:         lineTotalDec,
        documentLine: {
          quantity:      qty,
          basePrice:     basePriceNum,
          unitPrice:     unitPriceNum,
          lineTotal:     parseFloat(lineTotalDec.toString()),
          lineTaxAmount: lineTaxAmt * qty,
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

  const documentTotals = computeSaleDocumentTotals({
    lines:   documentLineInputs,
    channel: confirmChannelInput,
    coupon:  confirmCouponInput,
    // Fase 3: confirmSale aún no recibe pago / envío / descuento global del
    // documento. Pasan en 0 y se documenta en TODOs.
    paymentAdjustmentAmount: 0,
    shippingAmount:          0,
    globalDiscountAmount:    0,
    roundingAdjustment:      0,
    documentRounding:        docRoundingPolicy.documentRounding,
  });

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
    await tx.sale.update({
      where: { id },
      data: {
        status:          "CONFIRMED",
        confirmedAt:     new Date(),
        confirmedById:   userId || null,
        subtotal:        documentTotals.subtotalAfterLineDiscounts,
        taxAmount:       documentTotals.taxAmount,
        discountAmount:  documentTotals.legacyCouponOnlyDiscount,
        total:           documentTotals.total,
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
      } as any,
    });

    // 6. Emitir comprobante + cuenta corriente (Fase 5).
    //    El hook corre DENTRO de esta misma transacción — si algo falla,
    //    Postgres revierte el sale.update, el stockMovement y el receipt juntos.
    hookResult = await onSaleConfirmed(tx, id, {
      issueInvoice: true,
      issuedById:   userId || null,
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
    select: { id: true, status: true, stockMovementId: true, componentMovementId: true, clientId: true },
  });

  if (!sale) err("Venta no encontrada.", 404);
  if (sale.status === "CANCELLED") err("La venta ya está anulada.");

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

    // 2. Anular balance entries de cuenta corriente del cliente
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
};

export type DraftSaleLineOpts = {
  clientId?: string | null;
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
        suppressListDeferredRounding,
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
      const pricingSnapshot = buildPricingSnapshot(result, { composition });

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

  return { snapshot: buildPricingSnapshot(result), recomputed: true };
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
  /** Override manual de descuento por línea. */
  manualDiscountOverride?: {
    mode:      "PERCENT" | "AMOUNT";
    value:     number;
    appliesTo?: "METAL" | "HECHURA" | "PRODUCT" | "SERVICE" | "TOTAL";
  } | null;
  /** Override manual de impuesto por línea. Reemplaza el tax automático. */
  taxOverride?: {
    mode:      "PERCENT" | "AMOUNT";
    value:     number;
    appliesTo?: "METAL" | "HECHURA" | "PRODUCT" | "SERVICE" | "TOTAL";
  } | null;
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
  costPartial:          boolean;
  costMode:             string;

  // ── Política ─────────────────────────────────────────────────────────────
  policy: {
    canConfirm:     boolean;
    blockingAlerts: string[];
  };

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
    applyOn:       "PRICE" | "NET" | "TOTAL";
    mode:          string;
    direction:     string;
    preRounding:   number;     // valor por unidad antes del redondeo
    postRounding:  number;     // valor por unidad después del redondeo
    unitAdjustment: number;    // postRounding − preRounding (per unit)
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
};

export async function previewSale(
  jewelryId: string,
  input: SalePreviewInput,
): Promise<SalePreviewResult> {
  const { lines, clientId, paymentMethodId, installmentsQty = 0 } = input;

  // ── Política de redondeo a nivel comprobante (UNIFIED) ──────────────────
  // Se carga una sola vez al inicio del preview y se reutiliza para todas
  // las llamadas a resolveFinalSalePrice y para computeSaleDocumentTotals.
  const docRoundingPolicy = await loadDocumentRoundingConfig(jewelryId);

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
              type: true, label: true, quantity: true, unitValue: true, currencyId: true,
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

  // ── Resolver cada línea: precio + costo + impuestos ─────────────────────
  const resolvedLines = await Promise.all(
    lines.map(async (line): Promise<SalePreviewLine> => {
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
        // Aplicar bonificación manual.
        let unitPriceN = basePriceN;
        const md = line.manualDiscountOverride ?? null;
        if (md && Number.isFinite(md.value) && md.value >= 0) {
          const discAmt = md.mode === "PERCENT"
            ? (basePriceN * md.value) / 100
            : md.value;
          unitPriceN = Math.max(0, basePriceN - discAmt);
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
        // Fase 2A.7 — override de lista por línea (toma precedencia).
        priceListIdOverride:    effectivePriceListOverride,
        // Fase 3B — overrides de composición de costo por línea. El motor
        // ya los respetaba para `articles/pricing-preview`; ahora también
        // viajan en el endpoint `sales/preview` para edición desde Factura.
        gramsOverride:          line.gramsOverride          ?? null,
        mermaPercentOverride:   line.mermaPercentOverride   ?? null,
        metalVariantIdOverride: line.metalVariantIdOverride ?? null,
        hechuraOverrideAmount:  line.hechuraOverrideAmount  ?? null,
        // Anti doble redondeo: si el tenant tiene redondeo doc activo, el
        // motor IGNORA el redondeo diferido (NET/TOTAL) de la lista.
        suppressListDeferredRounding: docRoundingPolicy.suppressListDeferredRounding,
      });

      const n2 = (v: any) =>
        v != null && typeof v === "object" && "toNumber" in v
          ? (v as any).toNumber()
          : v != null ? parseFloat(String(v)) : null;

      const unitPrice = n2(pricing.unitPrice);
      const basePrice = n2(pricing.basePrice);

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
      if (unitPrice != null && art && !clientTaxExempt) {
        const taxIds: string[] = ((art as any).manualTaxIds ?? []) as string[];
        if (taxIds.length > 0) {
          const unitPriceDec = new Prisma.Decimal(unitPrice);
          const basePriceDec = new Prisma.Decimal(basePrice ?? unitPrice);
          const mhForTax = pricing.metalHechuraBreakdown
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
      const lineTaxAmount    = round2(unitTaxAmount * line.quantity);
      const lineTotal        = unitPrice != null ? round2(unitPrice * line.quantity)         : null;
      const lineTotalWithTax = lineTotal != null ? round2(lineTotal + lineTaxAmount)         : null;
      const lineDiscount =
        basePrice != null && unitPrice != null
          ? Math.max(0, round2((basePrice - unitPrice) * line.quantity))
          : 0;

      const mh = pricing.metalHechuraBreakdown
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

      // Snapshot reusable — lo mismo que createSale persiste en DRAFT.
      // F1.3 G4.x #5b — pasamos `composition` para que viaje en el snapshot
      // (igual al de DRAFT). El motor ya provee componentSaleBreakdown.
      const pricingSnapshotForLine = buildPricingSnapshot(pricing, { composition });
      // El snapshot del motor ya trae `totalWithTax` UNITARIO REDONDEADO
      // (preservando applyRounding cuando la lista aplica `applyOn=TOTAL`).
      // NO pisarlo: antes lo reescribíamos como `unitPrice + unitTaxAmount`
      // y perdíamos el redondeo. Solo sincronizamos `taxAmount` con el
      // cálculo local de previewSale (ya consistente con el motor).
      pricingSnapshotForLine.taxAmount = unitTaxAmount;

      // Fase 2A.7 — paridad con `articles/pricing-preview`.
      // 1) Costo de compra por línea (mismo helper que articles).
      const costTaxResult = await computePurchaseTaxes(
        jewelryId,
        line.articleId,
        pricing.unitCost ?? null,
      );
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
        costPartial:          pricing.costPartial,
        costMode:             pricing.costMode,
        policy:               pricing.policy,
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
    roundingAdjustment:   0,
    documentRounding:     docRoundingPolicy.documentRounding,
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

  // Armado del response — todo en moneda BASE del tenant. La conversión a la
  // moneda elegida (Fase MM) se aplica al final con `convertSalesPreviewResponseInPlace`.
  const responsePayload: SalePreviewResult & Record<string, unknown> = {
    lines:           resolvedLines,
    subtotal:        documentTotals.subtotalAfterLineDiscounts,
    channelResult,
    couponResult,
    checkoutResult,
    total:           documentTotals.total,
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
        ? {
            source:        "TENANT_POLICY",
            priceListId:   null,
            priceListName: null,
            applyOn:       documentTotals.documentRoundingApplied.applyOn,
            mode:          documentTotals.documentRoundingApplied.mode,
            direction:     documentTotals.documentRoundingApplied.direction,
          }
        : docRoundingInfo,
    },
    // ── Fase 2A.7 — info doc-level ───────────────────────────────────────
    clientBalanceType:     clientRow?.balanceType ?? null,
    clientCommercialRules,
    requestedPriceListId:  input.priceListId ?? null,
    appliedPriceListId:    consolidatedPriceListId,
    appliedPriceListName:  consolidatedPriceListName,
    priceListWasOverridden,
  };

  // ── Multimoneda (Fase MM) ────────────────────────────────────────────────
  // Si el operador eligió una moneda distinta a la base, convertir todos los
  // importes monetarios in-place (incluye lines[*], documentTotals,
  // channel/coupon/checkout) y adosar metadata. Si no, no-op.
  // confirmSale NUNCA pasa por acá — sus snapshots quedan en moneda base.
  // Fase MM ext: si el operador aplicó una cotización manual en el
  // documento (`draft.fxRate` → `input.currencyRate`), tiene precedencia
  // sobre la tasa vigente del catálogo. Sin override, fallback al
  // comportamiento original (última `CurrencyRate`).
  const currencyCtx = await getCurrencyDisplayContext(
    jewelryId,
    input.currencyId   ?? null,
    input.currencyRate ?? null,
  );
  if (currencyCtx?.applied) {
    convertSalesPreviewResponseInPlace(responsePayload, currencyCtx.rate);
  }
  if (currencyCtx) {
    Object.assign(responsePayload, buildResponseCurrencyMetadata(currencyCtx));
  }

  return responsePayload;
}
