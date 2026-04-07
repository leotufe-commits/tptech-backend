import { prisma } from "../../lib/prisma.js";
import { Prisma } from "@prisma/client";
import { computeCostPrice } from "../../lib/article-cost.utils.js";
import { evaluatePricingPolicy, resolveFinalSalePrice, computeLineTaxes } from "../../lib/pricing-engine/pricing-engine.js";
import type { CheckoutResult } from "../../lib/pricing-engine/pricing-engine.js";
import { getCheckoutPreview } from "../payments/payments.service.js";
import { buildBalanceBreakdownFromPrice } from "../../lib/pricing-engine/pricing-engine.balance.js";

// ─── Helpers ────────────────────────────────────────────────────────────────
function err(msg: string, status = 400): never {
  const e: any = new Error(msg);
  e.status = status;
  throw e;
}

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

// ─── Types ───────────────────────────────────────────────────────────────────
export type CreateSaleLineInput = {
  articleId: string;
  variantId?: string | null;
  quantity: number;
  unitPrice: number;
  discountPct?: number;
  priceSource?: string;
  appliedPriceListId?: string | null;
  appliedPromotionId?: string | null;
  appliedDiscountId?: string | null;
};

export type CreateSaleInput = {
  clientId?: string | null;
  sellerId?: string | null;
  warehouseId?: string | null;
  notes?: string;
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

  const code = await nextSaleCode(jewelryId);

  // Calculate totals
  let subtotal = 0;
  const linesData = body.lines.map((line, idx) => {
    const discPct = line.discountPct ?? 0;
    const lineTotal =
      Math.round(line.quantity * line.unitPrice * (1 - discPct / 100) * 100) / 100;
    subtotal += lineTotal;

    const art = articleMap.get(line.articleId)!;
    const vnt = line.variantId ? variantMap.get(line.variantId) : undefined;

    return {
      jewelryId,
      articleId: line.articleId,
      variantId: line.variantId ?? null,
      articleName: art.name,
      variantName: vnt?.name ?? "",
      sku: vnt?.sku || art.sku,
      barcode: vnt?.barcode || art.barcode || "",
      quantity: line.quantity,
      unitPrice: line.unitPrice,
      discountPct: discPct,
      lineTotal,
      priceSource:        line.priceSource        ?? "",
      appliedPriceListId: line.appliedPriceListId ?? null,
      appliedPromotionId: line.appliedPromotionId ?? null,
      appliedDiscountId:  line.appliedDiscountId  ?? null,
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
  const sale = await prisma.sale.findFirst({ where: { id, jewelryId }, select: { id: true, status: true } });
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

    let subtotal = 0;
    const linesData = body.lines.map((line, idx) => {
      const discPct = line.discountPct ?? 0;
      const lineTotal = Math.round(line.quantity * line.unitPrice * (1 - discPct / 100) * 100) / 100;
      subtotal += lineTotal;
      const art = articleMap.get(line.articleId)!;
      const vnt = line.variantId ? variantMap.get(line.variantId) : undefined;
      return {
        jewelryId,
        articleId: line.articleId,
        variantId: line.variantId ?? null,
        articleName: art?.name ?? "",
        variantName: vnt?.name ?? "",
        sku: vnt?.sku || art?.sku || "",
        barcode: vnt?.barcode || art?.barcode || "",
        quantity: line.quantity,
        unitPrice: line.unitPrice,
        discountPct: discPct,
        lineTotal,
        priceSource:        line.priceSource        ?? "",
        appliedPriceListId: line.appliedPriceListId ?? null,
        appliedPromotionId: line.appliedPromotionId ?? null,
        appliedDiscountId:  line.appliedDiscountId  ?? null,
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
      status: true,
      clientId: true,
      warehouseId: true,
      subtotal: true,
      discountAmount: true,
      taxAmount: true,
      total: true,
      client: { select: { id: true, displayName: true, code: true, documentType: true, documentNumber: true, ivaCondition: true, balanceType: true, taxExempt: true, taxApplyOnOverride: true, taxOverrides: { where: { isActive: true }, select: { taxId: true, overrideMode: true, applyOn: true, isActive: true } } } },
      lines: {
        select: {
          id: true,
          articleId: true,
          variantId: true,
          quantity: true,
          unitPrice: true,
          discountPct: true,
          lineTotal: true,
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

  // Decrement stock if warehouseId is set — con pre-check para prevenir negativo
  if (sale.warehouseId) {
    // Paso 1: verificar stock suficiente para todas las líneas (fail-fast antes de tocar nada)
    for (const line of sale.lines) {
      const stock = await prisma.articleStock.findFirst({
        where: {
          jewelryId,
          warehouseId: sale.warehouseId!,
          articleId: line.articleId,
          variantId: line.variantId ?? null,
        },
        select: { id: true, quantity: true },
      });

      // Sin registro = artículo NO_STOCK o sin movimientos previos → skip
      if (!stock) continue;

      const qty = new Prisma.Decimal(line.quantity.toString());
      if (stock.quantity.lt(qty)) {
        const artInfo = await prisma.article.findFirst({
          where: { id: line.articleId },
          select: { name: true },
        });
        const variantInfo = line.variantId
          ? await prisma.articleVariant.findFirst({
              where: { id: line.variantId },
              select: { name: true },
            })
          : null;
        const label = variantInfo
          ? `${artInfo?.name ?? line.articleId} (${variantInfo.name})`
          : (artInfo?.name ?? line.articleId);
        err(
          `Stock insuficiente para "${label}". Disponible: ${stock.quantity.toFixed(0)}, solicitado: ${qty.toFixed(0)}.`
        );
      }
    }

    // Paso 2: decrementar (ya validado)
    await Promise.all(
      sale.lines.map(async (line) => {
        const stock = await prisma.articleStock.findFirst({
          where: {
            jewelryId,
            warehouseId: sale.warehouseId!,
            articleId: line.articleId,
            variantId: line.variantId ?? null,
          },
          select: { id: true },
        });
        if (!stock) return;

        await prisma.articleStock.update({
          where: { id: stock.id },
          data: { quantity: { decrement: line.quantity } },
        });
      })
    );
  }

  // ── Snapshot de costo y margen por línea ──────────────────────────────────
  // Fetch article cost fields for all unique articles in the sale
  const uniqueArticleIds = [...new Set(sale.lines.map((l) => l.articleId))];
  const articleCostData = await prisma.article.findMany({
    where: { id: { in: uniqueArticleIds }, jewelryId },
    select: {
      id: true,
      costCalculationMode: true,
      costPrice: true,
      multiplierBase: true,
      multiplierValue: true,
      multiplierQuantity: true,
      hechuraPrice: true,
      hechuraPriceMode: true,
      mermaPercent: true,
      manualTaxIds: true,
      category: { select: { mermaPercent: true } },
      costComposition: {
        select: { type: true, quantity: true, unitValue: true, currencyId: true, mermaPercent: true, metalVariantId: true },
      },
      compositions: {
        select: { variantId: true, grams: true, isBase: true },
      },
    },
  });
  const articleCostMap = new Map(articleCostData.map((a) => [a.id, a]));

  // Compute and persist cost + tax snapshot for each line (allow null — no blocking)
  const lineTaxAmounts: number[] = [];

  await Promise.all(
    sale.lines.map(async (line) => {
      const artCost = articleCostMap.get(line.articleId);
      if (!artCost) { lineTaxAmounts.push(0); return; }

      const costResult = await computeCostPrice(jewelryId, artCost as any);

      // ── Impuestos por línea ──────────────────────────────────────────────
      const clientTaxExempt          = (sale.client as any)?.taxExempt ?? false;
      const clientTaxApplyOnOverride = (sale.client as any)?.taxApplyOnOverride ?? null;
      const clientTaxOverrides       = (sale.client as any)?.taxOverrides ?? null;
      const taxIds: string[] = clientTaxExempt ? [] : ((artCost as any).manualTaxIds ?? []);
      const unitPriceDec = new Prisma.Decimal(line.unitPrice.toString());
      const discPct      = parseFloat(line.discountPct.toString());
      // Reconstruir precio base (antes de descuento) para applyOn=SUBTOTAL_BEFORE_DISCOUNT
      const basePriceDec = discPct > 0
        ? unitPriceDec.div(new Prisma.Decimal(String(1 - discPct / 100)))
        : unitPriceDec;

      const { taxBreakdown, taxAmount } = await computeLineTaxes(
        jewelryId,
        taxIds,
        unitPriceDec,
        basePriceDec,
        null, // metalHechuraBreakdown no disponible en confirm — se estima desde costBreakdown
        costResult.breakdown ?? null,
        clientTaxApplyOnOverride,
        clientTaxOverrides,
      );

      const lineTaxAmt = parseFloat(taxAmount.toString());
      const qty        = parseFloat(line.quantity.toString());
      lineTaxAmounts.push(lineTaxAmt * qty);

      // ── Costo y margen ───────────────────────────────────────────────────
      if (costResult.value == null) {
        // Guardar solo impuestos si el costo no está disponible
        if (lineTaxAmt > 0) {
          await prisma.saleLine.update({
            where: { id: line.id },
            data: {
              taxAmount:   taxAmount,
              taxSnapshot: taxBreakdown.length > 0 ? (taxBreakdown as any) : Prisma.JsonNull,
            } as any,
          });
        }
        return;
      }

      const qtyDec    = new Prisma.Decimal(line.quantity.toString());
      const unitCost  = new Prisma.Decimal(costResult.value.toString());
      const lineTot   = new Prisma.Decimal(line.lineTotal.toString());
      const totalCost     = unitCost.mul(qtyDec);
      const totalMargin   = lineTot.sub(totalCost);
      const unitMargin    = unitPriceDec.sub(unitCost);
      const marginPercent = lineTot.gt(0) ? totalMargin.div(lineTot).mul(100) : new Prisma.Decimal(0);

      await prisma.saleLine.update({
        where: { id: line.id },
        data: {
          unitCost:          unitCost,
          totalCost:         totalCost,
          unitMargin:        unitMargin,
          totalMargin:       totalMargin,
          marginPercent:     marginPercent,
          breakdownSnapshot: costResult.breakdown ?? null,
          taxAmount:         lineTaxAmt > 0 ? taxAmount : null,
          taxSnapshot:       taxBreakdown.length > 0 ? (taxBreakdown as any) : Prisma.JsonNull,
        } as any,
      });
    })
  );

  // ── Actualizar totales de impuestos en el comprobante ──────────────────────
  const saleTaxTotal = lineTaxAmounts.reduce((s, v) => s + v, 0);
  if (saleTaxTotal > 0) {
    const subtotalNum      = parseFloat(sale.subtotal.toString());
    const discountAmtNum   = parseFloat(sale.discountAmount.toString());
    const newTotal = Math.round((subtotalNum - discountAmtNum + saleTaxTotal) * 100) / 100;
    await prisma.sale.update({
      where: { id },
      data: {
        taxAmount: Math.round(saleTaxTotal * 100) / 100,
        total:     newTotal,
      },
    });
  }

  // ── Cuenta corriente: crear EntityBalanceEntry por línea ─────────────────
  if (sale.clientId && sale.client) {
    const clientBalanceType = (sale.client as any).balanceType as "UNIFIED" | "BREAKDOWN" ?? "UNIFIED";

    // Re-fetch lines WITH breakdownSnapshot (computed in previous step)
    const updatedLines = await prisma.saleLine.findMany({
      where: { saleId: id },
      select: { id: true, lineTotal: true, breakdownSnapshot: true },
    });

    const balanceEntryData = updatedLines.map((line) => {
      const isBreakdown = clientBalanceType === "BREAKDOWN" && line.breakdownSnapshot != null;

      if (isBreakdown) {
        const bd = buildBalanceBreakdownFromPrice(line.breakdownSnapshot as any);
        return {
          entityId:          sale.clientId!,
          jewelryId,
          role:              "CLIENT" as const,
          entryType:         "INVOICE" as const,
          amount:            new Prisma.Decimal(0),     // metal no tiene equivalente dinerario directo
          currency:          "BASE",
          documentRef:       id,
          createdBy:         userId ?? "",
          breakdownSnapshot: bd as any,
        };
      } else {
        return {
          entityId:          sale.clientId!,
          jewelryId,
          role:              "CLIENT" as const,
          entryType:         "INVOICE" as const,
          amount:            new Prisma.Decimal(line.lineTotal.toString()),
          currency:          "BASE",
          documentRef:       id,
          createdBy:         userId ?? "",
          breakdownSnapshot: null,
        };
      }
    });

    if (balanceEntryData.length > 0) {
      await prisma.entityBalanceEntry.createMany({ data: balanceEntryData as any });
    }
  }

  // Build client snapshot
  const clientSnapshot = sale.client
    ? { ...sale.client, snapshotAt: new Date().toISOString() }
    : null;

  await prisma.sale.update({
    where: { id },
    data: {
      status: "CONFIRMED",
      confirmedAt: new Date(),
      confirmedById: userId || null,
      clientSnapshot: clientSnapshot ?? Prisma.JsonNull,
    } as any,
  });

  return getSale(id, jewelryId);
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
      id: true,
      status: true,
      warehouseId: true,
      lines: {
        select: { articleId: true, variantId: true, quantity: true },
      },
    },
  });

  if (!sale) err("Venta no encontrada.", 404);
  if (sale.status === "CANCELLED") err("La venta ya está anulada.");

  // Restore stock if it was confirmed
  if (sale.status !== "DRAFT" && sale.warehouseId) {
    await Promise.all(
      sale.lines.map(async (line) => {
        const stock = await prisma.articleStock.findFirst({
          where: {
            jewelryId,
            warehouseId: sale.warehouseId!,
            articleId: line.articleId,
            variantId: line.variantId ?? null,
          },
        });
        if (!stock) return;
        await prisma.articleStock.update({
          where: { id: stock.id },
          data: { quantity: { increment: line.quantity } },
        });
      })
    );
  }

  const cancelled = await prisma.sale.update({
    where: { id },
    data: {
      status: "CANCELLED",
      cancelledAt: new Date(),
      cancelledById: userId || null,
      cancelNote: note ?? "",
    },
    select: SALE_DETAIL_SELECT,
  });

  return cancelled;
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

// ─── Sale Preview ─────────────────────────────────────────────────────────────
// Resuelve precios + checkout sin persistir nada.
// Fuente única de verdad para el total en Ventas.

export type SalePreviewLineInput = {
  articleId: string;
  variantId?: string | null;
  quantity: number;
};

export type SalePreviewInput = {
  lines: SalePreviewLineInput[];
  clientId?: string | null;
  paymentMethodId?: string | null;
  installmentsQty?: number;
};

export type SalePreviewLine = {
  articleId:            string;
  variantId:            string | null;
  quantity:             number;
  unitPrice:            number | null;
  lineSubtotal:         number | null;
  priceSource:          string;
  appliedPriceListId:   string | null;
  appliedPriceListName: string | null;
  appliedPromotionId:   string | null;
  appliedPromotionName: string | null;
  appliedDiscountId:    string | null;
  unitCost:             number | null;
  costPartial:          boolean;
  costMode:             string;
  policy: {
    canConfirm:     boolean;
    blockingAlerts: string[];
  };
};

export type SalePreviewResult = {
  lines:         SalePreviewLine[];
  subtotal:      number;
  checkoutResult: CheckoutResult | null;
  total:         number;
};

export async function previewSale(
  jewelryId: string,
  input: SalePreviewInput,
): Promise<SalePreviewResult> {
  const { lines, clientId, paymentMethodId, installmentsQty = 0 } = input;

  // ── Precalcular totales por categoría / marca / grupo ─────────────────────
  // Se usan cuando un QuantityDiscount tiene evaluationMode CATEGORY_TOTAL,
  // BRAND_TOTAL o GROUP_TOTAL: la cantidad efectiva es la suma de todas las
  // líneas del comprobante que pertenecen al mismo alcance.
  const articleIds = [...new Set(lines.map(l => l.articleId))];
  const articleMeta = articleIds.length > 0
    ? await prisma.article.findMany({
        where: { id: { in: articleIds }, jewelryId, deletedAt: null },
        select: { id: true, categoryId: true, brand: true, groupId: true },
      })
    : [];
  const metaMap = new Map(articleMeta.map(a => [a.id, a]));

  const categoryTotals = new Map<string, number>();
  const brandTotals    = new Map<string, number>();
  const groupTotals    = new Map<string, number>();
  for (const line of lines) {
    const m = metaMap.get(line.articleId);
    if (!m) continue;
    if (m.categoryId) categoryTotals.set(m.categoryId, (categoryTotals.get(m.categoryId) ?? 0) + line.quantity);
    if (m.brand)      brandTotals.set(m.brand,          (brandTotals.get(m.brand)          ?? 0) + line.quantity);
    if (m.groupId)    groupTotals.set(m.groupId,         (groupTotals.get(m.groupId)         ?? 0) + line.quantity);
  }

  const resolvedLines = await Promise.all(
    lines.map(async (line): Promise<SalePreviewLine> => {
      const m = metaMap.get(line.articleId);
      const pricing = await resolveFinalSalePrice(jewelryId, {
        articleId: line.articleId,
        variantId: line.variantId ?? null,
        clientId:  clientId ?? undefined,
        quantity:  line.quantity,
        categoryTotal: m?.categoryId ? categoryTotals.get(m.categoryId) : undefined,
        brandTotal:    m?.brand      ? brandTotals.get(m.brand)         : undefined,
        groupTotal:    m?.groupId    ? groupTotals.get(m.groupId)       : undefined,
      });

      const n2 = (v: any) =>
        v != null && typeof v === "object" && "toNumber" in v
          ? (v as any).toNumber()
          : v != null ? parseFloat(String(v)) : null;

      const unitPrice = n2(pricing.unitPrice);
      const lineSubtotal =
        unitPrice != null
          ? Math.round(unitPrice * line.quantity * 100) / 100
          : null;

      return {
        articleId:            line.articleId,
        variantId:            line.variantId ?? null,
        quantity:             line.quantity,
        unitPrice,
        lineSubtotal,
        priceSource:          pricing.priceSource,
        appliedPriceListId:   pricing.appliedPriceListId,
        appliedPriceListName: pricing.appliedPriceListName,
        appliedPromotionId:   pricing.appliedPromotionId,
        appliedPromotionName: pricing.appliedPromotionName,
        appliedDiscountId:    pricing.appliedDiscountId,
        unitCost:             n2(pricing.unitCost),
        costPartial:          pricing.costPartial,
        costMode:             pricing.costMode,
        policy:               pricing.policy,
      };
    }),
  );

  const subtotal = Math.round(
    resolvedLines.reduce((s, l) => s + (l.lineSubtotal ?? 0), 0) * 100,
  ) / 100;

  const checkoutResult =
    subtotal > 0 && (paymentMethodId || installmentsQty >= 1)
      ? await getCheckoutPreview(
          jewelryId,
          subtotal,
          paymentMethodId ?? undefined,
          installmentsQty,
        )
      : null;

  const total = checkoutResult ? checkoutResult.finalAmount : subtotal;

  return { lines: resolvedLines, subtotal, checkoutResult, total };
}
