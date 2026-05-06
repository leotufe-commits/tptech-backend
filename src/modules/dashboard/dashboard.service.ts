// tptech-backend/src/modules/dashboard/dashboard.service.ts
import { prisma } from "../../lib/prisma.js";
import { Prisma, SaleStatus } from "@prisma/client";

export type DashboardRange = "7d" | "30d" | "90d" | "1y";

function rangeToDays(r: DashboardRange) {
  if (r === "7d") return 7;
  if (r === "30d") return 30;
  if (r === "90d") return 90;
  return 365;
}

function startOfDay(d: Date) {
  const x = new Date(d);
  x.setHours(0, 0, 0, 0);
  return x;
}

function dayKey(d: Date) {
  const x = startOfDay(d);
  return x.toISOString().slice(0, 10); // YYYY-MM-DD
}

function addDays(d: Date, n: number) {
  const x = new Date(d);
  x.setDate(x.getDate() + n);
  return x;
}

function buildDayAxis(from: Date, to: Date) {
  const out: string[] = [];
  let cur = startOfDay(from);
  const end = startOfDay(to);
  while (cur <= end) {
    out.push(dayKey(cur));
    cur = addDays(cur, 1);
  }
  return out;
}

function pickLastPerDay<T extends { effectiveAt: Date }>(
  rows: T[],
  valueOf: (r: T) => number
) {
  const map = new Map<string, { effectiveAt: Date; v: number }>();
  for (const r of rows) {
    const k = dayKey(r.effectiveAt);
    const prev = map.get(k);
    if (!prev || r.effectiveAt > prev.effectiveAt) {
      map.set(k, { effectiveAt: r.effectiveAt, v: valueOf(r) });
    }
  }
  return map;
}

function r2(n: number) {
  return Math.round(n * 100) / 100;
}

const SALE_ACTIVE: SaleStatus[] = ["CONFIRMED", "PAID", "PARTIALLY_PAID"];

export async function getDashboardSummary(args: {
  jewelryId: string;
  range: DashboardRange;
}) {
  const days = rangeToDays(args.range);
  const now = new Date();
  const from = addDays(now, -(days - 1));
  const axis = buildDayAxis(from, now);

  // ── 1. Contadores generales ────────────────────────────────────────────────
  const [
    baseCurrency,
    currenciesActiveCount,
    metalsActiveCount,
    warehousesActiveCount,
    usersByStatus,
  ] = await Promise.all([
    prisma.currency.findFirst({
      where: { jewelryId: args.jewelryId, deletedAt: null, isBase: true },
      select: { id: true, code: true, symbol: true, name: true },
    }),
    prisma.currency.count({
      where: { jewelryId: args.jewelryId, deletedAt: null, isActive: true },
    }),
    prisma.metal.count({
      where: { jewelryId: args.jewelryId, deletedAt: null, isActive: true },
    }),
    prisma.warehouse.count({
      where: { jewelryId: args.jewelryId, deletedAt: null, isActive: true },
    }),
    prisma.user.groupBy({
      by: ["status"],
      where: { jewelryId: args.jewelryId, deletedAt: null },
      _count: { _all: true },
    }),
  ]);

  // ── 2. Catálogos ──────────────────────────────────────────────────────────
  const [currencies, metals] = await Promise.all([
    prisma.currency.findMany({
      where: { jewelryId: args.jewelryId, deletedAt: null, isActive: true },
      select: { id: true, code: true, symbol: true, name: true, isBase: true },
      orderBy: [{ isBase: "desc" }, { code: "asc" }],
    }),
    prisma.metal.findMany({
      where: { jewelryId: args.jewelryId, deletedAt: null, isActive: true },
      select: { id: true, name: true, symbol: true, sortOrder: true },
      orderBy: [{ sortOrder: "asc" }, { name: "asc" }],
    }),
  ]);

  const metalIds = metals.map((m) => m.id);

  // ── 3. Variantes metálicas ────────────────────────────────────────────────
  const variants = await prisma.metalVariant.findMany({
    where: { metalId: { in: metalIds }, deletedAt: null, isActive: true },
    select: { id: true, metalId: true, name: true, sku: true, purity: true, saleFactor: true },
    orderBy: [{ purity: "desc" }, { name: "asc" }],
  });

  const variantIds = variants.map((v) => v.id);

  const latestVariantHistory = await prisma.metalVariantValueHistory.findMany({
    where: { variantId: { in: variantIds } },
    select: { variantId: true, finalSalePrice: true, effectiveAt: true },
    orderBy: { effectiveAt: "desc" },
  });

  const latestByVariant = new Map<string, number>();
  for (const row of latestVariantHistory) {
    if (!latestByVariant.has(row.variantId)) {
      latestByVariant.set(row.variantId, Number(row.finalSalePrice));
    }
  }

  const currencyIds = currencies.map((c) => c.id);

  // ── 4. Series históricas FX + metales ─────────────────────────────────────
  const [currencyRates, metalRefHistory] = await Promise.all([
    prisma.currencyRate.findMany({
      where: {
        currencyId: { in: currencyIds },
        effectiveAt: { gte: from, lte: now },
      },
      select: { currencyId: true, rate: true, effectiveAt: true },
      orderBy: [{ effectiveAt: "asc" }],
    }),
    prisma.metalRefValueHistory.findMany({
      where: {
        jewelryId: args.jewelryId,
        metalId: { in: metalIds },
        effectiveAt: { gte: from, lte: now },
      },
      select: { metalId: true, referenceValue: true, effectiveAt: true },
      orderBy: [{ effectiveAt: "asc" }],
    }),
  ]);

  // ── 5. Actividad reciente ─────────────────────────────────────────────────
  const activity = await prisma.auditLog.findMany({
    where: { jewelryId: args.jewelryId },
    select: { id: true, action: true, success: true, createdAt: true, userId: true },
    orderBy: { createdAt: "desc" },
    take: 12,
  });

  // ── 6. Ventas + Inventario (todas las queries en paralelo) ─────────────────
  const todayStart = startOfDay(now);
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1, 0, 0, 0, 0);

  const [
    salesTodayAgg,
    salesMonthAgg,
    salesRangeRows,
    saleLineRangeRows,
    allArticleStocks,
    articlesActiveCount,
  ] = await Promise.all([
    // Ventas hoy (aggregate)
    prisma.sale.aggregate({
      where: {
        jewelryId: args.jewelryId,
        status: { in: SALE_ACTIVE },
        confirmedAt: { gte: todayStart },
      },
      _sum: { total: true },
      _count: { _all: true },
    }),
    // Ventas este mes (aggregate)
    prisma.sale.aggregate({
      where: {
        jewelryId: args.jewelryId,
        status: { in: SALE_ACTIVE },
        confirmedAt: { gte: monthStart },
      },
      _sum: { total: true },
      _count: { _all: true },
    }),
    // Ventas en el rango (para serie diaria)
    prisma.sale.findMany({
      where: {
        jewelryId: args.jewelryId,
        status: { in: SALE_ACTIVE },
        confirmedAt: { gte: from, lte: now },
      },
      select: { total: true, confirmedAt: true },
      orderBy: { confirmedAt: "asc" },
    }),
    // Líneas de venta en el rango (para margen)
    prisma.saleLine.findMany({
      where: {
        jewelryId: args.jewelryId,
        sale: {
          status: { in: SALE_ACTIVE },
          confirmedAt: { gte: from, lte: now },
        },
      },
      select: {
        totalMargin: true,
        lineTotal: true,
        sale: { select: { confirmedAt: true } },
      },
    }),
    // Stock agrupado por artículo
    prisma.articleStock.groupBy({
      by: ["articleId"],
      where: { jewelryId: args.jewelryId },
      _sum: { quantity: true },
    }),
    // Artículos activos con control de stock
    prisma.article.count({
      where: {
        jewelryId: args.jewelryId,
        deletedAt: null,
        isActive: true,
        stockMode: { not: "NO_STOCK" as any },
      },
    }),
  ]);

  // ── Calcular KPIs de ventas ────────────────────────────────────────────────
  const todayRevenue = Number(salesTodayAgg._sum.total ?? 0);
  const todayCount = salesTodayAgg._count._all;
  const todayAvgTicket = todayCount > 0 ? r2(todayRevenue / todayCount) : 0;

  const monthRevenue = Number(salesMonthAgg._sum.total ?? 0);
  const monthCount = salesMonthAgg._count._all;
  const monthAvgTicket = monthCount > 0 ? r2(monthRevenue / monthCount) : 0;

  // Serie diaria de ventas
  const salesByDay = new Map<string, number>();
  let rangeRevenue = 0;
  for (const s of salesRangeRows) {
    if (s.confirmedAt) {
      const k = dayKey(s.confirmedAt);
      salesByDay.set(k, (salesByDay.get(k) ?? 0) + Number(s.total));
    }
    rangeRevenue += Number(s.total);
  }

  // Margen por día (solo líneas con costo cargado)
  let totalMarginRange = 0;
  let totalRevForMargin = 0;
  let linesWithoutCost = 0;
  const marginByDay = new Map<string, number>();

  for (const line of saleLineRangeRows) {
    if (line.totalMargin != null && line.sale?.confirmedAt) {
      const k = dayKey(line.sale.confirmedAt);
      const m = Number(line.totalMargin);
      marginByDay.set(k, (marginByDay.get(k) ?? 0) + m);
      totalMarginRange += m;
      totalRevForMargin += Number(line.lineTotal);
    } else {
      linesWithoutCost++;
    }
  }

  const hasMarginData =
    saleLineRangeRows.length > 0 &&
    saleLineRangeRows.some((l) => l.totalMargin != null);

  const rangeMargin = hasMarginData ? r2(totalMarginRange) : null;
  const rangeMarginPct =
    hasMarginData && totalRevForMargin > 0
      ? r2((totalMarginRange / totalRevForMargin) * 100)
      : null;

  // Serie diaria: revenue siempre presente (0 = sin ventas), margin null si no hay datos de costo
  const salesSeries = axis.map((k) => ({
    date: k,
    revenue: salesByDay.get(k) ?? 0,
    margin: hasMarginData ? (marginByDay.get(k) ?? null) : null,
  }));

  // ── Inventario ────────────────────────────────────────────────────────────
  const outOfStockItems = allArticleStocks.filter(
    (s) => Number(s._sum.quantity ?? 0) <= 0
  );
  const outOfStockCount = outOfStockItems.length;

  const topIds = outOfStockItems.slice(0, 5).map((s) => s.articleId);
  const topOutOfStock =
    topIds.length > 0
      ? await prisma.article.findMany({
          where: { id: { in: topIds }, deletedAt: null },
          select: { id: true, code: true, name: true },
        })
      : [];

  // ── Armar series de valuación ─────────────────────────────────────────────
  const ratesByCurrency = new Map<string, Map<string, number>>();
  for (const c of currencies) ratesByCurrency.set(c.id, new Map());

  const groupedRates = new Map<
    string,
    { currencyId: string; rate: any; effectiveAt: Date }[]
  >();
  for (const r of currencyRates) {
    const arr = groupedRates.get(r.currencyId) ?? [];
    arr.push({ currencyId: r.currencyId, rate: r.rate, effectiveAt: r.effectiveAt });
    groupedRates.set(r.currencyId, arr);
  }
  for (const [cid, rows] of groupedRates.entries()) {
    const perDay = pickLastPerDay(rows, (x) => Number(x.rate));
    const map = ratesByCurrency.get(cid);
    if (!map) continue;
    for (const [k, v] of perDay.entries()) map.set(k, v.v);
  }

  const refsByMetal = new Map<string, Map<string, number>>();
  for (const m of metals) refsByMetal.set(m.id, new Map());

  const groupedRefs = new Map<
    string,
    { metalId: string; referenceValue: any; effectiveAt: Date }[]
  >();
  for (const r of metalRefHistory) {
    const arr = groupedRefs.get(r.metalId) ?? [];
    arr.push({ metalId: r.metalId, referenceValue: r.referenceValue, effectiveAt: r.effectiveAt });
    groupedRefs.set(r.metalId, arr);
  }
  for (const [mid, rows] of groupedRefs.entries()) {
    const perDay = pickLastPerDay(rows, (x) => Number(x.referenceValue));
    const map = refsByMetal.get(mid);
    if (!map) continue;
    for (const [k, v] of perDay.entries()) map.set(k, v.v);
  }

  const fxSeries = axis.map((k) => {
    const row: Record<string, any> = { date: k };
    for (const c of currencies) {
      const v = ratesByCurrency.get(c.id)?.get(k);
      if (v != null) row[c.code] = v;
    }
    return row;
  });

  const metalsSeries = axis.map((k) => {
    const row: Record<string, any> = { date: k };
    for (const m of metals) {
      const v = refsByMetal.get(m.id)?.get(k);
      if (v != null) row[m.name] = v;
    }
    return row;
  });

  const users = { ACTIVE: 0, PENDING: 0, BLOCKED: 0, total: 0 };
  for (const g of usersByStatus as any[]) {
    const k = String(g.status) as "ACTIVE" | "PENDING" | "BLOCKED";
    const n = Number(g._count?._all ?? 0);
    if (k in users) (users as any)[k] = n;
    users.total += n;
  }

  return {
    range: args.range,
    from,
    to: now,
    kpis: {
      baseCurrency,
      currenciesActiveCount,
      metalsActiveCount,
      warehousesActiveCount,
      users,
    },
    currencies,
    metals,
    variants: variants.map((v) => ({
      id: v.id,
      metalId: v.metalId,
      name: v.name,
      sku: v.sku,
      purity: Number(v.purity),
      saleFactor: Number(v.saleFactor),
      value: latestByVariant.get(v.id) ?? null,
    })),
    series: { fx: fxSeries, metals: metalsSeries },
    activity,
    // ── Nuevo ──────────────────────────────────────────────────────────────
    salesKpis: {
      today: {
        revenue: r2(todayRevenue),
        ticketCount: todayCount,
        avgTicket: todayAvgTicket,
      },
      month: {
        revenue: r2(monthRevenue),
        ticketCount: monthCount,
        avgTicket: monthAvgTicket,
      },
      range: {
        revenue: r2(rangeRevenue),
        ticketCount: salesRangeRows.length,
        margin: rangeMargin,
        marginPercent: rangeMarginPct,
        linesWithoutCost,
      },
    },
    salesSeries,
    inventory: {
      articlesActive: articlesActiveCount,
      stockTrackedCount: allArticleStocks.length,
      outOfStockCount,
      topOutOfStock,
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// PROFIT SUMMARY (sin cambios)
// ─────────────────────────────────────────────────────────────────────────────

export type ProfitGroupBy = "day" | "week" | "month";

function bucketKey(date: Date, groupBy: ProfitGroupBy): string {
  const d = new Date(date);
  if (groupBy === "month") return d.toISOString().slice(0, 7);
  if (groupBy === "week") {
    d.setHours(0, 0, 0, 0);
    const dow = d.getDay();
    const diff = dow === 0 ? -6 : 1 - dow;
    d.setDate(d.getDate() + diff);
    return d.toISOString().slice(0, 10);
  }
  return d.toISOString().slice(0, 10);
}

export async function getProfitSummary(args: {
  jewelryId: string;
  from: Date;
  to: Date;
  groupBy: ProfitGroupBy;
}) {
  const { jewelryId, from, to, groupBy } = args;

  const lines = await prisma.saleLine.findMany({
    where: {
      jewelryId,
      sale: {
        status: { in: SALE_ACTIVE },
        confirmedAt: { gte: from, lte: to },
      },
    },
    select: {
      id: true,
      articleId: true,
      articleName: true,
      quantity: true,
      lineTotal: true,
      totalCost: true,
      totalMargin: true,
      sale: { select: { id: true, confirmedAt: true } },
    },
    orderBy: { createdAt: "asc" },
  });

  let revenue = 0;
  let cost = 0;
  let margin = 0;
  let linesWithCost = 0;
  let linesWithoutCost = 0;
  let linesNegativeMargin = 0;
  const negSaleIds = new Set<string>();

  const seriesMap = new Map<string, { revenue: number; cost: number; margin: number }>();
  const artMap = new Map<string, {
    articleId: string; articleName: string;
    revenue: number; cost: number; margin: number; quantity: number;
  }>();

  for (const line of lines) {
    const rev = Number(line.lineTotal);
    const c = line.totalCost != null ? Number(line.totalCost) : null;
    const m = line.totalMargin != null ? Number(line.totalMargin) : null;
    const qty = Number(line.quantity);

    revenue += rev;
    if (c != null) { cost += c; linesWithCost++; } else { linesWithoutCost++; }
    if (m != null) {
      margin += m;
      if (m < 0) { linesNegativeMargin++; if (line.sale?.id) negSaleIds.add(line.sale.id); }
    }

    const confirmedAt = line.sale?.confirmedAt;
    if (confirmedAt) {
      const key = bucketKey(confirmedAt, groupBy);
      const b = seriesMap.get(key) ?? { revenue: 0, cost: 0, margin: 0 };
      b.revenue += rev;
      if (c != null) b.cost += c;
      if (m != null) b.margin += m;
      seriesMap.set(key, b);
    }

    const a = artMap.get(line.articleId) ?? {
      articleId: line.articleId, articleName: line.articleName,
      revenue: 0, cost: 0, margin: 0, quantity: 0,
    };
    a.revenue += rev;
    if (c != null) a.cost += c;
    if (m != null) a.margin += m;
    a.quantity += qty;
    artMap.set(line.articleId, a);
  }

  const marginPct = revenue > 0 ? (margin / revenue) * 100 : 0;

  const series = Array.from(seriesMap.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([date, v]) => ({
      date,
      revenue: r2(v.revenue),
      cost: r2(v.cost),
      margin: r2(v.margin),
    }));

  const topArticles = Array.from(artMap.values())
    .map((a) => ({
      articleId: a.articleId,
      articleName: a.articleName,
      revenue: r2(a.revenue),
      cost: r2(a.cost),
      margin: r2(a.margin),
      marginPercent: a.revenue > 0 ? r2((a.margin / a.revenue) * 100) : 0,
      quantity: Number(Number(a.quantity).toFixed(4)),
    }))
    .sort((a, b) => b.margin - a.margin)
    .slice(0, 20);

  return {
    period: { from: from.toISOString(), to: to.toISOString(), groupBy },
    totals: {
      revenue: r2(revenue),
      cost: r2(cost),
      margin: r2(margin),
      marginPercent: r2(marginPct),
      linesCount: lines.length,
      linesWithCost,
      linesWithoutCost,
      linesNegativeMargin,
      salesWithNegativeMargin: negSaleIds.size,
    },
    series,
    topArticles,
  };
}

// Suppress unused import warning
void Prisma;
