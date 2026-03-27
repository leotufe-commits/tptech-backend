// tptech-backend/src/modules/dashboard/dashboard.service.ts
import { prisma } from "../../lib/prisma.js";
import { Prisma } from "@prisma/client";

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

export async function getDashboardSummary(args: {
  jewelryId: string;
  range: DashboardRange;
}) {
  const days = rangeToDays(args.range);
  const now = new Date();
  const from = addDays(now, -(days - 1));
  const axis = buildDayAxis(from, now);

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

  const activity = await prisma.auditLog.findMany({
    where: { jewelryId: args.jewelryId },
    select: { id: true, action: true, success: true, createdAt: true, userId: true },
    orderBy: { createdAt: "desc" },
    take: 12,
  });

  // Currency series (key = code)
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

  // Metals series (key = name)
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
      const key = m.name;
      const v = refsByMetal.get(m.id)?.get(k);
      if (v != null) row[key] = v;
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
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// PROFIT SUMMARY
// ─────────────────────────────────────────────────────────────────────────────

export type ProfitGroupBy = "day" | "week" | "month";

function bucketKey(date: Date, groupBy: ProfitGroupBy): string {
  const d = new Date(date);
  if (groupBy === "month") return d.toISOString().slice(0, 7); // YYYY-MM
  if (groupBy === "week") {
    d.setHours(0, 0, 0, 0);
    const dow = d.getDay();
    const diff = dow === 0 ? -6 : 1 - dow; // shift to Monday
    d.setDate(d.getDate() + diff);
    return d.toISOString().slice(0, 10);
  }
  return d.toISOString().slice(0, 10); // YYYY-MM-DD
}

function r2(n: number) {
  return Math.round(n * 100) / 100;
}

export async function getProfitSummary(args: {
  jewelryId: string;
  from: Date;
  to: Date;
  groupBy: ProfitGroupBy;
}) {
  const { jewelryId, from, to, groupBy } = args;

  // Only confirmed sales with frozen cost snapshots
  const lines = await prisma.saleLine.findMany({
    where: {
      jewelryId,
      sale: {
        status: { in: ["CONFIRMED", "PAID", "PARTIALLY_PAID"] as any[] },
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
  let cost    = 0;
  let margin  = 0;
  let linesWithCost     = 0;
  let linesWithoutCost  = 0;
  let linesNegativeMargin = 0;
  const negSaleIds = new Set<string>();

  const seriesMap = new Map<string, { revenue: number; cost: number; margin: number }>();
  const artMap    = new Map<string, {
    articleId: string; articleName: string;
    revenue: number; cost: number; margin: number; quantity: number;
  }>();

  for (const line of lines) {
    const rev = Number(line.lineTotal);
    const c   = line.totalCost   != null ? Number(line.totalCost)   : null;
    const m   = line.totalMargin != null ? Number(line.totalMargin) : null;
    const qty = Number(line.quantity);

    revenue += rev;
    if (c != null) { cost += c; linesWithCost++; } else { linesWithoutCost++; }
    if (m != null) {
      margin += m;
      if (m < 0) { linesNegativeMargin++; if (line.sale?.id) negSaleIds.add(line.sale.id); }
    }

    // Time series bucket
    const confirmedAt = line.sale?.confirmedAt;
    if (confirmedAt) {
      const key = bucketKey(confirmedAt, groupBy);
      const b   = seriesMap.get(key) ?? { revenue: 0, cost: 0, margin: 0 };
      b.revenue += rev;
      if (c != null) b.cost += c;
      if (m != null) b.margin += m;
      seriesMap.set(key, b);
    }

    // Top articles aggregation
    const a = artMap.get(line.articleId) ?? {
      articleId: line.articleId, articleName: line.articleName,
      revenue: 0, cost: 0, margin: 0, quantity: 0,
    };
    a.revenue  += rev;
    if (c != null) a.cost   += c;
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
      cost:    r2(v.cost),
      margin:  r2(v.margin),
    }));

  const topArticles = Array.from(artMap.values())
    .map((a) => ({
      articleId:     a.articleId,
      articleName:   a.articleName,
      revenue:       r2(a.revenue),
      cost:          r2(a.cost),
      margin:        r2(a.margin),
      marginPercent: a.revenue > 0 ? r2((a.margin / a.revenue) * 100) : 0,
      quantity:      Number(Number(a.quantity).toFixed(4)),
    }))
    .sort((a, b) => b.margin - a.margin)
    .slice(0, 20);

  return {
    period: { from: from.toISOString(), to: to.toISOString(), groupBy },
    totals: {
      revenue:       r2(revenue),
      cost:          r2(cost),
      margin:        r2(margin),
      marginPercent: r2(marginPct),
      linesCount:    lines.length,
      linesWithCost,
      linesWithoutCost,
      linesNegativeMargin,
      salesWithNegativeMargin: negSaleIds.size,
    },
    series,
    topArticles,
  };
}

// Suppress unused import warning — Prisma is imported for future Decimal use
void Prisma;