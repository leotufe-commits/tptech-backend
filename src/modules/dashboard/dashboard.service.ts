// tptech-backend/src/modules/dashboard/dashboard.service.ts
import { prisma } from "../../lib/prisma.js";

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

  const currencyIds = currencies.map((c) => c.id);
  const metalIds = metals.map((m) => m.id);

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
    series: { fx: fxSeries, metals: metalsSeries },
    activity,
  };
}