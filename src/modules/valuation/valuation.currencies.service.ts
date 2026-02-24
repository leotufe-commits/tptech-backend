// tptech-backend/src/modules/valuation/valuation.currencies.service.ts
import { Prisma } from "@prisma/client";
import { prisma } from "../../lib/prisma.js";

import { toNum, assertFinitePositive } from "./valuation.helpers.js";

function freedCode(code: string, id: string) {
  const suffix = `${Date.now()}_${Math.random().toString(16).slice(2)}`;
  return `deleted__${code}__${id}__${suffix}`;
}

/* =========================
   Monedas
========================= */

export async function listCurrencies(jewelryId: string) {
  const rows = await prisma.currency.findMany({
    where: { jewelryId, deletedAt: null },
    orderBy: [{ isBase: "desc" }, { code: "asc" }],
    select: {
      id: true,
      code: true,
      name: true,
      symbol: true,
      isBase: true,
      isActive: true,
      rates: {
        take: 1,
        orderBy: [{ effectiveAt: "desc" }, { createdAt: "desc" }],
        select: { rate: true, effectiveAt: true, createdAt: true },
      },
    },
  });

  return rows.map((c) => {
    const latest = c.rates?.[0] ?? null;
    return {
      id: c.id,
      code: c.code,
      name: c.name,
      symbol: c.symbol,
      isBase: c.isBase,
      isActive: c.isActive,
      latestRate: latest ? toNum(latest.rate, null as any) : null,
      latestAt: latest?.effectiveAt ?? null,
      latestCreatedAt: latest?.createdAt ?? null,
    };
  });
}

export async function createCurrency(jewelryId: string, data: { code: string; name: string; symbol: string }) {
  const code = String(data.code || "").trim().toUpperCase();
  const name = String(data.name || "").trim();
  const symbol = String(data.symbol || "").trim();

  if (!code) {
    const err: any = new Error("Código inválido.");
    err.status = 400;
    throw err;
  }

  return prisma.$transaction(async (tx) => {
    const exists = await tx.currency.findFirst({
      where: { jewelryId, code, deletedAt: null },
      select: { id: true },
    });
    if (exists) {
      const err: any = new Error("Ya existe una moneda con ese código.");
      err.status = 409;
      throw err;
    }

    // ✅ Si no hay monedas (no eliminadas), la primera queda como base automáticamente
    const count = await tx.currency.count({
      where: { jewelryId, deletedAt: null },
    });
    const isFirst = count === 0;

    // ✅ Seguridad extra: si por alguna razón existieran bases viejas, limpiarlas al crear la primera
    if (isFirst) {
      await tx.currency.updateMany({
        where: { jewelryId, deletedAt: null, isBase: true },
        data: { isBase: false },
      });
    }

    const created = await tx.currency.create({
      data: {
        jewelryId,
        code,
        name,
        symbol,
        isBase: isFirst,
        isActive: true, // ✅ la primera siempre activa
        deletedAt: null,
      },
      select: {
        id: true,
        code: true,
        name: true,
        symbol: true,
        isBase: true,
        isActive: true,
      },
    });

    return created;
  });
}

export async function updateCurrency(
  jewelryId: string,
  currencyId: string,
  data: { code: string; name: string; symbol: string }
) {
  const cur = await prisma.currency.findFirst({
    where: { id: currencyId, jewelryId, deletedAt: null },
    select: { id: true, code: true },
  });
  if (!cur) {
    const err: any = new Error("Moneda no encontrada.");
    err.status = 404;
    throw err;
  }

  const code = String(data.code || "").trim().toUpperCase();
  const name = String(data.name || "").trim();
  const symbol = String(data.symbol || "").trim();

  if (!code) {
    const err: any = new Error("Código inválido.");
    err.status = 400;
    throw err;
  }

  if (code !== cur.code) {
    const dup = await prisma.currency.findFirst({
      where: { jewelryId, code, deletedAt: null, id: { not: currencyId } },
      select: { id: true },
    });
    if (dup) {
      const err: any = new Error("Ya existe una moneda con ese código.");
      err.status = 409;
      throw err;
    }
  }

  return prisma.currency.update({
    where: { id: currencyId },
    data: { code, name, symbol },
    select: {
      id: true,
      code: true,
      name: true,
      symbol: true,
      isBase: true,
      isActive: true,
    },
  });
}

/**
 * Convención:
 * CurrencyRate.rate: 1 currency = rate * baseCurrency
 */
export async function setBaseCurrency(jewelryId: string, newBaseCurrencyId: string, createdById?: string | null) {
  const now = new Date();

  return prisma.$transaction(async (tx) => {
    const currencies = await tx.currency.findMany({
      where: { jewelryId, deletedAt: null },
      select: {
        id: true,
        code: true,
        name: true,
        symbol: true,
        isBase: true,
        isActive: true,
      },
      orderBy: [{ isBase: "desc" }, { code: "asc" }],
    });

    const oldBase = currencies.find((c) => c.isBase) ?? null;
    const newBase = currencies.find((c) => c.id === newBaseCurrencyId) ?? null;

    if (!newBase) {
      const err: any = new Error("Moneda no encontrada.");
      err.status = 404;
      throw err;
    }

    // ✅ Blindaje: aunque ya sea base, aseguramos unicidad (solo 1 base)
    if (newBase.isBase) {
      await tx.currency.updateMany({
        where: { jewelryId, deletedAt: null, isBase: true, id: { not: newBase.id } },
        data: { isBase: false },
      });

      await tx.currency.update({
        where: { id: newBase.id },
        data: { isActive: true, isBase: true },
      });

      const row = await tx.currency.findUnique({
        where: { id: newBase.id },
        select: { id: true, code: true, name: true, symbol: true, isBase: true, isActive: true },
      });
      return row!;
    }

    // Si no hay base vieja, simplemente marcamos base (y limpiamos cualquier base fantasma)
    if (!oldBase) {
      await tx.currency.updateMany({
        where: { jewelryId, deletedAt: null, isBase: true },
        data: { isBase: false },
      });

      const row = await tx.currency.update({
        where: { id: newBase.id },
        data: { isBase: true, isActive: true },
        select: { id: true, code: true, name: true, symbol: true, isBase: true, isActive: true },
      });

      return row;
    }

    async function lastRate(currencyId: string) {
      return tx.currencyRate.findFirst({
        where: { currencyId },
        orderBy: [{ effectiveAt: "desc" }, { createdAt: "desc" }],
        select: { rate: true, effectiveAt: true },
      });
    }

    const newBaseRateRow = await lastRate(newBase.id);
    const rN = toNum(newBaseRateRow?.rate, NaN);

    assertFinitePositive(
      rN,
      `No se puede cambiar la base: la moneda ${newBase.code} no tiene tipo de cambio cargado contra la base actual (${oldBase.code}).`
    );

    const rateById = new Map<string, number>();
    rateById.set(oldBase.id, 1);

    for (const c of currencies) {
      if (c.id === oldBase.id) continue;
      const row = await lastRate(c.id);
      const r = toNum(row?.rate, NaN);
      if (!Number.isFinite(r) || r <= 0) continue;
      rateById.set(c.id, r);
    }

    // ✅ solo metales no eliminados
    const metals = await tx.metal.findMany({
      where: { jewelryId, deletedAt: null },
      select: { id: true, referenceValue: true },
    });

    const k = new Prisma.Decimal(rN);

    for (const m of metals) {
      const oldRef = new Prisma.Decimal(m.referenceValue ?? 0);
      const newRef = oldRef.div(k);

      await tx.metal.update({
        where: { id: m.id },
        data: { referenceValue: newRef },
      });
    }

    const newRatesToCreate: Array<{
      currencyId: string;
      rate: Prisma.Decimal;
      effectiveAt: Date;
      createdById: string | null;
    }> = [];

    for (const c of currencies) {
      if (c.id === newBase.id) continue;

      const rC = rateById.get(c.id);
      if (!rC) continue;

      const rNew = rC / rN;
      assertFinitePositive(rNew, `Error recalculando tipo de cambio para ${c.code}.`);

      newRatesToCreate.push({
        currencyId: c.id,
        rate: new Prisma.Decimal(rNew),
        effectiveAt: now,
        createdById: createdById || null,
      });
    }

    await tx.currency.updateMany({
      where: { jewelryId, deletedAt: null, isBase: true },
      data: { isBase: false },
    });

    const baseRow = await tx.currency.update({
      where: { id: newBase.id },
      data: { isBase: true, isActive: true },
      select: { id: true, code: true, name: true, symbol: true, isBase: true, isActive: true },
    });

    for (const x of newRatesToCreate) {
      await tx.currencyRate.create({
        data: {
          currencyId: x.currencyId,
          rate: x.rate,
          effectiveAt: x.effectiveAt,
          createdById: x.createdById,
        },
      });
    }

    return baseRow;
  });
}

export async function setBaseCurrencyAndRecalc(args: {
  jewelryId: string;
  newBaseCurrencyId: string;
  actorUserId?: string | null;
  effectiveAt?: Date;
}) {
  const jewelryId = String(args?.jewelryId || "").trim();
  const newBaseCurrencyId = String(args?.newBaseCurrencyId || "").trim();
  if (!jewelryId || !newBaseCurrencyId) {
    const err: any = new Error("Datos inválidos para cambiar moneda base.");
    err.status = 400;
    throw err;
  }

  const oldBase = await prisma.currency.findFirst({
    where: { jewelryId, isBase: true, deletedAt: null },
    select: { id: true },
  });

  const row = await setBaseCurrency(jewelryId, newBaseCurrencyId, args.actorUserId ?? null);

  return {
    ok: true,
    changed: oldBase?.id !== row?.id,
    oldBaseId: oldBase?.id ?? null,
    newBaseId: row?.id ?? null,
    k: null as any,
  };
}

export async function toggleCurrencyActive(jewelryId: string, currencyId: string, isActive: boolean) {
  const cur = await prisma.currency.findFirst({
    where: { id: currencyId, jewelryId, deletedAt: null },
    select: { id: true, isBase: true },
  });
  if (!cur) {
    const err: any = new Error("Moneda no encontrada.");
    err.status = 404;
    throw err;
  }
  if (cur.isBase && !isActive) {
    const err: any = new Error("La moneda base no puede desactivarse.");
    err.status = 400;
    throw err;
  }

  return prisma.currency.update({
    where: { id: currencyId },
    data: { isActive },
    select: { id: true, code: true, name: true, symbol: true, isBase: true, isActive: true },
  });
}

export async function addCurrencyRate(
  jewelryId: string,
  currencyId: string,
  data: { rate: number; effectiveAt: Date },
  createdById: string | null
) {
  const cur = await prisma.currency.findFirst({
    where: { id: currencyId, jewelryId, deletedAt: null },
    select: { id: true, isBase: true },
  });
  if (!cur) {
    const err: any = new Error("Moneda no encontrada.");
    err.status = 404;
    throw err;
  }
  if (cur.isBase) {
    const err: any = new Error("La moneda base no necesita tipo de cambio.");
    err.status = 400;
    throw err;
  }

  assertFinitePositive(Number(data.rate), "Tipo de cambio inválido.");

  return prisma.currencyRate.create({
    data: {
      currencyId,
      rate: data.rate as any,
      effectiveAt: data.effectiveAt,
      createdById: createdById || null,
    },
    select: { id: true, rate: true, effectiveAt: true, createdAt: true },
  });
}

export async function listCurrencyRates(jewelryId: string, currencyId: string, take = 50) {
  const cur = await prisma.currency.findFirst({
    where: { id: currencyId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  if (!cur) {
    const err: any = new Error("Moneda no encontrada.");
    err.status = 404;
    throw err;
  }

  const rows = await prisma.currencyRate.findMany({
    where: { currencyId },
    orderBy: [{ effectiveAt: "desc" }, { createdAt: "desc" }],
    take,
    select: { id: true, rate: true, effectiveAt: true, createdAt: true },
  });

  return rows.map((r) => ({ ...r, rate: Number(r.rate) }));
}

/* =========================
   ✅ Soft delete currency
========================= */
export async function deleteCurrency(jewelryId: string, currencyId: string) {
  const cur = await prisma.currency.findFirst({
    where: { id: currencyId, jewelryId, deletedAt: null },
    select: { id: true, code: true, isBase: true },
  });
  if (!cur) {
    const err: any = new Error("Moneda no encontrada.");
    err.status = 404;
    throw err;
  }
  if (cur.isBase) {
    const err: any = new Error("No se puede eliminar la moneda base.");
    err.status = 400;
    throw err;
  }

  const usedQuotes = await prisma.metalQuote.count({ where: { currencyId: cur.id } });
  if (usedQuotes > 0) {
    const err: any = new Error(`No se puede eliminar ${cur.code}: está usada en ${usedQuotes} cotización(es) de metales.`);
    err.status = 409;
    throw err;
  }

  const now = new Date();
  await prisma.currency.update({
    where: { id: cur.id },
    data: {
      deletedAt: now,
      isActive: false,
      isBase: false,
      code: freedCode(cur.code, cur.id),
      name: "",
      symbol: "",
    },
    select: { id: true },
  });

  return { ok: true };
}