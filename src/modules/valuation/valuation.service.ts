// tptech-backend/src/modules/valuation/valuation.service.ts
import { Prisma } from "@prisma/client";
import { prisma } from "../../lib/prisma.js";

/* =========================
   Helpers
========================= */

function toNum(v: any, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function assertFinitePositive(n: number, msg: string) {
  if (!Number.isFinite(n) || n <= 0) {
    const err: any = new Error(msg);
    err.status = 400;
    throw err;
  }
}

function toRefValue(v: any) {
  if (v === undefined || v === null || v === "") return undefined;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) {
    const err: any = new Error("Valor de referencia inválido.");
    err.status = 400;
    throw err;
  }
  return n;
}

function clampTake(v: any, fallback = 80) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(1, Math.min(200, Math.trunc(n)));
}

function dec(v: any, fallback = 0) {
  const n = Number(v);
  if (!Number.isFinite(n)) return new Prisma.Decimal(fallback);
  return new Prisma.Decimal(n);
}

function decOrNull(v: any) {
  if (v === undefined || v === null || v === "") return null;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) return null;
  return new Prisma.Decimal(n);
}

function computeSuggested(referenceValue: Prisma.Decimal, purity: Prisma.Decimal) {
  // referenceValue (base currency per gram) * purity
  return referenceValue.mul(purity);
}

function computeFinal(suggested: Prisma.Decimal, factor: Prisma.Decimal, override: Prisma.Decimal | null) {
  if (override) return override;
  return suggested.mul(factor);
}

/* =========================
   Monedas
========================= */

export async function listCurrencies(jewelryId: string) {
  const rows = await prisma.currency.findMany({
    where: { jewelryId },
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
  const exists = await prisma.currency.findFirst({
    where: { jewelryId, code: data.code },
    select: { id: true },
  });
  if (exists) {
    const err: any = new Error("Ya existe una moneda con ese código.");
    err.status = 409;
    throw err;
  }

  return prisma.currency.create({
    data: {
      jewelryId,
      code: data.code,
      name: data.name,
      symbol: data.symbol,
      isBase: false,
      isActive: true,
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
}

export async function updateCurrency(
  jewelryId: string,
  currencyId: string,
  data: { code: string; name: string; symbol: string }
) {
  const cur = await prisma.currency.findFirst({
    where: { id: currencyId, jewelryId },
    select: { id: true, code: true },
  });
  if (!cur) {
    const err: any = new Error("Moneda no encontrada.");
    err.status = 404;
    throw err;
  }

  if (data.code !== cur.code) {
    const dup = await prisma.currency.findFirst({
      where: { jewelryId, code: data.code, id: { not: currencyId } },
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
    data: { code: data.code, name: data.name, symbol: data.symbol },
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
 * Cambia moneda base y:
 * - Recalcula Metal.referenceValue (metales padre) porque está expresado en moneda base.
 * - Recalcula y guarda nuevas CurrencyRate para mantener consistencia.
 *
 * Convención:
 * CurrencyRate.rate: 1 currency = rate * baseCurrency
 */
export async function setBaseCurrency(jewelryId: string, newBaseCurrencyId: string, createdById?: string | null) {
  const now = new Date();

  return prisma.$transaction(async (tx) => {
    const currencies = await tx.currency.findMany({
      where: { jewelryId },
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

    if (newBase.isBase) {
      await tx.currency.update({
        where: { id: newBase.id },
        data: { isActive: true },
      });
      const row = await tx.currency.findUnique({
        where: { id: newBase.id },
        select: {
          id: true,
          code: true,
          name: true,
          symbol: true,
          isBase: true,
          isActive: true,
        },
      });
      return row!;
    }

    if (!oldBase) {
      await tx.currency.updateMany({
        where: { jewelryId, isBase: true },
        data: { isBase: false },
      });

      const row = await tx.currency.update({
        where: { id: newBase.id },
        data: { isBase: true, isActive: true },
        select: {
          id: true,
          code: true,
          name: true,
          symbol: true,
          isBase: true,
          isActive: true,
        },
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

    // Recalcular metales padre
    const metals = await tx.metal.findMany({
      where: { jewelryId },
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

    const newRatesToUpsert: Array<{
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

      newRatesToUpsert.push({
        currencyId: c.id,
        rate: new Prisma.Decimal(rNew),
        effectiveAt: now,
        createdById: createdById || null,
      });
    }

    await tx.currency.updateMany({
      where: { jewelryId, isBase: true },
      data: { isBase: false },
    });

    const baseRow = await tx.currency.update({
      where: { id: newBase.id },
      data: { isBase: true, isActive: true },
      select: {
        id: true,
        code: true,
        name: true,
        symbol: true,
        isBase: true,
        isActive: true,
      },
    });

    for (const x of newRatesToUpsert) {
      const existing = await tx.currencyRate.findFirst({
        where: { currencyId: x.currencyId, effectiveAt: x.effectiveAt },
        select: { id: true },
      });

      if (existing) {
        await tx.currencyRate.update({
          where: { id: existing.id },
          data: { rate: x.rate, createdById: x.createdById },
        });
      } else {
        await tx.currencyRate.create({
          data: {
            currencyId: x.currencyId,
            rate: x.rate,
            effectiveAt: x.effectiveAt,
            createdById: x.createdById,
          },
        });
      }
    }

    return baseRow;
  });
}

/**
 * ✅ API para el controller (firma estable).
 */
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
    where: { jewelryId, isBase: true },
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
    where: { id: currencyId, jewelryId },
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

export async function addCurrencyRate(
  jewelryId: string,
  currencyId: string,
  data: { rate: number; effectiveAt: Date },
  createdById: string | null
) {
  const cur = await prisma.currency.findFirst({
    where: { id: currencyId, jewelryId },
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

  return prisma.currencyRate.create({
    data: {
      currencyId,
      rate: data.rate,
      effectiveAt: data.effectiveAt,
      createdById: createdById || null,
    },
    select: {
      id: true,
      rate: true,
      effectiveAt: true,
      createdAt: true,
    },
  });
}

export async function listCurrencyRates(jewelryId: string, currencyId: string, take = 50) {
  const cur = await prisma.currency.findFirst({
    where: { id: currencyId, jewelryId },
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
    select: {
      id: true,
      rate: true,
      effectiveAt: true,
      createdAt: true,
    },
  });

  return rows.map((r) => ({ ...r, rate: Number(r.rate) }));
}

export async function deleteCurrency(jewelryId: string, currencyId: string) {
  const cur = await prisma.currency.findFirst({
    where: { id: currencyId, jewelryId },
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

  await prisma.currency.delete({ where: { id: cur.id } });
  return { ok: true };
}

/* =========================
   Metales
========================= */

export async function listMetalRefHistory(jewelryId: string, metalId: string, take = 80) {
  const metal = await prisma.metal.findFirst({
    where: { id: metalId, jewelryId },
    select: { id: true },
  });
  if (!metal) {
    const err: any = new Error("Metal no encontrado.");
    err.status = 404;
    throw err;
  }

  const rows = await prisma.metalRefValueHistory.findMany({
    where: { jewelryId, metalId },
    orderBy: [{ effectiveAt: "desc" }, { createdAt: "desc" }],
    take: clampTake(take, 80),
    select: {
      id: true,
      referenceValue: true,
      effectiveAt: true,
      createdAt: true,
      createdBy: { select: { id: true, name: true, email: true } },
    },
  });

  return rows.map((r) => ({
    id: r.id,
    referenceValue: Number(r.referenceValue),
    effectiveAt: r.effectiveAt,
    createdAt: r.createdAt,
    user: r.createdBy ? { id: r.createdBy.id, name: r.createdBy.name, email: r.createdBy.email } : null,
  }));
}

export async function moveMetal(jewelryId: string, metalId: string, dir: "UP" | "DOWN") {
  return prisma.$transaction(async (tx) => {
    const list = await tx.metal.findMany({
      where: { jewelryId },
      orderBy: [{ sortOrder: "asc" }, { name: "asc" }],
      select: { id: true, sortOrder: true, name: true, symbol: true, referenceValue: true, isActive: true },
    });

    const idx = list.findIndex((m) => m.id === metalId);
    if (idx < 0) {
      const err: any = new Error("Metal no encontrado.");
      err.status = 404;
      throw err;
    }

    const swapWith = dir === "UP" ? idx - 1 : idx + 1;
    if (swapWith < 0 || swapWith >= list.length) {
      return { ok: true, changed: false, rows: list };
    }

    const needNormalize = list.every((x) => (x.sortOrder ?? 0) === 0);
    if (needNormalize) {
      for (let i = 0; i < list.length; i++) {
        await tx.metal.update({ where: { id: list[i].id }, data: { sortOrder: i } });
      }
    }

    const list2 = await tx.metal.findMany({
      where: { jewelryId },
      orderBy: [{ sortOrder: "asc" }, { name: "asc" }],
      select: { id: true, sortOrder: true, name: true, symbol: true, referenceValue: true, isActive: true },
    });

    const idx2 = list2.findIndex((m) => m.id === metalId);
    const swap2 = dir === "UP" ? idx2 - 1 : idx2 + 1;

    if (swap2 < 0 || swap2 >= list2.length) {
      return { ok: true, changed: false, rows: list2 };
    }

    const a = list2[idx2];
    const b = list2[swap2];

    await tx.metal.update({ where: { id: a.id }, data: { sortOrder: b.sortOrder ?? 0 } });
    await tx.metal.update({ where: { id: b.id }, data: { sortOrder: a.sortOrder ?? 0 } });

    const out = await tx.metal.findMany({
      where: { jewelryId },
      orderBy: [{ sortOrder: "asc" }, { name: "asc" }],
      select: { id: true, name: true, symbol: true, referenceValue: true, isActive: true, sortOrder: true },
    });

    return { ok: true, changed: true, rows: out.map((m) => ({ ...m, referenceValue: Number(m.referenceValue) })) };
  });
}

export async function createMetal(
  jewelryId: string,
  data: { name: string; symbol?: string; referenceValue?: number },
  actorUserId?: string | null
) {
  const ref = toRefValue((data as any).referenceValue);

  return prisma.$transaction(async (tx) => {
    const agg = await tx.metal.aggregate({
      where: { jewelryId },
      _max: { sortOrder: true },
    });
    const nextSort = Number(agg._max.sortOrder ?? 0) + 1;

    const row = await tx.metal.create({
      data: {
        jewelryId,
        name: String(data.name || "").trim(),
        symbol: String(data.symbol || "").trim(),
        referenceValue: ref ?? 0,
        sortOrder: nextSort,
        isActive: true,
      },
      select: { id: true, name: true, symbol: true, referenceValue: true, isActive: true, sortOrder: true },
    });

    if (ref !== undefined) {
      await tx.metalRefValueHistory.create({
        data: {
          jewelryId,
          metalId: row.id,
          referenceValue: new Prisma.Decimal(ref ?? 0),
          effectiveAt: new Date(),
          createdById: actorUserId ?? null,
        },
      });
    }

    return { ...row, referenceValue: Number(row.referenceValue) };
  });
}

export async function listMetals(jewelryId: string) {
  const rows = await prisma.metal.findMany({
    where: { jewelryId },
    orderBy: [{ sortOrder: "asc" }, { name: "asc" }],
    select: { id: true, name: true, symbol: true, referenceValue: true, isActive: true, sortOrder: true },
  });

  return rows.map((m) => ({ ...m, referenceValue: Number(m.referenceValue) }));
}

export async function updateMetal(
  jewelryId: string,
  metalId: string,
  data: { name: string; symbol: string; referenceValue?: number },
  actorUserId?: string | null
) {
  const m = await prisma.metal.findFirst({
    where: { id: metalId, jewelryId },
    select: { id: true, name: true, referenceValue: true },
  });
  if (!m) {
    const err: any = new Error("Metal no encontrado.");
    err.status = 404;
    throw err;
  }

  const nextName = String(data.name || "").trim();
  if (nextName !== m.name) {
    const dup = await prisma.metal.findFirst({
      where: { jewelryId, name: nextName, id: { not: metalId } },
      select: { id: true },
    });
    if (dup) {
      const err: any = new Error("Ya existe un metal con ese nombre.");
      err.status = 409;
      throw err;
    }
  }

  const ref = toRefValue((data as any).referenceValue);

  return prisma.$transaction(async (tx) => {
    const row = await tx.metal.update({
      where: { id: metalId },
      data: {
        name: nextName,
        symbol: String(data.symbol || "").trim(),
        ...(ref !== undefined ? { referenceValue: ref } : {}),
      },
      select: { id: true, name: true, symbol: true, referenceValue: true, isActive: true, sortOrder: true },
    });

    if (ref !== undefined) {
      const prev = Number(m.referenceValue ?? 0);
      const next = Number(ref ?? 0);
      if (prev !== next) {
        await tx.metalRefValueHistory.create({
          data: {
            jewelryId,
            metalId,
            referenceValue: new Prisma.Decimal(next),
            effectiveAt: new Date(),
            createdById: actorUserId ?? null,
          },
        });
      }
    }

    return { ...row, referenceValue: Number(row.referenceValue) };
  });
}

export async function deleteMetal(jewelryId: string, metalId: string) {
  const m = await prisma.metal.findFirst({
    where: { id: metalId, jewelryId },
    select: { id: true, name: true },
  });
  if (!m) {
    const err: any = new Error("Metal no encontrado.");
    err.status = 404;
    throw err;
  }

  const variantsCount = await prisma.metalVariant.count({
    where: { metalId: m.id },
  });

  if (variantsCount > 0) {
    const err: any = new Error(`No se puede eliminar ${m.name}: tiene ${variantsCount} variante(s).`);
    err.status = 409;
    throw err;
  }

  await prisma.metal.delete({ where: { id: m.id } });
  return { ok: true };
}

export async function toggleMetalActive(jewelryId: string, metalId: string, isActive: boolean) {
  const m = await prisma.metal.findFirst({
    where: { id: metalId, jewelryId },
    select: { id: true },
  });
  if (!m) {
    const err: any = new Error("Metal no encontrado.");
    err.status = 404;
    throw err;
  }

  return prisma.$transaction(async (tx) => {
    const row = await tx.metal.update({
      where: { id: metalId },
      data: { isActive },
      select: { id: true, name: true, symbol: true, referenceValue: true, isActive: true, sortOrder: true },
    });

    if (!isActive) {
      await tx.metalVariant.updateMany({
        where: { metalId },
        data: { isActive: false },
      });
    }

    return { ...row, referenceValue: Number(row.referenceValue) };
  });
}

/* =========================
   Variantes
========================= */

export async function createMetalVariant(
  jewelryId: string,
  data: {
    metalId: string;
    name: string;
    sku: string;
    purity: number;
    buyFactor?: number;
    saleFactor?: number;
    purchasePriceOverride?: number | null;
    salePriceOverride?: number | null;
  }
) {
  // Validación metal + referencia (la necesitamos para calcular)
  const metal = await prisma.metal.findFirst({
    where: { id: data.metalId, jewelryId },
    select: { id: true, referenceValue: true },
  });
  if (!metal) {
    const err: any = new Error("Metal no encontrado.");
    err.status = 404;
    throw err;
  }

  const buyFactorN = data.buyFactor === undefined ? undefined : Number(data.buyFactor);
  const saleFactorN = data.saleFactor === undefined ? undefined : Number(data.saleFactor);

  const pOverrideIn = data.purchasePriceOverride === undefined ? undefined : data.purchasePriceOverride;
  const sOverrideIn = data.salePriceOverride === undefined ? undefined : data.salePriceOverride;

  const pricingMode =
    (pOverrideIn ?? null) !== null || (sOverrideIn ?? null) !== null ? ("OVERRIDE" as any) : ("AUTO" as any);

  // Persistimos como Decimal
  const buyFactor = buyFactorN !== undefined ? dec(buyFactorN, 1) : new Prisma.Decimal(1);
  const saleFactor = saleFactorN !== undefined ? dec(saleFactorN, 1) : new Prisma.Decimal(1);

  const pOverride = pOverrideIn === undefined ? undefined : pOverrideIn === null ? null : dec(pOverrideIn);
  const sOverride = sOverrideIn === undefined ? undefined : sOverrideIn === null ? null : dec(sOverrideIn);

  // Creamos variante y devolvemos data base + pricing
  const v = await prisma.metalVariant.create({
    data: {
      metalId: data.metalId,
      name: String(data.name || "").trim(),
      sku: String(data.sku || "").trim(),
      purity: dec(data.purity, 0), // guardamos decimal
      isActive: true,
      isFavorite: false,

      buyFactor,
      saleFactor,
      ...(pOverride !== undefined ? { purchasePriceOverride: pOverride } : {}),
      ...(sOverride !== undefined ? { salePriceOverride: sOverride } : {}),
      pricingMode,
    },
    select: {
      id: true,
      metalId: true,
      name: true,
      sku: true,
      purity: true,
      isFavorite: true,
      isActive: true,
      createdAt: true,
      updatedAt: true,
      buyFactor: true,
      saleFactor: true,
      purchasePriceOverride: true,
      salePriceOverride: true,
      pricingMode: true,
    },
  });

  // ✅ Calculados (idéntico a listMetalVariants)
  const ref = new Prisma.Decimal(metal.referenceValue ?? 0);
  const purity = new Prisma.Decimal(v.purity ?? 0);
  const suggested = computeSuggested(ref, purity);

  const pOv = v.purchasePriceOverride ? new Prisma.Decimal(v.purchasePriceOverride as any) : null;
  const sOv = v.salePriceOverride ? new Prisma.Decimal(v.salePriceOverride as any) : null;

  const finalPurchase = computeFinal(suggested, new Prisma.Decimal(v.buyFactor ?? 1), pOv);
  const finalSale = computeFinal(suggested, new Prisma.Decimal(v.saleFactor ?? 1), sOv);

  return {
    id: v.id,
    metalId: v.metalId,
    name: v.name,
    sku: v.sku,
    purity: Number(v.purity),

    isFavorite: v.isFavorite,
    isActive: v.isActive,
    createdAt: v.createdAt,
    updatedAt: v.updatedAt,

    buyFactor: Number(v.buyFactor ?? 1),
    saleFactor: Number(v.saleFactor ?? 1),
    purchasePriceOverride: v.purchasePriceOverride === null ? null : Number(v.purchasePriceOverride),
    salePriceOverride: v.salePriceOverride === null ? null : Number(v.salePriceOverride),
    pricingMode: (v as any).pricingMode ?? "AUTO",

    suggestedPrice: Number(suggested),
    finalPurchasePrice: Number(finalPurchase),
    finalSalePrice: Number(finalSale),
    referenceValue: Number(ref),
  };
}

/**
 * ✅ NUEVO: editar variante completa (name/sku/purity + opcional saleFactor y saleOverride)
 * Devuelve row "enriquecida" con suggested/finalSale/referenceValue.
 */
export async function updateMetalVariant(
  jewelryId: string,
  variantId: string,
  data: {
    name: string;
    sku: string;
    purity: number;
    saleFactor?: number;
    salePriceOverride?: number | null;
  }
) {
  const existing = await prisma.metalVariant.findFirst({
    where: { id: variantId, metal: { jewelryId } },
    select: {
      id: true,
      metalId: true,
      sku: true,
      purity: true,
      saleFactor: true,
      salePriceOverride: true,
      buyFactor: true,
      purchasePriceOverride: true,
      isFavorite: true,
      isActive: true,
      pricingMode: true,
      metal: { select: { referenceValue: true } },
    },
  });

  if (!existing) {
    const err: any = new Error("Variante no encontrada.");
    err.status = 404;
    throw err;
  }

  const nextName = String(data.name || "").trim();
  const nextSku = String(data.sku || "").trim().toUpperCase();

  if (!nextName) {
    const err: any = new Error("Nombre requerido.");
    err.status = 400;
    throw err;
  }
  if (!nextSku) {
    const err: any = new Error("SKU requerido.");
    err.status = 400;
    throw err;
  }

  // SKU único dentro del metal
  const dup = await prisma.metalVariant.findFirst({
    where: {
      metalId: existing.metalId,
      sku: nextSku,
      id: { not: variantId },
    },
    select: { id: true },
  });
  if (dup) {
    const err: any = new Error(`SKU duplicado: "${nextSku}" ya existe.`);
    err.status = 409;
    throw err;
  }

  const purityDec = dec(data.purity, 0);
  const saleFactorDec = data.saleFactor !== undefined ? dec(data.saleFactor, 1) : undefined;

  const saleOverrideDec =
    data.salePriceOverride === undefined
      ? undefined
      : data.salePriceOverride === null
      ? null
      : dec(data.salePriceOverride);

  // pricingMode informativo (solo en base al override de venta)
  const pricingMode =
    saleOverrideDec === undefined ? undefined : saleOverrideDec === null ? ("AUTO" as any) : ("OVERRIDE" as any);

  const updated = await prisma.metalVariant.update({
    where: { id: variantId },
    data: {
      name: nextName,
      sku: nextSku,
      purity: purityDec,
      ...(saleFactorDec !== undefined ? { saleFactor: saleFactorDec } : {}),
      ...(saleOverrideDec !== undefined ? { salePriceOverride: saleOverrideDec } : {}),
      ...(pricingMode !== undefined ? { pricingMode } : {}),
    },
    select: {
      id: true,
      metalId: true,
      name: true,
      sku: true,
      purity: true,
      isFavorite: true,
      isActive: true,
      buyFactor: true,
      saleFactor: true,
      purchasePriceOverride: true,
      salePriceOverride: true,
      pricingMode: true,
      createdAt: true,
      updatedAt: true,
      metal: { select: { referenceValue: true } },
    },
  });

  const ref = new Prisma.Decimal(updated.metal.referenceValue ?? 0);
  const suggested = computeSuggested(ref, new Prisma.Decimal(updated.purity ?? 0));

  const finalPurchase = computeFinal(
    suggested,
    new Prisma.Decimal(updated.buyFactor ?? 1),
    updated.purchasePriceOverride ? new Prisma.Decimal(updated.purchasePriceOverride as any) : null
  );

  const finalSale = computeFinal(
    suggested,
    new Prisma.Decimal(updated.saleFactor ?? 1),
    updated.salePriceOverride ? new Prisma.Decimal(updated.salePriceOverride as any) : null
  );

  return {
    id: updated.id,
    metalId: updated.metalId,
    name: updated.name,
    sku: updated.sku,
    purity: Number(updated.purity),

    isFavorite: updated.isFavorite,
    isActive: updated.isActive,
    createdAt: updated.createdAt,
    updatedAt: updated.updatedAt,

    buyFactor: Number(updated.buyFactor ?? 1),
    saleFactor: Number(updated.saleFactor ?? 1),
    purchasePriceOverride: updated.purchasePriceOverride === null ? null : Number(updated.purchasePriceOverride),
    salePriceOverride: updated.salePriceOverride === null ? null : Number(updated.salePriceOverride),
    pricingMode: (updated as any).pricingMode ?? "AUTO",

    suggestedPrice: Number(suggested),
    finalPurchasePrice: Number(finalPurchase),
    finalSalePrice: Number(finalSale),
    referenceValue: Number(ref),
  };
}

export async function updateMetalVariantPricing(
  jewelryId: string,
  variantId: string,
  data: {
    buyFactor?: number;
    saleFactor?: number;
    purchasePriceOverride?: number | null;
    salePriceOverride?: number | null;
    clearPurchaseOverride?: boolean;
    clearSaleOverride?: boolean;
  }
) {
  const v = await prisma.metalVariant.findFirst({
    where: { id: variantId, metal: { jewelryId } },
    select: {
      id: true,
      purchasePriceOverride: true,
      salePriceOverride: true,
    },
  });
  if (!v) {
    const err: any = new Error("Variante no encontrada.");
    err.status = 404;
    throw err;
  }

  const patch: any = {};

  if (data.buyFactor !== undefined) patch.buyFactor = dec(data.buyFactor, 1);
  if (data.saleFactor !== undefined) patch.saleFactor = dec(data.saleFactor, 1);

  if (data.clearPurchaseOverride) patch.purchasePriceOverride = null;
  if (data.clearSaleOverride) patch.salePriceOverride = null;

  if (data.purchasePriceOverride !== undefined) {
    patch.purchasePriceOverride = data.purchasePriceOverride === null ? null : dec(data.purchasePriceOverride);
  }
  if (data.salePriceOverride !== undefined) {
    patch.salePriceOverride = data.salePriceOverride === null ? null : dec(data.salePriceOverride);
  }

  // pricingMode informativo
  const nextPurchase = patch.purchasePriceOverride !== undefined ? patch.purchasePriceOverride : v.purchasePriceOverride;
  const nextSale = patch.salePriceOverride !== undefined ? patch.salePriceOverride : v.salePriceOverride;

  patch.pricingMode = nextPurchase || nextSale ? ("OVERRIDE" as any) : ("AUTO" as any);

  return prisma.metalVariant.update({
    where: { id: variantId },
    data: patch,
  });
}

/**
 * ✅ Alias “estable” para el controller/frontend.
 * (Así no te queda el nombre “MetalVariant” en todos lados.)
 */
export async function updateVariantPricing(
  jewelryId: string,
  variantId: string,
  data: {
    buyFactor?: number;
    saleFactor?: number;
    purchasePriceOverride?: number | null;
    salePriceOverride?: number | null;
    clearPurchaseOverride?: boolean;
    clearSaleOverride?: boolean;
  }
) {
  return updateMetalVariantPricing(jewelryId, variantId, data);
}

export async function listMetalVariants(
  jewelryId: string,
  metalId: string,
  params?: {
    q?: string;
    isActive?: boolean;
    onlyFavorites?: boolean;
    minPurchase?: number;
    maxPurchase?: number;
    minSale?: number;
    maxSale?: number;
    currencyId?: string;
  }
) {
  const metal = await prisma.metal.findFirst({
    where: { id: metalId, jewelryId },
    select: { id: true, referenceValue: true },
  });
  if (!metal) {
    const err: any = new Error("Metal no encontrado.");
    err.status = 404;
    throw err;
  }

  const where: any = { metalId, metal: { jewelryId } };

  if (typeof params?.isActive === "boolean") where.isActive = params.isActive;
  if (params?.onlyFavorites) where.isFavorite = true;

  const q = String(params?.q || "").trim();
  if (q) {
    where.OR = [{ name: { contains: q, mode: "insensitive" } }, { sku: { contains: q, mode: "insensitive" } }];
  }

  const rows = await prisma.metalVariant.findMany({
    where,
    orderBy: [{ isFavorite: "desc" }, { name: "asc" }],
    select: {
      id: true,
      metalId: true,
      name: true,
      sku: true,
      purity: true,
      isFavorite: true,
      isActive: true,
      createdAt: true,
      updatedAt: true,

      // ✅ nuevos campos persistidos
      buyFactor: true,
      saleFactor: true,
      purchasePriceOverride: true,
      salePriceOverride: true,
      pricingMode: true,
    },
  });

  const ref = new Prisma.Decimal(metal.referenceValue ?? 0);

  return rows.map((v) => {
    const purity = new Prisma.Decimal(v.purity ?? 0);
    const suggested = computeSuggested(ref, purity);

    const buyFactor = new Prisma.Decimal(v.buyFactor ?? 1);
    const saleFactor = new Prisma.Decimal(v.saleFactor ?? 1);

    const pOverride = (v.purchasePriceOverride as any) ? new Prisma.Decimal(v.purchasePriceOverride as any) : null;
    const sOverride = (v.salePriceOverride as any) ? new Prisma.Decimal(v.salePriceOverride as any) : null;

    const finalPurchase = computeFinal(suggested, buyFactor, pOverride);
    const finalSale = computeFinal(suggested, saleFactor, sOverride);

    return {
      id: v.id,
      metalId: v.metalId,
      name: v.name,
      sku: v.sku,
      purity: Number(v.purity),

      isFavorite: v.isFavorite,
      isActive: v.isActive,
      createdAt: v.createdAt,
      updatedAt: v.updatedAt,

      buyFactor: Number(v.buyFactor ?? 1),
      saleFactor: Number(v.saleFactor ?? 1),
      purchasePriceOverride: v.purchasePriceOverride === null ? null : Number(v.purchasePriceOverride),
      salePriceOverride: v.salePriceOverride === null ? null : Number(v.salePriceOverride),
      pricingMode: (v as any).pricingMode ?? "AUTO",

      // ✅ calculados backend
      suggestedPrice: Number(suggested),
      finalPurchasePrice: Number(finalPurchase),
      finalSalePrice: Number(finalSale),
      referenceValue: Number(ref),
    };
  });
}

/**
 * ✅ FAVORITOS (MULTI)
 * - Antes: dejaba solo 1 favorita por metal (limpiaba las demás)
 * - Ahora: TOGGLE (podés tener 0, 1 o muchas)
 */
export async function setFavoriteVariant(jewelryId: string, variantId: string) {
  const v = await prisma.metalVariant.findFirst({
    where: { id: variantId, metal: { jewelryId } },
    select: { id: true, isFavorite: true },
  });
  if (!v) {
    const err: any = new Error("Variante no encontrada.");
    err.status = 404;
    throw err;
  }

  return prisma.metalVariant.update({
    where: { id: v.id },
    data: { isFavorite: !v.isFavorite },
  });
}

/**
 * ✅ NUEVO: limpiar favorito de un metal (deja todas las variantes isFavorite=false)
 */
export async function clearFavoriteVariant(jewelryId: string, metalId: string) {
  const metal = await prisma.metal.findFirst({
    where: { id: metalId, jewelryId },
    select: { id: true },
  });

  if (!metal) {
    const err: any = new Error("Metal no encontrado.");
    err.status = 404;
    throw err;
  }

  await prisma.metalVariant.updateMany({
    where: { metalId, metal: { jewelryId } },
    data: { isFavorite: false },
  });

  return { ok: true };
}

export async function toggleVariantActive(jewelryId: string, variantId: string, isActive: boolean) {
  const v = await prisma.metalVariant.findFirst({
    where: { id: variantId, metal: { jewelryId } },
    select: { id: true },
  });
  if (!v) {
    const err: any = new Error("Variante no encontrada.");
    err.status = 404;
    throw err;
  }

  return prisma.metalVariant.update({ where: { id: variantId }, data: { isActive } });
}

/**
 * ✅ Eliminar variante (con protección si tiene cotizaciones)
 * - Si tiene metalQuote(s), devolvemos 409 para que el frontend muestre hint.
 */
export async function deleteVariant(jewelryId: string, variantId: string) {
  const v = await prisma.metalVariant.findFirst({
    where: { id: variantId, metal: { jewelryId } },
    select: { id: true, name: true },
  });
  if (!v) {
    const err: any = new Error("Variante no encontrada.");
    err.status = 404;
    throw err;
  }

  const quotesCount = await prisma.metalQuote.count({
    where: { variantId: v.id },
  });

  if (quotesCount > 0) {
    const err: any = new Error(`No se puede eliminar la variante: tiene ${quotesCount} cotización(es).`);
    err.status = 409;
    throw err;
  }

  await prisma.metalVariant.delete({ where: { id: v.id } });
  return { ok: true };
}

/* =========================
   Quotes
========================= */

export async function addMetalQuote(
  jewelryId: string,
  data: {
    variantId: string;
    currencyId: string;
    purchasePrice: number;
    salePrice: number;
    effectiveAt?: Date;
  }
) {
  const v = await prisma.metalVariant.findFirst({
    where: { id: data.variantId, metal: { jewelryId } },
    select: { id: true },
  });
  if (!v) {
    const err: any = new Error("Variante no encontrada.");
    err.status = 404;
    throw err;
  }

  const c = await prisma.currency.findFirst({
    where: { id: data.currencyId, jewelryId },
    select: { id: true },
  });
  if (!c) {
    const err: any = new Error("Moneda no encontrada.");
    err.status = 404;
    throw err;
  }

  return prisma.metalQuote.create({
    data: {
      variantId: data.variantId,
      currencyId: data.currencyId,
      purchasePrice: data.purchasePrice,
      salePrice: data.salePrice,
      effectiveAt: data.effectiveAt ?? new Date(),
    },
  });
}

export async function listMetalQuotes(jewelryId: string, variantId: string, take = 50) {
  const v = await prisma.metalVariant.findFirst({
    where: { id: variantId, metal: { jewelryId } },
    select: { id: true },
  });
  if (!v) {
    const err: any = new Error("Variante no encontrada.");
    err.status = 404;
    throw err;
  }

  return prisma.metalQuote.findMany({
    where: {
      variantId,
      variant: { metal: { jewelryId } },
    },
    orderBy: [{ effectiveAt: "desc" }, { createdAt: "desc" }],
    take: clampTake(take, 50),
    include: { currency: { select: { id: true, code: true, symbol: true } } },
  });
}