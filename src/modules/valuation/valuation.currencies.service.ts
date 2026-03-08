// tptech-backend/src/modules/valuation/valuation.currencies.service.ts
import { Prisma } from "@prisma/client";
import { prisma } from "../../lib/prisma.js";

import { toNum, assertFinitePositive, same6 } from "./valuation.helpers.js";

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

/**
 * ✅ IMPORTANTE (soft-delete + unique):
 * - El índice unique es (jewelryId, code) y NO contempla deletedAt.
 * - Entonces, si se soft-elimina una moneda, hay que "liberar" el code.
 *
 * ✅ Estrategia (como en otros módulos):
 * - Si existe un registro borrado con ese code, lo "liberamos" renombrándolo (freedCode)
 *   y luego creamos la nueva moneda.
 */
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
    // 🔥 Buscar por code sin filtrar deletedAt (por el UNIQUE real en DB)
    const anyRow = await tx.currency.findFirst({
      where: { jewelryId, code },
      select: { id: true, deletedAt: true },
    });

    if (anyRow) {
      // Si está viva -> conflicto real
      if (!anyRow.deletedAt) {
        const err: any = new Error("Ya existe una moneda con ese código.");
        err.status = 409;
        throw err;
      }

      // Si está borrada -> liberar el unique renombrando el code del borrado
      await tx.currency.update({
        where: { id: anyRow.id },
        data: { code: freedCode(code, anyRow.id) },
      });
    }

    const count = await tx.currency.count({
      where: { jewelryId, deletedAt: null },
    });
    const isFirst = count === 0;

    if (isFirst) {
      await tx.currency.updateMany({
        where: { jewelryId, deletedAt: null, isBase: true },
        data: { isBase: false },
      });
    }

    try {
      return await tx.currency.create({
        data: {
          jewelryId,
          code,
          name,
          symbol,
          isBase: isFirst,
          isActive: true,
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
    } catch (e: any) {
      // ✅ Mensaje claro si igual hubo carrera/colisión
      if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002") {
        const err: any = new Error("Ya existe una moneda con ese código (o fue eliminada sin liberar el código).");
        err.status = 409;
        throw err;
      }
      throw e;
    }
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

  // ✅ Si cambia el code, hay que chequear duplicados SIN filtrar deletedAt
  // (por el UNIQUE real en DB). Si el duplicado está borrado, lo "liberamos".
  if (code !== cur.code) {
    await prisma.$transaction(async (tx) => {
      const dupAny = await tx.currency.findFirst({
        where: { jewelryId, code, id: { not: currencyId } },
        select: { id: true, deletedAt: true },
      });

      if (dupAny) {
        if (!dupAny.deletedAt) {
          const err: any = new Error("Ya existe una moneda con ese código.");
          err.status = 409;
          throw err;
        }

        // estaba borrada pero bloqueando el unique -> liberar
        await tx.currency.update({
          where: { id: dupAny.id },
          data: { code: freedCode(code, dupAny.id) },
        });
      }

      try {
        await tx.currency.update({
          where: { id: currencyId },
          data: { code, name, symbol },
        });
      } catch (e: any) {
        if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002") {
          const err: any = new Error("Ya existe una moneda con ese código.");
          err.status = 409;
          throw err;
        }
        throw e;
      }
    });

    // devolver la moneda actualizada (select consistente)
    return prisma.currency.findUnique({
      where: { id: currencyId },
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

  // ✅ Si NO cambia el code, update normal
  try {
    return await prisma.currency.update({
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
  } catch (e: any) {
    if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002") {
      const err: any = new Error("Ya existe una moneda con ese código.");
      err.status = 409;
      throw err;
    }
    throw e;
  }
}

/* ============================================================
   CAMBIO DE BASE REAL (Opción A)
   ✅ Unificado:
   - Convierte metales + historiales
   - ✅ Convierte overrides vivos (metalVariant)
   - Recalcula rates para NO-base
   - ✅ Crea rate para la vieja base (1/rN)
============================================================ */

export async function setBaseCurrency(jewelryId: string, newBaseCurrencyId: string, createdById?: string | null) {
  const now = new Date();

  return prisma.$transaction(async (tx) => {
    const currencies = await tx.currency.findMany({
      where: { jewelryId, deletedAt: null },
      select: { id: true, code: true, isBase: true },
    });

    const oldBase = currencies.find((c) => c.isBase) ?? null;
    const newBase = currencies.find((c) => c.id === newBaseCurrencyId) ?? null;

    if (!newBase) {
      const err: any = new Error("Moneda no encontrada.");
      err.status = 404;
      throw err;
    }

    // ya era base
    if (newBase.isBase) return newBase;

    // si por alguna razón no había base marcada
    if (!oldBase) {
      await tx.currency.updateMany({
        where: { jewelryId, deletedAt: null, isBase: true },
        data: { isBase: false },
      });

      return tx.currency.update({
        where: { id: newBase.id },
        data: { isBase: true, isActive: true },
      });
    }

    // rate de la nueva base (medido contra la base actual = oldBase)
    const lastRate = await tx.currencyRate.findFirst({
      where: { currencyId: newBase.id },
      orderBy: [{ effectiveAt: "desc" }, { createdAt: "desc" }],
      select: { rate: true },
    });

    const rN = toNum(lastRate?.rate, NaN);

    assertFinitePositive(rN, `No se puede cambiar la base: ${newBase.code} no tiene tipo de cambio cargado.`);

    const k = new Prisma.Decimal(rN);

    /* =========================
       Convertir metal (referenceValue)
    ========================= */
    const metals = await tx.metal.findMany({
      where: { jewelryId, deletedAt: null },
      select: { id: true, referenceValue: true },
    });

    for (const m of metals) {
      await tx.metal.update({
        where: { id: m.id },
        data: { referenceValue: new Prisma.Decimal(m.referenceValue).div(k) },
      });
    }

    /* =========================
       Convertir historial metal
    ========================= */
    const metalHistory = await tx.metalRefValueHistory.findMany({
      where: { jewelryId },
      select: { id: true, referenceValue: true },
    });

    for (const h of metalHistory) {
      await tx.metalRefValueHistory.update({
        where: { id: h.id },
        data: { referenceValue: new Prisma.Decimal(h.referenceValue).div(k) },
      });
    }

    /* =========================
       Convertir historial variantes
    ========================= */
    const variantHistory = await tx.metalVariantValueHistory.findMany({
      where: { jewelryId },
      select: { id: true, referenceValue: true, finalSalePrice: true },
    });

    for (const v of variantHistory) {
      await tx.metalVariantValueHistory.update({
        where: { id: v.id },
        data: {
          referenceValue: new Prisma.Decimal(v.referenceValue).div(k),
          finalSalePrice: new Prisma.Decimal(v.finalSalePrice).div(k),
        },
      });
    }

    /* =========================
       Convertir cotizaciones de variantes (MetalQuote)
       Solo las que estaban en la vieja base — se re-expresan en la nueva base.
       Las cotizaciones en otras monedas no se tocan.
    ========================= */
    const quotesInOldBase = await tx.metalQuote.findMany({
      where: {
        currencyId: oldBase.id,
        variant: { metal: { jewelryId } },
      },
      select: { id: true, price: true },
    });

    for (const q of quotesInOldBase) {
      await tx.metalQuote.update({
        where: { id: q.id },
        data: {
          price: new Prisma.Decimal(q.price).div(k),
          currencyId: newBase.id,
        },
      });
    }

    /* =========================
       Recalcular rates
       - Usamos el último rate disponible por currencyId
    ========================= */
    const allRates = await tx.currencyRate.findMany({
      where: { currencyId: { in: currencies.map((c) => c.id) } },
      orderBy: [{ effectiveAt: "desc" }, { createdAt: "desc" }],
      select: { currencyId: true, rate: true, effectiveAt: true, createdAt: true },
    });

    const rateMap = new Map<string, number>();
    for (const r of allRates) {
      if (!rateMap.has(r.currencyId)) {
        rateMap.set(r.currencyId, Number(r.rate));
      }
    }

    /* =========================
       Convertir historial de tipos de cambio
       (monedas que no son old ni new base)
    ========================= */
    const otherCurrencyIds = currencies
      .filter((c) => c.id !== newBase.id && c.id !== oldBase.id)
      .map((c) => c.id);

    if (otherCurrencyIds.length > 0) {
      const historicalCurrencyRates = await tx.currencyRate.findMany({
        where: { currencyId: { in: otherCurrencyIds } },
        select: { id: true, rate: true },
      });

      for (const r of historicalCurrencyRates) {
        await tx.currencyRate.update({
          where: { id: r.id },
          data: { rate: new Prisma.Decimal(r.rate).div(k) },
        });
      }
    }

    // crear nuevo último rate para cada moneda que NO sea la nueva base
    // (excepto la vieja base, la tratamos abajo con el inverso)
    for (const c of currencies) {
      if (c.id === newBase.id) continue;
      if (c.id === oldBase.id) continue;

      const oldRate = rateMap.get(c.id);
      if (!oldRate) continue;

      const newRate = oldRate / rN;

      await tx.currencyRate.create({
        data: {
          currencyId: c.id,
          rate: new Prisma.Decimal(newRate),
          effectiveAt: now,
          createdById: createdById || null,
        },
      });
    }

    // ✅ FIX CLAVE: la vieja base ahora pasa a ser NO-base, entonces necesita un rate.
    // Convención: "1 moneda = rate * (moneda base)"
    // Antes: 1 newBase = rN * oldBase
    // Ahora: 1 oldBase = (1 / rN) * newBase
    await tx.currencyRate.create({
      data: {
        currencyId: oldBase.id,
        rate: new Prisma.Decimal(1).div(k),
        effectiveAt: now,
        createdById: createdById || null,
      },
    });

    // flip base flags
    await tx.currency.updateMany({
      where: { jewelryId, deletedAt: null, isBase: true },
      data: { isBase: false },
    });

    return tx.currency.update({
      where: { id: newBase.id },
      data: { isBase: true, isActive: true },
    });
  });
}

export async function setBaseCurrencyAndRecalc(args: {
  jewelryId: string;
  newBaseCurrencyId: string;
  actorUserId?: string | null;
}) {
  const row = await setBaseCurrency(args.jewelryId, args.newBaseCurrencyId, args.actorUserId ?? null);

  return {
    ok: true,
    newBaseId: row?.id ?? null,
  };
}

/* ========== RESTO SIN CAMBIOS (con fix en delete) ========== */

export async function toggleCurrencyActive(jewelryId: string, currencyId: string, isActive: boolean) {
  const cur = await prisma.currency.findFirst({
    where: { id: currencyId, jewelryId, deletedAt: null },
    select: { id: true, isBase: true },
  });
  if (!cur) throw new Error("Moneda no encontrada.");
  if (cur.isBase && !isActive) throw new Error("La moneda base no puede desactivarse.");

  return prisma.currency.update({
    where: { id: currencyId },
    data: { isActive },
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
  if (!cur) throw new Error("Moneda no encontrada.");
  if (cur.isBase) throw new Error("La moneda base no necesita tipo de cambio.");

  assertFinitePositive(Number(data.rate), "Tipo de cambio inválido.");

  const last = await prisma.currencyRate.findFirst({
    where: { currencyId },
    orderBy: [{ effectiveAt: "desc" }, { createdAt: "desc" }],
    select: { id: true, rate: true },
  });

  if (last && same6(last.rate, data.rate)) {
    return prisma.currencyRate.findUniqueOrThrow({ where: { id: last.id } });
  }

  return prisma.currencyRate.create({
    data: {
      currencyId,
      rate: data.rate as any,
      effectiveAt: data.effectiveAt,
      createdById: createdById || null,
    },
  });
}

export async function listCurrencyRates(jewelryId: string, currencyId: string, take = 50) {
  return prisma.currencyRate.findMany({
    where: { currencyId },
    orderBy: [{ effectiveAt: "desc" }, { createdAt: "desc" }],
    take,
  });
}

export async function deleteCurrency(jewelryId: string, currencyId: string) {
  const cur = await prisma.currency.findFirst({
    where: { id: currencyId, jewelryId, deletedAt: null },
    select: { id: true, isBase: true, code: true },
  });
  if (!cur) throw new Error("Moneda no encontrada.");
  if (cur.isBase) throw new Error("No se puede eliminar la moneda base.");

  // ✅ FIX CLAVE: liberar UNIQUE (jewelryId, code) renombrando el code al soft-delete
  await prisma.currency.update({
    where: { id: cur.id },
    data: {
      deletedAt: new Date(),
      isActive: false,
      code: freedCode(String(cur.code || "").trim().toUpperCase(), cur.id),
    },
  });

  return { ok: true };
}