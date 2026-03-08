// tptech-backend/src/modules/valuation/valuation.metals.service.ts
import { Prisma } from "@prisma/client";
import { prisma } from "../../lib/prisma.js";

import { dec, assertNonEmpty, toRefValue, clampTake, computeSuggested, same6 } from "./valuation.helpers.js";
import { roundMoney } from "../../lib/money.js";
import { ensureBaseVariantQuoteSnapshot } from "./valuation.quotes.service.js";

function freedName(name: string, id: string) {
  const suffix = `${Date.now()}_${Math.random().toString(16).slice(2)}`;
  return `deleted__${name}__${id}__${suffix}`;
}


/* =========================
   Metales
========================= */

export async function listMetals(jewelryId: string) {
  const rows = await prisma.metal.findMany({
    where: { jewelryId, deletedAt: null },
    orderBy: [{ sortOrder: "asc" }, { name: "asc" }],
    select: {
      id: true,
      name: true,
      symbol: true,
      referenceValue: true,
      sortOrder: true,
      isActive: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  return rows.map((m) => ({
    id: m.id,
    name: m.name,
    symbol: m.symbol ?? "",
    referenceValue: Number(m.referenceValue ?? 0),
    sortOrder: m.sortOrder ?? 0,
    isActive: m.isActive,
    createdAt: m.createdAt,
    updatedAt: m.updatedAt,
  }));
}

export async function createMetal(
  jewelryId: string,
  data: { name: string; symbol?: string; referenceValue?: number },
  createdById?: string | null
) {
  const name = assertNonEmpty(data.name, "Nombre requerido.").trim();
  const symbol = String(data.symbol || "").trim();

  const refN = toRefValue(data.referenceValue);
  const ref = refN !== undefined ? dec(refN) : new Prisma.Decimal(0);

  const now = new Date();

  return prisma.$transaction(async (tx) => {
    // ✅ sortOrder al final (dentro de tx para evitar carreras)
    const max = await tx.metal.aggregate({
      where: { jewelryId, deletedAt: null },
      _max: { sortOrder: true },
    });
    const nextSort = Number(max._max.sortOrder ?? 0) + 1;

    // ✅ UNIQUE real en DB: (jewelryId, name) -> NO contempla deletedAt
    // Entonces buscamos por name sin filtrar deletedAt.
    const anyRow = await tx.metal.findFirst({
      where: { jewelryId, name },
      select: { id: true, deletedAt: true },
    });

    if (anyRow) {
      // vive -> conflicto real
      if (!anyRow.deletedAt) {
        const err: any = new Error("Ya existe un metal con ese nombre.");
        err.status = 409;
        throw err;
      }

      // borrado -> liberar el unique renombrando el name del borrado
      await tx.metal.update({
        where: { id: anyRow.id },
        data: { name: freedName(name, anyRow.id) },
      });
    }

    let row;
    try {
      row = await tx.metal.create({
        data: {
          jewelryId,
          name,
          symbol,
          referenceValue: ref,
          sortOrder: nextSort,
          isActive: true,
          deletedAt: null,
        },
        select: {
          id: true,
          name: true,
          symbol: true,
          referenceValue: true,
          sortOrder: true,
          isActive: true,
          createdAt: true,
          updatedAt: true,
        },
      });
    } catch (e: any) {
      // ✅ mensaje claro si igual hubo colisión
      if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002") {
        const err: any = new Error("Ya existe un metal con ese nombre (o fue eliminado sin liberar el nombre).");
        err.status = 409;
        throw err;
      }
      throw e;
    }

    // historial inicial metal padre
    await tx.metalRefValueHistory.create({
      data: {
        jewelryId,
        metalId: row.id,
        referenceValue: row.referenceValue ?? new Prisma.Decimal(0),
        effectiveAt: now,
        createdById: createdById || null,
      },
    });

    return {
      id: row.id,
      name: row.name,
      symbol: row.symbol ?? "",
      referenceValue: Number(row.referenceValue ?? 0),
      sortOrder: row.sortOrder ?? 0,
      isActive: row.isActive,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  });
}

export async function updateMetal(
  jewelryId: string,
  metalId: string,
  data: { name: string; symbol?: string; referenceValue?: number },
  createdById?: string | null
) {
  const metal = await prisma.metal.findFirst({
    where: { id: metalId, jewelryId, deletedAt: null },
    select: { id: true, name: true, referenceValue: true },
  });
  if (!metal) {
    const err: any = new Error("Metal no encontrado.");
    err.status = 404;
    throw err;
  }

  const name = assertNonEmpty(data.name, "Nombre requerido.").trim();
  const symbol = String(data.symbol || "").trim();

  const refN = toRefValue(data.referenceValue);
  const nextRef = refN !== undefined ? dec(refN) : undefined;

  const prevRef = new Prisma.Decimal(metal.referenceValue ?? 0);
  const now = new Date();

  return prisma.$transaction(async (tx) => {
    // ✅ Si cambia el name:
    // - si existe vivo con ese name -> 409
    // - si existe borrado con ese name -> liberar renombrándolo
    if (name !== metal.name) {
      const dupAny = await tx.metal.findFirst({
        where: { jewelryId, name, id: { not: metalId } },
        select: { id: true, deletedAt: true },
      });

      if (dupAny) {
        if (!dupAny.deletedAt) {
          const err: any = new Error("Ya existe un metal con ese nombre.");
          err.status = 409;
          throw err;
        }

        await tx.metal.update({
          where: { id: dupAny.id },
          data: { name: freedName(name, dupAny.id) },
        });
      }
    }

    let updated;
    try {
      updated = await tx.metal.update({
        where: { id: metalId },
        data: {
          name,
          symbol,
          ...(nextRef !== undefined ? { referenceValue: nextRef } : {}),
        },
        select: {
          id: true,
          name: true,
          symbol: true,
          referenceValue: true,
          sortOrder: true,
          isActive: true,
          createdAt: true,
          updatedAt: true,
        },
      });
    } catch (e: any) {
      if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002") {
        const err: any = new Error("Ya existe un metal con ese nombre.");
        err.status = 409;
        throw err;
      }
      throw e;
    }

    const newRef = new Prisma.Decimal(updated.referenceValue ?? 0);

    // guardar historial metal padre solo si cambió referenceValue
    const refChanged = !newRef.equals(prevRef);

    if (refChanged) {
      await tx.metalRefValueHistory.create({
        data: {
          jewelryId,
          metalId: updated.id,
          referenceValue: newRef,
          effectiveAt: now,
          createdById: createdById || null,
        },
      });

      // ✅ HISTORIAL PROFESIONAL: al cambiar el valor del metal padre,
      // guardamos snapshot para TODAS las variantes (sugerido/final).
      const variants = await tx.metalVariant.findMany({
        where: { metalId: updated.id, deletedAt: null },
        select: { id: true, purity: true, saleFactor: true },
      });

      for (const v of variants) {
        const purity = new Prisma.Decimal(v.purity ?? 0);
        const saleFactor = new Prisma.Decimal(v.saleFactor ?? 1);
        const suggested = computeSuggested(newRef, purity);
        const finalSale = suggested.mul(saleFactor);
        const finalSaleNum = roundMoney(Number(finalSale));

        await ensureBaseVariantQuoteSnapshot({
          jewelryId,
          variantId: v.id,
          price: finalSaleNum,
          effectiveAt: now,
          tx,
        });

        const lastHist = await tx.metalVariantValueHistory.findFirst({
          where: { variantId: v.id },
          orderBy: [{ effectiveAt: "desc" }, { createdAt: "desc" }],
          select: { referenceValue: true, purity: true, saleFactor: true, finalSalePrice: true },
        });

        const histChanged =
          !lastHist ||
          !same6(lastHist.referenceValue, newRef) ||
          !same6(lastHist.purity, purity) ||
          !same6(lastHist.saleFactor, saleFactor) ||
          !same6(lastHist.finalSalePrice, finalSaleNum);

        if (histChanged) {
          await tx.metalVariantValueHistory.create({
            data: {
              jewelryId,
              metalId: updated.id,
              variantId: v.id,
              referenceValue: newRef,
              purity,
              saleFactor,
              finalSalePrice: new Prisma.Decimal(finalSaleNum),
              effectiveAt: now,
              createdById: createdById || null,
            },
          });
        }
      }
    }

    return {
      id: updated.id,
      name: updated.name,
      symbol: updated.symbol ?? "",
      referenceValue: Number(updated.referenceValue ?? 0),
      sortOrder: updated.sortOrder ?? 0,
      isActive: updated.isActive,
      createdAt: updated.createdAt,
      updatedAt: updated.updatedAt,
    };
  });
}

/**
 * ✅ REGLA:
 * - Si Metal Padre pasa a INACTIVO => TODAS sus variantes deben quedar INACTIVAS.
 * - Si Metal Padre pasa a ACTIVO => NO tocamos variantes (cada variante define su estado).
 */
export async function toggleMetalActive(jewelryId: string, metalId: string, isActive: boolean) {
  const metal = await prisma.metal.findFirst({
    where: { id: metalId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  if (!metal) {
    const err: any = new Error("Metal no encontrado.");
    err.status = 404;
    throw err;
  }

  return prisma.$transaction(async (tx) => {
    // 1) actualizar metal
    const row = await tx.metal.update({
      where: { id: metalId },
      data: { isActive },
      select: {
        id: true,
        name: true,
        symbol: true,
        referenceValue: true,
        sortOrder: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    // 2) si se desactiva el padre, forzar variantes a inactivas (solo no borradas)
    if (!isActive) {
      await tx.metalVariant.updateMany({
        where: { metalId: metalId, deletedAt: null, isActive: true },
        data: { isActive: false },
      });
    }

    return {
      id: row.id,
      name: row.name,
      symbol: row.symbol ?? "",
      referenceValue: Number(row.referenceValue ?? 0),
      sortOrder: row.sortOrder ?? 0,
      isActive: row.isActive,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  });
}

/* =========================
   Orden (move up/down)
========================= */

export async function moveMetal(jewelryId: string, metalId: string, dir: "UP" | "DOWN") {
  return prisma.$transaction(async (tx) => {
    const current = await tx.metal.findFirst({
      where: { id: metalId, jewelryId, deletedAt: null },
      select: { id: true, sortOrder: true },
    });
    if (!current) {
      const err: any = new Error("Metal no encontrado.");
      err.status = 404;
      throw err;
    }

    const sortOrder = Number(current.sortOrder ?? 0);

    const neighbor = await tx.metal.findFirst({
      where: {
        jewelryId,
        deletedAt: null,
        ...(dir === "UP" ? { sortOrder: { lt: sortOrder } } : { sortOrder: { gt: sortOrder } }),
      },
      orderBy: [{ sortOrder: dir === "UP" ? "desc" : "asc" }],
      select: { id: true, sortOrder: true },
    });

    if (!neighbor) return { changed: false };

    const a = sortOrder;
    const b = Number(neighbor.sortOrder ?? 0);

    await tx.metal.update({ where: { id: current.id }, data: { sortOrder: b } });
    await tx.metal.update({ where: { id: neighbor.id }, data: { sortOrder: a } });

    return { changed: true };
  });
}

/* =========================
   Historial valor referencia
========================= */

export async function listMetalRefHistory(jewelryId: string, metalId: string, take = 120) {
  const t = clampTake(take, 120);

  const rows = await prisma.metalRefValueHistory.findMany({
    where: { jewelryId, metalId },
    orderBy: [{ effectiveAt: "desc" }, { createdAt: "desc" }],
    take: t,
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
    referenceValue: Number(r.referenceValue ?? 0),
    effectiveAt: r.effectiveAt,
    createdAt: r.createdAt,
    user: r.createdBy ? { id: r.createdBy.id, name: r.createdBy.name, email: r.createdBy.email } : null,
  }));
}

/* =========================
   Delete (soft)
========================= */

export async function deleteMetal(jewelryId: string, metalId: string) {
  const metal = await prisma.metal.findFirst({
    where: { id: metalId, jewelryId, deletedAt: null },
    select: { id: true, name: true },
  });
  if (!metal) {
    const err: any = new Error("Metal no encontrado.");
    err.status = 404;
    throw err;
  }

  const variantsCount = await prisma.metalVariant.count({
    where: { metalId: metal.id, deletedAt: null },
  });
  if (variantsCount > 0) {
    const err: any = new Error(`No se puede eliminar el metal: tiene ${variantsCount} variante(s).`);
    err.status = 409;
    throw err;
  }

  const now = new Date();

  await prisma.metal.update({
    where: { id: metal.id },
    data: {
      deletedAt: now,
      isActive: false,

      // ✅ FIX CLAVE: liberar UNIQUE (jewelryId, name)
      name: freedName(metal.name, metal.id),

      symbol: "",
      referenceValue: new Prisma.Decimal(0),
    },
    select: { id: true },
  });

  return { ok: true };
}