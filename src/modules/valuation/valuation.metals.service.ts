// tptech-backend/src/modules/valuation/valuation.metals.service.ts
import { Prisma } from "@prisma/client";
import { prisma } from "../../lib/prisma.js";

import { dec, assertNonEmpty, toRefValue, clampTake } from "./valuation.helpers.js";

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

  // sortOrder al final
  const max = await prisma.metal.aggregate({
    where: { jewelryId, deletedAt: null },
    _max: { sortOrder: true },
  });
  const nextSort = Number(max._max.sortOrder ?? 0) + 1;

  // unique name (solo no eliminados)
  const dup = await prisma.metal.findFirst({
    where: { jewelryId, name, deletedAt: null },
    select: { id: true },
  });
  if (dup) {
    const err: any = new Error("Ya existe un metal con ese nombre.");
    err.status = 409;
    throw err;
  }

  const now = new Date();

  return prisma.$transaction(async (tx) => {
    const row = await tx.metal.create({
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

    // historial inicial
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

  // si cambia el name, validar duplicado
  if (name !== metal.name) {
    const dup = await prisma.metal.findFirst({
      where: { jewelryId, name, deletedAt: null, id: { not: metalId } },
      select: { id: true },
    });
    if (dup) {
      const err: any = new Error("Ya existe un metal con ese nombre.");
      err.status = 409;
      throw err;
    }
  }

  const refN = toRefValue(data.referenceValue);
  const nextRef = refN !== undefined ? dec(refN) : undefined;

  const prevRef = new Prisma.Decimal(metal.referenceValue ?? 0);
  const now = new Date();

  return prisma.$transaction(async (tx) => {
    const updated = await tx.metal.update({
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

    const newRef = new Prisma.Decimal(updated.referenceValue ?? 0);

    // guardar historial solo si cambió referenceValue
    if (!newRef.equals(prevRef)) {
      await tx.metalRefValueHistory.create({
        data: {
          jewelryId,
          metalId: updated.id,
          referenceValue: newRef,
          effectiveAt: now,
          createdById: createdById || null,
        },
      });
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
      name: freedName(metal.name, metal.id),
      symbol: "",
      referenceValue: new Prisma.Decimal(0),
    },
    select: { id: true },
  });

  return { ok: true };
}