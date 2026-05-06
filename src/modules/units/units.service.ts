// src/modules/units/units.service.ts
import { prisma } from "../../lib/prisma.js";
import type { UnitType } from "@prisma/client";
import type { CreateUnitInput, UpdateUnitInput } from "./units.schemas.js";

const UNIT_SELECT = {
  id: true,
  jewelryId: true,
  name: true,
  code: true,
  type: true,
  isSystem: true,
  isFavorite: true,
  isActive: true,
  sortOrder: true,
  createdAt: true,
  updatedAt: true,
  deletedAt: true,
} as const;

function err(message: string, status = 400): Error {
  const e: any = new Error(message);
  e.status = status;
  return e;
}

function normCode(v: string) {
  return v.trim();
}
function normName(v: string) {
  return v.trim().replace(/\s+/g, " ");
}

export interface ListUnitsParams {
  type?: UnitType;
  isActive?: boolean;
  q?: string;
}

export async function listUnits(jewelryId: string, params: ListUnitsParams = {}) {
  const where: any = { jewelryId, deletedAt: null };
  if (params.type) where.type = params.type;
  if (typeof params.isActive === "boolean") where.isActive = params.isActive;
  if (params.q && params.q.trim()) {
    const q = params.q.trim();
    where.OR = [
      { name: { contains: q, mode: "insensitive" } },
      { code: { contains: q, mode: "insensitive" } },
    ];
  }

  const items = await prisma.unit.findMany({
    where,
    orderBy: [{ type: "asc" }, { sortOrder: "asc" }, { name: "asc" }],
    select: UNIT_SELECT,
  });

  return { items };
}

export async function createUnit(jewelryId: string, input: CreateUnitInput) {
  const name = normName(input.name);
  const code = normCode(input.code);
  if (!name) throw err("El nombre es obligatorio.");
  if (!code) throw err("El código es obligatorio.");

  // Duplicado activo (mismo jewelryId + type) por code o name
  const dup = await prisma.unit.findFirst({
    where: {
      jewelryId,
      type: input.type,
      deletedAt: null,
      OR: [
        { code: { equals: code, mode: "insensitive" } },
        { name: { equals: name, mode: "insensitive" } },
      ],
    },
    select: { id: true, code: true, name: true },
  });

  if (dup) {
    throw err("Ya existe una unidad con ese nombre o código en este tipo.", 409);
  }

  // Restauración si existe soft-deleted con mismo (type, code) o (type, name)
  const softDeleted = await prisma.unit.findFirst({
    where: {
      jewelryId,
      type: input.type,
      deletedAt: { not: null },
      OR: [
        { code: { equals: code, mode: "insensitive" } },
        { name: { equals: name, mode: "insensitive" } },
      ],
    },
    select: { id: true },
  });

  if (softDeleted) {
    const restored = await prisma.unit.update({
      where: { id: softDeleted.id },
      data: {
        deletedAt: null,
        isActive: input.isActive ?? true,
        isFavorite: input.isFavorite ?? false,
        sortOrder: input.sortOrder ?? 0,
        name,
        code,
        type: input.type,
      },
      select: UNIT_SELECT,
    });

    if (restored.isFavorite) {
      await clearOtherFavorites(jewelryId, restored.type, restored.id);
    }

    return { item: restored, restored: true };
  }

  const created = await prisma.unit.create({
    data: {
      jewelryId,
      name,
      code,
      type: input.type,
      isActive: input.isActive ?? true,
      isFavorite: input.isFavorite ?? false,
      sortOrder: input.sortOrder ?? 0,
    },
    select: UNIT_SELECT,
  });

  if (created.isFavorite) {
    await clearOtherFavorites(jewelryId, created.type, created.id);
  }

  return { item: created };
}

export async function updateUnit(id: string, jewelryId: string, input: UpdateUnitInput) {
  const existing = await prisma.unit.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true, type: true, code: true, name: true, isSystem: true },
  });
  if (!existing) throw err("Unidad no encontrada.", 404);

  const data: any = {};

  if (input.name !== undefined) {
    const v = normName(input.name);
    if (!v) throw err("El nombre no puede ser vacío.");
    data.name = v;
  }
  if (input.code !== undefined) {
    const v = normCode(input.code);
    if (!v) throw err("El código no puede ser vacío.");
    data.code = v;
  }
  if (input.type !== undefined) data.type = input.type;
  if (input.isActive !== undefined) data.isActive = input.isActive;
  if (input.sortOrder !== undefined) data.sortOrder = Math.trunc(input.sortOrder);

  if (Object.keys(data).length === 0) throw err("No hay campos para actualizar.");

  // Si cambia type/code/name → chequear duplicados
  const finalType = (data.type ?? existing.type) as UnitType;
  const finalCode = (data.code ?? existing.code) as string;
  const finalName = (data.name ?? existing.name) as string;

  const dup = await prisma.unit.findFirst({
    where: {
      jewelryId,
      type: finalType,
      deletedAt: null,
      NOT: { id },
      OR: [
        { code: { equals: finalCode, mode: "insensitive" } },
        { name: { equals: finalName, mode: "insensitive" } },
      ],
    },
    select: { id: true },
  });
  if (dup) throw err("Ya existe otra unidad con ese nombre o código en este tipo.", 409);

  const updated = await prisma.unit.update({
    where: { id },
    data,
    select: UNIT_SELECT,
  });

  return { item: updated };
}

async function clearOtherFavorites(jewelryId: string, type: UnitType, keepId: string) {
  await prisma.unit.updateMany({
    where: {
      jewelryId,
      type,
      isFavorite: true,
      NOT: { id: keepId },
    },
    data: { isFavorite: false },
  });
}

export async function setFavoriteUnit(id: string, jewelryId: string, isFavorite: boolean) {
  const existing = await prisma.unit.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true, type: true },
  });
  if (!existing) throw err("Unidad no encontrada.", 404);

  if (isFavorite) {
    await clearOtherFavorites(jewelryId, existing.type, id);
  }

  const updated = await prisma.unit.update({
    where: { id },
    data: { isFavorite },
    select: UNIT_SELECT,
  });

  return { item: updated };
}

export async function deleteUnit(id: string, jewelryId: string) {
  const existing = await prisma.unit.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true, isSystem: true },
  });
  if (!existing) throw err("Unidad no encontrada.", 404);

  await prisma.unit.update({
    where: { id },
    data: {
      deletedAt: new Date(),
      isActive: false,
      isFavorite: false,
    },
  });

  return { ok: true };
}
