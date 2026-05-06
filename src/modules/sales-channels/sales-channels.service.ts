import { prisma } from "../../lib/prisma.js";
import type { SalesChannelAdjustmentType } from "@prisma/client";

function s(v: any) { return String(v ?? "").trim(); }

function assert(cond: any, msg: string): asserts cond {
  if (!cond) { const err: any = new Error(msg); err.status = 400; throw err; }
}

const VALID_ADJ_TYPES: SalesChannelAdjustmentType[] = ["PERCENTAGE", "FIXED"];

const SC_SELECT = {
  id: true, jewelryId: true, name: true, code: true,
  adjustmentType: true, adjustmentValue: true,
  isActive: true, isFavorite: true, sortOrder: true, notes: true,
  deletedAt: true, createdAt: true, updatedAt: true,
} as const;

export async function listSalesChannels(jewelryId: string) {
  assert(jewelryId, "Tenant inválido.");
  return prisma.salesChannel.findMany({
    where: { jewelryId, deletedAt: null },
    select: SC_SELECT,
    orderBy: [{ isFavorite: "desc" }, { sortOrder: "asc" }, { name: "asc" }],
  });
}

export async function createSalesChannel(jewelryId: string, data: any) {
  assert(jewelryId, "Tenant inválido.");
  const name = s(data?.name);
  assert(name, "El nombre es obligatorio.");

  const adjustmentType: SalesChannelAdjustmentType = VALID_ADJ_TYPES.includes(data?.adjustmentType)
    ? data.adjustmentType
    : "PERCENTAGE";

  const adjustmentValue = parseFloat(String(data?.adjustmentValue ?? 0)) || 0;

  const code = s(data?.code) || await generateCode(jewelryId, name);
  const isFavorite = data?.isFavorite === true;
  const sortOrder  = Number(data?.sortOrder ?? 0) || 0;

  if (isFavorite) {
    await prisma.salesChannel.updateMany({ where: { jewelryId, deletedAt: null, isFavorite: true }, data: { isFavorite: false } });
  }

  return prisma.salesChannel.create({
    data: {
      jewelryId, name, code, adjustmentType,
      adjustmentValue: String(adjustmentValue),
      isFavorite, isActive: true, sortOrder,
      notes: s(data?.notes),
    },
    select: SC_SELECT,
  });
}

export async function updateSalesChannel(id: string, jewelryId: string, data: any) {
  assert(id && jewelryId, "Parámetros inválidos.");
  const existing = await prisma.salesChannel.findFirst({ where: { id, jewelryId, deletedAt: null }, select: { id: true } });
  assert(existing, "Canal no encontrado.");

  const name = s(data?.name);
  assert(name, "El nombre es obligatorio.");

  const adjustmentType: SalesChannelAdjustmentType = VALID_ADJ_TYPES.includes(data?.adjustmentType)
    ? data.adjustmentType
    : "PERCENTAGE";
  const adjustmentValue = parseFloat(String(data?.adjustmentValue ?? 0)) || 0;
  const isFavorite = data?.isFavorite === true;
  const isActive   = data?.isActive !== false;
  const code       = s(data?.code) || await generateCode(jewelryId, name);

  if (isFavorite) {
    await prisma.salesChannel.updateMany({ where: { jewelryId, deletedAt: null, isFavorite: true, id: { not: id } }, data: { isFavorite: false } });
  }

  return prisma.salesChannel.update({
    where: { id },
    data: {
      name, code, adjustmentType,
      adjustmentValue: String(adjustmentValue),
      isFavorite, isActive, sortOrder: Number(data?.sortOrder ?? 0) || 0,
      notes: s(data?.notes),
    },
    select: SC_SELECT,
  });
}

export async function toggleSalesChannel(id: string, jewelryId: string) {
  assert(id && jewelryId, "Parámetros inválidos.");
  const sc = await prisma.salesChannel.findFirst({ where: { id, jewelryId, deletedAt: null }, select: { id: true, isActive: true } });
  assert(sc, "Canal no encontrado.");
  return prisma.salesChannel.update({ where: { id }, data: { isActive: !sc.isActive }, select: SC_SELECT });
}

export async function setFavoriteSalesChannel(id: string, jewelryId: string) {
  assert(id && jewelryId, "Parámetros inválidos.");
  const sc = await prisma.salesChannel.findFirst({ where: { id, jewelryId, deletedAt: null }, select: { id: true, isFavorite: true } });
  assert(sc, "Canal no encontrado.");
  if (sc.isFavorite) {
    return prisma.salesChannel.update({ where: { id }, data: { isFavorite: false }, select: SC_SELECT });
  }
  await prisma.salesChannel.updateMany({ where: { jewelryId, deletedAt: null, id: { not: id } }, data: { isFavorite: false } });
  return prisma.salesChannel.update({ where: { id }, data: { isFavorite: true }, select: SC_SELECT });
}

export async function deleteSalesChannel(id: string, jewelryId: string) {
  assert(id && jewelryId, "Parámetros inválidos.");
  const sc = await prisma.salesChannel.findFirst({ where: { id, jewelryId, deletedAt: null }, select: { id: true } });
  assert(sc, "Canal no encontrado.");
  return prisma.salesChannel.update({ where: { id }, data: { deletedAt: new Date(), isActive: false }, select: { id: true } });
}

async function generateCode(jewelryId: string, name: string): Promise<string> {
  const prefix = name
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-zA-Z0-9]/g, "").toUpperCase().substring(0, 4).padEnd(3, "X");
  const count = await prisma.salesChannel.count({ where: { jewelryId } });
  return `${prefix}${String(count + 1).padStart(2, "0")}`;
}
