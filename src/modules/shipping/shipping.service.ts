import { prisma } from "../../lib/prisma.js";
import type { ShippingCalcMode } from "@prisma/client";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string): asserts cond {
  if (!cond) { const err: any = new Error(msg); err.status = 400; throw err; }
}

const VALID_CALC_MODES: ShippingCalcMode[] = ["FIXED", "BY_WEIGHT", "BY_ZONE"];

const CARRIER_SELECT = {
  id: true, jewelryId: true, name: true, code: true, logoUrl: true, trackingUrl: true,
  freeShippingThreshold: true, isFavorite: true, isActive: true, sortOrder: true,
  notes: true, deletedAt: true, createdAt: true, updatedAt: true,
  rates: {
    select: { id: true, name: true, zone: true, calculationMode: true, fixedPrice: true, pricePerKg: true, minWeight: true, maxWeight: true, isActive: true, sortOrder: true },
    orderBy: { sortOrder: "asc" as const },
  },
} as const;

function parseRates(rates: any[], jewelryId: string) {
  if (!Array.isArray(rates)) return [];
  return rates.filter((r) => r && s(r.name)).map((r, i) => ({
    jewelryId,
    name: s(r.name),
    zone: s(r.zone),
    calculationMode: (VALID_CALC_MODES.includes(r.calculationMode) ? r.calculationMode : "FIXED") as ShippingCalcMode,
    fixedPrice: r.fixedPrice != null && r.fixedPrice !== "" ? String(parseFloat(String(r.fixedPrice)) || 0) : null,
    pricePerKg: r.pricePerKg != null && r.pricePerKg !== "" ? String(parseFloat(String(r.pricePerKg)) || 0) : null,
    minWeight: r.minWeight != null && r.minWeight !== "" ? String(parseFloat(String(r.minWeight)) || 0) : null,
    maxWeight: r.maxWeight != null && r.maxWeight !== "" ? String(parseFloat(String(r.maxWeight)) || 0) : null,
    isActive: r.isActive !== false,
    sortOrder: i,
  }));
}

export async function listCarriers(jewelryId: string) {
  assert(jewelryId, "Tenant inválido.");
  return prisma.shippingCarrier.findMany({
    where: { jewelryId, deletedAt: null },
    select: CARRIER_SELECT,
    orderBy: [{ isFavorite: "desc" }, { sortOrder: "asc" }, { name: "asc" }],
  });
}

export async function createCarrier(jewelryId: string, data: any) {
  assert(jewelryId, "Tenant inválido.");
  const name = s(data?.name);
  assert(name, "Nombre requerido.");
  const code = s(data?.code) || await generateCode(jewelryId, name);
  const isFavorite = data?.isFavorite === true;
  const threshold = data?.freeShippingThreshold != null && data.freeShippingThreshold !== ""
    ? String(parseFloat(String(data.freeShippingThreshold)) || 0) : null;

  if (isFavorite) {
    await prisma.shippingCarrier.updateMany({ where: { jewelryId, deletedAt: null, isFavorite: true }, data: { isFavorite: false } });
  }

  const rates = parseRates(data?.rates ?? [], jewelryId);
  return prisma.shippingCarrier.create({
    data: {
      jewelryId, name, code,
      logoUrl: s(data?.logoUrl), trackingUrl: s(data?.trackingUrl),
      freeShippingThreshold: threshold ?? undefined,
      isFavorite, isActive: true,
      sortOrder: Number(data?.sortOrder ?? 0) || 0,
      notes: s(data?.notes),
      rates: rates.length > 0 ? { create: rates } : undefined,
    },
    select: CARRIER_SELECT,
  });
}

export async function updateCarrier(id: string, jewelryId: string, data: any) {
  assert(id, "Id inválido."); assert(jewelryId, "Tenant inválido.");
  const existing = await prisma.shippingCarrier.findFirst({ where: { id, jewelryId, deletedAt: null }, select: { id: true } });
  assert(existing, "Transportista no encontrado.");

  const name = s(data?.name);
  assert(name, "Nombre requerido.");
  const isFavorite = data?.isFavorite === true;
  const isActive = data?.isActive === false ? false : true;
  const threshold = data?.freeShippingThreshold != null && data.freeShippingThreshold !== ""
    ? String(parseFloat(String(data.freeShippingThreshold)) || 0) : null;

  if (isFavorite) {
    await prisma.shippingCarrier.updateMany({ where: { jewelryId, deletedAt: null, isFavorite: true, id: { not: id } }, data: { isFavorite: false } });
  }

  const rates = parseRates(data?.rates ?? [], jewelryId);
  await prisma.shippingRate.deleteMany({ where: { carrierId: id } });

  return prisma.shippingCarrier.update({
    where: { id },
    data: {
      name, code: s(data?.code) || undefined,
      logoUrl: s(data?.logoUrl), trackingUrl: s(data?.trackingUrl),
      freeShippingThreshold: threshold ?? undefined,
      isFavorite, isActive,
      sortOrder: Number(data?.sortOrder ?? 0) || 0,
      notes: s(data?.notes),
      rates: rates.length > 0 ? { create: rates } : undefined,
    },
    select: CARRIER_SELECT,
  });
}

export async function cloneCarrier(id: string, jewelryId: string) {
  assert(id, "Id inválido."); assert(jewelryId, "Tenant inválido.");
  const original = await prisma.shippingCarrier.findFirst({ where: { id, jewelryId, deletedAt: null }, select: CARRIER_SELECT });
  assert(original, "Transportista no encontrado.");
  const newCode = await generateCode(jewelryId, original.name + " copia");
  return prisma.shippingCarrier.create({
    data: {
      jewelryId, name: `${original.name} (copia)`, code: newCode,
      logoUrl: original.logoUrl, trackingUrl: original.trackingUrl,
      freeShippingThreshold: original.freeShippingThreshold ?? undefined,
      isFavorite: false, isActive: false,
      sortOrder: original.sortOrder, notes: original.notes,
      rates: original.rates.length > 0
        ? { create: original.rates.map((r) => ({ jewelryId, name: r.name, zone: r.zone, calculationMode: r.calculationMode, fixedPrice: r.fixedPrice ?? undefined, pricePerKg: r.pricePerKg ?? undefined, minWeight: r.minWeight ?? undefined, maxWeight: r.maxWeight ?? undefined, isActive: r.isActive, sortOrder: r.sortOrder })) }
        : undefined,
    },
    select: CARRIER_SELECT,
  });
}

export async function toggleCarrier(id: string, jewelryId: string) {
  assert(id, "Id inválido."); assert(jewelryId, "Tenant inválido.");
  const c = await prisma.shippingCarrier.findFirst({ where: { id, jewelryId, deletedAt: null }, select: { id: true, isActive: true } });
  assert(c, "Transportista no encontrado.");
  return prisma.shippingCarrier.update({ where: { id }, data: { isActive: !c.isActive }, select: CARRIER_SELECT });
}

export async function setFavoriteCarrier(id: string, jewelryId: string) {
  assert(id, "Id inválido."); assert(jewelryId, "Tenant inválido.");
  const c = await prisma.shippingCarrier.findFirst({ where: { id, jewelryId, deletedAt: null, isActive: true }, select: { id: true } });
  assert(c, "Transportista no encontrado o inactivo.");
  await prisma.shippingCarrier.updateMany({ where: { jewelryId, deletedAt: null }, data: { isFavorite: false } });
  return prisma.shippingCarrier.update({ where: { id }, data: { isFavorite: true }, select: CARRIER_SELECT });
}

export async function deleteCarrier(id: string, jewelryId: string) {
  assert(id, "Id inválido."); assert(jewelryId, "Tenant inválido.");
  const c = await prisma.shippingCarrier.findFirst({ where: { id, jewelryId, deletedAt: null }, select: { id: true } });
  assert(c, "Transportista no encontrado.");
  return prisma.shippingCarrier.update({ where: { id }, data: { deletedAt: new Date(), isActive: false }, select: { id: true } });
}

async function generateCode(jewelryId: string, name: string): Promise<string> {
  const prefix = name.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-zA-Z0-9]/g, "").toUpperCase().substring(0, 5).padEnd(3, "X");
  const count = await prisma.shippingCarrier.count({ where: { jewelryId } });
  return `${prefix}${String(count + 1).padStart(2, "0")}`;
}
