import { prisma } from "../../lib/prisma.js";
import type { ShippingCalcMode, ShippingCarrierType } from "@prisma/client";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string): asserts cond {
  if (!cond) { const err: any = new Error(msg); err.status = 400; throw err; }
}

const VALID_CALC_MODES: ShippingCalcMode[] = ["FIXED", "BY_WEIGHT", "BY_ZONE"];

function parseCarrierType(v: any): ShippingCarrierType {
  return v === "PICKUP" ? "PICKUP" : "DELIVERY";
}

const WAREHOUSE_SELECT = {
  id: true,
  name: true,
  code: true,
  street: true,
  number: true,
  city: true,
  province: true,
  country: true,
  postalCode: true,
  isActive: true,
} as const;

const CARRIER_SELECT = {
  id: true, jewelryId: true, name: true, code: true, logoUrl: true, trackingUrl: true,
  freeShippingThreshold: true, type: true, warehouseId: true, provider: true,
  providerConfig: true,
  city: true, province: true, country: true,
  isFavorite: true, isActive: true, sortOrder: true,
  notes: true, deletedAt: true, createdAt: true, updatedAt: true,
  warehouse: { select: WAREHOUSE_SELECT },
  rates: {
    select: { id: true, name: true, zones: true, province: true, countries: true, calculationMode: true, fixedPrice: true, pricePerKg: true, minWeight: true, maxWeight: true, isActive: true, sortOrder: true },
    orderBy: { sortOrder: "asc" as const },
  },
} as const;

function parseRates(rates: any[], jewelryId: string) {
  if (!Array.isArray(rates)) return [];
  return rates.filter((r) => r && s(r.name)).map((r, i) => ({
    jewelryId,
    name: s(r.name),
    zones: Array.isArray(r.zones) ? (r.zones as any[]).map(String).filter(Boolean) : [],
    province: s(r.province),
    countries: Array.isArray(r.countries) ? (r.countries as any[]).map(String).filter(Boolean) : [],
    calculationMode: (VALID_CALC_MODES.includes(r.calculationMode) ? r.calculationMode : "FIXED") as ShippingCalcMode,
    fixedPrice: r.fixedPrice != null && r.fixedPrice !== "" ? String(parseFloat(String(r.fixedPrice)) || 0) : null,
    pricePerKg: r.pricePerKg != null && r.pricePerKg !== "" ? String(parseFloat(String(r.pricePerKg)) || 0) : null,
    minWeight: r.minWeight != null && r.minWeight !== "" ? String(parseFloat(String(r.minWeight)) || 0) : null,
    maxWeight: r.maxWeight != null && r.maxWeight !== "" ? String(parseFloat(String(r.maxWeight)) || 0) : null,
    isActive: r.isActive !== false,
    sortOrder: i,
  }));
}

/** Rate fija $0 que siempre se crea para carriers PICKUP */
function pickupRate(jewelryId: string) {
  return [{
    jewelryId,
    name: "Retiro en sucursal",
    zones: [],
    province: "",
    countries: [],
    calculationMode: "FIXED" as ShippingCalcMode,
    fixedPrice: "0",
    pricePerKg: null,
    minWeight: null,
    maxWeight: null,
    isActive: true,
    sortOrder: 0,
  }];
}

export async function listCarriers(jewelryId: string) {
  assert(jewelryId, "Tenant inválido.");
  return prisma.shippingCarrier.findMany({
    where: { jewelryId, deletedAt: null },
    select: CARRIER_SELECT,
    orderBy: [{ isFavorite: "desc" }, { type: "asc" }, { sortOrder: "asc" }, { name: "asc" }],
  });
}

export async function createCarrier(jewelryId: string, data: any) {
  assert(jewelryId, "Tenant inválido.");
  const name = s(data?.name);
  assert(name, "Nombre requerido.");
  const type = parseCarrierType(data?.type);
  const code = s(data?.code) || await generateCode(jewelryId, name);
  const isFavorite = data?.isFavorite === true;

  // PICKUP requiere un warehouseId válido del tenant
  let warehouseId: string | undefined;
  if (type === "PICKUP") {
    const wid = s(data?.warehouseId);
    assert(wid, "Para Retiro en sucursal es obligatorio seleccionar un almacén.");
    const wh = await prisma.warehouse.findFirst({ where: { id: wid, jewelryId, deletedAt: null }, select: { id: true } });
    assert(wh, "El almacén seleccionado no existe o no pertenece a esta joyería.");
    warehouseId = wid;
    // Solo un PICKUP activo por warehouse
    await prisma.shippingCarrier.updateMany({
      where: { jewelryId, type: "PICKUP", warehouseId, deletedAt: null, isActive: true },
      data: { isActive: false },
    });
  }

  const threshold = type === "DELIVERY" && data?.freeShippingThreshold != null && data.freeShippingThreshold !== ""
    ? String(parseFloat(String(data.freeShippingThreshold)) || 0) : null;

  if (isFavorite) {
    await prisma.shippingCarrier.updateMany({ where: { jewelryId, deletedAt: null, isFavorite: true }, data: { isFavorite: false } });
  }

  const rates = type === "PICKUP" ? pickupRate(jewelryId) : parseRates(data?.rates ?? [], jewelryId);

  return prisma.shippingCarrier.create({
    data: {
      jewelryId, name, code, type,
      warehouseId: warehouseId ?? undefined,
      provider: s(data?.provider) || undefined,
      providerConfig: data?.providerConfig ?? undefined,
      logoUrl: s(data?.logoUrl), trackingUrl: type === "DELIVERY" ? s(data?.trackingUrl) : "",
      freeShippingThreshold: threshold ?? undefined,
      city: s(data?.city), province: s(data?.province), country: s(data?.country),
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
  const existing = await prisma.shippingCarrier.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true, type: true },
  });
  assert(existing, "Transportista no encontrado.");

  const name = s(data?.name);
  assert(name, "Nombre requerido.");
  // El type es inmutable después de crear
  const type = existing.type;
  const isFavorite = data?.isFavorite === true;
  const isActive = data?.isActive === false ? false : true;

  // PICKUP: actualizar warehouseId si se proporciona
  let warehouseId: string | undefined;
  if (type === "PICKUP") {
    const wid = s(data?.warehouseId);
    if (wid) {
      const wh = await prisma.warehouse.findFirst({ where: { id: wid, jewelryId, deletedAt: null }, select: { id: true } });
      assert(wh, "El almacén seleccionado no existe o no pertenece a esta joyería.");
      warehouseId = wid;
    }
  }

  const threshold = type === "DELIVERY" && data?.freeShippingThreshold != null && data.freeShippingThreshold !== ""
    ? String(parseFloat(String(data.freeShippingThreshold)) || 0) : null;

  if (isFavorite) {
    await prisma.shippingCarrier.updateMany({ where: { jewelryId, deletedAt: null, isFavorite: true, id: { not: id } }, data: { isFavorite: false } });
  }

  await prisma.shippingRate.deleteMany({ where: { carrierId: id } });
  const rates = type === "PICKUP" ? pickupRate(jewelryId) : parseRates(data?.rates ?? [], jewelryId);

  return prisma.shippingCarrier.update({
    where: { id },
    data: {
      name, code: s(data?.code) || undefined,
      logoUrl: s(data?.logoUrl),
      trackingUrl: type === "DELIVERY" ? s(data?.trackingUrl) : "",
      freeShippingThreshold: threshold ?? undefined,
      warehouseId: warehouseId ?? undefined,
      provider: s(data?.provider) || undefined,
      providerConfig: data?.providerConfig ?? undefined,
      city: s(data?.city), province: s(data?.province), country: s(data?.country),
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
      type: original.type,
      warehouseId: original.warehouseId ?? undefined,
      provider: original.provider ?? undefined,
      providerConfig: original.providerConfig ?? undefined,
      city: original.city, province: original.province, country: original.country,
      logoUrl: original.logoUrl, trackingUrl: original.trackingUrl,
      freeShippingThreshold: original.freeShippingThreshold ?? undefined,
      isFavorite: false, isActive: false,
      sortOrder: original.sortOrder, notes: original.notes,
      rates: original.rates.length > 0
        ? { create: original.rates.map((r) => ({ jewelryId, name: r.name, zones: Array.isArray(r.zones) ? (r.zones as any[]).map(String).filter(Boolean) : [], province: r.province ?? "", countries: Array.isArray(r.countries) ? (r.countries as any[]).map(String).filter(Boolean) : [], calculationMode: r.calculationMode, fixedPrice: r.fixedPrice ?? undefined, pricePerKg: r.pricePerKg ?? undefined, minWeight: r.minWeight ?? undefined, maxWeight: r.maxWeight ?? undefined, isActive: r.isActive, sortOrder: r.sortOrder })) }
        : undefined,
    },
    select: CARRIER_SELECT,
  });
}

export async function toggleCarrier(id: string, jewelryId: string) {
  assert(id, "Id inválido."); assert(jewelryId, "Tenant inválido.");
  const c = await prisma.shippingCarrier.findFirst({ where: { id, jewelryId, deletedAt: null }, select: { id: true, isActive: true, type: true, warehouseId: true } });
  assert(c, "Transportista no encontrado.");
  const nextActive = !c.isActive;
  // Al activar un PICKUP, desactivar el otro PICKUP del mismo warehouse
  if (c.type === "PICKUP" && nextActive && c.warehouseId) {
    await prisma.shippingCarrier.updateMany({
      where: { jewelryId, type: "PICKUP", warehouseId: c.warehouseId, deletedAt: null, isActive: true, id: { not: id } },
      data: { isActive: false },
    });
  }
  return prisma.shippingCarrier.update({ where: { id }, data: { isActive: nextActive }, select: CARRIER_SELECT });
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
