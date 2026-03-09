import { prisma } from "../../lib/prisma.js";
import type { PriceListScope, PriceListMode, RoundingTarget, RoundingMode, RoundingDirection } from "@prisma/client";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string): asserts cond {
  if (!cond) { const err: any = new Error(msg); err.status = 400; throw err; }
}
function toDecOrNull(v: any): string | null {
  const n = parseFloat(String(v ?? ""));
  return Number.isFinite(n) ? String(n) : null;
}

const VALID_SCOPES: PriceListScope[] = ["GENERAL", "CHANNEL", "CATEGORY", "CLIENT"];
const VALID_MODES: PriceListMode[] = ["MARGIN_TOTAL", "METAL_HECHURA", "COST_PER_GRAM"];
const VALID_RT: RoundingTarget[] = ["NONE", "METAL", "FINAL_PRICE"];
const VALID_RM: RoundingMode[] = ["NONE", "INTEGER", "DECIMAL_1", "DECIMAL_2", "TEN", "HUNDRED"];
const VALID_RD: RoundingDirection[] = ["NEAREST", "UP", "DOWN"];

const PL_SELECT = {
  id: true, jewelryId: true, name: true, code: true, description: true,
  scope: true, categoryId: true, channelId: true, clientId: true,
  mode: true, marginTotal: true, marginMetal: true, marginHechura: true, costPerGram: true,
  surcharge: true, minimumPrice: true,
  roundingTarget: true, roundingMode: true, roundingDirection: true,
  validFrom: true, validTo: true,
  isFavorite: true, isActive: true, sortOrder: true, notes: true,
  deletedAt: true, createdAt: true, updatedAt: true,
  category: { select: { id: true, name: true } },
} as const;

function parsePriceListData(data: any) {
  const scope: PriceListScope = VALID_SCOPES.includes(data?.scope) ? data.scope : "GENERAL";
  const mode: PriceListMode = VALID_MODES.includes(data?.mode) ? data.mode : "MARGIN_TOTAL";
  return {
    name: s(data?.name),
    code: s(data?.code),
    description: s(data?.description),
    scope,
    categoryId: scope === "CATEGORY" ? (s(data?.categoryId) || null) : null,
    channelId: s(data?.channelId) || null,
    clientId: s(data?.clientId) || null,
    mode,
    marginTotal: toDecOrNull(data?.marginTotal),
    marginMetal: toDecOrNull(data?.marginMetal),
    marginHechura: toDecOrNull(data?.marginHechura),
    costPerGram: toDecOrNull(data?.costPerGram),
    surcharge: toDecOrNull(data?.surcharge),
    minimumPrice: toDecOrNull(data?.minimumPrice),
    roundingTarget: (VALID_RT.includes(data?.roundingTarget) ? data.roundingTarget : "NONE") as RoundingTarget,
    roundingMode: (VALID_RM.includes(data?.roundingMode) ? data.roundingMode : "NONE") as RoundingMode,
    roundingDirection: (VALID_RD.includes(data?.roundingDirection) ? data.roundingDirection : "NEAREST") as RoundingDirection,
    validFrom: data?.validFrom ? new Date(data.validFrom) : null,
    validTo: data?.validTo ? new Date(data.validTo) : null,
    sortOrder: Number(data?.sortOrder ?? 0) || 0,
    notes: s(data?.notes),
  };
}

function validateMargins(mode: PriceListMode, d: ReturnType<typeof parsePriceListData>) {
  if (mode === "MARGIN_TOTAL") assert(d.marginTotal !== null, "Se requiere el margen total (%).");
  if (mode === "METAL_HECHURA") {
    assert(d.marginMetal !== null, "Se requiere el margen sobre metal (%).");
    assert(d.marginHechura !== null, "Se requiere el margen sobre hechura (%).");
  }
  if (mode === "COST_PER_GRAM") assert(d.costPerGram !== null, "Se requiere el costo por gramo.");
}

export async function listPriceLists(jewelryId: string) {
  assert(jewelryId, "Tenant inválido.");
  return prisma.priceList.findMany({
    where: { jewelryId, deletedAt: null },
    select: PL_SELECT,
    orderBy: [{ isFavorite: "desc" }, { scope: "asc" }, { name: "asc" }],
  });
}

export async function createPriceList(jewelryId: string, data: any) {
  assert(jewelryId, "Tenant inválido.");
  const parsed = parsePriceListData(data);
  assert(parsed.name, "Nombre requerido.");
  validateMargins(parsed.mode, parsed);

  if (parsed.categoryId) {
    const cat = await prisma.articleCategory.findFirst({ where: { id: parsed.categoryId, jewelryId, deletedAt: null }, select: { id: true } });
    assert(cat, "Categoría no encontrada.");
  }

  const code = parsed.code || await generateCode(jewelryId, parsed.name);
  const isFavorite = data?.isFavorite === true;

  if (isFavorite) {
    await prisma.priceList.updateMany({ where: { jewelryId, deletedAt: null, isFavorite: true, scope: parsed.scope }, data: { isFavorite: false } });
  }

  return prisma.priceList.create({
    data: { jewelryId, ...parsed, code, isFavorite, isActive: true,
      marginTotal: parsed.marginTotal ?? undefined, marginMetal: parsed.marginMetal ?? undefined,
      marginHechura: parsed.marginHechura ?? undefined, costPerGram: parsed.costPerGram ?? undefined,
      surcharge: parsed.surcharge ?? undefined, minimumPrice: parsed.minimumPrice ?? undefined,
    },
    select: PL_SELECT,
  });
}

export async function updatePriceList(id: string, jewelryId: string, data: any) {
  assert(id, "Id inválido."); assert(jewelryId, "Tenant inválido.");
  const existing = await prisma.priceList.findFirst({ where: { id, jewelryId, deletedAt: null }, select: { id: true } });
  assert(existing, "Lista de precios no encontrada.");

  const parsed = parsePriceListData(data);
  assert(parsed.name, "Nombre requerido.");
  validateMargins(parsed.mode, parsed);

  if (parsed.categoryId) {
    const cat = await prisma.articleCategory.findFirst({ where: { id: parsed.categoryId, jewelryId, deletedAt: null }, select: { id: true } });
    assert(cat, "Categoría no encontrada.");
  }

  const isFavorite = data?.isFavorite === true;
  const isActive = data?.isActive === false ? false : true;
  const code = parsed.code || s(data?.code);

  if (isFavorite) {
    await prisma.priceList.updateMany({ where: { jewelryId, deletedAt: null, isFavorite: true, scope: parsed.scope, id: { not: id } }, data: { isFavorite: false } });
  }

  return prisma.priceList.update({
    where: { id },
    data: { ...parsed, code, isFavorite, isActive,
      marginTotal: parsed.marginTotal ?? undefined, marginMetal: parsed.marginMetal ?? undefined,
      marginHechura: parsed.marginHechura ?? undefined, costPerGram: parsed.costPerGram ?? undefined,
      surcharge: parsed.surcharge ?? undefined, minimumPrice: parsed.minimumPrice ?? undefined,
    },
    select: PL_SELECT,
  });
}

export async function clonePriceList(id: string, jewelryId: string) {
  assert(id, "Id inválido."); assert(jewelryId, "Tenant inválido.");
  const original = await prisma.priceList.findFirst({ where: { id, jewelryId, deletedAt: null }, select: PL_SELECT });
  assert(original, "Lista de precios no encontrada.");
  const newCode = await generateCode(jewelryId, original.name + " copia");
  return prisma.priceList.create({
    data: {
      jewelryId, name: `${original.name} (copia)`, code: newCode,
      description: original.description, scope: original.scope,
      categoryId: original.categoryId, channelId: original.channelId, clientId: original.clientId,
      mode: original.mode,
      marginTotal: original.marginTotal ?? undefined, marginMetal: original.marginMetal ?? undefined,
      marginHechura: original.marginHechura ?? undefined, costPerGram: original.costPerGram ?? undefined,
      surcharge: original.surcharge ?? undefined, minimumPrice: original.minimumPrice ?? undefined,
      roundingTarget: original.roundingTarget, roundingMode: original.roundingMode, roundingDirection: original.roundingDirection,
      validFrom: original.validFrom, validTo: original.validTo,
      isFavorite: false, isActive: false, sortOrder: original.sortOrder, notes: original.notes,
    },
    select: PL_SELECT,
  });
}

export async function togglePriceList(id: string, jewelryId: string) {
  assert(id, "Id inválido."); assert(jewelryId, "Tenant inválido.");
  const pl = await prisma.priceList.findFirst({ where: { id, jewelryId, deletedAt: null }, select: { id: true, isActive: true } });
  assert(pl, "Lista de precios no encontrada.");
  return prisma.priceList.update({ where: { id }, data: { isActive: !pl.isActive }, select: PL_SELECT });
}

export async function setFavoritePriceList(id: string, jewelryId: string) {
  assert(id, "Id inválido."); assert(jewelryId, "Tenant inválido.");
  const pl = await prisma.priceList.findFirst({ where: { id, jewelryId, deletedAt: null, isActive: true }, select: { id: true, scope: true } });
  assert(pl, "Lista de precios no encontrada o inactiva.");
  await prisma.priceList.updateMany({ where: { jewelryId, deletedAt: null, scope: pl.scope }, data: { isFavorite: false } });
  return prisma.priceList.update({ where: { id }, data: { isFavorite: true }, select: PL_SELECT });
}

export async function deletePriceList(id: string, jewelryId: string) {
  assert(id, "Id inválido."); assert(jewelryId, "Tenant inválido.");
  const pl = await prisma.priceList.findFirst({ where: { id, jewelryId, deletedAt: null }, select: { id: true } });
  assert(pl, "Lista de precios no encontrada.");
  return prisma.priceList.update({ where: { id }, data: { deletedAt: new Date(), isActive: false }, select: { id: true } });
}

async function generateCode(jewelryId: string, name: string): Promise<string> {
  const prefix = name.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-zA-Z0-9]/g, "").toUpperCase().substring(0, 5).padEnd(3, "X");
  const count = await prisma.priceList.count({ where: { jewelryId } });
  return `${prefix}${String(count + 1).padStart(2, "0")}`;
}
