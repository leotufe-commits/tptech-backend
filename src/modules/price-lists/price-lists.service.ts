import { prisma } from "../../lib/prisma.js";
import type {
  PriceListScope,
  PriceListMode,
  RoundingTarget,
  RoundingMode,
  RoundingDirection,
} from "@prisma/client";

function s(v: any) {
  return String(v ?? "").trim();
}

function assert(cond: any, msg: string): asserts cond {
  if (!cond) {
    const err: any = new Error(msg);
    err.status = 400;
    throw err;
  }
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
  id: true,
  jewelryId: true,
  name: true,
  code: true,
  description: true,
  scope: true,
  categoryId: true,
  channelId: true,
  clientId: true,
  mode: true,
  marginTotal: true,
  marginMetal: true,
  marginHechura: true,
  costPerGram: true,
  surcharge: true,
  minimumPrice: true,
  roundingTarget: true,
  roundingMode: true,
  roundingDirection: true,
  roundingValueMetal: true,
  roundingValueHechura: true,
  validFrom: true,
  validTo: true,
  isFavorite: true,
  isActive: true,
  sortOrder: true,
  notes: true,
  deletedAt: true,
  createdAt: true,
  updatedAt: true,
  category: { select: { id: true, name: true } },
} as const;

function parsePriceListData(data: any) {
  const scope: PriceListScope = VALID_SCOPES.includes(data?.scope) ? data.scope : "GENERAL";
  const mode: PriceListMode = VALID_MODES.includes(data?.mode) ? data.mode : "MARGIN_TOTAL";

  let roundingTarget = (VALID_RT.includes(data?.roundingTarget)
    ? data.roundingTarget
    : "NONE") as RoundingTarget;

  let roundingMode = (VALID_RM.includes(data?.roundingMode)
    ? data.roundingMode
    : "NONE") as RoundingMode;

  let roundingDirection = (VALID_RD.includes(data?.roundingDirection)
    ? data.roundingDirection
    : "NEAREST") as RoundingDirection;

  if (roundingTarget === "NONE") {
    roundingMode = "NONE";
    roundingDirection = "NEAREST";
  }

  if (roundingMode === "NONE") {
    roundingDirection = "NEAREST";
  }

  // Los valores de redondeo solo aplican cuando hay un target activo
  const roundingValueMetal =
    roundingTarget !== "NONE" ? toDecOrNull(data?.roundingValueMetal) : null;
  const roundingValueHechura =
    roundingTarget !== "NONE" ? toDecOrNull(data?.roundingValueHechura) : null;

  const marginTotal = mode === "MARGIN_TOTAL" ? toDecOrNull(data?.marginTotal) : null;
  const marginMetal = mode === "METAL_HECHURA" ? toDecOrNull(data?.marginMetal) : null;
  const marginHechura = mode === "METAL_HECHURA" ? toDecOrNull(data?.marginHechura) : null;
  const costPerGram = mode === "COST_PER_GRAM" ? toDecOrNull(data?.costPerGram) : null;

  const validFrom = data?.validFrom ? new Date(data.validFrom) : null;
  const validTo = data?.validTo ? new Date(data.validTo) : null;

  return {
    name: s(data?.name),
    code: s(data?.code),
    description: s(data?.description),
    scope,
    categoryId: scope === "CATEGORY" ? s(data?.categoryId) || null : null,
    channelId: scope === "CHANNEL" ? s(data?.channelId) || null : null,
    clientId: scope === "CLIENT" ? s(data?.clientId) || null : null,
    mode,
    marginTotal,
    marginMetal,
    marginHechura,
    costPerGram,
    surcharge: toDecOrNull(data?.surcharge),
    minimumPrice: toDecOrNull(data?.minimumPrice),
    roundingTarget,
    roundingMode,
    roundingDirection,
    roundingValueMetal,
    roundingValueHechura,
    validFrom,
    validTo,
    sortOrder: Number(data?.sortOrder ?? 0) || 0,
    notes: s(data?.notes),
  };
}

function validateMargins(mode: PriceListMode, d: ReturnType<typeof parsePriceListData>) {
  if (mode === "MARGIN_TOTAL") {
    assert(d.marginTotal !== null, "Se requiere el margen total (%).");
  }

  if (mode === "METAL_HECHURA") {
    assert(d.marginMetal !== null, "Se requiere el margen sobre metal (%).");
    assert(d.marginHechura !== null, "Se requiere el margen sobre hechura (%).");
  }

  if (mode === "COST_PER_GRAM") {
    assert(d.costPerGram !== null, "Se requiere el costo por gramo (%).");
  }
}

function validateDates(d: ReturnType<typeof parsePriceListData>) {
  if (d.validFrom && Number.isNaN(d.validFrom.getTime())) {
    assert(false, "Fecha 'válida desde' inválida.");
  }
  if (d.validTo && Number.isNaN(d.validTo.getTime())) {
    assert(false, "Fecha 'válida hasta' inválida.");
  }
  if (d.validFrom && d.validTo) {
    assert(d.validTo >= d.validFrom, "La fecha hasta no puede ser menor que la fecha desde.");
  }
}

async function validateScopeRelations(jewelryId: string, d: ReturnType<typeof parsePriceListData>) {
  if (d.scope === "CATEGORY") {
    assert(d.categoryId, "Debes seleccionar una categoría.");
    const cat = await prisma.articleCategory.findFirst({
      where: { id: d.categoryId, jewelryId, deletedAt: null },
      select: { id: true },
    });
    assert(cat, "Categoría no encontrada.");
  }
}

export async function listPriceLists(jewelryId: string) {
  assert(jewelryId, "Tenant inválido.");

  return prisma.priceList.findMany({
    where: { jewelryId, deletedAt: null },
    select: PL_SELECT,
    orderBy: [{ isFavorite: "desc" }, { name: "asc" }],
  });
}

export async function createPriceList(jewelryId: string, data: any) {
  assert(jewelryId, "Tenant inválido.");

  const parsed = parsePriceListData(data);
  assert(parsed.name, "Nombre requerido.");

  const dupName = await prisma.priceList.findFirst({
    where: { jewelryId, deletedAt: null, name: { equals: parsed.name, mode: "insensitive" } },
    select: { id: true },
  });
  assert(!dupName, `Ya existe una lista de precios con el nombre "${parsed.name}".`);

  validateMargins(parsed.mode, parsed);
  validateDates(parsed);
  await validateScopeRelations(jewelryId, parsed);

  const code = parsed.code || (await generateCode(jewelryId, parsed.name));
  const isActive = data?.isActive === false ? false : true;

  // Auto-favorita: si no hay listas activas, la primera se marca automáticamente
  const activeCount = await prisma.priceList.count({
    where: { jewelryId, deletedAt: null, isActive: true },
  });
  const isFavorite = isActive && activeCount === 0 ? true : data?.isFavorite === true && isActive;

  if (isFavorite && activeCount > 0) {
    await prisma.priceList.updateMany({
      where: { jewelryId, deletedAt: null, isFavorite: true },
      data: { isFavorite: false },
    });
  }

  return prisma.priceList.create({
    data: {
      jewelryId,
      ...parsed,
      code,
      isFavorite,
      isActive,
      marginTotal: parsed.marginTotal ?? undefined,
      marginMetal: parsed.marginMetal ?? undefined,
      marginHechura: parsed.marginHechura ?? undefined,
      costPerGram: parsed.costPerGram ?? undefined,
      surcharge: parsed.surcharge ?? undefined,
      minimumPrice: parsed.minimumPrice ?? undefined,
      roundingValueMetal: parsed.roundingValueMetal ?? undefined,
      roundingValueHechura: parsed.roundingValueHechura ?? undefined,
    },
    select: PL_SELECT,
  });
}

export async function updatePriceList(id: string, jewelryId: string, data: any) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const existing = await prisma.priceList.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true, code: true, isActive: true, isFavorite: true },
  });
  assert(existing, "Lista de precios no encontrada.");

  const parsed = parsePriceListData(data);
  assert(parsed.name, "Nombre requerido.");

  const dupName = await prisma.priceList.findFirst({
    where: { jewelryId, deletedAt: null, id: { not: id }, name: { equals: parsed.name, mode: "insensitive" } },
    select: { id: true },
  });
  assert(!dupName, `Ya existe una lista de precios con el nombre "${parsed.name}".`);

  validateMargins(parsed.mode, parsed);
  validateDates(parsed);
  await validateScopeRelations(jewelryId, parsed);

  const isActive = data?.isActive === false ? false : true;
  const isFavorite = isActive ? data?.isFavorite === true : false;
  const code = parsed.code || existing.code;

  if (isFavorite) {
    await prisma.priceList.updateMany({
      where: { jewelryId, deletedAt: null, isFavorite: true, id: { not: id } },
      data: { isFavorite: false },
    });
  }

  return prisma.priceList.update({
    where: { id },
    data: {
      ...parsed,
      code,
      isFavorite,
      isActive,
      marginTotal: parsed.marginTotal ?? undefined,
      marginMetal: parsed.marginMetal ?? undefined,
      marginHechura: parsed.marginHechura ?? undefined,
      costPerGram: parsed.costPerGram ?? undefined,
      surcharge: parsed.surcharge ?? undefined,
      minimumPrice: parsed.minimumPrice ?? undefined,
      roundingValueMetal: parsed.roundingValueMetal ?? undefined,
      roundingValueHechura: parsed.roundingValueHechura ?? undefined,
    },
    select: PL_SELECT,
  });
}

export async function clonePriceList(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const original = await prisma.priceList.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: PL_SELECT,
  });
  assert(original, "Lista de precios no encontrada.");

  const newCode = await generateCode(jewelryId, `${original.name} copia`);

  return prisma.priceList.create({
    data: {
      jewelryId,
      name: `${original.name} (copia)`,
      code: newCode,
      description: original.description,
      scope: original.scope,
      categoryId: original.categoryId,
      channelId: original.channelId,
      clientId: original.clientId,
      mode: original.mode,
      marginTotal: original.marginTotal ?? undefined,
      marginMetal: original.marginMetal ?? undefined,
      marginHechura: original.marginHechura ?? undefined,
      costPerGram: original.costPerGram ?? undefined,
      surcharge: original.surcharge ?? undefined,
      minimumPrice: original.minimumPrice ?? undefined,
      roundingTarget: original.roundingTarget,
      roundingMode: original.roundingMode,
      roundingDirection: original.roundingDirection,
      roundingValueMetal: original.roundingValueMetal ?? undefined,
      roundingValueHechura: original.roundingValueHechura ?? undefined,
      validFrom: original.validFrom,
      validTo: original.validTo,
      isFavorite: false,
      isActive: false,
      sortOrder: original.sortOrder,
      notes: original.notes,
    },
    select: PL_SELECT,
  });
}

export async function togglePriceList(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const pl = await prisma.priceList.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true, isActive: true },
  });
  assert(pl, "Lista de precios no encontrada.");

  const nextIsActive = !pl.isActive;

  // Bloquear desactivación si es la única lista activa
  if (pl.isActive && !nextIsActive) {
    const activeCount = await prisma.priceList.count({
      where: { jewelryId, deletedAt: null, isActive: true },
    });
    assert(activeCount > 1, "Debe existir al menos una lista de precios activa.");
  }

  return prisma.priceList.update({
    where: { id },
    data: {
      isActive: nextIsActive,
      isFavorite: nextIsActive ? undefined : false,
    },
    select: PL_SELECT,
  });
}

export async function setFavoritePriceList(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const pl = await prisma.priceList.findFirst({
    where: { id, jewelryId, deletedAt: null, isActive: true },
    select: { id: true, isFavorite: true },
  });
  assert(pl, "Lista de precios no encontrada o inactiva.");

  if (pl.isFavorite) {
    // Ya es favorita — no permitir desmarcar para no dejar el sistema sin favorita
    return prisma.priceList.findFirstOrThrow({ where: { id }, select: PL_SELECT });
  }

  // Desmarcar todas las demás y marcar ésta
  await prisma.priceList.updateMany({
    where: { jewelryId, deletedAt: null, isFavorite: true },
    data: { isFavorite: false },
  });

  return prisma.priceList.update({
    where: { id },
    data: { isFavorite: true },
    select: PL_SELECT,
  });
}

export async function deletePriceList(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const pl = await prisma.priceList.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(pl, "Lista de precios no encontrada.");

  // No se puede eliminar la única lista
  const totalCount = await prisma.priceList.count({
    where: { jewelryId, deletedAt: null },
  });
  assert(totalCount > 1, "No podés eliminar la única lista de precios.");

  return prisma.priceList.update({
    where: { id },
    data: { deletedAt: new Date(), isActive: false, isFavorite: false },
    select: { id: true },
  });
}

async function generateCode(jewelryId: string, name: string): Promise<string> {
  const prefix = name
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-zA-Z0-9]/g, "")
    .toUpperCase()
    .substring(0, 5)
    .padEnd(3, "X");

  const count = await prisma.priceList.count({ where: { jewelryId } });
  return `${prefix}${String(count + 1).padStart(2, "0")}`;
}
