import { prisma } from "../../lib/prisma.js";
import type {
  PriceListScope,
  PriceListMode,
  RoundingTarget,
  RoundingMode,
  RoundingDirection,
  RoundingApplyOn,
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
const VALID_RAO: RoundingApplyOn[] = ["PRICE", "NET", "TOTAL"];

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
  roundingApplyOn: true,
  roundingModeHechura: true,
  roundingDirectionHechura: true,
  roundingValueMetal: true,
  roundingValueHechura: true,
  // Etapa C-comercial (POLICY §R-Rounding-14) — Default MONETARY; PHYSICAL
  // habilita redondeo en gramos por metal padre. JSON nullable.
  commercialRoundingMetalDomain: true,
  commercialPhysicalRoundingConfig: true,
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

  const roundingApplyOn = (VALID_RAO.includes(data?.roundingApplyOn)
    ? data.roundingApplyOn
    : "TOTAL") as RoundingApplyOn;

  let roundingModeHechura = (VALID_RM.includes(data?.roundingModeHechura)
    ? data.roundingModeHechura
    : "NONE") as RoundingMode;

  let roundingDirectionHechura = (VALID_RD.includes(data?.roundingDirectionHechura)
    ? data.roundingDirectionHechura
    : "NEAREST") as RoundingDirection;

  if (roundingTarget === "NONE") {
    roundingMode = "NONE";
    roundingDirection = "NEAREST";
    roundingModeHechura = "NONE";
    roundingDirectionHechura = "NEAREST";
  }

  if (roundingMode === "NONE") {
    roundingDirection = "NEAREST";
  }

  if (roundingModeHechura === "NONE") {
    roundingDirectionHechura = "NEAREST";
  }

  // Los valores de redondeo solo aplican cuando hay un target activo
  const roundingValueMetal =
    roundingTarget !== "NONE" ? toDecOrNull(data?.roundingValueMetal) : null;
  const roundingValueHechura =
    roundingTarget !== "NONE" ? toDecOrNull(data?.roundingValueHechura) : null;

  // ── Etapa C-comercial / C1 (POLICY §R-Rounding-14) ──────────────────────
  // Discriminador del dominio del metal en el redondeo COMERCIAL. Reusa el
  // enum `DocumentRoundingMetalDomain` (MONETARY | PHYSICAL). Default
  // MONETARY = compat hacia atrás. Cualquier valor distinto a "PHYSICAL"
  // cae a MONETARY (degradación segura).
  const commercialRoundingMetalDomain: "MONETARY" | "PHYSICAL" =
    data?.commercialRoundingMetalDomain === "PHYSICAL" ? "PHYSICAL" : "MONETARY";

  // Config JSON nullable — paralela a `documentPhysicalRoundingConfig`.
  // El parser runtime (Etapa C2) valida el shape detalladamente; acá solo
  // garantizamos que sea un objeto (o `null`). Si llega un valor con shape
  // inesperado, lo persistimos tal cual y el parser lo descarta en runtime
  // con `hasInvalidEntries=true` (mismo contrato que el financiero).
  let commercialPhysicalRoundingConfig: Record<string, unknown> | null = null;
  const rawCfg = data?.commercialPhysicalRoundingConfig;
  if (rawCfg && typeof rawCfg === "object" && !Array.isArray(rawCfg)) {
    commercialPhysicalRoundingConfig = rawCfg as Record<string, unknown>;
  }
  // Coherencia: si el dominio es MONETARY, no persistir config física
  // (evita JSON huérfano que confunde al operador en el editor).
  if (commercialRoundingMetalDomain !== "PHYSICAL") {
    commercialPhysicalRoundingConfig = null;
  }

  const marginTotal = mode === "MARGIN_TOTAL" ? toDecOrNull(data?.marginTotal) : null;
  // MARGIN_TOTAL (unified mode): replicate the value into marginMetal/marginHechura so the
  // pricing engine can treat it the same way as METAL_HECHURA internally.
  const marginMetal =
    mode === "METAL_HECHURA"
      ? toDecOrNull(data?.marginMetal)
      : mode === "MARGIN_TOTAL"
      ? toDecOrNull(data?.marginTotal)
      : null;
  const marginHechura =
    mode === "METAL_HECHURA"
      ? toDecOrNull(data?.marginHechura)
      : mode === "MARGIN_TOTAL"
      ? toDecOrNull(data?.marginTotal)
      : null;
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
    roundingApplyOn,
    roundingModeHechura,
    roundingDirectionHechura,
    roundingValueMetal,
    roundingValueHechura,
    commercialRoundingMetalDomain,
    commercialPhysicalRoundingConfig,
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

// ─── Prevención de doble redondeo (DECISIÓN ARQUITECTÓNICA) ─────────────────
//
// La prevención de doble redondeo (lista + documento) NO vive más en la
// validación de creación/edición de listas. Vive en el RUNTIME del pipeline:
//
//   · `loadDocumentRoundingConfig` (`src/lib/document-rounding.ts:154`)
//     emite `suppressListDeferredRounding = true` cuando el tenant tiene
//     política de documento activa.
//   · `pricing-engine.sale.ts:1620` consulta ese flag y NEUTRALIZA el
//     redondeo diferido de la lista (`applyOn = NET | TOTAL`) cuando está
//     activo. El documento es la única autoridad en ese caso.
//   · Capa 16 (`applyDocumentPhysicalRounding`) lleva el redondeo físico
//     de gramos por metal padre; suprime la capa 15.metal monetaria para
//     evitar doble redondeo (ver `document-rounding.ts:108-111`).
//
// Por qué se removió de acá:
//
//   La lista de precios es una regla COMERCIAL REUSABLE. Su configuración
//   no debe depender del estado vigente de `Jewelry.documentRounding*`:
//   un tenant puede cambiar la política financiera mañana sin que sus
//   listas comerciales queden bloqueadas (y viceversa). Acoplar las dos
//   configuraciones impedía operativas legítimas como:
//
//     · Lista METAL_HECHURA con `roundingModeMetal=INTEGER` /
//       `roundingModeHechura=HUNDRED` aunque el tenant también tenga
//       documentRoundingScope=BREAKDOWN financiero — el runtime ya
//       resuelve la colisión.
//     · Editar la política financiera del tenant sin tener que migrar
//       todas las listas existentes a configs "compatibles".
//
// Si en el futuro se necesita avisar al operador de un riesgo, debe ser
// un WARNING visual en el frontend (no un assert que rechace el guardado).
//
// (Antes vivía acá una función `validateRoundingPolicy` que rechazaba
// con HTTP 400 — eliminada en esta etapa. Test cobertura: ver
// `tptech-backend/src/lib/pricing-engine/__tests__/double-rounding-trap.test.ts`,
// que ahora cubre el contrato nuevo: lista pasa + runtime sigue activo.)

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
  // Prevención de doble redondeo eliminada de la creación de la lista —
  // vive en el runtime (`loadDocumentRoundingConfig` + `pricing-engine.sale`).
  // Ver comentario arriba de `createPriceList` / `updatePriceList`.

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
      // Etapa C-comercial — Prisma JSON nullable: `undefined` no setea,
      // `null` guarda NULL (= sin config). Cast `as any` por el mismo
      // motivo que `documentPhysicalRoundingConfig` en company.controller.
      commercialPhysicalRoundingConfig:
        parsed.commercialPhysicalRoundingConfig as any,
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
  // Prevención de doble redondeo eliminada de la edición de la lista —
  // misma razón que en `createPriceList` (ver comentario allá).

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
      // Etapa C-comercial — cuando el operador cambia de PHYSICAL a
      // MONETARY, `parsed.commercialPhysicalRoundingConfig` viene `null`
      // y Prisma lo persiste como NULL en DB (limpia la config huérfana).
      commercialPhysicalRoundingConfig:
        parsed.commercialPhysicalRoundingConfig as any,
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
      roundingApplyOn: original.roundingApplyOn,
      roundingModeHechura: original.roundingModeHechura,
      roundingDirectionHechura: original.roundingDirectionHechura,
      roundingValueMetal: original.roundingValueMetal ?? undefined,
      roundingValueHechura: original.roundingValueHechura ?? undefined,
      // Etapa C-comercial — preservar config al clonar.
      commercialRoundingMetalDomain: (original as any).commercialRoundingMetalDomain ?? "MONETARY",
      commercialPhysicalRoundingConfig:
        (original as any).commercialPhysicalRoundingConfig ?? undefined,
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
