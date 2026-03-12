import { prisma } from "../../lib/prisma.js";

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

/* =========================
   CONSTANTS
========================= */

const VALID_INPUT_TYPES = [
  "TEXT", "TEXTAREA", "NUMBER", "DECIMAL", "BOOLEAN",
  "DATE", "SELECT", "MULTISELECT", "COLOR",
] as const;

const OPTION_TYPES = ["SELECT", "MULTISELECT", "COLOR"] as const;

/* =========================
   SELECTS
========================= */

const DEF_SELECT = {
  id: true,
  jewelryId: true,
  name: true,
  code: true,
  inputType: true,
  helpText: true,
  unit: true,
  defaultValue: true,
  isActive: true,
  deletedAt: true,
  createdAt: true,
  updatedAt: true,
  options: {
    where: { isActive: true },
    select: {
      id: true,
      label: true,
      value: true,
      colorHex: true,
      sortOrder: true,
      isActive: true,
    },
    orderBy: [{ sortOrder: "asc" }, { label: "asc" }] as {
      sortOrder?: "asc" | "desc";
      label?: "asc" | "desc";
    }[],
  },
  assignments: {
    where: { deletedAt: null },
    select: {
      category: {
        select: { id: true, name: true },
      },
    },
  },
  _count: {
    select: {
      assignments: { where: { deletedAt: null } },
    },
  },
};

const OPT_SELECT = {
  id: true,
  definitionId: true,
  label: true,
  value: true,
  colorHex: true,
  sortOrder: true,
  isActive: true,
  createdAt: true,
  updatedAt: true,
} as const;

function mapDef(r: any) {
  const { _count, assignments, ...rest } = r;
  return {
    ...rest,
    assignmentCount: _count.assignments,
    assignedCategories: (assignments as any[]).map((a) => a.category),
  };
}

/* =========================
   LIST
========================= */
export async function listAttributeDefs(jewelryId: string) {
  assert(jewelryId, "Tenant inválido.");

  const rows = await prisma.articleAttributeDef.findMany({
    where: { jewelryId, deletedAt: null },
    select: DEF_SELECT,
    orderBy: [{ name: "asc" }, { createdAt: "asc" }],
  });

  return rows.map(mapDef);
}

/* =========================
   CREATE
========================= */
export async function createAttributeDef(jewelryId: string, data: any) {
  assert(jewelryId, "Tenant inválido.");

  const name = s(data?.name);
  assert(name, "Nombre del atributo requerido.");

  const inputType = s(data?.inputType);
  assert(
    (VALID_INPUT_TYPES as readonly string[]).includes(inputType),
    `Tipo de campo inválido. Valores permitidos: ${VALID_INPUT_TYPES.join(", ")}.`
  );

  const code = s(data?.code);

  const created = await prisma.articleAttributeDef.create({
    data: {
      jewelryId,
      name,
      code,
      inputType: inputType as any,
      helpText: s(data?.helpText),
      unit: s(data?.unit),
      defaultValue: s(data?.defaultValue),
      isActive: true,
    },
    select: DEF_SELECT,
  });

  return mapDef(created);
}

/* =========================
   UPDATE
========================= */
export async function updateAttributeDef(id: string, jewelryId: string, data: any) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const def = await prisma.articleAttributeDef.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(def, "Atributo no encontrado.");

  const name = s(data?.name);
  assert(name, "Nombre del atributo requerido.");

  const inputType = s(data?.inputType);
  assert(
    (VALID_INPUT_TYPES as readonly string[]).includes(inputType),
    `Tipo de campo inválido.`
  );

  const updated = await prisma.articleAttributeDef.update({
    where: { id },
    data: {
      name,
      code: s(data?.code),
      inputType: inputType as any,
      helpText: s(data?.helpText),
      unit: s(data?.unit),
      defaultValue: s(data?.defaultValue),
    },
    select: DEF_SELECT,
  });

  return mapDef(updated);
}

/* =========================
   TOGGLE ACTIVE
========================= */
export async function toggleAttributeDef(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const def = await prisma.articleAttributeDef.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true, isActive: true },
  });
  assert(def, "Atributo no encontrado.");

  const updated = await prisma.articleAttributeDef.update({
    where: { id },
    data: { isActive: !def.isActive },
    select: DEF_SELECT,
  });

  return mapDef(updated);
}

/* =========================
   DELETE (SOFT)
========================= */
export async function deleteAttributeDef(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const def = await prisma.articleAttributeDef.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true, name: true },
  });
  assert(def, "Atributo no encontrado.");

  const activeAssignments = await prisma.articleCategoryAttribute.count({
    where: { definitionId: id, deletedAt: null },
  });
  assert(
    activeAssignments === 0,
    `No se puede eliminar: "${def.name}" está asignado a ${activeAssignments} categoría(s). Desasignalo primero.`
  );

  return prisma.articleAttributeDef.update({
    where: { id },
    data: { deletedAt: new Date(), isActive: false },
    select: { id: true },
  });
}

/* =========================
   CREATE OPTION
========================= */
export async function createDefOption(defId: string, jewelryId: string, data: any) {
  assert(defId, "Id de atributo inválido.");
  assert(jewelryId, "Tenant inválido.");

  const def = await prisma.articleAttributeDef.findFirst({
    where: { id: defId, jewelryId, deletedAt: null },
    select: { id: true, inputType: true },
  });
  assert(def, "Atributo no encontrado.");
  assert(
    (OPTION_TYPES as readonly string[]).includes(def.inputType),
    "Este tipo de atributo no admite opciones. Solo SELECT, MULTISELECT y COLOR."
  );

  const label = s(data?.label);
  assert(label, "Etiqueta de la opción requerida.");

  return prisma.articleAttributeDefOption.create({
    data: {
      definitionId: defId,
      label,
      value: s(data?.value) || label,
      colorHex: s(data?.colorHex),
      sortOrder: Number(data?.sortOrder ?? 0) || 0,
      isActive: true,
    },
    select: OPT_SELECT,
  });
}

/* =========================
   UPDATE OPTION
========================= */
export async function updateDefOption(optionId: string, jewelryId: string, data: any) {
  assert(optionId, "Id de opción inválido.");
  assert(jewelryId, "Tenant inválido.");

  const opt = await prisma.articleAttributeDefOption.findFirst({
    where: { id: optionId, definition: { jewelryId } },
    select: { id: true },
  });
  assert(opt, "Opción no encontrada.");

  const label = s(data?.label);
  assert(label, "Etiqueta requerida.");

  return prisma.articleAttributeDefOption.update({
    where: { id: optionId },
    data: {
      label,
      value: s(data?.value) || label,
      colorHex: s(data?.colorHex),
      sortOrder: Number(data?.sortOrder ?? 0) || 0,
    },
    select: OPT_SELECT,
  });
}

/* =========================
   TOGGLE OPTION
========================= */
export async function toggleDefOption(optionId: string, jewelryId: string) {
  assert(optionId, "Id de opción inválido.");
  assert(jewelryId, "Tenant inválido.");

  const opt = await prisma.articleAttributeDefOption.findFirst({
    where: { id: optionId, definition: { jewelryId } },
    select: { id: true, isActive: true },
  });
  assert(opt, "Opción no encontrada.");

  return prisma.articleAttributeDefOption.update({
    where: { id: optionId },
    data: { isActive: !opt.isActive },
    select: { id: true, isActive: true },
  });
}

/* =========================
   REORDER OPTIONS
========================= */
export async function reorderDefOptions(
  defId: string,
  ids: string[],
  jewelryId: string
) {
  assert(defId, "Id de atributo inválido.");
  assert(Array.isArray(ids) && ids.length > 0, "Lista de ids inválida.");
  assert(jewelryId, "Tenant inválido.");

  const def = await prisma.articleAttributeDef.findFirst({
    where: { id: defId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(def, "Atributo no encontrado.");

  await prisma.$transaction(
    ids.map((id, idx) =>
      prisma.articleAttributeDefOption.updateMany({
        where: { id, definitionId: defId },
        data: { sortOrder: idx },
      })
    )
  );

  return { ok: true };
}

/* =========================
   DELETE OPTION (hard delete)
========================= */
export async function deleteDefOption(optionId: string, jewelryId: string) {
  assert(optionId, "Id de opción inválido.");
  assert(jewelryId, "Tenant inválido.");

  const opt = await prisma.articleAttributeDefOption.findFirst({
    where: { id: optionId, definition: { jewelryId } },
    select: { id: true },
  });
  assert(opt, "Opción no encontrada.");

  return prisma.articleAttributeDefOption.delete({
    where: { id: optionId },
    select: { id: true },
  });
}
