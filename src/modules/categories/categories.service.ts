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

/** Select for ArticleCategory rows */
const CAT_SELECT = {
  id: true,
  jewelryId: true,
  parentId: true,
  defaultPriceListId: true,
  name: true,
  description: true,
  imageUrl: true,
  sortOrder: true,
  isActive: true,
  deletedAt: true,
  createdAt: true,
  updatedAt: true,
  parent: { select: { id: true, name: true } },
  defaultPriceList: { select: { id: true, name: true, code: true } },
  _count: {
    select: {
      children: { where: { deletedAt: null } },
      attributes: { where: { deletedAt: null } },
    },
  },
} as const;

/** Select for ArticleCategoryAttribute (assignment) — includes definition join */
const ASSIGN_SELECT = {
  id: true,
  jewelryId: true,
  categoryId: true,
  definitionId: true,
  isRequired: true,
  isActive: true,
  isFilterable: true,
  isVariantAxis: true,
  inheritToChild: true,
  sortOrder: true,
  deletedAt: true,
  createdAt: true,
  updatedAt: true,
  definition: {
    select: {
      name: true,
      code: true,
      inputType: true,
      helpText: true,
      unit: true,
      defaultValue: true,
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

/* =========================
   HELPERS
========================= */

function mapCategory(r: any, previewMap?: Map<string, string[]>) {
  return {
    ...r,
    childrenCount: r._count.children,
    attributeCount: r._count.attributes,
    attributePreview: previewMap?.get(r.id) ?? [],
    _count: undefined,
  };
}

/** Flatten assignment + definition into a single response object */
function mapAssignment(row: any) {
  const { definition, ...assign } = row;
  return {
    ...assign,
    // Definition fields surfaced at root level (backward-compat shape)
    name: definition.name,
    code: definition.code,
    inputType: definition.inputType,
    helpText: definition.helpText,
    unit: definition.unit,
    defaultValue: definition.defaultValue,
    options: (definition.options ?? []).map((o: any) => ({
      id: o.id,
      attributeId: assign.id, // backward compat
      label: o.label,
      value: o.value,
      colorHex: o.colorHex,
      sortOrder: o.sortOrder,
      isActive: o.isActive,
    })),
  };
}

async function validateDefaultPriceList(
  jewelryId: string,
  defaultPriceListId: string | null
) {
  if (!defaultPriceListId) return;
  const pl = await prisma.priceList.findFirst({
    where: { id: defaultPriceListId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(pl, "La lista de precios por defecto no existe o no pertenece a este tenant.");
}

/* =========================
   LIST CATEGORIES
========================= */
export async function listCategories(jewelryId: string) {
  assert(jewelryId, "Tenant inválido.");

  const rows = await prisma.articleCategory.findMany({
    where: { jewelryId, deletedAt: null },
    select: CAT_SELECT,
    orderBy: [{ sortOrder: "asc" }, { name: "asc" }],
  });

  const categoryIds = rows.map((r) => r.id);

  const attrs = categoryIds.length
    ? await prisma.articleCategoryAttribute.findMany({
        where: {
          jewelryId,
          categoryId: { in: categoryIds },
          deletedAt: null,
          isActive: true,
          definition: {
            deletedAt: null,
            isActive: true,
          },
        },
        select: {
          categoryId: true,
          definition: {
            select: {
              name: true,
            },
          },
        },
        orderBy: [
          { sortOrder: "asc" },
          { definition: { name: "asc" } },
        ],
      })
    : [];

  const previewMap = new Map<string, string[]>();

  for (const row of attrs) {
    const list = previewMap.get(row.categoryId) ?? [];
    if (list.length < 3) {
      list.push(row.definition.name);
      previewMap.set(row.categoryId, list);
    }
  }

  return rows.map((r) => mapCategory(r, previewMap));
}

/* =========================
   CREATE CATEGORY
========================= */
export async function createCategory(jewelryId: string, data: any) {
  assert(jewelryId, "Tenant inválido.");

  const name = s(data?.name);
  assert(name, "Nombre requerido.");

  const parentId = s(data?.parentId) || null;
  const defaultPriceListId = s(data?.defaultPriceListId) || null;

  if (parentId) {
    const parent = await prisma.articleCategory.findFirst({
      where: { id: parentId, jewelryId, deletedAt: null },
      select: { id: true, parentId: true },
    });
    assert(parent, "La categoría padre no existe.");

    if (parent.parentId) {
      const grandParent = await prisma.articleCategory.findFirst({
        where: { id: parent.parentId, jewelryId, deletedAt: null },
        select: { parentId: true },
      });
      assert(!grandParent?.parentId, "Máximo 3 niveles de jerarquía permitidos.");
    }
  }

  const existing = await prisma.articleCategory.findFirst({
    where: {
      jewelryId,
      parentId: parentId ?? null,
      name: { equals: name, mode: "insensitive" },
      deletedAt: null,
    },
  });
  assert(!existing, `Ya existe una categoría con el nombre "${name}" en ese nivel.`);

  await validateDefaultPriceList(jewelryId, defaultPriceListId);

  const created = await prisma.articleCategory.create({
    data: {
      jewelryId,
      parentId,
      defaultPriceListId,
      name,
      description: s(data?.description),
      imageUrl: s(data?.imageUrl),
      sortOrder: Number(data?.sortOrder ?? 0) || 0,
      isActive: true,
    },
    select: CAT_SELECT,
  });

  return { ...mapCategory(created) };
}

/* =========================
   UPDATE CATEGORY
========================= */
export async function updateCategory(id: string, jewelryId: string, data: any) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const name = s(data?.name);
  assert(name, "Nombre requerido.");

  const existing = await prisma.articleCategory.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(existing, "Categoría no encontrada.");

  const parentId = s(data?.parentId) || null;
  const defaultPriceListId = s(data?.defaultPriceListId) || null;

  assert(parentId !== id, "Una categoría no puede ser su propia padre.");

  if (parentId) {
    const parent = await prisma.articleCategory.findFirst({
      where: { id: parentId, jewelryId, deletedAt: null },
      select: { id: true, parentId: true },
    });
    assert(parent, "La categoría padre no existe.");
    assert(parent.parentId !== id, "No se puede crear una referencia circular.");

    if (parent.parentId) {
      const grandParent = await prisma.articleCategory.findFirst({
        where: { id: parent.parentId, jewelryId, deletedAt: null },
        select: { parentId: true },
      });
      assert(!grandParent?.parentId, "Máximo 3 niveles de jerarquía permitidos.");
    }
  }

  const dup = await prisma.articleCategory.findFirst({
    where: {
      jewelryId,
      parentId: parentId ?? null,
      name: { equals: name, mode: "insensitive" },
      deletedAt: null,
      id: { not: id },
    },
  });
  assert(!dup, `Ya existe una categoría con el nombre "${name}" en ese nivel.`);

  await validateDefaultPriceList(jewelryId, defaultPriceListId);

  const isActive = data?.isActive === false ? false : true;

  const updated = await prisma.articleCategory.update({
    where: { id },
    data: {
      parentId,
      defaultPriceListId,
      name,
      description: s(data?.description),
      imageUrl: s(data?.imageUrl),
      sortOrder: Number(data?.sortOrder ?? 0) || 0,
      isActive,
    },
    select: CAT_SELECT,
  });

  const previewRows = await prisma.articleCategoryAttribute.findMany({
    where: {
      jewelryId,
      categoryId: id,
      deletedAt: null,
      isActive: true,
      definition: {
        deletedAt: null,
        isActive: true,
      },
    },
    select: {
      categoryId: true,
      definition: { select: { name: true } },
    },
    orderBy: [{ sortOrder: "asc" }, { definition: { name: "asc" } }],
    take: 3,
  });

  const previewMap = new Map<string, string[]>();
  previewMap.set(
    id,
    previewRows.map((r) => r.definition.name)
  );

  return mapCategory(updated, previewMap);
}

/* =========================
   TOGGLE CATEGORY
========================= */
export async function toggleCategory(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const cat = await prisma.articleCategory.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true, isActive: true },
  });
  assert(cat, "Categoría no encontrada.");

  const updated = await prisma.articleCategory.update({
    where: { id },
    data: { isActive: !cat.isActive },
    select: CAT_SELECT,
  });

  const previewRows = await prisma.articleCategoryAttribute.findMany({
    where: {
      jewelryId,
      categoryId: id,
      deletedAt: null,
      isActive: true,
      definition: {
        deletedAt: null,
        isActive: true,
      },
    },
    select: {
      categoryId: true,
      definition: { select: { name: true } },
    },
    orderBy: [{ sortOrder: "asc" }, { definition: { name: "asc" } }],
    take: 3,
  });

  const previewMap = new Map<string, string[]>();
  previewMap.set(
    id,
    previewRows.map((r) => r.definition.name)
  );

  return mapCategory(updated, previewMap);
}

/* =========================
   DELETE CATEGORY (SOFT)
========================= */
export async function deleteCategory(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const cat = await prisma.articleCategory.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true, name: true },
  });
  assert(cat, "Categoría no encontrada.");

  const childCount = await prisma.articleCategory.count({
    where: { parentId: id, jewelryId, deletedAt: null },
  });
  assert(
    childCount === 0,
    "No se puede eliminar: la categoría tiene subcategorías. Eliminá o reasigná las subcategorías primero."
  );

  return prisma.articleCategory.update({
    where: { id },
    data: { deletedAt: new Date(), isActive: false },
    select: { id: true },
  });
}

/* =========================
   REORDER CATEGORIES (same parent)
========================= */
export async function reorderCategories(
  jewelryId: string,
  parentId: string | null,
  orderedIds: string[]
) {
  assert(jewelryId, "Tenant inválido.");
  assert(Array.isArray(orderedIds) && orderedIds.length > 0, "Lista de ids inválida.");

  const cats = await prisma.articleCategory.findMany({
    where: {
      id: { in: orderedIds },
      jewelryId,
      deletedAt: null,
      parentId: parentId ?? null,
    },
    select: { id: true },
  });

  assert(
    cats.length === orderedIds.length,
    "Algunas categorías no existen, fueron eliminadas o no pertenecen a este nivel."
  );

  await prisma.$transaction(
    orderedIds.map((id, idx) =>
      prisma.articleCategory.update({
        where: { id },
        data: { sortOrder: idx * 10 },
      })
    )
  );

  return { ok: true };
}

/* =========================
   LIST ASSIGNMENTS (own only, active + inactive)
========================= */
export async function listAttributes(categoryId: string, jewelryId: string) {
  assert(categoryId, "Id de categoría inválido.");
  assert(jewelryId, "Tenant inválido.");

  const cat = await prisma.articleCategory.findFirst({
    where: { id: categoryId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(cat, "Categoría no encontrada.");

  const rows = await prisma.articleCategoryAttribute.findMany({
    where: { categoryId, jewelryId, deletedAt: null },
    select: ASSIGN_SELECT,
    orderBy: [{ sortOrder: "asc" }, { createdAt: "asc" }],
  });

  return rows.map(mapAssignment);
}

/* =========================
   GET EFFECTIVE ASSIGNMENTS (own + inherited, active only)
   Returns inherited with sourceCategoryId / sourceCategoryName
========================= */
export async function getEffectiveAttributes(categoryId: string, jewelryId: string) {
  assert(categoryId, "Id de categoría inválido.");
  assert(jewelryId, "Tenant inválido.");

  const chain: string[] = [];
  let currentId: string | null = categoryId;
  while (currentId) {
    const cat: { id: string; parentId: string | null } | null =
      await prisma.articleCategory.findFirst({
        where: { id: currentId, jewelryId, deletedAt: null },
        select: { id: true, parentId: true },
      });
    if (!cat) break;
    chain.push(cat.id);
    currentId = cat.parentId;
  }

  const chainCats = await prisma.articleCategory.findMany({
    where: { id: { in: chain }, jewelryId },
    select: { id: true, name: true },
  });
  const catNameMap = new Map(chainCats.map((c) => [c.id, c.name]));

  const allAssigns = await prisma.articleCategoryAttribute.findMany({
    where: {
      categoryId: { in: chain },
      jewelryId,
      deletedAt: null,
      isActive: true,
    },
    select: { ...ASSIGN_SELECT, categoryId: true },
    orderBy: [{ sortOrder: "asc" }, { createdAt: "asc" }],
  });

  const seen = new Map<
    string,
    ReturnType<typeof mapAssignment> & {
      inherited: boolean;
      sourceCategoryId: string;
      sourceCategoryName: string;
    }
  >();

  for (const levelId of [...chain].reverse()) {
    const levelAssigns = allAssigns.filter((a) => a.categoryId === levelId);
    const isOwn = levelId === categoryId;

    for (const assign of levelAssigns) {
      if (!isOwn && !assign.inheritToChild) continue;
      const mapped = mapAssignment(assign);
      seen.set(assign.definitionId, {
        ...mapped,
        inherited: !isOwn,
        sourceCategoryId: levelId,
        sourceCategoryName: catNameMap.get(levelId) ?? "",
      });
    }
  }

  return Array.from(seen.values());
}

/* =========================
   CREATE ASSIGNMENT
========================= */
export async function createAttribute(categoryId: string, jewelryId: string, data: any) {
  assert(categoryId, "Id de categoría inválido.");
  assert(jewelryId, "Tenant inválido.");

  const cat = await prisma.articleCategory.findFirst({
    where: { id: categoryId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(cat, "Categoría no encontrada.");

  const definitionId = s(data?.definitionId);

  if (definitionId) {
    const def = await prisma.articleAttributeDef.findFirst({
      where: { id: definitionId, jewelryId, deletedAt: null },
      select: { id: true },
    });
    assert(def, "El atributo no existe en la biblioteca de este tenant.");

    const existing = await prisma.articleCategoryAttribute.findFirst({
      where: { categoryId, definitionId, deletedAt: null },
      select: { id: true },
    });
    assert(!existing, "Este atributo ya está asignado a esta categoría.");

    const assign = await prisma.articleCategoryAttribute.create({
      data: {
        jewelryId,
        categoryId,
        definitionId,
        isRequired: Boolean(data?.isRequired),
        isActive: true,
        isFilterable: data?.isFilterable !== false,
        isVariantAxis: Boolean(data?.isVariantAxis),
        inheritToChild: data?.inheritToChild !== false,
        sortOrder: Number(data?.sortOrder ?? 0) || 0,
      },
      select: ASSIGN_SELECT,
    });
    return mapAssignment(assign);
  }

  const name = s(data?.name);
  assert(name, "Nombre del atributo requerido.");

  const inputType = s(data?.inputType);
  assert(
    (VALID_INPUT_TYPES as readonly string[]).includes(inputType),
    `Tipo de campo inválido. Valores permitidos: ${VALID_INPUT_TYPES.join(", ")}.`
  );

  const result = await prisma.$transaction(async (tx) => {
    const def = await tx.articleAttributeDef.create({
      data: {
        jewelryId,
        name,
        code: s(data?.code),
        inputType: inputType as any,
        helpText: s(data?.helpText),
        unit: s(data?.unit),
        defaultValue: s(data?.defaultValue),
        isActive: true,
      },
      select: { id: true },
    });

    const assign = await tx.articleCategoryAttribute.create({
      data: {
        jewelryId,
        categoryId,
        definitionId: def.id,
        isRequired: Boolean(data?.isRequired),
        isActive: true,
        isFilterable: data?.isFilterable !== false,
        isVariantAxis: Boolean(data?.isVariantAxis),
        inheritToChild: data?.inheritToChild !== false,
        sortOrder: Number(data?.sortOrder ?? 0) || 0,
      },
      select: ASSIGN_SELECT,
    });

    return assign;
  });

  return mapAssignment(result);
}

/* =========================
   UPDATE ASSIGNMENT CONFIG
========================= */
export async function updateAttribute(assignId: string, jewelryId: string, data: any) {
  assert(assignId, "Id de asignación inválido.");
  assert(jewelryId, "Tenant inválido.");

  const assign = await prisma.articleCategoryAttribute.findFirst({
    where: { id: assignId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(assign, "Asignación no encontrada.");

  const updated = await prisma.articleCategoryAttribute.update({
    where: { id: assignId },
    data: {
      isRequired: Boolean(data?.isRequired),
      isFilterable: data?.isFilterable !== false,
      isVariantAxis: Boolean(data?.isVariantAxis),
      inheritToChild: data?.inheritToChild !== false,
      sortOrder: Number(data?.sortOrder ?? 0) || 0,
    },
    select: ASSIGN_SELECT,
  });

  return mapAssignment(updated);
}

/* =========================
   TOGGLE ASSIGNMENT ACTIVE
========================= */
export async function toggleAttribute(assignId: string, jewelryId: string) {
  assert(assignId, "Id de asignación inválido.");
  assert(jewelryId, "Tenant inválido.");

  const assign = await prisma.articleCategoryAttribute.findFirst({
    where: { id: assignId, jewelryId, deletedAt: null },
    select: { id: true, isActive: true },
  });
  assert(assign, "Asignación no encontrada.");

  const updated = await prisma.articleCategoryAttribute.update({
    where: { id: assignId },
    data: { isActive: !assign.isActive },
    select: ASSIGN_SELECT,
  });

  return mapAssignment(updated);
}

/* =========================
   DELETE ASSIGNMENT (SOFT)
========================= */
export async function deleteAttribute(assignId: string, jewelryId: string) {
  assert(assignId, "Id de asignación inválido.");
  assert(jewelryId, "Tenant inválido.");

  const assign = await prisma.articleCategoryAttribute.findFirst({
    where: { id: assignId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(assign, "Asignación no encontrada.");

  return prisma.articleCategoryAttribute.update({
    where: { id: assignId },
    data: { deletedAt: new Date(), isActive: false },
    select: { id: true },
  });
}

/* =========================
   CREATE OPTION (on the global def via assignId)
========================= */
export async function createOption(assignId: string, jewelryId: string, data: any) {
  assert(assignId, "Id de asignación inválido.");
  assert(jewelryId, "Tenant inválido.");

  const assign = await prisma.articleCategoryAttribute.findFirst({
    where: { id: assignId, jewelryId, deletedAt: null },
    select: { id: true, definitionId: true, definition: { select: { inputType: true } } },
  });
  assert(assign, "Asignación no encontrada.");
  assert(
    (OPTION_TYPES as readonly string[]).includes(assign.definition.inputType),
    "Este tipo de atributo no admite opciones. Solo SELECT, MULTISELECT y COLOR."
  );

  const label = s(data?.label);
  assert(label, "Etiqueta de la opción requerida.");

  return prisma.articleAttributeDefOption.create({
    data: {
      definitionId: assign.definitionId,
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
   UPDATE OPTION (on global def)
========================= */
export async function updateOption(optionId: string, jewelryId: string, data: any) {
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
export async function toggleOption(optionId: string, jewelryId: string) {
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
   DELETE OPTION (hard delete on global def)
========================= */
export async function deleteOption(optionId: string, jewelryId: string) {
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