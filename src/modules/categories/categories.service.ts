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

const SELECT = {
  id: true,
  jewelryId: true,
  parentId: true,
  name: true,
  description: true,
  imageUrl: true,
  sortOrder: true,
  isActive: true,
  deletedAt: true,
  createdAt: true,
  updatedAt: true,
  parent: { select: { id: true, name: true } },
  _count: { select: { children: { where: { deletedAt: null } } } },
} as const;

/* =========================
   LIST
========================= */
export async function listCategories(jewelryId: string) {
  assert(jewelryId, "Tenant inválido.");

  const rows = await prisma.articleCategory.findMany({
    where: { jewelryId, deletedAt: null },
    select: SELECT,
    orderBy: [{ sortOrder: "asc" }, { name: "asc" }],
  });

  return rows.map((r) => ({
    ...r,
    childrenCount: r._count.children,
    _count: undefined,
  }));
}

/* =========================
   CREATE
========================= */
export async function createCategory(jewelryId: string, data: any) {
  assert(jewelryId, "Tenant inválido.");

  const name = s(data?.name);
  assert(name, "Nombre requerido.");

  const parentId = s(data?.parentId) || null;

  // Validate parentId belongs to this tenant and is not deleted
  if (parentId) {
    const parent = await prisma.articleCategory.findFirst({
      where: { id: parentId, jewelryId, deletedAt: null },
      select: { id: true, parentId: true },
    });
    assert(parent, "La categoría padre no existe.");

    // Prevent deeply nested: max 2 levels of children (so root -> level1 -> level2)
    if (parent.parentId) {
      const grandParent = await prisma.articleCategory.findFirst({
        where: { id: parent.parentId, jewelryId, deletedAt: null },
        select: { parentId: true },
      });
      assert(!grandParent?.parentId, "Máximo 3 niveles de jerarquía permitidos.");
    }
  }

  // Check duplicate name within same parent
  const existing = await prisma.articleCategory.findFirst({
    where: {
      jewelryId,
      parentId: parentId ?? null,
      name: { equals: name, mode: "insensitive" },
      deletedAt: null,
    },
  });
  assert(!existing, `Ya existe una categoría con el nombre "${name}" en ese nivel.`);

  return prisma.articleCategory.create({
    data: {
      jewelryId,
      parentId,
      name,
      description: s(data?.description),
      imageUrl: s(data?.imageUrl),
      sortOrder: Number(data?.sortOrder ?? 0) || 0,
      isActive: true,
    },
    select: SELECT,
  });
}

/* =========================
   UPDATE
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

  // Can't set itself as parent
  assert(parentId !== id, "Una categoría no puede ser su propia padre.");

  if (parentId) {
    const parent = await prisma.articleCategory.findFirst({
      where: { id: parentId, jewelryId, deletedAt: null },
      select: { id: true, parentId: true },
    });
    assert(parent, "La categoría padre no existe.");

    // Can't set a child as parent (would create cycle)
    assert(parent.parentId !== id, "No se puede crear una referencia circular.");

    if (parent.parentId) {
      const grandParent = await prisma.articleCategory.findFirst({
        where: { id: parent.parentId, jewelryId, deletedAt: null },
        select: { parentId: true },
      });
      assert(!grandParent?.parentId, "Máximo 3 niveles de jerarquía permitidos.");
    }
  }

  // Check duplicate name within same parent (excluding self)
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

  const isActive = data?.isActive === false ? false : true;

  return prisma.articleCategory.update({
    where: { id },
    data: {
      parentId,
      name,
      description: s(data?.description),
      imageUrl: s(data?.imageUrl),
      sortOrder: Number(data?.sortOrder ?? 0) || 0,
      isActive,
    },
    select: SELECT,
  });
}

/* =========================
   TOGGLE ACTIVE
========================= */
export async function toggleCategory(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const cat = await prisma.articleCategory.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true, isActive: true },
  });
  assert(cat, "Categoría no encontrada.");

  return prisma.articleCategory.update({
    where: { id },
    data: { isActive: !cat.isActive },
    select: SELECT,
  });
}

/* =========================
   DELETE (SOFT)
========================= */
export async function deleteCategory(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const cat = await prisma.articleCategory.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true, name: true },
  });
  assert(cat, "Categoría no encontrada.");

  // Check active children
  const childCount = await prisma.articleCategory.count({
    where: { parentId: id, jewelryId, deletedAt: null },
  });
  assert(childCount === 0, "No se puede eliminar: la categoría tiene subcategorías. Eliminá o reasigná las subcategorías primero.");

  return prisma.articleCategory.update({
    where: { id },
    data: { deletedAt: new Date(), isActive: false },
    select: { id: true },
  });
}
