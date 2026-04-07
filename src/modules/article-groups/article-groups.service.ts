import { prisma } from "../../lib/prisma.js";

function s(v: any): string { return String(v ?? "").trim(); }
function assert(cond: any, msg: string, status = 400): asserts cond {
  if (!cond) { const e: any = new Error(msg); e.status = status; throw e; }
}

function slugify(str: string): string {
  return str
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

const GROUP_SELECT = {
  id: true,
  jewelryId: true,
  name: true,
  slug: true,
  description: true,
  mainImageUrl: true,
  selectorLabel: true,
  isActive: true,
  createdAt: true,
  updatedAt: true,
  deletedAt: true,
  _count: { select: { articles: { where: { deletedAt: null } } } },
} as const;

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------
export async function listGroups(jewelryId: string) {
  assert(jewelryId, "Tenant inválido.");
  return prisma.articleGroup.findMany({
    where: { jewelryId, deletedAt: null },
    select: GROUP_SELECT,
    orderBy: [{ isActive: "desc" }, { name: "asc" }],
  });
}

// ---------------------------------------------------------------------------
// Get one (with articles — richer data for group management)
// ---------------------------------------------------------------------------
export async function getGroup(id: string, jewelryId: string) {
  const group = await prisma.articleGroup.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: {
      ...GROUP_SELECT,
      articles: {
        where: { deletedAt: null },
        select: {
          id: true,
          code: true,
          sku: true,
          name: true,
          mainImageUrl: true,
          isActive: true,
          status: true,
          salePrice: true,
          costPrice: true,
          groupOrder: true,
          category: { select: { id: true, name: true } },
        },
        orderBy: [{ groupOrder: "asc" }, { name: "asc" }],
      },
    },
  });
  assert(group, "Grupo no encontrado.", 404);

  // Agregar stock total por artículo
  const articleIds = group.articles.map((a) => a.id);
  const stockTotals = articleIds.length > 0
    ? await prisma.articleStock.groupBy({
        by: ["articleId"],
        where: { articleId: { in: articleIds } },
        _sum: { quantity: true },
      })
    : [];
  const stockMap: Record<string, number> = {};
  for (const s of stockTotals) {
    stockMap[s.articleId] = Number(s._sum.quantity ?? 0);
  }

  return {
    ...group,
    articles: group.articles.map((a) => ({
      ...a,
      stockTotal: stockMap[a.id] ?? 0,
    })),
  };
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------
export async function createGroup(jewelryId: string, data: any) {
  assert(jewelryId, "Tenant inválido.");
  const name = s(data?.name);
  assert(name, "El nombre es obligatorio.");

  const slug = s(data?.slug) || slugify(name);
  assert(slug, "Slug inválido.");

  const conflict = await prisma.articleGroup.findFirst({
    where: { jewelryId, slug, deletedAt: null }, select: { id: true },
  });
  assert(!conflict, `Ya existe un grupo con slug "${slug}".`);

  return prisma.articleGroup.create({
    data: {
      jewelryId,
      name,
      slug,
      description:   s(data?.description),
      mainImageUrl:  s(data?.mainImageUrl),
      selectorLabel: s(data?.selectorLabel),
      isActive:      data?.isActive !== false,
    },
    select: GROUP_SELECT,
  });
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------
export async function updateGroup(id: string, jewelryId: string, data: any) {
  const existing = await prisma.articleGroup.findFirst({
    where: { id, jewelryId, deletedAt: null }, select: { id: true, slug: true },
  });
  assert(existing, "Grupo no encontrado.", 404);

  const name = data?.name !== undefined ? s(data.name) : undefined;
  if (name !== undefined) assert(name, "El nombre es obligatorio.");

  // Si se envía nombre o slug, regenerar/validar slug
  let slug: string | undefined;
  if (data?.slug !== undefined || data?.name !== undefined) {
    slug = s(data?.slug) || (name ? slugify(name) : existing.slug);
    if (slug !== existing.slug) {
      const conflict = await prisma.articleGroup.findFirst({
        where: { jewelryId, slug, deletedAt: null, id: { not: id } },
        select: { id: true },
      });
      assert(!conflict, `Ya existe un grupo con slug "${slug}".`);
    }
  }

  return prisma.articleGroup.update({
    where: { id },
    data: {
      ...(name       !== undefined ? { name }          : {}),
      ...(slug       !== undefined ? { slug }          : {}),
      ...(data?.description   !== undefined ? { description:   s(data.description)   } : {}),
      ...(data?.mainImageUrl  !== undefined ? { mainImageUrl:  s(data.mainImageUrl)  } : {}),
      ...(data?.selectorLabel !== undefined ? { selectorLabel: s(data.selectorLabel) } : {}),
      ...(data?.isActive      !== undefined ? { isActive:      !!data.isActive       } : {}),
    },
    select: GROUP_SELECT,
  });
}

// ---------------------------------------------------------------------------
// Toggle active
// ---------------------------------------------------------------------------
export async function toggleGroup(id: string, jewelryId: string) {
  const existing = await prisma.articleGroup.findFirst({
    where: { id, jewelryId, deletedAt: null }, select: { id: true, isActive: true },
  });
  assert(existing, "Grupo no encontrado.", 404);
  return prisma.articleGroup.update({
    where: { id },
    data: { isActive: !existing.isActive },
    select: GROUP_SELECT,
  });
}

// ---------------------------------------------------------------------------
// Soft delete
// ---------------------------------------------------------------------------
export async function removeGroup(id: string, jewelryId: string) {
  const existing = await prisma.articleGroup.findFirst({
    where: { id, jewelryId, deletedAt: null }, select: { id: true },
  });
  assert(existing, "Grupo no encontrado.", 404);

  // Desasociar artículos antes de borrar (SetNull)
  await prisma.article.updateMany({
    where: { groupId: id, jewelryId },
    data: { groupId: null, groupOrder: 0 },
  });

  await prisma.articleGroup.update({
    where: { id },
    data: { deletedAt: new Date(), isActive: false },
  });
  return { id };
}

// ---------------------------------------------------------------------------
// Assign / remove article from group
// ---------------------------------------------------------------------------
export async function setArticleGroup(
  articleId: string,
  groupId: string | null,
  jewelryId: string,
) {
  const article = await prisma.article.findFirst({
    where: { id: articleId, jewelryId, deletedAt: null }, select: { id: true },
  });
  assert(article, "Artículo no encontrado.", 404);

  if (groupId) {
    const group = await prisma.articleGroup.findFirst({
      where: { id: groupId, jewelryId, deletedAt: null }, select: { id: true },
    });
    assert(group, "Grupo no encontrado.", 404);
  }

  return prisma.article.update({
    where: { id: articleId },
    data: { groupId: groupId ?? null, groupOrder: groupId ? 0 : 0 },
    select: { id: true, groupId: true },
  });
}

// ---------------------------------------------------------------------------
// Add article to group (desde pantalla de gestión del grupo)
// ---------------------------------------------------------------------------
export async function addArticleToGroup(groupId: string, articleId: string, jewelryId: string) {
  const group = await prisma.articleGroup.findFirst({
    where: { id: groupId, jewelryId, deletedAt: null }, select: { id: true },
  });
  assert(group, "Grupo no encontrado.", 404);

  const article = await prisma.article.findFirst({
    where: { id: articleId, jewelryId, deletedAt: null }, select: { id: true, groupId: true },
  });
  assert(article, "Artículo no encontrado.", 404);
  assert(!article.groupId || article.groupId === groupId, "El artículo ya pertenece a otro grupo.");

  // Determinar el siguiente groupOrder
  const maxOrder = await prisma.article.aggregate({
    where: { groupId, deletedAt: null },
    _max: { groupOrder: true },
  });
  const nextOrder = (maxOrder._max.groupOrder ?? -1) + 1;

  return prisma.article.update({
    where: { id: articleId },
    data: { groupId, groupOrder: nextOrder },
    select: { id: true, groupId: true, groupOrder: true },
  });
}

// ---------------------------------------------------------------------------
// Remove article from group (desde pantalla de gestión del grupo)
// ---------------------------------------------------------------------------
export async function removeArticleFromGroup(groupId: string, articleId: string, jewelryId: string) {
  const article = await prisma.article.findFirst({
    where: { id: articleId, jewelryId, groupId, deletedAt: null }, select: { id: true },
  });
  assert(article, "El artículo no pertenece a este grupo.", 404);

  return prisma.article.update({
    where: { id: articleId },
    data: { groupId: null, groupOrder: 0 },
    select: { id: true, groupId: true },
  });
}

// ---------------------------------------------------------------------------
// Reorder articles in group
// ---------------------------------------------------------------------------
export async function reorderGroupArticles(
  groupId: string,
  orderedIds: string[],
  jewelryId: string,
) {
  const group = await prisma.articleGroup.findFirst({
    where: { id: groupId, jewelryId, deletedAt: null }, select: { id: true },
  });
  assert(group, "Grupo no encontrado.", 404);
  assert(Array.isArray(orderedIds) && orderedIds.length > 0, "La lista de IDs es inválida.");

  await prisma.$transaction(
    orderedIds.map((articleId, idx) =>
      prisma.article.updateMany({
        where: { id: articleId, groupId, jewelryId, deletedAt: null },
        data: { groupOrder: idx },
      }),
    ),
  );
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Search articles available to add to a group
// ---------------------------------------------------------------------------
export async function searchAvailableArticles(
  groupId: string,
  q: string,
  jewelryId: string,
) {
  const group = await prisma.articleGroup.findFirst({
    where: { id: groupId, jewelryId, deletedAt: null }, select: { id: true },
  });
  assert(group, "Grupo no encontrado.", 404);

  const searchTerm = q.trim();
  const where: any = {
    jewelryId,
    deletedAt: null,
    OR: [
      { groupId: null },
    ],
  };

  if (searchTerm) {
    where.AND = [
      {
        OR: [
          { name: { contains: searchTerm, mode: "insensitive" } },
          { code: { contains: searchTerm, mode: "insensitive" } },
          { sku:  { contains: searchTerm, mode: "insensitive" } },
        ],
      },
    ];
  }

  return prisma.article.findMany({
    where,
    select: {
      id: true,
      code: true,
      sku: true,
      name: true,
      mainImageUrl: true,
      isActive: true,
      status: true,
      salePrice: true,
      category: { select: { id: true, name: true } },
    },
    orderBy: { name: "asc" },
    take: 20,
  });
}
