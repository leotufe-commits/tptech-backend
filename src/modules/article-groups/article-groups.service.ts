import { prisma } from "../../lib/prisma.js";
import { enrichVariants, enrichArticles } from "../articles/articles.service.js";

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

async function makeUniqueSlug(jewelryId: string, base: string, excludeId?: string): Promise<string> {
  const notId = excludeId ? { id: { not: excludeId } } : {};
  // Sin filtro deletedAt: el constraint @@unique([jewelryId, slug]) aplica a TODAS las filas,
  // incluyendo soft-deleted. Ignorar eliminados causaba P2002 al crear.
  const free = async (candidate: string) => !(await prisma.articleGroup.findFirst({
    where: { jewelryId, slug: candidate, ...notId }, select: { id: true },
  }));
  if (await free(base)) return base;
  for (let i = 1; i <= 99; i++) {
    const candidate = `${base}-${i}`;
    if (await free(candidate)) return candidate;
  }
  return `${base}-${Date.now()}`;
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
  _count: { select: { items: true } },
} as const;

const IMAGE_SELECT = {
  id: true,
  url: true,
  isMain: true,
  sortOrder: true,
  createdAt: true,
} as const;

const IMAGE_ORDER = [
  { isMain: "desc" as const },
  { sortOrder: "asc" as const },
  { createdAt: "asc" as const },
];

// ── Select reutilizable para artículo en items ─────────────────────────────
const ITEM_ARTICLE_SELECT = {
  id: true,
  name: true,
  code: true,
  mainImageUrl: true,
  status: true,
  isActive: true,
  salePrice: true,
  category: { select: { id: true, name: true } },
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
// Get one — con items enriquecidos (precio + stock)
// ---------------------------------------------------------------------------
export async function getGroup(id: string, jewelryId: string) {
  const group = await prisma.articleGroup.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: {
      ...GROUP_SELECT,
      images: { orderBy: IMAGE_ORDER, select: IMAGE_SELECT },
      items: {
        orderBy: { groupOrder: "asc" },
        select: {
          id: true,
          itemType: true,
          groupOrder: true,
          groupSelectorValue: true,
          article: {
            select: {
              ...ITEM_ARTICLE_SELECT,
              deletedAt: true,
            },
          },
          variant: {
            select: {
              id: true,
              code: true,
              sku: true,
              name: true,
              imageUrl: true,
              isActive: true,
              deletedAt: true,
              article: { select: ITEM_ARTICLE_SELECT },
              images: { where: { isMain: true }, select: { url: true }, take: 1 },
            },
          },
        },
      },
    },
  });
  assert(group, "Grupo no encontrado.", 404);

  // Filtrar items cuya entidad referenciada fue soft-deleted
  const activeItems = group.items.filter(item => {
    if (item.itemType === "VARIANT") return item.variant && !item.variant.deletedAt;
    if (item.itemType === "ARTICLE") return item.article && !item.article.deletedAt;
    return false;
  });

  // Enriquecer items con precio resuelto y stock real (motor de precios)
  const variantIds = activeItems
    .filter(i => i.itemType === "VARIANT")
    .map(i => i.variant!.id);
  const enrichMap = variantIds.length > 0 ? await enrichVariants(variantIds, jewelryId) : new Map();

  const articleItemIds = activeItems
    .filter(i => i.itemType === "ARTICLE")
    .map(i => i.article!.id);
  const articleEnrichMap = articleItemIds.length > 0 ? await enrichArticles(articleItemIds, jewelryId) : new Map();

  const members = activeItems.map(item => {
    if (item.itemType === "VARIANT" && item.variant) {
      const v = item.variant;
      const e = enrichMap.get(v.id) ?? { resolvedSalePrice: null, resolvedSalePriceWithTax: null, stockTotal: 0 };
      const imgUrl = v.images?.[0]?.url || v.imageUrl || v.article.mainImageUrl || "";
      return {
        id:                       item.id,
        itemType:                 "VARIANT" as const,
        refId:                    v.id,
        code:                     v.code,
        sku:                      v.sku,
        name:                     v.name,
        imageUrl:                 imgUrl,
        isActive:                 v.isActive,
        groupOrder:               item.groupOrder,
        groupSelectorValue:       item.groupSelectorValue,
        stockTotal:               e.stockTotal,
        resolvedSalePrice:        e.resolvedSalePrice,
        resolvedSalePriceWithTax: e.resolvedSalePriceWithTax,
        article:                  v.article,
      };
    }

    // ARTICLE item (artículo simple sin variantes)
    const a = item.article!;
    const ae = articleEnrichMap.get(a.id) ?? { resolvedSalePrice: null, resolvedSalePriceWithTax: null, stockTotal: 0 };
    return {
      id:                       item.id,
      itemType:                 "ARTICLE" as const,
      refId:                    a.id,
      code:                     a.code,
      sku:                      "",
      name:                     a.name,
      imageUrl:                 a.mainImageUrl,
      isActive:                 a.isActive,
      groupOrder:               item.groupOrder,
      groupSelectorValue:       item.groupSelectorValue,
      stockTotal:               ae.stockTotal,
      resolvedSalePrice:        ae.resolvedSalePrice,
      resolvedSalePriceWithTax: ae.resolvedSalePriceWithTax,
      article:                  a,
    };
  });

  const { items: _rawItems, ...groupRest } = group;
  return { ...groupRest, items: members };
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------
export async function createGroup(jewelryId: string, data: any) {
  assert(jewelryId, "Tenant inválido.");
  const name = s(data?.name);
  assert(name, "El nombre es obligatorio.");

  const baseSlug = s(data?.slug) || slugify(name) || `grupo-${Date.now()}`;

  // Hasta 5 intentos para manejar race conditions entre requests simultáneos
  for (let attempt = 0; attempt < 5; attempt++) {
    const slug = await makeUniqueSlug(jewelryId, baseSlug);
    try {
      return await prisma.articleGroup.create({
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
    } catch (err: any) {
      if (err?.code !== "P2002") throw err;
      // P2002 por race condition → reintentar con nuevo slug en el siguiente loop
    }
  }

  const e: any = new Error("No se pudo crear el grupo. Probá nuevamente.");
  e.status = 500;
  throw e;
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

  let slug: string | undefined;
  if (data?.slug !== undefined || data?.name !== undefined) {
    const explicitSlug = s(data?.slug);
    if (explicitSlug) {
      // El usuario escribió el slug a mano: validar y mostrar error amigable si hay conflicto
      if (explicitSlug !== existing.slug) {
        const conflict = await prisma.articleGroup.findFirst({
          where: { jewelryId, slug: explicitSlug, deletedAt: null, id: { not: id } },
          select: { id: true },
        });
        assert(!conflict, "Ya existe un grupo con ese nombre o slug. Usá uno diferente.");
      }
      slug = explicitSlug;
    } else if (name) {
      // Slug derivado del nombre: generar uno único automáticamente
      slug = await makeUniqueSlug(jewelryId, slugify(name), id);
    }
  }

  return prisma.articleGroup.update({
    where: { id },
    data: {
      ...(name                       !== undefined ? { name }                              : {}),
      ...(slug                       !== undefined ? { slug }                              : {}),
      ...(data?.description          !== undefined ? { description:   s(data.description)   } : {}),
      ...(data?.mainImageUrl         !== undefined ? { mainImageUrl:  s(data.mainImageUrl)  } : {}),
      ...(data?.selectorLabel        !== undefined ? { selectorLabel: s(data.selectorLabel) } : {}),
      ...(data?.isActive             !== undefined ? { isActive:      !!data.isActive       } : {}),
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
// Soft delete — los items del grupo se eliminan (son solo vínculos)
// ---------------------------------------------------------------------------
export async function removeGroup(id: string, jewelryId: string) {
  const existing = await prisma.articleGroup.findFirst({
    where: { id, jewelryId, deletedAt: null }, select: { id: true },
  });
  assert(existing, "Grupo no encontrado.", 404);

  // Eliminar items (son solo vínculos — artículos y variantes no se tocan)
  await prisma.articleGroupItem.deleteMany({ where: { groupId: id } });

  await prisma.articleGroup.update({
    where: { id },
    data: { deletedAt: new Date(), isActive: false },
  });
  return { id };
}

// ---------------------------------------------------------------------------
// Add item to group (ARTICLE o VARIANT)
// ---------------------------------------------------------------------------
export async function addItemToGroup(
  groupId: string,
  jewelryId: string,
  itemType: "ARTICLE" | "VARIANT",
  refId: string,
  selectorValue = "",
) {
  const group = await prisma.articleGroup.findFirst({
    where: { id: groupId, jewelryId, deletedAt: null }, select: { id: true },
  });
  assert(group, "Grupo no encontrado.", 404);
  assert(refId, "ID del item es requerido.");

  // Verificar que no esté ya en ESTE grupo
  const alreadyInGroup = await prisma.articleGroupItem.findFirst({
    where: itemType === "VARIANT"
      ? { groupId, variantId: refId }
      : { groupId, articleId: refId },
    select: { id: true },
  });
  assert(!alreadyInGroup, "Este item ya está en este grupo.", 409);

  // Verificar que no esté en OTRO grupo
  const inOtherGroup = await prisma.articleGroupItem.findFirst({
    where: itemType === "VARIANT"
      ? { variantId: refId, groupId: { not: groupId } }
      : { articleId: refId, groupId: { not: groupId } },
    select: { id: true },
  });
  assert(!inOtherGroup, "Este item ya pertenece a otro grupo.", 409);

  // Verificar que la entidad exista y no esté eliminada
  if (itemType === "VARIANT") {
    const variant = await prisma.articleVariant.findFirst({
      where: { id: refId, jewelryId, deletedAt: null }, select: { id: true },
    });
    assert(variant, "Variante no encontrada.", 404);
  } else {
    // Solo artículos simples (sin variantes activas) pueden agregarse como ARTICLE
    const article = await prisma.article.findFirst({
      where: { id: refId, jewelryId, deletedAt: null }, select: { id: true },
    });
    assert(article, "Artículo no encontrado.", 404);
    const hasVariants = await prisma.articleVariant.findFirst({
      where: { articleId: refId, deletedAt: null }, select: { id: true },
    });
    assert(!hasVariants, "El artículo tiene variantes. Agregue una variante en su lugar.", 400);
  }

  const maxOrder = await prisma.articleGroupItem.aggregate({
    where: { groupId },
    _max: { groupOrder: true },
  });
  const nextOrder = (maxOrder._max.groupOrder ?? -1) + 1;

  return prisma.articleGroupItem.create({
    data: {
      groupId,
      jewelryId,
      itemType,
      ...(itemType === "VARIANT" ? { variantId: refId } : { articleId: refId }),
      groupOrder:         nextOrder,
      groupSelectorValue: s(selectorValue),
    },
    select: { id: true, groupId: true, groupOrder: true, groupSelectorValue: true, itemType: true },
  });
}

// ---------------------------------------------------------------------------
// Remove item from group
// ---------------------------------------------------------------------------
export async function removeItemFromGroup(groupId: string, itemId: string, jewelryId: string) {
  const item = await prisma.articleGroupItem.findFirst({
    where: { id: itemId, groupId, jewelryId },
    select: { id: true },
  });
  assert(item, "Item no encontrado en el grupo.", 404);
  await prisma.articleGroupItem.delete({ where: { id: itemId } });
  return { id: itemId, groupId };
}

// ---------------------------------------------------------------------------
// Update groupSelectorValue for an item
// ---------------------------------------------------------------------------
export async function updateItemSelectorValue(
  groupId: string,
  itemId: string,
  jewelryId: string,
  value: string,
) {
  const item = await prisma.articleGroupItem.findFirst({
    where: { id: itemId, groupId, jewelryId },
    select: { id: true },
  });
  assert(item, "Item no encontrado en el grupo.", 404);
  return prisma.articleGroupItem.update({
    where: { id: itemId },
    data: { groupSelectorValue: s(value) },
    select: { id: true, groupSelectorValue: true },
  });
}

// ---------------------------------------------------------------------------
// Reorder items in group
// ---------------------------------------------------------------------------
export async function reorderGroupItems(
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
    orderedIds.map((itemId, idx) =>
      prisma.articleGroupItem.updateMany({
        where: { id: itemId, groupId, jewelryId },
        data: { groupOrder: idx },
      }),
    ),
  );
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Search available items (VARIANT + ARTICLE simple) to add to a group
// ---------------------------------------------------------------------------
export async function searchAvailableItems(
  groupId: string,
  q: string,
  jewelryId: string,
) {
  const group = await prisma.articleGroup.findFirst({
    where: { id: groupId, jewelryId, deletedAt: null }, select: { id: true },
  });
  assert(group, "Grupo no encontrado.", 404);

  const term = q.trim();

  // 1. Variantes
  const variantWhere: any = { jewelryId, deletedAt: null, article: { deletedAt: null } };
  if (term) {
    variantWhere.OR = [
      { name: { contains: term, mode: "insensitive" } },
      { code: { contains: term, mode: "insensitive" } },
      { sku:  { contains: term, mode: "insensitive" } },
      { article: { name: { contains: term, mode: "insensitive" } } },
      { article: { code: { contains: term, mode: "insensitive" } } },
    ];
  }

  const variants = await prisma.articleVariant.findMany({
    where: variantWhere,
    select: {
      id: true,
      code: true,
      sku: true,
      name: true,
      imageUrl: true,
      isActive: true,
      article: { select: { id: true, name: true, code: true, mainImageUrl: true, status: true } },
      groupItems: {
        select: { groupId: true, group: { select: { id: true, name: true } } },
        take: 1,
      },
      images: { where: { isMain: true }, select: { url: true }, take: 1 },
    },
    orderBy: [{ article: { name: "asc" } }, { name: "asc" }],
    take: 20,
  });

  // 2. Artículos simples (sin variantes activas)
  const articleWhere: any = {
    jewelryId,
    deletedAt: null,
    variants: { none: { deletedAt: null } },
  };
  if (term) {
    articleWhere.OR = [
      { name: { contains: term, mode: "insensitive" } },
      { code: { contains: term, mode: "insensitive" } },
    ];
  }

  const simpleArticles = await prisma.article.findMany({
    where: articleWhere,
    select: {
      id: true,
      code: true,
      name: true,
      mainImageUrl: true,
      status: true,
      isActive: true,
      groupItems: {
        select: { groupId: true, group: { select: { id: true, name: true } } },
        take: 1,
      },
    },
    orderBy: { name: "asc" },
    take: 15,
  });

  return [
    ...variants.map(v => ({
      itemType:  "VARIANT" as const,
      id:        v.id,
      code:      v.code,
      sku:       v.sku,
      name:      v.name,
      imageUrl:  v.images[0]?.url || v.imageUrl,
      isActive:  v.isActive,
      groupId:   v.groupItems[0]?.groupId ?? null,
      group:     v.groupItems[0]?.group   ?? null,
      article:   v.article,
    })),
    ...simpleArticles.map(a => ({
      itemType:  "ARTICLE" as const,
      id:        a.id,
      code:      a.code,
      sku:       "",
      name:      a.name,
      imageUrl:  a.mainImageUrl,
      isActive:  a.isActive,
      groupId:   a.groupItems[0]?.groupId ?? null,
      group:     a.groupItems[0]?.group   ?? null,
      article:   { id: a.id, name: a.name, code: a.code, mainImageUrl: a.mainImageUrl, status: a.status },
    })),
  ];
}

// ---------------------------------------------------------------------------
// List images of a group
// ---------------------------------------------------------------------------
export async function listGroupImages(groupId: string, jewelryId: string) {
  const group = await prisma.articleGroup.findFirst({
    where: { id: groupId, jewelryId, deletedAt: null }, select: { id: true },
  });
  assert(group, "Grupo no encontrado.", 404);
  return prisma.articleGroupImage.findMany({
    where: { groupId, jewelryId },
    orderBy: IMAGE_ORDER,
    select: IMAGE_SELECT,
  });
}

// ---------------------------------------------------------------------------
// Add image to a group
// ---------------------------------------------------------------------------
export async function addGroupImage(groupId: string, jewelryId: string, url: string) {
  const group = await prisma.articleGroup.findFirst({
    where: { id: groupId, jewelryId, deletedAt: null }, select: { id: true },
  });
  assert(group, "Grupo no encontrado.", 404);
  assert(url, "URL de imagen requerida.");

  const existingCount = await prisma.articleGroupImage.count({ where: { groupId, jewelryId } });
  const isMain = existingCount === 0;

  const image = await prisma.articleGroupImage.create({
    data: { groupId, jewelryId, url, isMain, sortOrder: existingCount },
    select: IMAGE_SELECT,
  });

  if (isMain) {
    await prisma.articleGroup.update({ where: { id: groupId }, data: { mainImageUrl: url } });
  }

  return image;
}

// ---------------------------------------------------------------------------
// Set main image
// ---------------------------------------------------------------------------
export async function setGroupMainImage(groupId: string, imageId: string, jewelryId: string) {
  const image = await prisma.articleGroupImage.findFirst({
    where: { id: imageId, groupId, jewelryId }, select: { id: true, url: true },
  });
  assert(image, "Imagen no encontrada.", 404);

  await prisma.$transaction([
    prisma.articleGroupImage.updateMany({ where: { groupId, jewelryId }, data: { isMain: false } }),
    prisma.articleGroupImage.update({ where: { id: imageId }, data: { isMain: true } }),
    prisma.articleGroup.update({ where: { id: groupId }, data: { mainImageUrl: image.url } }),
  ]);

  return prisma.articleGroupImage.findMany({
    where: { groupId, jewelryId },
    orderBy: IMAGE_ORDER,
    select: IMAGE_SELECT,
  });
}

// ---------------------------------------------------------------------------
// Remove image from a group
// ---------------------------------------------------------------------------
export async function removeGroupImage(groupId: string, imageId: string, jewelryId: string) {
  const image = await prisma.articleGroupImage.findFirst({
    where: { id: imageId, groupId, jewelryId }, select: { id: true, isMain: true },
  });
  assert(image, "Imagen no encontrada.", 404);

  await prisma.articleGroupImage.delete({ where: { id: imageId } });

  if (image.isMain) {
    const next = await prisma.articleGroupImage.findFirst({
      where: { groupId, jewelryId },
      orderBy: [{ sortOrder: "asc" }, { createdAt: "asc" }],
      select: { id: true, url: true },
    });
    if (next) {
      await prisma.articleGroupImage.update({ where: { id: next.id }, data: { isMain: true } });
      await prisma.articleGroup.update({ where: { id: groupId }, data: { mainImageUrl: next.url } });
    } else {
      await prisma.articleGroup.update({ where: { id: groupId }, data: { mainImageUrl: "" } });
    }
  }

  return { id: imageId };
}

// ---------------------------------------------------------------------------
// Search available articles as a tree (articles → variants) for the batch picker
// ---------------------------------------------------------------------------
export async function searchAvailableArticlesTree(
  groupId: string,
  q: string,
  jewelryId: string,
) {
  const group = await prisma.articleGroup.findFirst({
    where: { id: groupId, jewelryId, deletedAt: null }, select: { id: true },
  });
  assert(group, "Grupo no encontrado.", 404);

  const term = q.trim();
  const articleWhere: any = { jewelryId, deletedAt: null };
  if (term) {
    articleWhere.OR = [
      { name: { contains: term, mode: "insensitive" } },
      { code: { contains: term, mode: "insensitive" } },
      {
        variants: {
          some: {
            deletedAt: null,
            OR: [
              { name: { contains: term, mode: "insensitive" } },
              { code: { contains: term, mode: "insensitive" } },
              { sku:  { contains: term, mode: "insensitive" } },
            ],
          },
        },
      },
    ];
  }

  const articles = await prisma.article.findMany({
    where: articleWhere,
    select: {
      id: true,
      name: true,
      code: true,
      mainImageUrl: true,
      isActive: true,
      groupItems: {
        select: { groupId: true, group: { select: { name: true } } },
        take: 1,
      },
      variants: {
        where: { deletedAt: null },
        select: {
          id: true,
          name: true,
          code: true,
          sku: true,
          imageUrl: true,
          isActive: true,
          groupItems: {
            select: { groupId: true, group: { select: { name: true } } },
            take: 1,
          },
          images: { where: { isMain: true }, select: { url: true }, take: 1 },
        },
        orderBy: { sortOrder: "asc" },
      },
    },
    orderBy: { name: "asc" },
    take: 40,
  });

  return articles.map(article => {
    const hasVariants = article.variants.length > 0;
    if (hasVariants) {
      return {
        articleId:     article.id,
        name:          article.name,
        code:          article.code,
        mainImageUrl:  article.mainImageUrl,
        isActive:      article.isActive,
        hasVariants:   true,
        alreadyInGroup: false,
        inOtherGroup:   false,
        otherGroupName: null as string | null,
        variants: article.variants.map(v => {
          const gi = v.groupItems[0] ?? null;
          return {
            variantId:     v.id,
            name:          v.name,
            code:          v.code,
            sku:           v.sku,
            imageUrl:      v.images[0]?.url || v.imageUrl,
            isActive:      v.isActive,
            alreadyInGroup: gi?.groupId === groupId,
            inOtherGroup:   gi !== null && gi.groupId !== groupId,
            otherGroupName: gi && gi.groupId !== groupId ? (gi.group?.name ?? null) : null,
          };
        }),
      };
    }

    const gi = article.groupItems[0] ?? null;
    return {
      articleId:     article.id,
      name:          article.name,
      code:          article.code,
      mainImageUrl:  article.mainImageUrl,
      isActive:      article.isActive,
      hasVariants:   false,
      variants:      [] as any[],
      alreadyInGroup: gi?.groupId === groupId,
      inOtherGroup:   gi !== null && gi.groupId !== groupId,
      otherGroupName: gi && gi.groupId !== groupId ? (gi.group?.name ?? null) : null,
    };
  });
}

// ---------------------------------------------------------------------------
// Add multiple items to a group in one shot (batch picker)
// ARTICLE items with active variants are expanded to their VARIANT items.
// ---------------------------------------------------------------------------
export async function addItemsBatch(
  groupId: string,
  jewelryId: string,
  rawItems: Array<{ itemType: "ARTICLE" | "VARIANT"; refId: string; selectorValue?: string }>,
) {
  const group = await prisma.articleGroup.findFirst({
    where: { id: groupId, jewelryId, deletedAt: null }, select: { id: true },
  });
  assert(group, "Grupo no encontrado.", 404);
  assert(Array.isArray(rawItems) && rawItems.length > 0, "La lista de items es requerida.");
  assert(rawItems.length <= 200, "No se pueden agregar más de 200 items a la vez.");

  // 1. Get existing items in this group
  const existingItems = await prisma.articleGroupItem.findMany({
    where: { groupId },
    select: { variantId: true, articleId: true, groupOrder: true },
  });
  const existingVariantIds  = new Set(existingItems.map(i => i.variantId).filter((x): x is string => x !== null));
  const existingArticleIds  = new Set(existingItems.map(i => i.articleId).filter((x): x is string => x !== null));
  const maxCurrentOrder     = existingItems.reduce((m, i) => Math.max(m, i.groupOrder), -1);

  // 2. Resolve ARTICLE → VARIANT expansion where needed
  const articleRefIds = rawItems.filter(i => i.itemType === "ARTICLE").map(i => i.refId);
  const articleVariantsMap = new Map<string, string[]>();
  if (articleRefIds.length > 0) {
    const variants = await prisma.articleVariant.findMany({
      where: { articleId: { in: articleRefIds }, jewelryId, deletedAt: null },
      select: { id: true, articleId: true },
      orderBy: { sortOrder: "asc" },
    });
    for (const v of variants) {
      const arr = articleVariantsMap.get(v.articleId) ?? [];
      arr.push(v.id);
      articleVariantsMap.set(v.articleId, arr);
    }
  }

  type ResolvedItem = { itemType: "ARTICLE" | "VARIANT"; refId: string; selectorValue: string };
  const resolved: ResolvedItem[] = [];
  for (const item of rawItems) {
    if (item.itemType === "ARTICLE") {
      const variantIds = articleVariantsMap.get(item.refId) ?? [];
      if (variantIds.length > 0) {
        for (const vid of variantIds) resolved.push({ itemType: "VARIANT", refId: vid, selectorValue: "" });
      } else {
        resolved.push({ itemType: "ARTICLE", refId: item.refId, selectorValue: s(item.selectorValue) });
      }
    } else {
      resolved.push({ itemType: "VARIANT", refId: item.refId, selectorValue: s(item.selectorValue) });
    }
  }

  // 3. Deduplicate
  const seen = new Set<string>();
  const deduped = resolved.filter(i => {
    const key = `${i.itemType}:${i.refId}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // 4. Find items that belong to other groups
  const variantRefIds       = deduped.filter(i => i.itemType === "VARIANT").map(i => i.refId);
  const articleSimpleRefIds = deduped.filter(i => i.itemType === "ARTICLE").map(i => i.refId);
  const inOtherGroupVariantIds  = new Set<string>();
  const inOtherGroupArticleIds  = new Set<string>();

  if (variantRefIds.length > 0 || articleSimpleRefIds.length > 0) {
    const orClauses: any[] = [];
    if (variantRefIds.length > 0)       orClauses.push({ variantId:  { in: variantRefIds } });
    if (articleSimpleRefIds.length > 0) orClauses.push({ articleId: { in: articleSimpleRefIds } });
    const otherGroupItems = await prisma.articleGroupItem.findMany({
      where: { groupId: { not: groupId }, OR: orClauses },
      select: { variantId: true, articleId: true },
    });
    for (const i of otherGroupItems) {
      if (i.variantId) inOtherGroupVariantIds.add(i.variantId);
      if (i.articleId) inOtherGroupArticleIds.add(i.articleId);
    }
  }

  // 5. Filter to items that can actually be added
  const toAdd = deduped.filter(item =>
    item.itemType === "VARIANT"
      ? !existingVariantIds.has(item.refId)  && !inOtherGroupVariantIds.has(item.refId)
      : !existingArticleIds.has(item.refId) && !inOtherGroupArticleIds.has(item.refId),
  );
  const skipped = deduped.length - toAdd.length;

  if (toAdd.length === 0) return { added: 0, skipped, items: [] };

  // 6. Create all items in a transaction
  let order = maxCurrentOrder + 1;
  const createData = toAdd.map(item => ({
    groupId,
    jewelryId,
    itemType:           item.itemType,
    ...(item.itemType === "VARIANT" ? { variantId: item.refId } : { articleId: item.refId }),
    groupOrder:         order++,
    groupSelectorValue: item.selectorValue,
  }));

  const createdItems = await prisma.$transaction(
    createData.map(data =>
      prisma.articleGroupItem.create({
        data,
        select: { id: true, groupId: true, groupOrder: true, groupSelectorValue: true, itemType: true },
      }),
    ),
  );

  return { added: createdItems.length, skipped, items: createdItems };
}

// ---------------------------------------------------------------------------
// Direct group assignment from article context (PATCH /articles/:id/group)
// ---------------------------------------------------------------------------
export async function assignGroupToArticle(
  articleId: string,
  groupId: string | null,
  jewelryId: string,
) {
  assert(articleId, "Id de artículo inválido.");

  const article = await prisma.article.findFirst({
    where: { id: articleId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(article, "Artículo no encontrado.", 404);

  const variants = await prisma.articleVariant.findMany({
    where: { articleId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  const hasVariants = variants.length > 0;

  if (groupId === null) {
    if (hasVariants) {
      await prisma.articleGroupItem.deleteMany({
        where: { variantId: { in: variants.map(v => v.id) } },
      });
    } else {
      await prisma.articleGroupItem.deleteMany({ where: { articleId } });
    }
    return { ok: true, groupId: null };
  }

  const group = await prisma.articleGroup.findFirst({
    where: { id: groupId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(group, "Grupo no encontrado.", 404);

  if (hasVariants) {
    const variantIds = variants.map(v => v.id);
    await prisma.articleGroupItem.deleteMany({ where: { variantId: { in: variantIds } } });
    const maxOrder = await prisma.articleGroupItem.aggregate({ where: { groupId }, _max: { groupOrder: true } });
    let order = (maxOrder._max.groupOrder ?? -1) + 1;
    await prisma.$transaction(
      variantIds.map(variantId =>
        prisma.articleGroupItem.create({
          data: { groupId, jewelryId, itemType: "VARIANT", variantId, groupOrder: order++, groupSelectorValue: "" },
        }),
      ),
    );
  } else {
    await prisma.articleGroupItem.deleteMany({ where: { articleId } });
    const maxOrder = await prisma.articleGroupItem.aggregate({ where: { groupId }, _max: { groupOrder: true } });
    const nextOrder = (maxOrder._max.groupOrder ?? -1) + 1;
    await prisma.articleGroupItem.create({
      data: { groupId, jewelryId, itemType: "ARTICLE", articleId, groupOrder: nextOrder, groupSelectorValue: "" },
    });
  }

  return { ok: true, groupId };
}

// ---------------------------------------------------------------------------
// Get per-variant group state for an article (GET /articles/:id/group-state)
// ---------------------------------------------------------------------------
export async function getArticleGroupState(articleId: string, jewelryId: string) {
  assert(articleId, "Id de artículo inválido.");

  const variants = await prisma.articleVariant.findMany({
    where: { articleId, jewelryId, deletedAt: null },
    select: {
      id: true,
      name: true,
      code: true,
      sku: true,
      imageUrl: true,
      isActive: true,
      sortOrder: true,
      groupItems: {
        select: {
          id: true,
          groupId: true,
          group: { select: { id: true, name: true } },
        },
        take: 1,
      },
    },
    orderBy: { sortOrder: "asc" },
  });

  if (variants.length === 0) {
    const item = await prisma.articleGroupItem.findFirst({
      where: { articleId },
      select: { id: true, groupId: true, group: { select: { id: true, name: true } } },
    });
    return {
      hasVariants: false,
      articleItemId:   item?.id            ?? null,
      articleGroupId:  item?.groupId       ?? null,
      articleGroupName: item?.group?.name  ?? null,
      variants: [] as never[],
    };
  }

  return {
    hasVariants: true,
    articleItemId:   null as null,
    articleGroupId:  null as null,
    articleGroupName: null as null,
    variants: variants.map(v => ({
      id:        v.id,
      name:      v.name,
      code:      v.code,
      sku:       v.sku ?? "",
      imageUrl:  v.imageUrl ?? "",
      isActive:  v.isActive,
      itemId:    v.groupItems[0]?.id        ?? null,
      groupId:   v.groupItems[0]?.groupId   ?? null,
      groupName: v.groupItems[0]?.group?.name ?? null,
    })),
  };
}

// ---------------------------------------------------------------------------
// Batch group changes (PATCH /articles/:id/group-batch)
// Each change: { type: "ARTICLE"|"VARIANT"; id: string; groupId: string|null }
// ---------------------------------------------------------------------------
export async function applyArticleGroupBatch(
  articleId: string,
  jewelryId: string,
  changes: Array<{ type: "ARTICLE" | "VARIANT"; id: string; groupId: string | null }>,
) {
  assert(articleId, "Id de artículo inválido.");
  assert(Array.isArray(changes) && changes.length > 0, "La lista de cambios es inválida.");

  for (const change of changes) {
    if (change.type === "ARTICLE") {
      await prisma.articleGroupItem.deleteMany({ where: { articleId: change.id } });
      if (change.groupId !== null) {
        const maxOrder = await prisma.articleGroupItem.aggregate({ where: { groupId: change.groupId }, _max: { groupOrder: true } });
        await prisma.articleGroupItem.create({
          data: { groupId: change.groupId, jewelryId, itemType: "ARTICLE", articleId: change.id, groupOrder: (maxOrder._max.groupOrder ?? -1) + 1, groupSelectorValue: "" },
        });
      }
    } else {
      await prisma.articleGroupItem.deleteMany({ where: { variantId: change.id } });
      if (change.groupId !== null) {
        const maxOrder = await prisma.articleGroupItem.aggregate({ where: { groupId: change.groupId }, _max: { groupOrder: true } });
        await prisma.articleGroupItem.create({
          data: { groupId: change.groupId, jewelryId, itemType: "VARIANT", variantId: change.id, groupOrder: (maxOrder._max.groupOrder ?? -1) + 1, groupSelectorValue: "" },
        });
      }
    }
  }

  return { ok: true };
}
