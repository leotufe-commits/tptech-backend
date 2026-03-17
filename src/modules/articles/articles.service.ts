import { prisma } from "../../lib/prisma.js";

function s(v: any): string { return String(v ?? "").trim(); }
function assert(cond: any, msg: string, status = 400): void {
  if (!cond) { const e: any = new Error(msg); e.status = status; throw e; }
}

// ===========================================================================
// Code generation — ART-NNNN, unique per tenant
// ===========================================================================
async function generateArticleCode(jewelryId: string): Promise<string> {
  const count = await prisma.article.count({ where: { jewelryId } });
  let n = count + 1;
  while (true) {
    const candidate = `ART-${String(n).padStart(4, "0")}`;
    const exists = await prisma.article.findFirst({
      where: { jewelryId, code: candidate },
      select: { id: true },
    });
    if (!exists) return candidate;
    n++;
  }
}

// ===========================================================================
// Selects
// ===========================================================================
const ARTICLE_LIST_SELECT = {
  id: true,
  code: true,
  name: true,
  description: true,
  categoryId: true,
  status: true,
  stockMode: true,
  hechuraPrice: true,
  hechuraPriceMode: true,
  mermaPercent: true,
  mainImageUrl: true,
  isFavorite: true,
  isActive: true,
  createdAt: true,
  updatedAt: true,
  category: { select: { id: true, name: true } },
} as const;

const ARTICLE_DETAIL_SELECT = {
  id: true,
  jewelryId: true,
  code: true,
  name: true,
  description: true,
  categoryId: true,
  status: true,
  stockMode: true,
  hechuraPrice: true,
  hechuraPriceMode: true,
  mermaPercent: true,
  mainImageUrl: true,
  isFavorite: true,
  isActive: true,
  notes: true,
  createdAt: true,
  updatedAt: true,
  category: { select: { id: true, name: true } },
  compositions: {
    select: {
      id: true,
      variantId: true,
      grams: true,
      isBase: true,
      sortOrder: true,
      metalVariant: { select: { id: true, name: true, sku: true, purity: true, metal: { select: { id: true, name: true } } } },
    },
    orderBy: [{ sortOrder: "asc" as const }, { createdAt: "asc" as const }],
  },
  variants: {
    where: { deletedAt: null },
    select: {
      id: true,
      code: true,
      name: true,
      weightOverride: true,
      hechuraPriceOverride: true,
      priceOverride: true,
      imageUrl: true,
      isActive: true,
      sortOrder: true,
    },
    orderBy: [{ sortOrder: "asc" as const }, { createdAt: "asc" as const }],
  },
  attributeValues: {
    select: {
      id: true,
      assignmentId: true,
      value: true,
      assignment: {
        select: {
          id: true,
          isRequired: true,
          sortOrder: true,
          definition: { select: { id: true, name: true, code: true, inputType: true, options: { select: { id: true, label: true, value: true } } } },
        },
      },
    },
  },
  images: {
    select: { id: true, url: true, label: true, isMain: true, sortOrder: true },
    orderBy: [{ sortOrder: "asc" as const }, { createdAt: "asc" as const }],
  },
} as const;

// ===========================================================================
// Helpers
// ===========================================================================
async function assertArticleOwnership(articleId: string, jewelryId: string) {
  const a = await prisma.article.findFirst({
    where: { id: articleId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(a, "Artículo no encontrado.", 404);
}

// ===========================================================================
// List
// ===========================================================================
export async function listArticles(
  jewelryId: string,
  opts: {
    q?: string;
    categoryId?: string;
    status?: string;
    stockMode?: string;
    isFavorite?: boolean;
    showInactive?: boolean;
    skip?: number;
    take?: number;
  }
) {
  const { q, categoryId, status, stockMode, isFavorite, showInactive, skip = 0, take = 50 } = opts;

  const where: any = { jewelryId, deletedAt: null };
  if (!showInactive) where.isActive = true;
  if (categoryId) where.categoryId = categoryId;
  if (status && ["DRAFT", "ACTIVE", "DISCONTINUED", "ARCHIVED"].includes(status)) where.status = status;
  if (stockMode && ["NO_STOCK", "BY_ARTICLE", "BY_MATERIAL"].includes(stockMode)) where.stockMode = stockMode;
  if (isFavorite === true) where.isFavorite = true;
  if (q) {
    where.OR = [
      { name: { contains: q, mode: "insensitive" } },
      { code: { contains: q, mode: "insensitive" } },
      { description: { contains: q, mode: "insensitive" } },
    ];
  }

  const [rows, total] = await Promise.all([
    prisma.article.findMany({ where, select: ARTICLE_LIST_SELECT, orderBy: { name: "asc" }, skip, take }),
    prisma.article.count({ where }),
  ]);

  return { rows, total, skip, take };
}

// ===========================================================================
// Get one
// ===========================================================================
export async function getArticle(articleId: string, jewelryId: string) {
  const article = await prisma.article.findFirst({
    where: { id: articleId, jewelryId, deletedAt: null },
    select: ARTICLE_DETAIL_SELECT as any,
  });
  assert(article, "Artículo no encontrado.", 404);
  return article;
}

// ===========================================================================
// Create
// ===========================================================================
export async function createArticle(jewelryId: string, data: any) {
  assert(s(data?.name), "El nombre del artículo es obligatorio.");

  const code = s(data?.code) || await generateArticleCode(jewelryId);

  // Validate code uniqueness
  const codeExists = await prisma.article.findFirst({
    where: { jewelryId, code },
    select: { id: true },
  });
  assert(!codeExists, "Ya existe un artículo con ese código.");

  // Validate categoryId if provided
  if (data?.categoryId) {
    const cat = await prisma.articleCategory.findFirst({
      where: { id: data.categoryId, jewelryId, deletedAt: null },
      select: { id: true },
    });
    assert(cat, "Categoría no encontrada.");
  }

  const VALID_STATUS = new Set(["DRAFT", "ACTIVE", "DISCONTINUED", "ARCHIVED"]);
  const VALID_STOCK_MODE = new Set(["NO_STOCK", "BY_ARTICLE", "BY_MATERIAL"]);
  const VALID_HECHURA_MODE = new Set(["FIXED", "PER_GRAM"]);

  return prisma.article.create({
    data: {
      jewelryId,
      code,
      name: s(data.name),
      description: s(data?.description),
      categoryId: data?.categoryId || null,
      status: VALID_STATUS.has(data?.status) ? data.status : "DRAFT",
      stockMode: VALID_STOCK_MODE.has(data?.stockMode) ? data.stockMode : "NO_STOCK",
      hechuraPrice: data?.hechuraPrice != null ? data.hechuraPrice : null,
      hechuraPriceMode: VALID_HECHURA_MODE.has(data?.hechuraPriceMode) ? data.hechuraPriceMode : "FIXED",
      mermaPercent: data?.mermaPercent != null ? data.mermaPercent : null,
      isFavorite: !!data?.isFavorite,
      notes: s(data?.notes),
    },
    select: ARTICLE_DETAIL_SELECT as any,
  });
}

// ===========================================================================
// Update (base fields)
// ===========================================================================
export async function updateArticle(articleId: string, jewelryId: string, data: any) {
  await assertArticleOwnership(articleId, jewelryId);
  assert(s(data?.name), "El nombre del artículo es obligatorio.");

  const VALID_STATUS = new Set(["DRAFT", "ACTIVE", "DISCONTINUED", "ARCHIVED"]);
  const VALID_STOCK_MODE = new Set(["NO_STOCK", "BY_ARTICLE", "BY_MATERIAL"]);
  const VALID_HECHURA_MODE = new Set(["FIXED", "PER_GRAM"]);

  // Code change: validate uniqueness if different
  if (data?.code) {
    const newCode = s(data.code);
    const conflict = await prisma.article.findFirst({
      where: { jewelryId, code: newCode, id: { not: articleId } },
      select: { id: true },
    });
    assert(!conflict, "Ya existe un artículo con ese código.");
  }

  if (data?.categoryId) {
    const cat = await prisma.articleCategory.findFirst({
      where: { id: data.categoryId, jewelryId, deletedAt: null },
      select: { id: true },
    });
    assert(cat, "Categoría no encontrada.");
  }

  return prisma.article.update({
    where: { id: articleId },
    data: {
      ...(data?.code ? { code: s(data.code) } : {}),
      name: s(data.name),
      description: s(data?.description),
      categoryId: data?.categoryId !== undefined ? (data.categoryId || null) : undefined,
      status: VALID_STATUS.has(data?.status) ? data.status : undefined,
      stockMode: VALID_STOCK_MODE.has(data?.stockMode) ? data.stockMode : undefined,
      hechuraPrice: data?.hechuraPrice !== undefined ? (data.hechuraPrice ?? null) : undefined,
      hechuraPriceMode: VALID_HECHURA_MODE.has(data?.hechuraPriceMode) ? data.hechuraPriceMode : undefined,
      mermaPercent: data?.mermaPercent !== undefined ? (data.mermaPercent ?? null) : undefined,
      isFavorite: data?.isFavorite !== undefined ? !!data.isFavorite : undefined,
      notes: data?.notes !== undefined ? s(data.notes) : undefined,
    },
    select: ARTICLE_DETAIL_SELECT as any,
  });
}

// ===========================================================================
// Toggle active
// ===========================================================================
export async function toggleArticle(articleId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  const article = await prisma.article.findUnique({ where: { id: articleId }, select: { isActive: true } });
  return prisma.article.update({
    where: { id: articleId },
    data: { isActive: !article!.isActive },
    select: ARTICLE_LIST_SELECT,
  });
}

// ===========================================================================
// Toggle favorite
// ===========================================================================
export async function toggleFavorite(articleId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  const article = await prisma.article.findUnique({ where: { id: articleId }, select: { isFavorite: true } });
  return prisma.article.update({
    where: { id: articleId },
    data: { isFavorite: !article!.isFavorite },
    select: { id: true, isFavorite: true },
  });
}

// ===========================================================================
// Soft delete
// ===========================================================================
export async function deleteArticle(articleId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  await prisma.article.update({
    where: { id: articleId },
    data: { deletedAt: new Date(), isActive: false },
  });
  return { id: articleId };
}

// ===========================================================================
// Compositions
// ===========================================================================
const COMPOSITION_SELECT = {
  id: true,
  variantId: true,
  grams: true,
  isBase: true,
  sortOrder: true,
  createdAt: true,
  metalVariant: { select: { id: true, name: true, sku: true, purity: true, metal: { select: { id: true, name: true } } } },
} as const;

export async function listCompositions(articleId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  return prisma.articleMetalComposition.findMany({
    where: { articleId },
    select: COMPOSITION_SELECT,
    orderBy: [{ sortOrder: "asc" as const }, { createdAt: "asc" as const }],
  });
}

export async function upsertComposition(articleId: string, jewelryId: string, data: any) {
  await assertArticleOwnership(articleId, jewelryId);

  const variantId = s(data?.variantId);
  assert(variantId, "variantId es obligatorio.");
  assert(data?.grams != null, "grams es obligatorio.");

  // Verify metal variant exists
  const variant = await prisma.metalVariant.findFirst({
    where: { id: variantId, deletedAt: null },
    select: { id: true },
  });
  assert(variant, "Variante de metal no encontrada.");

  const isBase = !!data?.isBase;

  // If isBase=true, unset other isBase in transaction
  return prisma.$transaction(async (tx) => {
    if (isBase) {
      await tx.articleMetalComposition.updateMany({
        where: { articleId, id: { not: undefined } },
        data: { isBase: false },
      });
    }
    return tx.articleMetalComposition.upsert({
      where: { articleId_variantId: { articleId, variantId } },
      create: {
        articleId,
        jewelryId,
        variantId,
        grams: data.grams,
        isBase,
        sortOrder: typeof data?.sortOrder === "number" ? data.sortOrder : 0,
      },
      update: {
        grams: data.grams,
        isBase,
        sortOrder: typeof data?.sortOrder === "number" ? data.sortOrder : undefined,
      },
      select: COMPOSITION_SELECT,
    });
  });
}

export async function removeComposition(articleId: string, compositionId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  const comp = await prisma.articleMetalComposition.findFirst({
    where: { id: compositionId, articleId },
    select: { id: true },
  });
  assert(comp, "Composición no encontrada.");
  await prisma.articleMetalComposition.delete({ where: { id: compositionId } });
  return { id: compositionId };
}

// ===========================================================================
// Variants
// ===========================================================================
const VARIANT_SELECT = {
  id: true,
  code: true,
  name: true,
  weightOverride: true,
  hechuraPriceOverride: true,
  priceOverride: true,
  imageUrl: true,
  isActive: true,
  sortOrder: true,
  createdAt: true,
} as const;

export async function listVariants(articleId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  return prisma.articleVariant.findMany({
    where: { articleId, deletedAt: null },
    select: VARIANT_SELECT,
    orderBy: [{ sortOrder: "asc" as const }, { createdAt: "asc" as const }],
  });
}

export async function createVariant(articleId: string, jewelryId: string, data: any) {
  await assertArticleOwnership(articleId, jewelryId);
  const code = s(data?.code);
  assert(code, "El código de variante es obligatorio.");
  assert(s(data?.name), "El nombre de variante es obligatorio.");

  const conflict = await prisma.articleVariant.findFirst({
    where: { articleId, code, deletedAt: null },
    select: { id: true },
  });
  assert(!conflict, "Ya existe una variante con ese código en este artículo.");

  return prisma.articleVariant.create({
    data: {
      articleId,
      jewelryId,
      code,
      name: s(data.name),
      weightOverride: data?.weightOverride != null ? data.weightOverride : null,
      hechuraPriceOverride: data?.hechuraPriceOverride != null ? data.hechuraPriceOverride : null,
      priceOverride: data?.priceOverride != null ? data.priceOverride : null,
      sortOrder: typeof data?.sortOrder === "number" ? data.sortOrder : 0,
    },
    select: VARIANT_SELECT,
  });
}

export async function updateVariant(articleId: string, variantId: string, jewelryId: string, data: any) {
  await assertArticleOwnership(articleId, jewelryId);
  const variant = await prisma.articleVariant.findFirst({
    where: { id: variantId, articleId, deletedAt: null },
    select: { id: true },
  });
  assert(variant, "Variante no encontrada.");

  if (data?.code) {
    const code = s(data.code);
    const conflict = await prisma.articleVariant.findFirst({
      where: { articleId, code, deletedAt: null, id: { not: variantId } },
      select: { id: true },
    });
    assert(!conflict, "Ya existe una variante con ese código en este artículo.");
  }

  return prisma.articleVariant.update({
    where: { id: variantId },
    data: {
      ...(data?.code ? { code: s(data.code) } : {}),
      ...(data?.name ? { name: s(data.name) } : {}),
      weightOverride: data?.weightOverride !== undefined ? (data.weightOverride ?? null) : undefined,
      hechuraPriceOverride: data?.hechuraPriceOverride !== undefined ? (data.hechuraPriceOverride ?? null) : undefined,
      priceOverride: data?.priceOverride !== undefined ? (data.priceOverride ?? null) : undefined,
      ...(typeof data?.sortOrder === "number" ? { sortOrder: data.sortOrder } : {}),
    },
    select: VARIANT_SELECT,
  });
}

export async function toggleVariant(articleId: string, variantId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  const variant = await prisma.articleVariant.findFirst({
    where: { id: variantId, articleId, deletedAt: null },
    select: { id: true, isActive: true },
  });
  assert(variant, "Variante no encontrada.");
  return prisma.articleVariant.update({
    where: { id: variantId },
    data: { isActive: !variant!.isActive },
    select: VARIANT_SELECT,
  });
}

export async function removeVariant(articleId: string, variantId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  const variant = await prisma.articleVariant.findFirst({
    where: { id: variantId, articleId, deletedAt: null },
    select: { id: true },
  });
  assert(variant, "Variante no encontrada.");
  await prisma.articleVariant.update({
    where: { id: variantId },
    data: { deletedAt: new Date(), isActive: false },
  });
  return { id: variantId };
}

// ===========================================================================
// Attribute values (bulk set — replaces all for this article)
// ===========================================================================
export async function setAttributeValues(articleId: string, jewelryId: string, values: { assignmentId: string; value: string }[]) {
  await assertArticleOwnership(articleId, jewelryId);
  assert(Array.isArray(values), "values debe ser un array.");

  // Validate that all assignmentIds belong to the article's category (effective attributes)
  await prisma.$transaction(
    values.map(({ assignmentId, value }) =>
      prisma.articleAttributeValue.upsert({
        where: { articleId_assignmentId: { articleId, assignmentId } },
        create: { articleId, jewelryId, assignmentId, value: s(value) },
        update: { value: s(value) },
      })
    )
  );

  return prisma.articleAttributeValue.findMany({
    where: { articleId },
    select: {
      id: true,
      assignmentId: true,
      value: true,
      assignment: {
        select: {
          id: true,
          isRequired: true,
          sortOrder: true,
          definition: { select: { id: true, name: true, code: true, inputType: true, options: { select: { id: true, label: true, value: true } } } },
        },
      },
    },
    orderBy: { assignment: { sortOrder: "asc" as const } },
  });
}

// ===========================================================================
// Images
// ===========================================================================
const IMAGE_SELECT = { id: true, url: true, label: true, isMain: true, sortOrder: true } as const;

export async function addImage(articleId: string, jewelryId: string, data: { url: string; label?: string; isMain?: boolean }) {
  await assertArticleOwnership(articleId, jewelryId);
  assert(s(data?.url), "URL de imagen requerida.");

  const isMain = !!data?.isMain;

  return prisma.$transaction(async (tx) => {
    // Only one image can be main
    if (isMain) {
      await tx.articleImage.updateMany({ where: { articleId }, data: { isMain: false } });
      await tx.article.update({ where: { id: articleId }, data: { mainImageUrl: data.url } });
    }
    // If first image, auto-set as main
    const existingCount = await tx.articleImage.count({ where: { articleId } });
    const autoMain = existingCount === 0;
    if (autoMain && !isMain) {
      await tx.article.update({ where: { id: articleId }, data: { mainImageUrl: data.url } });
    }
    return tx.articleImage.create({
      data: {
        articleId,
        jewelryId,
        url: data.url,
        label: s(data?.label),
        isMain: isMain || autoMain,
        sortOrder: 0,
      },
      select: IMAGE_SELECT,
    });
  });
}

export async function setMainImage(articleId: string, imageId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  const image = await prisma.articleImage.findFirst({ where: { id: imageId, articleId }, select: { id: true, url: true } });
  assert(image, "Imagen no encontrada.");

  return prisma.$transaction(async (tx) => {
    await tx.articleImage.updateMany({ where: { articleId }, data: { isMain: false } });
    await tx.article.update({ where: { id: articleId }, data: { mainImageUrl: image!.url } });
    return tx.articleImage.update({ where: { id: imageId }, data: { isMain: true }, select: IMAGE_SELECT });
  });
}

export async function updateImageLabel(articleId: string, imageId: string, jewelryId: string, label: string) {
  await assertArticleOwnership(articleId, jewelryId);
  const image = await prisma.articleImage.findFirst({ where: { id: imageId, articleId }, select: { id: true } });
  assert(image, "Imagen no encontrada.");
  return prisma.articleImage.update({ where: { id: imageId }, data: { label: s(label) }, select: IMAGE_SELECT });
}

export async function removeImage(articleId: string, imageId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  const image = await prisma.articleImage.findFirst({ where: { id: imageId, articleId }, select: { id: true, isMain: true, url: true } });
  assert(image, "Imagen no encontrada.");

  return prisma.$transaction(async (tx) => {
    await tx.articleImage.delete({ where: { id: imageId } });
    // If removed image was main, promote next image
    if (image!.isMain) {
      const next = await tx.articleImage.findFirst({ where: { articleId }, orderBy: { sortOrder: "asc" } });
      if (next) {
        await tx.articleImage.update({ where: { id: next.id }, data: { isMain: true } });
        await tx.article.update({ where: { id: articleId }, data: { mainImageUrl: next.url } });
      } else {
        await tx.article.update({ where: { id: articleId }, data: { mainImageUrl: "" } });
      }
    }
    return { id: imageId };
  });
}

// ===========================================================================
// Stock (BY_ARTICLE only — read + adjust)
// ===========================================================================
const STOCK_SELECT = {
  id: true,
  variantId: true,
  warehouseId: true,
  quantity: true,
  updatedAt: true,
  variant: { select: { id: true, code: true, name: true } },
  warehouse: { select: { id: true, name: true, code: true } },
} as const;

export async function getStock(articleId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  return prisma.articleStock.findMany({
    where: { articleId, jewelryId },
    select: STOCK_SELECT,
    orderBy: { warehouse: { name: "asc" as const } },
  });
}

export async function adjustStock(
  articleId: string,
  jewelryId: string,
  data: { warehouseId: string; variantId?: string | null; quantity: number }
) {
  await assertArticleOwnership(articleId, jewelryId);

  const article = await prisma.article.findUnique({ where: { id: articleId }, select: { stockMode: true } });
  assert(article?.stockMode === "BY_ARTICLE", "Este artículo no tiene modo de stock BY_ARTICLE.");
  assert(data?.warehouseId, "warehouseId es obligatorio.");
  assert(data?.quantity != null, "quantity es obligatoria.");

  const warehouse = await prisma.warehouse.findFirst({
    where: { id: data.warehouseId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(warehouse, "Almacén no encontrado.");

  const variantId = data?.variantId ?? null;

  return prisma.articleStock.upsert({
    where: {
      jewelryId_warehouseId_articleId_variantId: {
        jewelryId,
        warehouseId: data.warehouseId,
        articleId,
        variantId: variantId as string,
      },
    },
    create: {
      articleId,
      variantId,
      warehouseId: data.warehouseId,
      jewelryId,
      quantity: data.quantity,
    },
    update: { quantity: data.quantity },
    select: STOCK_SELECT,
  });
}
