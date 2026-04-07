// src/modules/promotions/promotions.service.ts
import { prisma } from "../../lib/prisma.js";

function assert(cond: any, msg: string, status = 400) {
  if (!cond) { const e: any = new Error(msg); e.status = status; throw e; }
}

const PROMO_SELECT = {
  id:           true,
  name:         true,
  type:         true,
  value:        true,
  scope:        true,
  validFrom:    true,
  validTo:      true,
  untilStockEnd: true,
  priority:     true,
  isStackable:  true,
  isActive:     true,
  notes:        true,
  deletedAt:    true,
  createdAt:    true,
  updatedAt:    true,
  articles: {
    select: {
      articleId: true,
      article: { select: { id: true, code: true, name: true } },
    },
  },
  variants: {
    select: {
      variantId: true,
      variant: {
        select: {
          id:        true,
          code:      true,
          name:      true,
          articleId: true,
          article:   { select: { id: true, code: true, name: true } },
        },
      },
    },
  },
  categories: {
    select: {
      categoryId: true,
      category: { select: { id: true, name: true } },
    },
  },
  brands: {
    select: { brand: true },
  },
  groups: {
    select: {
      groupId: true,
      group: { select: { id: true, name: true } },
    },
  },
  applyOn: true,
} as const;

export async function listPromotions(
  jewelryId: string,
  opts: { skip?: number; take?: number; q?: string; active?: boolean }
) {
  const skip = opts.skip ?? 0;
  const take = Math.min(opts.take ?? 50, 200);

  const where: any = {
    jewelryId,
    deletedAt: null,
    ...(opts.active !== undefined ? { isActive: opts.active } : {}),
    ...(opts.q ? { name: { contains: opts.q, mode: "insensitive" } } : {}),
  };

  const [data, total] = await Promise.all([
    prisma.promotion.findMany({
      where,
      select: PROMO_SELECT,
      orderBy: [{ priority: "asc" }, { createdAt: "desc" }],
      skip,
      take,
    }),
    prisma.promotion.count({ where }),
  ]);

  return { data, total, skip, take };
}

export async function createPromotion(jewelryId: string, data: any) {
  assert(data.name?.trim(), "El nombre es obligatorio.");
  assert(data.type === "FIXED" || data.type === "PERCENTAGE", "Tipo inválido.");
  assert(data.value != null && Number(data.value) >= 0, "El valor debe ser >= 0.");

  const scope      = data.scope ?? "ALL";
  const articleIds: string[] = data.articleIds  ?? [];
  const variantIds: string[] = data.variantIds  ?? [];
  const categoryIds: string[]= data.categoryIds ?? [];
  const brands: string[]     = data.brands      ?? [];
  const groupIds: string[]   = data.groupIds    ?? [];

  return prisma.$transaction(async (tx) => {
    const promo = await tx.promotion.create({
      data: {
        jewelryId,
        name:          data.name.trim(),
        type:          data.type,
        value:         data.value,
        scope,
        applyOn:       data.applyOn ?? "TOTAL",
        validFrom:     data.validFrom  ? new Date(data.validFrom) : null,
        validTo:       data.validTo    ? new Date(data.validTo)   : null,
        untilStockEnd: !!data.untilStockEnd,
        priority:      Number(data.priority ?? 0),
        isStackable:   data.isStackable !== false,
        isActive:      data.isActive !== false,
        notes:         data.notes ?? "",
      },
    });

    if (articleIds.length > 0) {
      await tx.promotionArticle.createMany({
        data: articleIds.map((articleId) => ({ promotionId: promo.id, articleId, jewelryId })),
        skipDuplicates: true,
      });
    }
    if (variantIds.length > 0) {
      await tx.promotionVariant.createMany({
        data: variantIds.map((variantId) => ({ promotionId: promo.id, variantId, jewelryId })),
        skipDuplicates: true,
      });
    }
    if (categoryIds.length > 0) {
      await tx.promotionCategory.createMany({
        data: categoryIds.map((categoryId) => ({ promotionId: promo.id, categoryId, jewelryId })),
        skipDuplicates: true,
      });
    }
    if (brands.length > 0) {
      await tx.promotionBrand.createMany({
        data: brands.map((brand) => ({ promotionId: promo.id, brand, jewelryId })),
        skipDuplicates: true,
      });
    }
    if (groupIds.length > 0) {
      await tx.promotionGroup.createMany({
        data: groupIds.map((groupId) => ({ promotionId: promo.id, groupId, jewelryId })),
        skipDuplicates: true,
      });
    }

    return tx.promotion.findUniqueOrThrow({ where: { id: promo.id }, select: PROMO_SELECT });
  });
}

export async function updatePromotion(id: string, jewelryId: string, data: any) {
  const existing = await prisma.promotion.findFirst({ where: { id, jewelryId, deletedAt: null } });
  assert(existing, "Promoción no encontrada.", 404);

  return prisma.$transaction(async (tx) => {
    await tx.promotion.update({
      where: { id },
      data: {
        ...(data.name         !== undefined ? { name:          data.name.trim()          } : {}),
        ...(data.type         !== undefined ? { type:          data.type                 } : {}),
        ...(data.value        !== undefined ? { value:         data.value                } : {}),
        ...(data.scope        !== undefined ? { scope:         data.scope                } : {}),
        ...(data.validFrom    !== undefined ? { validFrom:     data.validFrom ? new Date(data.validFrom) : null } : {}),
        ...(data.validTo      !== undefined ? { validTo:       data.validTo   ? new Date(data.validTo)   : null } : {}),
        ...(data.untilStockEnd !== undefined ? { untilStockEnd: !!data.untilStockEnd      } : {}),
        ...(data.priority     !== undefined ? { priority:      Number(data.priority)     } : {}),
        ...(data.isStackable  !== undefined ? { isStackable:   !!data.isStackable        } : {}),
        ...(data.isActive     !== undefined ? { isActive:      !!data.isActive           } : {}),
        ...(data.notes        !== undefined ? { notes:         data.notes                } : {}),
      },
    });

    // Si se envían datos de alcance, reemplazar todas las tablas junction
    const hasJunctionUpdate =
      data.scope       !== undefined ||
      data.articleIds  !== undefined ||
      data.variantIds  !== undefined ||
      data.categoryIds !== undefined ||
      data.brands      !== undefined ||
      data.groupIds    !== undefined;

    if (hasJunctionUpdate) {
      await tx.promotionArticle.deleteMany({ where: { promotionId: id } });
      await tx.promotionVariant.deleteMany({ where: { promotionId: id } });
      await tx.promotionCategory.deleteMany({ where: { promotionId: id } });
      await tx.promotionBrand.deleteMany({ where: { promotionId: id } });
      await tx.promotionGroup.deleteMany({ where: { promotionId: id } });

      const articleIds: string[]  = data.articleIds  ?? [];
      const variantIds: string[]  = data.variantIds  ?? [];
      const categoryIds: string[] = data.categoryIds ?? [];
      const brands: string[]      = data.brands      ?? [];
      const groupIds: string[]    = data.groupIds    ?? [];

      if (articleIds.length > 0) {
        await tx.promotionArticle.createMany({
          data: articleIds.map((articleId) => ({ promotionId: id, articleId, jewelryId })),
          skipDuplicates: true,
        });
      }
      if (variantIds.length > 0) {
        await tx.promotionVariant.createMany({
          data: variantIds.map((variantId) => ({ promotionId: id, variantId, jewelryId })),
          skipDuplicates: true,
        });
      }
      if (categoryIds.length > 0) {
        await tx.promotionCategory.createMany({
          data: categoryIds.map((categoryId) => ({ promotionId: id, categoryId, jewelryId })),
          skipDuplicates: true,
        });
      }
      if (brands.length > 0) {
        await tx.promotionBrand.createMany({
          data: brands.map((brand) => ({ promotionId: id, brand, jewelryId })),
          skipDuplicates: true,
        });
      }
      if (groupIds.length > 0) {
        await tx.promotionGroup.createMany({
          data: groupIds.map((groupId) => ({ promotionId: id, groupId, jewelryId })),
          skipDuplicates: true,
        });
      }
    }

    return tx.promotion.findUniqueOrThrow({ where: { id }, select: PROMO_SELECT });
  });
}

export async function deletePromotion(id: string, jewelryId: string) {
  const existing = await prisma.promotion.findFirst({ where: { id, jewelryId, deletedAt: null } });
  assert(existing, "Promoción no encontrada.", 404);
  await prisma.promotion.update({ where: { id }, data: { deletedAt: new Date(), isActive: false } });
}
