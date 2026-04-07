// src/modules/quantity-discounts/quantity-discounts.service.ts
import { prisma } from "../../lib/prisma.js";

function assert(cond: any, msg: string, status = 400) {
  if (!cond) { const e: any = new Error(msg); e.status = status; throw e; }
}

function validateTiers(tiers: any[]) {
  assert(Array.isArray(tiers) && tiers.length > 0, "Debe haber al menos un tramo.");
  for (const t of tiers) {
    assert(t.minQty != null && Number(t.minQty) > 0, "La cantidad mínima de cada tramo debe ser > 0.");
    assert(t.type === "FIXED" || t.type === "PERCENTAGE", "Tipo inválido en tramo.");
    assert(t.value != null && Number(t.value) >= 0, "El valor de cada tramo debe ser >= 0.");
  }
  const qtys = tiers.map((t: any) => Number(t.minQty));
  assert(new Set(qtys).size === qtys.length, "No puede haber cantidades mínimas duplicadas en los tramos.");
}

const QD_SELECT = {
  id:             true,
  articleId:      true,
  variantId:      true,
  categoryId:     true,
  brand:          true,
  groupId:        true,
  isActive:       true,
  isStackable:    true,
  evaluationMode: true,
  applyOn:        true,
  sortOrder:      true,
  deletedAt:      true,
  createdAt:      true,
  updatedAt:      true,
  article:  { select: { id: true, code: true, name: true } },
  variant:  { select: { id: true, code: true, name: true } },
  category: { select: { id: true, name: true } },
  group:    { select: { id: true, name: true } },
  tiers:    { select: { id: true, minQty: true, type: true, value: true }, orderBy: { minQty: "asc" as const } },
} as const;

export async function listQuantityDiscounts(
  jewelryId: string,
  opts: { skip?: number; take?: number; articleId?: string }
) {
  const skip = opts.skip ?? 0;
  const take = Math.min(opts.take ?? 100, 500);

  const where: any = {
    jewelryId,
    deletedAt: null,
    ...(opts.articleId ? { articleId: opts.articleId } : {}),
  };

  const [data, total] = await Promise.all([
    prisma.quantityDiscount.findMany({ where, select: QD_SELECT, orderBy: [{ sortOrder: "asc" }, { createdAt: "asc" }], skip, take }),
    prisma.quantityDiscount.count({ where }),
  ]);

  return { data, total, skip, take };
}

export async function createQuantityDiscount(jewelryId: string, data: any) {
  validateTiers(data.tiers ?? []);

  return prisma.quantityDiscount.create({
    data: {
      jewelryId,
      articleId:      data.articleId      || null,
      variantId:      data.variantId      || null,
      categoryId:     data.categoryId     || null,
      brand:          data.brand          || null,
      groupId:        data.groupId        || null,
      isActive:       data.isActive !== false,
      isStackable:    data.isStackable !== false,
      evaluationMode: data.evaluationMode || "LINE",
      applyOn:        data.applyOn        || "TOTAL",
      sortOrder:      Number(data.sortOrder ?? 0),
      tiers: {
        create: (data.tiers as any[]).map((t: any) => ({
          minQty: t.minQty,
          type:   t.type,
          value:  t.value,
        })),
      },
    },
    select: QD_SELECT,
  });
}

export async function updateQuantityDiscount(id: string, jewelryId: string, data: any) {
  const existing = await prisma.quantityDiscount.findFirst({ where: { id, jewelryId, deletedAt: null } });
  assert(existing, "Descuento no encontrado.", 404);

  if (data.tiers !== undefined) {
    validateTiers(data.tiers);
  }

  return prisma.quantityDiscount.update({
    where: { id },
    data: {
      ...(data.articleId  !== undefined ? { articleId:  data.articleId  || null } : {}),
      ...(data.variantId  !== undefined ? { variantId:  data.variantId  || null } : {}),
      ...(data.categoryId !== undefined ? { categoryId: data.categoryId || null } : {}),
      ...(data.brand      !== undefined ? { brand:      data.brand      || null } : {}),
      ...(data.groupId    !== undefined ? { groupId:    data.groupId    || null } : {}),
      ...(data.isActive       !== undefined ? { isActive:       !!data.isActive }              : {}),
      ...(data.isStackable    !== undefined ? { isStackable:    !!data.isStackable }           : {}),
      ...(data.evaluationMode !== undefined ? { evaluationMode: data.evaluationMode || "LINE" } : {}),
      ...(data.applyOn        !== undefined ? { applyOn:        data.applyOn        || "TOTAL" } : {}),
      ...(data.sortOrder      !== undefined ? { sortOrder:      Number(data.sortOrder) }       : {}),
      ...(data.tiers !== undefined ? {
        tiers: {
          deleteMany: {},
          create: (data.tiers as any[]).map((t: any) => ({
            minQty: t.minQty,
            type:   t.type,
            value:  t.value,
          })),
        },
      } : {}),
    },
    select: QD_SELECT,
  });
}

export async function deleteQuantityDiscount(id: string, jewelryId: string) {
  const existing = await prisma.quantityDiscount.findFirst({ where: { id, jewelryId, deletedAt: null } });
  assert(existing, "Descuento no encontrado.", 404);
  await prisma.quantityDiscount.update({ where: { id }, data: { deletedAt: new Date(), isActive: false } });
}
