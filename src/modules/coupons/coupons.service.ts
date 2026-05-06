import { prisma } from "../../lib/prisma.js";
import type { CouponDiscountType, CouponScope } from "@prisma/client";
import { validateMetalVariantIds } from "../../lib/metal-scope-validator.js";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string, status = 400): asserts cond {
  if (!cond) { const e: any = new Error(msg); e.status = status; throw e; }
}

function isPriceListValidNow(validFrom: Date | null, validTo: Date | null): boolean {
  const now = new Date();
  if (validFrom && now < validFrom) return false;
  if (validTo   && now > validTo)   return false;
  return true;
}

const VALID_DISCOUNT_TYPES: CouponDiscountType[] = ["PERCENTAGE", "FIXED_AMOUNT"];
const VALID_SCOPES: CouponScope[] = ["ALL", "CLIENT", "CATEGORY", "ARTICLE", "GROUP", "BRAND", "METALS"];

const COUPON_SELECT = {
  id: true, jewelryId: true, name: true, code: true, description: true,
  discountType: true, discountValue: true,
  validFrom: true, validTo: true,
  maxUsesTotal: true, maxUsesPerClient: true,
  applyScope: true, isActive: true, notes: true,
  deletedAt: true, createdAt: true, updatedAt: true,
  articles:   { select: { articleId: true, article: { select: { id: true, code: true, name: true } } } },
  variants:   { select: { variantId: true, variant: { select: { id: true, code: true, name: true, articleId: true, article: { select: { id: true, name: true } } } } } },
  categories: { select: { categoryId: true, category: { select: { id: true, name: true } } } },
  groups:     { select: { groupId: true,   group:    { select: { id: true, name: true } } } },
  clients:    { select: { clientId: true,  client:   { select: { id: true, displayName: true, code: true } } } },
  brands:     { select: { brandName: true } },
  metalVariants: {
    select: {
      metalVariantId: true,
      metalVariant: { select: { id: true, name: true, sku: true, purity: true } },
    },
  },
  _count:     { select: { redemptions: true } },
} as const;

export async function listCoupons(jewelryId: string, opts: { skip?: number; take?: number; q?: string; active?: boolean }) {
  assert(jewelryId, "Tenant inválido.");
  const skip = opts.skip ?? 0;
  const take = Math.min(opts.take ?? 50, 200);
  const where: any = {
    jewelryId, deletedAt: null,
    ...(opts.active !== undefined ? { isActive: opts.active } : {}),
    ...(opts.q ? { OR: [
      { name: { contains: opts.q, mode: "insensitive" } },
      { code: { contains: opts.q, mode: "insensitive" } },
    ] } : {}),
  };
  const [data, total] = await Promise.all([
    prisma.coupon.findMany({ where, select: COUPON_SELECT, orderBy: [{ createdAt: "desc" }], skip, take }),
    prisma.coupon.count({ where }),
  ]);
  return { data, total, skip, take };
}

export async function getCoupon(id: string, jewelryId: string) {
  assert(id && jewelryId, "Parámetros inválidos.");
  const coupon = await prisma.coupon.findFirst({ where: { id, jewelryId, deletedAt: null }, select: COUPON_SELECT });
  assert(coupon, "Cupón no encontrado.", 404);
  return coupon;
}

export async function createCoupon(jewelryId: string, data: any) {
  assert(jewelryId, "Tenant inválido.");
  const name = s(data?.name);
  assert(name, "El nombre es obligatorio.");

  const code = s(data?.code).toUpperCase();
  assert(code, "El código es obligatorio.");

  const discountType: CouponDiscountType = VALID_DISCOUNT_TYPES.includes(data?.discountType) ? data.discountType : "PERCENTAGE";
  const discountValue = parseFloat(String(data?.discountValue ?? 0));
  assert(Number.isFinite(discountValue) && discountValue > 0, "El valor de descuento debe ser mayor a 0.");

  const applyScope: CouponScope = VALID_SCOPES.includes(data?.applyScope) ? data.applyScope : "ALL";

  // Validación temprana del scope METALS: si la lista es inválida, falla
  // antes de tocar DB. El array validado se reinyecta en `data` para que
  // syncScopeRelations lo use sin volver a validar.
  if (applyScope === "METALS") {
    data.metalVariantIds = await validateMetalVariantIds(jewelryId, data?.metalVariantIds);
  }

  // Verificar unicidad de code por jewelryId
  const existing = await prisma.coupon.findFirst({ where: { jewelryId, code, deletedAt: null }, select: { id: true } });
  assert(!existing, `El código "${code}" ya existe para este tenant.`);

  const created = await prisma.coupon.create({
    data: {
      jewelryId, name, code,
      description:     s(data?.description),
      discountType,
      discountValue:   String(discountValue),
      validFrom:       data?.validFrom ? new Date(data.validFrom) : null,
      validTo:         data?.validTo   ? new Date(data.validTo)   : null,
      maxUsesTotal:    data?.maxUsesTotal    != null ? parseInt(String(data.maxUsesTotal),    10) : null,
      maxUsesPerClient: data?.maxUsesPerClient != null ? parseInt(String(data.maxUsesPerClient), 10) : null,
      applyScope,
      isActive: true,
      notes: s(data?.notes),
    },
    select: COUPON_SELECT,
  });

  // Crear relaciones de alcance
  await syncScopeRelations(created.id, jewelryId, applyScope, data);

  return prisma.coupon.findFirst({ where: { id: created.id }, select: COUPON_SELECT });
}

export async function updateCoupon(id: string, jewelryId: string, data: any) {
  assert(id && jewelryId, "Parámetros inválidos.");
  const existing = await prisma.coupon.findFirst({ where: { id, jewelryId, deletedAt: null }, select: { id: true, code: true } });
  assert(existing, "Cupón no encontrado.");

  const name = s(data?.name);
  assert(name, "El nombre es obligatorio.");

  const code = s(data?.code).toUpperCase();
  assert(code, "El código es obligatorio.");

  const discountType: CouponDiscountType = VALID_DISCOUNT_TYPES.includes(data?.discountType) ? data.discountType : "PERCENTAGE";
  const discountValue = parseFloat(String(data?.discountValue ?? 0));
  assert(Number.isFinite(discountValue) && discountValue > 0, "El valor de descuento debe ser mayor a 0.");

  const applyScope: CouponScope = VALID_SCOPES.includes(data?.applyScope) ? data.applyScope : "ALL";

  // Validación temprana del scope METALS: si la lista es inválida, falla
  // antes de tocar DB. El array validado se reinyecta en `data`.
  if (applyScope === "METALS") {
    data.metalVariantIds = await validateMetalVariantIds(jewelryId, data?.metalVariantIds);
  }

  // Verificar unicidad si cambió el código
  if (code !== existing.code) {
    const dup = await prisma.coupon.findFirst({ where: { jewelryId, code, deletedAt: null, id: { not: id } }, select: { id: true } });
    assert(!dup, `El código "${code}" ya existe para este tenant.`);
  }

  await prisma.coupon.update({
    where: { id },
    data: {
      name, code,
      description:      s(data?.description),
      discountType,
      discountValue:    String(discountValue),
      validFrom:        data?.validFrom ? new Date(data.validFrom) : null,
      validTo:          data?.validTo   ? new Date(data.validTo)   : null,
      maxUsesTotal:     data?.maxUsesTotal    != null ? parseInt(String(data.maxUsesTotal),    10) : null,
      maxUsesPerClient: data?.maxUsesPerClient != null ? parseInt(String(data.maxUsesPerClient), 10) : null,
      applyScope,
      isActive: data?.isActive !== false,
      notes: s(data?.notes),
    },
  });

  // Re-sincronizar relaciones de alcance
  await syncScopeRelations(id, jewelryId, applyScope, data);

  return prisma.coupon.findFirst({ where: { id }, select: COUPON_SELECT });
}

export async function toggleCoupon(id: string, jewelryId: string) {
  assert(id && jewelryId, "Parámetros inválidos.");
  const coupon = await prisma.coupon.findFirst({ where: { id, jewelryId, deletedAt: null }, select: { id: true, isActive: true } });
  assert(coupon, "Cupón no encontrado.");
  return prisma.coupon.update({ where: { id }, data: { isActive: !coupon.isActive }, select: COUPON_SELECT });
}

export async function deleteCoupon(id: string, jewelryId: string) {
  assert(id && jewelryId, "Parámetros inválidos.");
  const coupon = await prisma.coupon.findFirst({ where: { id, jewelryId, deletedAt: null }, select: { id: true } });
  assert(coupon, "Cupón no encontrado.");
  return prisma.coupon.update({ where: { id }, data: { deletedAt: new Date(), isActive: false }, select: { id: true } });
}

/**
 * Valida si un código de cupón es aplicable en el contexto dado.
 * Retorna el cupón resuelto con toda la info necesaria para el pricing engine,
 * o lanza error con motivo si no aplica.
 */
export async function validateCoupon(
  jewelryId: string,
  code: string,
  context: {
    clientId?:   string | null;
    articleId?:  string | null;
    variantId?:  string | null;
    categoryId?: string | null;
    groupId?:    string | null;
    brandName?:  string | null;
    /**
     * FASE 3: set de variantes de metal del artículo (composición de costo).
     * Si no viene y `applyScope === "METALS"`, se calcula on-demand desde
     * `articleId`. v1: combos NO heredan metales de componentes.
     */
    articleMetalVariantIds?: string[];
  }
): Promise<{
  id:            string;
  code:          string;
  name:          string;
  discountType:  "PERCENTAGE" | "FIXED_AMOUNT";
  discountValue: number;
  valid:         boolean;
  reason?:       string;
}> {
  assert(jewelryId && code, "Parámetros inválidos.");
  const normalizedCode = code.trim().toUpperCase();

  const coupon = await prisma.coupon.findFirst({
    where: { jewelryId, code: normalizedCode, deletedAt: null },
    select: {
      id: true, name: true, code: true, discountType: true, discountValue: true,
      isActive: true, validFrom: true, validTo: true,
      maxUsesTotal: true, maxUsesPerClient: true, applyScope: true,
      articles:      { select: { articleId: true } },
      variants:      { select: { variantId: true } },
      categories:    { select: { categoryId: true } },
      groups:        { select: { groupId: true } },
      clients:       { select: { clientId: true } },
      brands:        { select: { brandName: true } },
      metalVariants: { select: { metalVariantId: true } },
      _count:        { select: { redemptions: true } },
    },
  });

  if (!coupon) return { id: "", code, name: "", discountType: "PERCENTAGE", discountValue: 0, valid: false, reason: "Código de cupón inválido o no encontrado." };
  if (!coupon.isActive) return { id: coupon.id, code, name: coupon.name, discountType: coupon.discountType as any, discountValue: 0, valid: false, reason: "El cupón está inactivo." };
  if (!isPriceListValidNow(coupon.validFrom, coupon.validTo)) return { id: coupon.id, code, name: coupon.name, discountType: coupon.discountType as any, discountValue: 0, valid: false, reason: "El cupón está fuera de vigencia." };

  // Límite total de usos
  if (coupon.maxUsesTotal != null && coupon._count.redemptions >= coupon.maxUsesTotal) {
    return { id: coupon.id, code, name: coupon.name, discountType: coupon.discountType as any, discountValue: 0, valid: false, reason: "El cupón ha alcanzado el límite de usos." };
  }

  // Límite por cliente
  if (coupon.maxUsesPerClient != null && context.clientId) {
    const clientUses = await prisma.couponRedemption.count({ where: { couponId: coupon.id, clientId: context.clientId } });
    if (clientUses >= coupon.maxUsesPerClient) {
      return { id: coupon.id, code, name: coupon.name, discountType: coupon.discountType as any, discountValue: 0, valid: false, reason: "Este cliente ya usó el cupón el máximo de veces permitido." };
    }
  }

  // Verificar alcance
  if (coupon.applyScope !== "ALL") {
    let scopeMatch = false;
    if (coupon.applyScope === "CLIENT")   scopeMatch = !!context.clientId   && coupon.clients.some(c => c.clientId === context.clientId);
    if (coupon.applyScope === "ARTICLE") {
      const articleMatch = !!context.articleId  && coupon.articles.some(a => a.articleId === context.articleId);
      const variantMatch = !!context.variantId  && coupon.variants.some(v => v.variantId === context.variantId);
      scopeMatch = articleMatch || variantMatch;
    }
    if (coupon.applyScope === "CATEGORY") scopeMatch = !!context.categoryId && coupon.categories.some(c => c.categoryId === context.categoryId);
    if (coupon.applyScope === "GROUP")    scopeMatch = !!context.groupId    && coupon.groups.some(g => g.groupId === context.groupId);
    if (coupon.applyScope === "BRAND") {
      if (context.brandName) {
        scopeMatch = coupon.brands.some(b => b.brandName === context.brandName);
      } else if (context.articleId) {
        const article = await prisma.article.findFirst({ where: { id: context.articleId }, select: { brand: true } });
        scopeMatch = !!article?.brand && coupon.brands.some(b => b.brandName === article.brand);
      } else {
        scopeMatch = true; // sin contexto de artículo, se valida en la confirmación
      }
    }
    if (coupon.applyScope === "METALS") {
      // FASE 3 — el cupón aplica si el artículo tiene en su composición al
      // menos una de las variantes seleccionadas. Si el caller ya nos pasó
      // el set, lo usamos; si no, lo calculamos desde `articleId`.
      let metals = context.articleMetalVariantIds;
      if (!metals && context.articleId) {
        const lines = await prisma.articleCostLine.findMany({
          where: {
            jewelryId,
            articleId: context.articleId,
            type: "METAL",
            metalVariantId: { not: null },
          },
          select: { metalVariantId: true },
        });
        metals = [...new Set(
          lines.map(l => l.metalVariantId).filter((v): v is string => !!v),
        )];
      }
      if (!metals || metals.length === 0) {
        scopeMatch = false; // sin metales en la composición → no aplica
      } else {
        const couponMetals = new Set(coupon.metalVariants.map(m => m.metalVariantId));
        scopeMatch = metals.some(id => couponMetals.has(id));
      }
    }
    if (!scopeMatch) {
      return { id: coupon.id, code, name: coupon.name, discountType: coupon.discountType as any, discountValue: 0, valid: false, reason: "El cupón no aplica al artículo/cliente seleccionado." };
    }
  }

  return {
    id:            coupon.id,
    code:          coupon.code,
    name:          coupon.name,
    discountType:  coupon.discountType as "PERCENTAGE" | "FIXED_AMOUNT",
    discountValue: parseFloat(coupon.discountValue.toString()),
    valid:         true,
  };
}

// ---------------------------------------------------------------------------
// Helper: sincronizar relaciones de alcance al crear/actualizar
// ---------------------------------------------------------------------------
async function syncScopeRelations(couponId: string, jewelryId: string, scope: CouponScope, data: any) {
  // Borrar todas las relaciones existentes de este cupón. Incluye METALS:
  // si el scope nuevo no es METALS, esto deja la tabla vacía (limpieza
  // automática). Si sí lo es, se vuelve a poblar abajo.
  await Promise.all([
    prisma.couponArticle.deleteMany({ where: { couponId } }),
    prisma.couponVariant.deleteMany({ where: { couponId } }),
    prisma.couponCategory.deleteMany({ where: { couponId } }),
    prisma.couponGroup.deleteMany({ where: { couponId } }),
    prisma.couponClient.deleteMany({ where: { couponId } }),
    prisma.couponBrand.deleteMany({ where: { couponId } }),
    prisma.couponMetalVariant.deleteMany({ where: { couponId } }),
  ]);

  if (scope === "ARTICLE") {
    if (Array.isArray(data?.articleIds) && data.articleIds.length > 0) {
      await prisma.couponArticle.createMany({
        data: data.articleIds.map((articleId: string) => ({ couponId, articleId, jewelryId })),
        skipDuplicates: true,
      });
    }
    if (Array.isArray(data?.variantIds) && data.variantIds.length > 0) {
      await prisma.couponVariant.createMany({
        data: data.variantIds.map((variantId: string) => ({ couponId, variantId, jewelryId })),
        skipDuplicates: true,
      });
    }
  }
  if (scope === "CATEGORY" && Array.isArray(data?.categoryIds) && data.categoryIds.length > 0) {
    await prisma.couponCategory.createMany({
      data: data.categoryIds.map((categoryId: string) => ({ couponId, categoryId, jewelryId })),
      skipDuplicates: true,
    });
  }
  if (scope === "GROUP" && Array.isArray(data?.groupIds) && data.groupIds.length > 0) {
    await prisma.couponGroup.createMany({
      data: data.groupIds.map((groupId: string) => ({ couponId, groupId, jewelryId })),
      skipDuplicates: true,
    });
  }
  if (scope === "CLIENT" && Array.isArray(data?.clientIds) && data.clientIds.length > 0) {
    await prisma.couponClient.createMany({
      data: data.clientIds.map((clientId: string) => ({ couponId, clientId, jewelryId })),
      skipDuplicates: true,
    });
  }
  if (scope === "BRAND" && Array.isArray(data?.brandNames) && data.brandNames.length > 0) {
    await prisma.couponBrand.createMany({
      data: data.brandNames.map((brandName: string) => ({ couponId, brandName, jewelryId })),
      skipDuplicates: true,
    });
  }
  // Scope METALS — los IDs ya fueron validados antes de llegar a esta función
  // (createCoupon/updateCoupon llaman a validateMetalVariantIds primero y
  // pasan el array limpio en `data.metalVariantIds`).
  if (scope === "METALS" && Array.isArray(data?.metalVariantIds) && data.metalVariantIds.length > 0) {
    await prisma.couponMetalVariant.createMany({
      data: data.metalVariantIds.map((metalVariantId: string) => ({ couponId, metalVariantId, jewelryId })),
      skipDuplicates: true,
    });
  }
}
