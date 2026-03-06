// tptech-backend/src/modules/valuation/valuation.variants.service.ts
import { Prisma } from "@prisma/client";
import { prisma } from "../../lib/prisma.js";

import {
  dec,
  assertNonEmpty,
  assertPurity,
  assertFactor,
  computeSuggested,
  computeFinal,
} from "./valuation.helpers.js";

import { ensureBaseVariantQuoteSnapshot } from "./valuation.quotes.service.js";

function freedSku(sku: string, id: string) {
  const suffix = `${Date.now()}_${Math.random().toString(16).slice(2)}`;
  return `deleted__${sku}__${id}__${suffix}`;
}

/** ✅ override válido: > 0; 0 o negativos => null */
function normalizeOverrideIn(v: any) {
  if (v === undefined) return undefined; // "no tocar"
  if (v === null) return null;
  const n = Number(v);
  if (!Number.isFinite(n)) return null;
  if (n <= 0) return null;
  return n;
}

/** ✅ salida: si es 0/negativo o no numérico => null */
function normalizeOverrideOut(v: any) {
  if (v === null || v === undefined) return null;
  const n = Number(v);
  if (!Number.isFinite(n)) return null;
  if (n <= 0) return null;
  return n;
}

/** ✅ crea snapshot profesional: purchase=sugerido, sale=final */
async function snapshotVariantAutoHistory(args: {
  jewelryId: string;
  variantId: string;
  referenceValue: Prisma.Decimal;
  purity: Prisma.Decimal;
  saleFactor: Prisma.Decimal;
  saleOverride: Prisma.Decimal | null;
  effectiveAt?: Date;
  tx?: Prisma.TransactionClient;

  /** ✅ Opción B: quién hizo el cambio (queda en createdById del quote) */
  actorUserId?: string;
}) {
  const suggested = computeSuggested(args.referenceValue, args.purity);
  const finalSale = computeFinal(suggested, args.saleFactor, args.saleOverride);

  await ensureBaseVariantQuoteSnapshot({
    jewelryId: args.jewelryId,
    variantId: args.variantId,
    suggestedPrice: Number(suggested),
    finalPrice: Number(finalSale),
    effectiveAt: args.effectiveAt,
    tx: args.tx,
    createdById: args.actorUserId,
  });

  return { suggested, finalSale };
}

/* =========================
   Variantes
========================= */

export async function createMetalVariant(
  jewelryId: string,
  data: {
    metalId: string;
    name: string;
    sku: string;
    purity: number;
    buyFactor?: number;
    saleFactor?: number;
    purchasePriceOverride?: number | null;
    salePriceOverride?: number | null;

    /** ✅ Opción B: actor */
    actorUserId?: string;
  }
) {
  const metal = await prisma.metal.findFirst({
    where: { id: data.metalId, jewelryId, deletedAt: null },
    select: { id: true, referenceValue: true },
  });
  if (!metal) {
    const err: any = new Error("Metal no encontrado.");
    err.status = 404;
    throw err;
  }

  const name = assertNonEmpty(data.name, "Nombre requerido.");
  const sku = assertNonEmpty(data.sku, "SKU requerido.").toUpperCase();
  const purityN = assertPurity(data.purity);

  const buyFactorN = assertFactor(data.buyFactor, "Ajuste compra (factor)");
  const saleFactorN = assertFactor(data.saleFactor, "Ajuste venta (factor)");

  const dup = await prisma.metalVariant.findFirst({
    where: { metalId: data.metalId, sku, deletedAt: null },
    select: { id: true },
  });
  if (dup) {
    const err: any = new Error(`SKU duplicado: "${sku}" ya existe.`);
    err.status = 409;
    throw err;
  }

  // ✅ normalizamos overrides: 0 => null
  const pOverrideIn = normalizeOverrideIn(data.purchasePriceOverride);
  const sOverrideIn = normalizeOverrideIn(data.salePriceOverride);

  const pricingMode =
    (pOverrideIn ?? null) !== null || (sOverrideIn ?? null) !== null
      ? ("OVERRIDE" as any)
      : ("AUTO" as any);

  const buyFactor =
    buyFactorN !== undefined ? dec(buyFactorN, 1) : new Prisma.Decimal(1);
  const saleFactor =
    saleFactorN !== undefined ? dec(saleFactorN, 1) : new Prisma.Decimal(1);

  const pOverride =
    pOverrideIn === undefined
      ? undefined
      : pOverrideIn === null
      ? null
      : dec(pOverrideIn);

  const sOverride =
    sOverrideIn === undefined
      ? undefined
      : sOverrideIn === null
      ? null
      : dec(sOverrideIn);

  const now = new Date();

  const out = await prisma.$transaction(async (tx) => {
    const v = await tx.metalVariant.create({
      data: {
        metalId: data.metalId,
        name,
        sku,

        // ✅ FIX: guardamos pureza con 4 decimales (schema: Decimal(6,4))
        purity: dec(purityN, 4),

        isActive: true,
        isFavorite: false,
        deletedAt: null,

        buyFactor,
        saleFactor,
        ...(pOverride !== undefined ? { purchasePriceOverride: pOverride } : {}),
        ...(sOverride !== undefined ? { salePriceOverride: sOverride } : {}),
        pricingMode,
      },
      select: {
        id: true,
        metalId: true,
        name: true,
        sku: true,
        purity: true,
        isFavorite: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
        buyFactor: true,
        saleFactor: true,
        purchasePriceOverride: true,
        salePriceOverride: true,
        pricingMode: true,
      },
    });

    const ref = new Prisma.Decimal(metal.referenceValue ?? 0);
    const purity = new Prisma.Decimal(v.purity ?? 0);
    const sOvNum = normalizeOverrideOut(v.salePriceOverride);
    const sOv =
      sOvNum !== null ? new Prisma.Decimal(v.salePriceOverride as any) : null;

    const { suggested, finalSale } = await snapshotVariantAutoHistory({
      jewelryId,
      variantId: v.id,
      referenceValue: ref,
      purity,
      saleFactor: new Prisma.Decimal(v.saleFactor ?? 1),
      saleOverride: sOv,
      effectiveAt: now,
      tx,
      actorUserId: data.actorUserId,
    });

    return {
      v,
      ref,
      suggested,
      finalSale,
      sOvNum,
      pOvNum: normalizeOverrideOut(v.purchasePriceOverride),
      finalPurchase: computeFinal(
        suggested,
        new Prisma.Decimal(v.buyFactor ?? 1),
        normalizeOverrideOut(v.purchasePriceOverride) !== null
          ? new Prisma.Decimal(v.purchasePriceOverride as any)
          : null
      ),
    };
  });

  return {
    id: out.v.id,
    metalId: out.v.metalId,
    name: out.v.name,
    sku: out.v.sku,
    purity: Number(out.v.purity),

    isFavorite: out.v.isFavorite,
    isActive: out.v.isActive,
    createdAt: out.v.createdAt,
    updatedAt: out.v.updatedAt,

    buyFactor: Number(out.v.buyFactor ?? 1),
    saleFactor: Number(out.v.saleFactor ?? 1),

    purchasePriceOverride: out.pOvNum,
    salePriceOverride: out.sOvNum,

    pricingMode: (out.v as any).pricingMode ?? "AUTO",

    suggestedPrice: Number(out.suggested),
    finalPurchasePrice: Number(out.finalPurchase),
    finalSalePrice: Number(out.finalSale),
    referenceValue: Number(out.ref),
  };
}

export async function updateMetalVariant(
  jewelryId: string,
  variantId: string,
  data: {
    name: string;
    sku: string;
    purity: number;
    saleFactor?: number;
    salePriceOverride?: number | null;

    /** ✅ Opción B: actor */
    actorUserId?: string;
  }
) {
  const existing = await prisma.metalVariant.findFirst({
    where: {
      id: variantId,
      deletedAt: null,
      metal: { jewelryId, deletedAt: null },
    },
    select: {
      id: true,
      metalId: true,
      sku: true,
      purity: true,
      saleFactor: true,
      salePriceOverride: true,
      buyFactor: true,
      purchasePriceOverride: true,
      isFavorite: true,
      isActive: true,
      pricingMode: true,
      metal: { select: { referenceValue: true } },
    },
  });

  if (!existing) {
    const err: any = new Error("Variante no encontrada.");
    err.status = 404;
    throw err;
  }

  const nextName = assertNonEmpty(data.name, "Nombre requerido.");
  const nextSku = assertNonEmpty(data.sku, "SKU requerido.").toUpperCase();
  const purityN = assertPurity(data.purity);

  const dup = await prisma.metalVariant.findFirst({
    where: {
      metalId: existing.metalId,
      sku: nextSku,
      deletedAt: null,
      id: { not: variantId },
    },
    select: { id: true },
  });
  if (dup) {
    const err: any = new Error(`SKU duplicado: "${nextSku}" ya existe.`);
    err.status = 409;
    throw err;
  }

  // ✅ FIX: 4 decimales (schema Decimal(6,4))
  const purityDec = dec(purityN, 4);

  const saleFactorN = assertFactor(data.saleFactor, "Ajuste venta (factor)");
  const saleFactorDec = saleFactorN !== undefined ? dec(saleFactorN, 1) : undefined;

  // ✅ normalizamos override: 0 => null
  const saleOverrideN = normalizeOverrideIn(data.salePriceOverride);
  const saleOverrideDec =
    saleOverrideN === undefined
      ? undefined
      : saleOverrideN === null
      ? null
      : dec(saleOverrideN);

  const pricingMode =
    saleOverrideDec === undefined
      ? undefined
      : saleOverrideDec === null
      ? ("AUTO" as any)
      : ("OVERRIDE" as any);

  const now = new Date();

  const out = await prisma.$transaction(async (tx) => {
    const updated = await tx.metalVariant.update({
      where: { id: variantId },
      data: {
        name: nextName,
        sku: nextSku,
        purity: purityDec,
        ...(saleFactorDec !== undefined ? { saleFactor: saleFactorDec } : {}),
        ...(saleOverrideDec !== undefined ? { salePriceOverride: saleOverrideDec } : {}),
        ...(pricingMode !== undefined ? { pricingMode } : {}),
      },
      select: {
        id: true,
        metalId: true,
        name: true,
        sku: true,
        purity: true,
        isFavorite: true,
        isActive: true,
        buyFactor: true,
        saleFactor: true,
        purchasePriceOverride: true,
        salePriceOverride: true,
        pricingMode: true,
        createdAt: true,
        updatedAt: true,
        metal: { select: { referenceValue: true } },
      },
    });

    const ref = new Prisma.Decimal(updated.metal.referenceValue ?? 0);
    const suggested = computeSuggested(ref, new Prisma.Decimal(updated.purity ?? 0));

    const pOvNum = normalizeOverrideOut(updated.purchasePriceOverride);
    const sOvNum = normalizeOverrideOut(updated.salePriceOverride);

    const finalPurchase = computeFinal(
      suggested,
      new Prisma.Decimal(updated.buyFactor ?? 1),
      pOvNum !== null ? new Prisma.Decimal(updated.purchasePriceOverride as any) : null
    );

    const sOv = sOvNum !== null ? new Prisma.Decimal(updated.salePriceOverride as any) : null;
    const finalSale = computeFinal(
      suggested,
      new Prisma.Decimal(updated.saleFactor ?? 1),
      sOv
    );

    // ✅ HISTORIAL AUTOMÁTICO (profesional) + createdById
    await ensureBaseVariantQuoteSnapshot({
      jewelryId,
      variantId: updated.id,
      suggestedPrice: Number(suggested),
      finalPrice: Number(finalSale),
      effectiveAt: now,
      tx,
      createdById: data.actorUserId,
    });

    return { updated, ref, suggested, finalPurchase, finalSale, pOvNum, sOvNum };
  });

  return {
    id: out.updated.id,
    metalId: out.updated.metalId,
    name: out.updated.name,
    sku: out.updated.sku,
    purity: Number(out.updated.purity),

    isFavorite: out.updated.isFavorite,
    isActive: out.updated.isActive,
    createdAt: out.updated.createdAt,
    updatedAt: out.updated.updatedAt,

    buyFactor: Number(out.updated.buyFactor ?? 1),
    saleFactor: Number(out.updated.saleFactor ?? 1),

    purchasePriceOverride: out.pOvNum,
    salePriceOverride: out.sOvNum,

    pricingMode: (out.updated as any).pricingMode ?? "AUTO",

    suggestedPrice: Number(out.suggested),
    finalPurchasePrice: Number(out.finalPurchase),
    finalSalePrice: Number(out.finalSale),
    referenceValue: Number(out.ref),
  };
}

export async function updateMetalVariantPricing(
  jewelryId: string,
  variantId: string,
  data: {
    buyFactor?: number;
    saleFactor?: number;
    purchasePriceOverride?: number | null;
    salePriceOverride?: number | null;
    clearPurchaseOverride?: boolean;
    clearSaleOverride?: boolean;

    /** ✅ Opción B: actor */
    actorUserId?: string;
  }
) {
  const v = await prisma.metalVariant.findFirst({
    where: { id: variantId, deletedAt: null, metal: { jewelryId, deletedAt: null } },
    select: {
      id: true,
      metalId: true,
      metal: { select: { referenceValue: true } },
      purity: true,
      buyFactor: true,
      saleFactor: true,
      purchasePriceOverride: true,
      salePriceOverride: true,
    },
  });
  if (!v) {
    const err: any = new Error("Variante no encontrada.");
    err.status = 404;
    throw err;
  }

  const patch: any = {};

  const bf = assertFactor(data.buyFactor, "Ajuste compra (factor)");
  const sf = assertFactor(data.saleFactor, "Ajuste venta (factor)");

  if (bf !== undefined) patch.buyFactor = dec(bf, 1);
  if (sf !== undefined) patch.saleFactor = dec(sf, 1);

  if (data.clearPurchaseOverride) patch.purchasePriceOverride = null;
  if (data.clearSaleOverride) patch.salePriceOverride = null;

  if (data.purchasePriceOverride !== undefined) {
    const n = normalizeOverrideIn(data.purchasePriceOverride);
    patch.purchasePriceOverride = n === undefined ? undefined : n === null ? null : dec(n);
  }
  if (data.salePriceOverride !== undefined) {
    const n = normalizeOverrideIn(data.salePriceOverride);
    patch.salePriceOverride = n === undefined ? undefined : n === null ? null : dec(n);
  }

  const nextPurchase =
    patch.purchasePriceOverride !== undefined ? patch.purchasePriceOverride : v.purchasePriceOverride;
  const nextSale =
    patch.salePriceOverride !== undefined ? patch.salePriceOverride : v.salePriceOverride;

  patch.pricingMode =
    (nextPurchase !== null && nextPurchase !== undefined) || (nextSale !== null && nextSale !== undefined)
      ? ("OVERRIDE" as any)
      : ("AUTO" as any);

  const now = new Date();

  const out = await prisma.$transaction(async (tx) => {
    const updated = await tx.metalVariant.update({
      where: { id: variantId },
      data: patch,
      select: {
        id: true,
        metalId: true,
        name: true,
        sku: true,
        purity: true,
        isFavorite: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
        buyFactor: true,
        saleFactor: true,
        purchasePriceOverride: true,
        salePriceOverride: true,
        pricingMode: true,
        metal: { select: { referenceValue: true } },
      },
    });

    const ref = new Prisma.Decimal(updated.metal.referenceValue ?? 0);
    const suggested = computeSuggested(ref, new Prisma.Decimal(updated.purity ?? 0));

    const pOvNum = normalizeOverrideOut(updated.purchasePriceOverride);
    const sOvNum = normalizeOverrideOut(updated.salePriceOverride);

    const finalPurchase = computeFinal(
      suggested,
      new Prisma.Decimal(updated.buyFactor ?? 1),
      pOvNum !== null ? new Prisma.Decimal(updated.purchasePriceOverride as any) : null
    );

    const sOv = sOvNum !== null ? new Prisma.Decimal(updated.salePriceOverride as any) : null;
    const finalSale = computeFinal(
      suggested,
      new Prisma.Decimal(updated.saleFactor ?? 1),
      sOv
    );

    // ✅ HISTORIAL AUTOMÁTICO (profesional) + createdById
    await ensureBaseVariantQuoteSnapshot({
      jewelryId,
      variantId: updated.id,
      suggestedPrice: Number(suggested),
      finalPrice: Number(finalSale),
      effectiveAt: now,
      tx,
      createdById: data.actorUserId,
    });

    return { updated, ref, suggested, finalPurchase, finalSale, pOvNum, sOvNum };
  });

  return {
    id: out.updated.id,
    metalId: out.updated.metalId,
    name: out.updated.name,
    sku: out.updated.sku,
    purity: Number(out.updated.purity),

    isFavorite: out.updated.isFavorite,
    isActive: out.updated.isActive,
    createdAt: out.updated.createdAt,
    updatedAt: out.updated.updatedAt,

    buyFactor: Number(out.updated.buyFactor ?? 1),
    saleFactor: Number(out.updated.saleFactor ?? 1),

    purchasePriceOverride: out.pOvNum,
    salePriceOverride: out.sOvNum,

    pricingMode: (out.updated as any).pricingMode ?? "AUTO",

    suggestedPrice: Number(out.suggested),
    finalPurchasePrice: Number(out.finalPurchase),
    finalSalePrice: Number(out.finalSale),
    referenceValue: Number(out.ref),
  };
}

export async function listMetalVariants(
  jewelryId: string,
  metalId: string,
  params?: {
    q?: string;
    isActive?: boolean;
    onlyFavorites?: boolean;
    minPurchase?: number;
    maxPurchase?: number;
    minSale?: number;
    maxSale?: number;
    currencyId?: string;
  }
) {
  const metal = await prisma.metal.findFirst({
    where: { id: metalId, jewelryId, deletedAt: null },
    select: { id: true, referenceValue: true },
  });
  if (!metal) {
    const err: any = new Error("Metal no encontrado.");
    err.status = 404;
    throw err;
  }

  const where: any = { metalId, deletedAt: null, metal: { jewelryId, deletedAt: null } };

  if (typeof params?.isActive === "boolean") where.isActive = params.isActive;
  if (params?.onlyFavorites) where.isFavorite = true;

  const q = String(params?.q || "").trim();
  if (q) {
    where.OR = [
      { name: { contains: q, mode: "insensitive" } },
      { sku: { contains: q, mode: "insensitive" } },
    ];
  }

  const rows = await prisma.metalVariant.findMany({
    where,
    orderBy: [{ isFavorite: "desc" }, { name: "asc" }],
    select: {
      id: true,
      metalId: true,
      name: true,
      sku: true,
      purity: true,
      isFavorite: true,
      isActive: true,
      createdAt: true,
      updatedAt: true,

      buyFactor: true,
      saleFactor: true,
      purchasePriceOverride: true,
      salePriceOverride: true,
      pricingMode: true,
    },
  });

  const ref = new Prisma.Decimal(metal.referenceValue ?? 0);

  let out = rows.map((v) => {
    const purity = new Prisma.Decimal(v.purity ?? 0);
    const suggested = computeSuggested(ref, purity);

    const buyFactor = new Prisma.Decimal(v.buyFactor ?? 1);
    const saleFactor = new Prisma.Decimal(v.saleFactor ?? 1);

    const pOvNum = normalizeOverrideOut(v.purchasePriceOverride);
    const sOvNum = normalizeOverrideOut(v.salePriceOverride);

    const pOverride = pOvNum !== null ? new Prisma.Decimal(v.purchasePriceOverride as any) : null;
    const sOverride = sOvNum !== null ? new Prisma.Decimal(v.salePriceOverride as any) : null;

    const finalPurchase = computeFinal(suggested, buyFactor, pOverride);
    const finalSale = computeFinal(suggested, saleFactor, sOverride);

    const effectivePricingMode =
      pOvNum !== null || sOvNum !== null ? ((v as any).pricingMode ?? "OVERRIDE") : "AUTO";

    return {
      id: v.id,
      metalId: v.metalId,
      name: v.name,
      sku: v.sku,
      purity: Number(v.purity),

      isFavorite: v.isFavorite,
      isActive: v.isActive,
      createdAt: v.createdAt,
      updatedAt: v.updatedAt,

      buyFactor: Number(v.buyFactor ?? 1),
      saleFactor: Number(v.saleFactor ?? 1),

      purchasePriceOverride: pOvNum,
      salePriceOverride: sOvNum,

      pricingMode: effectivePricingMode,

      suggestedPrice: Number(suggested),
      finalPurchasePrice: Number(finalPurchase),
      finalSalePrice: Number(finalSale),
      referenceValue: Number(ref),
    };
  });

  const minP = params?.minPurchase != null ? Number(params.minPurchase) : null;
  const maxP = params?.maxPurchase != null ? Number(params.maxPurchase) : null;
  const minS = params?.minSale != null ? Number(params.minSale) : null;
  const maxS = params?.maxSale != null ? Number(params.maxSale) : null;

  if (minP != null && Number.isFinite(minP)) out = out.filter((x) => Number(x.finalPurchasePrice) >= minP);
  if (maxP != null && Number.isFinite(maxP)) out = out.filter((x) => Number(x.finalPurchasePrice) <= maxP);
  if (minS != null && Number.isFinite(minS)) out = out.filter((x) => Number(x.finalSalePrice) >= minS);
  if (maxS != null && Number.isFinite(maxS)) out = out.filter((x) => Number(x.finalSalePrice) <= maxS);

  return out;
}

export async function setFavoriteVariant(jewelryId: string, variantId: string) {
  const v = await prisma.metalVariant.findFirst({
    where: { id: variantId, deletedAt: null, metal: { jewelryId, deletedAt: null } },
    select: { id: true, isFavorite: true, metalId: true },
  });
  if (!v) {
    const err: any = new Error("Variante no encontrada.");
    err.status = 404;
    throw err;
  }

  if (v.isFavorite) {
    return prisma.metalVariant.update({
      where: { id: v.id },
      data: { isFavorite: false },
      select: { id: true, isFavorite: true },
    });
  }

  const out = await prisma.$transaction(async (tx) => {
    await tx.metalVariant.updateMany({
      where: { metalId: v.metalId, deletedAt: null, metal: { jewelryId, deletedAt: null } },
      data: { isFavorite: false },
    });

    return tx.metalVariant.update({
      where: { id: v.id },
      data: { isFavorite: true },
      select: { id: true, isFavorite: true },
    });
  });

  return out;
}

export async function clearFavoriteVariant(jewelryId: string, metalId: string) {
  const metal = await prisma.metal.findFirst({
    where: { id: metalId, jewelryId, deletedAt: null },
    select: { id: true },
  });

  if (!metal) {
    const err: any = new Error("Metal no encontrado.");
    err.status = 404;
    throw err;
  }

  await prisma.metalVariant.updateMany({
    where: { metalId, deletedAt: null, metal: { jewelryId, deletedAt: null } },
    data: { isFavorite: false },
  });

  return { ok: true };
}

export async function toggleVariantActive(jewelryId: string, variantId: string, isActive: boolean) {
  const v = await prisma.metalVariant.findFirst({
    where: { id: variantId, deletedAt: null, metal: { jewelryId, deletedAt: null } },
    select: { id: true },
  });
  if (!v) {
    const err: any = new Error("Variante no encontrada.");
    err.status = 404;
    throw err;
  }

  const row = await prisma.metalVariant.update({
    where: { id: variantId },
    data: { isActive },
    select: { id: true, isActive: true },
  });

  return row;
}

/* =========================
   ✅ Soft delete variante
========================= */
export async function deleteMetalVariant(jewelryId: string, variantId: string) {
  const v = await prisma.metalVariant.findFirst({
    where: { id: variantId, deletedAt: null, metal: { jewelryId, deletedAt: null } },
    select: { id: true, name: true, sku: true },
  });
  if (!v) {
    const err: any = new Error("Variante no encontrada.");
    err.status = 404;
    throw err;
  }

  const quotesCount = await prisma.metalQuote.count({ where: { variantId: v.id } });
  if (quotesCount > 0) {
    const err: any = new Error(`No se puede eliminar la variante: tiene ${quotesCount} cotización(es).`);
    err.status = 409;
    throw err;
  }

  const now = new Date();

  await prisma.metalVariant.update({
    where: { id: v.id },
    data: {
      deletedAt: now,
      isActive: false,
      isFavorite: false,
      sku: freedSku(v.sku, v.id),
      name: "",
    },
    select: { id: true },
  });

  return { ok: true };
}