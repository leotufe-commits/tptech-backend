// tptech-backend/src/modules/valuation/valuation.variants.service.ts
import { Prisma } from "@prisma/client";
import { prisma } from "../../lib/prisma.js";

import {
  dec,
  assertNonEmpty,
  assertPurity,
  assertFactor,
  computeSuggested,
} from "./valuation.helpers.js";

import { ensureBaseVariantQuoteSnapshot } from "./valuation.quotes.service.js";
import { roundMoney, moneyMul } from "../../lib/money.js";

function freedSku(sku: string, id: string) {
  const suffix = `${Date.now()}_${Math.random().toString(16).slice(2)}`;
  return `deleted__${sku}__${id}__${suffix}`;
}

async function snapshotVariantHistory(args: {
  jewelryId: string;
  variantId: string;
  referenceValue: Prisma.Decimal;
  purity: Prisma.Decimal;
  saleFactor: Prisma.Decimal;
  effectiveAt?: Date;
  tx?: Prisma.TransactionClient;
  actorUserId?: string;
}) {
  const suggested = computeSuggested(args.referenceValue, args.purity);
  const finalPrice = moneyMul(suggested, args.saleFactor);

  await ensureBaseVariantQuoteSnapshot({
    jewelryId: args.jewelryId,
    variantId: args.variantId,
    price: roundMoney(finalPrice),
    effectiveAt: args.effectiveAt,
    tx: args.tx,
    createdById: args.actorUserId,
  });

  return {
    suggested: roundMoney(suggested),
    finalPrice: roundMoney(finalPrice),
  };
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
    saleFactor?: number;
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

  const saleFactor =
    saleFactorN !== undefined ? dec(saleFactorN, 1) : new Prisma.Decimal(1);
  const now = new Date();

  const out = await prisma.$transaction(async (tx) => {
    const v = await tx.metalVariant.create({
      data: {
        metalId: data.metalId,
        name,
        sku,
        purity: dec(purityN, 4),
        saleFactor,
        isActive: true,
        isFavorite: false,
        deletedAt: null,
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
        saleFactor: true,
      },
    });

    const ref = new Prisma.Decimal(metal.referenceValue ?? 0);
    const { suggested, finalPrice } = await snapshotVariantHistory({
      jewelryId,
      variantId: v.id,
      referenceValue: ref,
      purity: new Prisma.Decimal(v.purity ?? 0),
      saleFactor: new Prisma.Decimal(v.saleFactor ?? 1),
      effectiveAt: now,
      tx,
      actorUserId: data.actorUserId,
    });

    return { v, ref, suggested, finalPrice };
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
    saleFactor: roundMoney(out.v.saleFactor ?? 1),
    suggestedPrice: roundMoney(out.suggested),
    finalSalePrice: roundMoney(out.finalPrice),
    referenceValue: roundMoney(out.ref),
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
  const saleFactorN = assertFactor(data.saleFactor, "Ajuste venta (factor)");

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

  const purityDec = dec(purityN, 4);
  const saleFactorDec =
    saleFactorN !== undefined ? dec(saleFactorN, 1) : undefined;
  const now = new Date();

  const out = await prisma.$transaction(async (tx) => {
    const updated = await tx.metalVariant.update({
      where: { id: variantId },
      data: {
        name: nextName,
        sku: nextSku,
        purity: purityDec,
        ...(saleFactorDec !== undefined ? { saleFactor: saleFactorDec } : {}),
      },
      select: {
        id: true,
        metalId: true,
        name: true,
        sku: true,
        purity: true,
        isFavorite: true,
        isActive: true,
        saleFactor: true,
        createdAt: true,
        updatedAt: true,
        metal: { select: { referenceValue: true } },
      },
    });

    const ref = new Prisma.Decimal(updated.metal.referenceValue ?? 0);
    const { suggested, finalPrice } = await snapshotVariantHistory({
      jewelryId,
      variantId: updated.id,
      referenceValue: ref,
      purity: new Prisma.Decimal(updated.purity ?? 0),
      saleFactor: new Prisma.Decimal(updated.saleFactor ?? 1),
      effectiveAt: now,
      tx,
      actorUserId: data.actorUserId,
    });

    return { updated, ref, suggested, finalPrice };
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
    saleFactor: roundMoney(out.updated.saleFactor ?? 1),
    suggestedPrice: roundMoney(out.suggested),
    finalSalePrice: roundMoney(out.finalPrice),
    referenceValue: roundMoney(out.ref),
  };
}

export async function listMetalVariants(
  jewelryId: string,
  metalId: string,
  params?: {
    q?: string;
    isActive?: boolean;
    onlyFavorites?: boolean;
    minSale?: number;
    maxSale?: number;
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

  const where: any = {
    metalId,
    deletedAt: null,
    metal: { jewelryId, deletedAt: null },
  };

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
      saleFactor: true,
    },
  });

  const ref = new Prisma.Decimal(metal.referenceValue ?? 0);

  let out = rows.map((v) => {
    const purity = new Prisma.Decimal(v.purity ?? 0);
    const suggested = computeSuggested(ref, purity);
    const finalSale = moneyMul(suggested, new Prisma.Decimal(v.saleFactor ?? 1));

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
      saleFactor: roundMoney(v.saleFactor ?? 1),
      suggestedPrice: roundMoney(suggested),
      finalSalePrice: roundMoney(finalSale),
      referenceValue: roundMoney(ref),
    };
  });

  const minS = params?.minSale != null ? Number(params.minSale) : null;
  const maxS = params?.maxSale != null ? Number(params.maxSale) : null;

  if (minS != null && Number.isFinite(minS)) {
    out = out.filter((x) => x.finalSalePrice >= minS);
  }
  if (maxS != null && Number.isFinite(maxS)) {
    out = out.filter((x) => x.finalSalePrice <= maxS);
  }

  return out;
}

export async function setFavoriteVariant(jewelryId: string, variantId: string) {
  const v = await prisma.metalVariant.findFirst({
    where: {
      id: variantId,
      deletedAt: null,
      metal: { jewelryId, deletedAt: null },
    },
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
      where: {
        metalId: v.metalId,
        deletedAt: null,
        metal: { jewelryId, deletedAt: null },
      },
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

export async function toggleVariantActive(
  jewelryId: string,
  variantId: string,
  isActive: boolean
) {
  const v = await prisma.metalVariant.findFirst({
    where: {
      id: variantId,
      deletedAt: null,
      metal: { jewelryId, deletedAt: null },
    },
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
    where: {
      id: variantId,
      deletedAt: null,
      metal: { jewelryId, deletedAt: null },
    },
    select: { id: true, name: true, sku: true },
  });
  if (!v) {
    const err: any = new Error("Variante no encontrada.");
    err.status = 404;
    throw err;
  }

  const quotesCount = await prisma.metalQuote.count({
    where: { variantId: v.id },
  });
  if (quotesCount > 0) {
    const err: any = new Error(
      `No se puede eliminar la variante: tiene ${quotesCount} cotización(es).`
    );
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