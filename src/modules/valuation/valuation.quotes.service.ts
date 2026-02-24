// tptech-backend/src/modules/valuation/valuation.quotes.service.ts
import { prisma } from "../../lib/prisma.js";
import { clampTake } from "./valuation.helpers.js";

/* =========================
   Quotes
========================= */

export async function addMetalQuote(
  jewelryId: string,
  data: {
    variantId: string;
    currencyId: string;
    purchasePrice: number;
    salePrice: number;
    effectiveAt?: Date;
  }
) {
  const v = await prisma.metalVariant.findFirst({
    where: {
      id: data.variantId,
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

  const c = await prisma.currency.findFirst({
    where: { id: data.currencyId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  if (!c) {
    const err: any = new Error("Moneda no encontrada.");
    err.status = 404;
    throw err;
  }

  return prisma.metalQuote.create({
    data: {
      variantId: data.variantId,
      currencyId: data.currencyId,
      purchasePrice: data.purchasePrice,
      salePrice: data.salePrice,
      effectiveAt: data.effectiveAt ?? new Date(),
    },
  });
}

export async function listMetalQuotes(jewelryId: string, variantId: string, take = 50) {
  const v = await prisma.metalVariant.findFirst({
    where: { id: variantId, deletedAt: null, metal: { jewelryId, deletedAt: null } },
    select: { id: true },
  });
  if (!v) {
    const err: any = new Error("Variante no encontrada.");
    err.status = 404;
    throw err;
  }

  return prisma.metalQuote.findMany({
    where: {
      variantId,
      variant: { deletedAt: null, metal: { jewelryId, deletedAt: null } },
      currency: { deletedAt: null },
    },
    orderBy: [{ effectiveAt: "desc" }, { createdAt: "desc" }],
    take: clampTake(take, 50),
    include: {
      currency: {
        select: { id: true, code: true, symbol: true, isBase: true, isActive: true },
      },
    },
  });
}