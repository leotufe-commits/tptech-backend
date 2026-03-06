// tptech-backend/src/modules/valuation/valuation.quotes.service.ts
import { Prisma } from "@prisma/client";
import { prisma } from "../../lib/prisma.js";
import { clampTake, same6 } from "./valuation.helpers.js";

/* =========================
   Base currency
========================= */

export async function getBaseCurrencyOrThrow(jewelryId: string, tx?: Prisma.TransactionClient) {
  const db = tx ?? prisma;

  const base = await db.currency.findFirst({
    where: { jewelryId, isBase: true, deletedAt: null },
    select: { id: true, code: true, symbol: true },
  });

  if (!base) {
    const err: any = new Error(
      "No hay moneda base configurada. Definí una moneda base para poder guardar historial."
    );
    err.status = 409;
    throw err;
  }

  return base;
}

/* =========================
   Snapshot automático
========================= */

export async function ensureBaseVariantQuoteSnapshot(args: {
  jewelryId: string;
  variantId: string;
  suggestedPrice: number;
  finalPrice: number;
  effectiveAt?: Date;
  createdById?: string | null;
  tx?: Prisma.TransactionClient;
}) {
  const db = args.tx ?? prisma;

  const v = await db.metalVariant.findFirst({
    where: {
      id: args.variantId,
      deletedAt: null,
      metal: { jewelryId: args.jewelryId, deletedAt: null },
    },
    select: { id: true },
  });

  if (!v) {
    const err: any = new Error("Variante no encontrada.");
    err.status = 404;
    throw err;
  }

  const base = await getBaseCurrencyOrThrow(args.jewelryId, args.tx);

  const last = await db.metalQuote.findFirst({
    where: { variantId: args.variantId, currencyId: base.id },
    orderBy: [{ effectiveAt: "desc" }, { createdAt: "desc" }],
    select: { id: true, purchasePrice: true, salePrice: true },
  });

  const nextSuggested = Number(args.suggestedPrice);
  const nextFinal = Number(args.finalPrice);

  if (last) {
    const sameSuggested = same6(last.purchasePrice, nextSuggested);
    const sameFinal = same6(last.salePrice, nextFinal);

    if (sameSuggested && sameFinal) {
      return { created: false, quoteId: last.id };
    }
  }

  const row = await db.metalQuote.create({
    data: {
      variantId: args.variantId,
      currencyId: base.id,
      purchasePrice: nextSuggested,
      salePrice: nextFinal,
      effectiveAt: args.effectiveAt ?? new Date(),
      createdById: args.createdById ?? null,
    },
    select: { id: true },
  });

  return { created: true, quoteId: row.id };
}

/* =========================
   Quote manual
========================= */

export async function addMetalQuote(
  jewelryId: string,
  data: {
    variantId: string;
    currencyId: string;
    purchasePrice: number;
    salePrice: number;
    effectiveAt?: Date;
    createdById?: string | null;
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
      createdById: data.createdById ?? null,
    },
  });
}

/* =========================
   Conversión FX
========================= */

async function getRateAt(currencyId: string, at: Date) {
  const r = await prisma.currencyRate.findFirst({
    where: {
      currencyId,
      effectiveAt: { lte: at },
    },
    orderBy: { effectiveAt: "desc" },
    select: { rate: true, effectiveAt: true },
  });

  if (!r) return null;

  return {
    rate: Number(r.rate),
    effectiveAt: r.effectiveAt,
  };
}

/* =========================
   List quotes (conversión a base)
========================= */

export async function listMetalQuotes(jewelryId: string, variantId: string, take = 50) {
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

  const base = await getBaseCurrencyOrThrow(jewelryId);

  const rows = await prisma.metalQuote.findMany({
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
      createdBy: {
        select: { id: true, name: true, email: true },
      },
    },
  });

  const out: any[] = [];

  for (const r of rows) {
    const buy = Number(r.purchasePrice);
    const sell = Number(r.salePrice);

    if (r.currencyId === base.id) {
      out.push({
        ...r,
        baseCurrency: base,
        basePurchasePrice: buy,
        baseSalePrice: sell,
        fxRateUsed: 1,
      });
      continue;
    }

    const rateInfo = await getRateAt(r.currencyId, r.effectiveAt ?? r.createdAt);

    const rate = rateInfo?.rate ?? null;

    out.push({
      ...r,
      baseCurrency: base,
      basePurchasePrice: rate ? buy * rate : null,
      baseSalePrice: rate ? sell * rate : null,
      fxRateUsed: rate,
      fxRateEffectiveAt: rateInfo?.effectiveAt ?? null,
    });
  }

  return out;
}