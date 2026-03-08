// tptech-backend/src/modules/valuation/valuation.quotes.service.ts
import { Prisma } from "@prisma/client";
import { prisma } from "../../lib/prisma.js";
import { clampTake, same6 } from "./valuation.helpers.js";
import { roundMoney, moneyMul, moneyDiv } from "../../lib/money.js";

/* =========================
   Base currency
========================= */

export async function getBaseCurrencyOrThrow(
  jewelryId: string,
  tx?: Prisma.TransactionClient
) {
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
  price: number;
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
    select: { id: true, price: true },
  });

  const nextPrice = roundMoney(args.price);

  if (last && same6(last.price, nextPrice)) {
    return { created: false, quoteId: last.id };
  }

  const row = await db.metalQuote.create({
    data: {
      variantId: args.variantId,
      currencyId: base.id,
      price: nextPrice,
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
    price: number;
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
      price: roundMoney(data.price),
      effectiveAt: data.effectiveAt ?? new Date(),
      createdById: data.createdById ?? null,
    },
  });
}

/* =========================
   Conversión FX
========================= */

export async function getRateAt(currencyId: string, at: Date) {
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
    rate: roundMoney(r.rate),
    effectiveAt: r.effectiveAt,
  };
}

export async function convertPriceAt(args: {
  jewelryId: string;
  amount: number;
  fromCurrencyId: string;
  toCurrencyId: string;
  at: Date;
}) {
  const amount = roundMoney(args.amount);
  if (!Number.isFinite(amount)) return null;

  if (args.fromCurrencyId === args.toCurrencyId) {
    return roundMoney(amount);
  }

  const [fromCurrency, toCurrency] = await Promise.all([
    prisma.currency.findFirst({
      where: {
        id: args.fromCurrencyId,
        jewelryId: args.jewelryId,
        deletedAt: null,
      },
      select: { id: true, isBase: true, code: true, symbol: true },
    }),
    prisma.currency.findFirst({
      where: {
        id: args.toCurrencyId,
        jewelryId: args.jewelryId,
        deletedAt: null,
      },
      select: { id: true, isBase: true, code: true, symbol: true },
    }),
  ]);

  if (!fromCurrency || !toCurrency) return null;

  // Convención actual del sistema:
  // rate = valor de 1 unidad de la moneda en moneda base
  // Ejemplo: USD rate 1200 => 1 USD = 1200 ARS(base)
  if (fromCurrency.isBase) {
    const toRate = await getRateAt(toCurrency.id, args.at);
    if (!toRate || !Number.isFinite(toRate.rate) || toRate.rate <= 0) {
      return null;
    }
    return roundMoney(moneyDiv(amount, toRate.rate));
  }

  if (toCurrency.isBase) {
    const fromRate = await getRateAt(fromCurrency.id, args.at);
    if (!fromRate || !Number.isFinite(fromRate.rate) || fromRate.rate <= 0) {
      return null;
    }
    return roundMoney(moneyMul(amount, fromRate.rate));
  }

  const [fromRate, toRate] = await Promise.all([
    getRateAt(fromCurrency.id, args.at),
    getRateAt(toCurrency.id, args.at),
  ]);

  if (
    !fromRate ||
    !toRate ||
    !Number.isFinite(fromRate.rate) ||
    !Number.isFinite(toRate.rate) ||
    fromRate.rate <= 0 ||
    toRate.rate <= 0
  ) {
    return null;
  }

  const inBase = moneyMul(amount, fromRate.rate);
  const out = moneyDiv(inBase, toRate.rate);

  return roundMoney(out);
}

/* =========================
   List quotes
========================= */

export async function listMetalQuotes(
  jewelryId: string,
  variantId: string,
  take = 50
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

  const rows = await prisma.metalQuote.findMany({
    where: {
      variantId,
      variant: { deletedAt: null, metal: { jewelryId, deletedAt: null } },
      currency: { deletedAt: null },
    },
    orderBy: [{ effectiveAt: "desc" }, { createdAt: "desc" }],
    take: clampTake(take, 50),
    select: {
      id: true,
      variantId: true,
      currencyId: true,
      price: true,
      effectiveAt: true,
      createdAt: true,
      currency: {
        select: {
          id: true,
          code: true,
          symbol: true,
          isBase: true,
          isActive: true,
        },
      },
      createdBy: {
        select: { id: true, name: true, email: true },
      },
    },
  });

  return rows.map((r) => ({
    id: r.id,
    variantId: r.variantId,
    currencyId: r.currencyId,
    price: roundMoney(r.price),
    effectiveAt: r.effectiveAt,
    createdAt: r.createdAt,
    currency: r.currency,
    user: r.createdBy
      ? {
          id: r.createdBy.id,
          name: r.createdBy.name,
          email: r.createdBy.email,
        }
      : null,
  }));
}