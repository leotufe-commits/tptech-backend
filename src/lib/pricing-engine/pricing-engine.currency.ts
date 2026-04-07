// src/lib/pricing-engine/pricing-engine.currency.ts
// Utilidades centralizadas de conversión de moneda.
// Todos los resultados del motor están en moneda BASE del tenant.

import { Prisma } from "@prisma/client";
import { prisma } from "../prisma.js";
import type { PricingStep } from "./pricing-engine.types.js";

// ---------------------------------------------------------------------------
// getBaseCurrencyId — moneda base del tenant
// ---------------------------------------------------------------------------

export async function getBaseCurrencyId(
  jewelryId: string
): Promise<string | null> {
  const base = await prisma.currency.findFirst({
    where: { jewelryId, isBase: true, deletedAt: null },
    select: { id: true },
  });
  return base?.id ?? null;
}

// ---------------------------------------------------------------------------
// CurrencyInfo — tasa + datos de visualización de una moneda
// ---------------------------------------------------------------------------

export type CurrencyInfo = {
  rate:   Prisma.Decimal;
  code:   string;
  symbol: string;
};

// ---------------------------------------------------------------------------
// getExchangeRate — tasa de cambio más reciente + datos legibles de la moneda
// ---------------------------------------------------------------------------

export async function getExchangeRate(
  currencyId: string
): Promise<CurrencyInfo | null> {
  const row = await prisma.currencyRate.findFirst({
    where: { currencyId },
    orderBy: { createdAt: "desc" },
    select: {
      rate:     true,
      currency: { select: { code: true, symbol: true } },
    },
  });
  if (!row) return null;
  return {
    rate:   new Prisma.Decimal(row.rate.toString()),
    code:   row.currency.code,
    symbol: row.currency.symbol,
  };
}

// ---------------------------------------------------------------------------
// convertMoney — convierte un monto a moneda base
//
// Si fromCurrencyId === baseCurrencyId: devuelve el monto sin convertir.
// Si falta la tasa: marks the step as "missing" y devuelve null.
// ---------------------------------------------------------------------------

export async function convertMoney(opts: {
  amount: Prisma.Decimal;
  fromCurrencyId: string | null | undefined;
  baseCurrencyId: string;
  stepKey: string;
  stepLabel: string;
  steps: PricingStep[];
}): Promise<Prisma.Decimal | null> {
  const { amount, fromCurrencyId, baseCurrencyId, stepKey, stepLabel, steps } = opts;

  // Sin moneda origen → ya está en base
  if (!fromCurrencyId || fromCurrencyId === baseCurrencyId) {
    return amount;
  }

  const rateInfo = await getExchangeRate(fromCurrencyId);
  if (!rateInfo) {
    steps.push({
      key: stepKey,
      label: stepLabel,
      status: "missing",
      value: null,
      message: `Sin tasa de cambio para moneda ${fromCurrencyId}`,
      meta: { fromCurrencyId },
    });
    return null;
  }

  const converted = amount.mul(rateInfo.rate);
  steps.push({
    key: stepKey,
    label: stepLabel,
    status: "ok",
    value: converted,
    meta: {
      originalAmount: amount.toString(),
      fromCurrencyId,
      currencyCode:   rateInfo.code,
      currencySymbol: rateInfo.symbol,
      toCurrencyId:   baseCurrencyId,
      rate:           rateInfo.rate.toString(),
      convertedAmount: converted.toString(),
    },
  });
  return converted;
}

// ---------------------------------------------------------------------------
// normalizeToBaseCurrency — convierte un valor arbitrario a Decimal en base
//
// Combina: parseo → conversión → registro en steps.
// Devuelve null y empuja un step "missing" si la tasa no existe.
// ---------------------------------------------------------------------------

export async function normalizeToBaseCurrency(opts: {
  rawValue: any;
  currencyId: string | null | undefined;
  baseCurrencyId: string;
  stepKey: string;
  stepLabel: string;
  steps: PricingStep[];
}): Promise<Prisma.Decimal | null> {
  const { rawValue, currencyId, baseCurrencyId, stepKey, stepLabel, steps } = opts;

  if (rawValue == null) return null;
  const amount = new Prisma.Decimal(rawValue.toString());

  return convertMoney({
    amount,
    fromCurrencyId: currencyId,
    baseCurrencyId,
    stepKey,
    stepLabel,
    steps,
  });
}
