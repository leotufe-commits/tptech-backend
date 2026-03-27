// src/lib/pricing.utils.ts
// Motor de cálculo de precio de venta: resolución de lista y aplicación de márgenes.

import { Prisma } from "@prisma/client";
import { prisma } from "./prisma.js";

// ---------------------------------------------------------------------------
// Tipos
// ---------------------------------------------------------------------------
type PriceListData = {
  id: string;
  name: string;
  mode: string;
  marginTotal: any;
  marginMetal: any;
  marginHechura: any;
  costPerGram: any;
  surcharge: any;
  minimumPrice: any;
  roundingTarget: string;
  roundingMode: string;
  roundingDirection: string;
  validFrom: Date | null;
  validTo: Date | null;
  isActive: boolean;
};

export type CostBreakdown = {
  value: Prisma.Decimal | null;
  metalCost?: Prisma.Decimal | null;
  hechuraCost?: Prisma.Decimal | null;
  totalGrams?: Prisma.Decimal | null;
};

export type ResolvedPriceList = {
  priceList: PriceListData;
  /** Origen de la lista resuelta (de mayor a menor prioridad) */
  source: "CLIENT" | "CATEGORY" | "GENERAL";
};

export type PriceResult = {
  value: Prisma.Decimal | null;
  partial: boolean;
};

// ---------------------------------------------------------------------------
// Select mínimo para cálculo de precios
// ---------------------------------------------------------------------------
const PL_COMPUTE_SELECT = {
  id:               true,
  name:             true,
  mode:             true,
  marginTotal:      true,
  marginMetal:      true,
  marginHechura:    true,
  costPerGram:      true,
  surcharge:        true,
  minimumPrice:     true,
  roundingTarget:   true,
  roundingMode:     true,
  roundingDirection: true,
  validFrom:        true,
  validTo:          true,
  isActive:         true,
} as const;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function isValidNow(pl: PriceListData): boolean {
  if (!pl.isActive) return false;
  const now = new Date();
  if (pl.validFrom && pl.validFrom > now) return false;
  if (pl.validTo   && pl.validTo   < now) return false;
  return true;
}

function applyRounding(
  value: Prisma.Decimal,
  mode: string,
  direction: string
): Prisma.Decimal {
  if (mode === "NONE") return value;

  const v = value.toNumber();
  let step: number;
  switch (mode) {
    case "INTEGER":   step = 1;    break;
    case "DECIMAL_1": step = 0.1;  break;
    case "DECIMAL_2": step = 0.01; break;
    case "TEN":       step = 10;   break;
    case "HUNDRED":   step = 100;  break;
    default: return value;
  }

  let rounded: number;
  if (direction === "UP") {
    rounded = Math.ceil(v / step) * step;
  } else if (direction === "DOWN") {
    rounded = Math.floor(v / step) * step;
  } else {
    rounded = Math.round(v / step) * step;
  }

  return new Prisma.Decimal(String(rounded));
}

// ---------------------------------------------------------------------------
// resolvePriceList
//  Prioridad:
//    1) Lista habitual del cliente (CommercialEntity.priceListId)
//    2) Lista por defecto de la categoría (ArticleCategory.defaultPriceListId)
//    3) Lista GENERAL favorita activa
//
//  Respeta validFrom / validTo / isActive en todos los niveles.
// ---------------------------------------------------------------------------
export async function resolvePriceList(
  jewelryId: string,
  opts: {
    clientId?:   string | null;
    categoryId?: string | null;
  } = {}
): Promise<ResolvedPriceList | null> {

  // 1. Lista del cliente
  if (opts.clientId) {
    const entity = await prisma.commercialEntity.findFirst({
      where: { id: opts.clientId, jewelryId, deletedAt: null },
      select: { priceList: { select: PL_COMPUTE_SELECT } },
    });
    const pl = entity?.priceList as PriceListData | null | undefined;
    if (pl && isValidNow(pl)) {
      return { priceList: pl, source: "CLIENT" };
    }
  }

  // 2. Lista por defecto de la categoría
  if (opts.categoryId) {
    const cat = await prisma.articleCategory.findFirst({
      where: { id: opts.categoryId, jewelryId, deletedAt: null },
      select: { defaultPriceList: { select: PL_COMPUTE_SELECT } },
    });
    const pl = cat?.defaultPriceList as PriceListData | null | undefined;
    if (pl && isValidNow(pl)) {
      return { priceList: pl, source: "CATEGORY" };
    }
  }

  // 3. Lista GENERAL favorita
  const favPl = await prisma.priceList.findFirst({
    where: {
      jewelryId,
      scope: "GENERAL",
      isFavorite: true,
      isActive: true,
      deletedAt: null,
    },
    select: PL_COMPUTE_SELECT,
    orderBy: { sortOrder: "asc" },
  }) as PriceListData | null;

  if (favPl && isValidNow(favPl)) {
    return { priceList: favPl, source: "GENERAL" };
  }

  return null;
}

// ---------------------------------------------------------------------------
// applyPriceList
//  Aplica márgenes, recargo, redondeo y precio mínimo sobre el costo.
// ---------------------------------------------------------------------------
export function applyPriceList(
  priceList: PriceListData,
  cost: CostBreakdown
): PriceResult {
  const D = Prisma.Decimal;
  const {
    mode, marginTotal, marginMetal, marginHechura, costPerGram,
    surcharge, minimumPrice, roundingTarget, roundingMode, roundingDirection,
  } = priceList;

  let rawPrice: Prisma.Decimal | null = null;
  let partial = false;

  // ── Cálculo según modo de la lista ──────────────────────────────────────
  if (mode === "MARGIN_TOTAL") {
    if (cost.value == null) return { value: null, partial: true };
    const margin = new D(String(marginTotal ?? "0"));
    rawPrice = cost.value.mul(new D(1).add(margin.div(100)));

  } else if (mode === "METAL_HECHURA") {
    if (cost.metalCost != null && cost.hechuraCost != null) {
      const mMargin = new D(String(marginMetal ?? "0"));
      const hMargin = new D(String(marginHechura ?? "0"));
      rawPrice = cost.metalCost.mul(new D(1).add(mMargin.div(100)))
                   .add(cost.hechuraCost.mul(new D(1).add(hMargin.div(100))));
    } else if (cost.value != null) {
      // Sin desglose: fallback con marginMetal como total
      partial = true;
      const margin = new D(String(marginMetal ?? marginTotal ?? "0"));
      rawPrice = cost.value.mul(new D(1).add(margin.div(100)));
    } else {
      return { value: null, partial: true };
    }

  } else if (mode === "COST_PER_GRAM") {
    if (cost.totalGrams == null || !costPerGram) return { value: null, partial: true };
    rawPrice = cost.totalGrams.mul(new D(String(costPerGram)));

  } else {
    return { value: null, partial: true };
  }

  if (rawPrice == null) return { value: null, partial: true };

  // ── Recargo ─────────────────────────────────────────────────────────────
  if (surcharge) {
    rawPrice = rawPrice.mul(new D(1).add(new D(String(surcharge)).div(100)));
  }

  // ── Redondeo ─────────────────────────────────────────────────────────────
  if (roundingTarget !== "NONE" && roundingMode !== "NONE") {
    rawPrice = applyRounding(rawPrice, roundingMode, roundingDirection);
  }

  // ── Precio mínimo ────────────────────────────────────────────────────────
  if (minimumPrice) {
    const min = new D(String(minimumPrice));
    if (rawPrice.lessThan(min)) rawPrice = min;
  }

  return { value: rawPrice, partial };
}
