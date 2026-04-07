// src/lib/pricing.utils.ts
// ── DEPENDENCIA INTERNA DEL PRICING ENGINE ───────────────────────────────────
// Utilidades de resolución de lista de precios y aplicación de márgenes.
// Usado por: src/lib/pricing-engine/pricing-engine.sale.ts
//
// NO implementar lógica de negocio adicional aquí.
// Para nuevos cálculos de costo o precio, usar el motor directamente:
//   src/lib/pricing-engine/
// ─────────────────────────────────────────────────────────────────────────────

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
  roundingApplyOn: string;
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

/** Desglose metal/hechura calculado en modo METAL_HECHURA (valores pre-redondeo) */
export type MetalHechuraDetail = {
  metalCost:         number;
  metalSale:         number;
  metalMarginPct:    number;
  hechuraCost:       number;
  hechuraSale:       number;
  hechuraMarginPct:  number;
};

export type PriceResult = {
  value: Prisma.Decimal | null;
  partial: boolean;
  /** Valor antes del redondeo (solo cuando el redondeo cambió el valor) */
  preRounding?: Prisma.Decimal;
  /** Modo de redondeo aplicado (e.g. "INTEGER", "DECIMAL_2", "TEN") */
  roundingMode?: string;
  /** Dirección del redondeo ("UP", "DOWN", "NEAREST") */
  roundingDirection?: string;
  /**
   * Cuando `roundingApplyOn` es "NET" o "TOTAL", el redondeo NO se aplica
   * dentro de applyPriceList sino que el motor lo difiere para aplicarlo
   * después de los descuentos (NET) o después de los impuestos (TOTAL).
   * Este objeto lleva la config necesaria para ese redondeo diferido.
   */
  roundingDeferred?: { mode: string; direction: string; applyOn: "NET" | "TOTAL" };
  /** Solo disponible cuando mode=METAL_HECHURA y hay desglose completo */
  metalHechuraDetail?: MetalHechuraDetail | null;
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
  roundingTarget:    true,
  roundingMode:      true,
  roundingDirection: true,
  roundingApplyOn:   true,
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

export function applyRounding(
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
/** Carga una lista de precios por id, para uso en simulaciones (override). */
export async function resolvePriceListById(
  jewelryId: string,
  priceListId: string
): Promise<ResolvedPriceList | null> {
  const pl = await prisma.priceList.findFirst({
    where: { id: priceListId, jewelryId, deletedAt: null },
    select: PL_COMPUTE_SELECT,
  }) as PriceListData | null;
  if (!pl || !pl.isActive) return null;
  return { priceList: pl, source: "GENERAL" };
}

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
    roundingApplyOn,
  } = priceList;

  let rawPrice: Prisma.Decimal | null = null;
  let partial = false;
  let metalHechuraDetail: MetalHechuraDetail | null = null;

  // ── Cálculo según modo de la lista ──────────────────────────────────────
  if (mode === "MARGIN_TOTAL") {
    if (cost.value == null) return { value: null, partial: true };
    const margin = new D(String(marginTotal ?? "0"));
    rawPrice = cost.value.mul(new D(1).add(margin.div(100)));

  } else if (mode === "METAL_HECHURA") {
    if (cost.metalCost != null && cost.hechuraCost != null) {
      // Ambos componentes disponibles (uno puede ser cero — math correcto igual).
      // marginMetal aplica SOLO sobre metal; marginHechura SOLO sobre hechura.
      const mMarginPct = parseFloat(String(marginMetal ?? "0"));
      const hMarginPct = parseFloat(String(marginHechura ?? "0"));
      const mMargin = new D(String(mMarginPct));
      const hMargin = new D(String(hMarginPct));
      const metalSaleD   = cost.metalCost.mul(new D(1).add(mMargin.div(100)));
      const hechuraSaleD = cost.hechuraCost.mul(new D(1).add(hMargin.div(100)));
      rawPrice = metalSaleD.add(hechuraSaleD);

      // Guardar desglose para que el motor lo incluya en el resultado
      const mc = cost.metalCost.toNumber();
      const hc = cost.hechuraCost.toNumber();
      const ms = metalSaleD.toNumber();
      const hs = hechuraSaleD.toNumber();
      metalHechuraDetail = {
        metalCost:        mc,
        metalSale:        ms,
        metalMarginPct:   mMarginPct,
        hechuraCost:      hc,
        hechuraSale:      hs,
        hechuraMarginPct: hMarginPct,
      };
    } else if (cost.value != null) {
      // Sin desglose de componentes (modo MANUAL o MULTIPLIER):
      // No se puede determinar si hay metal, por lo que marginMetal nunca debe
      // ser el default. Se usa marginHechura como margen de referencia.
      partial = true;
      const margin = new D(String(marginHechura ?? marginMetal ?? marginTotal ?? "0"));
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
  // Si roundingApplyOn === "NET" o "TOTAL", el redondeo se difiere al motor
  // (se aplica después de descuentos o después de impuestos respectivamente).
  // Si roundingApplyOn === "PRICE" (default), se aplica aquí como siempre.
  let preRounding: Prisma.Decimal | undefined;
  let roundingDeferred: PriceResult["roundingDeferred"];

  const hasRounding = roundingTarget !== "NONE" && roundingMode !== "NONE";
  const effectiveApplyOn = (roundingApplyOn as string) || "TOTAL";

  if (hasRounding) {
    if (effectiveApplyOn === "NET" || effectiveApplyOn === "TOTAL") {
      // Diferir al motor — no aplicar aquí
      roundingDeferred = {
        mode:      roundingMode as string,
        direction: roundingDirection as string,
        applyOn:   effectiveApplyOn as "NET" | "TOTAL",
      };
    } else {
      // PRICE (default): aplicar sobre el precio de lista
      const before = rawPrice;
      rawPrice = applyRounding(rawPrice, roundingMode, roundingDirection);
      if (!rawPrice.equals(before)) {
        preRounding = before;
      }
    }
  }

  // ── Precio mínimo ────────────────────────────────────────────────────────
  if (minimumPrice) {
    const min = new D(String(minimumPrice));
    if (rawPrice.lessThan(min)) rawPrice = min;
  }

  return {
    value: rawPrice,
    partial,
    ...(preRounding != null
      ? { preRounding, roundingMode: roundingMode as string, roundingDirection: roundingDirection as string }
      : {}),
    ...(roundingDeferred != null ? { roundingDeferred } : {}),
    ...(metalHechuraDetail != null ? { metalHechuraDetail } : {}),
  };
}
