// src/lib/pricing-engine/pricing-engine.pricelist.ts
// ============================================================================
// Utilidades de lista de precios — resolución y aplicación de márgenes.
//
// Antes vivía en src/lib/pricing.utils.ts. Se absorbió dentro del directorio
// pricing-engine/ para centralizar TODA la lógica comercial en un único motor.
//
// Consumidores: pricing-engine.sale.ts (motor principal) y el barrel
// pricing-engine.ts (que re-exporta `resolvePriceList`, `applyPriceList`,
// `PL_COMPUTE_SELECT` e `isPriceListValidNow`).
//
// Código fuera del directorio pricing-engine/ NO debe importar este archivo.
// Debe consumir del barrel `pricing-engine.ts`.
// ============================================================================

import { Prisma } from "@prisma/client";
import { prisma } from "../prisma.js";

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
  roundingModeHechura: string;
  roundingDirectionHechura: string;
  validFrom: Date | null;
  validTo: Date | null;
  isActive: boolean;
};

export type CostBreakdown = {
  value: Prisma.Decimal | null;
  metalCost?: Prisma.Decimal | null;
  hechuraCost?: Prisma.Decimal | null;
  totalGrams?: Prisma.Decimal | null;
  /** Gramos de metal con merma aplicada (qty × mermaFactor). Propagado desde CostResult. */
  metalGramsWithMerma?: Prisma.Decimal | null;
  /** Sprint 3 — Pureza efectiva del metal (Decimal 0-1). Propagada desde
   *  CostResult.metalPurity para alimentar pureGramsBase. POLICY.md §8. */
  metalPurity?: Prisma.Decimal | null;
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
  /** Gramos base del metal (con merma). Disponible cuando el costo vino de COST_LINES o METAL_MERMA_HECHURA. */
  metalGramsBase?:    number | null;
  /** Gramos de venta = metalGramsBase × (1 + metalMarginPct/100). */
  metalGramsSale?:    number | null;
  /** Precio base por gramo = metalCost / metalGramsBase. Solo para display. */
  metalPricePerGram?: number | null;
  /** Sprint 3 — Gramos puros base = metalGramsBase × purity. Solo cuando el
   *  motor de costo expuso una `metalPurity` única. POLICY.md §8. */
  pureGramsBase?:     number | null;
  /** Sprint 3 — Gramos puros de venta = pureGramsBase × (1 + metalMarginPct/100). */
  pureGramsSale?:     number | null;
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
export const PL_COMPUTE_SELECT = {
  id:               true,
  name:             true,
  mode:             true,
  marginTotal:      true,
  marginMetal:      true,
  marginHechura:    true,
  costPerGram:      true,
  surcharge:        true,
  minimumPrice:     true,
  roundingTarget:           true,
  roundingMode:             true,
  roundingDirection:        true,
  roundingApplyOn:          true,
  roundingModeHechura:      true,
  roundingDirectionHechura: true,
  validFrom:        true,
  validTo:          true,
  isActive:         true,
} as const;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
/**
 * Comprueba si una lista de precios está vigente ahora mismo.
 * Exportada para ser utilizada por cualquier módulo que resuelva listas
 * sin pasar por resolvePriceList (ej: batch pricing en articles.service).
 * Garantiza una única implementación de la lógica de validez temporal.
 */
export function isPriceListValidNow(pl: { isActive: boolean; validFrom: Date | null; validTo: Date | null }): boolean {
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
  if (!pl || !isPriceListValidNow(pl)) return null;
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
    if (pl && isPriceListValidNow(pl)) {
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
    if (pl && isPriceListValidNow(pl)) {
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

  if (favPl && isPriceListValidNow(favPl)) {
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
    roundingApplyOn, roundingModeHechura, roundingDirectionHechura,
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
      let metalSaleD   = cost.metalCost.mul(new D(1).add(mMargin.div(100)));
      let hechuraSaleD = cost.hechuraCost.mul(new D(1).add(hMargin.div(100)));

      // Redondeo por componente (target METAL): se aplica antes de sumar
      if (roundingTarget === "METAL") {
        if (roundingMode !== "NONE") {
          metalSaleD = applyRounding(metalSaleD, roundingMode, roundingDirection);
        }
        const modeH = roundingModeHechura ?? "NONE";
        if (modeH !== "NONE") {
          hechuraSaleD = applyRounding(hechuraSaleD, modeH, roundingDirectionHechura ?? "NEAREST");
        }
      }

      rawPrice = metalSaleD.add(hechuraSaleD);

      // Guardar desglose para que el motor lo incluya en el resultado
      const mc = cost.metalCost.toNumber();
      const hc = cost.hechuraCost.toNumber();
      const ms = metalSaleD.toNumber();
      const hs = hechuraSaleD.toNumber();

      // Representación en gramos: margen sobre gramos, no sobre precio/gr.
      // metalGramsBase  = gramos con merma usados en el costo (qty × mermaFactor)
      // metalPricePerGram = precio promedio por gramo = metalCost / metalGramsBase
      // metalGramsSale  = metalGramsBase × (1 + margin%) → misma matemática, distinta vista
      let metalGramsBase:    number | null = null;
      let metalGramsSale:    number | null = null;
      let metalPricePerGram: number | null = null;
      // Sprint 3 — gramos puros (post purity). Solo se calculan cuando el
      // motor de costo expuso una `metalPurity` única (ver pricing-engine.
      // cost.ts). Si hay heterogeneidad de variantes, ambos quedan null y
      // el frontend muestra "—" (POLICY.md §4 R4.4 / §8).
      let pureGramsBase:     number | null = null;
      let pureGramsSale:     number | null = null;
      if (cost.metalGramsWithMerma != null && cost.metalGramsWithMerma.gt(0) && mc > 0) {
        metalGramsBase    = cost.metalGramsWithMerma.toNumber();
        metalPricePerGram = mc / metalGramsBase;
        metalGramsSale    = metalGramsBase * (1 + mMarginPct / 100);
        if (cost.metalPurity != null) {
          const purityNum = cost.metalPurity.toNumber();
          pureGramsBase   = metalGramsBase * purityNum;
          pureGramsSale   = pureGramsBase * (1 + mMarginPct / 100);
        }
      }

      metalHechuraDetail = {
        metalCost:        mc,
        metalSale:        ms,
        metalMarginPct:   mMarginPct,
        hechuraCost:      hc,
        hechuraSale:      hs,
        hechuraMarginPct: hMarginPct,
        ...(metalGramsBase != null ? { metalGramsBase, metalGramsSale, metalPricePerGram } : {}),
        ...(pureGramsBase  != null ? { pureGramsBase, pureGramsSale } : {}),
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

  // METAL target: rounding was already applied per-component above; skip final rounding.
  const hasRounding = roundingTarget === "FINAL_PRICE" && roundingMode !== "NONE";
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
