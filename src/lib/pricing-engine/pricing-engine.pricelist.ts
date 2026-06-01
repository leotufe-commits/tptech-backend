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
// Etapa C-comercial / C3 — integración del Comercial PHYSICAL (POLICY §R-Rounding-14).
import { resolveCommercialPhysicalRoundingConfig } from "../commercial-physical-rounding-config.js";
import {
  applyCommercialPhysicalRoundingForMetals,
  type CommercialPhysicalRoundingSnapshot,
} from "../commercial-physical-rounding-apply.js";

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
  // Etapa C-comercial / C3 (POLICY §R-Rounding-14) — discriminador del
  // dominio metal del redondeo COMERCIAL. Default `"MONETARY"` ⇒ comportamiento
  // legacy idéntico (redondea subtotal $ del metal). `"PHYSICAL"` activa el
  // nuevo path: redondeo en gramos por metal padre + equivalente monetario
  // que se suma al `metalSale`. `commercialPhysicalRoundingConfig` lleva el
  // shape canónico (mismo que `documentPhysicalRoundingConfig` del financiero).
  commercialRoundingMetalDomain?: string | null;
  commercialPhysicalRoundingConfig?: unknown;
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
  /** Etapa C-comercial / C3 (POLICY §R-Rounding-14) — desglose POR METAL PADRE
   *  consolidado a partir de los steps `COST_LINES_METAL` post-enrich del
   *  motor de costo. Habilitador del path PHYSICAL del redondeo comercial.
   *
   *  Cuando es `null` o `undefined` y la lista pide PHYSICAL, el path se
   *  degrada al fallback MONETARY (no rompe el preview; queda `physical=null`
   *  en el snapshot). Cuando la lista pide MONETARY, este campo se ignora
   *  (camino legacy intacto).
   *
   *  Shape canónico:
   *    metalParentId / metalParentName → id y nombre del PADRE (Oro Fino,
   *      Plata, Platino — nunca variante).
   *    gramsPure  → gramos consolidados al fino de ESTE padre dentro de la
   *      línea (= Σ `step.meta.gramsFineEquivalent` agrupados por `metalId`).
   *    metalPricePerGram → cotización promedio ponderada por gramo del padre
   *      en ESTA línea (= Σ($)/Σ(g) cuando hay heterogeneidad; o el quotePrice
   *      del step cuando hay una sola variante). */
  metalsByParent?: Array<{
    metalParentId:     string;
    metalParentName:   string;
    gramsPure:         number;
    metalPricePerGram: number;
  }> | null;
};

export type ResolvedPriceList = {
  priceList: PriceListData;
  /** Origen de la lista resuelta (de mayor a menor prioridad) */
  source: "CLIENT" | "CATEGORY" | "GENERAL";
};

/** Desglose metal/hechura calculado en modo METAL_HECHURA. `metalSale` y
 *  `hechuraSale` son SIEMPRE el valor POST-redondeo (cualquiera sea el
 *  dominio). Los campos `*PreRounding` / `*RoundingDelta` permiten auditar
 *  cuánto desplazó el redondeo y son nulos cuando no actuó. */
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
  // ── Etapa C-comercial / C3 (POLICY §R-Rounding-14) ────────────────────
  // Auditoría del redondeo comercial — válido para ambos dominios.
  /** `metalSale` ANTES del redondeo (cualquier dominio). `null` cuando no
   *  hubo redondeo (passthrough). */
  metalSalePreRounding?:    number | null;
  /** `hechuraSale` ANTES del redondeo. `null` idem. */
  hechuraSalePreRounding?:  number | null;
  /** `metalSale - metalSalePreRounding`. Cero cuando no actuó. */
  metalSaleRoundingDelta?:  number | null;
  /** `hechuraSale - hechuraSalePreRounding`. */
  hechuraSaleRoundingDelta?:number | null;
  /** Snapshot completo del redondeo COMERCIAL PHYSICAL (capa nueva). Solo
   *  presente cuando la lista operó en `commercialRoundingMetalDomain="PHYSICAL"`
   *  y había `metalsByParent` válidos. `null` en MONETARY (legacy). */
  physical?:                CommercialPhysicalRoundingSnapshot | null;
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
  // Etapa C-comercial / C3 — los lee `applyPriceList` para bifurcar entre el
  // path legacy MONETARY (default) y el nuevo PHYSICAL.
  commercialRoundingMetalDomain:    true,
  commercialPhysicalRoundingConfig: true,
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

/**
 * Opciones de supresión para el gate anti-doble redondeo (Etapa D').
 *
 * Cuando una lista opera con `commercialRoundingScope === "PER_DOCUMENT"`,
 * el redondeo de hechura y/o metal físico se aplica a nivel documento
 * (`computeSaleDocumentTotals` capa nueva). El caller activa estos flags
 * para suprimir el PER_LINE legacy de esta función y evitar que se aplique
 * dos veces.
 *
 * Defaults (`undefined` o `false`): comportamiento legacy PER_LINE intacto.
 */
export interface ApplyPriceListOptions {
  /**
   * Suprime el redondeo PER_LINE del bucket hechura (línea 442 — el
   * `applyRounding(hechuraSaleD, ...)` del path METAL_HECHURA).
   *
   * El caller lo activa cuando el documento opera en scope PER_DOCUMENT
   * y la nueva capa documental se encargará de redondear el saldo monetario
   * agregado.
   */
  suppressLineHechuraRounding?: boolean;
  /**
   * Suprime el redondeo PER_LINE del metal padre cuando opera por
   * componente (`effectiveTarget === "METAL"`). Cubre AMBOS paths:
   *   · path PHYSICAL (`applyCommercialPhysicalRoundingForMetals`)
   *   · path MONETARY legacy (`applyRounding(metalSaleD, ...)`)
   *
   * El caller lo activa cuando el documento opera en scope PER_DOCUMENT
   * y la capa nueva se encargará de redondear los gramos agregados por
   * metal padre a nivel doc.
   */
  suppressLineMetalPhysicalRounding?: boolean;
}

export function applyPriceList(
  priceList: PriceListData,
  cost:      CostBreakdown,
  options?:  ApplyPriceListOptions,
): PriceResult {
  const D = Prisma.Decimal;
  const {
    mode, marginTotal, marginMetal, marginHechura, costPerGram,
    surcharge, minimumPrice, roundingTarget, roundingMode, roundingDirection,
    roundingApplyOn, roundingModeHechura, roundingDirectionHechura,
  } = priceList;

  // ── Coherencia defensiva (fix 2026-05-28): listas migradas pueden
  //    haber quedado con `mode = METAL_HECHURA` pero `roundingTarget = FINAL_PRICE`
  //    (drift legacy del form). En esa combinación, el rounding por componente
  //    nunca se ejecutaba aunque el operador configurara HUNDRED para hechura.
  //
  //    Normalización runtime: si `mode = METAL_HECHURA` y hay rounding activo,
  //    el target efectivo debe ser "METAL" (rounding por componente). Esta
  //    derivación NO persiste — el campo de DB queda como está. Es solo para
  //    el runtime del motor.
  //
  //    Cuando se detecta drift, emitimos un warn para que dev/ops puedan
  //    identificar listas que conviene normalizar en DB en un cleanup futuro.
  const effectiveTarget: string =
    mode === "METAL_HECHURA" && roundingTarget !== "NONE"
      ? "METAL"
      : roundingTarget;
  if (
    mode === "METAL_HECHURA" &&
    roundingTarget !== "METAL" &&
    roundingTarget !== "NONE"
  ) {
    // eslint-disable-next-line no-console
    console.warn(
      "[pricing-engine] normalized inconsistent METAL_HECHURA roundingTarget",
      { roundingTarget, effectiveTarget, priceListId: (priceList as any).id ?? null },
    );
  }

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

      // ── Etapa C-comercial / C3 — bifurcación por dominio del METAL ──────
      // Contrato canónico (POLICY §R-Rounding-14): si la lista pide PHYSICAL
      // y tenemos los gramos por metal padre de ESTA línea (`cost.metalsByParent`),
      // el redondeo del metal se ejecuta en GRAMOS y el equivalente monetario
      // ajusta `metalSaleD`. Si la lista es MONETARY o el motor de costo no
      // expuso `metalsByParent`, se cae al path legacy (redondeo $ del metal).
      // La HECHURA queda intacta — siempre monetaria por contrato canónico.
      const commercialPhysicalCfg = resolveCommercialPhysicalRoundingConfig({
        commercialRoundingMetalDomain:
          (priceList as any).commercialRoundingMetalDomain ?? null,
        commercialPhysicalRoundingConfig:
          (priceList as any).commercialPhysicalRoundingConfig ?? null,
      });
      const physicalEnabled =
        commercialPhysicalCfg.enabled &&
        Array.isArray(cost.metalsByParent) &&
        cost.metalsByParent.length > 0;

      // Capturas pre-redondeo (auditoría — válidas para los dos dominios).
      const metalSalePreRounding   = metalSaleD.toNumber();
      const hechuraSalePreRounding = hechuraSaleD.toNumber();
      // DEBUG TEMPORAL 2026-05-28 — captura pre/post para diagnóstico del
      // bug reportado "hechura desglosada no redondea en producción".
      // Quitar este log una vez confirmado el comportamiento en producción.
      const __debugHechuraBefore = hechuraSalePreRounding;
      const __debugMetalBefore   = metalSalePreRounding;

      let commercialPhysicalSnapshot: CommercialPhysicalRoundingSnapshot | null = null;

      if (effectiveTarget === "METAL") {
        // ── Gate anti-doble (Etapa D') ────────────────────────────────────
        // Cuando la lista opera en scope PER_DOCUMENT, suppressLineMetal
        // PhysicalRounding=true y el redondeo del metal se hace a nivel
        // documento. Acá NO ejecutamos ni el path PHYSICAL ni el path
        // MONETARY legacy; la captura `commercialPhysicalSnapshot` queda
        // null para que el caller pueda diagnosticarlo.
        const suppressMetalLine = options?.suppressLineMetalPhysicalRounding === true;
        if (!suppressMetalLine) {
          if (physicalEnabled) {
            // ── Path PHYSICAL ─────────────────────────────────────────────
            // Redondea gramos POR METAL PADRE de la línea con la matemática
            // del helper neutral (`roundDocumentMetalGrams`) — misma usada
            // por el Financiero PHYSICAL. La suma de `monetaryEquivalent`
            // (Δgramos × metalPricePerGram) se aplica como ajuste $ sobre
            // `metalSaleD` (sin tocar la hechura, sin contaminar el bucket
            // monetario — regla canónica).
            const physicalResult = applyCommercialPhysicalRoundingForMetals({
              metals: cost.metalsByParent!.map((m) => ({
                metalParentId:     m.metalParentId,
                metalParentName:   m.metalParentName,
                grams:             m.gramsPure,
                metalPricePerGram: m.metalPricePerGram,
              })),
              configByMetalParentId: commercialPhysicalCfg.configByMetalParentId,
              fallbackConfig:        commercialPhysicalCfg.fallbackConfig,
            });
            commercialPhysicalSnapshot = {
              metals: physicalResult.metals.map((e) => ({
                ...e,
                // `applyCommercialPhysicalRoundingForMetals` ya emite `source =
                // "COMMERCIAL_PHYSICAL_ROUNDING"`; el cast estricto es necesario
                // porque el shape genérico admite la unión.
                source: "COMMERCIAL_PHYSICAL_ROUNDING" as const,
              })),
              metalMonetaryEquivalent: physicalResult.metalMonetaryEquivalent,
              fallback:                physicalResult.fallback,
            };
            if (physicalResult.metalMonetaryEquivalent !== 0) {
              metalSaleD = metalSaleD.add(
                new D(String(physicalResult.metalMonetaryEquivalent)),
              );
            }
          } else {
            // ── Path MONETARY (legacy / default) ───────────────────────────
            if (roundingMode !== "NONE") {
              metalSaleD = applyRounding(metalSaleD, roundingMode, roundingDirection);
            }
          }
        }
        // ── Gate anti-doble — hechura (Etapa D') ──────────────────────────
        // Cuando suppressLineHechuraRounding=true, el redondeo del bucket
        // hechura/saldo se aplica a nivel documento. Acá NO ejecutamos.
        // Hechura — SIEMPRE monetaria por contrato canónico (POLICY
        // §R-Rounding-14). No depende del dominio del metal.
        const modeH = roundingModeHechura ?? "NONE";
        const suppressHechuraLine = options?.suppressLineHechuraRounding === true;
        if (modeH !== "NONE" && !suppressHechuraLine) {
          hechuraSaleD = applyRounding(hechuraSaleD, modeH, roundingDirectionHechura ?? "NEAREST");
        }
      }
      if (process.env.TPTECH_DEBUG_ROUNDING === "1") {
        // eslint-disable-next-line no-console
        console.log("[PRICE_LIST_BREAKDOWN_ROUNDING_DEBUG]", {
          priceListId:                (priceList as any).id ?? null,
          priceListName:              (priceList as any).name ?? null,
          mode,
          roundingTarget,
          effectiveTarget,
          roundingMode,
          roundingDirection,
          roundingModeHechura:        roundingModeHechura ?? null,
          roundingDirectionHechura:   roundingDirectionHechura ?? null,
          roundingApplyOn,
          metalBeforeRounding:        __debugMetalBefore,
          metalAfterRounding:         metalSaleD.toNumber(),
          hechuraBeforeRounding:      __debugHechuraBefore,
          hechuraAfterRounding:       hechuraSaleD.toNumber(),
          willApplyComponentRounding: effectiveTarget === "METAL",
        });
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

      // Etapa C-comercial / C3 — calculamos deltas auditables. Solo emitimos
      // `*PreRounding` cuando hubo cambio (passthrough exacto cuando no actuó).
      const metalActed   = effectiveTarget === "METAL" &&
        (commercialPhysicalSnapshot != null || roundingMode !== "NONE") &&
        ms !== metalSalePreRounding;
      const hechuraActed = effectiveTarget === "METAL" &&
        (roundingModeHechura ?? "NONE") !== "NONE" &&
        hs !== hechuraSalePreRounding;
      const metalSaleRoundingDelta   = metalActed
        ? Math.round((ms - metalSalePreRounding) * 100) / 100
        : null;
      const hechuraSaleRoundingDelta = hechuraActed
        ? Math.round((hs - hechuraSalePreRounding) * 100) / 100
        : null;

      metalHechuraDetail = {
        metalCost:        mc,
        metalSale:        ms,
        metalMarginPct:   mMarginPct,
        hechuraCost:      hc,
        hechuraSale:      hs,
        hechuraMarginPct: hMarginPct,
        ...(metalGramsBase != null ? { metalGramsBase, metalGramsSale, metalPricePerGram } : {}),
        ...(pureGramsBase  != null ? { pureGramsBase, pureGramsSale } : {}),
        // Etapa C-comercial / C3 — campos de auditoría del redondeo comercial.
        ...(metalActed   ? { metalSalePreRounding,   metalSaleRoundingDelta }   : {}),
        ...(hechuraActed ? { hechuraSalePreRounding, hechuraSaleRoundingDelta } : {}),
        // Snapshot PHYSICAL solo cuando la nueva capa actuó.
        physical: commercialPhysicalSnapshot,
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
  // Usa `effectiveTarget` para que listas METAL_HECHURA con drift legacy
  // (target persistido = FINAL_PRICE) NO ejecuten el rounding final
  // (que duplicaría el rounding por componente que recién se aplicó arriba).
  const hasRounding = effectiveTarget === "FINAL_PRICE" && roundingMode !== "NONE";
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

  // ── Fallback: roundingTarget=METAL con cost SIN desglose (bug rep. 2026-05-28)
  //
  // Caso defensivo: la lista está configurada en modo METAL_HECHURA con
  // `roundingTarget=METAL` (rounding por componente) PERO el artículo cayó a
  // la rama "partial" porque su `cost` no expone `metalCost`/`hechuraCost`
  // (artículos legacy / MULTIPLIER / MANUAL). Sin este fallback, el rounding
  // configurado por el operador NO se aplica → usuario ve precio crudo (caso
  // reportado: hechura 59.384,06 esperando 59.400 con HUNDRED).
  //
  // Solución: cuando target=METAL pero NO hubo desglose, aplicar el rounding
  // del componente HECHURA sobre el `rawPrice` agregado (la rama partial usó
  // `marginHechura` sobre el costo total, así que el componente efectivo es
  // hechura). Esto preserva el contrato del operador sin tocar el caso
  // happy-path (cost con desglose, que ya redondea por componente arriba).
  if (
    effectiveTarget === "METAL" &&
    metalHechuraDetail == null &&        // ← cost sin desglose → no se ejecutó el bloque 284-292
    roundingModeHechura &&
    roundingModeHechura !== "NONE" &&
    // Gate anti-doble (Etapa D'): si el caller suprimió el redondeo PER_LINE
    // de hechura, este fallback también queda fuera. El redondeo del bucket
    // hechura/saldo va a aplicarse a nivel documento.
    options?.suppressLineHechuraRounding !== true
  ) {
    const before = rawPrice;
    rawPrice = applyRounding(
      rawPrice,
      roundingModeHechura,
      (roundingDirectionHechura ?? "NEAREST") as string,
    );
    if (!rawPrice.equals(before) && preRounding == null) {
      preRounding = before;
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
