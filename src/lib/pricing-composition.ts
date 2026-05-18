// src/lib/pricing-composition.ts
// ============================================================================
// Helpers de armado del bloque `composition` (metal / hechura / taxes) que se
// expone en los responses de pricing preview de articles y de sales.
//
// VIVE FUERA del directorio `pricing-engine/` a propósito: no toca el motor
// de cálculo, sólo lee `SalePriceResult.costOverrideContext` y `taxBreakdown`
// para armar la estructura de display compartida entre los dos endpoints.
//
// Antes de Fase 2A.7 esta lógica vivía únicamente dentro de
// `articles.controller.ts` (líneas ~1257-1296) y `sales/preview` no la
// exponía. Al extraerla acá, ambos endpoints producen exactamente el mismo
// shape sin duplicar lógica.
// ============================================================================

import { prisma } from "./prisma.js";
import type { SalePriceResult, PricingStep } from "./pricing-engine/pricing-engine.js";

// ---------------------------------------------------------------------------
// Tipos exportados
// ---------------------------------------------------------------------------

export type MetalVariantInfo = {
  purity:      number | null;
  purityLabel: string | null;
  metalName:   string | null;
  /**
   * Fase 2.4 — nombre comercial completo de la variante (= `MetalVariant.name`),
   * tal como aparece en la pantalla Divisas/Variantes (ej. "Oro 18 Kilates",
   * "Chafalonia 18 Kilates"). El frontend lo prefiere para el primary en
   * la fila METAL; cae a `metalName + purityLabel` cuando falta.
   */
  variantName: string | null;
};

export type CompositionMetalBlock = {
  originalGrams:     number | null;
  appliedGrams:      number | null;
  gramsManual:       boolean;
  originalMermaPct:  number | null;
  appliedMermaPct:   number | null;
  mermaManual:       boolean;
  originalVariantId: string | null;
  appliedVariantId:  string | null;
  variantManual:     boolean;
  purity:            number | null;
  purityLabel:       string | null;
  metalName:         string | null;
};

export type CompositionHechuraBlock = {
  originalAmount: number | null;
  appliedAmount:  number | null;
  manual:         boolean;
  appliesTo:      string | null;
};

/**
 * F1.3 G4.x #9-A — item de `composition.metals[]`. Uno por cada cost line
 * de tipo METAL del artículo. El motor cost emite un step
 * `COST_LINES_METAL` por línea (ver pricing-engine.cost.ts:211); este
 * shape mapea cada step a un item visualizable.
 *
 * Reader-only (POLICY R4.5): cero matemática derivada. `lineCost` es
 * `step.value` directo del motor (en moneda BASE del tenant).
 *
 * Notas de scope (decisiones D1/D2/D3 confirmadas):
 *   · NO incluye `originalGrams`/`gramsManual`/`originalMermaPct`/etc.
 *     Esos flags solo aplican al PRIMER item via override context y se
 *     mantienen en el alias legacy `metal` (=metals[0] enriquecido).
 *   · NO incluye `metalSale` (sale-side post-margen) — el motor agrega
 *     ese valor solo en `metalHechuraBreakdown` agregado, no per item.
 *     La UI lo muestra solo en el primer item via legacy.
 */
export type CompositionMetalItem = {
  /** ArticleCostLine.id — estable, snapshot-safe. */
  costLineId:        string | null;
  /** MetalVariant.id de esta línea METAL. */
  metalVariantId:    string | null;
  /** Resuelto vía batch query desde MetalVariant + Metal. null si la
   *  variante no se pudo resolver (ej. eliminada). */
  metalName:         string | null;
  /**
   * Fase 2.4 — nombre comercial completo de la variante (= `MetalVariant.name`).
   * Ejemplo: "Oro 18 Kilates" / "Chafalonia 18 Kilates". El frontend lo
   * usa como primary en la fila METAL; cae a `metalName + purityLabel`
   * cuando falta (snapshots viejos).
   */
  variantName:       string | null;
  purity:            number | null;
  purityLabel:       string | null;
  /** `quantity` original de la cost line (gramos físicos sin merma). */
  appliedGrams:      number | null;
  /** Merma efectiva aplicada por el motor (entity override > line). */
  appliedMermaPct:   number | null;
  /** Costo individual de esta línea = step.value del motor (en BASE).
   *  La suma de `lineCost` de todos los items === metalCost agregado. */
  lineCost:          number | null;
  /**
   * F1.5 #A++ — sale-side per cost-line METAL (passthrough). Calculado por el
   * motor como `lineCost × (metalSale / metalCost)` desde el
   * `metalHechuraBreakdown`. NO es derivación frontend: el motor agrupa todos
   * los METAL bajo un único `metalCost`/`metalSale` y el margen aplica
   * uniformemente al bucket, por lo tanto exponer el sale-side per línea es
   * passthrough del cálculo que el motor ya hace internamente.
   *
   * Paridad garantizada (modulo redondeo Decimal):
   *   `Σ metals[i].lineSale === metalHechuraBreakdown.metalSale`.
   *
   * `null` cuando no se pudo derivar (sin breakdown, lista MARGIN_TOTAL sin
   * desglose, snapshot legacy pre v7). Resuelve el bug "los metales muestran
   * '—' en Vista comercial cuando hay múltiples metales" y elimina el
   * prorrateo manual del Simulador (POLICY R4.1).
   */
  lineSale:          number | null;
  /**
   * Fase 2.3 — precio por gramo BASE (sin merma aplicada). Viene de
   * `step.meta.quotePrice` que el motor cost emite directo desde la
   * `MetalQuote.suggestedPrice`. El frontend lo usa como columna
   * "Val. unit." (base) en METAL — antes la columna mostraba post-merma
   * por falta de este campo.
   *
   * lineCost === appliedGrams × quotePrice × (1 + appliedMermaPct/100).
   */
  quotePrice:        number | null;
  /**
   * FASE F2 — origen de la merma efectiva aplicada por el motor.
   * Passthrough de `step.meta.mermaSource`:
   *   · "costLineOverride" → override manual del operador.
   *   · "entity"           → `EntityMermaOverride` del cliente.
   *   · "line"             → catálogo (`ArticleCostLine.mermaPercent`).
   *   · "default"          → sin merma (0).
   * Aditivo y opcional para mantener compat con steps viejos.
   */
  mermaSource?:      "costLineOverride" | "entity" | "line" | "default" | null;
  /**
   * FASE F3 — costo de la línea **sin merma comercial**.
   * = `appliedGrams × quotePrice` cuando ambos están disponibles, si no `null`.
   * Aditivo y opcional. Permite al frontend mostrar "Metal puro" en el
   * header del grupo METALES sin recalcular nada.
   */
  lineCostBase?:     number | null;
};

/**
 * F1.3 G4.x #9-A — item de `composition.hechuras[]`. Uno por cada cost
 * line de tipo HECHURA del artículo. Mismo patrón que CompositionMetalItem.
 *
 * Notas de scope:
 *   · NO incluye `manual`/`originalAmount` — flags solo aplican al primer
 *     item via override context (alias legacy `hechura`).
 */
export type CompositionHechuraItem = {
  /** ArticleCostLine.id — estable, snapshot-safe. */
  costLineId:        string | null;
  /** Valor unitario aplicado de esta línea HECHURA (`step.value` del motor
   *  POST-ajuste). NOTA: este campo trae el valor con bonif/recargo ya
   *  aplicado. Para mostrar el valor BASE pre-ajuste, usar `unitValue`. */
  appliedAmount:     number | null;
  /**
   * Fase 2.3.1 — valor unitario BASE (pre-ajuste). Viene de
   * `meta.unitValue` del cost engine (idéntico a `meta.unitValue` que ya
   * exponen PRODUCT/SERVICE). Sin este campo, la UI mostraba el valor
   * post-ajuste como si fuera base.
   *
   * lineCost (post-ajuste) === unitValue × qty + lineAdjAmount (signed).
   */
  unitValue:         number | null;
  /**
   * `unitValue × rate` — costo unitario en moneda BASE, **post-conversión**
   * pero **pre-ajuste**. Display-only — el motor ya tiene ambos factores
   * separados (`meta.unitValue` + `meta.rate`); este campo es la
   * multiplicación trivial. Permite que la UI muestre "USD 75,76 ≈ ARS X"
   * como conversión directa sin incluir el ajuste de la columna Merma/Ajuste,
   * evitando la percepción de doble descuento.
   *
   * Cuando no hubo conversión (cost line en moneda base) `unitValueBase`
   * coincide con `unitValue`. Cuando `unitValue` no está disponible →
   * undefined (frontend cae al fallback anterior).
   */
  unitValueBase?:    number;
  /** Costo individual de esta línea = step.value del motor (en BASE).
   *  La suma de `lineCost` de todos los items === hechuraCost agregado. */
  lineCost:          number | null;
  /**
   * F1.5 #A+ — sale-side per línea (passthrough). Calculado por el motor como
   * `lineCost × adjFactorGlobalCost × (1 + hechuraMarginPct/100)`. NO es
   * derivación frontend: el motor agrupa HECHURA+PRODUCT+SERVICE bajo
   * `hechuraCost` (cost.ts:334-336) y el margen sale-side `hechuraMarginPct`
   * aplica al bucket entero, por lo tanto exponer el sale-side per línea
   * es passthrough del cálculo que el motor ya hace internamente.
   *
   * Paridad garantizada (sin redondeo intermedio):
   *   `Σ products.lineSale + Σ services.lineSale + Σ hechuras.lineSale ===
   *    hechuraSale del metalHechuraBreakdown`.
   *
   * `null` cuando no se pudo derivar (sin breakdown, sin margen, sin
   * lineCost). Snapshots viejos (pre v7) caen aquí. */
  lineSale:          number | null;
  /** Etiqueta legible (label de la cost line, ej. "Mano de obra"). */
  lineLabel:         string | null;
  /** Unidad seleccionada por el operador en el modal del artículo (`u`, `g`,
   *  `hr`, etc., persistida en `ArticleCostLine.quantityUnit`). Display-only —
   *  passthrough desde `step.meta.quantityUnit` que el motor emite sin
   *  participar en cálculos. Frontend cae a fallback "Unidades" cuando es
   *  vacío o undefined (snapshots viejos o legacy). */
  quantityUnit?:     string;
  /**
   * Cantidad del cost line por unidad de artículo (= `ArticleCostLine.quantity`,
   * con `quantityOverride` aplicado si lo hubiera). Viene de `step.meta.qty`
   * que el motor cost ya emite — passthrough display, cero recálculo.
   *
   * Paridad con PRODUCT/SERVICE (que exponen `quantity` desde la primera
   * versión). Antes el extractor descartaba este campo para HECHURA y el
   * frontend caía a `1` hardcoded → pérdida de trazabilidad cuando un
   * cost line tenía `qty > 1` (ej. mano de obra desglosada por horas).
   *
   * Opcional para compatibilidad con snapshots viejos: el frontend cae a
   * `1` cuando este campo no está. */
  quantity?:         number;
  /** Id de la moneda original del cost line (= `ArticleCostLine.currencyId`).
   *  Sólo se emite cuando el motor registra `fromCurrencyId` en `conversionMeta`
   *  (es decir, hubo conversión efectiva a moneda base). Snapshots sin
   *  conversión efectiva o sin el campo → frontend cae a moneda del documento. */
  currencyId?:       string | null;
  /** Code ISO de la moneda original (ej. "USD"). Passthrough display desde
   *  `step.meta.currencyCode` cuando hubo conversión. */
  currencyCode?:     string | null;
  /** Símbolo de la moneda original (ej. "US$"). Passthrough display desde
   *  `step.meta.currencySymbol`. */
  currencySymbol?:   string | null;
  // Fase 2.2 — paridad con PRODUCT/SERVICE: el motor cost SÍ emite
  // `meta.lineAdjKind/Type/Value/Amount` para HECHURA cuando la cost line
  // del artículo trae ajuste configurado. Antes el extractor los descartaba
  // y el frontend no podía mostrar "Bonif/Recargo" original en la columna
  // AJUSTE. Aditivo, opcional — snapshots viejos sin estos campos quedan
  // en `null`.
  /** "BONUS" | "SURCHARGE" | null. */
  lineAdjKind:       "BONUS" | "SURCHARGE" | null;
  /** "PERCENTAGE" | "FIXED_AMOUNT" | null. */
  lineAdjType:       "PERCENTAGE" | "FIXED_AMOUNT" | null;
  /** Valor del ajuste (% o monto fijo según `lineAdjType`). */
  lineAdjValue:      number | null;
  /** Monto absoluto resultante del ajuste (post motor cost; ya redondeado).
   *  Frontend lo muestra como "−ARS X" (BONUS) o "+ARS X" (SURCHARGE)
   *  sin recalcular. */
  lineAdjAmount:     number | null;
};

export type CompositionTaxItem = {
  id:        string;
  name:      string;
  code:      string;
  rate:      number | null;
  appliesTo: string;
  taxAmount: number;
  manual:    boolean;
};

/**
 * Fase 2.5 — bloque de "Ajuste global de costo" (Article.manualAdjustment*).
 *
 * Es el ajuste que el operador configura en el modal del artículo
 * (Bonificación / Recargo) y aplica sobre la SUMA de todas las cost
 * lines (post merma metal y post lineAdj de cada componente). Se traduce
 * en `step.meta.adjustmentKind/Type/Value` del step `COST_LINES_FINAL`.
 *
 * Distinto de:
 *   · `lineAdj*` per cost line (PRODUCT/SERVICE/HECHURA) — Fase 2.2.
 *   · `lineManualDiscount` per línea de venta (appliesTo=TOTAL) — Fase 2.x.
 *   · `channel/coupon/payment/shipping/globalDiscount` (doc-level).
 *
 * Cuando el artículo no tiene ajuste configurado (`kind=""`), este bloque
 * queda `null` y la UI oculta el chip.
 */
export type CompositionCostAdjustment = {
  /** "BONUS" | "SURCHARGE". null cuando no hay ajuste configurado. */
  kind:   "BONUS" | "SURCHARGE" | null;
  /** "PERCENTAGE" | "FIXED_AMOUNT". null cuando no hay ajuste. */
  type:   "PERCENTAGE" | "FIXED_AMOUNT" | null;
  /** Valor configurado (% o monto fijo según `type`). */
  value:  number | null;
  /**
   * Monto absoluto del impacto del ajuste (signed: positivo = reducción,
   * negativo = aumento). Calculado por el motor como
   * `sumLines - adjustedTotal`. Cero recálculo en frontend.
   */
  amount: number | null;
};

/**
 * FASE F1.3 G4.1 — bloque per-item para PRODUCT y SERVICE.
 *
 * Cada cost line de tipo PRODUCT o SERVICE se expone como un item separado
 * (no se bucketean en hechura como hacía el motor por convención interna).
 * Permite a la UI mostrar cada componente del costo con su trazabilidad
 * completa (catalog ref, cantidad, ajuste per-línea, impacto stock).
 *
 * Campos opcionales (`null` o ausentes) cuando el motor no los expone:
 *   · `costLineId`, `catalogItemId`, `affectsStock` — requieren extensión
 *     del motor (commit G4.1.2). Hoy quedan null por compatibilidad.
 *   · `catalogItemCode` / `catalogItemName` — vienen del catálogo
 *     pre-cargado por el caller (Map opcional pasado a buildComposition).
 *
 * POLICY R4.5 — la UI lee passthrough; cero cálculo monetario derivado.
 */
export type CompositionItemBlock = {
  /** ArticleCostLine.id — null hasta que el motor lo exponga en step.meta. */
  costLineId:       string | null;
  /** Article.id referenciado (PRODUCT/SERVICE apuntan a otro artículo). */
  catalogItemId:    string | null;
  /** Código del catálogo (ej "PIEDRA-Z01"). Ya viene en step.meta.lineCode. */
  catalogItemCode:  string | null;
  /**
   * Fase 2.4 — SKU del Article catálogo referenciado (= `Article.sku`).
   * Distinto a `catalogItemCode` (= `Article.code`). El frontend lo prefiere
   * en la columna COMPONENTE; cae a `catalogItemCode` cuando falta.
   * Resuelto desde el catalog map; null si el Article fue eliminado o el
   * map no se pudo construir.
   */
  catalogItemSku:   string | null;
  /** Nombre legible (ej "Zafiro 0.5ct"). Resuelto desde catalog map o
   *  fallback a step.meta.lineLabel. */
  catalogItemName:  string | null;
  /** Cantidad del componente (ej. 2 piedras). */
  quantity:         number;
  /** Valor unitario en moneda del componente. */
  unitValue:        number;
  /** Unidad seleccionada por el operador en el modal del artículo
   *  (`u`, `g`, `hr`, etc.). Passthrough display desde `step.meta.quantityUnit`. */
  quantityUnit?:    string;
  /**
   * `unitValue × rate` — display-only, costo unitario en moneda BASE
   * post-conversión, pre-ajuste. Ver `CompositionHechuraItem.unitValueBase`. */
  unitValueBase?:   number;
  /** Total del item = quantity × unitValue (lo computa el motor en step.value). */
  totalValue:       number;
  /** Moneda original del componente (null = moneda base del tenant). */
  currencyId:       string | null;
  /** Code ISO de la moneda original (ej. "USD"). Passthrough display desde
   *  `step.meta.currencyCode` cuando el motor registró conversión. Opcional —
   *  cuando es null el frontend asume moneda base del documento. */
  currencyCode?:    string | null;
  /** Símbolo de la moneda original (ej. "US$"). Passthrough display desde
   *  `step.meta.currencySymbol`. Opcional. */
  currencySymbol?:  string | null;
  /** Unidad de medida del Article referenciado (`Article.unitOfMeasure`, ej.
   *  "unidad", "par", "set"). Resuelto desde el catalog map para que la UI
   *  no dependa del catálogo del tenant. null cuando el catalog map no lo
   *  resolvió o el Article maestro no la tenía definida. */
  quantityUnitName?: string | null;
  /** Tipo de ajuste per-línea ("BONUS" o "SURCHARGE"), si lo hay. */
  lineAdjKind:      "BONUS" | "SURCHARGE" | null;
  /** Tipo del valor del ajuste ("PERCENTAGE" o "FIXED_AMOUNT"). */
  lineAdjType:      "PERCENTAGE" | "FIXED_AMOUNT" | null;
  /** Valor configurado del ajuste (ej. 10 cuando es PERCENTAGE 10%). */
  lineAdjValue:     number | null;
  /** Monto absoluto del ajuste — null hasta que el motor lo exponga
   *  explícitamente (G4.1.2). Mientras tanto, la UI puede derivarlo
   *  como display-only si lo necesita (no es cálculo monetario crítico). */
  lineAdjAmount:    number | null;
  /** Si esta cost line descuenta stock al confirmar venta (PRODUCT/SERVICE).
   *  Default false — null hasta que el motor lo exponga (G4.1.2). */
  affectsStock:     boolean | null;
  /**
   * F1.5 #A+ — sale-side per línea (passthrough). Ver `CompositionHechuraItem.lineSale`
   * para la definición completa. PRODUCT/SERVICE comparten margen con HECHURA
   * porque el motor los agrupa en el mismo bucket (`cost.ts:334-336`).
   *
   * `null` cuando no se pudo derivar (sin breakdown, sin margen, sin totalValue).
   * Snapshots viejos (pre v7) caen aquí. */
  lineSale:         number | null;
};

export type Composition = {
  /**
   * F1.3 G4.x #9-A — alias LEGACY equivalente a `metals[0] ?? null`.
   *
   * INVARIANTE GARANTIZADO POR `buildComposition`:
   *   `composition.metal === composition.metals[0] ?? null`  (estructural)
   * Cualquier consumer que dependa de `metal` como objeto único sigue
   * funcionando. Para soportar múltiples METAL, leer `metals[]`.
   *
   * El alias enriquece el item con flags del costOverrideContext
   * (originalGrams, gramsManual, etc.) que el motor solo trackea para
   * el PRIMER METAL. Items 2+ son read-only display sin esos flags.
   */
  metal:   CompositionMetalBlock | null;
  /** F1.3 G4.x #9-A — alias LEGACY = `hechuras[0] ?? null`. Mismo
   *  contrato que `metal`/`metals[]`. */
  hechura: CompositionHechuraBlock | null;
  /** F1.3 G4.x #9-A — TODAS las cost lines de tipo METAL del artículo,
   *  una por step `COST_LINES_METAL`. SIEMPRE array (nunca undefined),
   *  vacío cuando el artículo no tiene METAL lines. */
  metals:   CompositionMetalItem[];
  /** F1.3 G4.x #9-A — TODAS las cost lines de tipo HECHURA. SIEMPRE array. */
  hechuras: CompositionHechuraItem[];
  /** F1.3 G4.1 — array de cost lines de tipo PRODUCT (insumos / productos
   *  externos). Vacío cuando el artículo no tiene PRODUCT lines. La UI
   *  rendereiza un bloque por item (no bucketean en hechura). */
  products: CompositionItemBlock[];
  /** F1.3 G4.1 — array de cost lines de tipo SERVICE (servicios externos).
   *  Mismo tratamiento que products. */
  services: CompositionItemBlock[];
  taxes:   CompositionTaxItem[];
  /**
   * Fase 2.5 — ajuste global de costo del artículo (Bonif/Recargo del modal).
   * `null` cuando el artículo no tiene `manualAdjustmentKind` configurado
   * o cuando el step `COST_LINES_FINAL` no fue emitido (caso degenerado).
   * Aditivo / opcional: snapshots viejos sin este campo lo leen como
   * `undefined` → frontend lo trata igual que `null` (oculto).
   */
  costAdjustment?: CompositionCostAdjustment | null;
};

// ---------------------------------------------------------------------------
// Métodos públicos
// ---------------------------------------------------------------------------

const EMPTY_METAL_VARIANT_INFO: MetalVariantInfo = {
  purity:      null,
  purityLabel: null,
  metalName:   null,
  variantName: null,
};

/**
 * Devuelve `purity / purityLabel / metalName` desde el modelo `MetalVariant`.
 * El motor no necesita la pureza para calcular precios — esta info es sólo
 * para mostrar en la composición.
 *
 * Si `metalVariantId` es `null` o no existe en DB, devuelve un objeto con
 * los tres campos en `null`.
 */
export async function fetchMetalVariantInfo(
  metalVariantId: string | null,
): Promise<MetalVariantInfo> {
  if (!metalVariantId) return EMPTY_METAL_VARIANT_INFO;

  const mv = await prisma.metalVariant.findUnique({
    where:  { id: metalVariantId },
    select: {
      purity: true,
      name:   true,
      metal:  { select: { name: true } },
    },
  });
  if (!mv) return EMPTY_METAL_VARIANT_INFO;

  const purityNum = mv.purity != null ? parseFloat(mv.purity.toString()) : null;
  let label: string | null = null;
  if (purityNum != null && purityNum > 0) {
    // Heurística: si parece quilatage (0 < p ≤ 1) → multiplicar × 24 y "k".
    if (purityNum <= 1) {
      const k = Math.round(purityNum * 24);
      label = `${k}k`;
    } else {
      // Ya viene en quilates u otra unidad → mostrar como número entero.
      label = `${Math.round(purityNum)}k`;
    }
  } else {
    label = mv.name;
  }
  return {
    purity:      purityNum,
    purityLabel: label,
    metalName:   mv.metal?.name ?? null,
    // Fase 2.4 — el SELECT ya trae `mv.name`. Lo exponemos directo
    // (sin trim/transformación; cero matemática nueva).
    variantName: mv.name ?? null,
  };
}

/**
 * Resuelve cuál `metalVariantId` usar para `fetchMetalVariantInfo`. Idéntica
 * heurística a la del controller original (`articles.controller.ts:1147-1150`):
 * primero el aplicado, luego el original. Devuelve `null` si no hay ninguno.
 */
export function resolveMetalVariantIdFromResult(
  result: SalePriceResult | null | undefined,
): string | null {
  return (
    result?.costOverrideContext?.metalVariant?.appliedId ??
    result?.costOverrideContext?.metalVariant?.originalId ??
    null
  );
}

/**
 * F1.3 G4.x #9-A (D3 confirmado) — batch metalVariant info por id.
 * UNA query con dedupe global, mismo patrón que
 * `buildCatalogItemsMapForCostLines`. Failure-safe: si Prisma falla, Map
 * vacío + warning, los items renderean con metalName=null.
 *
 * IMPORTANTE — cuándo llamar:
 *   · UNA vez por preview (post-engine, pre-buildComposition).
 *   · NO per item, NO dentro de buildComposition.
 */
export async function fetchMetalVariantInfoMap(
  metalVariantIds: Array<string | null | undefined>,
): Promise<Map<string, MetalVariantInfo>> {
  const empty = new Map<string, MetalVariantInfo>();
  const ids = new Set<string>();
  for (const id of metalVariantIds) {
    if (typeof id === "string" && id.length > 0) ids.add(id);
  }
  if (ids.size === 0) return empty;

  try {
    const rows = await prisma.metalVariant.findMany({
      where:  { id: { in: [...ids] } },
      select: {
        id:     true,
        purity: true,
        name:   true,
        metal:  { select: { name: true } },
      },
    });
    const map = new Map<string, MetalVariantInfo>();
    for (const mv of rows) {
      const purityNum = mv.purity != null ? parseFloat(mv.purity.toString()) : null;
      let label: string | null = null;
      if (purityNum != null && purityNum > 0) {
        if (purityNum <= 1) {
          const k = Math.round(purityNum * 24);
          label = `${k}k`;
        } else {
          label = `${Math.round(purityNum)}k`;
        }
      } else {
        label = mv.name;
      }
      map.set(mv.id, {
        purity:      purityNum,
        purityLabel: label,
        metalName:   mv.metal?.name ?? null,
        // Fase 2.4 — paridad con `fetchMetalVariantInfo`.
        variantName: mv.name ?? null,
      });
    }
    return map;
  } catch (err) {
    // Failure-safety: NO romper composition por metalVariant lookup fallido.
    // eslint-disable-next-line no-console
    console.warn(
      "[pricing-composition] metalVariant batch lookup falló; items con metalName=null:",
      err,
    );
    return empty;
  }
}

/**
 * F1.3 G4.1.3 — internal — query batch failure-safe por catalogItemIds.
 *
 * Centraliza el patrón de:
 *   1. Set dedupe (no se valida acá; el caller pasa el Set ya dedupeado).
 *   2. Single query Prisma con filtros multi-tenancy + soft-delete.
 *   3. Failure-safety: si Prisma throws, devuelve Map vacío + log warning.
 *
 * Reusada por `buildCatalogItemsMapForSteps` (post-engine) y
 * `buildCatalogItemsMapForCostLines` (pre-engine, para sales/preview que
 * conoce los catalogItemIds desde la precarga de articleData).
 */
async function loadCatalogItemsByIds(
  jewelryId: string,
  ids: Set<string>,
): Promise<Map<string, { code: string; name: string; sku: string; unitOfMeasure: string }>> {
  const empty = new Map<string, { code: string; name: string; sku: string; unitOfMeasure: string }>();
  if (!jewelryId || ids.size === 0) return empty;

  try {
    const items = await prisma.article.findMany({
      where:  { jewelryId, id: { in: [...ids] }, deletedAt: null },
      select: { id: true, code: true, name: true, sku: true, unitOfMeasure: true },
    });
    const map = new Map<string, { code: string; name: string; sku: string; unitOfMeasure: string }>();
    for (const a of items) {
      map.set(a.id, {
        code: a.code ?? "",
        name: a.name ?? "",
        // Fase 2.4 — `Article.sku` (nullable en schema, queda "" como fallback).
        sku:  a.sku  ?? "",
        // Unidad de medida del Article referenciado — sólo aplica a PRODUCT/SERVICE
        // (cost lines que referencian otro Article del catálogo). HECHURA / METAL
        // no usan este campo (METAL es siempre gramos, HECHURA no tiene unidad).
        // Fallback "" cuando el Article maestro no la definió.
        unitOfMeasure: (a as { unitOfMeasure?: string }).unitOfMeasure ?? "",
      });
    }
    return map;
  } catch (err) {
    // Failure-safety: NO romper composition por catalog lookup fallido.
    // Los items renderean igual con fallback meta.lineCode/lineLabel.
    // eslint-disable-next-line no-console
    console.warn(
      "[pricing-composition] catalog lookup falló; usando fallback meta.lineCode/lineLabel:",
      err,
    );
    return empty;
  }
}

/**
 * F1.3 G4.1.3 — pre-carga el catalog info (code/name) para los PRODUCT/SERVICE
 * referenciados en los steps de un resultado de pricing. UNA SOLA query
 * batch — evita N+1 cuando el artículo tiene múltiples cost lines.
 *
 * Variante para 1 artículo (post-engine). Para sales/preview con N líneas,
 * usar `buildCatalogItemsMapForCostLines` que dedupea GLOBAL antes del engine.
 *
 * IMPORTANTE — cuándo llamar:
 *   · UNA vez por request (post-engine, pre-buildComposition).
 *   · NO llamar per-línea, per-step, ni dentro de buildComposition.
 */
export async function buildCatalogItemsMapForSteps(
  jewelryId: string,
  steps: PricingStep[] | null | undefined,
): Promise<Map<string, { code: string; name: string; sku: string; unitOfMeasure: string }>> {
  if (!Array.isArray(steps) || steps.length === 0) {
    return new Map<string, { code: string; name: string; sku: string; unitOfMeasure: string }>();
  }
  const ids = new Set<string>();
  for (const s of steps) {
    if (!s) continue;
    if (s.key !== "COST_LINES_PRODUCT" && s.key !== "COST_LINES_SERVICE") continue;
    if (s.status !== "ok") continue;
    const id = (s.meta as any)?.catalogItemId;
    if (typeof id === "string" && id.length > 0) ids.add(id);
  }
  return loadCatalogItemsByIds(jewelryId, ids);
}

/**
 * F1.3 G4.1.4 — variante para sales/preview con N líneas del documento.
 *
 * Recibe arrays de cost lines (del articleData precargado por previewSale)
 * y dedupea catalogItemIds GLOBALMENTE antes de la query batch única.
 *
 * IMPORTANTE — cuándo llamar:
 *   · UNA vez por request, ANTES del engine loop (en paralelo con otras
 *     precargas via Promise.all).
 *   · NO per-línea, NO dentro del loop, NO dentro de buildComposition.
 *
 * Performance: query count = 1 incluso con 100 líneas y catalogItemIds
 * repetidos. Verificado por test específico de benchmark.
 *
 * Failure-safety: si Prisma falla, Map vacío (fallback a meta.lineCode/Label).
 *
 * @param jewelryId             Tenant scope obligatorio.
 * @param costLinesByArticle    Array de arrays de cost lines (típicamente
 *                              `articleData.map(a => a.costComposition ?? [])`).
 *                              Solo se inspecciona el campo `catalogItemId`.
 */
export async function buildCatalogItemsMapForCostLines(
  jewelryId: string,
  costLinesByArticle: Array<Array<{ catalogItemId?: string | null }>> | null | undefined,
): Promise<Map<string, { code: string; name: string; sku: string; unitOfMeasure: string }>> {
  if (!Array.isArray(costLinesByArticle) || costLinesByArticle.length === 0) {
    return new Map<string, { code: string; name: string; sku: string; unitOfMeasure: string }>();
  }
  const ids = new Set<string>();
  for (const lines of costLinesByArticle) {
    if (!Array.isArray(lines)) continue;
    for (const cl of lines) {
      const id = cl?.catalogItemId;
      if (typeof id === "string" && id.length > 0) ids.add(id);
    }
  }
  return loadCatalogItemsByIds(jewelryId, ids);
}

/**
 * F1.3 G4.x #9-A — extrae `composition.metals[]` desde steps
 * `COST_LINES_METAL` del motor cost. Uno por cost line de tipo METAL.
 * Cero recálculo monetario (POLICY R4.5): `lineCost` es passthrough de
 * `step.value` y `appliedGrams`/`appliedMermaPct` vienen de `step.meta`.
 *
 * `metalVariantInfoMap` (opcional) — pre-cargado por el caller via
 * `fetchMetalVariantInfoMap` (1 query batch). Sin map, los items quedan
 * con `metalName=null` (defensa: el render usa "—" o el variantId).
 */
export function extractCompositionMetals(
  steps: PricingStep[] | null | undefined,
  metalVariantInfoMap?: Map<string, MetalVariantInfo>,
  metalSaleFactor: number | null = null,
): CompositionMetalItem[] {
  if (!Array.isArray(steps) || steps.length === 0) return [];
  return steps
    .filter(s => s && s.key === "COST_LINES_METAL" && s.status === "ok")
    .map(s => {
      const meta = (s.meta ?? {}) as Record<string, unknown>;
      const variantId  = typeof meta.variantId === "string" ? meta.variantId : null;
      const variantInfo = variantId ? metalVariantInfoMap?.get(variantId) : null;
      const qtyNum   = meta.qty   != null ? Number(meta.qty)   : null;
      const mermaNum = meta.merma != null ? Number(meta.merma) : null;
      const lineCost = s.value != null ? Number(s.value) : null;
      // Fase 2.3 — precio base por gramo (pre-merma). El motor lo emite
      // como `meta.quotePrice` (string fixed(6)). Frontend lo usa como
      // columna "Val. unit." en METAL.
      const quotePriceNum = meta.quotePrice != null ? Number(meta.quotePrice) : null;
      const lineCostFinite = lineCost != null && Number.isFinite(lineCost) ? lineCost : null;
      // F1.5 #A++ — sale-side per cost-line METAL. Passthrough exacto:
      // lineSale = lineCost × (metalSale / metalCost). El motor ya emitió ambos
      // agregados en el breakdown; este factor se computó una vez en
      // computeMetalSaleFactor() y aplica linealmente.
      const lineSale =
        lineCostFinite != null && metalSaleFactor != null && Number.isFinite(metalSaleFactor)
          ? lineCostFinite * metalSaleFactor
          : null;
      // FASE F2 — propagar el origen de la merma desde el step. Valores
      // válidos: "costLineOverride" | "entity" | "line" | "default".
      // Steps viejos sin este campo caen a null → el frontend no muestra badge.
      const mermaSourceRaw = typeof meta.mermaSource === "string" ? meta.mermaSource : null;
      const mermaSource =
        mermaSourceRaw === "costLineOverride" || mermaSourceRaw === "entity"
          || mermaSourceRaw === "line" || mermaSourceRaw === "default"
          ? mermaSourceRaw
          : null;
      // FASE F3 — costo de la línea sin merma comercial (passthrough).
      // = appliedGrams × quotePrice cuando ambos finite; si no, null.
      const lineCostBase =
        qtyNum != null && Number.isFinite(qtyNum)
          && quotePriceNum != null && Number.isFinite(quotePriceNum)
          ? qtyNum * quotePriceNum
          : null;
      return {
        costLineId:      typeof meta.costLineId === "string" ? meta.costLineId : null,
        metalVariantId:  variantId,
        metalName:       variantInfo?.metalName   ?? null,
        // Fase 2.4 — variantName del MetalVariant (nombre comercial).
        variantName:     variantInfo?.variantName ?? null,
        purity:          variantInfo?.purity      ?? null,
        purityLabel:     variantInfo?.purityLabel ?? null,
        appliedGrams:    qtyNum   != null && Number.isFinite(qtyNum)   ? qtyNum   : null,
        appliedMermaPct: mermaNum != null && Number.isFinite(mermaNum) ? mermaNum : null,
        lineCost:        lineCostFinite,
        lineSale,
        quotePrice:      quotePriceNum != null && Number.isFinite(quotePriceNum) ? quotePriceNum : null,
        mermaSource,
        lineCostBase,
      };
    });
}

/**
 * F1.3 G4.x #9-A — extrae `composition.hechuras[]` desde steps
 * `COST_LINES_HECHURA` del motor cost. Mismo patrón que metals[].
 *
 * F1.5 #A+ — recibe `hechuraSaleFactor` (passthrough del motor) para emitir
 * `lineSale` per fila. Cuando es null, todos los items quedan con `lineSale=null`.
 * Ver `computeHechuraSaleFactor` para cómo se deriva.
 */
export function extractCompositionHechuras(
  steps: PricingStep[] | null | undefined,
  hechuraSaleFactor: number | null = null,
): CompositionHechuraItem[] {
  if (!Array.isArray(steps) || steps.length === 0) return [];
  return steps
    .filter(s => s && s.key === "COST_LINES_HECHURA" && s.status === "ok")
    .map(s => {
      const meta = (s.meta ?? {}) as Record<string, unknown>;
      const lineCost = s.value != null ? Number(s.value) : null;
      // appliedAmount: el motor cost emite `value = qty × unitValue` (post
      // conversión moneda). Para HECHURA típica (qty=1, unitValue=monto),
      // appliedAmount === lineCost.
      const lineLabel = typeof meta.lineLabel === "string" && meta.lineLabel.length > 0
        ? meta.lineLabel
        : (typeof s.label === "string" && s.label.length > 0 ? s.label : null);
      // Fase 2.2 — propagar lineAdj* del step.meta. Para HECHURA típica
      // (qty=1, sin ajuste) los 4 quedan null.
      const adjKindRaw  = typeof meta.lineAdjKind === "string" && meta.lineAdjKind.length > 0
        ? meta.lineAdjKind : null;
      const adjKind: "BONUS" | "SURCHARGE" | null =
        adjKindRaw === "BONUS" || adjKindRaw === "SURCHARGE" ? adjKindRaw : null;
      const adjTypeRaw  = typeof meta.lineAdjType === "string" && meta.lineAdjType.length > 0
        ? meta.lineAdjType : null;
      const adjType: "PERCENTAGE" | "FIXED_AMOUNT" | null =
        adjTypeRaw === "PERCENTAGE" || adjTypeRaw === "FIXED_AMOUNT" ? adjTypeRaw : null;
      // Fase 2.3.1 — propagar `meta.unitValue` como BASE pre-ajuste. Mismo
      // patrón que `extractCompositionItems` (PRODUCT/SERVICE).
      const unitValueRaw = meta.unitValue != null ? Number(meta.unitValue) : null;
      const lineCostFinite = lineCost != null && Number.isFinite(lineCost) ? lineCost : null;
      const lineSale =
        lineCostFinite != null && hechuraSaleFactor != null && Number.isFinite(hechuraSaleFactor)
          ? lineCostFinite * hechuraSaleFactor
          : null;
      // Paridad con PRODUCT/SERVICE: propagamos `meta.qty` para que la UI
      // pueda rehidratar la cantidad real del cost line (HECHURA con qty > 1).
      // El motor ya emite `meta.qty` en cada step COST_LINES_*; este extractor
      // solo lo pega al item. NO toca el cálculo (lineCost / lineSale / etc.).
      const qtyRaw = meta.qty != null ? Number(meta.qty) : null;
      const quantity = qtyRaw != null && Number.isFinite(qtyRaw) ? qtyRaw : undefined;
      // Unidad seleccionada por el operador en el modal — passthrough display.
      const quantityUnit = typeof meta.quantityUnit === "string" && meta.quantityUnit.length > 0
        ? meta.quantityUnit
        : undefined;
      // Moneda original — el motor inyecta `fromCurrencyId`, `currencyCode` y
      // `currencySymbol` en `step.meta` SOLO cuando hubo conversión efectiva
      // (cost line en moneda != base). Snapshots sin conversión los omiten.
      const currencyId     = typeof meta.fromCurrencyId === "string" && meta.fromCurrencyId.length > 0
        ? meta.fromCurrencyId
        : (typeof (meta as any).currencyId === "string" && (meta as any).currencyId.length > 0
            ? (meta as any).currencyId
            : null);
      const currencyCode   = typeof meta.currencyCode   === "string" && meta.currencyCode.length   > 0
        ? meta.currencyCode   : null;
      const currencySymbol = typeof meta.currencySymbol === "string" && meta.currencySymbol.length > 0
        ? meta.currencySymbol : null;
      // Display-only — `unitValue × rate`, costo unitario en moneda BASE
      // post-conversión y PRE-ajuste. Si no hubo conversión, rate=1 → coincide
      // con `unitValue`. Multiplicación trivial sobre dos passthrough del motor;
      // NO recalcula precios comerciales.
      const rateRaw = (meta as { rate?: unknown }).rate;
      const rate    = rateRaw != null && Number.isFinite(Number(rateRaw))
        ? Number(rateRaw)
        : 1;
      const unitValueBase = unitValueRaw != null && Number.isFinite(unitValueRaw)
        ? unitValueRaw * rate
        : undefined;
      return {
        costLineId:    typeof meta.costLineId === "string" ? meta.costLineId : null,
        appliedAmount: lineCostFinite,
        unitValue:     unitValueRaw != null && Number.isFinite(unitValueRaw) ? unitValueRaw : null,
        ...(unitValueBase != null && Number.isFinite(unitValueBase) ? { unitValueBase } : {}),
        lineCost:      lineCostFinite,
        lineSale,
        lineLabel,
        ...(quantity != null ? { quantity } : {}),
        ...(quantityUnit != null ? { quantityUnit } : {}),
        ...(currencyId     != null ? { currencyId }     : {}),
        ...(currencyCode   != null ? { currencyCode }   : {}),
        ...(currencySymbol != null ? { currencySymbol } : {}),
        lineAdjKind:   adjKind,
        lineAdjType:   adjType,
        lineAdjValue:  meta.lineAdjValue  != null ? Number(meta.lineAdjValue)  : null,
        lineAdjAmount: meta.lineAdjAmount != null ? Number(meta.lineAdjAmount) : null,
      };
    });
}

/**
 * F1.3 G4.1.1 — extrae bloques `products[]` o `services[]` desde
 * `result.steps[]` filtrando por la key correspondiente.
 *
 * El motor cost ya emite un step `COST_LINES_PRODUCT` / `COST_LINES_SERVICE`
 * por cada cost line de ese tipo. Este helper los mapea al shape display
 * sin recálculo monetario (POLICY R4.5).
 *
 * `catalogItems` es un Map opcional pre-cargado por el caller (1 query
 * batch, evita N+1) que asocia `catalogItemId` → `{ code, name }` del
 * artículo referenciado. Sin este map, el item queda con `catalogItemCode`
 * tomado de `step.meta.lineCode` (lo que el motor ya emite) y
 * `catalogItemName` derivado del label.
 *
 * Campos no expuestos hoy en step.meta (`costLineId`, `catalogItemId`,
 * `affectsStock`, `lineAdjAmount`) quedan null. Commit G4.1.2 extenderá el
 * motor para emitirlos. Mientras tanto, los items SE renderean con la info
 * disponible — la UI no se rompe.
 *
 * TODO Frontend: si products/services > 3 items, evaluar colapsado del
 * panel para evitar saturación visual.
 */
export function extractCompositionItems(
  steps: PricingStep[] | null | undefined,
  targetKey: "COST_LINES_PRODUCT" | "COST_LINES_SERVICE",
  catalogItems?: Map<string, { code: string; name: string; sku: string; unitOfMeasure: string }>,
  hechuraSaleFactor: number | null = null,
): CompositionItemBlock[] {
  if (!Array.isArray(steps) || steps.length === 0) return [];

  return steps
    .filter(s => s && s.key === targetKey && s.status === "ok")
    .map(s => {
      const meta = (s.meta ?? {}) as Record<string, unknown>;
      const catalogId = (meta.catalogItemId ?? null) as string | null;
      const catalogInfo = catalogId ? catalogItems?.get(catalogId) : null;

      const lineCodeFromMeta = typeof meta.lineCode === "string" && meta.lineCode.length > 0
        ? meta.lineCode
        : null;
      const lineLabelFromMeta = typeof meta.lineLabel === "string" && meta.lineLabel.length > 0
        ? meta.lineLabel
        : null;
      const fallbackLabel = typeof s.label === "string" && s.label.length > 0
        ? s.label
        : null;

      const adjKindRaw = typeof meta.lineAdjKind === "string" && meta.lineAdjKind.length > 0
        ? meta.lineAdjKind
        : null;
      const adjKind: "BONUS" | "SURCHARGE" | null =
        adjKindRaw === "BONUS" || adjKindRaw === "SURCHARGE" ? adjKindRaw : null;
      const adjTypeRaw = typeof meta.lineAdjType === "string" && meta.lineAdjType.length > 0
        ? meta.lineAdjType
        : null;
      const adjType: "PERCENTAGE" | "FIXED_AMOUNT" | null =
        adjTypeRaw === "PERCENTAGE" || adjTypeRaw === "FIXED_AMOUNT" ? adjTypeRaw : null;

      // step.value ya es qty × unitValue (post conversión moneda + ajuste)
      // — lo provee el motor cost. Cero recálculo acá.
      const totalValue = s.value != null ? Number(s.value) : 0;
      const qty       = meta.qty       != null ? Number(meta.qty)       : 0;
      const unitValue = meta.unitValue != null ? Number(meta.unitValue) : 0;
      const totalValueFinite = Number.isFinite(totalValue) ? totalValue : null;
      const lineSale =
        totalValueFinite != null && hechuraSaleFactor != null && Number.isFinite(hechuraSaleFactor)
          ? totalValueFinite * hechuraSaleFactor
          : null;

      // Moneda original — passthrough display desde `step.meta.currencyCode`
      // y `currencySymbol` que el motor cost inyecta (vía spread de
      // `conversionMeta`) cuando el cost line está en moneda != base.
      const currencyCode   = typeof meta.currencyCode   === "string" && meta.currencyCode.length   > 0
        ? meta.currencyCode   : null;
      const currencySymbol = typeof meta.currencySymbol === "string" && meta.currencySymbol.length > 0
        ? meta.currencySymbol : null;
      // Display-only — `unitValue × rate`, costo unitario en moneda BASE
      // post-conversión y PRE-ajuste. Ver `CompositionHechuraItem.unitValueBase`.
      const rateRawP = (meta as { rate?: unknown }).rate;
      const rateP    = rateRawP != null && Number.isFinite(Number(rateRawP))
        ? Number(rateRawP)
        : 1;
      const unitValueBase = Number.isFinite(unitValue) ? unitValue * rateP : undefined;
      // Unidad — se resuelve desde el catalog map (`Article.unitOfMeasure`
      // del componente referenciado). Sólo aplica a PRODUCT/SERVICE.
      const quantityUnitName = catalogInfo?.unitOfMeasure && catalogInfo.unitOfMeasure.length > 0
        ? catalogInfo.unitOfMeasure
        : null;
      // Unidad seleccionada por el operador en la línea de costo (gana sobre
      // la unidad del Article maestro). Passthrough display.
      const quantityUnit = typeof meta.quantityUnit === "string" && meta.quantityUnit.length > 0
        ? meta.quantityUnit
        : undefined;
      return {
        costLineId:       (meta.costLineId ?? null) as string | null,
        catalogItemId:    catalogId,
        catalogItemCode:  catalogInfo?.code ?? lineCodeFromMeta,
        // Fase 2.4 — SKU del Article catálogo. null si el map no tiene el id
        // o si el Article no tiene sku configurado (string vacío también →
        // se trata como null en el frontend para el fallback).
        catalogItemSku:   catalogInfo?.sku && catalogInfo.sku.length > 0
                          ? catalogInfo.sku
                          : null,
        catalogItemName:  catalogInfo?.name ?? lineLabelFromMeta ?? fallbackLabel,
        quantity:         Number.isFinite(qty)       ? qty       : 0,
        ...(quantityUnit != null ? { quantityUnit } : {}),
        unitValue:        Number.isFinite(unitValue) ? unitValue : 0,
        ...(unitValueBase != null && Number.isFinite(unitValueBase) ? { unitValueBase } : {}),
        totalValue:       Number.isFinite(totalValue) ? totalValue : 0,
        currencyId:       (meta.currencyId ?? null) as string | null,
        ...(currencyCode     != null ? { currencyCode }     : {}),
        ...(currencySymbol   != null ? { currencySymbol }   : {}),
        ...(quantityUnitName != null ? { quantityUnitName } : {}),
        lineAdjKind:      adjKind,
        lineAdjType:      adjType,
        lineAdjValue:     meta.lineAdjValue != null ? Number(meta.lineAdjValue) : null,
        lineAdjAmount:    meta.lineAdjAmount != null ? Number(meta.lineAdjAmount) : null,
        affectsStock:     typeof meta.affectsStock === "boolean" ? meta.affectsStock : null,
        lineSale,
      };
    });
}

/**
 * Fase 2.5 — extrae el ajuste global de costo del artículo desde el step
 * `COST_LINES_FINAL` que el motor cost emite (ver `pricing-engine.cost.ts`).
 *
 * Reglas:
 *   · Si el step no existe → retorna null (artículo sin cost lines, p.ej.).
 *   · Si `kind` no es "BONUS"/"SURCHARGE" (string vacío de DB) → retorna null.
 *   · `amount` = `meta.sumLines - step.value` (signed: positivo = reducción
 *     bonificación; negativo = aumento recargo). Cero recálculo: usa los
 *     dos números que el motor ya emitió.
 *   · Cuando step.value o meta.sumLines no son números válidos, `amount`
 *     queda null y la UI cae a "—" en el monto.
 */
export function extractCompositionCostAdjustment(
  steps: PricingStep[] | null | undefined,
): CompositionCostAdjustment | null {
  if (!Array.isArray(steps) || steps.length === 0) return null;
  const step = steps.find(s => s && s.key === "COST_LINES_FINAL");
  if (!step) return null;

  const meta = (step.meta ?? {}) as Record<string, unknown>;
  const kindRaw = typeof meta.adjustmentKind === "string" && meta.adjustmentKind.length > 0
    ? meta.adjustmentKind : null;
  const kind: "BONUS" | "SURCHARGE" | null =
    kindRaw === "BONUS" || kindRaw === "SURCHARGE" ? kindRaw : null;
  if (!kind) return null;     // sin ajuste → no exponemos el bloque.

  const typeRaw = typeof meta.adjustmentType === "string" && meta.adjustmentType.length > 0
    ? meta.adjustmentType : null;
  const type: "PERCENTAGE" | "FIXED_AMOUNT" | null =
    typeRaw === "PERCENTAGE" || typeRaw === "FIXED_AMOUNT" ? typeRaw : null;

  const value = meta.adjustmentValue != null ? Number(meta.adjustmentValue) : null;
  const adjusted = step.value != null ? Number(step.value) : null;
  const sumLines = meta.sumLines != null ? Number(meta.sumLines) : null;
  // amount = sumLines - adjusted. BONUS reduce → adjusted < sumLines → +.
  // SURCHARGE aumenta → adjusted > sumLines → −.
  // Convención del frontend: positivo = reducción (BONUS), negativo = aumento.
  const amount =
    sumLines != null && Number.isFinite(sumLines) &&
    adjusted != null && Number.isFinite(adjusted)
      ? sumLines - adjusted
      : null;

  return {
    kind,
    type,
    value: value != null && Number.isFinite(value) ? value : null,
    amount,
  };
}

/**
 * F1.5 #A+ — calcula el factor que convierte `lineCost` (pre ajuste global)
 * en `lineSale` (precio venta per fila). Passthrough exacto del cálculo
 * interno del motor:
 *
 *   `lineSale = lineCost × adjFactor × (1 + hechuraMarginPct/100)`
 *
 * Donde:
 *   · `adjFactor` = `COST_LINES_FINAL.value / COST_LINES_FINAL.meta.sumLines`
 *     (efecto del ajuste global de costo BONUS/SURCHARGE sobre cada línea).
 *   · `hechuraMarginPct` viene de `result.metalHechuraBreakdown` — margen
 *     que el motor aplica al bucket HECHURA+PRODUCT+SERVICE.
 *
 * Retorna `null` cuando alguno de los inputs falta o no es derivable
 * (snapshot legacy, lista MARGIN_TOTAL sin desglose, etc.). Los items
 * entonces emiten `lineSale=null` y la UI cae a "—" (POLICY R4.5: cero
 * matemática derivada en frontend).
 *
 * Paridad verificable:
 *   Σ lineSale(productos+servicios+hechuras) === hechuraSale del breakdown
 *   (tolerancia ≤ 0.01 por redondeo Decimal interno).
 */
/**
 * F1.5 #A++ — calcula el factor que convierte `lineCost` de METAL en
 * `lineSale` per fila. Passthrough exacto del breakdown agregado:
 *
 *   `lineSale = lineCost × (metalSale / metalCost)`
 *
 * El motor ya aplicó margen + ajuste global al bucket METAL completo (todas
 * las cost-lines comparten metalMarginPct); este factor distribuye el
 * sale-side per línea sin matemática nueva. La paridad
 * `Σ metals[i].lineSale === metalSale` se garantiza por construcción
 * (factor uniforme).
 *
 * Retorna `null` cuando:
 *   · no hay `metalHechuraBreakdown` (lista MARGIN_TOTAL sin desglose).
 *   · `metalCost` es 0 o no finito (división indefinida).
 *   · `metalSale` es null o no finito.
 *
 * En esos casos los `metals[i].lineSale` quedan null y la UI muestra "—"
 * (mismo patrón que F1.5 #A+ para HECHURA/PRODUCT/SERVICE).
 */
export function computeMetalSaleFactor(
  result: SalePriceResult | null | undefined,
): number | null {
  const br = result?.metalHechuraBreakdown;
  if (!br) return null;
  const metalCost = br.metalCost;
  const metalSale = br.metalSale;
  if (metalCost == null || !Number.isFinite(metalCost) || metalCost === 0) return null;
  if (metalSale == null || !Number.isFinite(metalSale)) return null;
  return metalSale / metalCost;
}

export function computeHechuraSaleFactor(
  result: SalePriceResult | null | undefined,
): number | null {
  const hechuraMarginPct = result?.metalHechuraBreakdown?.hechuraMarginPct;
  if (hechuraMarginPct == null || !Number.isFinite(hechuraMarginPct)) return null;

  // adjFactor desde el step COST_LINES_FINAL. Cuando no hay ajuste global,
  // adjusted === sumLines → adjFactor = 1.
  const finalStep = (result?.steps ?? []).find(s => s && s.key === "COST_LINES_FINAL");
  let adjFactor = 1;
  if (finalStep) {
    const meta = (finalStep.meta ?? {}) as Record<string, unknown>;
    const adjusted = finalStep.value != null ? Number(finalStep.value) : null;
    const sumLines = meta.sumLines != null ? Number(meta.sumLines) : null;
    if (adjusted != null && sumLines != null && Number.isFinite(adjusted)
        && Number.isFinite(sumLines) && sumLines !== 0) {
      adjFactor = adjusted / sumLines;
    }
  }
  return adjFactor * (1 + hechuraMarginPct / 100);
}

/**
 * Arma el bloque `composition` que aparece en los responses de preview.
 * Mismo shape que devolvía `articles.controller.ts:1257-1296` antes de la
 * extracción.
 *
 * El argumento `mvi` es el resultado de `fetchMetalVariantInfo`. Se pasa por
 * separado para que el caller controle cuándo hace la query (típicamente una
 * vez por línea, ya cacheable si hace falta optimizar).
 *
 * F1.3 G4.1.1 — agrega `products[]` y `services[]` extraídos de
 * `result.steps[]`. Por defecto vacíos; cuando el caller pasa `catalogItems`
 * map pre-cargado, los items incluyen `catalogItemCode` / `catalogItemName`
 * resueltos. Sin map, caen al `lineCode` / `lineLabel` que ya emite el motor.
 */
export function buildComposition(
  result: SalePriceResult,
  mvi: MetalVariantInfo,
  catalogItems?: Map<string, { code: string; name: string; sku: string; unitOfMeasure: string }>,
  metalVariantInfoMap?: Map<string, MetalVariantInfo>,
): Composition {
  const ctx = result.costOverrideContext;

  // F1.3 G4.x #9-A — extracción primaria: arrays con TODAS las cost lines.
  // Cero recálculo monetario; passthrough estructural de step.value/meta.
  // F1.5 #A+ — hechuraSaleFactor permite exponer `lineSale` per HECHURA/
  // PRODUCT/SERVICE (passthrough del margen y ajuste global que el motor
  // ya calcula internamente).
  // F1.5 #A++ — metalSaleFactor permite exponer `lineSale` per METAL
  // (passthrough del margen METAL del breakdown). Reemplaza el prorrateo
  // manual que hoy hace el Simulador (POLICY R4.1).
  const hechuraSaleFactor = computeHechuraSaleFactor(result);
  const metalSaleFactor   = computeMetalSaleFactor(result);
  const metals   = extractCompositionMetals(result.steps, metalVariantInfoMap, metalSaleFactor);
  const hechuras = extractCompositionHechuras(result.steps, hechuraSaleFactor);
  const products = extractCompositionItems(result.steps, "COST_LINES_PRODUCT", catalogItems, hechuraSaleFactor);
  const services = extractCompositionItems(result.steps, "COST_LINES_SERVICE", catalogItems, hechuraSaleFactor);
  // Fase 2.5 — ajuste global de costo extraído del step COST_LINES_FINAL.
  const costAdjustment = extractCompositionCostAdjustment(result.steps);

  // F1.3 G4.x #9-A — alias LEGACY `metal` y `hechura`. Garantiza el
  // invariante: `composition.metal === composition.metals[0] ?? null`
  // (estructural). El alias enriquece con flags del costOverrideContext
  // que solo aplican al PRIMER METAL/HECHURA (ver D1: edición inline solo
  // afecta al [0], los items 2+ son read-only).
  //
  // Cuando NO hay metals[]/hechuras[] (artículo sin cost lines de ese tipo)
  // el alias respeta el comportamiento legacy: si el ctx tiene flags
  // (override aplicado sin línea base), igual emite el bloque legacy.
  const firstMetal   = metals[0]   ?? null;
  const firstHechura = hechuras[0] ?? null;

  const metal: CompositionMetalBlock | null =
    firstMetal || ctx?.grams || ctx?.mermaPercent || ctx?.metalVariant
      ? {
          originalGrams:     ctx?.grams?.original ?? firstMetal?.appliedGrams    ?? null,
          appliedGrams:      ctx?.grams?.applied  ?? firstMetal?.appliedGrams    ?? null,
          gramsManual:       !!ctx?.grams?.manual,
          originalMermaPct:  ctx?.mermaPercent?.original ?? firstMetal?.appliedMermaPct ?? null,
          appliedMermaPct:   ctx?.mermaPercent?.applied  ?? firstMetal?.appliedMermaPct ?? null,
          mermaManual:       !!ctx?.mermaPercent?.manual,
          originalVariantId: ctx?.metalVariant?.originalId ?? firstMetal?.metalVariantId ?? null,
          appliedVariantId:  ctx?.metalVariant?.appliedId  ?? firstMetal?.metalVariantId ?? null,
          variantManual:     !!ctx?.metalVariant?.manual,
          // mvi (resuelto del primer variantId via fetchMetalVariantInfo
          // legacy) tiene precedencia sobre firstMetal.* para mantener el
          // comportamiento exacto pre-9-A. Si el caller pasa
          // metalVariantInfoMap, firstMetal.metalName/purity ya estarán
          // resueltos desde ahí.
          purity:            mvi.purity      ?? firstMetal?.purity      ?? null,
          purityLabel:       mvi.purityLabel ?? firstMetal?.purityLabel ?? null,
          metalName:         mvi.metalName   ?? firstMetal?.metalName   ?? null,
        }
      : null;

  const hechura: CompositionHechuraBlock | null =
    firstHechura || ctx?.hechura
      ? {
          originalAmount: ctx?.hechura?.original ?? firstHechura?.appliedAmount ?? null,
          appliedAmount:  ctx?.hechura?.applied  ?? firstHechura?.appliedAmount ?? null,
          manual:         !!ctx?.hechura?.manual,
          appliesTo:      null,
        }
      : null;

  const taxes: CompositionTaxItem[] = (result.taxBreakdown ?? []).map((t) => ({
    id:        t.taxId,
    name:      t.name,
    code:      t.code,
    rate:      t.rate != null ? Number(t.rate) : null,
    appliesTo: t.applyOn,
    taxAmount: Number(t.taxAmount ?? 0),
    manual:    t.taxId === "OVERRIDE_MANUAL",
  }));

  return { metal, hechura, metals, hechuras, products, services, taxes, costAdjustment };
}

/**
 * `appliedMermaPercent` plano — atajo para callers que no necesitan toda la
 * `composition`. Lee del mismo lugar (`costOverrideContext.mermaPercent.applied`).
 */
export function getAppliedMermaPercent(result: SalePriceResult | null | undefined): number | null {
  return result?.costOverrideContext?.mermaPercent?.applied ?? null;
}
