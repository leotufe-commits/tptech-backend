// src/lib/pricing-engine/commercial-document-rounding-context.ts
// =============================================================================
// Resolución del contexto comercial PER_DOCUMENT (Etapa D').
//
// Helper PURO. Decide si una venta opera en PER_LINE_LEGACY o PER_DOCUMENT,
// y arma:
//   · `applyPriceListOptions` con los flags de supresión para el motor de lista.
//   · `commercialDocumentRounding` con la config para la capa nueva del motor
//      documental (`computeSaleDocumentTotals`).
//
// Mientras NO haya schema (`PriceList.commercialRoundingScope`), el modo se
// activa por env var `PRICING_COMMERCIAL_DOC_ROUNDING_ENABLED=1` o por
// override explícito del caller. Cuando esté el schema, se lee de la lista
// activa del documento sin cambiar la firma de este helper — solo el resolvedor
// interno cambia.
//
// Reglas:
//   · Mixed-list (líneas con distintas listas) → `MIXED_LIST_FALLBACK` +
//     `fallback: "NO_SHARED_LIST"`. Comportamiento PER_LINE_LEGACY intacto.
//   · Lista sin redondeo de hechura ni metal físico activo → no se construye
//     `commercialDocumentRounding` (`null`), pero el modo sigue siendo
//     `PER_DOCUMENT` para mantener consistencia del wiring si el operador lo
//     activa explícitamente. La capa nueva no actúa (todo NONE).
// =============================================================================

import type {
  CommercialDocRoundingInput,
  CommercialDocRoundingMode,
  CommercialDocRoundingDirection,
} from "./commercial-document-rounding.js";

// Espejo mínimo de las opciones de `applyPriceList` para evitar import circular.
// El consumer real recibe el shape exacto vía propagación.
export interface ContextApplyPriceListOptions {
  suppressLineHechuraRounding?:      boolean;
  suppressLineMetalPhysicalRounding?: boolean;
}

/**
 * Datos mínimos de la lista activa del documento que el helper necesita para
 * armar el contexto. El caller lo extrae de la `PriceList` ya cargada.
 */
export interface PriceListSummaryForContext {
  id:                                 string;
  name:                               string;
  mode:                               string;  // MARGIN_TOTAL | METAL_HECHURA | COST_PER_GRAM
  roundingTarget:                     string;  // FINAL_PRICE | METAL | NONE
  roundingMode:                       string;  // INTEGER | DECIMAL_1 | ... | NONE
  roundingDirection:                  string;  // NEAREST | UP | DOWN
  roundingModeHechura:                string | null;
  roundingDirectionHechura:           string | null;
  commercialRoundingMetalDomain:      string | null;  // PHYSICAL | MONETARY
  /** Etapa D' — scope persistido en `PriceList.commercialRoundingScope`.
   *  `PER_LINE_LEGACY` = comportamiento histórico. `PER_DOCUMENT` = capa
   *  nueva post-tax. */
  commercialRoundingScope:            "PER_LINE_LEGACY" | "PER_DOCUMENT";
}

export type DocCommercialRoundingMode =
  | "PER_LINE_LEGACY"
  | "PER_DOCUMENT"
  | "MIXED_LIST_FALLBACK";

export interface ResolveDocCommercialRoundingArgs {
  /** Lista activa pre-resuelta por el caller. `null` cuando hay mixed-list
   *  o no hay lista identificable. */
  sharedPriceList: PriceListSummaryForContext | null;
  /** El caller declara explícitamente si todas las líneas comparten la
   *  `sharedPriceList`. Si `false` (mixed) o si `sharedPriceList` es `null`,
   *  el resultado es `MIXED_LIST_FALLBACK`. */
  allLinesShareList: boolean;
  /** Override de runtime mientras no haya schema. Cuando esté el schema, este
   *  campo dejará de usarse — el modo viene de `sharedPriceList.commercialRoundingScope`. */
  forceScope?: "PER_LINE_LEGACY" | "PER_DOCUMENT" | null;
}

export interface DocCommercialRoundingContext {
  mode: DocCommercialRoundingMode;
  /** Identidad de la lista activa del documento (para trace + display).
   *  `null` cuando mixed-list. */
  documentActivePriceList: {
    id:   string;
    name: string;
  } | null;
  /** Opciones a propagar al motor de lista (`applyPriceList`). Vacío `{}`
   *  cuando PER_LINE_LEGACY o MIXED_LIST_FALLBACK. */
  applyPriceListOptions: ContextApplyPriceListOptions;
  /** Config para la capa nueva en `computeSaleDocumentTotals`. `null` cuando
   *  no se aplica (PER_LINE_LEGACY, MIXED_LIST_FALLBACK, o PER_DOCUMENT sin
   *  redondeos activos en la lista). */
  commercialDocumentRounding: CommercialDocRoundingInput | null;
  fallback: "NO_SHARED_LIST" | null;
}

/**
 * Helper principal — decide el modo y arma el contexto.
 */
export function resolveDocCommercialRoundingContext(
  args: ResolveDocCommercialRoundingArgs,
): DocCommercialRoundingContext {
  if (!args.allLinesShareList || !args.sharedPriceList) {
    return {
      mode:                        "MIXED_LIST_FALLBACK",
      documentActivePriceList:     null,
      applyPriceListOptions:       {},
      commercialDocumentRounding:  null,
      fallback:                    "NO_SHARED_LIST",
    };
  }

  const scope = resolveScope(args.sharedPriceList, args.forceScope);

  if (scope === "PER_LINE_LEGACY") {
    return {
      mode: "PER_LINE_LEGACY",
      documentActivePriceList: {
        id:   args.sharedPriceList.id,
        name: args.sharedPriceList.name,
      },
      applyPriceListOptions:      {},
      commercialDocumentRounding: null,
      fallback:                   null,
    };
  }

  // PER_DOCUMENT
  const commercialDocumentRounding = buildCommercialDocRoundingFromPriceList(args.sharedPriceList);
  return {
    mode: "PER_DOCUMENT",
    documentActivePriceList: {
      id:   args.sharedPriceList.id,
      name: args.sharedPriceList.name,
    },
    applyPriceListOptions: {
      suppressLineHechuraRounding:       true,
      suppressLineMetalPhysicalRounding: true,
    },
    commercialDocumentRounding,
    fallback: null,
  };
}

/**
 * Determina el scope efectivo del documento.
 *
 * Prioridad:
 *   1. `forceScope` (override de runtime — solo para tests).
 *   2. `PriceList.commercialRoundingScope` persistido en DB.
 *   3. `PER_LINE_LEGACY` (default seguro si no hay valor — back-compat total).
 *
 * Nota: el env override `PRICING_COMMERCIAL_DOC_ROUNDING_ENABLED` se eliminó
 * en Etapa D'. Si una corrida lo encuentra setado, se ignora — la fuente de
 * verdad es ahora el campo persistido por lista (configurable desde la UI).
 */
function resolveScope(
  list:       PriceListSummaryForContext,
  forceScope: "PER_LINE_LEGACY" | "PER_DOCUMENT" | null | undefined,
): "PER_LINE_LEGACY" | "PER_DOCUMENT" {
  if (forceScope) return forceScope;
  return list.commercialRoundingScope ?? "PER_LINE_LEGACY";
}

/**
 * Construye el `CommercialDocRoundingInput` desde la config de la lista.
 *
 * Reglas:
 *   · `mode = METAL_HECHURA` + `roundingTarget = METAL` → `BREAKDOWN`.
 *   · Cualquier otra cosa → `UNIFIED` con `(roundingMode, roundingDirection)`.
 *   · Si todos los redondeos relevantes son NONE → devuelve `null` (la capa
 *     nueva no actúa; el wiring igual marca PER_DOCUMENT por consistencia).
 */
export function buildCommercialDocRoundingFromPriceList(
  list: PriceListSummaryForContext,
): CommercialDocRoundingInput | null {
  if (list.mode === "METAL_HECHURA" && list.roundingTarget === "METAL") {
    // BREAKDOWN — dos buckets disjuntos.
    const metalActive =
      list.commercialRoundingMetalDomain === "PHYSICAL" &&
      isModeActive(list.roundingMode);
    const hechuraActive = isModeActive(list.roundingModeHechura);
    if (!metalActive && !hechuraActive) return null;

    return {
      scope: "BREAKDOWN",
      metal: {
        mode:      metalActive ? (list.roundingMode as CommercialDocRoundingMode) : "NONE",
        direction: (list.roundingDirection as CommercialDocRoundingDirection) ?? "NEAREST",
      },
      hechura: {
        mode:      hechuraActive ? (list.roundingModeHechura as CommercialDocRoundingMode) : "NONE",
        direction: (list.roundingDirectionHechura as CommercialDocRoundingDirection) ?? "NEAREST",
      },
    };
  }

  // UNIFIED — un único redondeo sobre el total monetario comercial.
  if (!isModeActive(list.roundingMode)) return null;
  return {
    scope:     "UNIFIED",
    mode:      list.roundingMode as CommercialDocRoundingMode,
    direction: (list.roundingDirection as CommercialDocRoundingDirection) ?? "NEAREST",
  };
}

function isModeActive(mode: string | null | undefined): boolean {
  return typeof mode === "string" && mode.length > 0 && mode !== "NONE";
}

// ─────────────────────────────────────────────────────────────────────────────
// Defensa anti-doble — assertion que el caller debe correr antes de invocar
// `computeSaleDocumentTotals`.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Lanza error si la configuración del caller es inconsistente:
 *   · `commercialDocumentRounding` activo PERO flags PER_LINE apagados → doble.
 *   · Flags PER_LINE apagados PERO `commercialDocumentRounding` null → ningún
 *     redondeo aplica (sí, este caso técnicamente NO duplica, pero el caller
 *     se quedó a mitad de wiring — fail-fast para diagnosticarlo).
 *
 * El caller debe llamar este helper inmediatamente después de
 * `resolveDocCommercialRoundingContext` y antes de pasar las opciones al motor.
 */
export function assertCommercialDocRoundingConsistency(
  ctx: DocCommercialRoundingContext,
): void {
  const suppressing =
    ctx.applyPriceListOptions.suppressLineHechuraRounding === true ||
    ctx.applyPriceListOptions.suppressLineMetalPhysicalRounding === true;
  const hasDocLayer = ctx.commercialDocumentRounding != null;

  // Caso A: capa documento activa pero NO se suprime PER_LINE → DOBLE.
  if (hasDocLayer && !suppressing) {
    throw new Error(
      "[commercial-doc-rounding] Configuración inconsistente: " +
      "commercialDocumentRounding está activo pero los flags PER_LINE NO se suprimieron. " +
      "Esto produciría DOBLE redondeo (línea + documento). " +
      "Revisar el wiring del caller (sales.service).",
    );
  }

  // Caso B: flags PER_LINE suprimidos pero NO hay capa documento → wiring incompleto.
  if (suppressing && !hasDocLayer && ctx.mode === "PER_DOCUMENT") {
    // Excepción: si la lista activa NO tiene redondeo configurado, es OK que
    // commercialDocumentRounding sea null aunque suprimamos PER_LINE — no hay
    // delta que aplicar. Esto se admite porque el modo PER_DOCUMENT puede
    // estar activo en una lista sin redondeos.
    return;
  }
}
