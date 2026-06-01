// src/lib/commercial-physical-rounding-apply.ts
// =============================================================================
// Etapa C-comercial / C2 (POLICY §R-Rounding-14) — Helper PURO de aplicación
// del redondeo COMERCIAL PHYSICAL sobre UN metal padre.
//
// Contrato canónico TPTech (POLICY §R-Rounding-14):
//   DESGLOSADO = metal padre físico (gramos) + hechura / saldo monetario.
//
// Este helper se ocupa SÓLO del dominio metal padre. La hechura sigue
// monetariamente (no es competencia de este módulo).
//
// REUSO ABSOLUTO DEL ALGORITMO FINANCIERO:
//
//   `applyCommercialPhysicalRoundingForMetal` (y la versión batch
//   `applyCommercialPhysicalRoundingForMetals`) llaman directamente a
//   `roundDocumentMetalGrams` del módulo `document-physical-rounding.ts`
//   con `sourceTag = "COMMERCIAL_PHYSICAL_ROUNDING"`. La matemática y la
//   semántica son IDÉNTICAS a las del redondeo Financiero PHYSICAL — la
//   ÚNICA diferencia visible en el output es el campo `source` del entry.
//
//   Esa decisión es deliberada: garantiza que "mismo input → mismo
//   resultado físico" entre los dos mecanismos, alineado con la regla
//   canónica. Si en el futuro el algoritmo cambia, cambia en UN único
//   lugar (`document-physical-rounding.ts`) y ambos consumidores lo
//   heredan.
//
// C2 NO toca runtime de ninguna lista — Etapa C3 (motor de lista) será
// quien orqueste estos helpers a nivel línea, por cada step
// `COST_LINES_METAL` post-enrich. Aquí dejamos los helpers PUROS,
// reusables y testeables en aislamiento.
// =============================================================================

import {
  roundDocumentMetalGrams,
  type PhysicalMetalInput,
  type PhysicalMetalRoundingConfig,
  type PhysicalRoundingMode,
  type PhysicalRoundingDirection,
  type RoundedMetalEntry,
  type RoundDocumentMetalGramsResult,
} from "./document-physical-rounding.js";

/** Input por metal padre del helper unitario. Más liviano que
 *  `RoundDocumentMetalGramsInput` porque ya viene resuelta la config a
 *  aplicar a este metal (`mode` + `direction` directamente). El caller
 *  decide si tomó la config del `byMetalParentId` o del `fallback`.
 *
 *  Las claves coinciden 1:1 con el "Input esperado" definido en el brief
 *  de C2:
 *
 *    {
 *      metalParentId,
 *      metalParentName,
 *      preGrams,
 *      metalPricePerGram,
 *      roundingMode,
 *      roundingDirection,
 *      source: "COMMERCIAL_PHYSICAL_ROUNDING"
 *    } */
export interface ApplyCommercialPhysicalRoundingForMetalInput {
  metalParentId:     string | null;
  metalParentName:   string;
  preGrams:          number;
  metalPricePerGram: number | null;
  roundingMode:      PhysicalRoundingMode;
  roundingDirection: PhysicalRoundingDirection;
}

/**
 * Aplica el redondeo comercial PHYSICAL a UN metal padre. Devuelve el
 * entry canónico (`RoundedMetalEntry`) con `source =
 * "COMMERCIAL_PHYSICAL_ROUNDING"`. Cero matemática nueva — delega en
 * `roundDocumentMetalGrams` que ya conoce todos los modos / direcciones
 * y maneja los fallbacks (NO_METAL_PRICE, INVALID_GRAMS, etc.).
 *
 * Output (paralelo al brief):
 *   {
 *     metalParentId, metalParentName,
 *     preGrams, postGrams, deltaGrams,
 *     metalPricePerGram,
 *     monetaryEquivalent,
 *     source: "COMMERCIAL_PHYSICAL_ROUNDING",
 *     mode, direction,
 *     fallback   ← campo agregado para auditoría (no inventado:
 *                  proviene del helper financiero existente).
 *   }
 */
export function applyCommercialPhysicalRoundingForMetal(
  input: ApplyCommercialPhysicalRoundingForMetalInput,
): RoundedMetalEntry {
  const metal: PhysicalMetalInput = {
    metalParentId:     input.metalParentId,
    metalParentName:   input.metalParentName,
    grams:             input.preGrams,
    metalPricePerGram: input.metalPricePerGram,
  };
  const cfg: PhysicalMetalRoundingConfig = {
    mode:      input.roundingMode,
    direction: input.roundingDirection,
  };
  const result = roundDocumentMetalGrams({
    metals:                [metal],
    // Pasamos la config como FALLBACK para forzar que se aplique a este
    // metal sin tener que armar un `byMetalParentId` con la clave del id
    // (que puede ser `null` cuando el caller aún no resolvió el metalId).
    configByMetalParentId: {},
    fallbackConfig:        cfg,
    sourceTag:             "COMMERCIAL_PHYSICAL_ROUNDING",
  });
  // result.metals tiene EXACTAMENTE una entry por contrato (un único
  // metal en input.metals).
  return result.metals[0]!;
}

// ──────────────────────────────────────────────────────────────────────────
// Versión batch — útil para Etapa C3 cuando una línea tiene varios metales
// padre y queremos resolver de una sola vez. Reusa la firma del helper
// financiero salvo por el `sourceTag` forzado.
// ──────────────────────────────────────────────────────────────────────────

/** Input batch — espejo del de `roundDocumentMetalGrams` pero con
 *  `sourceTag` implícito a `COMMERCIAL_PHYSICAL_ROUNDING`. */
export interface ApplyCommercialPhysicalRoundingBatchInput {
  metals: PhysicalMetalInput[];
  configByMetalParentId: Record<string, PhysicalMetalRoundingConfig>;
  fallbackConfig?: PhysicalMetalRoundingConfig | null;
}

/** Versión batch — aplica a varios metales padre a la vez. Wrapper trivial
 *  sobre `roundDocumentMetalGrams` que fija `sourceTag` y mantiene el
 *  output shape (`RoundDocumentMetalGramsResult`). */
export function applyCommercialPhysicalRoundingForMetals(
  input: ApplyCommercialPhysicalRoundingBatchInput,
): RoundDocumentMetalGramsResult {
  return roundDocumentMetalGrams({
    metals:                input.metals,
    configByMetalParentId: input.configByMetalParentId ?? {},
    fallbackConfig:        input.fallbackConfig ?? null,
    sourceTag:             "COMMERCIAL_PHYSICAL_ROUNDING",
  });
}

// ──────────────────────────────────────────────────────────────────────────
// Contrato de snapshot — definido pero NO persistido todavía. Etapa C3
// será quien lo agregue al snapshot del motor de lista
// (`metalHechuraDetail.physical`). Lo dejamos acá como tipo público para
// que el motor pueda tipar el campo cuando lo agregue.
// ──────────────────────────────────────────────────────────────────────────

/** Snapshot del redondeo COMERCIAL PHYSICAL por metal padre. Es alias
 *  del `RoundedMetalEntry` con el `source` restringido al literal
 *  comercial — útil para que el motor de lista declare el campo del
 *  snapshot sin confundir orígenes. */
export interface CommercialPhysicalRoundingSnapshotEntry
  extends Omit<RoundedMetalEntry, "source"> {
  source: "COMMERCIAL_PHYSICAL_ROUNDING";
}

/** Bloque agregado del snapshot por LÍNEA del motor de lista (Etapa C3).
 *  Paralelo a `documentRoundingApplied.breakdown.metalPhysical` del
 *  financiero. */
export interface CommercialPhysicalRoundingSnapshot {
  metals:                  CommercialPhysicalRoundingSnapshotEntry[];
  /** Σ `metals[].monetaryEquivalent` round2. = aporte $ neto al
   *  `metalSale` post-redondeo cuando el motor encadene C3. */
  metalMonetaryEquivalent: number;
  /** Fallback a nivel batch (input vacío). `null` cuando hay al menos
   *  un metal procesado. */
  fallback:                | null
                           | "NO_BREAKDOWN_DATA"
                           | "NO_METALS_TO_ROUND";
}
