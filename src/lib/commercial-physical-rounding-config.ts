// src/lib/commercial-physical-rounding-config.ts
// =============================================================================
// Etapa C-comercial / C2 (POLICY §R-Rounding-14) — Resolver de configuración
// de redondeo COMERCIAL PHYSICAL desde un row de `PriceList`.
//
// Wrapper trivial sobre el helper NEUTRAL
// `resolvePhysicalRoundingConfig(domain, jsonRaw)` definido en
// `document-physical-rounding-config.ts`. La razón de tener un wrapper
// dedicado por mecanismo es la simetría con `resolveDocumentPhysicalRoundingConfig`
// (financiero / Jewelry) y la trazabilidad de los call-sites — el motor de
// lista importa ESTE helper, no el genérico.
//
// CONTRATO CANÓNICO (POLICY §R-Rounding-14):
//   DESGLOSADO = metal padre físico + hechura / saldo monetario.
// Este helper se ocupa SÓLO del dominio metal padre del redondeo comercial.
// La hechura sigue redondeada monetariamente por el motor de lista existente.
//
// Pure function — sin DB, sin async, sin side effects. Mismo input simple
// (row mínimo Prisma-like) → mismo output. El parser hereda las reglas de
// degradación segura del helper neutral.
//
// C2 NO toca runtime — Etapa C3 (motor de lista, `pricing-engine.pricelist.ts`)
// será quien lo consume con un row de PriceList real.
// =============================================================================

import {
  resolvePhysicalRoundingConfig,
  type ResolvedPhysicalRoundingConfig,
  type DocumentRoundingMetalDomain,
} from "./document-physical-rounding-config.js";

/** Subset PriceList-like que el helper necesita leer. Tipado al mínimo para
 *  no acoplar acá el modelo Prisma completo (la firma queda estable cuando
 *  PriceList gana campos nuevos sin que C2 se entere). */
export interface CommercialPhysicalRoundingPriceListLike {
  /** Discriminador del dominio metal del redondeo COMERCIAL. Default
   *  `MONETARY` (legacy) cuando el campo no está. */
  commercialRoundingMetalDomain?: DocumentRoundingMetalDomain | null;
  /** JSON crudo persistido. Shape canónico:
   *    { byMetalParentId: { [metalId]: { mode, direction } },
   *      fallback: { mode, direction } } */
  commercialPhysicalRoundingConfig?: unknown;
}

/**
 * Resuelve la configuración de redondeo COMERCIAL PHYSICAL para alimentar
 * al helper `roundDocumentMetalGrams` (Etapa C3 será quien lo invoque
 * desde el motor de lista).
 *
 * Reglas (delegadas al helper neutral):
 *   · `commercialRoundingMetalDomain !== "PHYSICAL"` → `{ enabled: false, ... }`.
 *     El caller NO debe correr el redondeo físico — el comportamiento
 *     legacy MONETARY del motor de lista sigue siendo el camino activo.
 *   · Domain PHYSICAL + JSON `null` → `{ enabled: true, ... config vacía }`.
 *     El helper físico marcará cada metal con `fallback="NO_CONFIG"`.
 *   · Domain PHYSICAL + JSON con shape parcialmente válido → entries
 *     buenas se conservan, las inválidas se descartan, `hasInvalidEntries=true`.
 *
 * Cero diferencias matemáticas con `resolveDocumentPhysicalRoundingConfig`:
 * los dos delegan al mismo helper neutral. Lo único distinto es de qué
 * fila Prisma sacan el dominio + JSON.
 */
export function resolveCommercialPhysicalRoundingConfig(
  priceList: CommercialPhysicalRoundingPriceListLike | null | undefined,
): ResolvedPhysicalRoundingConfig {
  if (!priceList) {
    return {
      enabled: false,
      configByMetalParentId: {},
      fallbackConfig: null,
      hasInvalidEntries: false,
    };
  }
  return resolvePhysicalRoundingConfig(
    priceList.commercialRoundingMetalDomain ?? null,
    priceList.commercialPhysicalRoundingConfig,
  );
}
