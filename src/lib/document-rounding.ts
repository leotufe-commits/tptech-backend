// src/lib/document-rounding.ts
// ============================================================================
// Helper compartido para leer la política de redondeo a nivel comprobante
// (Etapa 1B — UNIFIED / BREAKDOWN / BOTH) configurada en `Jewelry`. Lo
// consumen los flujos que llaman al pricing-engine y necesitan pasar
// `suppressListDeferredRounding` al motor y/o `documentRounding` a
// `computeSaleDocumentTotals`.
//
// Vive fuera de `src/modules/sales/` a propósito: tanto Sales como Articles
// (Simulador) lo necesitan, y no queremos acoplar Articles a Sales.
//
// Reglas:
//   · Si `documentRoundingEnabled = false` o no hay ningún componente con
//     modo distinto de NONE para el scope efectivo, la política devuelta es
//     INERTE: el motor se comporta como antes.
//   · Si la política está activa:
//       - `suppressListDeferredRounding = true` → el motor IGNORA el redondeo
//         diferido (`applyOn = NET | TOTAL`) de las listas para evitar doble
//         redondeo (regla idéntica para los 3 scopes — el motor doc es la
//         única autoridad cuando está activo).
//       - `documentRounding = { scope, mode, direction, breakdown? }` → se
//         pasa a `computeSaleDocumentTotals`. El motor aplica las capas en
//         cascada (BREAKDOWN → UNIFIED en BOTH) y persiste el snapshot.
// ============================================================================

import { prisma } from "./prisma.js";
import type {
  DocumentRoundingInput,
  DocumentRoundingScope,
} from "./pricing-engine/pricing-engine.js";
import {
  resolveDocumentPhysicalRoundingConfig,
  type ResolvedPhysicalRoundingConfig,
  type DocumentRoundingMetalDomain,
} from "./document-physical-rounding-config.js";

export type DocumentRoundingPolicy = {
  suppressListDeferredRounding: boolean;
  documentRounding:             DocumentRoundingInput | null;
  /** Scope efectivo resuelto desde DB. Útil para los validadores y para
   *  loguear en el snapshot. Mismo valor que `documentRounding?.scope`. */
  scope:                        DocumentRoundingScope | null;
  /** Etapa D2 — dominio del metal en BREAKDOWN. Default MONETARY. */
  metalDomain:                  DocumentRoundingMetalDomain;
  /** Etapa D3 — config física resuelta. `enabled=false` cuando metalDomain=MONETARY,
   *  domain PHYSICAL pero policy inactiva, o no hay config válida. El caller
   *  invoca `applyDocumentPhysicalRounding` solo cuando `enabled === true`. */
  physical:                     ResolvedPhysicalRoundingConfig;
};

export const DOC_ROUNDING_INERT: DocumentRoundingPolicy = {
  suppressListDeferredRounding: false,
  documentRounding:             null,
  scope:                        null,
  metalDomain:                  "MONETARY",
  physical: {
    enabled: false,
    configByMetalParentId: {},
    fallbackConfig: null,
    hasInvalidEntries: false,
  },
};

export async function loadDocumentRoundingConfig(
  jewelryId: string,
): Promise<DocumentRoundingPolicy> {
  // Defensa contra mocks parciales de prisma en tests: si el cliente no
  // expone `jewelry.findUnique`, devolvemos la política inerte. En
  // producción siempre existe.
  if (!(prisma as any).jewelry?.findUnique) return DOC_ROUNDING_INERT;
  const j = await prisma.jewelry.findUnique({
    where:  { id: jewelryId },
    select: {
      documentRoundingEnabled:          true,
      documentRoundingMode:             true,
      documentRoundingDirection:        true,
      documentRoundingScope:            true,
      documentRoundingModeMetal:        true,
      documentRoundingDirectionMetal:   true,
      documentRoundingModeHechura:      true,
      documentRoundingDirectionHechura: true,
      // Etapa D2 — dominio del metal + config física.
      documentRoundingMetalDomain:      true,
      documentPhysicalRoundingConfig:   true,
    },
  });
  if (!j?.documentRoundingEnabled) return DOC_ROUNDING_INERT;

  const metalDomain: DocumentRoundingMetalDomain =
    j.documentRoundingMetalDomain === "PHYSICAL" ? "PHYSICAL" : "MONETARY";
  const physical = resolveDocumentPhysicalRoundingConfig({
    documentRoundingMetalDomain:    metalDomain,
    documentPhysicalRoundingConfig: j.documentPhysicalRoundingConfig as any,
  });

  // Scope efectivo. Default UNIFIED para tenants previos a Etapa 1B (la
  // columna trae default UNIFIED desde Prisma, pero el helper también
  // tolera `null`/`undefined` por si el caller pasa por mocks viejos).
  const scope: DocumentRoundingScope = (j.documentRoundingScope as DocumentRoundingScope | undefined) ?? "UNIFIED";

  const unifiedMode        = j.documentRoundingMode             as DocumentRoundingInput["mode"];
  const unifiedDirection   = j.documentRoundingDirection        as DocumentRoundingInput["direction"];
  // Etapa D3 — cuando metalDomain=PHYSICAL, el motor NO debe redondear metal
  // monetario (capa 15.metal). Lo suprimimos aquí forzando NONE, y capa 16
  // (`applyDocumentPhysicalRounding`) lo redondea físicamente afuera del
  // motor. Esto evita doble redondeo y mantiene `pricing-engine.document.ts`
  // sin cambios.
  const physicalMetalActive = metalDomain === "PHYSICAL" && physical.enabled;
  const metalMode          = physicalMetalActive
    ? ("NONE" as DocumentRoundingInput["mode"])
    : (j.documentRoundingModeMetal as DocumentRoundingInput["mode"]);
  const metalDirection     = j.documentRoundingDirectionMetal   as DocumentRoundingInput["direction"];
  const hechuraMode        = j.documentRoundingModeHechura      as DocumentRoundingInput["mode"];
  const hechuraDirection   = j.documentRoundingDirectionHechura as DocumentRoundingInput["direction"];

  const unifiedActive  = !!unifiedMode && unifiedMode !== "NONE";
  // Metal y hechura tienen pares independientes — basta con que UNO esté en
  // un modo efectivo para que la capa BREAKDOWN tenga algo que aplicar.
  const breakdownActive =
    (!!metalMode   && metalMode   !== "NONE") ||
    (!!hechuraMode && hechuraMode !== "NONE");

  // Una política está activa cuando el componente que corresponde al scope
  // tiene un modo configurado. UNIFIED → unifiedActive. BREAKDOWN →
  // breakdownActive. BOTH → al menos uno de los dos.
  //
  // Etapa D3 — además, si metalDomain=PHYSICAL y hay config física válida,
  // la política BREAKDOWN/BOTH también está activa por su lado físico
  // (aunque metal monetario esté en NONE — el redondeo lo hace capa 16).
  const active =
    (scope === "UNIFIED"   && unifiedActive)  ||
    (scope === "BREAKDOWN" && (breakdownActive || physicalMetalActive)) ||
    (scope === "BOTH"      && (unifiedActive || breakdownActive || physicalMetalActive));
  if (!active) return { ...DOC_ROUNDING_INERT, metalDomain, physical };

  const documentRounding: DocumentRoundingInput = {
    scope,
    mode:      unifiedMode,
    direction: unifiedDirection,
    ...(scope === "BREAKDOWN" || scope === "BOTH"
      ? {
          breakdown: {
            // Metal y hechura conservan sus pares modo/dirección persistidos.
            // Si una sub-capa está en NONE, `applyRoundingLayer` la deja
            // pasar sin tocar el componente (delta=0).
            metal:   { mode: metalMode,   direction: metalDirection },
            hechura: { mode: hechuraMode, direction: hechuraDirection },
          },
        }
      : {}),
  };

  return {
    suppressListDeferredRounding: true,
    documentRounding,
    scope,
    metalDomain,
    physical,
  };
}
