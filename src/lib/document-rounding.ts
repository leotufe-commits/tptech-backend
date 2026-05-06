// src/lib/document-rounding.ts
// ============================================================================
// Helper compartido para leer la política de redondeo a nivel comprobante
// (modo UNIFIED) configurada en `Jewelry`. Lo consumen los flujos que llaman
// al pricing-engine y necesitan pasar `suppressListDeferredRounding` al motor
// y/o `documentRounding` a `computeSaleDocumentTotals`.
//
// Vive fuera de `src/modules/sales/` a propósito: tanto Sales como Articles
// (Simulador) lo necesitan, y no queremos acoplar Articles a Sales.
//
// Reglas:
//   · Si `documentRoundingEnabled = false` o `documentRoundingMode = NONE`,
//     la política devuelta es INERTE: el motor se comporta como antes.
//   · Si la política está activa:
//       - `suppressListDeferredRounding = true` → el motor IGNORA el redondeo
//         diferido (`applyOn = NET | TOTAL`) de las listas para evitar doble
//         redondeo.
//       - `documentRounding = { mode, direction }` → se pasa a
//         `computeSaleDocumentTotals` para que redondee el total final del
//         comprobante. Solo lo usa el flujo de venta; el simulador NO debe
//         aplicarlo (es per-artículo, no tiene comprobante).
// ============================================================================

import { prisma } from "./prisma.js";
import type { DocumentRoundingInput } from "./pricing-engine/pricing-engine.js";

export type DocumentRoundingPolicy = {
  suppressListDeferredRounding: boolean;
  documentRounding:             DocumentRoundingInput | null;
};

export const DOC_ROUNDING_INERT: DocumentRoundingPolicy = {
  suppressListDeferredRounding: false,
  documentRounding:             null,
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
      documentRoundingEnabled:   true,
      documentRoundingMode:      true,
      documentRoundingDirection: true,
    },
  });
  const active =
    !!j?.documentRoundingEnabled &&
    !!j?.documentRoundingMode &&
    j.documentRoundingMode !== "NONE";
  if (!active) return DOC_ROUNDING_INERT;
  return {
    suppressListDeferredRounding: true,
    documentRounding: {
      mode:      j!.documentRoundingMode      as DocumentRoundingInput["mode"],
      direction: j!.documentRoundingDirection as DocumentRoundingInput["direction"],
    },
  };
}
