// src/lib/pricing-engine/__tests__/commercial-doc-rounding-line-context.test.ts
//
// Etapa D' (cierre conceptual) — Contrato del campo `appliedAt` en el snapshot
// emitido por `applyCommercialDocumentRounding`.
//
// El helper SIEMPRE emite `appliedAt: "DOCUMENT"` cuando actúa (es la capa
// PER_DOCUMENT). El conteo de líneas (`appliedToLineCount`) lo agrega el
// caller en `previewSale` / `confirmSale` (no este helper).
//
// REGLA DE ORO verificada:
//   - El frontend NUNCA infiere `appliedAt`. El helper lo emite explícito.

import { describe, it, expect } from "vitest";
import {
  applyCommercialDocumentRounding,
  type CommercialDocMetalParentInput,
} from "../commercial-document-rounding.js";

function metalsOro(grams: number): CommercialDocMetalParentInput[] {
  return [{ metalParentId: "OroFino", metalParentName: "Oro Fino", gramsPure: grams, metalPricePerGram: 80000 }];
}

describe("appliedAt — siempre 'DOCUMENT' cuando el helper actúa", () => {
  it("UNIFIED con movimiento → appliedAt='DOCUMENT'", () => {
    const r = applyCommercialDocumentRounding({
      totalComercialPostTax: 182091.10,
      metalValuationSum:     0,
      config: { scope: "UNIFIED", mode: "HUNDRED", direction: "NEAREST" },
    });
    expect(r.applied).not.toBeNull();
    expect(r.applied!.appliedAt).toBe("DOCUMENT");
  });

  it("UNIFIED fallback ALL_NONE → snapshot informativo con appliedAt='DOCUMENT'", () => {
    const r = applyCommercialDocumentRounding({
      totalComercialPostTax: 100,
      metalValuationSum:     0,
      config: { scope: "UNIFIED", mode: "NONE", direction: "NEAREST" },
    });
    expect(r.applied).not.toBeNull();
    expect(r.applied!.appliedAt).toBe("DOCUMENT");
    expect(r.applied!.fallback).toBe("ALL_NONE");
  });

  it("BREAKDOWN con movimiento → appliedAt='DOCUMENT'", () => {
    const r = applyCommercialDocumentRounding({
      totalComercialPostTax: 281091.10,
      metalValuationSum:     99000,
      metalsByParent:        metalsOro(1.2375),
      config: {
        scope:   "BREAKDOWN",
        metal:   { mode: "DECIMAL_1", direction: "NEAREST" },
        hechura: { mode: "HUNDRED",   direction: "NEAREST" },
      },
    });
    expect(r.applied).not.toBeNull();
    expect(r.applied!.appliedAt).toBe("DOCUMENT");
    expect(r.applied!.scope).toBe("BREAKDOWN");
  });

  it("BREAKDOWN ALL_NONE → snapshot informativo con appliedAt='DOCUMENT'", () => {
    const r = applyCommercialDocumentRounding({
      totalComercialPostTax: 100,
      metalValuationSum:     50,
      metalsByParent:        metalsOro(0.5),
      config: {
        scope:   "BREAKDOWN",
        metal:   { mode: "NONE", direction: "NEAREST" },
        hechura: { mode: "NONE", direction: "NEAREST" },
      },
    });
    expect(r.applied).not.toBeNull();
    expect(r.applied!.appliedAt).toBe("DOCUMENT");
    expect(r.applied!.fallback).toBe("ALL_NONE");
  });

  it("Sin movimiento + sin fallback → applied=null (no se emite el snapshot)", () => {
    const r = applyCommercialDocumentRounding({
      totalComercialPostTax: 200,
      metalValuationSum:     0,
      config: { scope: "UNIFIED", mode: "HUNDRED", direction: "NEAREST" },
    });
    expect(r.applied).toBeNull();
  });
});

describe("appliedToLineCount — responsabilidad del caller (no del helper)", () => {
  it("el helper NO emite appliedToLineCount (es metadata del wiring)", () => {
    const r = applyCommercialDocumentRounding({
      totalComercialPostTax: 182091.10,
      metalValuationSum:     0,
      config: { scope: "UNIFIED", mode: "HUNDRED", direction: "NEAREST" },
    });
    expect(r.applied).not.toBeNull();
    expect((r.applied as any).appliedToLineCount).toBeUndefined();
  });

  it("contrato del caller: { ...snapshot, appliedAt, appliedToLineCount }", () => {
    // Simulamos lo que hace el wiring en sales.service.ts:
    const r = applyCommercialDocumentRounding({
      totalComercialPostTax: 182091.10,
      metalValuationSum:     0,
      config: { scope: "UNIFIED", mode: "HUNDRED", direction: "NEAREST" },
    });
    const ctx = r.applied
      ? { ...r.applied, appliedAt: "DOCUMENT" as const, appliedToLineCount: 3 }
      : null;
    expect(ctx).not.toBeNull();
    expect(ctx!.appliedAt).toBe("DOCUMENT");
    expect(ctx!.appliedToLineCount).toBe(3);
    expect(ctx!.unified?.adjustment).toBe(8.90);  // passthrough del snapshot
  });
});
