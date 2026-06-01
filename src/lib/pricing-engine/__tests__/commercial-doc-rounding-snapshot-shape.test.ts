// src/lib/pricing-engine/__tests__/commercial-doc-rounding-snapshot-shape.test.ts
//
// Etapa D' — Contrato de persistencia del snapshot.
//
// `confirmSale` persiste el snapshot mediante passthrough trivial:
//   data.commercialDocumentRoundingSnapshot =
//     totals.commercialDocumentRoundingApplied ?? Prisma.JsonNull
//
// Este test valida que el snapshot generado por `applyCommercialDocumentRounding`
// (UNIFIED, BREAKDOWN, con/sin fallback) es:
//
//   1. JSON-serializable byte-equivalente (mismo objeto entre preview y lo que
//      se guarda en DB y lo que se devuelve al leer el Sale).
//   2. Reversible vía `JSON.parse(JSON.stringify(snapshot))` sin pérdida.
//   3. Estructuralmente compatible con `Prisma.InputJsonValue`.
//
// Cubre el caso null → la columna se persiste como NULL via Prisma.JsonNull
// (verificación documental — el helper devuelve null, el caller lo mapea).

import { describe, it, expect } from "vitest";
import {
  applyCommercialDocumentRounding,
  type CommercialDocRoundingApplied,
  type CommercialDocRoundingInput,
  type CommercialDocMetalParentInput,
} from "../commercial-document-rounding.js";

function metalsOro(grams: number): CommercialDocMetalParentInput[] {
  return [{ metalParentId: "OroFino", metalParentName: "Oro Fino", gramsPure: grams, metalPricePerGram: 80000 }];
}

function roundtrip(s: CommercialDocRoundingApplied | null): unknown {
  return JSON.parse(JSON.stringify(s));
}

describe("Snapshot persistible — UNIFIED", () => {
  it("snapshot UNIFIED es JSON-roundtrip estable", () => {
    const r = applyCommercialDocumentRounding({
      totalComercialPostTax: 182091.10,
      metalValuationSum:     0,
      config: { scope: "UNIFIED", mode: "HUNDRED", direction: "NEAREST" },
    });
    expect(r.applied).not.toBeNull();
    const persisted = roundtrip(r.applied);
    expect(persisted).toEqual(r.applied);
    // Solo primitivos JSON.
    expect(typeof JSON.stringify(persisted)).toBe("string");
  });
});

describe("Snapshot persistible — BREAKDOWN", () => {
  it("snapshot BREAKDOWN (metal + hechura) preserva todos los campos", () => {
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
    const persisted = roundtrip(r.applied!) as CommercialDocRoundingApplied;
    expect(persisted.source).toBe("PRICE_LIST");
    expect(persisted.scope).toBe("BREAKDOWN");
    expect(persisted.totalAdjustment).toBeTypeOf("number");
    expect(persisted.breakdown!.metals[0].metalParentId).toBe("OroFino");
    expect(persisted.breakdown!.hechura.source).toBe("PRICE_LIST_HECHURA");
    // Idéntico al original.
    expect(JSON.stringify(persisted)).toBe(JSON.stringify(r.applied));
  });

  it("snapshot con fallback ALL_NONE persiste el fallback", () => {
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
    const persisted = roundtrip(r.applied!) as CommercialDocRoundingApplied;
    expect(persisted.fallback).toBe("ALL_NONE");
    expect(persisted.totalAdjustment).toBe(0);
  });
});

describe("Snapshot persistible — null path", () => {
  it("sin movimiento + sin fallback → null (caller persiste Prisma.JsonNull)", () => {
    const r = applyCommercialDocumentRounding({
      totalComercialPostTax: 200,    // ya está en múltiplo de 100
      metalValuationSum:     0,
      config: { scope: "UNIFIED", mode: "HUNDRED", direction: "NEAREST" },
    });
    expect(r.applied).toBeNull();
    // Documenta el contrato del caller (sales.service.confirmSale):
    //   data.commercialDocumentRoundingSnapshot = applied ?? Prisma.JsonNull
    // El test no usa Prisma real para no acoplar, pero verifica el flag.
    const wouldPersistNull = r.applied == null;
    expect(wouldPersistNull).toBe(true);
  });
});

describe("Determinismo persistible — preview = confirm", () => {
  it("dos corridas idénticas producen JSON byte-equivalente", () => {
    const config: CommercialDocRoundingInput = {
      scope:   "BREAKDOWN",
      metal:   { mode: "DECIMAL_1", direction: "NEAREST" },
      hechura: { mode: "HUNDRED",   direction: "NEAREST" },
    };
    const args = {
      totalComercialPostTax: 281091.10,
      metalValuationSum:     99000,
      metalsByParent:        metalsOro(1.2375),
      config,
    };
    const a = applyCommercialDocumentRounding(args).applied;
    const b = applyCommercialDocumentRounding(args).applied;
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    // Y el roundtrip JSON también es estable.
    expect(JSON.stringify(roundtrip(a))).toBe(JSON.stringify(roundtrip(b)));
  });
});
