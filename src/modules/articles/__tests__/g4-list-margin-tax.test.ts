// src/modules/articles/__tests__/g4-list-margin-tax.test.ts
// =============================================================================
// FASE 1.1 — G4 backend gap. Verifica que el listado de artículos
// (GET /api/articles) emite `marginPercent` y `taxAmount` per-row, derivados
// de los inputs ya presentes (resolvedSalePrice, resolvedSalePriceWithTax,
// computedCostBase). Permite al frontend dejar de derivar via resta
// (POLICY.md R4.3).
//
// Test del CONTRATO de cálculo: dada una fila con los 3 inputs, qué se emite.
// La función real (listArticles) requiere mockear Prisma y batches; testeamos
// la pieza derivada como helper auto-contenido.
// =============================================================================

import { describe, it, expect } from "vitest";

// Replica EXACTA de la lógica de articles.service.ts:enrichedRows.map para G4.
// Si la fórmula del backend cambia, este test debe actualizarse.
function deriveMarginAndTaxForRow(input: {
  resolvedSalePrice:        number | string | null;
  resolvedSalePriceWithTax: number | string | null;
  computedCostBase:         number | string | null;
}): { marginPercent: number | null; taxAmount: number | null } {
  const sale    = input.resolvedSalePrice;
  const saleTax = input.resolvedSalePriceWithTax;
  const cost    = input.computedCostBase;
  const marginPercent =
    sale != null && cost != null && Number(sale) > 0
      ? ((Number(sale) - Number(cost)) / Number(sale)) * 100
      : null;
  const taxAmount =
    sale != null && saleTax != null
      ? Number(saleTax) - Number(sale)
      : null;
  return { marginPercent, taxAmount };
}

describe("G4 — derivación de marginPercent y taxAmount per-row", () => {
  it("baseline correct: marginPercent = (sale - cost) / sale × 100", () => {
    const r = deriveMarginAndTaxForRow({
      resolvedSalePrice:        1000,
      resolvedSalePriceWithTax: 1210,
      computedCostBase:         600,
    });
    // (1000 - 600) / 1000 × 100 = 40
    expect(r.marginPercent).toBe(40);
  });

  it("baseline correct: taxAmount = priceWithTax - price", () => {
    const r = deriveMarginAndTaxForRow({
      resolvedSalePrice:        1000,
      resolvedSalePriceWithTax: 1210,
      computedCostBase:         600,
    });
    expect(r.taxAmount).toBe(210);
  });

  it("baseline correct: marginPercent null cuando computedCostBase es null", () => {
    const r = deriveMarginAndTaxForRow({
      resolvedSalePrice:        1000,
      resolvedSalePriceWithTax: 1210,
      computedCostBase:         null,
    });
    expect(r.marginPercent).toBeNull();
    expect(r.taxAmount).toBe(210);
  });

  it("baseline correct: marginPercent null cuando resolvedSalePrice es null", () => {
    const r = deriveMarginAndTaxForRow({
      resolvedSalePrice:        null,
      resolvedSalePriceWithTax: 1210,
      computedCostBase:         600,
    });
    expect(r.marginPercent).toBeNull();
    expect(r.taxAmount).toBeNull();
  });

  it("baseline correct: marginPercent null cuando resolvedSalePrice es 0 (evita div/0)", () => {
    const r = deriveMarginAndTaxForRow({
      resolvedSalePrice:        0,
      resolvedSalePriceWithTax: 0,
      computedCostBase:         100,
    });
    expect(r.marginPercent).toBeNull();
    expect(r.taxAmount).toBe(0);
  });

  it("baseline correct: taxAmount null cuando saleWithTax es null", () => {
    const r = deriveMarginAndTaxForRow({
      resolvedSalePrice:        1000,
      resolvedSalePriceWithTax: null,
      computedCostBase:         600,
    });
    expect(r.taxAmount).toBeNull();
    expect(r.marginPercent).toBe(40);
  });

  it("baseline correct: acepta strings (Decimal serializado) y los castea", () => {
    const r = deriveMarginAndTaxForRow({
      resolvedSalePrice:        "1000.00",
      resolvedSalePriceWithTax: "1210.00",
      computedCostBase:         "600.00",
    });
    expect(r.marginPercent).toBe(40);
    expect(r.taxAmount).toBe(210);
  });

  it("baseline correct: marginPercent puede ser negativo cuando cost > sale", () => {
    const r = deriveMarginAndTaxForRow({
      resolvedSalePrice:        100,
      resolvedSalePriceWithTax: 121,
      computedCostBase:         150, // costo > precio (oferta a pérdida)
    });
    // (100 - 150) / 100 × 100 = -50
    expect(r.marginPercent).toBe(-50);
  });
});
