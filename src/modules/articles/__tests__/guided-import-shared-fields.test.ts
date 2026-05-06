// src/modules/articles/__tests__/guided-import-shared-fields.test.ts
//
// Tests de regresión para la propagación de campos compartidos en el import Guided.
//
// Cubre:
//   A. checkParentConsistency — detección de inconsistencias en los campos nuevos
//      (IVA, ajuste global de costo, modo de stock, flags del artículo)
//   B. applyGuidedInheritedFields — persistencia de campos del padre
//      (estado, modo de stock, flags, dimensiones, ajuste de costo)

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock Prisma ──────────────────────────────────────────────────────────────
const mockPrisma = vi.hoisted(() => ({
  article:          { update: vi.fn().mockResolvedValue({}) },
  articleCostLine:  { deleteMany: vi.fn().mockResolvedValue({}), create: vi.fn().mockResolvedValue({}) },
}));

vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

// Imports DESPUÉS del mock
import {
  checkParentConsistency,
  applyGuidedInheritedFields,
  saveCostLinesForArticle,
  extractGuidedCostBlocks,
  costBlockSignature,
} from "../articles.import.service.js";
import type { CostLinesContext } from "../articles.import.service.js";

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Construye filas de variante con las cabeceras mínimas requeridas. */
function makeVariantRows(
  skuPadre: string,
  variants: { sku: string; fields: Record<string, string> }[],
): Record<string, string>[] {
  return variants.map(({ sku, fields }) => ({
    "SKU Padre": skuPadre,
    "SKU":       sku,
    "Nombre":    `Nombre ${sku}`,
    // Defaults vacíos para evitar false-positives
    "Categoría": "", "Grupo": "", "Proveedor": "", "Marca": "", "Fabricante": "",
    "Estado": "", "Descripción": "", "IVA 1": "", "IVA 2": "", "IVA 3": "",
    "Ajuste tipo": "", "Ajuste valor": "", "Ajuste modo": "",
    "Modo de stock": "", "Unidad": "", "En tienda": "", "Acepta devolución": "",
    "Vender sin variantes": "",
    ...fields,
  }));
}

/** Helper compacto: crea el artId y los mapas nulos para applyGuidedInheritedFields. */
const noopSupplier = () => null;
const noopTaxIds   = () => [] as string[];

beforeEach(() => {
  vi.clearAllMocks();
});

// ─────────────────────────────────────────────────────────────────────────────
// A. checkParentConsistency — nuevos campos del padre
// ─────────────────────────────────────────────────────────────────────────────

describe("checkParentConsistency — IVA (nuevos campos)", () => {
  it("IVA 1 distinto entre variantes → error bloqueante", () => {
    const rows = makeVariantRows("PAD-IVA", [
      { sku: "V1", fields: { "IVA 1": "IVA 21%" } },
      { sku: "V2", fields: { "IVA 1": "IVA 10,5%" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-IVA")).toBe(true);
    expect(result.get("PAD-IVA")!.some(m => m.includes("IVA 1"))).toBe(true);
  });

  it("IVA 2 distinto entre variantes → error bloqueante", () => {
    const rows = makeVariantRows("PAD-IVA2", [
      { sku: "V1", fields: { "IVA 2": "Ingresos Brutos 3%" } },
      { sku: "V2", fields: { "IVA 2": "Ingresos Brutos 5%" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-IVA2")).toBe(true);
    expect(result.get("PAD-IVA2")!.some(m => m.includes("IVA 2"))).toBe(true);
  });

  it("IVA 3 distinto entre variantes → error bloqueante", () => {
    const rows = makeVariantRows("PAD-IVA3", [
      { sku: "V1", fields: { "IVA 3": "Impuesto A" } },
      { sku: "V2", fields: { "IVA 3": "Impuesto B" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-IVA3")).toBe(true);
  });

  it("IVA 1 igual en todas las variantes → sin error", () => {
    const rows = makeVariantRows("PAD-IVA-OK", [
      { sku: "V1", fields: { "IVA 1": "IVA 21%" } },
      { sku: "V2", fields: { "IVA 1": "IVA 21%" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-IVA-OK")).toBe(false);
  });
});

describe("checkParentConsistency — Ajuste global de costo (nuevos campos)", () => {
  it("Ajuste tipo distinto → error bloqueante", () => {
    const rows = makeVariantRows("PAD-ADJ-T", [
      { sku: "V1", fields: { "Ajuste tipo": "Bonificación" } },
      { sku: "V2", fields: { "Ajuste tipo": "Recargo" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-ADJ-T")).toBe(true);
    expect(result.get("PAD-ADJ-T")!.some(m => m.includes("tipo de ajuste de costo"))).toBe(true);
  });

  it("Ajuste valor distinto → error bloqueante", () => {
    const rows = makeVariantRows("PAD-ADJ-V", [
      { sku: "V1", fields: { "Ajuste valor": "10" } },
      { sku: "V2", fields: { "Ajuste valor": "20" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-ADJ-V")).toBe(true);
    expect(result.get("PAD-ADJ-V")!.some(m => m.includes("valor de ajuste de costo"))).toBe(true);
  });

  it("Ajuste modo distinto → error bloqueante", () => {
    const rows = makeVariantRows("PAD-ADJ-M", [
      { sku: "V1", fields: { "Ajuste modo": "Porcentaje" } },
      { sku: "V2", fields: { "Ajuste modo": "Monto fijo" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-ADJ-M")).toBe(true);
    expect(result.get("PAD-ADJ-M")!.some(m => m.includes("modo de ajuste de costo"))).toBe(true);
  });

  it("Ajuste completo igual en todas → sin error", () => {
    const rows = makeVariantRows("PAD-ADJ-OK", [
      { sku: "V1", fields: { "Ajuste tipo": "Bonificación", "Ajuste valor": "10", "Ajuste modo": "Porcentaje" } },
      { sku: "V2", fields: { "Ajuste tipo": "Bonificación", "Ajuste valor": "10", "Ajuste modo": "Porcentaje" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-ADJ-OK")).toBe(false);
  });
});

describe("checkParentConsistency — Modo de stock, flags y unidad (nuevos campos)", () => {
  it("Modo de stock distinto → error bloqueante", () => {
    const rows = makeVariantRows("PAD-SM", [
      { sku: "V1", fields: { "Modo de stock": "Por artículo" } },
      { sku: "V2", fields: { "Modo de stock": "Sin stock" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-SM")).toBe(true);
    expect(result.get("PAD-SM")!.some(m => m.includes("modo de stock"))).toBe(true);
  });

  it("Unidad distinta → error bloqueante", () => {
    const rows = makeVariantRows("PAD-UOM", [
      { sku: "V1", fields: { "Unidad": "gramos" } },
      { sku: "V2", fields: { "Unidad": "unidad" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-UOM")).toBe(true);
    expect(result.get("PAD-UOM")!.some(m => m.includes("unidad de medida"))).toBe(true);
  });

  it("En tienda distinto → error bloqueante", () => {
    const rows = makeVariantRows("PAD-TIENDA", [
      { sku: "V1", fields: { "En tienda": "Sí" } },
      { sku: "V2", fields: { "En tienda": "No" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-TIENDA")).toBe(true);
    expect(result.get("PAD-TIENDA")!.some(m => m.includes("en tienda"))).toBe(true);
  });

  it("Acepta devolución distinto → error bloqueante", () => {
    const rows = makeVariantRows("PAD-DEV", [
      { sku: "V1", fields: { "Acepta devolución": "Sí" } },
      { sku: "V2", fields: { "Acepta devolución": "No" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-DEV")).toBe(true);
    expect(result.get("PAD-DEV")!.some(m => m.includes("acepta devolución"))).toBe(true);
  });

  it("Vender sin variantes distinto → error bloqueante", () => {
    const rows = makeVariantRows("PAD-SINVAR", [
      { sku: "V1", fields: { "Vender sin variantes": "Sí" } },
      { sku: "V2", fields: { "Vender sin variantes": "No" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-SINVAR")).toBe(true);
    expect(result.get("PAD-SINVAR")!.some(m => m.includes("vender sin variantes"))).toBe(true);
  });
});

describe("checkParentConsistency — campos de variante no bloquean al padre", () => {
  it("Peso distinto entre variantes → NO genera inconsistencia (es campo de variante)", () => {
    // Peso (g) es un campo propio de cada variante — no debe bloquear
    const rows = makeVariantRows("PAD-PESO", [
      { sku: "V1", fields: { "Peso (g)": "5" } },
      { sku: "V2", fields: { "Peso (g)": "10" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-PESO")).toBe(false);
  });

  it("Activo distinto entre variantes → NO genera inconsistencia (es campo de variante)", () => {
    const rows = makeVariantRows("PAD-ACTIVO", [
      { sku: "V1", fields: { "Activo": "Sí" } },
      { sku: "V2", fields: { "Activo": "No" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-ACTIVO")).toBe(false);
  });

  it("Notas distintas → NO genera inconsistencia (es campo de variante)", () => {
    const rows = makeVariantRows("PAD-NOTAS", [
      { sku: "V1", fields: { "Notas": "nota A" } },
      { sku: "V2", fields: { "Notas": "nota B" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-NOTAS")).toBe(false);
  });

  it("Pto. Reposición distinto → NO genera inconsistencia", () => {
    const rows = makeVariantRows("PAD-REPOS", [
      { sku: "V1", fields: { "Pto. Reposición": "2" } },
      { sku: "V2", fields: { "Pto. Reposición": "5" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-REPOS")).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// B. applyGuidedInheritedFields — persistencia al artículo padre
// ─────────────────────────────────────────────────────────────────────────────

describe("applyGuidedInheritedFields — estado y modo de stock", () => {
  it("Estado=Activo → article.update recibe status=ACTIVE", async () => {
    const row = makeVariantRows("P", [{ sku: "V1", fields: { "Estado": "Activo" } }])[0];
    await applyGuidedInheritedFields("art-1", row, new Map(), new Map(), noopSupplier, noopTaxIds);
    const data = mockPrisma.article.update.mock.calls[0][0].data;
    expect(data.status).toBe("ACTIVE");
  });

  it("Estado=Borrador → article.update recibe status=DRAFT", async () => {
    const row = makeVariantRows("P", [{ sku: "V1", fields: { "Estado": "Borrador" } }])[0];
    await applyGuidedInheritedFields("art-1", row, new Map(), new Map(), noopSupplier, noopTaxIds);
    const data = mockPrisma.article.update.mock.calls[0][0].data;
    expect(data.status).toBe("DRAFT");
  });

  it("Modo de stock=Por artículo → article.update recibe stockMode=BY_ARTICLE", async () => {
    const row = makeVariantRows("P", [{ sku: "V1", fields: { "Modo de stock": "Por artículo" } }])[0];
    await applyGuidedInheritedFields("art-1", row, new Map(), new Map(), noopSupplier, noopTaxIds);
    const data = mockPrisma.article.update.mock.calls[0][0].data;
    expect(data.stockMode).toBe("BY_ARTICLE");
  });

  it("Modo de stock=Sin stock → article.update recibe stockMode=NO_STOCK", async () => {
    const row = makeVariantRows("P", [{ sku: "V1", fields: { "Modo de stock": "Sin stock" } }])[0];
    await applyGuidedInheritedFields("art-1", row, new Map(), new Map(), noopSupplier, noopTaxIds);
    const data = mockPrisma.article.update.mock.calls[0][0].data;
    expect(data.stockMode).toBe("NO_STOCK");
  });
});

describe("applyGuidedInheritedFields — flags del artículo", () => {
  it("En tienda=Sí → showInStore=true", async () => {
    const row = makeVariantRows("P", [{ sku: "V1", fields: { "En tienda": "Sí" } }])[0];
    await applyGuidedInheritedFields("art-1", row, new Map(), new Map(), noopSupplier, noopTaxIds);
    const data = mockPrisma.article.update.mock.calls[0][0].data;
    expect(data.showInStore).toBe(true);
  });

  it("En tienda=No → showInStore=false", async () => {
    const row = makeVariantRows("P", [{ sku: "V1", fields: { "En tienda": "No" } }])[0];
    await applyGuidedInheritedFields("art-1", row, new Map(), new Map(), noopSupplier, noopTaxIds);
    const data = mockPrisma.article.update.mock.calls[0][0].data;
    expect(data.showInStore).toBe(false);
  });

  it("Acepta devolución=Sí → isReturnable=true", async () => {
    const row = makeVariantRows("P", [{ sku: "V1", fields: { "Acepta devolución": "Sí" } }])[0];
    await applyGuidedInheritedFields("art-1", row, new Map(), new Map(), noopSupplier, noopTaxIds);
    const data = mockPrisma.article.update.mock.calls[0][0].data;
    expect(data.isReturnable).toBe(true);
  });

  it("Vender sin variantes=Sí → sellWithoutVariants=true", async () => {
    const row = makeVariantRows("P", [{ sku: "V1", fields: { "Vender sin variantes": "sí" } }])[0];
    await applyGuidedInheritedFields("art-1", row, new Map(), new Map(), noopSupplier, noopTaxIds);
    const data = mockPrisma.article.update.mock.calls[0][0].data;
    expect(data.sellWithoutVariants).toBe(true);
  });

  it("Unidad=gramos → unitOfMeasure='gramos'", async () => {
    const row = makeVariantRows("P", [{ sku: "V1", fields: { "Unidad": "gramos" } }])[0];
    await applyGuidedInheritedFields("art-1", row, new Map(), new Map(), noopSupplier, noopTaxIds);
    const data = mockPrisma.article.update.mock.calls[0][0].data;
    expect(data.unitOfMeasure).toBe("gramos");
  });
});

describe("applyGuidedInheritedFields — ajuste global de costo", () => {
  it("tipo=Bonificación, modo=Porcentaje, valor=10 → BONUS/PERCENTAGE/10", async () => {
    const row = makeVariantRows("P", [{
      sku: "V1",
      fields: { "Ajuste tipo": "Bonificación", "Ajuste modo": "Porcentaje", "Ajuste valor": "10" },
    }])[0];
    await applyGuidedInheritedFields("art-1", row, new Map(), new Map(), noopSupplier, noopTaxIds);
    const data = mockPrisma.article.update.mock.calls[0][0].data;
    expect(data.manualAdjustmentKind).toBe("BONUS");
    expect(data.manualAdjustmentType).toBe("PERCENTAGE");
    expect(data.manualAdjustmentValue).toBe(10);
  });

  it("tipo=Recargo, modo=Monto fijo, valor=500 → SURCHARGE/FIXED_AMOUNT/500", async () => {
    const row = makeVariantRows("P", [{
      sku: "V1",
      fields: { "Ajuste tipo": "Recargo", "Ajuste modo": "Monto fijo", "Ajuste valor": "500" },
    }])[0];
    await applyGuidedInheritedFields("art-1", row, new Map(), new Map(), noopSupplier, noopTaxIds);
    const data = mockPrisma.article.update.mock.calls[0][0].data;
    expect(data.manualAdjustmentKind).toBe("SURCHARGE");
    expect(data.manualAdjustmentType).toBe("FIXED_AMOUNT");
    expect(data.manualAdjustmentValue).toBe(500);
  });

  it("valor con coma decimal → se parsea correctamente (1.234,56 → 1234.56 no; '10,5' → 10.5)", async () => {
    const row = makeVariantRows("P", [{
      sku: "V1",
      fields: { "Ajuste tipo": "Bonificación", "Ajuste valor": "10,5", "Ajuste modo": "Porcentaje" },
    }])[0];
    await applyGuidedInheritedFields("art-1", row, new Map(), new Map(), noopSupplier, noopTaxIds);
    const data = mockPrisma.article.update.mock.calls[0][0].data;
    expect(data.manualAdjustmentValue).toBeCloseTo(10.5, 2);
  });
});

describe("applyGuidedInheritedFields — dimensiones físicas", () => {
  it("Largo=5, Ancho=3, Alto=2, Unidad dim.=cm → dimensionLength/Width/Height/Unit correctos", async () => {
    const row = makeVariantRows("P", [{
      sku: "V1",
      fields: { "Largo": "5", "Ancho": "3", "Alto": "2", "Unidad dim.": "cm" },
    }])[0];
    await applyGuidedInheritedFields("art-1", row, new Map(), new Map(), noopSupplier, noopTaxIds);
    const data = mockPrisma.article.update.mock.calls[0][0].data;
    expect(data.dimensionLength).toBe(5);
    expect(data.dimensionWidth).toBe(3);
    expect(data.dimensionHeight).toBe(2);
    expect(data.dimensionUnit).toBe("cm");
  });
});

describe("applyGuidedInheritedFields — fila vacía no llama a update", () => {
  it("fila sin ningún campo del padre → NO llama a prisma.article.update", async () => {
    const row = makeVariantRows("P", [{ sku: "V1", fields: {} }])[0];
    await applyGuidedInheritedFields("art-1", row, new Map(), new Map(), noopSupplier, noopTaxIds);
    expect(mockPrisma.article.update).not.toHaveBeenCalled();
  });
});

describe("applyGuidedInheritedFields — categoría y grupo se resuelven por mapa", () => {
  it("Categoría presente en catMap → categoryId asignado al padre", async () => {
    const catMap = new Map([["anillos", "cat-id-123"]]);
    const row    = makeVariantRows("P", [{ sku: "V1", fields: { "Categoría": "Anillos" } }])[0];
    await applyGuidedInheritedFields("art-1", row, catMap, new Map(), noopSupplier, noopTaxIds);
    const data = mockPrisma.article.update.mock.calls[0][0].data;
    expect(data.categoryId).toBe("cat-id-123");
  });

  it("Categoría ausente del catMap → categoryId NO se incluye en el update", async () => {
    const catMap = new Map<string, string>(); // vacío
    const row    = makeVariantRows("P", [{ sku: "V1", fields: { "Categoría": "Categoría Inexistente" } }])[0];
    await applyGuidedInheritedFields("art-1", row, catMap, new Map(), noopSupplier, noopTaxIds);
    // Si no hay nada más en la fila → no debe llamar a update en absoluto
    expect(mockPrisma.article.update).not.toHaveBeenCalled();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// C. checkParentConsistency — dimensiones físicas (nueva cobertura)
// ─────────────────────────────────────────────────────────────────────────────

describe("checkParentConsistency — dimensiones físicas (nuevos campos)", () => {
  it("Largo distinto entre variantes → error bloqueante", () => {
    const rows = makeVariantRows("PAD-DIM", [
      { sku: "V1", fields: { "Largo": "5" } },
      { sku: "V2", fields: { "Largo": "10" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-DIM")).toBe(true);
    expect(result.get("PAD-DIM")!.some(m => m.includes("dimensión Largo"))).toBe(true);
  });

  it("Ancho distinto entre variantes → error bloqueante", () => {
    const rows = makeVariantRows("PAD-DIM2", [
      { sku: "V1", fields: { "Ancho": "3" } },
      { sku: "V2", fields: { "Ancho": "6" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-DIM2")).toBe(true);
    expect(result.get("PAD-DIM2")!.some(m => m.includes("dimensión Ancho"))).toBe(true);
  });

  it("Alto distinto entre variantes → error bloqueante", () => {
    const rows = makeVariantRows("PAD-DIM3", [
      { sku: "V1", fields: { "Alto": "2" } },
      { sku: "V2", fields: { "Alto": "8" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-DIM3")).toBe(true);
    expect(result.get("PAD-DIM3")!.some(m => m.includes("dimensión Alto"))).toBe(true);
  });

  it("Unidad dim. distinta entre variantes → error bloqueante", () => {
    const rows = makeVariantRows("PAD-DIM4", [
      { sku: "V1", fields: { "Unidad dim.": "cm" } },
      { sku: "V2", fields: { "Unidad dim.": "mm" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-DIM4")).toBe(true);
    expect(result.get("PAD-DIM4")!.some(m => m.includes("unidad de dimensión"))).toBe(true);
  });

  it("Dimensiones iguales en todas las variantes → sin error", () => {
    const rows = makeVariantRows("PAD-DIM-OK", [
      { sku: "V1", fields: { "Largo": "5", "Ancho": "3", "Alto": "2", "Unidad dim.": "cm" } },
      { sku: "V2", fields: { "Largo": "5", "Ancho": "3", "Alto": "2", "Unidad dim.": "cm" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-DIM-OK")).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// D. saveCostLinesForArticle — persistencia de composición de costo
// ─────────────────────────────────────────────────────────────────────────────

/** Contexto vacío para tests que no necesitan resolver monedas ni variantes de metal. */
function makeEmptyCtx(jewelryId = "j1"): CostLinesContext {
  return {
    jewelryId,
    currByCode:          new Map(),
    currByName:          new Map(),
    metalVariantByLabel: new Map(),
  };
}

describe("saveCostLinesForArticle — artículo padre directo (variantId=null)", () => {
  it("fila con HECHURA 500 → crea ArticleCostLine en el padre", async () => {
    const row: Record<string, string> = {
      "Tipo 1": "Hechura", "Precio Unit. 1": "500",
      "Descripción 1": "", "Cantidad 1": "1",
      "Merma % 1": "", "Moneda 1": "", "Bonif/Recargo 1": "",
    };
    await saveCostLinesForArticle("art-1", row, null, makeEmptyCtx());

    expect(mockPrisma.articleCostLine.deleteMany).toHaveBeenCalledOnce();
    expect(mockPrisma.articleCostLine.create).toHaveBeenCalledOnce();
    const data = mockPrisma.articleCostLine.create.mock.calls[0][0].data;
    expect(data.type).toBe("HECHURA");
    expect(Number(data.unitValue)).toBe(500);
    expect(data.articleId).toBe("art-1");
    expect(data.jewelryId).toBe("j1");
  });

  it("fila sin bloques → NO toca ArticleCostLine (preserva líneas existentes)", async () => {
    const row: Record<string, string> = {
      "Tipo 1": "", "Precio Unit. 1": "", "Descripción 1": "",
    };
    await saveCostLinesForArticle("art-1", row, null, makeEmptyCtx());

    expect(mockPrisma.articleCostLine.deleteMany).not.toHaveBeenCalled();
    expect(mockPrisma.articleCostLine.create).not.toHaveBeenCalled();
  });

  it("fila con 2 bloques → crea 2 ArticleCostLine con sortOrder 0 y 1", async () => {
    const row: Record<string, string> = {
      "Tipo 1": "Hechura", "Precio Unit. 1": "200", "Descripción 1": "", "Cantidad 1": "1", "Merma % 1": "", "Moneda 1": "", "Bonif/Recargo 1": "",
      "Tipo 2": "Hechura", "Precio Unit. 2": "300", "Descripción 2": "", "Cantidad 2": "2", "Merma % 2": "", "Moneda 2": "", "Bonif/Recargo 2": "",
    };
    await saveCostLinesForArticle("art-1", row, null, makeEmptyCtx());

    expect(mockPrisma.articleCostLine.create).toHaveBeenCalledTimes(2);
    const calls = mockPrisma.articleCostLine.create.mock.calls;
    expect(calls[0][0].data.sortOrder).toBe(0);
    expect(calls[1][0].data.sortOrder).toBe(1);
  });
});

describe("saveCostLinesForArticle — fila de variante", () => {
  it("variante con Origen costo='Hereda del padre' y bloques → actualiza el padre (misma lógica que 'Propio')", async () => {
    // FIX: "Hereda del padre" con bloques SÍ debe actualizar las cost lines del padre.
    // El export de artículos con variantes no genera fila de padre — solo filas de variante
    // con "Hereda del padre". Si estos bloques no se aplican, el padre nunca se actualiza.
    const row: Record<string, string> = {
      "Tipo 1": "Hechura", "Precio Unit. 1": "500",
      "Descripción 1": "", "Cantidad 1": "1",
      "Merma % 1": "", "Moneda 1": "", "Bonif/Recargo 1": "",
      "Origen costo": "Hereda del padre",
    };
    await saveCostLinesForArticle("art-1", row, "var-1", makeEmptyCtx());

    // Con el fix: deleteMany + create corren igual que con "Propio"
    expect(mockPrisma.articleCostLine.deleteMany).toHaveBeenCalledTimes(1);
    expect(mockPrisma.articleCostLine.create).toHaveBeenCalledTimes(1);
    const data = mockPrisma.articleCostLine.create.mock.calls[0][0].data;
    expect(data.articleId).toBe("art-1");
    expect(Number(data.unitValue)).toBe(500);
  });

  it("variante sin bloques y sin Origen costo → NO escribe (hereda del padre por defecto)", async () => {
    const row: Record<string, string> = {
      "Tipo 1": "", "Precio Unit. 1": "", "Origen costo": "",
    };
    await saveCostLinesForArticle("art-1", row, "var-1", makeEmptyCtx());

    expect(mockPrisma.articleCostLine.deleteMany).not.toHaveBeenCalled();
    expect(mockPrisma.articleCostLine.create).not.toHaveBeenCalled();
  });

  it("variante CON bloques propios (sin Origen costo heredado) → guarda en el PADRE (artId)", async () => {
    // Caso: import manual con variantes que traen su propia composición
    // checkParentConsistency ya garantizó que todas son iguales
    const row: Record<string, string> = {
      "Tipo 1": "Hechura", "Precio Unit. 1": "700",
      "Descripción 1": "", "Cantidad 1": "1",
      "Merma % 1": "", "Moneda 1": "", "Bonif/Recargo 1": "",
      "Origen costo": "",
    };
    await saveCostLinesForArticle("art-padre", row, "var-1", makeEmptyCtx("j1"));

    // Debe guardar en el PADRE (articleId=art-padre), NO en la variante
    expect(mockPrisma.articleCostLine.deleteMany).toHaveBeenCalledWith({
      where: { articleId: "art-padre", jewelryId: "j1" },
    });
    expect(mockPrisma.articleCostLine.create).toHaveBeenCalledOnce();
    const data = mockPrisma.articleCostLine.create.mock.calls[0][0].data;
    expect(data.articleId).toBe("art-padre");
    // variantId NO debe estar en los datos (la línea pertenece siempre al padre)
    expect(data.variantId).toBeUndefined();
  });

  it("bonificación '-10%' → lineAdjKind=BONUS, lineAdjType=PERCENTAGE, lineAdjValue=10", async () => {
    const row: Record<string, string> = {
      "Tipo 1": "Hechura", "Precio Unit. 1": "500",
      "Descripción 1": "", "Cantidad 1": "1",
      "Merma % 1": "", "Moneda 1": "", "Bonif/Recargo 1": "-10%",
      "Origen costo": "",
    };
    await saveCostLinesForArticle("art-1", row, null, makeEmptyCtx());

    const data = mockPrisma.articleCostLine.create.mock.calls[0][0].data;
    expect(data.lineAdjKind).toBe("BONUS");
    expect(data.lineAdjType).toBe("PERCENTAGE");
    expect(data.lineAdjValue).toBe(10);
  });

  it("recargo '+500' fijo → lineAdjKind=SURCHARGE, lineAdjType=FIXED_AMOUNT, lineAdjValue=500", async () => {
    const row: Record<string, string> = {
      "Tipo 1": "Hechura", "Precio Unit. 1": "500",
      "Descripción 1": "", "Cantidad 1": "1",
      "Merma % 1": "", "Moneda 1": "", "Bonif/Recargo 1": "+500",
      "Origen costo": "",
    };
    await saveCostLinesForArticle("art-1", row, null, makeEmptyCtx());

    const data = mockPrisma.articleCostLine.create.mock.calls[0][0].data;
    expect(data.lineAdjKind).toBe("SURCHARGE");
    expect(data.lineAdjType).toBe("FIXED_AMOUNT");
    expect(data.lineAdjValue).toBe(500);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// E. Roundtrip export→import — simetría de composición y campos heredados
// ─────────────────────────────────────────────────────────────────────────────

describe("Roundtrip export→import — booleans y costBlocks", () => {
  it("booleans exportados como 'SI' → applyGuidedInheritedFields los parsea como true", async () => {
    // El export usa xfmtBool: true → "SI", false → "NO", null/undefined → ""
    const row = makeVariantRows("P", [{
      sku: "V1",
      fields: { "En tienda": "SI", "Acepta devolución": "NO", "Vender sin variantes": "SI" },
    }])[0];
    await applyGuidedInheritedFields("art-1", row, new Map(), new Map(), noopSupplier, noopTaxIds);
    const data = mockPrisma.article.update.mock.calls[0][0].data;
    expect(data.showInStore).toBe(true);
    expect(data.isReturnable).toBe(false);
    expect(data.sellWithoutVariants).toBe(true);
  });

  it("campo exportado como '' (null original) → applyGuidedInheritedFields NO lo escribe (preserva valor DB)", async () => {
    // xfmtBool(null) → "" → el import lo omite → el padre no se toca para ese campo
    const row = makeVariantRows("P", [{
      sku: "V1",
      fields: { "En tienda": "" },  // null original → "" en Excel
    }])[0];
    await applyGuidedInheritedFields("art-1", row, new Map(), new Map(), noopSupplier, noopTaxIds);
    // No hay ningún campo válido → no llama a update
    expect(mockPrisma.article.update).not.toHaveBeenCalled();
  });

  it("variantes exportadas con mismos bloques + 'Hereda del padre' → checkParentConsistency sin error", () => {
    // Simula archivo exportado: dos variantes del mismo padre con los bloques del padre copiados
    // y origenCosto="Hereda del padre"
    const variantRow1: Record<string, string> = {
      "SKU Padre": "PADRE-001", "SKU": "V1", "Nombre": "Anillo · Talle 12",
      "Tipo 1": "Hechura", "Precio Unit. 1": "500",
      "Descripción 1": "", "Cantidad 1": "1",
      "Merma % 1": "", "Moneda 1": "", "Bonif/Recargo 1": "",
      "Origen costo": "Hereda del padre",
      // Todos los campos compartidos iguales
      "Categoría": "Anillos", "Estado": "Activo",
    };
    const variantRow2: Record<string, string> = {
      ...variantRow1,
      "SKU": "V2", "Nombre": "Anillo · Talle 14",
    };

    const result = checkParentConsistency([variantRow1, variantRow2]);
    expect(result.has("PADRE-001")).toBe(false);
  });

  it("extractGuidedCostBlocks en fila exportada con 'Hereda del padre' → devuelve bloques (decisión de no guardar es de saveCostLinesForArticle)", () => {
    // extractGuidedCostBlocks es agnóstico del campo Origen costo — solo parsea los bloques
    // La decisión de saltear el guardado es de saveCostLinesForArticle
    const row: Record<string, string> = {
      "Tipo 1": "Hechura", "Precio Unit. 1": "500",
      "Descripción 1": "", "Cantidad 1": "1",
      "Merma % 1": "", "Moneda 1": "", "Bonif/Recargo 1": "",
      "Origen costo": "Hereda del padre",
    };
    const blocks = extractGuidedCostBlocks(row);
    expect(blocks).toHaveLength(1);
    expect(blocks[0].type).toBe("HECHURA");
    expect(blocks[0].unitPrice).toBe(500);
  });

  it("costBlockSignature idéntica para dos filas con iguales bloques → checkParentConsistency sin error", () => {
    const fields = {
      "Tipo 1": "Hechura", "Precio Unit. 1": "500",
      "Descripción 1": "", "Cantidad 1": "1",
      "Merma % 1": "", "Moneda 1": "", "Bonif/Recargo 1": "",
    };
    const rows = [
      { "SKU Padre": "P", "SKU": "V1", ...fields },
      { "SKU Padre": "P", "SKU": "V2", ...fields },
    ];
    // Las firmas deben ser idénticas
    expect(costBlockSignature(rows[0])).toBe(costBlockSignature(rows[1]));
    // Por tanto checkParentConsistency no debe reportar conflicto de costo
    const result = checkParentConsistency(rows);
    expect(result.has("P")).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// F. saveCostLinesForArticle — idempotencia y escenarios multi-variante
// ─────────────────────────────────────────────────────────────────────────────

describe("saveCostLinesForArticle — idempotencia (N variantes, mismos bloques)", () => {
  const ROW_HECHURA_500: Record<string, string> = {
    "Tipo 1": "Hechura", "Precio Unit. 1": "500",
    "Descripción 1": "", "Cantidad 1": "1",
    "Merma % 1": "", "Moneda 1": "", "Bonif/Recargo 1": "",
    "Origen costo": "",
  };

  it("llamar saveCostLinesForArticle 3 veces con el mismo bloque → 3 deleteMany + 3 create (idempotente en DB)", async () => {
    // Simula 3 variantes del mismo padre con la misma composición.
    // Cada variante dispara un delete+create al importarse.
    // En la DB real, el deleteMany previo garantiza que no se acumulan duplicados.
    const ctx = makeEmptyCtx();
    await saveCostLinesForArticle("art-p", ROW_HECHURA_500, "var-1", ctx);
    await saveCostLinesForArticle("art-p", ROW_HECHURA_500, "var-2", ctx);
    await saveCostLinesForArticle("art-p", ROW_HECHURA_500, "var-3", ctx);

    // 3 ciclos delete+create — siempre el artículo padre
    expect(mockPrisma.articleCostLine.deleteMany).toHaveBeenCalledTimes(3);
    expect(mockPrisma.articleCostLine.create).toHaveBeenCalledTimes(3);

    // Todos los creates apuntan al mismo artículo padre
    for (const call of mockPrisma.articleCostLine.create.mock.calls) {
      expect(call[0].data.articleId).toBe("art-p");
    }
    // El contenido del último create es el correcto
    const last = mockPrisma.articleCostLine.create.mock.calls.at(-1)![0].data;
    expect(last.type).toBe("HECHURA");
    expect(Number(last.unitValue)).toBe(500);
  });

  it("variantes con 'Hereda del padre' y bloques → cada variante actualiza el padre (3 ciclos idempotentes)", async () => {
    // FIX: "Hereda del padre" con bloques ahora SÍ corre el deleteMany+create.
    // Esto es correcto porque el export genera SOLO filas de variante (sin fila de padre),
    // todas con "Hereda del padre". Si no actualizaran el padre, el padre nunca se actualizaría.
    // Los 3 ciclos son idempotentes: mismo resultado final que con 1 ciclo.
    const ctx = makeEmptyCtx();
    const ROW_INHERITED = { ...ROW_HECHURA_500, "Origen costo": "Hereda del padre" };

    await saveCostLinesForArticle("art-p", ROW_HECHURA_500, "var-1", ctx);
    await saveCostLinesForArticle("art-p", ROW_INHERITED, "var-2", ctx);
    await saveCostLinesForArticle("art-p", ROW_INHERITED, "var-3", ctx);

    // 3 ciclos (uno por variante) — resultado final idéntico al del primer ciclo
    expect(mockPrisma.articleCostLine.deleteMany).toHaveBeenCalledTimes(3);
    expect(mockPrisma.articleCostLine.create).toHaveBeenCalledTimes(3);

    // El último create tiene los mismos valores que el primero (idempotente)
    const last = mockPrisma.articleCostLine.create.mock.calls.at(-1)![0].data;
    expect(Number(last.unitValue)).toBe(500);
    expect(last.articleId).toBe("art-p");
  });

  it("escenario completo: checkParentConsistency aprueba → N variantes escriben correctamente en padre", async () => {
    // 1. Primero confirmar que las variantes son consistentes (pure-function)
    const variantFields = {
      "Tipo 1": "Hechura", "Precio Unit. 1": "200",
      "Descripción 1": "", "Cantidad 1": "2",
      "Merma % 1": "", "Moneda 1": "", "Bonif/Recargo 1": "",
    };
    const rows = [
      { "SKU Padre": "PAD-M", "SKU": "V1", ...variantFields },
      { "SKU Padre": "PAD-M", "SKU": "V2", ...variantFields },
      { "SKU Padre": "PAD-M", "SKU": "V3", ...variantFields },
    ];
    // Verificar que no hay inconsistencia
    const consistency = checkParentConsistency(rows);
    expect(consistency.has("PAD-M")).toBe(false);

    // 2. Simular el procesamiento de cada variante
    const ctx = makeEmptyCtx("jw-1");
    const row = { ...variantFields, "Origen costo": "" };
    await saveCostLinesForArticle("art-padre", row, "var-1", ctx);
    await saveCostLinesForArticle("art-padre", row, "var-2", ctx);
    await saveCostLinesForArticle("art-padre", row, "var-3", ctx);

    // 3. El estado final: el padre tiene exactamente 1 línea de costo (HECHURA qty=2 unitValue=200)
    //    El deleteMany antes de cada create garantiza que no se acumulan duplicados en DB.
    const lastCreate = mockPrisma.articleCostLine.create.mock.calls.at(-1)![0].data;
    expect(lastCreate.articleId).toBe("art-padre");
    expect(lastCreate.jewelryId).toBe("jw-1");
    expect(lastCreate.type).toBe("HECHURA");
    expect(Number(lastCreate.quantity)).toBe(2);
    expect(Number(lastCreate.unitValue)).toBe(200);
  });
});

describe("saveCostLinesForArticle — resolución de moneda y tipo METAL", () => {
  it("moneda 'ARS · Peso Argentino' se resuelve por código → currencyId correcto", async () => {
    const ctx: CostLinesContext = {
      jewelryId:           "j1",
      currByCode:          new Map([["ARS", "curr-ars-id"]]),
      currByName:          new Map(),
      metalVariantByLabel: new Map(),
    };
    const row: Record<string, string> = {
      "Tipo 1": "Hechura", "Precio Unit. 1": "300",
      "Descripción 1": "", "Cantidad 1": "1",
      "Merma % 1": "", "Moneda 1": "ARS · Peso Argentino", "Bonif/Recargo 1": "",
      "Origen costo": "",
    };
    await saveCostLinesForArticle("art-1", row, null, ctx);
    const data = mockPrisma.articleCostLine.create.mock.calls[0][0].data;
    expect(data.currencyId).toBe("curr-ars-id");
  });

  it("moneda no encontrada → currencyId=undefined (usa base del tenant)", async () => {
    const ctx: CostLinesContext = {
      jewelryId: "j1",
      currByCode: new Map(),   // vacío → moneda no se resuelve
      currByName: new Map(),
      metalVariantByLabel: new Map(),
    };
    const row: Record<string, string> = {
      "Tipo 1": "Hechura", "Precio Unit. 1": "300",
      "Descripción 1": "", "Cantidad 1": "1",
      "Merma % 1": "", "Moneda 1": "USD", "Bonif/Recargo 1": "",
      "Origen costo": "",
    };
    await saveCostLinesForArticle("art-1", row, null, ctx);
    const data = mockPrisma.articleCostLine.create.mock.calls[0][0].data;
    expect(data.currencyId).toBeUndefined();
  });

  it("tipo METAL con descripcion 'Oro 18k' → metalVariantId resuelto desde metalVariantByLabel", async () => {
    const ctx: CostLinesContext = {
      jewelryId:           "j1",
      currByCode:          new Map(),
      currByName:          new Map(),
      metalVariantByLabel: new Map([["oro 18k", "mv-oro-18k-id"]]),
    };
    const row: Record<string, string> = {
      "Tipo 1": "Metal", "Precio Unit. 1": "",
      "Descripción 1": "Oro 18k", "Cantidad 1": "5",
      "Merma % 1": "3", "Moneda 1": "", "Bonif/Recargo 1": "",
      "Origen costo": "",
    };
    await saveCostLinesForArticle("art-1", row, null, ctx);
    const data = mockPrisma.articleCostLine.create.mock.calls[0][0].data;
    expect(data.type).toBe("METAL");
    expect(data.metalVariantId).toBe("mv-oro-18k-id");
    expect(Number(data.quantity)).toBe(5);
    expect(Number(data.mermaPercent)).toBe(3);
  });

  it("mermaPercent con coma decimal ('2,5') → se parsea como 2.5", async () => {
    const row: Record<string, string> = {
      "Tipo 1": "Metal", "Precio Unit. 1": "",
      "Descripción 1": "Plata 925", "Cantidad 1": "10",
      "Merma % 1": "2,5", "Moneda 1": "", "Bonif/Recargo 1": "",
      "Origen costo": "",
    };
    const ctx: CostLinesContext = {
      jewelryId: "j1", currByCode: new Map(), currByName: new Map(),
      metalVariantByLabel: new Map([["plata 925", "mv-plata-id"]]),
    };
    await saveCostLinesForArticle("art-1", row, null, ctx);
    const data = mockPrisma.articleCostLine.create.mock.calls[0][0].data;
    expect(Number(data.mermaPercent)).toBeCloseTo(2.5, 2);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// G. Regresión: cantidad correcta en variantes idénticas
// ─────────────────────────────────────────────────────────────────────────────

describe("Regresión — variants with identical cost lines should persist correct quantity", () => {
  it("3 variantes con Cantidad 1=3 (Metal) → quantity=3, NO quantity=1", async () => {
    // Reproduce el bug reportado: artículo padre con múltiples variantes que tienen
    // la misma composición de costo (cantidad=3). El sistema debe guardar quantity=3
    // y NO usar el fallback ?? 1 que produciría quantity=1 de forma silenciosa.
    const row: Record<string, string> = {
      "Tipo 1":         "Metal",
      "Descripción 1":  "Oro 18k Amarillo",
      "Cantidad 1":     "3",
      "Precio Unit. 1": "",
      "Merma % 1":      "2",
      "Moneda 1":       "",
      "Bonif/Recargo 1": "",
      "Origen costo":   "",
    };

    const ctx = makeEmptyCtx("jw-1");

    // Simula 3 variantes del mismo padre con la misma composición
    await saveCostLinesForArticle("art-padre", row, "var-1", ctx);
    await saveCostLinesForArticle("art-padre", row, "var-2", ctx);
    await saveCostLinesForArticle("art-padre", row, "var-3", ctx);

    // 3 ciclos delete+create — todos apuntan al padre
    expect(mockPrisma.articleCostLine.deleteMany).toHaveBeenCalledTimes(3);
    expect(mockPrisma.articleCostLine.create).toHaveBeenCalledTimes(3);

    // El último create (estado final) debe tener quantity=3, tipo METAL
    const lastData = mockPrisma.articleCostLine.create.mock.calls.at(-1)![0].data;
    expect(lastData.articleId).toBe("art-padre");
    expect(lastData.type).toBe("METAL");
    expect(Number(lastData.quantity)).toBe(3);   // ← la regresión: esto era 1 si Cantidad estaba vacía
    expect(Number(lastData.mermaPercent)).toBeCloseTo(2, 2);
  });

  it("bloque METAL sin Cantidad → bloque descartado (no se crea con quantity=1 silencioso)", async () => {
    // Caso: usuario tiene Tipo 1=Metal y Descripción pero olvidó rellenar Cantidad.
    // El comportamiento correcto es NO crear la línea (la preview ya advierte).
    // El comportamiento incorrecto (antes del fix) era crear con quantity=1.
    const row: Record<string, string> = {
      "Tipo 1":         "Metal",
      "Descripción 1":  "Oro 18k Amarillo",
      "Cantidad 1":     "",            // ← vacío: sin gramos
      "Precio Unit. 1": "",
      "Merma % 1":      "",
      "Moneda 1":       "",
      "Bonif/Recargo 1": "",
      "Origen costo":   "",
    };

    await saveCostLinesForArticle("art-1", row, null, makeEmptyCtx());

    // Sin bloques válidos → no debe tocar la DB
    expect(mockPrisma.articleCostLine.deleteMany).not.toHaveBeenCalled();
    expect(mockPrisma.articleCostLine.create).not.toHaveBeenCalled();
  });

  it("bloque HECHURA sin Cantidad → se crea con quantity=1 (default razonable para 1 operación)", async () => {
    // HECHURA con Cantidad vacía sí debe crearse con quantity=1 (default correcto).
    // Solo METAL requiere cantidad explícita.
    const row: Record<string, string> = {
      "Tipo 1":         "Hechura",
      "Descripción 1":  "",
      "Cantidad 1":     "",            // ← vacío: usa default=1
      "Precio Unit. 1": "500",
      "Merma % 1":      "",
      "Moneda 1":       "",
      "Bonif/Recargo 1": "",
      "Origen costo":   "",
    };

    await saveCostLinesForArticle("art-1", row, null, makeEmptyCtx());

    expect(mockPrisma.articleCostLine.create).toHaveBeenCalledOnce();
    const data = mockPrisma.articleCostLine.create.mock.calls[0][0].data;
    expect(data.type).toBe("HECHURA");
    expect(Number(data.quantity)).toBe(1);   // default para HECHURA
    expect(Number(data.unitValue)).toBe(500);
  });

  it("bloque METAL con Cantidad=0 → se crea con quantity=0 (cero es un valor explícito válido)", async () => {
    // Cantidad=0 no es null — debe persistirse como 0, no convertirse a 1.
    const row: Record<string, string> = {
      "Tipo 1":         "Metal",
      "Descripción 1":  "Plata 925",
      "Cantidad 1":     "0",
      "Precio Unit. 1": "",
      "Merma % 1":      "",
      "Moneda 1":       "",
      "Bonif/Recargo 1": "",
      "Origen costo":   "",
    };

    await saveCostLinesForArticle("art-1", row, null, makeEmptyCtx());

    expect(mockPrisma.articleCostLine.create).toHaveBeenCalledOnce();
    const data = mockPrisma.articleCostLine.create.mock.calls[0][0].data;
    expect(Number(data.quantity)).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// J. Regresión crítica — "Hereda del padre" no debe bloquear el update del padre
// ─────────────────────────────────────────────────────────────────────────────
//
// BUG: el export de artículos CON variantes NO genera fila propia para el padre.
// Solo genera filas de variante, todas con "Origen costo = Hereda del padre".
// La condición anterior bloqueaba saveCostLinesForArticle cuando isExplicitlyInherited=true,
// haciendo que las cost lines del padre nunca se actualizaran en un reimport.

describe("Regresión — 'Hereda del padre' no bloquea el update de cost lines del padre", () => {
  it("fila de variante con 'Hereda del padre' y bloques → actualiza el padre (deleteMany + create)", async () => {
    // Caso exacto del bug:
    //   - A002 ya existe en DB con bloque: Oro 18k, cantidad=1
    //   - Export genera variantes con "Origen costo = Hereda del padre" y los bloques del padre
    //   - Usuario cambia a: Oro 24k, cantidad=4 en el Excel
    //   - Reimport con onConflict="update"
    //   - Esperado: padre termina con Oro 24k, cantidad=4
    //   - Bug anterior: padre conservaba Oro 18k, cantidad=1

    const ctx: CostLinesContext = {
      jewelryId:           "jw-a002",
      currByCode:          new Map(),
      currByName:          new Map(),
      metalVariantByLabel: new Map([
        ["oro 18k amarillo", "mv-oro18k-id"],
        ["oro 24k",          "mv-oro24k-id"],
      ]),
    };

    // ── Primer import (crea A002 con Oro 18k, cantidad=1) ─────────────────
    const rowImport1: Record<string, string> = {
      "Tipo 1":         "Metal",
      "Descripción 1":  "Oro 18k Amarillo",
      "Cantidad 1":     "1",
      "Precio Unit. 1": "",
      "Merma % 1":      "",
      "Moneda 1":       "",
      "Bonif/Recargo 1": "",
      "Origen costo":   "",  // artículo padre: sin origen costo
    };
    await saveCostLinesForArticle("art-a002", rowImport1, null, ctx);
    expect(mockPrisma.articleCostLine.create).toHaveBeenCalledTimes(1);
    expect(Number(mockPrisma.articleCostLine.create.mock.calls[0][0].data.quantity)).toBe(1);
    expect(mockPrisma.articleCostLine.create.mock.calls[0][0].data.metalVariantId).toBe("mv-oro18k-id");
    vi.clearAllMocks();

    // ── Reimport desde fila de variante con "Hereda del padre" ────────────
    // (tal como llega del export: variant row con origen="Hereda del padre"
    //  pero con los bloques actualizados por el usuario a Oro 24k, cantidad=4)
    const rowVarianteHeredada: Record<string, string> = {
      "Tipo 1":         "Metal",
      "Descripción 1":  "Oro 24k",      // cambió
      "Cantidad 1":     "4",            // cambió
      "Precio Unit. 1": "",
      "Merma % 1":      "2",
      "Moneda 1":       "",
      "Bonif/Recargo 1": "",
      "Origen costo":   "Hereda del padre",  // ← así llega del export
    };

    // variantId="var-v1" simula que se procesa como fila de variante
    await saveCostLinesForArticle("art-a002", rowVarianteHeredada, "var-v1", ctx);

    // Con el fix: deleteMany corre y create escribe los nuevos valores
    expect(mockPrisma.articleCostLine.deleteMany).toHaveBeenCalledTimes(1);
    expect(mockPrisma.articleCostLine.create).toHaveBeenCalledTimes(1);
    const finalData = mockPrisma.articleCostLine.create.mock.calls[0][0].data;
    expect(finalData.articleId).toBe("art-a002");
    expect(finalData.metalVariantId).toBe("mv-oro24k-id");  // Oro 24k
    expect(Number(finalData.quantity)).toBe(4);              // cantidad=4
    expect(Number(finalData.mermaPercent)).toBe(2);
  });

  it("3 variantes con 'Hereda del padre' mismo bloque → 3 deleteMany+create (idempotente, padre actualizado)", async () => {
    // Simula el caso exacto del usuario: A002 con 3 variantes (talle 12, 14, 16).
    // El export genera 3 filas de variante con "Hereda del padre" y los mismos bloques.
    // En el reimport se deben procesar las 3 filas; el resultado final es correcto.
    const ctx = makeEmptyCtx("jw-a002b");

    const rowVariante: Record<string, string> = {
      "Tipo 1":         "Hechura",
      "Precio Unit. 1": "800",
      "Cantidad 1":     "1",
      "Descripción 1":  "",
      "Merma % 1":      "",
      "Moneda 1":       "",
      "Bonif/Recargo 1": "",
      "Origen costo":   "Hereda del padre",
    };

    // 3 variantes del mismo padre, todas con "Hereda del padre"
    await saveCostLinesForArticle("art-a002b", rowVariante, "var-1", ctx);
    await saveCostLinesForArticle("art-a002b", rowVariante, "var-2", ctx);
    await saveCostLinesForArticle("art-a002b", rowVariante, "var-3", ctx);

    // 3 ciclos delete+create — idempotente (mismo bloque, mismo padre)
    expect(mockPrisma.articleCostLine.deleteMany).toHaveBeenCalledTimes(3);
    expect(mockPrisma.articleCostLine.create).toHaveBeenCalledTimes(3);

    // El estado final es correcto: precio=800
    const lastData = mockPrisma.articleCostLine.create.mock.calls.at(-1)![0].data;
    expect(Number(lastData.unitValue)).toBe(800);
    expect(lastData.articleId).toBe("art-a002b");
  });

  it("variante con 'Hereda del padre' pero sin bloques → NO toca cost lines (preserva existentes)", async () => {
    // "Hereda del padre" sin bloques: la fila de variante no trae datos de costo.
    // Tampoco debe limpiar las líneas existentes del padre.
    const row: Record<string, string> = {
      "Tipo 1":         "",             // sin tipo → sin bloques
      "Precio Unit. 1": "",
      "Descripción 1":  "",
      "Cantidad 1":     "",
      "Merma % 1":      "",
      "Moneda 1":       "",
      "Bonif/Recargo 1": "",
      "Origen costo":   "Hereda del padre",
    };

    await saveCostLinesForArticle("art-a002c", row, "var-1", makeEmptyCtx());

    // Sin bloques → no toca la DB
    expect(mockPrisma.articleCostLine.deleteMany).not.toHaveBeenCalled();
    expect(mockPrisma.articleCostLine.create).not.toHaveBeenCalled();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// H. Regresión — reimport con onConflict="update" actualiza todos los campos
// ─────────────────────────────────────────────────────────────────────────────

describe("Regresión — reimport actualiza todos los campos del padre desde fila de variante", () => {
  it("fila de variante con todos los campos del padre → applyGuidedInheritedFields escribe todos en el update", async () => {
    // Reproduce el caso de reimport donde la fila de variante trae datos del padre.
    // Verifica que applyGuidedInheritedFields construye el payload completo de update
    // sin omitir ningún campo (causa raíz: onConflict="skip" salteaba esta llamada).
    const catMap = new Map([["anillos", "cat-anillos-id"]]);
    const grpMap = new Map([["sortijas", "grp-sortijas-id"]]);
    const supFn  = (name: string | null) => name === "Proveedor ABC" ? "sup-abc-id" : null;
    const taxFn  = () => ["tax-iva21-id"];

    const row = makeVariantRows("PAD-001", [{
      sku: "V1",
      fields: {
        "Categoría":            "Anillos",
        "Grupo":                "Sortijas",
        "Proveedor":            "Proveedor ABC",
        "Marca":                "Marca XYZ",
        "Fabricante":           "Fab Corp",
        "Código Proveedor":     "COD-123",
        "Estado":               "Activo",
        "Modo de stock":        "Por artículo",
        "Unidad":               "gramos",
        "En tienda":            "Sí",
        "Acepta devolución":    "No",
        "Vender sin variantes": "No",
        "Largo":                "10",
        "Ancho":                "5",
        "Alto":                 "3",
        "Unidad dim.":          "cm",
        "Ajuste tipo":          "Bonificación",
        "Ajuste modo":          "Porcentaje",
        "Ajuste valor":         "15",
      },
    }])[0];

    await applyGuidedInheritedFields("art-1", row, catMap, grpMap, supFn, taxFn);
    const data = mockPrisma.article.update.mock.calls[0][0].data;

    expect(data.categoryId).toBe("cat-anillos-id");
    expect(data.groupId).toBe("grp-sortijas-id");
    expect(data.preferredSupplierId).toBe("sup-abc-id");
    expect(data.brand).toBe("Marca XYZ");
    expect(data.manufacturer).toBe("Fab Corp");
    expect(data.supplierCode).toBe("COD-123");
    expect(data.status).toBe("ACTIVE");
    expect(data.stockMode).toBe("BY_ARTICLE");
    expect(data.unitOfMeasure).toBe("gramos");
    // Nota: "Notas" en fila de variante → variant.notes (varUpdate), NO article.notes
    // Por eso applyGuidedInheritedFields no escribe notes en el artículo padre.
    expect(data.showInStore).toBe(true);
    expect(data.isReturnable).toBe(false);
    expect(data.sellWithoutVariants).toBe(false);
    expect(data.dimensionLength).toBe(10);
    expect(data.dimensionWidth).toBe(5);
    expect(data.dimensionHeight).toBe(3);
    expect(data.dimensionUnit).toBe("cm");
    expect(data.manualAdjustmentKind).toBe("BONUS");
    expect(data.manualAdjustmentType).toBe("PERCENTAGE");
    expect(data.manualAdjustmentValue).toBeCloseTo(15, 2);
    expect(data.manualTaxIds).toEqual(["tax-iva21-id"]);
  });

  it("flag explícito en false (En tienda=No) → se escribe false, no se omite", async () => {
    // Garantiza que el patrón `if (s(row[GH.EN_TIENDA])) update.showInStore = b(...)`
    // escribe `false` cuando el valor es "No" — NO omite el campo.
    // "No" es truthy como string → entra al if → b("No")=false → se asigna.
    const row = makeVariantRows("P", [{ sku: "V1", fields: { "En tienda": "No" } }])[0];
    await applyGuidedInheritedFields("art-1", row, new Map(), new Map(), noopSupplier, noopTaxIds);
    const data = mockPrisma.article.update.mock.calls[0][0].data;
    expect("showInStore" in data).toBe(true);
    expect(data.showInStore).toBe(false);
  });

  it("reimport con bloques de costo modificados → líneas anteriores eliminadas y nuevas creadas", async () => {
    // Simula: primer import con precio=300, luego reimport con precio=500.
    // El deleteMany antes de cada import garantiza que no quedan líneas duplicadas.
    const ctx = makeEmptyCtx("jw-reimport");

    const rowOriginal: Record<string, string> = {
      "Tipo 1": "Hechura", "Precio Unit. 1": "300", "Cantidad 1": "1",
      "Descripción 1": "", "Merma % 1": "", "Moneda 1": "", "Bonif/Recargo 1": "",
      "Origen costo": "",
    };
    const rowReimport: Record<string, string> = {
      "Tipo 1": "Hechura", "Precio Unit. 1": "500", "Cantidad 1": "1",
      "Descripción 1": "", "Merma % 1": "", "Moneda 1": "", "Bonif/Recargo 1": "",
      "Origen costo": "",
    };

    // Import original
    await saveCostLinesForArticle("art-r", rowOriginal, null, ctx);
    // Reimport con precio distinto
    await saveCostLinesForArticle("art-r", rowReimport, null, ctx);

    // 2 ciclos delete+create (idempotente: cada llamada limpia y recrea)
    expect(mockPrisma.articleCostLine.deleteMany).toHaveBeenCalledTimes(2);
    expect(mockPrisma.articleCostLine.create).toHaveBeenCalledTimes(2);

    // El estado final refleja el reimport (precio=500)
    const lastData = mockPrisma.articleCostLine.create.mock.calls.at(-1)![0].data;
    expect(Number(lastData.unitValue)).toBe(500);
    expect(lastData.articleId).toBe("art-r");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// I. Regresión — REPLACE TOTAL de ArticleCostLine en reimport (todos los campos)
// ─────────────────────────────────────────────────────────────────────────────

describe("Regresión — REPLACE TOTAL en reimport guided (A003)", () => {
  it("reimport A003: METAL merma+bonif → todos los campos reemplazados, sin restos de la línea anterior", async () => {
    // Reproduce el bug reportado: después de reimportar, el sistema conservaba
    // el valor del import anterior en lugar del nuevo.
    //
    // Causa raíz: con onConflict="skip" (default anterior), el bucle de procesamiento
    // hacía `continue` ANTES de llamar a saveCostLinesForArticle, por lo que el
    // deleteMany nunca corría y las cost lines viejas persistían intactas.
    //
    // Este test verifica que, con onConflict="update" (nuevo default para guided),
    // el REPLACE es total: deleteMany elimina TODAS las líneas y create escribe
    // exactamente los valores nuevos — sin restos, sin merge, sin upsert.

    const ctxWithMetal: CostLinesContext = {
      jewelryId:           "jw-a003",
      currByCode:          new Map([["USD", "curr-usd-id"]]),
      currByName:          new Map(),
      metalVariantByLabel: new Map([
        ["oro 18k amarillo",  "mv-oro18k-id"],
        ["plata 925",         "mv-plata-id"],
      ]),
    };

    // ── Import original (A003, primera vez) ───────────────────────────────
    const rowImport1: Record<string, string> = {
      "Tipo 1":         "Metal",
      "Descripción 1":  "Oro 18k Amarillo",
      "Cantidad 1":     "5",            // 5g de oro
      "Precio Unit. 1": "",
      "Merma % 1":      "2",            // merma 2%
      "Moneda 1":       "",
      "Bonif/Recargo 1": "-10%",        // bonificación 10%
      "Origen costo":   "",
    };

    await saveCostLinesForArticle("art-a003", rowImport1, null, ctxWithMetal);
    const firstCreate = mockPrisma.articleCostLine.create.mock.calls[0][0].data;
    expect(firstCreate.type).toBe("METAL");
    expect(Number(firstCreate.quantity)).toBe(5);
    expect(Number(firstCreate.mermaPercent)).toBe(2);
    expect(firstCreate.metalVariantId).toBe("mv-oro18k-id");
    expect(firstCreate.lineAdjKind).toBe("BONUS");
    expect(firstCreate.lineAdjType).toBe("PERCENTAGE");
    expect(Number(firstCreate.lineAdjValue)).toBe(10);

    vi.clearAllMocks();

    // ── Reimport con valores TOTALMENTE distintos en todos los campos ─────
    const rowReimport: Record<string, string> = {
      "Tipo 1":         "Hechura",      // cambió de Metal → Hechura
      "Descripción 1":  "",
      "Cantidad 1":     "1",
      "Precio Unit. 1": "1200",         // precio fijo
      "Merma % 1":      "",             // sin merma
      "Moneda 1":       "USD",          // en USD
      "Bonif/Recargo 1": "+5%",         // cambió a recargo
      "Origen costo":   "",
    };

    await saveCostLinesForArticle("art-a003", rowReimport, null, ctxWithMetal);

    // 1 deleteMany + 1 create en el reimport
    expect(mockPrisma.articleCostLine.deleteMany).toHaveBeenCalledTimes(1);
    expect(mockPrisma.articleCostLine.create).toHaveBeenCalledTimes(1);

    // El deleteMany eliminó TODAS las líneas del artículo (sin filtros extra)
    const deleteCall = mockPrisma.articleCostLine.deleteMany.mock.calls[0][0];
    expect(deleteCall.where.articleId).toBe("art-a003");
    expect(deleteCall.where.jewelryId).toBe("jw-a003");
    // NO hay filtro de variantId ni sortOrder — es un replace total
    expect("variantId"  in deleteCall.where).toBe(false);
    expect("sortOrder"  in deleteCall.where).toBe(false);

    // La línea final es exactamente la nueva — sin restos de la anterior
    const reimportCreate = mockPrisma.articleCostLine.create.mock.calls[0][0].data;
    expect(reimportCreate.type).toBe("HECHURA");      // cambió
    expect(Number(reimportCreate.quantity)).toBe(1);
    expect(Number(reimportCreate.unitValue)).toBe(1200);
    expect(reimportCreate.currencyId).toBe("curr-usd-id");  // cambió
    expect(reimportCreate.mermaPercent).toBeUndefined();    // sin merma
    expect(reimportCreate.metalVariantId).toBeUndefined();  // ya no es metal
    expect(reimportCreate.lineAdjKind).toBe("SURCHARGE");  // cambió de BONUS
    expect(reimportCreate.lineAdjType).toBe("PERCENTAGE");
    expect(Number(reimportCreate.lineAdjValue)).toBe(5);   // cambió de 10
  });

  it("A003 con 2 líneas → reimport con 1 línea → deleteMany elimina ambas, create crea solo 1", async () => {
    // Verifica que reducir el número de líneas funciona correctamente:
    // el deleteMany no es selectivo (no intenta borrar solo la segunda línea).
    const ctx = makeEmptyCtx("jw-a003b");

    const rowWith2: Record<string, string> = {
      "Tipo 1": "Hechura", "Precio Unit. 1": "400", "Cantidad 1": "1",
      "Descripción 1": "", "Merma % 1": "", "Moneda 1": "", "Bonif/Recargo 1": "",
      "Tipo 2": "Hechura", "Precio Unit. 2": "100", "Cantidad 2": "1",
      "Descripción 2": "", "Merma % 2": "", "Moneda 2": "", "Bonif/Recargo 2": "",
      "Origen costo": "",
    };
    await saveCostLinesForArticle("art-a003b", rowWith2, null, ctx);
    expect(mockPrisma.articleCostLine.create).toHaveBeenCalledTimes(2);
    vi.clearAllMocks();

    // Reimport con 1 sola línea
    const rowWith1: Record<string, string> = {
      "Tipo 1": "Hechura", "Precio Unit. 1": "550", "Cantidad 1": "1",
      "Descripción 1": "", "Merma % 1": "", "Moneda 1": "", "Bonif/Recargo 1": "",
      "Origen costo": "",
    };
    await saveCostLinesForArticle("art-a003b", rowWith1, null, ctx);

    // 1 deleteMany (elimina las 2 líneas anteriores), 1 create (la línea nueva)
    expect(mockPrisma.articleCostLine.deleteMany).toHaveBeenCalledTimes(1);
    expect(mockPrisma.articleCostLine.create).toHaveBeenCalledTimes(1);
    const finalData = mockPrisma.articleCostLine.create.mock.calls[0][0].data;
    expect(Number(finalData.unitValue)).toBe(550);
    expect(finalData.sortOrder).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// K. Escenario A002 — 4 casos pedidos explícitamente
//    Causa raíz del bug: la condición `|| isExplicitlyInherited` en saveCostLinesForArticle
//    hacía que el deleteMany+create nunca corriera para filas con "Hereda del padre",
//    dejando las cost lines del padre sin actualizar en un reimport.
// ─────────────────────────────────────────────────────────────────────────────

describe("Escenario A002 — replace total de composición de costo en reimport guided", () => {

  // ── CASO 1 + CASO 2: crear con Oro 18k/qty=1, reimportar con Oro 24k/qty=4 ──

  it("Caso 1→2: A002 creado con Oro 18k qty=1, reimportado con Oro 24k qty=4 → padre refleja Oro 24k qty=4", async () => {
    // CASO 1: primera importación (artículo creado desde fila de artículo directo)
    const ctx: CostLinesContext = {
      jewelryId:           "jw-a002",
      currByCode:          new Map(),
      currByName:          new Map(),
      metalVariantByLabel: new Map([
        ["oro 18k amarillo", "mv-oro18k-id"],
        ["oro 24 kilates",   "mv-oro24k-id"],
        ["oro · oro 24 kilates", "mv-oro24k-id"],   // label compuesto del export
      ]),
    };

    const rowCreacion: Record<string, string> = {
      "Tipo 1":         "Metal",
      "Descripción 1":  "Oro 18k Amarillo",
      "Cantidad 1":     "1",
      "Precio Unit. 1": "",
      "Merma % 1":      "",
      "Moneda 1":       "",
      "Bonif/Recargo 1": "",
      "Origen costo":   "",           // artículo directo
    };
    await saveCostLinesForArticle("art-a002", rowCreacion, null, ctx);
    const primerCreate = mockPrisma.articleCostLine.create.mock.calls[0][0].data;
    expect(primerCreate.metalVariantId).toBe("mv-oro18k-id");
    expect(Number(primerCreate.quantity)).toBe(1);
    vi.clearAllMocks();

    // CASO 2: reimport desde filas de variante con "Hereda del padre"
    // (así llegan del export: fila de variante con los bloques del padre actualizados)
    const rowVarianteReimport: Record<string, string> = {
      "Tipo 1":         "Metal",
      "Descripción 1":  "Oro · Oro 24 Kilates",   // cambió
      "Cantidad 1":     "4",                       // cambió
      "Precio Unit. 1": "",
      "Merma % 1":      "2",
      "Moneda 1":       "",
      "Bonif/Recargo 1": "",
      "Origen costo":   "Hereda del padre",
    };

    // variantId != null → ruta de variante
    await saveCostLinesForArticle("art-a002", rowVarianteReimport, "var-v1", ctx);

    // Esperado: replace total (deleteMany + create con nuevos valores)
    expect(mockPrisma.articleCostLine.deleteMany).toHaveBeenCalledTimes(1);
    expect(mockPrisma.articleCostLine.create).toHaveBeenCalledTimes(1);

    const segundoCreate = mockPrisma.articleCostLine.create.mock.calls[0][0].data;

    // ✅ Esperado: Oro 24k, qty=4
    expect(segundoCreate.metalVariantId).toBe("mv-oro24k-id");
    expect(Number(segundoCreate.quantity)).toBe(4);
    expect(Number(segundoCreate.mermaPercent)).toBe(2);

    // ✗ No esperado: Oro 18k ni qty=1
    expect(segundoCreate.metalVariantId).not.toBe("mv-oro18k-id");
    expect(Number(segundoCreate.quantity)).not.toBe(1);
  });

  // ── CASO 3: múltiples variantes, mismo bloque → 1 sola línea en el padre ─────

  it("Caso 3: 3 variantes con mismo bloque (Oro 24k, qty=4) → padre queda con 1 línea METAL correcta", async () => {
    // Simula exactamente el Excel del usuario: 3 filas de variante para A002,
    // todas con "Hereda del padre" y los mismos bloques.
    const ctx: CostLinesContext = {
      jewelryId:           "jw-a002-c3",
      currByCode:          new Map(),
      currByName:          new Map(),
      metalVariantByLabel: new Map([
        ["oro · oro 24 kilates", "mv-oro24k-id"],
        ["oro 24 kilates",       "mv-oro24k-id"],
      ]),
    };

    const bloqueCompartido: Record<string, string> = {
      "Tipo 1":         "Metal",
      "Descripción 1":  "Oro · Oro 24 Kilates",
      "Cantidad 1":     "4",
      "Precio Unit. 1": "",
      "Merma % 1":      "",
      "Moneda 1":       "",
      "Bonif/Recargo 1": "",
      "Origen costo":   "Hereda del padre",
    };

    // 3 variantes: talle 12, 14, 16
    await saveCostLinesForArticle("art-a002-c3", bloqueCompartido, "var-t12", ctx);
    await saveCostLinesForArticle("art-a002-c3", bloqueCompartido, "var-t14", ctx);
    await saveCostLinesForArticle("art-a002-c3", bloqueCompartido, "var-t16", ctx);

    // 3 ciclos idempotentes (mismo resultado final)
    expect(mockPrisma.articleCostLine.deleteMany).toHaveBeenCalledTimes(3);
    expect(mockPrisma.articleCostLine.create).toHaveBeenCalledTimes(3);

    // Estado final (último create): 1 línea METAL, Oro 24k, qty=4
    const lineaFinal = mockPrisma.articleCostLine.create.mock.calls.at(-1)![0].data;
    expect(lineaFinal.type).toBe("METAL");
    expect(lineaFinal.metalVariantId).toBe("mv-oro24k-id");
    expect(Number(lineaFinal.quantity)).toBe(4);
    expect(lineaFinal.articleId).toBe("art-a002-c3");

    // No hay mezcla ni acumulación: la función solo hace deleteMany+create (no upsert/merge)
    const deleteCall = mockPrisma.articleCostLine.deleteMany.mock.calls.at(-1)![0];
    expect(deleteCall.where).toStrictEqual({ articleId: "art-a002-c3", jewelryId: "jw-a002-c3" });
  });

  // ── CASO 4: variantes con bloques DISTINTOS → error de inconsistencia ─────────

  it("Caso 4: variantes con bloques de costo distintos → checkParentConsistency reporta inconsistencia", () => {
    // Si V1 dice "Oro 18k, qty=1" y V2 dice "Oro 24k, qty=4", son bloques distintos.
    // checkParentConsistency debe detectarlo y bloquear el import para ese padre.
    const rowV1: Record<string, string> = {
      "SKU Padre": "A002", "SKU": "A002-V1", "Nombre": "Anillo · Talle 12",
      "Tipo 1": "Metal", "Descripción 1": "Oro 18k Amarillo", "Cantidad 1": "1",
      "Precio Unit. 1": "", "Merma % 1": "", "Moneda 1": "", "Bonif/Recargo 1": "",
      "Origen costo": "Hereda del padre",
      // campos compartidos vacíos
      "Categoría": "", "Estado": "", "Grupo": "", "Proveedor": "", "Marca": "",
      "Fabricante": "", "IVA 1": "", "IVA 2": "", "IVA 3": "",
      "Ajuste tipo": "", "Ajuste valor": "", "Ajuste modo": "",
      "Modo de stock": "", "Unidad": "", "En tienda": "", "Acepta devolución": "",
      "Vender sin variantes": "", "Largo": "", "Ancho": "", "Alto": "", "Unidad dim.": "",
    };
    const rowV2: Record<string, string> = {
      ...rowV1,
      "SKU": "A002-V2", "Nombre": "Anillo · Talle 14",
      "Descripción 1": "Oro · Oro 24 Kilates",  // diferente
      "Cantidad 1": "4",                          // diferente
    };

    const result = checkParentConsistency([rowV1, rowV2]);

    // Debe detectar la inconsistencia de costo entre V1 y V2
    expect(result.has("A002")).toBe(true);
    const msgs = result.get("A002")!;
    expect(msgs.some(m => m.toLowerCase().includes("composici"))).toBe(true);
    // Ninguna otra inconsistencia (los campos compartidos son iguales)
    expect(msgs).toHaveLength(1);
  });

  // ── Confirmación de replace total: los campos de la línea cambian completamente ──

  it("replace total: todos los campos de la línea anterior son reemplazados (sin restos)", async () => {
    // Verifica campo por campo que NO hay mezcla entre la línea anterior y la nueva.
    const ctx: CostLinesContext = {
      jewelryId:           "jw-a002-rt",
      currByCode:          new Map([["USD", "curr-usd-id"]]),
      currByName:          new Map(),
      metalVariantByLabel: new Map([
        ["plata 925", "mv-plata-id"],
        ["oro 24k",   "mv-oro24k-id"],
      ]),
    };

    // Línea original: Plata 925, qty=10, merma=5, sin moneda, sin ajuste
    const rowOriginal: Record<string, string> = {
      "Tipo 1": "Metal", "Descripción 1": "Plata 925", "Cantidad 1": "10",
      "Precio Unit. 1": "", "Merma % 1": "5", "Moneda 1": "", "Bonif/Recargo 1": "",
      "Origen costo": "",
    };
    await saveCostLinesForArticle("art-rt", rowOriginal, null, ctx);
    vi.clearAllMocks();

    // Línea nueva (todo distinto): Hechura, qty=2, price=800, moneda USD, recargo +15%
    const rowNuevo: Record<string, string> = {
      "Tipo 1": "Hechura", "Descripción 1": "", "Cantidad 1": "2",
      "Precio Unit. 1": "800", "Merma % 1": "", "Moneda 1": "usd", "Bonif/Recargo 1": "+15%",
      "Origen costo": "Hereda del padre",
    };
    await saveCostLinesForArticle("art-rt", rowNuevo, "var-1", ctx);

    const d = mockPrisma.articleCostLine.create.mock.calls[0][0].data;

    // ✅ Todos los campos son los de la línea nueva
    expect(d.type).toBe("HECHURA");          // era METAL
    expect(Number(d.quantity)).toBe(2);       // era 10
    expect(Number(d.unitValue)).toBe(800);    // era 0
    expect(d.currencyId).toBe("curr-usd-id"); // era undefined (base)
    expect(d.lineAdjKind).toBe("SURCHARGE"); // era ""
    expect(d.lineAdjType).toBe("PERCENTAGE");// era ""
    expect(Number(d.lineAdjValue)).toBe(15); // era undefined

    // ✗ No hay restos de la línea anterior
    expect(d.metalVariantId).toBeUndefined(); // Hechura no tiene metalVariantId
    expect(d.mermaPercent).toBeUndefined();   // Hechura sin merma
  });
});
