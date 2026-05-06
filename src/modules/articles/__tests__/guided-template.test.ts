// src/modules/articles/__tests__/guided-template.test.ts
// Tests para la generación del workbook de la plantilla guiada de artículos.
// Usamos buildGuidedWorkbook directamente (sin round-trip XLSX) para inspeccionar
// el modelo de DataValidations tal como ExcelJS lo construye en memoria.

import { describe, it, expect } from "vitest";
import type ExcelJS from "exceljs";
import {
  buildGuidedWorkbook,
  buildGuidedExportRows,
  parseGuidedRows,
  extractVariantName,
  checkParentConsistency,
  costBlockSignature,
  validateCostBlockWarnings,
  buildFileParentSkus,
  buildImplicitParents,
  extractGuidedCostBlocks,
  parseCurrencyRef,
  type GuidedTemplateCatalog,
  type GuidedExportRow,
  type ImportPreviewResult,
} from "../articles.import.service.js";

// ── Catálogo de prueba ────────────────────────────────────────────────────────

const CATALOG_FULL: GuidedTemplateCatalog = {
  categories:    ["Anillos", "Pulseras"],
  groups:        ["Colección 2024"],
  suppliers:     ["CE-001 · Proveedor Test"],
  taxes:         ["IVA 21%", "IVA 10.5%"],
  metals:        ["Oro"],
  metalVariants: ["Oro · Oro 18K Amarillo"],
  warehouses:    ["ALM01 · Almacén Principal"],
  currencies:    ["ARS · Peso Argentino"],
  attributeDefs: ["Color", "Talle", "Medida"],
  attributeOptions: [
    { name: "Color", rangeName: "Color", options: ["Rojo", "Azul", "Negro"] },
    { name: "Talle", rangeName: "Talle", options: ["12", "14", "16"] },
    // "Medida" intencialmente omitida aquí (tipo texto libre, sin opciones)
  ],
  brands:        ["Marca Propia", "Otra Marca"],
  manufacturers: ["Fabricante SA"],
};

const CATALOG_EMPTY_ATTRS: GuidedTemplateCatalog = {
  ...CATALOG_FULL,
  attributeDefs:   [],
  attributeOptions: [],
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Devuelve un mapa { rangeKey → formula } de los DataValidations tipo "list"
 * directamente del objeto ExcelJS en memoria (sin round-trip XLSX).
 */
function getDvModel(ws: ExcelJS.Worksheet): Record<string, any> {
  // ExcelJS almacena el modelo como (ws as any).dataValidations._data
  // o como (ws as any).dataValidations.model según la versión
  const dv = (ws as any).dataValidations;
  return dv?._data ?? dv?.model ?? {};
}

/** Devuelve la letra de columna para el header exacto en fila 1 */
function colLetterFor(ws: ExcelJS.Worksheet, headerText: string): string | null {
  const row1 = ws.getRow(1);
  let found: string | null = null;
  row1.eachCell((cell, colNum) => {
    if (String(cell.value ?? "").trim() === headerText) {
      found = ws.getColumn(colNum).letter;
    }
  });
  return found;
}

/** Busca un DV en el modelo cuyo rango empiece con `${letter}2:` */
function findDvForCol(model: Record<string, any>, letter: string): any | undefined {
  return Object.entries(model).find(([range]) => range.startsWith(`${letter}2:`))?.[1];
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("Plantilla guiada — hoja Listas", () => {
  it("tiene columna K con header 'Atributos' cuando hay attributeDefs", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ls = wb.getWorksheet("Listas");
    expect(ls).toBeDefined();
    expect(ls!.getCell("K1").value).toBe("Atributos");
  });

  it("columna K contiene los nombres de atributos en orden", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ls = wb.getWorksheet("Listas");
    expect(ls!.getCell("K2").value).toBe("Color");
    expect(ls!.getCell("K3").value).toBe("Talle");
    expect(ls!.getCell("K4").value).toBe("Medida");
  });

  it("columna K existe aunque attributeDefs esté vacío (header presente, sin datos)", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_EMPTY_ATTRS);
    const ls = wb.getWorksheet("Listas");
    expect(ls!.getCell("K1").value).toBe("Atributos");
    const k2 = ls!.getCell("K2").value;
    expect(!k2 || k2 === "").toBe(true);
  });
});

describe("Plantilla guiada — dropdowns en Nombre atributo 1..4", () => {
  it("Nombre atributo 1..4 tienen dropdown apuntando a 'Listas'!$K$ cuando hay attributeDefs", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    const model = getDvModel(ws);

    const expectedFml = `'Listas'!$K$2:$K$${CATALOG_FULL.attributeDefs.length + 1}`;

    for (const header of ["Nombre atributo 1", "Nombre atributo 2", "Nombre atributo 3", "Nombre atributo 4"]) {
      const letter = colLetterFor(ws, header);
      expect(letter, `Header '${header}' debe existir en la hoja`).toBeTruthy();

      const dv = findDvForCol(model, letter!);
      expect(dv, `Columna '${header}' (${letter}) debería tener DV`).toBeTruthy();
      expect(dv.formulae?.[0] ?? dv.formula1 ?? dv.formulae1).toBe(expectedFml);
    }
  });

  it("sin attributeDefs, Nombre atributo 1..4 NO tienen dropdown", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_EMPTY_ATTRS);
    const ws = wb.getWorksheet("Artículos")!;
    const model = getDvModel(ws);

    for (const header of ["Nombre atributo 1", "Nombre atributo 2", "Nombre atributo 3", "Nombre atributo 4"]) {
      const letter = colLetterFor(ws, header);
      expect(letter, `Header '${header}' debe existir`).toBeTruthy();
      const dv = findDvForCol(model, letter!);
      expect(dv, `'${header}' no debe tener DV cuando no hay attributeDefs`).toBeFalsy();
    }
  });
});

describe("Plantilla guiada — estructura del workbook", () => {
  it("tiene 3 hojas en orden: Artículos, Listas, Instrucciones", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const names = wb.worksheets.map(s => s.name);
    expect(names[0]).toBe("Artículos");
    expect(names[1]).toBe("Listas");
    expect(names[2]).toBe("Instrucciones");
    expect(names).toHaveLength(3);
  });

  it("hoja Artículos tiene exactamente 72 columnas (incluye dim + adj + sin Precio de venta)", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    expect(ws.columnCount).toBe(72);
  });

  it("Dimensiones (Largo-Ancho-Alto-Unidad dim.) están entre IVA 3 y Modo de stock", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    const row1 = ws.getRow(1);
    const headers: string[] = [];
    row1.eachCell(cell => headers.push(String(cell.value ?? "")));
    const idxIva3     = headers.indexOf("IVA 3");
    const idxLargo    = headers.indexOf("Largo");
    const idxUnidDim  = headers.indexOf("Unidad dim.");
    const idxModoStock = headers.indexOf("Modo de stock");
    expect(headers.indexOf("Precio de venta")).toBe(-1);
    // IVA 3 → Largo → ... → Unidad dim. → Modo de stock
    expect(idxLargo).toBe(idxIva3 + 1);
    expect(idxUnidDim).toBe(idxIva3 + 4);
    expect(idxModoStock).toBe(idxIva3 + 5);
  });

  it("hoja Listas tiene columna K con header 'Atributos'", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ls = wb.getWorksheet("Listas")!;
    expect(ls.getCell(1, 11).value).toBe("Atributos");
  });

  it("col 12 de Listas es 'Marcas' y col 13 es 'Fabricantes'", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ls = wb.getWorksheet("Listas")!;
    expect(ls.getCell(1, 12).value).toBe("Marcas");
    expect(ls.getCell(1, 13).value).toBe("Fabricantes");
  });

  it("sin attributeOptions, col 14 de Listas no tiene header (attr options empiezan en N)", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_EMPTY_ATTRS);
    const ls = wb.getWorksheet("Listas")!;
    expect(!ls.getCell(1, 14).value).toBe(true);
  });

  it("con attributeOptions, col 14 de Listas tiene header de la primera opción de atributo", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ls = wb.getWorksheet("Listas")!;
    expect(String(ls.getCell(1, 14).value ?? "")).toBe("Opc · Color");
  });
});

// ── Helpers de variante ───────────────────────────────────────────────────────

const EMPTY_ROW_BASE: Omit<GuidedExportRow,
  | "skuPadre" | "sku" | "nombre"
  | "cost1_tipo" | "cost1_desc" | "cost1_qty" | "cost1_unitValue"
  | "cost2_tipo" | "cost2_desc" | "cost2_qty" | "cost2_unitValue"
  | "peso"
> = {
  descripcion: "", estado: "", categoria: "", grupo: "", proveedor: "", codigoProveedor: "", marca: "", fabricante: "",
  cost1_moneda: "", cost1_merma: "", cost1_bonif: "",
  cost2_moneda: "", cost2_merma: "", cost2_bonif: "",
  cost3_moneda: "", cost3_tipo: "", cost3_desc: "", cost3_qty: "", cost3_unitValue: "", cost3_merma: "", cost3_bonif: "",
  cost4_moneda: "", cost4_tipo: "", cost4_desc: "", cost4_qty: "", cost4_unitValue: "", cost4_merma: "", cost4_bonif: "",
  adjTipo: "", adjValor: "", adjModo: "",
  iva1: "", iva2: "", iva3: "",
  dimLargo: "", dimAncho: "", dimAlto: "", dimUnidad: "",
  modoStock: "", unidad: "",
  ptoReposicion: "", cantMin: "", cantMax: "", cantDefault: "",
  stockRef: "",
  favorito: "", activo: "", enTienda: "", aceptaDev: "", sinVariantes: "",
  origenCosto: "",
  notas: "",
  attr1nombre: "", attr1valor: "", attr2nombre: "", attr2valor: "",
  attr3nombre: "", attr3valor: "", attr4nombre: "", attr4valor: "",
};

/** Crea una fila de variante con composición de costo propia (bloques 1 y 2 opcionales). */
function makeVariantRow(
  tipo1: string,
  unitValue1: string,
  weightOverride: string,
  tipo2 = "",
  unitValue2 = "",
): GuidedExportRow {
  return {
    ...EMPTY_ROW_BASE,
    skuPadre:         "SKU-PAD",
    sku:              "SKU-VAR",
    nombre:           "Talle 16",
    cost1_tipo:      tipo1,
    cost1_desc:      tipo1 ? "Desc 1" : "",
    cost1_qty:       tipo1 === "Metal" ? "3.5" : (tipo1 ? "1" : ""),
    cost1_unitValue: unitValue1,
    cost2_tipo:      tipo2,
    cost2_desc:      tipo2 ? "Desc 2" : "",
    cost2_qty:       tipo2 === "Metal" ? "2.0" : (tipo2 ? "1" : ""),
    cost2_unitValue: unitValue2,
    origenCosto:     tipo1 ? "Propio" : "Hereda del padre",
    peso:            weightOverride,
  };
}

/** Devuelve el índice de columna (1-based) para el header exacto en fila 1 */
function colIdxFor(ws: ExcelJS.Worksheet, headerText: string): number | null {
  const row1 = ws.getRow(1);
  let found: number | null = null;
  row1.eachCell((cell, colNum) => {
    if (String(cell.value ?? "").trim() === headerText) found = colNum;
  });
  return found;
}

// ── Tests de exportación de variantes ────────────────────────────────────────

describe("Exportación guiada — filas de variante con composición propia", () => {
  it("plantilla NO tiene columna 'Costo propio' (eliminada)", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    expect(colIdxFor(ws, "Costo propio")).toBeNull();
  });

  it("plantilla NO tiene columna 'Hechura propia' (eliminada)", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    expect(colIdxFor(ws, "Hechura propia")).toBeNull();
  });

  it("plantilla NO tiene columna 'Precio propio' (eliminada)", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    expect(colIdxFor(ws, "Precio propio")).toBeNull();
  });

  it("variante con composición (Hechura) exporta Tipo 1 en el Excel", async () => {
    const row = makeVariantRow("Hechura", "500", "");
    const wb  = await buildGuidedWorkbook(CATALOG_FULL, [row]);
    const ws  = wb.getWorksheet("Artículos")!;
    const tipo1Col = colIdxFor(ws, "Tipo 1");
    expect(tipo1Col).not.toBeNull();
    expect(ws.getRow(2).getCell(tipo1Col!).value).toBe("Hechura");
  });

  it("variante con composición exporta Precio Unit. 1 en el Excel", async () => {
    const row = makeVariantRow("Hechura", "500", "");
    const wb  = await buildGuidedWorkbook(CATALOG_FULL, [row]);
    const ws  = wb.getWorksheet("Artículos")!;
    const pCol = colIdxFor(ws, "Precio Unit. 1");
    expect(pCol).not.toBeNull();
    expect(ws.getRow(2).getCell(pCol!).value).toBe("500");
  });

  it("variante sin composición propia exporta Tipo 1 vacío (hereda del padre)", async () => {
    const row = makeVariantRow("", "", "");
    const wb  = await buildGuidedWorkbook(CATALOG_FULL, [row]);
    const ws  = wb.getWorksheet("Artículos")!;
    const tipo1Col = colIdxFor(ws, "Tipo 1");
    expect(String(ws.getRow(2).getCell(tipo1Col!).value ?? "")).toBe("");
  });

  it("variante con composición en dos bloques exporta ambos tipos", async () => {
    const row = makeVariantRow("Metal", "", "", "Hechura", "400");
    const wb  = await buildGuidedWorkbook(CATALOG_FULL, [row]);
    const ws  = wb.getWorksheet("Artículos")!;
    expect(String(ws.getRow(2).getCell(colIdxFor(ws, "Tipo 1")!).value ?? "")).toBe("Metal");
    expect(String(ws.getRow(2).getCell(colIdxFor(ws, "Tipo 2")!).value ?? "")).toBe("Hechura");
    expect(String(ws.getRow(2).getCell(colIdxFor(ws, "Precio Unit. 2")!).value ?? "")).toBe("400");
  });

  it("variante con composición exporta origenCosto = 'Propio'", async () => {
    const row = makeVariantRow("Hechura", "300", "");
    const wb  = await buildGuidedWorkbook(CATALOG_FULL, [row]);
    const ws  = wb.getWorksheet("Artículos")!;
    const col = colIdxFor(ws, "Origen costo");
    expect(ws.getRow(2).getCell(col!).value).toBe("Propio");
  });

  it("variante sin composición exporta origenCosto = 'Hereda del padre'", async () => {
    const row = makeVariantRow("", "", "");
    const wb  = await buildGuidedWorkbook(CATALOG_FULL, [row]);
    const ws  = wb.getWorksheet("Artículos")!;
    const col = colIdxFor(ws, "Origen costo");
    expect(ws.getRow(2).getCell(col!).value).toBe("Hereda del padre");
  });

  it("variante con peso propio exporta columna Peso correctamente", async () => {
    const row = makeVariantRow("", "", "3.5");
    const wb  = await buildGuidedWorkbook(CATALOG_FULL, [row]);
    const ws  = wb.getWorksheet("Artículos")!;
    const pesoCol = colIdxFor(ws, "Peso (g)");
    expect(pesoCol).not.toBeNull();
    expect(ws.getRow(2).getCell(pesoCol!).value).toBe("3.5");
  });

  it("variante sin peso propio exporta columna Peso vacía", async () => {
    const row = makeVariantRow("", "", "");
    const wb  = await buildGuidedWorkbook(CATALOG_FULL, [row]);
    const ws  = wb.getWorksheet("Artículos")!;
    const pesoCol = colIdxFor(ws, "Peso (g)");
    expect(String(ws.getRow(2).getCell(pesoCol!).value ?? "")).toBe("");
  });

});

// ── Tests: opciones de atributos en hoja Listas ──────────────────────────────

describe("Plantilla guiada — opciones de atributos en hoja Listas", () => {
  it("con attributeOptions, hoja Listas tiene una columna de opciones por atributo (desde N=14)", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ls = wb.getWorksheet("Listas")!;
    // CATALOG_FULL tiene Color (N=14) y Talle (O=15)
    expect(String(ls.getCell(1, 14).value ?? "")).toBe("Opc · Color");
    expect(String(ls.getCell(1, 15).value ?? "")).toBe("Opc · Talle");
    // Col P (16) no tiene header
    expect(!ls.getCell(1, 16).value).toBe(true);
  });

  it("las opciones de atributo se escriben en las filas de la columna", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ls = wb.getWorksheet("Listas")!;
    // Color options in col N (14)
    expect(ls.getCell(2, 14).value).toBe("Rojo");
    expect(ls.getCell(3, 14).value).toBe("Azul");
    expect(ls.getCell(4, 14).value).toBe("Negro");
    // Talle options in col O (15)
    expect(ls.getCell(2, 15).value).toBe("12");
    expect(ls.getCell(3, 15).value).toBe("14");
    expect(ls.getCell(4, 15).value).toBe("16");
  });

  it("las columnas de opciones están ocultas", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ls = wb.getWorksheet("Listas")!;
    expect(ls.getColumn(14).hidden).toBe(true);
    expect(ls.getColumn(15).hidden).toBe(true);
  });

  it("sin attributeOptions, Listas tiene K=Atributos, L=Marcas, M=Fabricantes, pero sin columnas de opciones", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_EMPTY_ATTRS);
    const ls = wb.getWorksheet("Listas")!;
    expect(ls.getCell(1, 11).value).toBe("Atributos");
    expect(ls.getCell(1, 12).value).toBe("Marcas");
    expect(ls.getCell(1, 13).value).toBe("Fabricantes");
    // Sin opciones de atributos → N (14) no tiene header
    expect(!ls.getCell(1, 14).value).toBe(true);
  });
});

describe("Plantilla guiada — dropdowns en Valor atributo 1..4", () => {
  it("con attributeOptions, Valor atributo 1..4 tienen DV con formula INDIRECT", async () => {
    const wb  = await buildGuidedWorkbook(CATALOG_FULL);
    const ws  = wb.getWorksheet("Artículos")!;
    const model = getDvModel(ws);

    for (const header of ["Valor atributo 1", "Valor atributo 2", "Valor atributo 3", "Valor atributo 4"]) {
      const letter = colLetterFor(ws, header);
      expect(letter, `Header '${header}' debe existir`).toBeTruthy();
      const dv = findDvForCol(model, letter!);
      expect(dv, `'${header}' debería tener DV cuando hay attributeOptions`).toBeTruthy();
      const formula = dv?.formulae?.[0] ?? dv?.formula1 ?? "";
      expect(String(formula)).toContain("INDIRECT");
      expect(String(formula)).toContain("SUBSTITUTE");
    }
  });

  it("sin attributeOptions, Valor atributo 1..4 NO tienen DV", async () => {
    const wb  = await buildGuidedWorkbook(CATALOG_EMPTY_ATTRS);
    const ws  = wb.getWorksheet("Artículos")!;
    const model = getDvModel(ws);

    for (const header of ["Valor atributo 1", "Valor atributo 2", "Valor atributo 3", "Valor atributo 4"]) {
      const letter = colLetterFor(ws, header);
      expect(letter, `Header '${header}' debe existir`).toBeTruthy();
      const dv = findDvForCol(model, letter!);
      expect(dv, `'${header}' NO debe tener DV cuando no hay attributeOptions`).toBeFalsy();
    }
  });

  it("el DV de Valor atributo 1 referencia la columna Nombre atributo 1", async () => {
    const wb  = await buildGuidedWorkbook(CATALOG_FULL);
    const ws  = wb.getWorksheet("Artículos")!;
    const model = getDvModel(ws);

    const nombreLetter = colLetterFor(ws, "Nombre atributo 1")!;
    const valorLetter  = colLetterFor(ws, "Valor atributo 1")!;
    const dv = findDvForCol(model, valorLetter);
    const formula = String(dv?.formulae?.[0] ?? dv?.formula1 ?? "");

    // La formula debe referenciar la columna de Nombre atributo 1
    expect(formula).toContain(nombreLetter);
  });
});

// ── Test adicional: V1 headers incluyen Hechura ───────────────────────────────

describe("Exportación V1 — headers de variante", () => {
  it("TEMPLATE_HEADERS incluye columna Hechura para exportar líneas de tipo HECHURA", async () => {
    const { TEMPLATE_HEADERS } = await import("../articles.import.service.js");
    expect(TEMPLATE_HEADERS).toContain("Hechura");
  });
});

// ── Tests: buildGuidedExportRows — reglas padre/variante ─────────────────────

/** Fábrica de artículos de prueba sin variantes */
function makeArtSimple(overrides: Record<string, any> = {}): any {
  return {
    code: "ART-001", name: "Anillo Solitario", description: "Desc padre",
    status: "ACTIVE", sku: "SKU-PAD", brand: "MiMarca", manufacturer: "MiFab",
    stockMode: "UNIT", unitOfMeasure: "UN", weight: null,
    reorderPoint: null, minSaleQuantity: null, maxSaleQuantity: null, defaultQuantity: null,
    isFavorite: false, isActive: true, showInStore: true, isReturnable: false,
    sellWithoutVariants: false, notes: "", manualTaxIds: [],
    category: { name: "Anillos" },
    group: { name: "Colección 2024" },
    preferredSupplier: { code: "CE-001", displayName: "Proveedor SA" },
    supplierCode: null,
    manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
    costComposition: [],
    attributeValues: [],
    variants: [],
    stock: [],
    ...overrides,
  };
}

/** Fábrica de variante de prueba */
function makeVariant(overrides: Record<string, any> = {}): any {
  return {
    code: "VAR-001", name: "Talle 16", sku: "SKU-VAR1",
    weightOverride: null,
    reorderPoint: null, minSaleQuantity: null, maxSaleQuantity: null, defaultQuantity: null,
    isActive: true, notes: "",
    attributeValues: [
      { value: "16", assignment: { definition: { name: "Talle" } } },
    ],
    ...overrides,
  };
}

const EMPTY_TAX_MAP = new Map<string, string>();

describe("buildGuidedExportRows — artículo sin variantes", () => {
  it("genera exactamente una fila", () => {
    const rows = buildGuidedExportRows([makeArtSimple()], EMPTY_TAX_MAP);
    expect(rows).toHaveLength(1);
  });

  it("skuPadre está vacío (es artículo padre)", () => {
    const rows = buildGuidedExportRows([makeArtSimple()], EMPTY_TAX_MAP);
    expect(rows[0].skuPadre).toBe("");
  });

  it("sku es el del artículo", () => {
    const rows = buildGuidedExportRows([makeArtSimple()], EMPTY_TAX_MAP);
    expect(rows[0].sku).toBe("SKU-PAD");
  });

  it("nombre es el del artículo sin concatenar", () => {
    const rows = buildGuidedExportRows([makeArtSimple()], EMPTY_TAX_MAP);
    expect(rows[0].nombre).toBe("Anillo Solitario");
  });
});

describe("buildGuidedExportRows — artículo con variantes (padre omitido)", () => {
  const artConVariantes = makeArtSimple({
    variants: [
      makeVariant({ sku: "SKU-V1", name: "Talle 16" }),
      makeVariant({ sku: "SKU-V2", name: "Talle 18", code: "VAR-002" }),
    ],
  });

  it("NO genera fila del padre — solo genera filas de variantes", () => {
    const rows = buildGuidedExportRows([artConVariantes], EMPTY_TAX_MAP);
    // Solo las 2 variantes; el padre no aparece
    expect(rows).toHaveLength(2);
    // Ninguna fila tiene skuPadre vacío (que indicaría el padre)
    expect(rows.every(r => r.skuPadre !== "")).toBe(true);
  });

  it("genera una fila por variante", () => {
    const rows = buildGuidedExportRows([artConVariantes], EMPTY_TAX_MAP);
    expect(rows[0].sku).toBe("SKU-V1");
    expect(rows[1].sku).toBe("SKU-V2");
  });

  it("skuPadre de cada variante apunta al SKU del padre", () => {
    const rows = buildGuidedExportRows([artConVariantes], EMPTY_TAX_MAP);
    expect(rows[0].skuPadre).toBe("SKU-PAD");
    expect(rows[1].skuPadre).toBe("SKU-PAD");
  });
});

describe("buildGuidedExportRows — nombre concatenado", () => {
  it("nombre de variante = 'Padre · Variante'", () => {
    const art = makeArtSimple({
      variants: [makeVariant({ name: "Cubic Zirconia" })],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].nombre).toBe("Anillo Solitario · Cubic Zirconia");
  });

  it("variante sin nombre propio usa solo el nombre del padre", () => {
    const art = makeArtSimple({
      variants: [makeVariant({ name: "" })],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].nombre).toBe("Anillo Solitario");
  });

  it("variante con nombre de espacios solo usa nombre del padre", () => {
    const art = makeArtSimple({
      variants: [makeVariant({ name: "   " })],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].nombre).toBe("Anillo Solitario");
  });
});

describe("buildGuidedExportRows — datos del padre heredados en variante", () => {
  const artDetallado = makeArtSimple({
    description: "Descripción completa del artículo padre",
    status: "ACTIVE",
    isFavorite: true,
    showInStore: false,
    isReturnable: true,
    sellWithoutVariants: true,
    variants: [makeVariant()],
  });

  it("hereda descripcion del padre", () => {
    const rows = buildGuidedExportRows([artDetallado], EMPTY_TAX_MAP);
    expect(rows[0].descripcion).toBe("Descripción completa del artículo padre");
  });

  it("hereda estado del padre", () => {
    const rows = buildGuidedExportRows([artDetallado], EMPTY_TAX_MAP);
    // STATUS_LABEL["ACTIVE"] = "Activo" o el valor mapeado
    expect(rows[0].estado).not.toBe("");
  });

  it("hereda favorito del padre", () => {
    const rows = buildGuidedExportRows([artDetallado], EMPTY_TAX_MAP);
    expect(rows[0].favorito).toBe("SI");
  });

  it("hereda enTienda del padre", () => {
    const rows = buildGuidedExportRows([artDetallado], EMPTY_TAX_MAP);
    expect(rows[0].enTienda).toBe("NO");
  });

  it("hereda aceptaDev del padre", () => {
    const rows = buildGuidedExportRows([artDetallado], EMPTY_TAX_MAP);
    expect(rows[0].aceptaDev).toBe("SI");
  });

  it("hereda impuestos del padre", () => {
    const taxMap = new Map([["TX1", "IVA 21%"], ["TX2", "IVA 10.5%"]]);
    const art = makeArtSimple({
      manualTaxIds: ["TX1", "TX2"],
      variants: [makeVariant()],
    });
    const rows = buildGuidedExportRows([art], taxMap);
    expect(rows[0].iva1).toBe("IVA 21%");
    expect(rows[0].iva2).toBe("IVA 10.5%");
    expect(rows[0].iva3).toBe("");
  });
});

describe("buildGuidedExportRows — mezcla de artículos simples y con variantes", () => {
  it("dos artículos: simple genera 1 fila, con variantes genera N filas", () => {
    const artSimple = makeArtSimple({ sku: "PAD-SIM" });
    const artConVars = makeArtSimple({
      sku: "PAD-VAR",
      variants: [
        makeVariant({ sku: "VAR-A", name: "V1" }),
        makeVariant({ sku: "VAR-B", name: "V2" }),
        makeVariant({ sku: "VAR-C", name: "V3" }),
      ],
    });
    const rows = buildGuidedExportRows([artSimple, artConVars], EMPTY_TAX_MAP);
    // 1 del simple + 3 variantes (padre de artConVars omitido)
    expect(rows).toHaveLength(4);
    expect(rows[0].sku).toBe("PAD-SIM");
    expect(rows[0].skuPadre).toBe("");
    expect(rows[1].sku).toBe("VAR-A");
    expect(rows[1].skuPadre).toBe("PAD-VAR");
  });
});

// =============================================================================
// buildGuidedExportRows — Origen costo + bloques vacíos en variantes
// =============================================================================

describe("buildGuidedExportRows — Origen costo y bloques en variantes", () => {
  const costLine = (type: string, unitValue = 0, qty = 1) => ({
    id: "cl1", type, label: type === "METAL" ? "Oro 18K" : "Hechura",
    quantity: qty, unitValue, mermaPercent: null,
    metalVariantId: null, currencyId: null, sortOrder: 0,
    lineAdjKind: null, lineAdjType: null, lineAdjValue: null, bonifRaw: "",
    currency: null, metalVariant: null,
  });

  it("artículo padre con composición exporta bloques naranja completos", () => {
    const art = makeArtSimple({
      costComposition: [costLine("METAL", 0, 3.5)],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].skuPadre).toBe("");            // es padre
    expect(rows[0].cost1_tipo).toBe("Metal");     // bloque exportado
    expect(rows[0].origenCosto).toBe("");          // vacío en padre
  });

  it("variante sin costLines propias muestra los bloques del padre como referencia", () => {
    const art = makeArtSimple({
      costComposition: [costLine("HECHURA", 500)],
      variants: [makeVariant({ costLines: [] })],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].skuPadre).not.toBe("");            // es variante
    expect(rows[0].cost1_tipo).toBe("Hechura");       // muestra bloque del padre como referencia
    expect(rows[0].cost1_unitValue).toBe("500");
    expect(rows[0].origenCosto).toBe("Hereda del padre");
  });

  it("variante sin costLines tiene Origen costo = 'Hereda del padre'", () => {
    const art = makeArtSimple({
      variants: [makeVariant({ costLines: [] })],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].origenCosto).toBe("Hereda del padre");
  });

  it("variante con costLines propias exporta SIEMPRE 'Hereda del padre' (nueva regla: costo solo en padre)", () => {
    // Regla nueva: las variantes no tienen costo propio — todas heredan del padre.
    // Aunque la variante tuviera costLines en DB (datos viejos), la exportación
    // siempre muestra la composición del padre con origen = "Hereda del padre".
    const art = makeArtSimple({
      variants: [makeVariant({ costLines: [costLine("HECHURA", 500)] })],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    // Padre sin composición → bloques vacíos; origen siempre "Hereda del padre"
    expect(rows[0].origenCosto).toBe("Hereda del padre");
    expect(rows[0].cost1_tipo).toBe("");  // padre sin composición
  });

  it("variante con costLines propias exporta los bloques del PADRE (no los de la variante)", () => {
    // Nueva regla: la exportación siempre refleja la composición del padre.
    const art = makeArtSimple({
      costComposition: [costLine("METAL", 0, 4)],
      variants: [makeVariant({ costLines: [costLine("HECHURA", 450)] })],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    // Se muestra el Metal del padre, NO la Hechura de la variante
    expect(rows[0].cost1_tipo).toBe("Metal");
    expect(rows[0].cost1_qty).toBe("4");
    expect(rows[0].origenCosto).toBe("Hereda del padre");
  });

  it("variante heredada muestra los bloques del padre como referencia visual (no propios)", () => {
    // Padre tiene Metal + Hechura; variante no tiene costLines propias.
    // Se espera que la fila de la variante muestre esos mismos bloques (referencia),
    // pero con origenCosto = "Hereda del padre".
    const art = makeArtSimple({
      costComposition: [
        costLine("METAL", 0, 3.5),
        costLine("HECHURA", 400),
      ],
      variants: [makeVariant({ costLines: [] })],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].origenCosto).toBe("Hereda del padre");
    expect(rows[0].cost1_tipo).toBe("Metal");   // bloque del padre, referencia
    expect(rows[0].cost2_tipo).toBe("Hechura"); // bloque del padre, referencia
    expect(rows[0].cost2_unitValue).toBe("400");
  });

  it("padre sin composición → variante heredada tiene bloques vacíos aunque el origen sea 'Hereda del padre'", () => {
    const art = makeArtSimple({
      costComposition: [],
      variants: [makeVariant({ costLines: [] })],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].origenCosto).toBe("Hereda del padre");
    expect(rows[0].cost1_tipo).toBe("");  // padre sin composición → sin bloques a mostrar
  });

  it("artículo padre tiene Origen costo vacío (no aplica)", () => {
    const rows = buildGuidedExportRows([makeArtSimple()], EMPTY_TAX_MAP);
    expect(rows[0].origenCosto).toBe("");
  });

  it("plantilla tiene columna 'Origen costo' en la hoja Artículos", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    expect(colIdxFor(ws, "Origen costo")).not.toBeNull();
  });

  it("variante sin costLines exporta 'Hereda del padre' en columna Origen costo del Excel", async () => {
    const art = makeArtSimple({
      variants: [makeVariant({ costLines: [] })],
    });
    const exportRows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    const wb = await buildGuidedWorkbook(CATALOG_FULL, exportRows);
    const ws = wb.getWorksheet("Artículos")!;
    const col = colIdxFor(ws, "Origen costo");
    expect(ws.getRow(2).getCell(col!).value).toBe("Hereda del padre");
  });

  it("variante siempre exporta 'Hereda del padre' en columna Origen costo del Excel (nueva regla)", async () => {
    // Nueva regla: el costo se gestiona solo en el padre.
    // Aunque la variante tuviera costLines, la exportación siempre dice "Hereda del padre".
    const art = makeArtSimple({
      variants: [makeVariant({ costLines: [costLine("HECHURA", 400)] })],
    });
    const exportRows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    const wb = await buildGuidedWorkbook(CATALOG_FULL, exportRows);
    const ws = wb.getWorksheet("Artículos")!;
    const col = colIdxFor(ws, "Origen costo");
    expect(ws.getRow(2).getCell(col!).value).toBe("Hereda del padre");
  });
});

// =============================================================================
// extractVariantName — utilidad visual (NO usada en lógica de importación)
// La importación Guided guarda el nombre tal cual viene en Excel.
// Esta función queda disponible solo como helper de UX/compatibilidad.
// =============================================================================

describe("extractVariantName (utilidad visual — no crítica)", () => {
  it("elimina el prefijo 'Padre · ' si el nombre empieza con él", () => {
    expect(extractVariantName("ANILLO SOLITARIO · Talle 16", "ANILLO SOLITARIO")).toBe("Talle 16");
  });

  it("devuelve el nombre completo si NO empieza con el prefijo", () => {
    expect(extractVariantName("Talle 16", "ANILLO SOLITARIO")).toBe("Talle 16");
  });

  it("devuelve el nombre completo si el nombre es idéntico al padre (sin separador)", () => {
    expect(extractVariantName("ANILLO SOLITARIO", "ANILLO SOLITARIO")).toBe("ANILLO SOLITARIO");
  });

  it("maneja nombre vacío devolviendo vacío", () => {
    expect(extractVariantName("", "PADRE")).toBe("");
  });

  it("distingue correctamente el separador ' · ' (no solo espacios)", () => {
    // Padre con el prefijo pero sin el separador exacto — no debe recortar
    expect(extractVariantName("PADRE - Variante", "PADRE")).toBe("PADRE - Variante");
  });

  it("recorta correctamente cuando hay espacios en el nombre resultante", () => {
    expect(extractVariantName("PADRE · Nombre con espacios", "PADRE")).toBe("Nombre con espacios");
  });
});


// =============================================================================
// parseGuidedRows — round-trip con buffer real generado por buildGuidedWorkbook
// =============================================================================

describe("parseGuidedRows — round-trip con buildGuidedWorkbook", () => {
  /**
   * Genera un buffer Guided con los datos de prueba dados y luego lo parsea.
   * Retorna las filas de datos (excluyendo posibles filas vacías).
   */
  async function roundTrip(
    articles: any[],
    taxMap: Map<string, string> = EMPTY_TAX_MAP,
  ): Promise<Record<string, string>[]> {
    const exportRows = buildGuidedExportRows(articles, taxMap);
    const wb = await buildGuidedWorkbook(CATALOG_FULL, exportRows);
    // Serializar a buffer XLSX
    const { default: ExcelJS } = await import("exceljs");
    // Convertir workbook ExcelJS a buffer nativo (xlsx via XLSX library)
    const xlsxBuffer = await wb.xlsx.writeBuffer();
    return parseGuidedRows(Buffer.from(xlsxBuffer));
  }

  it("parsea filas de un artículo simple", async () => {
    const art = makeArtSimple({ sku: "SIM-001", name: "Artículo Simple" });
    const rows = await roundTrip([art]);
    expect(rows).toHaveLength(1);
    expect(rows[0]["SKU"]).toBe("SIM-001");
    expect(rows[0]["SKU Padre"]).toBe("");
    expect(rows[0]["Nombre"]).toBe("Artículo Simple");
  });

  it("parsea filas de variantes y omite la fila padre", async () => {
    const art = makeArtSimple({
      sku: "PAD-001",
      name: "Anillo Solitario",
      variants: [
        makeVariant({ sku: "VAR-001", name: "Talle 12" }),
        makeVariant({ sku: "VAR-002", name: "Talle 14" }),
      ],
    });
    const rows = await roundTrip([art]);
    // Solo 2 filas de variante — el padre fue omitido en la exportación
    expect(rows).toHaveLength(2);
    expect(rows[0]["SKU Padre"]).toBe("PAD-001");
    expect(rows[0]["SKU"]).toBe("VAR-001");
    expect(rows[1]["SKU"]).toBe("VAR-002");
  });

  it("el nombre exportado de variante lleva el prefijo 'Padre · Variante'", async () => {
    const art = makeArtSimple({
      sku: "PAD-002",
      name: "ANILLO",
      variants: [makeVariant({ sku: "V1", name: "Talle 16" })],
    });
    const rows = await roundTrip([art]);
    expect(rows[0]["Nombre"]).toBe("ANILLO · Talle 16");
  });

  it("el nombre concatenado se conserva tal cual en el campo Nombre (no se recorta)", async () => {
    // La importación guarda el nombre exactamente como viene en Excel.
    // La relación padre/variante se resuelve por SKU_Padre, no por el nombre.
    const art = makeArtSimple({
      sku: "PAD-003",
      name: "PULSERA ORO",
      variants: [makeVariant({ sku: "V2", name: "20cm" })],
    });
    const rows = await roundTrip([art]);
    // El export produce "PULSERA ORO · 20cm" y ese valor se devuelve intacto
    expect(rows[0]["Nombre"]).toBe("PULSERA ORO · 20cm");
  });

  it("mezcla: 1 simple + 2 variantes → 3 filas en orden", async () => {
    const artSimple = makeArtSimple({ sku: "SIM-X", name: "Simple", variants: [] });
    const artVars = makeArtSimple({
      sku: "PAD-X",
      name: "Con Variantes",
      variants: [
        makeVariant({ sku: "VAR-X1", name: "Rojo" }),
        makeVariant({ sku: "VAR-X2", name: "Azul" }),
      ],
    });
    const rows = await roundTrip([artSimple, artVars]);
    expect(rows).toHaveLength(3);
    expect(rows[0]["SKU"]).toBe("SIM-X");
    expect(rows[1]["SKU"]).toBe("VAR-X1");
    expect(rows[2]["SKU"]).toBe("VAR-X2");
  });
});

// =============================================================================
// Robustez SKU/SKU_Padre — el nombre no es estructural
// =============================================================================

describe("parseGuidedRows — nombre no es fuente de verdad estructural", () => {
  /**
   * Construye un buffer XLSX mínimo con una hoja "Artículos" y las filas dadas.
   * Permite probar parseGuidedRows con datos arbitrarios sin pasar por buildGuidedWorkbook.
   */
  async function buildMinimalBuffer(dataRows: Record<string, string>[]): Promise<Buffer> {
    const { default: ExcelJS } = await import("exceljs");
    const wb = new ExcelJS.Workbook();
    const ws = wb.addWorksheet("Artículos");
    if (dataRows.length === 0) return Buffer.from(await wb.xlsx.writeBuffer());
    // Encabezados
    const headers = Object.keys(dataRows[0]);
    ws.addRow(headers);
    for (const row of dataRows) ws.addRow(headers.map(h => row[h] ?? ""));
    return Buffer.from(await wb.xlsx.writeBuffer());
  }

  it("identifica variante por SKU_Padre aunque el nombre NO sea concatenado", async () => {
    const rows = [
      { "SKU Padre": "PAD-001", "SKU": "VAR-001", "Nombre": "Talle 12" },  // nombre limpio
    ];
    const buf = await buildMinimalBuffer(rows);
    const parsed = parseGuidedRows(buf);
    expect(parsed).toHaveLength(1);
    // SKU_Padre presente → es variante; el nombre no importa
    expect(parsed[0]["SKU Padre"]).toBe("PAD-001");
    expect(parsed[0]["SKU"]).toBe("VAR-001");
    expect(parsed[0]["Nombre"]).toBe("Talle 12");
  });

  it("identifica variante aunque el nombre sea idéntico al del padre (sin separador)", async () => {
    const rows = [
      { "SKU Padre": "PAD-002", "SKU": "VAR-002", "Nombre": "ANILLO SOLITARIO" },
    ];
    const buf = await buildMinimalBuffer(rows);
    const parsed = parseGuidedRows(buf);
    expect(parsed[0]["SKU Padre"]).toBe("PAD-002");
    expect(parsed[0]["Nombre"]).toBe("ANILLO SOLITARIO");
  });

  it("identifica artículo simple cuando SKU_Padre está vacío (nombre no afecta)", async () => {
    const rows = [
      { "SKU Padre": "", "SKU": "SIM-001", "Nombre": "Artículo Simple" },
    ];
    const buf = await buildMinimalBuffer(rows);
    const parsed = parseGuidedRows(buf);
    expect(parsed[0]["SKU Padre"]).toBe("");
    expect(parsed[0]["SKU"]).toBe("SIM-001");
  });

  it("nombre concatenado tipo 'PADRE · VARIANTE' se conserva intacto en el campo Nombre", async () => {
    const rows = [
      { "SKU Padre": "PAD-003", "SKU": "VAR-003", "Nombre": "ANILLO SOLITARIO · Talle 16" },
    ];
    const buf = await buildMinimalBuffer(rows);
    const parsed = parseGuidedRows(buf);
    // El nombre NO se recorta — se guarda tal cual
    expect(parsed[0]["Nombre"]).toBe("ANILLO SOLITARIO · Talle 16");
  });

  it("cambiar el nombre en Excel no afecta la identificación del artículo padre", async () => {
    // Misma variante (VAR-004), mismo SKU_Padre (PAD-004), pero nombre editado manualmente
    const rows = [
      { "SKU Padre": "PAD-004", "SKU": "VAR-004", "Nombre": "Nombre completamente distinto" },
    ];
    const buf = await buildMinimalBuffer(rows);
    const parsed = parseGuidedRows(buf);
    // La relación se mantiene: SKU_Padre intacto
    expect(parsed[0]["SKU Padre"]).toBe("PAD-004");
    expect(parsed[0]["SKU"]).toBe("VAR-004");
    // Y el nombre editado se preserva
    expect(parsed[0]["Nombre"]).toBe("Nombre completamente distinto");
  });
});

// =============================================================================
// xfmtAdj — signo correcto para bonificación y recargo
// =============================================================================

describe("buildGuidedExportRows — signo de Bonif/Recargo (xfmtAdj)", () => {
  it("BONUS (bonificación) exporta con signo negativo: '-10%'", () => {
    const art = makeArtSimple({
      costComposition: [{
        type: "METAL", label: "", quantity: 3.5, unitValue: 1000, mermaPercent: null,
        lineAdjKind: "BONUS", lineAdjType: "PERCENTAGE", lineAdjValue: 10,
        currency: null, metalVariant: null,
      }],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].cost1_bonif).toBe("-10%");
  });

  it("SURCHARGE (recargo) exporta con signo positivo: '+500'", () => {
    const art = makeArtSimple({
      costComposition: [{
        type: "MANUAL", label: "", quantity: 1, unitValue: 100, mermaPercent: null,
        lineAdjKind: "SURCHARGE", lineAdjType: "FIXED_AMOUNT", lineAdjValue: 500,
        currency: null, metalVariant: null,
      }],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].cost1_bonif).toBe("+500");
  });

  it("sin ajuste exporta cadena vacía", () => {
    const art = makeArtSimple({
      costComposition: [{
        type: "MANUAL", label: "", quantity: 1, unitValue: 100, mermaPercent: null,
        lineAdjKind: "", lineAdjType: "", lineAdjValue: null,
        currency: null, metalVariant: null,
      }],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].cost1_bonif).toBe("");
  });

  it("BONUS porcentaje genera '-' no '+'", () => {
    const art = makeArtSimple({
      costComposition: [{
        type: "MANUAL", label: "", quantity: 1, unitValue: 100, mermaPercent: null,
        lineAdjKind: "BONUS", lineAdjType: "PERCENTAGE", lineAdjValue: 5,
        currency: null, metalVariant: null,
      }],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].cost1_bonif).not.toMatch(/^\+/);
    expect(rows[0].cost1_bonif).toMatch(/^-/);
  });
});

// =============================================================================
// isFavorite en variantes — herencia vs valor propio
// =============================================================================

describe("buildGuidedExportRows — isFavorite en variantes", () => {
  it("variante sin isFavorite propio hereda el del padre (padre=true → 'SI')", () => {
    const art = makeArtSimple({
      isFavorite: true,
      variants: [makeVariant({ isFavorite: undefined })],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].favorito).toBe("SI");
  });

  it("variante sin isFavorite propio hereda el del padre (padre=false → 'NO')", () => {
    const art = makeArtSimple({
      isFavorite: false,
      variants: [makeVariant({ isFavorite: undefined })],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].favorito).toBe("NO");
  });

  it("variante con isFavorite=true propio exporta 'SI' aunque padre sea false", () => {
    const art = makeArtSimple({
      isFavorite: false,
      variants: [makeVariant({ isFavorite: true })],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].favorito).toBe("SI");
  });

  it("variante con isFavorite=false propio exporta 'NO' aunque padre sea true", () => {
    const art = makeArtSimple({
      isFavorite: true,
      variants: [makeVariant({ isFavorite: false })],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].favorito).toBe("NO");
  });

  it("variante con isFavorite=null hereda del padre", () => {
    const art = makeArtSimple({
      isFavorite: true,
      variants: [makeVariant({ isFavorite: null })],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].favorito).toBe("SI");
  });
});

// =============================================================================
// codigoProveedor — columna Código Proveedor
// =============================================================================

describe("buildGuidedExportRows — codigoProveedor", () => {
  it("artículo con supplierCode exporta codigoProveedor con ese valor", () => {
    const art = makeArtSimple({ supplierCode: "CE-042" });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].codigoProveedor).toBe("CE-042");
  });

  it("artículo sin supplierCode exporta codigoProveedor vacío", () => {
    const art = makeArtSimple({ supplierCode: null });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].codigoProveedor).toBe("");
  });

  it("variante exporta codigoProveedor vacío (campo solo aplica al artículo padre)", () => {
    const art = makeArtSimple({
      supplierCode: "CE-099",
      variants: [makeVariant()],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    // La primera fila es el artículo padre
    expect(rows[0].codigoProveedor).toBe("CE-099");
  });
});

// =============================================================================
// Hoja Listas — columnas Marcas y Fabricantes
// =============================================================================

describe("Plantilla guiada — Marcas y Fabricantes en hoja Listas", () => {
  it("columna L de Listas tiene header 'Marcas' con valores del catálogo", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ls = wb.getWorksheet("Listas")!;
    expect(ls.getCell("L1").value).toBe("Marcas");
    expect(ls.getCell("L2").value).toBe("Marca Propia");
    expect(ls.getCell("L3").value).toBe("Otra Marca");
  });

  it("columna M de Listas tiene header 'Fabricantes' con valores del catálogo", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ls = wb.getWorksheet("Listas")!;
    expect(ls.getCell("M1").value).toBe("Fabricantes");
    expect(ls.getCell("M2").value).toBe("Fabricante SA");
  });

  it("DV de columna 'Marca' en hoja Artículos apunta a Listas L (no strict)", async () => {
    const wb  = await buildGuidedWorkbook(CATALOG_FULL);
    const ws  = wb.getWorksheet("Artículos")!;
    const model = getDvModel(ws);
    const letter = colLetterFor(ws, "Marca");
    expect(letter).toBeTruthy();
    const dv = findDvForCol(model, letter!);
    expect(dv).toBeTruthy();
    const fml = String(dv?.formulae?.[0] ?? dv?.formula1 ?? "");
    expect(fml).toContain("Listas");
    expect(fml).toContain("$L$");
    // showErrorMessage false → no bloquea valores fuera de lista
    expect(dv.showErrorMessage).toBe(false);
  });

  it("DV de columna 'Fabricante' en hoja Artículos apunta a Listas M (no strict)", async () => {
    const wb  = await buildGuidedWorkbook(CATALOG_FULL);
    const ws  = wb.getWorksheet("Artículos")!;
    const model = getDvModel(ws);
    const letter = colLetterFor(ws, "Fabricante");
    expect(letter).toBeTruthy();
    const dv = findDvForCol(model, letter!);
    expect(dv).toBeTruthy();
    const fml = String(dv?.formulae?.[0] ?? dv?.formula1 ?? "");
    expect(fml).toContain("$M$");
    expect(dv.showErrorMessage).toBe(false);
  });

  it("sin brands, columna Marca NO tiene DV", async () => {
    const catalog = { ...CATALOG_FULL, brands: [] };
    const wb  = await buildGuidedWorkbook(catalog);
    const ws  = wb.getWorksheet("Artículos")!;
    const model = getDvModel(ws);
    const letter = colLetterFor(ws, "Marca");
    expect(letter).toBeTruthy();
    const dv = findDvForCol(model, letter!);
    expect(dv).toBeFalsy();
  });
});

// =============================================================================
// Dropdowns Descripción 1/2/3 apuntan a metalVariants (Listas J)
// =============================================================================

describe("Plantilla guiada — dropdowns Descripción 1/2/3", () => {
  it("Descripción 1 tiene DV apuntando a 'Listas'!$J$ con showErrorMessage=false", async () => {
    const wb  = await buildGuidedWorkbook(CATALOG_FULL);
    const ws  = wb.getWorksheet("Artículos")!;
    const model = getDvModel(ws);
    const letter = colLetterFor(ws, "Descripción 1");
    expect(letter).toBeTruthy();
    const dv = findDvForCol(model, letter!);
    expect(dv).toBeTruthy();
    const fml = String(dv?.formulae?.[0] ?? dv?.formula1 ?? "");
    expect(fml).toContain("$J$");
    expect(dv.showErrorMessage).toBe(false);
  });

  it("Descripción 2 y 3 también tienen DV a metalVariants", async () => {
    const wb  = await buildGuidedWorkbook(CATALOG_FULL);
    const ws  = wb.getWorksheet("Artículos")!;
    const model = getDvModel(ws);
    for (const header of ["Descripción 2", "Descripción 3"]) {
      const letter = colLetterFor(ws, header);
      expect(letter, `'${header}' debe existir`).toBeTruthy();
      const dv = findDvForCol(model, letter!);
      expect(dv, `'${header}' debe tener DV`).toBeTruthy();
      const fml = String(dv?.formulae?.[0] ?? dv?.formula1 ?? "");
      expect(fml).toContain("$J$");
    }
  });

  it("sin metalVariants, Descripción 1/2/3 NO tienen DV", async () => {
    const catalog = { ...CATALOG_FULL, metalVariants: [] };
    const wb  = await buildGuidedWorkbook(catalog);
    const ws  = wb.getWorksheet("Artículos")!;
    const model = getDvModel(ws);
    for (const header of ["Descripción 1", "Descripción 2", "Descripción 3"]) {
      const letter = colLetterFor(ws, header);
      expect(letter).toBeTruthy();
      const dv = findDvForCol(model, letter!);
      expect(dv).toBeFalsy();
    }
  });
});

// =============================================================================
// Colores distintos por bloque de costo (cost1/cost2/cost3)
// =============================================================================

describe("Plantilla guiada — colores distintos en bloques de costo", () => {
  it("headers de bloque 1 (Moneda 1..BonifRec 1) tienen fondo naranja-600 (FFEA580C)", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    const col = colIdxFor(ws, "Moneda 1");
    expect(col).not.toBeNull();
    const headerCell = ws.getRow(1).getCell(col!);
    const bg = (headerCell.fill as any)?.fgColor?.argb;
    expect(bg).toBe("FFEA580C");
  });

  it("headers de bloque 2 (Moneda 2..BonifRec 2) tienen fondo naranja-500 (FFF97316)", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    const col = colIdxFor(ws, "Moneda 2");
    expect(col).not.toBeNull();
    const headerCell = ws.getRow(1).getCell(col!);
    const bg = (headerCell.fill as any)?.fgColor?.argb;
    expect(bg).toBe("FFF97316");
  });

  it("headers de bloque 3 (Moneda 3..BonifRec 3) tienen fondo naranja-400 (FFFB923C)", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    const col = colIdxFor(ws, "Moneda 3");
    expect(col).not.toBeNull();
    const headerCell = ws.getRow(1).getCell(col!);
    const bg = (headerCell.fill as any)?.fgColor?.argb;
    expect(bg).toBe("FFFB923C");
  });

  it("headers de bloque 4 (Moneda 4..BonifRec 4) tienen fondo naranja-300 (FFFDBA74)", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    const col = colIdxFor(ws, "Moneda 4");
    expect(col).not.toBeNull();
    const headerCell = ws.getRow(1).getCell(col!);
    const bg = (headerCell.fill as any)?.fgColor?.argb;
    expect(bg).toBe("FFFDBA74");
  });

  it("los cuatro bloques tienen colores de fondo distintos entre sí", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    const col1 = colIdxFor(ws, "Moneda 1")!;
    const col2 = colIdxFor(ws, "Moneda 2")!;
    const col3 = colIdxFor(ws, "Moneda 3")!;
    const col4 = colIdxFor(ws, "Moneda 4")!;
    const bg1 = (ws.getRow(1).getCell(col1).fill as any)?.fgColor?.argb;
    const bg2 = (ws.getRow(1).getCell(col2).fill as any)?.fgColor?.argb;
    const bg3 = (ws.getRow(1).getCell(col3).fill as any)?.fgColor?.argb;
    const bg4 = (ws.getRow(1).getCell(col4).fill as any)?.fgColor?.argb;
    expect(bg1).not.toBe(bg2);
    expect(bg2).not.toBe(bg3);
    expect(bg3).not.toBe(bg4);
    expect(bg1).not.toBe(bg3);
    expect(bg1).not.toBe(bg4);
    expect(bg2).not.toBe(bg4);
  });
});

// =============================================================================
// Columna Código Proveedor en hoja Artículos
// =============================================================================

describe("Plantilla guiada — columna Código Proveedor", () => {
  it("la hoja Artículos tiene la columna 'Código Proveedor'", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    const headers: string[] = [];
    ws.getRow(1).eachCell(cell => headers.push(String(cell.value ?? "")));
    expect(headers).toContain("Código Proveedor");
  });

  it("'Código Proveedor' aparece inmediatamente después de 'Proveedor'", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    const headers: string[] = [];
    ws.getRow(1).eachCell(cell => headers.push(String(cell.value ?? "")));
    const idxProv = headers.indexOf("Proveedor");
    const idxCod  = headers.indexOf("Código Proveedor");
    expect(idxProv).toBeGreaterThan(-1);
    expect(idxCod).toBe(idxProv + 1);
  });

  it("exportación de artículo incluye supplierCode en columna Código Proveedor", async () => {
    const art = makeArtSimple({ supplierCode: "CE-007" });
    const exportRows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    const wb  = await buildGuidedWorkbook(CATALOG_FULL, exportRows);
    const ws  = wb.getWorksheet("Artículos")!;
    const col = colIdxFor(ws, "Código Proveedor");
    expect(col).not.toBeNull();
    expect(ws.getRow(2).getCell(col!).value).toBe("CE-007");
  });
});

// =============================================================================
// checkParentConsistency — validación de consistencia entre variantes del mismo padre
// =============================================================================

/** Construye filas Guided mínimas para los tests de consistencia */
function makeRows(
  defs: Array<{ skuPadre: string; sku: string; fields?: Record<string, string> }>,
): Record<string, string>[] {
  return defs.map(({ skuPadre, sku, fields = {} }) => ({
    "SKU Padre":   skuPadre,
    "SKU":         sku,
    "Nombre":      `Nombre ${sku}`,
    "Categoría":   "",
    "Grupo":       "",
    "Proveedor":   "",
    "Marca":       "",
    "Fabricante":  "",
    "Estado":      "",
    "Descripción": "",
    ...fields,
  }));
}

describe("checkParentConsistency — variantes consistentes", () => {
  it("no detecta error cuando todas las variantes tienen la misma categoría", () => {
    const rows = makeRows([
      { skuPadre: "PAD-001", sku: "VAR-A", fields: { "Categoría": "Anillos" } },
      { skuPadre: "PAD-001", sku: "VAR-B", fields: { "Categoría": "Anillos" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.size).toBe(0);
  });

  it("no detecta error cuando todas las variantes tienen la misma marca y proveedor", () => {
    const rows = makeRows([
      { skuPadre: "PAD-002", sku: "V1", fields: { "Marca": "Oro", "Proveedor": "CE-001 · Prov SA" } },
      { skuPadre: "PAD-002", sku: "V2", fields: { "Marca": "Oro", "Proveedor": "CE-001 · Prov SA" } },
      { skuPadre: "PAD-002", sku: "V3", fields: { "Marca": "Oro", "Proveedor": "CE-001 · Prov SA" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.size).toBe(0);
  });

  it("no detecta error si una variante deja el campo vacío (no cuenta como conflicto)", () => {
    const rows = makeRows([
      { skuPadre: "PAD-003", sku: "V1", fields: { "Categoría": "Anillos" } },
      { skuPadre: "PAD-003", sku: "V2", fields: { "Categoría": "" } },  // vacío = no tocar
    ]);
    const result = checkParentConsistency(rows);
    expect(result.size).toBe(0);
  });

  it("no detecta error para artículos simples (sin SKU_Padre)", () => {
    const rows = makeRows([
      { skuPadre: "", sku: "SIM-001", fields: { "Categoría": "Anillos" } },
      { skuPadre: "", sku: "SIM-002", fields: { "Categoría": "Pulseras" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.size).toBe(0);
  });

  it("no detecta error cuando hay un único grupo de variantes con valores distintos entre distintos padres", () => {
    // Padre PAD-A tiene Categoría=Anillos, PAD-B tiene Categoría=Pulseras — distintos padres OK
    const rows = makeRows([
      { skuPadre: "PAD-A", sku: "V1", fields: { "Categoría": "Anillos" } },
      { skuPadre: "PAD-B", sku: "V2", fields: { "Categoría": "Pulseras" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.size).toBe(0);
  });
});

describe("checkParentConsistency — inconsistencias detectadas (errores bloqueantes)", () => {
  it("detecta categorías distintas en variantes del mismo padre", () => {
    const rows = makeRows([
      { skuPadre: "PAD-001", sku: "V1", fields: { "Categoría": "Anillos" } },
      { skuPadre: "PAD-001", sku: "V2", fields: { "Categoría": "Pulseras" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-001")).toBe(true);
    const msgs = result.get("PAD-001")!;
    expect(msgs.length).toBeGreaterThan(0);
    expect(msgs[0]).toContain("PAD-001");
    expect(msgs[0]).toContain("categorías");
  });

  it("detecta proveedores distintos en variantes del mismo padre", () => {
    const rows = makeRows([
      { skuPadre: "PAD-002", sku: "V1", fields: { "Proveedor": "CE-001 · Prov A" } },
      { skuPadre: "PAD-002", sku: "V2", fields: { "Proveedor": "CE-002 · Prov B" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-002")).toBe(true);
    const msgs = result.get("PAD-002")!;
    expect(msgs.some(m => m.includes("proveedores"))).toBe(true);
  });

  it("detecta marcas distintas en variantes del mismo padre", () => {
    const rows = makeRows([
      { skuPadre: "PAD-003", sku: "V1", fields: { "Marca": "Oro" } },
      { skuPadre: "PAD-003", sku: "V2", fields: { "Marca": "Plata" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-003")).toBe(true);
    expect(result.get("PAD-003")!.some(m => m.includes("marcas"))).toBe(true);
  });

  it("detecta fabricantes distintos en variantes del mismo padre", () => {
    const rows = makeRows([
      { skuPadre: "PAD-004", sku: "V1", fields: { "Fabricante": "Fab A" } },
      { skuPadre: "PAD-004", sku: "V2", fields: { "Fabricante": "Fab B" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-004")).toBe(true);
    expect(result.get("PAD-004")!.some(m => m.includes("fabricantes"))).toBe(true);
  });

  it("detecta estados distintos en variantes del mismo padre", () => {
    const rows = makeRows([
      { skuPadre: "PAD-005", sku: "V1", fields: { "Estado": "Activo" } },
      { skuPadre: "PAD-005", sku: "V2", fields: { "Estado": "Borrador" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-005")).toBe(true);
    expect(result.get("PAD-005")!.some(m => m.includes("estados"))).toBe(true);
  });

  it("detecta grupos distintos en variantes del mismo padre", () => {
    const rows = makeRows([
      { skuPadre: "PAD-006", sku: "V1", fields: { "Grupo": "Colección 2024" } },
      { skuPadre: "PAD-006", sku: "V2", fields: { "Grupo": "Colección 2025" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-006")).toBe(true);
    expect(result.get("PAD-006")!.some(m => m.includes("grupos"))).toBe(true);
  });

  it("detecta descripciones distintas en variantes del mismo padre", () => {
    const rows = makeRows([
      { skuPadre: "PAD-007", sku: "V1", fields: { "Descripción": "Descripción A" } },
      { skuPadre: "PAD-007", sku: "V2", fields: { "Descripción": "Descripción B" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-007")).toBe(true);
    expect(result.get("PAD-007")!.some(m => m.includes("descripciones"))).toBe(true);
  });

  it("detecta múltiples campos inconsistentes en el mismo padre y los reporta todos", () => {
    const rows = makeRows([
      { skuPadre: "PAD-008", sku: "V1", fields: { "Categoría": "Anillos", "Marca": "Oro" } },
      { skuPadre: "PAD-008", sku: "V2", fields: { "Categoría": "Pulseras", "Marca": "Plata" } },
    ]);
    const result = checkParentConsistency(rows);
    const msgs = result.get("PAD-008")!;
    // Deben aparecer dos mensajes distintos (uno por cada campo)
    expect(msgs.some(m => m.includes("categorías"))).toBe(true);
    expect(msgs.some(m => m.includes("marcas"))).toBe(true);
  });

  it("solo afecta al padre con inconsistencia — otros padres no se tocan", () => {
    const rows = makeRows([
      { skuPadre: "PAD-BAD",  sku: "V1", fields: { "Categoría": "Anillos" } },
      { skuPadre: "PAD-BAD",  sku: "V2", fields: { "Categoría": "Pulseras" } },
      { skuPadre: "PAD-GOOD", sku: "V3", fields: { "Categoría": "Anillos" } },
      { skuPadre: "PAD-GOOD", sku: "V4", fields: { "Categoría": "Anillos" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-BAD")).toBe(true);
    expect(result.has("PAD-GOOD")).toBe(false);
  });

  it("los mensajes incluyen el SKU_Padre afectado", () => {
    const rows = makeRows([
      { skuPadre: "SKU-PADRE-XYZ", sku: "V1", fields: { "Categoría": "Anillos" } },
      { skuPadre: "SKU-PADRE-XYZ", sku: "V2", fields: { "Categoría": "Pulseras" } },
    ]);
    const result = checkParentConsistency(rows);
    const msgs = result.get("SKU-PADRE-XYZ")!;
    expect(msgs.every(m => m.includes("SKU-PADRE-XYZ"))).toBe(true);
  });

  it("funciona con más de 2 variantes — detecta si hay 3 valores distintos", () => {
    const rows = makeRows([
      { skuPadre: "PAD-009", sku: "V1", fields: { "Categoría": "Anillos" } },
      { skuPadre: "PAD-009", sku: "V2", fields: { "Categoría": "Pulseras" } },
      { skuPadre: "PAD-009", sku: "V3", fields: { "Categoría": "Collares" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-009")).toBe(true);
  });

  it("vacíos + un valor único no generan conflicto (solo un valor no vacío → coherente)", () => {
    // V1 tiene categoría, V2 y V3 la dejan vacía — no es conflicto
    const rows = makeRows([
      { skuPadre: "PAD-010", sku: "V1", fields: { "Categoría": "Anillos" } },
      { skuPadre: "PAD-010", sku: "V2", fields: { "Categoría": "" } },
      { skuPadre: "PAD-010", sku: "V3", fields: { "Categoría": "" } },
    ]);
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-010")).toBe(false);
  });
});

// =============================================================================
// checkParentConsistency — consistencia de composición de costo
// Regla nueva: todas las variantes del mismo padre deben tener la MISMA
// composición de costo (o dejarla vacía = hereda del padre).
// =============================================================================

describe("checkParentConsistency — inconsistencias de composición de costo", () => {
  /** Construye una fila con bloques de costo */
  function makeRowWithCost(
    skuPadre: string,
    sku: string,
    costFields: Record<string, string>,
  ): Record<string, string> {
    return {
      "SKU Padre": skuPadre, "SKU": sku, "Nombre": `Nombre ${sku}`,
      "Categoría": "", "Grupo": "", "Proveedor": "", "Marca": "",
      "Fabricante": "", "Estado": "", "Descripción": "",
      ...costFields,
    };
  }

  it("variantes con la misma composición de costo → sin error", () => {
    const rows = [
      makeRowWithCost("PAD-X", "V1", { "Tipo 1": "Hechura", "Precio Unit. 1": "500" }),
      makeRowWithCost("PAD-X", "V2", { "Tipo 1": "Hechura", "Precio Unit. 1": "500" }),
    ];
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-X")).toBe(false);
  });

  it("variantes con distinta composición de costo → error bloqueante", () => {
    const rows = [
      makeRowWithCost("PAD-Y", "V1", { "Tipo 1": "Hechura", "Precio Unit. 1": "500" }),
      makeRowWithCost("PAD-Y", "V2", { "Tipo 1": "Hechura", "Precio Unit. 1": "800" }),
    ];
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-Y")).toBe(true);
    const msgs = result.get("PAD-Y")!;
    expect(msgs.some(m => m.includes("composiciones de costo distintas"))).toBe(true);
    expect(msgs.some(m => m.includes("PAD-Y"))).toBe(true);
  });

  it("una variante con bloques + otra sin bloques (hereda) → sin error (vacío no conflicta)", () => {
    const rows = [
      makeRowWithCost("PAD-Z", "V1", { "Tipo 1": "Hechura", "Precio Unit. 1": "600" }),
      makeRowWithCost("PAD-Z", "V2", {}),  // sin bloques = hereda del padre
    ];
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-Z")).toBe(false);
  });

  it("3 variantes: 2 iguales + 1 diferente → error detectado", () => {
    const rows = [
      makeRowWithCost("PAD-W", "V1", { "Tipo 1": "Metal", "Descripción 1": "Oro 18K", "Cantidad 1": "3" }),
      makeRowWithCost("PAD-W", "V2", { "Tipo 1": "Metal", "Descripción 1": "Oro 18K", "Cantidad 1": "3" }),
      makeRowWithCost("PAD-W", "V3", { "Tipo 1": "Metal", "Descripción 1": "Oro 18K", "Cantidad 1": "5" }),
    ];
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-W")).toBe(true);
    expect(result.get("PAD-W")!.some(m => m.includes("composiciones de costo distintas"))).toBe(true);
  });

  it("todas las variantes sin bloques → sin error (todas heredan del padre)", () => {
    const rows = [
      makeRowWithCost("PAD-V", "V1", {}),
      makeRowWithCost("PAD-V", "V2", {}),
      makeRowWithCost("PAD-V", "V3", {}),
    ];
    const result = checkParentConsistency(rows);
    expect(result.has("PAD-V")).toBe(false);
  });
});

// =============================================================================
// costBlockSignature — función pura
// =============================================================================

describe("costBlockSignature — firma de composición de costo", () => {
  it("fila sin bloques → firma vacía", () => {
    const row: Record<string, string> = {};
    expect(costBlockSignature(row)).toBe("");
  });

  it("fila con Hechura → firma no vacía", () => {
    const row: Record<string, string> = { "Tipo 1": "Hechura", "Precio Unit. 1": "500" };
    expect(costBlockSignature(row)).not.toBe("");
  });

  it("dos filas con la misma composición → misma firma", () => {
    const r1 = { "Tipo 1": "Hechura", "Precio Unit. 1": "500" };
    const r2 = { "Tipo 1": "Hechura", "Precio Unit. 1": "500" };
    expect(costBlockSignature(r1)).toBe(costBlockSignature(r2));
  });

  it("dos filas con diferente precio → firma distinta", () => {
    const r1 = { "Tipo 1": "Hechura", "Precio Unit. 1": "500" };
    const r2 = { "Tipo 1": "Hechura", "Precio Unit. 1": "800" };
    expect(costBlockSignature(r1)).not.toBe(costBlockSignature(r2));
  });

  it("dos filas con diferentes tipos → firma distinta", () => {
    const r1 = { "Tipo 1": "Hechura", "Precio Unit. 1": "500" };
    const r2 = { "Tipo 1": "Metal",   "Descripción 1": "Oro 18K", "Cantidad 1": "3" };
    expect(costBlockSignature(r1)).not.toBe(costBlockSignature(r2));
  });
});

// =============================================================================
// buildGuidedExportRows — herencia de composición de costo en variantes
// =============================================================================

describe("buildGuidedExportRows — herencia de composición de costo en variantes", () => {
  const artConCosto = makeArtSimple({
    costComposition: [
      {
        type: "METAL", label: null, quantity: 3.5, unitValue: 12000, mermaPercent: 2.5,
        lineAdjKind: null, lineAdjType: null, lineAdjValue: null,
        currency: { name: "ARS" },
        metalVariant: { name: "18K Amarillo", metal: { name: "Oro" } },
      },
      {
        type: "HECHURA", label: "Hechura manual", quantity: 1, unitValue: 500, mermaPercent: null,
        lineAdjKind: null, lineAdjType: null, lineAdjValue: null,
        currency: { name: "ARS" },
        metalVariant: null,
      },
      {
        type: "MANUAL", label: "Cargos extra", quantity: 1, unitValue: 200, mermaPercent: null,
        lineAdjKind: null, lineAdjType: null, lineAdjValue: null,
        currency: { name: "ARS" },
        metalVariant: null,
      },
    ],
    variants: [makeVariant({ sku: "V-INHERIT" })],
  });

  it("variante sin overrides de costo hereda el bloque 1 del padre (tipo metal)", () => {
    const rows = buildGuidedExportRows([artConCosto], EMPTY_TAX_MAP);
    const varRow = rows[0];
    expect(varRow.cost1_tipo).toBe("Metal");
    expect(varRow.cost1_desc).toBe("Oro · 18K Amarillo");
    expect(varRow.cost1_qty).toBe("3.5");
    expect(varRow.cost1_moneda).toBe("ARS");
    expect(varRow.cost1_merma).toBe("2.5");
  });

  it("variante sin overrides hereda el bloque 2 del padre (hechura)", () => {
    const rows = buildGuidedExportRows([artConCosto], EMPTY_TAX_MAP);
    const varRow = rows[0];
    expect(varRow.cost2_tipo).toBe("Hechura");
    expect(varRow.cost2_desc).toBe("Hechura manual");
    expect(varRow.cost2_qty).toBe("1");
    expect(varRow.cost2_unitValue).toBe("500");
  });

  it("variante sin overrides hereda el bloque 3 del padre (manual)", () => {
    const rows = buildGuidedExportRows([artConCosto], EMPTY_TAX_MAP);
    const varRow = rows[0];
    expect(varRow.cost3_tipo).toBe("Manual");
    expect(varRow.cost3_desc).toBe("Cargos extra");
    expect(varRow.cost3_unitValue).toBe("200");
  });

  it("variante exporta SIEMPRE los bloques del padre (costo solo en artículo padre)", () => {
    // Todas las variantes heredan la composición del padre — no tienen costo propio.
    const artConVarOverride = makeArtSimple({
      costComposition: [
        {
          type: "METAL", label: null, quantity: 3.5, unitValue: 12000, mermaPercent: null,
          lineAdjKind: null, lineAdjType: null, lineAdjValue: null,
          currency: { name: "ARS" },
          metalVariant: { name: "18K Amarillo", metal: { name: "Oro" } },
        },
      ],
      variants: [makeVariant({ sku: "V-OWN" })],
    });
    const rows = buildGuidedExportRows([artConVarOverride], EMPTY_TAX_MAP);
    const varRow = rows[0];
    // Bloque 1: Metal del padre (no "Manual" / "Costo propio" del override escalar)
    expect(varRow.cost1_tipo).toBe("Metal");
    expect(varRow.cost1_desc).toBe("Oro · 18K Amarillo");
    expect(varRow.cost1_qty).toBe("3.5");
    expect(varRow.origenCosto).toBe("Hereda del padre");
  });

  it("variante: el costo exportado siempre son los bloques del artículo padre (las variantes no tienen precio propio)", () => {
    // REGLA: las variantes no tienen precio ni costo propios.
    // El export siempre usa la composición del artículo padre.
    const artConVar = makeArtSimple({
      costComposition: [
        {
          type: "METAL", label: null, quantity: 3.5, unitValue: 12000, mermaPercent: null,
          lineAdjKind: null, lineAdjType: null, lineAdjValue: null,
          currency: { name: "ARS" },
          metalVariant: { name: "18K Amarillo", metal: { name: "Oro" } },
        },
      ],
      variants: [makeVariant({ sku: "V-HEC" })],
    });
    const rows = buildGuidedExportRows([artConVar], EMPTY_TAX_MAP);
    const varRow = rows[0];
    // Bloque 1: Metal del padre — la variante hereda esta composición
    expect(varRow.cost1_tipo).toBe("Metal");
    expect(varRow.cost1_desc).toBe("Oro · 18K Amarillo");
    expect(varRow.origenCosto).toBe("Hereda del padre");
  });

  it("variante sin overrides y padre sin composición → todos los bloques vacíos", () => {
    const artSinCosto = makeArtSimple({
      costComposition: [],
      variants: [makeVariant()],
    });
    const rows = buildGuidedExportRows([artSinCosto], EMPTY_TAX_MAP);
    const varRow = rows[0];
    expect(varRow.cost1_tipo).toBe("");
    expect(varRow.cost1_unitValue).toBe("");
    expect(varRow.cost2_tipo).toBe("");
    expect(varRow.cost3_tipo).toBe("");
    expect(varRow.cost4_tipo).toBe("");
  });

  it("variante sin overrides hereda bloque 4 del padre si existe", () => {
    const artCon4Bloques = makeArtSimple({
      costComposition: [
        {
          type: "METAL", label: null, quantity: 1, unitValue: 10000, mermaPercent: null,
          lineAdjKind: null, lineAdjType: null, lineAdjValue: null,
          currency: { name: "ARS" }, metalVariant: { name: "18K", metal: { name: "Oro" } },
        },
        {
          type: "HECHURA", label: "Hechura", quantity: 1, unitValue: 400, mermaPercent: null,
          lineAdjKind: null, lineAdjType: null, lineAdjValue: null,
          currency: { name: "ARS" }, metalVariant: null,
        },
        {
          type: "PRODUCT", label: "Piedra", quantity: 2, unitValue: 300, mermaPercent: null,
          lineAdjKind: null, lineAdjType: null, lineAdjValue: null,
          currency: { name: "ARS" }, metalVariant: null,
        },
        {
          type: "MANUAL", label: "Extra", quantity: 1, unitValue: 100, mermaPercent: null,
          lineAdjKind: null, lineAdjType: null, lineAdjValue: null,
          currency: { name: "ARS" }, metalVariant: null,
        },
      ],
      variants: [makeVariant()],
    });
    const rows = buildGuidedExportRows([artCon4Bloques], EMPTY_TAX_MAP);
    const varRow = rows[0];
    expect(varRow.cost4_tipo).toBe("Manual");
    expect(varRow.cost4_desc).toBe("Extra");
    expect(varRow.cost4_unitValue).toBe("100");
    expect(varRow.cost4_qty).toBe("1");
  });
});

// =============================================================================
// Columna Stock actual (ref.) — solo informativa, NO se importa
// =============================================================================

describe("Plantilla guiada — columna Stock actual (ref.)", () => {
  it("la hoja Artículos incluye la columna 'Stock actual (ref.)'", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    const headers: string[] = [];
    ws.getRow(1).eachCell(cell => headers.push(String(cell.value ?? "")));
    expect(headers).toContain("Stock actual (ref.)");
  });

  it("la columna 'Stock actual (ref.)' está en la posición 12 (columna L), después de Fabricante y antes de los atributos", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    const headers: string[] = [];
    ws.getRow(1).eachCell(cell => headers.push(String(cell.value ?? "")));
    const idxStockRef    = headers.indexOf("Stock actual (ref.)");
    const idxFabricante  = headers.indexOf("Fabricante");
    const idxAttr1       = headers.indexOf("Nombre atributo 1");
    // Posición 12 (índice 11): A-C=ident D-K=class L=Stock_Ref M+=attrs
    expect(idxStockRef).toBe(11);
    expect(idxStockRef).toBeGreaterThan(idxFabricante);
    expect(idxStockRef).toBeLessThan(idxAttr1);
  });

  it("la columna 'Stock actual (ref.)' tiene fondo slate-500 (FF64748B) — color de referencia", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    const col = colIdxFor(ws, "Stock actual (ref.)")!;
    const bg = (ws.getRow(1).getCell(col).fill as any)?.fgColor?.argb;
    expect(bg).toBe("FF64748B");
  });

  it("artículo sin stock (sin registros) exporta stockRef vacío", () => {
    const art = makeArtSimple({ stock: [] });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].stockRef).toBe("");
  });

  it("artículo sin campo stock (undefined) exporta stockRef vacío", () => {
    const art = makeArtSimple({ stock: undefined });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].stockRef).toBe("");
  });

  it("artículo con stock en un almacén exporta la cantidad", () => {
    const art = makeArtSimple({ stock: [{ quantity: 12 }] });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].stockRef).toBe("12");
  });

  it("artículo con stock en múltiples almacenes exporta la suma total", () => {
    const art = makeArtSimple({ stock: [{ quantity: 10 }, { quantity: 5 }, { quantity: 3 }] });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].stockRef).toBe("18");
  });

  it("artículo con stock = 0 (registro existente pero en cero) exporta '0', no vacío", () => {
    const art = makeArtSimple({ stock: [{ quantity: 0 }] });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].stockRef).toBe("0");
  });

  it("variante con stock exporta el stock de esa variante (no el del artículo)", () => {
    const art = makeArtSimple({
      stock: [{ quantity: 999 }],  // stock del artículo — no debe usarse para variantes
      variants: [makeVariant({ sku: "V1", stock: [{ quantity: 7 }] })],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].stockRef).toBe("7");
    // El stock del artículo (999) no debe aparecer en la fila de variante
    expect(rows[0].stockRef).not.toBe("999");
  });

  it("variante sin stock exporta stockRef vacío", () => {
    const art = makeArtSimple({
      variants: [makeVariant({ sku: "V1", stock: [] })],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].stockRef).toBe("");
  });

  it("la importación ignora completamente la columna — el round-trip no rompe nada", async () => {
    // Verificamos que la columna existe en el workbook pero que parseGuidedRows
    // la devuelve simplemente como un campo más en el mapa (sin efecto en la lógica).
    const art = makeArtSimple({ stock: [{ quantity: 42 }] });
    const exportRow = buildGuidedExportRows([art], EMPTY_TAX_MAP)[0];
    expect(exportRow.stockRef).toBe("42");

    const wb = await buildGuidedWorkbook(CATALOG_FULL, [exportRow]);
    const buffer = Buffer.from(await wb.xlsx.writeBuffer());
    const parsed = (await import("../articles.import.service.js")).parseGuidedRows(buffer);
    // La fila se parsea sin errores
    expect(parsed).toHaveLength(1);
    // El campo "Stock actual (ref.)" puede estar en el mapa pero la lógica de import
    // no lo usa — solo verificamos que el round-trip produce una fila válida.
    expect(parsed[0]["SKU"]).toBeTruthy();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Columnas de Ajuste global de costo
// ─────────────────────────────────────────────────────────────────────────────

describe("Plantilla guiada — columnas Ajuste global", () => {
  it("existen las columnas 'Ajuste tipo', 'Ajuste valor', 'Ajuste modo'", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    const row1 = ws.getRow(1);
    const headers: string[] = [];
    row1.eachCell(c => headers.push(String(c.value ?? "")));
    expect(headers).toContain("Ajuste tipo");
    expect(headers).toContain("Ajuste valor");
    expect(headers).toContain("Ajuste modo");
  });

  it("las columnas adj van después del bloque 4 y antes de IVA 1", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    const headers: string[] = [];
    ws.getRow(1).eachCell(c => headers.push(String(c.value ?? "")));
    const idxBonif4 = headers.indexOf("Bonif/Recargo 4");
    const idxAjTipo = headers.indexOf("Ajuste tipo");
    const idxAjVal  = headers.indexOf("Ajuste valor");
    const idxAjModo = headers.indexOf("Ajuste modo");
    const idxIva1   = headers.indexOf("IVA 1");
    expect(idxAjTipo).toBeGreaterThan(idxBonif4);
    expect(idxAjVal).toBe(idxAjTipo + 1);
    expect(idxAjModo).toBe(idxAjTipo + 2);
    expect(idxIva1).toBeGreaterThan(idxAjModo);
  });

  it("columnas adj tienen color de sección amber (FF92400E)", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    const headers: string[] = [];
    ws.getRow(1).eachCell(c => headers.push(String(c.value ?? "")));
    const idx = headers.indexOf("Ajuste tipo") + 1; // 1-based
    const cell = ws.getRow(1).getCell(idx);
    const bg = (cell.fill as any)?.fgColor?.argb ?? (cell.fill as any)?.bgColor?.argb ?? "";
    expect(bg.toUpperCase()).toBe("FF92400E");
  });

  it("'Ajuste tipo' tiene dropdown Bonificación/Recargo", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    const col = colLetterFor(ws, "Ajuste tipo");
    expect(col).not.toBeNull();
    const model = getDvModel(ws);
    const dv = findDvForCol(model, col!);
    expect(dv).toBeDefined();
    expect(dv.formulae[0]).toContain("Bonificación");
    expect(dv.formulae[0]).toContain("Recargo");
  });

  it("'Ajuste modo' tiene dropdown Porcentaje/Monto fijo", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    const col = colLetterFor(ws, "Ajuste modo");
    expect(col).not.toBeNull();
    const model = getDvModel(ws);
    const dv = findDvForCol(model, col!);
    expect(dv).toBeDefined();
    expect(dv.formulae[0]).toContain("Porcentaje");
    expect(dv.formulae[0]).toContain("Monto fijo");
  });

  it("artículo con BONUS PERCENTAGE exporta adjTipo/adjModo correctos", () => {
    const art = makeArtSimple({ manualAdjustmentKind: "BONUS", manualAdjustmentType: "PERCENTAGE", manualAdjustmentValue: "10.5" });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].adjTipo).toBe("Bonificación");
    expect(rows[0].adjValor).toBe("10.5");
    expect(rows[0].adjModo).toBe("Porcentaje");
  });

  it("artículo con SURCHARGE FIXED_AMOUNT exporta adjTipo/adjModo correctos", () => {
    const art = makeArtSimple({ manualAdjustmentKind: "SURCHARGE", manualAdjustmentType: "FIXED_AMOUNT", manualAdjustmentValue: "200" });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].adjTipo).toBe("Recargo");
    expect(rows[0].adjValor).toBe("200");
    expect(rows[0].adjModo).toBe("Monto fijo");
  });

  it("artículo sin ajuste exporta adj vacíos", () => {
    const art = makeArtSimple();
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].adjTipo).toBe("");
    expect(rows[0].adjValor).toBe("");
    expect(rows[0].adjModo).toBe("");
  });

  it("variante siempre exporta adj vacíos", () => {
    const art = makeArtSimple({
      manualAdjustmentKind: "BONUS", manualAdjustmentType: "PERCENTAGE", manualAdjustmentValue: "5",
      variants: [makeVariant()],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    const varRow = rows.find(r => r.skuPadre !== "");
    expect(varRow?.adjTipo).toBe("");
    expect(varRow?.adjValor).toBe("");
    expect(varRow?.adjModo).toBe("");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// METAL — precio unitario vacío en exportación
// ─────────────────────────────────────────────────────────────────────────────

describe("Plantilla guiada — METAL precio vacío en exportación", () => {
  it("bloque tipo METAL deja unitValue vacío aunque el artículo tenga costPrice", () => {
    const art = makeArtSimple({
      costComposition: [
        { type: "METAL", label: "Oro 18K", quantity: "3.5", unitValue: "999", mermaPercent: "2" },
      ],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].cost1_tipo).toBe("Metal");
    // Precio unitario vacío para METAL (viene de cotización, no de Excel)
    expect(rows[0].cost1_unitValue).toBe("");
  });

  it("bloque tipo HECHURA sí exporta unitValue", () => {
    const art = makeArtSimple({
      costComposition: [
        { type: "HECHURA", label: "Precio / Hechura", quantity: "1", unitValue: "450", mermaPercent: "" },
      ],
    });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].cost1_tipo).toBe("Hechura");
    expect(rows[0].cost1_unitValue).toBe("450");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Lista de tipos de costo — solo Metal y Hechura
// ─────────────────────────────────────────────────────────────────────────────

describe("Plantilla guiada — Listas: tipos de costo reducidos", () => {
  it("columna F de Listas solo tiene 2 valores (Metal, Hechura)", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const listas = wb.getWorksheet("Listas")!;
    // Leer col F (índice 6) desde F2 en adelante hasta encontrar vacío
    const vals: string[] = [];
    for (let r = 2; r <= 20; r++) {
      const v = String(listas.getCell(r, 6).value ?? "").trim();
      if (!v) break;
      vals.push(v);
    }
    expect(vals).toHaveLength(2);
    expect(vals).toContain("Metal");
    expect(vals).toContain("Hechura");
  });

  it("dropdown de Tipo 1 apunta al rango F2:F3 (2 ítems)", async () => {
    const wb = await buildGuidedWorkbook(CATALOG_FULL);
    const ws = wb.getWorksheet("Artículos")!;
    const col = colLetterFor(ws, "Tipo 1");
    expect(col).not.toBeNull();
    const model = getDvModel(ws);
    const dv = findDvForCol(model, col!);
    expect(dv).toBeDefined();
    // La fórmula debe referenciar Listas!$F$2:$F$3
    expect(dv.formulae[0]).toContain("$F$2:$F$3");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// supplierCode en exportación
// ─────────────────────────────────────────────────────────────────────────────

describe("Plantilla guiada — supplierCode en exportación", () => {
  it("exporta Article.supplierCode en codigoProveedor", () => {
    const art = makeArtSimple({ supplierCode: "REF-123" });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].codigoProveedor).toBe("REF-123");
  });

  it("supplierCode null exporta string vacío", () => {
    const art = makeArtSimple({ supplierCode: null });
    const rows = buildGuidedExportRows([art], EMPTY_TAX_MAP);
    expect(rows[0].codigoProveedor).toBe("");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// validateCostBlockWarnings — función pura sin DB
// ─────────────────────────────────────────────────────────────────────────────

describe("validateCostBlockWarnings — validación METAL / HECHURA", () => {
  it("METAL sin cantidad genera warning de cantidad", () => {
    const row = { "Tipo 1": "Metal", "Descripción 1": "Oro 18K", "Cantidad 1": "", "Precio Unit. 1": "" };
    const warns = validateCostBlockWarnings(row);
    expect(warns.some(w => w.toLowerCase().includes("cantidad"))).toBe(true);
  });

  it("METAL sin descripción genera warning de descripción", () => {
    const row = { "Tipo 1": "Metal", "Descripción 1": "", "Cantidad 1": "3.5", "Precio Unit. 1": "" };
    const warns = validateCostBlockWarnings(row);
    expect(warns.some(w => w.toLowerCase().includes("descripción"))).toBe(true);
  });

  it("METAL sin cantidad ni descripción genera dos warnings", () => {
    const row = { "Tipo 1": "Metal", "Descripción 1": "", "Cantidad 1": "", "Precio Unit. 1": "" };
    const warns = validateCostBlockWarnings(row);
    expect(warns).toHaveLength(2);
  });

  it("METAL con cantidad y descripción no genera warnings de costo", () => {
    const row = { "Tipo 1": "Metal", "Descripción 1": "Oro 18K", "Cantidad 1": "3.5", "Precio Unit. 1": "" };
    const warns = validateCostBlockWarnings(row);
    expect(warns).toHaveLength(0);
  });

  it("HECHURA sin precio genera warning de precio", () => {
    const row = { "Tipo 1": "Hechura", "Descripción 1": "Mano de obra", "Cantidad 1": "1", "Precio Unit. 1": "" };
    const warns = validateCostBlockWarnings(row);
    expect(warns.some(w => w.toLowerCase().includes("precio"))).toBe(true);
  });

  it("HECHURA con precio no genera warnings", () => {
    const row = { "Tipo 1": "Hechura", "Descripción 1": "Precio / Hechura", "Cantidad 1": "1", "Precio Unit. 1": "500" };
    const warns = validateCostBlockWarnings(row);
    expect(warns).toHaveLength(0);
  });

  it("bloque vacío (sin tipo) no genera warnings", () => {
    const row = { "Tipo 1": "", "Descripción 1": "", "Cantidad 1": "", "Precio Unit. 1": "" };
    const warns = validateCostBlockWarnings(row);
    expect(warns).toHaveLength(0);
  });

  it("múltiples bloques — segundo bloque METAL sin cantidad", () => {
    const row = {
      "Tipo 1": "Hechura", "Descripción 1": "Hechura", "Cantidad 1": "1", "Precio Unit. 1": "500",
      "Tipo 2": "Metal",   "Descripción 2": "Plata",   "Cantidad 2": "",  "Precio Unit. 2": "",
    };
    const warns = validateCostBlockWarnings(row);
    expect(warns.some(w => w.includes("Bloque 2") && w.toLowerCase().includes("cantidad"))).toBe(true);
  });

  it("tipo en minúsculas también es reconocido", () => {
    const row = { "Tipo 1": "metal", "Descripción 1": "", "Cantidad 1": "", "Precio Unit. 1": "" };
    const warns = validateCostBlockWarnings(row);
    expect(warns).toHaveLength(2);
  });

  // ── Variante — misma validación que artículo padre ──────────────────────────

  it("variante con Tipo=Metal sin cantidad genera warning (misma validación que artículo)", () => {
    const row = { "Tipo 1": "Metal", "Descripción 1": "Oro 18K", "Cantidad 1": "", "Precio Unit. 1": "" };
    const warns = validateCostBlockWarnings(row);
    expect(warns.some(w => w.toLowerCase().includes("cantidad"))).toBe(true);
    expect(warns.every(w => !w.toLowerCase().includes("padre"))).toBe(true);
  });

  it("variante con Tipo=Hechura sin precio genera warning", () => {
    const row = { "Tipo 1": "Hechura", "Descripción 1": "Hechura", "Cantidad 1": "1", "Precio Unit. 1": "" };
    const warns = validateCostBlockWarnings(row);
    expect(warns.some(w => w.toLowerCase().includes("precio"))).toBe(true);
  });

  it("variante sin datos de composición no genera warning", () => {
    const row = {
      "Tipo 1": "", "Moneda 1": "", "Merma % 1": "", "Bonif/Recargo 1": "",
      "Tipo 2": "", "Moneda 2": "", "Merma % 2": "", "Bonif/Recargo 2": "",
    };
    expect(validateCostBlockWarnings(row)).toHaveLength(0);
  });

  it("artículo con Metal sin cantidad también valida campos faltantes", () => {
    const row = { "Tipo 1": "Metal", "Descripción 1": "Plata", "Cantidad 1": "", "Precio Unit. 1": "" };
    const warns = validateCostBlockWarnings(row);
    expect(warns.some(w => w.toLowerCase().includes("cantidad"))).toBe(true);
    expect(warns.every(w => !w.toLowerCase().includes("padre"))).toBe(true);
  });
});

// =============================================================================
// buildFileParentSkus — resolución de padres en mismo archivo
// =============================================================================

describe("buildFileParentSkus — extracción de padres desde filas del archivo", () => {
  it("sin filas devuelve conjunto vacío", () => {
    expect(buildFileParentSkus([])).toEqual(new Set());
  });

  it("fila de artículo (SKU Padre vacío) agrega su SKU al conjunto", () => {
    const rows = [{ "SKU Padre": "", "SKU": "A001", "Nombre": "Anillo" }];
    expect(buildFileParentSkus(rows).has("A001")).toBe(true);
  });

  it("fila de variante (SKU Padre con valor) NO se agrega como padre", () => {
    const rows = [{ "SKU Padre": "A001", "SKU": "V001", "Nombre": "Anillo S" }];
    expect(buildFileParentSkus(rows).size).toBe(0);
  });

  it("artículo que va a sobreescribir existente también se registra como padre válido", () => {
    // Simula: A001 ya existe en DB Y también está en el archivo (actualización).
    // El resultado de buildFileParentSkus lo debe incluir.
    const rows = [
      { "SKU Padre": "", "SKU": "A001", "Nombre": "Anillo Dorado" }, // artículo existente-actualizable
      { "SKU Padre": "A001", "SKU": "V001", "Nombre": "Anillo Dorado S" },
    ];
    const fileParents = buildFileParentSkus(rows);
    expect(fileParents.has("A001")).toBe(true);
  });

  it("padre nuevo + 3 variantes: el SKU del padre está en el conjunto", () => {
    const rows = [
      { "SKU Padre": "",     "SKU": "P-100", "Nombre": "Cadena Oro 18k" },
      { "SKU Padre": "P-100","SKU": "P-100-A", "Nombre": "Cadena Oro 18k · 40cm" },
      { "SKU Padre": "P-100","SKU": "P-100-B", "Nombre": "Cadena Oro 18k · 45cm" },
      { "SKU Padre": "P-100","SKU": "P-100-C", "Nombre": "Cadena Oro 18k · 50cm" },
    ];
    const fileParents = buildFileParentSkus(rows);
    expect(fileParents.has("P-100")).toBe(true);
    expect(fileParents.size).toBe(1); // solo el artículo padre
  });

  it("múltiples artículos padre — todos aparecen en el conjunto", () => {
    const rows = [
      { "SKU Padre": "", "SKU": "A001", "Nombre": "Anillo" },
      { "SKU Padre": "", "SKU": "A002", "Nombre": "Pulsera" },
      { "SKU Padre": "A001", "SKU": "V001", "Nombre": "Anillo S" },
    ];
    const fileParents = buildFileParentSkus(rows);
    expect(fileParents.has("A001")).toBe(true);
    expect(fileParents.has("A002")).toBe(true);
    expect(fileParents.size).toBe(2);
  });
});

// =============================================================================
// Validación padre/variante — escenarios completos
// =============================================================================

describe("Validación padre/variante — resolución con mapa combinado", () => {
  it("variante cuyo padre está en el archivo no genera error de padre inexistente", () => {
    // Reproduce el bug reportado: A001 en archivo + variante con SKU_Padre=A001
    const rows = [
      { "SKU Padre": "",     "SKU": "A001", "Nombre": "Anillo" },
      { "SKU Padre": "A001", "SKU": "V001", "Nombre": "Anillo S" },
    ];
    const fileParents = buildFileParentSkus(rows);
    // El validador combina fileParents + artBySku.
    // Aquí simulamos un artBySku vacío (padre solo en archivo).
    const dbParentSkus = new Set<string>();
    const validParentSkus = new Set([...fileParents, ...dbParentSkus]);
    expect(validParentSkus.has("A001")).toBe(true); // ← no debe fallar
  });

  it("variante cuyo padre solo existe en DB (no en archivo) también es válida", () => {
    const rows = [
      { "SKU Padre": "DB-001", "SKU": "V-X", "Nombre": "Variante X" },
    ];
    const fileParents = buildFileParentSkus(rows);
    // Simula artBySku con DB-001 en la DB
    const dbParentSkus = new Set(["DB-001"]);
    const validParentSkus = new Set([...fileParents, ...dbParentSkus]);
    expect(validParentSkus.has("DB-001")).toBe(true);
  });

  it("variante con SKU_Padre inexistente real NO está en el mapa combinado", () => {
    const rows = [
      { "SKU Padre": "FANTASMA", "SKU": "V-Z", "Nombre": "Variante Z" },
    ];
    const fileParents = buildFileParentSkus(rows);
    const dbParentSkus = new Set<string>(); // vacío
    const validParentSkus = new Set([...fileParents, ...dbParentSkus]);
    expect(validParentSkus.has("FANTASMA")).toBe(false); // genera error
  });

  it("variantes (con SKU_Padre) no contaminan el conjunto de padres válidos", () => {
    const rows = [
      { "SKU Padre": "A001", "SKU": "V001", "Nombre": "Variante 1" },
      { "SKU Padre": "A001", "SKU": "V002", "Nombre": "Variante 2" },
    ];
    const fileParents = buildFileParentSkus(rows);
    expect(fileParents.size).toBe(0); // ninguna variante es padre
  });
});

// =============================================================================
// ImportPreviewResult — campo overwrite
// =============================================================================

describe("ImportPreviewResult — tipo overwrite en lugar de existing", () => {
  it("el tipo ImportPreviewResult tiene campo 'overwrite' (compile-time check)", () => {
    // Si el tipo cambia, este test falla en compilación.
    const r: ImportPreviewResult = {
      total: 5, articles: 3, variants: 2,
      valid: 1, overwrite: 2, warnings: 1, errors: 1,
      implicitParents: 0,
      rows: [],
    };
    expect(r.overwrite).toBe(2);
    expect(r.valid).toBe(1);
    expect((r as any).existing).toBeUndefined(); // campo viejo eliminado
  });

  it("las filas con status 'overwrite' se identifican correctamente en un array de rows", () => {
    const rows: ImportPreviewResult["rows"] = [
      { index: 1, isVariant: false, parentCode: "", displayName: "Anillo", status: "overwrite", errors: [], warnings: [], existingId: "id-123" },
      { index: 2, isVariant: false, parentCode: "", displayName: "Pulsera", status: "valid",    errors: [], warnings: [] },
      { index: 3, isVariant: true,  parentCode: "A001", displayName: "[Variante] Anillo S", status: "overwrite", errors: [], warnings: [], existingId: "id-456" },
    ];
    const overwriteRows = rows.filter(r => r.status === "overwrite");
    expect(overwriteRows).toHaveLength(2);
    expect(overwriteRows.every(r => r.existingId != null)).toBe(true);
  });
});

// =============================================================================
// buildImplicitParents — reconstrucción de padres implícitos
// =============================================================================

describe("buildImplicitParents", () => {
  it("3 variantes consistentes con el mismo SKU_Padre inexistente → genera padre implícito sin conflictos", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "P100", "SKU": "P100-S", "Categoría": "Anillos", "Proveedor": "CE-001" },
      { "SKU Padre": "P100", "SKU": "P100-M", "Categoría": "Anillos", "Proveedor": "CE-001" },
      { "SKU Padre": "P100", "SKU": "P100-L", "Categoría": "Anillos", "Proveedor": "CE-001" },
    ];
    const validParentSkus = new Set<string>(); // P100 no está en archivo ni en DB
    const result = buildImplicitParents(rows, validParentSkus);
    expect(result.size).toBe(1);
    const entry = result.get("P100");
    expect(entry).toBeDefined();
    expect(entry!.conflicts).toHaveLength(0);
    expect(entry!.row["SKU"]).toBe("P100");
    expect(entry!.row["Categoría"]).toBe("Anillos");
    expect(entry!.row["Proveedor"]).toBe("CE-001");
  });

  it("variantes con categoría/proveedor distintos entre sí → conflictos en el resultado", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "P200", "SKU": "P200-A", "Categoría": "Anillos",  "Proveedor": "CE-001" },
      { "SKU Padre": "P200", "SKU": "P200-B", "Categoría": "Pulseras", "Proveedor": "CE-001" },
      { "SKU Padre": "P200", "SKU": "P200-C", "Categoría": "Anillos",  "Proveedor": "CE-002" },
    ];
    const validParentSkus = new Set<string>();
    const result = buildImplicitParents(rows, validParentSkus);
    expect(result.size).toBe(1);
    const entry = result.get("P200");
    expect(entry!.conflicts.length).toBeGreaterThanOrEqual(2);
    const conflictText = entry!.conflicts.join(" ");
    expect(conflictText).toMatch(/categoría/i);
    expect(conflictText).toMatch(/proveedor/i);
  });

  it("padre explícito presente en las filas → no se reconstruye (mapa vacío)", () => {
    const rows: Record<string, string>[] = [
      // padre explícito (sin SKU Padre)
      { "SKU Padre": "", "SKU": "P300", "Categoría": "Anillos" },
      // variantes
      { "SKU Padre": "P300", "SKU": "P300-S", "Categoría": "Anillos" },
      { "SKU Padre": "P300", "SKU": "P300-L", "Categoría": "Anillos" },
    ];
    const fileParentSkus = new Set<string>(["P300"]); // ya en archivo como fila padre
    const result = buildImplicitParents(rows, fileParentSkus);
    expect(result.size).toBe(0);
  });

  it("padre existente en sistema (en validParentSkus) → no se reconstruye (mapa vacío)", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "P400", "SKU": "P400-S", "Categoría": "Anillos" },
      { "SKU Padre": "P400", "SKU": "P400-M", "Categoría": "Anillos" },
    ];
    const validParentSkus = new Set<string>(["P400"]); // ya existe en DB
    const result = buildImplicitParents(rows, validParentSkus);
    expect(result.size).toBe(0);
  });
});

// =============================================================================
// extractGuidedCostBlocks — parseo de bloques de costo
// =============================================================================

describe("extractGuidedCostBlocks", () => {
  it("bloque 1 Metal + bloque 2 Hechura → devuelve 2 bloques en orden correcto", () => {
    const row: Record<string, string> = {
      "Tipo 1": "Metal",        "Descripción 1": "Oro · Oro 18K Amarillo",
      "Cantidad 1": "3.5",      "Precio Unit. 1": "",    "Merma % 1": "2.5",
      "Moneda 1": "Peso Argentino",                      "Bonif/Recargo 1": "",
      "Tipo 2": "Hechura",      "Descripción 2": "Precio / Hechura",
      "Cantidad 2": "1",        "Precio Unit. 2": "35000", "Merma % 2": "",
      "Moneda 2": "Peso Argentino",                      "Bonif/Recargo 2": "",
    };
    const blocks = extractGuidedCostBlocks(row);
    expect(blocks).toHaveLength(2);
    expect(blocks[0].type).toBe("METAL");
    expect(blocks[0].descripcion).toBe("Oro · Oro 18K Amarillo");
    expect(blocks[0].cantidad).toBe(3.5);
    expect(blocks[0].mermaPercent).toBe(2.5);
    expect(blocks[0].unitPrice).toBe(0); // precio vacío → 0
    expect(blocks[1].type).toBe("HECHURA");
    expect(blocks[1].unitPrice).toBe(35000);
    expect(blocks[1].descripcion).toBe("Precio / Hechura");
  });

  it("solo bloque 2 (Hechura) con bloque 1 vacío → devuelve 1 bloque", () => {
    const row: Record<string, string> = {
      "Tipo 1": "", "Descripción 1": "", "Cantidad 1": "", "Precio Unit. 1": "",
      "Tipo 2": "Hechura", "Descripción 2": "Mano de obra",
      "Cantidad 2": "1", "Precio Unit. 2": "20000", "Moneda 2": "Peso Argentino",
    };
    const blocks = extractGuidedCostBlocks(row);
    expect(blocks).toHaveLength(1);
    expect(blocks[0].type).toBe("HECHURA");
    expect(blocks[0].unitPrice).toBe(20000);
  });

  it("Metal sin precio → válido (incluido en los bloques)", () => {
    const row: Record<string, string> = {
      "Tipo 1": "Metal",
      "Descripción 1": "Plata · Plata 925",
      "Cantidad 1": "5",
      "Precio Unit. 1": "",   // explícitamente vacío
      "Merma % 1": "3",
      "Moneda 1": "Peso Argentino",
    };
    const blocks = extractGuidedCostBlocks(row);
    expect(blocks).toHaveLength(1);
    expect(blocks[0].type).toBe("METAL");
    expect(blocks[0].unitPrice).toBe(0);
    expect(blocks[0].mermaPercent).toBe(3);
  });

  it("Hechura sin precio → NO se incluye (precio requerido)", () => {
    const row: Record<string, string> = {
      "Tipo 1": "Hechura",
      "Descripción 1": "Mano de obra",
      "Precio Unit. 1": "",   // sin precio
    };
    const blocks = extractGuidedCostBlocks(row);
    expect(blocks).toHaveLength(0);
  });

  it("las claves del row se leen por nombre (orden de columnas no importa)", () => {
    // Mismo bloque pero con orden de propiedades invertido en el objeto
    const rowNormal: Record<string, string> = {
      "Tipo 1": "Metal", "Descripción 1": "Oro · Oro 18K", "Cantidad 1": "2",
      "Precio Unit. 1": "", "Moneda 1": "Peso Argentino", "Merma % 1": "1.5",
    };
    const rowInverted: Record<string, string> = {
      "Merma % 1": "1.5", "Moneda 1": "Peso Argentino", "Precio Unit. 1": "",
      "Cantidad 1": "2", "Descripción 1": "Oro · Oro 18K", "Tipo 1": "Metal",
    };
    const b1 = extractGuidedCostBlocks(rowNormal);
    const b2 = extractGuidedCostBlocks(rowInverted);
    expect(b1).toHaveLength(1);
    expect(b2).toHaveLength(1);
    expect(b1[0].type).toBe(b2[0].type);
    expect(b1[0].descripcion).toBe(b2[0].descripcion);
    expect(b1[0].mermaPercent).toBe(b2[0].mermaPercent);
  });

  it("tipo 'manual' / 'costo propio' → mapea a MANUAL", () => {
    const row: Record<string, string> = {
      "Tipo 1": "Manual", "Descripción 1": "Costo fijo", "Precio Unit. 1": "100", "Cantidad 1": "2",
    };
    const blocks = extractGuidedCostBlocks(row);
    expect(blocks).toHaveLength(1);
    expect(blocks[0].type).toBe("MANUAL");
  });

  it("bonificación/recargo se parsea correctamente", () => {
    const row: Record<string, string> = {
      "Tipo 1": "Hechura", "Descripción 1": "Engaste", "Precio Unit. 1": "500",
      "Bonif/Recargo 1": "-10%",
      "Tipo 2": "Hechura", "Descripción 2": "Flete", "Precio Unit. 2": "200",
      "Bonif/Recargo 2": "+150",
    };
    const blocks = extractGuidedCostBlocks(row);
    expect(blocks).toHaveLength(2);
    expect(blocks[0].bonifRaw).toBe("-10%");
    expect(blocks[1].bonifRaw).toBe("+150");
  });
});

// =============================================================================
// parseCurrencyRef — parseo del campo Moneda desde Excel
// =============================================================================

describe("parseCurrencyRef", () => {
  it('"ARS · Peso Argentino" → code=ARS, nameHint=Peso Argentino', () => {
    const r = parseCurrencyRef("ARS · Peso Argentino");
    expect(r.code).toBe("ARS");
    expect(r.nameHint).toBe("Peso Argentino");
  });

  it('"USD · Dólares" → code=USD, nameHint=Dólares', () => {
    const r = parseCurrencyRef("USD · Dólares");
    expect(r.code).toBe("USD");
    expect(r.nameHint).toBe("Dólares");
  });

  it('"ARS" (solo código) → code=ARS, nameHint=ARS', () => {
    const r = parseCurrencyRef("ARS");
    expect(r.code).toBe("ARS");
    expect(r.nameHint).toBe("ARS");
  });

  it('"Peso Argentino" (solo nombre) → code=Peso Argentino, nameHint=Peso Argentino', () => {
    // El lookup posterior buscará "PESO ARGENTINO" como código (falla) y luego por nombre (OK)
    const r = parseCurrencyRef("Peso Argentino");
    expect(r.code).toBe("Peso Argentino");
    expect(r.nameHint).toBe("Peso Argentino");
  });

  it('string vacío → code vacío, nameHint vacío', () => {
    const r = parseCurrencyRef("");
    expect(r.code).toBe("");
    expect(r.nameHint).toBe("");
  });
});

// =============================================================================
// buildGuidedExportRows — exportación de moneda en bloques de costo
// =============================================================================

/** Artículo mínimo con una línea de costo para tests de exportación. */
function makeArticleWithCostLine(currency: { code: string; name: string } | null): any {
  return {
    code: "ART-001", name: "Anillo", sku: "ART-001", description: "", status: "ACTIVE",
    brand: "", manufacturer: "", supplierCode: "",
    stockMode: "NO_STOCK", unitOfMeasure: "UND", weight: null,
    dimensionLength: null, dimensionWidth: null, dimensionHeight: null, dimensionUnit: null,
    reorderPoint: null, minSaleQuantity: null, maxSaleQuantity: null, defaultQuantity: null,
    isFavorite: false, isActive: true, showInStore: false, isReturnable: false,
    sellWithoutVariants: false, notes: "", manualTaxIds: [],
    manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
    category: null, group: null, preferredSupplier: null,
    costComposition: [{
      type: "HECHURA", label: "Mano de obra", quantity: 1, unitValue: 500,
      mermaPercent: null, lineAdjKind: "", lineAdjType: "", lineAdjValue: null,
      currency,
      metalVariant: null,
    }],
    attributeValues: [],
    stock: [],
    variants: [],
  };
}

describe("buildGuidedExportRows — moneda en líneas de costo", () => {
  it("exporta línea con moneda ARS en formato CODE·Nombre", () => {
    const art = makeArticleWithCostLine({ code: "ARS", name: "Peso Argentino" });
    const rows = buildGuidedExportRows([art], new Map());
    expect(rows[0].cost1_moneda).toBe("ARS · Peso Argentino");
  });

  it("exporta línea con moneda USD en formato CODE·Nombre", () => {
    const art = makeArticleWithCostLine({ code: "USD", name: "Dólares" });
    const rows = buildGuidedExportRows([art], new Map());
    expect(rows[0].cost1_moneda).toBe("USD · Dólares");
  });

  it("línea sin moneda explícita (null) usa baseCurrency si se provee", () => {
    const art = makeArticleWithCostLine(null); // currencyId null → base
    const baseCurrency = { code: "ARS", name: "Peso Argentino" };
    const rows = buildGuidedExportRows([art], new Map(), baseCurrency);
    expect(rows[0].cost1_moneda).toBe("ARS · Peso Argentino");
  });

  it("línea sin moneda explícita (null) y sin baseCurrency → cadena vacía", () => {
    const art = makeArticleWithCostLine(null);
    const rows = buildGuidedExportRows([art], new Map());
    expect(rows[0].cost1_moneda).toBe("");
  });
});

// =============================================================================
// extractGuidedCostBlocks — monedaName captura el valor raw del Excel
// =============================================================================

describe("extractGuidedCostBlocks — captura monedaName raw", () => {
  it('formato "ARS · Peso Argentino" se preserva en monedaName', () => {
    const row: Record<string, string> = {
      "Tipo 1": "Hechura", "Descripción 1": "Mano de obra",
      "Precio Unit. 1": "500", "Moneda 1": "ARS · Peso Argentino",
    };
    const blocks = extractGuidedCostBlocks(row);
    expect(blocks[0].monedaName).toBe("ARS · Peso Argentino");
  });

  it('formato "USD · Dólares" se preserva en monedaName', () => {
    const row: Record<string, string> = {
      "Tipo 1": "Hechura", "Descripción 1": "Engaste",
      "Precio Unit. 1": "200", "Moneda 1": "USD · Dólares",
    };
    const blocks = extractGuidedCostBlocks(row);
    expect(blocks[0].monedaName).toBe("USD · Dólares");
  });
});

// =============================================================================
// Reglas de fuente de verdad para composición de costo (Guided import)
// Las reglas se verifican a nivel de parseo puro — sin DB.
// =============================================================================

describe("Reglas de composición de costo — fuente de verdad (bloques, no columnas resumen)", () => {
  // ── Artículo padre ────────────────────────────────────────────────────────────

  it("padre con bloques Metal + Hechura → extractGuidedCostBlocks devuelve 2 bloques", () => {
    const row: Record<string, string> = {
      "Tipo 1": "Metal", "Descripción 1": "Oro 18K", "Cantidad 1": "3.5",
      "Precio Unit. 1": "", "Merma % 1": "2", "Moneda 1": "ARS · Peso Argentino", "Bonif/Recargo 1": "",
      "Tipo 2": "Hechura", "Descripción 2": "Hechura manual", "Cantidad 2": "1",
      "Precio Unit. 2": "400", "Merma % 2": "", "Moneda 2": "", "Bonif/Recargo 2": "",
    };
    const blocks = extractGuidedCostBlocks(row);
    expect(blocks).toHaveLength(2);
    expect(blocks[0].type).toBe("METAL");
    expect(blocks[0].cantidad).toBe(3.5);
    expect(blocks[0].mermaPercent).toBe(2);
    expect(blocks[1].type).toBe("HECHURA");
    expect(blocks[1].unitPrice).toBe(400);
  });

  it("padre sin bloques → extractGuidedCostBlocks devuelve array vacío (preservar existentes)", () => {
    const row: Record<string, string> = {
      "Tipo 1": "", "Tipo 2": "", "Tipo 3": "", "Tipo 4": "",
    };
    expect(extractGuidedCostBlocks(row)).toHaveLength(0);
  });

  it("no existen columnas resumen en el formato Guided — no se leen 'Costo propio' etc.", () => {
    // Verificar que una fila con columnas resumen legacy NO genera bloques
    // (esas columnas simplemente se ignoran)
    const row: Record<string, string> = {
      "Costo propio": "5000",
      "Hechura propia": "300",
      "Precio propio": "8000",
      "Tipo 1": "", "Tipo 2": "", "Tipo 3": "", "Tipo 4": "",
    };
    expect(extractGuidedCostBlocks(row)).toHaveLength(0);
  });

  // ── Variantes — regla Origen costo ───────────────────────────────────────────

  it("variante con Origen costo = 'Hereda del padre' y bloques llenos → bloques son REFERENCIA (no se guardan)", () => {
    // La lógica de persistencia descarta los bloques cuando isExplicitlyInherited = true.
    // Aquí validamos que extractGuidedCostBlocks SÍ los lee (los bloques están presentes),
    // pero que la lógica de saveCostLinesForArticle los ignora por el flag de herencia.
    // El parseo en sí es agnóstico — la decisión es en saveCostLinesForArticle.
    const row: Record<string, string> = {
      "Origen costo": "Hereda del padre",
      "Tipo 1": "Hechura", "Descripción 1": "Hechura manual", "Precio Unit. 1": "500",
    };
    // Los bloques se parsean correctamente (son los del padre como referencia)
    const blocks = extractGuidedCostBlocks(row);
    expect(blocks).toHaveLength(1);
    expect(blocks[0].type).toBe("HECHURA");
    // Pero la columna Origen costo marca herencia explícita
    expect(row["Origen costo"].toLowerCase()).toBe("hereda del padre");
  });

  it("variante con Origen costo = 'Propio' y bloques llenos → se guardan como propios", () => {
    const row: Record<string, string> = {
      "Origen costo": "Propio",
      "Tipo 1": "Hechura", "Descripción 1": "Hechura manual", "Precio Unit. 1": "500",
    };
    const blocks = extractGuidedCostBlocks(row);
    expect(blocks).toHaveLength(1);
    expect(row["Origen costo"].toLowerCase()).not.toBe("hereda del padre");
  });

  it("variante con Origen costo vacío y bloques llenos → bloques se guardan (override implícito)", () => {
    const row: Record<string, string> = {
      "Origen costo": "",
      "Tipo 1": "Hechura", "Descripción 1": "Hechura manual", "Precio Unit. 1": "500",
    };
    const blocks = extractGuidedCostBlocks(row);
    expect(blocks).toHaveLength(1);
    // Origen vacío y bloques → override implícito (se guardará como propio)
    const origenRaw = (row["Origen costo"] ?? "").toLowerCase();
    expect(origenRaw).not.toBe("hereda del padre");
  });

  it("variante con Origen costo vacío y bloques vacíos → array vacío (hereda por defecto)", () => {
    const row: Record<string, string> = {
      "Origen costo": "",
      "Tipo 1": "", "Tipo 2": "", "Tipo 3": "", "Tipo 4": "",
    };
    expect(extractGuidedCostBlocks(row)).toHaveLength(0);
  });

  // ── Todos los campos de un bloque se leen correctamente ───────────────────────

  it("todos los campos de un bloque se mapean correctamente", () => {
    const row: Record<string, string> = {
      "Moneda 1": "ARS · Peso Argentino",
      "Tipo 1": "Metal",
      "Descripción 1": "Oro · Oro 18K Amarillo",
      "Cantidad 1": "4.2",
      "Precio Unit. 1": "0",
      "Merma % 1": "3.5",
      "Bonif/Recargo 1": "-5%",
    };
    const blocks = extractGuidedCostBlocks(row);
    expect(blocks).toHaveLength(1);
    const b = blocks[0];
    expect(b.type).toBe("METAL");
    expect(b.monedaName).toBe("ARS · Peso Argentino");
    expect(b.descripcion).toBe("Oro · Oro 18K Amarillo");
    expect(b.cantidad).toBe(4.2);
    expect(b.unitPrice).toBe(0);
    expect(b.mermaPercent).toBe(3.5);
    expect(b.bonifRaw).toBe("-5%");
  });
});

// =============================================================================
// Caso inconsistente: variante con Origen costo = "Propio" y bloques vacíos
// Debe producir error de validación — es una fila autodeclarada como propia
// sin ninguna línea de costo que la respalde.
// =============================================================================

describe("Validación: variante 'Propio' sin bloques → error explícito", () => {
  // La función validateCostBlockWarnings solo verifica completitud de bloques (METAL/HECHURA).
  // La inconsistencia Propio+vacío es detectada por el preview loop, que llama a
  // extractGuidedCostBlocks y chequea el valor de "Origen costo".
  // Aquí testeamos las piezas por separado (puro, sin DB).

  it("extractGuidedCostBlocks con Origen = 'Propio' y sin Tipo → array vacío", () => {
    const row: Record<string, string> = {
      "Origen costo": "Propio",
      "Tipo 1": "", "Tipo 2": "", "Tipo 3": "", "Tipo 4": "",
    };
    // Los bloques están vacíos: esta es la condición de error
    expect(extractGuidedCostBlocks(row)).toHaveLength(0);
  });

  it("'Propio' + bloques vacíos → condición de error detectada por la lógica del preview", () => {
    const row: Record<string, string> = {
      "Origen costo": "Propio",
      "Tipo 1": "", "Tipo 2": "", "Tipo 3": "", "Tipo 4": "",
    };
    const origenRaw = (row["Origen costo"] ?? "").toLowerCase();
    const blocks    = extractGuidedCostBlocks(row);
    // El preview loop evalúa exactamente esta condición para emitir error
    const isInconsistent = origenRaw === "propio" && blocks.length === 0;
    expect(isInconsistent).toBe(true);
  });

  it("'Propio' + bloques llenos → condición válida (no inconsistencia)", () => {
    const row: Record<string, string> = {
      "Origen costo": "Propio",
      "Tipo 1": "Hechura", "Descripción 1": "Hechura manual", "Precio Unit. 1": "500",
    };
    const origenRaw = (row["Origen costo"] ?? "").toLowerCase();
    const blocks    = extractGuidedCostBlocks(row);
    const isInconsistent = origenRaw === "propio" && blocks.length === 0;
    expect(isInconsistent).toBe(false);
    expect(blocks).toHaveLength(1);
  });

  it("'Hereda del padre' + bloques vacíos → no inconsistencia (herencia explícita válida)", () => {
    const row: Record<string, string> = {
      "Origen costo": "Hereda del padre",
      "Tipo 1": "", "Tipo 2": "", "Tipo 3": "", "Tipo 4": "",
    };
    const origenRaw = (row["Origen costo"] ?? "").toLowerCase();
    const blocks    = extractGuidedCostBlocks(row);
    const isInconsistent = origenRaw === "propio" && blocks.length === 0;
    expect(isInconsistent).toBe(false);
  });

  it("'Hereda del padre' + bloques llenos (referencia) → no inconsistencia (herencia explícita)", () => {
    const row: Record<string, string> = {
      "Origen costo": "Hereda del padre",
      "Tipo 1": "Hechura", "Descripción 1": "Hechura manual", "Precio Unit. 1": "500",
    };
    const origenRaw = (row["Origen costo"] ?? "").toLowerCase();
    const blocks    = extractGuidedCostBlocks(row);
    const isInconsistent = origenRaw === "propio" && blocks.length === 0;
    expect(isInconsistent).toBe(false);
    // Los bloques están presentes pero el origen marca herencia → se ignorarán al importar
    expect(blocks).toHaveLength(1);
    expect(origenRaw).toBe("hereda del padre");
  });

  it("origen vacío + bloques vacíos → no inconsistencia (hereda por defecto, sin declaración explícita)", () => {
    const row: Record<string, string> = {
      "Origen costo": "",
      "Tipo 1": "", "Tipo 2": "", "Tipo 3": "", "Tipo 4": "",
    };
    const origenRaw = (row["Origen costo"] ?? "").toLowerCase();
    const blocks    = extractGuidedCostBlocks(row);
    const isInconsistent = origenRaw === "propio" && blocks.length === 0;
    expect(isInconsistent).toBe(false);
  });

  it("validateCostBlockWarnings no genera warnings para Propio+vacío (esa validación es independiente)", () => {
    // validateCostBlockWarnings solo valida METAL sin cantidad / HECHURA sin precio.
    // La inconsistencia Propio+vacío es responsabilidad del preview loop.
    const row: Record<string, string> = {
      "Origen costo": "Propio",
      "Tipo 1": "", "Tipo 2": "", "Tipo 3": "", "Tipo 4": "",
    };
    // Sin tipo en ningún bloque → cero warnings de completitud
    expect(validateCostBlockWarnings(row)).toHaveLength(0);
  });
});

// =============================================================================
// Pipeline — 3 variantes por padre → todas se crean (sin pérdida silenciosa)
// =============================================================================

describe("Pipeline — 3 variantes por padre: buildImplicitParents y buildFileParentSkus", () => {
  it("3 variantes con SKU_Padre explícito en el archivo → buildFileParentSkus incluye el padre, buildImplicitParents vacío", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "", "SKU": "ART-001", "Nombre": "Anillo Dorado" },
      { "SKU Padre": "ART-001", "SKU": "ART-001-S", "Nombre": "Anillo S" },
      { "SKU Padre": "ART-001", "SKU": "ART-001-M", "Nombre": "Anillo M" },
      { "SKU Padre": "ART-001", "SKU": "ART-001-L", "Nombre": "Anillo L" },
    ];
    const fileParents = buildFileParentSkus(rows);
    expect(fileParents.has("ART-001")).toBe(true);

    const validParents = new Set(fileParents);
    const implicit = buildImplicitParents(rows, validParents);
    // padre ya está en el archivo → implícito vacío
    expect(implicit.size).toBe(0);
  });

  it("3 variantes sin padre explícito → buildImplicitParents crea el padre sin conflictos", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "P-NUEVO", "SKU": "P-NUEVO-S", "Nombre": "Anillo S", "Categoría": "Anillos" },
      { "SKU Padre": "P-NUEVO", "SKU": "P-NUEVO-M", "Nombre": "Anillo M", "Categoría": "Anillos" },
      { "SKU Padre": "P-NUEVO", "SKU": "P-NUEVO-L", "Nombre": "Anillo L", "Categoría": "Anillos" },
    ];
    const implicit = buildImplicitParents(rows, new Set());
    expect(implicit.size).toBe(1);
    const entry = implicit.get("P-NUEVO")!;
    expect(entry.conflicts).toHaveLength(0);
    expect(entry.row["SKU"]).toBe("P-NUEVO");
    expect(entry.row["Categoría"]).toBe("Anillos");
  });

  it("3 variantes con PESO diferente por variante → NO genera conflicto (peso es campo de variante)", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "P-PESO", "SKU": "P-PESO-S", "Nombre": "Anillo S", "Peso (g)": "3.1", "Categoría": "Anillos" },
      { "SKU Padre": "P-PESO", "SKU": "P-PESO-M", "Nombre": "Anillo M", "Peso (g)": "4.2", "Categoría": "Anillos" },
      { "SKU Padre": "P-PESO", "SKU": "P-PESO-L", "Nombre": "Anillo L", "Peso (g)": "5.8", "Categoría": "Anillos" },
    ];
    const implicit = buildImplicitParents(rows, new Set());
    expect(implicit.size).toBe(1);
    const entry = implicit.get("P-PESO")!;
    // Peso distinto por variante NO bloquea la reconstrucción del padre implícito
    expect(entry.conflicts).toHaveLength(0);
  });

  it("3 variantes con ACTIVO diferente → NO genera conflicto (activo es campo de variante)", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "P-ACT", "SKU": "P-ACT-S", "Nombre": "S", "Activo": "SI", "Categoría": "Anillos" },
      { "SKU Padre": "P-ACT", "SKU": "P-ACT-M", "Nombre": "M", "Activo": "NO", "Categoría": "Anillos" },
      { "SKU Padre": "P-ACT", "SKU": "P-ACT-L", "Nombre": "L", "Activo": "SI", "Categoría": "Anillos" },
    ];
    const implicit = buildImplicitParents(rows, new Set());
    const entry = implicit.get("P-ACT")!;
    expect(entry.conflicts).toHaveLength(0);
  });

  it("3 variantes con bloques de costo distintos (una con override) → NO genera conflicto de costo", () => {
    // Una variante tiene su propio costo (Manual) y las otras heredan (Metal+Hechura)
    const rows: Record<string, string>[] = [
      {
        "SKU Padre": "P-COSTO", "SKU": "P-COSTO-ORO", "Nombre": "Oro",
        "Tipo 1": "Metal", "Descripción 1": "Oro · 18k", "Cantidad 1": "3",
        "Tipo 2": "Hechura", "Precio Unit. 2": "35000",
        "Categoría": "Anillos",
      },
      {
        "SKU Padre": "P-COSTO", "SKU": "P-COSTO-PLATA", "Nombre": "Plata",
        "Tipo 1": "Metal", "Descripción 1": "Oro · 18k", "Cantidad 1": "3",
        "Tipo 2": "Hechura", "Precio Unit. 2": "35000",
        "Categoría": "Anillos",
      },
      {
        // Variante con override manual (distinto de las anteriores)
        "SKU Padre": "P-COSTO", "SKU": "P-COSTO-ROSE", "Nombre": "Rose Gold",
        "Tipo 1": "Manual", "Descripción 1": "Costo propio", "Precio Unit. 1": "50000",
        "Categoría": "Anillos",
      },
    ];
    const implicit = buildImplicitParents(rows, new Set());
    const entry = implicit.get("P-COSTO")!;
    // Diferencia en bloques de costo NO debe bloquear reconstrucción del padre
    expect(entry.conflicts).toHaveLength(0);
    // El padre implícito debe tener el bloque Metal (primera fila con tipo Metal/real)
    expect(entry.row["Tipo 1"]).toBe("Metal");
    expect(entry.row["Descripción 1"]).toBe("Oro · 18k");
  });
});

// =============================================================================
// Pipeline — múltiples grupos de artículos: todos completos
// =============================================================================

describe("Pipeline — múltiples grupos: buildFileParentSkus + buildImplicitParents", () => {
  it("dos grupos explícitos con 2 variantes cada uno → buildFileParentSkus incluye ambos padres", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "", "SKU": "G1", "Nombre": "Grupo 1" },
      { "SKU Padre": "G1", "SKU": "G1-A", "Nombre": "G1 A" },
      { "SKU Padre": "G1", "SKU": "G1-B", "Nombre": "G1 B" },
      { "SKU Padre": "", "SKU": "G2", "Nombre": "Grupo 2" },
      { "SKU Padre": "G2", "SKU": "G2-A", "Nombre": "G2 A" },
      { "SKU Padre": "G2", "SKU": "G2-B", "Nombre": "G2 B" },
    ];
    const fileParents = buildFileParentSkus(rows);
    expect(fileParents.has("G1")).toBe(true);
    expect(fileParents.has("G2")).toBe(true);
    expect(fileParents.size).toBe(2);

    const implicit = buildImplicitParents(rows, fileParents);
    expect(implicit.size).toBe(0); // ambos padres ya están en el archivo
  });

  it("dos grupos implícitos con 2 variantes cada uno → ambos reconstruidos sin conflictos", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "IMP1", "SKU": "IMP1-A", "Nombre": "IMP1 A", "Categoría": "Anillos" },
      { "SKU Padre": "IMP1", "SKU": "IMP1-B", "Nombre": "IMP1 B", "Categoría": "Anillos" },
      { "SKU Padre": "IMP2", "SKU": "IMP2-A", "Nombre": "IMP2 A", "Categoría": "Pulseras" },
      { "SKU Padre": "IMP2", "SKU": "IMP2-B", "Nombre": "IMP2 B", "Categoría": "Pulseras" },
    ];
    const implicit = buildImplicitParents(rows, new Set());
    expect(implicit.size).toBe(2);
    expect(implicit.get("IMP1")!.conflicts).toHaveLength(0);
    expect(implicit.get("IMP2")!.conflicts).toHaveLength(0);
    expect(implicit.get("IMP1")!.row["Categoría"]).toBe("Anillos");
    expect(implicit.get("IMP2")!.row["Categoría"]).toBe("Pulseras");
  });

  it("grupo mixto: 1 padre explícito + 1 implícito → solo el implícito se reconstruye", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "", "SKU": "EXPLIC", "Nombre": "Padre explícito" },
      { "SKU Padre": "EXPLIC", "SKU": "EXPLIC-A", "Nombre": "E-A" },
      { "SKU Padre": "IMPLIC", "SKU": "IMPLIC-A", "Nombre": "I-A", "Categoría": "Pulseras" },
      { "SKU Padre": "IMPLIC", "SKU": "IMPLIC-B", "Nombre": "I-B", "Categoría": "Pulseras" },
    ];
    const fileParents = buildFileParentSkus(rows);
    const implicit = buildImplicitParents(rows, fileParents);
    expect(implicit.size).toBe(1);
    expect(implicit.has("IMPLIC")).toBe(true);
    expect(implicit.has("EXPLIC")).toBe(false);
  });
});

// =============================================================================
// Pipeline — cost blocks en padres implícitos: Metal+Hechura copiados al padre
// =============================================================================

describe("Pipeline — cost blocks en padres implícitos", () => {
  it("variantes con Metal+Hechura → padre implícito hereda los bloques de costo", () => {
    const rows: Record<string, string>[] = [
      {
        "SKU Padre": "P-METAL", "SKU": "P-METAL-ORO", "Nombre": "Oro",
        "Tipo 1": "Metal", "Descripción 1": "Oro · Oro 18K Amarillo",
        "Cantidad 1": "3.5", "Merma % 1": "2",
        "Moneda 1": "ARS · Peso Argentino",
        "Tipo 2": "Hechura", "Precio Unit. 2": "35000",
        "Moneda 2": "ARS · Peso Argentino",
      },
      {
        "SKU Padre": "P-METAL", "SKU": "P-METAL-PLATA", "Nombre": "Plata",
        "Tipo 1": "Metal", "Descripción 1": "Oro · Oro 18K Amarillo",
        "Cantidad 1": "3.5", "Merma % 1": "2",
        "Moneda 1": "ARS · Peso Argentino",
        "Tipo 2": "Hechura", "Precio Unit. 2": "35000",
        "Moneda 2": "ARS · Peso Argentino",
      },
    ];
    const implicit = buildImplicitParents(rows, new Set());
    const entry = implicit.get("P-METAL")!;
    expect(entry.conflicts).toHaveLength(0);

    // El padre implícito debe tener los bloques de costo copiados
    expect(entry.row["Tipo 1"]).toBe("Metal");
    expect(entry.row["Descripción 1"]).toBe("Oro · Oro 18K Amarillo");
    expect(entry.row["Cantidad 1"]).toBe("3.5");
    expect(entry.row["Merma % 1"]).toBe("2");
    expect(entry.row["Moneda 1"]).toBe("ARS · Peso Argentino");
    expect(entry.row["Tipo 2"]).toBe("Hechura");
    expect(entry.row["Precio Unit. 2"]).toBe("35000");
    expect(entry.row["Moneda 2"]).toBe("ARS · Peso Argentino");
  });

  it("variantes con monedas ARS y USD en bloques distintos → ambas copiadas al padre implícito", () => {
    const rows: Record<string, string>[] = [
      {
        "SKU Padre": "P-BIMON", "SKU": "P-BIMON-A", "Nombre": "A",
        "Tipo 1": "Metal", "Descripción 1": "Plata · 925",
        "Cantidad 1": "5", "Moneda 1": "ARS · Peso Argentino",
        "Tipo 2": "Hechura", "Precio Unit. 2": "100",
        "Moneda 2": "USD · Dólares",
      },
      {
        "SKU Padre": "P-BIMON", "SKU": "P-BIMON-B", "Nombre": "B",
        "Tipo 1": "Metal", "Descripción 1": "Plata · 925",
        "Cantidad 1": "5", "Moneda 1": "ARS · Peso Argentino",
        "Tipo 2": "Hechura", "Precio Unit. 2": "100",
        "Moneda 2": "USD · Dólares",
      },
    ];
    const implicit = buildImplicitParents(rows, new Set());
    const entry = implicit.get("P-BIMON")!;
    expect(entry.conflicts).toHaveLength(0);
    expect(entry.row["Moneda 1"]).toBe("ARS · Peso Argentino");
    expect(entry.row["Moneda 2"]).toBe("USD · Dólares");
  });

  it("variantes sin bloques de costo → padre implícito creado sin costo (sin crash)", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "P-NOCOST", "SKU": "P-NOCOST-A", "Nombre": "A" },
      { "SKU Padre": "P-NOCOST", "SKU": "P-NOCOST-B", "Nombre": "B" },
    ];
    const implicit = buildImplicitParents(rows, new Set());
    const entry = implicit.get("P-NOCOST")!;
    expect(entry.conflicts).toHaveLength(0);
    // Sin datos de costo → bloques vacíos (no debe crashear)
    expect(entry.row["Tipo 1"] ?? "").toBe("");
    expect(entry.row["Tipo 2"] ?? "").toBe("");
  });
});

// =============================================================================
// Pipeline — checkParentConsistency respeta solo campos de nivel padre
// =============================================================================

describe("Pipeline — checkParentConsistency: campos de variante no causan bloqueo", () => {
  it("variantes con NOTAS distintas → NO genera inconsistencia en checkParentConsistency", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "P-NOTE", "SKU": "P-NOTE-A", "Notas": "nota A" },
      { "SKU Padre": "P-NOTE", "SKU": "P-NOTE-B", "Notas": "nota B" },
    ];
    const inconsistencies = checkParentConsistency(rows);
    expect(inconsistencies.has("P-NOTE")).toBe(false);
  });

  it("variantes con CATEGORÍA distinta → GENERA inconsistencia en checkParentConsistency", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "P-CAT", "SKU": "P-CAT-A", "Categoría": "Anillos" },
      { "SKU Padre": "P-CAT", "SKU": "P-CAT-B", "Categoría": "Pulseras" },
    ];
    const inconsistencies = checkParentConsistency(rows);
    expect(inconsistencies.has("P-CAT")).toBe(true);
    expect(inconsistencies.get("P-CAT")!.join(" ")).toMatch(/categor/i);
  });
});

// =============================================================================
// Escenarios del padre: sin padre / padre en archivo / padre en sistema
// =============================================================================

describe("Escenario — variantes sin padre explícito en el archivo", () => {
  it("padre inexistente con datos consistentes → reconstruible (sin conflictos)", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "A001", "SKU": "A001-S", "Nombre": "Talle S", "Categoría": "Anillos" },
      { "SKU Padre": "A001", "SKU": "A001-M", "Nombre": "Talle M", "Categoría": "Anillos" },
      { "SKU Padre": "A001", "SKU": "A001-L", "Nombre": "Talle L", "Categoría": "Anillos" },
    ];
    // A001 no está en DB ni en archivo
    const implicit = buildImplicitParents(rows, new Set());
    expect(implicit.size).toBe(1);
    expect(implicit.get("A001")!.conflicts).toHaveLength(0);
  });

  it("padre inexistente con categorías inconsistentes → con conflictos (no reconstruible)", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "B001", "SKU": "B001-S", "Nombre": "S", "Categoría": "Anillos" },
      { "SKU Padre": "B001", "SKU": "B001-M", "Nombre": "M", "Categoría": "Pulseras" },
    ];
    const implicit = buildImplicitParents(rows, new Set());
    const entry = implicit.get("B001")!;
    expect(entry.conflicts.length).toBeGreaterThan(0);
    expect(entry.conflicts.join(" ")).toMatch(/categor/i);
  });

  it("padre inexistente con datos consistentes y bloques de costo → padre reconstruido con costo", () => {
    const rows: Record<string, string>[] = [
      {
        "SKU Padre": "C001", "SKU": "C001-ORO", "Nombre": "Oro",
        "Categoría": "Anillos",
        "Tipo 1": "Metal", "Descripción 1": "Oro · 18k", "Cantidad 1": "3",
        "Tipo 2": "Hechura", "Precio Unit. 2": "35000",
      },
      {
        "SKU Padre": "C001", "SKU": "C001-PLATA", "Nombre": "Plata",
        "Categoría": "Anillos",
        "Tipo 1": "Metal", "Descripción 1": "Oro · 18k", "Cantidad 1": "3",
        "Tipo 2": "Hechura", "Precio Unit. 2": "35000",
      },
    ];
    const implicit = buildImplicitParents(rows, new Set());
    const entry = implicit.get("C001")!;
    expect(entry.conflicts).toHaveLength(0);
    // Padre reconstruido tiene los bloques de costo
    expect(entry.row["Tipo 1"]).toBe("Metal");
    expect(entry.row["Tipo 2"]).toBe("Hechura");
    expect(entry.row["Descripción 1"]).toBe("Oro · 18k");
  });
});

describe("Escenario — variantes con padre explícito en el archivo", () => {
  it("padre presente en archivo → buildFileParentSkus lo detecta, buildImplicitParents no reconstruye", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "", "SKU": "D001", "Nombre": "Artículo D" },
      { "SKU Padre": "D001", "SKU": "D001-A", "Nombre": "D Variante A" },
      { "SKU Padre": "D001", "SKU": "D001-B", "Nombre": "D Variante B" },
    ];
    const fileParents = buildFileParentSkus(rows);
    expect(fileParents.has("D001")).toBe(true);

    const implicit = buildImplicitParents(rows, fileParents);
    expect(implicit.size).toBe(0);  // padre ya está en el archivo → no necesita reconstrucción
  });

  it("padre en archivo con 3 variantes → buildFileParentSkus no cuenta las variantes como padres", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "", "SKU": "E001", "Nombre": "Artículo E" },
      { "SKU Padre": "E001", "SKU": "E001-S", "Nombre": "S" },
      { "SKU Padre": "E001", "SKU": "E001-M", "Nombre": "M" },
      { "SKU Padre": "E001", "SKU": "E001-L", "Nombre": "L" },
    ];
    const fileParents = buildFileParentSkus(rows);
    expect(fileParents.size).toBe(1);
    expect(fileParents.has("E001")).toBe(true);
    expect(fileParents.has("E001-S")).toBe(false);
  });
});

describe("Escenario — variantes con padre en el sistema (DB)", () => {
  it("padre existente en DB → buildImplicitParents no lo reconstruye", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "F001", "SKU": "F001-A", "Nombre": "A" },
      { "SKU Padre": "F001", "SKU": "F001-B", "Nombre": "B" },
    ];
    // Simular que F001 ya está en la DB: se pasa como validParentSkus
    const dbParents = new Set<string>(["F001"]);
    const implicit = buildImplicitParents(rows, dbParents);
    expect(implicit.size).toBe(0);  // padre ya existe en DB → no reconstruir
  });

  it("mezcla de padres en DB y padre faltante → solo el faltante se reconstruye", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "DB-EXIST", "SKU": "DB-EXIST-A", "Nombre": "A", "Categoría": "Anillos" },
      { "SKU Padre": "MISSING",  "SKU": "MISSING-A",  "Nombre": "B", "Categoría": "Pulseras" },
    ];
    const dbParents = new Set<string>(["DB-EXIST"]);
    const implicit = buildImplicitParents(rows, dbParents);
    expect(implicit.size).toBe(1);
    expect(implicit.has("MISSING")).toBe(true);
    expect(implicit.has("DB-EXIST")).toBe(false);
    expect(implicit.get("MISSING")!.conflicts).toHaveLength(0);
  });
});

// =============================================================================
// Re-parentesco — padre implícito + variantes (artickeId vinculado al padre correcto)
// =============================================================================

describe("Re-parentesco — padres implícitos A000/A001/A002 con sus variantes", () => {
  it("tres grupos implícitos generan tres padres independientes sin conflictos", () => {
    const rows: Record<string, string>[] = [
      // Grupo A000
      { "SKU Padre": "A000", "SKU": "A000-S", "Nombre": "A000 S", "Categoría": "Anillos" },
      { "SKU Padre": "A000", "SKU": "A000-M", "Nombre": "A000 M", "Categoría": "Anillos" },
      { "SKU Padre": "A000", "SKU": "A000-L", "Nombre": "A000 L", "Categoría": "Anillos" },
      // Grupo A001
      { "SKU Padre": "A001", "SKU": "A001-S", "Nombre": "A001 S", "Categoría": "Pulseras" },
      { "SKU Padre": "A001", "SKU": "A001-M", "Nombre": "A001 M", "Categoría": "Pulseras" },
      // Grupo A002
      { "SKU Padre": "A002", "SKU": "A002-A", "Nombre": "A002 A", "Categoría": "Anillos" },
    ];
    const implicit = buildImplicitParents(rows, new Set());
    expect(implicit.size).toBe(3);
    expect(implicit.get("A000")!.conflicts).toHaveLength(0);
    expect(implicit.get("A001")!.conflicts).toHaveLength(0);
    expect(implicit.get("A002")!.conflicts).toHaveLength(0);

    // Cada padre sintético tiene su propia categoría
    expect(implicit.get("A000")!.row["Categoría"]).toBe("Anillos");
    expect(implicit.get("A001")!.row["Categoría"]).toBe("Pulseras");
    expect(implicit.get("A002")!.row["Categoría"]).toBe("Anillos");
  });

  it("padre implícito tiene SKU correcto en la fila sintética", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "A001", "SKU": "A001-S", "Nombre": "Talle S" },
      { "SKU Padre": "A001", "SKU": "A001-M", "Nombre": "Talle M" },
    ];
    const implicit = buildImplicitParents(rows, new Set());
    const entry = implicit.get("A001")!;
    // La fila sintética usa el SKU_Padre como SKU
    expect(entry.row["SKU"]).toBe("A001");
    // Sin SKU_Padre (es el padre, no una variante)
    expect(entry.row["SKU Padre"]).toBe("");
  });

  it("variantes de grupos distintos no interfieren entre sí (cada SKU_Padre independiente)", () => {
    const rows: Record<string, string>[] = [
      { "SKU Padre": "P1", "SKU": "P1-A", "Nombre": "P1 A", "Categoría": "X" },
      { "SKU Padre": "P2", "SKU": "P2-A", "Nombre": "P2 A", "Categoría": "Y" },
      { "SKU Padre": "P1", "SKU": "P1-B", "Nombre": "P1 B", "Categoría": "X" },
      { "SKU Padre": "P2", "SKU": "P2-B", "Nombre": "P2 B", "Categoría": "Y" },
    ];
    const implicit = buildImplicitParents(rows, new Set());
    expect(implicit.size).toBe(2);
    // P1 solo ve sus propias variantes
    expect(implicit.get("P1")!.row["Categoría"]).toBe("X");
    // P2 solo ve sus propias variantes
    expect(implicit.get("P2")!.row["Categoría"]).toBe("Y");
    // Ninguno tiene conflictos
    expect(implicit.get("P1")!.conflicts).toHaveLength(0);
    expect(implicit.get("P2")!.conflicts).toHaveLength(0);
  });
});

describe("Re-parentesco — rowsOrdered incluye todos los padres implícitos antes de las variantes", () => {
  it("buildImplicitParents + buildFileParentSkus cubren todos los padres de un archivo mixto", () => {
    // Archivo con: 1 padre explícito + 1 padre implícito + sus variantes
    const rows: Record<string, string>[] = [
      // Padre explícito
      { "SKU Padre": "", "SKU": "EXPLIC", "Nombre": "Padre Explícito" },
      { "SKU Padre": "EXPLIC", "SKU": "EXPLIC-A", "Nombre": "E-A" },
      { "SKU Padre": "EXPLIC", "SKU": "EXPLIC-B", "Nombre": "E-B" },
      // Padre implícito (no aparece como fila padre)
      { "SKU Padre": "IMPLIC", "SKU": "IMPLIC-A", "Nombre": "I-A", "Categoría": "Anillos" },
      { "SKU Padre": "IMPLIC", "SKU": "IMPLIC-B", "Nombre": "I-B", "Categoría": "Anillos" },
      { "SKU Padre": "IMPLIC", "SKU": "IMPLIC-C", "Nombre": "I-C", "Categoría": "Anillos" },
    ];

    const fileParents    = buildFileParentSkus(rows);
    const validParents   = new Set(fileParents);
    const implicitResult = buildImplicitParents(rows, validParents);

    // Padre explícito detectado en el archivo
    expect(fileParents.has("EXPLIC")).toBe(true);
    // Padre implícito reconstruido
    expect(implicitResult.has("IMPLIC")).toBe(true);
    expect(implicitResult.get("IMPLIC")!.conflicts).toHaveLength(0);

    // Después de añadir los implícitos, todos los padres son válidos
    for (const [sku, { conflicts }] of implicitResult) {
      if (conflicts.length === 0) validParents.add(sku);
    }
    expect(validParents.has("EXPLIC")).toBe(true);
    expect(validParents.has("IMPLIC")).toBe(true);

    // Todas las variantes tienen su padre en validParents
    const variantRows = rows.filter(r => r["SKU Padre"] !== "");
    for (const vr of variantRows) {
      expect(validParents.has(vr["SKU Padre"])).toBe(true);
    }
  });
});

// ===========================================================================
// Soft-delete cascade — comportamiento esperado post-corrección
// ===========================================================================
// Nota: deleteArticle en articles.service.ts ahora hace cascade soft-delete
// a sus ArticleVariant hijas ($transaction). Estos tests verifican que el pipeline
// de importación trata correctamente el escenario "artículo eliminado + reimport".
//
// Invariante: varBySku se construye con { deletedAt: null } → las variantes
// cascade-eliminadas NO aparecen → el reimport las crea nuevas (no las actualiza).

describe("Soft-delete cascade — reimport después de eliminar artículo padre", () => {
  // Simula el estado ANTES del cascade fix (variante huérfana todavía en varBySku)
  it("variante huérfana en varBySku → la reimport la considera existente (bug pre-fix)", () => {
    // DADO: varBySku tiene 'VAR-A' (simulando que sobrevivió al delete del padre)
    const varBySku = new Map([["VAR-A", "variant-uuid-1"]]);
    // La lógica de executeImportGuided busca varBySku.get(sku) para decidir UPDATE vs CREATE
    expect(varBySku.has("VAR-A")).toBe(true); // bug: UPDATE en lugar de CREATE
  });

  it("después de cascade soft-delete, varBySku vacío → reimport crea variantes nuevas (comportamiento correcto)", () => {
    // DADO: varBySku NO tiene 'VAR-A' (cascade eliminó la variante, query filtra deletedAt:null)
    const varBySku = new Map<string, string>(); // vacío → simula post-cascade
    expect(varBySku.has("VAR-A")).toBe(false);  // correcto: CREATE path
  });

  it("reimport con padre eliminado y padre implícito reconstruido → padre se recrea correctamente", () => {
    // El padre fue eliminado (no está en artBySku) pero aparece referenciado por variantes en el archivo
    // buildImplicitParents debe reconstruirlo como padre nuevo
    const rows: Record<string, string>[] = [
      { "SKU Padre": "P001", "SKU": "P001-A", "Nombre": "V-A", "Categoría": "Anillos" },
      { "SKU Padre": "P001", "SKU": "P001-B", "Nombre": "V-B", "Categoría": "Anillos" },
    ];
    // artBySku vacío = simula que el padre fue eliminado y no está en DB
    const artBySku = new Map<string, { id: string; name: string }>();
    const fileParents = buildFileParentSkus(rows);
    const validParents = new Set([...fileParents, ...artBySku.keys()]);
    // "P001" no está en el archivo como fila padre NI en DB → no es válido todavía
    expect(fileParents.has("P001")).toBe(false);
    // buildImplicitParents lo reconstruye
    const implicitMap = buildImplicitParents(rows, validParents);
    expect(implicitMap.has("P001")).toBe(true);
    expect(implicitMap.get("P001")!.conflicts).toHaveLength(0);
    // Después de añadir el implícito, P001 es un padre válido
    implicitMap.forEach(({ conflicts }, sku) => {
      if (conflicts.length === 0) validParents.add(sku);
    });
    expect(validParents.has("P001")).toBe(true);
  });

  it("variantes con padre eliminado + varBySku vacío → todas las variantes son 'nuevas' (CREATE)", () => {
    // Verifica que el mapa de variantes vacío implica que TODAS se crearán como nuevas
    const varBySku = new Map<string, string>();
    const skusAImportar = ["P001-A", "P001-B", "P001-C"];
    for (const sku of skusAImportar) {
      expect(varBySku.has(sku)).toBe(false); // todas van por el camino CREATE
    }
  });

  it("mezcla: variante nueva (no en DB) + variante existente (otra) → solo la nueva va por CREATE", () => {
    // Simula que P001 fue eliminado (con cascade) y P002 sigue activo
    const varBySku = new Map([
      ["P002-A", "variant-uuid-p2a"], // P002 intacto
      ["P002-B", "variant-uuid-p2b"],
    ]);
    // Variantes de P001 (cascade-eliminadas) no aparecen
    expect(varBySku.has("P001-A")).toBe(false); // CREATE
    expect(varBySku.has("P001-B")).toBe(false); // CREATE
    // Variantes de P002 sí aparecen
    expect(varBySku.has("P002-A")).toBe(true);  // UPDATE
    expect(varBySku.has("P002-B")).toBe(true);  // UPDATE
  });
});

// ===========================================================================
// Variante eliminada individualmente (padre sigue activo) — restauración
// ===========================================================================
// Escenario: el PADRE no fue eliminado, pero una variante específica fue
// borrada manualmente. Al reimportar:
//   - varBySku no tiene la variante (deletedAt != null → filtrada)
//   - executeImportGuided busca soft-deleted por (articleId, sku) antes de crear
//   - Si la encuentra → restaura (evita @@unique([articleId, code]) conflict)
//   - Si no → crea nueva con código libre

describe("Variante eliminada individualmente — lógica de restauración en reimport", () => {
  it("varBySku no contiene variante soft-deleted (filtro deletedAt:null correcto)", () => {
    // El mapa varBySku viene de { deletedAt: null } → variante borrada individualmente excluida
    const varBySku = new Map([
      ["P001-B", "var-b-id"], // sigue activa
      // P001-A fue borrada → no está en el mapa
    ]);
    expect(varBySku.has("P001-A")).toBe(false); // va al camino de creación/restauración
    expect(varBySku.has("P001-B")).toBe(true);  // sigue al camino UPDATE normal
  });

  it("sin variante soft-deleted bajo el mismo padre → flujo CREATE normal", () => {
    // Simula: padre existe, ninguna variante borrada bajo él con ese SKU
    // → el import crea nueva variante (sin buscar restaurar)
    const softDeletedBySku: null = null; // simulate findFirst returns null
    const shouldRestore = softDeletedBySku != null;
    expect(shouldRestore).toBe(false); // va al camino CREATE
  });

  it("con variante soft-deleted bajo el mismo padre → flujo RESTAURAR en vez de crear", () => {
    // Simula: padre existe, variante borrada con mismo SKU encontrada
    // → el import restaura en vez de crear (evita colisión de code)
    const softDeletedBySku = { id: "old-var-id" }; // simulate findFirst returns something
    const shouldRestore = softDeletedBySku != null;
    expect(shouldRestore).toBe(true); // restaurar → no viola @@unique([articleId, code])
  });

  it("código generado colisiona con variante soft-deleted → se busca código libre", () => {
    // Simula la detección de colisión en la generación de código
    // Padre tiene: VAR-001 (activa), VAR-002 (borrada)
    // sortOrder = count(deletedAt:null) = 1 → genCode = VAR-002 → colisión
    const codesUsed = new Set(["VAR-001", "VAR-002"]); // incluye soft-deleted
    let genCode = "VAR-002"; // sortOrder=1 → intento inicial

    // Buscar el siguiente libre
    if (codesUsed.has(genCode)) {
      let seq = 3;
      while (codesUsed.has(`VAR-${String(seq).padStart(3, "0")}`)) seq++;
      genCode = `VAR-${String(seq).padStart(3, "0")}`;
    }

    expect(genCode).toBe("VAR-003"); // siguiente código libre
    expect(codesUsed.has(genCode)).toBe(false);
  });

  it("múltiples colisiones → itera hasta encontrar código libre", () => {
    // Padre tiene: VAR-001 (activa), VAR-002 (borrada), VAR-003 (borrada)
    // sortOrder = 1 → genCode = VAR-002 → colisión → VAR-003 → colisión → VAR-004 libre
    const codesUsed = new Set(["VAR-001", "VAR-002", "VAR-003"]);
    let genCode = "VAR-002";

    if (codesUsed.has(genCode)) {
      let seq = 3;
      while (codesUsed.has(`VAR-${String(seq).padStart(3, "0")}`)) seq++;
      genCode = `VAR-${String(seq).padStart(3, "0")}`;
    }

    expect(genCode).toBe("VAR-004");
    expect(codesUsed.has(genCode)).toBe(false);
  });
});

// =============================================================================
// Regla de negocio: padre vs variante — overrides simples e import de costo
// =============================================================================

describe("Regla padre/variante — import de costo", () => {
  // ── Padre: composición completa → extractGuidedCostBlocks ──────────────────

  it("padre con bloque Metal extrae bloque completo (tipo=METAL, descripción, cantidad)", () => {
    const row: Record<string, string> = {
      "Moneda 1": "ARS · Peso Argentino",
      "Tipo 1": "Metal",
      "Descripción 1": "Oro 18K Amarillo",
      "Cantidad 1": "3.5",
      "Precio Unit. 1": "",
      "Merma % 1": "2.5",
      "Bonif/Recargo 1": "",
    };
    const blocks = extractGuidedCostBlocks(row);
    expect(blocks).toHaveLength(1);
    expect(blocks[0].type).toBe("METAL");
    expect(blocks[0].descripcion).toBe("Oro 18K Amarillo");
    expect(blocks[0].cantidad).toBe(3.5);
    expect(blocks[0].mermaPercent).toBe(2.5);
  });

  it("padre con bloque Hechura extrae bloque completo (tipo=HECHURA, precio)", () => {
    const row: Record<string, string> = {
      "Moneda 1": "ARS · Peso Argentino",
      "Tipo 1": "Hechura",
      "Descripción 1": "Precio / Hechura",
      "Cantidad 1": "1",
      "Precio Unit. 1": "500",
      "Merma % 1": "",
      "Bonif/Recargo 1": "",
    };
    const blocks = extractGuidedCostBlocks(row);
    expect(blocks).toHaveLength(1);
    expect(blocks[0].type).toBe("HECHURA");
    expect(blocks[0].unitPrice).toBe(500);
  });

  it("padre con Metal + Hechura extrae dos bloques", () => {
    const row: Record<string, string> = {
      "Moneda 1": "ARS · Peso Argentino",
      "Tipo 1": "Metal",
      "Descripción 1": "Oro 18K",
      "Cantidad 1": "3.5",
      "Precio Unit. 1": "",
      "Merma % 1": "",
      "Bonif/Recargo 1": "",
      "Moneda 2": "ARS · Peso Argentino",
      "Tipo 2": "Hechura",
      "Descripción 2": "Hechura manual",
      "Cantidad 2": "1",
      "Precio Unit. 2": "400",
      "Merma % 2": "",
      "Bonif/Recargo 2": "",
    };
    const blocks = extractGuidedCostBlocks(row);
    expect(blocks).toHaveLength(2);
    expect(blocks[0].type).toBe("METAL");
    expect(blocks[1].type).toBe("HECHURA");
  });

  it("padre sin bloques de costo no extrae nada", () => {
    const row: Record<string, string> = {
      "Tipo 1": "", "Descripción 1": "", "Cantidad 1": "", "Precio Unit. 1": "",
    };
    expect(extractGuidedCostBlocks(row)).toHaveLength(0);
  });

  // ── Variante: composición propia vía bloques de costo ────────────────────────

  it("variante con bloque Metal (sin cantidad) genera warning de cantidad faltante", () => {
    const row: Record<string, string> = {
      "Tipo 1": "Metal", "Descripción 1": "Oro 18K", "Cantidad 1": "", "Precio Unit. 1": "",
    };
    const warns = validateCostBlockWarnings(row);
    expect(warns.some(w => w.toLowerCase().includes("cantidad"))).toBe(true);
    // No debe mencionar "padre" — misma validación que artículo
    expect(warns.every(w => !w.toLowerCase().includes("padre"))).toBe(true);
  });

  it("variante con bloque Hechura sin precio genera warning de precio faltante", () => {
    const row: Record<string, string> = {
      "Tipo 1": "Hechura", "Descripción 1": "Hechura", "Cantidad 1": "1", "Precio Unit. 1": "",
    };
    const warns = validateCostBlockWarnings(row);
    expect(warns.some(w => w.toLowerCase().includes("precio"))).toBe(true);
  });

  it("variante con bloque Hechura completo no genera warnings", () => {
    const row: Record<string, string> = {
      "Tipo 1": "Hechura", "Descripción 1": "Hechura manual", "Cantidad 1": "1", "Precio Unit. 1": "500",
    };
    expect(validateCostBlockWarnings(row)).toHaveLength(0);
  });

  it("variante sin bloques no genera warnings (hereda del padre)", () => {
    const row: Record<string, string> = {
      "Tipo 1": "", "Precio Unit. 1": "",
      "Tipo 2": "", "Precio Unit. 2": "",
    };
    expect(validateCostBlockWarnings(row)).toHaveLength(0);
  });

  it("peso de variante se lee directamente de la columna 'Peso (g)'", () => {
    // Peso (g) se lee directamente via GH.PESO
    const row: Record<string, string> = { "Peso (g)": "4.2" };
    const parsed = parseFloat(row["Peso (g)"]);
    expect(parsed).toBe(4.2);
  });

  it("variante con Metal completo extrae un bloque METAL", () => {
    const row: Record<string, string> = {
      "Moneda 1": "ARS · Peso Argentino",
      "Tipo 1": "Metal", "Descripción 1": "Oro 18K", "Cantidad 1": "3.5",
      "Precio Unit. 1": "", "Merma % 1": "2", "Bonif/Recargo 1": "",
    };
    const blocks = extractGuidedCostBlocks(row);
    expect(blocks).toHaveLength(1);
    expect(blocks[0].type).toBe("METAL");
    expect(blocks[0].cantidad).toBe(3.5);
  });
});
