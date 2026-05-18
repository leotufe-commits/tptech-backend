// src/modules/articles/articles.import.service.ts
// Servicio de importación masiva de artículos y variantes desde Excel/CSV.
import * as XLSX from "xlsx";
import ExcelJS from "exceljs";
import { Prisma } from "@prisma/client";
import { prisma } from "../../lib/prisma.js";
import { applyStockDelta as engineApplyStockDelta } from "../../lib/stock-engine.js";
import { saveBatch, buildBatchRowsFromArticleResults, type V2RetryPayload } from "../../lib/importBatch.helper.js";

// ─── Helpers ─────────────────────────────────────────────────────────────────
function s(v: any): string { return String(v ?? "").trim(); }
function n(v: any): number | null {
  if (v == null || v === "") return null;
  const x = typeof v === "string" ? parseFloat(v.replace(",", ".")) : Number(v);
  return isFinite(x) ? x : null;
}
function b(v: string): boolean {
  return ["si", "sí", "yes", "true", "1"].includes(v.toLowerCase().trim());
}
function normalizeStr(v: string): string {
  return v.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/\s+/g, " ").trim();
}

// ─── Tipos y helpers de atributos de variante ─────────────────────────────────
type CatAxis = {
  id: string;
  isRequired: boolean;
  definition: {
    name: string;
    code: string;
    inputType: string;
    options: { value: string }[];
  };
};

/** Extrae columnas Atrib_* de una fila → { Color: "Rojo", Medida: "16" } */
function extractAttributes(row: ImportRow): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(row)) {
    if (k.startsWith("Atrib_") && s(v)) {
      out[k.slice(6)] = s(v); // "Atrib_Color" → "Color"
    }
  }
  return out;
}

/** Normaliza el valor según el inputType antes de persistir */
function normalizeAttrValue(value: string, inputType: string): string {
  const v = value.trim();
  if (inputType === "BOOLEAN") {
    if (["si", "sí", "yes", "true", "1"].includes(v.toLowerCase())) return "true";
    if (["no", "false", "0"].includes(v.toLowerCase())) return "false";
  }
  if (inputType === "NUMBER" || inputType === "DECIMAL") {
    return v.replace(",", ".");
  }
  return v;
}

/** Valida el valor de un atributo según su inputType. Devuelve mensaje de error o null. */
function validateAttrValue(
  attrName: string,
  value: string,
  inputType: string,
  options: { value: string }[],
): string | null {
  const v = value.trim();
  if (!v) return null;
  if (inputType === "NUMBER" || inputType === "DECIMAL") {
    if (isNaN(Number(v.replace(",", ".")))) {
      return `Valor "${v}" no es un número válido para el atributo "${attrName}".`;
    }
  }
  if (inputType === "BOOLEAN") {
    const valid = ["true", "false", "si", "sí", "no", "yes", "1", "0"];
    if (!valid.includes(v.toLowerCase())) {
      return `Valor "${v}" para "${attrName}" debe ser SI/NO o true/false.`;
    }
  }
  if (inputType === "SELECT") {
    const opts = options.map(o => o.value);
    if (!opts.includes(v)) {
      return `Valor "${v}" no es una opción válida para "${attrName}". Opciones: ${opts.join(", ") || "(ninguna)"}`;
    }
  }
  if (inputType === "MULTISELECT") {
    const opts = new Set(options.map(o => o.value));
    const selected = v.split(",").map(x => x.trim());
    for (const sel of selected) {
      if (!opts.has(sel)) {
        return `Valor "${sel}" no es válido para "${attrName}". Opciones: ${[...opts].join(", ") || "(ninguna)"}`;
      }
    }
  }
  return null;
}

/** Clave normalizada de combinación de atributos (para detección de duplicados) */
function buildAttrComboKey(attrs: { assignmentId: string; value: string }[]): string {
  return attrs
    .slice()
    .sort((a, b) => a.assignmentId.localeCompare(b.assignmentId))
    .map(a => `${a.assignmentId}:${a.value.trim().toLowerCase()}`)
    .join("|");
}

/** Devuelve los ejes de variante efectivos de una categoría (propios + heredados) */
async function getEffectiveCategoryAxes(categoryId: string, jewelryId: string): Promise<CatAxis[]> {
  const axisMap = new Map<string, CatAxis>(); // defCode → axis (propios tienen prioridad)
  let currentId: string | null = categoryId;
  let isOwnLevel = true;
  const visited = new Set<string>();

  while (currentId && !visited.has(currentId)) {
    visited.add(currentId);
    const cat: { parentId: string | null; attributes: CatAxis[] } | null = await prisma.articleCategory.findFirst({
      where: { id: currentId, jewelryId, deletedAt: null },
      select: {
        parentId: true,
        attributes: {
          where: {
            isVariantAxis: true,
            isActive: true,
            deletedAt: null,
            ...(isOwnLevel ? {} : { inheritToChild: true }),
          },
          select: {
            id: true,
            isRequired: true,
            definition: {
              select: {
                name: true,
                code: true,
                inputType: true,
                options: { select: { value: true } },
              },
            },
          },
        },
      },
    });
    if (!cat) break;
    for (const attr of cat.attributes) {
      if (!axisMap.has(attr.definition.code)) {
        axisMap.set(attr.definition.code, attr);
      }
    }
    currentId = cat.parentId ?? null;
    isOwnLevel = false;
  }

  return Array.from(axisMap.values());
}

// ─── Columnas del template ────────────────────────────────────────────────────
export const TEMPLATE_HEADERS = [
  "Es_Variante",       // SI/NO
  "Articulo_Padre",    // Código del artículo padre (solo para variantes)
  "Nombre",            // Obligatorio
  "Codigo",            // Auto-generado si está vacío
  "Tipo",              // PRODUCT | SERVICE | MATERIAL
  "Estado",            // DRAFT | ACTIVE | DISCONTINUED | ARCHIVED
  "SKU",
  "Barcode",
  "Tipo_Barcode",      // CODE128 | EAN13 | QR
  "Categoria",         // Nombre de la categoría (búsqueda por nombre)
  "Grupo",             // Nombre del grupo comercial
  "Proveedor",         // Código del proveedor preferido (ej. CE-0001)
  "Marca",
  "Fabricante",
  "Descripcion",
  "Precio_Costo",
  "Precio_Venta",
  "Hechura",
  "Hechura_Modo",      // FIXED | PER_GRAM
  "Merma_Pct",
  "Modo_Stock",        // NO_STOCK | BY_ARTICLE | BY_MATERIAL
  "Unidad",
  "Peso",              // En gramos (artículo) o weightOverride (variante)
  "Reorder_Point",
  "Cant_Min",
  "Cant_Max",
  "Cant_Default",
  "Favorito",          // SI | NO
  "Activo",            // SI | NO
  "En_Tienda",         // SI | NO
  "Acepta_Devolucion", // SI | NO
  "Vender_Sin_Variantes", // SI | NO
  "Notas",
  // Columnas opcionales de atributos de variante (Atrib_NombreAtributo)
  "Atrib_Color",
  "Atrib_Medida",
];

// Índices de columna para el helper de exports (0-based)
const COL = Object.fromEntries(TEMPLATE_HEADERS.map((h, i) => [h, i]));

const EXAMPLE_ARTICLE = [
  "NO", "", "Anillo de Oro 18K", "ART-001", "PRODUCT", "ACTIVE",
  "SKU-001", "", "CODE128", "Anillos", "", "",
  "Marca Propia", "", "Anillo de oro amarillo 18K", "15000", "25000",
  "500", "FIXED", "2.5", "BY_ARTICLE", "UND", "3", "5", "", "", "1",
  "SI", "SI", "SI", "SI", "NO", "Ejemplo de artículo",
  "", "",
];
const EXAMPLE_VARIANT = [
  "SI", "ART-001", "Talle 16", "VAR-001-T16", "", "",
  "SKU-001-T16", "", "CODE128", "", "", "",
  "", "", "", "16000", "27000",
  "", "", "", "", "", "3.2", "", "", "", "",
  "", "", "", "", "", "Variante talle 16",
  "Rojo", "16",
];
const EXAMPLE_SERVICE = [
  "NO", "", "Engaste de piedras", "SRV-001", "SERVICE", "ACTIVE",
  "", "", "CODE128", "Servicios", "", "",
  "", "", "Servicio de engaste manual", "0", "3500",
  "3500", "FIXED", "0", "NO_STOCK", "UND", "", "", "", "", "",
  "NO", "SI", "NO", "NO", "NO", "Servicio",
  "", "",
];

// ─── Tipos públicos ──────────────────────────────────────────────────────────
export type ImportRow = Record<string, string>;

export type ImportPreviewRow = {
  index: number;
  isVariant: boolean;
  parentCode: string;
  displayName: string;
  /**
   * "valid"           → nueva fila sin advertencias (se creará)
   * "overwrite"       → SKU ya existe en sistema (se sobreescribirá)
   * "warning"         → nueva fila con advertencias
   * "implicit_parent" → padre reconstruido automáticamente de variantes consistentes
   * "error"           → error bloqueante, no se importará
   */
  status: "valid" | "overwrite" | "warning" | "implicit_parent" | "error";
  errors: string[];
  warnings: string[];
  existingId?: string;
  /** Atributos de variante detectados en columnas Atrib_* (solo para variantes) */
  attributes?: Record<string, string>;
};

export type ImportPreviewResult = {
  total: number;
  articles: number;
  variants: number;
  valid: number;
  errors: number;
  /** Filas que corresponden a registros existentes (serán sobreescritos si se elige "actualizar"). */
  overwrite: number;
  warnings: number;
  /** Artículos padre reconstruidos implícitamente de sus variantes (no tenían fila propia). */
  implicitParents: number;
  rows: ImportPreviewRow[];
};

export type ImportCommitRow = {
  index:         number;
  displayName:   string;
  status:        "created" | "updated" | "skipped" | "error";
  errors?:       string[];
  id?:           string;
  /** Campo interno para V2 — almacena payload de reintento para FAILED rows */
  _retryPayload?: V2RetryPayload;
};

export type ImportCommitResult = {
  results:  ImportCommitRow[];
  summary:  { created: number; updated: number; skipped: number; errors: number };
  batchId?: string | null;
};

// ─── Datos de tenant para el template ─────────────────────────────────────────
export type TemplateCatalogData = {
  categories: string[];          // nombres de categorías
  groups: string[];              // nombres de grupos
  suppliers: string[];           // códigos de proveedores (ej. CE-0001 · Proveedor SA)
};

// ─── Widths de columna (por índice, 0-based) ────────────────────────────────
const TEMPLATE_COL_WIDTHS: number[] = [
  14, 16, 30, 14, 12, 14, 16, 16, 14,  // Es_Variante … Tipo_Barcode
  22, 18, 26, 16, 16, 35,               // Categoria … Descripcion
  14, 14, 14, 14, 12,                   // Precio_Costo … Merma_Pct
  14, 12, 10, 14, 12, 12, 14,          // Modo_Stock … Cant_Default
  12, 12, 12, 18, 20, 30,              // Favorito … Notas
  16, 16,                               // Atrib_Color, Atrib_Medida
];

// ─── Generar template XLSX (con ExcelJS: estilos, dropdowns, fila congelada) ─
export async function generateImportTemplate(catalog: TemplateCatalogData): Promise<Buffer> {
  const wb = new ExcelJS.Workbook();
  wb.creator = "TPTech";
  wb.created = new Date();

  // ── Hoja Catálogos (oculta — fuente de datos para dropdowns dinámicos) ──────
  const catSheet = wb.addWorksheet("Catálogos", { state: "hidden" });
  catSheet.getCell("A1").value = "Categorias";
  catSheet.getCell("B1").value = "Grupos";
  catSheet.getCell("C1").value = "Proveedores";

  const maxRows = Math.max(catalog.categories.length, catalog.groups.length, catalog.suppliers.length, 1);
  for (let i = 0; i < maxRows; i++) {
    catSheet.getCell(`A${i + 2}`).value = catalog.categories[i] ?? "";
    catSheet.getCell(`B${i + 2}`).value = catalog.groups[i] ?? "";
    catSheet.getCell(`C${i + 2}`).value = catalog.suppliers[i] ?? "";
  }

  // ── Hoja Artículos ────────────────────────────────────────────────────────
  const ws = wb.addWorksheet("Artículos");

  // Columnas con anchos
  ws.columns = TEMPLATE_HEADERS.map((header, i) => ({
    header,
    key: header,
    width: TEMPLATE_COL_WIDTHS[i] ?? 14,
  }));

  // Estilo de cabecera: fondo gris, negrita, centrado
  const headerRow = ws.getRow(1);
  headerRow.height = 24;
  headerRow.eachCell((cell) => {
    cell.font = { bold: true, size: 10 };
    cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFD9D9D9" } };
    cell.alignment = { vertical: "middle", horizontal: "center", wrapText: false };
    cell.border = { bottom: { style: "thin", color: { argb: "FF999999" } } };
  });

  // Fijar primera fila
  ws.views = [{ state: "frozen", xSplit: 0, ySplit: 1, topLeftCell: "A2" }];

  // Filtros en la cabecera
  ws.autoFilter = { from: "A1", to: { row: 1, column: TEMPLATE_HEADERS.length } };

  // ── Filas de ejemplo ─────────────────────────────────────────────────────
  const exRow1 = ws.addRow(EXAMPLE_ARTICLE);
  const exRow2 = ws.addRow(EXAMPLE_VARIANT);
  const exRow3 = ws.addRow(EXAMPLE_SERVICE);
  // Estilo sutil en filas de ejemplo
  [exRow1, exRow2, exRow3].forEach((r) => {
    r.font = { italic: true, color: { argb: "FF888888" }, size: 9 };
  });

  // ── Validaciones de datos (dropdowns) ────────────────────────────────────
  const DATA_ROWS = 2001; // filas 2 a 2001

  const wsAny = ws as any;
  const addValidation = (col: number, formula: string) => {
    const colLetter = ws.getColumn(col).letter;
    wsAny.dataValidations.add(`${colLetter}2:${colLetter}${DATA_ROWS}`, {
      type: "list",
      allowBlank: true,
      formulae: [formula],
      showErrorMessage: true,
      errorTitle: "Valor inválido",
      error: "Seleccioná un valor de la lista.",
    });
  };

  // Enumerados fijos (inline)
  addValidation(COL["Es_Variante"] + 1,       '"SI,NO"');
  addValidation(COL["Tipo"] + 1,              '"PRODUCT,SERVICE,MATERIAL"');
  addValidation(COL["Estado"] + 1,            '"DRAFT,ACTIVE,DISCONTINUED,ARCHIVED"');
  addValidation(COL["Tipo_Barcode"] + 1,      '"CODE128,EAN13,QR"');
  addValidation(COL["Hechura_Modo"] + 1,      '"FIXED,PER_GRAM"');
  addValidation(COL["Modo_Stock"] + 1,        '"NO_STOCK,BY_ARTICLE,BY_MATERIAL"');
  addValidation(COL["Favorito"] + 1,          '"SI,NO"');
  addValidation(COL["Activo"] + 1,            '"SI,NO"');
  addValidation(COL["En_Tienda"] + 1,         '"SI,NO"');
  addValidation(COL["Acepta_Devolucion"] + 1, '"SI,NO"');
  addValidation(COL["Vender_Sin_Variantes"] + 1, '"SI,NO"');

  // Catálogos dinámicos (referencia a hoja Catálogos)
  if (catalog.categories.length > 0) {
    const catEnd = catalog.categories.length + 1;
    addValidation(COL["Categoria"] + 1, `'Catálogos'!$A$2:$A$${catEnd}`);
  }
  if (catalog.groups.length > 0) {
    const grpEnd = catalog.groups.length + 1;
    addValidation(COL["Grupo"] + 1, `'Catálogos'!$B$2:$B$${grpEnd}`);
  }
  if (catalog.suppliers.length > 0) {
    const supEnd = catalog.suppliers.length + 1;
    addValidation(COL["Proveedor"] + 1, `'Catálogos'!$C$2:$C$${supEnd}`);
  }

  // ── Hoja Instrucciones ────────────────────────────────────────────────────
  const instrSheet = wb.addWorksheet("Instrucciones");
  instrSheet.getColumn(1).width = 90;
  const instrLines = [
    ["INSTRUCCIONES DE IMPORTACIÓN MASIVA DE ARTÍCULOS — TPTech"],
    [""],
    ["TIPOS DE FILA"],
    ["  Es_Variante = NO (o vacío) → fila de artículo"],
    ["  Es_Variante = SI          → fila de variante (requiere Articulo_Padre = código del padre)"],
    [""],
    ["COLUMNAS OBLIGATORIAS"],
    ["  Nombre: siempre requerido"],
    ["  Articulo_Padre: requerido si Es_Variante = SI"],
    [""],
    ["NUEVOS CAMPOS (v2)"],
    ["  Grupo: nombre del grupo comercial del artículo"],
    ["  Proveedor: código del proveedor preferido (ej. CE-0001)"],
    ["  Peso: gramaje del artículo o weightOverride de la variante"],
    ["  Reorder_Point: nivel de reorden para alertas de stock"],
    ["  Cant_Min / Cant_Max / Cant_Default: cantidades de venta"],
    ["  Favorito / Activo: SI o NO"],
    ["  Vender_Sin_Variantes: SI o NO (solo para artículos con variantes)"],
    [""],
    ["VALORES VÁLIDOS"],
    ["  Tipo:        PRODUCT | SERVICE | MATERIAL  (default: PRODUCT)"],
    ["  Estado:      DRAFT | ACTIVE | DISCONTINUED | ARCHIVED  (default: DRAFT)"],
    ["  Tipo_Barcode: CODE128 | EAN13 | QR  (default: CODE128)"],
    ["  Hechura_Modo: FIXED | PER_GRAM  (default: FIXED)"],
    ["  Modo_Stock:  NO_STOCK | BY_ARTICLE | BY_MATERIAL  (default: NO_STOCK)"],
    ["  Booleanos (Favorito, Activo, etc.): SI o NO"],
    [""],
    ["CAMPOS OPCIONALES"],
    ["  Codigo:  Si está vacío se genera automáticamente (ART-0001, ART-0002...)"],
    ["  Barcode: Si está vacío no se asigna código de barras"],
    ["  Categoria / Grupo / Proveedor: Si no se encuentra se omite sin error"],
    ["  Los precios y cantidades aceptan punto o coma como separador decimal"],
    [""],
    ["ATRIBUTOS DE VARIANTE (columnas Atrib_*)"],
    ["  Solo aplican a filas con Es_Variante = SI"],
    ["  El nombre de la columna (Atrib_Color, Atrib_Talle, etc.) debe coincidir con"],
    ["  el nombre o código de un atributo de variante configurado en la categoría del padre"],
    ["  Se pueden agregar tantas columnas Atrib_* como sea necesario"],
    [""],
    ["ESTRATEGIA ANTE DUPLICADOS (elegir al ejecutar)"],
    ["  Omitir (skip):   si el artículo ya existe por código, se ignora"],
    ["  Actualizar (update): si el artículo ya existe, se actualizan los campos del Excel"],
    [""],
    ["LÍMITES"],
    ["  Máximo 2.000 filas por importación"],
    ["  Máximo 10 MB por archivo"],
  ];
  instrLines.forEach((line, i) => {
    const cell = instrSheet.getCell(`A${i + 1}`);
    cell.value = line[0] ?? "";
    if (i === 0) cell.font = { bold: true, size: 12 };
    else if (line[0]?.match(/^[A-Z ]+$/) && !line[0].startsWith(" ")) cell.font = { bold: true };
    else cell.font = { size: 10 };
  });

  const buffer = await wb.xlsx.writeBuffer();
  return Buffer.from(buffer);
}

// ─── Exportar artículos existentes ───────────────────────────────────────────
export async function exportArticles(
  jewelryId: string,
  catalog: TemplateCatalogData
): Promise<Buffer> {
  // Cargar artículos con variantes y relaciones
  const articles = await prisma.article.findMany({
    where: { jewelryId, deletedAt: null },
    select: {
      code: true, name: true, description: true, articleType: true, status: true,
      sku: true, barcode: true, barcodeType: true, brand: true, manufacturer: true,
      salePrice: true,
      mermaPercent: true, stockMode: true, unitOfMeasure: true, weight: true,
      reorderPoint: true, minSaleQuantity: true, maxSaleQuantity: true, defaultQuantity: true,
      isFavorite: true, isActive: true, showInStore: true, isReturnable: true,
      sellWithoutVariants: true, notes: true,
      category: { select: { name: true } },
      preferredSupplier: { select: { code: true } },
      variants: {
        where: { deletedAt: null },
        select: {
          code: true, name: true, sku: true,
          weightOverride: true, notes: true,
        },
        orderBy: { sortOrder: "asc" },
      },
    },
    orderBy: { code: "asc" },
    take: 5000,
  });

  const wb = new ExcelJS.Workbook();
  wb.creator = "TPTech";
  wb.created = new Date();

  // Hoja Catálogos (oculta)
  const catSheet = wb.addWorksheet("Catálogos", { state: "hidden" });
  catSheet.getCell("A1").value = "Categorias";
  catSheet.getCell("B1").value = "Grupos";
  catSheet.getCell("C1").value = "Proveedores";
  const maxRows = Math.max(catalog.categories.length, catalog.groups.length, catalog.suppliers.length, 1);
  for (let i = 0; i < maxRows; i++) {
    catSheet.getCell(`A${i + 2}`).value = catalog.categories[i] ?? "";
    catSheet.getCell(`B${i + 2}`).value = catalog.groups[i] ?? "";
    catSheet.getCell(`C${i + 2}`).value = catalog.suppliers[i] ?? "";
  }

  const ws = wb.addWorksheet("Artículos");
  ws.columns = TEMPLATE_HEADERS.map((header, i) => ({
    header, key: header, width: TEMPLATE_COL_WIDTHS[i] ?? 14,
  }));

  // Estilo de cabecera
  const headerRow = ws.getRow(1);
  headerRow.height = 24;
  headerRow.eachCell((cell) => {
    cell.font = { bold: true, size: 10 };
    cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFD9D9D9" } };
    cell.alignment = { vertical: "middle", horizontal: "center" };
    cell.border = { bottom: { style: "thin", color: { argb: "FF999999" } } };
  });
  ws.views = [{ state: "frozen", xSplit: 0, ySplit: 1, topLeftCell: "A2" }];
  ws.autoFilter = { from: "A1", to: { row: 1, column: TEMPLATE_HEADERS.length } };

  function fmt(v: any): string {
    if (v == null) return "";
    return String(v);
  }
  function fmtBool(v: boolean | null | undefined): string {
    if (v == null) return "";
    return v ? "SI" : "NO";
  }
  function fmtDec(v: any): string {
    if (v == null) return "";
    return String(Number(v));
  }

  for (const art of articles) {
    // Fila artículo
    const artRow: string[] = new Array(TEMPLATE_HEADERS.length).fill("");
    artRow[COL["Es_Variante"]]       = "NO";
    artRow[COL["Nombre"]]            = fmt(art.name);
    artRow[COL["Codigo"]]            = fmt(art.code);
    artRow[COL["Tipo"]]              = fmt(art.articleType);
    artRow[COL["Estado"]]            = fmt(art.status);
    artRow[COL["SKU"]]               = fmt(art.sku);
    artRow[COL["Barcode"]]           = fmt(art.barcode);
    artRow[COL["Tipo_Barcode"]]      = fmt(art.barcodeType);
    artRow[COL["Categoria"]]         = fmt(art.category?.name);
    artRow[COL["Grupo"]]             = "";
    artRow[COL["Proveedor"]]         = fmt(art.preferredSupplier?.code);
    artRow[COL["Marca"]]             = fmt(art.brand);
    artRow[COL["Fabricante"]]        = fmt(art.manufacturer);
    artRow[COL["Descripcion"]]       = fmt(art.description);
    artRow[COL["Precio_Costo"]]      = "";
    artRow[COL["Precio_Venta"]]      = fmtDec(art.salePrice);
    artRow[COL["Hechura"]]           = "";
    artRow[COL["Hechura_Modo"]]      = "";
    artRow[COL["Merma_Pct"]]         = fmtDec(art.mermaPercent);
    artRow[COL["Modo_Stock"]]        = fmt(art.stockMode);
    artRow[COL["Unidad"]]            = fmt(art.unitOfMeasure);
    artRow[COL["Peso"]]              = fmtDec(art.weight);
    artRow[COL["Reorder_Point"]]     = fmtDec(art.reorderPoint);
    artRow[COL["Cant_Min"]]          = fmtDec(art.minSaleQuantity);
    artRow[COL["Cant_Max"]]          = fmtDec(art.maxSaleQuantity);
    artRow[COL["Cant_Default"]]      = fmtDec(art.defaultQuantity);
    artRow[COL["Favorito"]]          = fmtBool(art.isFavorite);
    artRow[COL["Activo"]]            = fmtBool(art.isActive);
    artRow[COL["En_Tienda"]]         = fmtBool(art.showInStore);
    artRow[COL["Acepta_Devolucion"]] = fmtBool(art.isReturnable);
    artRow[COL["Vender_Sin_Variantes"]] = fmtBool(art.sellWithoutVariants);
    artRow[COL["Notas"]]             = fmt(art.notes);
    ws.addRow(artRow);

    // Filas de variantes
    for (const v of art.variants) {
      const varRow: string[] = new Array(TEMPLATE_HEADERS.length).fill("");
      varRow[COL["Es_Variante"]]  = "SI";
      varRow[COL["Articulo_Padre"]] = fmt(art.code);
      varRow[COL["Nombre"]]       = fmt(v.name);
      varRow[COL["Codigo"]]       = fmt(v.code);
      varRow[COL["SKU"]]          = fmt(v.sku);
      varRow[COL["Precio_Costo"]] = "";
      varRow[COL["Precio_Venta"]] = ""; // Las variantes no tienen precio propio; se hereda del artículo padre
      varRow[COL["Hechura"]]      = "";
      varRow[COL["Peso"]]         = fmtDec(v.weightOverride);
      varRow[COL["Notas"]]        = fmt(v.notes);
      ws.addRow(varRow);
    }
  }

  const buffer = await wb.xlsx.writeBuffer();
  return Buffer.from(buffer);
}

// ─────────────────────────────────────────────────────────────────────────────
// V2 — TEMPLATE MULTI-HOJA (joyería)
// ─────────────────────────────────────────────────────────────────────────────

// ── Cabeceras por hoja ────────────────────────────────────────────────────────

export const ARTICLE_HEADERS_V2 = [
  "Nombre", "Codigo", "Tipo", "Estado",
  "SKU", "Barcode", "Tipo_Barcode",
  "Categoria", "Grupo", "Proveedor",
  "Marca", "Fabricante", "Descripcion",
  "Precio_Costo", "Precio_Venta",
  "Hechura", "Hechura_Modo", "Merma_Pct", "Modo_Costo",
  "Modo_Stock", "Unidad", "Peso",
  "Reorder_Point", "Cant_Min", "Cant_Max", "Cant_Default",
  "Favorito", "Activo", "En_Tienda", "Acepta_Devolucion", "Vender_Sin_Variantes",
  "Notas",
];

export const VARIANT_HEADERS_V2 = [
  "Articulo_Codigo", "Codigo", "Nombre", "SKU", "Barcode", "Tipo_Barcode",
  "Precio_Costo", "Precio_Venta", "Hechura", "Peso",
  "Reorder_Point", "Cant_Min", "Cant_Max", "Cant_Default",
  "Activo", "Notas",
];

export const METAL_HEADERS_V2 = [
  "Articulo_Codigo", "Codigo_Variante",
  "Metal_Padre", "Metal_Variante",
  "Gramos", "Merma_Pct", "Hechura_Metal", "Es_Base",
];

export const STOCK_HEADERS_V2 = [
  "Articulo_Codigo", "Codigo_Variante",
  "Almacen", "Cantidad", "Peso_Total", "Modo",
];

export const ATTRIBUTE_HEADERS_V2 = [
  "Articulo_Codigo", "Codigo_Variante", "Atributo", "Valor",
];

// ── COL maps ──────────────────────────────────────────────────────────────────
const ACOL = Object.fromEntries(ARTICLE_HEADERS_V2.map((h, i) => [h, i]));
const VCOL = Object.fromEntries(VARIANT_HEADERS_V2.map((h, i) => [h, i]));
const MCOL = Object.fromEntries(METAL_HEADERS_V2.map((h, i) => [h, i]));
const SCOL = Object.fromEntries(STOCK_HEADERS_V2.map((h, i) => [h, i]));

// ── Tipo de catálogo v2 ───────────────────────────────────────────────────────
export type TemplateCatalogDataV2 = {
  categories: string[];      // ArticleCategory.name
  groups: string[];           // ArticleGroup.name
  suppliers: string[];        // "code · displayName"
  metals: string[];           // Metal.name
  metalVariants: string[];    // "Metal.name · MetalVariant.name"
  warehouses: string[];       // "code · name" o solo name
};

// ── Anchos de columna ─────────────────────────────────────────────────────────
const ARTICLE_WIDTHS_V2: number[] = [
  30, 14, 12, 14,             // Nombre … Estado
  16, 16, 14,                 // SKU, Barcode, Tipo_Barcode
  22, 18, 26,                 // Categoria, Grupo, Proveedor
  16, 16, 35,                 // Marca, Fabricante, Descripcion
  14, 14, 14, 14, 12, 22,    // Precio_Costo … Modo_Costo
  14, 12, 10,                 // Modo_Stock, Unidad, Peso
  14, 12, 12, 14,             // Reorder_Point … Cant_Default
  12, 12, 12, 18, 20,        // Favorito … Vender_Sin_Variantes
  30,                         // Notas
];
const VARIANT_WIDTHS_V2: number[] = [
  18, 16, 28, 14, 16, 14,    // Articulo_Codigo … Tipo_Barcode
  14, 14, 14, 10,             // Precio_Costo … Peso
  14, 12, 12, 14,             // Reorder_Point … Cant_Default
  12, 30,                     // Activo, Notas
];
const METAL_WIDTHS_V2: number[] = [
  18, 16, 22, 28,            // Articulo_Codigo, Codigo_Variante, Metal_Padre, Metal_Variante
  12, 12, 14, 12,            // Gramos, Merma_Pct, Hechura_Metal, Es_Base
];
const STOCK_WIDTHS_V2: number[] = [
  18, 16, 26, 12, 12, 10,
];
const ATTRIBUTE_WIDTHS_V2: number[] = [
  18, 16, 26, 30,
];

// ── Filas de ejemplo ──────────────────────────────────────────────────────────
const EX_ART_V2 = [
  "Anillo de Oro 18K", "ART-001", "PRODUCT", "ACTIVE",
  "SKU-001", "", "CODE128", "Anillos", "", "",
  "Marca Propia", "", "Anillo de oro amarillo 18K",
  "15000", "25000", "500", "FIXED", "2.5", "METAL_MERMA_HECHURA",
  "BY_ARTICLE", "UND", "", "5", "", "", "1",
  "SI", "SI", "NO", "SI", "NO",
  "Artículo de ejemplo — eliminar antes de importar",
];
const EX_ART_SERVICE_V2 = [
  "Engaste de piedras", "SRV-001", "SERVICE", "ACTIVE",
  "", "", "CODE128", "Servicios", "", "",
  "", "", "Servicio de engaste manual",
  "0", "3500", "3500", "FIXED", "0", "MANUAL",
  "NO_STOCK", "UND", "", "", "", "", "",
  "NO", "SI", "NO", "NO", "NO",
  "Servicio de ejemplo — eliminar antes de importar",
];
const EX_VAR_V2 = ["ART-001", "VAR-001-T16", "Talle 16", "SKU-001-T16", "", "CODE128", "16000", "27000", "", "3.2", "", "", "", "", "SI", "Variante talle 16"];
const EX_VAR2_V2 = ["ART-001", "VAR-001-T18", "Talle 18", "SKU-001-T18", "", "CODE128", "16500", "27500", "", "3.8", "", "", "", "", "SI", "Variante talle 18"];
const EX_METAL_V2 = ["ART-001", "", "Oro", "Oro 18K Amarillo", "3.5", "2.5", "500", "SI"];
const EX_METAL2_V2 = ["ART-001", "VAR-001-T16", "Plata", "Plata 925", "2.0", "", "", "NO"];
const EX_STOCK_V2 = ["ART-001", "", "Almacén Principal", "5", "", "SET"];
const EX_STOCK2_V2 = ["ART-001", "VAR-001-T16", "Almacén Principal", "3", "", "SET"];
const EX_ATTR_V2 = ["ART-001", "", "Material", "Oro 18K"];
const EX_ATTR2_V2 = ["ART-001", "VAR-001-T16", "Color", "Amarillo"];

// ── Helpers privados ──────────────────────────────────────────────────────────

/** Crea una hoja con cabecera estilizada, fila fija y auto-filtro */
function setupDataSheet(
  wb: ExcelJS.Workbook,
  name: string,
  headers: string[],
  widths: number[]
): ExcelJS.Worksheet {
  const ws = wb.addWorksheet(name);
  ws.columns = headers.map((h, i) => ({ header: h, key: h, width: widths[i] ?? 14 }));
  const headerRow = ws.getRow(1);
  headerRow.height = 24;
  headerRow.eachCell((cell) => {
    cell.font = { bold: true, size: 10 };
    cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFD9D9D9" } };
    cell.alignment = { vertical: "middle", horizontal: "center", wrapText: false };
    cell.border = { bottom: { style: "thin", color: { argb: "FF999999" } } };
  });
  ws.views = [{ state: "frozen", xSplit: 0, ySplit: 1, topLeftCell: "A2" }];
  ws.autoFilter = { from: "A1", to: { row: 1, column: headers.length } };
  return ws;
}

/** Agrega validación tipo lista a una columna */
function addDv(ws: ExcelJS.Worksheet, colIndex: number, formula: string, maxRow = 2001): void {
  const colLetter = ws.getColumn(colIndex).letter;
  (ws as any).dataValidations.add(`${colLetter}2:${colLetter}${maxRow}`, {
    type: "list",
    allowBlank: true,
    formulae: [formula],
    showErrorMessage: true,
    errorTitle: "Valor inválido",
    error: "Seleccioná un valor de la lista.",
  });
}

/** Agrega fila de ejemplo con estilo gris/italic */
function addExampleRow(ws: ExcelJS.Worksheet, data: string[]): void {
  const row = ws.addRow(data);
  row.font = { italic: true, color: { argb: "FF888888" }, size: 9 };
}

/** Construye hoja Catálogos oculta (v2: 6 columnas) */
function buildCatalogsSheetV2(wb: ExcelJS.Workbook, catalog: TemplateCatalogDataV2): void {
  const cs = wb.addWorksheet("Catálogos", { state: "hidden" });
  cs.getCell("A1").value = "Categorias";
  cs.getCell("B1").value = "Grupos";
  cs.getCell("C1").value = "Proveedores";
  cs.getCell("D1").value = "Metales";
  cs.getCell("E1").value = "Variantes_Metal";
  cs.getCell("F1").value = "Almacenes";

  const maxR = Math.max(
    catalog.categories.length, catalog.groups.length, catalog.suppliers.length,
    catalog.metals.length, catalog.metalVariants.length, catalog.warehouses.length, 1
  );
  for (let i = 0; i < maxR; i++) {
    if (catalog.categories[i])    cs.getCell(`A${i + 2}`).value = catalog.categories[i];
    if (catalog.groups[i])        cs.getCell(`B${i + 2}`).value = catalog.groups[i];
    if (catalog.suppliers[i])     cs.getCell(`C${i + 2}`).value = catalog.suppliers[i];
    if (catalog.metals[i])        cs.getCell(`D${i + 2}`).value = catalog.metals[i];
    if (catalog.metalVariants[i]) cs.getCell(`E${i + 2}`).value = catalog.metalVariants[i];
    if (catalog.warehouses[i])    cs.getCell(`F${i + 2}`).value = catalog.warehouses[i];
  }
}

/** Construye hoja Instrucciones v2 */
function buildInstructionsSheetV2(wb: ExcelJS.Workbook): void {
  const ws = wb.addWorksheet("Instrucciones");
  ws.getColumn(1).width = 90;
  type Line = [string, boolean?];
  const lines: Line[] = [
    ["INSTRUCCIONES DE IMPORTACIÓN MASIVA v2 — TPTech (Joyería)", true],
    [""],
    ["FLUJO RECOMENDADO", true],
    ["  1. Completar hoja Artículos (datos base de cada pieza o servicio)"],
    ["  2. Completar hoja Variantes (talles, colores, etc.) — opcional"],
    ["  3. Completar hoja Metales (composición metálica) — solo artículos PRODUCT/MATERIAL"],
    ["  4. Completar hoja Stock (existencias por almacén) — opcional"],
    ["  5. Completar hoja Atributos (atributos de artículo o variante) — opcional"],
    ["  6. Importar el archivo completo en el sistema"],
    [""],
    ["DETECCIÓN DE FORMATO", true],
    ["  El sistema detecta v2 automáticamente si el archivo contiene las hojas"],
    ["  'Variantes', 'Metales', 'Stock' o 'Atributos'. Si solo existe 'Artículos'"],
    ["  se procesa como formato v1 (compatibilidad total con archivos anteriores)."],
    [""],
    ["HOJA: ARTÍCULOS", true],
    ["  Nombre:     OBLIGATORIO. Nombre comercial del artículo."],
    ["  Codigo:     Opcional. Si vacío se genera automáticamente (ART-0001...)"],
    ["  Tipo:       PRODUCT | SERVICE | MATERIAL"],
    ["  Estado:     DRAFT | ACTIVE | DISCONTINUED | ARCHIVED"],
    ["  Modo_Costo: MANUAL | METAL_MERMA_HECHURA | MULTIPLIER"],
    ["              Si el artículo tiene filas en hoja Metales el sistema lo pone"],
    ["              automáticamente en METAL_MERMA_HECHURA."],
    ["  Modo_Stock: NO_STOCK | BY_ARTICLE | BY_MATERIAL"],
    ["  REGLA: Tipo=SERVICE ignora stock y metales (se avisa al usuario)."],
    [""],
    ["HOJA: VARIANTES", true],
    ["  Articulo_Codigo: OBLIGATORIO. Código del artículo padre."],
    ["  Codigo:          Código único dentro del artículo."],
    ["  Nombre:          OBLIGATORIO."],
    ["  Los campos de precio son override del artículo padre (todos opcionales)."],
    ["  Peso:            weightOverride en gramos (opcional)."],
    [""],
    ["HOJA: METALES", true],
    ["  Articulo_Codigo:  OBLIGATORIO."],
    ["  Codigo_Variante:  Opcional. Si presente → la composición aplica a esa variante."],
    ["                    Si vacío → aplica al artículo globalmente."],
    ["  Metal_Padre:      OBLIGATORIO. Nombre del metal (ej: Oro)."],
    ["  Metal_Variante:   OBLIGATORIO. Variante del metal (ej: Oro 18K Amarillo)."],
    ["  Gramos:           OBLIGATORIO cuando hay fila en esta hoja."],
    ["  Merma_Pct:        Opcional. Override de porcentaje de merma por línea."],
    ["  Hechura_Metal:    Opcional. Costo de hechura específico de este metal."],
    ["  Es_Base:          SI/NO. Marca como metal base del artículo."],
    ["  REGLA: Tipo=SERVICE → las filas de ese artículo se ignoran con advertencia."],
    ["  REGLA: si hay al menos una fila de metal → Modo_Costo = METAL_MERMA_HECHURA."],
    [""],
    ["HOJA: STOCK", true],
    ["  Articulo_Codigo:  OBLIGATORIO."],
    ["  Codigo_Variante:  Opcional. Si vacío → stock a nivel artículo."],
    ["  Almacen:          OBLIGATORIO. Nombre exacto o 'código · nombre'."],
    ["  Cantidad:         OBLIGATORIO."],
    ["  Peso_Total:       Opcional. Solo informativo."],
    ["  Modo:             SET (sobreescribe) | ADD (suma al existente). Default: SET."],
    ["  REGLA: si Modo_Stock = BY_MATERIAL → se ignora la fila con advertencia."],
    [""],
    ["HOJA: ATRIBUTOS", true],
    ["  Articulo_Codigo:  OBLIGATORIO."],
    ["  Codigo_Variante:  Opcional. Si presente → atributo de variante."],
    ["  Atributo:         Nombre o código del atributo definido en la categoría."],
    ["  Valor:            Valor a asignar (texto libre, respetando tipo del atributo)."],
    [""],
    ["PROVEEDOR (columna Proveedor en hoja Artículos)", true],
    ["  Se acepta cualquiera de estas formas:"],
    ["    · Código exacto: CE-0001"],
    ["    · Nombre: Proveedor SA"],
    ["    · Formato completo: CE-0001 · Proveedor SA"],
    [""],
    ["LÍMITES DE CARGA", true],
    ["  Artículos:  máx 2.000 filas por importación."],
    ["  Variantes:  máx 5.000 filas."],
    ["  Metales:    máx 10.000 filas."],
    ["  Stock:      máx 5.000 filas."],
    ["  Atributos:  máx 10.000 filas."],
    ["  Tamaño del archivo: máx 10 MB."],
  ];
  lines.forEach(([text, bold], i) => {
    const cell = ws.getCell(`A${i + 1}`);
    cell.value = text;
    if (i === 0)       cell.font = { bold: true, size: 12 };
    else if (bold)     cell.font = { bold: true, size: 10 };
    else               cell.font = { size: 10 };
  });
}

// ─── Generar template v2 ──────────────────────────────────────────────────────
export async function generateImportTemplateV2(catalog: TemplateCatalogDataV2): Promise<Buffer> {
  const wb = new ExcelJS.Workbook();
  wb.creator = "TPTech";
  wb.created = new Date();

  // 1. Catálogos (oculta)
  buildCatalogsSheetV2(wb, catalog);

  // 2. Artículos
  const wsA = setupDataSheet(wb, "Artículos", ARTICLE_HEADERS_V2, ARTICLE_WIDTHS_V2);
  addDv(wsA, ACOL["Tipo"] + 1,                  '"PRODUCT,SERVICE,MATERIAL"');
  addDv(wsA, ACOL["Estado"] + 1,                '"DRAFT,ACTIVE,DISCONTINUED,ARCHIVED"');
  addDv(wsA, ACOL["Tipo_Barcode"] + 1,          '"CODE128,EAN13,QR"');
  addDv(wsA, ACOL["Hechura_Modo"] + 1,          '"FIXED,PER_GRAM"');
  addDv(wsA, ACOL["Modo_Costo"] + 1,            '"MANUAL,METAL_MERMA_HECHURA,MULTIPLIER"');
  addDv(wsA, ACOL["Modo_Stock"] + 1,            '"NO_STOCK,BY_ARTICLE,BY_MATERIAL"');
  addDv(wsA, ACOL["Favorito"] + 1,              '"SI,NO"');
  addDv(wsA, ACOL["Activo"] + 1,               '"SI,NO"');
  addDv(wsA, ACOL["En_Tienda"] + 1,             '"SI,NO"');
  addDv(wsA, ACOL["Acepta_Devolucion"] + 1,     '"SI,NO"');
  addDv(wsA, ACOL["Vender_Sin_Variantes"] + 1,  '"SI,NO"');
  if (catalog.categories.length > 0)
    addDv(wsA, ACOL["Categoria"] + 1, `'Catálogos'!$A$2:$A$${catalog.categories.length + 1}`);
  if (catalog.groups.length > 0)
    addDv(wsA, ACOL["Grupo"] + 1, `'Catálogos'!$B$2:$B$${catalog.groups.length + 1}`);
  if (catalog.suppliers.length > 0)
    addDv(wsA, ACOL["Proveedor"] + 1, `'Catálogos'!$C$2:$C$${catalog.suppliers.length + 1}`);
  addExampleRow(wsA, EX_ART_V2);
  addExampleRow(wsA, EX_ART_SERVICE_V2);

  // 3. Variantes
  const wsV = setupDataSheet(wb, "Variantes", VARIANT_HEADERS_V2, VARIANT_WIDTHS_V2);
  addDv(wsV, VCOL["Tipo_Barcode"] + 1, '"CODE128,EAN13,QR"');
  addDv(wsV, VCOL["Activo"] + 1,      '"SI,NO"');
  addExampleRow(wsV, EX_VAR_V2);
  addExampleRow(wsV, EX_VAR2_V2);

  // 4. Metales
  const wsM = setupDataSheet(wb, "Metales", METAL_HEADERS_V2, METAL_WIDTHS_V2);
  addDv(wsM, MCOL["Es_Base"] + 1, '"SI,NO"');
  if (catalog.metals.length > 0)
    addDv(wsM, MCOL["Metal_Padre"] + 1, `'Catálogos'!$D$2:$D$${catalog.metals.length + 1}`);
  if (catalog.metalVariants.length > 0)
    addDv(wsM, MCOL["Metal_Variante"] + 1, `'Catálogos'!$E$2:$E$${catalog.metalVariants.length + 1}`);
  addExampleRow(wsM, EX_METAL_V2);
  addExampleRow(wsM, EX_METAL2_V2);

  // 5. Stock
  const wsS = setupDataSheet(wb, "Stock", STOCK_HEADERS_V2, STOCK_WIDTHS_V2);
  addDv(wsS, SCOL["Modo"] + 1, '"SET,ADD"');
  if (catalog.warehouses.length > 0)
    addDv(wsS, SCOL["Almacen"] + 1, `'Catálogos'!$F$2:$F$${catalog.warehouses.length + 1}`);
  addExampleRow(wsS, EX_STOCK_V2);
  addExampleRow(wsS, EX_STOCK2_V2);

  // 6. Atributos
  const wsAt = setupDataSheet(wb, "Atributos", ATTRIBUTE_HEADERS_V2, ATTRIBUTE_WIDTHS_V2);
  addExampleRow(wsAt, EX_ATTR_V2);
  addExampleRow(wsAt, EX_ATTR2_V2);

  // 7. Instrucciones
  buildInstructionsSheetV2(wb);

  const buf = await wb.xlsx.writeBuffer();
  return Buffer.from(buf);
}

// ─── Plantilla Guiada ────────────────────────────────────────────────────────

export type GuidedTemplateCatalog = {
  categories:    string[];
  groups:        string[];
  suppliers:     string[];
  taxes:         string[];
  metals:        string[];
  metalVariants: string[];
  warehouses:    string[];
  currencies:    string[];
  attributeDefs: string[];   // nombres de atributos de la librería del tenant
  /** Atributos con opciones predefinidas (SELECT/MULTISELECT/COLOR).
   *  rangeName es un identificador válido para named range de Excel. */
  attributeOptions: { name: string; rangeName: string; options: string[] }[];
  /** Marcas y fabricantes distintos registrados en artículos del tenant. */
  brands:        string[];
  manufacturers: string[];
};

type GuidedSection = "ident" | "class" | "cost1" | "cost2" | "cost3" | "cost4" | "adj" | "tax" | "dim" | "stock" | "ref" | "flags" | "notes" | "attr";
type GuidedColDef  = { key: string; header: string; width: number; section: GuidedSection };

const GUIDED_SECTION_BG: Record<GuidedSection, string> = {
  ident:    "FF2563EB",  // blue-600
  class:    "FF9333EA",  // purple-600
  cost1:    "FFEA580C",  // orange-600  — bloque 1
  cost2:    "FFF97316",  // orange-500  — bloque 2
  cost3:    "FFFB923C",  // orange-400  — bloque 3
  cost4:    "FFFDBA74",  // orange-300  — bloque 4
  adj:      "FF92400E",  // amber-800   — ajuste global de costo
  tax:      "FF15803D",  // green-700
  dim:      "FF0F766E",  // teal-700   — dimensiones físicas
  stock:    "FF16A34A",  // green-600
  ref:      "FF64748B",  // slate-500  — columnas de referencia (NO se importan)
  flags:    "FF7C3AED",  // violet-600
  notes:    "FFD97706",  // amber-600
  attr:     "FF0891B2",  // cyan-600
};

const GUIDED_SECTION_FG: Record<GuidedSection, string> = {
  ident:    "FFFFFFFF",
  class:    "FFFFFFFF",
  cost1:    "FFFFFFFF",
  cost2:    "FFFFFFFF",
  cost3:    "FF1C1917",  // slate-950 — contraste sobre naranja claro (orange-400)
  cost4:    "FF1C1917",  // slate-950 — contraste sobre naranja muy claro (orange-300)
  adj:      "FFFFFFFF",
  tax:      "FFFFFFFF",
  dim:      "FFFFFFFF",  // texto blanco sobre teal-700
  stock:    "FFFFFFFF",
  ref:      "FFFFFFFF",
  flags:    "FFFFFFFF",
  notes:    "FFFFFFFF",
  attr:     "FFFFFFFF",
};

const GUIDED_COLS: GuidedColDef[] = [
  // ─ Identificación (azul) col A-C ─────────────────────────────────────────
  { key: "SKU_Padre",        header: "SKU Padre",             width: 18, section: "ident" },
  { key: "SKU",              header: "SKU",                   width: 18, section: "ident" },
  { key: "Nombre",           header: "Nombre",                width: 34, section: "ident" },
  // ─ Clasificación (violeta) col D-K ───────────────────────────────────────
  { key: "Descripcion",      header: "Descripción",           width: 38, section: "class" },
  { key: "Estado",           header: "Estado",                width: 18, section: "class" },
  { key: "Categoria",        header: "Categoría",             width: 24, section: "class" },
  { key: "Grupo",            header: "Grupo",                 width: 20, section: "class" },
  { key: "Proveedor",        header: "Proveedor",             width: 28, section: "class" },
  { key: "Codigo_Proveedor", header: "Código Proveedor",      width: 20, section: "class" },
  { key: "Marca",            header: "Marca",                 width: 18, section: "class" },
  { key: "Fabricante",       header: "Fabricante",            width: 18, section: "class" },
  // ─ Stock actual (referencia visual, no importable) — col L ───────────────
  { key: "Stock_Ref",        header: "Stock actual (ref.)",   width: 22, section: "ref"   },
  // ─ Atributos de variante (celeste) col M-T ───────────────────────────────
  { key: "Attr1_Nombre",     header: "Nombre atributo 1",     width: 20, section: "attr"  },
  { key: "Attr1_Valor",      header: "Valor atributo 1",      width: 18, section: "attr"  },
  { key: "Attr2_Nombre",     header: "Nombre atributo 2",     width: 20, section: "attr"  },
  { key: "Attr2_Valor",      header: "Valor atributo 2",      width: 18, section: "attr"  },
  { key: "Attr3_Nombre",     header: "Nombre atributo 3",     width: 20, section: "attr"  },
  { key: "Attr3_Valor",      header: "Valor atributo 3",      width: 18, section: "attr"  },
  { key: "Attr4_Nombre",     header: "Nombre atributo 4",     width: 20, section: "attr"  },
  { key: "Attr4_Valor",      header: "Valor atributo 4",      width: 18, section: "attr"  },
  // ─ Composición de costo — bloque 1 (naranja-600) ──────────────────────────
  { key: "Moneda_1",         header: "Moneda 1",              width: 16, section: "cost1" },
  { key: "Tipo_1",           header: "Tipo 1",                width: 14, section: "cost1" },
  { key: "Desc_1",           header: "Descripción 1",         width: 26, section: "cost1" },
  { key: "Cantidad_1",       header: "Cantidad 1",            width: 12, section: "cost1" },
  { key: "P_Unit_1",         header: "Precio Unit. 1",        width: 16, section: "cost1" },
  { key: "Merma_1",          header: "Merma % 1",             width: 12, section: "cost1" },
  { key: "BonifRec_1",       header: "Bonif/Recargo 1",       width: 16, section: "cost1" },
  // ─ Composición de costo — bloque 2 (naranja-500) ──────────────────────────
  { key: "Moneda_2",         header: "Moneda 2",              width: 16, section: "cost2" },
  { key: "Tipo_2",           header: "Tipo 2",                width: 14, section: "cost2" },
  { key: "Desc_2",           header: "Descripción 2",         width: 26, section: "cost2" },
  { key: "Cantidad_2",       header: "Cantidad 2",            width: 12, section: "cost2" },
  { key: "P_Unit_2",         header: "Precio Unit. 2",        width: 16, section: "cost2" },
  { key: "Merma_2",          header: "Merma % 2",             width: 12, section: "cost2" },
  { key: "BonifRec_2",       header: "Bonif/Recargo 2",       width: 16, section: "cost2" },
  // ─ Composición de costo — bloque 3 (naranja-400) ──────────────────────────
  { key: "Moneda_3",         header: "Moneda 3",              width: 16, section: "cost3" },
  { key: "Tipo_3",           header: "Tipo 3",                width: 14, section: "cost3" },
  { key: "Desc_3",           header: "Descripción 3",         width: 26, section: "cost3" },
  { key: "Cantidad_3",       header: "Cantidad 3",            width: 12, section: "cost3" },
  { key: "P_Unit_3",         header: "Precio Unit. 3",        width: 16, section: "cost3" },
  { key: "Merma_3",          header: "Merma % 3",             width: 12, section: "cost3" },
  { key: "BonifRec_3",       header: "Bonif/Recargo 3",       width: 16, section: "cost3" },
  // ─ Composición de costo — bloque 4 (naranja-300) ──────────────────────────
  { key: "Moneda_4",         header: "Moneda 4",              width: 16, section: "cost4" },
  { key: "Tipo_4",           header: "Tipo 4",                width: 14, section: "cost4" },
  { key: "Desc_4",           header: "Descripción 4",         width: 26, section: "cost4" },
  { key: "Cantidad_4",       header: "Cantidad 4",            width: 12, section: "cost4" },
  { key: "P_Unit_4",         header: "Precio Unit. 4",        width: 16, section: "cost4" },
  { key: "Merma_4",          header: "Merma % 4",             width: 12, section: "cost4" },
  { key: "BonifRec_4",       header: "Bonif/Recargo 4",       width: 16, section: "cost4" },
  // ─ Ajuste global de costo (amber-800) ────────────────────────────────────
  { key: "Ajuste_Tipo",      header: "Ajuste tipo",           width: 18, section: "adj"  },
  { key: "Ajuste_Valor",     header: "Ajuste valor",          width: 16, section: "adj"  },
  { key: "Ajuste_Modo",      header: "Ajuste modo",           width: 16, section: "adj"  },
  // ─ Impuestos (verde oscuro) ───────────────────────────────────────────────
  { key: "IVA_1",            header: "IVA 1",                 width: 22, section: "tax"  },
  { key: "IVA_2",            header: "IVA 2",                 width: 22, section: "tax"  },
  { key: "IVA_3",            header: "IVA 3",                 width: 22, section: "tax"  },
  // ─ Dimensiones físicas (teal-700) — después de impuestos ─────────────────
  { key: "Dim_Largo",        header: "Largo",                 width: 12, section: "dim"  },
  { key: "Dim_Ancho",        header: "Ancho",                 width: 12, section: "dim"  },
  { key: "Dim_Alto",         header: "Alto",                  width: 12, section: "dim"  },
  { key: "Dim_Unidad",       header: "Unidad dim.",           width: 13, section: "dim"  },
  // ─ Stock (verde) ─────────────────────────────────────────────────────────
  { key: "Modo_Stock",       header: "Modo de stock",         width: 18, section: "stock" },
  { key: "Unidad",           header: "Unidad",                width: 12, section: "stock" },
  { key: "Peso",             header: "Peso (g)",              width: 10, section: "stock" },
  { key: "Pto_Repos",        header: "Pto. Reposición",       width: 16, section: "stock" },
  { key: "Cant_Min",         header: "Cant. mínima",          width: 14, section: "stock" },
  { key: "Cant_Max",         header: "Cant. máxima",          width: 14, section: "stock" },
  { key: "Cant_Default",     header: "Cant. por defecto",     width: 18, section: "stock" },
  // ─ Opciones / variante (violet) ──────────────────────────────────────────
  { key: "Favorito",         header: "Favorito",              width: 12, section: "flags" },
  { key: "Activo",           header: "Activo",                width: 12, section: "flags" },
  { key: "En_Tienda",        header: "En tienda",             width: 12, section: "flags" },
  { key: "Acepta_Dev",       header: "Acepta devolución",     width: 18, section: "flags" },
  { key: "Sin_Variantes",    header: "Vender sin variantes",  width: 20, section: "flags" },
  // ─ Origen de costo (gris — referencia visual, NO se importa) ─────────────
  { key: "Origen_Costo",       header: "Origen costo",      width: 22, section: "ref"      },
  // ─ Notas (amarillo) ──────────────────────────────────────────────────────
  { key: "Notas",            header: "Notas",                 width: 34, section: "notes" },
];

const GUIDED_COL_IDX = Object.fromEntries(GUIDED_COLS.map((c, i) => [c.key, i]));

// Mapas de traducción DB → Excel
const STATUS_LABEL: Record<string, string> = {
  DRAFT: "Borrador", ACTIVE: "Activo", DISCONTINUED: "Descontinuado", ARCHIVED: "Archivado",
};
const STOCK_MODE_LABEL: Record<string, string> = {
  NO_STOCK: "Sin stock", BY_ARTICLE: "Por artículo", BY_MATERIAL: "Por material",
};
const COST_TYPE_LABEL: Record<string, string> = {
  METAL: "Metal", HECHURA: "Hechura", PRODUCT: "Producto", SERVICE: "Servicio", MANUAL: "Manual",
};
// Mapas de decodificación Excel label → DB enum para ajuste global de costo.
// Usados en applyGuidedInheritedFields y en el bloque de artículo simple de executeImportGuided.
const GUIDED_ADJ_TIPO_MAP: Record<string, string> = {
  "bonificación": "BONUS", "bonificacion": "BONUS", "bonus": "BONUS",
  "recargo": "SURCHARGE", "surcharge": "SURCHARGE",
};
const GUIDED_ADJ_MODO_MAP: Record<string, string> = {
  "porcentaje": "PERCENTAGE", "percentage": "PERCENTAGE",
  "monto fijo": "FIXED_AMOUNT", "fixed_amount": "FIXED_AMOUNT",
};

// Codifica ajuste bonificación/recargo → "-10%" (BONUS) | "+500" (SURCHARGE) | ""
// BONUS = bonificación = descuento = signo negativo
// SURCHARGE = recargo = cargo extra = signo positivo
function xfmtAdj(kind: string | null, adjType: string | null, val: any): string {
  if (!kind || !adjType || val == null) return "";
  const sign = kind === "SURCHARGE" ? "+" : "-";
  const suffix = adjType === "PERCENTAGE" ? "%" : "";
  return `${sign}${Number(val)}${suffix}`;
}

/** Fila de artículo o variante para el workbook de exportación guiada */
export type GuidedExportRow = {
  skuPadre:        string;
  sku:             string;
  nombre:          string;
  descripcion:     string;
  estado:          string;
  categoria:       string;
  grupo:           string;
  proveedor:       string;
  codigoProveedor: string;
  marca:           string;
  fabricante:      string;
  // bloques de costo 1/2/3
  cost1_moneda:    string;
  cost1_tipo:      string;
  cost1_desc:      string;
  cost1_qty:       string;
  cost1_unitValue: string;
  cost1_merma:     string;
  cost1_bonif:     string;
  cost2_moneda:    string;
  cost2_tipo:      string;
  cost2_desc:      string;
  cost2_qty:       string;
  cost2_unitValue: string;
  cost2_merma:     string;
  cost2_bonif:     string;
  cost3_moneda:    string;
  cost3_tipo:      string;
  cost3_desc:      string;
  cost3_qty:       string;
  cost3_unitValue: string;
  cost3_merma:     string;
  cost3_bonif:     string;
  cost4_moneda:    string;
  cost4_tipo:      string;
  cost4_desc:      string;
  cost4_qty:       string;
  cost4_unitValue: string;
  cost4_merma:     string;
  cost4_bonif:     string;
  // Ajuste global de costo (mapea a Article.manualAdjustmentKind/Type/Value)
  adjTipo:         string;  // "Bonificación" | "Recargo" | ""
  adjValor:        string;
  adjModo:         string;  // "Porcentaje" | "Monto fijo" | ""
  iva1:            string;
  iva2:            string;
  iva3:            string;
  // Dimensiones físicas (padre; variante hereda)
  dimLargo:        string;
  dimAncho:        string;
  dimAlto:         string;
  dimUnidad:       string;
  modoStock:       string;
  unidad:          string;
  peso:            string;
  ptoReposicion:   string;
  cantMin:         string;
  cantMax:         string;
  cantDefault:     string;
  /** Stock actual sumado de todos los almacenes. Solo referencia visual — NO se importa. */
  stockRef:        string;
  favorito:        string;
  activo:          string;
  enTienda:        string;
  aceptaDev:       string;
  sinVariantes:    string;
  /** Informativo (NO se importa): "Propio" | "Hereda del padre" | "" */
  origenCosto:     string;
  notas:           string;
  attr1nombre:     string;
  attr1valor:      string;
  attr2nombre:     string;
  attr2valor:      string;
  attr3nombre:     string;
  attr3valor:      string;
  attr4nombre:     string;
  attr4valor:      string;
};

/**
 * Construye el workbook oficial unificado (3 hojas: Artículos, Listas, Instrucciones).
 * - Sin exportRows → modo plantilla (fila de ejemplo, celdas vacías para completar)
 * - Con exportRows → modo exportación (filas reales del sistema)
 * La hoja "Listas" provee dropdowns dinámicos y catálogos de referencia.
 */
/** @internal — exportado solo para tests unitarios */
export async function buildGuidedWorkbook(
  catalog: GuidedTemplateCatalog,
  exportRows?: GuidedExportRow[],
): Promise<ExcelJS.Workbook> {
  const isExport = Array.isArray(exportRows) && exportRows.length > 0;
  const wb = new ExcelJS.Workbook();
  wb.creator = "TPTech";
  wb.created = new Date();

  // ── 1. Hoja Artículos (principal, primera hoja = tab activo) ──────────────
  const ws = wb.addWorksheet("Artículos");
  ws.columns = GUIDED_COLS.map(c => ({ header: c.header, key: c.key, width: c.width }));

  // Cabecera con colores por sección
  const headerRow = ws.getRow(1);
  headerRow.height = 40;
  GUIDED_COLS.forEach((colDef, idx) => {
    const cell = headerRow.getCell(idx + 1);
    cell.font      = { bold: true, size: 9, color: { argb: GUIDED_SECTION_FG[colDef.section] } };
    cell.fill      = { type: "pattern", pattern: "solid", fgColor: { argb: GUIDED_SECTION_BG[colDef.section] } };
    cell.alignment = { vertical: "middle", horizontal: "center", wrapText: false };
    cell.border    = { bottom: { style: "medium", color: { argb: "FF111827" } } };
  });

  ws.views = [{ state: "frozen", xSplit: 0, ySplit: 1, topLeftCell: "A2" }];
  ws.autoFilter = { from: "A1", to: { row: 1, column: GUIDED_COLS.length } };

  if (isExport) {
    // Modo exportación — filas reales del sistema
    // ARGB azul-50 muy tenue: distingue visualmente variantes de artículos simples
    // sin afectar valores, filtros, dropdowns ni importación.
    const VARIANT_ROW_FILL: ExcelJS.Fill = {
      type: "pattern", pattern: "solid", fgColor: { argb: "FFF0F9FF" },
    };

    for (const row of exportRows!) {
      const colMap: Record<string, string> = {
        SKU_Padre:        row.skuPadre,
        SKU:              row.sku,
        Nombre:           row.nombre,
        Descripcion:      row.descripcion,
        Estado:           row.estado,
        Categoria:        row.categoria,
        Grupo:            row.grupo,
        Proveedor:        row.proveedor,
        Codigo_Proveedor: row.codigoProveedor,
        Marca:            row.marca,
        Fabricante:       row.fabricante,
        Moneda_1:      row.cost1_moneda,
        Tipo_1:        row.cost1_tipo,
        Desc_1:        row.cost1_desc,
        Cantidad_1:    row.cost1_qty,
        P_Unit_1:      row.cost1_unitValue,
        Merma_1:       row.cost1_merma,
        BonifRec_1:    row.cost1_bonif,
        Moneda_2:      row.cost2_moneda,
        Tipo_2:        row.cost2_tipo,
        Desc_2:        row.cost2_desc,
        Cantidad_2:    row.cost2_qty,
        P_Unit_2:      row.cost2_unitValue,
        Merma_2:       row.cost2_merma,
        BonifRec_2:    row.cost2_bonif,
        Moneda_3:      row.cost3_moneda,
        Tipo_3:        row.cost3_tipo,
        Desc_3:        row.cost3_desc,
        Cantidad_3:    row.cost3_qty,
        P_Unit_3:      row.cost3_unitValue,
        Merma_3:       row.cost3_merma,
        BonifRec_3:    row.cost3_bonif,
        Moneda_4:      row.cost4_moneda,
        Tipo_4:        row.cost4_tipo,
        Desc_4:        row.cost4_desc,
        Cantidad_4:    row.cost4_qty,
        P_Unit_4:      row.cost4_unitValue,
        Merma_4:       row.cost4_merma,
        BonifRec_4:    row.cost4_bonif,
        Ajuste_Tipo:   row.adjTipo,
        Ajuste_Valor:  row.adjValor,
        Ajuste_Modo:   row.adjModo,
        IVA_1:         row.iva1,
        IVA_2:         row.iva2,
        IVA_3:         row.iva3,
        Dim_Largo:     row.dimLargo,
        Dim_Ancho:     row.dimAncho,
        Dim_Alto:      row.dimAlto,
        Dim_Unidad:    row.dimUnidad,
        Modo_Stock:    row.modoStock,
        Unidad:        row.unidad,
        Peso:          row.peso,
        Pto_Repos:     row.ptoReposicion,
        Cant_Min:      row.cantMin,
        Cant_Max:      row.cantMax,
        Cant_Default:  row.cantDefault,
        Stock_Ref:     row.stockRef,
        Favorito:      row.favorito,
        Activo:        row.activo,
        En_Tienda:     row.enTienda,
        Acepta_Dev:    row.aceptaDev,
        Sin_Variantes:    row.sinVariantes,
        Origen_Costo:  row.origenCosto,
        Notas:         row.notas,
        Attr1_Nombre:  row.attr1nombre,
        Attr1_Valor:   row.attr1valor,
        Attr2_Nombre:  row.attr2nombre,
        Attr2_Valor:   row.attr2valor,
        Attr3_Nombre:  row.attr3nombre,
        Attr3_Valor:   row.attr3valor,
        Attr4_Nombre:  row.attr4nombre,
        Attr4_Valor:   row.attr4valor,
      };
      const addedRow = ws.addRow(GUIDED_COLS.map(c => colMap[c.key] ?? ""));

      // Fondo tenue en filas de variante: agrupación visual sin merge ni sangría
      if (row.skuPadre !== "") {
        addedRow.eachCell({ includeEmpty: true }, cell => { cell.fill = VARIANT_ROW_FILL; });
      }
    }
  } else {
    // Modo plantilla — fila de ejemplo (gris, itálica)
    const exValues: Record<string, string> = {
      SKU_Padre: "",
      SKU: "SKU-001",
      Nombre: "Anillo de Oro 18K",
      Descripcion: "Anillo de oro amarillo 18K",
      Estado: "Activo",
      Categoria:        catalog.categories[0] ?? "Anillos",
      Grupo:            catalog.groups[0] ?? "",
      Proveedor:        catalog.suppliers[0] ?? "",
      Codigo_Proveedor: "",
      Marca:            catalog.brands[0] ?? "",
      Fabricante:       catalog.manufacturers[0] ?? "",
      Moneda_1:   catalog.currencies[0] ?? "",
      Tipo_1:     "Metal",
      Desc_1:     catalog.metalVariants[0] ?? "Oro 18K Amarillo",
      Cantidad_1: "3.5",
      P_Unit_1:   "",
      Merma_1:    "2.5",
      BonifRec_1: "",
      Moneda_2:   catalog.currencies[0] ?? "",
      Tipo_2:     "Hechura",
      Desc_2:     "Precio / Hechura",
      Cantidad_2: "1",
      P_Unit_2:   "500",
      Merma_2:    "",
      BonifRec_2: "",
      Moneda_3: "", Tipo_3: "", Desc_3: "", Cantidad_3: "", P_Unit_3: "", Merma_3: "", BonifRec_3: "",
      Moneda_4: "", Tipo_4: "", Desc_4: "", Cantidad_4: "", P_Unit_4: "", Merma_4: "", BonifRec_4: "",
      Ajuste_Tipo: "", Ajuste_Valor: "", Ajuste_Modo: "",
      IVA_1: catalog.taxes[0] ?? "",
      IVA_2: catalog.taxes[1] ?? "",
      IVA_3: "",
      Dim_Largo: "", Dim_Ancho: "", Dim_Alto: "", Dim_Unidad: "cm",
      Modo_Stock: "Por artículo",
      Unidad: "UND",
      Peso: "3",
      Pto_Repos: "5",
      Cant_Min: "", Cant_Max: "", Cant_Default: "1",
      Stock_Ref: "",  // referencia — vacío en plantilla
      Favorito: "SI", Activo: "SI", En_Tienda: "SI", Acepta_Dev: "SI", Sin_Variantes: "NO",
      Origen_Costo: "",
      Notas: "Ejemplo — completá tus datos a partir de la fila 3",
      Attr1_Nombre: "", Attr1_Valor: "",
      Attr2_Nombre: "", Attr2_Valor: "",
      Attr3_Nombre: "", Attr3_Valor: "",
      Attr4_Nombre: "", Attr4_Valor: "",
    };
    const exRow = ws.addRow(GUIDED_COLS.map(c => exValues[c.key] ?? ""));
    exRow.font = { italic: true, color: { argb: "FF6B7280" }, size: 9 };
  }

  // ── Validaciones de datos (dropdowns desde 'Listas') ──────────────────────
  // NOTA: la hoja 'Listas' se crea después, pero Excel resuelve las referencias
  // por nombre al abrir — el orden de creación en ExcelJS no importa.
  const DATA_ROWS = 2001;
  const wsAny = ws as any;
  /**
   * Agrega data validation tipo lista para una columna.
   * @param strict true (por defecto) = bloquea valores fuera de la lista.
   *               false = sugerencia/autocomplete sin bloqueo (para Marca, Fabricante, Desc).
   */
  function addDv(colKey: string, formula: string, strict = true) {
    const idx = GUIDED_COL_IDX[colKey];
    if (idx == null) return;
    const letter = ws.getColumn(idx + 1).letter;
    const dvDef: any = { type: "list", allowBlank: true, formulae: [formula], showErrorMessage: strict };
    if (strict) { dvDef.errorTitle = "Valor inválido"; dvDef.error = "Seleccioná un valor de la lista."; }
    wsAny.dataValidations.add(`${letter}2:${letter}${DATA_ROWS}`, dvDef);
  }

  // Enumerados SI/NO
  for (const key of ["Favorito", "Activo", "En_Tienda", "Acepta_Dev", "Sin_Variantes"]) {
    addDv(key, '"SI,NO"');
  }

  // Estado y Modo_Stock → columnas G y H de 'Listas' (valores traducidos)
  addDv("Estado",     "'Listas'!$G$2:$G$5");   // 4 valores: Borrador/Activo/Descontinuado/Archivado
  addDv("Modo_Stock", "'Listas'!$H$2:$H$4");   // 3 valores: Sin stock/Por artículo/Por material

  // Tipo de costo → columna F de 'Listas' (solo Metal y Hechura)
  for (const key of ["Tipo_1", "Tipo_2", "Tipo_3", "Tipo_4"]) {
    addDv(key, "'Listas'!$F$2:$F$3");           // 2 valores: Metal / Hechura
  }
  // Ajuste tipo y modo → listas inline
  addDv("Ajuste_Tipo", '"Bonificación,Recargo"');
  addDv("Ajuste_Modo", '"Porcentaje,Monto fijo"');
  // Unidad de medida de artículo → sugerencia sin bloqueo
  addDv("Unidad", '"UND,PAR,JGO,KG,GR,MT,CM,LT,ML,OZ"', false);
  // Unidad de dimensiones → inline
  addDv("Dim_Unidad", '"cm,mm,m,in"');

  // Catálogos dinámicos
  if (catalog.categories.length > 0)
    addDv("Categoria", `'Listas'!$A$2:$A$${catalog.categories.length + 1}`);
  if (catalog.groups.length > 0)
    addDv("Grupo",     `'Listas'!$B$2:$B$${catalog.groups.length + 1}`);
  if (catalog.suppliers.length > 0)
    addDv("Proveedor", `'Listas'!$C$2:$C$${catalog.suppliers.length + 1}`);
  // Marca y Fabricante: sugerencia desde Listas col L y M (no bloquea si escribe distinto)
  if (catalog.brands.length > 0)
    addDv("Marca",       `'Listas'!$L$2:$L$${catalog.brands.length + 1}`,        false);
  if (catalog.manufacturers.length > 0)
    addDv("Fabricante",  `'Listas'!$M$2:$M$${catalog.manufacturers.length + 1}`, false);
  // Desc_1/2/3/4: sugerencia con variantes de metal (col J). No bloquea texto libre.
  if (catalog.metalVariants.length > 0) {
    const mvFml = `'Listas'!$J$2:$J$${catalog.metalVariants.length + 1}`;
    addDv("Desc_1", mvFml, false);
    addDv("Desc_2", mvFml, false);
    addDv("Desc_3", mvFml, false);
    addDv("Desc_4", mvFml, false);
  }
  if (catalog.taxes.length > 0) {
    const taxFml = `'Listas'!$D$2:$D$${catalog.taxes.length + 1}`;
    addDv("IVA_1", taxFml);
    addDv("IVA_2", taxFml);
    addDv("IVA_3", taxFml);
  }
  if (catalog.currencies.length > 0) {
    const curFml = `'Listas'!$E$2:$E$${catalog.currencies.length + 1}`;
    addDv("Moneda_1", curFml);
    addDv("Moneda_2", curFml);
    addDv("Moneda_3", curFml);
    addDv("Moneda_4", curFml);
  }

  // Dropdowns para Nombre atributo 1..4 → columna K de 'Listas'
  if (catalog.attributeDefs.length > 0) {
    const attrFml = `'Listas'!$K$2:$K$${catalog.attributeDefs.length + 1}`;
    addDv("Attr1_Nombre", attrFml);
    addDv("Attr2_Nombre", attrFml);
    addDv("Attr3_Nombre", attrFml);
    addDv("Attr4_Nombre", attrFml);
  }

  // Dropdowns para Valor atributo 1..4 → INDIRECT resuelve el named range del atributo elegido.
  // Comportamiento:
  //   · Si el atributo tiene opciones → el usuario ve un combo con esas opciones.
  //   · Si el atributo no tiene opciones (texto libre) → INDIRECT falla silenciosamente
  //     y la celda acepta cualquier texto sin restricción.
  // showErrorMessage: false → no bloquea valores fuera de la lista (permite edición libre).
  if (catalog.attributeOptions.length > 0) {
    const pairs: [string, string][] = [
      ["Attr1_Nombre", "Attr1_Valor"],
      ["Attr2_Nombre", "Attr2_Valor"],
      ["Attr3_Nombre", "Attr3_Valor"],
      ["Attr4_Nombre", "Attr4_Valor"],
    ];
    for (const [nombreKey, valorKey] of pairs) {
      const nombreIdx = GUIDED_COL_IDX[nombreKey];
      const valorIdx  = GUIDED_COL_IDX[valorKey];
      if (nombreIdx == null || valorIdx == null) continue;
      const nombreLetter = ws.getColumn(nombreIdx + 1).letter;
      const valorLetter  = ws.getColumn(valorIdx  + 1).letter;
      wsAny.dataValidations.add(`${valorLetter}2:${valorLetter}${DATA_ROWS}`, {
        type: "list", allowBlank: true,
        formulae: [`INDIRECT(SUBSTITUTE(${nombreLetter}2," ","_"))`],
        showErrorMessage: false,
      });
    }
  }

  // ── 2. Hoja Listas ────────────────────────────────────────────────────────
  // 13 columnas: A=Categorías B=Grupos C=Proveedores D=Impuestos/IVA E=Monedas
  //              F=Tipo costo G=Estado H=Modo stock I=Metales J=Variantes Metal
  //              K=Atributos  L=Marcas  M=Fabricantes
  //              N onwards = opciones de atributos (ocultas)
  const listSheet = wb.addWorksheet("Listas");
  const LIST_COLS  = ["Categorías", "Grupos", "Proveedores", "Impuestos / IVA", "Monedas",
                      "Tipo de costo", "Estado", "Modo de stock", "Metales", "Variantes de Metal",
                      "Atributos", "Marcas", "Fabricantes"];
  const LIST_BG    = ["FF2563EB", "FF9333EA", "FF9333EA", "FF15803D", "FF0891B2",
                      "FFEA580C", "FF9333EA", "FF16A34A", "FFEA580C", "FFEA580C",
                      "FF0891B2", "FF9333EA", "FF9333EA"];
  const LIST_WIDTHS = [26, 22, 32, 26, 22, 18, 18, 20, 22, 30, 24, 20, 20];

  LIST_COLS.forEach((h, i) => {
    listSheet.getColumn(i + 1).width = LIST_WIDTHS[i];
    const cell = listSheet.getCell(1, i + 1);
    cell.value     = h;
    cell.font      = { bold: true, size: 10, color: { argb: "FFFFFFFF" } };
    cell.fill      = { type: "pattern", pattern: "solid", fgColor: { argb: LIST_BG[i] } };
    cell.alignment = { vertical: "middle", horizontal: "center" };
    cell.border    = { bottom: { style: "medium", color: { argb: "FF111827" } } };
  });
  listSheet.getRow(1).height = 22;
  listSheet.views = [{ state: "frozen", xSplit: 0, ySplit: 1, topLeftCell: "A2" }];

  // Valores estáticos para columnas F (Tipo costo), G (Estado), H (Modo stock)
  // Solo Metal y Hechura: los otros tipos (Producto, Servicio, Manual) se
  // gestionan desde la ficha del artículo, no desde la importación masiva.
  const COST_TYPE_VALS = ["Metal", "Hechura"];
  const STATUS_VALS    = ["Borrador", "Activo", "Descontinuado", "Archivado"];
  const STOCK_MODE_VALS = ["Sin stock", "Por artículo", "Por material"];

  // Combina dinámicos + estáticos en el orden de columnas
  const listData: string[][] = [
    catalog.categories,    // A
    catalog.groups,        // B
    catalog.suppliers,     // C
    catalog.taxes,         // D
    catalog.currencies,    // E
    COST_TYPE_VALS,        // F
    STATUS_VALS,           // G
    STOCK_MODE_VALS,       // H
    catalog.metals,        // I
    catalog.metalVariants, // J
    catalog.attributeDefs, // K
    catalog.brands,        // L
    catalog.manufacturers, // M
  ];
  const listMax = Math.max(...listData.map(a => a.length), 0);
  for (let i = 0; i < listMax; i++) {
    const r = listSheet.getRow(i + 2);
    listData.forEach((arr, colIdx) => { r.getCell(colIdx + 1).value = arr[i] ?? ""; });
    if (i % 2 === 0) {
      r.eachCell({ includeEmpty: true }, (cell, cn) => {
        if (cn <= LIST_COLS.length)
          cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFF9FAFB" } };
      });
    }
  }

  // ── Columnas de opciones por atributo (N, O, P…) — ocultas ────────────────
  // Cada atributo con opciones (SELECT/MULTISELECT/COLOR) obtiene su propia columna
  // en la hoja Listas y un named range en el workbook, lo que permite que los
  // dropdowns de Valor_Atributo_1..4 usen INDIRECT para resolverlos dinámicamente.
  // A=1..K=11, L=12 (Marcas), M=13 (Fabricantes) → opciones desde N=14 en adelante.
  if (catalog.attributeOptions.length > 0) {
    catalog.attributeOptions.forEach((attr, idx) => {
      const colNum    = 14 + idx;   // N=14, O=15, P=16, …
      const colLetter = listSheet.getColumn(colNum).letter;

      // Header de la columna (visible solo si el usuario muestra columnas ocultas)
      const hCell = listSheet.getCell(1, colNum);
      hCell.value     = `Opc · ${attr.name}`;
      hCell.font      = { bold: true, size: 9, color: { argb: "FFFFFFFF" } };
      hCell.fill      = { type: "pattern", pattern: "solid", fgColor: { argb: "FF0891B2" } };
      hCell.alignment = { vertical: "middle", horizontal: "center" };
      hCell.border    = { bottom: { style: "medium", color: { argb: "FF111827" } } };

      // Valores de opciones
      attr.options.forEach((opt, i) => {
        listSheet.getCell(i + 2, colNum).value = opt;
      });

      // Columna oculta (no distrae al usuario)
      listSheet.getColumn(colNum).hidden = true;
      listSheet.getColumn(colNum).width  = 20;

      // Named range: rangeName → 'Listas'!$L$2:$L$N
      const endRow = 1 + attr.options.length;
      wb.definedNames.add(
        `'Listas'!$${colLetter}$2:$${colLetter}$${endRow}`,
        attr.rangeName,
      );
    });
  }

  // ── 3. Hoja Instrucciones ─────────────────────────────────────────────────
  const instr = wb.addWorksheet("Instrucciones");
  instr.getColumn(1).width = 100;
  const instrLines: [string, "title" | "section" | "body"][] = [
    ["PLANTILLA GUIADA — ARTÍCULOS — TPTech", "title"],
    ["", "body"],
    ["REGLA CLAVE: ARTÍCULO PADRE vs. VARIANTE", "section"],
    ["  Las filas de esta plantilla son de dos tipos según si 'SKU Padre' está vacío o tiene valor:", "body"],
    ["", "body"],
    ["  ARTÍCULO PADRE (SKU Padre vacío):", "body"],
    ["    · Define el artículo con todos sus datos: nombre, categoría, impuestos, dimensiones, stock.", "body"],
    ["    · Puede tener composición de costo completa en las columnas naranja:", "body"],
    ["      Metal/Hechura, Moneda, Cantidad, Merma %, Bonif/Recargo, Ajuste global.", "body"],
    ["", "body"],
    ["  VARIANTE (SKU Padre con valor):", "body"],
    ["    · Puede tener su propia composición de costo (columnas naranja) — composición completa o vacía.", "body"],
    ["    · Si los bloques naranja están vacíos → la variante HEREDA la composición del artículo padre.", "body"],
    ["    · Si los bloques naranja tienen datos → son la composición PROPIA de esa variante.", "body"],
    ["    · Peso (g): override del peso del padre.", "body"],
    ["    · También puede tener: stock, cantidades, notas, atributos (Color, Talle, etc.).", "body"],
    ["    · Regla de composición: completa o vacía — NO composiciones parciales.", "body"],
    ["", "body"],
    ["ESTRUCTURA DE COLUMNAS (orden de izquierda a derecha)", "section"],
    ["  Azul          →  Identificación: SKU Padre, SKU, Nombre", "body"],
    ["  Violeta       →  Clasificación: Descripción, Estado, Categoría, Grupo, Proveedor, Marca, Fabricante", "body"],
    ["  Gris          →  Stock actual / Origen costo (referencia — NO se importan, son informativos)", "body"],
    ["  Celeste       →  Atributos de variante (Nombre atrib. N / Valor atrib. N, hasta 4 pares)", "body"],
    ["  Naranja       →  Composición de costo (4 bloques × 7 campos) — padre y variante", "body"],
    ["  Marrón        →  Ajuste global de costo: tipo, valor, modo — solo artículo padre", "body"],
    ["  Verde oscuro  →  Impuestos: IVA 1, IVA 2, IVA 3", "body"],
    ["  Verde azulado →  Dimensiones: Largo, Ancho, Alto, Unidad dim.", "body"],
    ["  Verde         →  Stock: Modo de stock, Unidad, Peso (g), Pto. Reposición, cantidades", "body"],
    ["  Violeta       →  Opciones: Favorito, Activo, En tienda, Acepta devolución, Vender sin variantes", "body"],
    ["  Amarillo      →  Notas", "body"],
    ["", "body"],
    ["IDENTIFICACIÓN", "section"],
    ["  SKU Padre:  SKU del artículo padre. Si está vacío → la fila es un artículo simple.", "body"],
    ["  SKU:        SKU propio del artículo o variante. Obligatorio.", "body"],
    ["  Nombre:     Nombre del artículo o variante. Obligatorio.", "body"],
    ["", "body"],
    ["COMPOSICIÓN DE COSTO (columnas naranja) — ARTÍCULO PADRE Y VARIANTES", "section"],
    ["  Hay 4 bloques numerados (1, 2, 3, 4). Cada bloque tiene 7 campos:", "body"],
    ["  · Moneda N:        Moneda del costo (dropdown desde Listas, col E).", "body"],
    ["  · Tipo N:          Metal | Hechura (solo estos dos tipos).", "body"],
    ["  · Descripción N:   Descripción del componente (ej: 'Oro 18K Amarillo', 'Precio / Hechura').", "body"],
    ["  · Cantidad N:      Gramos (obligatorio para Metal). No aplica a Hechura.", "body"],
    ["  · Precio Unit. N:  Solo para Hechura. Metal toma precio automático de cotización.", "body"],
    ["  · Merma % N:       Porcentaje de merma (solo aplica a tipo Metal).", "body"],
    ["  · Bonif/Recargo N: Ajuste en formato +10% (bonificación) o -500 (recargo fijo).", "body"],
    ["  Tanto artículos padre como variantes pueden tener estos bloques.", "body"],
    ["  Si la variante hereda del padre, sus bloques no se importan aunque estén visibles.", "body"],
    ["", "body"],
    ["EXPORTACIÓN — COMPOSICIÓN DE COSTO EN VARIANTES", "section"],
    ["  Al exportar artículos con variantes:", "body"],
    ["  · El artículo PADRE muestra su composición completa (bloques naranja).", "body"],
    ["  · Las variantes con composición PROPIA muestran sus propios bloques (naranja).", "body"],
    ["  · Las variantes que HEREDAN del padre muestran los bloques del padre como referencia", "body"],
    ["    (para que puedas ver qué están heredando), pero con 'Origen costo = Hereda del padre'.", "body"],
    ["", "body"],
    ["  COLUMNA 'ORIGEN COSTO' (gris) — controla la herencia al importar:", "body"],
    ["  · 'Hereda del padre' → la variante hereda la composición del padre.", "body"],
    ["    Los bloques mostrados son solo referencia visual; al importar, no se guardan como propios.", "body"],
    ["  · 'Propio'            → la variante tiene su propia composición.", "body"],
    ["    Los bloques se guardan como propios de esa variante.", "body"],
    ["", "body"],
    ["  Para que una variante tenga composición propia: cambiá 'Origen costo' a 'Propio'", "body"],
    ["  y modificá los bloques. Para que una variante vuelva a heredar: ponela en 'Hereda del padre'.", "body"],
    ["", "body"],
    ["AJUSTE GLOBAL DE COSTO (columnas marrón) — SOLO ARTÍCULO PADRE", "section"],
    ["  Permite aplicar un ajuste adicional al costo total calculado.", "body"],
    ["  · Ajuste tipo:  Bonificación | Recargo", "body"],
    ["  · Ajuste valor: Número positivo (porcentaje o monto fijo).", "body"],
    ["  · Ajuste modo:  Porcentaje | Monto fijo", "body"],
    ["", "body"],
    ["IMPUESTOS (columnas verde oscuro)", "section"],
    ["  IVA 1, IVA 2, IVA 3 → nombre del impuesto configurado en el sistema.", "body"],
    ["  Se pueden asignar hasta 3 impuestos por artículo.", "body"],
    ["", "body"],
    ["ESTADO", "section"],
    ["  Borrador | Activo | Descontinuado | Archivado", "body"],
    ["", "body"],
    ["MODO DE STOCK", "section"],
    ["  Sin stock | Por artículo | Por material", "body"],
    ["", "body"],
    ["ATRIBUTOS DE VARIANTE (celeste)", "section"],
    ["  Solo aplican a filas con SKU Padre completado (es decir, variantes).", "body"],
    ["  Nombre atributo N: nombre del atributo (ej: Color, Talle, Medida).", "body"],
    ["  Valor atributo N:  valor del atributo para esta variante.", "body"],
    ["  Podés usar hasta 4 pares nombre/valor por fila.", "body"],
    ["", "body"],
    ["DIMENSIONES (verde azulado)", "section"],
    ["  Largo, Ancho, Alto: medidas en números (decimales permitidos).", "body"],
    ["  Unidad dim.: unidad de medida — cm, mm, m, in. Por defecto 'cm'.", "body"],
    ["  Las variantes heredan las dimensiones del artículo padre.", "body"],
    ["", "body"],
    ["HOJA LISTAS", "section"],
    ["  Contiene los valores válidos para los dropdowns de la hoja Artículos.", "body"],
    ["  Col A: Categorías  Col B: Grupos  Col C: Proveedores  Col D: Impuestos", "body"],
    ["  Col E: Monedas     Col F: Tipos de costo  Col G: Estados  Col H: Modos de stock", "body"],
    ["  Col I: Metales     Col J: Variantes de Metal  Col K: Atributos disponibles", "body"],
    ["  Col L: Marcas      Col M: Fabricantes  (Col N+: opciones de atributos, ocultas)", "body"],
    ["", "body"],
    ["CÓMO USAR", "section"],
    ["  1. Completá los datos en la hoja 'Artículos' (borrá la fila de ejemplo primero).", "body"],
    ["  2. Para artículos con variantes: una fila de artículo padre + una fila por variante.", "body"],
    ["  3. Las variantes pueden tener composición propia (bloques naranja) o dejarlos vacíos para heredar del padre.", "body"],
    ["  4. Guardá el archivo como .xlsx.", "body"],
    ["  5. En TPTech: Artículos → Importar → subí el archivo.", "body"],
    ["", "body"],
    ["LÍMITES", "section"],
    ["  Máximo 2.000 filas por importación", "body"],
    ["  Máximo 10 MB por archivo", "body"],
  ];
  instrLines.forEach(([text, kind], i) => {
    const cell = instr.getCell(`A${i + 1}`);
    cell.value = text;
    if (kind === "title")        cell.font = { bold: true, size: 14 };
    else if (kind === "section") cell.font = { bold: true, size: 10 };
    else                         cell.font = { size: 10 };
  });

  // "Artículos" es la primera hoja (index 0) → queda activa al abrir el archivo
  wb.views = [{ x: 0, y: 0, width: 10000, height: 20000, firstSheet: 0, activeTab: 0, visibility: "visible" }];
  return wb;
}

/** Genera la plantilla guiada vacía (con fila de ejemplo). */
export async function generateGuidedTemplate(catalog: GuidedTemplateCatalog): Promise<Buffer> {
  const wb = await buildGuidedWorkbook(catalog);
  const buffer = await wb.xlsx.writeBuffer();
  return Buffer.from(buffer);
}

/**
 * Transforma artículos (con sus variantes) y el mapa de impuestos en filas GuidedExportRow.
 *
 * Reglas de representación:
 *  - Artículos SIN variantes → una fila (artículo padre).
 *  - Artículos CON variantes → una fila por variante; la fila del padre se omite.
 *  - Nombre de variante = "Nombre padre · Nombre variante" (autosuficiente).
 *  - Campos sin override propio en la variante se heredan del artículo padre.
 */
export function buildGuidedExportRows(
  articles: any[],
  taxMap: Map<string, string>,
  baseCurrency?: { code: string; name: string },
): GuidedExportRow[] {
  function xfmtBool(v: boolean | null | undefined): string { return v == null ? "" : v ? "SI" : "NO"; }
  function xfmtDec(v: any): string { return v == null ? "" : String(Number(v)); }
  function xfmtAdjTipo(v: string | null | undefined): string {
    if (v === "BONUS")     return "Bonificación";
    if (v === "SURCHARGE") return "Recargo";
    return "";
  }
  function xfmtAdjModo(v: string | null | undefined): string {
    if (v === "PERCENTAGE")   return "Porcentaje";
    if (v === "FIXED_AMOUNT") return "Monto fijo";
    return "";
  }

  function extractAttrPairs(attrValues: any[]): { nombre: string; valor: string }[] {
    const pairs = (attrValues ?? []).slice(0, 4).map((av: any) => ({
      nombre: av.assignment?.definition?.name ?? "",
      valor:  av.value ?? "",
    }));
    while (pairs.length < 4) pairs.push({ nombre: "", valor: "" });
    return pairs;
  }

  /**
   * Suma la `quantity` de todos los registros de stock (por almacén).
   * Devuelve "" si no hay registros (artículo sin seguimiento de stock).
   * Devuelve el total como cadena si hay al menos un registro (aunque sea 0).
   */
  function sumStock(stockRows: any[] | null | undefined): string {
    if (!stockRows || stockRows.length === 0) return "";
    const total = stockRows.reduce((acc: number, r: any) => acc + Number(r.quantity ?? 0), 0);
    return String(total);
  }

  function extractCostBlock(line: any) {
    if (!line) return { moneda: "", tipo: "", desc: "", qty: "", unitValue: "", merma: "", bonif: "" };
    const variantLabel = line.metalVariant
      ? `${line.metalVariant.metal?.name ?? ""} · ${line.metalVariant.name ?? ""}`.replace(/^ · | · $/, "")
      : "";
    // Moneda: usar la moneda de la línea; si es null (= base) usar baseCurrency.
    // Siempre exportar en formato "CODE · Nombre" para que el import lo resuelva por código.
    const cur = line.currency ?? baseCurrency ?? null;
    const moneda = cur?.code && cur?.name ? `${cur.code} · ${cur.name}` : (cur?.name ?? "");
    return {
      moneda,
      tipo:      COST_TYPE_LABEL[line.type] ?? line.type ?? "",
      desc:      variantLabel || line.label || "",
      qty:       xfmtDec(line.quantity),
      // METAL: el precio se toma de MetalQuote al calcular — no se exporta para
      // evitar confusión (el valor del Excel sería stale). Se ignora en import.
      unitValue: line.type === "METAL" ? "" : xfmtDec(line.unitValue),
      merma:     xfmtDec(line.mermaPercent),
      bonif:     xfmtAdj(line.lineAdjKind, line.lineAdjType, line.lineAdjValue),
    };
  }

  const rows: GuidedExportRow[] = [];

  for (const art of articles) {
    const costLines = (art as any).costComposition ?? [];
    const c1 = extractCostBlock(costLines[0]);
    const c2 = extractCostBlock(costLines[1]);
    const c3 = extractCostBlock(costLines[2]);
    const c4 = extractCostBlock(costLines[3]);

    const taxIds: string[] = (art as any).manualTaxIds ?? [];
    const iva1 = taxMap.get(taxIds[0] ?? "") ?? "";
    const iva2 = taxMap.get(taxIds[1] ?? "") ?? "";
    const iva3 = taxMap.get(taxIds[2] ?? "") ?? "";

    const artAttrs = extractAttrPairs((art as any).attributeValues);
    const hasVariants = ((art as any).variants as any[]).length > 0;

    if (!hasVariants) {
      rows.push({
        skuPadre:        "",
        sku:             art.sku ?? art.code ?? "",
        nombre:          art.name,
        descripcion:     art.description ?? "",
        estado:          STATUS_LABEL[art.status ?? ""] ?? art.status ?? "",
        categoria:       (art.category as any)?.name ?? "",
        grupo:           (art.group as any)?.name ?? "",
        proveedor:       (art.preferredSupplier as any)?.displayName ?? "",
        // supplierCode = código del artículo en el sistema del proveedor (ej. ref. del catálogo del proveedor)
        codigoProveedor: art.supplierCode ?? "",
        marca:           art.brand ?? "",
        fabricante:      art.manufacturer ?? "",
        cost1_moneda:    c1.moneda,
        cost1_tipo:      c1.tipo,
        cost1_desc:      c1.desc,
        cost1_qty:       c1.qty,
        cost1_unitValue: c1.unitValue,
        cost1_merma:     c1.merma,
        cost1_bonif:     c1.bonif,
        cost2_moneda:    c2.moneda,
        cost2_tipo:      c2.tipo,
        cost2_desc:      c2.desc,
        cost2_qty:       c2.qty,
        cost2_unitValue: c2.unitValue,
        cost2_merma:     c2.merma,
        cost2_bonif:     c2.bonif,
        cost3_moneda:    c3.moneda,
        cost3_tipo:      c3.tipo,
        cost3_desc:      c3.desc,
        cost3_qty:       c3.qty,
        cost3_unitValue: c3.unitValue,
        cost3_merma:     c3.merma,
        cost3_bonif:     c3.bonif,
        cost4_moneda:    c4.moneda,
        cost4_tipo:      c4.tipo,
        cost4_desc:      c4.desc,
        cost4_qty:       c4.qty,
        cost4_unitValue: c4.unitValue,
        cost4_merma:     c4.merma,
        cost4_bonif:     c4.bonif,
        adjTipo:         xfmtAdjTipo(art.manualAdjustmentKind),
        adjValor:        xfmtDec(art.manualAdjustmentValue),
        adjModo:         xfmtAdjModo(art.manualAdjustmentType),
        iva1, iva2, iva3,
        dimLargo:        xfmtDec(art.dimensionLength),
        dimAncho:        xfmtDec(art.dimensionWidth),
        dimAlto:         xfmtDec(art.dimensionHeight),
        dimUnidad:       art.dimensionUnit ?? "",
        modoStock:       STOCK_MODE_LABEL[art.stockMode ?? ""] ?? art.stockMode ?? "",
        unidad:          art.unitOfMeasure ?? "",
        peso:            xfmtDec(art.weight),
        ptoReposicion:   xfmtDec(art.reorderPoint),
        cantMin:         xfmtDec(art.minSaleQuantity),
        cantMax:         xfmtDec(art.maxSaleQuantity),
        cantDefault:     xfmtDec(art.defaultQuantity),
        stockRef:        sumStock((art as any).stock),
        favorito:        xfmtBool(art.isFavorite),
        activo:          xfmtBool(art.isActive),
        enTienda:        xfmtBool(art.showInStore),
        aceptaDev:       xfmtBool(art.isReturnable),
        sinVariantes:    xfmtBool(art.sellWithoutVariants),
        origenCosto:     "",
        notas:           art.notes ?? "",
        attr1nombre: artAttrs[0].nombre, attr1valor: artAttrs[0].valor,
        attr2nombre: artAttrs[1].nombre, attr2valor: artAttrs[1].valor,
        attr3nombre: artAttrs[2].nombre, attr3valor: artAttrs[2].valor,
        attr4nombre: artAttrs[3].nombre, attr4valor: artAttrs[3].valor,
      });
    }

    for (const variant of (art as any).variants) {
      const varAttrs = extractAttrPairs((variant as any).attributeValues);
      const nombreVariante = (variant.name as string)?.trim()
        ? `${art.name} · ${variant.name}`
        : art.name;

      // Composición de costo de la variante: SIEMPRE se exporta la composición del artículo padre.
      // Las variantes no tienen composición propia — todas heredan del padre.
      // "Origen costo = Hereda del padre" indica al importador que no debe persistir
      // estos bloques como propios de la variante.
      const vC1 = extractCostBlock(costLines[0] ?? null);
      const vC2 = extractCostBlock(costLines[1] ?? null);
      const vC3 = extractCostBlock(costLines[2] ?? null);
      const vC4 = extractCostBlock(costLines[3] ?? null);
      const origenCostoVariante = "Hereda del padre";

      rows.push({
        skuPadre:        art.sku ?? art.code ?? "",
        sku:             variant.sku ?? variant.code ?? "",
        nombre:          nombreVariante,
        descripcion:     art.description ?? "",
        estado:          STATUS_LABEL[art.status ?? ""] ?? art.status ?? "",
        categoria:       (art.category as any)?.name ?? "",
        grupo:           (art.group as any)?.name ?? "",
        proveedor:       (art.preferredSupplier as any)?.displayName ?? "",
        codigoProveedor: art.supplierCode ?? "",
        marca:           art.brand ?? "",
        fabricante:      art.manufacturer ?? "",
        cost1_moneda:    vC1.moneda,
        cost1_tipo:      vC1.tipo,
        cost1_desc:      vC1.desc,
        cost1_qty:       vC1.qty,
        cost1_unitValue: vC1.unitValue,
        cost1_merma:     vC1.merma,
        cost1_bonif:     vC1.bonif,
        cost2_moneda:    vC2.moneda,
        cost2_tipo:      vC2.tipo,
        cost2_desc:      vC2.desc,
        cost2_qty:       vC2.qty,
        cost2_unitValue: vC2.unitValue,
        cost2_merma:     vC2.merma,
        cost2_bonif:     vC2.bonif,
        cost3_moneda:    vC3.moneda,
        cost3_tipo:      vC3.tipo,
        cost3_desc:      vC3.desc,
        cost3_qty:       vC3.qty,
        cost3_unitValue: vC3.unitValue,
        cost3_merma:     vC3.merma,
        cost3_bonif:     vC3.bonif,
        cost4_moneda:    vC4.moneda,
        cost4_tipo:      vC4.tipo,
        cost4_desc:      vC4.desc,
        cost4_qty:       vC4.qty,
        cost4_unitValue: vC4.unitValue,
        cost4_merma:     vC4.merma,
        cost4_bonif:     vC4.bonif,
        // Ajuste global: solo aplica al artículo padre — vacío en variantes
        adjTipo: "", adjValor: "", adjModo: "",
        iva1, iva2, iva3,
        // Dimensiones: variante hereda del artículo padre
        dimLargo:        xfmtDec(art.dimensionLength),
        dimAncho:        xfmtDec(art.dimensionWidth),
        dimAlto:         xfmtDec(art.dimensionHeight),
        dimUnidad:       art.dimensionUnit ?? "",
        modoStock:       STOCK_MODE_LABEL[art.stockMode ?? ""] ?? art.stockMode ?? "",
        unidad:          art.unitOfMeasure ?? "",
        peso:            xfmtDec(variant.weightOverride),
        ptoReposicion:   xfmtDec(variant.reorderPoint),
        cantMin:         xfmtDec(variant.minSaleQuantity),
        cantMax:         xfmtDec(variant.maxSaleQuantity),
        cantDefault:     xfmtDec(variant.defaultQuantity),
        stockRef:        sumStock((variant as any).stock),
        favorito:        xfmtBool(variant.isFavorite ?? art.isFavorite),
        activo:          xfmtBool(variant.isActive),
        enTienda:        xfmtBool(art.showInStore),
        aceptaDev:       xfmtBool(art.isReturnable),
        sinVariantes:    xfmtBool(art.sellWithoutVariants),
        origenCosto:     origenCostoVariante,
        notas:           variant.notes ?? "",
        attr1nombre: varAttrs[0].nombre, attr1valor: varAttrs[0].valor,
        attr2nombre: varAttrs[1].nombre, attr2valor: varAttrs[1].valor,
        attr3nombre: varAttrs[2].nombre, attr3valor: varAttrs[2].valor,
        attr4nombre: varAttrs[3].nombre, attr4valor: varAttrs[3].valor,
      });
    }
  }
  return rows;
}

/** Exporta artículos existentes en el formato guiado oficial. */
export async function exportArticlesGuided(
  jewelryId: string,
  catalog: GuidedTemplateCatalog,
): Promise<Buffer> {
  // Obtener artículos con composición de costo, impuestos y moneda base del tenant
  const [articles, taxRecords, baseCurrencyRaw] = await Promise.all([
    prisma.article.findMany({
      where: { jewelryId, deletedAt: null },
      select: {
        code: true, name: true, description: true, articleType: true, status: true,
        sku: true, brand: true, manufacturer: true, supplierCode: true,
        stockMode: true, unitOfMeasure: true, weight: true,
        dimensionLength: true, dimensionWidth: true, dimensionHeight: true, dimensionUnit: true,
        reorderPoint: true, minSaleQuantity: true, maxSaleQuantity: true, defaultQuantity: true,
        isFavorite: true, isActive: true, showInStore: true, isReturnable: true,
        sellWithoutVariants: true, notes: true, manualTaxIds: true,
        manualAdjustmentKind: true, manualAdjustmentType: true, manualAdjustmentValue: true,
        category:          { select: { name: true } },
        preferredSupplier: { select: { code: true, displayName: true } },
        costComposition: {
          select: {
            type: true, label: true, quantity: true, quantityUnit: true, unitValue: true, mermaPercent: true,
            lineAdjKind: true, lineAdjType: true, lineAdjValue: true,
            currency:    { select: { code: true, name: true } },
            metalVariant: { select: { name: true, metal: { select: { name: true } } } },
          },
          orderBy: { sortOrder: "asc" },
          take: 4,
        },
        attributeValues: {
          select: {
            value: true,
            assignment: { select: { definition: { select: { name: true } } } },
          },
          take: 4,
        },
        // Stock del artículo (para artículos sin variantes — variantId null)
        stock: {
          where: { variantId: null },
          select: { quantity: true },
        },
        variants: {
          where: { deletedAt: null },
          select: {
            code: true, name: true, sku: true,
            weightOverride: true, reorderPoint: true,
            minSaleQuantity: true, maxSaleQuantity: true, defaultQuantity: true,
            isActive: true, isFavorite: true, notes: true,
            // Stock de la variante (todos los almacenes)
            stock: {
              select: { quantity: true },
            },
            attributeValues: {
              select: {
                value: true,
                assignment: { select: { definition: { select: { name: true } } } },
              },
              take: 4,
            },
          },
          orderBy: { sortOrder: "asc" },
        },
      },
      orderBy: { code: "asc" },
      take: 5000,
    }),
    prisma.tax.findMany({
      where: { jewelryId, deletedAt: null },
      select: { id: true, name: true },
    }),
    prisma.currency.findFirst({
      where: { jewelryId, isBase: true, deletedAt: null },
      select: { code: true, name: true },
    }),
  ]);

  // Mapa ID → nombre de impuesto
  const taxMap = new Map<string, string>(taxRecords.map((t: any) => [t.id, t.name]));
  const baseCurrency = baseCurrencyRaw ?? undefined;
  const rows = buildGuidedExportRows(articles, taxMap, baseCurrency);

  const wb = await buildGuidedWorkbook(catalog, rows);
  const buffer = await wb.xlsx.writeBuffer();
  return Buffer.from(buffer);
}

// ─── Exportar artículos existentes (v2) ──────────────────────────────────────
export async function exportArticlesV2(
  jewelryId: string,
  catalog: TemplateCatalogDataV2
): Promise<Buffer> {
  const articles = await prisma.article.findMany({
    where: { jewelryId, deletedAt: null },
    select: {
      code: true, name: true, description: true, articleType: true, status: true,
      sku: true, barcode: true, barcodeType: true, brand: true, manufacturer: true,
      salePrice: true,
      mermaPercent: true,
      stockMode: true, unitOfMeasure: true, weight: true,
      reorderPoint: true, minSaleQuantity: true, maxSaleQuantity: true, defaultQuantity: true,
      isFavorite: true, isActive: true, showInStore: true, isReturnable: true,
      sellWithoutVariants: true, notes: true,
      category:          { select: { name: true } },
      preferredSupplier: { select: { code: true, displayName: true } },
      variants: {
        where: { deletedAt: null },
        select: {
          code: true, name: true, sku: true, barcode: true, barcodeType: true,
          weightOverride: true, reorderPoint: true,
          minSaleQuantity: true, maxSaleQuantity: true, defaultQuantity: true,
          isActive: true, notes: true,
          stock: {
            select: {
              quantity: true,
              warehouse: { select: { name: true, code: true } },
            },
          },
        },
        orderBy: { sortOrder: "asc" },
      },
      // Líneas de costo METAL
      costComposition: {
        where: { type: "METAL" as any },
        select: {
          quantity: true, mermaPercent: true, unitValue: true,
          metalVariant: { select: { name: true, metal: { select: { name: true } } } },
        },
        orderBy: { sortOrder: "asc" },
      },
      // Stock del artículo (sin variante)
      stock: {
        where: { variantId: null },
        select: {
          quantity: true,
          warehouse: { select: { name: true, code: true } },
        },
      },
    },
    orderBy: { code: "asc" },
    take: 5000,
  });

  const wb = new ExcelJS.Workbook();
  wb.creator = "TPTech";
  wb.created = new Date();

  buildCatalogsSheetV2(wb, catalog);
  const wsA  = setupDataSheet(wb, "Artículos",  ARTICLE_HEADERS_V2,   ARTICLE_WIDTHS_V2);
  const wsV  = setupDataSheet(wb, "Variantes",  VARIANT_HEADERS_V2,   VARIANT_WIDTHS_V2);
  const wsM  = setupDataSheet(wb, "Metales",    METAL_HEADERS_V2,     METAL_WIDTHS_V2);
  const wsS  = setupDataSheet(wb, "Stock",      STOCK_HEADERS_V2,     STOCK_WIDTHS_V2);
  const wsAt = setupDataSheet(wb, "Atributos",  ATTRIBUTE_HEADERS_V2, ATTRIBUTE_WIDTHS_V2);
  buildInstructionsSheetV2(wb);

  function xfmt(v: any): string { return v == null ? "" : String(v); }
  function xfmtBool(v: boolean | null | undefined): string { return v == null ? "" : v ? "SI" : "NO"; }
  function xfmtDec(v: any): string { return v == null ? "" : String(Number(v)); }
  function xfmtWh(w: { code: string; name: string }): string {
    return w.code ? `${w.code} · ${w.name}` : w.name;
  }
  function xfmtSup(sp: { code: string; displayName: string } | null): string {
    return sp ? `${sp.code} · ${sp.displayName}` : "";
  }

  for (const art of articles) {
    // ── Fila artículo ────────────────────────────────────────────────────────
    const ar: string[] = new Array(ARTICLE_HEADERS_V2.length).fill("");
    ar[ACOL["Nombre"]]            = xfmt(art.name);
    ar[ACOL["Codigo"]]            = xfmt(art.code);
    ar[ACOL["Tipo"]]              = xfmt(art.articleType);
    ar[ACOL["Estado"]]            = xfmt(art.status);
    ar[ACOL["SKU"]]               = xfmt(art.sku);
    ar[ACOL["Barcode"]]           = xfmt(art.barcode);
    ar[ACOL["Tipo_Barcode"]]      = xfmt(art.barcodeType);
    ar[ACOL["Categoria"]]         = xfmt(art.category?.name);
    ar[ACOL["Grupo"]]             = "";
    ar[ACOL["Proveedor"]]         = xfmtSup(art.preferredSupplier as any);
    ar[ACOL["Marca"]]             = xfmt(art.brand);
    ar[ACOL["Fabricante"]]        = xfmt(art.manufacturer);
    ar[ACOL["Descripcion"]]       = xfmt(art.description);
    ar[ACOL["Precio_Costo"]]      = "";
    ar[ACOL["Precio_Venta"]]      = xfmtDec(art.salePrice);
    ar[ACOL["Hechura"]]           = "";
    ar[ACOL["Hechura_Modo"]]      = "";
    ar[ACOL["Merma_Pct"]]         = xfmtDec(art.mermaPercent);
    ar[ACOL["Modo_Costo"]]        = "";
    ar[ACOL["Modo_Stock"]]        = xfmt(art.stockMode);
    ar[ACOL["Unidad"]]            = xfmt(art.unitOfMeasure);
    ar[ACOL["Peso"]]              = xfmtDec(art.weight);
    ar[ACOL["Reorder_Point"]]     = xfmtDec(art.reorderPoint);
    ar[ACOL["Cant_Min"]]          = xfmtDec(art.minSaleQuantity);
    ar[ACOL["Cant_Max"]]          = xfmtDec(art.maxSaleQuantity);
    ar[ACOL["Cant_Default"]]      = xfmtDec(art.defaultQuantity);
    ar[ACOL["Favorito"]]          = xfmtBool(art.isFavorite);
    ar[ACOL["Activo"]]            = xfmtBool(art.isActive);
    ar[ACOL["En_Tienda"]]         = xfmtBool(art.showInStore);
    ar[ACOL["Acepta_Devolucion"]] = xfmtBool(art.isReturnable);
    ar[ACOL["Vender_Sin_Variantes"]] = xfmtBool(art.sellWithoutVariants);
    ar[ACOL["Notas"]]             = xfmt(art.notes);
    wsA.addRow(ar);

    // ── Variantes ────────────────────────────────────────────────────────────
    for (const v of art.variants) {
      const vr: string[] = new Array(VARIANT_HEADERS_V2.length).fill("");
      vr[VCOL["Articulo_Codigo"]] = xfmt(art.code);
      vr[VCOL["Codigo"]]          = xfmt(v.code);
      vr[VCOL["Nombre"]]          = xfmt(v.name);
      vr[VCOL["SKU"]]             = xfmt(v.sku);
      vr[VCOL["Barcode"]]         = xfmt(v.barcode);
      vr[VCOL["Tipo_Barcode"]]    = xfmt(v.barcodeType);
      vr[VCOL["Precio_Costo"]]    = "";
      vr[VCOL["Precio_Venta"]]    = ""; // Las variantes no tienen precio propio; se hereda del artículo padre
      vr[VCOL["Hechura"]]         = "";
      vr[VCOL["Peso"]]            = xfmtDec(v.weightOverride);
      vr[VCOL["Reorder_Point"]]   = xfmtDec(v.reorderPoint);
      vr[VCOL["Cant_Min"]]        = xfmtDec(v.minSaleQuantity);
      vr[VCOL["Cant_Max"]]        = xfmtDec(v.maxSaleQuantity);
      vr[VCOL["Cant_Default"]]    = xfmtDec(v.defaultQuantity);
      vr[VCOL["Activo"]]          = xfmtBool(v.isActive);
      vr[VCOL["Notas"]]           = xfmt(v.notes);
      wsV.addRow(vr);

      // Stock de la variante
      for (const st of v.stock) {
        if (Number(xfmtDec(st.quantity)) === 0) continue;
        const sr: string[] = new Array(STOCK_HEADERS_V2.length).fill("");
        sr[SCOL["Articulo_Codigo"]] = xfmt(art.code);
        sr[SCOL["Codigo_Variante"]] = xfmt(v.code);
        sr[SCOL["Almacen"]]         = xfmtWh(st.warehouse as any);
        sr[SCOL["Cantidad"]]        = xfmtDec(st.quantity);
        sr[SCOL["Modo"]]            = "SET";
        wsS.addRow(sr);
      }
    }

    // ── Metales ──────────────────────────────────────────────────────────────
    for (const cl of art.costComposition) {
      const mr: string[] = new Array(METAL_HEADERS_V2.length).fill("");
      mr[MCOL["Articulo_Codigo"]] = xfmt(art.code);
      mr[MCOL["Metal_Padre"]]     = xfmt((cl.metalVariant as any)?.metal?.name);
      mr[MCOL["Metal_Variante"]]  = xfmt((cl.metalVariant as any)?.name);
      mr[MCOL["Gramos"]]          = xfmtDec(cl.quantity);
      mr[MCOL["Merma_Pct"]]       = xfmtDec(cl.mermaPercent);
      mr[MCOL["Hechura_Metal"]]   = xfmtDec(cl.unitValue);
      wsM.addRow(mr);
    }

    // ── Stock del artículo (sin variante) ────────────────────────────────────
    for (const st of art.stock) {
      if (Number(xfmtDec(st.quantity)) === 0) continue;
      const sr: string[] = new Array(STOCK_HEADERS_V2.length).fill("");
      sr[SCOL["Articulo_Codigo"]] = xfmt(art.code);
      sr[SCOL["Almacen"]]         = xfmtWh(st.warehouse as any);
      sr[SCOL["Cantidad"]]        = xfmtDec(st.quantity);
      sr[SCOL["Modo"]]            = "SET";
      wsS.addRow(sr);
    }
  }

  // Hoja Atributos: se exporta vacía (solo cabecera) — la info de atributos
  // requiere joins adicionales que se hacen bajo demanda
  wsAt.addRow(["# Los atributos no se exportan en esta versión."].concat(new Array(ATTRIBUTE_HEADERS_V2.length - 1).fill("")));

  const buf = await wb.xlsx.writeBuffer();
  return Buffer.from(buf);
}

// ─── Parsear archivo ──────────────────────────────────────────────────────────
export function parseImportFile(buffer: Buffer, mimetype: string): ImportRow[] {
  const wb = XLSX.read(buffer, { type: "buffer" });
  const sheetName = wb.SheetNames[0];
  const ws = wb.Sheets[sheetName];
  const raw = XLSX.utils.sheet_to_json<ImportRow>(ws, {
    header: "A",
    defval: "",
    blankrows: false,
  });

  if (!raw.length) return [];

  // Detectar si la primera fila es header
  const firstRow = raw[0] as Record<string, string>;
  const firstCellVal = s(firstRow["A"] ?? firstRow["__rowNum__"]);
  const isHeader = firstCellVal === "Es_Variante" || firstCellVal === "es_variante";

  // Construir rows con nombres de columna
  const headers = isHeader
    ? Object.values(firstRow).map((v) => s(v))
    : TEMPLATE_HEADERS;

  const dataRows = isHeader ? raw.slice(1) : raw;

  return dataRows.map((row) => {
    const out: ImportRow = {};
    const vals = Object.values(row);
    headers.forEach((h, i) => {
      out[h] = s(vals[i] ?? "");
    });
    return out;
  }).filter((r) => Object.values(r).some((v) => v !== ""));
}

// ─── Preview ─────────────────────────────────────────────────────────────────
export async function previewImport(
  rows: ImportRow[],
  jewelryId: string
): Promise<ImportPreviewResult> {
  // Cargar categorías para matching por nombre
  const categories = await prisma.articleCategory.findMany({
    where: { jewelryId, deletedAt: null },
    select: { id: true, name: true },
  });
  const catMap = new Map(categories.map((c) => [normalizeStr(c.name), c.id]));

  // Códigos existentes en la DB
  const existingArticles = await prisma.article.findMany({
    where: { jewelryId, deletedAt: null },
    select: { id: true, code: true },
  });
  const existingCodesDb = new Map(existingArticles.map((a) => [a.code, a.id]));

  // SKUs existentes en la DB (artículos + variantes) — para detectar conflictos en preview
  const existingSkuArts = await prisma.article.findMany({
    where: { jewelryId, deletedAt: null, NOT: { sku: "" } },
    select: { sku: true, code: true },
  });
  const existingSkuVars = await prisma.articleVariant.findMany({
    where: { jewelryId, deletedAt: null, NOT: { sku: "" } },
    select: { sku: true, code: true },
  });
  const existingSkuDbMap = new Map<string, string>(); // sku → code del dueño
  existingSkuArts.forEach((a) => existingSkuDbMap.set(a.sku, a.code));
  existingSkuVars.forEach((v) => existingSkuDbMap.set(v.sku, v.code));

  // SKUs dentro del archivo (para detectar duplicados internos)
  const skusInFile = new Map<string, number>(); // sku → row index

  // Códigos de artículos en el archivo (para validar padres de variantes)
  const codesInFile = new Set<string>();
  const parentCatMapInFile = new Map<string, string | null>(); // parentCode → categoryId
  for (const row of rows) {
    const isVariant = b(s(row["Es_Variante"] ?? row["es_variante"] ?? ""));
    if (!isVariant) {
      const code = s(row["Codigo"] ?? row["codigo"] ?? "");
      if (code) {
        codesInFile.add(code);
        const catName = s(row["Categoria"] ?? "");
        parentCatMapInFile.set(code, catName ? (catMap.get(normalizeStr(catName)) ?? null) : null);
      }
    }
  }

  // Barcodes usados en el archivo (para detectar duplicados internos)
  const barcodesInFile = new Map<string, number>(); // barcode → row index

  // ── Setup de atributos de variante ────────────────────────────────────
  // Recopilar codes de padres que NO están en el archivo (viven solo en DB)
  const dbOnlyParentCodes = new Set<string>();
  for (const row of rows) {
    if (b(s(row["Es_Variante"] ?? ""))) {
      const pc = s(row["Articulo_Padre"] ?? "");
      if (pc && !parentCatMapInFile.has(pc)) dbOnlyParentCodes.add(pc);
    }
  }
  if (dbOnlyParentCodes.size > 0) {
    const dbParentsAttr = await prisma.article.findMany({
      where: { jewelryId, code: { in: [...dbOnlyParentCodes] }, deletedAt: null },
      select: { code: true, categoryId: true },
    });
    for (const p of dbParentsAttr) {
      parentCatMapInFile.set(p.code, p.categoryId ?? null);
    }
  }
  // Cargar ejes efectivos (isVariantAxis=true) de cada categoría referenciada
  const categoryAxesCache = new Map<string, CatAxis[]>();
  const uniqueCatIdsForAxes = [
    ...new Set([...parentCatMapInFile.values()].filter((v): v is string => v !== null)),
  ];
  for (const catId of uniqueCatIdsForAxes) {
    categoryAxesCache.set(catId, await getEffectiveCategoryAxes(catId, jewelryId));
  }
  // Combo keys de variantes dentro del archivo (para detectar duplicados)
  const variantComboKeysInFile = new Map<string, Set<string>>(); // parentCode → Set<comboKey>

  const result: ImportPreviewRow[] = [];
  let artCount = 0;
  let varCount = 0;
  let validCount = 0;
  let errCount = 0;
  let existingCount = 0;
  let warnCount = 0;

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const isVariant = b(s(row["Es_Variante"] ?? ""));
    const name = s(row["Nombre"] ?? "");
    const code = s(row["Codigo"] ?? "");
    const parentCode = s(row["Articulo_Padre"] ?? "");
    const barcode = s(row["Barcode"] ?? "");
    const tipo = s(row["Tipo"] ?? "").toUpperCase() || "PRODUCT";
    const estado = s(row["Estado"] ?? "").toUpperCase() || "DRAFT";
    const stockMode = s(row["Modo_Stock"] ?? "").toUpperCase() || "NO_STOCK";
    const barcodeType = s(row["Tipo_Barcode"] ?? "").toUpperCase() || "CODE128";
    const catName = s(row["Categoria"] ?? "");

    const errors: string[] = [];
    const warnings: string[] = [];

    if (isVariant) varCount++; else artCount++;

    // SKU — duplicados en el archivo y conflictos contra DB
    const sku = s(row["SKU"] ?? "");
    if (sku) {
      if (skusInFile.has(sku)) {
        errors.push(`SKU "${sku}" duplicado en el archivo (fila ${skusInFile.get(sku)! + 2}).`);
      } else {
        skusInFile.set(sku, i);
        // Conflicto contra DB (para artículos nuevos y variantes nuevas)
        const thisCode = s(row["Codigo"] ?? "");
        const conflictCode = existingSkuDbMap.get(sku);
        if (conflictCode && conflictCode !== thisCode) {
          errors.push(`El SKU "${sku}" ya está en uso por el registro "${conflictCode}" en la base de datos.`);
        }
      }
    }

    // Validar nombre
    if (!name) errors.push("Nombre es obligatorio.");

    if (!isVariant) {
      // Validar tipo
      if (!["PRODUCT", "SERVICE", "MATERIAL"].includes(tipo)) {
        warnings.push(`Tipo "${tipo}" inválido → se usará PRODUCT.`);
      }
      // Validar estado
      if (!["DRAFT", "ACTIVE", "DISCONTINUED", "ARCHIVED"].includes(estado)) {
        warnings.push(`Estado "${estado}" inválido → se usará DRAFT.`);
      }
      // Validar modo stock con tipo
      if (tipo === "SERVICE" && stockMode !== "NO_STOCK") {
        warnings.push(`Servicio con Modo_Stock = "${stockMode}" → se usará NO_STOCK.`);
      }
      if (tipo === "MATERIAL" && stockMode === "BY_MATERIAL") {
        warnings.push(`Material no puede usar BY_MATERIAL → se usará NO_STOCK.`);
      }
      // Validar barcode type
      if (barcode && !["CODE128", "EAN13", "QR"].includes(barcodeType)) {
        errors.push(`Tipo_Barcode "${barcodeType}" inválido.`);
      }
      if (barcode && barcodeType === "EAN13" && !/^\d{13}$/.test(barcode)) {
        errors.push(`EAN13 debe tener exactamente 13 dígitos: "${barcode}".`);
      }
      // Categoria
      if (catName && !catMap.has(normalizeStr(catName))) {
        warnings.push(`Categoría "${catName}" no encontrada → se importará sin categoría.`);
      }
      // Barcode duplicado en archivo
      if (barcode) {
        if (barcodesInFile.has(barcode)) {
          errors.push(`Barcode "${barcode}" duplicado en el archivo (fila ${barcodesInFile.get(barcode)! + 2}).`);
        } else {
          barcodesInFile.set(barcode, i);
        }
      }
    } else {
      // Es variante
      if (!parentCode) {
        errors.push("Variante requiere Articulo_Padre (código del artículo padre).");
      } else {
        const parentInFile = codesInFile.has(parentCode);
        const parentInDb = existingCodesDb.has(parentCode);
        if (!parentInFile && !parentInDb) {
          errors.push(`Artículo padre "${parentCode}" no encontrado en el archivo ni en la base de datos.`);
        }
      }
      // Validar atributos de variante (columnas Atrib_*)
      const attrEntries = Object.entries(extractAttributes(row));
      if (attrEntries.length > 0 && parentCode) {
        const catId = parentCatMapInFile.get(parentCode) ?? null;
        if (!catId) {
          warnings.push(`El artículo padre "${parentCode}" no tiene categoría. Los atributos se ignorarán.`);
        } else {
          const axes = categoryAxesCache.get(catId) ?? [];
          if (axes.length === 0) {
            warnings.push("La categoría del artículo padre no tiene ejes de variante configurados. Los atributos se ignorarán.");
          } else {
            const axesByNorm = new Map<string, CatAxis>();
            for (const ax of axes) {
              axesByNorm.set(normalizeStr(ax.definition.name), ax);
              axesByNorm.set(normalizeStr(ax.definition.code), ax);
            }
            const resolvedAttrs: { assignmentId: string; value: string }[] = [];
            let attrValid = true;
            for (const [attrName, attrValue] of attrEntries) {
              const axis = axesByNorm.get(normalizeStr(attrName));
              if (!axis) {
                warnings.push(`Atributo "${attrName}" no encontrado en la categoría del artículo padre. Se ignora.`);
              } else {
                const errMsg = validateAttrValue(attrName, attrValue, axis.definition.inputType, axis.definition.options);
                if (errMsg) {
                  errors.push(errMsg);
                  attrValid = false;
                } else {
                  resolvedAttrs.push({ assignmentId: axis.id, value: normalizeAttrValue(attrValue, axis.definition.inputType) });
                }
              }
            }
            // Verificar atributos requeridos
            if (attrValid) {
              for (const axis of axes) {
                if (axis.isRequired) {
                  const provided = resolvedAttrs.find(a => a.assignmentId === axis.id && a.value !== "");
                  if (!provided) {
                    errors.push(`El atributo requerido "${axis.definition.name}" falta en esta variante.`);
                    attrValid = false;
                  }
                }
              }
            }
            // Detectar combinación duplicada dentro del archivo
            if (attrValid && resolvedAttrs.length > 0 && errors.length === 0) {
              const comboKey = buildAttrComboKey(resolvedAttrs);
              if (!variantComboKeysInFile.has(parentCode)) variantComboKeysInFile.set(parentCode, new Set());
              const comboSet = variantComboKeysInFile.get(parentCode)!;
              if (comboSet.has(comboKey)) {
                errors.push("Combinación de atributos duplicada dentro del archivo para este artículo padre.");
              } else {
                comboSet.add(comboKey);
              }
            }
          }
        }
      }
    }

    const rowAttrs = isVariant ? extractAttributes(row) : {};
    const displayName = isVariant
      ? `[Variante] ${name}${parentCode ? ` (→ ${parentCode})` : ""}`
      : name;

    let status: ImportPreviewRow["status"] = "valid";
    let existingId: string | undefined;

    if (errors.length > 0) {
      status = "error";
      errCount++;
    } else if (!isVariant && code && existingCodesDb.has(code)) {
      status = "overwrite";
      existingId = existingCodesDb.get(code);
      existingCount++;
      if (warnings.length > 0) warnCount++;
    } else {
      status = warnings.length > 0 ? "warning" : "valid";
      if (warnings.length > 0) warnCount++;
      else validCount++;
    }

    result.push({
      index: i + 1,
      isVariant,
      parentCode,
      displayName,
      status,
      errors,
      warnings,
      existingId,
      ...(Object.keys(rowAttrs).length > 0 ? { attributes: rowAttrs } : {}),
    });
  }

  return {
    total: rows.length,
    articles: artCount,
    variants: varCount,
    valid: validCount,
    errors: errCount,
    overwrite: existingCount,
    warnings: warnCount,
    implicitParents: 0,
    rows: result,
  };
}

// ─── Execute ─────────────────────────────────────────────────────────────────
export async function executeImport(
  rows: ImportRow[],
  jewelryId: string,
  options: { onConflict: "skip" | "update"; userId?: string; fileName?: string }
): Promise<ImportCommitResult> {
  // Cargar datos de referencia
  const categories = await prisma.articleCategory.findMany({
    where: { jewelryId, deletedAt: null },
    select: { id: true, name: true },
  });
  const catMap = new Map(categories.map((c) => [normalizeStr(c.name), c.id]));

  // Grupos y proveedores para los nuevos campos
  const groups = await prisma.articleGroup.findMany({
    where: { jewelryId, deletedAt: null },
    select: { id: true, name: true },
  });
  const groupMap = new Map(groups.map((g) => [normalizeStr(g.name), g.id]));

  const suppliers = await prisma.commercialEntity.findMany({
    where: { jewelryId, deletedAt: null, isSupplier: true, isActive: true },
    select: { id: true, code: true, displayName: true },
  });
  // Resolución por código exacto o displayName normalizado
  const supplierByCode = new Map(suppliers.map((sp) => [sp.code.toLowerCase(), sp.id]));
  const supplierByName = new Map(suppliers.map((sp) => [normalizeStr(sp.displayName), sp.id]));

  const existingArticles = await prisma.article.findMany({
    where: { jewelryId, deletedAt: null },
    select: { id: true, code: true },
  });
  const existingCodesDb = new Map(existingArticles.map((a) => [a.code, a.id]));

  // SKUs existentes para validar unicidad durante execute
  const artSkuMap = new Map<string, string>(); // sku → articleId
  const varSkuMap = new Map<string, string>(); // sku → variantId
  const allArtSkus = await prisma.article.findMany({
    where: { jewelryId, deletedAt: null, NOT: { sku: "" } },
    select: { id: true, sku: true },
  });
  allArtSkus.forEach((a) => artSkuMap.set(a.sku, a.id));
  const allVarSkus = await prisma.articleVariant.findMany({
    where: { jewelryId, deletedAt: null, NOT: { sku: "" } },
    select: { id: true, sku: true },
  });
  allVarSkus.forEach((v) => varSkuMap.set(v.sku, v.id));
  const usedSkusInBatch = new Set<string>(); // SKUs comprometidos en esta ejecución

  // ── Setup de atributos de variante (execute) ────────────────────────────
  const parentCodeToCatId = new Map<string, string | null>(); // parentCode → categoryId
  // Pre-cargar categoryId de padres ya existentes en DB
  const variantParentCodesExec = new Set<string>();
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    if (b(s(row["Es_Variante"] ?? ""))) {
      const pc = s(row["Articulo_Padre"] ?? "");
      if (pc) variantParentCodesExec.add(pc);
    }
  }
  if (variantParentCodesExec.size > 0) {
    const dbParentsExec = await prisma.article.findMany({
      where: { jewelryId, code: { in: [...variantParentCodesExec] }, deletedAt: null },
      select: { code: true, categoryId: true },
    });
    for (const p of dbParentsExec) {
      parentCodeToCatId.set(p.code, p.categoryId ?? null);
    }
  }
  const categoryAxesCacheExec = new Map<string, CatAxis[]>();
  async function getAxesExec(catId: string): Promise<CatAxis[]> {
    if (!categoryAxesCacheExec.has(catId)) {
      categoryAxesCacheExec.set(catId, await getEffectiveCategoryAxes(catId, jewelryId));
    }
    return categoryAxesCacheExec.get(catId)!;
  }

  // Separar artículos y variantes
  const articleRows: { index: number; row: ImportRow }[] = [];
  const variantRows: { index: number; row: ImportRow }[] = [];

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const isVariant = b(s(row["Es_Variante"] ?? ""));
    if (isVariant) variantRows.push({ index: i, row });
    else articleRows.push({ index: i, row });
  }

  // rawRows para trazabilidad: rowIndex (1-based) → fila original
  const rawRowsV1 = new Map<number, ImportRow>();
  for (const { index, row } of articleRows) rawRowsV1.set(index + 1, row);
  for (const { index, row } of variantRows) rawRowsV1.set(index + 1, row);

  const results: ImportCommitRow[] = [];
  const createdCodeMap = new Map<string, string>(); // code → id (artículos recién creados)
  let created = 0, updated = 0, skipped = 0, errors = 0;

  // Contador de secuencia para códigos autogenerados
  let seqOffset = 0;

  async function nextArticleCode(): Promise<string> {
    const count = await prisma.article.count({ where: { jewelryId } });
    let n = count + seqOffset + 1;
    while (true) {
      const candidate = `ART-${String(n).padStart(4, "0")}`;
      const existsDb = await prisma.article.findFirst({
        where: { jewelryId, code: candidate }, select: { id: true },
      });
      const existsMap = createdCodeMap.has(candidate);
      if (!existsDb && !existsMap) { seqOffset++; return candidate; }
      n++;
    }
  }

  // ── Importar artículos ──────────────────────────────────────────────────
  for (const { index, row } of articleRows) {
    const name = s(row["Nombre"] ?? "");
    if (!name) {
      results.push({ index: index + 1, displayName: "(sin nombre)", status: "skipped" });
      skipped++;
      continue;
    }

    let code = s(row["Codigo"] ?? "");
    const barcode = s(row["Barcode"] ?? "") || null;
    const barcodeType = (["CODE128", "EAN13", "QR"].includes((s(row["Tipo_Barcode"] ?? "")).toUpperCase())
      ? (s(row["Tipo_Barcode"] ?? "")).toUpperCase()
      : "CODE128") as "CODE128" | "EAN13" | "QR";

    const rawType = s(row["Tipo"] ?? "").toUpperCase();
    const articleType = (["PRODUCT", "SERVICE", "MATERIAL"].includes(rawType) ? rawType : "PRODUCT") as "PRODUCT" | "SERVICE" | "MATERIAL";

    const rawStatus = s(row["Estado"] ?? "").toUpperCase();
    const status = (["DRAFT", "ACTIVE", "DISCONTINUED", "ARCHIVED"].includes(rawStatus) ? rawStatus : "DRAFT") as "DRAFT" | "ACTIVE" | "DISCONTINUED" | "ARCHIVED";

    let rawStockMode = s(row["Modo_Stock"] ?? "").toUpperCase() || "NO_STOCK";
    if (articleType === "SERVICE") rawStockMode = "NO_STOCK";
    if (articleType === "MATERIAL" && rawStockMode === "BY_MATERIAL") rawStockMode = "NO_STOCK";
    const stockMode = (["NO_STOCK", "BY_ARTICLE", "BY_MATERIAL"].includes(rawStockMode) ? rawStockMode : "NO_STOCK") as "NO_STOCK" | "BY_ARTICLE" | "BY_MATERIAL";

    const catName = s(row["Categoria"] ?? "");
    const categoryId = catName ? (catMap.get(normalizeStr(catName)) ?? null) : null;

    // Nuevos campos
    const groupNameRaw = s(row["Grupo"] ?? "");
    const groupId = groupNameRaw ? (groupMap.get(normalizeStr(groupNameRaw)) ?? null) : null;

    const supplierRaw = s(row["Proveedor"] ?? "");
    const preferredSupplierId = supplierRaw
      ? (supplierByCode.get(supplierRaw.toLowerCase()) ?? supplierByName.get(normalizeStr(supplierRaw)) ?? null)
      : null;

    const weightVal   = n(row["Peso"]);
    const reorderPt   = n(row["Reorder_Point"]);
    const cantMin     = n(row["Cant_Min"]);
    const cantMax     = n(row["Cant_Max"]);
    const cantDefault = n(row["Cant_Default"]);
    const isFavorite  = row["Favorito"] ? b(s(row["Favorito"])) : undefined;
    const isActive    = row["Activo"]   ? b(s(row["Activo"]))   : undefined;
    const sellWithout = row["Vender_Sin_Variantes"] ? b(s(row["Vender_Sin_Variantes"])) : undefined;

    // SKU — validar unicidad antes de procesar
    const sku = s(row["SKU"] ?? "");
    if (sku) {
      if (usedSkusInBatch.has(sku)) {
        results.push({ index: index + 1, displayName: name, status: "error", errors: [`SKU "${sku}" ya fue usado en esta importación.`] });
        errors++;
        continue;
      }
      const existingArtId = code ? existingCodesDb.get(code) : undefined;
      const artSkuOwner = artSkuMap.get(sku);
      if (artSkuOwner && artSkuOwner !== existingArtId) {
        results.push({ index: index + 1, displayName: name, status: "error", errors: [`El SKU "${sku}" ya está en uso por otro artículo.`] });
        errors++;
        continue;
      }
      if (!artSkuOwner && varSkuMap.has(sku)) {
        results.push({ index: index + 1, displayName: name, status: "error", errors: [`El SKU "${sku}" ya está en uso por una variante.`] });
        errors++;
        continue;
      }
    }

    try {
      // ¿Existe ya?
      const existingId = code ? existingCodesDb.get(code) : undefined;

      if (existingId) {
        if (options.onConflict === "skip") {
          results.push({ index: index + 1, displayName: name, status: "skipped", id: existingId });
          skipped++;
          if (code) {
            createdCodeMap.set(code, existingId);
            parentCodeToCatId.set(code, categoryId ?? null);
          }
          continue;
        }
        // update
        await prisma.article.update({
          where: { id: existingId },
          data: {
            name,
            description: s(row["Descripcion"] ?? "") || undefined,
            articleType,
            status,
            stockMode,
            sku: s(row["SKU"] ?? "") || undefined,
            brand: s(row["Marca"] ?? "") || undefined,
            manufacturer: s(row["Fabricante"] ?? "") || undefined,
            categoryId,
            ...(preferredSupplierId !== null ? { preferredSupplierId } : {}),
            salePrice: n(row["Precio_Venta"]),
            mermaPercent: n(row["Merma_Pct"]),
            unitOfMeasure: s(row["Unidad"] ?? "") || undefined,
            ...(weightVal   != null ? { weight: weightVal }                 : {}),
            ...(reorderPt   != null ? { reorderPoint: reorderPt }           : {}),
            ...(cantMin     != null ? { minSaleQuantity: cantMin }          : {}),
            ...(cantMax     != null ? { maxSaleQuantity: cantMax }          : {}),
            ...(cantDefault != null ? { defaultQuantity: cantDefault }      : {}),
            ...(isFavorite  != null ? { isFavorite }                        : {}),
            ...(isActive    != null ? { isActive }                          : {}),
            ...(sellWithout != null ? { sellWithoutVariants: sellWithout }  : {}),
            showInStore: row["En_Tienda"] ? b(s(row["En_Tienda"])) : undefined,
            isReturnable: row["Acepta_Devolucion"] ? b(s(row["Acepta_Devolucion"])) : undefined,
            notes: s(row["Notas"] ?? "") || undefined,
          },
        });
        createdCodeMap.set(code, existingId);
        parentCodeToCatId.set(code, categoryId ?? null);
        if (sku) { usedSkusInBatch.add(sku); artSkuMap.set(sku, existingId); }
        results.push({ index: index + 1, displayName: name, status: "updated", id: existingId });
        updated++;
      } else {
        // Crear
        if (!code) code = await nextArticleCode();
        const codeExists = await prisma.article.findFirst({
          where: { jewelryId, code }, select: { id: true },
        });
        if (codeExists) code = await nextArticleCode();

        const created_article = await prisma.article.create({
          data: {
            jewelryId,
            code,
            name,
            description: s(row["Descripcion"] ?? "") || "",
            articleType,
            status,
            stockMode,
            sku: s(row["SKU"] ?? ""),
            barcode: barcode || null,
            barcodeType,
            brand: s(row["Marca"] ?? ""),
            manufacturer: s(row["Fabricante"] ?? ""),
            categoryId: categoryId ?? undefined,
            preferredSupplierId: preferredSupplierId ?? undefined,
            salePrice: n(row["Precio_Venta"]),
            mermaPercent: n(row["Merma_Pct"]),
            unitOfMeasure: s(row["Unidad"] ?? ""),
            weight: weightVal ?? undefined,
            reorderPoint: reorderPt ?? undefined,
            minSaleQuantity: cantMin ?? undefined,
            maxSaleQuantity: cantMax ?? undefined,
            defaultQuantity: cantDefault ?? undefined,
            isFavorite: isFavorite ?? false,
            isActive: isActive ?? true,
            sellWithoutVariants: sellWithout ?? false,
            showInStore: b(s(row["En_Tienda"] ?? "")),
            isReturnable: s(row["Acepta_Devolucion"]) ? b(s(row["Acepta_Devolucion"])) : true,
            notes: s(row["Notas"] ?? ""),
          },
          select: { id: true, code: true },
        });
        createdCodeMap.set(code, created_article.id);
        existingCodesDb.set(code, created_article.id);
        parentCodeToCatId.set(code, categoryId ?? null);
        if (sku) { usedSkusInBatch.add(sku); artSkuMap.set(sku, created_article.id); }
        results.push({ index: index + 1, displayName: name, status: "created", id: created_article.id });
        created++;
      }
    } catch (e: any) {
      results.push({ index: index + 1, displayName: name, status: "error", errors: [e?.message ?? "Error desconocido"] });
      errors++;
    }
  }

  // ── Importar variantes ──────────────────────────────────────────────────
  for (const { index, row } of variantRows) {
    const name = s(row["Nombre"] ?? "");
    const parentCode = s(row["Articulo_Padre"] ?? "");

    if (!name) {
      results.push({ index: index + 1, displayName: "(variante sin nombre)", status: "skipped" });
      skipped++;
      continue;
    }
    if (!parentCode) {
      results.push({ index: index + 1, displayName: `[Variante] ${name}`, status: "error", errors: ["Falta Articulo_Padre."] });
      errors++;
      continue;
    }

    const parentId = createdCodeMap.get(parentCode) || existingCodesDb.get(parentCode);
    if (!parentId) {
      results.push({ index: index + 1, displayName: `[Variante] ${name}`, status: "error", errors: [`Artículo padre "${parentCode}" no encontrado.`] });
      errors++;
      continue;
    }

    const variantCode = s(row["Codigo"] ?? "");

    // SKU — validar unicidad antes de procesar
    const varSku = s(row["SKU"] ?? "");
    if (varSku) {
      if (usedSkusInBatch.has(varSku)) {
        results.push({ index: index + 1, displayName: `[Variante] ${name}`, status: "error", errors: [`SKU "${varSku}" ya fue usado en esta importación.`] });
        errors++;
        continue;
      }
      if (artSkuMap.has(varSku)) {
        results.push({ index: index + 1, displayName: `[Variante] ${name}`, status: "error", errors: [`El SKU "${varSku}" ya está en uso por un artículo.`] });
        errors++;
        continue;
      }
    }

    try {
      // ¿Existe ya esa variante?
      // Si tiene código → buscar por (artículo, código). Si no tiene código pero estamos
      // en modo skip → buscar por (artículo, nombre) para evitar duplicados en reimport.
      let existingVariant: { id: string } | null = null;
      if (variantCode) {
        existingVariant = await prisma.articleVariant.findFirst({
          where: { articleId: parentId, code: variantCode, deletedAt: null },
          select: { id: true },
        });
      } else if (options.onConflict === "skip") {
        existingVariant = await prisma.articleVariant.findFirst({
          where: { articleId: parentId, name, deletedAt: null },
          select: { id: true },
        });
      }

      // Validar SKU de variante contra otras variantes (excluyendo la propia en update)
      if (varSku) {
        const varSkuOwner = varSkuMap.get(varSku);
        if (varSkuOwner && varSkuOwner !== existingVariant?.id) {
          results.push({ index: index + 1, displayName: `[Variante] ${name}`, status: "error", errors: [`El SKU "${varSku}" ya está en uso por otra variante.`] });
          errors++;
          continue;
        }
      }

      if (existingVariant) {
        if (options.onConflict === "skip") {
          results.push({ index: index + 1, displayName: `[Variante] ${name}`, status: "skipped", id: existingVariant.id });
          skipped++;
          continue;
        }
        const varWeightRaw = n(row["Peso"]);
        await prisma.articleVariant.update({
          where: { id: existingVariant.id },
          data: {
            name,
            sku: s(row["SKU"] ?? "") || undefined,
            // priceOverride eliminado: las variantes no tienen precio propio (REGLA de herencia)
            ...(varWeightRaw != null ? { weightOverride: varWeightRaw } : {}),
            notes: s(row["Notas"] ?? "") || undefined,
          },
        });
        if (varSku) { usedSkusInBatch.add(varSku); varSkuMap.set(varSku, existingVariant.id); }
        // Actualizar atributos de variante (best-effort)
        try {
          const rowAttrs = extractAttributes(row);
          const catId = parentCodeToCatId.get(parentCode) ?? null;
          if (catId && Object.keys(rowAttrs).length > 0) {
            const axes = await getAxesExec(catId);
            const axesByNorm = new Map<string, CatAxis>();
            for (const ax of axes) {
              axesByNorm.set(normalizeStr(ax.definition.name), ax);
              axesByNorm.set(normalizeStr(ax.definition.code), ax);
            }
            const attrData: { jewelryId: string; variantId: string; assignmentId: string; value: string }[] = [];
            for (const [attrName, attrValue] of Object.entries(rowAttrs)) {
              const axis = axesByNorm.get(normalizeStr(attrName));
              if (axis && attrValue.trim()) {
                attrData.push({
                  jewelryId,
                  variantId: existingVariant.id,
                  assignmentId: axis.id,
                  value: normalizeAttrValue(attrValue, axis.definition.inputType),
                });
              }
            }
            if (attrData.length > 0) {
              // Eliminar atributos anteriores y recrear (reemplazo completo)
              await prisma.articleVariantAttributeValue.deleteMany({
                where: { variantId: existingVariant.id, assignmentId: { in: attrData.map(a => a.assignmentId) } },
              });
              await prisma.articleVariantAttributeValue.createMany({ data: attrData, skipDuplicates: true });
            }
          }
        } catch (attrErr: any) {
          console.warn(`[TPTech Import] No se pudieron actualizar atributos de variante "${name}":`, attrErr?.message ?? attrErr);
        }
        results.push({ index: index + 1, displayName: `[Variante] ${name}`, status: "updated", id: existingVariant.id });
        updated++;
      } else {
        const sortOrder = await prisma.articleVariant.count({
          where: { articleId: parentId, deletedAt: null },
        });
        const finalCode = variantCode || `VAR-${String(sortOrder + 1).padStart(3, "0")}`;
        const varWeightCreate = n(row["Peso"]);
        const newVariant = await prisma.articleVariant.create({
          data: {
            jewelryId,
            articleId: parentId,
            code: finalCode,
            name,
            sku: s(row["SKU"] ?? ""),
            // priceOverride eliminado: las variantes no tienen precio propio (REGLA de herencia)
            weightOverride: varWeightCreate ?? undefined,
            notes: s(row["Notas"] ?? ""),
            sortOrder,
          },
          select: { id: true },
        });
        if (varSku) { usedSkusInBatch.add(varSku); varSkuMap.set(varSku, newVariant.id); }
        // Persistir atributos de variante (best-effort)
        try {
          const rowAttrs = extractAttributes(row);
          const catId = parentCodeToCatId.get(parentCode) ?? null;
          if (catId && Object.keys(rowAttrs).length > 0) {
            const axes = await getAxesExec(catId);
            const axesByNorm = new Map<string, CatAxis>();
            for (const ax of axes) {
              axesByNorm.set(normalizeStr(ax.definition.name), ax);
              axesByNorm.set(normalizeStr(ax.definition.code), ax);
            }
            const attrData: { jewelryId: string; variantId: string; assignmentId: string; value: string }[] = [];
            for (const [attrName, attrValue] of Object.entries(rowAttrs)) {
              const axis = axesByNorm.get(normalizeStr(attrName));
              if (axis && attrValue.trim()) {
                attrData.push({
                  jewelryId,
                  variantId: newVariant.id,
                  assignmentId: axis.id,
                  value: normalizeAttrValue(attrValue, axis.definition.inputType),
                });
              }
            }
            if (attrData.length > 0) {
              await prisma.articleVariantAttributeValue.createMany({ data: attrData, skipDuplicates: true });
            }
          }
        } catch (attrErr: any) {
          console.warn(`[TPTech Import] No se pudieron persistir atributos de variante "${name}":`, attrErr?.message ?? attrErr);
        }
        results.push({ index: index + 1, displayName: `[Variante] ${name}`, status: "created", id: newVariant.id });
        created++;
      }
    } catch (e: any) {
      results.push({ index: index + 1, displayName: `[Variante] ${name}`, status: "error", errors: [e?.message ?? "Error desconocido"] });
      errors++;
    }
  }

  // Ordenar por index
  results.sort((a, b) => a.index - b.index);

  // Registrar batch + detalle por fila (best-effort)
  const batchId = await saveBatch({
    jewelryId,
    entityType: "ARTICLE",
    fileName:   options.fileName ?? "",
    onConflict: options.onConflict,
    userId:     options.userId,
    summary:    { created, updated, skipped, errors },
    rows:       buildBatchRowsFromArticleResults(results, rawRowsV1),
  });

  return {
    results,
    summary: { created, updated, skipped, errors },
    batchId,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// V2 — PARSEO Y EJECUCIÓN DE IMPORTACIÓN MULTI-HOJA
// ─────────────────────────────────────────────────────────────────────────────

export type V2ParsedData = {
  articles:   ImportRow[];
  variants:   ImportRow[];
  metals:     ImportRow[];
  stock:      ImportRow[];
  attributes: ImportRow[];
};

export type ParsedImportFile =
  | { format: "v1";      rows:   ImportRow[]   }
  | { format: "v2";      data:   V2ParsedData  }
  | { format: "guided";  buffer: Buffer        };

/** Detecta automáticamente si el archivo es v1 o v2 según los nombres de hoja */
export function parseImportFileAuto(buffer: Buffer, mimetype: string): ParsedImportFile {
  const wb = XLSX.read(buffer, { type: "buffer" });

  // ── Detectar formato Guided ────────────────────────────────────────────────
  // Criterio: primera hoja = "Artículos" cuya primera columna de header es "SKU Padre".
  if (wb.SheetNames[0] === "Artículos") {
    const ws = wb.Sheets["Artículos"];
    const firstRow = XLSX.utils.sheet_to_json<any[]>(ws, { header: 1, defval: "" })[0] as any[];
    if (firstRow?.[0] === "SKU Padre") return { format: "guided", buffer };
  }

  const isV2 = wb.SheetNames.some(n =>
    ["Variantes", "Metales", "Stock", "Atributos"].includes(n)
  );
  if (!isV2) return { format: "v1", rows: parseImportFile(buffer, mimetype) };

  function parseSheet(sheetName: string, headers: string[]): ImportRow[] {
    const ws = wb.Sheets[sheetName];
    if (!ws) return [];
    const raw = XLSX.utils.sheet_to_json<any[]>(ws, { header: 1, defval: "" });
    if (raw.length < 2) return [];
    return (raw.slice(1) as any[][])
      .map((cols) => {
        const row: ImportRow = {};
        headers.forEach((h, i) => { row[h] = s(String(cols[i] ?? "")); });
        return row;
      })
      .filter(row => Object.values(row).some(v => v !== ""));
  }

  return {
    format: "v2",
    data: {
      articles:   parseSheet("Artículos",  ARTICLE_HEADERS_V2),
      variants:   parseSheet("Variantes",  VARIANT_HEADERS_V2),
      metals:     parseSheet("Metales",    METAL_HEADERS_V2),
      stock:      parseSheet("Stock",      STOCK_HEADERS_V2),
      attributes: parseSheet("Atributos",  ATTRIBUTE_HEADERS_V2),
    },
  };
}

// ─── Preview v2 ──────────────────────────────────────────────────────────────
export async function previewImportV2(
  data: V2ParsedData,
  jewelryId: string
): Promise<ImportPreviewResult & { metalRows: number; stockRows: number; attributeRows: number }> {
  const [categories, existingArticles, existingSkuArts, existingSkuVars, existingBarcodeArts, existingBarcodeVars] = await Promise.all([
    prisma.articleCategory.findMany({
      where: { jewelryId, deletedAt: null },
      select: { id: true, name: true },
    }),
    prisma.article.findMany({
      where: { jewelryId, deletedAt: null },
      select: { id: true, code: true },
    }),
    prisma.article.findMany({
      where: { jewelryId, deletedAt: null, NOT: { sku: "" } },
      select: { sku: true, code: true },
    }),
    prisma.articleVariant.findMany({
      where: { jewelryId, deletedAt: null, NOT: { sku: "" } },
      select: { sku: true, code: true },
    }),
    prisma.article.findMany({
      where: { jewelryId, deletedAt: null, NOT: { barcode: "" } },
      select: { barcode: true, code: true },
    }),
    prisma.articleVariant.findMany({
      where: { jewelryId, deletedAt: null, NOT: { barcode: "" } },
      select: { barcode: true, code: true },
    }),
  ]);

  const catMap = new Map(categories.map(c => [normalizeStr(c.name), c.id]));
  const existingCodesDb = new Map(existingArticles.map(a => [a.code, a.id]));
  const existingSkuDb = new Map<string, string>();
  existingSkuArts.forEach(a => existingSkuDb.set(a.sku, a.code));
  existingSkuVars.forEach(v => existingSkuDb.set(v.sku, v.code));
  // F1.3: mapa de barcodes existentes en DB (barcode → código del propietario)
  const existingBarcodeDb = new Map<string, string>();
  existingBarcodeArts.forEach(a => { if (a.barcode) existingBarcodeDb.set(a.barcode, a.code); });
  existingBarcodeVars.forEach(v => { if (v.barcode) existingBarcodeDb.set(v.barcode, v.code); });

  const codesInFile     = new Set<string>();
  const skusInFile      = new Map<string, number>(); // sku → row index
  const barcodesInFile  = new Map<string, number>(); // barcode → row index (F1.3)
  const resultRows: ImportPreviewRow[] = [];
  let artCount = 0, varCount = 0, validCount = 0, errCount = 0, existingCount = 0, warnCount = 0;

  // ── Artículos ──────────────────────────────────────────────────────────────
  for (let i = 0; i < data.articles.length; i++) {
    const row  = data.articles[i];
    const name = s(row["Nombre"] ?? "");
    const code = s(row["Codigo"] ?? "");
    const errors: string[]   = [];
    const warnings: string[] = [];

    if (!name) errors.push("Nombre es obligatorio.");

    const rawType = s(row["Tipo"] ?? "").toUpperCase();
    if (rawType && !["PRODUCT","SERVICE","MATERIAL"].includes(rawType))
      errors.push(`Tipo "${rawType}" inválido. Usar PRODUCT, SERVICE o MATERIAL.`);

    const sku = s(row["SKU"] ?? "");
    if (sku) {
      if (skusInFile.has(sku)) {
        errors.push(`SKU "${sku}" duplicado en el archivo (fila ${skusInFile.get(sku)}).`);
      } else {
        const owner = existingSkuDb.get(sku);
        if (owner && owner !== code) errors.push(`SKU "${sku}" ya está en uso.`);
        skusInFile.set(sku, i + 1);
      }
    }

    // F1.3: validar barcode — duplicados internos y contra DB
    const barcode = s(row["Barcode"] ?? "");
    const barcodeType = s(row["Tipo_Barcode"] ?? "").toUpperCase() || "CODE128";
    if (barcode) {
      if (!["CODE128", "EAN13", "QR"].includes(barcodeType)) {
        errors.push(`Tipo_Barcode "${barcodeType}" inválido.`);
      }
      if (barcodeType === "EAN13" && !/^\d{13}$/.test(barcode)) {
        errors.push(`EAN13 debe tener exactamente 13 dígitos: "${barcode}".`);
      }
      if (barcodesInFile.has(barcode)) {
        errors.push(`Barcode "${barcode}" duplicado en el archivo (fila ${barcodesInFile.get(barcode)}).`);
      } else {
        const barcodeOwner = existingBarcodeDb.get(barcode);
        if (barcodeOwner && barcodeOwner !== code) {
          errors.push(`Barcode "${barcode}" ya está en uso por el registro "${barcodeOwner}" en la base de datos.`);
        }
        barcodesInFile.set(barcode, i + 1);
      }
    }

    const catName = s(row["Categoria"] ?? "");
    if (catName && !catMap.has(normalizeStr(catName)))
      warnings.push(`Categoría "${catName}" no encontrada — se importará sin categoría.`);

    artCount++;
    if (code) codesInFile.add(code);
    const existingId = code ? existingCodesDb.get(code) : undefined;

    let status: ImportPreviewRow["status"];
    if (errors.length > 0)        { status = "error";     errCount++;      }
    else if (existingId)          { status = "overwrite"; existingCount++; }
    else if (warnings.length > 0) { status = "warning";   warnCount++;     }
    else                          { status = "valid";     validCount++;    }

    resultRows.push({
      index: i + 1, isVariant: false, parentCode: "",
      displayName: name || "(sin nombre)",
      status, errors, warnings, existingId,
    });
  }

  // ── Variantes ──────────────────────────────────────────────────────────────
  for (let i = 0; i < data.variants.length; i++) {
    const row     = data.variants[i];
    const artCode = s(row["Articulo_Codigo"] ?? "");
    const name    = s(row["Nombre"] ?? "");
    const errors: string[]   = [];
    const warnings: string[] = [];

    if (!name)    errors.push("Nombre es obligatorio.");
    if (!artCode) errors.push("Articulo_Codigo es obligatorio.");
    else if (!codesInFile.has(artCode) && !existingCodesDb.has(artCode))
      errors.push(`Artículo "${artCode}" no encontrado.`);

    const sku = s(row["SKU"] ?? "");
    if (sku) {
      if (skusInFile.has(sku)) {
        errors.push(`SKU "${sku}" duplicado en el archivo.`);
      } else {
        if (existingSkuDb.has(sku))
          warnings.push(`SKU "${sku}" ya existe en el sistema — se actualizará si coincide.`);
        skusInFile.set(sku, i + 1);
      }
    }

    // F1.3: validar barcode en variantes
    const varBarcode = s(row["Barcode"] ?? "");
    const varBarcodeType = s(row["Tipo_Barcode"] ?? "").toUpperCase() || "CODE128";
    if (varBarcode) {
      if (!["CODE128", "EAN13", "QR"].includes(varBarcodeType)) {
        errors.push(`Tipo_Barcode "${varBarcodeType}" inválido.`);
      }
      if (varBarcodeType === "EAN13" && !/^\d{13}$/.test(varBarcode)) {
        errors.push(`EAN13 debe tener exactamente 13 dígitos: "${varBarcode}".`);
      }
      if (barcodesInFile.has(varBarcode)) {
        errors.push(`Barcode "${varBarcode}" duplicado en el archivo (fila ${barcodesInFile.get(varBarcode)}).`);
      } else {
        const barcodeOwner = existingBarcodeDb.get(varBarcode);
        if (barcodeOwner) {
          errors.push(`Barcode "${varBarcode}" ya está en uso por "${barcodeOwner}" en la base de datos.`);
        }
        barcodesInFile.set(varBarcode, i + 1);
      }
    }

    varCount++;
    const existingParentId = artCode ? existingCodesDb.get(artCode) : undefined;

    let status: ImportPreviewRow["status"];
    if (errors.length > 0)        { status = "error";    errCount++;      }
    else if (warnings.length > 0) { status = "warning";  warnCount++;     }
    else                          { status = "valid";    validCount++;    }

    resultRows.push({
      index: i + 1, isVariant: true, parentCode: artCode,
      displayName: name || "(sin nombre)",
      status, errors, warnings,
      existingId: existingParentId,
    });
  }

  return {
    total: resultRows.length,
    articles: artCount,
    variants: varCount,
    valid: validCount,
    errors: errCount,
    overwrite: existingCount,
    warnings: warnCount,
    implicitParents: 0,
    rows: resultRows,
    metalRows: data.metals.length,
    stockRows: data.stock.length,
    attributeRows: data.attributes.length,
  };
}

// ─── Execute v2 ──────────────────────────────────────────────────────────────
export async function executeImportV2(
  data: V2ParsedData,
  jewelryId: string,
  options: { onConflict: "skip" | "update"; userId?: string; fileName?: string }
): Promise<ImportCommitResult & { metalRows: number; stockRows: number; attributeRows: number }> {
  // ── 0. Pre-cargar catálogos en paralelo ──────────────────────────────────
  const [
    categoriesRaw,
    groupsRaw,
    suppliersRaw,
    existingArticlesRaw,
    metalsRaw,
    warehousesRaw,
    allArtSkusRaw,
    allVarSkusRaw,
  ] = await Promise.all([
    prisma.articleCategory.findMany({
      where: { jewelryId, deletedAt: null },
      select: { id: true, name: true },
    }),
    prisma.articleGroup.findMany({
      where: { jewelryId, deletedAt: null },
      select: { id: true, name: true },
    }),
    prisma.commercialEntity.findMany({
      where: { jewelryId, deletedAt: null, isSupplier: true, isActive: true },
      select: { id: true, code: true, displayName: true },
    }),
    prisma.article.findMany({
      where: { jewelryId, deletedAt: null },
      select: { id: true, code: true, articleType: true, stockMode: true, categoryId: true },
    }),
    prisma.metal.findMany({
      where: { jewelryId, deletedAt: null },
      select: {
        id: true, name: true,
        variants: {
          where: { isActive: true },
          select: { id: true, name: true },
        },
      },
    }),
    prisma.warehouse.findMany({
      where: { jewelryId, deletedAt: null, isActive: true },
      select: { id: true, name: true, code: true },
    }),
    prisma.article.findMany({
      where: { jewelryId, deletedAt: null, NOT: { sku: "" } },
      select: { id: true, sku: true },
    }),
    prisma.articleVariant.findMany({
      where: { jewelryId, deletedAt: null, NOT: { sku: "" } },
      select: { id: true, sku: true },
    }),
  ]);

  // Maps de catálogo
  const catMap         = new Map(categoriesRaw.map(c => [normalizeStr(c.name), c.id]));
  const groupMap       = new Map(groupsRaw.map(g => [normalizeStr(g.name), g.id]));
  const supplierByCode = new Map(suppliersRaw.map(sp => [sp.code.toLowerCase(), sp.id]));
  const supplierByName = new Map(suppliersRaw.map(sp => [normalizeStr(sp.displayName), sp.id]));

  // Map: article.code → { id, articleType, stockMode, categoryId }
  type ArtInfo = { id: string; articleType: string; stockMode: string; categoryId: string | null };
  const existingByCode = new Map<string, ArtInfo>(
    existingArticlesRaw.map(a => [a.code, {
      id: a.id, articleType: a.articleType, stockMode: a.stockMode, categoryId: a.categoryId,
    }])
  );

  // Maps de metal variant: "metalNorm||variantNorm" → MetalVariant.id
  const metalVariantById = new Map<string, string>();
  for (const metal of metalsRaw as any[]) {
    for (const variant of (metal.variants as any[])) {
      metalVariantById.set(`${normalizeStr(metal.name)}||${normalizeStr(variant.name)}`, variant.id);
    }
  }

  // Maps de almacén
  const warehouseByName = new Map(warehousesRaw.map(w => [normalizeStr(w.name), w.id]));
  const warehouseByCode = new Map(
    warehousesRaw.filter(w => w.code).map(w => [w.code.toLowerCase(), w.id])
  );

  // Maps de SKU
  const artSkuMap = new Map<string, string>();
  const varSkuMap = new Map<string, string>();
  allArtSkusRaw.forEach(a => artSkuMap.set(a.sku, a.id));
  allVarSkusRaw.forEach(v => varSkuMap.set(v.sku, v.id));
  const usedSkusInBatch = new Set<string>();

  // Maps de progreso (se actualizan durante la ejecución)
  const codeToId        = new Map<string, string>();        // article.code → article.id
  const codeToType      = new Map<string, string>();        // article.code → articleType
  const codeToCatId     = new Map<string, string | null>(); // article.code → categoryId
  const codeToStockMode = new Map<string, string>();        // article.code → stockMode

  for (const a of existingArticlesRaw) {
    codeToId.set(a.code, a.id);
    codeToType.set(a.code, a.articleType);
    codeToCatId.set(a.code, a.categoryId);
    codeToStockMode.set(a.code, a.stockMode);
  }

  const results: ImportCommitRow[] = [];
  let created = 0, updated = 0, skipped = 0, errors = 0;

  // Artículos y variantes omitidos por onConflict=skip. Sus secciones derivadas
  // (metales, stock, atributos) no deben procesarse para respetar "no tocar".
  const skippedArtCodes = new Set<string>();
  const skippedVarCodes = new Set<string>();

  let seqOffset = 0;
  async function nextArticleCode(): Promise<string> {
    const count = await prisma.article.count({ where: { jewelryId } });
    let num = count + seqOffset + 1;
    while (true) {
      const candidate = `ART-${String(num).padStart(4, "0")}`;
      const inDb  = await prisma.article.findFirst({ where: { jewelryId, code: candidate }, select: { id: true } });
      const inMap = codeToId.has(candidate);
      if (!inDb && !inMap) { seqOffset++; return candidate; }
      num++;
    }
  }

  function resolveSupplierV2(raw: string): string | null {
    if (!raw) return null;
    const parts = raw.split("·").map(p => p.trim());
    if (parts.length >= 2) {
      const byCode = supplierByCode.get(parts[0].toLowerCase());
      if (byCode) return byCode;
    }
    return supplierByCode.get(raw.toLowerCase()) ?? supplierByName.get(normalizeStr(raw)) ?? null;
  }

  function resolveWarehouseId(raw: string): string | null {
    if (!raw) return null;
    const parts = raw.split("·").map(p => p.trim());
    if (parts.length >= 2) {
      const byCode = warehouseByCode.get(parts[0].toLowerCase());
      if (byCode) return byCode;
      const byName = warehouseByName.get(normalizeStr(parts[1]));
      if (byName) return byName;
    }
    return warehouseByCode.get(raw.toLowerCase()) ?? warehouseByName.get(normalizeStr(raw)) ?? null;
  }

  // ── 1. Artículos ─────────────────────────────────────────────────────────
  for (let index = 0; index < data.articles.length; index++) {
    const row  = data.articles[index];
    const name = s(row["Nombre"] ?? "");
    if (!name) {
      results.push({ index: index + 1, displayName: "(sin nombre)", status: "skipped" });
      skipped++; continue;
    }

    let code = s(row["Codigo"] ?? "");
    const barcode     = s(row["Barcode"] ?? "") || null;
    const barcodeType = (["CODE128","EAN13","QR"].includes(s(row["Tipo_Barcode"] ?? "").toUpperCase())
      ? s(row["Tipo_Barcode"] ?? "").toUpperCase() : "CODE128") as "CODE128" | "EAN13" | "QR";

    const rawType    = s(row["Tipo"] ?? "").toUpperCase();
    const articleType = (["PRODUCT","SERVICE","MATERIAL"].includes(rawType) ? rawType : "PRODUCT") as "PRODUCT" | "SERVICE" | "MATERIAL";

    const rawStatus = s(row["Estado"] ?? "").toUpperCase();
    const artStatus = (["DRAFT","ACTIVE","DISCONTINUED","ARCHIVED"].includes(rawStatus) ? rawStatus : "DRAFT") as "DRAFT" | "ACTIVE" | "DISCONTINUED" | "ARCHIVED";

    let rawStockMode = s(row["Modo_Stock"] ?? "").toUpperCase() || "NO_STOCK";
    if (articleType === "SERVICE") rawStockMode = "NO_STOCK";
    if (articleType === "MATERIAL" && rawStockMode === "BY_MATERIAL") rawStockMode = "NO_STOCK";
    const stockMode = (["NO_STOCK","BY_ARTICLE","BY_MATERIAL"].includes(rawStockMode) ? rawStockMode : "NO_STOCK") as "NO_STOCK" | "BY_ARTICLE" | "BY_MATERIAL";

    const catName    = s(row["Categoria"] ?? "");
    const categoryId = catName ? (catMap.get(normalizeStr(catName)) ?? null) : null;

    const groupNameRaw        = s(row["Grupo"] ?? "");
    const groupId             = groupNameRaw ? (groupMap.get(normalizeStr(groupNameRaw)) ?? null) : null;
    const preferredSupplierId = resolveSupplierV2(s(row["Proveedor"] ?? ""));

    const weightVal   = n(row["Peso"]);
    const reorderPt   = n(row["Reorder_Point"]);
    const cantMin     = n(row["Cant_Min"]);
    const cantMax     = n(row["Cant_Max"]);
    const cantDefault = n(row["Cant_Default"]);
    const isFavorite  = row["Favorito"] ? b(s(row["Favorito"])) : undefined;
    const isActive    = row["Activo"]   ? b(s(row["Activo"]))   : undefined;
    const sellWithout = row["Vender_Sin_Variantes"] ? b(s(row["Vender_Sin_Variantes"])) : undefined;

    const sku = s(row["SKU"] ?? "");
    if (sku) {
      if (usedSkusInBatch.has(sku)) {
        results.push({ index: index + 1, displayName: name, status: "error", errors: [`SKU "${sku}" duplicado en esta importación.`], _retryPayload: { type: "article", payload: row } });
        errors++; continue;
      }
      const existingArtId = code ? existingByCode.get(code)?.id : undefined;
      if (artSkuMap.get(sku) && artSkuMap.get(sku) !== existingArtId) {
        results.push({ index: index + 1, displayName: name, status: "error", errors: [`SKU "${sku}" ya está en uso.`], _retryPayload: { type: "article", payload: row } });
        errors++; continue;
      }
      if (!artSkuMap.has(sku) && varSkuMap.has(sku)) {
        results.push({ index: index + 1, displayName: name, status: "error", errors: [`SKU "${sku}" ya está en uso por una variante.`], _retryPayload: { type: "article", payload: row } });
        errors++; continue;
      }
    }

    try {
      const existingEntry = code ? existingByCode.get(code) : undefined;
      const existingId    = existingEntry?.id;

      if (existingId) {
        if (options.onConflict === "skip") {
          skippedArtCodes.add(code);
          codeToId.set(code, existingId);
          codeToType.set(code, existingEntry!.articleType);
          codeToCatId.set(code, categoryId ?? existingEntry!.categoryId);
          codeToStockMode.set(code, existingEntry!.stockMode);
          results.push({ index: index + 1, displayName: name, status: "skipped", id: existingId });
          skipped++; continue;
        }
        await prisma.article.update({
          where: { id: existingId },
          data: {
            name, articleType, status: artStatus, stockMode,
            description: s(row["Descripcion"] ?? "") || undefined,
            sku: sku || undefined,
            barcodeType,
            brand:        s(row["Marca"] ?? "") || undefined,
            manufacturer: s(row["Fabricante"] ?? "") || undefined,
            categoryId,
            ...(preferredSupplierId !== null ? { preferredSupplierId }  : {}),
            salePrice:        n(row["Precio_Venta"]),
            mermaPercent:     n(row["Merma_Pct"]),
            unitOfMeasure: s(row["Unidad"] ?? "") || undefined,
            ...(weightVal   != null ? { weight: weightVal }                  : {}),
            ...(reorderPt   != null ? { reorderPoint: reorderPt }            : {}),
            ...(cantMin     != null ? { minSaleQuantity: cantMin }           : {}),
            ...(cantMax     != null ? { maxSaleQuantity: cantMax }           : {}),
            ...(cantDefault != null ? { defaultQuantity: cantDefault }       : {}),
            ...(isFavorite  != null ? { isFavorite }                         : {}),
            ...(isActive    != null ? { isActive }                           : {}),
            ...(sellWithout != null ? { sellWithoutVariants: sellWithout }   : {}),
            showInStore:  row["En_Tienda"]        ? b(s(row["En_Tienda"]))        : undefined,
            isReturnable: row["Acepta_Devolucion"] ? b(s(row["Acepta_Devolucion"])) : undefined,
            notes: s(row["Notas"] ?? "") || undefined,
          },
        });
        codeToId.set(code, existingId);
        codeToType.set(code, articleType);
        codeToCatId.set(code, categoryId);
        codeToStockMode.set(code, stockMode);
        if (sku) { usedSkusInBatch.add(sku); artSkuMap.set(sku, existingId); }
        results.push({ index: index + 1, displayName: name, status: "updated", id: existingId });
        updated++;
      } else {
        if (!code) code = await nextArticleCode();
        const codeCheck = await prisma.article.findFirst({ where: { jewelryId, code }, select: { id: true } });
        if (codeCheck) code = await nextArticleCode();

        const newArt = await prisma.article.create({
          data: {
            jewelryId, code, name, articleType, status: artStatus, stockMode,
            description: s(row["Descripcion"] ?? ""),
            sku,
            barcode: barcode || null,
            barcodeType,
            brand:        s(row["Marca"] ?? ""),
            manufacturer: s(row["Fabricante"] ?? ""),
            categoryId:          categoryId          ?? undefined,
            preferredSupplierId: preferredSupplierId ?? undefined,
            salePrice:        n(row["Precio_Venta"]),
            mermaPercent:     n(row["Merma_Pct"]),
            unitOfMeasure: s(row["Unidad"] ?? ""),
            weight:          weightVal   ?? undefined,
            reorderPoint:    reorderPt   ?? undefined,
            minSaleQuantity: cantMin     ?? undefined,
            maxSaleQuantity: cantMax     ?? undefined,
            defaultQuantity: cantDefault ?? undefined,
            isFavorite:  isFavorite  ?? false,
            isActive:    isActive    ?? true,
            sellWithoutVariants: sellWithout ?? false,
            showInStore:  b(s(row["En_Tienda"] ?? "")),
            isReturnable: row["Acepta_Devolucion"] ? b(s(row["Acepta_Devolucion"])) : true,
            notes: s(row["Notas"] ?? ""),
          },
          select: { id: true, code: true },
        });
        codeToId.set(code, newArt.id);
        codeToType.set(code, articleType);
        codeToCatId.set(code, categoryId ?? null);
        codeToStockMode.set(code, stockMode);
        if (sku) { usedSkusInBatch.add(sku); artSkuMap.set(sku, newArt.id); }
        results.push({ index: index + 1, displayName: name, status: "created", id: newArt.id });
        created++;
      }
    } catch (e: any) {
      results.push({ index: index + 1, displayName: name, status: "error", errors: [e?.message ?? "Error desconocido"], _retryPayload: { type: "article", payload: row } });
      errors++;
    }
  }

  // ── 2. Variantes ─────────────────────────────────────────────────────────
  // Pre-cargar variantes existentes de los artículos involucrados
  const allArtIds = [...new Set([...codeToId.values()])];
  const existingVarsRaw = allArtIds.length > 0
    ? await prisma.articleVariant.findMany({
        where: { articleId: { in: allArtIds }, deletedAt: null },
        select: { id: true, code: true, articleId: true },
      })
    : [];

  // artId → Map<varCode, varId>
  const varsByArtId = new Map<string, Map<string, string>>();
  for (const v of existingVarsRaw) {
    if (!varsByArtId.has(v.articleId)) varsByArtId.set(v.articleId, new Map());
    varsByArtId.get(v.articleId)!.set(v.code, v.id);
  }
  // varCode → varId (global, para metales/stock/atributos)
  const varCodeToId = new Map<string, string>();
  for (const v of existingVarsRaw) { if (v.code) varCodeToId.set(v.code, v.id); }

  for (let index = 0; index < data.variants.length; index++) {
    const row     = data.variants[index];
    const artCode = s(row["Articulo_Codigo"] ?? "");
    const name    = s(row["Nombre"] ?? "");

    if (!name) {
      results.push({ index: index + 1, displayName: "(variante sin nombre)", status: "skipped" });
      skipped++; continue;
    }
    if (!artCode) {
      results.push({ index: index + 1, displayName: `[Variante] ${name}`, status: "error", errors: ["Falta Articulo_Codigo."], _retryPayload: { type: "variant", payload: row } });
      errors++; continue;
    }
    const artId = codeToId.get(artCode);
    if (!artId) {
      results.push({ index: index + 1, displayName: `[Variante] ${name}`, status: "error", errors: [`Artículo "${artCode}" no encontrado.`], _retryPayload: { type: "variant", payload: row } });
      errors++; continue;
    }

    const variantCode = s(row["Codigo"] ?? "");
    const varSku      = s(row["SKU"] ?? "");
    if (varSku) {
      if (usedSkusInBatch.has(varSku)) {
        results.push({ index: index + 1, displayName: `[Variante] ${name}`, status: "error", errors: [`SKU "${varSku}" duplicado.`], _retryPayload: { type: "variant", payload: row } });
        errors++; continue;
      }
      if (artSkuMap.has(varSku)) {
        results.push({ index: index + 1, displayName: `[Variante] ${name}`, status: "error", errors: [`SKU "${varSku}" ya está en uso por un artículo.`], _retryPayload: { type: "variant", payload: row } });
        errors++; continue;
      }
    }

    try {
      const artVars           = varsByArtId.get(artId);
      const existingVariantId = variantCode ? artVars?.get(variantCode) : undefined;

      if (varSku) {
        const varSkuOwner = varSkuMap.get(varSku);
        if (varSkuOwner && varSkuOwner !== existingVariantId) {
          results.push({ index: index + 1, displayName: `[Variante] ${name}`, status: "error", errors: [`SKU "${varSku}" ya está en uso.`], _retryPayload: { type: "variant", payload: row } });
          errors++; continue;
        }
      }

      const barcodeTypeV = (["CODE128","EAN13","QR"].includes(s(row["Tipo_Barcode"] ?? "").toUpperCase())
        ? s(row["Tipo_Barcode"] ?? "").toUpperCase() : "CODE128") as "CODE128" | "EAN13" | "QR";
      const varWeightVal = n(row["Peso"]);

      if (existingVariantId) {
        if (options.onConflict === "skip") {
          if (variantCode) skippedVarCodes.add(variantCode);
          results.push({ index: index + 1, displayName: `[Variante] ${name}`, status: "skipped", id: existingVariantId });
          skipped++; continue;
        }
        await prisma.articleVariant.update({
          where: { id: existingVariantId },
          data: {
            name,
            sku: varSku || undefined,
            barcodeType: barcodeTypeV,
            // priceOverride eliminado: las variantes no tienen precio propio (REGLA de herencia)
            ...(varWeightVal != null ? { weightOverride: varWeightVal } : {}),
            reorderPoint:    n(row["Reorder_Point"]) ?? undefined,
            minSaleQuantity: n(row["Cant_Min"])      ?? undefined,
            maxSaleQuantity: n(row["Cant_Max"])      ?? undefined,
            defaultQuantity: n(row["Cant_Default"])  ?? undefined,
            isActive: row["Activo"] ? b(s(row["Activo"])) : undefined,
            notes: s(row["Notas"] ?? "") || undefined,
          },
          select: { id: true },
        });
        if (varSku) { usedSkusInBatch.add(varSku); varSkuMap.set(varSku, existingVariantId); }
        if (variantCode) varCodeToId.set(variantCode, existingVariantId);
        results.push({ index: index + 1, displayName: `[Variante] ${name}`, status: "updated", id: existingVariantId });
        updated++;
      } else {
        const sortOrder = await prisma.articleVariant.count({ where: { articleId: artId, deletedAt: null } });
        const vCode     = variantCode || `VAR-${String(sortOrder + 1).padStart(3, "0")}`;
        const newVar = await prisma.articleVariant.create({
          data: {
            jewelryId, articleId: artId, code: vCode, name,
            sku: varSku,
            barcode:     s(row["Barcode"] ?? "") || null,
            barcodeType: barcodeTypeV,
            // priceOverride eliminado: las variantes no tienen precio propio (REGLA de herencia)
            weightOverride: varWeightVal ?? undefined,
            reorderPoint:    n(row["Reorder_Point"]) ?? undefined,
            minSaleQuantity: n(row["Cant_Min"])      ?? undefined,
            maxSaleQuantity: n(row["Cant_Max"])      ?? undefined,
            defaultQuantity: n(row["Cant_Default"])  ?? undefined,
            isActive: row["Activo"] ? b(s(row["Activo"])) : true,
            notes: s(row["Notas"] ?? ""),
            sortOrder,
          },
          select: { id: true },
        });
        if (varSku) { usedSkusInBatch.add(varSku); varSkuMap.set(varSku, newVar.id); }
        varCodeToId.set(vCode, newVar.id);
        if (!artVars) varsByArtId.set(artId, new Map([[vCode, newVar.id]]));
        else artVars.set(vCode, newVar.id);
        results.push({ index: index + 1, displayName: `[Variante] ${name}`, status: "created", id: newVar.id });
        created++;
      }
    } catch (e: any) {
      results.push({ index: index + 1, displayName: `[Variante] ${name}`, status: "error", errors: [e?.message ?? "Error desconocido"], _retryPayload: { type: "variant", payload: row } });
      errors++;
    }
  }

  // ── 3. Metales ────────────────────────────────────────────────────────────
  type MetalEntry = {
    metalVariantId: string;
    grams: number;
    mermaPercent: number | null;
    hechuraMetal: number | null;
    isBase: boolean;
    variantCode: string;
  };
  const metalsByArtCode = new Map<string, MetalEntry[]>();

  for (const row of data.metals) {
    const artCode  = s(row["Articulo_Codigo"] ?? "");
    const metalPad = s(row["Metal_Padre"] ?? "");
    const metalVar = s(row["Metal_Variante"] ?? "");
    const grams    = n(row["Gramos"]);
    if (!artCode || !metalPad || !metalVar || !grams) continue;
    if (codeToType.get(artCode) === "SERVICE") continue; // regla

    const mvId = metalVariantById.get(`${normalizeStr(metalPad)}||${normalizeStr(metalVar)}`);
    if (!mvId) continue; // variante de metal no encontrada → skip silencioso

    if (!metalsByArtCode.has(artCode)) metalsByArtCode.set(artCode, []);
    metalsByArtCode.get(artCode)!.push({
      metalVariantId: mvId,
      grams,
      mermaPercent: n(row["Merma_Pct"]),
      hechuraMetal: n(row["Hechura_Metal"]),
      isBase:       row["Es_Base"] ? b(s(row["Es_Base"])) : false,
      variantCode:  s(row["Codigo_Variante"] ?? ""),
    });
  }

  let metalRows = 0;
  for (const [artCode, entries] of metalsByArtCode) {
    if (options.onConflict === "skip" && skippedArtCodes.has(artCode)) continue;
    const artId = codeToId.get(artCode);
    if (!artId) continue;
    try {
      // Eliminar líneas METAL previas
      await prisma.articleCostLine.deleteMany({ where: { articleId: artId, type: "METAL" as any } });

      // Crear nuevas líneas de costo METAL
      await prisma.articleCostLine.createMany({
        data: entries.map((e, i) => ({
          jewelryId,
          articleId:     artId,
          type:          "METAL",
          label:         "",
          quantity:      e.grams,
          unitValue:     e.hechuraMetal ?? 0,
          metalVariantId: e.metalVariantId,
          mermaPercent:  e.mermaPercent ?? undefined,
          sortOrder:     i,
        })) as any,
      });

      codeToStockMode.set(artCode, codeToStockMode.get(artCode) ?? "NO_STOCK");

      // Si hay Codigo_Variante → sumar gramos por variante y actualizar weightOverride
      const varGramsMap = new Map<string, number>();
      for (const e of entries) {
        if (e.variantCode) {
          varGramsMap.set(e.variantCode, (varGramsMap.get(e.variantCode) ?? 0) + e.grams);
        }
      }
      for (const [varCode, totalGrams] of varGramsMap) {
        const varId = varCodeToId.get(varCode);
        if (varId) {
          await prisma.articleVariant.update({
            where: { id: varId },
            data: { weightOverride: totalGrams },
          });
        }
      }

      metalRows += entries.length;
    } catch (e: any) {
      console.warn(`[TPTech Import v2] Error en metales de "${artCode}":`, e?.message ?? e);
    }
  }

  // ── 4. Stock ─────────────────────────────────────────────────────────────
  let stockRows = 0;
  for (const row of data.stock) {
    const artCode = s(row["Articulo_Codigo"] ?? "");
    const varCode = s(row["Codigo_Variante"] ?? "");
    const almacen = s(row["Almacen"] ?? "");
    const qty     = n(row["Cantidad"]);
    const modo    = s(row["Modo"] ?? "SET").toUpperCase() === "ADD" ? "ADD" : "SET";

    if (options.onConflict === "skip" && skippedArtCodes.has(artCode)) continue;
    if (options.onConflict === "skip" && varCode && skippedVarCodes.has(varCode)) continue;
    const artId = codeToId.get(artCode);
    const whId  = resolveWarehouseId(almacen);
    if (!artId || !whId || qty == null) continue;
    if (codeToStockMode.get(artCode) !== "BY_ARTICLE") continue; // solo artículos con stock propio

    const varId = varCode ? varCodeToId.get(varCode) : undefined;
    // Si se especificó un código de variante pero no se encontró → skip (no crear stock a nivel artículo por error)
    if (varCode && varId === undefined) continue;

    try {
      await prisma.$transaction(async (tx) => {
        let delta: number;
        let kind: "IN" | "ADJUST";
        const PREFIX = { IN: "AE", ADJUST: "AA" } as const;

        if (modo === "ADD") {
          delta = qty;
          kind  = "IN";
        } else {
          // SET: calcular delta respecto al saldo actual (robusto para re-importaciones)
          const existing = await tx.articleStock.findFirst({
            where:  { jewelryId, articleId: artId, warehouseId: whId, variantId: varId ?? null },
            select: { quantity: true },
          });
          delta = qty - Number(existing?.quantity ?? 0);
          kind  = "ADJUST";
        }

        if (delta === 0) return;

        const count = await tx.articleMovement.count({ where: { jewelryId, kind } });
        const code  = `${PREFIX[kind]}-${String(count + 1).padStart(4, "0")}`;

        await tx.articleMovement.create({
          data: {
            jewelryId,
            kind,
            status:      "CONFIRMED",
            sourceType:  "IMPORT",
            code,
            note:        "Importación masiva",
            effectiveAt: new Date(),
            warehouseId: whId,
            createdById: null,
            lines: {
              create: {
                jewelryId,
                articleId: artId,
                variantId: varId ?? null,
                quantity:  new Prisma.Decimal(delta.toString()),
              },
            },
          },
        });

        await engineApplyStockDelta(tx, {
          jewelryId, articleId: artId, warehouseId: whId,
          variantId: varId ?? null, delta,
        });
      });
      stockRows++;
    } catch (e: any) {
      console.warn(`[TPTech Import v2] Error en stock "${artCode}":`, e?.message ?? e);
    }
  }

  // ── 5. Atributos ──────────────────────────────────────────────────────────
  // Pre-cargar ejes de categoría en caché
  const catAttrCache = new Map<string, CatAxis[]>();
  async function getCatAxes(catId: string): Promise<CatAxis[]> {
    if (!catAttrCache.has(catId)) {
      catAttrCache.set(catId, await getEffectiveCategoryAxes(catId, jewelryId));
    }
    return catAttrCache.get(catId)!;
  }

  let attributeRows = 0;
  for (const row of data.attributes) {
    const artCode  = s(row["Articulo_Codigo"] ?? "");
    const varCode  = s(row["Codigo_Variante"] ?? "");
    const attrName = s(row["Atributo"] ?? "");
    const value    = s(row["Valor"] ?? "");

    // Atributos de artículo (sin varCode): skip si el artículo fue omitido.
    // Atributos de variante (con varCode): la guarda se aplica más abajo, sobre el varCode.
    if (!varCode && options.onConflict === "skip" && skippedArtCodes.has(artCode)) continue;
    const artId = codeToId.get(artCode);
    if (!artId || !attrName || !value) continue;

    const catId = codeToCatId.get(artCode);
    if (!catId) continue; // sin categoría → no hay atributos definidos

    try {
      const axes = await getCatAxes(catId);
      const axesByNorm = new Map<string, CatAxis>();
      for (const ax of axes) {
        axesByNorm.set(normalizeStr(ax.definition.name), ax);
        axesByNorm.set(normalizeStr(ax.definition.code), ax);
      }
      const axis = axesByNorm.get(normalizeStr(attrName));
      if (!axis) continue;

      const normalizedValue = normalizeAttrValue(value, axis.definition.inputType);

      if (varCode) {
        if (options.onConflict === "skip" && skippedVarCodes.has(varCode)) continue;
        const varId = varCodeToId.get(varCode);
        if (!varId) continue;
        await prisma.articleVariantAttributeValue.upsert({
          where:  { variantId_assignmentId: { variantId: varId, assignmentId: axis.id } },
          create: { jewelryId, variantId: varId, assignmentId: axis.id, value: normalizedValue },
          update: { value: normalizedValue },
        });
      } else {
        await prisma.articleAttributeValue.upsert({
          where:  { articleId_assignmentId: { articleId: artId, assignmentId: axis.id } },
          create: { jewelryId, articleId: artId, assignmentId: axis.id, value: normalizedValue },
          update: { value: normalizedValue },
        });
      }
      attributeRows++;
    } catch (e: any) {
      console.warn(`[TPTech Import v2] Error en atributo "${attrName}" de "${artCode}":`, e?.message ?? e);
    }
  }

  results.sort((a, b) => a.index - b.index);

  // Registrar batch + detalle por fila (best-effort).
  // En v2 los índices de artículos y variantes se solapan, por lo que
  // rawRows se pasa vacío: el identifier se extrae del displayName.
  const batchId = await saveBatch({
    jewelryId,
    entityType: "ARTICLE",
    fileName:   options.fileName ?? "",
    onConflict: options.onConflict,
    userId:     options.userId,
    summary:    { created, updated, skipped, errors },
    rows:       buildBatchRowsFromArticleResults(results, new Map()),
  });

  return {
    results,
    summary: { created, updated, skipped, errors },
    batchId,
    metalRows,
    stockRows,
    attributeRows,
  };
}

// ─── Formato Guided: importación ─────────────────────────────────────────────

/**
 * Cabeceras de la hoja "Artículos" en el formato Guided.
 * Coinciden exactamente con los `header` de GUIDED_COLS.
 */
const GH = {
  SKU_PADRE:     "SKU Padre",
  SKU:           "SKU",
  NOMBRE:        "Nombre",
  DESCRIPCION:   "Descripción",
  ESTADO:        "Estado",
  CATEGORIA:     "Categoría",
  GRUPO:         "Grupo",
  PROVEEDOR:        "Proveedor",
  CODIGO_PROVEEDOR: "Código Proveedor",
  MARCA:            "Marca",
  FABRICANTE:    "Fabricante",
  // Nota: los bloques de costo (Moneda N, Tipo N, Descripción N, etc.) se acceden
  // con template strings directamente — no se definen como constantes en GH.
  AJUSTE_TIPO:   "Ajuste tipo",
  AJUSTE_VALOR:  "Ajuste valor",
  AJUSTE_MODO:   "Ajuste modo",
  IVA_1:         "IVA 1",
  IVA_2:         "IVA 2",
  IVA_3:         "IVA 3",
  DIM_LARGO:     "Largo",
  DIM_ANCHO:     "Ancho",
  DIM_ALTO:      "Alto",
  DIM_UNIDAD:    "Unidad dim.",
  MODO_STOCK:    "Modo de stock",
  UNIDAD:        "Unidad",
  PESO:          "Peso (g)",
  PTO_REPOS:     "Pto. Reposición",
  CANT_MIN:      "Cant. mínima",
  CANT_MAX:      "Cant. máxima",
  CANT_DEFAULT:  "Cant. por defecto",
  FAVORITO:      "Favorito",
  ACTIVO:        "Activo",
  EN_TIENDA:     "En tienda",
  ACEPTA_DEV:    "Acepta devolución",
  SIN_VARIANTES: "Vender sin variantes",
  NOTAS:         "Notas",
  ATTR1_NOMBRE:  "Nombre atributo 1",
  ATTR1_VALOR:   "Valor atributo 1",
  ATTR2_NOMBRE:  "Nombre atributo 2",
  ATTR2_VALOR:   "Valor atributo 2",
  ATTR3_NOMBRE:  "Nombre atributo 3",
  ATTR3_VALOR:   "Valor atributo 3",
  ATTR4_NOMBRE:  "Nombre atributo 4",
  ATTR4_VALOR:   "Valor atributo 4",
  // Referencia visual — columna informativa, NO se importa
  ORIGEN_COSTO:   "Origen costo",
} as const;

/** Parsea la hoja "Artículos" de un buffer Guided y devuelve las filas con datos. */
export function parseGuidedRows(buffer: Buffer): Record<string, string>[] {
  const wb = XLSX.read(buffer, { type: "buffer" });
  const ws = wb.Sheets["Artículos"];
  if (!ws) throw Object.assign(new Error('El archivo no tiene hoja "Artículos".'), { status: 400 });
  return (XLSX.utils.sheet_to_json<Record<string, any>>(ws, { defval: "" }) as Record<string, any>[])
    .map(row => Object.fromEntries(Object.entries(row).map(([k, v]) => [k, s(String(v ?? ""))])))
    .filter(row => Object.values(row).some(v => v !== ""));
}

/**
 * Valida los bloques de costo de una fila Guided y devuelve warnings.
 * Función pura — no requiere DB.
 *
 * Aplica tanto a artículos padre como a variantes (ambos pueden tener composición):
 *   METAL:   requiere Cantidad y Descripción.
 *   HECHURA: requiere Precio Unit.
 */
export function validateCostBlockWarnings(
  row: Record<string, string>,
): string[] {
  const warnings: string[] = [];

  for (let ci = 1; ci <= 4; ci++) {
    const tipoBloque = s(row[`Tipo ${ci}`]).toLowerCase();
    if (!tipoBloque) continue;

    if (tipoBloque === "metal") {
      if (!s(row[`Cantidad ${ci}`])) {
        warnings.push(`Bloque ${ci} (Metal): falta la cantidad de gramos.`);
      }
      if (!s(row[`Descripción ${ci}`])) {
        warnings.push(`Bloque ${ci} (Metal): falta la descripción del metal.`);
      }
    } else if (tipoBloque === "hechura") {
      if (!s(row[`Precio Unit. ${ci}`])) {
        warnings.push(`Bloque ${ci} (Hechura): falta el precio unitario.`);
      }
    }
  }
  return warnings;
}

/**
 * Parsea el valor de una celda Moneda del Excel Guided.
 *
 * Formatos aceptados:
 *  "ARS · Peso Argentino"  → { code: "ARS", nameHint: "Peso Argentino" }
 *  "ARS"                   → { code: "ARS", nameHint: "ARS" }
 *  "Peso Argentino"        → { code: "Peso Argentino", nameHint: "Peso Argentino" }
 *
 * El campo `code` siempre es el primer token (antes del " · ").
 * El campo `nameHint` es todo lo que sigue al separador, o el valor completo si no hay separador.
 *
 * Función pura — exportada para tests.
 */
export function parseCurrencyRef(raw: string): { code: string; nameHint: string } {
  const parts = raw.split("·").map(p => p.trim());
  if (parts.length >= 2) {
    return { code: parts[0], nameHint: parts.slice(1).join(" · ") };
  }
  return { code: raw.trim(), nameHint: raw.trim() };
}

// Mapa Excel label → CostLineType enum
const GUIDED_TIPO_TO_LINE_TYPE: Record<string, string> = {
  "metal":          "METAL",
  "hechura":        "HECHURA",
  "hechura propia": "HECHURA",
  "producto":       "PRODUCT",
  "servicio":       "SERVICE",
  "manual":         "MANUAL",
  "costo propio":   "MANUAL",
};

/** Bloque de costo parseado de una fila Guided (función pura). */
export type GuidedCostBlock = {
  /** CostLineType string: "METAL" | "HECHURA" | "PRODUCT" | "SERVICE" | "MANUAL" */
  type: string;
  tipoRaw: string;
  /** Nombre de la moneda (para lookup por nombre, no por código). */
  monedaName: string;
  /** Descripción / label. Para METAL: formato "MetalPadre · VarianteNombre". */
  descripcion: string;
  cantidad: number;
  unitPrice: number;
  mermaPercent: number | null;
  /** Cadena cruda de bonificación/recargo (ej. "-10%" o "+500"). */
  bonifRaw: string;
};

/**
 * Extrae hasta 4 bloques de costo de una fila Guided.
 * Función pura — no requiere DB ni estado externo.
 *
 * Esta es la ÚNICA fuente de verdad para la composición de costo en la importación Guided.
 * Lee las columnas reales de composición: Moneda N, Tipo N, Descripción N, Cantidad N,
 * Precio Unit. N, Merma % N, Bonif/Recargo N (N = 1..4).
 *
 * NO lee columnas resumen (no existen en el formato Guided actual).
 *
 * Criterios de inclusión:
 *  METAL:   tipo + descripción presentes (precio opcional — viene de cotización)
 *  HECHURA: tipo + precio presente (descripción opcional)
 *  Otros:   tipo + descripción presentes
 */
export function extractGuidedCostBlocks(row: Record<string, string>): GuidedCostBlock[] {
  const blocks: GuidedCostBlock[] = [];
  for (let i = 1; i <= 4; i++) {
    const tipoRaw    = s(row[`Tipo ${i}`]).toLowerCase();
    const descripcion = s(row[`Descripción ${i}`]);
    const pUnit       = n(row[`Precio Unit. ${i}`]);

    // ── Criterio de inclusión ────────────────────────────────────────────────
    let include: boolean;
    if (!tipoRaw) {
      include = false;
    } else if (tipoRaw === "metal") {
      include = descripcion !== "";                     // metal: requiere descripción, no precio
    } else if (tipoRaw === "hechura" || tipoRaw === "hechura propia") {
      include = pUnit != null;                          // hechura: requiere precio
    } else {
      include = descripcion !== "";                     // otros: requiere descripción
    }

    if (!include) continue;

    const rawQty = n(row[`Cantidad ${i}`]);
    // METAL requiere cantidad explícita (gramos). Sin cantidad, el bloque se descarta
    // para evitar guardar 1g por defecto — la preview ya muestra una advertencia en este caso.
    // HECHURA / SERVICE / otros: quantity=1 es el valor por defecto razonable (1 operación).
    if (tipoRaw === "metal" && rawQty == null) continue;
    const cantidad = rawQty ?? 1;
    const mermaRaw = s(row[`Merma % ${i}`]);
    const mermaPercent = mermaRaw !== "" ? (parseFloat(mermaRaw.replace(",", ".")) || null) : null;

    blocks.push({
      type:        GUIDED_TIPO_TO_LINE_TYPE[tipoRaw] ?? "MANUAL",
      tipoRaw,
      monedaName:  s(row[`Moneda ${i}`]),
      descripcion,
      cantidad,
      unitPrice:   pUnit ?? 0,
      mermaPercent,
      bonifRaw:    s(row[`Bonif/Recargo ${i}`]),
    });
  }
  return blocks;
}

/**
 * Utilidad de compatibilidad visual — NO usada en lógica de importación.
 *
 * Elimina el prefijo del artículo padre de un nombre Guided concatenado.
 * "ANILLO SOLITARIO · Talle 16" → "Talle 16" (si parentName = "ANILLO SOLITARIO")
 * Si el nombre no empieza con el prefijo, se devuelve tal cual.
 *
 * La importación Guided NO usa esta función: el nombre se guarda tal cual viene
 * en Excel y la relación padre/variante se resuelve exclusivamente por SKU_Padre.
 */
export function extractVariantName(fullName: string, parentName: string): string {
  const prefix = parentName + " · ";
  return fullName.startsWith(prefix) ? fullName.slice(prefix.length).trim() : fullName;
}

/** Extrae hasta 4 pares nombre/valor de atributo de una fila Guided. */
function extractGuidedAttrPairs(row: Record<string, string>): { nombre: string; valor: string }[] {
  return [
    { nombre: s(row[GH.ATTR1_NOMBRE]), valor: s(row[GH.ATTR1_VALOR]) },
    { nombre: s(row[GH.ATTR2_NOMBRE]), valor: s(row[GH.ATTR2_VALOR]) },
    { nombre: s(row[GH.ATTR3_NOMBRE]), valor: s(row[GH.ATTR3_VALOR]) },
    { nombre: s(row[GH.ATTR4_NOMBRE]), valor: s(row[GH.ATTR4_VALOR]) },
  ].filter(p => p.nombre !== "" && p.valor !== "");
}

/** Actualiza los campos del artículo padre con valores heredados de una fila de variante. */
export async function applyGuidedInheritedFields(
  artId: string,
  row: Record<string, string>,
  catMap: Map<string, string>,
  groupMap: Map<string, string>,
  resolveSupplier: (raw: string) => string | null,
  resolveTaxIds: (row: Record<string, string>) => string[],
): Promise<void> {
  const catName = s(row[GH.CATEGORIA]);
  const grpName = s(row[GH.GRUPO]);
  const brand   = s(row[GH.MARCA]);
  const mfr     = s(row[GH.FABRICANTE]);
  const desc    = s(row[GH.DESCRIPCION]);

  // Mapas de traducción Excel label → DB enum (derivados de constantes de módulo)
  const STATUS_TO_DB    = new Map<string, string>(Object.entries(STATUS_LABEL).map(([db, xl]) => [normalizeStr(xl), db]));
  const STOCKMODE_TO_DB = new Map<string, string>(Object.entries(STOCK_MODE_LABEL).map(([db, xl]) => [normalizeStr(xl), db]));

  const update: Record<string, any> = {};

  // ── Campos de clasificación ───────────────────────────────────────────────
  if (catName) { const id = catMap.get(normalizeStr(catName));   if (id) update.categoryId = id; }
  if (grpName) { const id = groupMap.get(normalizeStr(grpName)); if (id) update.groupId    = id; }
  if (s(row[GH.PROVEEDOR])) {
    const id = resolveSupplier(s(row[GH.PROVEEDOR]));
    if (id) update.preferredSupplierId = id;
  }
  if (brand) update.brand = brand;
  if (mfr)   update.manufacturer = mfr;
  if (desc)  update.description  = desc;
  if (s(row[GH.CODIGO_PROVEEDOR])) update.supplierCode = s(row[GH.CODIGO_PROVEEDOR]);

  // ── Impuestos ─────────────────────────────────────────────────────────────
  const taxIds = resolveTaxIds(row);
  if (taxIds.length > 0) update.manualTaxIds = taxIds;

  // ── Estado y modo de stock ────────────────────────────────────────────────
  const statusRaw = s(row[GH.ESTADO]);
  if (statusRaw) {
    const db = STATUS_TO_DB.get(normalizeStr(statusRaw));
    if (db) update.status = db;
  }
  const smRaw = s(row[GH.MODO_STOCK]);
  if (smRaw) {
    const db = STOCKMODE_TO_DB.get(normalizeStr(smRaw));
    if (db) update.stockMode = db;
  }

  // ── Unidad de medida y flags del artículo ─────────────────────────────────
  if (s(row[GH.UNIDAD]))        update.unitOfMeasure     = s(row[GH.UNIDAD]);
  if (s(row[GH.EN_TIENDA]))     update.showInStore       = b(s(row[GH.EN_TIENDA]));
  if (s(row[GH.ACEPTA_DEV]))    update.isReturnable      = b(s(row[GH.ACEPTA_DEV]));
  if (s(row[GH.SIN_VARIANTES])) update.sellWithoutVariants = b(s(row[GH.SIN_VARIANTES]));

  // ── Dimensiones físicas ───────────────────────────────────────────────────
  const dimLargo = n(row[GH.DIM_LARGO]);
  const dimAncho = n(row[GH.DIM_ANCHO]);
  const dimAlto  = n(row[GH.DIM_ALTO]);
  if (dimLargo != null) update.dimensionLength = dimLargo;
  if (dimAncho != null) update.dimensionWidth  = dimAncho;
  if (dimAlto  != null) update.dimensionHeight = dimAlto;
  if (s(row[GH.DIM_UNIDAD])) update.dimensionUnit = s(row[GH.DIM_UNIDAD]);

  // ── Ajuste global de costo ────────────────────────────────────────────────
  const rawTipo  = s(row[GH.AJUSTE_TIPO]);
  const rawValor = s(row[GH.AJUSTE_VALOR]);
  const rawModo  = s(row[GH.AJUSTE_MODO]);
  if (rawTipo)  update.manualAdjustmentKind  = GUIDED_ADJ_TIPO_MAP[rawTipo.toLowerCase()]  ?? null;
  if (rawValor) update.manualAdjustmentValue = parseFloat(rawValor.replace(",", ".")) || null;
  if (rawModo)  update.manualAdjustmentType  = GUIDED_ADJ_MODO_MAP[rawModo.toLowerCase()]  ?? null;

  if (Object.keys(update).length > 0) {
    await prisma.article.update({ where: { id: artId }, data: update });
  }
}

// ── Validación de consistencia entre variantes del mismo padre ────────────────

/**
 * Campos "heredados" del padre que TODAS las variantes de un mismo SKU_Padre
 * deben declarar con el mismo valor no-vacío.
 *
 * Regla: si en un grupo de variantes hay ≥2 valores NO VACÍOS distintos para
 * el mismo campo → inconsistencia bloqueante.
 * Si una variante deja el campo vacío (= "no tocar") no cuenta como conflicto,
 * salvo que otra variante tenga un valor diferente al vacío.
 *
 * Excepción: si TODAS las ocurrencias no vacías coinciden, no hay problema.
 */
const PARENT_CONSISTENCY_FIELDS: { key: string; label: string }[] = [
  { key: GH.CATEGORIA,      label: "categorías" },
  { key: GH.GRUPO,          label: "grupos" },
  { key: GH.PROVEEDOR,      label: "proveedores" },
  { key: GH.MARCA,          label: "marcas" },
  { key: GH.FABRICANTE,     label: "fabricantes" },
  { key: GH.ESTADO,         label: "estados" },
  { key: GH.DESCRIPCION,    label: "descripciones" },
  // Campos del padre que pueden venir en filas de variante y deben ser consistentes
  { key: GH.IVA_1,          label: "IVA 1" },
  { key: GH.IVA_2,          label: "IVA 2" },
  { key: GH.IVA_3,          label: "IVA 3" },
  { key: GH.AJUSTE_TIPO,    label: "tipo de ajuste de costo" },
  { key: GH.AJUSTE_VALOR,   label: "valor de ajuste de costo" },
  { key: GH.AJUSTE_MODO,    label: "modo de ajuste de costo" },
  { key: GH.MODO_STOCK,     label: "modo de stock" },
  { key: GH.UNIDAD,         label: "unidad de medida" },
  { key: GH.EN_TIENDA,      label: "en tienda" },
  { key: GH.ACEPTA_DEV,     label: "acepta devolución" },
  { key: GH.SIN_VARIANTES,  label: "vender sin variantes" },
  // Dimensiones físicas: se aplican al padre y deben ser consistentes entre variantes
  { key: GH.DIM_LARGO,      label: "dimensión Largo" },
  { key: GH.DIM_ANCHO,      label: "dimensión Ancho" },
  { key: GH.DIM_ALTO,       label: "dimensión Alto" },
  { key: GH.DIM_UNIDAD,     label: "unidad de dimensión" },
];

/**
 * Serializa los bloques de costo de una fila en un string canónico para comparación.
 * Devuelve "" si la fila no tiene bloques (= hereda del padre, sin conflicto).
 * Función pura.
 */
export function costBlockSignature(row: Record<string, string>): string {
  const blocks = extractGuidedCostBlocks(row);
  if (blocks.length === 0) return "";
  return blocks
    .map(b =>
      [b.type, b.monedaName, b.descripcion,
       String(b.cantidad), String(b.unitPrice),
       b.mermaPercent != null ? String(b.mermaPercent) : "",
       b.bonifRaw,
      ].join("|"),
    )
    .join(";");
}

/**
 * Recorre las filas Guided y detecta inconsistencias entre variantes que
 * comparten el mismo SKU_Padre.
 *
 * Verifica:
 *  - Campos de nivel artículo (categoría, grupo, proveedor, etc.)
 *  - Composición de costo: todas las variantes que aporten bloques deben tener
 *    exactamente los mismos bloques. Si difieren, es un error bloqueante.
 *
 * @returns Map cuya clave es el SKU_Padre afectado y cuyo valor es un array
 *          de mensajes de error listos para mostrar al usuario.
 */
export function checkParentConsistency(
  rows: Record<string, string>[],
): Map<string, string[]> {
  // Agrupar valores por (skuPadre, fieldKey)
  const groups    = new Map<string, Map<string, Set<string>>>();
  // Firma de composición de costo por skuPadre (solo firmas no vacías)
  const costSigs  = new Map<string, Set<string>>();

  for (const row of rows) {
    const skuPadre = s(row[GH.SKU_PADRE] ?? "");
    if (!skuPadre) continue;   // artículo simple → ignorar

    if (!groups.has(skuPadre)) groups.set(skuPadre, new Map());
    const fieldMap = groups.get(skuPadre)!;

    for (const { key } of PARENT_CONSISTENCY_FIELDS) {
      const val = s(row[key] ?? "");
      if (!val) continue;   // celda vacía = "no tocar", no cuenta como conflicto
      if (!fieldMap.has(key)) fieldMap.set(key, new Set());
      fieldMap.get(key)!.add(val);
    }

    // Costo: recoger firma no vacía (vacía = hereda, no conflicta)
    const sig = costBlockSignature(row);
    if (sig) {
      if (!costSigs.has(skuPadre)) costSigs.set(skuPadre, new Set());
      costSigs.get(skuPadre)!.add(sig);
    }
  }

  // Detectar qué padres tienen al menos un campo con >1 valor distinto
  const result = new Map<string, string[]>();

  for (const [skuPadre, fieldMap] of groups) {
    const messages: string[] = [];
    for (const { key, label } of PARENT_CONSISTENCY_FIELDS) {
      const values = fieldMap.get(key);
      if (values && values.size > 1) {
        messages.push(
          `Las variantes del artículo padre "${skuPadre}" tienen ${label} distintos.`,
        );
      }
    }
    // Verificar consistencia de composición de costo
    const sigs = costSigs.get(skuPadre);
    if (sigs && sigs.size > 1) {
      messages.push(
        `Las variantes del artículo padre "${skuPadre}" tienen composiciones de costo distintas. ` +
        `Todas las variantes de un mismo artículo deben compartir la misma composición de costo.`,
      );
    }
    if (messages.length > 0) result.set(skuPadre, messages);
  }

  return result;
}

// ── Reconstrucción de padres implícitos ──────────────────────────────────────

/**
 * Campos del artículo padre que se verifican para consistencia cuando se intenta
 * reconstruir un padre implícito a partir de sus variantes.
 * Si varias variantes tienen valores DISTINTOS no vacíos para el mismo campo,
 * la reconstrucción falla con un conflicto en ese campo.
 */
/**
 * Campos del artículo padre (nivel artículo, no variante) que se chequean para
 * consistencia al reconstruir un padre implícito.
 *
 * EXCLUIDOS intencionalmente:
 *  - Campos de variante: Peso, Pto. Reposición, Cant. mínima/máxima/default,
 *    Favorito, Activo, Notas — pueden diferir legítimamente entre variantes.
 *  - Bloques de costo (Tipo/Moneda/Descripción/etc.): son del padre, pero
 *    algunas variantes exportan sus propios overrides → no deben bloquear
 *    la reconstrucción. El costo del padre implícito se extrae en buildImplicitParents
 *    usando el primer bloque "real" (Metal/Hechura/Producto/Servicio) encontrado.
 */
const IMPLICIT_PARENT_FIELDS: { key: string; label: string }[] = [
  { key: GH.DESCRIPCION,       label: "descripción" },
  { key: GH.ESTADO,            label: "estado" },
  { key: GH.CATEGORIA,         label: "categoría" },
  { key: GH.GRUPO,             label: "grupo" },
  { key: GH.PROVEEDOR,         label: "proveedor" },
  { key: GH.CODIGO_PROVEEDOR,  label: "código proveedor" },
  { key: GH.MARCA,             label: "marca" },
  { key: GH.FABRICANTE,        label: "fabricante" },
  { key: GH.IVA_1,             label: "IVA 1" },
  { key: GH.IVA_2,             label: "IVA 2" },
  { key: GH.IVA_3,             label: "IVA 3" },
  { key: GH.DIM_LARGO,         label: "Largo" },
  { key: GH.DIM_ANCHO,         label: "Ancho" },
  { key: GH.DIM_ALTO,          label: "Alto" },
  { key: GH.DIM_UNIDAD,        label: "unidad dim." },
  { key: GH.MODO_STOCK,        label: "modo de stock" },
  { key: GH.UNIDAD,            label: "unidad" },
  { key: GH.EN_TIENDA,         label: "en tienda" },
  { key: GH.ACEPTA_DEV,        label: "acepta devolución" },
  { key: GH.SIN_VARIANTES,     label: "vender sin variantes" },
  { key: GH.AJUSTE_TIPO,       label: "ajuste tipo" },
  { key: GH.AJUSTE_VALOR,      label: "ajuste valor" },
  { key: GH.AJUSTE_MODO,       label: "ajuste modo" },
];

/**
 * Intenta reconstruir artículos padre implícitos a partir de las variantes
 * que los referencian pero que no tienen fila propia en el archivo ni en la DB.
 *
 * Función pura — no requiere DB.
 * Usada en previewImportGuided, executeImportGuided y en tests.
 *
 * @param rows           Filas parseadas del archivo Guided
 * @param validParentSkus SKUs de padres ya conocidos (del archivo + de la DB).
 *                        Los SKUs que SÍ están aquí se ignoran (no necesitan reconstrucción).
 *
 * @returns Map cuya clave es el SKU_Padre huérfano y cuyo valor contiene:
 *   - row:      fila sintética con los campos heredables consistentes (listo para importar)
 *   - conflicts: mensajes de error si hay campos inconsistentes
 */
export function buildImplicitParents(
  rows: Record<string, string>[],
  validParentSkus: Set<string>,
): Map<string, { row: Record<string, string>; conflicts: string[] }> {
  // Encontrar SKU_Padre referenciados que NO están en validParentSkus
  const missingSkus = new Set<string>();
  for (const row of rows) {
    const skuPadre = s(row[GH.SKU_PADRE]);
    if (skuPadre && !validParentSkus.has(skuPadre)) missingSkus.add(skuPadre);
  }

  const result = new Map<string, { row: Record<string, string>; conflicts: string[] }>();
  if (missingSkus.size === 0) return result;

  for (const skuPadre of missingSkus) {
    const variantRows = rows.filter(r => s(r[GH.SKU_PADRE]) === skuPadre);
    const conflicts: string[] = [];

    // Fila sintética base: sin SKU_Padre (será artículo), SKU = skuPadre
    const reconstructed: Record<string, string> = {
      [GH.SKU_PADRE]: "",
      [GH.SKU]:       skuPadre,
      [GH.NOMBRE]:    skuPadre,   // nombre por defecto = SKU
    };

    // Verificar consistencia de los campos de nivel padre
    for (const { key, label } of IMPLICIT_PARENT_FIELDS) {
      const nonEmpty = [...new Set(
        variantRows.map(r => s(r[key] ?? "")).filter(v => v !== ""),
      )];
      if (nonEmpty.length > 1) {
        conflicts.push(`"${label}": valores distintos entre variantes (${nonEmpty.join(", ")}).`);
      } else if (nonEmpty.length === 1) {
        reconstructed[key] = nonEmpty[0];
      }
    }

    // Copiar bloques de costo desde la primera fila de variante que tenga un
    // bloque "real" (Metal/Hechura/Producto/Servicio). Esto permite que el
    // padre implícito tenga sus líneas de costo al ser importado.
    // No se usa para chequeo de consistencia (para no bloquear la reconstrucción
    // cuando algunas variantes tienen sus propios overrides de costo).
    const REAL_TYPES = new Set(["metal", "hechura", "hechura propia", "producto", "servicio"]);
    for (let ci = 1; ci <= 4; ci++) {
      const typeKey = `Tipo ${ci}`;
      const blockRow =
        variantRows.find(r => REAL_TYPES.has(s(r[typeKey] ?? "").toLowerCase())) ??
        variantRows.find(r => s(r[typeKey] ?? "") !== "");
      if (blockRow) {
        for (const fk of [
          `Tipo ${ci}`, `Moneda ${ci}`, `Descripción ${ci}`,
          `Cantidad ${ci}`, `Precio Unit. ${ci}`, `Merma % ${ci}`, `Bonif/Recargo ${ci}`,
        ]) {
          reconstructed[fk] = s(blockRow[fk] ?? "");
        }
      }
    }

    result.set(skuPadre, { row: reconstructed, conflicts });
  }

  return result;
}

// ── Preview Guided ────────────────────────────────────────────────────────────

/**
 * Extrae del archivo los SKUs de filas que actúan como artículo padre
 * (es decir, filas donde SKU_Padre está vacío y tienen SKU).
 *
 * Función pura — no requiere DB.
 * Usada en previewImportGuided y en tests.
 */
export function buildFileParentSkus(rows: Record<string, string>[]): Set<string> {
  const skus = new Set<string>();
  for (const row of rows) {
    if (!s(row[GH.SKU_PADRE])) {
      const sku = s(row[GH.SKU]);
      if (sku) skus.add(sku);
    }
  }
  return skus;
}

/**
 * Analiza un archivo Guided y devuelve un preview de lo que se importaría.
 * No ejecuta ningún cambio en la base de datos.
 *
 * Reglas de identificación:
 *  - `SKU Padre` vacío  → artículo simple (o artículo padre sin variantes)
 *  - `SKU Padre` con valor → variante (buscar padre por ese SKU)
 */
export async function previewImportGuided(
  buffer: Buffer,
  jewelryId: string,
): Promise<ImportPreviewResult> {
  const rows = parseGuidedRows(buffer);

  const [existingArtsRaw, existingVarSkusRaw] = await Promise.all([
    prisma.article.findMany({
      where: { jewelryId, deletedAt: null },
      select: { id: true, sku: true, name: true },
    }),
    prisma.articleVariant.findMany({
      where: { jewelryId, deletedAt: null },
      select: { id: true, sku: true },
    }),
  ]);

  const artBySku = new Map<string, { id: string; name: string }>();
  existingArtsRaw.forEach(a => { if (a.sku) artBySku.set(a.sku, { id: a.id, name: a.name }); });
  const varBySku = new Map<string, string>();
  existingVarSkusRaw.forEach(v => { if (v.sku) varBySku.set(v.sku, v.id); });

  // Mapa base de padres válidos (archivo + DB)
  const fileParentSkus  = buildFileParentSkus(rows);
  const validParentSkus = new Set<string>([...fileParentSkus, ...artBySku.keys()]);

  // Intentar reconstruir padres implícitos (padres no presentes pero referenciados)
  const implicitMap = buildImplicitParents(rows, validParentSkus);
  const reconstructable = new Map<string, Record<string, string>>();  // sin conflictos
  const conflicting     = new Map<string, string[]>();                // con conflictos

  for (const [sku, { row, conflicts }] of implicitMap) {
    if (conflicts.length === 0) {
      reconstructable.set(sku, row);
      validParentSkus.add(sku);   // ahora es padre válido
    } else {
      conflicting.set(sku, conflicts);
    }
  }

  // Pre-pass: detectar inconsistencias entre variantes del mismo padre
  const parentInconsistencies = checkParentConsistency(rows);

  const skusInFile = new Map<string, number>(); // sku → fila (1-based)
  const result: ImportPreviewRow[] = [];
  let artCount = 0, varCount = 0, validCount = 0, errCount = 0, overwriteCount = 0, warnCount = 0;

  for (let i = 0; i < rows.length; i++) {
    const row      = rows[i];
    const skuPadre = s(row[GH.SKU_PADRE]);
    const sku      = s(row[GH.SKU]);
    const nombre   = s(row[GH.NOMBRE]);
    const isVariant = skuPadre !== "";
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!sku)    errors.push("SKU es obligatorio.");
    if (!nombre) errors.push("Nombre es obligatorio.");
    if (sku && skuPadre && sku === skuPadre) errors.push("SKU_Padre no puede ser igual al SKU.");

    if (sku) {
      if (skusInFile.has(sku)) {
        errors.push(`SKU "${sku}" aparece duplicado (ya aparece en la fila ${skusInFile.get(sku)}).`);
      } else {
        skusInFile.set(sku, i + 1);
      }
    }

    if (isVariant) {
      varCount++;
      if (!validParentSkus.has(skuPadre)) {
        // El padre no existe y tampoco es reconstruible
        if (conflicting.has(skuPadre)) {
          const msgs = conflicting.get(skuPadre)!;
          errors.push(
            `El artículo padre "${skuPadre}" no existe y no puede reconstruirse automáticamente. Conflictos: ${msgs.join("; ")}`,
          );
        } else {
          errors.push(`El artículo padre "${skuPadre}" no existe en el archivo ni en el sistema.`);
        }
      } else if (reconstructable.has(skuPadre)) {
        // El padre no existe aún pero SERÁ creado automáticamente → warning informativo
        warnings.push(
          `El artículo padre "${skuPadre}" no existe aún — se creará automáticamente a partir de sus variantes.`,
        );
      }
      // Inconsistencias entre variantes del mismo padre (detectadas en pre-pass)
      const inconsistencyMsgs = parentInconsistencies.get(skuPadre);
      if (inconsistencyMsgs) errors.push(...inconsistencyMsgs);
    } else {
      artCount++;
    }

    // Validaciones de bloques de costo (Metal / Hechura) — aplica igual a padre y variante
    warnings.push(...validateCostBlockWarnings(row));

    // Validación de inconsistencia: variante con Origen costo = "Propio" pero sin bloques.
    // Es un error de datos: la fila afirma tener composición propia pero no la define.
    if (isVariant) {
      const origenCostoRaw = s(row[GH.ORIGEN_COSTO] ?? "").toLowerCase();
      if (origenCostoRaw === "propio" && extractGuidedCostBlocks(row).length === 0) {
        errors.push(
          "'Origen costo = Propio' pero no hay bloques de composición de costo. " +
          "Agregá al menos un bloque o cambiá el origen a 'Hereda del padre'.",
        );
      }
    }

    let existingId: string | undefined;
    if (isVariant && sku)  existingId = varBySku.get(sku);
    if (!isVariant && sku) existingId = artBySku.get(sku)?.id;

    // Prioridad: error > overwrite (existente) > warning > valid
    const status: ImportPreviewRow["status"] =
      errors.length > 0   ? "error"    :
      existingId          ? "overwrite" :
      warnings.length > 0 ? "warning"  : "valid";

    if (errors.length > 0)         errCount++;
    else if (existingId)           overwriteCount++;
    else if (warnings.length > 0)  warnCount++;
    else                           validCount++;

    const attrPairs = extractGuidedAttrPairs(row);
    result.push({
      index: i + 1,
      isVariant,
      parentCode: skuPadre,
      displayName: isVariant ? `[Variante] ${nombre}` : nombre,
      status,
      errors,
      warnings,
      existingId,
      attributes: attrPairs.length > 0
        ? Object.fromEntries(attrPairs.map(p => [p.nombre, p.valor]))
        : undefined,
    });
  }

  // Filas sintéticas para padres implícitos (aparecen al final de la tabla)
  let synIdx = rows.length + 1;
  for (const [sku] of reconstructable) {
    artCount++;
    validCount++;
    result.push({
      index: synIdx++,
      isVariant: false,
      parentCode: "",
      displayName: `[Padre implícito] ${sku}`,
      status: "implicit_parent",
      errors: [],
      warnings: [`Se reconstruirá automáticamente el artículo padre "${sku}" a partir de sus variantes.`],
    });
  }
  for (const [sku, msgs] of conflicting) {
    errCount++;
    result.push({
      index: synIdx++,
      isVariant: false,
      parentCode: "",
      displayName: `[Padre implícito] ${sku}`,
      status: "error",
      errors: [`No se puede reconstruir el padre "${sku}". Conflictos: ${msgs.join("; ")}`],
      warnings: [],
    });
  }

  return {
    total: rows.length,
    articles: artCount,
    variants: varCount,
    valid: validCount,
    errors: errCount,
    overwrite: overwriteCount,
    warnings: warnCount,
    implicitParents: reconstructable.size,
    rows: result,
  };
}

// ── saveCostLinesForArticle ───────────────────────────────────────────────────

/** Contexto de catálogos pre-cargados que saveCostLinesForArticle necesita. */
export type CostLinesContext = {
  jewelryId:           string;
  currByCode:          Map<string, string>;
  currByName:          Map<string, string>;
  metalVariantByLabel: Map<string, string>;
};

/**
 * Persiste la composición de costo de un artículo a partir de los bloques
 * detectados en una fila Guided (extractGuidedCostBlocks).
 *
 * REGLA: el costo se guarda SIEMPRE en el artículo padre (variantId = null en DB).
 * Las variantes NO tienen composición propia — todas heredan del padre.
 *
 * Cuando se llama desde una fila de variante (variantId != null):
 *   - Si la fila NO trae bloques → la variante hereda del padre (sin acción).
 *   - Si el campo "Origen costo" dice "Hereda del padre" → ídem, sin acción.
 *   - Si la fila SÍ trae bloques propios → se guardan en el PADRE (idempotente
 *     porque checkParentConsistency garantizó que todos los bloques son iguales).
 *
 * Cuando se llama desde el artículo padre (variantId = null):
 *   - Sin bloques → se preservan las líneas existentes (sin cambio).
 *   - Con bloques → se reemplazan las líneas del padre.
 */
export async function saveCostLinesForArticle(
  artId:     string,
  row:       Record<string, string>,
  variantId: string | null,
  ctx:       CostLinesContext,
): Promise<void> {
  const { jewelryId, currByCode, currByName, metalVariantByLabel } = ctx;
  const blocks = extractGuidedCostBlocks(row);

  if (variantId !== null) {
    // Sin bloques → la variante no tiene datos de costo: preservar las líneas existentes del padre.
    if (blocks.length === 0) return;

    // Con bloques → reemplazar las líneas del padre.
    //
    // NOTA SOBRE "Hereda del padre":
    //   El export de artículos CON variantes no genera fila propia para el padre —
    //   solo genera filas de variante, todas con 'origenCosto = "Hereda del padre"'.
    //   Los bloques en esas filas SON los bloques del padre (exportados como referencia).
    //   Si se bloquea el update cuando isExplicitlyInherited=true, las cost lines del padre
    //   nunca se actualizan en un reimport → BUG reportado.
    //
    //   El flag "Hereda del padre" solo indica que la variante no tiene composición PROPIA;
    //   NO implica que el padre no deba actualizarse. Todas las cost lines se guardan
    //   siempre en el padre (variantId nunca se persiste en ArticleCostLine), por lo
    //   que "Propio" y "Hereda del padre" tienen el mismo efecto en la importación.
    await prisma.articleCostLine.deleteMany({
      where: { articleId: artId, jewelryId },
    });
    // Continúa al bloque de creación abajo
  } else {
    // Artículo padre: si no hay bloques, preservar las existentes
    if (blocks.length === 0) return;
    // Reemplazar todas las líneas del artículo
    await prisma.articleCostLine.deleteMany({
      where: { articleId: artId, jewelryId },
    });
  }

  for (let si = 0; si < blocks.length; si++) {
    const blk = blocks[si];

    // ── Resolver moneda ───────────────────────────────────────────────────
    let currId: string | null = null;
    if (blk.monedaName) {
      const { code, nameHint } = parseCurrencyRef(blk.monedaName);
      currId =
        currByCode.get(code.toUpperCase())
        ?? currByName.get(normalizeStr(nameHint))
        ?? currByName.get(normalizeStr(blk.monedaName))
        ?? null;
      if (!currId) {
        console.warn(`[Guided Import] Bloque ${si + 1}: moneda "${blk.monedaName}" no encontrada — se usará la base del tenant.`);
      }
    }

    // Resolver metalVariantId para tipo METAL
    let metalVariantId: string | null = null;
    if (blk.type === "METAL" && blk.descripcion) {
      metalVariantId = metalVariantByLabel.get(normalizeStr(blk.descripcion)) ?? null;
    }

    // Parsear bonificación/recargo — formato: "-10%" | "+500" | "-500%" | "+10%" | ""
    let lineAdjKind: string | undefined;
    let lineAdjType: string | undefined;
    let lineAdjValue: number | undefined;
    if (blk.bonifRaw) {
      const isNeg = blk.bonifRaw.startsWith("-");
      const isPos = blk.bonifRaw.startsWith("+");
      const isPct = blk.bonifRaw.endsWith("%");
      const numStr = blk.bonifRaw.replace(/^[+-]/, "").replace(/%$/, "").trim();
      const val = parseFloat(numStr.replace(",", "."));
      if ((isNeg || isPos) && isFinite(val)) {
        lineAdjKind  = isNeg ? "BONUS" : "SURCHARGE";
        lineAdjType  = isPct ? "PERCENTAGE" : "FIXED_AMOUNT";
        lineAdjValue = val;
      }
    }

    try {
      await prisma.articleCostLine.create({
        data: {
          articleId:      artId,
          jewelryId,
          // variantId omitido: las líneas de costo se guardan SIEMPRE en el padre
          type:           blk.type as any,
          label:          blk.descripcion,
          quantity:       blk.cantidad,
          unitValue:      blk.unitPrice,
          currencyId:     currId ?? undefined,
          mermaPercent:   blk.mermaPercent ?? undefined,
          metalVariantId: metalVariantId ?? undefined,
          lineAdjKind:    lineAdjKind  ?? "",
          lineAdjType:    lineAdjType  ?? "",
          lineAdjValue:   lineAdjValue ?? undefined,
          sortOrder:      si,
        },
      });
    } catch (e: any) {
      console.warn(`[Guided Import] Cost line ${si + 1}:`, e?.message ?? e);
    }
  }
}

// ── Execute Guided ────────────────────────────────────────────────────────────

/**
 * Ejecuta la importación de un archivo Guided y aplica los cambios a la DB.
 *
 * - Filas sin SKU_Padre → crean/actualizan artículo simple.
 * - Filas con SKU_Padre → crean/actualizan variante del artículo padre identificado por SKU_Padre.
 * - Override de variante: solo weightOverride (las variantes no tienen precio propio).
 *   Se escribe SOLO si la celda tiene valor (no se pisa con null).
 * - Campos heredados (categoría, grupo, proveedor, etc.) se aplican al artículo padre.
 */
export async function executeImportGuided(
  buffer: Buffer,
  jewelryId: string,
  options: { onConflict: "skip" | "update"; userId?: string; fileName?: string },
): Promise<ImportCommitResult> {
  const rows = parseGuidedRows(buffer);

  // ── Pre-cargar catálogos ──────────────────────────────────────────────────
  const [
    categoriesRaw, groupsRaw, suppliersRaw, taxesRaw,
    existingArtsRaw, existingVarSkusRaw,
    currenciesRaw, metalVariantsRaw,
  ] = await Promise.all([
    prisma.articleCategory.findMany({
      where: { jewelryId, deletedAt: null }, select: { id: true, name: true },
    }),
    prisma.articleGroup.findMany({
      where: { jewelryId, deletedAt: null }, select: { id: true, name: true },
    }),
    prisma.commercialEntity.findMany({
      where: { jewelryId, deletedAt: null, isSupplier: true, isActive: true },
      select: { id: true, displayName: true, code: true },
    }),
    prisma.tax.findMany({
      where: { jewelryId, deletedAt: null }, select: { id: true, name: true },
    }),
    prisma.article.findMany({
      where: { jewelryId, deletedAt: null },
      select: { id: true, sku: true, name: true, categoryId: true },
    }),
    prisma.articleVariant.findMany({
      where: { jewelryId, deletedAt: null },
      select: { id: true, sku: true, articleId: true },
    }),
    prisma.currency.findMany({
      where: { jewelryId, deletedAt: null, isActive: true },
      select: { id: true, name: true, code: true },
    }),
    prisma.metalVariant.findMany({
      where: { deletedAt: null, metal: { deletedAt: null } },
      select: { id: true, name: true, metal: { select: { name: true } } },
    }),
  ]);

  const catMap         = new Map(categoriesRaw.map(c => [normalizeStr(c.name), c.id]));
  const groupMap       = new Map(groupsRaw.map(g => [normalizeStr(g.name), g.id]));
  const supplierByName = new Map(suppliersRaw.map(sp => [normalizeStr(sp.displayName), sp.id]));
  const supplierByCode = new Map(suppliersRaw.map(sp => [sp.code.toLowerCase(), sp.id]));
  const taxByName      = new Map(taxesRaw.map(t => [normalizeStr(t.name), t.id]));

  // Mapas inversos: Excel label → DB enum
  const STATUS_TO_DB    = new Map<string, string>(Object.entries(STATUS_LABEL).map(([db, xl]) => [normalizeStr(xl), db]));
  const STOCKMODE_TO_DB = new Map<string, string>(Object.entries(STOCK_MODE_LABEL).map(([db, xl]) => [normalizeStr(xl), db]));

  // Artículos por SKU (se actualiza durante el import)
  const artBySku = new Map<string, { id: string; name: string; categoryId: string | null }>();
  existingArtsRaw.forEach(a => { if (a.sku) artBySku.set(a.sku, { id: a.id, name: a.name, categoryId: a.categoryId }); });

  // Variantes por SKU (id) y su articleId actual en DB (para detectar re-parentesco)
  const varBySku       = new Map<string, string>(); // sku → variant id
  const varArticleById = new Map<string, string>(); // variant id → articleId actual en DB
  existingVarSkusRaw.forEach(v => {
    if (v.sku) {
      varBySku.set(v.sku, v.id);
      varArticleById.set(v.id, v.articleId);
    }
  });

  // Monedas por nombre (y por código como fallback)
  const currByName = new Map<string, string>();
  const currByCode = new Map<string, string>();
  for (const c of currenciesRaw) {
    currByName.set(normalizeStr(c.name), c.id);
    currByCode.set(c.code.toUpperCase(), c.id);
  }

  // Variantes de metal por label compuesto "Metal · Variante" (y solo por nombre de variante como fallback)
  const metalVariantByLabel = new Map<string, string>();
  for (const mv of metalVariantsRaw) {
    const fullLabel = `${(mv.metal as any).name} · ${mv.name}`;
    metalVariantByLabel.set(normalizeStr(fullLabel), mv.id);
    metalVariantByLabel.set(normalizeStr(mv.name), mv.id);
  }

  // Generador de código único para artículos nuevos
  let seqOffset = 0;
  async function nextArtCode(): Promise<string> {
    const base = await prisma.article.count({ where: { jewelryId } });
    let num = base + seqOffset + 1;
    while (true) {
      const candidate = `ART-${String(num).padStart(4, "0")}`;
      const exists = await prisma.article.findFirst({ where: { jewelryId, code: candidate }, select: { id: true } });
      if (!exists) { seqOffset++; return candidate; }
      num++;
    }
  }

  function resolveSupplier(raw: string): string | null {
    if (!raw) return null;
    const parts = raw.split("·").map(p => p.trim());
    if (parts.length >= 2) {
      const byCode = supplierByCode.get(parts[0].toLowerCase());
      if (byCode) return byCode;
    }
    return supplierByCode.get(raw.toLowerCase()) ?? supplierByName.get(normalizeStr(raw)) ?? null;
  }

  function resolveTaxIds(row: Record<string, string>): string[] {
    return [s(row[GH.IVA_1]), s(row[GH.IVA_2]), s(row[GH.IVA_3])]
      .filter(Boolean)
      .map(name => taxByName.get(normalizeStr(name)) ?? null)
      .filter((id): id is string => id !== null);
  }

  // Caché de ejes de categoría para guardar atributos
  const catAxesCache = new Map<string, CatAxis[]>();
  async function getCatAxes(catId: string): Promise<CatAxis[]> {
    if (!catAxesCache.has(catId)) {
      catAxesCache.set(catId, await getEffectiveCategoryAxes(catId, jewelryId));
    }
    return catAxesCache.get(catId)!;
  }

  async function saveVariantAttr(variantId: string, catId: string, row: Record<string, string>): Promise<void> {
    const pairs = extractGuidedAttrPairs(row);
    if (pairs.length === 0) return;
    const axes = await getCatAxes(catId);
    const byNorm = new Map<string, CatAxis>();
    for (const ax of axes) {
      byNorm.set(normalizeStr(ax.definition.name), ax);
      byNorm.set(normalizeStr(ax.definition.code), ax);
    }
    for (const { nombre, valor } of pairs) {
      const axis = byNorm.get(normalizeStr(nombre));
      if (!axis) continue;
      const val = normalizeAttrValue(valor, axis.definition.inputType);
      try {
        await prisma.articleVariantAttributeValue.upsert({
          where:  { variantId_assignmentId: { variantId, assignmentId: axis.id } },
          create: { jewelryId, variantId, assignmentId: axis.id, value: val },
          update: { value: val },
        });
      } catch (e: any) {
        console.warn(`[Guided Import] Atributo "${nombre}":`, e?.message ?? e);
      }
    }
  }

  // Contexto pre-cargado para la función de nivel de módulo saveCostLinesForArticle
  const costCtx: CostLinesContext = { jewelryId, currByCode, currByName, metalVariantByLabel };

  // Pre-pass: detectar inconsistencias entre variantes del mismo padre
  const parentInconsistencies = checkParentConsistency(rows);

  // Construir padres implícitos (sin fila propia ni existencia en DB)
  const exFileParents   = buildFileParentSkus(rows);
  const exValidParents  = new Set<string>([...exFileParents, ...artBySku.keys()]);
  const implicitForExec = buildImplicitParents(rows, exValidParents);
  // Filas sintéticas para padres implícitos sin conflictos (se insertan en el pass 2)
  const implicitExecRows = [...implicitForExec.entries()]
    .filter(([, { conflicts }]) => conflicts.length === 0)
    .map(([, { row }], n) => ({ row, i: rows.length + n }));

  const results: ImportCommitRow[] = [];
  let created = 0, updated = 0, skipped = 0, errors = 0;

  // Three-pass: artículos explícitos → padres implícitos → variantes.
  // Garantiza que artBySku tenga todos los padres antes de procesar variantes.
  const rowsOrdered = [
    ...rows.map((r, i) => ({ row: r, i })).filter(({ row: r }) => !s(r[GH.SKU_PADRE])),
    ...implicitExecRows,
    ...rows.map((r, i) => ({ row: r, i })).filter(({ row: r }) =>  s(r[GH.SKU_PADRE])),
  ];

  // ── Diagnóstico inicial ──────────────────────────────────────────────────────
  {
    const variantGroups = new Map<string, number>();
    for (const row of rows) {
      const sp = s(row[GH.SKU_PADRE]);
      if (sp) variantGroups.set(sp, (variantGroups.get(sp) ?? 0) + 1);
    }
    console.log(`[Guided Import] Iniciando: ${rows.length} filas, ${variantGroups.size} grupo(s) de variantes`);
    if (variantGroups.size > 0) {
      console.log(`[Guided Import] Grupos: ${[...variantGroups.entries()].map(([k, v]) => `${k}(×${v})`).join(", ")}`);
    }
    if (implicitExecRows.length > 0) {
      console.log(`[Guided Import] Padres implícitos a crear: ${implicitExecRows.map(r => s(r.row[GH.SKU])).join(", ")}`);
    }
    const conflicting = [...implicitForExec.entries()].filter(([, v]) => v.conflicts.length > 0);
    if (conflicting.length > 0) {
      console.warn(`[Guided Import] Padres implícitos CON CONFLICTOS (no se crearán): ${conflicting.map(([k]) => k).join(", ")}`);
    }
  }

  for (const { row, i } of rowsOrdered) {
    const skuPadre    = s(row[GH.SKU_PADRE]);
    const sku         = s(row[GH.SKU]);
    const nombre      = s(row[GH.NOMBRE]);
    const isVariant   = skuPadre !== "";
    // Filas sintéticas de padres implícitos tienen índice ≥ rows.length
    const isImplicit  = i >= rows.length;

    console.log(`[Guided Import] Fila ${i + 1}: SKU="${sku}" SKU_Padre="${skuPadre}" tipo=${isVariant ? "variante" : isImplicit ? "padre implícito" : "artículo"}`);

    if (!sku) {
      results.push({ index: i + 1, displayName: nombre || "(sin nombre)", status: "error", errors: ["SKU es obligatorio."] });
      errors++; continue;
    }
    if (!nombre) {
      results.push({ index: i + 1, displayName: sku, status: "error", errors: ["Nombre es obligatorio."] });
      errors++; continue;
    }

    if (sku && skuPadre && sku === skuPadre) {
      results.push({ index: i + 1, displayName: nombre || sku, status: "error", errors: ["SKU_Padre no puede ser igual al SKU."] });
      errors++; continue;
    }

    if (isVariant) {
      // ── VARIANTE ─────────────────────────────────────────────────────────

      // Bloquear variantes cuyo padre tiene campos estructurales inconsistentes
      const inconsistencyMsgs = parentInconsistencies.get(skuPadre);
      if (inconsistencyMsgs) {
        console.warn(`[Guided Import] Variante "${sku}": padre "${skuPadre}" tiene inconsistencias → error`);
        results.push({ index: i + 1, displayName: `[Variante] ${nombre || sku}`, status: "error", errors: inconsistencyMsgs });
        errors++; continue;
      }

      const parent = artBySku.get(skuPadre);
      if (!parent) {
        console.warn(`[Guided Import] Variante "${sku}": SKU_Padre="${skuPadre}" no encontrado en artBySku (${artBySku.size} entradas)`);
        // Explicar por qué el padre no existe: conflictos de reconstrucción o padre faltante
        const reconflicts = implicitForExec.get(skuPadre)?.conflicts;
        const parentErrMsg = reconflicts && reconflicts.length > 0
          ? `El artículo padre "${skuPadre}" no pudo reconstruirse automáticamente. Conflictos: ${reconflicts.join("; ")}`
          : `El artículo padre "${skuPadre}" no existe en el archivo ni en el sistema.`;
        results.push({ index: i + 1, displayName: `[Variante] ${nombre}`, status: "error", errors: [parentErrMsg] });
        errors++; continue;
      }

      console.log(`[Guided Import] Variante "${sku}": padre "${skuPadre}" → id=${parent.id}`);

      // El nombre se guarda tal cual viene en Excel (puede ser concatenado o no).
      // La relación padre/variante se resuelve exclusivamente por SKU_Padre — no por parsing del nombre.
      const variantName   = nombre || sku;
      const existingVarId = varBySku.get(sku);

      if (existingVarId && options.onConflict === "skip") {
        results.push({ index: i + 1, displayName: `[Variante] ${variantName}`, status: "skipped", id: existingVarId });
        skipped++; continue;
      }

      const weightOverrideV = n(row[GH.PESO]);
      const reorderPoint    = n(row[GH.PTO_REPOS]);
      const minSaleQty      = n(row[GH.CANT_MIN]);
      const maxSaleQty      = n(row[GH.CANT_MAX]);
      const defaultQty      = n(row[GH.CANT_DEFAULT]);
      const activoStr       = s(row[GH.ACTIVO]);
      const isActive        = activoStr ? b(activoStr) : undefined;
      const favoritoStr     = s(row[GH.FAVORITO]);
      const isFavorite      = favoritoStr ? b(favoritoStr) : undefined;
      const notesV          = s(row[GH.NOTAS]) || undefined;

      // Solo escribir campos con valor (no pisar con null).
      // SIEMPRE incluir articleId para re-vincular la variante al padre correcto
      // aunque ya existiese bajo otro padre (re-parentesco explícito vía SKU_Padre).
      const varUpdate: Record<string, any> = { name: variantName, articleId: parent.id };
      if (weightOverrideV != null)      varUpdate.weightOverride        = weightOverrideV;
      if (reorderPoint != null)         varUpdate.reorderPoint          = reorderPoint;
      if (minSaleQty != null)           varUpdate.minSaleQuantity       = minSaleQty;
      if (maxSaleQty != null)           varUpdate.maxSaleQuantity       = maxSaleQty;
      if (defaultQty != null)           varUpdate.defaultQuantity       = defaultQty;
      if (isActive != null)             varUpdate.isActive              = isActive;
      if (isFavorite != null)           varUpdate.isFavorite            = isFavorite;
      if (notesV != null)               varUpdate.notes                 = notesV;

      try {
        // Guardar PRIMERO la variante, LUEGO los campos heredados y atributos.
        // results.push se hace al FINAL del try para que el catch sea la
        // única entrada en caso de error (sin duplicados creado+error).
        let variantId: string;
        let isNewVariant: boolean;

        if (existingVarId) {
          const prevArticleId = varArticleById.get(existingVarId);
          if (prevArticleId && prevArticleId !== parent.id) {
            console.warn(`[Guided Import] Variante "${sku}": re-parentesco ${prevArticleId} → ${parent.id} (SKU_Padre="${skuPadre}")`);
          }
          await prisma.articleVariant.update({ where: { id: existingVarId }, data: varUpdate });
          variantId = existingVarId;
          isNewVariant = false;
        } else {
          // Verificar si existe una variante soft-deleted con el mismo SKU bajo el mismo padre.
          // Esto ocurre cuando la variante fue eliminada individualmente (no por cascade del padre).
          // En ese caso: restaurar en vez de crear para preservar el `code` original y evitar
          // la violación del constraint @@unique([articleId, code]).
          const softDeletedBySku = sku
            ? await prisma.articleVariant.findFirst({
                where: { articleId: parent.id, sku, deletedAt: { not: null } },
                select: { id: true },
              })
            : null;

          if (softDeletedBySku) {
            console.log(`[Guided Import] Variante "${sku}": soft-deleted encontrada bajo mismo padre → restaurando id=${softDeletedBySku.id}`);
            await prisma.articleVariant.update({
              where: { id: softDeletedBySku.id },
              data: { deletedAt: null, isActive: isActive ?? true, ...varUpdate },
            });
            variantId = softDeletedBySku.id;
            varBySku.set(sku, variantId);
          } else {
            // Calcular sortOrder y código evitando colisión con variantes soft-deleted
            // bajo el mismo padre (@@unique([articleId, code]) no ignora deletedAt).
            const sortOrder = await prisma.articleVariant.count({ where: { articleId: parent.id, deletedAt: null } });
            let genCode = `VAR-${String(sortOrder + 1).padStart(3, "0")}`;
            // Si el código generado colisiona con una variante soft-deleted, buscar el siguiente libre
            const codeUsed = new Set(
              (await prisma.articleVariant.findMany({
                where: { articleId: parent.id },
                select: { code: true },
              })).map(v => v.code)
            );
            if (codeUsed.has(genCode)) {
              let seq = sortOrder + 2;
              while (codeUsed.has(`VAR-${String(seq).padStart(3, "0")}`)) seq++;
              genCode = `VAR-${String(seq).padStart(3, "0")}`;
            }
            const newVar = await prisma.articleVariant.create({
              data: {
                jewelryId, articleId: parent.id, sku,
                code: genCode,
                name: variantName,
                isActive: isActive ?? true,
                notes: notesV ?? "",
                sortOrder,
                ...(weightOverrideV != null      ? { weightOverride: weightOverrideV } : {}),
                ...(reorderPoint != null         ? { reorderPoint }               : {}),
                ...(minSaleQty != null           ? { minSaleQuantity: minSaleQty }   : {}),
                ...(maxSaleQty != null           ? { maxSaleQuantity: maxSaleQty }   : {}),
                ...(defaultQty != null           ? { defaultQuantity: defaultQty }   : {}),
                ...(isFavorite != null           ? { isFavorite }                    : {}),
              },
              select: { id: true },
            });
            variantId = newVar.id;
            varBySku.set(sku, variantId);
          }
          isNewVariant = true;
        }

        // Aplicar campos heredados al artículo padre
        await applyGuidedInheritedFields(parent.id, row, catMap, groupMap, resolveSupplier, resolveTaxIds);

        // Actualizar categoryId en caché si cambió
        const newCatName = s(row[GH.CATEGORIA]);
        if (newCatName) {
          const newCatId = catMap.get(normalizeStr(newCatName)) ?? null;
          if (newCatId) artBySku.set(skuPadre, { ...parent, categoryId: newCatId });
        }

        // Guardar atributos de variante
        const catIdForAttrs = artBySku.get(skuPadre)?.categoryId ?? parent.categoryId;
        if (catIdForAttrs) await saveVariantAttr(variantId, catIdForAttrs, row);

        // Guardar composición de costo de la variante (si trae bloques propios)
        // Bloques vacíos = la variante hereda la composición del artículo padre.
        await saveCostLinesForArticle(parent.id, row, variantId, costCtx);

        // ── resultado final (único push por variante) ───────────────────
        if (isNewVariant) {
          console.log(`[Guided Import] Variante "${sku}" → CREADA id=${variantId} articleId=${parent.id}`);
          results.push({ index: i + 1, displayName: `[Variante] ${variantName}`, status: "created", id: variantId });
          created++;
        } else {
          console.log(`[Guided Import] Variante "${sku}" → ACTUALIZADA id=${variantId} articleId=${parent.id}`);
          results.push({ index: i + 1, displayName: `[Variante] ${variantName}`, status: "updated", id: variantId });
          updated++;
        }

      } catch (e: any) {
        console.error(`[Guided Import] Variante "${sku}": ERROR →`, e?.message ?? e);
        results.push({ index: i + 1, displayName: `[Variante] ${variantName}`, status: "error", errors: [e?.message ?? "Error desconocido"] });
        errors++;
      }

    } else {
      // ── ARTÍCULO SIMPLE ──────────────────────────────────────────────────
      const existingArt = artBySku.get(sku);

      if (existingArt && options.onConflict === "skip") {
        results.push({ index: i + 1, displayName: nombre, status: "skipped", id: existingArt.id });
        skipped++; continue;
      }

      const catName  = s(row[GH.CATEGORIA]);
      const catId    = catName ? (catMap.get(normalizeStr(catName)) ?? null) : null;
      const grpName  = s(row[GH.GRUPO]);
      const groupId  = grpName ? (groupMap.get(normalizeStr(grpName)) ?? null) : null;
      const supId    = resolveSupplier(s(row[GH.PROVEEDOR]));
      const taxIds   = resolveTaxIds(row);

      const statusRaw = s(row[GH.ESTADO]);
      const status    = statusRaw ? STATUS_TO_DB.get(normalizeStr(statusRaw)) : undefined;
      const smRaw     = s(row[GH.MODO_STOCK]);
      const stockMode = smRaw ? STOCKMODE_TO_DB.get(normalizeStr(smRaw)) : undefined;

      const weightV  = n(row[GH.PESO]);
      const repoPt   = n(row[GH.PTO_REPOS]);
      const cantMin  = n(row[GH.CANT_MIN]);
      const cantMax  = n(row[GH.CANT_MAX]);
      const cantDef  = n(row[GH.CANT_DEFAULT]);

      // Solo escribir campos con valor
      const artUpdate: Record<string, any> = { name: nombre };
      if (s(row[GH.DESCRIPCION]))   artUpdate.description   = s(row[GH.DESCRIPCION]);
      if (status)                   artUpdate.status        = status;
      if (catId != null)            artUpdate.categoryId    = catId;
      if (supId != null)            artUpdate.preferredSupplierId = supId;
      if (s(row[GH.MARCA]))            artUpdate.brand            = s(row[GH.MARCA]);
      if (s(row[GH.FABRICANTE]))       artUpdate.manufacturer     = s(row[GH.FABRICANTE]);
      if (s(row[GH.CODIGO_PROVEEDOR])) artUpdate.supplierCode     = s(row[GH.CODIGO_PROVEEDOR]);
      if (stockMode)                artUpdate.stockMode     = stockMode;
      if (s(row[GH.UNIDAD]))        artUpdate.unitOfMeasure = s(row[GH.UNIDAD]);
      if (weightV != null)          artUpdate.weight        = weightV;
      if (repoPt != null)           artUpdate.reorderPoint  = repoPt;
      if (cantMin != null)          artUpdate.minSaleQuantity = cantMin;
      if (cantMax != null)          artUpdate.maxSaleQuantity = cantMax;
      if (cantDef != null)          artUpdate.defaultQuantity = cantDef;
      if (s(row[GH.ACTIVO]))        artUpdate.isActive      = b(s(row[GH.ACTIVO]));
      if (s(row[GH.FAVORITO]))      artUpdate.isFavorite    = b(s(row[GH.FAVORITO]));
      if (s(row[GH.EN_TIENDA]))     artUpdate.showInStore   = b(s(row[GH.EN_TIENDA]));
      if (s(row[GH.ACEPTA_DEV]))    artUpdate.isReturnable  = b(s(row[GH.ACEPTA_DEV]));
      if (s(row[GH.SIN_VARIANTES])) artUpdate.sellWithoutVariants = b(s(row[GH.SIN_VARIANTES]));
      if (s(row[GH.NOTAS]))         artUpdate.notes         = s(row[GH.NOTAS]);
      // Dimensiones físicas
      {
        const largo = n(row[GH.DIM_LARGO]), ancho = n(row[GH.DIM_ANCHO]), alto = n(row[GH.DIM_ALTO]);
        if (largo != null)              artUpdate.dimensionLength = largo;
        if (ancho != null)              artUpdate.dimensionWidth  = ancho;
        if (alto  != null)              artUpdate.dimensionHeight = alto;
        if (s(row[GH.DIM_UNIDAD]))      artUpdate.dimensionUnit   = s(row[GH.DIM_UNIDAD]);
      }
      if (taxIds.length > 0)        artUpdate.manualTaxIds  = taxIds;
      // Ajuste global de costo
      {
        const rawTipo  = s(row[GH.AJUSTE_TIPO]);
        const rawValor = s(row[GH.AJUSTE_VALOR]);
        const rawModo  = s(row[GH.AJUSTE_MODO]);
        if (rawTipo)  artUpdate.manualAdjustmentKind  = GUIDED_ADJ_TIPO_MAP[rawTipo.toLowerCase()]  ?? null;
        if (rawValor) artUpdate.manualAdjustmentValue = parseFloat(rawValor.replace(",", ".")) || null;
        if (rawModo)  artUpdate.manualAdjustmentType  = GUIDED_ADJ_MODO_MAP[rawModo.toLowerCase()]  ?? null;
      }

      try {
        let artId: string;
        if (existingArt) {
          await prisma.article.update({ where: { id: existingArt.id }, data: artUpdate });
          artId = existingArt.id;
          artBySku.set(sku, { id: artId, name: nombre, categoryId: catId ?? existingArt.categoryId });
          await saveCostLinesForArticle(artId, row, null, costCtx);
          const updDN = isImplicit ? `[Padre implícito] ${nombre}` : nombre;
          console.log(`[Guided Import] Artículo "${sku}" → ACTUALIZADO id=${artId}${isImplicit ? " (padre implícito)" : ""}`);
          results.push({ index: i + 1, displayName: updDN, status: "updated", id: artId });
          updated++;
        } else {
          const code = await nextArtCode();
          const newArt = await prisma.article.create({
            data: {
              jewelryId, code, sku,
              name:        nombre,
              description: s(row[GH.DESCRIPCION]),
              status:      (status as any) ?? "DRAFT",
              categoryId:          catId    ?? undefined,
              preferredSupplierId: supId    ?? undefined,
              brand:               s(row[GH.MARCA]),
              manufacturer:        s(row[GH.FABRICANTE]),
              stockMode:           (stockMode as any) ?? "NO_STOCK",
              unitOfMeasure:       s(row[GH.UNIDAD]),
              weight:            weightV  ?? undefined,
              reorderPoint:      repoPt   ?? undefined,
              minSaleQuantity:   cantMin  ?? undefined,
              maxSaleQuantity:   cantMax  ?? undefined,
              defaultQuantity:   cantDef  ?? undefined,
              isActive:    s(row[GH.ACTIVO])        ? b(s(row[GH.ACTIVO]))        : true,
              isFavorite:  s(row[GH.FAVORITO])      ? b(s(row[GH.FAVORITO]))      : false,
              showInStore: s(row[GH.EN_TIENDA])     ? b(s(row[GH.EN_TIENDA]))     : false,
              isReturnable: s(row[GH.ACEPTA_DEV])   ? b(s(row[GH.ACEPTA_DEV]))   : false,
              sellWithoutVariants: s(row[GH.SIN_VARIANTES]) ? b(s(row[GH.SIN_VARIANTES])) : false,
              notes:       s(row[GH.NOTAS]),
              manualTaxIds: taxIds,
            },
            select: { id: true },
          });
          artId = newArt.id;
          artBySku.set(sku, { id: artId, name: nombre, categoryId: catId ?? null });
          await saveCostLinesForArticle(artId, row, null, costCtx);
          const crDN = isImplicit ? `[Padre implícito] ${nombre}` : nombre;
          console.log(`[Guided Import] Artículo "${sku}" → CREADO id=${artId}${isImplicit ? " (padre implícito)" : ""}`);
          results.push({ index: i + 1, displayName: crDN, status: "created", id: artId });
          created++;
        }
      } catch (e: any) {
        console.error(`[Guided Import] Artículo "${sku}": ERROR →`, e?.message ?? e);
        const errDN = isImplicit ? `[Padre implícito] ${nombre}` : nombre;
        results.push({ index: i + 1, displayName: errDN, status: "error", errors: [e?.message ?? "Error desconocido"] });
        errors++;
      }
    }
  }

  results.sort((a, b) => a.index - b.index);

  const batchId = await saveBatch({
    jewelryId,
    entityType: "ARTICLE",
    fileName:   options.fileName ?? "",
    onConflict: options.onConflict,
    userId:     options.userId,
    summary:    { created, updated, skipped, errors },
    rows:       buildBatchRowsFromArticleResults(results, new Map()),
  });

  return { results, summary: { created, updated, skipped, errors }, batchId };
}
