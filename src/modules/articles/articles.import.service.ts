// src/modules/articles/articles.import.service.ts
// Servicio de importación masiva de artículos y variantes desde Excel/CSV.
import * as XLSX from "xlsx";
import { prisma } from "../../lib/prisma.js";

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
    const cat = await prisma.articleCategory.findFirst({
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
  "Es_Variante",
  "Articulo_Padre",
  "Nombre",
  "Codigo",
  "Tipo",
  "Estado",
  "SKU",
  "Barcode",
  "Tipo_Barcode",
  "Categoria",
  "Marca",
  "Fabricante",
  "Descripcion",
  "Precio_Costo",
  "Precio_Venta",
  "Hechura",
  "Hechura_Modo",
  "Merma_Pct",
  "Modo_Stock",
  "Unidad",
  "En_Tienda",
  "Acepta_Devolucion",
  "Notas",
  // Columnas opcionales de atributos de variante (Atrib_NombreAtributo)
  "Atrib_Color",
  "Atrib_Medida",
];

const EXAMPLE_ARTICLE = [
  "NO", "", "Anillo de Oro 18K", "ART-001", "PRODUCT", "ACTIVE",
  "SKU-001", "", "CODE128", "Anillos", "Marca Propia", "",
  "Anillo de oro amarillo 18K", "15000", "25000", "500", "FIXED",
  "2.5", "BY_ARTICLE", "UND", "SI", "SI", "Ejemplo de artículo",
  "", "", // Atrib_Color, Atrib_Medida
];
const EXAMPLE_VARIANT = [
  "SI", "ART-001", "Talle 16", "VAR-001-T16", "", "",
  "SKU-001-T16", "", "CODE128", "", "", "",
  "", "16000", "27000", "", "",
  "", "", "", "", "",
  "Variante talle 16",
  "Rojo", "16", // Atrib_Color, Atrib_Medida
];
const EXAMPLE_SERVICE = [
  "NO", "", "Engaste de piedras", "SRV-001", "SERVICE", "ACTIVE",
  "", "", "CODE128", "Servicios", "", "",
  "Servicio de engaste manual", "0", "3500", "3500", "FIXED",
  "0", "NO_STOCK", "UND", "NO", "NO", "Servicio",
  "", "", // Atrib_Color, Atrib_Medida
];

// ─── Tipos públicos ──────────────────────────────────────────────────────────
export type ImportRow = Record<string, string>;

export type ImportPreviewRow = {
  index: number;
  isVariant: boolean;
  parentCode: string;
  displayName: string;
  status: "valid" | "existing" | "error" | "warning";
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
  existing: number;
  warnings: number;
  rows: ImportPreviewRow[];
};

export type ImportCommitRow = {
  index: number;
  displayName: string;
  status: "created" | "updated" | "skipped" | "error";
  errors?: string[];
  id?: string;
};

export type ImportCommitResult = {
  results: ImportCommitRow[];
  summary: { created: number; updated: number; skipped: number; errors: number };
};

// ─── Generar template XLSX ────────────────────────────────────────────────────
export function generateImportTemplate(): Buffer {
  const wb = XLSX.utils.book_new();

  // Hoja principal con datos
  const data = [
    TEMPLATE_HEADERS,
    EXAMPLE_ARTICLE,
    EXAMPLE_VARIANT,
    EXAMPLE_SERVICE,
  ];
  const ws = XLSX.utils.aoa_to_sheet(data);

  // Ancho de columnas
  ws["!cols"] = TEMPLATE_HEADERS.map((h) => ({
    wch: Math.max(h.length + 2, 14),
  }));

  XLSX.utils.book_append_sheet(wb, ws, "Artículos");

  // Hoja de instrucciones
  const instrData = [
    ["INSTRUCCIONES DE IMPORTACIÓN"],
    [""],
    ["COLUMNAS OBLIGATORIAS:"],
    ["Nombre: Nombre del artículo o variante (requerido)"],
    [""],
    ["TIPOS DE FILA:"],
    ["Es_Variante = NO (o vacío): Fila de artículo"],
    ["Es_Variante = SI: Fila de variante (requiere Articulo_Padre = código del artículo padre)"],
    [""],
    ["VALORES VÁLIDOS:"],
    ["Tipo: PRODUCT | SERVICE | MATERIAL (default: PRODUCT)"],
    ["Estado: DRAFT | ACTIVE | DISCONTINUED (default: DRAFT)"],
    ["Tipo_Barcode: CODE128 | EAN13 | QR (default: CODE128)"],
    ["Hechura_Modo: FIXED | PER_GRAM (default: FIXED)"],
    ["Modo_Stock: NO_STOCK | BY_ARTICLE | BY_MATERIAL (default: NO_STOCK)"],
    ["En_Tienda: SI | NO"],
    ["Acepta_Devolucion: SI | NO"],
    [""],
    ["NOTAS:"],
    ["- Codigo: Si está vacío se genera automáticamente"],
    ["- Barcode: Si está vacío no se asigna barcode"],
    ["- Categoria: Si no existe se omite (no falla la importación)"],
    ["- Los precios usan punto o coma como separador decimal"],
    ["- Atrib_*: Columnas opcionales para atributos de variante (ej. Atrib_Color, Atrib_Talle)"],
    ["  Solo aplican a filas con Es_Variante=SI. El nombre debe coincidir con un atributo"],
    ["  de variante (isVariantAxis=true) configurado en la categoría del artículo padre."],
    ["  Podés agregar tantas columnas Atrib_* como necesites según tu configuración."],
  ];
  const wsInstr = XLSX.utils.aoa_to_sheet(instrData);
  wsInstr["!cols"] = [{ wch: 80 }];
  XLSX.utils.book_append_sheet(wb, wsInstr, "Instrucciones");

  return Buffer.from(XLSX.write(wb, { type: "buffer", bookType: "xlsx" }));
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
      status = "existing";
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
    existing: existingCount,
    warnings: warnCount,
    rows: result,
  };
}

// ─── Execute ─────────────────────────────────────────────────────────────────
export async function executeImport(
  rows: ImportRow[],
  jewelryId: string,
  options: { onConflict: "skip" | "update" }
): Promise<ImportCommitResult> {
  // Cargar datos de referencia
  const categories = await prisma.articleCategory.findMany({
    where: { jewelryId, deletedAt: null },
    select: { id: true, name: true },
  });
  const catMap = new Map(categories.map((c) => [normalizeStr(c.name), c.id]));

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
    const hechuraModo = (["FIXED", "PER_GRAM"].includes(s(row["Hechura_Modo"] ?? "").toUpperCase()) ? s(row["Hechura_Modo"] ?? "").toUpperCase() : "FIXED") as "FIXED" | "PER_GRAM";

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
            costPrice: n(row["Precio_Costo"]),
            salePrice: n(row["Precio_Venta"]),
            hechuraPrice: n(row["Hechura"]),
            hechuraPriceMode: hechuraModo,
            mermaPercent: n(row["Merma_Pct"]),
            unitOfMeasure: s(row["Unidad"] ?? "") || undefined,
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
            jewelry: { connect: { id: jewelryId } },
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
            categoryId,
            costPrice: n(row["Precio_Costo"]),
            salePrice: n(row["Precio_Venta"]),
            hechuraPrice: n(row["Hechura"]),
            hechuraPriceMode: hechuraModo,
            mermaPercent: n(row["Merma_Pct"]),
            unitOfMeasure: s(row["Unidad"] ?? ""),
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
      const existingVariant = variantCode
        ? await prisma.articleVariant.findFirst({
            where: { articleId: parentId, code: variantCode, deletedAt: null },
            select: { id: true },
          })
        : null;

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
        await prisma.articleVariant.update({
          where: { id: existingVariant.id },
          data: {
            name,
            sku: s(row["SKU"] ?? "") || undefined,
            costPrice: n(row["Precio_Costo"]),
            priceOverride: n(row["Precio_Venta"]),
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
        const newVariant = await prisma.articleVariant.create({
          data: {
            jewelryId,
            articleId: parentId,
            code: finalCode,
            name,
            sku: s(row["SKU"] ?? ""),
            costPrice: n(row["Precio_Costo"]),
            priceOverride: n(row["Precio_Venta"]),
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

  return {
    results,
    summary: { created, updated, skipped, errors },
  };
}
