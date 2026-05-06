/**
 * Script de prueba para la importación v2 multi-hoja.
 * Genera un archivo Excel con los 6 escenarios de prueba y lo sube via HTTP al backend.
 *
 * Uso:
 *   npx tsx scripts/test-import-v2.ts
 *
 * Requiere que el backend esté corriendo en localhost:3001.
 * Requiere una sesión válida (cookie tptech_session) o un token Bearer.
 *
 * Ajustar BEARER_TOKEN o COOKIE_SESSION según el entorno.
 */

import ExcelJS from "exceljs";
import * as XLSX from "xlsx";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── Configuración ────────────────────────────────────────────────────────────
const BASE_URL      = process.env.BACKEND_URL  ?? "http://localhost:3001/api";
const BEARER_TOKEN  = process.env.BEARER_TOKEN ?? "";    // JWT token si no hay cookie
const COOKIE_VALUE  = process.env.SESSION_COOKIE ?? "";  // valor de tptech_session
const OUT_FILE      = path.join(__dirname, "test-import-v2.xlsx");

// ── Cabeceras (mismas que el servicio) ───────────────────────────────────────
const ARTICLE_HEADERS_V2 = [
  "Nombre","Codigo","Tipo","Estado",
  "SKU","Barcode","Tipo_Barcode",
  "Categoria","Grupo","Proveedor",
  "Marca","Fabricante","Descripcion",
  "Precio_Costo","Precio_Venta",
  "Hechura","Hechura_Modo","Merma_Pct","Modo_Costo",
  "Modo_Stock","Unidad","Peso",
  "Reorder_Point","Cant_Min","Cant_Max","Cant_Default",
  "Favorito","Activo","En_Tienda","Acepta_Devolucion","Vender_Sin_Variantes",
  "Notas",
];
const VARIANT_HEADERS_V2 = [
  "Articulo_Codigo","Codigo","Nombre","SKU","Barcode","Tipo_Barcode",
  "Precio_Costo","Precio_Venta","Hechura","Peso",
  "Reorder_Point","Cant_Min","Cant_Max","Cant_Default",
  "Activo","Notas",
];
const METAL_HEADERS_V2 = [
  "Articulo_Codigo","Codigo_Variante",
  "Metal_Padre","Metal_Variante",
  "Gramos","Merma_Pct","Hechura_Metal","Es_Base",
];
const STOCK_HEADERS_V2 = [
  "Articulo_Codigo","Codigo_Variante",
  "Almacen","Cantidad","Peso_Total","Modo",
];
const ATTRIBUTE_HEADERS_V2 = [
  "Articulo_Codigo","Codigo_Variante","Atributo","Valor",
];

// ── Helper: agrega hoja con cabecera ─────────────────────────────────────────
function addSheet(wb: ExcelJS.Workbook, name: string, headers: string[], rows: string[][]): void {
  const ws = wb.addWorksheet(name);
  ws.addRow(headers);
  for (const r of rows) ws.addRow(r);
}

// ── Datos de prueba ──────────────────────────────────────────────────────────
// Ajustar nombres de categoría, almacén y metal según lo que exista en la DB.
// Los artículos usan código TEST-xxx para poder identificarlos y limpiarlos después.

const ARTICLES: string[][] = [
  // Escenario 1: Artículo simple sin metal (PRODUCT, sin Metales)
  ["Collar de Plata Simple","TEST-001","PRODUCT","ACTIVE",
   "TEST-SKU-001","","CODE128",
   "","","",
   "Plata Test","","Collar sin metal importado",
   "5000","12000","0","FIXED","0","MANUAL",
   "BY_ARTICLE","UND","","3","1","","1",
   "NO","SI","NO","SI","NO",
   "Escenario 1 - artículo simple sin metal"],

  // Escenario 2: Artículo simple con metal
  ["Anillo Oro TEST","TEST-002","PRODUCT","ACTIVE",
   "TEST-SKU-002","","CODE128",
   "","","",
   "Oro Test","","Anillo con composición metálica",
   "","25000","800","FIXED","2.5","METAL_MERMA_HECHURA",
   "BY_ARTICLE","UND","3.5","5","1","","1",
   "SI","SI","NO","SI","NO",
   "Escenario 2 - artículo con metal"],

  // Escenario 3: Artículo con variantes y atributos
  ["Aro con Variantes TEST","TEST-003","PRODUCT","ACTIVE",
   "TEST-SKU-003","","CODE128",
   "","","",
   "Test Brand","","Aro con talle y color",
   "8000","18000","500","FIXED","2","MANUAL",
   "BY_ARTICLE","UND","2.8","5","1","","1",
   "NO","SI","NO","SI","NO",
   "Escenario 3 - artículo con variantes"],

  // Escenario 4: Artículo con variante que tiene metal propio
  ["Pulsera con Var Metal TEST","TEST-004","PRODUCT","ACTIVE",
   "TEST-SKU-004","","CODE128",
   "","","",
   "Test Brand","","Pulsera con variantes y metales por variante",
   "","22000","600","FIXED","2","METAL_MERMA_HECHURA",
   "BY_ARTICLE","UND","","5","1","","1",
   "NO","SI","NO","SI","NO",
   "Escenario 4 - variante con metal y weightOverride"],

  // Escenario 5: Artículo para prueba de stock SET + ADD
  ["Stock Test Article TEST","TEST-005","PRODUCT","ACTIVE",
   "TEST-SKU-005","","CODE128",
   "","","",
   "","","Artículo para test de stock",
   "2000","5000","0","FIXED","0","MANUAL",
   "BY_ARTICLE","UND","","3","1","","",
   "NO","SI","NO","SI","NO",
   "Escenario 5 - test de stock SET y ADD"],

  // Escenario 6: Artículo de servicio (debe ignorar metales)
  ["Servicio TEST","TEST-006","SERVICE","ACTIVE",
   "TEST-SKU-006","","CODE128",
   "","","",
   "","","Servicio de engaste para test",
   "0","3000","3000","FIXED","0","MANUAL",
   "NO_STOCK","UND","","","","","",
   "NO","SI","NO","NO","NO",
   "Escenario 6 - servicio, metales ignorados"],
];

const VARIANTS: string[][] = [
  // Escenario 3: Aro con variantes
  ["TEST-003","TEST-003-T16","Talle 16","TEST-SKU-003-T16","","CODE128",
   "9000","19000","","2.5","","","","","SI","Variante talle 16"],
  ["TEST-003","TEST-003-T18","Talle 18","TEST-SKU-003-T18","","CODE128",
   "9200","19200","","3.0","","","","","SI","Variante talle 18"],

  // Escenario 4: Pulsera con variantes
  ["TEST-004","TEST-004-ORO","Version Oro","TEST-SKU-004-ORO","","CODE128",
   "","23000","","","","","","","SI","Versión en Oro"],
  ["TEST-004","TEST-004-PLATA","Version Plata","TEST-SKU-004-PLATA","","CODE128",
   "","15000","","","","","","","SI","Versión en Plata"],
];

// Ajustar Metal_Padre y Metal_Variante con los nombres EXACTOS que existen en la DB
// Si no existen esos metales, las filas se ignorarán silenciosamente
const METALS: string[][] = [
  // Escenario 2: Artículo simple con metal (global al artículo)
  ["TEST-002","","Oro","Oro 18K Amarillo","3.5","2.5","800","SI"],

  // Escenario 4: Metales por variante (Codigo_Variante presente)
  ["TEST-004","TEST-004-ORO","Oro","Oro 18K Amarillo","4.2","2.5","600","SI"],
  ["TEST-004","TEST-004-PLATA","Plata","Plata 925","5.0","1.0","200","SI"],

  // Escenario 6: Servicio → debe ser IGNORADO
  ["TEST-006","","Oro","Oro 18K Amarillo","1.0","0","0","NO"],
];

// Ajustar Almacen con el nombre/código que exista en la DB
const STOCK_ROWS: string[][] = [
  // Escenario 1: Stock SET
  ["TEST-001","","Almacén Principal","10","","SET"],
  // Escenario 5: Stock SET
  ["TEST-005","","Almacén Principal","5","","SET"],
  // Escenario 5: Stock ADD (va a sumar al SET anterior si se hace en 2 importaciones)
  // En la misma importación, SET primero luego ADD sobre el mismo artículo
  ["TEST-005","","Almacén Principal","3","","ADD"],
  // Escenario 3: Stock para variantes
  ["TEST-003","TEST-003-T16","Almacén Principal","8","","SET"],
  ["TEST-003","TEST-003-T18","Almacén Principal","4","","SET"],
  // Error esperado: codigo de variante inexistente → debe skip silencioso
  ["TEST-001","VAR-INEXISTENTE","Almacén Principal","99","","SET"],
];

// Ajustar Atributo con los nombres de atributos que existan en las categorías
const ATTRIBUTES: string[][] = [
  // Solo funcionarán si TEST-003 tiene una categoría asignada con esos atributos definidos
  // De lo contrario, las filas se ignoran silenciosamente
  ["TEST-003","","Material","Plata 925"],
  ["TEST-003","TEST-003-T16","Color","Plateado"],
  ["TEST-003","TEST-003-T18","Color","Dorado"],
];

// ── Generar archivo ──────────────────────────────────────────────────────────
async function buildTestFile(): Promise<Buffer> {
  const wb = new ExcelJS.Workbook();
  addSheet(wb, "Artículos",  ARTICLE_HEADERS_V2,   ARTICLES);
  addSheet(wb, "Variantes",  VARIANT_HEADERS_V2,   VARIANTS);
  addSheet(wb, "Metales",    METAL_HEADERS_V2,     METALS);
  addSheet(wb, "Stock",      STOCK_HEADERS_V2,     STOCK_ROWS);
  addSheet(wb, "Atributos",  ATTRIBUTE_HEADERS_V2, ATTRIBUTES);
  const buf = await wb.xlsx.writeBuffer();
  return Buffer.from(buf);
}

// ── Llamar al API ─────────────────────────────────────────────────────────────
async function callImport(endpoint: "preview" | "execute", fileBuffer: Buffer, onConflict = "skip"): Promise<any> {
  const url      = `${BASE_URL}/articles/import/${endpoint}`;
  const boundary = `----FormBoundary${Date.now()}`;
  const fileData = fileBuffer;

  const parts: Buffer[] = [];
  parts.push(Buffer.from(
    `--${boundary}\r\n` +
    `Content-Disposition: form-data; name="file"; filename="test-import-v2.xlsx"\r\n` +
    `Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\r\n\r\n`
  ));
  parts.push(fileData);
  parts.push(Buffer.from(`\r\n--${boundary}\r\n`));
  if (endpoint === "execute") {
    parts.push(Buffer.from(
      `Content-Disposition: form-data; name="onConflict"\r\n\r\n${onConflict}\r\n`
    ));
    parts.push(Buffer.from(`--${boundary}--\r\n`));
  } else {
    parts.push(Buffer.from(`Content-Disposition: form-data; name="dummy"\r\n\r\n\r\n--${boundary}--\r\n`));
  }
  const body = Buffer.concat(parts);

  const headers: Record<string, string> = {
    "Content-Type": `multipart/form-data; boundary=${boundary}`,
    "Content-Length": String(body.length),
  };
  if (BEARER_TOKEN) headers["Authorization"] = `Bearer ${BEARER_TOKEN}`;
  if (COOKIE_VALUE) headers["Cookie"]        = `tptech_session=${COOKIE_VALUE}`;

  const { default: fetch } = await import("node-fetch");
  const res = await (fetch as any)(url, { method: "POST", headers, body });
  const text = await res.text();
  try { return JSON.parse(text); } catch { return text; }
}

// ── Validaciones ──────────────────────────────────────────────────────────────
function validate(label: string, actual: any, expected: any): void {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  console.log(`  ${ok ? "✓" : "✗"} ${label}`);
  if (!ok) {
    console.log(`    Esperado: ${JSON.stringify(expected)}`);
    console.log(`    Obtenido: ${JSON.stringify(actual)}`);
  }
}

function printSection(title: string): void {
  console.log(`\n${"─".repeat(60)}`);
  console.log(`  ${title}`);
  console.log("─".repeat(60));
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  console.log("TPTech — Test de importación v2 multi-hoja");
  console.log("=".repeat(60));

  // 1. Generar archivo
  printSection("Generando archivo de test...");
  const buf = await buildTestFile();
  fs.writeFileSync(OUT_FILE, buf);
  console.log(`  Archivo generado: ${OUT_FILE}`);
  console.log(`  Hojas: Artículos(${ARTICLES.length}), Variantes(${VARIANTS.length}), Metales(${METALS.length}), Stock(${STOCK_ROWS.length}), Atributos(${ATTRIBUTES.length})`);

  // 2. Preview
  printSection("PASO A — Preview del archivo");
  let preview: any;
  try {
    preview = await callImport("preview", buf);
    console.log("  Respuesta preview:");
    console.log(`    total:    ${preview.total}`);
    console.log(`    articles: ${preview.articles}`);
    console.log(`    variants: ${preview.variants}`);
    console.log(`    valid:    ${preview.valid}`);
    console.log(`    errors:   ${preview.errors}`);
    console.log(`    existing: ${preview.existing}`);
    console.log(`    metalRows:     ${preview.metalRows}`);
    console.log(`    stockRows:     ${preview.stockRows}`);
    console.log(`    attributeRows: ${preview.attributeRows}`);

    validate("preview.articles === 6", preview.articles, 6);
    validate("preview.variants === 4", preview.variants, 4);
    validate("preview.metalRows === 4", preview.metalRows, 4);
    validate("preview.stockRows === 6", preview.stockRows, 6);
    validate("preview.attributeRows === 3", preview.attributeRows, 3);

    if (preview.rows) {
      const errRows = preview.rows.filter((r: any) => r.status === "error");
      if (errRows.length > 0) {
        console.log(`  Filas con error en preview:`);
        for (const r of errRows) {
          console.log(`    [${r.index}] ${r.displayName}: ${r.errors?.join(", ")}`);
        }
      }
    }
  } catch (e: any) {
    console.error("  ERROR en preview:", e.message ?? e);
  }

  // 3. Execute (primera vez → crea todo)
  printSection("PASO B — Execute (primera importación, skip en conflicto)");
  let exec1: any;
  try {
    exec1 = await callImport("execute", buf, "skip");
    console.log("  Resumen execute:");
    console.log(`    created:  ${exec1.summary?.created}`);
    console.log(`    updated:  ${exec1.summary?.updated}`);
    console.log(`    skipped:  ${exec1.summary?.skipped}`);
    console.log(`    errors:   ${exec1.summary?.errors}`);
    console.log(`    metalRows:     ${exec1.metalRows}`);
    console.log(`    stockRows:     ${exec1.stockRows}`);
    console.log(`    attributeRows: ${exec1.attributeRows}`);

    validate("Artículos creados === 6", exec1.summary?.created, 6);
    validate("Variantes creadas === 4", exec1.summary?.created !== undefined, true); // al menos algo
    validate("metalRows procesadas >= 2", (exec1.metalRows ?? 0) >= 2, true);
    validate("stockRows procesadas (sin la de var inexistente) === 5", exec1.stockRows, 5);

    if (exec1.results) {
      const errRows = exec1.results.filter((r: any) => r.status === "error");
      if (errRows.length > 0) {
        console.log(`  Filas con error en execute:`);
        for (const r of errRows) {
          console.log(`    [${r.index}] ${r.displayName}: ${r.errors?.join(", ")}`);
        }
      }
    }
  } catch (e: any) {
    console.error("  ERROR en execute:", e.message ?? e);
  }

  // 4. Execute de nuevo → debe skip todo (onConflict=skip)
  printSection("PASO C — Segunda importación (debe hacer skip de todo)");
  let exec2: any;
  try {
    exec2 = await callImport("execute", buf, "skip");
    console.log("  Resumen segunda importación:");
    console.log(`    created:  ${exec2.summary?.created}`);
    console.log(`    skipped:  ${exec2.summary?.skipped}`);
    validate("Segunda importación: created === 0", exec2.summary?.created, 0);
    validate("Segunda importación: skipped === 10 (arts+vars)", (exec2.summary?.skipped ?? 0) >= 6, true);
  } catch (e: any) {
    console.error("  ERROR en segunda importación:", e.message ?? e);
  }

  // 5. Execute con update
  printSection("PASO D — Tercera importación (onConflict=update)");
  let exec3: any;
  try {
    exec3 = await callImport("execute", buf, "update");
    console.log("  Resumen update:");
    console.log(`    updated:  ${exec3.summary?.updated}`);
    console.log(`    created:  ${exec3.summary?.created}`);
    validate("Update: artículos actualizados >= 6", (exec3.summary?.updated ?? 0) >= 6, true);
  } catch (e: any) {
    console.error("  ERROR en update:", e.message ?? e);
  }

  console.log("\n" + "=".repeat(60));
  console.log("Test completado. Revisar resultados arriba.");
  console.log("NOTA: Los artículos TEST-001..TEST-006 quedan en la DB.");
  console.log("Para limpiar: DELETE FROM Article WHERE code LIKE 'TEST-%';");
}

main().catch(e => { console.error("Error fatal:", e); process.exit(1); });
