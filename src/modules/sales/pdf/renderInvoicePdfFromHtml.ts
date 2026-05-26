// src/modules/sales/pdf/renderInvoicePdfFromHtml.ts
// =============================================================================
//  C4 — Renderer HTML/Puppeteer (PARALELO al pdfkit; aún NO activo).
//
//  ⛔ REGLA DURA — Este archivo NO calcula negocio.
//
//  Lee snapshots ya persistidos (sale.subtotal/discountAmount/taxAmount/total,
//  line.lineTotal, etc.) y los pasa tal cual al `<SaleInvoicePrintable>`
//  compartido (`@tptech/shared/document-printables/...`). Si en algún
//  momento aparece `*`, `/`, `+=`, `-=`, `Math.*` o cualquier loop tipo
//  `acc += line.x` sobre montos, es BUG: el número correcto ya está en
//  el snapshot que viene como input. El guard
//  `renderInvoicePdfFromHtml.no-math.guard.test.ts` falla si aparecen
//  esos patrones.
//
//  Paridad visual:
//    · El componente `SaleInvoicePrintable` es el mismo que monta el
//      frontend para `window.print()`. Browser print, PDF descargado y
//      PDF adjuntado por mail comparten EXACTAMENTE este componente.
//    · El watermark BORRADOR/ANULADA ya lo dibuja el componente segun
//      `status`. Acá no se agrega ninguno extra.
//
//  Activación:
//    · C4 (este archivo) sólo crea la infraestructura. NO se llama
//      desde sales.service todavía — el motor activo sigue siendo
//      `renderInvoicePdf.ts` (pdfkit).
//    · C5 cableará `generateSalePdfFromLoadedSale` para que use este
//      renderer cuando `PDF_ENGINE=html` y con fallback automático al
//      pdfkit si la generación HTML falla.
// =============================================================================

import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { Browser } from "puppeteer-core";

// Tipos del printable compartido. Importamos `type` para que TS no
// intente compilar el .tsx que vive fuera del `rootDir` del backend.
// El módulo real se resuelve dinámicamente en runtime (más abajo)
// vía el alias `@tptech/shared` que tsx + vitest resuelven via paths.
// La declaración ambient está en `src/types/tptech-shared.d.ts`.
import type {
  SaleInvoicePrintableProps,
  SaleInvoicePrintableLine,
} from "@tptech/shared/document-printables/SaleInvoicePrintable.js";

import { getBrowser } from "../../../lib/pdf/browserPool.js";

import type {
  RenderInvoiceInput,
  PdfSale,
  PdfSaleLine,
  PdfReceipt,
  PdfTemplate,
  PdfJewelry,
} from "./renderInvoicePdf.js";

// ─── Helpers PUROS (sin matemática comercial) ────────────────────────────────

/** Mapea el `status` del Sale (string libre del backend) a uno de los
 *  literales aceptados por `<SaleInvoicePrintable>`. Estados desconocidos
 *  → undefined (sin sello). */
function mapStatus(raw: string): SaleInvoicePrintableProps["status"] {
  switch (raw) {
    case "DRAFT":     return "DRAFT";
    case "PENDING":   return "PENDING";
    case "PARTIAL":   return "PARTIAL";
    case "PAID":      return "PAID";
    case "CANCELLED": return "CANCELLED";
    default:          return undefined;
  }
}

/** Mapea una línea del snapshot al shape mínimo que consume el shared
 *  printable. `articleId` se setea a un placeholder no vacío SOLO para
 *  satisfacer el filtro interno del componente (`renderableLines`), que
 *  descarta filas sin `articleId`/`isManual`/HEADER. Esto es display, no
 *  business logic — la verdad sigue siendo el snapshot. */
function mapLine(line: PdfSaleLine, index: number): SaleInvoicePrintableLine {
  return {
    id:        String(index),
    articleId: "snapshot",      // marker no-vacío para que el filtro lo pinte.
    article:   line.articleName,
    variant:   line.variantName,
    sku:       line.sku,
    quantity:  line.quantity,
    unitPrice: line.unitPrice,
    lineTotal: line.lineTotal,
  };
}

function getClientName(sale: PdfSale): string {
  if (sale.client?.displayName) return sale.client.displayName;
  return "Consumidor final";
}

function getClientTaxId(sale: PdfSale): string | undefined {
  const c = sale.client;
  if (!c || !c.documentNumber) return undefined;
  return `${c.documentType || "Doc."}: ${c.documentNumber}`;
}

function getDocumentNumber(sale: PdfSale, receipt: PdfReceipt | null): string {
  return receipt?.code ?? sale.code;
}

function isoDate(d: Date | string): string {
  const date = typeof d === "string" ? new Date(d) : d;
  return date.toISOString().slice(0, 10);
}

function getCurrencyCode(sale: PdfSale): string {
  return sale.currencySnapshot?.currencyCode ?? "ARS";
}

function getFxRate(sale: PdfSale): number {
  const r = sale.currencySnapshot?.currencyRate;
  return typeof r === "number" ? r : 1;
}

/** Construye las props del `<SaleInvoicePrintable>` desde el snapshot. */
function buildPrintableProps(input: RenderInvoiceInput): SaleInvoicePrintableProps {
  const { sale, receipt, template } = input;
  return {
    // Pasamos el template completo como `config`. El printable hoy no lee
    // ningún campo concreto del config — la prop existe para compatibilidad
    // y para futuras vistas que sí consuman parte del template.
    config:         template as unknown as SaleInvoicePrintableProps["config"],
    company:        {
      name:         input.jewelry.name,
      legalName:    input.jewelry.legalName,
      logoUrl:      input.jewelry.logoUrl,
      cuit:         input.jewelry.cuit,
      ivaCondition: input.jewelry.ivaCondition,
      addressLine:  input.jewelry.fullAddress,
      phone:        input.jewelry.phone,
      email:        input.jewelry.email,
      website:      input.jewelry.website,
    },
    documentNumber: getDocumentNumber(sale, receipt),
    documentDate:   isoDate(sale.saleDate),
    clientName:     getClientName(sale),
    clientTaxId:    getClientTaxId(sale),
    clientAddress:  undefined,
    lines:          sale.lines.map(mapLine),
    totals: {
      subtotal:       sale.subtotal,
      discountAmount: sale.discountAmount,
      taxAmount:      sale.taxAmount,
      total:          sale.total,
    },
    currencyCode: getCurrencyCode(sale),
    fxRate:       getFxRate(sale),
    notes:        sale.notes,
    terms:        template.footerTerms,
    sellerName:   sale.sellerSnapshot?.displayName ?? sale.sellerSnapshot?.name,
    status:       mapStatus(sale.status),
  };
}

/** Envuelve el markup del printable en un documento HTML completo,
 *  con `<meta charset>` y un reset mínimo. NO inyecta estilos de negocio
 *  ni clases adicionales — el printable es self-contained con estilos
 *  inline. El bloque `@page` controla el tamaño / orientación reales del
 *  PDF; los márgenes se setean en `page.pdf({ margin })` desde el caller
 *  para respetar DocumentTemplate.
 *
 *  Override `padding: 0` en `body > div` porque el printable trae un
 *  padding interno de 16/14mm para el browser print. En el PDF server-side
 *  los márgenes los gobierna DocumentTemplate vía Puppeteer, así que
 *  duplicarlos generaría márgenes acumulados. */
function buildHtmlDocument(printableMarkup: string, template: PdfTemplate): string {
  const pageOrientation = template.orientation === "landscape" ? "landscape" : "portrait";
  const pageSize = (template.isCustomSize && template.pageWidthMm > 0 && template.pageHeightMm > 0)
    ? `${template.pageWidthMm}mm ${template.pageHeightMm}mm`
    : (template.pageSizePreset || "A4");
  return `<!DOCTYPE html>
<html lang="es">
  <head>
    <meta charset="utf-8" />
    <title>Factura</title>
    <style>
      @page {
        size: ${pageSize} ${pageOrientation};
      }
      html, body {
        margin: 0;
        padding: 0;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }
      body > div {
        padding: 0 !important;
      }
    </style>
  </head>
  <body>${printableMarkup}</body>
</html>`;
}

// ─── Tipos del renderer ──────────────────────────────────────────────────────

/** Inyección opcional para tests: permite pasar un Browser mock sin
 *  tocar el pool. El renderer en producción NO recibe esta prop — usa
 *  `getBrowser()` del pool singleton. */
export interface RenderInvoiceHtmlOpts {
  /** Browser pre-resuelto. Si está, salta `getBrowser()`. Sólo tests. */
  browser?: Browser;
}

// ─── Render principal ────────────────────────────────────────────────────────

export async function renderInvoicePdfFromHtml(
  input: RenderInvoiceInput,
  opts: RenderInvoiceHtmlOpts = {},
): Promise<Buffer> {
  const { template } = input;

  // 1) HTML estático (puro, sin I/O).
  //
  // El componente se resuelve dinámicamente. Esto permite que TS no
  // intente compilar el .tsx del submódulo shared (que vive fuera del
  // `rootDir`) y deja al runtime (tsx en dev/test, post-procesador en
  // prod) la resolución del alias `@tptech/shared`.
  const SaleInvoicePrintable = await loadSaleInvoicePrintable();
  const props                = buildPrintableProps(input);
  const printableMarkup      = renderToStaticMarkup(
    React.createElement(SaleInvoicePrintable, props),
  );
  const html = buildHtmlDocument(printableMarkup, template);

  // 2) Render con Puppeteer.
  const browser = opts.browser ?? await getBrowser();
  const page    = await browser.newPage();
  try {
    // `load` basta porque el printable es self-contained (estilos inline,
    // sin fetches, sin imágenes remotas en v1). No esperamos network-idle.
    await page.setContent(html, { waitUntil: "load" });

    const pdfResult = await page.pdf({
      format:          "A4",
      printBackground: true,
      margin: {
        top:    `${template.marginTop}mm`,
        right:  `${template.marginRight}mm`,
        bottom: `${template.marginBottom}mm`,
        left:   `${template.marginLeft}mm`,
      },
    });

    // `page.pdf` puede devolver `Uint8Array` o `Buffer` segun versión de
    // puppeteer — normalizamos a Buffer para no romper el contrato con
    // el caller actual (que también devuelve Buffer).
    return Buffer.isBuffer(pdfResult) ? pdfResult : Buffer.from(pdfResult);
  } finally {
    // Cerrar la page siempre — fugas de Page acumulan tabs en el browser
    // y son la causa #1 de OOM en Puppeteer en producción.
    await safeClosePage(page);
  }
}

async function safeClosePage(page: { close: () => Promise<void> }): Promise<void> {
  try {
    await page.close();
  } catch {
    // ignore — la page puede haberse cerrado sola si crasheó.
  }
}

// ─── Carga del componente shared ─────────────────────────────────────────────

/** Cargador del `SaleInvoicePrintable` con cache de módulo. Usamos un
 *  dynamic import porque el componente vive en `tptech-shared/` (fuera
 *  del rootDir del backend) — TS sólo conoce los tipos vía la
 *  declaración ambient. Inyectable por tests vía
 *  `__setPrintableLoaderForTests`. */
type PrintableComponent = (props: SaleInvoicePrintableProps) => React.ReactElement;
let printableLoader: () => Promise<PrintableComponent> = defaultPrintableLoader;

async function defaultPrintableLoader(): Promise<PrintableComponent> {
  const mod = await import("@tptech/shared/document-printables/SaleInvoicePrintable.js");
  return (mod as { default: PrintableComponent }).default;
}

async function loadSaleInvoicePrintable(): Promise<PrintableComponent> {
  return printableLoader();
}

/** Sólo para tests. Reemplaza el cargador del componente — el mock
 *  puede devolver un stub que no requiera la infra del shared. */
export function __setPrintableLoaderForTests(
  loader: (() => Promise<PrintableComponent>) | null,
): void {
  printableLoader = loader ?? defaultPrintableLoader;
}
