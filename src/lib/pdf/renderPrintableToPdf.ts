// src/lib/pdf/renderPrintableToPdf.ts
// =============================================================================
//  Helper común para renderear `<SaleInvoicePrintable>` a PDF vía
//  HTML/Puppeteer. Lo usan DOS flujos:
//    1. `renderInvoicePdfFromHtml` (legacy) — adapta el Sale persistido
//       a props del printable y delega acá.
//    2. `renderSaleDraftPdf` (C5-fix Opción A) — recibe DIRECTAMENTE
//       las props del printable desde el frontend (mismo objeto que se
//       pasa al `<SaleInvoicePrintable>` en `window.print()`), sin
//       intermediarios. Garantiza paridad visual Imprimir ↔ Descargar
//       ↔ Mail.
//
//  Reglas:
//    · Cero lógica de negocio. Sólo: renderToStaticMarkup + Puppeteer.
//    · `page.pdf({ margin: 0 })` — IDÉNTICO al browser print del
//      frontend (`@page { margin: 0 }`). El padding visual lo gobierna
//      el printable con su `padding: 16mm 14mm` interno.
//    · El tamaño/orientación de página vienen como `pageConfig`,
//      separados de los props del printable.
//    · `waitUntil: "load"` — el printable es self-contained (estilos
//      inline, sin recursos externos en v1).
// =============================================================================

import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { Browser } from "puppeteer-core";

import { getBrowser } from "./browserPool.js";

// ─── Tipos públicos ──────────────────────────────────────────────────────────

/** Subset de SaleInvoicePrintableProps consumido server-side. Se
 *  mantiene minimal y permisivo (los nombres y tipos vienen del frontend
 *  via el body del request). Validación granular: la hace el schema
 *  Zod del endpoint. Acá tipamos lo justo para renderear. */
export interface SaleDraftPrintableProps {
  config?:           unknown;
  company?:          {
    name?:         string;
    legalName?:    string;
    logoUrl?:      string;
    cuit?:         string;
    ivaCondition?: string;
    addressLine?:  string;
    phone?:        string;
    email?:        string;
    website?:      string;
  };
  documentNumber:    string;
  documentDate:      string;
  clientName:        string;
  clientTaxId?:      string;
  clientAddress?:    string;
  lines:             Array<{
    id:                 string;
    type?:              "ARTICLE" | "HEADER";
    title?:             string;
    articleId?:         string;
    isManual?:          boolean;
    manualDescription?: string;
    article?:           string;
    variant?:           string;
    sku?:               string;
    quantity?:          number;
    unitPrice?:         number;
    subtotal?:          number;
    lineTotal?:         number;
  }>;
  totals: {
    subtotal:       number;
    discountAmount: number;
    taxAmount:      number;
    total:          number;
  };
  currencyCode:     string;
  fxRate:           number;
  notes?:           string;
  terms?:           string;
  sellerName?:      string;
  warehouseName?:   string;
  paymentTermName?: string;
  status?:          "DRAFT" | "PENDING" | "PARTIAL" | "PAID" | "CANCELLED";
}

export interface RenderPrintablePageConfig {
  widthMm:      number;
  heightMm:     number;
  orientation?: "portrait" | "landscape";
}

export interface RenderPrintableOpts {
  /** Browser pre-resuelto. Si está, salta `getBrowser()`. Sólo tests. */
  browser?: Browser;
}

// ─── Inyección del cargador del componente (sólo tests) ──────────────────────

type PrintableComponent = (props: SaleDraftPrintableProps) => React.ReactElement;
let printableLoader: () => Promise<PrintableComponent> = defaultPrintableLoader;

async function defaultPrintableLoader(): Promise<PrintableComponent> {
  const mod = await import("@tptech/shared/document-printables/SaleInvoicePrintable.js");
  return (mod as { default: PrintableComponent }).default;
}

export function __setRenderPrintableLoaderForTests(
  loader: (() => Promise<PrintableComponent>) | null,
): void {
  printableLoader = loader ?? defaultPrintableLoader;
}

// ─── Render principal ────────────────────────────────────────────────────────

export async function renderPrintableToPdf(
  props:      SaleDraftPrintableProps,
  pageConfig: RenderPrintablePageConfig,
  opts:       RenderPrintableOpts = {},
): Promise<Buffer> {
  // 1) HTML estático del printable.
  const SaleInvoicePrintable = await printableLoader();
  const markup = renderToStaticMarkup(
    React.createElement(SaleInvoicePrintable, props),
  );
  const html = buildHtmlDocument(markup, pageConfig);

  // 2) Render Puppeteer — margin 0, igual que browser print.
  const browser = opts.browser ?? await getBrowser();
  const page    = await browser.newPage();
  try {
    await page.setContent(html, { waitUntil: "load" });
    const out = await page.pdf({
      width:           `${pageConfig.widthMm}mm`,
      height:          `${pageConfig.heightMm}mm`,
      printBackground: true,
      margin:          { top: 0, right: 0, bottom: 0, left: 0 },
    });
    return Buffer.isBuffer(out) ? out : Buffer.from(out);
  } finally {
    try { await page.close(); } catch { /* page pudo crashearse */ }
  }
}

// ─── HTML wrapper ────────────────────────────────────────────────────────────

/** Envuelve el markup del printable en un documento HTML completo
 *  con `<meta charset>` y `@page` config. NO override del padding
 *  del printable — el componente trae `padding: 16mm 14mm` interno
 *  que reproduce los márgenes visuales del browser print. Combinado
 *  con `page.pdf({ margin: 0 })`, esto da paridad pixel-cercana con
 *  el output del frontend `@page { margin: 0 }` + popup print. */
function buildHtmlDocument(markup: string, pageConfig: RenderPrintablePageConfig): string {
  const orient = pageConfig.orientation === "landscape" ? "landscape" : "portrait";
  return `<!DOCTYPE html>
<html lang="es">
  <head>
    <meta charset="utf-8" />
    <title>Factura</title>
    <style>
      @page {
        size: ${pageConfig.widthMm}mm ${pageConfig.heightMm}mm ${orient};
        margin: 0;
      }
      html, body {
        margin: 0;
        padding: 0;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }
    </style>
  </head>
  <body>${markup}</body>
</html>`;
}
