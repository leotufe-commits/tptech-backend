// src/modules/sales/pdf/renderInvoicePdf.ts
// =============================================================================
//  ⛔ REGLA DURA — Este archivo NO calcula negocio.
//
//  Lee snapshots ya persistidos (sale.subtotal/discountAmount/taxAmount/total,
//  line.lineTotal, etc.) y los DIBUJA en un PDF. Si en algun momento se
//  agrega `*`, `/`, `+=`, `-=`, `Math.*` o cualquier loop tipo
//  `acc += line.x` sobre montos, **es bug**: el numero correcto ya esta en
//  el snapshot que viene como input. El guard
//  `renderInvoicePdf.no-math.guard.test.ts` falla si aparecen esos patrones.
//
//  Configuracion documental → SSOT = `DocumentTemplate` (modulo
//  `document-templates`). Este archivo NO inventa columnas ni secciones
//  propias: respeta exactamente lo que la plantilla activa devuelve.
//
//  Formato de numero v1 → es-AR + `template.currencyDecimals`. TODO(v2):
//  cablear con `Jewelry.numberFormat` real del tenant cuando esa pieza
//  exista server-side (hoy esa logica vive solo en frontend bajo
//  `src/lib/number-format/`).
// =============================================================================

import PDFDocument from "pdfkit";
import type { ColumnConfig } from "../../document-templates/document-templates.constants.js";

// ─── Tipos de entrada ──────────────────────────────────────────────────────────
// Mantener estos tipos PLANOS (numeros ya convertidos desde Prisma.Decimal por
// el caller). Asi el renderer es testeable sin tocar Prisma ni pricing-engine.

export interface PdfSaleLine {
  articleName: string;
  variantName: string;
  sku:         string;
  barcode:     string;
  quantity:    number;
  unitPrice:   number;
  discountPct: number;
  lineTotal:   number;
  taxAmount:   number | null;
}

export interface PdfSale {
  id:              string;
  code:            string;            // numero interno del draft (VTA-XXXX)
  status:          string;
  saleDate:        Date | string;
  notes:           string;
  // Totales persistidos por el pricing-engine al confirmar. Leer tal cual.
  subtotal:        number;
  discountAmount:  number;
  taxAmount:       number;
  total:           number;
  paidAmount:      number;
  currencySnapshot: { currencyCode?: string; symbol?: string; currencyRate?: number } | null;
  clientSnapshot:  Record<string, unknown> | null;
  sellerSnapshot:  { displayName?: string; name?: string } | null;
  lines:           PdfSaleLine[];
  client:          { displayName: string; documentType: string; documentNumber: string; ivaCondition: string } | null;
}

export interface PdfReceipt {
  id:        string;
  code:      string;                  // numero oficial: A-0001-00000001
  type:      string;
  issueDate: Date | string;
}

export interface PdfTemplate {
  pageSizePreset:        string;
  isCustomSize:          boolean;
  pageWidthMm:           number;
  pageHeightMm:          number;
  orientation:           string;
  marginTop:             number;       // mm
  marginRight:           number;
  marginBottom:          number;
  marginLeft:            number;
  fontFamily:            string;
  fontSizeBase:          number;
  accentColor:           string;
  tableStyle:            string;
  headerLogoEnabled:     boolean;
  headerLogoSize:        string;
  headerShowName:        boolean;
  headerShowLegalName:   boolean;
  headerShowCuit:        boolean;
  headerShowAddress:     boolean;
  headerShowPhone:       boolean;
  headerShowEmail:       boolean;
  headerShowWebsite:     boolean;
  headerCustomText:      string;
  currencyShowSymbol:    boolean;
  currencyShowRate:      boolean;
  currencyDecimals:      number;
  pricesIncludeTax:      boolean;
  footerText:            string;
  footerLegalText:       string;
  footerBankData:        string;
  footerTerms:           string;
  footerShowPageNumbers: boolean;
  footerPageFormat:      string;
  footerPagePosition:    string;
  sections:              Record<string, boolean>;
  columns:               ColumnConfig[];
}

export interface PdfJewelry {
  name:         string;
  legalName:    string;
  cuit:         string;
  ivaCondition: string;
  logoUrl:      string;       // puede estar vacio
  fullAddress:  string;       // calle + numero + ciudad ya compuesto por el caller
  phone:        string;
  email:        string;
  website:      string;
}

export interface RenderInvoiceInput {
  sale:     PdfSale;
  receipt:  PdfReceipt | null;
  template: PdfTemplate;
  jewelry:  PdfJewelry;
}

// ─── Helpers PUROS (sin matematica comercial) ─────────────────────────────────

const MM_TO_PT = 2.83465;
function mmToPt(mm: number): number { return mm * MM_TO_PT; }

interface MoneyFmtOpts { showSymbol: boolean; symbol: string; decimals: number; locale?: string }
function formatMoney(value: number, opts: MoneyFmtOpts): string {
  const fmt = new Intl.NumberFormat(opts.locale ?? "es-AR", {
    minimumFractionDigits: opts.decimals,
    maximumFractionDigits: opts.decimals,
  });
  const body = fmt.format(value);
  return opts.showSymbol && opts.symbol ? `${opts.symbol} ${body}` : body;
}

function formatDate(d: Date | string, locale = "es-AR"): string {
  const date = typeof d === "string" ? new Date(d) : d;
  return new Intl.DateTimeFormat(locale, { dateStyle: "medium" }).format(date);
}

function hexToRgb(hex: string): [number, number, number] {
  const m = /^#?([0-9a-fA-F]{6})$/.exec((hex ?? "").trim());
  if (!m) return [26, 26, 26]; // #1a1a1a default
  const v = parseInt(m[1]!, 16);
  return [(v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff];
}

function visibleColumns(cols: ColumnConfig[]): ColumnConfig[] {
  return cols.filter((c) => c.visible).slice().sort((a, b) => a.sortOrder - b.sortOrder);
}

function getPageSize(template: PdfTemplate): [number, number] | string {
  if (template.isCustomSize && template.pageWidthMm > 0 && template.pageHeightMm > 0) {
    return [mmToPt(template.pageWidthMm), mmToPt(template.pageHeightMm)];
  }
  return (template.pageSizePreset || "A4").toUpperCase();
}

/** Devuelve el valor textual de una columna para una linea.
 *  No hace matematica: extrae campos del snapshot y los formatea. */
function getColumnText(
  col:    ColumnConfig,
  line:   PdfSaleLine,
  index:  number,
  moneyOpts: MoneyFmtOpts,
): string {
  switch (col.key) {
    case "position":    return String(index + 1);
    case "code":        return line.sku || "";
    case "sku":         return line.sku || "";
    case "description": return [line.articleName, line.variantName].filter(Boolean).join(" — ");
    case "variant":     return line.variantName || "";
    case "quantity":    return String(line.quantity);
    case "unit":        return "";       // SaleLine no persiste unidad en v1
    case "weight":      return "";       // SaleLine no persiste gramos en v1
    case "unitPrice":   return formatMoney(line.unitPrice, moneyOpts);
    case "discount":    return line.discountPct ? `${line.discountPct}%` : "";
    case "tax":         return line.taxAmount != null ? formatMoney(line.taxAmount, moneyOpts) : "";
    case "subtotal":    return formatMoney(line.lineTotal, moneyOpts);
    default:            return "";
  }
}

// ─── Render principal ─────────────────────────────────────────────────────────

export async function renderInvoicePdf(input: RenderInvoiceInput): Promise<Buffer> {
  const { sale, receipt, template, jewelry } = input;
  const cols     = visibleColumns(template.columns);
  const sections = template.sections;
  const sym      = sale.currencySnapshot?.symbol ?? "";
  const accent   = hexToRgb(template.accentColor);
  const base     = template.fontSizeBase || 10;

  const moneyOpts: MoneyFmtOpts = {
    showSymbol: template.currencyShowSymbol,
    symbol:     sym,
    decimals:   template.currencyDecimals,
  };

  const margins = {
    top:    mmToPt(template.marginTop),
    right:  mmToPt(template.marginRight),
    bottom: mmToPt(template.marginBottom),
    left:   mmToPt(template.marginLeft),
  };

  const doc = new PDFDocument({
    size:    getPageSize(template) as any,
    layout:  template.orientation === "landscape" ? "landscape" : "portrait",
    margins,
    info:    {
      Title:  `Factura ${receipt?.code ?? sale.code}`,
      Author: jewelry.name || "TPTech",
    },
  });

  const chunks: Buffer[] = [];
  doc.on("data", (c) => chunks.push(c));
  const done = new Promise<Buffer>((resolve, reject) => {
    doc.on("end",   () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);
  });

  doc.font("Helvetica").fontSize(base);

  // ── Header ───────────────────────────────────────────────────────────────
  renderHeaderAndMeta({ doc, template, jewelry, sale, receipt, accent, base });

  // ── Cliente ──────────────────────────────────────────────────────────────
  renderClientBlock({ doc, sale, base });

  // ── Tabla de lineas ──────────────────────────────────────────────────────
  if (cols.length > 0 && sale.lines.length > 0) {
    renderLinesTable({ doc, cols, lines: sale.lines, moneyOpts, accent, base });
  }

  // ── Totales (sections-aware) ─────────────────────────────────────────────
  renderTotalsBlock({ doc, sections, sale, moneyOpts, template, base });

  // ── Observaciones ────────────────────────────────────────────────────────
  if (sections.observations && sale.notes && sale.notes.trim().length > 0) {
    doc.moveDown(0.6);
    doc.font("Helvetica-Bold").fontSize(base).text("Observaciones");
    doc.font("Helvetica").fontSize(base).text(sale.notes);
  }

  // ── Terminos y condiciones (del template) ────────────────────────────────
  if (sections.termsAndConditions && template.footerTerms && template.footerTerms.trim().length > 0) {
    doc.moveDown(0.6);
    doc.font("Helvetica-Bold").fontSize(base).text("Términos y condiciones");
    doc.font("Helvetica").fontSize(base).text(template.footerTerms);
  }

  // ── Footer (texto libre + legales + bancarios) ───────────────────────────
  renderFooterTexts({ doc, template, base });

  doc.end();
  return done;
}

// ─── Sub-renderers (cada uno solo dibuja, no calcula) ─────────────────────────

interface HeaderArgs {
  doc:      PDFKit.PDFDocument;
  template: PdfTemplate;
  jewelry:  PdfJewelry;
  sale:     PdfSale;
  receipt:  PdfReceipt | null;
  accent:   [number, number, number];
  base:     number;
}
function renderHeaderAndMeta(args: HeaderArgs): void {
  const { doc, template, jewelry, sale, receipt, accent, base } = args;
  const startY = doc.y;
  const pageW  = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const leftX  = doc.page.margins.left;
  const halfW  = pageW / 2;

  // Logo: solo si esta activo Y hay URL. Si falta el archivo, skip silencioso
  // (no rompe la generacion).
  // TODO(v2): cargar la imagen via `fetch(jewelry.logoUrl)`. v1 omite la imagen
  // remota para no bloquear render con I/O. El bloque de texto del emisor se
  // renderea siempre.
  // Bloque emisor (lado izq).
  doc.font("Helvetica-Bold").fontSize(base + 4)
     .fillColor(`rgb(${accent[0]}, ${accent[1]}, ${accent[2]})`)
     .text(jewelry.name || "—", leftX, startY, { width: halfW, lineGap: 1 });
  doc.font("Helvetica").fontSize(base).fillColor("black");
  if (template.headerShowLegalName && jewelry.legalName) {
    doc.text(jewelry.legalName, { width: halfW });
  }
  if (template.headerShowCuit    && jewelry.cuit)         doc.text(`CUIT: ${jewelry.cuit}`,            { width: halfW });
  if (jewelry.ivaCondition)                               doc.text(`Cond. IVA: ${jewelry.ivaCondition}`, { width: halfW });
  if (template.headerShowAddress && jewelry.fullAddress)  doc.text(jewelry.fullAddress,                 { width: halfW });
  if (template.headerShowPhone   && jewelry.phone)        doc.text(`Tel: ${jewelry.phone}`,             { width: halfW });
  if (template.headerShowEmail   && jewelry.email)        doc.text(jewelry.email,                       { width: halfW });
  if (template.headerShowWebsite && jewelry.website)      doc.text(jewelry.website,                     { width: halfW });
  if (template.headerCustomText && template.headerCustomText.trim().length > 0) {
    doc.text(template.headerCustomText, { width: halfW });
  }
  const leftBottom = doc.y;

  // Bloque comprobante (lado der) — siempre en la misma franja superior.
  const rightX = leftX + halfW + 12;
  const rightW = halfW - 12;
  doc.font("Helvetica-Bold").fontSize(base + 6)
     .fillColor(`rgb(${accent[0]}, ${accent[1]}, ${accent[2]})`)
     .text("FACTURA", rightX, startY, { width: rightW, align: "right" });
  doc.font("Helvetica").fontSize(base).fillColor("black");
  const number = receipt?.code ?? sale.code;
  doc.text(`N° ${number}`, rightX, doc.y, { width: rightW, align: "right" });
  doc.text(`Fecha: ${formatDate(sale.saleDate)}`, rightX, doc.y, { width: rightW, align: "right" });
  if (receipt) {
    doc.text(`Emitida: ${formatDate(receipt.issueDate)}`, rightX, doc.y, { width: rightW, align: "right" });
  }

  const rightBottom = doc.y;
  doc.y = Math.max(leftBottom, rightBottom);
  doc.x = leftX;
  doc.moveDown(0.8);

  // Linea divisoria.
  doc.moveTo(leftX, doc.y).lineTo(leftX + pageW, doc.y)
     .strokeColor(`rgb(${accent[0]}, ${accent[1]}, ${accent[2]})`)
     .lineWidth(0.7).stroke();
  doc.moveDown(0.4);
}

interface ClientArgs { doc: PDFKit.PDFDocument; sale: PdfSale; base: number }
function renderClientBlock(args: ClientArgs): void {
  const { doc, sale, base } = args;
  const c = sale.client;
  doc.font("Helvetica-Bold").fontSize(base).text("Cliente");
  doc.font("Helvetica").fontSize(base);
  if (!c) {
    doc.text("Consumidor final");
  } else {
    doc.text(c.displayName || "—");
    if (c.documentNumber) doc.text(`${c.documentType || "Doc."}: ${c.documentNumber}`);
    if (c.ivaCondition)   doc.text(`Cond. IVA: ${c.ivaCondition}`);
  }
  doc.moveDown(0.6);
}

interface TableArgs {
  doc:       PDFKit.PDFDocument;
  cols:      ColumnConfig[];
  lines:     PdfSaleLine[];
  moneyOpts: MoneyFmtOpts;
  accent:    [number, number, number];
  base:      number;
}
function renderLinesTable(args: TableArgs): void {
  const { doc, cols, lines, moneyOpts, accent, base } = args;
  const pageW = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const leftX = doc.page.margins.left;

  // Anchos: tomamos los `width` declarados por el template como pesos relativos.
  // No es un calculo de negocio; es layout puro.
  const totalDeclared = cols.reduce((acc, c) => acc + (c.width > 0 ? c.width : 60), 0);
  const widths = cols.map((c) => ((c.width > 0 ? c.width : 60) / totalDeclared) * pageW);

  // Header de tabla.
  const headerY = doc.y;
  doc.font("Helvetica-Bold").fontSize(base)
     .fillColor(`rgb(${accent[0]}, ${accent[1]}, ${accent[2]})`);
  let x = leftX;
  cols.forEach((c, i) => {
    doc.text(c.label, x + 2, headerY, { width: widths[i]! - 4, align: c.align });
    x += widths[i]!;
  });
  doc.fillColor("black");
  const headerBottom = doc.y;
  doc.moveTo(leftX, headerBottom + 1).lineTo(leftX + pageW, headerBottom + 1)
     .strokeColor(`rgb(${accent[0]}, ${accent[1]}, ${accent[2]})`).lineWidth(0.5).stroke();
  doc.y = headerBottom + 3;

  // Filas.
  doc.font("Helvetica").fontSize(base);
  lines.forEach((line, idx) => {
    const rowY = doc.y;
    let lineH  = 0;
    let cx     = leftX;
    cols.forEach((c, i) => {
      const text = getColumnText(c, line, idx, moneyOpts);
      doc.text(text, cx + 2, rowY, { width: widths[i]! - 4, align: c.align });
      lineH = Math.max(lineH, doc.y - rowY);
      cx += widths[i]!;
    });
    doc.y = rowY + lineH + 1;
  });
  doc.moveDown(0.4);
  doc.moveTo(leftX, doc.y).lineTo(leftX + pageW, doc.y)
     .strokeColor("#bbbbbb").lineWidth(0.3).stroke();
  doc.moveDown(0.3);
}

interface TotalsArgs {
  doc:       PDFKit.PDFDocument;
  sections:  Record<string, boolean>;
  sale:      PdfSale;
  moneyOpts: MoneyFmtOpts;
  template:  PdfTemplate;
  base:      number;
}
function renderTotalsBlock(args: TotalsArgs): void {
  const { doc, sections, sale, moneyOpts, template, base } = args;
  const pageW = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const leftX = doc.page.margins.left;
  const blockW = pageW * 0.4;
  const blockX = leftX + pageW - blockW;

  const startY = doc.y;
  let y = startY;
  const row = (label: string, value: string, bold = false): void => {
    doc.font(bold ? "Helvetica-Bold" : "Helvetica").fontSize(base);
    doc.text(label, blockX,           y, { width: blockW * 0.55, align: "left"  });
    doc.text(value, blockX + blockW * 0.55, y, { width: blockW * 0.45, align: "right" });
    y = doc.y + 1;
  };

  // Cada fila se imprime SOLO si la seccion esta activa Y el campo del
  // snapshot esta presente. Cero calculo: imprimimos los Numbers como vienen.
  if (sections.subtotal) row("Subtotal", formatMoney(sale.subtotal, moneyOpts));
  if (sections.discount && sale.discountAmount > 0) {
    row("Descuento", `- ${formatMoney(sale.discountAmount, moneyOpts)}`);
  }
  if (sections.taxes && sale.taxAmount > 0) row("Impuestos", formatMoney(sale.taxAmount, moneyOpts));
  if (sections.total) row("Total", formatMoney(sale.total, moneyOpts), true);

  // Cotizacion (si moneda != base y el template lo pide).
  if (sections.exchangeRate && template.currencyShowRate && sale.currencySnapshot?.currencyRate) {
    row("Cotización", String(sale.currencySnapshot.currencyRate));
  }
  // Pago parcial (informativo).
  if (sale.paidAmount > 0) row("Pagado", formatMoney(sale.paidAmount, moneyOpts));

  if (template.pricesIncludeTax) {
    doc.font("Helvetica-Oblique").fontSize(base - 1)
       .text("Precios con impuestos incluidos", blockX, y, { width: blockW, align: "right" });
    y = doc.y;
  }

  doc.y = y;
  doc.moveDown(0.6);
}

interface FooterArgs { doc: PDFKit.PDFDocument; template: PdfTemplate; base: number }
function renderFooterTexts(args: FooterArgs): void {
  const { doc, template, base } = args;
  const parts = [template.footerText, template.footerLegalText, template.footerBankData]
    .filter((t) => t && t.trim().length > 0);
  if (parts.length === 0) return;

  doc.moveDown(0.6);
  doc.font("Helvetica").fontSize(base - 1).fillColor("#555555");
  for (const t of parts) {
    doc.text(t!);
    doc.moveDown(0.2);
  }
  doc.fillColor("black");
}
