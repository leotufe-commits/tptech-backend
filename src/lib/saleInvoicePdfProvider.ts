// tptech-backend/src/lib/saleInvoicePdfProvider.ts
// =============================================================================
// Etapa 2 — PDF unico canonico para Factura de Ventas (provider fachada).
//
// SSOT del PDF de FACTURA. Todos los call-sites que producen un PDF (descarga,
// impresion, adjunto del mail, draft preview) pasan por este modulo — NUNCA
// invocan renderers directos. Asi:
//
//   · Hay un unico punto de entrada con shape uniforme (buffer + filename +
//     mimeType + source). Cualquier cambio futuro en el render (consolidar
//     pdfkit vs HTML, agregar firma digital, watermarks de seguridad) se hace
//     en una sola funcion.
//   · El controller no decide el renderer — solo elige `renderFromPersisted`
//     o `renderFromDraft` segun el endpoint, y el provider se encarga del
//     resto (template activa, motor PDF, fallback, adapter de pdfSale).
//   · El flujo de mail (sendSaleByEmail / sendSaleDraftByEmail) reutiliza
//     el mismo provider que la descarga → garantizado que el adjunto es
//     identico al PDF que el operador acaba de bajar.
//
// Responsabilidades:
//   1. Adapter — convierte `Sale` (persistido, con Decimals/strings) a
//      `PdfSale` (numeros planos) que consume el renderer. Cero matematica
//      comercial — el pricing-engine ya proceso todo y los valores vienen
//      del snapshot.
//   2. Engine selector — decide HTML/Puppeteer vs pdfkit segun `PDF_ENGINE`
//      env; fallback automatico a pdfkit si HTML falla.
//   3. Filename composer — `Borrador-` / `Factura-ANULADA-` / `Factura-`
//      segun el status del sale.
//   4. Draft wrapper — recibe props ya armadas por el frontend y delega
//      a `renderPrintableToPdf` (paridad con el print del browser).
//
// NO responsabilidades:
//   · NO carga el `Sale` de DB. El caller debe pasarlo ya cargado
//     (via `getSale` en sales.service). Esto evita un ciclo de imports
//     con sales.service y mantiene el provider agnostico al "owner"
//     del dominio Sale.
//   · NO toca pricing-engine. Recibe el `Sale` y serializa al renderer.
//   · NO valida estado del Sale. Eso es responsabilidad del caller (que
//     decide si una factura ANULADA puede o no descargarse — la respuesta
//     actual es SI, con filename `Factura-ANULADA-...`).
//
// Replicable: cuando se sumen presupuestos / ordenes / NC / remitos, cada
// uno tendra su propio provider analogico (`quotePdfProvider.ts`,
// `creditNotePdfProvider.ts`, etc.) con la misma interfaz publica
// (`renderFromPersisted` / `renderFromDraft` → `{ buffer, filename,
// mimeType, source }`).
// =============================================================================

import { prisma } from "./prisma.js";
import { getOrCreateTemplate } from "../modules/document-templates/document-templates.service.js";
import {
  renderInvoicePdf,
  type RenderInvoiceInput,
} from "../modules/sales/pdf/renderInvoicePdf.js";
import { renderInvoicePdfFromHtml } from "../modules/sales/pdf/renderInvoicePdfFromHtml.js";
import {
  renderPrintableToPdf,
  type SaleDraftPrintableProps,
  type RenderPrintablePageConfig,
} from "./pdf/renderPrintableToPdf.js";

// ─── Tipos publicos del provider ─────────────────────────────────────────────

/** Resultado uniforme para los 2 flujos (persisted/draft). El `source`
 *  permite a los call-sites distinguir si el PDF salio del Sale persistido
 *  (con receipt oficial, snapshot inmutable) o del draft vivo. */
export type SaleInvoicePdfResult = {
  buffer:   Buffer;
  filename: string;
  /** Hardcoded — todos los PDFs salen como application/pdf. Lo
   *  expongo en el shape para que los callers no lo hardcodeen en
   *  cada `res.setHeader("Content-Type", ...)`. */
  mimeType: "application/pdf";
  source:   "persisted" | "draft";
};

/** Input para el flujo desde Sale persistido. El caller (sales.service)
 *  ya hizo `getSale(id, jewelryId)` con sus validaciones de tenant. */
export type RenderFromPersistedInput = {
  sale:      any;       // Sale completo con receipts/lines/snapshots
  jewelryId: string;
};

/** Input para el flujo draft (props vivas del frontend). 1:1 con
 *  `<SaleInvoicePrintable>` del shared printable. */
export type RenderFromDraftInput = {
  printable: SaleDraftPrintableProps;
  page:      RenderPrintablePageConfig;
  filename?: string;
};

// ─── API publica ─────────────────────────────────────────────────────────────

/**
 * Renderea el PDF oficial desde un Sale persistido.
 *
 * Cadena: adapter `Sale → PdfSale` + carga template/jewelry config +
 * delega al renderer (HTML/Puppeteer con fallback pdfkit). NO valida estado
 * — la decision de bloquear o permitir descarga por estado vive en el
 * caller (sales.service / sales.controller).
 *
 * Filename adaptivo segun status:
 *   · DRAFT     → `Borrador-<Sale.code>.pdf`
 *   · CANCELLED → `Factura-ANULADA-<Receipt.code o Sale.code>.pdf`
 *   · default   → `Factura-<Receipt.code o Sale.code>.pdf`
 */
export async function renderFromPersisted(
  input: RenderFromPersistedInput,
): Promise<SaleInvoicePdfResult> {
  const { sale, jewelryId } = input;
  const receipt = (sale.receipts && sale.receipts.length > 0) ? sale.receipts[0] : null;

  const [template, jewelry] = await Promise.all([
    getOrCreateTemplate(jewelryId, "FACTURA"),
    prisma.jewelry.findUnique({
      where: { id: jewelryId },
      select: {
        name: true, legalName: true, cuit: true, ivaCondition: true,
        logoUrl: true, email: true, website: true,
        phoneCountry: true, phoneNumber: true,
        street: true, number: true, floor: true, apartment: true,
        city: true, province: true, postalCode: true, country: true,
      },
    }),
  ]);

  if (!jewelry) {
    const e: any = new Error("Joyería no encontrada.");
    e.status = 404;
    throw e;
  }

  // Adaptador → PdfSale (numeros ya planos; el renderer es pure).
  const pdfSale = {
    id:              sale.id,
    code:            sale.code,
    status:          sale.status,
    saleDate:        sale.saleDate,
    notes:           sale.notes ?? "",
    subtotal:        toN(sale.subtotal),
    discountAmount:  toN(sale.discountAmount),
    taxAmount:       toN(sale.taxAmount),
    total:           toN(sale.total),
    paidAmount:      toN(sale.paidAmount),
    currencySnapshot: sale.currencySnapshot ?? null,
    clientSnapshot:  sale.clientSnapshot ?? null,
    sellerSnapshot:  sale.sellerSnapshot ?? null,
    client:          sale.client
      ? {
          displayName:    sale.client.displayName ?? "",
          documentType:   sale.client.documentType ?? "",
          documentNumber: sale.client.documentNumber ?? "",
          ivaCondition:   sale.client.ivaCondition ?? "",
        }
      : null,
    lines: (sale.lines ?? []).map((l: any) => ({
      articleName: l.articleName ?? "",
      variantName: l.variantName ?? "",
      sku:         l.sku ?? "",
      barcode:     l.barcode ?? "",
      quantity:    toN(l.quantity),
      unitPrice:   toN(l.unitPrice),
      discountPct: toN(l.discountPct),
      lineTotal:   toN(l.lineTotal),
      taxAmount:   l.taxAmount == null ? null : toN(l.taxAmount),
      // Subtotal pre-descuento de la linea: si el snapshot lo trae
      // explicito, usalo; si no, fallback a `lineTotal` (NO se
      // recalcula — el printable acepta ambos como source de display).
      subtotal:    l.subtotal != null ? toN(l.subtotal) : toN(l.lineTotal),
    })),
    sellerName:      sale.seller?.displayName
                       ?? sale.sellerSnapshot?.displayName
                       ?? sale.sellerSnapshot?.name
                       ?? undefined,
    warehouseName:   sale.warehouse?.name ?? undefined,
    paymentTermName: sale.payments?.[0]?.paymentMethodName ?? undefined,
  };

  const pdfReceipt = receipt
    ? { id: receipt.id, code: receipt.code, type: receipt.type, issueDate: receipt.issueDate }
    : null;

  // Componer la direccion completa del emisor desde los campos atomicos.
  // El renderer NO arma direcciones; solo dibuja la string que recibe.
  const addrParts = [
    [jewelry.street, jewelry.number].filter(Boolean).join(" "),
    [jewelry.floor && `Piso ${jewelry.floor}`, jewelry.apartment && `Dpto ${jewelry.apartment}`].filter(Boolean).join(" "),
    [jewelry.city, jewelry.province, jewelry.postalCode].filter(Boolean).join(", "),
    jewelry.country,
  ].filter((p) => p && p.trim().length > 0);
  const fullAddress = addrParts.join(" — ");
  const phone = [jewelry.phoneCountry, jewelry.phoneNumber].filter((s) => s && s.trim().length > 0).join(" ");

  const pdfJewelry = {
    name:         jewelry.name ?? "",
    legalName:    jewelry.legalName ?? "",
    cuit:         jewelry.cuit ?? "",
    ivaCondition: jewelry.ivaCondition ?? "",
    logoUrl:      jewelry.logoUrl ?? "",
    fullAddress,
    phone,
    email:        jewelry.email ?? "",
    website:      jewelry.website ?? "",
  };

  const buffer = await renderInvoicePdfBuffer({
    sale:     pdfSale,
    receipt:  pdfReceipt,
    template: template as any,
    jewelry:  pdfJewelry,
  });

  const filename = composeFilename(sale.status, sale.code, receipt?.code ?? null);

  return { buffer, filename, mimeType: "application/pdf", source: "persisted" };
}

/**
 * Renderea el PDF desde props vivas del frontend (draft preview / mail
 * sin esperar a confirmar). Garantiza paridad visual con
 * `window.print()` del browser porque ambos consumen el MISMO
 * `<SaleInvoicePrintable>` con las MISMAS props.
 *
 * Sin fallback pdfkit — pdfkit requiere template completo y Sale
 * persistido, que el draft no tiene. Si HTML/Puppeteer falla, el
 * error se propaga al caller (el endpoint legacy `GET /sales/:id/pdf`
 * sigue funcionando como rollback).
 */
export async function renderFromDraft(
  input: RenderFromDraftInput,
): Promise<SaleInvoicePdfResult> {
  console.info("[PDF] engine=html source=draft");
  const buffer   = await renderPrintableToPdf(input.printable, input.page);
  const filename = input.filename ?? "Factura.pdf";
  return { buffer, filename, mimeType: "application/pdf", source: "draft" };
}

// ─── Helpers privados ────────────────────────────────────────────────────────

/**
 * Selector de motor PDF para el flujo PERSISTED (legacy):
 *   · PDF_ENGINE=pdfkit → renderer pdfkit
 *   · PDF_ENGINE=html (default) → renderer HTML/Puppeteer + fallback
 *     pdfkit si HTML falla
 *
 * NO calcula — solo selecciona el motor y propaga el input. Es el
 * unico lugar del sistema donde se decide HTML vs pdfkit.
 */
async function renderInvoicePdfBuffer(input: RenderInvoiceInput): Promise<Buffer> {
  const engine = (process.env.PDF_ENGINE ?? "html").toLowerCase();

  if (engine === "pdfkit") {
    console.info("[PDF] engine=pdfkit");
    return renderInvoicePdf(input);
  }

  // Default y "html": intentamos HTML, fallback transparente a pdfkit.
  try {
    const buffer = await renderInvoicePdfFromHtml(input);
    console.info("[PDF] engine=html");
    return buffer;
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    console.warn(`[PDF] fallback=pdfkit reason=${reason}`);
    return renderInvoicePdf(input);
  }
}

/**
 * Compone el filename del PDF segun status. Helper PURO — testeable
 * directo. El renderer y el provider lo usan como SSOT del naming.
 */
export function composeFilename(
  status:      string,
  saleCode:    string,
  receiptCode: string | null,
): string {
  const visibleNumber = receiptCode ?? saleCode;
  switch (status) {
    case "DRAFT":     return `Borrador-${saleCode}.pdf`;
    case "CANCELLED": return `Factura-ANULADA-${visibleNumber}.pdf`;
    default:          return `Factura-${visibleNumber}.pdf`;
  }
}

/** Conversion segura Decimal/string/number → number. Solo para serializar
 *  al renderer; NO se usa para calcular nada (mismo helper que tenia
 *  sales.service — movido aca para mantener el provider auto-contenido). */
function toN(v: any): number {
  if (v == null) return 0;
  if (typeof v === "number") return v;
  if (typeof v === "string") return Number(v) || 0;
  if (typeof v === "object" && typeof (v as { toNumber?: () => number }).toNumber === "function") {
    return (v as { toNumber: () => number }).toNumber();
  }
  return Number(v) || 0;
}
