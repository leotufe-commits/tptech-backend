// src/modules/sales/__tests__/renderInvoicePdfFromHtml.test.ts
// =============================================================================
// C4 — Tests del renderer HTML/Puppeteer. NO lanzan Chromium real:
// mockeamos Browser + Page + el cargador del componente compartido.
//
// Cobertura:
//   1) `page.setContent` recibe HTML que contiene los datos del comprobante
//      (número, totales, nombre del cliente).
//   2) `page.pdf` se llama con `printBackground: true` y `margin` mapeado
//      del DocumentTemplate (mm → "Nmm").
//   3) `page.close()` se invoca SIEMPRE — incluso si `page.pdf` lanza.
//   4) Si la generación falla, el error se propaga al caller (C5
//      tendrá su propio fallback a pdfkit alrededor de esto).
//   5) Devuelve un `Buffer` aunque page.pdf entregue un `Uint8Array`.
// =============================================================================

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  renderInvoicePdfFromHtml,
  __setPrintableLoaderForTests,
} from "../pdf/renderInvoicePdfFromHtml.js";
import type { RenderInvoiceInput } from "../pdf/renderInvoicePdf.js";
import React from "react";

// ─── Fixture builder ─────────────────────────────────────────────────────────

function buildInput(over: { withClient?: boolean; status?: string } = {}): RenderInvoiceInput {
  return {
    sale: {
      id:               "sale-1",
      code:             "VTA-0001",
      status:           over.status ?? "PENDING",
      saleDate:         new Date("2026-05-25T10:00:00Z"),
      notes:            "Entrega martes",
      subtotal:         200,
      discountAmount:   0,
      taxAmount:        42,
      total:            242,
      paidAmount:       0,
      currencySnapshot: { currencyCode: "ARS", symbol: "$", currencyRate: 1 },
      clientSnapshot:   null,
      sellerSnapshot:   null,
      client: over.withClient
        ? { displayName: "Acme SA", documentType: "CUIT", documentNumber: "30-12345678-9", ivaCondition: "RI" }
        : null,
      lines: [
        {
          articleName: "Anillo Oro 18k",
          variantName: "Talle 14",
          sku:         "AN-001",
          barcode:     "",
          quantity:    2,
          unitPrice:   100,
          discountPct: 0,
          lineTotal:   200,
          taxAmount:   42,
        },
      ],
    },
    receipt: {
      id:        "rcpt-1",
      code:      "A-0001-00000001",
      type:      "INVOICE",
      issueDate: new Date("2026-05-25T10:00:00Z"),
    },
    template: {
      pageSizePreset:        "A4",
      isCustomSize:          false,
      pageWidthMm:           210,
      pageHeightMm:          297,
      orientation:           "portrait",
      marginTop:             18,
      marginRight:           12,
      marginBottom:          22,
      marginLeft:            14,
      fontFamily:            "inter",
      fontSizeBase:          10,
      accentColor:           "#1a1a1a",
      tableStyle:            "bordered",
      headerLogoEnabled:     true,
      headerLogoSize:        "md",
      headerShowName:        true,
      headerShowLegalName:   false,
      headerShowCuit:        true,
      headerShowAddress:     true,
      headerShowPhone:       true,
      headerShowEmail:       false,
      headerShowWebsite:     false,
      headerCustomText:      "",
      currencyShowSymbol:    true,
      currencyShowRate:      false,
      currencyDecimals:      2,
      pricesIncludeTax:      false,
      footerText:            "",
      footerLegalText:       "",
      footerBankData:        "",
      footerTerms:           "",
      footerShowPageNumbers: true,
      footerPageFormat:      "page_of_total",
      footerPagePosition:    "bottom_right",
      sections: { seller: true, subtotal: true, total: true, discount: true, taxes: true, observations: true, termsAndConditions: false, fiscalData: true },
      columns:  [],
    },
    jewelry: {
      name:         "Joyería Test",
      legalName:    "Joyería Test SRL",
      cuit:         "30-99999999-0",
      ivaCondition: "RI",
      logoUrl:      "",
      fullAddress:  "Av. Siempre Viva 123, CABA",
      phone:        "+54 11 5555-1234",
      email:        "info@test.ar",
      website:      "test.ar",
    },
  };
}

// ─── Mocks de Puppeteer ──────────────────────────────────────────────────────

function makeMockPage(opts: { pdfThrows?: boolean } = {}) {
  const setContent = vi.fn().mockResolvedValue(undefined);
  const pdf        = opts.pdfThrows
    ? vi.fn().mockRejectedValue(new Error("boom"))
    : vi.fn().mockResolvedValue(Buffer.from("%PDF-1.4 stub %%EOF"));
  const close      = vi.fn().mockResolvedValue(undefined);
  return { setContent, pdf, close };
}

function makeMockBrowser(page: ReturnType<typeof makeMockPage>) {
  return {
    newPage: vi.fn().mockResolvedValue(page),
    connected: true,
    on: vi.fn(),
    close: vi.fn().mockResolvedValue(undefined),
  } as any;
}

// Stub del componente shared — un FC que pinta un marcador con los datos
// críticos. Lo importante NO es el HTML exacto, sino que el renderer
// llame correctamente al componente y le pase los datos. El test mira
// que `page.setContent` reciba el marcador y los datos clave.
const StubPrintable = (props: any) =>
  React.createElement(
    "div",
    { id: "stub-printable" },
    React.createElement("span", { className: "doc-number" }, props.documentNumber),
    React.createElement("span", { className: "client-name" }, props.clientName),
    React.createElement("span", { className: "total" }, String(props.totals.total)),
    React.createElement("span", { className: "status" }, props.status ?? "—"),
  );

beforeEach(() => {
  __setPrintableLoaderForTests(async () => StubPrintable);
});

afterEach(() => {
  __setPrintableLoaderForTests(null);
});

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("renderInvoicePdfFromHtml — render HTML/Puppeteer", () => {
  it("llama page.setContent con HTML que contiene los datos del comprobante", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderInvoicePdfFromHtml(buildInput({ withClient: true }), { browser });

    expect(page.setContent).toHaveBeenCalledOnce();
    const [html, options] = page.setContent.mock.calls[0]!;
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("id=\"stub-printable\"");
    expect(html).toContain("A-0001-00000001");   // documentNumber
    expect(html).toContain("Acme SA");            // clientName
    expect(html).toContain("242");                // total del snapshot
    expect(options).toEqual({ waitUntil: "load" });
  });

  it("page.pdf recibe printBackground true y margin desde el template", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderInvoicePdfFromHtml(buildInput(), { browser });

    expect(page.pdf).toHaveBeenCalledOnce();
    const opts = page.pdf.mock.calls[0]![0];
    expect(opts.printBackground).toBe(true);
    expect(opts.format).toBe("A4");
    expect(opts.margin).toEqual({
      top:    "18mm",
      right:  "12mm",
      bottom: "22mm",
      left:   "14mm",
    });
  });

  it("propaga el status del sale para que el watermark del printable se active", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderInvoicePdfFromHtml(buildInput({ status: "DRAFT" }), { browser });

    const [html] = page.setContent.mock.calls[0]!;
    expect(html).toContain(">DRAFT<");
  });

  it("cierra la page en finally aunque page.pdf lance", async () => {
    const page    = makeMockPage({ pdfThrows: true });
    const browser = makeMockBrowser(page);

    await expect(
      renderInvoicePdfFromHtml(buildInput(), { browser })
    ).rejects.toThrow("boom");

    expect(page.close).toHaveBeenCalledOnce();
  });

  it("propaga el error al caller para que C5 pueda fallback a pdfkit", async () => {
    const page    = makeMockPage({ pdfThrows: true });
    const browser = makeMockBrowser(page);

    await expect(
      renderInvoicePdfFromHtml(buildInput(), { browser })
    ).rejects.toThrow(/boom/);
  });

  it("devuelve Buffer aunque page.pdf entregue Uint8Array", async () => {
    const page    = makeMockPage();
    page.pdf      = vi.fn().mockResolvedValue(new Uint8Array([0x25, 0x50, 0x44, 0x46]));
    const browser = makeMockBrowser(page);

    const out = await renderInvoicePdfFromHtml(buildInput(), { browser });
    expect(Buffer.isBuffer(out)).toBe(true);
    expect(out.subarray(0, 4).toString("ascii")).toBe("%PDF");
  });

  it("no llama a getBrowser si el caller inyecta un browser por opts (testabilidad)", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    // Si el renderer pidiera getBrowser() del pool real, intentaría
    // descargar chromium (lento + red). Como inyectamos uno, debe
    // saltearlo. La señal indirecta: la llamada termina rápido y la
    // newPage del mock se invoca exactamente una vez.
    await renderInvoicePdfFromHtml(buildInput(), { browser });
    expect(browser.newPage).toHaveBeenCalledOnce();
  });
});
