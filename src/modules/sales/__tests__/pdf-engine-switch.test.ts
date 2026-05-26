// src/modules/sales/__tests__/pdf-engine-switch.test.ts
// =============================================================================
// C5 — Tests del selector de motor PDF + fallback automático.
//
// Mockeamos los DOS renderers (HTML y pdfkit) y observamos cuál se
// invoca según `PDF_ENGINE` y según si HTML falla. NO lanzamos Chromium
// ni generamos PDFs reales: lo único que importa acá es la decisión
// del switch + el comportamiento del fallback.
//
// Cobertura:
//   1) Default (sin PDF_ENGINE)        → HTML.
//   2) PDF_ENGINE="html"               → HTML.
//   3) PDF_ENGINE="pdfkit"             → pdfkit.
//   4) HTML lanza                      → fallback transparente a pdfkit,
//                                        emite console.warn.
//   5) downloadPdf y sendEmail comparten el helper (un único PDF por
//      operación; no se duplica ni se recalcula nada).
//   6) El input que recibe el renderer es el mismo en cualquier rama
//      (no se mutan / recalculan montos según el motor).
// =============================================================================

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Prisma } from "@prisma/client";

// ─── Mocks ───────────────────────────────────────────────────────────────────

const mockPrisma = vi.hoisted(() => ({
  sale:    { findFirst: vi.fn() },
  jewelry: { findUnique: vi.fn() },
  // E2 — log documental persistido al final del flujo de envío.
  documentEmailLog: { create: vi.fn().mockResolvedValue({ id: "log-1" }) },
}));
vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma, Prisma }));

vi.mock("../../document-templates/document-templates.service.js", () => ({
  getOrCreateTemplate: vi.fn().mockResolvedValue({
    id: "tpl-1", kind: "FACTURA", layoutType: "A4", name: "",
    isDefault: true, isActive: true,
    headerLogoEnabled: false, headerLogoSize: "md", headerLogoPosition: "left", headerLogoBorderRadius: 0,
    headerShowProductImage: false, headerShowName: true, headerShowLegalName: false,
    headerShowCuit: true, headerShowAddress: true, headerShowPhone: true,
    headerShowEmail: false, headerShowWebsite: false, headerCustomText: "",
    pageSizePreset: "A4", isCustomSize: false, pageWidthMm: 210, pageHeightMm: 297, orientation: "portrait",
    marginTop: 15, marginRight: 15, marginBottom: 20, marginLeft: 15,
    fontFamily: "inter", fontSizeBase: 10, accentColor: "#1a1a1a", tableStyle: "bordered",
    currencyShowSymbol: true, currencyShowRate: false, currencyDecimals: 2, pricesIncludeTax: false,
    footerText: "", footerLegalText: "", footerBankData: "", footerTerms: "",
    footerShowPageNumbers: true, footerPageFormat: "page_of_total", footerPagePosition: "bottom_right",
    sections: { subtotal: true, total: true, discount: true, taxes: true, observations: true, fiscalData: true },
    columns: [],
    columnsVersion: 1,
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
  }),
}));

const mockSendMail = vi.hoisted(() => vi.fn().mockResolvedValue({ messageId: null }));
vi.mock("../../../lib/mail.service.js", () => ({ sendMail: mockSendMail }));

// Mock de AMBOS renderers. Devuelven Buffers con marcador identificable
// para que el test sepa cuál corrió.
const mockRenderPdfkit = vi.hoisted(() => vi.fn().mockResolvedValue(Buffer.from("PDFKIT_OUTPUT")));
vi.mock("../pdf/renderInvoicePdf.js", async (importOriginal) => {
  // Importamos el original SOLO para preservar los tipos exportados que
  // el service consume (`RenderInvoiceInput`). El renderer real no se
  // ejecuta — el spy `mockRenderPdfkit` lo intercepta.
  const actual = await importOriginal<typeof import("../pdf/renderInvoicePdf.js")>();
  return {
    ...actual,
    renderInvoicePdf: mockRenderPdfkit,
  };
});

const mockRenderHtml = vi.hoisted(() => vi.fn().mockResolvedValue(Buffer.from("HTML_OUTPUT")));
vi.mock("../pdf/renderInvoicePdfFromHtml.js", () => ({
  renderInvoicePdfFromHtml: mockRenderHtml,
}));

import { generateSalePdf, sendSaleByEmail } from "../sales.service.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

function makeJewelry() {
  return {
    name: "Joyería Test", legalName: "Test SRL", cuit: "30-99999999-0",
    ivaCondition: "RI", logoUrl: "", email: "info@test.ar", website: "test.ar",
    phoneCountry: "+54", phoneNumber: "11 5555-1234",
    street: "Av. Siempre Viva", number: "123", floor: "", apartment: "",
    city: "CABA", province: "Buenos Aires", postalCode: "1000", country: "Argentina",
  };
}

function makeSale() {
  return {
    id:             "sale-1",
    code:           "VTA-0001",
    status:         "PENDING",
    saleDate:       new Date("2026-05-25T10:00:00Z"),
    notes:          "",
    subtotal:       200,
    discountAmount: 0,
    taxAmount:      42,
    total:          242,
    paidAmount:     0,
    currencySnapshot: { currencyCode: "ARS", symbol: "$", currencyRate: 1 },
    clientSnapshot:  null,
    sellerSnapshot:  null,
    client: { displayName: "Cliente SA", documentType: "CUIT", documentNumber: "30-1-2", ivaCondition: "RI" },
    lines: [
      {
        articleName: "Anillo Oro 18k", variantName: "Talle 14",
        sku: "AN-001", barcode: "",
        quantity: 2, unitPrice: 100, discountPct: 0, lineTotal: 200, taxAmount: 42,
      },
    ],
    receipts: [
      { id: "rcpt-1", code: "A-0001-00000001", type: "INVOICE",
        direction: "OUTBOUND", status: "ISSUED",
        issueDate: new Date("2026-05-25T10:00:00Z"),
        issuedAt:  new Date("2026-05-25T10:00:00Z") },
    ],
  };
}

const ORIG_PDF_ENGINE = process.env.PDF_ENGINE;

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.jewelry.findUnique.mockResolvedValue(makeJewelry());
  // Reset de los mocks de renderer (default exitoso).
  mockRenderHtml.mockResolvedValue(Buffer.from("HTML_OUTPUT"));
  mockRenderPdfkit.mockResolvedValue(Buffer.from("PDFKIT_OUTPUT"));
});

afterEach(() => {
  // Limpieza para no contaminar otros tests del repo.
  if (ORIG_PDF_ENGINE === undefined) delete process.env.PDF_ENGINE;
  else                                process.env.PDF_ENGINE = ORIG_PDF_ENGINE;
});

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("PDF engine switch (C5)", () => {
  it("sin PDF_ENGINE setea default a html y usa el renderer HTML", async () => {
    delete process.env.PDF_ENGINE;
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());

    const out = await generateSalePdf("sale-1", "jw-1");

    expect(mockRenderHtml).toHaveBeenCalledOnce();
    expect(mockRenderPdfkit).not.toHaveBeenCalled();
    expect(out.buffer.toString()).toBe("HTML_OUTPUT");
  });

  it("PDF_ENGINE=html usa el renderer HTML", async () => {
    process.env.PDF_ENGINE = "html";
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());

    const out = await generateSalePdf("sale-1", "jw-1");

    expect(mockRenderHtml).toHaveBeenCalledOnce();
    expect(mockRenderPdfkit).not.toHaveBeenCalled();
    expect(out.buffer.toString()).toBe("HTML_OUTPUT");
  });

  it("PDF_ENGINE=pdfkit usa el renderer legacy y NO invoca HTML", async () => {
    process.env.PDF_ENGINE = "pdfkit";
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());

    const out = await generateSalePdf("sale-1", "jw-1");

    expect(mockRenderPdfkit).toHaveBeenCalledOnce();
    expect(mockRenderHtml).not.toHaveBeenCalled();
    expect(out.buffer.toString()).toBe("PDFKIT_OUTPUT");
  });

  it("si HTML lanza, fallback transparente a pdfkit + console.warn", async () => {
    delete process.env.PDF_ENGINE;
    mockRenderHtml.mockRejectedValueOnce(new Error("chromium unavailable"));
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());

    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    try {
      const out = await generateSalePdf("sale-1", "jw-1");

      expect(mockRenderHtml).toHaveBeenCalledOnce();
      expect(mockRenderPdfkit).toHaveBeenCalledOnce();
      expect(out.buffer.toString()).toBe("PDFKIT_OUTPUT");

      // Log del fallback con el motivo embebido para diagnostico.
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringMatching(/\[PDF\] fallback=pdfkit reason=chromium unavailable/),
      );
    } finally {
      warnSpy.mockRestore();
    }
  });

  it("downloadPdf y sendEmail comparten el helper (un único PDF, no se duplica)", async () => {
    delete process.env.PDF_ENGINE;

    // download
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());
    await generateSalePdf("sale-1", "jw-1");

    // email — segunda llamada a sendSaleByEmail. La signatura es
    // (id, jewelryId, { to, subject, message }).
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());
    await sendSaleByEmail("sale-1", "jw-1", {
      to:      "cliente@example.com",
      subject: "Factura A-0001-00000001",
      message: "Adjuntamos su factura.",
    });

    // El renderer HTML se llamó exactamente DOS veces (una por
    // operación). NO se renderea 4 veces ni se invoca pdfkit en
    // paralelo. El mail attachment es el mismo buffer que se
    // generaria para el download.
    expect(mockRenderHtml).toHaveBeenCalledTimes(2);
    expect(mockRenderPdfkit).not.toHaveBeenCalled();
    expect(mockSendMail).toHaveBeenCalledOnce();

    // El attachment del mail tiene el contenido del HTML renderer
    // (los dos paths usan el mismo helper).
    const mailArgs = mockSendMail.mock.calls[0]![0];
    expect(mailArgs.attachments?.[0]?.content.toString()).toBe("HTML_OUTPUT");
  });

  it("ambos renderers reciben EXACTAMENTE el mismo input (sin recálculo)", async () => {
    // Caso 1 — HTML
    process.env.PDF_ENGINE = "html";
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());
    await generateSalePdf("sale-1", "jw-1");
    const htmlInput = mockRenderHtml.mock.calls[0]![0];

    // Caso 2 — pdfkit
    vi.clearAllMocks();
    mockPrisma.jewelry.findUnique.mockResolvedValue(makeJewelry());
    process.env.PDF_ENGINE = "pdfkit";
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());
    await generateSalePdf("sale-1", "jw-1");
    const pdfkitInput = mockRenderPdfkit.mock.calls[0]![0];

    // Los snapshots del sale (subtotal, total, taxAmount) son idénticos
    // — el switch no recalcula nada, sólo cambia el renderer.
    expect(htmlInput.sale.subtotal).toBe(pdfkitInput.sale.subtotal);
    expect(htmlInput.sale.total).toBe(pdfkitInput.sale.total);
    expect(htmlInput.sale.taxAmount).toBe(pdfkitInput.sale.taxAmount);
    expect(htmlInput.sale.lines).toEqual(pdfkitInput.sale.lines);
  });
});
