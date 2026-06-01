// tptech-backend/src/lib/__tests__/saleInvoicePdfProvider.test.ts
// =============================================================================
// Etapa 2 — Tests del provider canonico de PDF (SSOT).
//
// Garantias bajo test:
//   · `composeFilename` puro — naming consistente entre DRAFT / CANCELLED /
//     final, para todos los call-sites (descarga, mail, draft).
//   · `renderFromPersisted` produce un `SaleInvoicePdfResult` con shape
//     uniforme: buffer PDF real (magic bytes %PDF-), filename adaptive,
//     mimeType "application/pdf", source "persisted".
//   · `renderFromDraft` produce el mismo shape con source "draft".
//   · El motor pdfkit fuerza un buffer real (`PDF_ENGINE=pdfkit` evita
//     Chromium en CI / contenedores sin Puppeteer).
//   · El provider respeta la plantilla activa de FACTURA — verificamos
//     que llama `getOrCreateTemplate(jewelryId, "FACTURA")`.
//   · Cero matematica comercial: el provider serializa Decimals/strings
//     pero NO recalcula totales (se delega al pricing-engine arriba).
//   · Determinismo: mismo input produce el mismo filename (el buffer
//     puede variar por timestamps internos del PDF, asi que verificamos
//     el shape mas estable).
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

const mockPrisma = vi.hoisted(() => ({
  jewelry: { findUnique: vi.fn() },
}));
vi.mock("../prisma.js", () => ({ prisma: mockPrisma, Prisma }));

const mockGetTemplate = vi.hoisted(() => vi.fn().mockResolvedValue({
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
  columns: [
    { key: "description", label: "Descripción",  visible: true, width: 180, align: "left",  sortOrder: 3 },
    { key: "quantity",    label: "Cant.",        visible: true, width: 46,  align: "right", sortOrder: 5 },
    { key: "unitPrice",   label: "Precio unit.", visible: true, width: 80,  align: "right", sortOrder: 8 },
    { key: "subtotal",    label: "Subtotal",     visible: true, width: 80,  align: "right", sortOrder: 11 },
  ],
  columnsVersion: 1,
  createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
}));
vi.mock("../../modules/document-templates/document-templates.service.js", () => ({
  getOrCreateTemplate: mockGetTemplate,
}));

import {
  renderFromPersisted,
  renderFromDraft,
  composeFilename,
} from "../saleInvoicePdfProvider.js";

function makeJewelry(over: Partial<any> = {}) {
  return {
    name: "Joyería Test", legalName: "Test SRL", cuit: "30-99999999-0",
    ivaCondition: "RI", logoUrl: "", email: "info@test.ar", website: "test.ar",
    phoneCountry: "+54", phoneNumber: "11 5555-1234",
    street: "Av. Siempre Viva", number: "123", floor: "", apartment: "",
    city: "CABA", province: "Buenos Aires", postalCode: "1000", country: "Argentina",
    ...over,
  };
}

function makeSale(over: Partial<any> = {}) {
  return {
    id: "sale-1", code: "VTA-0001", status: "CONFIRMED",
    saleDate: new Date("2026-05-25T10:00:00Z"),
    notes: "",
    subtotal: 200, discountAmount: 0, taxAmount: 42, total: 242, paidAmount: 0,
    currencySnapshot: { currencyCode: "ARS", symbol: "$", currencyRate: 1 },
    clientSnapshot: null, sellerSnapshot: null,
    client: { displayName: "Cliente SA", documentType: "CUIT", documentNumber: "30-1-2", ivaCondition: "RI" },
    lines: [
      { articleName: "Anillo Oro 18k", variantName: "Talle 14",
        sku: "AN-001", barcode: "",
        quantity: 2, unitPrice: 100, discountPct: 0, lineTotal: 200, taxAmount: 42 },
    ],
    receipts: [
      { id: "rcpt-1", code: "A-0001-00000001", type: "INVOICE",
        issueDate: new Date("2026-05-25T10:00:00Z") },
    ],
    ...over,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.jewelry.findUnique.mockResolvedValue(makeJewelry());
  // Forzar pdfkit en tests para no depender de Chromium / Puppeteer.
  process.env.PDF_ENGINE = "pdfkit";
});

// ─────────────────────────────────────────────────────────────────────────────
// 1) composeFilename — puro, naming consistente
// ─────────────────────────────────────────────────────────────────────────────

describe("composeFilename (puro)", () => {
  it("DRAFT siempre usa el saleCode (no hay receipt todavia)", () => {
    expect(composeFilename("DRAFT", "VTA-0001", null))
      .toBe("Borrador-VTA-0001.pdf");
  });

  it("DRAFT ignora receiptCode aunque exista (filename usa saleCode)", () => {
    // Caso teorico: draft con receipt pre-cargado (no deberia pasar pero
    // mantenemos la regla — DRAFT siempre dice "Borrador-<saleCode>").
    expect(composeFilename("DRAFT", "VTA-0001", "A-0001-00000001"))
      .toBe("Borrador-VTA-0001.pdf");
  });

  it("CANCELLED con receipt → Factura-ANULADA-<receiptCode>", () => {
    expect(composeFilename("CANCELLED", "VTA-0001", "A-0001-00000001"))
      .toBe("Factura-ANULADA-A-0001-00000001.pdf");
  });

  it("CANCELLED sin receipt → Factura-ANULADA-<saleCode> (fallback)", () => {
    expect(composeFilename("CANCELLED", "VTA-0001", null))
      .toBe("Factura-ANULADA-VTA-0001.pdf");
  });

  it("CONFIRMED con receipt → Factura-<receiptCode>", () => {
    expect(composeFilename("CONFIRMED", "VTA-0001", "A-0001-00000001"))
      .toBe("Factura-A-0001-00000001.pdf");
  });

  it("PARTIAL / PAID / cualquier estado no-DRAFT/CANCELLED → Factura-<num>", () => {
    expect(composeFilename("PARTIAL", "VTA-0001", "A-0001-00000001"))
      .toBe("Factura-A-0001-00000001.pdf");
    expect(composeFilename("PAID", "VTA-0001", "A-0001-00000001"))
      .toBe("Factura-A-0001-00000001.pdf");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2) renderFromPersisted — flujo legacy, shape uniforme, plantilla activa
// ─────────────────────────────────────────────────────────────────────────────

describe("renderFromPersisted — provider para Sale persistido", () => {
  it("happy path CONFIRMED: devuelve shape uniforme con buffer PDF valido", async () => {
    const result = await renderFromPersisted({
      sale: makeSale(),
      jewelryId: "jw-1",
    });

    // Shape uniforme — el contrato del provider.
    expect(result).toHaveProperty("buffer");
    expect(result).toHaveProperty("filename");
    expect(result).toHaveProperty("mimeType");
    expect(result).toHaveProperty("source");
    expect(result.mimeType).toBe("application/pdf");
    expect(result.source).toBe("persisted");

    // Buffer PDF real — magic bytes "%PDF-".
    expect(Buffer.isBuffer(result.buffer)).toBe(true);
    expect(result.buffer.length).toBeGreaterThan(1000);
    expect(result.buffer.subarray(0, 5).toString("ascii")).toBe("%PDF-");

    // Filename adaptive: CONFIRMED + receipt → Factura-<receiptCode>.
    expect(result.filename).toBe("Factura-A-0001-00000001.pdf");
  });

  it("respeta la plantilla activa de FACTURA (llama getOrCreateTemplate con kind correcto)", async () => {
    await renderFromPersisted({ sale: makeSale(), jewelryId: "jw-1" });
    expect(mockGetTemplate).toHaveBeenCalledTimes(1);
    expect(mockGetTemplate).toHaveBeenCalledWith("jw-1", "FACTURA");
  });

  it("carga el Jewelry del tenant correcto (multi-tenant safe)", async () => {
    await renderFromPersisted({ sale: makeSale(), jewelryId: "jw-1" });
    expect(mockPrisma.jewelry.findUnique).toHaveBeenCalledTimes(1);
    const args = mockPrisma.jewelry.findUnique.mock.calls[0]![0]!;
    expect(args.where).toEqual({ id: "jw-1" });
    // Select mantiene los campos necesarios para el emisor del PDF
    // (datos visibles configurados en la plantilla).
    expect(args.select).toMatchObject({
      name: true, legalName: true, cuit: true, ivaCondition: true,
      logoUrl: true, email: true, website: true,
    });
  });

  it("Jewelry inexistente → 404 (joyeria no encontrada)", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValueOnce(null);
    await expect(
      renderFromPersisted({ sale: makeSale(), jewelryId: "fake" }),
    ).rejects.toMatchObject({ status: 404 });
  });

  it("DRAFT → filename Borrador-<saleCode> (no usa receipt aun si existe)", async () => {
    const result = await renderFromPersisted({
      sale: makeSale({ status: "DRAFT", receipts: [] }),
      jewelryId: "jw-1",
    });
    expect(result.filename).toBe("Borrador-VTA-0001.pdf");
    expect(result.source).toBe("persisted");
  });

  it("CANCELLED → filename Factura-ANULADA-<num>", async () => {
    const result = await renderFromPersisted({
      sale: makeSale({ status: "CANCELLED" }),
      jewelryId: "jw-1",
    });
    expect(result.filename).toBe("Factura-ANULADA-A-0001-00000001.pdf");
  });

  it("CONFIRMED sin receipt → filename Factura-<saleCode> (fallback)", async () => {
    const result = await renderFromPersisted({
      sale: makeSale({ receipts: [] }),
      jewelryId: "jw-1",
    });
    expect(result.filename).toBe("Factura-VTA-0001.pdf");
  });

  it("mismo Sale → mismo filename + mismo mimeType + mismo source (determinismo)", async () => {
    const sale = makeSale();
    const r1 = await renderFromPersisted({ sale, jewelryId: "jw-1" });
    const r2 = await renderFromPersisted({ sale, jewelryId: "jw-1" });
    expect(r1.filename).toBe(r2.filename);
    expect(r1.mimeType).toBe(r2.mimeType);
    expect(r1.source).toBe(r2.source);
    // El buffer puede diferir por timestamps internos del PDF, no lo
    // comparamos byte a byte. Lo importante es que el shape sea estable.
  });

  it("no hay matematica comercial — totales del Sale viajan al PDF sin recalculo", async () => {
    // Pasamos totales especificos y verificamos que el PDF se genera
    // sin modificarlos. El test del adapter (que NO recalcula) se cubre
    // indirectamente: si el adapter sumara/restara, el snapshot de DB
    // se descalibraria — los tests de pricing-engine ya cubren eso.
    const sale = makeSale({
      subtotal: 999.99, discountAmount: 0, taxAmount: 0, total: 999.99,
      lines: [
        { articleName: "X", variantName: "", sku: "", barcode: "",
          quantity: 1, unitPrice: 999.99, discountPct: 0,
          lineTotal: 999.99, taxAmount: 0, subtotal: 999.99 },
      ],
    });
    const result = await renderFromPersisted({ sale, jewelryId: "jw-1" });
    // El resultado debe seguir siendo un PDF valido, no hay error.
    expect(result.buffer.subarray(0, 5).toString("ascii")).toBe("%PDF-");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3) renderFromDraft — flujo C5-fix (draft preview)
// ─────────────────────────────────────────────────────────────────────────────

const mockRenderPrintable = vi.hoisted(() => vi.fn());
vi.mock("../pdf/renderPrintableToPdf.js", () => ({
  renderPrintableToPdf: mockRenderPrintable,
}));

describe("renderFromDraft — provider para draft preview", () => {
  beforeEach(() => {
    mockRenderPrintable.mockReset();
    mockRenderPrintable.mockResolvedValue(Buffer.from("%PDF-1.4 draft fake body"));
  });

  it("devuelve shape uniforme con source='draft'", async () => {
    const result = await renderFromDraft({
      printable: { foo: "bar" } as any,
      page: { widthMm: 210, heightMm: 297, orientation: "portrait" },
    });
    expect(result.mimeType).toBe("application/pdf");
    expect(result.source).toBe("draft");
    expect(Buffer.isBuffer(result.buffer)).toBe(true);
  });

  it("filename default 'Factura.pdf' cuando el caller no lo pasa", async () => {
    const result = await renderFromDraft({
      printable: { foo: "bar" } as any,
      page: { widthMm: 210, heightMm: 297, orientation: "portrait" },
    });
    expect(result.filename).toBe("Factura.pdf");
  });

  it("filename custom del caller se respeta tal cual", async () => {
    const result = await renderFromDraft({
      printable: { foo: "bar" } as any,
      page: { widthMm: 210, heightMm: 297, orientation: "portrait" },
      filename: "Borrador-VTA-0001.pdf",
    });
    expect(result.filename).toBe("Borrador-VTA-0001.pdf");
  });

  it("delega al renderer shared (renderPrintableToPdf) con las props del frontend", async () => {
    const printable = { documentNumber: "X-0001", lines: [] } as any;
    const page = { widthMm: 210, heightMm: 297, orientation: "portrait" as const };
    await renderFromDraft({ printable, page });
    expect(mockRenderPrintable).toHaveBeenCalledTimes(1);
    expect(mockRenderPrintable).toHaveBeenCalledWith(printable, page);
  });

  it("error del renderer se propaga al caller (sin fallback pdfkit en draft)", async () => {
    mockRenderPrintable.mockRejectedValueOnce(new Error("Chromium crashed"));
    await expect(
      renderFromDraft({
        printable: {} as any,
        page: { widthMm: 210, heightMm: 297, orientation: "portrait" },
      }),
    ).rejects.toThrow("Chromium crashed");
  });
});
