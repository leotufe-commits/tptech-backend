// src/modules/sales/__tests__/pdf-endpoint.test.ts
// =============================================================================
// 1.B — Tests del flujo `generateSalePdf` (service-level). Mockeamos `prisma`
// y `getOrCreateTemplate`; el renderer corre real (es la mejor forma de
// validar que el PDF sale como Buffer valido).
//
// Cubre:
//   · DRAFT     → 409 SALE_NOT_CONFIRMED.
//   · CANCELLED → 409 SALE_CANCELLED.
//   · CONFIRMED → buffer PDF + filename con Receipt.code.
//   · cross-tenant → 404 (heredado de getSale).
//   · sin Receipt persistido → filename cae al Sale.code interno.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

const mockPrisma = vi.hoisted(() => ({
  sale:    { findFirst: vi.fn() },
  jewelry: { findUnique: vi.fn() },
}));
vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma, Prisma }));

// Template real con defaults — para no acoplar al estado de la DB.
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
    columns: [
      { key: "description", label: "Descripción",  visible: true, width: 180, align: "left",  sortOrder: 3 },
      { key: "quantity",    label: "Cant.",        visible: true, width: 46,  align: "right", sortOrder: 5 },
      { key: "unitPrice",   label: "Precio unit.", visible: true, width: 80,  align: "right", sortOrder: 8 },
      { key: "subtotal",    label: "Subtotal",     visible: true, width: 80,  align: "right", sortOrder: 11 },
    ],
    columnsVersion: 1,
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
  }),
}));

import { generateSalePdf } from "../sales.service.js";

function makeJewelry() {
  return {
    name: "Joyería Test", legalName: "Test SRL", cuit: "30-99999999-0",
    ivaCondition: "RI", logoUrl: "", email: "info@test.ar", website: "test.ar",
    phoneCountry: "+54", phoneNumber: "11 5555-1234",
    street: "Av. Siempre Viva", number: "123", floor: "", apartment: "",
    city: "CABA", province: "Buenos Aires", postalCode: "1000", country: "Argentina",
  };
}

function makeSale(over: Partial<any> = {}) {
  return {
    id:             "sale-1",
    code:           "VTA-0001",
    status:         "CONFIRMED",
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
      {
        id: "rcpt-1", code: "A-0001-00000001", type: "INVOICE",
        direction: "OUTBOUND", status: "ISSUED",
        issueDate: new Date("2026-05-25T10:00:00Z"),
        issuedAt:  new Date("2026-05-25T10:00:00Z"),
      },
    ],
    ...over,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.jewelry.findUnique.mockResolvedValue(makeJewelry());
});

describe("generateSalePdf — pivot funcional (sellos, no bloqueos)", () => {
  it("DRAFT → genera PDF con filename Borrador-<Sale.code>.pdf", async () => {
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({ status: "DRAFT", receipts: [] }));
    const out = await generateSalePdf("sale-1", "jw-1");
    expect(out.buffer.length).toBeGreaterThan(1000);
    expect(out.buffer.subarray(0, 5).toString("ascii")).toBe("%PDF-");
    expect(out.filename).toBe("Borrador-VTA-0001.pdf");
  });

  it("CANCELLED → genera PDF con filename Factura-ANULADA-<numero>.pdf", async () => {
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({ status: "CANCELLED" }));
    const out = await generateSalePdf("sale-1", "jw-1");
    expect(out.buffer.length).toBeGreaterThan(1000);
    expect(out.filename).toBe("Factura-ANULADA-A-0001-00000001.pdf");
  });

  it("CANCELLED sin receipt → filename Factura-ANULADA-<Sale.code>.pdf", async () => {
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({ status: "CANCELLED", receipts: [] }));
    const out = await generateSalePdf("sale-1", "jw-1");
    expect(out.filename).toBe("Factura-ANULADA-VTA-0001.pdf");
  });

  it("CONFIRMED → buffer PDF valido + filename con Receipt.code", async () => {
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());
    const out = await generateSalePdf("sale-1", "jw-1");
    expect(out.buffer).toBeInstanceOf(Buffer);
    expect(out.buffer.length).toBeGreaterThan(1000);
    expect(out.buffer.subarray(0, 5).toString("ascii")).toBe("%PDF-");
    expect(out.filename).toBe("Factura-A-0001-00000001.pdf");
  });

  it("CONFIRMED sin Receipt → filename Factura-<Sale.code>.pdf (fallback)", async () => {
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({ receipts: [] }));
    const out = await generateSalePdf("sale-1", "jw-1");
    expect(out.filename).toBe("Factura-VTA-0001.pdf");
  });

  it("cross-tenant → 404 (getSale falla porque sale no es del tenant)", async () => {
    mockPrisma.sale.findFirst.mockResolvedValueOnce(null);
    await expect(generateSalePdf("sale-1", "otro-tenant")).rejects.toMatchObject({
      status: 404,
    });
  });
});
