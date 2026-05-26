// src/modules/sales/__tests__/send-email.test.ts
// =============================================================================
// 1.D — Tests del flujo `sendSaleByEmail` (service-level).
//
// Mockeamos:
//   · `prisma.sale.findFirst`  → estado del sale + receipts.
//   · `prisma.jewelry.findUnique` → datos del emisor (logo/CUIT/dir/email).
//   · `getOrCreateTemplate`    → plantilla FACTURA con defaults.
//   · `sendMail`               → spy para validar payload + attachments.
//
// El renderer del PDF corre real (validamos que llega un Buffer
// application/pdf con la magic bytes esperadas).
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

const mockPrisma = vi.hoisted(() => ({
  sale:    { findFirst:  vi.fn() },
  jewelry: { findUnique: vi.fn() },
  // E2 — el flujo de envío persiste un log documental al final.
  // Mockeado para que no contamine los asserts del happy path.
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

const mockSendMail = vi.hoisted(() => vi.fn().mockResolvedValue({ messageId: null }));
vi.mock("../../../lib/mail.service.js", () => ({ sendMail: mockSendMail }));

import { sendSaleByEmail } from "../sales.service.js";

function makeJewelry(over: Partial<any> = {}) {
  return {
    name: "Joyería Test", legalName: "Test SRL", cuit: "30-99999999-0",
    ivaCondition: "RI", logoUrl: "", email: "joyeria@tenant.example", website: "test.ar",
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
        direction: "OUTBOUND", status: "ISSUED",
        issueDate: new Date("2026-05-25T10:00:00Z"),
        issuedAt:  new Date("2026-05-25T10:00:00Z") },
    ],
    ...over,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.jewelry.findUnique.mockResolvedValue(makeJewelry());
  mockSendMail.mockResolvedValue({ messageId: null });
  // C5 — Fijamos el motor en pdfkit para que el attachment sea un PDF
  // real sin lanzar Chromium. La selección de motor se cubre en
  // `pdf-engine-switch.test.ts`.
  process.env.PDF_ENGINE = "pdfkit";
});

const HAPPY_INPUT = {
  to:      "cliente@example.com",
  subject: "Factura A-0001-00000001 - Joyería Test",
  message: "Hola,\n\nAdjunto te enviamos la factura A-0001-00000001.\n\nSaludos.",
};

describe("sendSaleByEmail — pivot funcional (sellos, no bloqueos)", () => {
  it("DRAFT → envia con attachment Borrador-<code>.pdf (no bloquea)", async () => {
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({ status: "DRAFT", receipts: [] }));
    const out = await sendSaleByEmail("sale-1", "jw-1", HAPPY_INPUT);
    expect(out.filename).toBe("Borrador-VTA-0001.pdf");
    expect(mockSendMail).toHaveBeenCalledTimes(1);
    expect(mockSendMail.mock.calls[0]![0]!.attachments[0]).toMatchObject({
      filename:    "Borrador-VTA-0001.pdf",
      contentType: "application/pdf",
    });
  });

  it("CANCELLED → envia con attachment Factura-ANULADA-<num>.pdf (no bloquea)", async () => {
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({ status: "CANCELLED" }));
    const out = await sendSaleByEmail("sale-1", "jw-1", HAPPY_INPUT);
    expect(out.filename).toBe("Factura-ANULADA-A-0001-00000001.pdf");
    expect(mockSendMail).toHaveBeenCalledTimes(1);
  });

  it("CONFIRMED sin receipts → envia con filename Factura-<Sale.code>.pdf (fallback, no bloquea)", async () => {
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({ receipts: [] }));
    const out = await sendSaleByEmail("sale-1", "jw-1", HAPPY_INPUT);
    expect(out.filename).toBe("Factura-VTA-0001.pdf");
    expect(mockSendMail).toHaveBeenCalledTimes(1);
  });

  it("cross-tenant → 404 (getSale devuelve null) y NO llama a sendMail", async () => {
    mockPrisma.sale.findFirst.mockResolvedValueOnce(null);
    await expect(sendSaleByEmail("sale-1", "otro-tenant", HAPPY_INPUT))
      .rejects.toMatchObject({ status: 404 });
    expect(mockSendMail).not.toHaveBeenCalled();
  });

  it("CONFIRMED happy path → genera PDF, llama sendMail con attachment application/pdf + ReplyTo del tenant", async () => {
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());
    const out = await sendSaleByEmail("sale-1", "jw-1", HAPPY_INPUT);

    expect(out.filename).toBe("Factura-A-0001-00000001.pdf");
    expect(out.messagedRecipient).toBe("cliente@example.com");

    expect(mockSendMail).toHaveBeenCalledTimes(1);
    const call = mockSendMail.mock.calls[0]![0]!;
    expect(call.to).toBe("cliente@example.com");
    expect(call.subject).toBe(HAPPY_INPUT.subject);
    expect(call.text).toBe(HAPPY_INPUT.message);
    expect(call.html).toContain("<pre");
    expect(call.replyTo).toBe("joyeria@tenant.example");
    expect(call.attachments).toHaveLength(1);
    expect(call.attachments[0]).toMatchObject({
      filename:    "Factura-A-0001-00000001.pdf",
      contentType: "application/pdf",
    });
    // Validamos que el adjunto sea un PDF real (no un buffer vacio).
    const buf: Buffer = call.attachments[0].content;
    expect(Buffer.isBuffer(buf)).toBe(true);
    expect(buf.length).toBeGreaterThan(1000);
    expect(buf.subarray(0, 5).toString("ascii")).toBe("%PDF-");
  });

  it("sin email de joyeria configurado → omite ReplyTo (no rompe)", async () => {
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());
    mockPrisma.jewelry.findUnique
      .mockReset()
      // Primera llamada: la hace generateSalePdf (para componer el emisor).
      .mockResolvedValueOnce(makeJewelry({ email: "" }))
      // Segunda llamada: la hace sendSaleByEmail para resolver replyTo.
      .mockResolvedValueOnce({ email: "" });

    await sendSaleByEmail("sale-1", "jw-1", HAPPY_INPUT);
    const call = mockSendMail.mock.calls[0]![0]!;
    expect(call.replyTo).toBeUndefined();
  });

  it("HTML del cuerpo escapea entidades del message del usuario", async () => {
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());
    await sendSaleByEmail("sale-1", "jw-1", {
      ...HAPPY_INPUT,
      message: 'Mira <script>alert("xss")</script> & comp <3',
    });
    const call = mockSendMail.mock.calls[0]![0]!;
    expect(call.html).not.toContain("<script>");
    expect(call.html).toContain("&lt;script&gt;");
    expect(call.html).toContain("&amp;");
  });
});
