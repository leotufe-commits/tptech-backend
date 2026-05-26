// src/modules/sales/__tests__/sales.draft-pdf.test.ts
// =============================================================================
// C5-fix Opción A — Tests del flujo render-only desde el draft.
//
// Cobertura:
//   1) `renderSaleDraftPdf` invoca el helper común con los props que
//      recibe (sin transformación intermedia).
//   2) `renderSaleDraftPdf` NO toca prisma (no crea Sale, no persiste).
//   3) `sendSaleDraftByEmail` adjunta el MISMO buffer que se generaría
//      en download → garantiza que el operador recibe lo mismo que ve.
//   4) Watermark BORRADOR/ANULADA se propaga por status (paridad con
//      `SaleInvoicePrintable` del browser print).
//   5) Edits en el draft se reflejan al render — el endpoint NO lee
//      ningún estado persistido.
// =============================================================================

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock prisma — el test verifica que el flujo NO llame a prisma.
const mockPrisma = vi.hoisted(() => ({
  sale:    { findFirst: vi.fn(), create: vi.fn(), update: vi.fn() },
  jewelry: { findUnique: vi.fn().mockResolvedValue({ email: "tenant@example.com" }) },
}));
vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

const mockSendMail = vi.hoisted(() => vi.fn().mockResolvedValue(undefined));
vi.mock("../../../lib/mail.service.js", () => ({ sendMail: mockSendMail }));

// Mock del helper de render (no lanzamos Puppeteer real). Devolvemos un
// buffer con marca para verificar que es el mismo en download y email.
const mockRender = vi.hoisted(() => vi.fn().mockResolvedValue(Buffer.from("DRAFT_PDF_BYTES")));
vi.mock("../../../lib/pdf/renderPrintableToPdf.js", () => ({
  renderPrintableToPdf: mockRender,
}));

import {
  renderSaleDraftPdf,
  sendSaleDraftByEmail,
} from "../sales.draft-pdf.service.js";

// ─── Fixture: draft "vivo" con todos los campos visibles ─────────────────────

function buildDraftRequest(over: { status?: any } = {}) {
  return {
    printable: {
      config:         {},
      company: {
        name:         "Joyería Test",
        legalName:    "Joyería Test SRL",
        cuit:         "30-99999999-0",
        ivaCondition: "RI",
        addressLine:  "Av. Siempre Viva 123, CABA",
        phone:        "+54 11 5555-1234",
        email:        "info@test.ar",
        website:      "test.ar",
      },
      documentNumber: "A-0001-00000001",
      documentDate:   "2026-05-26",
      clientName:     "Cliente Test SA",
      clientTaxId:    "CUIT: 30-12345678-9",
      clientAddress:  "Calle 1, CABA",
      lines: [
        {
          id:        "ln-1",
          articleId: "art-1",
          article:   "Anillo Oro 18k",
          variant:   "Talle 14",
          sku:       "AN-001",
          quantity:  2,
          unitPrice: 500,
          subtotal:  1000,
          lineTotal: 1000,
        },
      ],
      totals: {
        subtotal:       1000,
        discountAmount: 150,
        taxAmount:      178.5,
        total:          1028.5,
      },
      currencyCode:    "ARS",
      fxRate:          1,
      notes:           "Entregar el martes",
      terms:           "Pagos en pesos. No se aceptan devoluciones pasados 30 días.",
      sellerName:      "Juan Pérez",
      warehouseName:   "Depósito Central",
      paymentTermName: "Contado",
      status:          over.status ?? "DRAFT",
    },
    page: {
      widthMm:     210,
      heightMm:    297,
      orientation: "portrait" as const,
    },
    filename: "Borrador-VTA-0001.pdf",
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.jewelry.findUnique.mockResolvedValue({ email: "tenant@example.com" });
  mockRender.mockResolvedValue(Buffer.from("DRAFT_PDF_BYTES"));
});

afterEach(() => {
  vi.clearAllMocks();
});

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("renderSaleDraftPdf — flujo render-only desde draft", () => {
  it("invoca el helper con los props recibidos sin transformación intermedia", async () => {
    const req = buildDraftRequest();

    await renderSaleDraftPdf(req);

    expect(mockRender).toHaveBeenCalledOnce();
    const [props, pageConfig] = mockRender.mock.calls[0]!;
    expect(props).toBe(req.printable);              // mismo objeto, sin clonar/mutar
    expect(pageConfig).toBe(req.page);
  });

  it("NO toca prisma (cero persistencia, cero Sale.create/update/findFirst)", async () => {
    await renderSaleDraftPdf(buildDraftRequest());

    expect(mockPrisma.sale.create).not.toHaveBeenCalled();
    expect(mockPrisma.sale.update).not.toHaveBeenCalled();
    expect(mockPrisma.sale.findFirst).not.toHaveBeenCalled();
  });

  it("devuelve el Buffer del helper directo (sin re-encoding)", async () => {
    const out = await renderSaleDraftPdf(buildDraftRequest());
    expect(Buffer.isBuffer(out)).toBe(true);
    expect(out.toString()).toBe("DRAFT_PDF_BYTES");
  });

  it("edits en el draft se reflejan inmediatamente (no hay caché)", async () => {
    // Mismo `printable` mutado entre llamadas — el endpoint pasa lo que recibe.
    const reqA = buildDraftRequest();
    reqA.printable.totals.total = 100;
    await renderSaleDraftPdf(reqA);
    const [propsA] = mockRender.mock.calls[0]!;
    expect(propsA.totals.total).toBe(100);

    const reqB = buildDraftRequest();
    reqB.printable.totals.total = 999;
    await renderSaleDraftPdf(reqB);
    const [propsB] = mockRender.mock.calls[1]!;
    expect(propsB.totals.total).toBe(999);
  });

  it("propaga status DRAFT al printable (watermark BORRADOR depende del componente)", async () => {
    await renderSaleDraftPdf(buildDraftRequest({ status: "DRAFT" }));
    const [props] = mockRender.mock.calls[0]!;
    expect(props.status).toBe("DRAFT");
  });

  it("propaga status CANCELLED al printable (watermark ANULADA)", async () => {
    await renderSaleDraftPdf(buildDraftRequest({ status: "CANCELLED" }));
    const [props] = mockRender.mock.calls[0]!;
    expect(props.status).toBe("CANCELLED");
  });
});

describe("sendSaleDraftByEmail — adjunto == download", () => {
  it("renderea UNA sola vez y adjunta el mismo buffer del download", async () => {
    const req = {
      ...buildDraftRequest(),
      to:      "cliente@example.com",
      subject: "Factura A-0001-00000001",
      message: "Adjuntamos su factura.",
    };

    await sendSaleDraftByEmail(req, "jw-1");

    // Un único render por operación.
    expect(mockRender).toHaveBeenCalledOnce();
    // Un único mail con el buffer del render como attachment.
    expect(mockSendMail).toHaveBeenCalledOnce();
    const mailArgs = mockSendMail.mock.calls[0]![0];
    expect(mailArgs.to).toBe("cliente@example.com");
    expect(mailArgs.subject).toBe("Factura A-0001-00000001");
    expect(mailArgs.attachments).toHaveLength(1);
    expect(mailArgs.attachments[0].filename).toBe("Borrador-VTA-0001.pdf");
    expect(mailArgs.attachments[0].contentType).toBe("application/pdf");
    expect(mailArgs.attachments[0].content.toString()).toBe("DRAFT_PDF_BYTES");
  });

  it("usa el email del tenant como replyTo cuando está configurado", async () => {
    const req = {
      ...buildDraftRequest(),
      to:      "cliente@example.com",
      subject: "Test",
      message: "Test",
    };
    await sendSaleDraftByEmail(req, "jw-1");

    const mailArgs = mockSendMail.mock.calls[0]![0];
    expect(mailArgs.replyTo).toBe("tenant@example.com");
  });

  it("omite replyTo si el tenant no tiene email configurado", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValueOnce({ email: "" });
    const req = {
      ...buildDraftRequest(),
      to:      "cliente@example.com",
      subject: "Test",
      message: "Test",
    };
    await sendSaleDraftByEmail(req, "jw-1");

    const mailArgs = mockSendMail.mock.calls[0]![0];
    expect(mailArgs.replyTo).toBeUndefined();
  });

  it("NO toca prisma.sale (cero persistencia)", async () => {
    const req = {
      ...buildDraftRequest(),
      to:      "cliente@example.com",
      subject: "Test",
      message: "Test",
    };
    await sendSaleDraftByEmail(req, "jw-1");

    expect(mockPrisma.sale.create).not.toHaveBeenCalled();
    expect(mockPrisma.sale.update).not.toHaveBeenCalled();
    expect(mockPrisma.sale.findFirst).not.toHaveBeenCalled();
  });
});
