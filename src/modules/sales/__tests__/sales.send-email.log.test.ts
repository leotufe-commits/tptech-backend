// src/modules/sales/__tests__/sales.send-email.log.test.ts
// =============================================================================
// E2 — Tests de integración del logging automático en el flujo
// `sendSaleDraftByEmail` (Opción A, el path render-only).
//
// Cobertura específica del hook:
//   1) Persiste log con status SENT cuando el provider acepta.
//   2) Persiste log con status FAILED cuando el provider lanza —
//      Y propaga el error al caller (la falla NO se traga).
//   3) El log NO impide enviar el mail: si la persistencia del log
//      falla, el envío YA ocurrió y el caller no ve el error del log.
//   4) Multi-tenant: jewelryId del request context viaja al log
//      sin transformación.
//   5) bodySnapshot persiste TEXTO PLANO del mensaje (no el HTML
//      con <pre> que se manda al provider).
//   6) saleId del input se persiste como `saleId` Y como `documentId`
//      en el log (anchor doble: legible por documento, FK-libre).
//   7) providerMessageId del SendMailResult viaja al log.
// =============================================================================

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mockPrisma = vi.hoisted(() => ({
  sale:    { findFirst: vi.fn(), create: vi.fn(), update: vi.fn() },
  jewelry: { findUnique: vi.fn().mockResolvedValue({ email: "tenant@example.com" }) },
  documentEmailLog: { create: vi.fn().mockResolvedValue({ id: "log-1" }) },
}));
vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

const mockSendMail = vi.hoisted(() => vi.fn());
vi.mock("../../../lib/mail.service.js", () => ({ sendMail: mockSendMail }));

const mockRender = vi.hoisted(() => vi.fn().mockResolvedValue(Buffer.from("PDF")));
vi.mock("../../../lib/pdf/renderPrintableToPdf.js", () => ({
  renderPrintableToPdf: mockRender,
}));

import { sendSaleDraftByEmail } from "../sales.draft-pdf.service.js";

function buildInput(over: Partial<{ saleId: string; to: string; subject: string; message: string }> = {}) {
  return {
    printable: {
      config: {}, company: { name: "T" }, documentNumber: "A-1", documentDate: "2026-05-26",
      clientName: "C", lines: [],
      totals: { subtotal: 100, discountAmount: 0, taxAmount: 0, total: 100 },
      currencyCode: "ARS", fxRate: 1,
    },
    page: { widthMm: 210, heightMm: 297, orientation: "portrait" as const },
    filename: "Factura-A-1.pdf",
    to:      over.to      ?? "cliente@example.com",
    subject: over.subject ?? "Factura A-1",
    message: over.message ?? "Adjuntamos su factura.",
    saleId:  over.saleId  ?? "sale-123",
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.jewelry.findUnique.mockResolvedValue({ email: "tenant@example.com" });
  mockPrisma.documentEmailLog.create.mockResolvedValue({ id: "log-1" });
  mockSendMail.mockResolvedValue({ messageId: "postmark-msg-001" });
  mockRender.mockResolvedValue(Buffer.from("PDF"));
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("sendSaleDraftByEmail — E2 logging integration", () => {
  it("(1) provider OK → persiste log con status SENT + messageId", async () => {
    await sendSaleDraftByEmail(buildInput(), "jw-1", "user-42");

    expect(mockPrisma.documentEmailLog.create).toHaveBeenCalledOnce();
    const data = mockPrisma.documentEmailLog.create.mock.calls[0]![0].data;
    expect(data.status).toBe("SENT");
    expect(data.providerMessageId).toBe("postmark-msg-001");
    expect(data.provider).toBe("postmark");
    expect(data.documentKind).toBe("SALE_INVOICE");
  });

  it("(2) provider falla → persiste log FAILED + propaga el error al caller", async () => {
    mockSendMail.mockRejectedValueOnce(new Error("postmark down"));

    await expect(sendSaleDraftByEmail(buildInput(), "jw-1", "user-42"))
      .rejects.toThrow("postmark down");

    // El log se persistió ANTES del throw — auditoría queda registrada.
    expect(mockPrisma.documentEmailLog.create).toHaveBeenCalledOnce();
    const data = mockPrisma.documentEmailLog.create.mock.calls[0]![0].data;
    expect(data.status).toBe("FAILED");
    expect(data.providerMessageId).toBeNull();
  });

  it("(3) log falla pero envío fue OK → caller NO ve error del log", async () => {
    mockPrisma.documentEmailLog.create.mockRejectedValueOnce(new Error("DB down"));
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);

    try {
      // El flujo del envío termina OK aunque el log haya fallado:
      // el helper `createDocumentEmailLog` traga el error y devuelve null.
      await expect(sendSaleDraftByEmail(buildInput(), "jw-1", "user-42"))
        .resolves.toMatchObject({ messagedRecipient: "cliente@example.com" });

      // El envío real (sendMail) sí ocurrió antes del log fallido.
      expect(mockSendMail).toHaveBeenCalledOnce();
      expect(errSpy).toHaveBeenCalled();   // console.error del helper
    } finally {
      errSpy.mockRestore();
    }
  });

  it("(4) multi-tenant: jewelryId del context viaja al log sin transformación", async () => {
    await sendSaleDraftByEmail(buildInput(), "tenant-XYZ-abc", "user-42");
    const data = mockPrisma.documentEmailLog.create.mock.calls[0]![0].data;
    expect(data.jewelryId).toBe("tenant-XYZ-abc");
  });

  it("(5) bodySnapshot persiste TEXTO PLANO del mensaje (no el HTML que se manda al provider)", async () => {
    const message = "Hola Juan,\nTe adjuntamos tu factura.\nGracias.";
    await sendSaleDraftByEmail(buildInput({ message }), "jw-1", "user-42");

    const data = mockPrisma.documentEmailLog.create.mock.calls[0]![0].data;
    expect(data.bodySnapshot).toBe(message);
    // El HTML SÍ va al provider (envuelve el mensaje en <pre>), pero al
    // log persistimos plano.
    const mailCall = mockSendMail.mock.calls[0]![0];
    expect(mailCall.html).toContain("<pre");
    expect(mailCall.text).toBe(message);
  });

  it("(6) saleId del input se persiste como saleId Y como documentId (doble anchor)", async () => {
    await sendSaleDraftByEmail(buildInput({ saleId: "sale-99" }), "jw-1", "user-42");
    const data = mockPrisma.documentEmailLog.create.mock.calls[0]![0].data;
    expect(data.saleId).toBe("sale-99");
    expect(data.documentId).toBe("sale-99");
  });

  it("(7) providerMessageId del SendMailResult viaja al log para futuros webhooks", async () => {
    mockSendMail.mockResolvedValueOnce({ messageId: "uuid-abc-123" });
    await sendSaleDraftByEmail(buildInput(), "jw-1", "user-42");
    const data = mockPrisma.documentEmailLog.create.mock.calls[0]![0].data;
    expect(data.providerMessageId).toBe("uuid-abc-123");
  });

  it("(8) sentByUserId del context se persiste cuando viene", async () => {
    await sendSaleDraftByEmail(buildInput(), "jw-1", "user-7");
    const data = mockPrisma.documentEmailLog.create.mock.calls[0]![0].data;
    expect(data.sentByUserId).toBe("user-7");
  });

  it("(9) sentByUserId null cuando el caller no lo pasa (auditoría preservada igual)", async () => {
    await sendSaleDraftByEmail(buildInput(), "jw-1");
    const data = mockPrisma.documentEmailLog.create.mock.calls[0]![0].data;
    expect(data.sentByUserId).toBeNull();
  });

  it("(10) attachmentFilename del input se persiste en el log", async () => {
    await sendSaleDraftByEmail(buildInput(), "jw-1", "user-42");
    const data = mockPrisma.documentEmailLog.create.mock.calls[0]![0].data;
    expect(data.attachmentFilename).toBe("Factura-A-1.pdf");
  });
});
