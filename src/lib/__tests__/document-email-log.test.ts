// src/lib/__tests__/document-email-log.test.ts
// =============================================================================
// E1 — Tests del helper `createDocumentEmailLog`.
//
// Cobertura:
//   1) Persiste con defaults: status=SENT, provider=postmark, campos
//      opcionales en null.
//   2) Status custom (FAILED) cuando se pasa.
//   3) Multi-tenant: `jewelryId` viaja al payload sin transformación.
//   4) `bodySnapshot` persiste TAL CUAL (texto plano).
//   5) NO LANZA cuando prisma falla — devuelve null + console.error.
//      (es la garantía de "el log no rompe el envío").
//   6) `documentId` es string libre — no se valida FK.
//      Sobrevive a un documentId que NO existe como Sale.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";

const mockPrisma = vi.hoisted(() => ({
  documentEmailLog: { create: vi.fn() },
}));
vi.mock("../prisma.js", () => ({ prisma: mockPrisma }));

import { createDocumentEmailLog } from "../document-email-log.js";

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.documentEmailLog.create.mockResolvedValue({ id: "log-1" });
});

const baseInput = {
  jewelryId:       "jw-1",
  documentKind:    "SALE_INVOICE" as const,
  documentId:      "sale-1",
  recipientEmail:  "cliente@example.com",
  subjectSnapshot: "Factura A-0001-00000001",
  bodySnapshot:    "Adjuntamos su factura. Gracias por confiar en TPTech.",
};

describe("createDocumentEmailLog (E1)", () => {
  it("persiste con defaults: status=SENT, provider=postmark, opcionales=null", async () => {
    const out = await createDocumentEmailLog(baseInput);

    expect(out).toEqual({ id: "log-1" });
    expect(mockPrisma.documentEmailLog.create).toHaveBeenCalledOnce();
    const args = mockPrisma.documentEmailLog.create.mock.calls[0]![0];

    expect(args.data.status).toBe("SENT");
    expect(args.data.provider).toBe("postmark");
    expect(args.data.saleId).toBeNull();
    expect(args.data.providerMessageId).toBeNull();
    expect(args.data.attachmentFilename).toBeNull();
    expect(args.data.sentByUserId).toBeNull();
  });

  it("status FAILED se propaga al payload cuando se pasa explicito", async () => {
    await createDocumentEmailLog({ ...baseInput, status: "FAILED" });
    const args = mockPrisma.documentEmailLog.create.mock.calls[0]![0];
    expect(args.data.status).toBe("FAILED");
  });

  it("multi-tenant: jewelryId viaja al payload sin transformación", async () => {
    await createDocumentEmailLog({ ...baseInput, jewelryId: "tenant-XYZ-123" });
    const args = mockPrisma.documentEmailLog.create.mock.calls[0]![0];
    expect(args.data.jewelryId).toBe("tenant-XYZ-123");
  });

  it("bodySnapshot persiste texto plano TAL CUAL (sin escapes, sin HTML wrap)", async () => {
    const body = "Hola, te paso la factura.\nSaldo a favor de cliente.\n— Juan";
    await createDocumentEmailLog({ ...baseInput, bodySnapshot: body });
    const args = mockPrisma.documentEmailLog.create.mock.calls[0]![0];
    expect(args.data.bodySnapshot).toBe(body);
  });

  it("documentId es string libre — acepta valor que NO matchea ningún Sale", async () => {
    // Caso límite: el caller pasa un id no-existe. El helper no valida
    // FK porque el schema no la tiene. Persiste igual.
    await createDocumentEmailLog({ ...baseInput, documentId: "no-existe-456" });
    const args = mockPrisma.documentEmailLog.create.mock.calls[0]![0];
    expect(args.data.documentId).toBe("no-existe-456");
  });

  it("saleId opcional: cuando se pasa, viaja; cuando se omite, null", async () => {
    await createDocumentEmailLog({ ...baseInput, saleId: "sale-anchor-789" });
    const args = mockPrisma.documentEmailLog.create.mock.calls[0]![0];
    expect(args.data.saleId).toBe("sale-anchor-789");
  });

  it("providerMessageId opcional: se persiste cuando viene del provider", async () => {
    await createDocumentEmailLog({
      ...baseInput,
      providerMessageId: "5d0a2f-postmark-msg-id",
    });
    const args = mockPrisma.documentEmailLog.create.mock.calls[0]![0];
    expect(args.data.providerMessageId).toBe("5d0a2f-postmark-msg-id");
  });

  it("attachmentFilename opcional: se persiste cuando viene", async () => {
    await createDocumentEmailLog({
      ...baseInput,
      attachmentFilename: "Factura-A-0001-00000001.pdf",
    });
    const args = mockPrisma.documentEmailLog.create.mock.calls[0]![0];
    expect(args.data.attachmentFilename).toBe("Factura-A-0001-00000001.pdf");
  });

  it("sentByUserId opcional: se persiste cuando viene del context del request", async () => {
    await createDocumentEmailLog({ ...baseInput, sentByUserId: "user-42" });
    const args = mockPrisma.documentEmailLog.create.mock.calls[0]![0];
    expect(args.data.sentByUserId).toBe("user-42");
  });

  it("NUNCA lanza — si prisma.create falla, devuelve null + console.error", async () => {
    mockPrisma.documentEmailLog.create.mockRejectedValueOnce(new Error("DB down"));
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);

    try {
      const out = await createDocumentEmailLog(baseInput);
      expect(out).toBeNull();                  // ← contract: returns null, doesn't throw
      expect(errSpy).toHaveBeenCalledWith(
        "[document-email-log] failed to persist log:",
        expect.any(Error),
      );
    } finally {
      errSpy.mockRestore();
    }
  });
});
