// src/modules/sales/__tests__/sales.send-draft-email.contract.test.ts
// =============================================================================
// E2 — Tests del controller `sendDraftEmail`. Verifica el nuevo
// requirement: `saleId` obligatorio en el body — el frontend debe
// persistir el draft antes de invocar este endpoint para garantizar
// trazabilidad en el log documental.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";

const mockService = vi.hoisted(() => ({
  sendSaleDraftByEmail: vi.fn().mockResolvedValue({ messagedRecipient: "x@y.com", filename: "f.pdf" }),
  renderSaleDraftPdf:   vi.fn(),
}));
vi.mock("../sales.draft-pdf.service.js", () => mockService);

// Stub mínimo de `service` (no se usa en estos handlers pero sales.controller lo importa).
vi.mock("../sales.service.js", () => ({}));

import * as controller from "../sales.controller.js";

function makeReq(body: any) {
  return {
    user: { jewelryId: "jw-1", id: "user-1" },
    body,
  };
}

function makeRes() {
  const res: any = {
    statusCode: 200,
    headers:    {} as Record<string, string>,
    body:       null as any,
    setHeader(k: string, v: string)  { this.headers[k] = v; },
    send(b: any)                      { this.body = b; return this; },
    json(b: any)                      { this.body = b; return this; },
    status(c: number)                 { this.statusCode = c; return this; },
  };
  return res;
}

function validBody(over: Partial<any> = {}) {
  return {
    printable: {
      config: {},
      company: { name: "T" },
      documentNumber: "A-1",
      documentDate: "2026-05-26",
      clientName: "C",
      lines: [],
      totals: { subtotal: 100, discountAmount: 0, taxAmount: 0, total: 100 },
      currencyCode: "ARS",
      fxRate: 1,
    },
    page: { widthMm: 210, heightMm: 297, orientation: "portrait" },
    filename: "Factura.pdf",
    to:      "cliente@example.com",
    subject: "Factura A-1",
    message: "Adjuntamos.",
    saleId:  "sale-123",
    ...over,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockService.sendSaleDraftByEmail.mockResolvedValue({ messagedRecipient: "x", filename: "f.pdf" });
});

describe("sendDraftEmail controller — saleId obligatorio (E2)", () => {
  it("body completo con saleId → llama al service y responde 200 ok", async () => {
    const req = makeReq(validBody());
    const res = makeRes();

    await controller.sendDraftEmail(req, res);

    expect(mockService.sendSaleDraftByEmail).toHaveBeenCalledOnce();
    const [input, jewelryId, sentByUserId] = mockService.sendSaleDraftByEmail.mock.calls[0]!;
    expect(input.saleId).toBe("sale-123");
    expect(jewelryId).toBe("jw-1");
    expect(sentByUserId).toBe("user-1");
    expect(res.body).toMatchObject({ ok: true });
  });

  it("sin saleId → rechaza con 400 antes de tocar el service", async () => {
    const body = validBody();
    delete (body as Record<string, unknown>).saleId;
    const req = makeReq(body);
    const res = makeRes();

    await expect(controller.sendDraftEmail(req, res)).rejects.toMatchObject({
      status: 400,
    });
    expect(mockService.sendSaleDraftByEmail).not.toHaveBeenCalled();
  });

  it("saleId vacío (string vacío) → rechaza con 400", async () => {
    const req = makeReq(validBody({ saleId: "" }));
    const res = makeRes();
    await expect(controller.sendDraftEmail(req, res)).rejects.toMatchObject({ status: 400 });
    expect(mockService.sendSaleDraftByEmail).not.toHaveBeenCalled();
  });

  it("saleId solo espacios → rechaza con 400", async () => {
    const req = makeReq(validBody({ saleId: "   " }));
    const res = makeRes();
    await expect(controller.sendDraftEmail(req, res)).rejects.toMatchObject({ status: 400 });
    expect(mockService.sendSaleDraftByEmail).not.toHaveBeenCalled();
  });
});
