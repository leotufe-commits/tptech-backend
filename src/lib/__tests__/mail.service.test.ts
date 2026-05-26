// src/lib/__tests__/mail.service.test.ts
// =============================================================================
// 1.C — Tests del soporte de attachments en mail.service + postmark provider.
//
// Cubre:
//   · MAIL_MODE=preview: sendMail guarda metadata de attachments (filename,
//     contentType, size) en el preview store accesible via registerMailPreviewRoute.
//   · MAIL_MODE=production: postmarkSendMail mapea attachments a base64 con
//     ContentType correcto y los envia a la API de Postmark con ReplyTo.
//
// Mockeamos `fetch` global para el modo production sin tocar la red.
// =============================================================================

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const ORIGINAL_FETCH = globalThis.fetch;

describe("mail.service / postmark — attachments", () => {
  beforeEach(() => {
    vi.resetModules();   // re-importar mail.service con MAIL_MODE actual
  });

  afterEach(() => {
    globalThis.fetch = ORIGINAL_FETCH;
    delete (process.env as Record<string, string | undefined>).MAIL_MODE;
    delete (process.env as Record<string, string | undefined>).POSTMARK_SERVER_TOKEN;
    delete (process.env as Record<string, string | undefined>).MAIL_FROM;
  });

  it("MAIL_MODE=preview: registra metadata de attachments en el preview store", async () => {
    process.env.MAIL_MODE = "preview";
    const { sendMail, registerMailPreviewRoute } = await import("../mail.service.js");

    const pdfBuffer = Buffer.from("%PDF-1.4 fake pdf body — solo para size", "utf-8");
    const res = await sendMail({
      to:      "cliente@example.com",
      subject: "Factura A-0001-00000001",
      html:    "<p>Adjunta la factura</p>",
      text:    "Adjunta la factura",
      from:    "no-reply@tptech.local",
      attachments: [
        { filename: "Factura-A-0001-00000001.pdf", content: pdfBuffer, contentType: "application/pdf" },
      ],
    });

    const previewId = res.previewId;
    expect(previewId).toBeTruthy();

    // Verificamos indirectamente via la ruta de preview HTML — capturamos
    // el body que mande el handler con un mock minimo de Express.
    const handlers = new Map<string, (req: unknown, res: unknown) => void>();
    const fakeApp = { get: (path: string, cb: (req: unknown, res: unknown) => void) => { handlers.set(path, cb); } };
    registerMailPreviewRoute(fakeApp);
    const handler = handlers.get("/dev/mail/:id");
    expect(handler).toBeDefined();

    let sentBody = "";
    const fakeRes = {
      setHeader: () => undefined,
      send:      (b: string) => { sentBody = b; return fakeRes; },
      status:    (_n: number) => fakeRes,
    };
    handler!({ params: { id: previewId } }, fakeRes);

    expect(sentBody).toContain("Adjuntos");
    expect(sentBody).toContain("Factura-A-0001-00000001.pdf");
    expect(sentBody).toContain("application/pdf");
    expect(sentBody).toContain(String(pdfBuffer.length));   // size
  });

  it("MAIL_MODE=production: postmarkSendMail envia Attachments en base64 + ReplyTo + ContentType", async () => {
    process.env.MAIL_MODE             = "production";
    process.env.POSTMARK_SERVER_TOKEN = "token-fake";
    process.env.MAIL_FROM             = "no-reply@tptech.local";

    let capturedBody: string | null = null;
    const mockFetch = vi.fn(async (_url: string, init: { body?: string }) => {
      capturedBody = String(init.body ?? "");
      return new Response(JSON.stringify({ MessageID: "msg-1" }), {
        status: 200, headers: { "Content-Type": "application/json" },
      });
    });
    globalThis.fetch = mockFetch as unknown as typeof globalThis.fetch;

    const { sendMail } = await import("../mail.service.js");
    const pdfBuffer = Buffer.from("%PDF-1.4 sample");
    await sendMail({
      to:       "cliente@example.com",
      subject:  "Factura A-0001-00000001",
      html:     "<p>Hola</p>",
      text:     "Hola",
      replyTo:  "joyeria@tenant.example",
      attachments: [
        { filename: "Factura-A-0001-00000001.pdf", content: pdfBuffer, contentType: "application/pdf" },
      ],
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(capturedBody).not.toBeNull();
    const body = JSON.parse(capturedBody!);
    expect(body.To).toBe("cliente@example.com");
    expect(body.ReplyTo).toBe("joyeria@tenant.example");
    expect(Array.isArray(body.Attachments)).toBe(true);
    expect(body.Attachments).toHaveLength(1);
    expect(body.Attachments[0]).toMatchObject({
      Name:        "Factura-A-0001-00000001.pdf",
      ContentType: "application/pdf",
    });
    // base64 round-trip exacto.
    expect(Buffer.from(body.Attachments[0].Content, "base64").toString("utf-8"))
      .toBe(pdfBuffer.toString("utf-8"));
  });

  it("MAIL_MODE=production sin attachments: no agrega clave Attachments al payload", async () => {
    process.env.MAIL_MODE             = "production";
    process.env.POSTMARK_SERVER_TOKEN = "token-fake";
    process.env.MAIL_FROM             = "no-reply@tptech.local";

    let capturedBody: string | null = null;
    const mockFetch = vi.fn(async (_url: string, init: { body?: string }) => {
      capturedBody = String(init.body ?? "");
      return new Response(JSON.stringify({ MessageID: "msg-2" }), { status: 200 });
    });
    globalThis.fetch = mockFetch as unknown as typeof globalThis.fetch;

    const { sendMail } = await import("../mail.service.js");
    await sendMail({ to: "x@y.z", subject: "S", html: "<p>h</p>" });

    const body = JSON.parse(capturedBody!);
    expect("Attachments" in body).toBe(false);
  });
});
