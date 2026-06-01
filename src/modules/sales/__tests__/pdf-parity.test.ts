// tptech-backend/src/modules/sales/__tests__/pdf-parity.test.ts
// =============================================================================
// Etapa 3 — Tests de paridad: descarga / adjunto mail / draft pasan por
// el provider canonico `saleInvoicePdfProvider` (SSOT de PDF).
//
// HARDENING — NO toca pricing-engine, NO crea renderers paralelos, NO cambia
// el aspecto del PDF. Solo blinda con tests que TODOS los call-sites de PDF
// pasan por el mismo provider, con los mismos argumentos, y propagan el
// mismo buffer/filename a sus consumidores (res.send / sendMail).
//
// Estrategia:
//   · Mockeamos `saleInvoicePdfProvider` con un buffer deterministico
//     (`%PDF-1.4 PARITY-MARKER`). Esto evita la pelea contra timestamps
//     internos del PDF real (CreationDate del PDF cambia entre invocaciones)
//     — la paridad ARQUITECTONICA queda garantizada: si el provider devuelve
//     el mismo buffer, todos los call-sites lo entregan al usuario tal cual.
//   · La paridad VISUAL (mismo render por dentro) ya esta cubierta por:
//       - `saleInvoicePdfProvider.test.ts` (Etapa 2) — un solo punto de
//         generacion + adapter + selector HTML/pdfkit + filename.
//       - `renderInvoicePdfFromHtml.parity.test.ts` — paridad render puro
//         (legacy) con el shared printable.
//       - `pdf-engine-switch.test.ts` — fallback pdfkit cuando HTML falla.
//
// Print en TPTech NO tiene endpoint backend — es `window.print()` del
// frontend (ver `VentasFacturas.tsx:handlePrintDocument`) que imprime el
// MISMO `<SaleInvoicePrintable>` (shared) que el backend HTML/Puppeteer
// usa via `renderPrintableToPdf`. La paridad print/draft es estructural
// (mismo componente React); no requiere test backend.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

const mockPrisma = vi.hoisted(() => ({
  sale:             { findFirst:  vi.fn() },
  jewelry:          { findUnique: vi.fn() },
  documentEmailLog: { create:     vi.fn().mockResolvedValue({ id: "log-1" }) },
}));
vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma, Prisma }));

// El provider canonico se MOCKEA con un buffer deterministico. Las dos
// funciones publicas (`renderFromPersisted` / `renderFromDraft`) devuelven
// shapes equivalentes — los tests verifican que los services llaman al
// metodo correcto y que el resultado se propaga sin modificacion.
const PARITY_BUFFER_PERSISTED = Buffer.from("%PDF-1.4 PARITY-MARKER-persisted", "utf-8");
const PARITY_BUFFER_DRAFT     = Buffer.from("%PDF-1.4 PARITY-MARKER-draft",     "utf-8");

const mockProvider = vi.hoisted(() => ({
  renderFromPersisted: vi.fn(),
  renderFromDraft:     vi.fn(),
}));
vi.mock("../../../lib/saleInvoicePdfProvider.js", () => mockProvider);

// `sendMail` mockeado para inspeccionar attachments + from/replyTo.
const mockSendMail = vi.hoisted(() => vi.fn().mockResolvedValue({ messageId: null }));
vi.mock("../../../lib/mail.service.js", () => ({ sendMail: mockSendMail }));

import { generateSalePdf, sendSaleByEmail } from "../sales.service.js";
import { renderSaleDraftPdf, sendSaleDraftByEmail } from "../sales.draft-pdf.service.js";

// ─────────────────────────────────────────────────────────────────────────────
// Factories
// ─────────────────────────────────────────────────────────────────────────────

function makeJewelry(over: Partial<any> = {}) {
  return {
    // Campos para resolveTenantMailContext.
    emailEnabled:    true,
    emailSenderName: "Joyería Test",
    emailReplyTo:    "ventas@test.ar",
    email:           "info@test.ar",
    ...over,
  };
}

function makeSale(over: Partial<any> = {}) {
  return {
    id: "sale-1", code: "VTA-0001", status: "CONFIRMED",
    saleDate: new Date("2026-05-25T10:00:00Z"),
    lines: [], receipts: [
      { id: "rcpt-1", code: "A-0001-00000001", type: "INVOICE", issueDate: new Date() },
    ],
    ...over,
  };
}

function makeDraftInput() {
  return {
    printable: {
      documentNumber: "VTA-0001",
      documentDate:   "2026-05-25",
      clientName:     "Cliente SA",
      lines: [],
      totals: { subtotal: 0, discountAmount: 0, taxAmount: 0, total: 0 },
      currencyCode: "ARS",
    } as any,
    page: { widthMm: 210, heightMm: 297, orientation: "portrait" as const },
  };
}

const PERSISTED_INPUT = {
  to:      "cliente@example.com",
  subject: "Factura A-0001-00000001",
  message: "Adjunta la factura.",
};

beforeEach(() => {
  vi.clearAllMocks();
  mockProvider.renderFromPersisted.mockResolvedValue({
    buffer:   PARITY_BUFFER_PERSISTED,
    filename: "Factura-A-0001-00000001.pdf",
    mimeType: "application/pdf",
    source:   "persisted",
  });
  mockProvider.renderFromDraft.mockResolvedValue({
    buffer:   PARITY_BUFFER_DRAFT,
    filename: "Factura.pdf",
    mimeType: "application/pdf",
    source:   "draft",
  });
  mockPrisma.jewelry.findUnique.mockResolvedValue(makeJewelry());
  mockSendMail.mockResolvedValue({ messageId: "msg-1" });
});

// ─────────────────────────────────────────────────────────────────────────────
// 1) Paridad PERSISTED — descarga vs adjunto mail
// ─────────────────────────────────────────────────────────────────────────────

describe("Etapa 3 — Paridad PERSISTED (descarga vs mail)", () => {
  it("descarga llama renderFromPersisted con { sale, jewelryId }", async () => {
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());
    await generateSalePdf("sale-1", "jw-1");

    expect(mockProvider.renderFromPersisted).toHaveBeenCalledTimes(1);
    expect(mockProvider.renderFromDraft).not.toHaveBeenCalled();

    const args = mockProvider.renderFromPersisted.mock.calls[0]![0]!;
    expect(args.jewelryId).toBe("jw-1");
    expect(args.sale).toBeDefined();
    expect(args.sale.id).toBe("sale-1");
  });

  it("mail llama renderFromPersisted con { sale, jewelryId } (mismo shape que descarga)", async () => {
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());
    await sendSaleByEmail("sale-1", "jw-1", PERSISTED_INPUT);

    expect(mockProvider.renderFromPersisted).toHaveBeenCalledTimes(1);
    expect(mockProvider.renderFromDraft).not.toHaveBeenCalled();

    const args = mockProvider.renderFromPersisted.mock.calls[0]![0]!;
    expect(args.jewelryId).toBe("jw-1");
    expect(args.sale.id).toBe("sale-1");
  });

  it("descarga y mail invocan al provider con MISMOS argumentos (cero divergencia)", async () => {
    // Descarga primero.
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());
    await generateSalePdf("sale-1", "jw-1");
    const downloadArgs = mockProvider.renderFromPersisted.mock.calls[0]![0]!;

    // Limpiar y mail despues con el MISMO sale persistido.
    mockProvider.renderFromPersisted.mockClear();
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());
    await sendSaleByEmail("sale-1", "jw-1", PERSISTED_INPUT);
    const mailArgs = mockProvider.renderFromPersisted.mock.calls[0]![0]!;

    expect(downloadArgs.jewelryId).toBe(mailArgs.jewelryId);
    // sale serializable equivalente — ambos vienen de `getSale(id, jewelryId)`
    // con el mismo mock, asi que son objetos clonados de `makeSale()`.
    expect(downloadArgs.sale).toEqual(mailArgs.sale);
  });

  it("descarga DEVUELVE el buffer + filename TAL CUAL del provider (cero modificacion)", async () => {
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());
    const result = await generateSalePdf("sale-1", "jw-1");
    // El service NO toca el buffer del provider — pasa directo.
    expect(result.buffer).toBe(PARITY_BUFFER_PERSISTED);
    expect(result.filename).toBe("Factura-A-0001-00000001.pdf");
  });

  it("mail ADJUNTA el buffer + filename TAL CUAL del provider (byte-equivalente con descarga)", async () => {
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());
    await sendSaleByEmail("sale-1", "jw-1", PERSISTED_INPUT);

    expect(mockSendMail).toHaveBeenCalledTimes(1);
    const mailCall = mockSendMail.mock.calls[0]![0]!;
    expect(mailCall.attachments).toHaveLength(1);
    // El attachment apunta EXACTAMENTE al buffer del provider — la
    // referencia es la misma (no es una copia). Garantia: byte a byte
    // identico al buffer que se descargaria desde GET /sales/:id/pdf.
    expect(mailCall.attachments[0].content).toBe(PARITY_BUFFER_PERSISTED);
    expect(mailCall.attachments[0].filename).toBe("Factura-A-0001-00000001.pdf");
    expect(mailCall.attachments[0].contentType).toBe("application/pdf");
  });

  it("provider devuelve mimeType=application/pdf — propagado al adjunto del mail", async () => {
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());
    await sendSaleByEmail("sale-1", "jw-1", PERSISTED_INPUT);
    const mailCall = mockSendMail.mock.calls[0]![0]!;
    expect(mailCall.attachments[0].contentType).toBe("application/pdf");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2) Paridad DRAFT — render-pdf vs adjunto mail draft
// ─────────────────────────────────────────────────────────────────────────────

describe("Etapa 3 — Paridad DRAFT (render-pdf vs mail draft)", () => {
  it("renderSaleDraftPdf llama renderFromDraft con printable+page+filename", async () => {
    const input = { ...makeDraftInput(), filename: "Borrador-VTA-0001.pdf" };
    await renderSaleDraftPdf(input);

    expect(mockProvider.renderFromDraft).toHaveBeenCalledTimes(1);
    expect(mockProvider.renderFromPersisted).not.toHaveBeenCalled();

    const args = mockProvider.renderFromDraft.mock.calls[0]![0]!;
    expect(args.printable).toBe(input.printable);
    expect(args.page).toBe(input.page);
    expect(args.filename).toBe("Borrador-VTA-0001.pdf");
  });

  it("sendSaleDraftByEmail llama renderFromDraft con LOS MISMOS args que render-pdf", async () => {
    const input = { ...makeDraftInput(), filename: "Borrador-VTA-0001.pdf" };

    // Render directo primero.
    await renderSaleDraftPdf(input);
    const renderArgs = mockProvider.renderFromDraft.mock.calls[0]![0]!;

    // Mail despues con el mismo input + datos de mail.
    mockProvider.renderFromDraft.mockClear();
    await sendSaleDraftByEmail(
      { ...input, to: "cliente@example.com", subject: "S", message: "M", saleId: "sale-1" },
      "jw-1",
    );
    const mailArgs = mockProvider.renderFromDraft.mock.calls[0]![0]!;

    expect(mailArgs.printable).toBe(renderArgs.printable);
    expect(mailArgs.page).toBe(renderArgs.page);
    expect(mailArgs.filename).toBe(renderArgs.filename);
  });

  it("render-pdf DEVUELVE el buffer del provider TAL CUAL (cero modificacion)", async () => {
    const input = makeDraftInput();
    const buffer = await renderSaleDraftPdf(input);
    expect(buffer).toBe(PARITY_BUFFER_DRAFT);
  });

  it("mail draft ADJUNTA el buffer del provider TAL CUAL (byte-equivalente con render-pdf)", async () => {
    const input = makeDraftInput();
    await sendSaleDraftByEmail(
      { ...input, to: "cliente@example.com", subject: "S", message: "M", saleId: "sale-1" },
      "jw-1",
    );
    const mailCall = mockSendMail.mock.calls[0]![0]!;
    expect(mailCall.attachments[0].content).toBe(PARITY_BUFFER_DRAFT);
    expect(mailCall.attachments[0].contentType).toBe("application/pdf");
  });

  it("filename del provider se propaga al log + al attachment del mail draft", async () => {
    // Override del filename que el provider devuelve para este test.
    mockProvider.renderFromDraft.mockResolvedValueOnce({
      buffer:   PARITY_BUFFER_DRAFT,
      filename: "Custom-Filename.pdf",
      mimeType: "application/pdf",
      source:   "draft",
    });
    const input = makeDraftInput();
    const result = await sendSaleDraftByEmail(
      { ...input, to: "cliente@example.com", subject: "S", message: "M", saleId: "sale-1" },
      "jw-1",
    );
    expect(result.filename).toBe("Custom-Filename.pdf");
    const mailCall = mockSendMail.mock.calls[0]![0]!;
    expect(mailCall.attachments[0].filename).toBe("Custom-Filename.pdf");
    // Log documental tambien recibe el filename canonico del provider.
    const logCall = mockPrisma.documentEmailLog.create.mock.calls[0]![0]!;
    expect(logCall.data.attachmentFilename).toBe("Custom-Filename.pdf");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3) Routing — cada flujo invoca SOLO su rama del provider
// ─────────────────────────────────────────────────────────────────────────────

describe("Etapa 3 — Routing del provider (sin cross-paths)", () => {
  it("flujo persisted NUNCA toca renderFromDraft (separacion estricta)", async () => {
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());
    await generateSalePdf("sale-1", "jw-1");
    expect(mockProvider.renderFromDraft).not.toHaveBeenCalled();

    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale());
    await sendSaleByEmail("sale-1", "jw-1", PERSISTED_INPUT);
    expect(mockProvider.renderFromDraft).not.toHaveBeenCalled();
  });

  it("flujo draft NUNCA toca renderFromPersisted (no carga Sale)", async () => {
    await renderSaleDraftPdf(makeDraftInput());
    expect(mockProvider.renderFromPersisted).not.toHaveBeenCalled();

    await sendSaleDraftByEmail(
      { ...makeDraftInput(), to: "x@y.z", subject: "S", message: "M", saleId: "sale-1" },
      "jw-1",
    );
    expect(mockProvider.renderFromPersisted).not.toHaveBeenCalled();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4) Print — invariante estructural documentada (sin endpoint backend)
// ─────────────────────────────────────────────────────────────────────────────

describe("Etapa 3 — Print (invariante estructural, no endpoint)", () => {
  // No hay endpoint backend de print en TPTech. La paridad print ↔
  // download/draft se garantiza estructuralmente:
  //
  //   ┌──────────────────────────────────────────────────────────────────────┐
  //   │   Frontend: handlePrintDocument (VentasFacturas.tsx:2530)            │
  //   │       ↓ copia innerHTML del <SaleInvoicePrintable> oculto al popup   │
  //   │       ↓ aplica @page del DocumentTemplate (size + margins)           │
  //   │       ↓ window.print()                                               │
  //   │                                                                      │
  //   │   Backend: renderFromDraft (saleInvoicePdfProvider)                  │
  //   │       ↓ renderPrintableToPdf(printable, page) — SHARED               │
  //   │       ↓ rendea el MISMO <SaleInvoicePrintable> con Puppeteer         │
  //   │                                                                      │
  //   │   ⇒ Mismo React tree + misma @page config = mismo PDF visual         │
  //   └──────────────────────────────────────────────────────────────────────┘
  //
  // El test concreto vive en `renderInvoicePdfFromHtml.parity.test.ts`
  // (paridad render puro). Aca solo dejamos el invariante asentado.
  it("(documentacion) print=window.print() del frontend; no hay endpoint backend a testear", () => {
    expect(true).toBe(true);
  });
});
