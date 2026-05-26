// src/lib/pdf/__tests__/renderPrintableToPdf.test.ts
// =============================================================================
// C5-fix Opción A — Tests del helper común renderPrintableToPdf.
//
// Usa el componente REAL (`@tptech/shared/document-printables/...`) y
// mockea sólo Puppeteer. Verifica que:
//   1) el HTML inyectado a `page.setContent` contiene los datos del
//      draft (paridad pixel-cercana con `<SaleInvoicePrintable>`
//      del browser print).
//   2) `page.pdf` se llama con `margin: 0` (IDÉNTICO al
//      `@page { margin: 0 }` del frontend popup print).
//   3) la página usa `width/height` en mm, no `format`, para
//      respetar configs custom (no-A4).
//   4) `page.close()` siempre se llama (no fugas).
//   5) errors propagan al caller (sin fallback acá — pdfkit es
//      fallback solo del flujo legacy).
//   6) Watermark BORRADOR / ANULADA aparece según `status`.
// =============================================================================

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  renderPrintableToPdf,
  __setRenderPrintableLoaderForTests,
  type SaleDraftPrintableProps,
  type RenderPrintablePageConfig,
} from "../renderPrintableToPdf.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

function buildProps(over: { status?: SaleDraftPrintableProps["status"] } = {}): SaleDraftPrintableProps {
  return {
    config:         {},
    company: {
      name:         "Joyería Test",
      legalName:    "Joyería Test SRL",
      cuit:         "30-99999999-0",
      ivaCondition: "RI",
      addressLine:  "Av. Siempre Viva 123, CABA",
      phone:        "+54 11 5555-1234",
      email:        "info@test.ar",
    },
    documentNumber: "A-0001-00000001",
    documentDate:   "2026-05-26",
    clientName:     "Cliente Test SA",
    clientTaxId:    "CUIT: 30-12345678-9",
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
    terms:           "Pagos en pesos.",
    sellerName:      "Juan Pérez",
    warehouseName:   "Depósito Central",
    paymentTermName: "Contado",
    status:          over.status,
  };
}

function buildPage(): RenderPrintablePageConfig {
  return { widthMm: 210, heightMm: 297, orientation: "portrait" };
}

function makeMockPage(opts: { pdfThrows?: boolean } = {}) {
  return {
    setContent: vi.fn().mockResolvedValue(undefined),
    pdf:        opts.pdfThrows
      ? vi.fn().mockRejectedValue(new Error("boom"))
      : vi.fn().mockResolvedValue(Buffer.from("%PDF-1.4")),
    close:      vi.fn().mockResolvedValue(undefined),
  };
}

function makeMockBrowser(page: ReturnType<typeof makeMockPage>) {
  return {
    newPage: vi.fn().mockResolvedValue(page),
    connected: true,
    on:      vi.fn(),
    close:   vi.fn().mockResolvedValue(undefined),
  } as any;
}

beforeEach(() => {
  __setRenderPrintableLoaderForTests(null);  // usa el componente real via node_modules
});

afterEach(() => {
  __setRenderPrintableLoaderForTests(null);
});

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("renderPrintableToPdf — paridad con browser print", () => {
  it("inyecta HTML con `@page { margin: 0 }` (paridad con frontend popup)", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderPrintableToPdf(buildProps(), buildPage(), { browser });

    const [html] = page.setContent.mock.calls[0]!;
    expect(html).toContain("@page");
    // Regex flexible: el size puede tener formato distinto pero margin: 0 es CRÍTICO.
    expect(html).toMatch(/@page\s*\{[^}]*margin:\s*0/);
  });

  it("`page.pdf` recibe margin: 0 en los 4 lados (no del template)", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderPrintableToPdf(buildProps(), buildPage(), { browser });

    const opts = page.pdf.mock.calls[0]![0];
    expect(opts.margin).toEqual({ top: 0, right: 0, bottom: 0, left: 0 });
    expect(opts.printBackground).toBe(true);
  });

  it("`page.pdf` usa width/height en mm (no `format`)", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderPrintableToPdf(buildProps(), { widthMm: 100, heightMm: 200 }, { browser });

    const opts = page.pdf.mock.calls[0]![0];
    expect(opts.width).toBe("100mm");
    expect(opts.height).toBe("200mm");
    expect(opts.format).toBeUndefined();
  });

  it("HTML contiene los datos clave del draft (paridad con printable browser)", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderPrintableToPdf(buildProps(), buildPage(), { browser });

    const [html] = page.setContent.mock.calls[0]!;
    expect(html).toContain("A-0001-00000001");          // documentNumber
    expect(html).toContain("Cliente Test SA");           // clientName
    expect(html).toContain("Anillo Oro 18k");            // article
    expect(html).toContain("Descuento");                  // fila descuento
    expect(html).toMatch(/-\s*150/);                      // -150,00
    expect(html).toContain("Impuestos");
    expect(html).toMatch(/178/);                          // 178,50
    expect(html).toMatch(/1[\.,]?028/);                   // total 1.028,50
    expect(html).toMatch(/Almac[eé]n[:\s]+Dep[oó]sito Central/);
    expect(html).toContain("Pagos en pesos");             // términos
    expect(html).toContain("Juan");                       // vendedor
    expect(html).toContain("Contado");                    // forma de pago
  });

  it("DRAFT → watermark BORRADOR en el HTML", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderPrintableToPdf(buildProps({ status: "DRAFT" }), buildPage(), { browser });

    const [html] = page.setContent.mock.calls[0]!;
    expect(html).toContain("BORRADOR");
  });

  it("CANCELLED → watermark ANULADA en el HTML", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderPrintableToPdf(buildProps({ status: "CANCELLED" }), buildPage(), { browser });

    const [html] = page.setContent.mock.calls[0]!;
    expect(html).toContain("ANULADA");
  });

  it("PENDING / undefined → sin watermark", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderPrintableToPdf(buildProps({ status: "PENDING" }), buildPage(), { browser });

    const [html] = page.setContent.mock.calls[0]!;
    expect(html).not.toContain("BORRADOR");
    expect(html).not.toContain("ANULADA");
  });

  it("cierra la page en finally aunque page.pdf lance", async () => {
    const page    = makeMockPage({ pdfThrows: true });
    const browser = makeMockBrowser(page);

    await expect(renderPrintableToPdf(buildProps(), buildPage(), { browser })).rejects.toThrow("boom");
    expect(page.close).toHaveBeenCalledOnce();
  });

  it("devuelve Buffer aunque page.pdf entregue Uint8Array", async () => {
    const page    = makeMockPage();
    page.pdf      = vi.fn().mockResolvedValue(new Uint8Array([0x25, 0x50, 0x44, 0x46]));
    const browser = makeMockBrowser(page);

    const out = await renderPrintableToPdf(buildProps(), buildPage(), { browser });
    expect(Buffer.isBuffer(out)).toBe(true);
    expect(out.subarray(0, 4).toString("ascii")).toBe("%PDF");
  });

  it("[paridad] el size del @page coincide con widthMm/heightMm pasados", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderPrintableToPdf(buildProps(), { widthMm: 148, heightMm: 210 }, { browser });

    const [html] = page.setContent.mock.calls[0]!;
    expect(html).toMatch(/size:\s*148mm\s+210mm/);
  });
});
