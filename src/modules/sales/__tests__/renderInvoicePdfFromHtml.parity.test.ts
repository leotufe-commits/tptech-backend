// src/modules/sales/__tests__/renderInvoicePdfFromHtml.parity.test.ts
// =============================================================================
// C5-FIX — Paridad documental entre el PDF HTML/Puppeteer y el print del
// browser. AMBOS consumen `<SaleInvoicePrintable>` (shared, C1). El test
// usa el componente REAL (sin stub) y verifica que el HTML que llega a
// `page.setContent` contiene los textos clave que el printable produce:
//
//   · Descuento (con signo y monto)
//   · Impuestos
//   · Total final (distinto al subtotal cuando hay descuento o tax)
//   · Almacén
//   · Términos
//   · Vendedor (si está)
//   · Watermark según status
//
// Bug histórico: el PDF descargado salía sin descuento/impuestos/almacén
// porque o (a) caía al fallback pdfkit por `@tptech/shared` no resoluble
// en runtime, o (b) el mapping de props del adapter no traía esos
// campos. Este test cubre la rama (b).
//
// La rama (a) — runtime resolution — se valida indirectamente porque
// el dynamic `import("@tptech/shared/...")` ahora corre real contra el
// node_modules symlinked (file:../tptech-shared) y la prueba falla si
// el módulo no se puede cargar.
// =============================================================================

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  renderInvoicePdfFromHtml,
  __setPrintableLoaderForTests,
} from "../pdf/renderInvoicePdfFromHtml.js";
import type { RenderInvoiceInput } from "../pdf/renderInvoicePdf.js";

// ─── Fixture: factura con descuento + impuestos + almacén + términos ─────────

function buildRichInput(over: { status?: string } = {}): RenderInvoiceInput {
  return {
    sale: {
      id:               "sale-1",
      code:             "VTA-0001",
      status:           over.status ?? "PENDING",
      saleDate:         new Date("2026-05-25T10:00:00Z"),
      notes:            "Entregar el martes",
      subtotal:         1000,
      discountAmount:   150,
      taxAmount:        178.5,
      total:            1028.5,
      paidAmount:       0,
      currencySnapshot: { currencyCode: "ARS", symbol: "$", currencyRate: 1 },
      clientSnapshot:   null,
      sellerSnapshot:   null,
      client: { displayName: "Cliente Test SA", documentType: "CUIT", documentNumber: "30-12345678-9", ivaCondition: "RI" },
      lines: [
        {
          articleName: "Anillo Oro 18k",
          variantName: "Talle 14",
          sku:         "AN-001",
          barcode:     "",
          quantity:    2,
          unitPrice:   500,
          discountPct: 0,
          subtotal:    1000,
          lineTotal:   1000,
          taxAmount:   178.5,
        },
      ],
      sellerName:      "Juan Pérez",
      warehouseName:   "Depósito Central",
      paymentTermName: "Contado",
    },
    receipt: {
      id:        "rcpt-1",
      code:      "A-0001-00000001",
      type:      "INVOICE",
      issueDate: new Date("2026-05-25T10:00:00Z"),
    },
    template: {
      pageSizePreset:        "A4",
      isCustomSize:          false,
      pageWidthMm:           210,
      pageHeightMm:          297,
      orientation:           "portrait",
      marginTop:             15, marginRight: 15, marginBottom: 20, marginLeft: 15,
      fontFamily:            "inter",
      fontSizeBase:          10,
      accentColor:           "#1a1a1a",
      tableStyle:            "bordered",
      headerLogoEnabled:     false, headerLogoSize: "md",
      headerShowName:        true, headerShowLegalName: false,
      headerShowCuit:        true, headerShowAddress: true,
      headerShowPhone:       true, headerShowEmail: false, headerShowWebsite: false,
      headerCustomText:      "",
      currencyShowSymbol:    true, currencyShowRate: false, currencyDecimals: 2,
      pricesIncludeTax:      false,
      footerText:            "", footerLegalText: "", footerBankData: "",
      footerTerms:           "Pagos en pesos. No se aceptan devoluciones pasados 30 días.",
      footerShowPageNumbers: true, footerPageFormat: "page_of_total", footerPagePosition: "bottom_right",
      sections: { subtotal: true, total: true, discount: true, taxes: true, observations: true, fiscalData: true },
      columns:  [],
    },
    jewelry: {
      name:         "Joyería Test",
      legalName:    "Joyería Test SRL",
      cuit:         "30-99999999-0",
      ivaCondition: "RI",
      logoUrl:      "",
      fullAddress:  "Av. Siempre Viva 123, CABA",
      phone:        "+54 11 5555-1234",
      email:        "info@test.ar",
      website:      "test.ar",
    },
  };
}

function makeMockPage() {
  return {
    setContent: vi.fn().mockResolvedValue(undefined),
    pdf:        vi.fn().mockResolvedValue(Buffer.from("%PDF-1.4 stub %%EOF")),
    close:      vi.fn().mockResolvedValue(undefined),
  };
}

function makeMockBrowser(page: ReturnType<typeof makeMockPage>) {
  return {
    newPage:  vi.fn().mockResolvedValue(page),
    connected: true,
    on:       vi.fn(),
    close:    vi.fn().mockResolvedValue(undefined),
  } as any;
}

// IMPORTANTE: NO stubbeamos el componente. Usamos el real (cargado por
// el dynamic import a través del symlink node_modules/@tptech/shared →
// tptech-shared/src). Si el module no se puede resolver, falla. Si las
// props que arma el renderer son incompletas, el HTML resultante NO
// contendrá los textos clave y los asserts fallan.
beforeEach(() => {
  __setPrintableLoaderForTests(null);
});

afterEach(() => {
  __setPrintableLoaderForTests(null);
});

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("renderInvoicePdfFromHtml — paridad documental con printable", () => {
  it("incluye el número de comprobante (Receipt.code) en el HTML", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderInvoicePdfFromHtml(buildRichInput(), { browser });

    const [html] = page.setContent.mock.calls[0]!;
    expect(html).toContain("A-0001-00000001");
  });

  it("renderea Descuento con monto y signo cuando discountAmount > 0", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderInvoicePdfFromHtml(buildRichInput(), { browser });

    const [html] = page.setContent.mock.calls[0]!;
    expect(html).toContain("Descuento");
    // El printable formatea como "-150,00" (es-AR). Verificamos el
    // numero sin el separador para no acoplar al locale del runner.
    expect(html).toMatch(/-\s*150/);
  });

  it("renderea Impuestos con su monto", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderInvoicePdfFromHtml(buildRichInput(), { browser });

    const [html] = page.setContent.mock.calls[0]!;
    expect(html).toContain("Impuestos");
    expect(html).toMatch(/178/);   // 178.50
  });

  it("Total final ≠ Subtotal cuando hay descuento + impuestos (no rompe la matemática del snapshot)", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderInvoicePdfFromHtml(buildRichInput(), { browser });

    const [html] = page.setContent.mock.calls[0]!;
    // El printable muestra subtotal y total separados. El total
    // (1028.50) no puede ser igual al subtotal (1000) cuando hay
    // descuento y tax — eso seria perdida de datos del snapshot.
    expect(html).toMatch(/1[\.,]?028/);    // 1.028,50 o 1,028.50
    expect(html).toMatch(/1[\.,]?000/);    // 1.000,00 o 1,000.00
  });

  it("incluye el almacén en el bloque meta", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderInvoicePdfFromHtml(buildRichInput(), { browser });

    const [html] = page.setContent.mock.calls[0]!;
    // El printable lo etiqueta como "Almacen:" (sin acento — paridad
    // con el componente shared actual).
    expect(html).toMatch(/Almac[eé]n[:\s]+Dep[oó]sito Central/);
  });

  it("incluye los términos del template cuando no hay sale.terms persistido", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderInvoicePdfFromHtml(buildRichInput(), { browser });

    const [html] = page.setContent.mock.calls[0]!;
    expect(html).toContain("Pagos en pesos");
  });

  it("incluye el vendedor cuando sale.sellerName está", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderInvoicePdfFromHtml(buildRichInput(), { browser });

    const [html] = page.setContent.mock.calls[0]!;
    expect(html).toContain("Juan");
  });

  it("incluye la forma de pago", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderInvoicePdfFromHtml(buildRichInput(), { browser });

    const [html] = page.setContent.mock.calls[0]!;
    expect(html).toContain("Contado");
  });

  it("DRAFT → renderea sello BORRADOR en el HTML", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderInvoicePdfFromHtml(buildRichInput({ status: "DRAFT" }), { browser });

    const [html] = page.setContent.mock.calls[0]!;
    expect(html).toContain("BORRADOR");
  });

  it("CANCELLED → renderea sello ANULADA en el HTML", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderInvoicePdfFromHtml(buildRichInput({ status: "CANCELLED" }), { browser });

    const [html] = page.setContent.mock.calls[0]!;
    expect(html).toContain("ANULADA");
  });

  it("PENDING → sin sello (factura confirmada)", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderInvoicePdfFromHtml(buildRichInput({ status: "PENDING" }), { browser });

    const [html] = page.setContent.mock.calls[0]!;
    expect(html).not.toContain("BORRADOR");
    expect(html).not.toContain("ANULADA");
  });

  // Regression test específico para el bug de QA local 2026-05-26:
  // "Total = Subtotal" porque el adapter no pasaba descuento al
  // printable. Si el printable recibe `discountAmount=0` cuando el
  // snapshot tiene `discountAmount=150`, ese assert detecta la
  // pérdida.
  it("[regresión] no oculta el descuento si discountAmount > 0 en el snapshot", async () => {
    const page    = makeMockPage();
    const browser = makeMockBrowser(page);

    await renderInvoicePdfFromHtml(buildRichInput(), { browser });

    const [html] = page.setContent.mock.calls[0]!;
    // La fila de Descuento del printable sólo se renderea si
    // discountAmount > 0. Si el HTML no la contiene, es bug: el
    // snapshot tiene 150 de descuento y se está perdiendo en el
    // mapeo.
    expect(html).toContain("Descuento");
  });
});
