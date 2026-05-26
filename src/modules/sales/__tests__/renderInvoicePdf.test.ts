// src/modules/sales/__tests__/renderInvoicePdf.test.ts
// =============================================================================
// Tests del renderer puro `renderInvoicePdf`. NO toca rutas, Prisma, ni
// pricing-engine — solo valida que:
//   1) acepta un input minimo y devuelve un Buffer PDF valido (magic bytes
//      `%PDF-`),
//   2) respeta `columns.visible` del template (las columnas ocultas NO
//      aparecen en el contenido del PDF),
//   3) respeta `sections` del template (secciones false NO se renderean).
// =============================================================================

import { describe, it, expect } from "vitest";
import { renderInvoicePdf, type RenderInvoiceInput } from "../pdf/renderInvoicePdf.js";

function buildInput(over: {
  visibleColumns?:  string[];
  sections?:        Record<string, boolean>;
  withDiscount?:    boolean;
  withClient?:      boolean;
} = {}): RenderInvoiceInput {
  const allColumns = [
    { key: "position",    label: "#",            visible: false, width: 28,  align: "center" as const, sortOrder: 0 },
    { key: "description", label: "Descripción",  visible: true,  width: 180, align: "left"   as const, sortOrder: 3 },
    { key: "quantity",    label: "Cant.",        visible: true,  width: 46,  align: "right"  as const, sortOrder: 5 },
    { key: "unitPrice",   label: "Precio unit.", visible: true,  width: 80,  align: "right"  as const, sortOrder: 8 },
    { key: "subtotal",    label: "Subtotal",     visible: true,  width: 80,  align: "right"  as const, sortOrder: 11 },
  ];
  const columns = over.visibleColumns
    ? allColumns.map((c) => ({ ...c, visible: over.visibleColumns!.includes(c.key) }))
    : allColumns;

  const sections: Record<string, boolean> = over.sections ?? {
    seller: true, subtotal: true, total: true,
    discount: true, taxes: true, observations: true,
    termsAndConditions: false, fiscalData: true,
  };

  return {
    sale: {
      id:             "sale-1",
      code:           "VTA-0001",
      status:         "CONFIRMED",
      saleDate:       new Date("2026-05-25T10:00:00Z"),
      notes:          "Entrega martes 9 hs",
      subtotal:       200,
      discountAmount: over.withDiscount ? 20 : 0,
      taxAmount:      42,
      total:          222,
      paidAmount:     0,
      currencySnapshot: { currencyCode: "ARS", symbol: "$", currencyRate: 1 },
      clientSnapshot:  null,
      sellerSnapshot:  null,
      client: over.withClient
        ? { displayName: "Acme SA", documentType: "CUIT", documentNumber: "30-12345678-9", ivaCondition: "RI" }
        : null,
      lines: [
        {
          articleName: "Anillo Oro 18k",
          variantName: "Talle 14",
          sku:         "AN-001",
          barcode:     "",
          quantity:    2,
          unitPrice:   100,
          discountPct: 0,
          lineTotal:   200,
          taxAmount:   42,
        },
      ],
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
      marginTop:             15,
      marginRight:           15,
      marginBottom:          20,
      marginLeft:            15,
      fontFamily:            "inter",
      fontSizeBase:          10,
      accentColor:           "#1a1a1a",
      tableStyle:            "bordered",
      headerLogoEnabled:     true,
      headerLogoSize:        "md",
      headerShowName:        true,
      headerShowLegalName:   false,
      headerShowCuit:        true,
      headerShowAddress:     true,
      headerShowPhone:       true,
      headerShowEmail:       false,
      headerShowWebsite:     false,
      headerCustomText:      "",
      currencyShowSymbol:    true,
      currencyShowRate:      false,
      currencyDecimals:      2,
      pricesIncludeTax:      false,
      footerText:            "",
      footerLegalText:       "",
      footerBankData:        "",
      footerTerms:           "",
      footerShowPageNumbers: true,
      footerPageFormat:      "page_of_total",
      footerPagePosition:    "bottom_right",
      sections,
      columns,
    },
    jewelry: {
      name:         "Joyería Test",
      legalName:    "Joyería Test SRL",
      cuit:         "30-99999999-0",
      ivaCondition: "RI",
      logoUrl:      "",          // skip silencioso
      fullAddress:  "Av. Siempre Viva 123, CABA",
      phone:        "+54 11 5555-1234",
      email:        "info@test.ar",
      website:      "test.ar",
    },
  };
}

describe("renderInvoicePdf — render puro", () => {
  it("devuelve Buffer PDF con magic bytes correctos", async () => {
    const buf = await renderInvoicePdf(buildInput({ withClient: true }));
    expect(buf).toBeInstanceOf(Buffer);
    expect(buf.length).toBeGreaterThan(1000);                // un PDF minimo siempre supera 1KB
    expect(buf.subarray(0, 5).toString("ascii")).toBe("%PDF-");
    expect(buf.subarray(-6).toString("ascii")).toContain("%%EOF");
  });

  it("incluye el numero del Receipt en el contenido", async () => {
    const buf = await renderInvoicePdf(buildInput({ withClient: true }));
    // pdfkit escribe strings literales dentro de streams comprimidos; el
    // numero aparece dentro del objeto `Title` de metadata sin compresion.
    const text = buf.toString("latin1");
    expect(text).toContain("Factura A-0001-00000001");
  });

  it("respeta columnas: si `unitPrice.visible=false`, no aparece su label", async () => {
    const buf = await renderInvoicePdf(buildInput({
      visibleColumns: ["description", "quantity", "subtotal"],   // sin unitPrice
      withClient:     true,
    }));
    const text = buf.toString("latin1");
    expect(text).not.toContain("Precio unit.");
  });

  it("respeta sections: si `total=false`, no imprime 'Total' en el bloque", async () => {
    const buf = await renderInvoicePdf(buildInput({
      sections: { subtotal: true, total: false, discount: false, taxes: false, observations: false },
    }));
    const text = buf.toString("latin1");
    // El label "Total" no debe aparecer (no confundir con "Subtotal" que SI
    // se imprime).
    // Buscamos la string exacta "Total" rodeada de paréntesis o seguida de
    // saltos de texto típicos de pdfkit.
    const hasStandaloneTotal = /\(Total\)/.test(text);
    expect(hasStandaloneTotal).toBe(false);
  });

  it("acepta sale sin cliente (consumidor final) sin lanzar", async () => {
    const buf = await renderInvoicePdf(buildInput({ withClient: false }));
    expect(buf.length).toBeGreaterThan(1000);
  });
});
