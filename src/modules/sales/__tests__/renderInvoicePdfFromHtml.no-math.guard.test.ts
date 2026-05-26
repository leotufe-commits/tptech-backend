// src/modules/sales/__tests__/renderInvoicePdfFromHtml.no-math.guard.test.ts
// =============================================================================
// Guard estático — espejo del guard de `renderInvoicePdf.ts` (motor
// pdfkit) aplicado al renderer HTML (C4). El renderer HTML NO debe
// calcular negocio: lee los snapshots y los pasa al
// `<SaleInvoicePrintable>` shared.
//
// Si en algún momento aparece `Math.*` sobre montos, asignaciones
// aritméticas (`+=`, `-=`, `*=`, `/=`), multiplicaciones/divisiones
// sobre nombres de campos monetarios conocidos, o `.reduce(...)` sobre
// `lines` acumulando montos, este test falla.
//
// Excepciones permitidas (mismo criterio que el guard del motor
// pdfkit): conversiones de layout puro (mm→pt, anchos de columna, etc.).
// Hoy el renderer HTML no hace ninguna conversión de layout — usa
// directamente los mm del template. El guard queda en su lugar para
// detectar regresiones futuras.
// =============================================================================

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname     = dirname(fileURLToPath(import.meta.url));
const RENDERER_PATH = resolve(__dirname, "../pdf/renderInvoicePdfFromHtml.ts");

function stripComments(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|\n)\s*\/\/[^\n]*/g, "$1");
}

describe("renderInvoicePdfFromHtml — guard anti-math", () => {
  const rawSrc = readFileSync(RENDERER_PATH, "utf-8");
  const src    = stripComments(rawSrc);

  it("no usa `Math.*` sobre montos del snapshot", () => {
    const moneyFields = "(subtotal|total|taxAmount|discountAmount|lineTotal|unitPrice|paidAmount|discountPct)";
    const re = new RegExp(`Math\\.\\w+\\s*\\([^)]*${moneyFields}`, "g");
    const offenders = src.match(re) ?? [];
    expect(offenders, `Math sobre montos:\n${offenders.join("\n")}`).toEqual([]);
  });

  it("no usa operadores de asignacion aritmetica sobre montos del snapshot", () => {
    const re = /\b(subtotal|total|taxAmount|discountAmount|lineTotal|unitPrice|paidAmount)\s*[+\-*/]=/g;
    const offenders = src.match(re) ?? [];
    expect(offenders, `Asignacion aritmetica sobre montos:\n${offenders.join("\n")}`).toEqual([]);
  });

  it("no multiplica/divide montos del snapshot por otros valores", () => {
    const moneyFields = "subtotal|total|taxAmount|discountAmount|lineTotal|unitPrice|paidAmount";
    const re = new RegExp(
      `\\b(?:line|sale|opts|totals)\\.(?:${moneyFields})\\s*[*/]\\s*\\S+`,
      "g",
    );
    const offenders = src.match(re) ?? [];
    expect(offenders, `Multiplicacion/division sobre montos:\n${offenders.join("\n")}`).toEqual([]);
  });

  it("no recorre `lines` para sumar / acumular montos manualmente", () => {
    const re = /\.reduce\s*\(\s*\([^)]*\)\s*=>\s*[^,]*\b(line|l|item)\.(lineTotal|unitPrice|taxAmount|subtotal|total|discountAmount|paidAmount)\b/g;
    const offenders = src.match(re) ?? [];
    expect(offenders, `Acumulacion de montos via reduce:\n${offenders.join("\n")}`).toEqual([]);
  });

  it("contiene el comentario de cabecera prohibiendo cálculos", () => {
    expect(rawSrc).toMatch(/NO calcula negocio/);
    expect(rawSrc).toMatch(/snapshot/i);
  });
});
