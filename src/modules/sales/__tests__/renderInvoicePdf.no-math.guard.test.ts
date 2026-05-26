// src/modules/sales/__tests__/renderInvoicePdf.no-math.guard.test.ts
// =============================================================================
// Guard estatico — `renderInvoicePdf.ts` NO debe contener matematica sobre
// montos del snapshot. Si aparece `Math.`, operadores de asignacion
// aritmetica (`+=`, `-=`, `*=`, `/=`) o multiplicaciones/divisiones sobre
// nombres de campos monetarios conocidos (subtotal/total/taxAmount/
// discountAmount/lineTotal/unitPrice/paidAmount), este test falla.
//
// Excepciones permitidas (sumas/multiplicaciones inocuas):
//   · `mmToPt`           — conversion mm → pt (layout, NO negocio).
//   · `pageW`, `halfW`,  — layout (anchos/posiciones del PDF).
//     anchos de columna
//   · `getColumnText`    — extrae texto, no calcula montos.
//   · indices del array  — `index + 1`, etc.
//
// El test usa un regex acotado y deja whitelist textual de las lineas que
// puedan parecer aritmetica pero son layout puro.
// =============================================================================

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const RENDERER_PATH = resolve(__dirname, "../pdf/renderInvoicePdf.ts");

/** Strip de comentarios `//...` y `/* ...
 *
*\/` para que el guard no
 *  matchee texto documentativo (ej. "sale.subtotal/total" en una linea
 *  de comentario debe ser ignorado por los regex de matematica). */
function stripComments(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, "")   // block comments
    .replace(/(^|\n)\s*\/\/[^\n]*/g, "$1"); // line comments
}

describe("renderInvoicePdf — guard anti-math", () => {
  const rawSrc = readFileSync(RENDERER_PATH, "utf-8");
  const src    = stripComments(rawSrc);

  it("no usa `Math.*` sobre montos del snapshot", () => {
    // `Math.max` y `Math.min` son aceptables SOLO sobre coordenadas
    // (`leftBottom`, `rightBottom`, `lineH`). Si aparecen sobre nombres
    // de campos monetarios, falla.
    const moneyFields = "(subtotal|total|taxAmount|discountAmount|lineTotal|unitPrice|paidAmount|discountPct)";
    const re = new RegExp(`Math\\.\\w+\\s*\\([^)]*${moneyFields}`, "g");
    const offenders = src.match(re) ?? [];
    expect(offenders, `Math sobre montos:\n${offenders.join("\n")}`).toEqual([]);
  });

  it("no usa operadores de asignacion aritmetica sobre montos del snapshot", () => {
    // Detecta `subtotal += x`, `total -= y`, `taxAmount *= z`, etc.
    const re = /\b(subtotal|total|taxAmount|discountAmount|lineTotal|unitPrice|paidAmount)\s*[+\-*/]=/g;
    const offenders = src.match(re) ?? [];
    expect(offenders, `Asignacion aritmetica sobre montos:\n${offenders.join("\n")}`).toEqual([]);
  });

  it("no multiplica/divide montos del snapshot por otros valores", () => {
    // `quantity * unitPrice` o `lineTotal / 2` u `unitPrice * 1.21`.
    // Si aparece, es un calculo comercial que deberia venir del snapshot.
    const moneyFields = "subtotal|total|taxAmount|discountAmount|lineTotal|unitPrice|paidAmount";
    // pattern: `<money> [*/] <something-not-currencyDecimals-or-0>`.
    const re = new RegExp(
      `\\b(?:line|sale|opts)\\.(?:${moneyFields})\\s*[*/]\\s*(?!opts\\.decimals)\\S+`,
      "g",
    );
    const offenders = src.match(re) ?? [];
    expect(offenders, `Multiplicacion/division sobre montos:\n${offenders.join("\n")}`).toEqual([]);
  });

  it("no recorre `lines` para sumar / acumular montos manualmente", () => {
    // Patron tipico: `.reduce((acc, l) => acc + l.lineTotal, ...)` o
    // `for (const line of lines) { total += line.X }`.
    const re = /\.reduce\s*\(\s*\([^)]*\)\s*=>\s*[^,]*\b(line|l|item)\.(lineTotal|unitPrice|taxAmount|subtotal|total|discountAmount|paidAmount)\b/g;
    const offenders = src.match(re) ?? [];
    expect(offenders, `Acumulacion de montos via reduce:\n${offenders.join("\n")}`).toEqual([]);
  });

  it("contiene el comentario de cabecera prohibiendo calculos", () => {
    // Esta assertion corre sobre el SOURCE CRUDO (con comentarios) para
    // validar que la documentacion esta en su lugar.
    expect(rawSrc).toMatch(/NO calcula negocio/);
    expect(rawSrc).toMatch(/snapshot/i);
  });
});
