// src/lib/pricing-engine/__tests__/balance-mode-resolver.test.ts
// =============================================================================
// T51 — Tests del resolver puro `resolveBalanceMode`. Sub-fase 3B.1.
//
// Estos tests congelan la prioridad oficial R11.4 (POLICY.md §11):
//   1. Override del documento  → DOCUMENT_OVERRIDE
//   2. Default del cliente     → ENTITY_DEFAULT
//   3. Default de la lista     → PRICELIST_DEFAULT
//   4. Default del tenant      → TENANT_DEFAULT
//   5. Fallback                → UNIFIED + FALLBACK_UNIFIED
//
// Función pura — sin mocks, sin DB, sin side effects.
// =============================================================================

import { describe, it, expect } from "vitest";
import { resolveBalanceMode } from "../balance-mode-resolver.js";

describe("resolveBalanceMode — prioridad R11.4", () => {
  it("prioridad 1: documentOverride GANA aunque el resto esté seteado", () => {
    const r = resolveBalanceMode({
      documentOverride: "BREAKDOWN",
      entityDefault:    "UNIFIED",
      priceListDefault: "UNIFIED",
      tenantDefault:    "UNIFIED",
    });
    expect(r).toEqual({ mode: "BREAKDOWN", source: "DOCUMENT_OVERRIDE" });
  });

  it("prioridad 1 (UNIFIED override): puede forzar UNIFIED sobre cliente/lista que pedirían BREAKDOWN", () => {
    const r = resolveBalanceMode({
      documentOverride: "UNIFIED",
      entityDefault:    "BREAKDOWN",
      priceListDefault: "BREAKDOWN",
      tenantDefault:    "BREAKDOWN",
    });
    expect(r).toEqual({ mode: "UNIFIED", source: "DOCUMENT_OVERRIDE" });
  });

  it("prioridad 2: entityDefault cuando documentOverride es null", () => {
    const r = resolveBalanceMode({
      documentOverride: null,
      entityDefault:    "BREAKDOWN",
      priceListDefault: "UNIFIED",
      tenantDefault:    "UNIFIED",
    });
    expect(r).toEqual({ mode: "BREAKDOWN", source: "ENTITY_DEFAULT" });
  });

  it("prioridad 3: priceListDefault cuando documento y entity son null", () => {
    const r = resolveBalanceMode({
      documentOverride: null,
      entityDefault:    null,
      priceListDefault: "BREAKDOWN",
      tenantDefault:    "UNIFIED",
    });
    expect(r).toEqual({ mode: "BREAKDOWN", source: "PRICELIST_DEFAULT" });
  });

  it("prioridad 4: tenantDefault cuando los 3 niveles superiores son null", () => {
    const r = resolveBalanceMode({
      documentOverride: null,
      entityDefault:    null,
      priceListDefault: null,
      tenantDefault:    "BREAKDOWN",
    });
    expect(r).toEqual({ mode: "BREAKDOWN", source: "TENANT_DEFAULT" });
  });

  it("fallback: TODOS los niveles null → UNIFIED + FALLBACK_UNIFIED", () => {
    const r = resolveBalanceMode({
      documentOverride: null,
      entityDefault:    null,
      priceListDefault: null,
      tenantDefault:    null,
    });
    expect(r).toEqual({ mode: "UNIFIED", source: "FALLBACK_UNIFIED" });
  });

  it("fallback: input vacío {} → UNIFIED + FALLBACK_UNIFIED (defensive)", () => {
    const r = resolveBalanceMode({});
    expect(r).toEqual({ mode: "UNIFIED", source: "FALLBACK_UNIFIED" });
  });
});

describe("resolveBalanceMode — robustez ante valores inválidos", () => {
  it("documentOverride con string ajeno al enum → delega al siguiente nivel", () => {
    const r = resolveBalanceMode({
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      documentOverride: "FOO" as any,
      entityDefault:    "BREAKDOWN",
    });
    // "FOO" no es BalanceMode → cae a entityDefault.
    expect(r).toEqual({ mode: "BREAKDOWN", source: "ENTITY_DEFAULT" });
  });

  it("documentOverride undefined → delega correctamente", () => {
    const r = resolveBalanceMode({
      documentOverride: undefined,
      entityDefault:    "UNIFIED",
    });
    expect(r).toEqual({ mode: "UNIFIED", source: "ENTITY_DEFAULT" });
  });

  it("entityDefault con número → delega al siguiente nivel", () => {
    const r = resolveBalanceMode({
      documentOverride: null,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      entityDefault:    0 as any,
      priceListDefault: "BREAKDOWN",
    });
    expect(r).toEqual({ mode: "BREAKDOWN", source: "PRICELIST_DEFAULT" });
  });

  it("todos los niveles con valores inválidos → fallback UNIFIED", () => {
    const r = resolveBalanceMode({
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      documentOverride: "X" as any,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      entityDefault:    "" as any,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      priceListDefault: 1 as any,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      tenantDefault:    {} as any,
    });
    expect(r).toEqual({ mode: "UNIFIED", source: "FALLBACK_UNIFIED" });
  });
});

describe("resolveBalanceMode — invariantes", () => {
  it("siempre devuelve un mode válido (UNIFIED o BREAKDOWN)", () => {
    const cases: Array<Parameters<typeof resolveBalanceMode>[0]> = [
      {},
      { documentOverride: null },
      { documentOverride: "UNIFIED" },
      { documentOverride: "BREAKDOWN" },
      { entityDefault: "UNIFIED" },
      { priceListDefault: "BREAKDOWN" },
      { tenantDefault: "UNIFIED" },
    ];
    for (const c of cases) {
      const r = resolveBalanceMode(c);
      expect(r.mode === "UNIFIED" || r.mode === "BREAKDOWN").toBe(true);
    }
  });

  it("siempre devuelve un source válido del enum", () => {
    const validSources = new Set([
      "DOCUMENT_OVERRIDE",
      "ENTITY_DEFAULT",
      "PRICELIST_DEFAULT",
      "TENANT_DEFAULT",
      "FALLBACK_UNIFIED",
    ]);
    const r1 = resolveBalanceMode({});
    const r2 = resolveBalanceMode({ documentOverride: "BREAKDOWN" });
    const r3 = resolveBalanceMode({ entityDefault: "UNIFIED" });
    expect(validSources.has(r1.source)).toBe(true);
    expect(validSources.has(r2.source)).toBe(true);
    expect(validSources.has(r3.source)).toBe(true);
  });

  it("FALLBACK_UNIFIED → mode siempre UNIFIED (regla R11.4)", () => {
    const r = resolveBalanceMode({});
    if (r.source === "FALLBACK_UNIFIED") {
      expect(r.mode).toBe("UNIFIED");
    }
  });

  it("función pura: misma entrada → misma salida (deterministic)", () => {
    const input = {
      documentOverride: null,
      entityDefault:    "BREAKDOWN" as const,
      priceListDefault: "UNIFIED" as const,
      tenantDefault:    null,
    };
    const r1 = resolveBalanceMode(input);
    const r2 = resolveBalanceMode(input);
    const r3 = resolveBalanceMode({ ...input });
    expect(r1).toEqual(r2);
    expect(r1).toEqual(r3);
  });

  it("no muta el input", () => {
    const input = {
      documentOverride: null,
      entityDefault:    "BREAKDOWN" as const,
      priceListDefault: "UNIFIED" as const,
      tenantDefault:    null,
    };
    const before = JSON.stringify(input);
    resolveBalanceMode(input);
    const after = JSON.stringify(input);
    expect(after).toBe(before);
  });
});
