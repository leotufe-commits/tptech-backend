// src/lib/__tests__/document-physical-rounding-config.test.ts
// =============================================================================
// Etapa D2 — Tests del parser/normalizador
// `resolveDocumentPhysicalRoundingConfig`.
//
// Reglas (POLICY §R-Rounding-13):
//   · Domain MONETARY (default) o ausente → enabled=false. Sin parsing.
//   · Domain PHYSICAL + JSON null → enabled=true, config vacía (D1 marca NO_CONFIG).
//   · Domain PHYSICAL + JSON válido → parsea byMetalParentId + fallback.
//   · JSON con shape inválido → degradación segura, hasInvalidEntries=true.
//   · Unknown mode/direction → entry descartada.
// =============================================================================

import { describe, it, expect } from "vitest";
import { resolveDocumentPhysicalRoundingConfig } from "../document-physical-rounding-config.js";

describe("resolveDocumentPhysicalRoundingConfig — domain MONETARY (back-compat)", () => {
  it("Jewelry-like sin datos → enabled=false", () => {
    expect(resolveDocumentPhysicalRoundingConfig(null)).toEqual({
      enabled: false,
      configByMetalParentId: {},
      fallbackConfig: null,
      hasInvalidEntries: false,
    });
    expect(resolveDocumentPhysicalRoundingConfig(undefined)).toEqual({
      enabled: false,
      configByMetalParentId: {},
      fallbackConfig: null,
      hasInvalidEntries: false,
    });
  });

  it("documentRoundingMetalDomain ausente → MONETARY default → enabled=false", () => {
    const out = resolveDocumentPhysicalRoundingConfig({});
    expect(out.enabled).toBe(false);
  });

  it("documentRoundingMetalDomain='MONETARY' → enabled=false (cero parsing)", () => {
    const out = resolveDocumentPhysicalRoundingConfig({
      documentRoundingMetalDomain: "MONETARY",
      documentPhysicalRoundingConfig: {
        byMetalParentId: { "oro-fino": { mode: "INTEGER", direction: "NEAREST" } },
      },
    });
    expect(out).toEqual({
      enabled: false,
      configByMetalParentId: {},
      fallbackConfig: null,
      hasInvalidEntries: false,
    });
  });

  it("valor garbage en domain cae a MONETARY (safe-default)", () => {
    const out = resolveDocumentPhysicalRoundingConfig({
      documentRoundingMetalDomain: "GARBAGE" as any,
    });
    expect(out.enabled).toBe(false);
  });
});

describe("resolveDocumentPhysicalRoundingConfig — domain PHYSICAL, config válida", () => {
  it("byMetalParentId + fallback completos → parseo limpio", () => {
    const out = resolveDocumentPhysicalRoundingConfig({
      documentRoundingMetalDomain: "PHYSICAL",
      documentPhysicalRoundingConfig: {
        byMetalParentId: {
          "oro-fino":  { mode: "INTEGER", direction: "NEAREST" },
          "plata-925": { mode: "HALF",    direction: "DOWN" },
        },
        fallback: { mode: "DECIMAL_1", direction: "UP" },
      },
    });
    expect(out.enabled).toBe(true);
    expect(out.configByMetalParentId).toEqual({
      "oro-fino":  { mode: "INTEGER", direction: "NEAREST" },
      "plata-925": { mode: "HALF",    direction: "DOWN" },
    });
    expect(out.fallbackConfig).toEqual({ mode: "DECIMAL_1", direction: "UP" });
    expect(out.hasInvalidEntries).toBe(false);
  });

  it("config null → enabled=true con config vacía (D1 marcará NO_CONFIG)", () => {
    const out = resolveDocumentPhysicalRoundingConfig({
      documentRoundingMetalDomain: "PHYSICAL",
      documentPhysicalRoundingConfig: null,
    });
    expect(out).toEqual({
      enabled: true,
      configByMetalParentId: {},
      fallbackConfig: null,
      hasInvalidEntries: false,
    });
  });

  it("byMetalParentId vacío + fallback válido → fallback aplicado a todos", () => {
    const out = resolveDocumentPhysicalRoundingConfig({
      documentRoundingMetalDomain: "PHYSICAL",
      documentPhysicalRoundingConfig: {
        byMetalParentId: {},
        fallback: { mode: "INTEGER", direction: "NEAREST" },
      },
    });
    expect(out.enabled).toBe(true);
    expect(out.configByMetalParentId).toEqual({});
    expect(out.fallbackConfig).toEqual({ mode: "INTEGER", direction: "NEAREST" });
    expect(out.hasInvalidEntries).toBe(false);
  });

  it("sin fallback → fallbackConfig=null (no se inventa)", () => {
    const out = resolveDocumentPhysicalRoundingConfig({
      documentRoundingMetalDomain: "PHYSICAL",
      documentPhysicalRoundingConfig: {
        byMetalParentId: { "oro-fino": { mode: "INTEGER", direction: "NEAREST" } },
      },
    });
    expect(out.fallbackConfig).toBeNull();
  });
});

describe("resolveDocumentPhysicalRoundingConfig — degradación segura", () => {
  it("JSON con shape totalmente inválido (string) → hasInvalidEntries=true, config vacía", () => {
    const out = resolveDocumentPhysicalRoundingConfig({
      documentRoundingMetalDomain: "PHYSICAL",
      documentPhysicalRoundingConfig: "garbage" as any,
    });
    expect(out.enabled).toBe(true);
    expect(out.configByMetalParentId).toEqual({});
    expect(out.fallbackConfig).toBeNull();
    expect(out.hasInvalidEntries).toBe(true);
  });

  it("byMetalParentId como array (shape malformado) → descartado, flag set", () => {
    const out = resolveDocumentPhysicalRoundingConfig({
      documentRoundingMetalDomain: "PHYSICAL",
      documentPhysicalRoundingConfig: {
        byMetalParentId: [{ mode: "INTEGER", direction: "NEAREST" }] as any,
      },
    });
    expect(out.configByMetalParentId).toEqual({});
    expect(out.hasInvalidEntries).toBe(true);
  });

  it("mode desconocido → entry descartada, otras válidas se conservan, flag set", () => {
    const out = resolveDocumentPhysicalRoundingConfig({
      documentRoundingMetalDomain: "PHYSICAL",
      documentPhysicalRoundingConfig: {
        byMetalParentId: {
          "oro-fino":  { mode: "INTEGER",       direction: "NEAREST" },
          "plata-925": { mode: "PIRAMIDAL",     direction: "NEAREST" },  // ← inválido
          "platino":   { mode: "HALF",          direction: "GIRATORIA" }, // ← direction inválida
        },
      },
    });
    expect(out.configByMetalParentId).toEqual({
      "oro-fino": { mode: "INTEGER", direction: "NEAREST" },
    });
    expect(out.hasInvalidEntries).toBe(true);
  });

  it("fallback con shape inválido → fallbackConfig=null + flag set", () => {
    const out = resolveDocumentPhysicalRoundingConfig({
      documentRoundingMetalDomain: "PHYSICAL",
      documentPhysicalRoundingConfig: {
        byMetalParentId: { "oro-fino": { mode: "INTEGER", direction: "NEAREST" } },
        fallback: { mode: "MAGICO", direction: "NEAREST" },  // mode inválido
      },
    });
    expect(out.configByMetalParentId).toEqual({
      "oro-fino": { mode: "INTEGER", direction: "NEAREST" },
    });
    expect(out.fallbackConfig).toBeNull();
    expect(out.hasInvalidEntries).toBe(true);
  });

  it("entry con key vacío string → descartada", () => {
    const out = resolveDocumentPhysicalRoundingConfig({
      documentRoundingMetalDomain: "PHYSICAL",
      documentPhysicalRoundingConfig: {
        byMetalParentId: {
          "":          { mode: "INTEGER", direction: "NEAREST" },
          "   ":       { mode: "INTEGER", direction: "NEAREST" },
          "oro-fino":  { mode: "HALF",    direction: "UP" },
        },
      },
    });
    expect(Object.keys(out.configByMetalParentId)).toEqual(["oro-fino"]);
    expect(out.hasInvalidEntries).toBe(true);
  });

  it("fallback null + entries vacías → enabled=true sin flag", () => {
    const out = resolveDocumentPhysicalRoundingConfig({
      documentRoundingMetalDomain: "PHYSICAL",
      documentPhysicalRoundingConfig: { byMetalParentId: {}, fallback: null },
    });
    expect(out.enabled).toBe(true);
    expect(out.hasInvalidEntries).toBe(false);
  });
});

describe("resolveDocumentPhysicalRoundingConfig — todos los modes y directions del enum", () => {
  it("acepta los 6 modes válidos", () => {
    const out = resolveDocumentPhysicalRoundingConfig({
      documentRoundingMetalDomain: "PHYSICAL",
      documentPhysicalRoundingConfig: {
        byMetalParentId: {
          a: { mode: "NONE",      direction: "NEAREST" },
          b: { mode: "INTEGER",   direction: "NEAREST" },
          c: { mode: "DECIMAL_1", direction: "NEAREST" },
          d: { mode: "DECIMAL_2", direction: "NEAREST" },
          e: { mode: "HALF",      direction: "NEAREST" },
          f: { mode: "QUARTER",   direction: "NEAREST" },
        },
      },
    });
    expect(Object.keys(out.configByMetalParentId)).toHaveLength(6);
    expect(out.hasInvalidEntries).toBe(false);
  });

  it("acepta las 3 directions válidas", () => {
    const out = resolveDocumentPhysicalRoundingConfig({
      documentRoundingMetalDomain: "PHYSICAL",
      documentPhysicalRoundingConfig: {
        byMetalParentId: {
          a: { mode: "INTEGER", direction: "NEAREST" },
          b: { mode: "INTEGER", direction: "UP" },
          c: { mode: "INTEGER", direction: "DOWN" },
        },
      },
    });
    expect(Object.keys(out.configByMetalParentId)).toHaveLength(3);
  });
});

describe("resolveDocumentPhysicalRoundingConfig — pasaje directo a roundDocumentMetalGrams", () => {
  it("el output puede usarse como input parcial del helper D1", async () => {
    const { roundDocumentMetalGrams } = await import("../document-physical-rounding.js");
    const cfg = resolveDocumentPhysicalRoundingConfig({
      documentRoundingMetalDomain: "PHYSICAL",
      documentPhysicalRoundingConfig: {
        byMetalParentId: {
          "oro-fino": { mode: "INTEGER", direction: "NEAREST" },
        },
        fallback: { mode: "HALF", direction: "NEAREST" },
      },
    });
    const out = roundDocumentMetalGrams({
      metals: [
        { metalParentId: "oro-fino",  metalParentName: "Oro Fino", grams: 0.908, metalPricePerGram: 100000 },
        { metalParentId: "plata-925", metalParentName: "Plata",    grams: 0.76,  metalPricePerGram: 500 },
      ],
      configByMetalParentId: cfg.configByMetalParentId,
      fallbackConfig: cfg.fallbackConfig,
    });
    const oro   = out.metals.find((m) => m.metalParentId === "oro-fino")!;
    const plata = out.metals.find((m) => m.metalParentId === "plata-925")!;
    expect(oro.postGrams).toBe(1);                 // entry específica
    expect(plata.postGrams).toBe(1);               // fallback HALF NEAREST 0,76 → 1
    expect(out.metalMonetaryEquivalent).toBeGreaterThan(0);
  });
});
