// src/lib/__tests__/commercial-physical-rounding-config.test.ts
// =============================================================================
// Etapa C-comercial / C2 — `resolveCommercialPhysicalRoundingConfig` (parser
// del row PriceList-like) delega al helper neutral
// `resolvePhysicalRoundingConfig` y debe producir EXACTAMENTE el mismo
// resultado que `resolveDocumentPhysicalRoundingConfig` para inputs equivalentes.
// =============================================================================

import { describe, it, expect } from "vitest";
import { resolveCommercialPhysicalRoundingConfig as resolveCom } from "../commercial-physical-rounding-config.js";
import { resolveDocumentPhysicalRoundingConfig } from "../document-physical-rounding-config.js";

describe("resolveCommercialPhysicalRoundingConfig — degradación segura", () => {
  it("null / undefined → disabled", () => {
    expect(resolveCom(null)).toEqual({
      enabled: false, configByMetalParentId: {}, fallbackConfig: null, hasInvalidEntries: false,
    });
    expect(resolveCom(undefined)).toEqual({
      enabled: false, configByMetalParentId: {}, fallbackConfig: null, hasInvalidEntries: false,
    });
  });

  it("domain MONETARY → disabled (sin parsear JSON)", () => {
    const out = resolveCom({
      commercialRoundingMetalDomain: "MONETARY",
      commercialPhysicalRoundingConfig: { byMetalParentId: { "oro-fino": { mode: "INTEGER", direction: "NEAREST" } } },
    });
    expect(out.enabled).toBe(false);
    expect(out.configByMetalParentId).toEqual({});
    expect(out.fallbackConfig).toBeNull();
    expect(out.hasInvalidEntries).toBe(false);
  });

  it("domain PHYSICAL + config canónica → entries válidas", () => {
    const out = resolveCom({
      commercialRoundingMetalDomain: "PHYSICAL",
      commercialPhysicalRoundingConfig: {
        byMetalParentId: {
          "oro-fino": { mode: "INTEGER", direction: "NEAREST" },
          "plata":    { mode: "HALF",    direction: "DOWN" },
        },
        fallback: { mode: "NONE", direction: "NEAREST" },
      },
    });
    expect(out.enabled).toBe(true);
    expect(out.configByMetalParentId["oro-fino"]).toEqual({ mode: "INTEGER", direction: "NEAREST" });
    expect(out.configByMetalParentId["plata"]).toEqual({ mode: "HALF", direction: "DOWN" });
    expect(out.fallbackConfig).toEqual({ mode: "NONE", direction: "NEAREST" });
    expect(out.hasInvalidEntries).toBe(false);
  });

  it("domain PHYSICAL + JSON null → enabled vacío", () => {
    const out = resolveCom({
      commercialRoundingMetalDomain: "PHYSICAL",
      commercialPhysicalRoundingConfig: null,
    });
    expect(out.enabled).toBe(true);
    expect(out.configByMetalParentId).toEqual({});
    expect(out.fallbackConfig).toBeNull();
  });

  it("domain PHYSICAL + entries inválidas → descarte + hasInvalidEntries=true", () => {
    const out = resolveCom({
      commercialRoundingMetalDomain: "PHYSICAL",
      commercialPhysicalRoundingConfig: {
        byMetalParentId: {
          "oro-fino": { mode: "INTEGER", direction: "NEAREST" }, // válido
          "plata":    { mode: "BANANA",  direction: "DOWN" },    // inválido
        },
        fallback: { mode: "WRONG", direction: "DOWN" },          // inválido
      },
    });
    expect(out.enabled).toBe(true);
    expect(out.configByMetalParentId["oro-fino"]).toBeDefined();
    expect(out.configByMetalParentId["plata"]).toBeUndefined();
    expect(out.fallbackConfig).toBeNull();
    expect(out.hasInvalidEntries).toBe(true);
  });
});

describe("paridad comercial ↔ financiero para inputs equivalentes", () => {
  it("mismas reglas de domain/JSON → mismo ResolvedPhysicalRoundingConfig", () => {
    const cfg = {
      byMetalParentId: {
        "oro-fino": { mode: "INTEGER", direction: "NEAREST" },
        "plata":    { mode: "HALF",    direction: "DOWN" },
      },
      fallback: { mode: "QUARTER", direction: "UP" },
    };
    const com = resolveCom({
      commercialRoundingMetalDomain: "PHYSICAL",
      commercialPhysicalRoundingConfig: cfg,
    });
    const fin = resolveDocumentPhysicalRoundingConfig({
      documentRoundingMetalDomain: "PHYSICAL",
      documentPhysicalRoundingConfig: cfg,
    });
    expect(com).toEqual(fin);
  });

  it("MONETARY en ambos → mismo EMPTY_RESULT", () => {
    const com = resolveCom({ commercialRoundingMetalDomain: "MONETARY" });
    const fin = resolveDocumentPhysicalRoundingConfig({ documentRoundingMetalDomain: "MONETARY" });
    expect(com).toEqual(fin);
  });
});

