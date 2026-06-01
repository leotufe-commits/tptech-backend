// src/lib/__tests__/document-rounding.test.ts
// =============================================================================
// Etapa 1B — `loadDocumentRoundingConfig` con discriminated union
//
// Reglas:
//   · documentRoundingEnabled=false → política inerte (suppress=false, null, null).
//   · scope=UNIFIED + mode=NONE → inerte (ningún componente activo).
//   · scope=UNIFIED + mode efectivo → activa, sin breakdown.
//   · scope=BREAKDOWN + modeHechura efectivo → activa con breakdown.
//   · scope=BOTH + alguno efectivo → activa con breakdown (cuando aplica).
//   · suppressListDeferredRounding=true SIEMPRE que la política esté activa.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";

const mockPrisma = vi.hoisted(() => ({
  jewelry: { findUnique: vi.fn() },
}));
vi.mock("../prisma.js", () => ({ prisma: mockPrisma }));

import { loadDocumentRoundingConfig } from "../document-rounding.js";

const TENANT_ID = "j1";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("loadDocumentRoundingConfig — política inerte", () => {
  it("documentRoundingEnabled=false → todo en null", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      documentRoundingEnabled:          false,
      documentRoundingMode:             "INTEGER",
      documentRoundingDirection:        "NEAREST",
      documentRoundingScope:            "UNIFIED",
      documentRoundingModeMetal:        "NONE",
      documentRoundingDirectionMetal:   "NEAREST",
      documentRoundingModeHechura:      "NONE",
      documentRoundingDirectionHechura: "NEAREST",
    });
    const cfg = await loadDocumentRoundingConfig(TENANT_ID);
    expect(cfg.suppressListDeferredRounding).toBe(false);
    expect(cfg.documentRounding).toBeNull();
    expect(cfg.scope).toBeNull();
  });

  it("UNIFIED + mode=NONE → inerte", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      documentRoundingEnabled:          true,
      documentRoundingMode:             "NONE",
      documentRoundingDirection:        "NEAREST",
      documentRoundingScope:            "UNIFIED",
      documentRoundingModeMetal:        "NONE",
      documentRoundingDirectionMetal:   "NEAREST",
      documentRoundingModeHechura:      "NONE",
      documentRoundingDirectionHechura: "NEAREST",
    });
    const cfg = await loadDocumentRoundingConfig(TENANT_ID);
    expect(cfg.documentRounding).toBeNull();
  });
});

describe("loadDocumentRoundingConfig — UNIFIED", () => {
  it("emite scope=UNIFIED sin breakdown", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      documentRoundingEnabled:          true,
      documentRoundingMode:             "INTEGER",
      documentRoundingDirection:        "UP",
      documentRoundingScope:            "UNIFIED",
      documentRoundingModeMetal:        "NONE",
      documentRoundingDirectionMetal:   "NEAREST",
      documentRoundingModeHechura:      "NONE",
      documentRoundingDirectionHechura: "NEAREST",
    });
    const cfg = await loadDocumentRoundingConfig(TENANT_ID);
    expect(cfg.suppressListDeferredRounding).toBe(true);
    expect(cfg.scope).toBe("UNIFIED");
    expect(cfg.documentRounding).toEqual({
      scope:     "UNIFIED",
      mode:      "INTEGER",
      direction: "UP",
    });
  });
});

describe("loadDocumentRoundingConfig — BREAKDOWN", () => {
  it("emite scope=BREAKDOWN con metal y hechura INDEPENDIENTES", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      documentRoundingEnabled:          true,
      documentRoundingMode:             "NONE",
      documentRoundingDirection:        "NEAREST",
      documentRoundingScope:            "BREAKDOWN",
      // Metal a la decena, hacia abajo.
      documentRoundingModeMetal:        "TEN",
      documentRoundingDirectionMetal:   "DOWN",
      // Hechura al entero, hacia arriba.
      documentRoundingModeHechura:      "INTEGER",
      documentRoundingDirectionHechura: "UP",
    });
    const cfg = await loadDocumentRoundingConfig(TENANT_ID);
    expect(cfg.scope).toBe("BREAKDOWN");
    expect(cfg.documentRounding).toMatchObject({
      scope: "BREAKDOWN",
      breakdown: {
        metal:   { mode: "TEN",     direction: "DOWN" },
        hechura: { mode: "INTEGER", direction: "UP"   },
      },
    });
  });

  it("BREAKDOWN con SOLO metal configurado → activo, hechura en NONE pasa intacta", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      documentRoundingEnabled:          true,
      documentRoundingMode:             "NONE",
      documentRoundingDirection:        "NEAREST",
      documentRoundingScope:            "BREAKDOWN",
      documentRoundingModeMetal:        "HUNDRED",
      documentRoundingDirectionMetal:   "NEAREST",
      documentRoundingModeHechura:      "NONE",
      documentRoundingDirectionHechura: "NEAREST",
    });
    const cfg = await loadDocumentRoundingConfig(TENANT_ID);
    expect(cfg.documentRounding?.breakdown?.metal).toEqual({
      mode: "HUNDRED", direction: "NEAREST",
    });
    expect(cfg.documentRounding?.breakdown?.hechura).toEqual({
      mode: "NONE", direction: "NEAREST",
    });
  });

  it("BREAKDOWN + ambos componentes en NONE → inerte", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      documentRoundingEnabled:          true,
      documentRoundingMode:             "INTEGER",  // unified activo
      documentRoundingDirection:        "NEAREST",
      documentRoundingScope:            "BREAKDOWN",
      documentRoundingModeMetal:        "NONE",
      documentRoundingDirectionMetal:   "NEAREST",
      documentRoundingModeHechura:      "NONE",
      documentRoundingDirectionHechura: "NEAREST",
    });
    const cfg = await loadDocumentRoundingConfig(TENANT_ID);
    // unifiedActive=true pero scope=BREAKDOWN ignora unified → inerte.
    expect(cfg.documentRounding).toBeNull();
  });
});

describe("loadDocumentRoundingConfig — BOTH", () => {
  it("emite ambos componentes cuando UNIFIED y BREAKDOWN están activos", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      documentRoundingEnabled:          true,
      documentRoundingMode:             "INTEGER",
      documentRoundingDirection:        "NEAREST",
      documentRoundingScope:            "BOTH",
      // Metal y hechura configurados ASIMÉTRICAMENTE.
      documentRoundingModeMetal:        "TEN",
      documentRoundingDirectionMetal:   "DOWN",
      documentRoundingModeHechura:      "INTEGER",
      documentRoundingDirectionHechura: "UP",
    });
    const cfg = await loadDocumentRoundingConfig(TENANT_ID);
    expect(cfg.scope).toBe("BOTH");
    expect(cfg.documentRounding).toMatchObject({
      scope:     "BOTH",
      mode:      "INTEGER",
      direction: "NEAREST",
      breakdown: {
        metal:   { mode: "TEN",     direction: "DOWN" },
        hechura: { mode: "INTEGER", direction: "UP"   },
      },
    });
  });

  it("BOTH activa cuando solo UNIFIED tiene config efectiva", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      documentRoundingEnabled:          true,
      documentRoundingMode:             "INTEGER",
      documentRoundingDirection:        "NEAREST",
      documentRoundingScope:            "BOTH",
      documentRoundingModeMetal:        "NONE",
      documentRoundingDirectionMetal:   "NEAREST",
      documentRoundingModeHechura:      "NONE",
      documentRoundingDirectionHechura: "NEAREST",
    });
    const cfg = await loadDocumentRoundingConfig(TENANT_ID);
    // Sigue activa (unified actúa); breakdown se emite pero ambos en NONE.
    expect(cfg.scope).toBe("BOTH");
    expect(cfg.documentRounding?.mode).toBe("INTEGER");
  });

  it("BOTH activa cuando solo BREAKDOWN tiene config efectiva (asimetría completa)", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      documentRoundingEnabled:          true,
      documentRoundingMode:             "NONE",      // UNIFIED inactivo
      documentRoundingDirection:        "NEAREST",
      documentRoundingScope:            "BOTH",
      documentRoundingModeMetal:        "TEN",       // solo metal activo
      documentRoundingDirectionMetal:   "DOWN",
      documentRoundingModeHechura:      "NONE",      // hechura inactiva
      documentRoundingDirectionHechura: "NEAREST",
    });
    const cfg = await loadDocumentRoundingConfig(TENANT_ID);
    expect(cfg.scope).toBe("BOTH");
    expect(cfg.documentRounding?.breakdown?.metal.mode).toBe("TEN");
    expect(cfg.documentRounding?.breakdown?.hechura.mode).toBe("NONE");
  });
});
