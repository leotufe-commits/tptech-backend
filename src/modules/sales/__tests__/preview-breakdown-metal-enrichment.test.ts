// src/modules/sales/__tests__/preview-breakdown-metal-enrichment.test.ts
// ============================================================================
// REGRESIÓN — Auditoría BREAKDOWN Etapa C/D.
//
// Bug original: `previewSale` (sales.service.ts) llamaba
// `calculateCostFromLines(...)` y persistía sus steps en `lineCostStepsByIdx`
// SIN llamar antes a `enrichCostMetalSteps(...)`. Resultado:
//
//   step.meta.metalId   = undefined   (sólo había variantId)
//   step.meta.purity    = undefined
//   step.meta.gramsOriginal = undefined (sólo qty cruda)
//
// → `extractMetalItemsFromSteps` (balance-mode-runtime.ts) descarta cada
// item por su guard `if (!metalId) continue;` → `balanceBreakdown.metals`
// queda en `[]` aunque la línea tenga composición de metal → el ajuste
// manual BREAKDOWN tampoco encuentra Oro Fino y el snapshot pierde el
// componente metálico.
//
// Este test documenta el contrato que el fix garantiza:
//   1. Steps crudos (pre-enrich) → extractMetalItemsFromSteps devuelve []
//      (estado bug — debería ser inalcanzable post-fix).
//   2. Steps post-enrich → emite items con metalId/purity/gramsOriginal.
//   3. El call-site del fix (sales.service.ts previewSale) tiene el
//      `await enrichCostMetalSteps(costResult.steps)` antes del
//      `lineCostStepsByIdx.set(...)` — verificación textual contra
//      regresión de orden / borrado accidental del await.
//
// El test es PURO (no toca Prisma ni DB). Para una validación E2E
// integrada con DB real, ver el smoke script
// `_test-breakdown-clean.ts` (one-shot, no commiteado al test suite).
// ============================================================================

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { extractMetalItemsFromSteps } from "../balance-mode-runtime.js";

// Shape mínimo de step `COST_LINES_METAL` tal como lo emite
// `calculateCostFromLines` ANTES de pasar por `enrichCostMetalSteps`.
// Solo contiene `variantId`/`qty` — el resto viene del enrich.
type CrudeMetalStep = {
  key: "COST_LINES_METAL";
  status: "ok";
  meta: {
    variantId: string;
    qty: string;          // "1.526"
    quotePrice?: number;
    // metalId / purity / gramsOriginal / metalName / variantName: AUSENTES
  };
};

type EnrichedMetalStep = {
  key: "COST_LINES_METAL";
  status: "ok";
  meta: {
    variantId:        string;
    metalId:          string;
    metalName:        string;
    variantName:      string;
    purity:           number;
    gramsOriginal:    number;
    gramsFineEquivalent: number;
    quotePrice:       number;
    qty:              string;
  };
};

const CRUDE_STEP: CrudeMetalStep = {
  key: "COST_LINES_METAL",
  status: "ok",
  meta: {
    variantId:  "variant-oro-18k-id",
    qty:        "1.526",
    quotePrice: 95000,
  },
};

const ENRICHED_STEP: EnrichedMetalStep = {
  key: "COST_LINES_METAL",
  status: "ok",
  meta: {
    variantId:           "variant-oro-18k-id",
    metalId:             "metal-oro-fino-id",
    metalName:           "Oro Fino",
    variantName:         "Oro 18K",
    purity:              0.750,
    gramsOriginal:       1.526,
    gramsFineEquivalent: 1.1445,
    quotePrice:          95000,
    qty:                 "1.526",
  },
};

describe("BREAKDOWN — contrato extractMetalItemsFromSteps", () => {
  it("steps CRUDOS (pre-enrich) → devuelve [] por falta de metalId (estado bug)", () => {
    const items = extractMetalItemsFromSteps([CRUDE_STEP] as any);
    expect(items).toEqual([]);
  });

  it("steps POST-enrich → emite item con metalId/purity/gramsOriginal", () => {
    const items = extractMetalItemsFromSteps([ENRICHED_STEP] as any);
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      metalId:       "metal-oro-fino-id",
      variantId:     "variant-oro-18k-id",
      gramsOriginal: 1.526,
      purity:        0.750,
      unitValue:     95000,
    });
  });

  it("mezcla crudo + enriched → solo emite el enriched (no infla con basura)", () => {
    const items = extractMetalItemsFromSteps([CRUDE_STEP, ENRICHED_STEP] as any);
    expect(items).toHaveLength(1);
    expect(items[0]?.metalId).toBe("metal-oro-fino-id");
  });

  it("varios steps enriched de distintas variantes del mismo padre → todos emitidos", () => {
    const a = ENRICHED_STEP;
    const b: EnrichedMetalStep = {
      ...ENRICHED_STEP,
      meta: {
        ...ENRICHED_STEP.meta,
        variantId:     "variant-oro-14k-id",
        variantName:   "Oro 14K",
        purity:        0.585,
        gramsOriginal: 0.500,
        gramsFineEquivalent: 0.2925,
        qty:           "0.500",
      },
    };
    const items = extractMetalItemsFromSteps([a, b] as any);
    expect(items).toHaveLength(2);
    expect(items.map((i) => i.variantId).sort()).toEqual([
      "variant-oro-14k-id",
      "variant-oro-18k-id",
    ]);
    // ambos comparten metalId (mismo padre Oro Fino)
    expect(items.every((i) => i.metalId === "metal-oro-fino-id")).toBe(true);
  });

  it("step COST_LINES_METAL con status != ok → ignorado", () => {
    const skipped = { ...ENRICHED_STEP, status: "error" as any };
    expect(extractMetalItemsFromSteps([skipped] as any)).toEqual([]);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// Guard textual sobre el call-site del fix: si alguien borra el
// `await enrichCostMetalSteps(costResult.steps);` previo a
// `lineCostStepsByIdx.set(...)`, este test falla y avisa.
// ──────────────────────────────────────────────────────────────────────────

describe("BREAKDOWN — guard textual sobre sales.service.previewSale", () => {
  const SERVICE_PATH = join(
    __dirname,
    "..",
    "sales.service.ts",
  );
  const SOURCE = readFileSync(SERVICE_PATH, "utf8");

  it("importa enrichCostMetalSteps desde pricing-engine", () => {
    expect(SOURCE).toMatch(/enrichCostMetalSteps/);
    // verifica que el import es desde el barrel del pricing-engine, no de otro lado.
    const importRegion = SOURCE.slice(0, 5000);
    expect(importRegion).toMatch(
      /enrichCostMetalSteps[\s\S]{0,2000}from\s+["']\.\.\/\.\.\/lib\/pricing-engine/,
    );
  });

  it("llama await enrichCostMetalSteps ANTES de lineCostStepsByIdx.set", () => {
    // Busca el bloque previewSale donde está el set; asegura que el await está justo antes.
    const re =
      /await\s+enrichCostMetalSteps\s*\(\s*costResult\.steps\s*\)\s*;\s*\n\s*lineCostStepsByIdx\.set\s*\(\s*__lineIdx\s*,\s*costResult\.steps\s*\)\s*;/;
    expect(SOURCE).toMatch(re);
  });

  it("NO existe un lineCostStepsByIdx.set sin enrich previo", () => {
    const allSets = SOURCE.match(/lineCostStepsByIdx\.set\s*\([^)]*\)\s*;/g) ?? [];
    expect(allSets.length).toBeGreaterThan(0);
    for (const setCall of allSets) {
      const idx = SOURCE.indexOf(setCall);
      const before = SOURCE.slice(Math.max(0, idx - 400), idx);
      expect(before).toMatch(/await\s+enrichCostMetalSteps\s*\(/);
    }
  });
});
