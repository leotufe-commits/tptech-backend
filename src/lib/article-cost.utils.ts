// src/lib/article-cost.utils.ts
// ── DEPRECATED ENTRYPOINT ────────────────────────────────────────────────────
// Usar src/lib/pricing-engine/ como fuente de verdad.
// Este archivo es un wrapper de compatibilidad que mantiene la API pública
// original para no romper importadores existentes.
//
// La lógica real está en:
//   src/lib/pricing-engine/pricing-engine.cost.ts
//
// NO agregar lógica de negocio aquí. Todo cambio debe ir al motor.
// ─────────────────────────────────────────────────────────────────────────────

import type { CostBreakdown } from "./pricing.utils.js";
import { resolveArticleCost } from "./pricing-engine/pricing-engine.js";

// ---------------------------------------------------------------------------
// Tipos públicos
// ---------------------------------------------------------------------------

export type ArticleCostInput = {
  costCalculationMode:    string;
  costPrice:              any;
  manualCurrencyId?:      string | null;
  manualBaseCost?:        any;
  manualAdjustmentKind?:  string | null;
  manualAdjustmentType?:  string | null;
  manualAdjustmentValue?: any;
  multiplierBase:          string | null;
  multiplierValue:         any;
  multiplierQuantity:      any;
  multiplierCurrencyId?:   string | null;
  hechuraPrice:           any;
  hechuraPriceMode:       string;
  mermaPercent:           any;
  compositions?: Array<{ variantId: string; grams: any; isBase: boolean }>;
  category?:     { mermaPercent?: any } | null;
  costComposition?: Array<{
    type:           string;
    quantity:       any;
    unitValue:      any;
    currencyId:     string | null;
    mermaPercent:   any;
    metalVariantId: string | null;
    lineAdjKind?:   string | null;
    lineAdjType?:   string | null;
    lineAdjValue?:  any;
  }>;
};

export type CostResult = CostBreakdown & {
  mode: string;
  partial: boolean;
  steps?: import("./pricing-engine/pricing-engine.types.js").PricingStep[];
  breakdown?: import("./pricing-engine/pricing-engine.types.js").PriceBreakdown | null;
};

/**
 * Prisma select shape que garantiza todos los campos necesarios para computeCostPrice().
 * Usar en cualquier query que luego llame a computeCostPrice().
 */
export const ARTICLE_COST_SELECT = {
  costCalculationMode:    true,
  costPrice:              true,
  manualCurrencyId:       true,
  manualBaseCost:         true,
  manualAdjustmentKind:   true,
  manualAdjustmentType:   true,
  manualAdjustmentValue:  true,
  multiplierBase:          true,
  multiplierValue:         true,
  multiplierQuantity:      true,
  multiplierCurrencyId:    true,
  hechuraPrice:        true,
  hechuraPriceMode:    true,
  mermaPercent:        true,
  category:        { select: { mermaPercent: true } },
  costComposition: {
    select: {
      type:           true,
      quantity:       true,
      unitValue:      true,
      currencyId:     true,
      mermaPercent:   true,
      metalVariantId: true,
      lineAdjKind:    true,
      lineAdjType:    true,
      lineAdjValue:   true,
    },
  },
  compositions: {
    select: { variantId: true, grams: true, isBase: true },
  },
} as const;

// ---------------------------------------------------------------------------
// computeCostPrice — función oficial de costo (exportada)
// ---------------------------------------------------------------------------

export async function computeCostPrice(
  jewelryId: string,
  article: ArticleCostInput
): Promise<CostResult> {
  // Delegar al motor centralizado
  return resolveArticleCost(jewelryId, article);
}
