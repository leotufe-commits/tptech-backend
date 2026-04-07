// src/lib/pricing-engine/pricing-engine.balance.ts
// Conversión de PriceBreakdown → BalanceBreakdown para cuenta corriente.
//
// Reglas clave:
//   - Metal se acumula en GRAMOS PUROS (gramsPure)
//   - Hechura se acumula en DINERO (moneda base)
//   - No se mezclan ni se convierten entre sí

import type { PriceBreakdown } from "./pricing-engine.types.js";

// ---------------------------------------------------------------------------
// Tipos de balance breakdown
// ---------------------------------------------------------------------------

export interface BalanceMetalItem {
  /** ID del metal padre (para agrupar por metal en la cuenta corriente) */
  metalId: string;
  /** ID de la variante de origen */
  variantId: string;
  /** Gramos originales ingresados */
  gramsOriginal: number;
  /** Pureza (0–1) */
  purity: number;
  /** Gramos puros = gramsOriginal × purity — UNIDAD DE ACUMULACIÓN */
  gramsPure: number;
}

export interface BalanceBreakdown {
  /** Ítems metálicos individuales (uno por variante en el breakdown) */
  metals: BalanceMetalItem[];
  /** Saldo en dinero (hechura + ajustes) */
  hechura: {
    amount: number;
    /** Código de moneda. "BASE" indica moneda base del tenant. */
    currency: string;
  };
}

// ---------------------------------------------------------------------------
// buildBalanceBreakdownFromPrice
// ---------------------------------------------------------------------------

/**
 * Convierte un PriceBreakdown (motor de costo) en un BalanceBreakdown
 * apto para persistir en EntityBalanceEntry.breakdownSnapshot.
 *
 * Solo se incluyen ítems metálicos con gramsPure > 0 y con metalId resuelto.
 * Si el breakdown no tiene ítems metálicos válidos, metals = [].
 */
export function buildBalanceBreakdownFromPrice(breakdown: PriceBreakdown): BalanceBreakdown {
  const metals: BalanceMetalItem[] = [];

  for (const item of breakdown.metal.items) {
    if (!item.metalId || !item.variantId) continue;
    if (!item.gramsPure || item.gramsPure <= 0) continue;

    metals.push({
      metalId:       item.metalId,
      variantId:     item.variantId,
      gramsOriginal: item.gramsOriginal ?? 0,
      purity:        item.purity ?? 0,
      gramsPure:     item.gramsPure,
    });
  }

  return {
    metals,
    hechura: {
      amount:   breakdown.totals.hechura,
      currency: "BASE",
    },
  };
}
