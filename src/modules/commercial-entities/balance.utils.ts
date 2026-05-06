// src/modules/commercial-entities/balance.utils.ts
// Agregación de saldo de cuenta corriente para CommercialEntity.
//
// Soporta dos modos según el balanceType de la entidad:
//   UNIFIED   → suma de amounts (saldo monetario clásico)
//   BREAKDOWN → suma de gramsPure por metalId + suma de hechura por moneda

import type { BalanceBreakdown } from "../../lib/pricing-engine/pricing-engine.js";

// ---------------------------------------------------------------------------
// Tipos de entrada (subset de EntityBalanceEntry que se necesita)
// ---------------------------------------------------------------------------

export interface BalanceEntryLike {
  amount: { toString(): string };
  voidedAt: Date | null;
  breakdownSnapshot: unknown;
}

// ---------------------------------------------------------------------------
// Tipos de resultado
// ---------------------------------------------------------------------------

export interface AggregatedBalanceUnified {
  mode: "UNIFIED";
  amount: number;
  currency: string;
}

export interface AggregatedBalanceBreakdown {
  mode: "BREAKDOWN";
  /** Saldo acumulado por metalId. Clave = metalId, valor = gramos puros. */
  metals: { metalId: string; gramsPure: number }[];
  /**
   * Saldo de hechura agrupado por moneda.
   * Clave = código de moneda (ej: "ARS", "USD", "BASE").
   * Valor positivo = deuda (les debemos), negativo = saldo a favor nuestro.
   */
  hechura: { byCurrency: Record<string, number> };
}

export type AggregatedBalance = AggregatedBalanceUnified | AggregatedBalanceBreakdown;

// ---------------------------------------------------------------------------
// aggregateEntityBalance
// ---------------------------------------------------------------------------

/**
 * Agrega las entradas de cuenta corriente de una entidad.
 *
 * - Las entradas anuladas (voidedAt != null) se excluyen del cálculo.
 * - Si balanceType = "BREAKDOWN", usa breakdownSnapshot; las entradas sin
 *   snapshot se tratan como hechura en "BASE".
 * - Si balanceType = "UNIFIED", suma todos los amounts directamente.
 */
export function aggregateEntityBalance(
  entries: BalanceEntryLike[],
  balanceType: "UNIFIED" | "BREAKDOWN",
): AggregatedBalance {
  const active = entries.filter((e) => e.voidedAt == null);

  if (balanceType === "UNIFIED") {
    const total = active.reduce(
      (sum, e) => sum + parseFloat(e.amount.toString()),
      0,
    );
    return { mode: "UNIFIED", amount: total, currency: "BASE" };
  }

  // ── BREAKDOWN ─────────────────────────────────────────────────────────────
  const metalMap   = new Map<string, number>();  // metalId → gramsPure acumulados
  const hechuraMap = new Map<string, number>();  // currency → amount acumulado

  for (const entry of active) {
    if (entry.breakdownSnapshot != null) {
      const snap = entry.breakdownSnapshot as BalanceBreakdown;
      // Acumular metales
      for (const m of snap.metals ?? []) {
        if (!m.metalId || m.gramsPure == null) continue;
        metalMap.set(m.metalId, (metalMap.get(m.metalId) ?? 0) + m.gramsPure);
      }
      // Acumular hechura por moneda
      const amount   = snap.hechura?.amount ?? 0;
      const currency = snap.hechura?.currency ?? "BASE";
      if (amount !== 0) {
        hechuraMap.set(currency, (hechuraMap.get(currency) ?? 0) + amount);
      }
    } else {
      // Entrada sin snapshot (UNIFIED legacy mezclada) → cuenta como hechura BASE
      const amount = parseFloat(entry.amount.toString());
      if (amount !== 0) {
        hechuraMap.set("BASE", (hechuraMap.get("BASE") ?? 0) + amount);
      }
    }
  }

  const metals = Array.from(metalMap.entries()).map(([metalId, gramsPure]) => ({
    metalId,
    gramsPure: parseFloat(gramsPure.toFixed(6)),
  }));

  const byCurrency: Record<string, number> = {};
  for (const [currency, amount] of hechuraMap.entries()) {
    byCurrency[currency] = parseFloat(amount.toFixed(2));
  }

  return {
    mode: "BREAKDOWN",
    metals,
    hechura: { byCurrency },
  };
}
