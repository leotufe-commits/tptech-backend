import type { CommissionType, CommissionBase } from "@prisma/client";
import type { PriceBreakdown } from "./pricing-engine/pricing-engine.types.js";

export interface LineCommissionInput {
  commissionType:  CommissionType;
  commissionValue: number | null; // porcentaje (0-100) o monto fijo total de venta
  commissionBase:  CommissionBase;
  lineTotal:       number;        // cantidad × unitPrice × (1 − discountPct/100), ya calculado
  breakdownSnapshot: PriceBreakdown | null;
  quantity:        number;
  /** Factor canal+cupón ya calculado a nivel venta (finalAmount / subtotal). Default: 1. */
  lineDiscountFactor?: number;
}

export interface LineCommissionResult {
  base:   number | null; // importe sobre el que se aplicó el %
  amount: number;        // comisión de la línea
}

/**
 * Calcula la comisión de una línea individual.
 * FIXED_AMOUNT se distribuye pro-rata al nivel de Sale, no por línea — devuelve base=null, amount=0.
 * El llamador suma los amounts y luego agrega el FIXED_AMOUNT al total de Sale.
 */
export function calculateLineCommission(input: LineCommissionInput): LineCommissionResult {
  const { commissionType, commissionValue, commissionBase, lineTotal, breakdownSnapshot, quantity, lineDiscountFactor = 1 } = input;

  if (commissionType === "NONE" || commissionValue == null || commissionValue <= 0) {
    return { base: null, amount: 0 };
  }

  if (commissionType === "FIXED_AMOUNT") {
    // FIXED_AMOUNT se calcula a nivel Sale, no por línea
    return { base: null, amount: 0 };
  }

  // PERCENTAGE
  const pct = commissionValue / 100;

  let base: number;

  switch (commissionBase) {
    case "TOTAL":
      base = lineTotal;
      break;

    case "TOTAL_AFTER_DISCOUNTS":
    case "TOTAL_AFTER_PAYMENT":
      // TOTAL_AFTER_PAYMENT: provisional en confirmSale (mismo factor canal+cupón).
      // El total definitivo se ajusta al registrar el primer pago en addPayment.
      base = round2(lineTotal * Math.max(0, lineDiscountFactor));
      break;

    case "METAL":
      base = breakdownSnapshot != null
        ? round2(breakdownSnapshot.metal.total * quantity)
        : 0;
      break;

    case "HECHURA":
      base = breakdownSnapshot != null
        ? round2(breakdownSnapshot.hechura.total * quantity)
        : 0;
      break;

    case "METAL_Y_HECHURA":
      base = breakdownSnapshot != null
        ? round2((breakdownSnapshot.metal.total + breakdownSnapshot.hechura.total) * quantity)
        : 0;
      break;

    case "HECHURA_AFTER_DISCOUNTS":
      base = breakdownSnapshot != null
        ? round2(breakdownSnapshot.hechura.total * quantity * Math.max(0, lineDiscountFactor))
        : 0;
      break;

    default:
      base = lineTotal;
  }

  return { base: round2(base), amount: round2(base * pct) };
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}
