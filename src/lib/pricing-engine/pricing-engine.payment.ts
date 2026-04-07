// src/lib/pricing-engine/pricing-engine.payment.ts
// ============================================================================
// Capa de checkout: aplica ajuste por forma de pago y divide en cuotas.
//
// Opera SOBRE el precio comercial (unitPrice de SalePriceResult).
// NO modifica ni reemplaza resolveFinalSalePrice().
//
// Flujo:
//   baseAmount        = unitPrice × quantity
//   paymentAdjustment = baseAmount × (pct/100)  |  valor fijo
//   finalAmount       = baseAmount + paymentAdjustment
//   installmentAmount = finalAmount / cuotas
// ============================================================================

import type {
  CheckoutOpts,
  CheckoutResult,
  CheckoutStep,
} from "./pricing-engine.types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

function safe(n: number): number {
  return Number.isFinite(n) ? n : 0;
}

function fmt(n: number): string {
  return n.toLocaleString("es-AR", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

// ---------------------------------------------------------------------------
// resolveCheckoutPrice
// ---------------------------------------------------------------------------

export function resolveCheckoutPrice(opts: CheckoutOpts): CheckoutResult {
  const {
    unitPrice,
    quantity    = 1,
    currencyCode = "ARS",
    paymentMethod,
    installments,
  } = opts;

  const steps: CheckoutStep[] = [];

  // ── 1. Base ────────────────────────────────────────────────────────────────
  const safeQty   = quantity >= 1 ? quantity : 1;
  const safePrice = safe(unitPrice);
  const baseAmount = round2(safePrice * safeQty);

  steps.push({
    code:         "CHECKOUT_BASE",
    label:        "Precio base",
    formula:      safeQty === 1
      ? `$${fmt(safePrice)}`
      : `$${fmt(safePrice)} × ${safeQty} = $${fmt(baseAmount)}`,
    amount:       baseAmount,
    currencyCode,
  });

  // ── 2. Ajuste por forma de pago ────────────────────────────────────────────
  let paymentAdjustment = 0;

  if (paymentMethod) {
    const { adjustmentType, adjustmentValue, name } = paymentMethod;
    const safeAdj = safe(adjustmentValue);

    if (adjustmentType === "PERCENTAGE") {
      paymentAdjustment = round2(baseAmount * (safeAdj / 100));
      const sign   = safeAdj >= 0 ? "recargo" : "descuento";
      const label  = name ? `${name} (${sign})` : sign;
      steps.push({
        code:         "PAYMENT_ADJUSTMENT",
        label,
        formula:      `$${fmt(baseAmount)} × ${safeAdj}% = $${fmt(paymentAdjustment)}`,
        amount:       paymentAdjustment,
        currencyCode,
      });
    } else {
      // FIXED
      paymentAdjustment = round2(safeAdj);
      const sign  = safeAdj >= 0 ? "recargo" : "descuento";
      const label = name ? `${name} (${sign})` : sign;
      steps.push({
        code:         "PAYMENT_ADJUSTMENT",
        label,
        formula:      `$${fmt(paymentAdjustment)} (fijo)`,
        amount:       paymentAdjustment,
        currencyCode,
      });
    }
  }

  // ── 3. Total final ─────────────────────────────────────────────────────────
  const finalAmount = round2(baseAmount + paymentAdjustment);

  steps.push({
    code:         "CHECKOUT_FINAL",
    label:        "Total a pagar",
    formula:      paymentAdjustment !== 0
      ? `$${fmt(baseAmount)} + $${fmt(paymentAdjustment)} = $${fmt(finalAmount)}`
      : `$${fmt(finalAmount)}`,
    amount:       finalAmount,
    currencyCode,
  });

  // ── 4. Cuotas ──────────────────────────────────────────────────────────────
  let installmentAmount: number | undefined;
  let installmentCount: number | undefined;

  if (installments && installments.quantity >= 1) {
    installmentCount  = installments.quantity;
    installmentAmount = round2(finalAmount / installmentCount);
    const planLabel   = installments.label
      ? `${installmentCount} cuotas (${installments.label})`
      : `${installmentCount} cuota${installmentCount > 1 ? "s" : ""}`;

    steps.push({
      code:         "INSTALLMENT_VALUE",
      label:        planLabel,
      formula:      `$${fmt(finalAmount)} ÷ ${installmentCount} = $${fmt(installmentAmount)} c/u`,
      amount:       installmentAmount,
      currencyCode,
    });
  }

  return {
    baseAmount,
    paymentAdjustment,
    finalAmount,
    ...(installmentCount !== undefined && { installments: installmentCount }),
    ...(installmentAmount !== undefined && { installmentAmount }),
    steps,
  };
}
