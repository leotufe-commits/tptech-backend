// src/lib/pricing-engine/pricing-engine.ts
// ============================================================================
// PRICING ENGINE — Fuente única de verdad para TPTech
// ============================================================================
//
// Este módulo es la ÚNICA fuente de verdad para:
//   - Cálculo de costo de artículo  →  resolveArticleCost()
//   - Precio base y precio final     →  resolveFinalSalePrice()
//   - Alertas de negocio             →  PricingAlert[]
//   - Política de confirmación       →  PricingPolicyResult / evaluatePricingPolicy()
//
// REGLAS ARQUITECTÓNICAS:
//   1. NO implementar cálculos de costo o precio fuera de este directorio.
//   2. Todo cambio futuro en lógica de pricing debe pasar por este motor.
//   3. Los wrappers legacy (article-cost.utils.ts, sale-pricing.utils.ts) solo
//      delegan a este motor; NO contienen lógica propia.
//   4. pricing.utils.ts es dependencia interna del motor (resolvePriceList /
//      applyPriceList); no duplicar su lógica en services ni controllers.
//
// Importar siempre desde este barrel, no desde los sub-archivos directamente,
// salvo en tests o en los propios sub-módulos del motor.
// ============================================================================

export { resolveArticleCost } from "./pricing-engine.cost.js";
export { resolveFinalSalePrice, evaluatePricingPolicy, computeLineTaxes } from "./pricing-engine.sale.js";
export { resolveCheckoutPrice } from "./pricing-engine.payment.js";
export { getBaseCurrencyId, getExchangeRate, convertMoney, normalizeToBaseCurrency } from "./pricing-engine.currency.js";

export type {
  PricingStep,
  PricingStepStatus,
  CostResult,
  SalePriceResult,
  SalePriceOpts,
  ArticleCostInput,
  CostLineInput,
  CompositionInput,
  PricingAlert,
  PricingAlertLevel,
  PricingPolicyResult,
  CheckoutStep,
  CheckoutResult,
  CheckoutOpts,
  CheckoutPaymentMethod,
  CheckoutInstallments,
  TaxBreakdownItem,
} from "./pricing-engine.types.js";
