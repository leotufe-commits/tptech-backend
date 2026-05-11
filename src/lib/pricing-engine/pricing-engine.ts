// src/lib/pricing-engine/pricing-engine.ts
// ============================================================================
// PRICING ENGINE — Fuente única de verdad para TPTech
// ============================================================================
//
// Este módulo es la ÚNICA fuente de verdad para:
//   - Cálculo de costo de artículo       → calculateCostFromLines()
//   - Precio base y precio final          → resolveFinalSalePrice()
//   - Impuestos (venta + compra, batch)   → computeLineTaxes / computePurchaseTaxes / applyTaxesFromMap
//   - Alertas de negocio                  → PricingAlert[]
//   - Política de confirmación            → PricingPolicyResult / evaluatePricingPolicy()
//   - Resolución de lista de precios      → resolvePriceList() / applyPriceList()
//   - Canal de venta / cupón / pago       → applySalesChannelAdjustment / applyCouponAdjustment / resolveCheckoutPrice
//   - Moneda base y conversión            → getBaseCurrencyId / convertMoney / normalizeToBaseCurrency
//   - Desglose metal/hechura              → buildBalanceBreakdownFromPrice
//
// REGLAS ARQUITECTÓNICAS:
//   1. NO implementar cálculos de costo o precio fuera de este directorio.
//   2. Todo cambio futuro en lógica de pricing debe pasar por este motor.
//   3. NO importar directamente sub-archivos del motor (pricing-engine.sale.ts,
//      pricing-engine.cost.ts, pricing-engine.pricelist.ts, etc.).
//      Usar siempre este barrel como punto de entrada.
//
// Ver README.md para la whitelist de módulos autorizados y el orden de capas.
// ============================================================================

export {
  resolveVariantAwareWeight,
  calculateCostFromLines,
  buildBatchCostContext,
  getArticleMetalVariantIds,
  loadArticleMetalVariantsBatch,
} from "./pricing-engine.cost.js";
export {
  resolveFinalSalePrice,
  evaluatePricingPolicy,
  computeLineTaxes,
  applyTaxesFromMap,
  computePurchaseTaxes,
  buildPricingSnapshot,
  isPromotionValid,
  // FASE 1 — helper puro para tests y consumidores que necesiten armar el
  // breakdown a partir de inputs ya resueltos por el motor.
  deriveMetalHechuraBreakdown,
} from "./pricing-engine.sale.js";
export type {
  LinePolicyBlock,
  PurchaseTaxBreakdownItem,
  PurchaseTaxResult,
  DeriveMetalHechuraInput,
  MetalHechuraExactDetail,
  MetalHechuraBreakdownResult,
} from "./pricing-engine.sale.js";
export { resolveCheckoutPrice } from "./pricing-engine.payment.js";
export { getBaseCurrencyId, getExchangeRate, convertMoney, normalizeToBaseCurrency } from "./pricing-engine.currency.js";
export { buildBalanceBreakdownFromPrice } from "./pricing-engine.balance.js";
export type { BalanceBreakdown, BalanceMetalItem } from "./pricing-engine.balance.js";
// Canal de venta — ajuste posterior a lista, previo a forma de pago
export { applySalesChannelAdjustment } from "./pricing-engine.channel.js";
export type { ChannelAdjustmentInput, ChannelAdjustmentResult } from "./pricing-engine.channel.js";
// Cupón de descuento — ajuste posterior a canal, previo a forma de pago
export { applyCouponAdjustment } from "./pricing-engine.coupon.js";
export type { CouponInput, CouponAdjustmentResult } from "./pricing-engine.coupon.js";
// Sprint 3 — Capa 10 del orden inmutable. Único punto autorizado para
// resolver el monto de envío. POLICY.md §5.
export { resolveShippingAmount } from "./pricing-engine.shipping.js";
export type { ShippingInput, ShippingResult, ShippingMode } from "./pricing-engine.shipping.js";
// Utilidades de lista de precios — expuestas para batch pricing en services
export { resolvePriceList, applyPriceList, PL_COMPUTE_SELECT, isPriceListValidNow } from "./pricing-engine.pricelist.js";
export type { CostBreakdown, ResolvedPriceList } from "./pricing-engine.pricelist.js";
// Fase 5: snapshot de documento para comprobantes
// Fase 3 refactor Ventas: + computeSaleDocumentTotals como fuente única de
// verdad de los totales del comprobante de venta.
export {
  buildDocumentPricingSnapshot,
  computeSaleDocumentTotals,
  DOCUMENT_SNAPSHOT_VERSION,
} from "./pricing-engine.document.js";
export type {
  DocumentPricingSnapshot,
  DocumentLineSnapshot,
  DocumentLineInput,
  BuildSnapshotInput,
  SnapshotCurrency,
  SnapshotIssuer,
  SnapshotCounterparty,
  SnapshotChannel,
  SnapshotCoupon,
  SnapshotPromotion,
  SnapshotQuantityDiscount,
  SnapshotPaymentMethod,
  SnapshotRounding,
  SnapshotTaxBreakdownItem,
  SnapshotTotals,
  SnapshotCost,
  SaleDocumentTotalsLineInput,
  SaleDocumentTotalsInput,
  SaleDocumentTotals,
  SaleDocumentTotalsTraceStep,
  DocumentRoundingInput,
} from "./pricing-engine.document.js";

export type {
  PricingStep,
  PricingStepStatus,
  CostResult,
  SalePriceResult,
  SalePriceOpts,
  ArticleCostInput,
  CostLineInput,
  BatchCostContext,
  PricingAlert,
  PricingAlertLevel,
  PricingPolicyResult,
  CheckoutStep,
  CheckoutResult,
  CheckoutOpts,
  CheckoutPaymentMethod,
  CheckoutInstallments,
  TaxBreakdownItem,
  PriceBreakdown,
  PriceBreakdownMetalItem,
  PriceBreakdownAdjustment,
  PricingLineSnapshot,
  CostSnapshot,
  ComponentSaleAdjustment,
  ComponentSaleBreakdown,
  ComponentSaleDetail,
  ComponentAdjustmentKind,
  MetalHechuraBreakdownSource,
  PriceSource,
  // F1.4 G5 #11-A — overrides per costLineId expuestos para que los
  // call-sites (sales.service, articles.controller) los tipen sin
  // importar el archivo interno (CLAUDE.md — siempre vía barrel).
  CostLineOverride,
  DebugWarning,
} from "./pricing-engine.types.js";
