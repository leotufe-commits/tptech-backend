// src/lib/pricing-currency-display.ts
// ============================================================================
// Helper de visualización en otra moneda para los responses de PREVIEW
// (`articles/pricing-preview` y `sales/preview`).
//
// IMPORTANTE — separación preview vs persistencia:
//
//   - El motor (`pricing-engine/`) SIEMPRE calcula y devuelve importes en
//     MONEDA BASE del tenant. No se toca.
//   - `pricingSnapshot` y todo lo que persiste `confirmSale` queda en MONEDA
//     BASE para no perder fidelidad histórica (las tasas cambian; lo
//     persistido debe ser reproducible).
//   - Este helper solo se usa en el RESPONSE del PREVIEW: si el operador
//     elige una moneda distinta a la base, el controller convierte los
//     importes monetarios para mostrar y agrega metadata `responseCurrency`.
//   - `confirmSale` NO debe importar este helper. Si lo hace, romperíamos
//     la fidelidad de los snapshots.
//
// Dirección de la conversión:
//
//   `convertMoney` del motor convierte EXTRANJERA → BASE (`amount × rate`,
//   donde `rate` se interpreta como "1 unidad extranjera = `rate` unidades
//   base").
//
//   Acá necesitamos el INVERSO (BASE → EXTRANJERA): si el operador elige
//   USD y el rate de USD es "1500" (1 USD = 1500 ARS), entonces:
//       amountUSD = amountARS / 1500
//
// Whitelist de campos:
//
//   Los responses tienen mezcla de monetarios y NO monetarios (porcentajes,
//   gramos, ids, rates). Las funciones `convertArticlePreviewResponse` y
//   `convertSalesPreviewResponse` enumeran EXPLÍCITAMENTE los campos a
//   convertir. Si se agregan campos nuevos al response, hay que sumarlos
//   acá — no hay recursión automática a propósito.
// ============================================================================

import { Prisma } from "@prisma/client";
import { prisma } from "./prisma.js";
import { getBaseCurrencyId, getExchangeRate } from "./pricing-engine/pricing-engine.currency.js";

// ─────────────────────────────────────────────────────────────────────────────
// Tipos exportados
// ─────────────────────────────────────────────────────────────────────────────

export type CurrencyMeta = {
  id:     string;
  code:   string;
  symbol: string;
};

export type ResolvedCurrencyContext = {
  /** Moneda BASE del tenant — SIEMPRE presente. */
  base: CurrencyMeta;
  /**
   * Moneda en la que se devuelve el response. Si el operador no eligió
   * ninguna o eligió la base, `target = base` y `rate = 1`.
   */
  target: CurrencyMeta;
  /** Tasa "1 unidad target = `rate` unidades base". `1` si target = base. */
  rate: number;
  /** true cuando hubo conversión real (target != base). */
  applied: boolean;
};

// ─────────────────────────────────────────────────────────────────────────────
// Resolución del contexto de moneda
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Resuelve el contexto a usar al armar el response del preview. Devuelve la
 * moneda base del tenant (siempre) y la moneda elegida por el operador (si
 * existe y es válida; si no, vuelve a la base).
 *
 * @param targetCurrencyId  id de la moneda elegida por el operador. Puede
 *                          ser null/undefined ⇒ usar moneda base.
 * @param rateOverride       cotización manual aplicada por el operador en
 *                          el documento (`draft.fxRate`). Cuando viene
 *                          válida (> 0) reemplaza la cotización vigente
 *                          del catálogo. Sin override ⇒ se usa la última
 *                          tasa de `CurrencyRate`. Sigue cayendo a base
 *                          si target no existe / está inactiva, igual que
 *                          en el flujo original.
 */
export async function getCurrencyDisplayContext(
  jewelryId: string,
  targetCurrencyId?: string | null,
  rateOverride?: number | null,
): Promise<ResolvedCurrencyContext | null> {
  const baseId = await getBaseCurrencyId(jewelryId);
  if (!baseId) return null;

  // Necesito code/symbol de la base — `getBaseCurrencyId` solo devuelve id.
  const baseRow = await prisma.currency.findFirst({
    where: { id: baseId, jewelryId, deletedAt: null },
    select: { id: true, code: true, symbol: true },
  });
  if (!baseRow) return null;
  const base: CurrencyMeta = baseRow;

  // Sin target o target = base ⇒ no convierto.
  if (!targetCurrencyId || targetCurrencyId === baseId) {
    return { base, target: base, rate: 1, applied: false };
  }

  // Resolver target. Debe ser del mismo tenant, activa.
  const targetRow = await prisma.currency.findFirst({
    where: { id: targetCurrencyId, jewelryId, isActive: true, deletedAt: null },
    select: { id: true, code: true, symbol: true },
  });
  if (!targetRow) {
    // Target no existe o está inactiva ⇒ caer a base sin error (preview es
    // tolerante).
    return { base, target: base, rate: 1, applied: false };
  }

  // Rate de target. Prioridad:
  //   1. `rateOverride` del request (cotización manual aplicada en el
  //      documento por el operador).
  //   2. `getExchangeRate(targetCurrencyId)` — última tasa del catálogo.
  // Si ninguna está disponible o es inválida ⇒ caer a base (preview es
  // tolerante).
  let rateNum: number | null = null;
  if (rateOverride != null && Number.isFinite(rateOverride) && rateOverride > 0) {
    rateNum = rateOverride;
  } else {
    const rateInfo = await getExchangeRate(targetCurrencyId);
    if (rateInfo) {
      const parsed = Number(rateInfo.rate.toString());
      if (Number.isFinite(parsed) && parsed > 0) {
        rateNum = parsed;
      }
    }
  }
  if (rateNum == null) {
    // Sin tasa válida (ni override ni catálogo) ⇒ caer a base.
    return { base, target: base, rate: 1, applied: false };
  }

  return {
    base,
    target:  { id: targetRow.id, code: targetRow.code, symbol: targetRow.symbol },
    rate:    rateNum,
    applied: true,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Conversión BASE → TARGET
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Convierte un valor monetario en moneda BASE a la moneda TARGET dividiendo
 * por la tasa. Tolera string/Decimal/number/null. Devuelve `null` cuando el
 * input es null/undefined o no es numérico.
 *
 * Mantengo precisión de 6 decimales en el intermedio y redondeo al string
 * final con 4 decimales para alinear con el formato que usa el motor.
 */
export function convertFromBase(
  amount: number | string | Prisma.Decimal | null | undefined,
  rate: number,
): number | null {
  if (amount == null) return null;
  if (!Number.isFinite(rate) || rate <= 0) return null;
  const n = typeof amount === "number"
    ? amount
    : typeof amount === "string"
      ? parseFloat(amount)
      : Number(amount.toString());
  if (!Number.isFinite(n)) return null;
  return Math.round((n / rate) * 10000) / 10000;
}

/**
 * Inversa de `convertFromBase`: convierte un monto expresado en la moneda
 * de DISPLAY (la que el operador tipeó en el documento) a la moneda BASE
 * que consume el motor. `rate` = "1 unidad display = `rate` unidades base"
 * (mismo `rate` que usa `convertFromBase`, pero multiplicando en vez de
 * dividir). No-op si no hay conversión real.
 */
export function convertToBase(
  amount: number | null | undefined,
  rate: number,
): number | null {
  if (amount == null) return null;
  if (!Number.isFinite(rate) || rate <= 0) return null;
  if (!Number.isFinite(amount)) return null;
  return Math.round((amount * rate) * 10000) / 10000;
}

/**
 * Variante que devuelve string fixed(4) — útil para campos que originalmente
 * son string (Prisma.Decimal serializado como string en muchos endpoints).
 */
export function convertFromBaseToString(
  amount: number | string | Prisma.Decimal | null | undefined,
  rate: number,
): string | null {
  const n = convertFromBase(amount, rate);
  return n == null ? null : n.toFixed(4);
}

// ─────────────────────────────────────────────────────────────────────────────
// Conversión en-place por bloques — whitelist explícita
// ─────────────────────────────────────────────────────────────────────────────
//
// Cada bloque del response del preview se convierte con una función
// dedicada. Las funciones MUTAN el objeto recibido (in-place) porque el
// response se construye fresh en el endpoint y no se comparte con nada.
//
// Reglas:
//   - Campos monetarios: SE CONVIERTEN.
//   - Cantidades físicas (gramos, peso, cantidad de unidades): NO se convierten.
//   - Porcentajes (rate, marginPct, mermaPct): NO se convierten.
//   - Identificadores (id, code, name, mode, source): NO se convierten.
//   - Si `rate === 1` (no hay conversión real), todos los helpers son no-op
//     gracias al guard en `convertFieldString` / `convertFieldNumber`.

function convertFieldString<T extends Record<string, any>>(obj: T, key: keyof T, rate: number): void {
  if (!obj || rate === 1) return;
  const v = obj[key];
  if (v == null) return;
  const conv = convertFromBaseToString(v as any, rate);
  (obj as any)[key] = conv;
}

function convertFieldNumber<T extends Record<string, any>>(obj: T, key: keyof T, rate: number): void {
  if (!obj || rate === 1) return;
  const v = obj[key];
  if (v == null) return;
  const conv = convertFromBase(v as any, rate);
  (obj as any)[key] = conv;
}

/** Bloque `taxBreakdown` de venta (lo expone tanto articles como sales por línea). */
export function convertTaxBreakdownItemsInPlace(items: any[] | null | undefined, rate: number): void {
  if (!Array.isArray(items) || rate === 1) return;
  for (const it of items) {
    convertFieldNumber(it, "base",        rate);  // baseImponible
    convertFieldNumber(it, "fixedAmount", rate);  // monto fijo (si aplica)
    convertFieldNumber(it, "taxAmount",   rate);
    // NO: rate (porcentaje), applyOn, name, code, taxId.
  }
}

/** Bloque `costTaxBreakdown` (impuestos de COMPRA). */
export function convertCostTaxBreakdownItemsInPlace(items: any[] | null | undefined, rate: number): void {
  if (!Array.isArray(items) || rate === 1) return;
  for (const it of items) {
    convertFieldNumber(it, "fixedAmount", rate);
    convertFieldNumber(it, "taxAmount",   rate);
    // NO: rate, calculationType, name, taxId.
  }
}

/** `composition` (mismo shape en articles y sales). */
export function convertCompositionInPlace(comp: any, rate: number): void {
  if (!comp || rate === 1) return;

  if (comp.metal) {
    // Metal: NO convertir grams, mermaPct, purity, ids ni labels.
    // No hay campos monetarios en composition.metal — la pieza monetaria
    // del metal vive en metalHechuraBreakdown.
  }
  if (comp.hechura) {
    convertFieldNumber(comp.hechura, "originalAmount", rate);
    convertFieldNumber(comp.hechura, "appliedAmount",  rate);
  }
  // F1.3 G4.x #9-A — metals[]/hechuras[] arrays. Mismos campos
  // monetarios que el alias legacy. Cero conversión de grams/merma/ids.
  if (Array.isArray(comp.metals)) {
    for (const m of comp.metals) {
      convertFieldNumber(m, "lineCost", rate);
      // F1.5 #A++ FIX — `lineSale` (sale-side per cost-line, passthrough del
      // motor, BASE) es monetario y DEBE convertirse igual que `lineCost`.
      // Sin esto, en multimoneda `lineCost` queda en moneda display y
      // `lineSale` en BASE → el margen por fila se calcula mezclando
      // monedas (`(saleBASE − costDISPLAY)/costDISPLAY`) y explota a
      // valores absurdos (+295.900%). Además rompe la invariante
      // documentada `Σ metals[i].lineSale === metalHechuraBreakdown.metalSale`
      // (metalSale SÍ se convierte, ver convertMetalHechuraBreakdownInPlace).
      convertFieldNumber(m, "lineSale", rate);
      // Fase 2.3 — `quotePrice` (precio por gramo BASE pre-merma) es
      // monetario y necesita conversión. Sin esto, VAL. UNIT. METAL
      // queda en moneda base mientras el resto del response viene en la
      // moneda elegida → mezcla visual.
      convertFieldNumber(m, "quotePrice", rate);
      // NO: appliedGrams, appliedMermaPct, purity, ids ni labels.
    }
  }
  if (Array.isArray(comp.hechuras)) {
    for (const h of comp.hechuras) {
      convertFieldNumber(h, "appliedAmount", rate);
      convertFieldNumber(h, "lineCost",      rate);
      // F1.5 #A+ FIX — `lineSale` monetario (mismo motivo que metals[]):
      // sin convertir, el margen por fila mezcla USD/ARS.
      convertFieldNumber(h, "lineSale",      rate);
      // Fase 2.3.1 — `unitValue` BASE pre-ajuste es monetario.
      convertFieldNumber(h, "unitValue",     rate);
      // Fase 2.2 — monto absoluto del ajuste de HECHURA. Mismo tratamiento
      // que products/services: convertir siempre `lineAdjAmount`, y
      // `lineAdjValue` SOLO cuando el ajuste es FIXED_AMOUNT (PERCENTAGE
      // queda intacto).
      convertFieldNumber(h, "lineAdjAmount", rate);
      if (h?.lineAdjType === "FIXED_AMOUNT") {
        convertFieldNumber(h, "lineAdjValue", rate);
      }
    }
  }
  // F1.3 G4.1.3 — products/services arrays. Convertir SOLO los campos
  // monetarios (unitValue, totalValue, lineAdjAmount, y lineAdjValue
  // únicamente cuando type=FIXED_AMOUNT). PRESERVAR sin convertir:
  //   · quantity (no es moneda)
  //   · ids/codes/names (strings)
  //   · lineAdjValue cuando type=PERCENTAGE (porcentaje)
  //   · affectsStock (boolean)
  //   · currencyId (id, no monto)
  for (const items of [comp.products, comp.services]) {
    if (!Array.isArray(items)) continue;
    for (const it of items) {
      convertFieldNumber(it, "unitValue",     rate);
      convertFieldNumber(it, "totalValue",    rate);
      // F1.5 #A+ FIX — `lineSale` monetario (passthrough motor, BASE). Sin
      // convertir, PRODUCT/SERVICE muestran margen con monedas mezcladas y
      // rompen `Σ lineSale === hechuraSale` en multimoneda.
      convertFieldNumber(it, "lineSale",      rate);
      convertFieldNumber(it, "lineAdjAmount", rate);
      // lineAdjValue: convertir SOLO si es FIXED_AMOUNT (es monto, no %).
      if (it?.lineAdjType === "FIXED_AMOUNT") {
        convertFieldNumber(it, "lineAdjValue", rate);
      }
    }
  }
  // Fase 2.5 — `costAdjustment` global del artículo. `amount` es siempre
  // monto absoluto (signed); `value` solo se convierte si es FIXED_AMOUNT.
  if (comp.costAdjustment) {
    convertFieldNumber(comp.costAdjustment, "amount", rate);
    if (comp.costAdjustment.type === "FIXED_AMOUNT") {
      convertFieldNumber(comp.costAdjustment, "value", rate);
    }
  }
  if (Array.isArray(comp.taxes)) {
    for (const t of comp.taxes) {
      convertFieldNumber(t, "taxAmount", rate);
      // NO: rate (porcentaje).
    }
  }
}

/** `metalHechuraBreakdown` — articles result-level y sales por línea. */
export function convertMetalHechuraBreakdownInPlace(mhb: any, rate: number): void {
  if (!mhb || rate === 1) return;
  convertFieldNumber(mhb, "metalCost",         rate);
  convertFieldNumber(mhb, "metalSale",         rate);
  convertFieldNumber(mhb, "hechuraCost",       rate);
  convertFieldNumber(mhb, "hechuraSale",       rate);
  convertFieldNumber(mhb, "metalPricePerGram", rate);
  // NO: metalMarginPct, hechuraMarginPct (porcentajes).
  // NO: metalGramsBase, metalGramsSale (cantidades físicas).
}

/** `componentSaleBreakdown` — desglose Metal/Hechura post-descuentos. */
export function convertComponentSaleBreakdownInPlace(csb: any, rate: number): void {
  if (!csb || rate === 1) return;
  for (const compKey of ["metal", "hechura"] as const) {
    const comp = csb[compKey];
    if (!comp) continue;
    convertFieldNumber(comp, "base",  rate);
    convertFieldNumber(comp, "final", rate);
    if (Array.isArray(comp.adjustments)) {
      for (const adj of comp.adjustments) {
        convertFieldNumber(adj, "amount", rate);
        // `base` también es monetario (porción del precio sobre la que se
        // calculó el ajuste). `percentage` y `valueType`/`source` no son
        // monetarios — quedan intactos.
        convertFieldNumber(adj, "base", rate);
      }
    }
  }
}

/** `appliedRounding` — el delta del redondeo es monetario, applyOn no. */
export function convertAppliedRoundingInPlace(ar: any, rate: number): void {
  if (!ar || rate === 1) return;
  convertFieldString(ar, "preRounding",   rate);
  convertFieldString(ar, "postRounding",  rate);
  convertFieldNumber(ar, "unitAdjustment", rate);
}

/** `costOverrideContext` — solo hechura.original/applied (grams/merma no). */
export function convertCostOverrideContextInPlace(ctx: any, rate: number): void {
  if (!ctx || rate === 1) return;
  if (ctx.hechura) {
    convertFieldNumber(ctx.hechura, "original", rate);
    convertFieldNumber(ctx.hechura, "applied",  rate);
  }
  // NO: grams, mermaPercent, metalVariant.
}

/** `channelResult` (articles y sales). */
export function convertChannelResultInPlace(cr: any, rate: number): void {
  if (!cr || rate === 1) return;
  convertFieldNumber(cr, "baseAmount",    rate);
  convertFieldNumber(cr, "channelAmount", rate);
  convertFieldNumber(cr, "finalAmount",   rate);
  // NO: channelId, channelName, adjustmentType, adjustmentValue (PERCENT/AMOUNT).
}

/** `couponResult`. */
export function convertCouponResultInPlace(cr: any, rate: number): void {
  if (!cr || rate === 1) return;
  convertFieldNumber(cr, "baseAmount",     rate);
  convertFieldNumber(cr, "discountAmount", rate);
  convertFieldNumber(cr, "finalAmount",    rate);
  // NO: couponCode, couponName, discountType, discountValue (puede ser
  //     PERCENT o AMOUNT — el frontend lo formatea con el discountType).
}

/** `checkoutResult` y sus `steps[]`. */
export function convertCheckoutResultInPlace(co: any, rate: number): void {
  if (!co || rate === 1) return;
  convertFieldNumber(co, "baseAmount",        rate);
  convertFieldNumber(co, "paymentAdjustment", rate);
  convertFieldNumber(co, "finalAmount",       rate);
  convertFieldNumber(co, "installmentAmount", rate);
  // NO: installments (cantidad de cuotas, entero).
  if (Array.isArray(co.steps)) {
    for (const s of co.steps) {
      convertFieldNumber(s, "amount", rate);
      // NO: code, label, formula (texto), currencyCode.
    }
  }
}

/** `shippingResult` (articles). */
export function convertShippingResultInPlace(sr: any, rate: number): void {
  if (!sr || rate === 1) return;
  convertFieldNumber(sr, "amount", rate);
  // NO: mode, label.
}

/** `documentTotals` del response de sales (y articles desde Fase 4).
 *
 *  Mantener sincronizado con `SaleDocumentTotals` en
 *  `pricing-engine.document.ts`. Si el motor agrega un campo numérico nuevo
 *  al shape, hay que sumarlo a la lista de abajo o queda en moneda base
 *  cuando se serializa en multimoneda. */
export function convertSaleDocumentTotalsInPlace(dt: any, rate: number): void {
  if (!dt || rate === 1) return;
  for (const k of [
    "subtotalBeforeDiscounts",
    "lineDiscountAmount",
    "subtotalAfterLineDiscounts",
    "channelAdjustmentAmount",
    "couponDiscountAmount",
    "paymentAdjustmentAmount",
    "shippingAmount",
    "globalDiscountAmount",
    "taxableBase",
    "taxAmount",
    "roundingAdjustment",
    "totalBeforeTax",
    "totalWithTax",
    "total",
    "legacyCouponOnlyDiscount",
    // FASE 2 — agregados Metal/Hechura a nivel documento. El motor los
    // popula desde `computeSaleDocumentTotals`. `breakdownEstimated` es
    // boolean → NO se convierte.
    "metalCostSubtotal",
    "hechuraCostSubtotal",
    "metalSaleSubtotal",
    "hechuraSaleSubtotal",
  ]) {
    convertFieldNumber(dt, k, rate);
  }
  // sourceTrace[].amount también (si existe)
  if (Array.isArray(dt.sourceTrace)) {
    for (const s of dt.sourceTrace) convertFieldNumber(s, "amount", rate);
  }
  // `documentRoundingApplied` (modo UNIFIED) — campos numéricos del delta.
  if (dt.documentRoundingApplied) {
    convertFieldNumber(dt.documentRoundingApplied, "preRounding",  rate);
    convertFieldNumber(dt.documentRoundingApplied, "postRounding", rate);
    convertFieldNumber(dt.documentRoundingApplied, "adjustment",   rate);
    // NO: source, applyOn, mode, direction (texto).
  }
  // `channelResult` y `couponResult` que viven dentro de documentTotals son
  // referencias distintas a las top-level del response — el caller puede
  // construirlas separadas (caso articles) o reusar la del motor (sales).
  // Convertimos defensivamente; si ya estaba convertido por el conversor
  // top-level, `convertFromBase` con valores ya escalados no rompe — pero
  // no debería ocurrir porque cada referencia se convierte una sola vez.
  // Para evitar doble conversión, NO convertimos acá: el caller ya las
  // convierte como bloques top-level del response. El comparador y la UI
  // leen los top-level, no los anidados en documentTotals.
  // NO: roundingInfo (mode, applyOn, direction, priceListName — texto).
}

/** Una línea del response de sales (`SalePreviewLine`). */
export function convertSalesLineInPlace(line: any, rate: number): void {
  if (!line || rate === 1) return;
  // Precios y descuentos.
  convertFieldNumber(line, "unitPrice",               rate);
  convertFieldNumber(line, "basePrice",               rate);
  convertFieldNumber(line, "lineSubtotal",            rate);
  convertFieldNumber(line, "lineTotal",               rate);
  convertFieldNumber(line, "lineDiscount",            rate);
  convertFieldNumber(line, "unitTaxAmount",           rate);
  convertFieldNumber(line, "lineTaxAmount",           rate);
  convertFieldNumber(line, "lineTotalWithTax",        rate);
  convertFieldNumber(line, "quantityDiscountAmount",  rate);
  convertFieldNumber(line, "promotionDiscountAmount", rate);
  // Costo y margen.
  convertFieldNumber(line, "unitCost",     rate);
  convertFieldNumber(line, "unitMargin",   rate);
  // marginPercent — NO se convierte.
  // Costo de compra (Fase 2A.7).
  convertFieldString(line, "costBase",      rate);
  convertFieldString(line, "costTaxAmount", rate);
  convertFieldString(line, "costWithTax",   rate);
  convertCostTaxBreakdownItemsInPlace(line.costTaxBreakdown, rate);
  // Bloques anidados.
  convertTaxBreakdownItemsInPlace(line.taxBreakdown, rate);
  convertMetalHechuraBreakdownInPlace(line.metalHechuraBreakdown, rate);
  convertComponentSaleBreakdownInPlace(line.componentSaleBreakdown, rate);
  convertCompositionInPlace(line.composition, rate);
  convertAppliedRoundingInPlace(line.appliedRounding, rate);
  // pricingSnapshot — Fase 5 contiene los mismos amounts pero también es
  // serializable; lo persiste confirmSale en moneda BASE. Acá solo mostramos
  // — convertimos en-place pero el caller (sales.service) NO debe reusar
  // este objeto para persistir.
  if (line.pricingSnapshot) {
    const ps = line.pricingSnapshot;
    convertFieldNumber(ps, "unitPrice",      rate);
    convertFieldNumber(ps, "basePrice",      rate);
    convertFieldNumber(ps, "discountAmount", rate);
    convertFieldNumber(ps, "taxAmount",      rate);
    convertFieldNumber(ps, "totalWithTax",   rate);
    convertFieldNumber(ps, "unitCost",       rate);
    convertFieldNumber(ps, "unitMargin",     rate);
    // NO: marginPercent, priceSource, baseSource, ids, costMode.
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Conversores top-level
// ─────────────────────────────────────────────────────────────────────────────

/** Response completo de `articles/pricing-preview`. */
export function convertArticlePreviewResponseInPlace(res: any, rate: number): void {
  if (!res || rate === 1) return;

  // Precios principales (string formateado en el controller).
  convertFieldString(res, "unitPrice",               rate);
  convertFieldString(res, "basePrice",               rate);
  convertFieldString(res, "quantityDiscountAmount",  rate);
  convertFieldString(res, "promotionDiscountAmount", rate);
  convertFieldString(res, "discountAmount",          rate);

  // Costo / margen.
  convertFieldString(res, "unitCost",   rate);
  convertFieldString(res, "unitMargin", rate);
  // marginPercent — NO.

  // Impuestos venta.
  convertFieldString(res, "taxAmount",    rate);
  convertFieldString(res, "totalWithTax", rate);
  convertTaxBreakdownItemsInPlace(res.taxBreakdown, rate);

  // FASE 1.1 G3 — totales per-line top-level (números, no strings).
  convertFieldNumber(res, "lineTotal",        rate);
  convertFieldNumber(res, "lineTaxAmount",    rate);
  convertFieldNumber(res, "lineTotalWithTax", rate);
  // FASE 1.2 G3.1 — descuento per-line top-level (mismo patrón que G3).
  convertFieldNumber(res, "lineDiscount",     rate);

  // Costo de compra.
  convertFieldString(res, "costBase",      rate);
  convertFieldString(res, "costTaxAmount", rate);
  convertFieldString(res, "costWithTax",   rate);
  convertCostTaxBreakdownItemsInPlace(res.costTaxBreakdown, rate);

  // Bloques anidados.
  convertChannelResultInPlace(res.channelResult, rate);
  convertCouponResultInPlace(res.couponResult, rate);
  convertCheckoutResultInPlace(res.checkoutResult, rate);
  convertShippingResultInPlace(res.shippingResult, rate);
  convertMetalHechuraBreakdownInPlace(res.metalHechuraBreakdown, rate);
  convertComponentSaleBreakdownInPlace(res.componentSaleBreakdown, rate);
  convertCompositionInPlace(res.composition, rate);
  convertAppliedRoundingInPlace(res.appliedRounding, rate);
  convertCostOverrideContextInPlace(res.costOverrideContext, rate);

  // `documentTotals` — articles lo popula desde Fase 4 (mismo shape que
  // sales). Se convierte con el mismo helper para garantizar simetría con
  // `sales/preview` y que el comparador y los consumidores frontend reciban
  // todos los importes en la moneda seleccionada.
  convertSaleDocumentTotalsInPlace(res.documentTotals, rate);
}

/**
 * FASE 1.1 G6 — convierte el response de `articles/:id/cost-lines/preview` a
 * la moneda solicitada. Los campos monetarios (value/metalCost/hechuraCost
 * + costBase/costTaxAmount/costWithTax) se dividen por la rate; gramos y
 * purity NO se convierten (no son moneda).
 */
export function convertCostPreviewResponseInPlace(res: any, rate: number): void {
  if (!res || rate === 1) return;
  if (res.cost) {
    convertFieldString(res.cost, "value",       rate);
    convertFieldString(res.cost, "metalCost",   rate);
    convertFieldString(res.cost, "hechuraCost", rate);
    // totalGrams, metalGramsWithMerma, metalPurity → NO se convierten.
  }
  if (res.purchaseTaxes) {
    // purchaseTaxes ya viene como objeto con campos string ("0.0000").
    convertFieldString(res.purchaseTaxes, "costBase",      rate);
    convertFieldString(res.purchaseTaxes, "costTaxAmount", rate);
    convertFieldString(res.purchaseTaxes, "costWithTax",   rate);
    convertCostTaxBreakdownItemsInPlace(res.purchaseTaxes.costTaxBreakdown, rate);
  }
}

/** Response completo de `sales/preview`. */
export function convertSalesPreviewResponseInPlace(res: any, rate: number): void {
  if (!res || rate === 1) return;
  if (Array.isArray(res.lines)) {
    for (const l of res.lines) convertSalesLineInPlace(l, rate);
  }
  convertChannelResultInPlace(res.channelResult, rate);
  convertCouponResultInPlace(res.couponResult, rate);
  convertCheckoutResultInPlace(res.checkoutResult, rate);
  convertFieldNumber(res, "subtotal", rate);
  convertFieldNumber(res, "total",    rate);
  convertSaleDocumentTotalsInPlace(res.documentTotals, rate);
}

/**
 * Inversa de `convertSalesPreviewResponseInPlace`. Convierte los inputs
 * MONETARIOS que el operador tipeó en la moneda del documento (display) a
 * moneda BASE, ANTES de que el motor (que trabaja 100% en base) los consuma.
 *
 * Simetría obligatoria: input display→base acá, response base→display al
 * final. Sin esto, un descuento/impuesto/precio AMOUNT de "20" (p.ej. USD)
 * se aplicaba como "20" en base (p.ej. ARS) y volvía como ~"0,01" tras la
 * conversión del response.
 *
 * Whitelist EXPLÍCITA (mismo criterio que el response):
 *   - Montos AMOUNT: SÍ. Porcentajes (mode/type PERCENT): NO (son adimensionales).
 *   - Cantidades físicas (gramos, merma, weight): NO.
 *   - `currencyRate`: NO (es la tasa, no un monto).
 *   - Overrides de composición de costo (hechura/gramos/merma/costLines):
 *     fuera de alcance acá (capa de costo, no input monetario del documento).
 *
 * Solo se invoca cuando hay moneda de display ≠ base (`ctx.applied`).
 */
export function convertSalesPreviewInputInPlace(
  input: {
    lines?: Array<{
      manualPriceOverride?: number | null;
      manualDiscountOverride?: { mode: "PERCENT" | "AMOUNT"; value: number } | null;
      taxOverride?:           { mode: "PERCENT" | "AMOUNT"; value: number } | null;
    }> | null;
    shippingAmount?: number;
    shipping?: { mode: "FIXED" | "BY_WEIGHT" | "FREE"; value?: number | null; weight?: number | null } | null;
    globalDiscountAmount?: number;
    globalDiscount?: { type: "PERCENT" | "AMOUNT"; value: number } | null;
  } | null | undefined,
  rate: number,
): void {
  if (!input || rate === 1 || !Number.isFinite(rate) || rate <= 0) return;
  const toB = (n: number) => Math.round((n * rate) * 10000) / 10000;

  for (const l of input.lines ?? []) {
    if (typeof l.manualPriceOverride === "number") {
      l.manualPriceOverride = toB(l.manualPriceOverride);
    }
    // SOLO AMOUNT: PERCENT es adimensional y NO se convierte.
    if (l.manualDiscountOverride && l.manualDiscountOverride.mode === "AMOUNT") {
      l.manualDiscountOverride.value = toB(l.manualDiscountOverride.value);
    }
    if (l.taxOverride && l.taxOverride.mode === "AMOUNT") {
      l.taxOverride.value = toB(l.taxOverride.value);
    }
  }

  if (typeof input.shippingAmount === "number") {
    input.shippingAmount = toB(input.shippingAmount);
  }
  if (input.shipping && input.shipping.mode === "FIXED"
      && typeof input.shipping.value === "number") {
    input.shipping.value = toB(input.shipping.value);
  }
  if (typeof input.globalDiscountAmount === "number") {
    input.globalDiscountAmount = toB(input.globalDiscountAmount);
  }
  if (input.globalDiscount && input.globalDiscount.type === "AMOUNT") {
    input.globalDiscount.value = toB(input.globalDiscount.value);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Metadata de moneda para adosar al response
// ─────────────────────────────────────────────────────────────────────────────

export type ResponseCurrencyMetadata = {
  responseCurrencyId:     string;
  responseCurrencyCode:   string;
  responseCurrencySymbol: string;
  baseCurrencyId:         string;
  baseCurrencyCode:       string;
  baseCurrencySymbol:     string;
  /** Tasa "1 unidad responseCurrency = `currencyRate` unidades base". `1` si
   *  responseCurrency = base. */
  currencyRate:           number;
  /** true cuando hubo conversión real. */
  currencyConverted:      boolean;
};

export function buildResponseCurrencyMetadata(ctx: ResolvedCurrencyContext): ResponseCurrencyMetadata {
  return {
    responseCurrencyId:     ctx.target.id,
    responseCurrencyCode:   ctx.target.code,
    responseCurrencySymbol: ctx.target.symbol,
    baseCurrencyId:         ctx.base.id,
    baseCurrencyCode:       ctx.base.code,
    baseCurrencySymbol:     ctx.base.symbol,
    currencyRate:           ctx.rate,
    currencyConverted:      ctx.applied,
  };
}
