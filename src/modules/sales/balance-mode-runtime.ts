// src/modules/sales/balance-mode-runtime.ts
// =============================================================================
// T55 (Fase 3B.5) — Runtime de Balance Mode para Ventas.
//
// Centraliza el cableado del motor de Balance Mode (POLICY.md §11) en el flujo
// previewSale / confirmSale / sale.hook:
//
//   1. `resolveSaleBalanceMode(args)`   — invoca `resolveBalanceMode` con los
//      defaults comerciales del documento (cliente / lista / tenant), aplicando
//      la compatibilidad legacy `CommercialEntity.balanceType` vía
//      `mapBalanceTypeToMode`.
//   2. `buildSaleBalanceBreakdownFromLines(args)` — proyecta las líneas
//      resueltas + totales del documento al input canónico de
//      `buildDocumentBalanceBreakdown`. Las líneas con metales aportan gramos;
//      las componentes monetarias se enriquecen como display-only.
//
// Reglas críticas:
//   · NO recalcula precios, costos ni impuestos.
//   · NO toca cuenta corriente / movimientos / AccountMovementMetalEntry —
//     eso es 3B.6.
//   · Pure functions (módulo carga de nombres de metal, que sí hace DB).
// =============================================================================

// NOTA: importamos DIRECTAMENTE desde los archivos fuente (no desde el barrel
// `pricing-engine.js`) porque varios tests de `sales` mockean el barrel
// completo con `vi.mock("../../../lib/pricing-engine/pricing-engine.js")` y
// esos mocks no exponen estas funciones nuevas. Importando los archivos
// fuente sorteamos el mock y preservamos compatibilidad con tests legados
// que solo pretenden simular `resolveFinalSalePrice` y similares.
import {
  resolveBalanceMode,
} from "../../lib/pricing-engine/balance-mode-resolver.js";
import {
  buildDocumentBalanceBreakdown,
  mapBalanceTypeToMode,
  type BuildBreakdownLineInput,
} from "../../lib/pricing-engine/pricing-engine.balance.js";
import type {
  BalanceMode,
  BalanceModeResolution,
  DocumentBalanceBreakdown,
  DocumentBalanceMonetaryComponent,
} from "../../lib/pricing-engine/pricing-engine.types.js";

// ─────────────────────────────────────────────────────────────────────────────
// Resolución
// ─────────────────────────────────────────────────────────────────────────────

/** Inputs comerciales del documento para resolver Balance Mode. */
export interface ResolveSaleBalanceModeArgs {
  /** Override manual del documento (top de R11.4). */
  documentOverride?: BalanceMode | null;
  /** Default del cliente desde el nuevo campo `CommercialEntity.balanceMode`. */
  entityBalanceMode?: BalanceMode | null;
  /** Legacy `CommercialEntity.balanceType` para back-compat. Se traduce con
   *  `mapBalanceTypeToMode`; el nuevo campo tiene prioridad sobre este. */
  entityBalanceTypeLegacy?: string | null;
  /** Default de la lista de precios resuelta. */
  priceListDefault?: BalanceMode | null;
  /** `PriceList.mode` de la lista resuelta (`MARGIN_TOTAL` / `METAL_HECHURA`
   *  / `COST_PER_GRAM`). Habilita el "default inteligente del nivel lista":
   *  cuando `priceListDefault` viene `null` (lista sin `balanceMode` explícito)
   *  y la lista calcula precios separando metal y hechura
   *  (`mode === "METAL_HECHURA"`), el nivel "lista" aporta `BREAKDOWN` antes
   *  de delegar al tenant. Si la lista tiene `balanceMode` definido, ese gana
   *  — el default inteligente NO sobreescribe la intención explícita.
   *  Opcional para back-compat: callers viejos que no lo pasen se comportan
   *  exactamente como antes (priceListDefault crudo). */
  priceListMode?: string | null;
  /** Default global del tenant (`Jewelry.defaultBalanceMode`). */
  tenantDefault?: BalanceMode | null;
}

/** Resuelve el Balance Mode del documento aplicando R11.4 + back-compat
 *  `balanceType` legacy. Función pura — sin DB, sin async.
 *
 *  Default inteligente del nivel lista (POLICY §11 R11.4 — extensión 2026-05):
 *  cuando `PriceList.balanceMode` viene `null` y `PriceList.mode ==="METAL_HECHURA"`,
 *  el resolver trata el nivel "lista" como aporte `BREAKDOWN`. Esto evita que
 *  listas desglosadas legacy (creadas antes del rollout del campo `balanceMode`)
 *  caigan a UNIFIED por el tenant default y rompan el render del Patrimonio
 *  Metálico — el operador SIEMPRE espera saldo desglosado cuando la lista
 *  separa metal y hechura. La inferencia ocurre acá, NO en `resolveBalanceMode`
 *  (que sigue siendo puro estricto sobre los 4 niveles). El source emitido
 *  sigue siendo `PRICELIST_DEFAULT` — la fuente del veredicto es la lista. */
export function resolveSaleBalanceMode(
  args: ResolveSaleBalanceModeArgs,
): BalanceModeResolution {
  // Compatibilidad: nuevo campo `balanceMode` gana sobre legacy `balanceType`.
  const entityDefault =
    args.entityBalanceMode ?? mapBalanceTypeToMode(args.entityBalanceTypeLegacy ?? null);

  // Default inteligente del nivel lista — sólo cuando `balanceMode` no está
  // explícito. Si la lista trae UNIFIED/BREAKDOWN explícito, ese gana siempre.
  const priceListDefault =
    args.priceListDefault
    ?? (args.priceListMode === "METAL_HECHURA" ? ("BREAKDOWN" as BalanceMode) : null);

  return resolveBalanceMode({
    documentOverride: args.documentOverride ?? null,
    entityDefault,
    priceListDefault,
    tenantDefault:    args.tenantDefault    ?? null,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Construcción del breakdown desde líneas resueltas
// ─────────────────────────────────────────────────────────────────────────────

/** Forma compacta de una línea de venta para alimentar el builder. Solo los
 *  campos relevantes para Balance Mode — el resto del pricing engine no entra. */
export interface SaleLineForBalance {
  /** ID estable de la línea (SaleLine.id o índice en preview). */
  lineId:   string;
  /** Cantidad de la línea. */
  quantity: number;
  /** Items metálicos del costo de la línea — uno por variante (del motor).
   *  Producidos por `extractMetalItemsFromSteps` desde `costResult.steps`
   *  enriquecidos (key `COST_LINES_METAL` + `enrichCostMetalSteps`).
   *
   *  Nota arquitectónica: hasta el bug fix de Opción A se leía desde
   *  `costResult.breakdown.metal.items[]`, pero `calculateCostFromLines`
   *  NUNCA poblaba ese array (siempre `items: []`). La fuente real son los
   *  steps `COST_LINES_METAL` que el motor de cost emite por cada cost
   *  line tipo METAL. Esos steps son la única ruta canónica hoy. */
  metalItems?: Array<{
    metalId?:       string | null;
    variantId?:     string | null;
    gramsOriginal?: number | null;
    purity?:        number | null;
    gramsPure?:     number | null;
    /** Gramos POR UNIDAD post pureza Y post merma — passthrough exacto del
     *  `step.meta.gramsFineEquivalent` que ya emite
     *  `enrichCostMetalSteps` (`pricing-engine.cost.ts:585-588` →
     *  `gramsOriginal × purity × (1+merma/100)`). Es la fórmula canónica del
     *  redondeo comercial (regla R-COMMERCIAL-GRAMS-WITH-MERMA). `null` cuando
     *  el motor no pudo computarlo (purity ausente, etc.). */
    gramsFineEquivalent?: number | null;
    /** Cotización por gramo en moneda BASE (= quotePrice del step METAL). */
    unitValue?:     number | null;
  }>;
  /** Valuación del metal de la línea EN MONEDA DEL DOCUMENTO (= metalSale ×
   *  quantity del motor). Determina cuánto del total cae fuera del monetary
   *  en BREAKDOWN. */
  metalLineValuationDocCurrency?: number | null;
}

// ─────────────────────────────────────────────────────────────────────────────
// extractMetalItemsFromSteps — Opción A del fix balance metals.
//
// Convierte los `costResult.steps[]` del motor de cost (post
// `enrichCostMetalSteps`) en el shape `SaleLineForBalance.metalItems`.
//
// CONTRATO de los steps (pricing-engine.cost.ts):
//   - key:           "COST_LINES_METAL"
//   - status:        "ok"
//   - value:         Decimal (lineCost en BASE — NO usamos acá)
//   - meta.variantId, meta.qty (string), meta.merma, meta.quotePrice (string),
//     meta.costLineId
//   - meta enriquecido (post enrichCostMetalSteps):
//       · meta.metalId            → ID del METAL PADRE (clave para agrupar)
//       · meta.purity             → 0..1
//       · meta.gramsOriginal      → number (alias de qty parseado)
//       · meta.gramsFineEquivalent → number = qty × purity × (1+merma/100)
//       · meta.variantName, metalName, etc.
//
// Cero matemática nueva: passthrough de campos ya emitidos por el motor.
// El builder (`buildDocumentBalanceBreakdown`) aplica multiplicación por
// `quantity` de la línea Y `gramsPure = grams × purity`.
//
// Si el step no tiene `metalId` (raro — sería un MetalVariant huérfano), se
// descarta. Si no tiene `purity`, se asume 1 (puro) — comportamiento alineado
// con el builder.
// ─────────────────────────────────────────────────────────────────────────────

/** Shape mínimo de step que necesitamos. Compatible con `PricingStep` del motor. */
interface MetalStepLike {
  key:    string;
  status: string;
  meta?:  Record<string, unknown> | null;
}

/** Lee un campo numérico defensivamente — acepta number, string ("1.5") o
 *  Decimal-like (con `toString`). Devuelve `null` si no es finite. */
function readNum(v: unknown): number | null {
  if (v == null) return null;
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v === "string") {
    const n = parseFloat(v);
    return Number.isFinite(n) ? n : null;
  }
  if (typeof v === "object" && v !== null && "toString" in v) {
    const n = parseFloat((v as { toString(): string }).toString());
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

function readStr(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

/** Extrae los items metálicos POR UNIDAD del artículo desde los steps del
 *  motor de cost. Función PURA — sin DB, sin async. */
export function extractMetalItemsFromSteps(
  steps: ReadonlyArray<MetalStepLike> | null | undefined,
): NonNullable<SaleLineForBalance["metalItems"]> {
  if (!Array.isArray(steps) || steps.length === 0) return [];
  const out: NonNullable<SaleLineForBalance["metalItems"]> = [];
  for (const s of steps) {
    if (!s || s.key !== "COST_LINES_METAL" || s.status !== "ok") continue;
    const meta = (s.meta ?? {}) as Record<string, unknown>;
    const metalId   = readStr(meta.metalId);
    const variantId = readStr(meta.variantId);
    // `gramsOriginal` post-enrich es number; fallback a qty (string) parseado.
    const grams =
      readNum(meta.gramsOriginal)
      ?? readNum(meta.qty);
    if (grams == null || grams <= 1e-9) continue;
    // metalId puede faltar si `enrichCostMetalSteps` no corrió aún o la
    // variante quedó huérfana. Sin metalId no podemos agrupar por padre.
    if (!metalId) continue;
    const purity    = readNum(meta.purity);
    const quotePrice = readNum(meta.quotePrice);
    // Passthrough del campo canónico que ya emite `enrichCostMetalSteps`:
    // `gramsOriginal × purity × (1+merma/100)`. Es la fuente única del
    // redondeo comercial (regla R-COMMERCIAL-GRAMS-WITH-MERMA). No
    // recalculamos: si el motor no lo emitió, queda null y los callers
    // hacen fallback explícito.
    const gramsFineEquivalent = readNum(meta.gramsFineEquivalent);
    out.push({
      metalId,
      variantId,
      gramsOriginal: grams,
      purity,
      // gramsPure se omite: el builder lo calcula como `grams × purity` (con
      // fallback purity=1 cuando es null). Pasarlo acá duplicaría el cálculo.
      gramsFineEquivalent,
      unitValue: quotePrice,
    });
  }
  return out;
}

/** Args para construir el breakdown del documento. */
export interface BuildSaleBalanceBreakdownArgs {
  mode:              BalanceMode;
  /** Total final del documento en moneda del documento. */
  documentTotal:     number;
  /** Total en moneda BASE. = `documentTotal × currencyRate` por construcción. */
  documentTotalBase: number;
  currency:          { code: string; rate: number };
  lines:             SaleLineForBalance[];
  /** Mapa metalId → nombre del padre. Lo provee el caller (preview/confirm)
   *  con una query batch antes de invocar este helper. Si falta, se usa el
   *  metalId como nombre. */
  metalNames?:       Map<string, string>;
  /** Mapa variantId → nombre. Mismo contrato. */
  variantNames?:     Map<string, string>;
  /** Componentes monetarios consolidados a NIVEL DOCUMENTO (hechura, IVA,
   *  descuentos, recargos, canal, cupón, pago, envío, redondeo, ajuste).
   *  DISPLAY-ONLY — el saldo monetario sigue saliendo de `documentTotal`.
   *  El caller los arma desde valores ya calculados por el motor — cero
   *  matemática nueva. Quedan persistidos en `monetaryBalance.components[]`
   *  del snapshot v3. */
  documentMonetaryComponents?: DocumentBalanceMonetaryComponent[];
}

/** Convierte las líneas + totales del flujo de venta al input canónico de
 *  `buildDocumentBalanceBreakdown`. NO recalcula nada: solo proyecta. */
export function buildSaleBalanceBreakdown(
  args: BuildSaleBalanceBreakdownArgs,
): DocumentBalanceBreakdown {
  const { mode, documentTotal, documentTotalBase, currency, lines } = args;

  const projected: BuildBreakdownLineInput[] = lines.map((l) => ({
    lineId:   l.lineId,
    quantity: l.quantity,
    ...(l.metalItems && l.metalItems.length > 0
      ? {
          metals: l.metalItems
            // Descartamos items sin metalId (no podemos agrupar por padre)
            // y sin gramos significativos.
            .filter((m) => !!m.metalId && (m.gramsOriginal ?? 0) > 1e-9)
            .map((m) => {
              const parentId   = m.metalId!;
              const variantId  = m.variantId ?? "";
              const parentName = args.metalNames?.get(parentId) ?? parentId;
              const variantName = variantId
                ? (args.variantNames?.get(variantId) ?? variantId)
                : parentName;
              // El breakdown del motor expone `gramsOriginal` POR UNIDAD (ya
              // que la línea entera multiplica por quantity al sumar). Pasamos
              // directamente y dejamos que el builder multiplique por qty.
              const gramsPerUnit = Number(m.gramsOriginal ?? 0);
              const purity = m.purity != null ? Number(m.purity) : null;
              // El metalLineValuationDocCurrency va una sola vez por línea
              // (no por variante). Lo pasamos en la PRIMERA variante para
              // no contarlo doble. (Si el motor expusiera valuación por
              // variante en el futuro, esto cambia.)
              return {
                metalParentId:    parentId,
                metalParentName:  parentName,
                metalVariantId:   variantId,
                metalVariantName: variantName,
                appliedGramsPerUnit: gramsPerUnit,
                purity,
                quotePriceSnapshot:
                  m.unitValue != null ? Number(m.unitValue) : null,
                // Solo el primer item de la línea lleva la valuación monetaria
                // de la línea — es el agregado, no per-variant.
                metalLineValuationDocCurrency:
                  null,
              };
            })
            .map((m, idx, arr) =>
              idx === 0 && arr.length > 0
                ? {
                    ...m,
                    metalLineValuationDocCurrency:
                      l.metalLineValuationDocCurrency ?? null,
                  }
                : m,
            ),
        }
      : {}),
  }));

  return buildDocumentBalanceBreakdown(
    {
      documentTotal,
      documentTotalBase,
      currency,
      lines: projected,
      ...(args.documentMonetaryComponents && args.documentMonetaryComponents.length > 0
        ? { documentMonetaryComponents: args.documentMonetaryComponents }
        : {}),
    },
    mode,
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// buildDocumentMonetaryComponentsFromTotals
//
// Construye los componentes monetarios DOC-LEVEL a partir de los agregados que
// el motor ya emitió en `SaleDocumentTotals`. CERO matemática nueva: cada
// `amount` es un passthrough (a lo sumo, con cambio de signo cuando el campo
// del motor es magnitud positiva pero conceptualmente RESTA del saldo —
// p.ej. `couponDiscountAmount`).
//
// Los componentes son DISPLAY-ONLY: NO afectan el saldo monetario final
// (`monetary.amount` sale de `documentTotal`). Sirven para que la UI pinte
// "Composición del total" y para auditoría futura del snapshot.
//
// Componentes emitidos (omitidos cuando son 0):
//   · HECHURA           → totals.hechuraSaleSubtotal   (group HECHURA)
//                        Nota: en `pricing-engine.cost.ts:339-341` "todo lo
//                        que NO es metal" se acumula en hechuraTotal, así que
//                        este bucket YA incluye PRODUCT + SERVICE + MANUAL del
//                        cost-line. NO emitir PRODUCT/SERVICE por separado
//                        sería doble contabilización.
//   · DISCOUNT_QTY      → −totals.lineDiscountAmount   (group DISCOUNT)
//   · CHANNEL           → totals.channelAdjustmentAmount signed (group CHANNEL)
//   · COUPON            → −totals.couponDiscountAmount  (group COUPON)
//   · DISCOUNT_MANUAL   → −totals.globalDiscountAmount  (group DISCOUNT)
//   · PAYMENT           → totals.paymentAdjustmentAmount signed (group PAYMENT)
//   · SHIPPING          → totals.shippingAmount         (group SHIPPING)
//   · TAX               → totals.taxAmount              (group TAX)
//   · ROUNDING_MONETARY → totals.roundingAdjustment signed (group ROUNDING)
//
// Etapa UX-Auditable (2026-05-29) — agregados para que Σ components cuadre
// con el "Saldo monetario" canónico (= total − Σ valuationMonetary):
//   · METAL_MARGIN      → metalCostSubtotal − Σ valuationMonetary (group MARGIN)
//                        Cubre la diferencia entre la valuación del metal del
//                        cost-line y el valor físico puro del balance. Si esos
//                        dos coinciden (purity=1 y merma=0), queda en 0.
//   · MANUAL_ADJUSTMENT → manualAdjustmentMonetaryAmount signed (group ADJUSTMENT)
//                        Snapshot.totals.totalMonetaryAdjustment de la capa 17.
// ─────────────────────────────────────────────────────────────────────────────

/** Inputs opcionales de etiquetado / trazabilidad. Cuando faltan, el helper
 *  usa labels genéricos en español ("Canal de venta", "Cupón", etc.). */
export interface BuildDocumentMonetaryComponentsArgs {
  /** Agregados emitidos por `computeSaleDocumentTotals`. */
  totals: {
    hechuraSaleSubtotal?:    number;
    lineDiscountAmount?:     number;
    channelAdjustmentAmount?: number;
    couponDiscountAmount?:   number;
    globalDiscountAmount?:   number;
    paymentAdjustmentAmount?: number;
    shippingAmount?:         number;
    taxAmount?:              number;
    roundingAdjustment?:     number;
    /** Etapa UX-Auditable — Σ metalCost × qty del cost-line (sin margen del
     *  motor de lista). Junto con `metalValuationSum` permite emitir el
     *  componente `METAL_MARGIN`. Cuando falta, METAL_MARGIN no se emite. */
    metalCostSubtotal?:      number;
  };
  /** Etapa UX-Auditable — Σ `balanceBreakdown.metals[i].valuationMonetary`
   *  (= gramsPure × quotePriceSnapshot, valor físico puro del balance).
   *  El caller calcula esta suma DESPUÉS de construir el balance. */
  metalValuationSum?: number | null;
  /** Etapa UX-Auditable — `manualAdjustmentSnapshot.totals.totalMonetaryAdjustment`
   *  (capa 17). Cubre tanto UNIFIED como BREAKDOWN. Cuando viene 0 o null
   *  no emite el component. */
  manualAdjustmentMonetaryAmount?: number | null;
  /** Nombre humano del canal (`channelResult.channelName`). */
  channelLabel?:  string | null;
  /** ID del canal para drill-down (`channelResult.channelId`). */
  channelSource?: string | null;
  /** Nombre del cupón (`couponResult.couponName`). */
  couponLabel?:   string | null;
  /** ID del cupón. */
  couponSource?:  string | null;
  /** Etiqueta de la forma de pago (ej. "Tarjeta Visa 12 cuotas"). */
  paymentLabel?:  string | null;
}

const EPS = 0.005;

/** Construye `documentMonetaryComponents[]` desde los agregados del motor.
 *  Función pura — sin DB, sin async, sin side effects. */
export function buildDocumentMonetaryComponentsFromTotals(
  args: BuildDocumentMonetaryComponentsArgs,
): DocumentBalanceMonetaryComponent[] {
  const t = args.totals ?? {};
  const out: DocumentBalanceMonetaryComponent[] = [];

  const hechura = num(t.hechuraSaleSubtotal);
  if (hechura > EPS) {
    out.push({
      type:   "HECHURA",
      group:  "HECHURA",
      label:  "Hechura",
      amount: hechura,
    });
  }

  // Etapa UX-Auditable — METAL_MARGIN. Diferencia entre el costo del metal
  // del cost-line (= qty × purity × (1+merma) × unitValue) y el valor físico
  // puro del balance (= gramsPure × quotePriceSnapshot). Esa diferencia
  // captura merma, margen del metal del motor de lista y cualquier delta
  // contable entre el motor de cost y el balance — sin doblar el redondeo
  // físico (que ya viaja por ROUNDING_MONETARY).
  // Solo emite cuando hay datos suficientes (ambos inputs ≥ 0 finitos) y la
  // diferencia es significativa. Acepta signo: puede ser negativo si el
  // balance valúa el metal por encima del cost-line (caso poco usual).
  const metalCostSubtotal = num(t.metalCostSubtotal);
  const metalValuationSum = num(args.metalValuationSum);
  if (
    (typeof t.metalCostSubtotal === "number" && Number.isFinite(t.metalCostSubtotal))
    && (typeof args.metalValuationSum === "number" && Number.isFinite(args.metalValuationSum))
  ) {
    const metalMargin = Math.round((metalCostSubtotal - metalValuationSum) * 100) / 100;
    if (Math.abs(metalMargin) > EPS) {
      out.push({
        type:   "METAL_MARGIN",
        group:  "MARGIN",
        label:  "Diferencia metal (venta vs físico)",
        amount: metalMargin,
      });
    }
  }

  const lineDiscount = num(t.lineDiscountAmount);
  if (lineDiscount > EPS) {
    out.push({
      type:   "DISCOUNT_QTY",
      group:  "DISCOUNT",
      label:  "Descuentos de línea",
      amount: -lineDiscount,
    });
  }

  const channelAmount = num(t.channelAdjustmentAmount);
  if (Math.abs(channelAmount) > EPS) {
    out.push({
      type:   "CHANNEL",
      group:  "CHANNEL",
      label:  args.channelLabel || "Canal de venta",
      amount: channelAmount,
      ...(args.channelSource ? { source: args.channelSource } : {}),
    });
  }

  const couponAmount = num(t.couponDiscountAmount);
  if (couponAmount > EPS) {
    out.push({
      type:   "COUPON",
      group:  "COUPON",
      label:  args.couponLabel || "Cupón",
      amount: -couponAmount,
      ...(args.couponSource ? { source: args.couponSource } : {}),
    });
  }

  const globalDiscount = num(t.globalDiscountAmount);
  if (globalDiscount > EPS) {
    out.push({
      type:   "DISCOUNT_MANUAL",
      group:  "DISCOUNT",
      label:  "Descuento global",
      amount: -globalDiscount,
    });
  }

  const paymentAmount = num(t.paymentAdjustmentAmount);
  if (Math.abs(paymentAmount) > EPS) {
    out.push({
      type:   "PAYMENT",
      group:  "PAYMENT",
      label:  args.paymentLabel || "Forma de pago",
      amount: paymentAmount,
    });
  }

  const shippingAmount = num(t.shippingAmount);
  if (shippingAmount > EPS) {
    out.push({
      type:   "SHIPPING",
      group:  "SHIPPING",
      label:  "Envío",
      amount: shippingAmount,
    });
  }

  const taxAmount = num(t.taxAmount);
  if (taxAmount > EPS) {
    out.push({
      type:   "TAX",
      group:  "TAX",
      label:  "IVA",
      amount: taxAmount,
    });
  }

  const rounding = num(t.roundingAdjustment);
  if (Math.abs(rounding) > EPS) {
    out.push({
      type:   "ROUNDING_MONETARY",
      group:  "ROUNDING",
      label:  "Redondeo",
      amount: rounding,
    });
  }

  // Etapa UX-Auditable — MANUAL_ADJUSTMENT. Capa 17 del pipeline (post-motor).
  // Passthrough EXACTO de `manualAdjustmentSnapshot.totals.totalMonetaryAdjustment`
  // (consolida UNIFIED `amount` o BREAKDOWN `monetary.amount + metalMonetaryEquivalent`).
  // Solo emite cuando hay snapshot y el delta es significativo.
  const manualAdj = num(args.manualAdjustmentMonetaryAmount);
  if (Math.abs(manualAdj) > EPS) {
    out.push({
      type:   "MANUAL_ADJUSTMENT",
      group:  "ADJUSTMENT",
      label:  "Ajuste manual",
      amount: manualAdj,
    });
  }

  return out;
}

function num(v: number | null | undefined): number {
  return typeof v === "number" && Number.isFinite(v) ? v : 0;
}
