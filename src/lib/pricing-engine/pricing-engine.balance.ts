// src/lib/pricing-engine/pricing-engine.balance.ts
// Conversión de PriceBreakdown → BalanceBreakdown para cuenta corriente.
//
// Reglas clave:
//   - Metal se acumula en GRAMOS PUROS (gramsPure)
//   - Hechura se acumula en DINERO (moneda base)
//   - No se mezclan ni se convierten entre sí

import type {
  BalanceMode,
  DocumentBalanceBreakdown,
  DocumentBalanceMetalEntry,
  DocumentBalanceMetalVariant,
  DocumentBalanceMonetary,
  DocumentBalanceMonetaryComponent,
  PriceBreakdown,
} from "./pricing-engine.types.js";

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

// =============================================================================
// T52 (Fase 3B.2) — buildDocumentBalanceBreakdown
// Builder puro del DocumentBalanceBreakdown canónico (Snapshot v6 Balance
// Mode — técnicamente v3). Construye el shape que se persiste en
// `DocumentPricingSnapshot.balanceBreakdown` (sub-fase 3B.3) y que el hook
// `onSaleConfirmed` proyectará a `CurrentAccountMovement` +
// `AccountMovementMetalEntry[]` (sub-fase 3B.6).
//
// Reglas (POLICY.md §11):
//   · UNIFIED   → metals = [], monetary.amount = documentTotal.
//   · BREAKDOWN → metals agrupados por padre con pureza ponderada,
//                 monetary.amount = documentTotal − Σ valuación metal
//                 (regla canónica del Simulador SSOT: "el saldo
//                 monetario absorbe todo lo no-metal").
//   · IVA, promos, descuentos, recargos, redondeos: siempre afectan al
//     monetary; NUNCA modifican `gramsPure` (R11.3 + R11.2).
//   · `manualPrice` NO afecta gramos físicos: éstos son `appliedGrams`
//     del cost. Su efecto cae en monetary.
//   · Pureza ponderada del padre: Σ(g_i × p_i) / Σ g_i, null cuando Σ g_i = 0.
//
// Función pura: sin DB, sin async, sin side effects, sin mutar input.
// No se invoca en runtime todavía (3B.5 hace la integración a previewSale/
// confirmSale).
// =============================================================================

/** Input compacto para construir el breakdown del documento. */
export interface BuildDocumentBalanceBreakdownInput {
  /** Total final del documento (con impuestos, post-descuentos) en moneda
   *  del documento. Passthrough del motor — el builder NO recalcula. */
  documentTotal:     number;
  /** Total final en moneda BASE del tenant. = `documentTotal × currency.rate`
   *  por construcción del motor; el caller lo provee igualmente para
   *  preservar redondeos del cierre del documento. */
  documentTotalBase: number;
  /** Moneda del documento.
   *  · `code` — code ISO ("ARS"/"USD"/etc).
   *  · `rate` — unidades de moneda BASE por 1 unidad de la moneda doc
   *    (1 si el documento está en moneda base). Coherente con
   *    `pricing-currency-display.ts`. */
  currency: { code: string; rate: number };
  /** Líneas del documento. Cada línea aporta gramos al metal padre y
   *  componentes monetarios opcionales. */
  lines: BuildBreakdownLineInput[];
  /** Componentes monetarios del documento (channel, coupon, paymentSurcharge,
   *  shipping, rounding doc-level). DISPLAY-ONLY: se acumulan en
   *  `monetary.components[]` para "Ver composición" pero no participan en
   *  el cálculo de `monetary.amount` (que sale de `documentTotal`). */
  documentMonetaryComponents?: DocumentBalanceMonetaryComponent[];
}

/** Línea del documento para alimentar el builder. */
export interface BuildBreakdownLineInput {
  /** ID de la línea (SaleLine.id / similar). Fuente para `sourceLineId`. */
  lineId:   string;
  /** Cantidad de la línea — multiplica gramos por unidad. */
  quantity: number;
  /** Metales presentes en la composición de costo de la línea. Una entrada
   *  por variante (el builder los agrupa por padre). Puede ser undefined si
   *  la línea no tiene metales (ej. solo hechura). */
  metals?: Array<{
    metalParentId:   string;
    metalParentName: string;
    metalVariantId:  string;
    metalVariantName: string;
    /** Gramos POR UNIDAD del cost (= `composition.metals[i].appliedGrams`).
     *  El builder multiplica internamente por `quantity`. NO afectado por
     *  manualPrice ni descuentos — son gramos físicos. */
    appliedGramsPerUnit: number;
    /** Pureza de la variante (0..1). `null` cuando snapshot legacy sin
     *  pureza explícita; el builder asume 1 (puro) para no perder gramos
     *  pero la variante queda con `purity = null` en el output. */
    purity:               number | null;
    /** Cotización del metal padre snapshot. DISPLAY-only: se usa para
     *  calcular `valuationMonetary` referencial. Si null, no se calcula
     *  valoración y `metalLineValuationDocCurrency` debería tampoco estar. */
    quotePriceSnapshot?:  number | null;
    /** Valorización del metal de esta línea en moneda del documento
     *  (= `composition.metals[i].lineSale × quantity` del motor). El
     *  builder lo resta del `documentTotal` para calcular `monetary.amount`
     *  (regla T16/T30 — "Hechura absorbe todo no-metal"). Si null o ausente,
     *  el monetary se setea = documentTotal (fallback legacy/UNIFIED-like). */
    metalLineValuationDocCurrency?: number | null;
  }>;
  /** Componentes monetarios de la línea (hechura/productos/services/tax/
   *  bonificación/recargo/etc.). DISPLAY-only: se acumulan en
   *  `monetary.components[]` para auditoría/UI; el saldo real sale de
   *  `documentTotal`. */
  monetaryComponents?: DocumentBalanceMonetaryComponent[];
}

/** Accumulator interno: agrega por metal padre antes de proyectar al shape
 *  canónico. */
interface MetalAccumulator {
  metalParentId:      string;
  metalParentName:    string;
  gramsOriginal:      number;
  gramsPure:          number;
  quotePriceSnapshot: number | null;
  variants:           DocumentBalanceMetalVariant[];
  sourceLineIds:      Set<string>;
}

/** Construye el `DocumentBalanceBreakdown` canónico desde el output del motor.
 *
 *  · `mode = "UNIFIED"`   → metals=[], monetary.amount = documentTotal.
 *  · `mode = "BREAKDOWN"` → agrupa metales por padre con pureza ponderada;
 *    monetary = documentTotal − Σ valuación metal.
 *
 *  Sin mutación del input. Determinístico. Cero matemática nueva — solo
 *  agrega bases que el motor ya emitió. */
export function buildDocumentBalanceBreakdown(
  input: BuildDocumentBalanceBreakdownInput,
  mode: BalanceMode,
): DocumentBalanceBreakdown {
  const currencyCode = input.currency.code;
  const currencyRate =
    Number.isFinite(input.currency.rate) && input.currency.rate > 0
      ? input.currency.rate
      : 1;

  // Componentes monetarios consolidados (line-level + document-level).
  const components = collectMonetaryComponents(input);

  // ── UNIFIED: un único saldo monetario; metals vacío ─────────────────────
  if (mode === "UNIFIED") {
    return {
      metals: [],
      monetaryBalance: {
        amount:       input.documentTotal,
        currencyCode,
        currencyRate,
        amountBase:   input.documentTotalBase,
        ...(components ? { components } : {}),
      },
    };
  }

  // ── BREAKDOWN: agrupar metales por padre, calcular pureza ponderada ────
  const accByParent = new Map<string, MetalAccumulator>();
  let totalMetalValuationDoc = 0;

  for (const line of input.lines) {
    if (!line.metals?.length) continue;
    const qty =
      Number.isFinite(line.quantity) && line.quantity > 0 ? line.quantity : 1;
    for (const m of line.metals) {
      const parentId = m.metalParentId;
      if (!parentId) continue;
      let acc = accByParent.get(parentId);
      if (!acc) {
        acc = {
          metalParentId:      parentId,
          metalParentName:    m.metalParentName,
          gramsOriginal:      0,
          gramsPure:          0,
          quotePriceSnapshot: m.quotePriceSnapshot ?? null,
          variants:           [],
          sourceLineIds:      new Set<string>(),
        };
        accByParent.set(parentId, acc);
      }
      // Conservar quotePrice si el accumulator no lo tenía aún.
      if (acc.quotePriceSnapshot == null && m.quotePriceSnapshot != null) {
        acc.quotePriceSnapshot = m.quotePriceSnapshot;
      }
      const gramsOriginalLine = m.appliedGramsPerUnit * qty;
      if (!Number.isFinite(gramsOriginalLine) || gramsOriginalLine <= 0) continue;
      // Pureza null → tratamos como puro (1) para no perder gramos, pero la
      // variante queda con `purity = null` en el output (transparencia).
      const purityForMath =
        m.purity != null && Number.isFinite(m.purity) ? m.purity : 1;
      const gramsPureLine = gramsOriginalLine * purityForMath;
      acc.gramsOriginal += gramsOriginalLine;
      acc.gramsPure     += gramsPureLine;
      acc.variants.push({
        variantId:     m.metalVariantId,
        variantName:   m.metalVariantName,
        gramsOriginal: gramsOriginalLine,
        purity:        m.purity != null ? m.purity : 1,
        gramsPure:     gramsPureLine,
        sourceLineId:  line.lineId,
      });
      acc.sourceLineIds.add(line.lineId);
      // Valuación monetaria del metal por línea (passthrough motor).
      if (
        m.metalLineValuationDocCurrency != null &&
        Number.isFinite(m.metalLineValuationDocCurrency)
      ) {
        totalMetalValuationDoc += m.metalLineValuationDocCurrency;
      }
    }
  }

  const metals: DocumentBalanceMetalEntry[] = Array.from(accByParent.values())
    .filter((acc) => acc.gramsOriginal > 1e-9 || acc.gramsPure > 1e-9)
    .map((acc) => {
      // Pureza ponderada (R11.x): Σ(g_i × p_i) / Σ g_i. null si Σ g_i = 0.
      const purityPonderada =
        acc.gramsOriginal > 1e-9 ? acc.gramsPure / acc.gramsOriginal : null;
      // Valorización referencial (display): gramsPure × quotePrice.
      const valuationMonetary =
        acc.quotePriceSnapshot != null && acc.gramsPure > 0
          ? acc.gramsPure * acc.quotePriceSnapshot
          : null;
      const entry: DocumentBalanceMetalEntry = {
        metalParentId:         acc.metalParentId,
        metalParentName:       acc.metalParentName,
        gramsOriginal:         acc.gramsOriginal,
        purity:                purityPonderada,
        gramsPure:             acc.gramsPure,
        quotePriceSnapshot:    acc.quotePriceSnapshot,
        valuationMonetary,
        valuationCurrencyCode: currencyCode,
        sourceLineIds:         Array.from(acc.sourceLineIds),
      };
      if (acc.variants.length > 0) {
        entry.variants = acc.variants;
      }
      return entry;
    })
    .sort((a, b) => a.metalParentName.localeCompare(b.metalParentName, "es"));

  // Saldo monetario = total − valuación metal (regla canónica T16/T30).
  // Si no hay valuaciones de metal (legacy o solo hechura), monetary = total.
  //
  // T58 (Etapa 4) — Se ACEPTAN negativos en BREAKDOWN. Hasta esta etapa el
  // motor clampeaba con `Math.max(0, ...)` para evitar saldos negativos, lo
  // que ocultaba dos casos comerciales legítimos:
  //   · descuentos / bonificaciones que superan la base monetaria
  //     (ej. hechura 10.000, bonificación −15.000 → saldo monetario −5.000)
  //   · créditos monetarios a favor del cliente (ej. devoluciones parciales,
  //     promos agresivas que dejan al cliente con saldo a favor en moneda
  //     aunque siga debiendo gramos).
  // POLICY.md §11 nunca prohibió negativos — el clamp era hardening
  // defensivo no documentado. El downstream (`CurrentAccountMovement`,
  // `EntityAccountStatement`) ya suma firmado y acepta `amount < 0`.
  // Los metales siguen como deuda separada; el negativo monetario NO
  // compensa gramos.
  const monetaryAmountDoc =
    totalMetalValuationDoc > 0.005
      ? input.documentTotal - totalMetalValuationDoc
      : input.documentTotal;
  // amountBase derivado por proporción exacta con el rate snapshot.
  // En documento BASE (rate=1) coincide con monetaryAmountDoc.
  const monetaryAmountBase =
    input.documentTotalBase - totalMetalValuationDoc * currencyRate;

  const monetary: DocumentBalanceMonetary = {
    amount:       monetaryAmountDoc,
    currencyCode,
    currencyRate,
    amountBase:   monetaryAmountBase,
    ...(components ? { components } : {}),
  };

  return { metals, monetaryBalance: monetary };
}

/** Junta componentes monetarios de líneas + documento. DISPLAY-only. */
function collectMonetaryComponents(
  input: BuildDocumentBalanceBreakdownInput,
): DocumentBalanceMonetaryComponent[] | undefined {
  const out: DocumentBalanceMonetaryComponent[] = [];
  for (const line of input.lines) {
    if (!line.monetaryComponents?.length) continue;
    for (const c of line.monetaryComponents) {
      // Si el componente no trae `sourceLineId`, lo enriquecemos con la
      // línea propietaria — preserva trazabilidad sin modificar el input.
      out.push(c.sourceLineId ? c : { ...c, sourceLineId: line.lineId });
    }
  }
  if (input.documentMonetaryComponents?.length) {
    for (const c of input.documentMonetaryComponents) {
      out.push(c);
    }
  }
  return out.length > 0 ? out : undefined;
}

// =============================================================================
// T53 (Fase 3B.3) — readBalanceBreakdown
//
// Helper de LECTURA TOLERANTE para snapshots de documento. Convierte cualquier
// snapshot (v3 con balanceBreakdown nativo, v2/legacy, parcial o inválido) en
// un `DocumentBalanceBreakdown` consumible por la UI / cuenta corriente.
//
// Reglas (POLICY.md §11):
//   · v3 con `balanceBreakdown` válido → devolverlo tal cual.
//   · v2/legacy o `balanceBreakdown` ausente/inválido → UNIFIED IMPLÍCITO:
//       - metals = []
//       - monetary.amount = snapshot.totals.total
//       - currencyCode / currencyRate / amountBase desde el snapshot.
//     Nunca se intenta reconstruir metales desde snapshots viejos — los
//     históricos quedan UNIFIED por diseño.
//   · Snapshot null / undefined / shape inesperado → UNIFIED VACÍO (0, "").
//   · Función NUNCA tira. Nunca muta el snapshot.
// =============================================================================

/** De dónde salió el breakdown devuelto por `readBalanceBreakdown`:
 *   · `SNAPSHOT_V3`     — snapshot v3 con `balanceBreakdown` nativo válido.
 *   · `LEGACY_UNIFIED`  — snapshot v1/v2 sin breakdown; UNIFIED implícito
 *                         derivado de `totals.total`.
 *   · `INVALID`         — input ausente / no-objeto. Devuelve UNIFIED vacío. */
export type BalanceBreakdownReadSource =
  | "SNAPSHOT_V3"
  | "LEGACY_UNIFIED"
  | "INVALID";

export interface BalanceBreakdownReadResult {
  /** Breakdown listo para consumir. Siempre presente. */
  breakdown: DocumentBalanceBreakdown;
  /** Auditoría: explica de dónde salió el breakdown. */
  source:    BalanceBreakdownReadSource;
}

/** Identifica si un valor parece un `DocumentBalanceBreakdown` consumible.
 *  Defensivo contra snapshots corruptos / parciales. */
function isValidBalanceBreakdown(v: unknown): v is DocumentBalanceBreakdown {
  if (!v || typeof v !== "object") return false;
  const obj = v as Record<string, unknown>;
  if (!Array.isArray(obj.metals)) return false;
  const m = obj.monetaryBalance;
  if (!m || typeof m !== "object") return false;
  const mb = m as Record<string, unknown>;
  return typeof mb.amount === "number";
}

/** Lectura tolerante del breakdown de un snapshot histórico o vigente.
 *  Nunca tira. Nunca muta. Devuelve siempre un breakdown consumible más
 *  metadata de origen para auditoría. */
export function readBalanceBreakdown(snapshot: unknown): BalanceBreakdownReadResult {
  // ── 1) snapshot ausente / no-objeto → UNIFIED vacío + INVALID ───────────
  if (!snapshot || typeof snapshot !== "object") {
    return {
      breakdown: {
        metals: [],
        monetaryBalance: {
          amount:       0,
          currencyCode: "",
          currencyRate: 1,
          amountBase:   0,
        },
      },
      source: "INVALID",
    };
  }
  const snap = snapshot as Record<string, unknown>;
  const version =
    typeof snap.version === "number" && Number.isFinite(snap.version)
      ? snap.version
      : 0;

  // ── 2) v3+ con breakdown válido → passthrough ────────────────────────────
  if (version >= 3 && isValidBalanceBreakdown(snap.balanceBreakdown)) {
    return { breakdown: snap.balanceBreakdown, source: "SNAPSHOT_V3" };
  }

  // ── 3) v2/legacy/parcial → UNIFIED implícito desde totals ────────────────
  const totals = (snap.totals && typeof snap.totals === "object")
    ? (snap.totals as Record<string, unknown>)
    : null;
  const currency = (snap.currency && typeof snap.currency === "object")
    ? (snap.currency as Record<string, unknown>)
    : null;

  const total = typeof totals?.total === "number" && Number.isFinite(totals.total)
    ? (totals.total as number)
    : 0;
  const totalBase =
    typeof totals?.totalBase === "number" && Number.isFinite(totals.totalBase)
      ? (totals.totalBase as number)
      : total;
  const currencyCode =
    typeof currency?.currencyCode === "string"
      ? (currency.currencyCode as string)
      : "";
  const currencyRate =
    typeof currency?.currencyRate === "number" &&
    Number.isFinite(currency.currencyRate) &&
    (currency.currencyRate as number) > 0
      ? (currency.currencyRate as number)
      : 1;

  return {
    breakdown: {
      metals: [],
      monetaryBalance: {
        amount:       total,
        currencyCode,
        currencyRate,
        amountBase:   totalBase,
      },
    },
    source: "LEGACY_UNIFIED",
  };
}

// =============================================================================
// T55 (Fase 3B.5) — mapBalanceTypeToMode
//
// Helper de COMPATIBILIDAD para el campo legacy `CommercialEntity.balanceType`
// (enum `BalanceType` con valores UNIFIED/BREAKDOWN, pre-POLICY.md §11). El
// runtime de 3B.5 lee primero el nuevo `CommercialEntity.balanceMode` (enum
// canónico `BalanceMode`); si está null, cae a `balanceType` mapeado vía este
// helper.
//
//   entityDefault =
//     commercialEntity.balanceMode
//     ?? mapBalanceTypeToMode(commercialEntity.balanceType)
//     ?? null
//
// Reglas:
//   · "UNIFIED" / "BREAKDOWN" pasan tal cual al `BalanceMode` canónico.
//   · null / undefined / cualquier otro valor → null (no traduce ni inventa).
//   · El campo legacy NO se elimina en 3B.5 — sigue presente y operativo
//     para otras vistas. Sub-fase 3B.7+ decidirá la deprecación.
// =============================================================================

/**
 * Traduce el enum legacy `BalanceType` (CommercialEntity.balanceType) al
 * enum canónico `BalanceMode`. Devuelve `null` cuando el input no es
 * reconocible o es null/undefined — el caller debe seguir con el siguiente
 * nivel de la prioridad R11.4.
 *
 * @deprecated Fase 3B.8 — `CommercialEntity.balanceType` queda como campo
 * legacy. Toda escritura nueva debe usar el campo canónico
 * `CommercialEntity.balanceMode`. Este helper se mantiene EXCLUSIVAMENTE
 * para back-compat de filas históricas que aún no migraron a
 * `balanceMode`. No usar en flujos nuevos: el resolver
 * (`resolveSaleBalanceMode`) ya lo invoca internamente como último
 * fallback antes de bajar a `priceListDefault`/`tenantDefault`.
 *
 * TODO(balance-mode-cleanup-fase-3C+): migrar todas las filas de
 * `CommercialEntity` que aún tienen `balanceType` distinto del default
 * UNIFIED y `balanceMode = null` → seteando `balanceMode` con el valor
 * mapeado; después eliminar `balanceType` del schema y este helper. */
export function mapBalanceTypeToMode(
  balanceType: string | null | undefined,
): BalanceMode | null {
  if (balanceType === "UNIFIED" || balanceType === "BREAKDOWN") {
    return balanceType;
  }
  return null;
}
