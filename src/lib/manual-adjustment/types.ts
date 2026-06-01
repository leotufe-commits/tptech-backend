// src/lib/manual-adjustment/types.ts
// =============================================================================
// Manual Adjustment — Etapa A (UNIFIED) + Etapa C (BREAKDOWN, solo manual).
//
// Override comercial humano sobre el `engineTotal` del documento (capa 17 del
// pipeline, POLICY §R-Rounding-1). NO modifica pricing-engine, NO recalcula
// impuestos, NO toca costos. Es un ajuste financiero/comercial puro.
//
// ── Definición canónica (POLICY §R-Rounding-1 / §11) ───────────────────────
//
// Etapa A — scope=UNIFIED:
//   Aplica sobre el TOTAL UNIFICADO del comprobante. Un único monto humano
//   global. No distingue metales / hechura.
//
// Etapa C — scope=BREAKDOWN (solo MANUAL):
//   Aplica sobre el SALDO DESGLOSADO del comprobante. El operador ajusta
//   por separado:
//     a) Cada metal padre en GRAMOS (targetGrams o deltaGrams).
//     b) La hechura / saldo monetario en DINERO (monetaryAmount).
//
//   En modo BREAKDOWN, "hechura / saldo monetario" abarca TODO lo que NO
//   es metal padre del documento:
//     hechura física, productos, servicios, impuestos, envío, descuentos,
//     cupones, canal de venta, forma de pago, redondeos monetarios,
//     ajustes monetarios manuales.
//
//   Solo se permite scope=BREAKDOWN cuando el documento opera en modo
//   BREAKDOWN (`balanceMode === "BREAKDOWN"`).
//
// ── Principio "no mezclar" (regla obligatoria) ─────────────────────────────
//
//   · Los ajustes en gramos SOLO afectan al metal padre correspondiente.
//   · Los ajustes monetarios SOLO afectan al bucket de hechura/saldo.
//   · Nunca se mezcla ajuste monetario dentro de gramos ni viceversa.
//
// ── Equivalencia monetaria de ajustes en metales padre (regla crítica) ─────
//
// Todo ajuste sobre un metal padre en modo BREAKDOWN impacta también
// monetariamente el comprobante — EXACTAMENTE igual que el redondeo
// BREAKDOWN. La equivalencia es CONSOLIDACIÓN FINANCIERA, no reasignación.
//
// Ejemplo:
//   · Oro 0,908 g → operador ajusta a 1,000 g.
//   · Delta físico: +0,092 g → vive en el metal padre "oro-fino".
//   · metalPricePerGram: 100.000.
//   · monetaryEquivalent: 9.200 → consolida Sale.total + totalMonetaryAdjustment.
//
// El monetaryEquivalent:
//   · SÍ impacta Sale.total, totals.totalMonetaryAdjustment,
//     totals.metalMonetaryEquivalent y displays.
//   · NO mueve el valor a breakdown.monetary.amount (hechura).
//   · NO convierte el ajuste físico en "ajuste monetario de hechura".
//   · NO mezcla dominios — el ajuste físico sigue perteneciendo al metal.
//
// Resultado: BREAKDOWN tiene dos dominios PARALELOS:
//   A. METAL — gramos físicos + monetaryEquivalent del delta.
//   B. HECHURA / SALDO MONETARIO — bucket no-metal único.
// Y solo se suman en `totalMonetaryAdjustment` = consolidado financiero.
//
// ── Etapas NO implementadas todavía ────────────────────────────────────────
//   · Redondeo físico AUTOMÁTICO de gramos (lista o comprobante). Ver
//     POLICY §R-Rounding-13.
//   · AccountMovementMetalEntry por delta de gramos en cuenta corriente
//     metálica. Hoy `Sale.total` refleja el equivalente monetario completo
//     del ajuste BREAKDOWN; las entries físicas por metal quedan pendientes.
//     Ver §Etapa C en POLICY.md / CLAUDE.md raíz.
// =============================================================================

/** Scope del ajuste. Etapa A: UNIFIED. Etapa C: BREAKDOWN. */
export type ManualAdjustmentScope = "UNIFIED" | "BREAKDOWN";

// ──────────────────────────────────────────────────────────────────────────
// INPUT — lo que tipea el operador en el frontend.
// ──────────────────────────────────────────────────────────────────────────

/** Input UNIFIED (Etapa A). Un único monto sobre el `engineTotal`. */
export interface ManualAdjustmentInputUnified {
  scope:  "UNIFIED";
  amount: number;
  /** Motivo libre, opcional. */
  reason?: string | null;
}

/** Entrada por metal padre del input BREAKDOWN.
 *
 *  Reglas:
 *    · `targetGrams` PISA `deltaGrams` cuando viene definido y finito.
 *    · `deltaGrams` se aplica sobre los gramos pre del balance del documento.
 *    · Sin `targetGrams` ni `deltaGrams` significativos → la entry se
 *      considera "sin ajuste" (el sanitizer la descarta).
 *    · `metalParentId === null` matchea metales sin id (legacy / consolidado
 *      por nombre). El sanitizer respeta el caller (no inventa ids).
 */
export interface ManualAdjustmentMetalInput {
  metalParentId:   string | null;
  metalParentName?: string;
  targetGrams?: number | null;
  deltaGrams?:  number | null;
  reason?:      string | null;
}

/** Input BREAKDOWN (Etapa C). Ajuste por metal padre en gramos + ajuste
 *  monetario sobre el bucket hechura/saldo. Solo aplica si el documento
 *  opera en modo BREAKDOWN. */
export interface ManualAdjustmentInputBreakdown {
  scope: "BREAKDOWN";
  /** Lista de ajustes en GRAMOS por metal padre. Solo entries con delta
   *  significativo sobreviven al sanitizer. Puede ser `[]` si solo se
   *  ajusta el bucket monetario.
   *
   *  Cada ajuste vive en su metal padre — NO contamina hechura ni otros
   *  metales. */
  metals?:        ManualAdjustmentMetalInput[];
  /** Ajuste monetario directo sobre el BUCKET HECHURA / SALDO MONETARIO.
   *
   *  En modo BREAKDOWN este bucket abarca TODO lo no-metal-padre:
   *  hechura física + productos + servicios + impuestos + envío +
   *  descuentos + cupones + canal + forma de pago + redondeos +
   *  ajustes monetarios.
   *
   *  El delta NO contamina los gramos. */
  monetaryAmount?: number | null;
  /** Motivo global del ajuste (opcional). */
  reason?: string | null;
}

/** Unión expuesta al resto del backend. */
export type ManualAdjustmentInput =
  | ManualAdjustmentInputUnified
  | ManualAdjustmentInputBreakdown;

// ──────────────────────────────────────────────────────────────────────────
// AUDIT — info de quién/cuándo/por qué (compartido UNIFIED / BREAKDOWN).
// ──────────────────────────────────────────────────────────────────────────

export interface ManualAdjustmentAudit {
  appliedBy: { userId: string; userName: string } | null;
  appliedAt: string; // ISO 8601
  reason?:   string | null;
}

// ──────────────────────────────────────────────────────────────────────────
// SNAPSHOT — congelado al confirmar; pasa por preview también.
// ──────────────────────────────────────────────────────────────────────────

/** Capa UNIFIED del snapshot — Etapa A. */
export interface ManualAdjustmentSnapshotUnifiedLayer {
  /** Monto pre-ajuste = engineTotal (lo que el motor calculó). */
  preAmount:  number;
  /** Monto post-ajuste = engineTotal + amount efectivo. Clamp ≥ 0. */
  postAmount: number;
  /** Delta efectivo que movió el operador. Puede ser negativo. */
  amount:     number;
}

/** Entrada por metal del snapshot BREAKDOWN — Etapa C.
 *
 *  El ajuste físico (gramos) vive en este entry — pertenece al metal padre
 *  para siempre. Su `monetaryEquivalent` es la CONSOLIDACIÓN FINANCIERA
 *  que impacta `Sale.total` (vía `totals.metalMonetaryEquivalent` y
 *  `totals.totalMonetaryAdjustment`), exactamente igual que el redondeo
 *  BREAKDOWN — sin mover el valor a `breakdown.monetary.amount`. */
export interface ManualAdjustmentSnapshotMetalEntry {
  metalParentId:      string | null;
  metalParentName:    string;
  /** Gramos pre-ajuste tomados del balance del documento. */
  preGrams:           number;
  /** Gramos post-ajuste = target o pre+delta. NUNCA negativo (clamp 0). */
  postGrams:          number;
  /** Delta efectivo en gramos. Puede ser negativo. El ajuste físico
   *  pertenece al metal padre — auditoría + cuenta corriente metálica
   *  futura. */
  deltaGrams:         number;
  /** Cotización por gramo usada para el equivalente monetario.
   *  `null` cuando el metal no tenía cotización vigente (no se puede
   *  estimar el equivalente — se persiste como 0 con cotización 0). */
  metalPricePerGram:  number;
  /** Equivalente monetario del delta físico de gramos
   *  = `deltaGrams × metalPricePerGram` (round2).
   *
   *  Consolidación financiera — paralelo al redondeo BREAKDOWN. Impacta:
   *    · `Sale.total`
   *    · `totals.metalMonetaryEquivalent`
   *    · `totals.totalMonetaryAdjustment`
   *    · displays del frontend.
   *
   *  NO se mueve a `breakdown.monetary.amount`. NO contamina los gramos
   *  del metal padre. NO convierte el ajuste físico en "ajuste monetario
   *  de hechura". El ajuste físico sigue siendo del metal. */
  monetaryEquivalent: number;
}

/** Capa monetaria (BUCKET hechura / saldo monetario) del snapshot BREAKDOWN.
 *
 *  Representa el saldo monetario CONSOLIDADO del documento — todo lo que
 *  NO es metal padre (POLICY §11 R11.2 / §R-Rounding-1). El delta del
 *  operador (`amount`) NUNCA contamina los gramos: vive exclusivamente
 *  en este bucket monetario. */
export interface ManualAdjustmentSnapshotMonetaryLayer {
  /** Saldo monetario pre-ajuste manual. Es Σ de hechura física +
   *  productos + servicios + impuestos + envío + descuentos + cupones +
   *  canal + forma de pago + redondeos monetarios. */
  preAmount:  number;
  /** Delta monetario humano aplicado sobre el bucket hechura/saldo.
   *  Puede ser negativo. Recortado si el clamp ≥ 0 lo requiere. */
  amount:     number;
  /** Saldo monetario post-ajuste = preAmount + amount. */
  postAmount: number;
}

/** Snapshot UNIFIED (Etapa A) — congela el monto humano. */
export interface ManualAdjustmentSnapshotUnified {
  scope: "UNIFIED";
  unified: ManualAdjustmentSnapshotUnifiedLayer;
  /** Capa BREAKDOWN inexistente en UNIFIED — se omite (undefined). */
  breakdown?: undefined;
  totals: ManualAdjustmentSnapshotTotals;
  audit: ManualAdjustmentAudit;
}

/** Snapshot BREAKDOWN (Etapa C) — congela ajustes por metal + hechura. */
export interface ManualAdjustmentSnapshotBreakdown {
  scope: "BREAKDOWN";
  /** Capa UNIFIED inexistente en BREAKDOWN. */
  unified?: undefined;
  breakdown: {
    metals:   ManualAdjustmentSnapshotMetalEntry[];
    monetary: ManualAdjustmentSnapshotMonetaryLayer;
  };
  totals: ManualAdjustmentSnapshotTotals;
  audit: ManualAdjustmentAudit;
}

/** Totales sintetizados — contrato UNIVERSAL (UNIFIED y BREAKDOWN).
 *
 *  Cada campo representa un dominio bien separado del ajuste humano:
 *
 *  · `monetaryAdjustment` = ajuste monetario DIRECTO del BUCKET HECHURA /
 *    SALDO MONETARIO (todo lo no-metal-padre del documento).
 *      UNIFIED   → `unified.amount` (no hay separación; es el ajuste global).
 *      BREAKDOWN → `breakdown.monetary.amount` (solo el delta de hechura/saldo).
 *
 *  · `metalMonetaryEquivalent` = Σ EQUIVALENTES MONETARIOS de los deltas de
 *    gramos por metal padre. El ajuste físico vive en el metal padre; este
 *    campo solo lleva su valuación al momento del ajuste para consolidar
 *    `Sale.total` y auditoría.
 *      UNIFIED   → `0` (no se ajustan gramos en UNIFIED).
 *      BREAKDOWN → `Σ breakdown.metals[].monetaryEquivalent`.
 *
 *  · `totalMonetaryAdjustment` = `monetaryAdjustment + metalMonetaryEquivalent`.
 *    Es lo que `confirmSale` suma a `engineTotal` para producir `Sale.total`
 *    (con clamp ≥ 0).
 *
 *  Contrato (rige siempre):
 *      `Sale.total = max(0, Sale.engineTotal + totals.totalMonetaryAdjustment)`
 *
 *  Principio "no mezclar" (POLICY §R-Rounding-1):
 *    `monetaryAdjustment` y `metalMonetaryEquivalent` son DOMINIOS DISJUNTOS.
 *    Sumarlos solo es legítimo en `totalMonetaryAdjustment`, que es un
 *    consolidado financiero, NUNCA una pieza usada por el motor de precios. */
export interface ManualAdjustmentSnapshotTotals {
  monetaryAdjustment:      number;
  metalMonetaryEquivalent: number;
  totalMonetaryAdjustment: number;
}

/** Unión del snapshot — expuesta al resto del backend. */
export type ManualAdjustmentSnapshot =
  | ManualAdjustmentSnapshotUnified
  | ManualAdjustmentSnapshotBreakdown;

// ──────────────────────────────────────────────────────────────────────────
// CONTEXTO — datos del balance del documento que el helper necesita SOLO
// para BREAKDOWN. Función pura: el caller los inyecta.
// ──────────────────────────────────────────────────────────────────────────

/** Item de metal del documento usado como referencia para el ajuste. */
export interface ManualAdjustmentMetalContextItem {
  metalParentId:     string | null;
  metalParentName:   string;
  /** Gramos pre del balance (lado venta). Es el `gramsPure` consolidado. */
  gramsPure:         number;
  /** Cotización por gramo vigente para el delta monetario.
   *  `null` cuando el motor no la expuso (delta monetario quedará en 0). */
  metalPricePerGram: number | null;
}

/** Contexto BREAKDOWN. Solo requerido cuando el input lleva scope BREAKDOWN. */
export interface ManualAdjustmentBreakdownContext {
  /** Saldo monetario (hechura + ajustes mon) pre-ajuste manual.
   *  Tomado de `balanceBreakdown.monetaryBalance.amount`. */
  monetaryHechura: { preAmount: number };
  /** Lista de metales del documento (orden estable por metalParentId/nombre). */
  metals:          ManualAdjustmentMetalContextItem[];
}

// ──────────────────────────────────────────────────────────────────────────
// PREVIEW — bloque agregado al `SalePreviewResult`. Passthrough exacto al
// frontend, cero matemática local.
// ──────────────────────────────────────────────────────────────────────────

export interface ManualAdjustmentPreview {
  snapshot:    ManualAdjustmentSnapshot | null;
  engineTotal: number;
  /** Total final pagable = engineTotal + totals.totalMonetaryAdjustment (clamp ≥ 0). */
  finalTotal:  number;
}
