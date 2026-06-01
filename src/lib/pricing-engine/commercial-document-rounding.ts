// src/lib/pricing-engine/commercial-document-rounding.ts
// =============================================================================
// Redondeo Comercial PER_DOCUMENT (Etapa D' canónica — POLICY §R-Rounding-15).
//
// Helper PURO — sin DB, sin async, sin imports de Prisma. Determinístico:
// mismo input → mismo output. Imprescindible para preview/confirm parity.
//
// ── Posición en el pipeline ──────────────────────────────────────────────────
//
// Esta capa corre DESPUÉS de impuestos (con §Tax.4 aplicado) y ANTES de
// envío / forma de pago / redondeo financiero / ajuste manual:
//
//   ... → Canal → Cupón → Bonif. Global → Taxable Base → Impuestos
//      → [🆕 REDONDEO COMERCIAL PER_DOCUMENT] ← acá
//      → Envío → Forma de Pago
//      → Redondeo Financiero (intacto)
//      → Ajuste Manual (intacto)
//
// ── Contrato canónico (POLICY §R-Rounding-14) ───────────────────────────────
//
// UNIFIED:
//   Un único redondeo sobre el total monetario comercial post-tax
//   (= `taxableBase + tax`). Sin distinguir metal vs hechura.
//
// BREAKDOWN:
//   Dos dominios DISJUNTOS:
//     a) METAL FÍSICO  → redondea gramos por metal padre (PER_DOCUMENT,
//        Σ líneas gramsPure × qty). El delta monetario equivalente
//        (`deltaGrams × metalPricePerGram`) impacta `Sale.total`.
//     b) HECHURA / SALDO MONETARIO  → redondea el residuo monetario:
//          saldoMonetario = totalComercialPostTax − metalValuationSum
//        El delta impacta `Sale.total` directo.
//
//   El redondeo físico de gramos NO altera el saldo monetario: cambia tanto
//   el total comercial como la valorización física en la misma magnitud, y
//   esos dos términos se cancelan en `saldo = total − valorización`.
//
// ── Salida (Sale.commercialDocumentRoundingSnapshot) ────────────────────────
//
//   {
//     source: "PRICE_LIST",
//     scope:  "UNIFIED" | "BREAKDOWN",
//     totalAdjustment: number,            // delta a sumar a totalComercial
//     unified?: { pre, post, adjustment, mode, direction },
//     breakdown?: {
//       metals: [{ metalParentId, metalParentName,
//                  preGrams, postGrams, deltaGrams,
//                  metalPricePerGram, monetaryEquivalent, mode, direction }],
//       metalMonetaryEquivalent: number,
//       hechura: {
//         preRoundingSaldoMonetario, postRoundingSaldoMonetario,
//         deltaSaldoMonetario, mode, direction, source: "PRICE_LIST_HECHURA",
//       },
//       combinedAdjustment: number,
//     },
//     fallback?: "ALL_NONE" | "NO_METALS_BREAKDOWN_DATA" | "NO_SHARED_LIST",
//   }
//
// `fallback = "NO_SHARED_LIST"` lo emite el CALLER (sales.service) cuando las
// líneas no comparten una sola lista — no se ejecuta el helper, se persiste
// el snapshot con ese fallback para diagnóstico.
//
// ── Anti-doble redondeo ──────────────────────────────────────────────────────
//
// El caller es responsable de:
//   1. Suprimir el PER_LINE legacy de hechura (`applyPriceList` línea 442) y
//      el metal físico PER_UNIT cuando la lista tiene
//      `commercialRoundingScope === "PER_DOCUMENT"`.
//   2. Coordinar con el redondeo financiero (capa siguiente): si financiero
//      scope=BREAKDOWN sobre hechura monetaria, el caller suprime esa parte
//      del financiero (decisión D4) — el comercial gana por ser más específico.
//
// =============================================================================

// Modos y direcciones del redondeo — espejo de pricing-engine.pricelist.applyRounding
// pero numéricos puros (sin Prisma.Decimal) para mantener este módulo aislado.
export type CommercialDocRoundingMode =
  | "NONE" | "INTEGER" | "DECIMAL_1" | "DECIMAL_2" | "TEN" | "HUNDRED";

export type CommercialDocRoundingDirection = "NEAREST" | "UP" | "DOWN";

export interface CommercialDocRoundingPartConfig {
  mode:      CommercialDocRoundingMode;
  direction: CommercialDocRoundingDirection;
}

export interface CommercialDocRoundingInputUnified {
  scope:     "UNIFIED";
  mode:      CommercialDocRoundingMode;
  direction: CommercialDocRoundingDirection;
}

export interface CommercialDocRoundingInputBreakdown {
  scope:   "BREAKDOWN";
  /** Config para gramos físicos por metal padre. NONE = no redondear metal. */
  metal:   CommercialDocRoundingPartConfig;
  /** Config para el saldo monetario residual. NONE = no redondear hechura. */
  hechura: CommercialDocRoundingPartConfig;
}

export type CommercialDocRoundingInput =
  | CommercialDocRoundingInputUnified
  | CommercialDocRoundingInputBreakdown;

/** Entrada de un metal padre AGREGADO a nivel documento. */
export interface CommercialDocMetalParentInput {
  metalParentId:     string;
  metalParentName:   string;
  /** Σ líneas (gramsPure × qty) — gramos puros agregados a nivel documento. */
  gramsPure:         number;
  /** Cotización por gramo (del balance del tenant). */
  metalPricePerGram: number;
  /** Valor de referencia del metal padre (`Metal.referenceValue`) = precio por
   *  gramo COMERCIAL equivalente (con el que `gramsSale × refValue = metalSale`).
   *  Se usa para el redondeo comercial CON MARGEN: el impacto monetario del
   *  redondeo de gramos comerciales = `deltaGramsSale × refValue`. Si falta,
   *  fallback a `metalPricePerGram` (físico, back-compat). */
  metalReferenceValue?: number;
}

export interface CommercialDocRoundingArgs {
  /** Total monetario comercial post-tax = `taxableBase + tax`. Ya con
   *  §Tax.4 aplicado por el caller. */
  totalComercialPostTax: number;
  /** Σ líneas Σ (gramsPure × quotePrice) = valoración FÍSICA del metal (sin
   *  margen). Ya NO se usa para el saldo comercial (contrato canónico
   *  `CLAUDE.md`: el saldo comercial es `total − Σ metalSale`, no
   *  `total − valoración física`). Se conserva por back-compat de la firma
   *  (y por si algún consumer lo lee); el saldo lo deriva `metalSaleSum`. */
  metalValuationSum:     number;
  /** Σ líneas metalSale = METAL COMERCIAL (con margen) agregado a nivel
   *  documento. Es la base del SALDO comercial DESGLOSADO:
   *    saldoMonetario = totalComercialPostTax − metalSaleSum
   *  (contrato canónico — composición de VENTA, no valoración física). Solo
   *  en BREAKDOWN. Si no se provee, fallback a `metalValuationSum` (legacy). */
  metalSaleSum?:         number;
  /** Factor de margen comercial del metal (= Σ metalSale / Σ metalCost). Se usa
   *  SOLO para `breakdown.metalsPostGrams` (display): el redondeo físico COMERCIAL
   *  de los gramos incluye el margen → `gramsSale = gramsPure × marginFactor` y
   *  `postGrams = round(gramsSale)`. NO afecta el saldo monetario ni los totales
   *  (que siguen derivando de `metalSaleSum`/`metalValuationSum`). Default 1
   *  (sin margen) para back-compat. */
  metalCommercialMarginFactor?: number;
  /** Metales agregados a nivel documento (por padre). Solo en BREAKDOWN. */
  metalsByParent?:       CommercialDocMetalParentInput[];
  /** Configuración del redondeo. */
  config:                CommercialDocRoundingInput;
}

// ── Output ──────────────────────────────────────────────────────────────────

export interface CommercialDocMetalSnapshotEntry {
  metalParentId:      string;
  metalParentName:    string;
  preGrams:           number;
  postGrams:          number;
  deltaGrams:         number;
  metalPricePerGram:  number;
  monetaryEquivalent: number;
  /** Importe monetario PRE redondeo físico (= preGrams × metalPricePerGram).
   *  Opcional para back-compat con snapshots históricos persistidos antes de
   *  su introducción. Invariante: `postAmount = preAmount + monetaryEquivalent`. */
  preAmount?:         number;
  /** Importe monetario POST redondeo físico (= postGrams × metalPricePerGram).
   *  Opcional para back-compat con snapshots históricos persistidos antes de
   *  su introducción. Invariante: `postAmount = preAmount + monetaryEquivalent`. */
  postAmount?:        number;
  mode:               CommercialDocRoundingMode;
  direction:          CommercialDocRoundingDirection;
}

export interface CommercialDocHechuraSnapshot {
  preRoundingSaldoMonetario:  number;
  postRoundingSaldoMonetario: number;
  deltaSaldoMonetario:        number;
  mode:                       CommercialDocRoundingMode;
  direction:                  CommercialDocRoundingDirection;
  source:                     "PRICE_LIST_HECHURA";
}

export interface CommercialDocUnifiedSnapshot {
  pre:        number;
  post:       number;
  adjustment: number;
  mode:       CommercialDocRoundingMode;
  direction:  CommercialDocRoundingDirection;
}

export type CommercialDocRoundingFallback =
  | "ALL_NONE"
  | "NO_METALS_BREAKDOWN_DATA"
  | "NO_SHARED_LIST";

/**
 * Indica DÓNDE se aplicó el redondeo comercial.
 *   · `"LINE"`     — comportamiento histórico PER_LINE (dentro de
 *     `applyPriceList`, snapshot vive en `metalHechuraBreakdown` por línea).
 *     Este helper NO lo emite.
 *   · `"DOCUMENT"` — comportamiento canónico Etapa D' (capa nueva en
 *     `computeSaleDocumentTotals` agregando el saldo del documento). Este
 *     helper SIEMPRE lo emite con este valor cuando actúa.
 */
export type CommercialRoundingAppliedAt = "LINE" | "DOCUMENT";

export interface CommercialDocRoundingApplied {
  source:  "PRICE_LIST";
  scope:   "UNIFIED" | "BREAKDOWN";
  /** Etapa D' — Dónde se aplicó el redondeo. Este helper SIEMPRE emite
   *  `"DOCUMENT"` cuando actúa (es la capa PER_DOCUMENT). El PER_LINE
   *  legacy vive en otro snapshot y no usa este tipo. */
  appliedAt?: CommercialRoundingAppliedAt;
  /** Delta total a sumar al total comercial (post-tax) para obtener el total
   *  post-comercial. En UNIFIED == `unified.adjustment`. En BREAKDOWN ==
   *  `metalMonetaryEquivalent + hechura.deltaSaldoMonetario`. */
  totalAdjustment: number;
  unified?:   CommercialDocUnifiedSnapshot;
  breakdown?: {
    metals:                  CommercialDocMetalSnapshotEntry[];
    metalMonetaryEquivalent: number;
    hechura:                 CommercialDocHechuraSnapshot;
    combinedAdjustment:      number;
    /** Opción PURE (consistencia visual) — gramos físicos POST-redondeo de
     *  TODOS los metales padre, INCLUSO los que no redondearon (deltaGrams=0).
     *  `metals` (arriba) sigue conteniendo SOLO los que movieron (delta≠0) —
     *  esa es la fuente del footer y de los equivalentes monetarios, NO se
     *  altera. Este campo es SOLO display: el frontend lo usa para mostrar
     *  SIEMPRE `postGrams` (gramos puros redondeados) en todos los metales,
     *  sin alternar con los gramos de venta (con margen). */
    metalsPostGrams?: {
      metalParentId:   string;
      metalParentName: string;
      preGrams:        number;
      postGrams:       number;
    }[];
  };
  fallback?: CommercialDocRoundingFallback | null;
}

/**
 * Alias canónico (post-Etapa D' cierre conceptual). El nombre `CommercialDoc…`
 * conservaba el infijo `Doc` por motivos históricos (refleja que la mecánica
 * es PER_DOCUMENT). Conceptualmente el redondeo es **comercial** — pertenece
 * a la construcción del precio comercial (puede aplicarse PER_LINE o
 * PER_DOCUMENT según la config de la lista).
 *
 * Nuevos consumers deben usar `CommercialRoundingApplied`. El alias original
 * (`CommercialDocRoundingApplied`) se mantiene como back-compat.
 */
export type CommercialRoundingApplied = CommercialDocRoundingApplied;

export interface CommercialDocRoundingResult {
  /** `null` si la capa no actuó (todos NONE + delta 0). Snapshot canónico
   *  cuando actuó O cuando hay fallback que reportar. */
  applied:             CommercialDocRoundingApplied | null;
  /** `totalComercialPostTax + (applied?.totalAdjustment ?? 0)`. */
  totalPostCommercial: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Implementación
// ─────────────────────────────────────────────────────────────────────────────

const EPS_MONEY = 0.005;
const EPS_GRAMS = 1e-9;

const round2      = (n: number): number => Math.round(n * 100)   / 100;
const round4Grams = (n: number): number => Math.round(n * 10000) / 10000;

/**
 * Aplica el redondeo comercial PER_DOCUMENT sobre el total comercial post-tax.
 * Helper PURO — sin DB, sin async, sin Prisma.
 *
 * Casos en los que devuelve `applied: null` (no hubo capa efectiva):
 *   · UNIFIED con `mode = NONE`.
 *   · BREAKDOWN con metal=NONE y hechura=NONE.
 *   · Cualquier scope donde el delta total da exactamente 0.
 *
 * Casos en los que devuelve `applied != null` con `totalAdjustment = 0`:
 *   · Solo cuando hay un `fallback` que reportar (ej. ALL_NONE explícito o
 *     NO_METALS_BREAKDOWN_DATA). Útil para diagnóstico aunque no hubo movimiento.
 *
 * Casos en los que el caller debe emitir `fallback = NO_SHARED_LIST`:
 *   · Mixed-list (líneas con distintas listas). El caller no llama este
 *     helper y persiste manualmente el snapshot con ese fallback.
 */
export function applyCommercialDocumentRounding(
  args: CommercialDocRoundingArgs,
): CommercialDocRoundingResult {
  const { config } = args;
  if (config.scope === "UNIFIED") {
    return applyUnified(args.totalComercialPostTax, config);
  }
  return applyBreakdown(
    args.totalComercialPostTax,
    args.metalValuationSum,
    // Base canónica del saldo comercial = Σ metalSale (con margen). Fallback a
    // la valoración física si el caller no la provee (snapshots/llamadas legacy).
    args.metalSaleSum ?? args.metalValuationSum,
    // Factor de margen del metal para los gramos comerciales (display). Default
    // 1 (sin margen) cuando el caller no lo provee.
    typeof args.metalCommercialMarginFactor === "number"
      && Number.isFinite(args.metalCommercialMarginFactor)
      && args.metalCommercialMarginFactor > 0
      ? args.metalCommercialMarginFactor
      : 1,
    args.metalsByParent ?? [],
    config,
  );
}

function applyUnified(
  totalPre: number,
  cfg:      CommercialDocRoundingInputUnified,
): CommercialDocRoundingResult {
  const pre = round2(totalPre);

  if (cfg.mode === "NONE") {
    // Reportamos fallback informativo — el caller decide si serializa.
    return {
      applied: {
        source:          "PRICE_LIST",
        scope:           "UNIFIED",
        appliedAt:       "DOCUMENT",
        totalAdjustment: 0,
        fallback:        "ALL_NONE",
      },
      totalPostCommercial: pre,
    };
  }

  const post  = applyRoundingNumber(pre, cfg.mode, cfg.direction);
  const delta = round2(post - pre);

  if (Math.abs(delta) <= EPS_MONEY) {
    return { applied: null, totalPostCommercial: pre };
  }

  return {
    applied: {
      source:  "PRICE_LIST",
      scope:   "UNIFIED",
      appliedAt: "DOCUMENT",
      unified: {
        pre,
        post:       round2(post),
        adjustment: delta,
        mode:       cfg.mode,
        direction:  cfg.direction,
      },
      totalAdjustment: delta,
    },
    totalPostCommercial: round2(post),
  };
}

function applyBreakdown(
  totalPre:          number,
  metalValuationSum: number,
  metalSaleSum:      number,
  metalMarginFactor: number,
  metalsByParent:    CommercialDocMetalParentInput[],
  cfg:               CommercialDocRoundingInputBreakdown,
): CommercialDocRoundingResult {
  const totalComercial = round2(totalPre);
  // `valuationSum` (físico, sin margen) ya NO alimenta el saldo comercial —
  // queda como referencia/diagnóstico. La base del saldo es `metalSaleSum`.
  void metalValuationSum;
  const metalSaleBase  = round2(metalSaleSum);

  const metalCfgActive   = cfg.metal.mode   !== "NONE";
  const hechuraCfgActive = cfg.hechura.mode !== "NONE";

  // ── ALL_NONE: ambos NONE → no acción, pero reportamos fallback. ─────────
  if (!metalCfgActive && !hechuraCfgActive) {
    return {
      applied: {
        source:          "PRICE_LIST",
        scope:           "BREAKDOWN",
        appliedAt:       "DOCUMENT",
        totalAdjustment: 0,
        fallback:        "ALL_NONE",
      },
      totalPostCommercial: totalComercial,
    };
  }

  // ── 1) METAL FÍSICO ─────────────────────────────────────────────────────
  const metalEntries: CommercialDocMetalSnapshotEntry[] = [];
  let metalMonetaryDelta = 0;
  const metalsExpectedButMissing = metalCfgActive && metalsByParent.length === 0;

  if (metalCfgActive) {
    for (const m of metalsByParent) {
      // CON MARGEN (regla final) — el redondeo físico COMERCIAL opera sobre los
      // gramos comerciales (con margen): gramsSale = gramsPure × marginFactor.
      // El impacto monetario usa el precio de referencia del metal (refValue),
      // con el que `gramsSale × refValue = metalSale`. Una sola base alimenta
      // gramos, impacto, saldo, total y footer.
      const refValue = typeof m.metalReferenceValue === "number"
        && Number.isFinite(m.metalReferenceValue) && m.metalReferenceValue > 0
        ? m.metalReferenceValue
        : m.metalPricePerGram;
      const preGrams   = round4Grams(round4Grams(m.gramsPure) * metalMarginFactor);
      const postGrams  = round4Grams(
        roundGramsToStep(preGrams, cfg.metal.mode, cfg.metal.direction),
      );
      const deltaGrams = round4Grams(postGrams - preGrams);
      if (Math.abs(deltaGrams) <= EPS_GRAMS) continue;
      const monetaryEquivalent = round2(deltaGrams * refValue);
      const preAmount  = round2(preGrams  * refValue);
      const postAmount = round2(postGrams * refValue);
      metalMonetaryDelta += monetaryEquivalent;
      metalEntries.push({
        metalParentId:      m.metalParentId,
        metalParentName:    m.metalParentName,
        preGrams,
        postGrams,
        deltaGrams,
        metalPricePerGram:  refValue,
        monetaryEquivalent,
        preAmount,
        postAmount,
        mode:               cfg.metal.mode,
        direction:          cfg.metal.direction,
      });
    }
  }
  metalMonetaryDelta = round2(metalMonetaryDelta);

  // ── 2) HECHURA / SALDO MONETARIO (COMERCIAL) ─────────────────────────────
  // CONTRATO CANÓNICO (CLAUDE.md — "comercial DESGLOSADO opera sobre la
  // composición de VENTA, no sobre valoración física"):
  //   saldoMonetario = totalComercial − Σ metalSale (metal COMERCIAL con margen)
  // NO `totalComercial − valoración física` — esa fórmula pertenece al
  // dominio financiero/físico (capa 16), no al redondeo comercial del artículo.
  //
  // Así el margen del metal queda dentro del METAL comercial (no del saldo), y
  // se cumple por construcción:
  //   METAL comercial (Σ metalSale + Δredondeo) + saldoPost = totalPostComercial
  const saldoPre = round2(totalComercial - metalSaleBase);

  let saldoPost  = saldoPre;
  let saldoDelta = 0;
  if (hechuraCfgActive) {
    saldoPost  = round2(applyRoundingNumber(saldoPre, cfg.hechura.mode, cfg.hechura.direction));
    saldoDelta = round2(saldoPost - saldoPre);
  }

  // ── Consolidación ───────────────────────────────────────────────────────
  const combinedDelta = round2(metalMonetaryDelta + saldoDelta);

  // Snapshot mínimo cuando hubo fallback pero ningún movimiento real
  if (combinedDelta === 0 && !metalsExpectedButMissing) {
    return { applied: null, totalPostCommercial: totalComercial };
  }

  const hechura: CommercialDocHechuraSnapshot = {
    preRoundingSaldoMonetario:  saldoPre,
    postRoundingSaldoMonetario: saldoPost,
    deltaSaldoMonetario:        saldoDelta,
    mode:                       cfg.hechura.mode,
    direction:                  cfg.hechura.direction,
    source:                     "PRICE_LIST_HECHURA",
  };

  // Redondeo físico COMERCIAL de los gramos (display) — MISMA fórmula ÚNICA que
  // `metalEntries` (footer/monetario), aplicada a TODOS los metales padre,
  // incluso delta=0:
  //   gramsSale = gramos × pureza × merma × MARGEN  (= gramsPure × marginFactor)
  //   postGrams = round(gramsSale)
  // `metalEntries` usa exactamente esta base (CON MARGEN) → card (metalsPostGrams)
  // y footer (metalEntries) NUNCA difieren para un mismo metal. La única
  // diferencia es que `metalsPostGrams` incluye los delta=0 (card muestra todos)
  // y `metalEntries` los omite (footer solo audita los que se redondearon).
  // `preGrams` acá es el gramsSale (con margen) SIN redondear; `postGrams` el
  // redondeado. Factor 1 ⇒ sin margen (back-compat).
  const metalsPostGrams = metalsByParent.map((m) => {
    const gramsSale = round4Grams(round4Grams(m.gramsPure) * metalMarginFactor);
    const postGrams = round4Grams(
      roundGramsToStep(gramsSale, cfg.metal.mode, cfg.metal.direction),
    );
    return {
      metalParentId:   m.metalParentId,
      metalParentName: m.metalParentName,
      preGrams:        gramsSale,
      postGrams,
    };
  });

  return {
    applied: {
      source:    "PRICE_LIST",
      scope:     "BREAKDOWN",
      appliedAt: "DOCUMENT",
      breakdown: {
        metals:                  metalEntries,
        metalMonetaryEquivalent: metalMonetaryDelta,
        hechura,
        combinedAdjustment:      combinedDelta,
        metalsPostGrams,
      },
      totalAdjustment: combinedDelta,
      ...(metalsExpectedButMissing ? { fallback: "NO_METALS_BREAKDOWN_DATA" as const } : {}),
    },
    totalPostCommercial: round2(totalComercial + combinedDelta),
  };
}

/**
 * SSOT del redondeo físico COMERCIAL de gramos de UN metal padre — la MISMA
 * fórmula que usan `metalEntries` (footer) y `breakdown.metalsPostGrams` (card
 * agregado), pero expuesta para aplicarla PER-LÍNEA:
 *
 *   gramsSale = gramos × pureza × merma × MARGEN  (= gramsPure × marginFactor)
 *   postGrams = round(gramsSale)                  (cfg.mode/direction)
 *
 * Es display-only: NO toca dinero, saldo ni totales. Usar con el `gramsPure`
 * de la línea (no el agregado del documento) y el `marginFactor` de la PROPIA
 * línea (= metalSale_línea / metalCost_línea) para que agregar otra línea no
 * altere ésta. `marginFactor` ≤ 0 o no finito ⇒ 1 (sin margen, back-compat).
 */
export function computeCommercialPostGrams(
  gramsPure:    number,
  marginFactor: number,
  cfg:          CommercialDocRoundingPartConfig,
): { preGrams: number; postGrams: number; deltaGrams: number } {
  const factor    = Number.isFinite(marginFactor) && marginFactor > 0 ? marginFactor : 1;
  const preGrams  = round4Grams(round4Grams(gramsPure) * factor);
  const postGrams = cfg.mode === "NONE"
    ? preGrams
    : round4Grams(roundGramsToStep(preGrams, cfg.mode, cfg.direction));
  const deltaGrams = round4Grams(postGrams - preGrams);
  return { preGrams, postGrams, deltaGrams };
}

/**
 * SSOT del redondeo COMERCIAL de un saldo MONETARIO (bucket hechura). Misma
 * mecánica `applyRoundingNumber` que el documento, expuesta para aplicarla
 * sobre el saldo PROPIO de una línea (line-autonomous). `mode="NONE"` ⇒ sin
 * redondeo (devuelve el valor a 2 decimales). Acepta negativos (componentes
 * negativos válidos) — NO clampa.
 */
export function applyCommercialRoundingMonetary(
  value: number,
  cfg:   CommercialDocRoundingPartConfig,
): number {
  if (cfg.mode === "NONE") return round2(value);
  return round2(applyRoundingNumber(value, cfg.mode, cfg.direction));
}

/**
 * Espejo numérico puro de `pricing-engine.pricelist.applyRounding`. Se duplica
 * acá para mantener este módulo sin imports de Prisma. Si en el futuro se
 * unifica el helper, mover ambos a un módulo `rounding-math.ts` neutral.
 */
function applyRoundingNumber(
  value:     number,
  mode:      CommercialDocRoundingMode,
  direction: CommercialDocRoundingDirection,
): number {
  if (mode === "NONE") return value;
  let step: number;
  switch (mode) {
    case "INTEGER":   step = 1;    break;
    case "DECIMAL_1": step = 0.1;  break;
    case "DECIMAL_2": step = 0.01; break;
    case "TEN":       step = 10;   break;
    case "HUNDRED":   step = 100;  break;
    default:          return value;
  }
  if (direction === "UP")   return Math.ceil(value  / step) * step;
  if (direction === "DOWN") return Math.floor(value / step) * step;
  return Math.round(value / step) * step;
}

/**
 * Redondeo de GRAMOS físicos comerciales del metal a un `step`, ROBUSTO ante el
 * error de punto flotante en los puntos medios (.X5) y los bordes de step.
 *
 * Bug que corrige: `Math.round(value / step)` falla porque `value / step` arrastra
 * ruido binario. Ej.: `1.65 / 0.1 = 16.499999999999996` (no 16,5) → `Math.round`
 * baja a 16 → 1,60. También `1.6 / 0.1 = 16.000000000000004` → `Math.ceil` sube a
 * 17 → 1,70. Limpiamos el COCIENTE (~9 decimales) antes de redondear ⇒ half-up
 * comercial real: 1,65 → 1,70 ; 1,60 → 1,60.
 *
 * ALCANCE: SOLO gramos físicos comerciales del metal. NO se usa en el redondeo
 * MONETARIO (saldo/hechura/UNIFIED), que conserva `applyRoundingNumber` intacto
 * — ni en el redondeo FINANCIERO (otro módulo). Es un fix de correctitud: solo
 * cambia valores que hoy redondean MAL; ningún valor correcto se altera.
 */
function roundGramsToStep(
  value:     number,
  mode:      CommercialDocRoundingMode,
  direction: CommercialDocRoundingDirection,
): number {
  if (mode === "NONE") return value;
  let step: number;
  switch (mode) {
    case "INTEGER":   step = 1;    break;
    case "DECIMAL_1": step = 0.1;  break;
    case "DECIMAL_2": step = 0.01; break;
    case "TEN":       step = 10;   break;
    case "HUNDRED":   step = 100;  break;
    default:          return value;
  }
  // Limpia el ruido FP del cociente antes de redondear (1e9 ≈ 9 decimales,
  // muy por encima de la precisión de gramos y muy por debajo del epsilon FP).
  const q  = value / step;
  const qc = Math.round(q * 1e9) / 1e9;
  if (direction === "UP")   return Math.ceil(qc)  * step;
  if (direction === "DOWN") return Math.floor(qc) * step;
  return Math.round(qc) * step;
}
