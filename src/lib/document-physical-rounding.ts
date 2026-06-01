// src/lib/document-physical-rounding.ts
// =============================================================================
// Etapa D1 — Helper PURO de redondeo automático físico de gramos por metal
// padre (POLICY §R-Rounding-13).
//
// Aplica al nivel COMPROBANTE (redondeo financiero). El operador NO interviene:
// es política del tenant. La regla canónica es paralela al ajuste manual
// BREAKDOWN (Etapa C):
//   · El ajuste físico vive en el metal padre.
//   · `monetaryEquivalent = deltaGrams × metalPricePerGram` es CONSOLIDACIÓN
//     financiera — impacta `Sale.total` vía `metalMonetaryEquivalent`, sin
//     moverse al bucket hechura/saldo monetario.
//   · Los dos dominios (metal en gramos / hechura en moneda) permanecen
//     PARALELOS — solo se suman en `totalRoundingAdjustment` del snapshot
//     consolidado (definido en capa 16, fuera de este helper).
//
// D1 (este archivo): SOLO el helper puro + tipos. Sin DB, sin async, sin
// dependencias del motor de precios. Determinístico — mismo input → mismo
// output. Para preview/confirm parity en etapas siguientes.
//
// NO incluye:
//   · Integración en `pricing-engine.document.ts` (Etapa D3).
//   · Persistencia en `documentRoundingSnapshot` (Etapa D4).
//   · Conversión multimoneda (Etapa D5).
//   · UI (Etapa D6).
//   · Cuenta corriente metálica (etapa separada futura).
// =============================================================================

// ──────────────────────────────────────────────────────────────────────────
// Tipos públicos
// ──────────────────────────────────────────────────────────────────────────

/** Modos de redondeo físico soportados.
 *
 *  · `NONE`      → no redondea ese metal (passthrough explícito).
 *  · `INTEGER`   → múltiplos de 1   (ej. 0,908 → 1,000).
 *  · `DECIMAL_1` → múltiplos de 0,1 (ej. 0,94  → 0,9 / 1,0 según direction).
 *  · `DECIMAL_2` → múltiplos de 0,01.
 *  · `HALF`      → múltiplos de 0,5 (ej. 0,74 → 0,5; 0,76 → 1,0).
 *  · `QUARTER`   → múltiplos de 0,25 (ej. 0,62 → 0,5; 0,63 → 0,75).
 */
export type PhysicalRoundingMode =
  | "NONE"
  | "INTEGER"
  | "DECIMAL_1"
  | "DECIMAL_2"
  | "HALF"
  | "QUARTER";

/** Dirección del redondeo.
 *
 *  · `NEAREST` → al múltiplo más cercano. EMPATES (mitad exacta) van
 *    HACIA ARRIBA (half-up) — comportamiento determinístico definido para
 *    el operador joyero (ej. 0,5 con INTEGER → 1).
 *  · `UP`      → al siguiente múltiplo hacia arriba (ceil).
 *  · `DOWN`    → al múltiplo anterior hacia abajo (floor).
 */
export type PhysicalRoundingDirection = "NEAREST" | "UP" | "DOWN";

/** Metal consolidado por metal padre — input del helper. */
export interface PhysicalMetalInput {
  /** Id estable del metal padre. Si es `null`, el match con `configByMetalParentId`
   *  cae a `fallbackConfig` (no se invente claves a partir del nombre). */
  metalParentId:   string | null;
  metalParentName: string;
  /** Gramos consolidados (lado venta) del metal padre en el documento. */
  grams:           number;
  /** Cotización por gramo snapshot (= `balanceBreakdown.metals[i].quotePriceSnapshot`).
   *  `null` si el motor no la expuso → el helper marca `NO_METAL_PRICE` y NO
   *  redondea ese metal. */
  metalPricePerGram: number | null;
}

/** Config de redondeo de un metal padre. */
export interface PhysicalMetalRoundingConfig {
  mode:      PhysicalRoundingMode;
  direction: PhysicalRoundingDirection;
}

/** Input completo del helper.
 *
 *  `configByMetalParentId` resuelve cada metal por su id. Si un metal no
 *  tiene config explícita y `fallbackConfig` viene definido, se usa
 *  `fallbackConfig` (ej. "Plata sin config específica → redondear a HALF NEAREST").
 *  Si tampoco hay fallback, el metal queda sin redondear con marca `NO_CONFIG`.
 *
 *  Etapa C2 — `sourceTag` opcional permite al caller comercial marcar las
 *  entries con `"COMMERCIAL_PHYSICAL_ROUNDING"`. Default
 *  `"DOCUMENT_PHYSICAL_ROUNDING"` ⇒ back-compat para el caller financiero
 *  existente. La matemática y la semántica del redondeo son IDÉNTICAS
 *  para los dos sources — solo cambia el literal que viaja al snapshot. */
export interface RoundDocumentMetalGramsInput {
  metals: PhysicalMetalInput[];
  configByMetalParentId: Record<string, PhysicalMetalRoundingConfig>;
  fallbackConfig?: PhysicalMetalRoundingConfig | null;
  sourceTag?: PhysicalRoundingSource;
}

/** Marca de fallback PER METAL — explica por qué un metal no se redondeó. */
export type PhysicalRoundingEntryFallback =
  | null
  | "NO_METAL_PRICE"
  | "NO_CONFIG"
  | "INVALID_GRAMS";

/** Marca de fallback A NIVEL HELPER — explica por qué la corrida entera
 *  no produjo redondeo. Solo se emite cuando el input es trivial; con
 *  metales válidos siempre es `null`. */
export type PhysicalRoundingTopLevelFallback =
  | null
  | "NO_METALS_TO_ROUND"
  | "NO_BREAKDOWN_DATA";

/** Etapa C2 — origen del redondeo físico. Discrimina el snapshot por mecanismo:
 *
 *   · `DOCUMENT_PHYSICAL_ROUNDING` — redondeo financiero (Jewelry, capa 16).
 *   · `COMMERCIAL_PHYSICAL_ROUNDING` — redondeo comercial (PriceList, Etapa C). */
export type PhysicalRoundingSource =
  | "DOCUMENT_PHYSICAL_ROUNDING"
  | "COMMERCIAL_PHYSICAL_ROUNDING";

/** Entry del snapshot por metal padre — uno por cada item del input. */
export interface RoundedMetalEntry {
  metalParentId:      string | null;
  metalParentName:    string;
  preGrams:           number;
  postGrams:          number;
  deltaGrams:         number;
  /** Precio efectivo usado para el equivalente. `0` cuando el input fue
   *  `null`/inválido (se persiste 0 con fallback `NO_METAL_PRICE`). */
  metalPricePerGram:  number;
  /** `deltaGrams × metalPricePerGram` redondeado a 2 decimales. */
  monetaryEquivalent: number;
  /** Modo y dirección efectivos. En fallback se persiste lo intentado
   *  (o `NONE`/`NEAREST` cuando no se pudo resolver config). */
  mode:               PhysicalRoundingMode;
  direction:          PhysicalRoundingDirection;
  source:             PhysicalRoundingSource;
  fallback:           PhysicalRoundingEntryFallback;
}

/** Resultado del helper. */
export interface RoundDocumentMetalGramsResult {
  metals: RoundedMetalEntry[];
  /** Σ `metals[].monetaryEquivalent` redondeado a 2 decimales. */
  metalMonetaryEquivalent: number;
  fallback: PhysicalRoundingTopLevelFallback;
}

// ──────────────────────────────────────────────────────────────────────────
// Internals — redondeo seguro en ticks enteros
// ──────────────────────────────────────────────────────────────────────────

// SCALE elegido para evitar artifacts FP en los step soportados (1, 0,1,
// 0,01, 0,5, 0,25 — todos representables exactos con 4 decimales).
const SCALE   = 10000;
const round2  = (n: number): number => Math.round(n * 100) / 100;
const round4  = (n: number): number => Math.round(n * 10000) / 10000;

/** Convierte un mode a su step (gramos). `NONE` → `null` (no redondear). */
function modeToStep(mode: PhysicalRoundingMode): number | null {
  switch (mode) {
    case "INTEGER":   return 1;
    case "DECIMAL_1": return 0.1;
    case "DECIMAL_2": return 0.01;
    case "HALF":      return 0.5;
    case "QUARTER":   return 0.25;
    case "NONE":      return null;
    default:          return null;
  }
}

/** Redondea `value` al múltiplo de `step` más cercano según `direction`.
 *
 *  Trabaja con ticks enteros para minimizar artifacts de coma flotante.
 *  Empates (`frac === 0.5`) en `NEAREST` van HACIA ARRIBA (half-up). */
function roundToStep(
  value: number,
  step:  number,
  direction: PhysicalRoundingDirection,
): number {
  if (!Number.isFinite(value) || step <= 0) return value;
  const scaledValue = Math.round(value * SCALE);
  const scaledStep  = Math.round(step * SCALE);
  if (scaledStep <= 0) return value;
  const ticks = scaledValue / scaledStep;
  let roundedTicks: number;
  switch (direction) {
    case "UP":
      roundedTicks = Math.ceil(ticks);
      break;
    case "DOWN":
      roundedTicks = Math.floor(ticks);
      break;
    case "NEAREST":
    default: {
      // Half-up: empate exacto sube al siguiente múltiplo.
      const floor = Math.floor(ticks);
      const frac  = ticks - floor;
      roundedTicks = frac >= 0.5 ? floor + 1 : floor;
      break;
    }
  }
  return (roundedTicks * scaledStep) / SCALE;
}

/** Resuelve la config aplicable a un metal padre. */
function resolveConfig(
  metalParentId: string | null,
  byId: Record<string, PhysicalMetalRoundingConfig> | undefined,
  fallback?: PhysicalMetalRoundingConfig | null,
): { config: PhysicalMetalRoundingConfig | null; missing: boolean } {
  if (metalParentId && byId && Object.prototype.hasOwnProperty.call(byId, metalParentId)) {
    return { config: byId[metalParentId]!, missing: false };
  }
  if (fallback) {
    return { config: fallback, missing: false };
  }
  return { config: null, missing: true };
}

/** Procesa un metal — siempre emite UNA entry para auditoría completa. */
function processMetal(
  m: PhysicalMetalInput,
  configByMetalParentId: Record<string, PhysicalMetalRoundingConfig>,
  fallbackConfig?: PhysicalMetalRoundingConfig | null,
  sourceTag: PhysicalRoundingSource = "DOCUMENT_PHYSICAL_ROUNDING",
): RoundedMetalEntry {
  const baseEntry = {
    metalParentId:   m.metalParentId,
    metalParentName: m.metalParentName,
    source:          sourceTag,
  };
  const priceFinal = typeof m.metalPricePerGram === "number" && Number.isFinite(m.metalPricePerGram)
    ? m.metalPricePerGram
    : 0;

  // ── Validación de gramos ────────────────────────────────────────────────
  if (typeof m.grams !== "number" || !Number.isFinite(m.grams) || m.grams < 0) {
    const safePre = Number.isFinite(m.grams as number) && (m.grams as number) >= 0
      ? round4(m.grams as number)
      : 0;
    return {
      ...baseEntry,
      preGrams:           safePre,
      postGrams:          safePre,
      deltaGrams:         0,
      metalPricePerGram:  priceFinal,
      monetaryEquivalent: 0,
      mode:               "NONE",
      direction:          "NEAREST",
      fallback:           "INVALID_GRAMS",
    };
  }

  const preGrams = round4(m.grams);

  // ── Resolución de config ────────────────────────────────────────────────
  const resolved = resolveConfig(m.metalParentId, configByMetalParentId, fallbackConfig);
  if (resolved.missing) {
    return {
      ...baseEntry,
      preGrams,
      postGrams:          preGrams,
      deltaGrams:         0,
      metalPricePerGram:  priceFinal,
      monetaryEquivalent: 0,
      mode:               "NONE",
      direction:          "NEAREST",
      fallback:           "NO_CONFIG",
    };
  }
  const cfg = resolved.config!;

  // ── Mode NONE → passthrough explícito (no es fallback, es intencional) ──
  if (cfg.mode === "NONE") {
    return {
      ...baseEntry,
      preGrams,
      postGrams:          preGrams,
      deltaGrams:         0,
      metalPricePerGram:  priceFinal,
      monetaryEquivalent: 0,
      mode:               "NONE",
      direction:          cfg.direction,
      fallback:           null,
    };
  }

  // ── Sin metalPricePerGram → no redondear, fallback NO_METAL_PRICE ───────
  if (m.metalPricePerGram == null || !Number.isFinite(m.metalPricePerGram)) {
    return {
      ...baseEntry,
      preGrams,
      postGrams:          preGrams,
      deltaGrams:         0,
      metalPricePerGram:  0,
      monetaryEquivalent: 0,
      mode:               cfg.mode,
      direction:          cfg.direction,
      fallback:           "NO_METAL_PRICE",
    };
  }

  // ── Redondeo efectivo ──────────────────────────────────────────────────
  const step = modeToStep(cfg.mode);
  if (step == null) {
    // Defensivo: mode NONE manejado arriba; este caso no debería ocurrir.
    return {
      ...baseEntry,
      preGrams,
      postGrams:          preGrams,
      deltaGrams:         0,
      metalPricePerGram:  priceFinal,
      monetaryEquivalent: 0,
      mode:               "NONE",
      direction:          cfg.direction,
      fallback:           null,
    };
  }

  const rawPost            = roundToStep(preGrams, step, cfg.direction);
  const postGrams          = round4(Math.max(0, rawPost));
  const deltaGrams         = round4(postGrams - preGrams);
  const monetaryEquivalent = round2(deltaGrams * priceFinal);

  return {
    ...baseEntry,
    preGrams,
    postGrams,
    deltaGrams,
    metalPricePerGram:  priceFinal,
    monetaryEquivalent,
    mode:               cfg.mode,
    direction:          cfg.direction,
    fallback:           null,
  };
}

// ──────────────────────────────────────────────────────────────────────────
// Helper principal
// ──────────────────────────────────────────────────────────────────────────

/**
 * Redondea automáticamente los gramos consolidados por metal padre del
 * documento. Pure function — sin DB, sin side effects, sin mutación del
 * input. Mismo input → mismo output.
 *
 * Por cada metal del input emite UNA entry con `preGrams / postGrams /
 * deltaGrams / monetaryEquivalent / mode / direction / source / fallback`.
 * Los metales que cayeron en fallback igual aparecen en `metals[]` con la
 * marca correspondiente — auditoría completa sin pérdidas.
 *
 * Suma todos los `monetaryEquivalent` en `metalMonetaryEquivalent` (round2).
 * Este campo es lo que la capa 16 futura sumará al total del comprobante.
 *
 * `fallback` a nivel resultado se setea solo cuando el input es trivial:
 *   · `NO_BREAKDOWN_DATA` → input no tiene array `metals` válido.
 *   · `NO_METALS_TO_ROUND` → input.metals está vacío.
 */
export function roundDocumentMetalGrams(
  input: RoundDocumentMetalGramsInput,
): RoundDocumentMetalGramsResult {
  if (!input || !Array.isArray(input.metals)) {
    return {
      metals: [],
      metalMonetaryEquivalent: 0,
      fallback: "NO_BREAKDOWN_DATA",
    };
  }
  if (input.metals.length === 0) {
    return {
      metals: [],
      metalMonetaryEquivalent: 0,
      fallback: "NO_METALS_TO_ROUND",
    };
  }

  const configByMetalParentId = input.configByMetalParentId ?? {};
  const fallbackConfig        = input.fallbackConfig ?? null;
  const sourceTag             = input.sourceTag ?? "DOCUMENT_PHYSICAL_ROUNDING";

  const out: RoundedMetalEntry[] = [];
  let sumEq = 0;
  for (const m of input.metals) {
    const entry = processMetal(m, configByMetalParentId, fallbackConfig, sourceTag);
    out.push(entry);
    sumEq += entry.monetaryEquivalent;
  }

  return {
    metals: out,
    metalMonetaryEquivalent: round2(sumEq),
    fallback: null,
  };
}
