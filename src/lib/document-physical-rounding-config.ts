// src/lib/document-physical-rounding-config.ts
// =============================================================================
// Etapa D2 — Lectura / validación de la configuración de redondeo físico de
// gramos persistida en `Jewelry.documentPhysicalRoundingConfig` (JSON nullable)
// + `Jewelry.documentRoundingMetalDomain` (enum MONETARY | PHYSICAL).
//
// Helper PURO — sin DB, sin async. Recibe un objeto "Jewelry-like" con los
// dos campos persistidos y devuelve un shape listo para alimentar
// `roundDocumentMetalGrams` (D1). Si el JSON guardado está corrupto o
// incompleto, el helper degrada de forma segura sin tirar errores: las
// entries inválidas se descartan, y el resultado se normaliza al shape
// canónico aunque sea vacío.
//
// IMPORTANT: este helper NO se usa en runtime todavía. Etapa D3 lo
// conectará desde `pricing-engine.document.ts` cuando se implemente
// la capa 16. D2 solo prepara la persistencia y el contrato de lectura.
// =============================================================================

import type {
  PhysicalMetalRoundingConfig,
  PhysicalRoundingMode,
  PhysicalRoundingDirection,
} from "./document-physical-rounding.js";

// ──────────────────────────────────────────────────────────────────────────
// Tipos públicos
// ──────────────────────────────────────────────────────────────────────────

/** Discriminador del dominio del metal en BREAKDOWN. Default DB: MONETARY. */
export type DocumentRoundingMetalDomain = "MONETARY" | "PHYSICAL";

/** Subset Jewelry-like que el helper necesita leer. Tipado al mínimo para
 *  no acoplar acá el modelo Prisma completo. */
export interface DocumentPhysicalRoundingJewelryLike {
  documentRoundingMetalDomain?: DocumentRoundingMetalDomain | null;
  documentPhysicalRoundingConfig?: unknown;
}

/** Resultado normalizado del helper — paralelo al input de
 *  `roundDocumentMetalGrams`. */
export interface ResolvedPhysicalRoundingConfig {
  /** `true` cuando el tenant pidió el dominio PHYSICAL. Cuando es `false`,
   *  el caller NO debe invocar `roundDocumentMetalGrams` — el redondeo
   *  monetario (capa 15) sigue actuando como hasta hoy. */
  enabled: boolean;
  /** Map metalParentId → config. Vacío cuando no hay entries válidas. */
  configByMetalParentId: Record<string, PhysicalMetalRoundingConfig>;
  /** Config fallback aplicada a metales sin entry específica. `null`
   *  cuando el tenant no la configuró (en ese caso D1 emite `NO_CONFIG`
   *  por cada metal sin entry). */
  fallbackConfig: PhysicalMetalRoundingConfig | null;
  /** `true` cuando el JSON persistido tenía estructura inesperada o entries
   *  inválidas que el helper descartó. Permite que el caller logue una
   *  alerta sin romper el preview. */
  hasInvalidEntries: boolean;
}

// ──────────────────────────────────────────────────────────────────────────
// Validadores de enums (string → enum). `null` cuando el valor crudo no
// matchea ningún miembro válido.
// ──────────────────────────────────────────────────────────────────────────

const VALID_MODES: readonly PhysicalRoundingMode[] = [
  "NONE",
  "INTEGER",
  "DECIMAL_1",
  "DECIMAL_2",
  "HALF",
  "QUARTER",
];

const VALID_DIRECTIONS: readonly PhysicalRoundingDirection[] = [
  "NEAREST",
  "UP",
  "DOWN",
];

function asMode(raw: unknown): PhysicalRoundingMode | null {
  if (typeof raw !== "string") return null;
  return VALID_MODES.includes(raw as PhysicalRoundingMode)
    ? (raw as PhysicalRoundingMode)
    : null;
}

function asDirection(raw: unknown): PhysicalRoundingDirection | null {
  if (typeof raw !== "string") return null;
  return VALID_DIRECTIONS.includes(raw as PhysicalRoundingDirection)
    ? (raw as PhysicalRoundingDirection)
    : null;
}

function asDomain(raw: unknown): DocumentRoundingMetalDomain {
  if (raw === "PHYSICAL") return "PHYSICAL";
  // Default safe: cualquier otro valor (null, "MONETARY", "garbage") → MONETARY.
  return "MONETARY";
}

/** Convierte un `{ mode, direction }` crudo a `PhysicalMetalRoundingConfig`
 *  válido, o `null` si alguno de los dos campos no matchea su enum. */
function parseConfig(raw: unknown): PhysicalMetalRoundingConfig | null {
  if (!raw || typeof raw !== "object") return null;
  const mode      = asMode((raw as any).mode);
  const direction = asDirection((raw as any).direction);
  if (mode == null || direction == null) return null;
  return { mode, direction };
}

// ──────────────────────────────────────────────────────────────────────────
// Helper público
// ──────────────────────────────────────────────────────────────────────────

const EMPTY_RESULT: ResolvedPhysicalRoundingConfig = {
  enabled: false,
  configByMetalParentId: {},
  fallbackConfig: null,
  hasInvalidEntries: false,
};

/**
 * Helper NEUTRAL — resuelve la configuración de redondeo físico a partir
 * del dominio + JSON crudo, sin conocer si viene de `Jewelry` (financiero)
 * o `PriceList` (comercial). Reutilizado por:
 *
 *   · `resolveDocumentPhysicalRoundingConfig` (financiero / Jewelry).
 *   · `resolveCommercialPhysicalRoundingConfig` (comercial / PriceList,
 *     Etapa C2).
 *
 * Mismas reglas de degradación segura que el wrapper original:
 *   · `domain !== "PHYSICAL"` → `enabled: false`. Cero parsing del JSON.
 *   · Domain PHYSICAL + JSON `null` → `enabled: true`, config vacía.
 *   · Domain PHYSICAL + JSON con shape inesperado (no objeto) →
 *     `enabled: true`, `hasInvalidEntries: true`.
 *   · Entries inválidas dentro de `byMetalParentId` → descartadas con
 *     `hasInvalidEntries: true`.
 *   · `fallback` con shape inválido → ignorado (resultado `null`) y
 *     `hasInvalidEntries: true`.
 *
 * Pure function. Sin DB, sin async, sin side effects.
 */
export function resolvePhysicalRoundingConfig(
  domainRaw: unknown,
  jsonRaw:   unknown,
): ResolvedPhysicalRoundingConfig {
  const domain = asDomain(domainRaw ?? null);
  if (domain !== "PHYSICAL") {
    return EMPTY_RESULT;
  }

  // Domain PHYSICAL — parsear JSON.
  if (jsonRaw == null) {
    return { ...EMPTY_RESULT, enabled: true };
  }
  if (typeof jsonRaw !== "object") {
    return { ...EMPTY_RESULT, enabled: true, hasInvalidEntries: true };
  }

  const byMetalParentIdRaw = (jsonRaw as any).byMetalParentId;
  const fallbackRaw        = (jsonRaw as any).fallback;

  let hasInvalidEntries = false;

  const configByMetalParentId: Record<string, PhysicalMetalRoundingConfig> = {};
  if (byMetalParentIdRaw && typeof byMetalParentIdRaw === "object" && !Array.isArray(byMetalParentIdRaw)) {
    for (const key of Object.keys(byMetalParentIdRaw)) {
      const cfg = parseConfig((byMetalParentIdRaw as any)[key]);
      if (cfg && typeof key === "string" && key.trim().length > 0) {
        configByMetalParentId[key] = cfg;
      } else {
        hasInvalidEntries = true;
      }
    }
  } else if (byMetalParentIdRaw !== undefined) {
    hasInvalidEntries = true;
  }

  const fallbackConfig = parseConfig(fallbackRaw);
  if (fallbackRaw !== undefined && fallbackConfig == null && fallbackRaw !== null) {
    hasInvalidEntries = true;
  }

  return {
    enabled: true,
    configByMetalParentId,
    fallbackConfig,
    hasInvalidEntries,
  };
}

/**
 * Wrapper Jewelry — back-compat 1:1 con el contrato anterior. Delegado al
 * helper neutral.
 *
 * Mantiene el shape de input `{ documentRoundingMetalDomain,
 * documentPhysicalRoundingConfig }` que `loadDocumentRoundingConfig` ya
 * sabe construir desde el row de Prisma. Cero cambio para los call-sites
 * existentes.
 */
export function resolveDocumentPhysicalRoundingConfig(
  jewelry: DocumentPhysicalRoundingJewelryLike | null | undefined,
): ResolvedPhysicalRoundingConfig {
  if (!jewelry) return EMPTY_RESULT;
  return resolvePhysicalRoundingConfig(
    jewelry.documentRoundingMetalDomain ?? null,
    jewelry.documentPhysicalRoundingConfig,
  );
}
