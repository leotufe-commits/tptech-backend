// src/lib/pricing-engine/pricing-engine.cost-line-overrides.ts
// =============================================================================
// FASE F1.4 G5 #11-A — helpers centralizados para CostLineOverride.
//
// Una sola fuente de verdad para:
//   1. Validar un override contra una cost line (`validateCostLineOverride`).
//   2. Unificar overrides legacy + explicit en un único array
//      (`unifyCostLineOverrides`).
//   3. Helpers puros para resolver el valor "effective" de cada campo
//      (`resolveEffectiveQuantity`, etc.).
//
// Reglas críticas (POLICY R4.5 + decisiones del usuario en F1.4):
//   · `costLineOverrides` SIEMPRE gana sobre overrides legacy cuando
//     refieren al mismo costLineId.
//   · Cero mutación: trabajamos con valores derivados locales.
//   · Cero mentalidad de índice — todo se resuelve por `costLineId`.
//   · Validaciones devuelven `DebugWarning[]` que NO contaminan steps[]
//     visuales — son diagnóstico interno.
// =============================================================================

import type {
  CostLineOverride,
  DebugWarning,
} from "./pricing-engine.types.js";
import type { CostLineInput } from "./pricing-engine.types.js";

// ─────────────────────────────────────────────────────────────────────────────
// Validación per override
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Valida un override contra la cost line a la que apunta. Devuelve:
 *   · `applicable`: false si el override entero debe descartarse
 *     (costLineId no existe o type mismatch).
 *   · `sanitized`: copia del override con campos no aplicables BORRADOS
 *     (ej: unitValueOverride para METAL → eliminado del objeto).
 *   · `warnings`: array de DebugWarning para los campos descartados.
 *
 * Casos cubiertos:
 *   · `costLineId` no existe en `lines` → applicable=false + 1 warning.
 *   · `type` no coincide con la cost line real → applicable=false + 1 warning.
 *   · METAL + `unitValueOverride` → applicable=true, campo borrado, warning.
 *   · METAL + `adjustment*` → applicable=true, campos borrados, warning.
 *   · ≠METAL + `mermaPercentOverride` → applicable=true, campo borrado, warning.
 */
export function validateCostLineOverride(
  override: CostLineOverride,
  line:     CostLineInput | undefined,
): {
  applicable: boolean;
  sanitized:  CostLineOverride;
  warnings:   DebugWarning[];
} {
  const warnings: DebugWarning[] = [];

  // 1. costLineId no encontrado.
  if (!line) {
    return {
      applicable: false,
      sanitized:  override,
      warnings:   [{
        code:    "COST_LINE_OVERRIDE_NOT_FOUND",
        message: `costLineId "${override.costLineId}" no existe en la composición — override ignorado`,
        context: { costLineId: override.costLineId, type: override.type },
      }],
    };
  }

  // 2. type mismatch — todo el override se descarta para evitar aplicar
  //    un campo de un tipo a otro.
  if (override.type !== line.type) {
    return {
      applicable: false,
      sanitized:  override,
      warnings:   [{
        code:    "COST_LINE_OVERRIDE_TYPE_MISMATCH",
        message: `costLineId "${override.costLineId}": override.type="${override.type}" no coincide con la cost line real (type="${line.type}") — override ignorado`,
        context: { costLineId: override.costLineId, requestedType: override.type, actualType: line.type },
      }],
    };
  }

  // 3. Campos no aplicables al tipo — se borran del sanitized + 1 warning
  //    por campo. El override se mantiene aplicable con los campos válidos.
  const sanitized: CostLineOverride = { ...override };

  if (line.type === "METAL") {
    if (sanitized.unitValueOverride !== undefined && sanitized.unitValueOverride !== null) {
      warnings.push({
        code:    "COST_LINE_OVERRIDE_FIELD_NOT_APPLICABLE",
        message: `costLineId "${override.costLineId}": unitValueOverride no aplica a METAL (precio viene de MetalQuote) — campo ignorado`,
        context: { costLineId: override.costLineId, field: "unitValueOverride", type: "METAL" },
      });
      delete (sanitized as unknown as Record<string, unknown>).unitValueOverride;
    }
    if (
      sanitized.adjustmentKind  !== undefined ||
      sanitized.adjustmentType  !== undefined ||
      sanitized.adjustmentValue !== undefined
    ) {
      warnings.push({
        code:    "COST_LINE_OVERRIDE_FIELD_NOT_APPLICABLE",
        message: `costLineId "${override.costLineId}": adjustment* no aplica a METAL (motor cost descarta lineAdj para METAL) — campos ignorados`,
        context: { costLineId: override.costLineId, type: "METAL" },
      });
      delete (sanitized as unknown as Record<string, unknown>).adjustmentKind;
      delete (sanitized as unknown as Record<string, unknown>).adjustmentType;
      delete (sanitized as unknown as Record<string, unknown>).adjustmentValue;
    }
  } else {
    // HECHURA / PRODUCT / SERVICE — mermaPercentOverride no aplica.
    if (sanitized.mermaPercentOverride !== undefined && sanitized.mermaPercentOverride !== null) {
      warnings.push({
        code:    "COST_LINE_OVERRIDE_FIELD_NOT_APPLICABLE",
        message: `costLineId "${override.costLineId}": mermaPercentOverride solo aplica a METAL (type actual: ${line.type}) — campo ignorado`,
        context: { costLineId: override.costLineId, field: "mermaPercentOverride", type: line.type },
      });
      delete (sanitized as unknown as Record<string, unknown>).mermaPercentOverride;
    }
  }

  return { applicable: true, sanitized, warnings };
}

// ─────────────────────────────────────────────────────────────────────────────
// Unificación legacy ↔ explicit
// ─────────────────────────────────────────────────────────────────────────────

export interface LegacyOverridesShape {
  gramsOverride?:        number | null;
  mermaPercentOverride?: number | null;
  hechuraOverrideAmount?: number | null;
}

/**
 * Une los overrides legacy (gramsOverride / mermaPercentOverride /
 * hechuraOverrideAmount) con el array `explicit` (costLineOverrides
 * provisto por el caller).
 *
 * Reglas (decisión del usuario):
 *   · Explicit SIEMPRE gana cuando hay match por costLineId.
 *   · Legacy se sintetiza apuntando al PRIMER METAL/HECHURA si y solo
 *     si NO hay un explicit ya para ese costLineId.
 *   · `metalVariantIdOverride` queda LEGACY-ONLY (no se incluye acá).
 *   · NO additive merge ni fallback ambiguo.
 *
 * Devuelve un array nuevo (no muta inputs).
 */
export function unifyCostLineOverrides(
  baseLines: ReadonlyArray<CostLineInput>,
  legacy:    LegacyOverridesShape,
  explicit:  ReadonlyArray<CostLineOverride> | undefined,
): CostLineOverride[] {
  const result: CostLineOverride[] = [];
  const explicitMap = new Map<string, CostLineOverride>();
  for (const ov of explicit ?? []) {
    if (ov?.costLineId) explicitMap.set(ov.costLineId, ov);
  }

  // Primer METAL / HECHURA — solo se usan para sintetizar legacy.
  const firstMetal   = baseLines.find(l => l.type === "METAL"   && typeof l.id === "string" && l.id.length > 0);
  const firstHechura = baseLines.find(l => l.type === "HECHURA" && typeof l.id === "string" && l.id.length > 0);

  // Sintetizar legacy METAL.
  if (firstMetal?.id && !explicitMap.has(firstMetal.id)) {
    const synth: CostLineOverride = { costLineId: firstMetal.id, type: "METAL" };
    let any = false;
    if (legacy.gramsOverride != null) {
      synth.quantityOverride = legacy.gramsOverride;
      any = true;
    }
    if (legacy.mermaPercentOverride != null) {
      synth.mermaPercentOverride = legacy.mermaPercentOverride;
      any = true;
    }
    if (any) result.push(synth);
  }

  // Sintetizar legacy HECHURA.
  if (firstHechura?.id && !explicitMap.has(firstHechura.id)
      && legacy.hechuraOverrideAmount != null) {
    result.push({
      costLineId:        firstHechura.id,
      type:              "HECHURA",
      quantityOverride:  1,
      unitValueOverride: legacy.hechuraOverrideAmount,
    });
  }

  // Agregar explicit (gana sobre legacy por la lógica de skip arriba).
  for (const ov of explicit ?? []) {
    if (ov?.costLineId) result.push(ov);
  }

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Builder de Map sanitizado
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Procesa un array de `costLineOverrides` (post-unify) y devuelve:
 *   · `map`: Map<costLineId, sanitized override> — solo entries aplicables.
 *   · `applied`: array de overrides sanitizados (lo que el motor USÓ).
 *   · `warnings`: todos los warnings recolectados.
 *
 * El motor cost consume el Map para lookup O(1) per line. El `applied`
 * y los `warnings` van al `CostResult` y de ahí al `SalePriceResult`.
 */
export function buildCostLineOverrideMap(
  overrides: ReadonlyArray<CostLineOverride>,
  baseLines: ReadonlyArray<CostLineInput>,
): {
  map:      Map<string, CostLineOverride>;
  applied:  CostLineOverride[];
  warnings: DebugWarning[];
} {
  const map: Map<string, CostLineOverride> = new Map();
  const applied: CostLineOverride[] = [];
  const warnings: DebugWarning[] = [];
  // Lookup line por id — sin mentalidad de índice.
  const byId = new Map<string, CostLineInput>();
  for (const l of baseLines) {
    if (typeof l.id === "string" && l.id.length > 0) byId.set(l.id, l);
  }
  for (const ov of overrides) {
    if (!ov?.costLineId) continue;
    const line = byId.get(ov.costLineId);
    const { applicable, sanitized, warnings: w } = validateCostLineOverride(ov, line);
    warnings.push(...w);
    if (applicable && line) {
      map.set(ov.costLineId, sanitized);
      applied.push(sanitized);
    }
  }
  return { map, applied, warnings };
}

// ─────────────────────────────────────────────────────────────────────────────
// Resolvers de valor "effective" (cero mutación)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Resuelve la `quantity` efectiva de una cost line, aplicando override
 * si existe. Cero mutación del input.
 *
 * Semántica null/undefined:
 *   · `quantityOverride === undefined` → no override (mantener original).
 *   · `quantityOverride === null` → tratado como undefined (no override).
 *   · `quantityOverride` numérico → reemplaza el original.
 */
export function resolveEffectiveQuantity(
  originalQty: unknown,
  override:    CostLineOverride | undefined,
): unknown {
  if (override?.quantityOverride != null) return override.quantityOverride;
  return originalQty;
}

/**
 * Resuelve `unitValue` efectivo. Solo aplica para no-METAL — el caller
 * debe garantizar que no se llame con override de METAL (ya filtrado por
 * `validateCostLineOverride`).
 */
export function resolveEffectiveUnitValue(
  originalUnitValue: unknown,
  override:          CostLineOverride | undefined,
): unknown {
  if (override?.unitValueOverride != null) return override.unitValueOverride;
  return originalUnitValue;
}

/**
 * Resuelve `mermaPercent` efectivo. Solo aplica para METAL.
 */
export function resolveEffectiveMermaPercent(
  originalMerma: number | null | undefined,
  override:      CostLineOverride | undefined,
): number | null | undefined {
  if (override?.mermaPercentOverride != null) return override.mermaPercentOverride;
  return originalMerma;
}

/**
 * Resuelve los 3 campos del adjustment efectivo. Aplica solo a HECHURA/
 * PRODUCT/SERVICE (METAL filtrado por validate).
 *
 * Semántica:
 *   · `override.adjustmentKind === undefined` → mantener original.
 *   · `override.adjustmentKind === null` → LIMPIAR (kind=null, type=null,
 *     value=null) — sin bonif/recargo.
 *   · `override.adjustmentKind` valor → reemplazar (kind/type/value).
 */
export function resolveEffectiveAdjustment(
  originalKind:  unknown,
  originalType:  unknown,
  originalValue: unknown,
  override:      CostLineOverride | undefined,
): { kind: unknown; type: unknown; value: unknown } {
  if (!override) return { kind: originalKind, type: originalType, value: originalValue };
  // Si TODOS los 3 son undefined → no override.
  if (
    override.adjustmentKind  === undefined &&
    override.adjustmentType  === undefined &&
    override.adjustmentValue === undefined
  ) {
    return { kind: originalKind, type: originalType, value: originalValue };
  }
  // Si adjustmentKind === null → LIMPIAR los 3 (sin importar los otros).
  if (override.adjustmentKind === null) {
    return { kind: null, type: null, value: null };
  }
  // Si vino algún campo concreto → reemplazar (los undefined mantienen el original).
  return {
    kind:  override.adjustmentKind  !== undefined ? override.adjustmentKind  : originalKind,
    type:  override.adjustmentType  !== undefined ? override.adjustmentType  : originalType,
    value: override.adjustmentValue !== undefined ? override.adjustmentValue : originalValue,
  };
}
