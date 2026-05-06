// src/lib/pricing-engine/pricing-engine.shipping.ts
// =============================================================================
// Capa 10 del orden inmutable — Envío (POLICY.md §5).
//
// Resuelve el monto de envío desde el input crudo `{ mode, value, weight }`.
// Único punto autorizado para este cálculo en el sistema. El frontend envía
// solo los inputs del usuario (modo elegido, precio/kg, kg). El motor resuelve.
//
// Modos soportados:
//   · FREE       → amount = 0
//   · FIXED      → amount = round2(value)               (value: monto fijo)
//   · BY_WEIGHT  → amount = round2(value × weight)      (value: $/kg, weight: kg)
//
// Errores: lanza Error con `status = 400` cuando los inputs son inconsistentes
// (sigue el patrón del backend: `assert(cond, msg)` o `throw err` con
// `err.status`).
// =============================================================================

export type ShippingMode = "FIXED" | "BY_WEIGHT" | "FREE";

export interface ShippingInput {
  mode:    ShippingMode;
  /** Monto fijo (FIXED) o precio por kg (BY_WEIGHT). Ignorado en FREE. */
  value?:  number | null;
  /** Kilogramos del envío. Solo aplica en BY_WEIGHT. */
  weight?: number | null;
}

export interface ShippingResult {
  mode:   ShippingMode;
  amount: number;
  label?: string;
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

function badRequest(msg: string): Error {
  const err: any = new Error(msg);
  err.status = 400;
  return err;
}

/**
 * Resuelve el monto de envío. Devuelve `null` si `input` es nullish o el
 * `mode` no está definido (caso "no hay envío configurado en el documento").
 */
export function resolveShippingAmount(
  input: ShippingInput | null | undefined,
): ShippingResult | null {
  if (!input || !input.mode) return null;

  if (input.mode === "FREE") {
    return { mode: "FREE", amount: 0, label: "Envío gratis" };
  }

  if (input.mode === "FIXED") {
    if (input.value == null) {
      throw badRequest("Envío FIXED requiere `value` numérico ≥ 0.");
    }
    const v = Number(input.value);
    if (!Number.isFinite(v) || v < 0) {
      throw badRequest("Envío FIXED requiere `value` numérico ≥ 0.");
    }
    return { mode: "FIXED", amount: round2(v), label: "Envío fijo" };
  }

  if (input.mode === "BY_WEIGHT") {
    if (input.value == null) {
      throw badRequest("Envío BY_WEIGHT requiere `value` (precio/kg) numérico ≥ 0.");
    }
    if (input.weight == null) {
      throw badRequest("Envío BY_WEIGHT requiere `weight` (kg) numérico ≥ 0.");
    }
    const ppk = Number(input.value);
    const kg  = Number(input.weight);
    if (!Number.isFinite(ppk) || ppk < 0) {
      throw badRequest("Envío BY_WEIGHT requiere `value` (precio/kg) numérico ≥ 0.");
    }
    if (!Number.isFinite(kg) || kg < 0) {
      throw badRequest("Envío BY_WEIGHT requiere `weight` (kg) numérico ≥ 0.");
    }
    return { mode: "BY_WEIGHT", amount: round2(ppk * kg), label: "Envío por peso" };
  }

  // Modo desconocido → null (no validamos contra una whitelist más estricta
  // para no romper si en el futuro se agregan modos en el schema).
  return null;
}
