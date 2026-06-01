// src/lib/pricing-engine/balance-mode-resolver.ts
// =============================================================================
// Resolver puro del `BalanceMode` del documento.
//
// Aplica la prioridad oficial (POLICY.md §11 R11.4):
//   1. Override manual del documento (`Sale.balanceModeOverride`)
//   2. Default del cliente/proveedor (`CommercialEntity.balanceMode`)
//   3. Default de la lista de precios (`PriceList.balanceMode`)
//   4. Default del tenant (`Jewelry.defaultBalanceMode`)
//   5. Fallback → `UNIFIED`
//
// Función pura: sin side effects, sin DB, sin async. Testeable aisladamente.
//
// Esta función NO se invoca todavía en runtime (sub-fase 3B.1 es solo
// type-safety + lógica aislada). La integración a `previewSale`/`confirmSale`
// ocurre en sub-fase 3B.5.
// =============================================================================

import type {
  BalanceMode,
  BalanceModeResolution,
  BalanceModeResolverInput,
} from "./pricing-engine.types.js";

/** Identifica si un valor es un `BalanceMode` válido (`"UNIFIED"`/`"BREAKDOWN"`).
 *  Defiende contra valores ajenos al enum (ej. string vacío, número, undefined
 *  que llegan desde inputs no tipados). */
function isBalanceMode(value: unknown): value is BalanceMode {
  return value === "UNIFIED" || value === "BREAKDOWN";
}

/** Resuelve el `BalanceMode` aplicable al documento siguiendo la prioridad
 *  oficial R11.4. Devuelve siempre un resultado válido — nunca lanza.
 *
 *  Reglas:
 *    · El primer nivel con un `BalanceMode` válido gana.
 *    · `null`/`undefined`/cualquier valor no-enum se interpreta como "sin
 *      preferencia" y delega al siguiente nivel.
 *    · Si TODOS los niveles son nulos, devuelve `UNIFIED` con
 *      source `FALLBACK_UNIFIED` (regla R11.4 final).
 *
 *  Esta función NO consulta la DB. El caller debe haber cargado los defaults
 *  del cliente / lista / tenant antes de invocarla. */
export function resolveBalanceMode(
  input: BalanceModeResolverInput,
): BalanceModeResolution {
  if (isBalanceMode(input.documentOverride)) {
    return { mode: input.documentOverride, source: "DOCUMENT_OVERRIDE" };
  }
  if (isBalanceMode(input.entityDefault)) {
    return { mode: input.entityDefault, source: "ENTITY_DEFAULT" };
  }
  if (isBalanceMode(input.priceListDefault)) {
    return { mode: input.priceListDefault, source: "PRICELIST_DEFAULT" };
  }
  if (isBalanceMode(input.tenantDefault)) {
    return { mode: input.tenantDefault, source: "TENANT_DEFAULT" };
  }
  return { mode: "UNIFIED", source: "FALLBACK_UNIFIED" };
}
