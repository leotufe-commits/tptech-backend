// src/lib/pricing-engine/__tests__/pricelist-validity.test.ts
// =============================================================================
// Tests para isPriceListValidNow — función canónica de validez de listas.
//
// Por qué importa:
//   isPriceListValidNow es la ÚNICA implementación de la lógica de vigencia
//   de listas de precios. Antes existía como función privada duplicada en dos
//   archivos: `isValidNow` en pricing-engine.pricelist.ts y `_isPLValidNow`
//   en articles.service.ts. Ahora hay una sola implementación exportada del barrel.
//
//   Si esta función diverge en algún caso de borde, los precios del listado
//   de artículos (batch) diferirían silenciosamente de los del simulador y
//   la venta (que usan resolvePriceList → isPriceListValidNow internamente).
//
// Esta función es pura — no requiere mock de Prisma.
// =============================================================================

import { describe, it, expect } from "vitest";
import { isPriceListValidNow } from "../pricing-engine.js";

// ---------------------------------------------------------------------------
// Helper — construye un PL con los campos mínimos relevantes
// ---------------------------------------------------------------------------

function pl(overrides: {
  isActive?: boolean;
  validFrom?: Date | null;
  validTo?:   Date | null;
} = {}) {
  return {
    isActive:  true,
    validFrom: null,
    validTo:   null,
    ...overrides,
  };
}

const PAST   = new Date(Date.now() - 86_400_000);   // ayer
const FUTURE = new Date(Date.now() + 86_400_000);   // mañana
const TWO_DAYS_AGO = new Date(Date.now() - 2 * 86_400_000);

// ---------------------------------------------------------------------------

describe("isPriceListValidNow — actividad", () => {
  it("activa sin fechas → válida", () => {
    expect(isPriceListValidNow(pl())).toBe(true);
  });

  it("isActive=false → inválida, independientemente de las fechas", () => {
    expect(isPriceListValidNow(pl({ isActive: false }))).toBe(false);
    expect(isPriceListValidNow(pl({ isActive: false, validFrom: PAST, validTo: FUTURE }))).toBe(false);
  });
});

describe("isPriceListValidNow — validFrom", () => {
  it("validFrom en el pasado → válida (ya comenzó)", () => {
    expect(isPriceListValidNow(pl({ validFrom: PAST }))).toBe(true);
  });

  it("validFrom en el futuro → inválida (aún no comenzó)", () => {
    expect(isPriceListValidNow(pl({ validFrom: FUTURE }))).toBe(false);
  });

  it("validFrom=null → sin restricción de inicio", () => {
    expect(isPriceListValidNow(pl({ validFrom: null }))).toBe(true);
  });
});

describe("isPriceListValidNow — validTo", () => {
  it("validTo en el futuro → válida (no venció)", () => {
    expect(isPriceListValidNow(pl({ validTo: FUTURE }))).toBe(true);
  });

  it("validTo en el pasado → inválida (vencida)", () => {
    expect(isPriceListValidNow(pl({ validTo: PAST }))).toBe(false);
  });

  it("validTo=null → sin restricción de vencimiento", () => {
    expect(isPriceListValidNow(pl({ validTo: null }))).toBe(true);
  });
});

describe("isPriceListValidNow — rango completo", () => {
  it("dentro del rango [ayer, mañana] → válida", () => {
    expect(isPriceListValidNow(pl({ validFrom: PAST, validTo: FUTURE }))).toBe(true);
  });

  it("rango pasado [2 días atrás, ayer] → inválida (vencida)", () => {
    expect(isPriceListValidNow(pl({ validFrom: TWO_DAYS_AGO, validTo: PAST }))).toBe(false);
  });

  it("rango futuro [mañana, mañana+1d] → inválida (aún no comenzó)", () => {
    const dayAfterTomorrow = new Date(Date.now() + 2 * 86_400_000);
    expect(isPriceListValidNow(pl({ validFrom: FUTURE, validTo: dayAfterTomorrow }))).toBe(false);
  });
});

describe("isPriceListValidNow — contrato de consistencia con batch pricing", () => {
  // Esta función reemplazó la función privada _isPLValidNow de articles.service.ts.
  // Los tests de arriba aseguran que la lógica es correcta.
  // Si la firma cambia, el uso en articles.service.ts y en pricing-engine.pricelist.ts
  // (via resolvePriceList) seguirá siendo coherente porque ambos usan la misma.

  it("el mismo PL inválido es rechazado independientemente del contexto que lo llame", () => {
    const expired = pl({ validTo: PAST });
    // Esta es la lógica que tantos _isPLValidNow privados verificaban por separado.
    // Ahora hay una sola fuente de verdad.
    expect(isPriceListValidNow(expired)).toBe(false);
  });

  it("el mismo PL válido es aceptado independientemente del contexto", () => {
    const active = pl({ validFrom: PAST, validTo: FUTURE });
    expect(isPriceListValidNow(active)).toBe(true);
  });
});
