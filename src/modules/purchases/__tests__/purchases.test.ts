// src/modules/purchases/__tests__/purchases.test.ts
// Tests unitarios del módulo de compras y balance de proveedores.
//
// Estrategia: testear la lógica de agregación de balance con datos mock,
// sin acceso real a base de datos.

import { describe, it, expect } from "vitest";
import { aggregateEntityBalance } from "../../commercial-entities/balance.utils.js";
import {
  buildBalanceBreakdownFromPrice,
  type PriceBreakdown,
  type BalanceBreakdown,
} from "../../../lib/pricing-engine/pricing-engine.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function D(v: number) {
  return { toString: () => v.toFixed(2) };
}

function makeEntry(
  amount: number,
  breakdown: BalanceBreakdown | null = null,
  voided = false
) {
  return {
    amount: D(amount),
    voidedAt: voided ? new Date() : null,
    breakdownSnapshot: breakdown,
  };
}

function metalBreakdown(
  metalId: string,
  gramsPure: number,
  hechura = 0,
  currency = "BASE"
): BalanceBreakdown {
  return {
    metals: [
      {
        metalId,
        variantId: `var-${metalId}`,
        gramsOriginal: gramsPure / 0.75,
        purity: 0.75,
        gramsPure,
      },
    ],
    hechura: { amount: hechura, currency },
  };
}

function hechuraOnlyBreakdown(amount: number, currency = "BASE"): BalanceBreakdown {
  return {
    metals: [],
    hechura: { amount, currency },
  };
}

/** Helper: extrae saldo de hechura para una moneda dada */
function hechuraFor(result: ReturnType<typeof aggregateEntityBalance>, currency = "BASE"): number {
  if (result.mode !== "BREAKDOWN") return 0;
  return result.hechura.byCurrency[currency] ?? 0;
}

// ---------------------------------------------------------------------------
// Test 1: Compra UNIFIED genera saldo monetario
// ---------------------------------------------------------------------------

describe("Compra UNIFIED", () => {
  it("genera saldo monetario correcto", () => {
    const entries = [makeEntry(50000, null), makeEntry(30000, null)];
    const result = aggregateEntityBalance(entries, "UNIFIED");
    expect(result.mode).toBe("UNIFIED");
    if (result.mode === "UNIFIED") {
      expect(result.amount).toBeCloseTo(80000, 2);
    }
  });
});

// ---------------------------------------------------------------------------
// Test 2: Compra BREAKDOWN genera metal + hechura
// ---------------------------------------------------------------------------

describe("Compra BREAKDOWN", () => {
  it("genera saldo metal + hechura correcto", () => {
    const breakdown1 = metalBreakdown("metal-gold", 5, 1000);
    const breakdown2 = metalBreakdown("metal-gold", 3, 500);
    const entries = [
      makeEntry(0, breakdown1),
      makeEntry(0, breakdown2),
    ];
    const result = aggregateEntityBalance(entries, "BREAKDOWN");
    expect(result.mode).toBe("BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      expect(result.metals.find((m) => m.metalId === "metal-gold")?.gramsPure).toBeCloseTo(8, 4);
      expect(hechuraFor(result, "BASE")).toBeCloseTo(1500, 2);
    }
  });
});

// ---------------------------------------------------------------------------
// Test 3: Pago en dinero reduce solo hechura (BREAKDOWN)
// ---------------------------------------------------------------------------

describe("Pago dinero en BREAKDOWN", () => {
  it("reduce solo la porción monetaria (hechura)", () => {
    const compraBreakdown = metalBreakdown("metal-gold", 5, 2000);
    const pagoBreakdown   = hechuraOnlyBreakdown(-1000); // pago de $1000

    const entries = [
      makeEntry(0, compraBreakdown),
      makeEntry(0, pagoBreakdown),
    ];

    const result = aggregateEntityBalance(entries, "BREAKDOWN");
    expect(result.mode).toBe("BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      // Metal no se toca
      expect(result.metals.find((m) => m.metalId === "metal-gold")?.gramsPure).toBeCloseTo(5, 4);
      // Hechura reducida
      expect(hechuraFor(result, "BASE")).toBeCloseTo(1000, 2);
    }
  });
});

// ---------------------------------------------------------------------------
// Test 4: Devolución de metal reduce solo gramos puros
// ---------------------------------------------------------------------------

describe("Devolución de metal", () => {
  it("reduce solo los gramos puros del metal correspondiente", () => {
    const compra = metalBreakdown("metal-gold", 10, 3000);
    // Devolución de 3 gramos puros de oro (negativo)
    const devolucion: BalanceBreakdown = {
      metals: [
        {
          metalId:       "metal-gold",
          variantId:     "var-metal-gold",
          gramsOriginal: 4,
          purity:        0.75,
          gramsPure:     -3,
        },
      ],
      hechura: { amount: 0, currency: "BASE" },
    };

    const entries = [makeEntry(0, compra), makeEntry(0, devolucion)];
    const result  = aggregateEntityBalance(entries, "BREAKDOWN");

    expect(result.mode).toBe("BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      expect(result.metals.find((m) => m.metalId === "metal-gold")?.gramsPure).toBeCloseTo(7, 4);
      expect(hechuraFor(result, "BASE")).toBeCloseTo(3000, 2);
    }
  });
});

// ---------------------------------------------------------------------------
// Test 5: Pago mixto reduce ambos
// ---------------------------------------------------------------------------

describe("Pago mixto", () => {
  it("reduce dinero Y metal simultáneamente", () => {
    const compra: BalanceBreakdown = {
      metals: [
        { metalId: "metal-gold", variantId: "v1", gramsOriginal: 10, purity: 0.75, gramsPure: 7.5 },
      ],
      hechura: { amount: 5000, currency: "BASE" },
    };

    // Pago mixto: $2000 dinero + 2g puros de oro
    const pagoMixto: BalanceBreakdown = {
      metals: [
        { metalId: "metal-gold", variantId: "v1", gramsOriginal: 2.67, purity: 0.75, gramsPure: -2 },
      ],
      hechura: { amount: -2000, currency: "BASE" },
    };

    const entries = [makeEntry(0, compra), makeEntry(0, pagoMixto)];
    const result  = aggregateEntityBalance(entries, "BREAKDOWN");

    expect(result.mode).toBe("BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      expect(result.metals.find((m) => m.metalId === "metal-gold")?.gramsPure).toBeCloseTo(5.5, 4);
      expect(hechuraFor(result, "BASE")).toBeCloseTo(3000, 2);
    }
  });
});

// ---------------------------------------------------------------------------
// Test 6: Cancelación revierte correctamente (entradas anuladas excluidas)
// ---------------------------------------------------------------------------

describe("Cancelación de compra", () => {
  it("excluye entradas anuladas del saldo", () => {
    const compra = metalBreakdown("metal-gold", 5, 1000);
    // La entrada de la compra cancelada está anulada
    const entries = [
      makeEntry(0, compra, true), // voidedAt != null → excluida
    ];

    const result = aggregateEntityBalance(entries, "BREAKDOWN");
    expect(result.mode).toBe("BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      expect(result.metals).toHaveLength(0);
      expect(Object.keys(result.hechura.byCurrency)).toHaveLength(0);
    }
  });

  it("revierte solo la compra cancelada, mantiene compras activas", () => {
    const compraActiva    = metalBreakdown("metal-gold", 8, 2000);
    const compraCancelada = metalBreakdown("metal-gold", 5, 1000);

    const entries = [
      makeEntry(0, compraActiva, false),  // activa
      makeEntry(0, compraCancelada, true), // anulada (cancelada)
    ];

    const result = aggregateEntityBalance(entries, "BREAKDOWN");
    expect(result.mode).toBe("BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      expect(result.metals.find((m) => m.metalId === "metal-gold")?.gramsPure).toBeCloseTo(8, 4);
      expect(hechuraFor(result, "BASE")).toBeCloseTo(2000, 2);
    }
  });
});

// ---------------------------------------------------------------------------
// Test 7: Múltiples compras + múltiples pagos → saldo neto correcto
// ---------------------------------------------------------------------------

describe("Múltiples compras y pagos", () => {
  it("calcula saldo neto correcto (UNIFIED)", () => {
    const entries = [
      makeEntry(100000),  // compra 1
      makeEntry(80000),   // compra 2
      makeEntry(-60000),  // pago 1
      makeEntry(-30000),  // pago 2
    ];
    const result = aggregateEntityBalance(entries, "UNIFIED");
    expect(result.mode).toBe("UNIFIED");
    if (result.mode === "UNIFIED") {
      expect(result.amount).toBeCloseTo(90000, 2);
    }
  });

  it("calcula saldo neto correcto (BREAKDOWN)", () => {
    const c1: BalanceBreakdown = {
      metals: [{ metalId: "Au", variantId: "v1", gramsOriginal: 10, purity: 0.75, gramsPure: 7.5 }],
      hechura: { amount: 3000, currency: "BASE" },
    };
    const c2: BalanceBreakdown = {
      metals: [{ metalId: "Au", variantId: "v1", gramsOriginal: 5, purity: 0.75, gramsPure: 3.75 }],
      hechura: { amount: 2000, currency: "BASE" },
    };
    const p1: BalanceBreakdown = {
      metals: [{ metalId: "Au", variantId: "v1", gramsOriginal: 4, purity: 0.75, gramsPure: -3 }],
      hechura: { amount: -1500, currency: "BASE" },
    };

    const entries = [
      makeEntry(0, c1),
      makeEntry(0, c2),
      makeEntry(0, p1),
    ];

    const result = aggregateEntityBalance(entries, "BREAKDOWN");
    expect(result.mode).toBe("BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      // 7.5 + 3.75 - 3 = 8.25
      expect(result.metals.find((m) => m.metalId === "Au")?.gramsPure).toBeCloseTo(8.25, 4);
      // 3000 + 2000 - 1500 = 3500
      expect(hechuraFor(result, "BASE")).toBeCloseTo(3500, 2);
    }
  });
});

// ---------------------------------------------------------------------------
// Test 8: Multi-metal agregado correcto
// ---------------------------------------------------------------------------

describe("Multi-metal", () => {
  it("agrega saldos de distintos metales correctamente", () => {
    const c1: BalanceBreakdown = {
      metals: [
        { metalId: "Au", variantId: "v1", gramsOriginal: 10, purity: 0.75, gramsPure: 7.5 },
        { metalId: "Ag", variantId: "v2", gramsOriginal: 50, purity: 0.925, gramsPure: 46.25 },
      ],
      hechura: { amount: 5000, currency: "BASE" },
    };
    const c2: BalanceBreakdown = {
      metals: [
        { metalId: "Au", variantId: "v1", gramsOriginal: 5, purity: 0.75, gramsPure: 3.75 },
      ],
      hechura: { amount: 2000, currency: "BASE" },
    };

    const entries = [makeEntry(0, c1), makeEntry(0, c2)];
    const result  = aggregateEntityBalance(entries, "BREAKDOWN");

    expect(result.mode).toBe("BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      expect(result.metals.find((m) => m.metalId === "Au")?.gramsPure).toBeCloseTo(11.25, 4);
      expect(result.metals.find((m) => m.metalId === "Ag")?.gramsPure).toBeCloseTo(46.25, 4);
      expect(hechuraFor(result, "BASE")).toBeCloseTo(7000, 2);
    }
  });
});

// ---------------------------------------------------------------------------
// Test adicional: buildBalanceBreakdownFromPrice funciona como fuente
// ---------------------------------------------------------------------------

describe("buildBalanceBreakdownFromPrice como fuente de breakdownSnapshot", () => {
  it("convierte PriceBreakdown a BalanceBreakdown correctamente", () => {
    const priceBreakdown: PriceBreakdown = {
      mode: "COST_LINES",
      metal: {
        items: [
          {
            metalId:       "metal-gold",
            variantId:     "variant-18k",
            gramsOriginal: 10,
            purity:        0.75,
            gramsPure:     7.5,
            unitValue:     5000,
            totalValue:    37500,
          },
        ],
        total: 37500,
      },
      hechura: {
        base: 2000,
        adjustments: [],
        total: 2000,
      },
      totals: {
        metal:   37500,
        hechura: 2000,
        unified: 39500,
      },
    };

    const result = buildBalanceBreakdownFromPrice(priceBreakdown);
    expect(result.metals).toHaveLength(1);
    expect(result.metals[0].metalId).toBe("metal-gold");
    expect(result.metals[0].gramsPure).toBeCloseTo(7.5, 4);
    expect(result.hechura.amount).toBeCloseTo(2000, 2);
  });
});

// ===========================================================================
// PHASE 3 — Overpayments, multimoneda, saldo a favor
// ===========================================================================

// ---------------------------------------------------------------------------
// Test P1: Overpayment en dinero genera saldo negativo
// ---------------------------------------------------------------------------

describe("Overpayment en dinero", () => {
  it("genera saldo de hechura negativo (crédito a favor)", () => {
    const compra = hechuraOnlyBreakdown(5000, "ARS");
    const pago   = hechuraOnlyBreakdown(-6000, "ARS"); // pagó de más

    const entries = [makeEntry(0, compra), makeEntry(0, pago)];
    const result  = aggregateEntityBalance(entries, "BREAKDOWN");

    expect(result.mode).toBe("BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      expect(hechuraFor(result, "ARS")).toBeCloseTo(-1000, 2);
    }
  });
});

// ---------------------------------------------------------------------------
// Test P2: Overpayment en metal genera gramos negativos
// ---------------------------------------------------------------------------

describe("Overpayment en metal", () => {
  it("genera gramsPure negativo cuando devuelven más metal del que deben", () => {
    const compra: BalanceBreakdown = {
      metals: [{ metalId: "Au", variantId: "v1", gramsOriginal: 5, purity: 0.75, gramsPure: 3.75 }],
      hechura: { amount: 0, currency: "BASE" },
    };
    // Devuelven 5g puros, pero solo debían 3.75g → crédito de 1.25g
    const devolucionExcesiva: BalanceBreakdown = {
      metals: [{ metalId: "Au", variantId: "v1", gramsOriginal: 6.67, purity: 0.75, gramsPure: -5 }],
      hechura: { amount: 0, currency: "BASE" },
    };

    const entries = [makeEntry(0, compra), makeEntry(0, devolucionExcesiva)];
    const result  = aggregateEntityBalance(entries, "BREAKDOWN");

    expect(result.mode).toBe("BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      expect(result.metals.find((m) => m.metalId === "Au")?.gramsPure).toBeCloseTo(-1.25, 4);
    }
  });
});

// ---------------------------------------------------------------------------
// Test P3: Multimoneda — ARS y USD se agrupan por separado
// ---------------------------------------------------------------------------

describe("Multimoneda hechura", () => {
  it("mantiene saldos ARS y USD independientes", () => {
    const compraARS: BalanceBreakdown = {
      metals: [],
      hechura: { amount: 10000, currency: "ARS" },
    };
    const compraUSD: BalanceBreakdown = {
      metals: [],
      hechura: { amount: 200, currency: "USD" },
    };
    const pagoARS: BalanceBreakdown = {
      metals: [],
      hechura: { amount: -4000, currency: "ARS" },
    };

    const entries = [
      makeEntry(0, compraARS),
      makeEntry(0, compraUSD),
      makeEntry(0, pagoARS),
    ];
    const result = aggregateEntityBalance(entries, "BREAKDOWN");

    expect(result.mode).toBe("BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      expect(hechuraFor(result, "ARS")).toBeCloseTo(6000, 2);
      expect(hechuraFor(result, "USD")).toBeCloseTo(200, 2);
      // BASE no debe existir
      expect(result.hechura.byCurrency["BASE"]).toBeUndefined();
    }
  });
});

// ---------------------------------------------------------------------------
// Test P4: Aplicación parcial de saldo a favor (MONEY)
// ---------------------------------------------------------------------------

describe("Aplicación parcial de crédito en dinero", () => {
  it("reduce el saldo negativo parcialmente", () => {
    // Situación: proveedor tiene crédito de -2000 ARS
    const compra = hechuraOnlyBreakdown(3000, "ARS");
    const pagoDeMas = hechuraOnlyBreakdown(-5000, "ARS"); // crédito: -2000
    // Aplica 1500 del crédito (entrada positiva)
    const aplicacionCredito = hechuraOnlyBreakdown(1500, "ARS");

    const entries = [
      makeEntry(0, compra),
      makeEntry(0, pagoDeMas),
      makeEntry(0, aplicacionCredito),
    ];
    const result = aggregateEntityBalance(entries, "BREAKDOWN");

    expect(result.mode).toBe("BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      // -2000 + 1500 = -500
      expect(hechuraFor(result, "ARS")).toBeCloseTo(-500, 2);
    }
  });
});

// ---------------------------------------------------------------------------
// Test P5: Aplicación parcial de saldo a favor (METAL)
// ---------------------------------------------------------------------------

describe("Aplicación parcial de crédito en metal", () => {
  it("reduce los gramos negativos parcialmente", () => {
    // Compra: 5g puros; devolución excesiva: -7g → crédito: -2g
    const compra: BalanceBreakdown = {
      metals: [{ metalId: "Au", variantId: "v1", gramsOriginal: 6.67, purity: 0.75, gramsPure: 5 }],
      hechura: { amount: 0, currency: "BASE" },
    };
    const devExcesiva: BalanceBreakdown = {
      metals: [{ metalId: "Au", variantId: "v1", gramsOriginal: 9.33, purity: 0.75, gramsPure: -7 }],
      hechura: { amount: 0, currency: "BASE" },
    };
    // Aplica 1.5g del crédito (positivo → consume crédito)
    const aplicacionCredito: BalanceBreakdown = {
      metals: [{ metalId: "Au", variantId: "v1", gramsOriginal: 2, purity: 0.75, gramsPure: 1.5 }],
      hechura: { amount: 0, currency: "BASE" },
    };

    const entries = [
      makeEntry(0, compra),
      makeEntry(0, devExcesiva),
      makeEntry(0, aplicacionCredito),
    ];
    const result = aggregateEntityBalance(entries, "BREAKDOWN");

    expect(result.mode).toBe("BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      // 5 - 7 + 1.5 = -0.5
      expect(result.metals.find((m) => m.metalId === "Au")?.gramsPure).toBeCloseTo(-0.5, 4);
    }
  });
});

// ---------------------------------------------------------------------------
// Test P6: Aplicaciones sucesivas agotan el crédito
// ---------------------------------------------------------------------------

describe("Aplicaciones sucesivas", () => {
  it("dos aplicaciones agotan el crédito completamente", () => {
    const compra       = hechuraOnlyBreakdown(2000, "ARS");
    const pagoDeMas    = hechuraOnlyBreakdown(-5000, "ARS"); // crédito: -3000
    const aplicacion1  = hechuraOnlyBreakdown(1000, "ARS"); // consume 1000 → -2000
    const aplicacion2  = hechuraOnlyBreakdown(2000, "ARS"); // consume 2000 → 0

    const entries = [
      makeEntry(0, compra),
      makeEntry(0, pagoDeMas),
      makeEntry(0, aplicacion1),
      makeEntry(0, aplicacion2),
    ];
    const result = aggregateEntityBalance(entries, "BREAKDOWN");

    expect(result.mode).toBe("BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      expect(hechuraFor(result, "ARS")).toBeCloseTo(0, 2);
      // byCurrency["ARS"] puede ser 0 o no existir (depende de cómo se limpie)
    }
  });
});

// ---------------------------------------------------------------------------
// Test P7: Crédito mixto — metal y dinero simultáneos
// ---------------------------------------------------------------------------

describe("Crédito mixto metal + dinero", () => {
  it("aplica crédito de metal y dinero en simultáneo", () => {
    const compra: BalanceBreakdown = {
      metals: [{ metalId: "Au", variantId: "v1", gramsOriginal: 10, purity: 0.75, gramsPure: 7.5 }],
      hechura: { amount: 4000, currency: "ARS" },
    };
    // Overpayment: paga más en dinero y devuelve más metal
    const overpayment: BalanceBreakdown = {
      metals: [{ metalId: "Au", variantId: "v1", gramsOriginal: 13.33, purity: 0.75, gramsPure: -10 }],
      hechura: { amount: -6000, currency: "ARS" },
    };
    // Aplica parte del crédito mixto
    const aplicacion: BalanceBreakdown = {
      metals: [{ metalId: "Au", variantId: "v1", gramsOriginal: 1.33, purity: 0.75, gramsPure: 1 }],
      hechura: { amount: 1000, currency: "ARS" },
    };

    const entries = [
      makeEntry(0, compra),
      makeEntry(0, overpayment),
      makeEntry(0, aplicacion),
    ];
    const result = aggregateEntityBalance(entries, "BREAKDOWN");

    expect(result.mode).toBe("BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      // 7.5 - 10 + 1 = -1.5
      expect(result.metals.find((m) => m.metalId === "Au")?.gramsPure).toBeCloseTo(-1.5, 4);
      // 4000 - 6000 + 1000 = -1000
      expect(hechuraFor(result, "ARS")).toBeCloseTo(-1000, 2);
    }
  });
});

// ---------------------------------------------------------------------------
// Test P8: Saldo neto después de múltiples operaciones multimoneda
// ---------------------------------------------------------------------------

describe("Saldo neto multimoneda complejo", () => {
  it("calcula correctamente con ARS, USD y metal en simultáneo", () => {
    const c1: BalanceBreakdown = {
      metals: [{ metalId: "Au", variantId: "v1", gramsOriginal: 10, purity: 0.75, gramsPure: 7.5 }],
      hechura: { amount: 5000, currency: "ARS" },
    };
    const c2: BalanceBreakdown = {
      metals: [],
      hechura: { amount: 300, currency: "USD" },
    };
    const p1: BalanceBreakdown = {
      metals: [{ metalId: "Au", variantId: "v1", gramsOriginal: 4, purity: 0.75, gramsPure: -3 }],
      hechura: { amount: -2000, currency: "ARS" },
    };
    const p2: BalanceBreakdown = {
      metals: [],
      hechura: { amount: -100, currency: "USD" },
    };
    const cred: BalanceBreakdown = {
      metals: [],
      hechura: { amount: 500, currency: "ARS" }, // aplicación de crédito ARS
    };

    const entries = [
      makeEntry(0, c1),
      makeEntry(0, c2),
      makeEntry(0, p1),
      makeEntry(0, p2),
      makeEntry(0, cred),
    ];
    const result = aggregateEntityBalance(entries, "BREAKDOWN");

    expect(result.mode).toBe("BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      // Au: 7.5 - 3 = 4.5
      expect(result.metals.find((m) => m.metalId === "Au")?.gramsPure).toBeCloseTo(4.5, 4);
      // ARS: 5000 - 2000 + 500 = 3500
      expect(hechuraFor(result, "ARS")).toBeCloseTo(3500, 2);
      // USD: 300 - 100 = 200
      expect(hechuraFor(result, "USD")).toBeCloseTo(200, 2);
    }
  });
});
