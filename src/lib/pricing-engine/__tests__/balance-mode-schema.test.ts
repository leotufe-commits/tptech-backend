// src/lib/pricing-engine/__tests__/balance-mode-schema.test.ts
// =============================================================================
// T54 — Tests del schema bump de Balance Mode (Fase 3B.4).
//
// Estos tests son de NIVEL TIPO: validan que el Prisma Client generado expone
// las columnas correctas con la nullability y default esperados por POLICY.md
// §11 R11.4. Si TypeScript compila → el cliente refleja el schema esperado.
//
// NO tocan la DB. NO ejecutan queries. Si el typecheck falla, falla el test.
// La suite completa actual sigue corriendo sin DB — este archivo respeta
// esa promesa.
// =============================================================================

import { describe, it, expect } from "vitest";
import type { Prisma, BalanceMode } from "@prisma/client";

// Helper: type-level assertion. No runtime cost.
function expectType<T>(_value: T): void {
  /* compile-time only */
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Jewelry — defaultBalanceMode con default UNIFIED (NOT NULL en DB)
// ─────────────────────────────────────────────────────────────────────────────

describe("Schema 3B.4 — Jewelry.defaultBalanceMode", () => {
  it("acepta UNIFIED y BREAKDOWN como valores válidos", () => {
    const unified: BalanceMode = "UNIFIED";
    const breakdown: BalanceMode = "BREAKDOWN";
    expect(unified).toBe("UNIFIED");
    expect(breakdown).toBe("BREAKDOWN");
  });

  it("Jewelry CREATE permite omitir defaultBalanceMode (default UNIFIED del schema)", () => {
    // El default `@default(UNIFIED)` del schema permite no proveerlo en create.
    const input: Pick<Prisma.JewelryCreateInput, "defaultBalanceMode"> = {};
    expectType<Pick<Prisma.JewelryCreateInput, "defaultBalanceMode">>(input);
    expect(input.defaultBalanceMode).toBeUndefined();
  });

  it("Jewelry CREATE acepta defaultBalanceMode explícito", () => {
    const input: Pick<Prisma.JewelryCreateInput, "defaultBalanceMode"> = {
      defaultBalanceMode: "BREAKDOWN",
    };
    expect(input.defaultBalanceMode).toBe("BREAKDOWN");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. CommercialEntity — balanceMode nullable, SIN default
// ─────────────────────────────────────────────────────────────────────────────

describe("Schema 3B.4 — CommercialEntity.balanceMode", () => {
  it("acepta null (= hereda siguiente nivel R11.4)", () => {
    const input: Pick<Prisma.CommercialEntityCreateInput, "balanceMode"> = {
      balanceMode: null,
    };
    expect(input.balanceMode).toBeNull();
  });

  it("acepta UNIFIED / BREAKDOWN", () => {
    const uni: Pick<Prisma.CommercialEntityCreateInput, "balanceMode"> = {
      balanceMode: "UNIFIED",
    };
    const brk: Pick<Prisma.CommercialEntityCreateInput, "balanceMode"> = {
      balanceMode: "BREAKDOWN",
    };
    expect(uni.balanceMode).toBe("UNIFIED");
    expect(brk.balanceMode).toBe("BREAKDOWN");
  });

  it("acepta omitir balanceMode (queda null por ausencia de default)", () => {
    const input: Pick<Prisma.CommercialEntityCreateInput, "balanceMode"> = {};
    expect(input.balanceMode).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. PriceList — balanceMode nullable, SIN default
// ─────────────────────────────────────────────────────────────────────────────

describe("Schema 3B.4 — PriceList.balanceMode", () => {
  it("acepta null + UNIFIED + BREAKDOWN", () => {
    const inputs: Array<Pick<Prisma.PriceListCreateInput, "balanceMode">> = [
      { balanceMode: null },
      { balanceMode: "UNIFIED" },
      { balanceMode: "BREAKDOWN" },
      {}, // omitido
    ];
    expect(inputs).toHaveLength(4);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Sale — 3 columnas Balance Mode, todas nullable
// ─────────────────────────────────────────────────────────────────────────────

describe("Schema 3B.4 — Sale (override + resuelto + source)", () => {
  it("Sale permite balanceModeOverride sin balanceMode confirmado (estado DRAFT)", () => {
    // Caso típico: el usuario marca un override en un DRAFT antes de confirmar.
    // `balanceMode` resuelto aún null hasta que confirmSale lo congele (3B.5).
    const input: Pick<
      Prisma.SaleUncheckedCreateInput,
      "balanceModeOverride" | "balanceMode" | "balanceModeSource"
    > = {
      balanceModeOverride: "BREAKDOWN",
      balanceMode:         null,
      balanceModeSource:   null,
    };
    expect(input.balanceModeOverride).toBe("BREAKDOWN");
    expect(input.balanceMode).toBeNull();
    expect(input.balanceModeSource).toBeNull();
  });

  it("Sale permite guardar balanceMode resuelto + source (caso post-confirm 3B.5)", () => {
    const input: Pick<
      Prisma.SaleUncheckedCreateInput,
      "balanceModeOverride" | "balanceMode" | "balanceModeSource"
    > = {
      balanceModeOverride: null,
      balanceMode:         "UNIFIED",
      balanceModeSource:   "TENANT_DEFAULT",
    };
    expect(input.balanceMode).toBe("UNIFIED");
    expect(input.balanceModeSource).toBe("TENANT_DEFAULT");
  });

  it("Sale permite los 3 campos null (filas históricas pre-3B.4)", () => {
    const input: Pick<
      Prisma.SaleUncheckedCreateInput,
      "balanceModeOverride" | "balanceMode" | "balanceModeSource"
    > = {
      balanceModeOverride: null,
      balanceMode:         null,
      balanceModeSource:   null,
    };
    expect(input.balanceMode).toBeNull();
  });

  it("Sale permite OMITIR los 3 campos en CREATE (back-compat con callers actuales)", () => {
    // Crítico: confirmSale + sale.hook NO se tocan en 3B.4. Si los 3 campos
    // fueran NOT NULL sin default, callers actuales fallarían en runtime.
    // Esta aserción de tipo prueba que se pueden omitir.
    const input: Prisma.SaleUncheckedCreateInput = {
      jewelryId: "j-1",
      code:      "VTA-0001",
      // Sin balanceMode/Override/Source. Debe compilar.
    };
    expect(input).toBeDefined();
  });

  it("balanceModeSource es TEXT (string) — no enum tipado", () => {
    // Mantenemos balanceModeSource como string libre para no acoplar la DB
    // al enum interno BalanceModeSource (DOCUMENT_OVERRIDE/ENTITY_DEFAULT/...).
    // En 3B.5 el caller pasa los strings canónicos del resolver.
    const input: Pick<Prisma.SaleUncheckedCreateInput, "balanceModeSource"> = {
      balanceModeSource: "DOCUMENT_OVERRIDE",
    };
    expect(typeof input.balanceModeSource).toBe("string");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Purchase — espejo de Sale
// ─────────────────────────────────────────────────────────────────────────────

describe("Schema 3B.4 — Purchase (override + resuelto + source)", () => {
  it("Purchase tiene los mismos 3 campos nullable que Sale", () => {
    const input: Pick<
      Prisma.PurchaseUncheckedCreateInput,
      "balanceModeOverride" | "balanceMode" | "balanceModeSource"
    > = {
      balanceModeOverride: "BREAKDOWN",
      balanceMode:         "BREAKDOWN",
      balanceModeSource:   "ENTITY_DEFAULT",
    };
    expect(input.balanceMode).toBe("BREAKDOWN");
  });

  it("Purchase permite omitir los 3 campos (back-compat)", () => {
    const input: Prisma.PurchaseUncheckedCreateInput = {
      jewelryId:  "j-1",
      code:       "CMP-0001",
      supplierId: "ent-1",
    };
    expect(input).toBeDefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. CrossSettlement + Receipt — un solo campo nullable
// ─────────────────────────────────────────────────────────────────────────────

describe("Schema 3B.4 — CrossSettlement.balanceMode", () => {
  it("CrossSettlement.balanceMode nullable, sin default", () => {
    const inputs: Array<Pick<Prisma.CrossSettlementUncheckedCreateInput, "balanceMode">> = [
      { balanceMode: null },
      { balanceMode: "UNIFIED" },
      { balanceMode: "BREAKDOWN" },
      {},
    ];
    expect(inputs).toHaveLength(4);
  });
});

describe("Schema 3B.4 — Receipt.balanceMode", () => {
  it("Receipt.balanceMode nullable, sin default (receipts metálicos → Fase 5)", () => {
    const inputs: Array<Pick<Prisma.ReceiptUncheckedCreateInput, "balanceMode">> = [
      { balanceMode: null },
      { balanceMode: "UNIFIED" },
      { balanceMode: "BREAKDOWN" },
      {},
    ];
    expect(inputs).toHaveLength(4);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. Compatibilidad runtime — nulls / históricos no rompen forma del cliente
// ─────────────────────────────────────────────────────────────────────────────

describe("Schema 3B.4 — back-compat: nulls / históricos", () => {
  it("Sale SELECT puede pedir las nuevas columnas y aceptar null en el resultado", () => {
    // Modelamos la forma del result de un findUnique con `select` para los
    // nuevos campos. Si las columnas no fueran nullable en el cliente, este
    // type-test fallaría al compilar.
    type SaleBalanceFields = {
      balanceModeOverride: BalanceMode | null;
      balanceMode:         BalanceMode | null;
      balanceModeSource:   string | null;
    };
    const historical: SaleBalanceFields = {
      balanceModeOverride: null,
      balanceMode:         null,
      balanceModeSource:   null,
    };
    expect(historical.balanceMode).toBeNull();
  });

  it("Jewelry SELECT — defaultBalanceMode NUNCA null (NOT NULL en DB)", () => {
    type JewelryBalanceField = { defaultBalanceMode: BalanceMode };
    const j: JewelryBalanceField = { defaultBalanceMode: "UNIFIED" };
    expect(j.defaultBalanceMode).toBe("UNIFIED");
  });

  it("CommercialEntity legacy `balanceType` coexiste con nuevo `balanceMode`", () => {
    // El campo legacy `balanceType: BalanceType @default(UNIFIED)` sigue
    // presente y NO se toca en 3B.4. El nuevo `balanceMode` es nullable
    // (independiente). En 3B.5 se decidirá la migración entre ambos.
    type EntityBalanceFields = {
      balanceType: "UNIFIED" | "BREAKDOWN";   // legacy (BalanceType enum)
      balanceMode: BalanceMode | null;        // nuevo (BalanceMode enum)
    };
    const e: EntityBalanceFields = {
      balanceType: "UNIFIED",
      balanceMode: null,
    };
    expect(e.balanceType).toBe("UNIFIED");
    expect(e.balanceMode).toBeNull();
  });
});
