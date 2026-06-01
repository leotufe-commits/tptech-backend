// src/lib/pricing-engine/__tests__/metal-hechura.test.ts
// Tests para applyPriceList en modo METAL_HECHURA

import { describe, it, expect } from "vitest";
import { applyPriceList } from "../pricing-engine.pricelist.js";
import { Prisma } from "@prisma/client";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makePriceList(overrides: Record<string, any> = {}) {
  return {
    id:               "pl-1",
    name:             "Lista Test",
    mode:             "METAL_HECHURA",
    marginTotal:      null,
    marginMetal:      "20",
    marginHechura:    "30",
    costPerGram:      null,
    surcharge:        null,
    minimumPrice:     null,
    roundingTarget:   "NONE",
    roundingMode:     "NONE",
    roundingDirection:"NEAREST",
    validFrom:        null,
    validTo:          null,
    isActive:         true,
    ...overrides,
  };
}

function D(v: number | string) {
  return new Prisma.Decimal(String(v));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("applyPriceList — METAL_HECHURA", () => {

  it("calcula metalSale y hechuraSale con los márgenes correctos", () => {
    const pl   = makePriceList({ marginMetal: "20", marginHechura: "30" });
    const cost = { value: D(1300), metalCost: D(1000), hechuraCost: D(300) };

    const result = applyPriceList(pl as any, cost);

    // metalSale   = 1000 * 1.20 = 1200
    // hechuraSale = 300  * 1.30 = 390
    // total       = 1590
    expect(result.value?.toNumber()).toBeCloseTo(1590, 2);
    expect(result.partial).toBe(false);
    expect(result.metalHechuraDetail).not.toBeNull();
    expect(result.metalHechuraDetail!.metalCost).toBeCloseTo(1000, 4);
    expect(result.metalHechuraDetail!.metalSale).toBeCloseTo(1200, 4);
    expect(result.metalHechuraDetail!.metalMarginPct).toBe(20);
    expect(result.metalHechuraDetail!.hechuraCost).toBeCloseTo(300, 4);
    expect(result.metalHechuraDetail!.hechuraSale).toBeCloseTo(390, 4);
    expect(result.metalHechuraDetail!.hechuraMarginPct).toBe(30);
  });

  it("funciona cuando metalCost=0 (artículo sin metal)", () => {
    const pl   = makePriceList({ marginMetal: "20", marginHechura: "40" });
    const cost = { value: D(500), metalCost: D(0), hechuraCost: D(500) };

    const result = applyPriceList(pl as any, cost);

    // metalSale   = 0   * 1.20 = 0
    // hechuraSale = 500 * 1.40 = 700
    expect(result.value?.toNumber()).toBeCloseTo(700, 2);
    expect(result.partial).toBe(false);
    expect(result.metalHechuraDetail!.metalSale).toBeCloseTo(0, 4);
    expect(result.metalHechuraDetail!.hechuraSale).toBeCloseTo(700, 4);
  });

  it("funciona cuando hechuraCost=0 (artículo solo metal)", () => {
    const pl   = makePriceList({ marginMetal: "25", marginHechura: "30" });
    const cost = { value: D(800), metalCost: D(800), hechuraCost: D(0) };

    const result = applyPriceList(pl as any, cost);

    // metalSale   = 800 * 1.25 = 1000
    // hechuraSale = 0   * 1.30 = 0
    expect(result.value?.toNumber()).toBeCloseTo(1000, 2);
    expect(result.metalHechuraDetail!.metalSale).toBeCloseTo(1000, 4);
    expect(result.metalHechuraDetail!.hechuraSale).toBeCloseTo(0, 4);
  });

  it("cae a modo parcial cuando no hay desglose (solo value)", () => {
    const pl   = makePriceList({ marginMetal: "20", marginHechura: "30" });
    const cost = { value: D(1000), metalCost: null, hechuraCost: null };

    const result = applyPriceList(pl as any, cost);

    // Fallback: usa marginHechura sobre el costo total → 1000 * 1.30 = 1300
    expect(result.partial).toBe(true);
    expect(result.value?.toNumber()).toBeCloseTo(1300, 2);
    // Sin desglose disponible
    expect(result.metalHechuraDetail).toBeUndefined();
  });

  it("devuelve null cuando no hay costo disponible", () => {
    const pl   = makePriceList({ marginMetal: "20", marginHechura: "30" });
    const cost = { value: null, metalCost: null, hechuraCost: null };

    const result = applyPriceList(pl as any, cost);

    expect(result.value).toBeNull();
    expect(result.partial).toBe(true);
  });

  // ───────────────────────────────────────────────────────────────────────
  // BUG REPORTADO (2026-05-28) — Rounding desglosado no aplica
  //
  // Reporte del usuario: lista en modo "Metal+Hechura desglosado" con
  // configuración Metal=INTEGER/NEAREST + Hechura=HUNDRED/NEAREST +
  // applyOn=TOTAL. Resultado visible Hechura=59.384,06 (sin redondear),
  // esperado 59.400 si HUNDRED se aplicara.
  //
  // Estos tests reproducen el escenario en aislamiento del motor para
  // determinar si el bug está en `applyPriceList` o más arriba en la cadena
  // (cost del artículo / mapping / frontend).
  // ───────────────────────────────────────────────────────────────────────

  it("BUG-RPT — METAL_HECHURA + roundingTarget=METAL + applyOn=TOTAL: rounding POR COMPONENTE se aplica (cost con desglose)", () => {
    const pl = makePriceList({
      marginMetal:    "18.77",
      marginHechura:  "18.77",
      roundingTarget: "METAL",
      // Metal: INTEGER NEAREST.
      roundingMode:      "INTEGER",
      roundingDirection: "NEAREST",
      // Hechura: HUNDRED NEAREST.
      roundingModeHechura:      "HUNDRED",
      roundingDirectionHechura: "NEAREST",
      // ★ Caso reportado: applyOn=TOTAL — no debe suprimir el rounding
      // por componente (que opera en CAPA 2 del pipeline, independiente
      // del momento de aplicación al total).
      roundingApplyOn: "TOTAL",
    });
    const cost = {
      value:       D(100000),
      metalCost:   D(50000),
      hechuraCost: D(50000),
    };

    const result = applyPriceList(pl as any, cost);

    // metalSale   = 50000 × 1.1877 = 59385 → INTEGER NEAREST → 59385
    // hechuraSale = 50000 × 1.1877 = 59385 → HUNDRED  NEAREST → 59400
    expect(result.metalHechuraDetail).toBeDefined();
    expect(result.metalHechuraDetail!.hechuraSale).toBeCloseTo(59400, 0);
    expect(result.metalHechuraDetail!.metalSale).toBeCloseTo(59385, 0);
    // Total = suma de componentes redondeados.
    expect(result.value!.toNumber()).toBeCloseTo(59385 + 59400, 0);
  });

  it("BUG-RPT — escenario exacto del usuario (Hechura sola redondea a centena)", () => {
    // metal=0 (sin metal), hechura=50000 con margen 18.77%.
    // hechuraSale crudo = 50000 × 1.1877 = 59385 → HUNDRED → 59400.
    const pl = makePriceList({
      marginMetal:              "0",
      marginHechura:            "18.77",
      roundingTarget:           "METAL",
      roundingMode:             "NONE",       // metal sin rounding
      roundingDirection:        "NEAREST",
      roundingModeHechura:      "HUNDRED",
      roundingDirectionHechura: "NEAREST",
      roundingApplyOn:          "TOTAL",
    });
    const cost = {
      value:       D(50000),
      metalCost:   D(0),
      hechuraCost: D(50000),
    };
    const result = applyPriceList(pl as any, cost);
    expect(result.metalHechuraDetail!.hechuraSale).toBeCloseTo(59400, 0);
    expect(result.value!.toNumber()).toBeCloseTo(59400, 0);
  });

  // ───────────────────────────────────────────────────────────────────────
  // FIX 2026-05-28 — Fallback de rounding cuando target=METAL pero el cost
  // del artículo NO tiene desglose.
  //
  // Antes: si `cost.metalCost`/`hechuraCost` venían null (artículo legacy /
  // MULTIPLIER / MANUAL), el motor caía a la rama "partial" línea 336 y NI
  // el bloque de rounding por componente (284-292) NI el bloque final
  // (369-389, que solo aplica para FINAL_PRICE) actuaban → ningún rounding.
  //
  // Ahora: la rama defensiva agrega `applyRounding(rawPrice, roundingModeHechura)`
  // como fallback cuando se cumplen las 3 condiciones (target=METAL, sin
  // metalHechuraDetail, hechura mode efectivo). El operador ve el rounding
  // configurado aunque el artículo no tenga desglose explícito.
  // ───────────────────────────────────────────────────────────────────────

  it("FIX — cost SIN desglose + roundingTarget=METAL: rounding se aplica como fallback usando modo de hechura", () => {
    const pl = makePriceList({
      marginMetal:              "18.77",
      marginHechura:            "18.77",
      roundingTarget:           "METAL",
      roundingMode:             "INTEGER",
      roundingDirection:        "NEAREST",
      roundingModeHechura:      "HUNDRED",
      roundingDirectionHechura: "NEAREST",
      roundingApplyOn:          "TOTAL",
    });
    // Cost SIN desglose — artículo legacy / MULTIPLIER / MANUAL.
    const cost = {
      value:       D(50000),
      metalCost:   null,
      hechuraCost: null,
    };
    const result = applyPriceList(pl as any, cost);
    // Rama partial: usa marginHechura sobre el total → 50000 × 1.1877 = 59385.
    // Fallback aplica HUNDRED NEAREST → 59400.
    expect(result.partial).toBe(true);
    expect(result.value!.toNumber()).toBeCloseTo(59400, 0);
    // metalHechuraDetail sigue undefined en esta rama (no hay desglose).
    expect(result.metalHechuraDetail).toBeUndefined();
    // preRounding se captura porque el rounding movió el valor.
    expect(result.preRounding).toBeDefined();
    expect(result.preRounding!.toNumber()).toBeCloseTo(59385, 0);
  });

  it("FIX — fallback NO se ejecuta cuando cost SÍ tiene desglose (no duplica el rounding)", () => {
    const pl = makePriceList({
      marginMetal:              "18.77",
      marginHechura:            "18.77",
      roundingTarget:           "METAL",
      roundingMode:             "INTEGER",
      roundingDirection:        "NEAREST",
      roundingModeHechura:      "HUNDRED",
      roundingDirectionHechura: "NEAREST",
      roundingApplyOn:          "TOTAL",
    });
    const cost = {
      value:       D(100000),
      metalCost:   D(50000),
      hechuraCost: D(50000),
    };
    const result = applyPriceList(pl as any, cost);
    // metalSale 59385 (INTEGER) + hechuraSale 59400 (HUNDRED) = 118785.
    // El fallback NO debe sumar otro HUNDRED sobre el total (no duplicación).
    expect(result.metalHechuraDetail).toBeDefined();
    expect(result.value!.toNumber()).toBeCloseTo(118785, 0);
    // El total NO debe ser 118800 (que sería redondear otra vez a centena).
    expect(result.value!.toNumber()).not.toBeCloseTo(118800, 0);
  });

  it("FIX — fallback respeta hechura=NONE (sin rounding configurado)", () => {
    const pl = makePriceList({
      marginMetal:              "18.77",
      marginHechura:            "18.77",
      roundingTarget:           "METAL",
      roundingMode:             "INTEGER",
      roundingDirection:        "NEAREST",
      roundingModeHechura:      "NONE",        // ← hechura sin rounding
      roundingDirectionHechura: "NEAREST",
      roundingApplyOn:          "TOTAL",
    });
    const cost = { value: D(50000), metalCost: null, hechuraCost: null };
    const result = applyPriceList(pl as any, cost);
    // Sin modo de hechura efectivo, el fallback NO actúa.
    expect(result.value!.toNumber()).toBeCloseTo(59385, 0);
    expect(result.preRounding).toBeUndefined();
  });

  // ───────────────────────────────────────────────────────────────────────
  // FIX DEFENSIVO 2026-05-28 — Coherencia interna `effectiveTarget`.
  //
  // Listas migradas / con drift legacy pueden persistir
  // `mode = METAL_HECHURA` + `roundingTarget = FINAL_PRICE` (combinación
  // inconsistente — el form del frontend la corrige al guardar, pero
  // listas viejas pueden no haber pasado por el form).
  //
  // El motor ahora normaliza runtime: cuando `mode === "METAL_HECHURA"`
  // y `roundingTarget !== "NONE"`, fuerza `effectiveTarget = "METAL"`.
  // Esto garantiza que el rounding por componente SIEMPRE se ejecute en
  // modo desglosado.
  //
  // Sin doble rounding: el bloque "final rounding" se salta porque
  // `effectiveTarget !== "FINAL_PRICE"`, evitando que se aplique el
  // rounding del agregado además del rounding por componente.
  // ───────────────────────────────────────────────────────────────────────

  it("FIX-DEFENSIVO — lista legacy METAL_HECHURA + roundingTarget=FINAL_PRICE redondea hechura como METAL", () => {
    const pl = makePriceList({
      mode:                     "METAL_HECHURA",
      marginMetal:              "18.77",
      marginHechura:            "18.77",
      roundingTarget:           "FINAL_PRICE",  // ← DRIFT legacy
      roundingMode:             "INTEGER",
      roundingDirection:        "NEAREST",
      roundingModeHechura:      "HUNDRED",
      roundingDirectionHechura: "NEAREST",
      roundingApplyOn:          "TOTAL",
    });
    const cost = {
      value:       D(100000),
      metalCost:   D(50000),
      hechuraCost: D(50000),
    };
    const result = applyPriceList(pl as any, cost);

    // A pesar del `roundingTarget=FINAL_PRICE` persistido, el motor normaliza
    // a METAL (por el mode METAL_HECHURA) y aplica el rounding por componente.
    // hechura 59385 → HUNDRED NEAREST → 59400.
    expect(result.metalHechuraDetail).toBeDefined();
    expect(result.metalHechuraDetail!.hechuraSale).toBeCloseTo(59400, 0);
    expect(result.metalHechuraDetail!.metalSale).toBeCloseTo(59385, 0);
    // Total = suma de componentes redondeados.
    expect(result.value!.toNumber()).toBeCloseTo(118785, 0);
  });

  it("FIX-DEFENSIVO — lista MARGIN_TOTAL + FINAL_PRICE sigue funcionando (no se toca el caso unificado)", () => {
    const pl = makePriceList({
      mode:                     "MARGIN_TOTAL",
      marginTotal:              "18.77",
      roundingTarget:           "FINAL_PRICE",  // ← config correcta para unificado
      roundingMode:             "HUNDRED",
      roundingDirection:        "NEAREST",
      // Para unificado el form usa los campos *Hechura* como bind único.
      roundingModeHechura:      "HUNDRED",
      roundingDirectionHechura: "NEAREST",
      roundingApplyOn:          "PRICE",
    });
    const cost = { value: D(400000), metalCost: null, hechuraCost: null };
    const result = applyPriceList(pl as any, cost);

    // 400000 × 1.1877 = 475080 → HUNDRED NEAREST → 475100 (PRICE: aplicado acá).
    expect(result.value!.toNumber()).toBeCloseTo(475100, 0);
    // metalHechuraDetail no se popula para MARGIN_TOTAL sin desglose.
    expect(result.metalHechuraDetail).toBeUndefined();
  });

  it("FIX-DEFENSIVO — METAL_HECHURA + roundingTarget=NONE NO se altera (sin rounding configurado)", () => {
    const pl = makePriceList({
      mode:                     "METAL_HECHURA",
      marginMetal:              "10",
      marginHechura:            "10",
      roundingTarget:           "NONE",          // ← operador desactivó rounding
      roundingMode:             "NONE",
      roundingDirection:        "NEAREST",
      roundingModeHechura:      "NONE",
      roundingDirectionHechura: "NEAREST",
    });
    const cost = {
      value:       D(1000),
      metalCost:   D(500),
      hechuraCost: D(500),
    };
    const result = applyPriceList(pl as any, cost);
    // Sin rounding configurado, los valores no se modifican.
    // 500 × 1.10 = 550 cada componente. Total 1100. Sin rounding.
    expect(result.value!.toNumber()).toBeCloseTo(1100, 2);
    expect(result.metalHechuraDetail!.metalSale).toBeCloseTo(550, 2);
    expect(result.metalHechuraDetail!.hechuraSale).toBeCloseTo(550, 2);
  });

  it("FIX-DEFENSIVO — anti doble-rounding: METAL_HECHURA con drift NO aplica rounding final (solo por componente)", () => {
    // Sanity check: con drift legacy, el motor normaliza a METAL pero NO
    // ejecuta el bloque final de rounding (que rondea el agregado). Eso
    // evita doble rounding (componente + agregado).
    const pl = makePriceList({
      mode:                     "METAL_HECHURA",
      marginMetal:              "20",
      marginHechura:            "20",
      roundingTarget:           "FINAL_PRICE",  // ← drift
      roundingMode:             "INTEGER",
      roundingDirection:        "NEAREST",
      roundingModeHechura:      "INTEGER",
      roundingDirectionHechura: "NEAREST",
      roundingApplyOn:          "PRICE",
    });
    const cost = {
      value:       D(2000),
      metalCost:   D(1000),
      hechuraCost: D(1000),
    };
    const result = applyPriceList(pl as any, cost);
    // metalSale 1000 × 1.20 = 1200 → INTEGER → 1200
    // hechuraSale 1000 × 1.20 = 1200 → INTEGER → 1200
    // Total = 2400. NO se aplica rounding adicional al total (sin doble).
    expect(result.value!.toNumber()).toBeCloseTo(2400, 0);
    expect(result.preRounding).toBeUndefined();
  });

});
