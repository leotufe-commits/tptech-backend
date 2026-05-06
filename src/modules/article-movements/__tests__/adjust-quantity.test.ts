// src/modules/article-movements/__tests__/adjust-quantity.test.ts
//
// Verifica las reglas de cantidad por tipo de movimiento en createArticleMovement.
//
// Invariantes:
//   - ADJUST quantity=0  → error antes de tocar la BD
//   - ADJUST quantity>0  → pasa validación de cantidad
//   - ADJUST quantity<0  → pasa validación de cantidad
//   - IN / OUT / OPENING quantity<=0 → error
//   - IN / OUT / OPENING quantity>0  → pasa validación de cantidad

import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mock de Prisma ───────────────────────────────────────────────────────────
// Las validaciones de cantidad ocurren ANTES de prisma.$transaction,
// por lo que el mock solo necesita existir para que el import no falle.

const mockPrisma = vi.hoisted(() => ({
  $transaction: vi.fn(),
}));

vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

// Silenciar el import de stock-engine (no se llama en validaciones pre-tx)
vi.mock("../../../lib/stock-engine.js", () => ({
  validateStockLineIntegrity: vi.fn(),
  applyMovementImpact:        vi.fn(),
  reverseMovementImpact:      vi.fn(),
}));

import { createArticleMovement } from "../article-movements.service.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

const BASE_OPTS = {
  jewelryId:   "j-1",
  userId:      "u-1",
  warehouseId: "wh-1",
  effectiveAt: new Date(),
  note:        "",
} as const;

/** Opts para ADJUST con una sola línea */
function adjustOpts(quantity: string) {
  return {
    ...BASE_OPTS,
    kind: "ADJUST" as const,
    lines: [{ articleId: "a-1", quantity }],
  };
}

/** Opts para tipos no-ADJUST con una sola línea */
function nonAdjustOpts(kind: "IN" | "OUT" | "OPENING", quantity: string) {
  return {
    ...BASE_OPTS,
    kind,
    lines: [{ articleId: "a-1", quantity }],
  };
}

// ─── Setup ────────────────────────────────────────────────────────────────────

beforeEach(() => {
  vi.clearAllMocks();
  // Por defecto la transacción nunca se ejecuta para tests de validación pre-tx.
  // Si un test necesita que llegue a la tx, sobreescribe este mock.
  mockPrisma.$transaction.mockRejectedValue(new Error("tx no esperada en este test"));
});

// ─── A. ADJUST — reglas de cantidad ──────────────────────────────────────────

describe("ADJUST — validación de cantidad", () => {
  it("quantity=0 lanza error antes de la transacción", async () => {
    await expect(createArticleMovement(adjustOpts("0")))
      .rejects.toThrow("El delta de ajuste no puede ser 0.");

    // La transacción no debe haberse llamado
    expect(mockPrisma.$transaction).not.toHaveBeenCalled();
  });

  it("quantity='0.0000' (cero decimal) lanza error antes de la transacción", async () => {
    await expect(createArticleMovement(adjustOpts("0.0000")))
      .rejects.toThrow("El delta de ajuste no puede ser 0.");

    expect(mockPrisma.$transaction).not.toHaveBeenCalled();
  });

  it("quantity positiva pasa la validación de cantidad y llega a la transacción", async () => {
    // Hacemos que la tx lance algo distinto para saber que SÍ se llegó a ella
    mockPrisma.$transaction.mockRejectedValue(new Error("dentro-de-tx"));

    await expect(createArticleMovement(adjustOpts("10")))
      .rejects.toThrow("dentro-de-tx");

    expect(mockPrisma.$transaction).toHaveBeenCalledOnce();
  });

  it("quantity negativa pasa la validación de cantidad y llega a la transacción", async () => {
    mockPrisma.$transaction.mockRejectedValue(new Error("dentro-de-tx"));

    await expect(createArticleMovement(adjustOpts("-5")))
      .rejects.toThrow("dentro-de-tx");

    expect(mockPrisma.$transaction).toHaveBeenCalledOnce();
  });
});

// ─── B. IN / OUT / OPENING — reglas de cantidad no cambiadas ─────────────────

describe("IN — validación de cantidad (no regresión)", () => {
  it("quantity=0 lanza error antes de la transacción", async () => {
    await expect(createArticleMovement(nonAdjustOpts("IN", "0")))
      .rejects.toThrow("La cantidad debe ser mayor a 0.");

    expect(mockPrisma.$transaction).not.toHaveBeenCalled();
  });

  it("quantity negativa lanza error antes de la transacción", async () => {
    await expect(createArticleMovement(nonAdjustOpts("IN", "-1")))
      .rejects.toThrow("La cantidad debe ser mayor a 0.");

    expect(mockPrisma.$transaction).not.toHaveBeenCalled();
  });

  it("quantity positiva pasa la validación y llega a la transacción", async () => {
    mockPrisma.$transaction.mockRejectedValue(new Error("dentro-de-tx"));

    await expect(createArticleMovement(nonAdjustOpts("IN", "5")))
      .rejects.toThrow("dentro-de-tx");

    expect(mockPrisma.$transaction).toHaveBeenCalledOnce();
  });
});

describe("OUT — validación de cantidad (no regresión)", () => {
  it("quantity=0 lanza error antes de la transacción", async () => {
    await expect(createArticleMovement(nonAdjustOpts("OUT", "0")))
      .rejects.toThrow("La cantidad debe ser mayor a 0.");

    expect(mockPrisma.$transaction).not.toHaveBeenCalled();
  });

  it("quantity positiva pasa la validación y llega a la transacción", async () => {
    mockPrisma.$transaction.mockRejectedValue(new Error("dentro-de-tx"));

    await expect(createArticleMovement(nonAdjustOpts("OUT", "3")))
      .rejects.toThrow("dentro-de-tx");

    expect(mockPrisma.$transaction).toHaveBeenCalledOnce();
  });
});

describe("OPENING — validación de cantidad (no regresión)", () => {
  it("quantity=0 lanza error antes de la transacción", async () => {
    await expect(createArticleMovement(nonAdjustOpts("OPENING", "0")))
      .rejects.toThrow("La cantidad debe ser mayor a 0.");

    expect(mockPrisma.$transaction).not.toHaveBeenCalled();
  });

  it("quantity positiva pasa la validación y llega a la transacción", async () => {
    mockPrisma.$transaction.mockRejectedValue(new Error("dentro-de-tx"));

    await expect(createArticleMovement(nonAdjustOpts("OPENING", "100")))
      .rejects.toThrow("dentro-de-tx");

    expect(mockPrisma.$transaction).toHaveBeenCalledOnce();
  });
});

// ─── C. Líneas vacías — validación compartida ─────────────────────────────────

describe("Líneas vacías — validación independiente del kind", () => {
  it("sin líneas lanza error antes de la transacción", async () => {
    await expect(createArticleMovement({ ...BASE_OPTS, kind: "ADJUST", lines: [] }))
      .rejects.toThrow("Agregá al menos una línea.");

    expect(mockPrisma.$transaction).not.toHaveBeenCalled();
  });
});
