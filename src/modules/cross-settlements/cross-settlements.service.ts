// src/modules/cross-settlements/cross-settlements.service.ts
// Módulo de liquidaciones cruzadas entre componentes distintos de cuenta corriente.
// Ej: pago en USD cancela deuda en ARS, o pago en USD cancela deuda en metal Au.

import { prisma } from "../../lib/prisma.js";
import type { CrossSettlement } from "@prisma/client";
import type { BalanceBreakdown } from "../../lib/pricing-engine/pricing-engine.js";

// ---------------------------------------------------------------------------
// Tipos de input
// ---------------------------------------------------------------------------

export type CrossSettlementFromInput = {
  componentType: "MONEY" | "METAL";
  currency?: string;
  amount?: number;
  metalId?: string;
  variantId?: string;
  gramsOriginal?: number;
  purity?: number;
  gramsPure?: number;
};

export type CrossSettlementConversion = {
  fxRate?: number;
  metalQuotePerGram?: number;
  quoteCurrency?: string;
};

export type CrossSettlementInput = {
  supplierId: string;
  targetPurchaseId?: string | null;
  from: CrossSettlementFromInput;
  to: CrossSettlementFromInput;
  conversion: CrossSettlementConversion;
  notes?: string;
};

// ---------------------------------------------------------------------------
// Helper: describe un componente para mensajes de error y notas
// ---------------------------------------------------------------------------

function describeComponent(c: CrossSettlementFromInput): string {
  if (c.componentType === "MONEY") return c.currency ?? "MONEY";
  return `metal:${c.metalId ?? "?"}`;
}

// ---------------------------------------------------------------------------
// buildCrossSettlementEntries — función pura (testeable sin DB)
// ---------------------------------------------------------------------------

/**
 * Construye las dos entradas de cuenta corriente (entryA, entryB) para una
 * liquidación cruzada. No toca la base de datos.
 *
 * Convención de signo:
 *   + delta = deuda (nos deben / debemos)
 *   − delta = crédito (se entregó / canceló)
 *
 * Combinaciones válidas:
 *   MONEY → MONEY   → entry A: hechura [from.currency] -= from.amount
 *                     entry B: hechura [to.currency]   -= to.amount
 *   MONEY → METAL   → entry A: hechura [from.currency] -= from.amount
 *                     entry B: metal   [to.metalId]    -= to.gramsPure
 *   METAL → MONEY   → entry A: metal   [from.metalId]  -= from.gramsPure
 *                     entry B: hechura [to.currency]   -= to.amount
 *   METAL → METAL   → no implementado (lanza error)
 */
export function buildCrossSettlementEntries(
  input: CrossSettlementInput,
  settlementId: string,
): {
  entryA: { breakdownSnapshot: unknown; amount: number; currency: string; notes: string };
  entryB: { breakdownSnapshot: unknown; amount: number; currency: string; notes: string };
} {
  const { from, to } = input;

  // ── Validar combinación ────────────────────────────────────────────────────
  if (from.componentType === "METAL" && to.componentType === "METAL") {
    const err: any = new Error("Liquidación metal→metal no implementada.");
    err.status = 400;
    throw err;
  }

  // ── Validar que no sea el mismo componente contra sí mismo ─────────────────
  if (from.componentType === to.componentType) {
    if (
      from.componentType === "MONEY" &&
      from.currency != null &&
      from.currency === to.currency
    ) {
      const err: any = new Error(
        "No se puede liquidar un componente contra sí mismo.",
      );
      err.status = 400;
      throw err;
    }
    if (
      from.componentType === "METAL" &&
      from.metalId != null &&
      from.metalId === to.metalId
    ) {
      const err: any = new Error(
        "No se puede liquidar un componente contra sí mismo.",
      );
      err.status = 400;
      throw err;
    }
  }

  const fromDesc  = describeComponent(from);
  const toDesc    = describeComponent(to);
  const xsettle   = `XSETTLE-${settlementId}`;
  const notesA    = `Liquidación cruzada ${fromDesc} → ${toDesc} (${xsettle}): entregado`;
  const notesB    = `Liquidación cruzada ${fromDesc} → ${toDesc} (${xsettle}): cancelado`;

  // ── Construir snapshots según combinación ──────────────────────────────────
  let snapshotA: BalanceBreakdown;
  let snapshotB: BalanceBreakdown;

  if (from.componentType === "MONEY" && to.componentType === "MONEY") {
    // MONEY → MONEY: entregamos from.amount en from.currency (negativo = crédito)
    //                cancelamos  to.amount   en to.currency   (negativo = crédito)
    snapshotA = {
      metals: [],
      hechura: { amount: -(from.amount ?? 0), currency: from.currency ?? "BASE" },
    };
    snapshotB = {
      metals: [],
      hechura: { amount: -(to.amount ?? 0), currency: to.currency ?? "BASE" },
    };
  } else if (from.componentType === "MONEY" && to.componentType === "METAL") {
    // MONEY → METAL: entregamos dinero (hechura negativa), cancelamos deuda en metal
    snapshotA = {
      metals: [],
      hechura: { amount: -(from.amount ?? 0), currency: from.currency ?? "BASE" },
    };
    snapshotB = {
      metals: [
        {
          metalId:       to.metalId    ?? "",
          variantId:     to.variantId  ?? "",
          gramsOriginal: to.gramsOriginal ?? 0,
          purity:        to.purity     ?? 1,
          gramsPure:     -(to.gramsPure ?? 0),
        },
      ],
      hechura: { amount: 0, currency: "BASE" },
    };
  } else {
    // METAL → MONEY: entregamos metal (metal negativo), cancelamos deuda en dinero
    snapshotA = {
      metals: [
        {
          metalId:       from.metalId    ?? "",
          variantId:     from.variantId  ?? "",
          gramsOriginal: from.gramsOriginal ?? 0,
          purity:        from.purity     ?? 1,
          gramsPure:     -(from.gramsPure ?? 0),
        },
      ],
      hechura: { amount: 0, currency: "BASE" },
    };
    snapshotB = {
      metals: [],
      hechura: { amount: -(to.amount ?? 0), currency: to.currency ?? "BASE" },
    };
  }

  return {
    entryA: {
      breakdownSnapshot: snapshotA,
      amount:            0,
      currency:          from.currency ?? from.metalId ?? "BASE",
      notes:             notesA,
    },
    entryB: {
      breakdownSnapshot: snapshotB,
      amount:            0,
      currency:          to.currency ?? to.metalId ?? "BASE",
      notes:             notesB,
    },
  };
}

// ---------------------------------------------------------------------------
// Selección estándar de CrossSettlement para respuestas
// ---------------------------------------------------------------------------

const CROSS_SETTLEMENT_SELECT = {
  id:                true,
  jewelryId:         true,
  supplierId:        true,
  targetPurchaseId:  true,
  status:            true,
  fromComponentType: true,
  fromCurrency:      true,
  fromMetalId:       true,
  fromVariantId:     true,
  fromGramsOriginal: true,
  fromPurity:        true,
  fromGramsPure:     true,
  fromAmount:        true,
  toComponentType:   true,
  toCurrency:        true,
  toMetalId:         true,
  toVariantId:       true,
  toGramsOriginal:   true,
  toPurity:          true,
  toGramsPure:       true,
  toAmount:          true,
  fxRate:            true,
  metalQuotePerGram: true,
  quoteCurrency:     true,
  notes:             true,
  createdAt:         true,
  confirmedAt:       true,
  voidedAt:          true,
  voidReason:        true,
  createdById:       true,
  voidedById:        true,
} as const;

// ---------------------------------------------------------------------------
// registerCrossSettlement
// ---------------------------------------------------------------------------

export async function registerCrossSettlement(
  jewelryId: string,
  userId: string,
  input: CrossSettlementInput,
): Promise<CrossSettlement> {
  const { supplierId, targetPurchaseId, from, to, conversion, notes } = input;

  // 1. Cargar proveedor
  const supplier = await prisma.commercialEntity.findFirst({
    where: { id: supplierId, jewelryId, isSupplier: true, deletedAt: null },
    select: { id: true, balanceType: true },
  });
  if (!supplier) {
    const err: any = new Error("Proveedor no encontrado.");
    err.status = 404;
    throw err;
  }

  // 2. Validar balanceType
  if (supplier.balanceType !== "BREAKDOWN") {
    const err: any = new Error(
      "Las liquidaciones cruzadas solo están disponibles para proveedores con modo de saldo BREAKDOWN.",
    );
    err.status = 400;
    throw err;
  }

  // 3. Validar compra destino si se especificó
  if (targetPurchaseId) {
    const purchase = await prisma.purchase.findFirst({
      where: { id: targetPurchaseId, jewelryId, supplierId },
      select: { id: true, status: true },
    });
    if (!purchase) {
      const err: any = new Error("Compra destino no encontrada o no pertenece al proveedor.");
      err.status = 404;
      throw err;
    }
    if (purchase.status === "DRAFT") {
      const err: any = new Error("No se puede asociar una liquidación cruzada a una compra en borrador.");
      err.status = 400;
      throw err;
    }
  }

  // 4. Validar combinación llamando buildCrossSettlementEntries con un ID placeholder
  //    (se llama de nuevo dentro de la transacción con el ID real)
  buildCrossSettlementEntries(input, "validate-only");

  // 5. Transacción: crear CrossSettlement + 2 entradas de balance
  const settlement = await prisma.$transaction(async (tx) => {
    // Crear cabecera
    const cs = await tx.crossSettlement.create({
      data: {
        jewelryId,
        supplierId,
        targetPurchaseId: targetPurchaseId ?? null,
        status:           "CONFIRMED",
        confirmedAt:      new Date(),
        createdById:      userId,

        fromComponentType:  from.componentType,
        fromCurrency:       from.currency       ?? null,
        fromMetalId:        from.metalId        ?? null,
        fromVariantId:      from.variantId      ?? null,
        fromGramsOriginal:  from.gramsOriginal  != null ? from.gramsOriginal : null,
        fromPurity:         from.purity         != null ? from.purity        : null,
        fromGramsPure:      from.gramsPure      != null ? from.gramsPure     : null,
        fromAmount:         from.amount         != null ? from.amount        : null,

        toComponentType:  to.componentType,
        toCurrency:       to.currency       ?? null,
        toMetalId:        to.metalId        ?? null,
        toVariantId:      to.variantId      ?? null,
        toGramsOriginal:  to.gramsOriginal  != null ? to.gramsOriginal : null,
        toPurity:         to.purity         != null ? to.purity        : null,
        toGramsPure:      to.gramsPure      != null ? to.gramsPure     : null,
        toAmount:         to.amount         != null ? to.amount        : null,

        fxRate:            conversion.fxRate            != null ? conversion.fxRate            : null,
        metalQuotePerGram: conversion.metalQuotePerGram != null ? conversion.metalQuotePerGram : null,
        quoteCurrency:     conversion.quoteCurrency     ?? null,

        notes: notes ?? "",
      },
      select: CROSS_SETTLEMENT_SELECT,
    });

    // Construir entradas con el ID real
    const { entryA, entryB } = buildCrossSettlementEntries(input, cs.id);
    const documentRef = `XSETTLE-${cs.id}`;

    await tx.entityBalanceEntry.create({
      data: {
        jewelryId,
        entityId:          supplierId,
        entryType:         "CROSS_SETTLEMENT",
        role:              "SUPPLIER",
        documentRef,
        amount:            entryA.amount,
        currency:          entryA.currency,
        notes:             entryA.notes,
        breakdownSnapshot: entryA.breakdownSnapshot as any,
        createdBy:         userId,
      },
    });

    await tx.entityBalanceEntry.create({
      data: {
        jewelryId,
        entityId:          supplierId,
        entryType:         "CROSS_SETTLEMENT",
        role:              "SUPPLIER",
        documentRef,
        amount:            entryB.amount,
        currency:          entryB.currency,
        notes:             entryB.notes,
        breakdownSnapshot: entryB.breakdownSnapshot as any,
        createdBy:         userId,
      },
    });

    return cs;
  });

  return settlement as unknown as CrossSettlement;
}

// ---------------------------------------------------------------------------
// voidCrossSettlement
// ---------------------------------------------------------------------------

export async function voidCrossSettlement(
  id: string,
  jewelryId: string,
  userId: string,
  reason: string,
): Promise<CrossSettlement> {
  // 1. Cargar liquidación
  const existing = await prisma.crossSettlement.findFirst({
    where: { id, jewelryId },
    select: { ...CROSS_SETTLEMENT_SELECT },
  });
  if (!existing) {
    const err: any = new Error("Liquidación cruzada no encontrada.");
    err.status = 404;
    throw err;
  }
  if (existing.status === "VOIDED") {
    const err: any = new Error("La liquidación cruzada ya fue anulada.");
    err.status = 400;
    throw err;
  }

  // 2. Transacción: anular cabecera + anular entradas de balance
  const updated = await prisma.$transaction(async (tx) => {
    const cs = await tx.crossSettlement.update({
      where: { id },
      data: {
        status:     "VOIDED",
        voidedAt:   new Date(),
        voidedById: userId,
        voidReason: reason,
      },
      select: CROSS_SETTLEMENT_SELECT,
    });

    await tx.entityBalanceEntry.updateMany({
      where: {
        jewelryId,
        documentRef: `XSETTLE-${id}`,
        voidedAt:    null,
      },
      data: {
        voidedAt:  new Date(),
        voidedBy:  userId,
        voidReason: reason,
      },
    });

    return cs;
  });

  return updated as unknown as CrossSettlement;
}

// ---------------------------------------------------------------------------
// listCrossSettlements
// ---------------------------------------------------------------------------

export async function listCrossSettlements(
  supplierId: string,
  jewelryId: string,
  opts?: { skip?: number; take?: number; includeVoided?: boolean },
): Promise<{ items: CrossSettlement[]; total: number }> {
  const skip           = opts?.skip          ?? 0;
  const take           = Math.min(opts?.take ?? 25, 100);
  const includeVoided  = opts?.includeVoided ?? false;

  const where = {
    supplierId,
    jewelryId,
    ...(includeVoided ? {} : { status: "CONFIRMED" as const }),
  };

  const [items, total] = await Promise.all([
    prisma.crossSettlement.findMany({
      where,
      select:  CROSS_SETTLEMENT_SELECT,
      orderBy: { createdAt: "desc" },
      skip,
      take,
    }),
    prisma.crossSettlement.count({ where }),
  ]);

  return { items: items as unknown as CrossSettlement[], total };
}

// ---------------------------------------------------------------------------
// getCrossSettlement
// ---------------------------------------------------------------------------

export async function getCrossSettlement(
  id: string,
  jewelryId: string,
): Promise<CrossSettlement> {
  const settlement = await prisma.crossSettlement.findFirst({
    where:  { id, jewelryId },
    select: CROSS_SETTLEMENT_SELECT,
  });
  if (!settlement) {
    const err: any = new Error("Liquidación cruzada no encontrada.");
    err.status = 404;
    throw err;
  }
  return settlement as unknown as CrossSettlement;
}
