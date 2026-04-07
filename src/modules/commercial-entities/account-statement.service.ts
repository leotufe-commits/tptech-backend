// src/modules/commercial-entities/account-statement.service.ts
// Genera extracto de cuenta corriente para una CommercialEntity.

import { prisma } from "../../lib/prisma.js";
import type { BalanceBreakdown } from "../../lib/pricing-engine/pricing-engine.balance.js";

// ---------------------------------------------------------------------------
// Tipos exportados
// ---------------------------------------------------------------------------

export type StatementBalance = {
  metal: Record<string, number>;    // metalId → gramsPure
  hechura: Record<string, number>;  // currency → amount
};

export type StatementMovement = {
  id: string;
  date: string;
  entryType: string;
  typeLabel: string;
  reference: string;
  description: string;
  isVoided: boolean;
  metalDelta: Record<string, number>;
  hechuraDelta: Record<string, number>;
  runningMetal: Record<string, number>;
  runningHechura: Record<string, number>;
};

export type AccountStatement = {
  entity: {
    id: string;
    displayName: string;
    code: string;
    documentNumber: string;
    email: string;
    balanceType: string;
  };
  period: {
    from: string | null;
    to: string | null;
    generatedAt: string;
  };
  openingBalance: StatementBalance;
  movements: StatementMovement[];
  closingBalance: StatementBalance;
};

// ---------------------------------------------------------------------------
// Tipo interno de entrada (subset de EntityBalanceEntry)
// ---------------------------------------------------------------------------

export interface StatementEntry {
  id: string;
  entryType: string;
  amount: { toString(): string };
  currency: string;
  documentRef: string;
  notes: string;
  createdAt: Date;
  voidedAt: Date | null;
  breakdownSnapshot: unknown;
}

// ---------------------------------------------------------------------------
// Helpers puros
// ---------------------------------------------------------------------------

/** Extrae los deltas de metal y hechura de una entrada. */
export function extractDeltas(entry: StatementEntry): {
  metalDelta: Record<string, number>;
  hechuraDelta: Record<string, number>;
} {
  if (entry.breakdownSnapshot != null) {
    const snap = entry.breakdownSnapshot as BalanceBreakdown;
    const metalDelta: Record<string, number> = {};
    for (const m of snap.metals ?? []) {
      if (!m.metalId || m.gramsPure == null) continue;
      metalDelta[m.metalId] = (metalDelta[m.metalId] ?? 0) + m.gramsPure;
    }
    const hechuraDelta: Record<string, number> = {};
    const amount = snap.hechura?.amount ?? 0;
    const currency = snap.hechura?.currency ?? "BASE";
    if (amount !== 0) {
      hechuraDelta[currency] = amount;
    }
    return { metalDelta, hechuraDelta };
  }

  // Sin snapshot: el importe va como hechura en la moneda del campo currency
  const amount = parseFloat(entry.amount.toString());
  const currency = entry.currency || "BASE";
  return {
    metalDelta: {},
    hechuraDelta: amount !== 0 ? { [currency]: amount } : {},
  };
}

/** Aplica un delta sobre un balance, devuelve nuevo balance. */
export function applyDelta(
  balance: StatementBalance,
  delta: { metalDelta: Record<string, number>; hechuraDelta: Record<string, number> },
): StatementBalance {
  const metal = { ...balance.metal };
  for (const [metalId, grams] of Object.entries(delta.metalDelta)) {
    metal[metalId] = (metal[metalId] ?? 0) + grams;
  }
  const hechura = { ...balance.hechura };
  for (const [currency, amount] of Object.entries(delta.hechuraDelta)) {
    hechura[currency] = (hechura[currency] ?? 0) + amount;
  }
  return { metal, hechura };
}

/** Elimina claves con valor absoluto menor a 0.0001. */
export function cleanZeros(record: Record<string, number>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [k, v] of Object.entries(record)) {
    if (Math.abs(v) >= 0.0001) out[k] = v;
  }
  return out;
}

/** Mapea entryType + notes a un label legible. */
export function resolveTypeLabel(entryType: string, notes: string): string {
  if (notes.startsWith("Compra confirmada")) return "Compra";
  if (notes.startsWith("Saldo a favor")) return "Aplicación de crédito";
  if (notes.startsWith("Pago a proveedor")) return "Pago";
  if (notes.startsWith("Liquidación cruzada")) return "Liquidación cruzada";

  const map: Record<string, string> = {
    METAL_RETURN:       "Devolución de metal",
    INVOICE:            "Factura",
    PAYMENT:            "Cobro",
    CREDIT_NOTE:        "Nota de crédito",
    DEBIT_NOTE:         "Nota de débito",
    ADJUSTMENT:         "Ajuste",
    PURCHASE_INVOICE:   "Compra",
    SUPPLIER_PAYMENT:   "Pago",
    CROSS_SETTLEMENT:   "Liquidación cruzada",
  };
  return map[entryType] ?? entryType;
}

// ---------------------------------------------------------------------------
// buildStatementFromEntries — lógica pura, testeable sin DB
// ---------------------------------------------------------------------------

export function buildStatementFromEntries(
  entity: {
    id: string;
    displayName: string;
    code: string;
    documentNumber: string;
    email: string;
    balanceType: string;
  },
  entries: StatementEntry[],
  period: { from: string | null; to: string | null },
): AccountStatement {
  const fromDate = period.from ? new Date(period.from) : null;
  const toDate   = period.to   ? new Date(period.to)   : null;

  // ── Opening balance: entradas NO anuladas ANTES de fromDate ──────────────
  const beforeEntries = fromDate
    ? entries.filter((e) => e.voidedAt == null && e.createdAt < fromDate)
    : [];

  let openingBalance: StatementBalance = { metal: {}, hechura: {} };
  for (const entry of beforeEntries) {
    openingBalance = applyDelta(openingBalance, extractDeltas(entry));
  }
  openingBalance = {
    metal:   cleanZeros(openingBalance.metal),
    hechura: cleanZeros(openingBalance.hechura),
  };

  // ── Entradas del período ──────────────────────────────────────────────────
  const periodEntries = entries.filter((e) => {
    if (fromDate && e.createdAt < fromDate) return false;
    if (toDate) {
      // incluir hasta el final del día toDate
      const endOfDay = new Date(toDate);
      endOfDay.setHours(23, 59, 59, 999);
      if (e.createdAt > endOfDay) return false;
    }
    return true;
  });

  // Ordenar por createdAt ASC
  periodEntries.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());

  // ── Construir movimientos con balance running ─────────────────────────────
  let running: StatementBalance = {
    metal:   { ...openingBalance.metal },
    hechura: { ...openingBalance.hechura },
  };

  const movements: StatementMovement[] = periodEntries.map((entry) => {
    const isVoided = entry.voidedAt != null;
    const { metalDelta, hechuraDelta } = extractDeltas(entry);

    if (!isVoided) {
      running = applyDelta(running, { metalDelta, hechuraDelta });
    }

    return {
      id:          entry.id,
      date:        entry.createdAt.toISOString(),
      entryType:   entry.entryType,
      typeLabel:   resolveTypeLabel(entry.entryType, entry.notes),
      reference:   entry.documentRef,
      description: entry.notes,
      isVoided,
      metalDelta:    isVoided ? {} : metalDelta,
      hechuraDelta:  isVoided ? {} : hechuraDelta,
      runningMetal:    cleanZeros({ ...running.metal }),
      runningHechura:  cleanZeros({ ...running.hechura }),
    };
  });

  const closingBalance: StatementBalance = {
    metal:   cleanZeros(running.metal),
    hechura: cleanZeros(running.hechura),
  };

  return {
    entity: {
      id:             entity.id,
      displayName:    entity.displayName,
      code:           entity.code,
      documentNumber: entity.documentNumber,
      email:          entity.email,
      balanceType:    entity.balanceType,
    },
    period: {
      from:        period.from,
      to:          period.to,
      generatedAt: new Date().toISOString(),
    },
    openingBalance,
    movements,
    closingBalance,
  };
}

// ---------------------------------------------------------------------------
// getAccountStatement — carga DB y delega en buildStatementFromEntries
// ---------------------------------------------------------------------------

export async function getAccountStatement(
  entityId: string,
  jewelryId: string,
  opts: { fromDate?: string; toDate?: string },
): Promise<AccountStatement> {
  const entity = await prisma.commercialEntity.findFirst({
    where: { id: entityId, jewelryId, deletedAt: null },
    select: {
      id:             true,
      displayName:    true,
      code:           true,
      documentNumber: true,
      email:          true,
      balanceType:    true,
    },
  });
  if (!entity) {
    const err: any = new Error("Entidad no encontrada.");
    err.status = 404;
    throw err;
  }

  // Cargar TODAS las entradas (incluyendo anuladas, para mostrarlas en el período)
  const rawEntries = await prisma.entityBalanceEntry.findMany({
    where: { entityId, jewelryId },
    select: {
      id:                true,
      entryType:         true,
      amount:            true,
      currency:          true,
      documentRef:       true,
      notes:             true,
      createdAt:         true,
      voidedAt:          true,
      breakdownSnapshot: true,
    },
    orderBy: { createdAt: "asc" },
  });

  const entries: StatementEntry[] = rawEntries.map((e) => ({
    ...e,
    entryType: e.entryType as string,
  }));

  return buildStatementFromEntries(
    {
      id:             entity.id,
      displayName:    entity.displayName,
      code:           entity.code,
      documentNumber: entity.documentNumber,
      email:          entity.email,
      balanceType:    entity.balanceType,
    },
    entries,
    {
      from: opts.fromDate ?? null,
      to:   opts.toDate   ?? null,
    },
  );
}
