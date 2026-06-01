// src/modules/commercial-entities/balance-movements.service.ts
// =============================================================================
// T57 (Fase 3B.7) — Lectura de CurrentAccountMovement (modelo canónico Balance
// Mode) con metalEntries[] y trazabilidad sourceDocumentType/Id.
//
// Este service es la lectura NUEVA del modelo canónico de cuenta corriente:
//   · `CurrentAccountMovement` (creado por sale.hook en Fase 3B.6).
//   · `AccountMovementMetalEntry[]` (creado en BREAKDOWN).
//   · `balanceMode` + `sourceDocumentType` + `sourceDocumentId`.
//
// Coexiste con `account-statement.service.ts` (lectura legacy de
// `EntityBalanceEntry`) — esta fase NO migra el legacy, solo agrega la
// lectura canónica para que el frontend pueda consumir BREAKDOWN.
//
// NO calcula nada. NO convierte moneda (el caller decide). NO recompone
// históricos — sólo proyecta filas tal cual están persistidas.
// =============================================================================

import { prisma } from "../../lib/prisma.js";

// ─────────────────────────────────────────────────────────────────────────────
// DTOs públicos
// ─────────────────────────────────────────────────────────────────────────────

export interface BalanceMovementMetalEntryDTO {
  id:              string;
  metalParentId:   string | null;
  metalParentName: string;
  gramsOriginal:   number;
  /** Pureza ponderada del padre. `null` cuando Σg=0 (caso edge). */
  purity:          number | null;
  gramsPure:       number;
  sourceLineId:    string | null;
  createdAt:       string;
}

export interface BalanceMovementDTO {
  id:                  string;
  entityId:            string;
  kind:                "DEBIT" | "CREDIT" | string;
  source:              string;
  receiptId:           string | null;
  paymentAllocationId: string | null;
  amountBase:          number;
  amountOriginal:      number;
  currencyCode:        string;
  currencyRate:        number;
  movementDate:        string;
  createdAt:           string;
  notes:               string;
  // ── Balance Mode (POLICY.md §11) ────────────────────────────────────────
  balanceMode:         "UNIFIED" | "BREAKDOWN";
  /** Trazabilidad "Ver origen" — R11.7. */
  sourceDocumentType:  string | null;
  sourceDocumentId:    string | null;
  /** Filas de metales del movimiento. Vacío en UNIFIED; ≥1 en BREAKDOWN
   *  cuando el documento aportó gramos. */
  metalEntries:        BalanceMovementMetalEntryDTO[];
}

export interface ListBalanceMovementsArgs {
  entityId:  string;
  jewelryId: string;
  fromDate?: string;
  toDate?:   string;
  /** Paginación opcional. */
  skip?:     number;
  take?:     number;
}

export interface ListBalanceMovementsResult {
  data:  BalanceMovementDTO[];
  total: number;
  skip:  number;
  take:  number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers puros
// ─────────────────────────────────────────────────────────────────────────────

function toNum(v: unknown): number {
  if (v == null) return 0;
  if (typeof v === "number") return v;
  if (typeof v === "string") return parseFloat(v) || 0;
  if (typeof v === "object" && v && "toString" in v) {
    return parseFloat((v as { toString(): string }).toString()) || 0;
  }
  return 0;
}

/** Proyección pura (sin DB): fila Prisma → DTO. Testeable aisladamente. */
export function projectBalanceMovement(row: any): BalanceMovementDTO {
  return {
    id:                  row.id,
    entityId:            row.entityId,
    kind:                row.kind,
    source:              row.source,
    receiptId:           row.receiptId ?? null,
    paymentAllocationId: row.paymentAllocationId ?? null,
    amountBase:          toNum(row.amountBase),
    amountOriginal:      toNum(row.amountOriginal),
    currencyCode:        row.currencyCode ?? "",
    currencyRate:        toNum(row.currencyRate),
    movementDate:        row.movementDate instanceof Date
      ? row.movementDate.toISOString()
      : String(row.movementDate ?? ""),
    createdAt:           row.createdAt instanceof Date
      ? row.createdAt.toISOString()
      : String(row.createdAt ?? ""),
    notes:               row.notes ?? "",
    balanceMode:         row.balanceMode ?? "UNIFIED",
    sourceDocumentType:  row.sourceDocumentType ?? null,
    sourceDocumentId:    row.sourceDocumentId ?? null,
    metalEntries: Array.isArray(row.metalEntries)
      ? row.metalEntries.map(projectMetalEntry)
      : [],
  };
}

/** Proyección de una metalEntry persistida al DTO público. */
export function projectMetalEntry(row: any): BalanceMovementMetalEntryDTO {
  return {
    id:              row.id,
    metalParentId:   row.metalParentId ?? null,
    metalParentName: row.metalParentName ?? "",
    gramsOriginal:   toNum(row.gramsOriginal),
    purity:          row.purity != null ? toNum(row.purity) : null,
    gramsPure:       toNum(row.gramsPure),
    sourceLineId:    row.sourceLineId ?? null,
    createdAt:       row.createdAt instanceof Date
      ? row.createdAt.toISOString()
      : String(row.createdAt ?? ""),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// listBalanceMovements — carga + proyección
// ─────────────────────────────────────────────────────────────────────────────

/** Lista movimientos canónicos de cuenta corriente de una entidad con sus
 *  metalEntries hidratadas. Lectura pura — no escribe, no recalcula.
 *
 *  El frontend usa esto para mostrar BREAKDOWN (Oro X gr / Plata Y gr +
 *  saldo monetario) y para implementar "Ver origen" navegando al documento
 *  via `sourceDocumentType`/`sourceDocumentId`. */
export async function listBalanceMovements(
  args: ListBalanceMovementsArgs,
): Promise<ListBalanceMovementsResult> {
  const { entityId, jewelryId } = args;
  const skip = Math.max(0, args.skip ?? 0);
  const take = Math.min(500, Math.max(1, args.take ?? 100));

  const where: any = { entityId, jewelryId };
  if (args.fromDate || args.toDate) {
    where.movementDate = {};
    if (args.fromDate) where.movementDate.gte = new Date(args.fromDate);
    if (args.toDate) {
      const end = new Date(args.toDate);
      end.setHours(23, 59, 59, 999);
      where.movementDate.lte = end;
    }
  }

  const [rows, total] = await Promise.all([
    prisma.currentAccountMovement.findMany({
      where,
      select: {
        id:                  true,
        entityId:            true,
        kind:                true,
        source:              true,
        receiptId:           true,
        paymentAllocationId: true,
        amountBase:          true,
        amountOriginal:      true,
        currencyCode:        true,
        currencyRate:        true,
        movementDate:        true,
        createdAt:           true,
        notes:               true,
        balanceMode:         true,
        sourceDocumentType:  true,
        sourceDocumentId:    true,
        metalEntries: {
          select: {
            id:              true,
            metalParentId:   true,
            metalParentName: true,
            gramsOriginal:   true,
            purity:          true,
            gramsPure:       true,
            sourceLineId:    true,
            createdAt:       true,
          },
        },
      },
      orderBy: { movementDate: "desc" },
      skip,
      take,
    }),
    prisma.currentAccountMovement.count({ where }),
  ]);

  return {
    data: rows.map(projectBalanceMovement),
    total,
    skip,
    take,
  };
}
