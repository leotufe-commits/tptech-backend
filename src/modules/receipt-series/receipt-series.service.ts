// src/modules/receipt-series/receipt-series.service.ts
// ============================================================================
// CRUD admin de ReceiptSeries — Etapa A (2026-05-29).
//
// Responsabilidades:
//   · Listar / leer / crear / actualizar / soft-delete series de numeración.
//   · Multi-tenant estricto (todas las queries filtran por jewelryId).
//   · Soft-delete bloqueado si la serie tiene Receipts emitidos.
//   · Validación crítica: `nextNumber` no puede bajar del último emitido + 1.
//   · Validación de unicidad respetando el UNIQUE compuesto
//     (jewelryId, type, direction, prefix, pointOfSale).
//
// NO toca:
//   · `sale.hook.ts` ni `confirmSale` — la generación atómica del número
//     sigue intacta. Esta capa es admin pura.
//   · `Receipt` ni `ReceiptLine` — solo se LEE Receipt para validar guards
//     (último emitido + bloqueo de delete).
// ============================================================================

import { prisma } from "../../lib/prisma.js";
import type {
  CreateReceiptSeriesInput,
  UpdateReceiptSeriesInput,
} from "./receipt-series.schemas.js";

// ─── Helpers ────────────────────────────────────────────────────────────────

function assert(cond: any, msg: string, status: number = 400): asserts cond {
  if (!cond) {
    const err: any = new Error(msg);
    err.status = status;
    throw err;
  }
}

/**
 * Select público. Excluye `deletedAt` y campos internos no relevantes para
 * el frontend / consumidores externos. `jewelryId` también se omite — el
 * caller siempre conoce el tenant del usuario autenticado.
 */
const PUBLIC_SELECT = {
  id: true,
  name: true,
  type: true,
  direction: true,
  prefix: true,
  pointOfSale: true,
  nextNumber: true,
  isActive: true,
  createdAt: true,
  updatedAt: true,
} as const;

export type ReceiptSeriesRow = {
  id: string;
  name: string;
  type: string;
  direction: string;
  prefix: string;
  pointOfSale: string;
  nextNumber: number;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
};

/**
 * Convierte un error de P2002 (unique constraint) de Prisma en un 409
 * con mensaje accionable. Cualquier otro error se re-lanza.
 */
function handleUniqueConstraintError(err: any, ctx: { type: string; direction: string; prefix: string; pointOfSale: string }): never {
  if (err?.code === "P2002") {
    const e: any = new Error(
      `Ya existe una serie con tipo ${ctx.type}, dirección ${ctx.direction}, ` +
      `prefijo "${ctx.prefix}" y punto de venta ${ctx.pointOfSale}. ` +
      `Usá otra combinación de prefijo/punto de venta.`,
    );
    e.status = 409;
    throw e;
  }
  throw err;
}

// ─── List ───────────────────────────────────────────────────────────────────

/**
 * Lista todas las series activas (no soft-deleted) del tenant. Orden:
 * type → direction → prefix → pointOfSale.
 */
export async function listReceiptSeries(jewelryId: string): Promise<ReceiptSeriesRow[]> {
  return prisma.receiptSeries.findMany({
    where:  { jewelryId, deletedAt: null },
    select: PUBLIC_SELECT,
    orderBy: [
      { type:        "asc" },
      { direction:   "asc" },
      { prefix:      "asc" },
      { pointOfSale: "asc" },
    ],
  });
}

// ─── Get one ────────────────────────────────────────────────────────────────

export async function getReceiptSeries(id: string, jewelryId: string): Promise<ReceiptSeriesRow> {
  const row = await prisma.receiptSeries.findFirst({
    where:  { id, jewelryId, deletedAt: null },
    select: PUBLIC_SELECT,
  });
  assert(row, "Serie de numeración no encontrada.", 404);
  return row!;
}

// ─── Create ─────────────────────────────────────────────────────────────────

export async function createReceiptSeries(
  jewelryId: string,
  input: CreateReceiptSeriesInput,
): Promise<ReceiptSeriesRow> {
  try {
    return await prisma.receiptSeries.create({
      data: {
        jewelryId,
        name:        input.name,
        type:        input.type,
        direction:   input.direction,
        prefix:      input.prefix,
        pointOfSale: input.pointOfSale,
        nextNumber:  input.nextNumber,
        isActive:    input.isActive,
      },
      select: PUBLIC_SELECT,
    });
  } catch (err: any) {
    handleUniqueConstraintError(err, {
      type:        input.type,
      direction:   input.direction,
      prefix:      input.prefix,
      pointOfSale: input.pointOfSale,
    });
  }
}

// ─── Update ─────────────────────────────────────────────────────────────────

/**
 * Actualiza nombre / prefix / pointOfSale / nextNumber / isActive.
 * `type` y `direction` son inmutables — el schema PATCH ya los excluye.
 *
 * Validación crítica: si el operador intenta bajar `nextNumber` por debajo
 * del último Receipt emitido (status=ISSUED), bloquear con 400 para evitar
 * que el próximo confirm choque con el UNIQUE de Receipt.code.
 */
export async function updateReceiptSeries(
  id: string,
  jewelryId: string,
  input: UpdateReceiptSeriesInput,
): Promise<ReceiptSeriesRow> {
  // 1) Verificar pertenencia al tenant (404 si no existe).
  const current = await prisma.receiptSeries.findFirst({
    where:  { id, jewelryId, deletedAt: null },
    select: { id: true, type: true, direction: true, prefix: true, pointOfSale: true, nextNumber: true },
  });
  assert(current, "Serie de numeración no encontrada.", 404);

  // 2) Si se intenta cambiar nextNumber, validar piso.
  if (input.nextNumber != null) {
    await assertNextNumberAboveLastIssued(id, jewelryId, input.nextNumber);
  }

  // 3) Aplicar update.
  const nextPrefix       = input.prefix       ?? current!.prefix;
  const nextPointOfSale  = input.pointOfSale  ?? current!.pointOfSale;

  try {
    return await prisma.receiptSeries.update({
      where: { id },
      data: {
        ...(input.name        != null ? { name:        input.name        } : {}),
        ...(input.prefix      != null ? { prefix:      input.prefix      } : {}),
        ...(input.pointOfSale != null ? { pointOfSale: input.pointOfSale } : {}),
        ...(input.nextNumber  != null ? { nextNumber:  input.nextNumber  } : {}),
        ...(input.isActive    != null ? { isActive:    input.isActive    } : {}),
      },
      select: PUBLIC_SELECT,
    });
  } catch (err: any) {
    handleUniqueConstraintError(err, {
      type:        current!.type,
      direction:   current!.direction,
      prefix:      nextPrefix,
      pointOfSale: nextPointOfSale,
    });
  }
}

/**
 * Guard CRÍTICO: nextNumber ≥ último emitido + 1.
 *
 * Lee el receipt ISSUED más reciente de la serie y parsea su sufijo
 * numérico. Si el operador intenta bajar `nextNumber` por debajo,
 * lanzamos 400 con mensaje claro. Esto evita chocar con el UNIQUE
 * compuesto `(jewelryId, seriesId, code)` al próximo confirmSale.
 *
 * Implementación: ordenamos los Receipts ISSUED por `nextNumber` (DESC
 * lexicográfico del code NO es seguro porque el code es texto). En su
 * lugar usamos `issueDate` desc + parseo del code. Como el contador es
 * monotónico, el más reciente por createdAt es el último número.
 */
async function assertNextNumberAboveLastIssued(
  seriesId: string,
  jewelryId: string,
  requestedNext: number,
): Promise<void> {
  const lastIssued = await prisma.receipt.findFirst({
    where: {
      jewelryId,
      seriesId,
      status: "ISSUED",
    },
    orderBy: { createdAt: "desc" },
    select: { code: true },
  });
  if (!lastIssued) return; // No hay emitidos, cualquier nextNumber ≥ 1 vale.

  const lastNumber = parseTrailingNumber(lastIssued.code);
  if (lastNumber == null) return; // Code con formato inesperado: no podemos validar, permitimos.

  if (requestedNext <= lastNumber) {
    const err: any = new Error(
      `No se puede establecer un próximo número menor al último comprobante emitido. ` +
      `El último emitido fue número ${lastNumber}; el próximo debe ser ${lastNumber + 1} o mayor.`,
    );
    err.status = 400;
    throw err;
  }
}

/**
 * Extrae el sufijo numérico de un code estilo "A-0001-00000025".
 * Devuelve `null` si el code no coincide con el patrón canónico.
 *
 * Helper PURO (exportado para tests). NO hace I/O.
 */
export function parseTrailingNumber(code: string): number | null {
  const m = /(\d+)\s*$/.exec(code);
  if (!m) return null;
  const n = parseInt(m[1]!, 10);
  return Number.isFinite(n) ? n : null;
}

// ─── Soft delete ────────────────────────────────────────────────────────────

/**
 * Soft-delete: setea `deletedAt`. Bloquea si la serie tiene Receipts con
 * status=ISSUED — borrar una serie con comprobantes oficiales emitidos
 * rompería la trazabilidad fiscal.
 *
 * Receipts DRAFT no bloquean (son borradores no oficiales).
 */
export async function softDeleteReceiptSeries(
  id: string,
  jewelryId: string,
): Promise<{ id: string }> {
  // 1) Verificar pertenencia.
  const current = await prisma.receiptSeries.findFirst({
    where:  { id, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(current, "Serie de numeración no encontrada.", 404);

  // 2) Bloquear si tiene receipts emitidos.
  const issued = await prisma.receipt.count({
    where: { seriesId: id, jewelryId, status: "ISSUED" },
  });
  if (issued > 0) {
    const err: any = new Error(
      "No se puede eliminar una serie con comprobantes emitidos.",
    );
    err.status = 409;
    throw err;
  }

  // 3) Soft delete.
  await prisma.receiptSeries.update({
    where: { id },
    data:  { deletedAt: new Date() },
  });
  return { id };
}
