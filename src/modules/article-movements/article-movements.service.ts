import { Prisma } from "@prisma/client";
import { prisma } from "../../lib/prisma.js";
import { applyStockDelta } from "../articles/articles.service.js";

type Kind = "IN" | "OUT" | "TRANSFER" | "ADJUST" | "OPENING";

function s(v: any): string { return String(v ?? "").trim(); }
function toDec(v: any): Prisma.Decimal | null {
  const raw = String(v ?? "").trim().replace(/\s/g, "").replace(",", ".");
  if (!raw) return null;
  const n = Number(raw);
  if (!Number.isFinite(n)) return null;
  return new Prisma.Decimal(raw);
}
function assert(cond: any, msg: string, status = 400): void {
  if (!cond) { const e: any = new Error(msg); e.status = status; throw e; }
}
function clampTake(v: any, fallback = 50): number {
  const n = Number(v);
  return Number.isFinite(n) ? Math.max(1, Math.min(200, Math.floor(n))) : fallback;
}

// ===========================================================================
// Código correlativo por tenant + kind
// Formato: AE-NNNN (IN), AS-NNNN (OUT), AT-NNNN (TRANSFER),
//          AA-NNNN (ADJUST), AO-NNNN (OPENING)
// Se cuentan TODOS los movimientos incluyendo anulados para no reutilizar números.
// ===========================================================================
const KIND_PREFIX: Record<Kind, string> = {
  IN:       "AE",
  OUT:      "AS",
  TRANSFER: "AT",
  ADJUST:   "AA",
  OPENING:  "AO",
};

async function generateCode(tx: Prisma.TransactionClient, jewelryId: string, kind: Kind): Promise<string> {
  const prefix = KIND_PREFIX[kind];
  // Contar incluyendo anulados para que el código nunca se reutilice
  const count = await tx.articleMovement.count({ where: { jewelryId, kind } });
  return `${prefix}-${String(count + 1).padStart(4, "0")}`;
}

// ===========================================================================
// Validaciones comunes de líneas
// ===========================================================================
type RawLine = { articleId: string; variantId?: string | null; quantity: any };

function parseLines(raw: any[]): Array<{ articleId: string; variantId: string | null; quantity: Prisma.Decimal }> {
  return (raw ?? [])
    .map((l) => ({
      articleId: s(l?.articleId),
      variantId: s(l?.variantId) || null,
      quantity: toDec(l?.quantity),
    }))
    .filter((l) => l.articleId && l.quantity !== null) as any;
}

async function validateLinesForStock(
  tx: Prisma.TransactionClient,
  jewelryId: string,
  lines: Array<{ articleId: string; variantId: string | null; quantity: Prisma.Decimal }>
) {
  for (const line of lines) {
    // El artículo debe existir, pertenecer al tenant y usar BY_ARTICLE
    const article = await tx.article.findFirst({
      where: { id: line.articleId, jewelryId, deletedAt: null },
      select: { id: true, stockMode: true, name: true },
    });
    assert(article, `Artículo ${line.articleId} no encontrado.`);
    assert(
      article!.stockMode === "BY_ARTICLE",
      `El artículo "${article!.name}" no usa stock BY_ARTICLE. Solo se puede mover stock de artículos con stockMode BY_ARTICLE.`
    );

    // Verificar si el artículo tiene variantes activas → variantId es obligatorio
    const variantCount = await tx.articleVariant.count({
      where: { articleId: line.articleId, deletedAt: null, isActive: true },
    });
    if (variantCount > 0) {
      assert(
        line.variantId,
        `El artículo "${article!.name}" tiene variantes activas. Especificá la variante (variantId) en cada línea del movimiento.`
      );
    }

    // Si se especifica variantId, debe pertenecer al artículo, al tenant, estar activa y no eliminada
    if (line.variantId) {
      const variant = await tx.articleVariant.findFirst({
        where: {
          id: line.variantId,
          articleId: line.articleId,
          jewelryId,
          deletedAt: null,
          isActive: true,
        },
        select: { id: true, name: true },
      });
      assert(
        variant,
        `Variante "${line.variantId}" no encontrada, inactiva o no pertenece al artículo "${article!.name}".`,
        404
      );
    }
  }
}

// ===========================================================================
// List movements
// ===========================================================================
export async function listArticleMovements(opts: {
  jewelryId: string;
  page?: number;
  pageSize?: number;
  q?: string;
  warehouseId?: string | null;
  kind?: string | null;
  from?: Date | null;
  to?: Date | null;
  articleId?: string | null;
}) {
  const { jewelryId } = opts;
  const take = clampTake(opts.pageSize ?? 50);
  const skip = (Math.max(1, opts.page ?? 1) - 1) * take;

  const q = s(opts.q || "");
  const where: any = { jewelryId, voidedAt: null };

  if (opts.kind) where.kind = opts.kind;
  if (opts.warehouseId) {
    where.OR = [
      { warehouseId: opts.warehouseId },
      { fromWarehouseId: opts.warehouseId },
      { toWarehouseId: opts.warehouseId },
    ];
  }
  if (opts.from || opts.to) {
    where.effectiveAt = {};
    if (opts.from) where.effectiveAt.gte = opts.from;
    if (opts.to) where.effectiveAt.lte = opts.to;
  }
  if (opts.articleId) {
    where.lines = { some: { articleId: opts.articleId } };
  }
  if (q) {
    where.OR = [
      ...(where.OR ?? []),
      { note: { contains: q, mode: "insensitive" } },
      { code: { contains: q, mode: "insensitive" } },
    ];
  }

  const [total, rows] = await prisma.$transaction([
    prisma.articleMovement.count({ where }),
    prisma.articleMovement.findMany({
      where,
      orderBy: [{ effectiveAt: "desc" }, { createdAt: "desc" }],
      skip,
      take,
      select: {
        id: true,
        kind: true,
        code: true,
        note: true,
        effectiveAt: true,
        voidedAt: true,
        voidedNote: true,
        createdAt: true,
        warehouse:     { select: { id: true, name: true, code: true } },
        fromWarehouse: { select: { id: true, name: true, code: true } },
        toWarehouse:   { select: { id: true, name: true, code: true } },
        createdBy:     { select: { id: true, name: true, email: true } },
        voidedBy:      { select: { id: true, name: true, email: true } },
        lines: {
          select: {
            id: true,
            articleId: true,
            variantId: true,
            quantity: true,
            article: { select: { id: true, code: true, name: true } },
            variant:  { select: { id: true, code: true, name: true } },
          },
        },
      },
    }),
  ]);

  return { rows, total, page: opts.page ?? 1, pageSize: take };
}

// ===========================================================================
// Create — IN / OUT / ADJUST / OPENING
// ===========================================================================
export async function createArticleMovement(opts: {
  jewelryId: string;
  userId: string;
  kind: Exclude<Kind, "TRANSFER">;
  warehouseId: string;
  effectiveAt: Date;
  note?: string;
  lines: RawLine[];
}) {
  const { jewelryId, userId } = opts;
  assert(jewelryId, "Tenant inválido.");
  assert(userId, "Usuario inválido.");
  assert(opts.warehouseId, "Almacén requerido.");
  assert(["IN", "OUT", "ADJUST", "OPENING"].includes(opts.kind), "Tipo de movimiento inválido.");

  const lines = parseLines(opts.lines);
  assert(lines.length > 0, "Agregá al menos una línea.");

  // Para ADJUST las cantidades pueden ser negativas (delta), para el resto deben ser positivas
  if (opts.kind !== "ADJUST") {
    for (const l of lines) {
      assert(l.quantity.gt(0), `La cantidad debe ser mayor a 0. (artículo: ${l.articleId})`);
    }
  }

  return prisma.$transaction(async (tx) => {
    const wh = await tx.warehouse.findFirst({
      where: { id: opts.warehouseId, jewelryId, deletedAt: null },
      select: { id: true, isActive: true },
    });
    assert(wh, "Almacén no encontrado.");
    assert(wh!.isActive, "El almacén está inactivo.");

    await validateLinesForStock(tx, jewelryId, lines);

    // Verificar stock suficiente para OUT
    if (opts.kind === "OUT") {
      for (const line of lines) {
        await applyStockDelta(tx, {
          jewelryId,
          warehouseId: opts.warehouseId,
          articleId: line.articleId,
          variantId: line.variantId,
          delta: line.quantity.neg(),
          preventNegative: true,
        });
      }
    } else if (opts.kind === "IN" || opts.kind === "OPENING") {
      for (const line of lines) {
        await applyStockDelta(tx, {
          jewelryId,
          warehouseId: opts.warehouseId,
          articleId: line.articleId,
          variantId: line.variantId,
          delta: line.quantity,
          preventNegative: false,
        });
      }
    } else if (opts.kind === "ADJUST") {
      // Para ADJUST: la línea ya tiene el delta firmado
      for (const line of lines) {
        await applyStockDelta(tx, {
          jewelryId,
          warehouseId: opts.warehouseId,
          articleId: line.articleId,
          variantId: line.variantId,
          delta: line.quantity,
          preventNegative: false, // ajuste puede llevar a negativo si así se quiere
        });
      }
    }

    const code = await generateCode(tx, jewelryId, opts.kind);

    return tx.articleMovement.create({
      data: {
        jewelryId,
        kind: opts.kind,
        code,
        note: s(opts.note || ""),
        effectiveAt: opts.effectiveAt ?? new Date(),
        warehouseId: opts.warehouseId,
        createdById: userId || null,
        lines: {
          create: lines.map((l) => ({
            jewelryId,
            articleId: l.articleId,
            variantId: l.variantId ?? null,
            quantity: l.quantity,
          })),
        },
      },
      select: {
        id: true,
        kind: true,
        code: true,
        note: true,
        effectiveAt: true,
        createdAt: true,
        warehouse:  { select: { id: true, name: true, code: true } },
        createdBy:  { select: { id: true, name: true, email: true } },
        lines: {
          select: {
            id: true,
            articleId: true,
            variantId: true,
            quantity: true,
            article: { select: { id: true, code: true, name: true } },
            variant:  { select: { id: true, code: true, name: true } },
          },
        },
      },
    });
  });
}

// ===========================================================================
// Transfer
// ===========================================================================
export async function transferArticleMovement(opts: {
  jewelryId: string;
  userId: string;
  fromWarehouseId: string;
  toWarehouseId: string;
  effectiveAt: Date;
  note?: string;
  lines: RawLine[];
}) {
  const { jewelryId, userId } = opts;
  assert(jewelryId, "Tenant inválido.");
  assert(userId, "Usuario inválido.");
  assert(opts.fromWarehouseId, "Almacén origen requerido.");
  assert(opts.toWarehouseId, "Almacén destino requerido.");
  assert(opts.fromWarehouseId !== opts.toWarehouseId, "Origen y destino no pueden ser el mismo.");

  const lines = parseLines(opts.lines);
  assert(lines.length > 0, "Agregá al menos una línea.");
  for (const l of lines) {
    assert(l.quantity.gt(0), `La cantidad debe ser mayor a 0. (artículo: ${l.articleId})`);
  }

  return prisma.$transaction(async (tx) => {
    const [fromWh, toWh] = await Promise.all([
      tx.warehouse.findFirst({ where: { id: opts.fromWarehouseId, jewelryId, deletedAt: null }, select: { id: true, isActive: true } }),
      tx.warehouse.findFirst({ where: { id: opts.toWarehouseId, jewelryId, deletedAt: null }, select: { id: true, isActive: true } }),
    ]);
    assert(fromWh, "Almacén origen no encontrado.");
    assert(toWh, "Almacén destino no encontrado.");
    assert(fromWh!.isActive, "El almacén origen está inactivo.");
    assert(toWh!.isActive, "El almacén destino está inactivo.");

    await validateLinesForStock(tx, jewelryId, lines);

    // Restar del origen (con control de stock negativo)
    for (const line of lines) {
      await applyStockDelta(tx, {
        jewelryId,
        warehouseId: opts.fromWarehouseId,
        articleId: line.articleId,
        variantId: line.variantId,
        delta: line.quantity.neg(),
        preventNegative: true,
      });
    }

    // Sumar al destino
    for (const line of lines) {
      await applyStockDelta(tx, {
        jewelryId,
        warehouseId: opts.toWarehouseId,
        articleId: line.articleId,
        variantId: line.variantId,
        delta: line.quantity,
        preventNegative: false,
      });
    }

    const code = await generateCode(tx, jewelryId, "TRANSFER");

    return tx.articleMovement.create({
      data: {
        jewelryId,
        kind: "TRANSFER",
        code,
        note: s(opts.note || ""),
        effectiveAt: opts.effectiveAt ?? new Date(),
        fromWarehouseId: opts.fromWarehouseId,
        toWarehouseId: opts.toWarehouseId,
        createdById: userId || null,
        lines: {
          create: lines.map((l) => ({
            jewelryId,
            articleId: l.articleId,
            variantId: l.variantId ?? null,
            quantity: l.quantity,
          })),
        },
      },
      select: {
        id: true,
        kind: true,
        code: true,
        note: true,
        effectiveAt: true,
        createdAt: true,
        fromWarehouse: { select: { id: true, name: true, code: true } },
        toWarehouse:   { select: { id: true, name: true, code: true } },
        createdBy:     { select: { id: true, name: true, email: true } },
        lines: {
          select: {
            id: true,
            articleId: true,
            variantId: true,
            quantity: true,
            article: { select: { id: true, code: true, name: true } },
            variant:  { select: { id: true, code: true, name: true } },
          },
        },
      },
    });
  });
}

// ===========================================================================
// Void (anular)
// Revierte el efecto del movimiento sobre el stock de forma segura.
// ===========================================================================
export async function voidArticleMovement(opts: {
  id: string;
  jewelryId: string;
  userId: string;
  note?: string;
}) {
  const { id, jewelryId, userId } = opts;
  assert(id, "Movimiento inválido.");
  assert(jewelryId, "Tenant inválido.");

  return prisma.$transaction(async (tx) => {
    const movement = await tx.articleMovement.findFirst({
      where: { id, jewelryId },
      select: {
        id: true,
        kind: true,
        voidedAt: true,
        warehouseId: true,
        fromWarehouseId: true,
        toWarehouseId: true,
        lines: {
          select: {
            articleId: true,
            variantId: true,
            quantity: true,
          },
        },
      },
    });

    assert(movement, "Movimiento no encontrado.", 404);
    assert(!movement!.voidedAt, "El movimiento ya fue anulado.");

    // Revertir el efecto en el stock
    const kind = movement!.kind as Kind;

    if (kind === "IN" || kind === "OPENING") {
      // Revertir: descontar del almacén destino
      for (const line of movement!.lines) {
        await applyStockDelta(tx, {
          jewelryId,
          warehouseId: movement!.warehouseId!,
          articleId: line.articleId,
          variantId: line.variantId,
          delta: new Prisma.Decimal(line.quantity.toString()).neg(),
          preventNegative: true,
        });
      }
    } else if (kind === "OUT") {
      // Revertir: devolver al almacén
      for (const line of movement!.lines) {
        await applyStockDelta(tx, {
          jewelryId,
          warehouseId: movement!.warehouseId!,
          articleId: line.articleId,
          variantId: line.variantId,
          delta: line.quantity,
          preventNegative: false,
        });
      }
    } else if (kind === "TRANSFER") {
      // Revertir: devolver al origen, quitar del destino
      for (const line of movement!.lines) {
        await applyStockDelta(tx, {
          jewelryId,
          warehouseId: movement!.toWarehouseId!,
          articleId: line.articleId,
          variantId: line.variantId,
          delta: new Prisma.Decimal(line.quantity.toString()).neg(),
          preventNegative: true,
        });
        await applyStockDelta(tx, {
          jewelryId,
          warehouseId: movement!.fromWarehouseId!,
          articleId: line.articleId,
          variantId: line.variantId,
          delta: line.quantity,
          preventNegative: false,
        });
      }
    } else if (kind === "ADJUST") {
      // Revertir: aplicar el delta opuesto
      for (const line of movement!.lines) {
        await applyStockDelta(tx, {
          jewelryId,
          warehouseId: movement!.warehouseId!,
          articleId: line.articleId,
          variantId: line.variantId,
          delta: new Prisma.Decimal(line.quantity.toString()).neg(),
          preventNegative: false,
        });
      }
    }

    return tx.articleMovement.update({
      where: { id },
      data: {
        voidedAt: new Date(),
        voidedById: userId || null,
        voidedNote: s(opts.note || ""),
      },
      select: {
        id: true,
        kind: true,
        code: true,
        note: true,
        effectiveAt: true,
        voidedAt: true,
        voidedNote: true,
        createdAt: true,
        warehouse:     { select: { id: true, name: true, code: true } },
        fromWarehouse: { select: { id: true, name: true, code: true } },
        toWarehouse:   { select: { id: true, name: true, code: true } },
        createdBy:     { select: { id: true, name: true, email: true } },
        voidedBy:      { select: { id: true, name: true, email: true } },
        lines: {
          select: {
            id: true,
            articleId: true,
            variantId: true,
            quantity: true,
            article: { select: { id: true, code: true, name: true } },
            variant:  { select: { id: true, code: true, name: true } },
          },
        },
      },
    });
  });
}
