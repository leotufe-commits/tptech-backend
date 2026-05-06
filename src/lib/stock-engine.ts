// src/lib/stock-engine.ts
/**
 * Motor central de stock de artículos.
 *
 * ── FUENTE DE VERDAD ─────────────────────────────────────────────────────────
 *  1. ArticleMovement + ArticleMovementLine = fuente de verdad del historial.
 *  2. ArticleStock = cache materializado. Nadie escribe en ArticleStock
 *     fuera de este archivo.
 *
 * ── TIPOS DE ARTÍCULO ────────────────────────────────────────────────────────
 *  3. articleType=SERVICE → nunca tiene stock. validateStockLineIntegrity
 *     lo rechaza antes de cualquier operación.
 *  4. Solo artículos con stockMode=BY_ARTICLE generan movimientos y saldo.
 *
 * ── VARIANTES ────────────────────────────────────────────────────────────────
 *  5. Artículo CON variantes activas → stock SOLO en variantes (variantId ≠ null).
 *     variantId=null rechazado; la variante debe estar activa y pertenecer al artículo.
 *  6. Artículo SIN variantes activas → stock en padre (variantId=null).
 *     variantId≠null rechazado.
 *
 * ── ESTADOS DEL MOVIMIENTO ───────────────────────────────────────────────────
 *  7. DRAFT    → no impacta stock. Sin endpoint de creación público (reservado).
 *  8. CONFIRMED → impacta stock vía applyMovementImpact al momento de crear.
 *  9. VOIDED   → revierte impacto vía reverseMovementImpact; estado terminal.
 *     Solo movimientos sourceType=MANUAL pueden anularse manualmente desde
 *     el módulo de movimientos. Otros orígenes (SALE, IMPORT, PURCHASE) deben
 *     anularse desde su módulo de origen.
 *
 * ── SOFT DELETE ──────────────────────────────────────────────────────────────
 * 10. ArticleMovement NO tiene deletedAt. VOIDED es el único mecanismo de
 *     "reversión". Borrar un movimiento corrompería el historial y el recalc.
 *     Los movimientos son inmutables una vez CONFIRMED: no tienen endpoint de
 *     edición ni de borrado.
 *
 * ── OTRAS REGLAS ─────────────────────────────────────────────────────────────
 * 11. Saldo negativo permitido: el sistema lo registra pero no lo bloquea.
 * 12. Todas las operaciones deben ejecutarse dentro de una transacción Prisma.
 */

import { Prisma } from "@prisma/client";

function assert(cond: any, msg: string, status = 400): asserts cond {
  if (!cond) { const e: any = new Error(msg); e.status = status; throw e; }
}

// ===========================================================================
// Tipos públicos
// ===========================================================================

export type StockKey = {
  jewelryId:   string;
  warehouseId: string;
  articleId:   string;
  variantId:   string | null;
};

/** Resultado de applyStockDelta: cantidades antes/después + flag de negativo. */
export type StockDeltaResult = {
  previousQty: Prisma.Decimal;
  newQty:      Prisma.Decimal;
  isNegative:  boolean;
};

export type MovementKind = "IN" | "OUT" | "OPENING" | "ADJUST" | "TRANSFER";

export type MovementLine = {
  articleId: string;
  variantId: string | null;
  quantity:  Prisma.Decimal;
};

/** Parámetros para applyMovementImpact / reverseMovementImpact. */
export type MovementImpactParams = {
  kind:            MovementKind;
  jewelryId:       string;
  warehouseId?:    string;       // IN | OUT | ADJUST | OPENING
  fromWarehouseId?: string;      // TRANSFER — origen
  toWarehouseId?:  string;       // TRANSFER — destino
  lines:           MovementLine[];
};

// ===========================================================================
// findStock — lectura de saldo actual
// ===========================================================================

export async function findStock(
  tx: Prisma.TransactionClient,
  key: StockKey
): Promise<{ id: string; quantity: Prisma.Decimal; reservedQty: Prisma.Decimal } | null> {
  return tx.articleStock.findFirst({
    where: {
      jewelryId:   key.jewelryId,
      warehouseId: key.warehouseId,
      articleId:   key.articleId,
      variantId:   key.variantId ?? null,
    },
    select: { id: true, quantity: true, reservedQty: true },
  });
}

// ===========================================================================
// validateStockLineIntegrity — validaciones obligatorias por línea
// Garantiza que variantId sea coherente con la estructura del artículo.
// ===========================================================================

export async function validateStockLineIntegrity(
  tx: Prisma.TransactionClient,
  jewelryId: string,
  line: { articleId: string; variantId: string | null }
): Promise<void> {
  const article = await tx.article.findFirst({
    where: { id: line.articleId, jewelryId, deletedAt: null },
    select: { id: true, name: true, articleType: true, stockMode: true },
  });
  assert(article, `Artículo ${line.articleId} no encontrado o no pertenece al tenant.`, 404);
  assert(
    article!.articleType !== "SERVICE",
    `El artículo "${article!.name}" es un servicio y no tiene stock. Los servicios no se inventarían.`
  );
  assert(
    article!.stockMode === "BY_ARTICLE",
    `El artículo "${article!.name}" tiene Modo_Stock "${article!.stockMode}". Solo los artículos con Modo_Stock BY_ARTICLE aceptan movimientos de stock.`
  );

  const activeVariantCount = await tx.articleVariant.count({
    where: { articleId: line.articleId, jewelryId, deletedAt: null, isActive: true },
  });

  if (activeVariantCount > 0) {
    // Artículo con variantes activas → variantId obligatorio
    assert(
      line.variantId,
      `El artículo "${article!.name}" tiene variantes activas. Especificá variantId en cada línea.`
    );
    const variant = await tx.articleVariant.findFirst({
      where: {
        id:        line.variantId!,
        articleId: line.articleId,
        jewelryId,
        deletedAt: null,
        isActive:  true,
      },
      select: { id: true },
    });
    assert(
      variant,
      `Variante "${line.variantId}" no encontrada, inactiva o no pertenece al artículo "${article!.name}".`,
      404
    );
  } else {
    // Artículo sin variantes activas → variantId debe ser null
    assert(
      !line.variantId,
      `El artículo "${article!.name}" no tiene variantes activas. No se debe especificar variantId.`
    );
  }
}

// ===========================================================================
// applyStockDelta — ÚNICA función que modifica ArticleStock
// ===========================================================================
// - Siempre dentro de una transacción.
// - Permite saldo negativo (isNegative = true en resultado).
// - Si el registro no existe → lo crea con quantity = delta.
// - Si existe → suma el delta a la cantidad actual.
// ===========================================================================

export async function applyStockDelta(
  tx: Prisma.TransactionClient,
  key: StockKey & { delta: number | Prisma.Decimal }
): Promise<StockDeltaResult> {
  const { jewelryId, warehouseId, articleId, variantId } = key;
  const delta    = new Prisma.Decimal(key.delta.toString());
  const existing = await findStock(tx, { jewelryId, warehouseId, articleId, variantId });

  if (existing) {
    const previousQty = existing.quantity;
    const newQty      = previousQty.add(delta);
    await tx.articleStock.update({
      where: { id: existing.id },
      data:  { quantity: newQty },
    });
    return { previousQty, newQty, isNegative: newQty.lt(0) };
  }

  // No existe → crear
  const newQty = delta;
  await tx.articleStock.create({
    data: {
      jewelryId,
      warehouseId,
      articleId,
      variantId: variantId ?? null,
      quantity:  newQty,
    },
  });
  return {
    previousQty: new Prisma.Decimal(0),
    newQty,
    isNegative: newQty.lt(0),
  };
}

// ===========================================================================
// applyMovementImpact — aplica el impacto de un movimiento CONFIRMED al stock
// Devuelve si alguna línea quedó con saldo negativo (solo informativo).
// ===========================================================================

export async function applyMovementImpact(
  tx: Prisma.TransactionClient,
  params: MovementImpactParams
): Promise<{ hasNegativeStock: boolean }> {
  const { kind, jewelryId, lines } = params;
  let hasNegativeStock = false;

  switch (kind) {
    case "IN":
    case "OPENING":
      for (const line of lines) {
        const r = await applyStockDelta(tx, {
          jewelryId,
          warehouseId: params.warehouseId!,
          articleId:   line.articleId,
          variantId:   line.variantId,
          delta:       line.quantity,
        });
        if (r.isNegative) hasNegativeStock = true;
      }
      break;

    case "OUT":
      for (const line of lines) {
        const r = await applyStockDelta(tx, {
          jewelryId,
          warehouseId: params.warehouseId!,
          articleId:   line.articleId,
          variantId:   line.variantId,
          delta:       line.quantity.neg(),
        });
        if (r.isNegative) hasNegativeStock = true;
      }
      break;

    case "ADJUST":
      // quantity puede ser positiva (sumar) o negativa (restar)
      for (const line of lines) {
        const r = await applyStockDelta(tx, {
          jewelryId,
          warehouseId: params.warehouseId!,
          articleId:   line.articleId,
          variantId:   line.variantId,
          delta:       line.quantity,
        });
        if (r.isNegative) hasNegativeStock = true;
      }
      break;

    case "TRANSFER":
      // Primero descontar del origen
      for (const line of lines) {
        const r = await applyStockDelta(tx, {
          jewelryId,
          warehouseId: params.fromWarehouseId!,
          articleId:   line.articleId,
          variantId:   line.variantId,
          delta:       line.quantity.neg(),
        });
        if (r.isNegative) hasNegativeStock = true;
      }
      // Luego agregar al destino
      for (const line of lines) {
        await applyStockDelta(tx, {
          jewelryId,
          warehouseId: params.toWarehouseId!,
          articleId:   line.articleId,
          variantId:   line.variantId,
          delta:       line.quantity,
        });
      }
      break;
  }

  return { hasNegativeStock };
}

// ===========================================================================
// reverseMovementImpact — revierte el impacto de un movimiento (para VOID)
// Aplica exactamente el delta opuesto al que aplicó applyMovementImpact.
// ===========================================================================

export async function reverseMovementImpact(
  tx: Prisma.TransactionClient,
  params: MovementImpactParams
): Promise<{ hasNegativeStock: boolean }> {
  const { kind, jewelryId, lines } = params;
  let hasNegativeStock = false;

  switch (kind) {
    case "IN":
    case "OPENING":
      // Revertir entrada → descontar
      for (const line of lines) {
        const r = await applyStockDelta(tx, {
          jewelryId,
          warehouseId: params.warehouseId!,
          articleId:   line.articleId,
          variantId:   line.variantId,
          delta:       line.quantity.neg(),
        });
        if (r.isNegative) hasNegativeStock = true;
      }
      break;

    case "OUT":
      // Revertir salida → devolver
      for (const line of lines) {
        const r = await applyStockDelta(tx, {
          jewelryId,
          warehouseId: params.warehouseId!,
          articleId:   line.articleId,
          variantId:   line.variantId,
          delta:       line.quantity,
        });
        if (r.isNegative) hasNegativeStock = true;
      }
      break;

    case "ADJUST":
      // Revertir ajuste → delta opuesto
      for (const line of lines) {
        const r = await applyStockDelta(tx, {
          jewelryId,
          warehouseId: params.warehouseId!,
          articleId:   line.articleId,
          variantId:   line.variantId,
          delta:       line.quantity.neg(),
        });
        if (r.isNegative) hasNegativeStock = true;
      }
      break;

    case "TRANSFER":
      // Revertir transferencia → devolver al origen, quitar del destino
      for (const line of lines) {
        await applyStockDelta(tx, {
          jewelryId,
          warehouseId: params.fromWarehouseId!,
          articleId:   line.articleId,
          variantId:   line.variantId,
          delta:       line.quantity, // devuelve al origen
        });
      }
      for (const line of lines) {
        const r = await applyStockDelta(tx, {
          jewelryId,
          warehouseId: params.toWarehouseId!,
          articleId:   line.articleId,
          variantId:   line.variantId,
          delta:       line.quantity.neg(), // quita del destino
        });
        if (r.isNegative) hasNegativeStock = true;
      }
      break;
  }

  return { hasNegativeStock };
}

// ===========================================================================
// recalcArticleStock — reconstruye ArticleStock desde cero para un artículo
// Borra todos los saldos del artículo y reproduce todos los movimientos
// CONFIRMED en orden de effectiveAt para recalcular los saldos correctos.
// SIEMPRE dentro de una transacción.
// ===========================================================================

export async function recalcArticleStock(
  tx: Prisma.TransactionClient,
  articleId: string,
  jewelryId: string
): Promise<void> {
  await tx.articleStock.deleteMany({ where: { articleId, jewelryId } });

  const movements = await tx.articleMovement.findMany({
    where: {
      jewelryId,
      status: "CONFIRMED",
      lines: { some: { articleId } },
    },
    orderBy: { effectiveAt: "asc" },
    select: {
      kind:            true,
      warehouseId:     true,
      fromWarehouseId: true,
      toWarehouseId:   true,
      lines: {
        where:  { articleId },
        select: { articleId: true, variantId: true, quantity: true },
      },
    },
  });

  for (const m of movements) {
    await applyMovementImpact(tx, {
      kind:            m.kind as MovementKind,
      jewelryId,
      warehouseId:     m.warehouseId     ?? undefined,
      fromWarehouseId: m.fromWarehouseId ?? undefined,
      toWarehouseId:   m.toWarehouseId   ?? undefined,
      lines: m.lines.map(l => ({
        articleId: l.articleId,
        variantId: l.variantId,
        quantity:  l.quantity,
      })),
    });
  }
}
