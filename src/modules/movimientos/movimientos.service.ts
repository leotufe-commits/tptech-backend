import { Prisma } from "@prisma/client";
import { prisma } from "../../lib/prisma.js";

type Kind = "IN" | "OUT" | "TRANSFER" | "ADJUST";

function s(v: any) {
  return String(v ?? "").trim();
}
function toDec(v: any) {
  const raw = String(v ?? "").trim().replace(/\s/g, "").replace(",", ".");
  if (!raw) return null;
  const n = Number(raw);
  if (!Number.isFinite(n)) return null;
  return new Prisma.Decimal(raw);
}
function assert(cond: any, msg: string) {
  if (!cond) {
    const err: any = new Error(msg);
    err.status = 400;
    throw err;
  }
}

function clampTake(v: any, fallback = 50) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(1, Math.min(200, Math.floor(n)));
}

/* =========================
   CÓDIGO CORRELATIVO
   Formato: E-0001 | S-0001 | T-0001 | A-0001
   Cuenta TODOS los movimientos del tenant+kind (incluso anulados)
   para que el número nunca se reutilice.
========================= */
const KIND_PREFIX: Record<Kind, string> = {
  IN: "E",
  OUT: "S",
  TRANSFER: "T",
  ADJUST: "A",
};

async function generateMovementCode(
  tx: Prisma.TransactionClient,
  jewelryId: string,
  kind: Kind,
): Promise<string> {
  const prefix = KIND_PREFIX[kind] ?? "M";
  const count = await tx.inventoryMovement.count({
    where: { jewelryId, kind },
  });
  return `${prefix}-${String(count + 1).padStart(4, "0")}`;
}

// ===========================================================================
// Stock materializado de metales (WarehouseStock)
//
// WarehouseStock mantiene gramos actualizados por (jewelryId, warehouseId, variantId).
// Es la fuente de verdad para calcMaterialAvailability (artículos BY_MATERIAL).
// getWarehouseNetGrams y getWarehouseMetalStock siguen usando InventoryMovement
// de forma dinámica para display — ambas fuentes deben estar siempre sincronizadas.
//
// Se llama dentro de transacciones de creación y anulación de movimientos.
// No previene stock negativo: la misma política que getWarehouseNetGrams.
// ===========================================================================
async function applyMetalStockDelta(
  tx: Prisma.TransactionClient,
  params: {
    jewelryId: string;
    warehouseId: string;
    variantId: string;
    delta: Prisma.Decimal;  // positivo = suma, negativo = resta
  },
): Promise<void> {
  const { jewelryId, warehouseId, variantId, delta } = params;
  const existing = await tx.warehouseStock.findFirst({
    where: { jewelryId, warehouseId, variantId },
    select: { id: true, grams: true },
  });
  if (existing) {
    await tx.warehouseStock.update({
      where: { id: existing.id },
      data: { grams: existing.grams.add(delta) },
    });
  } else {
    await tx.warehouseStock.create({
      data: { jewelryId, warehouseId, variantId, grams: delta },
    });
  }
}

// ===========================================================================
// Enriquecimiento de líneas de metales: aplica snapshot cuando está disponible
// para que renombrar Metal/MetalVariant no afecte el historial.
// Patrón idéntico a enrichMovement() en article-movements.service.ts.
//
// Con snapshot  → variant.name y variant.metal.name se reemplazan por los
//                 valores congelados al momento de creación.
// Sin snapshot  → se mantienen los datos vivos (movimientos legacy).
// ===========================================================================
function enrichMetalMovement(movement: any): any {
  return {
    ...movement,
    lines: (movement.lines ?? []).map((line: any) => {
      const snap = (line.snapshot as any) ?? null;
      // Siempre eliminamos snapshot del response — el cliente no lo necesita
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { snapshot: _snap, ...lineWithoutSnap } = line;

      if (snap) {
        // Usar snapshot: sobreescribir nombre de variante y metal con valores históricos
        const variant = line.variant
          ? {
              ...line.variant,
              name: snap.metalVariantName ?? line.variant.name,
              metal: line.variant.metal
                ? { ...line.variant.metal, name: snap.metalName ?? line.variant.metal.name }
                : null,
            }
          : null;
        return { ...lineWithoutSnap, variant };
      }

      // Fallback legacy: snapshot === null → datos vivos del JOIN (sin regresión)
      return lineWithoutSnap;
    }),
  };
}

export async function listMovements(opts: {
  jewelryId: string;
  userId: string;

  page: number;
  pageSize: number;

  q?: string;
  warehouseId?: string | null;
  kind?: string | null;
  from?: Date | null;
  to?: Date | null;
}) {
  const { jewelryId, page, pageSize } = opts;
  const take = clampTake(pageSize, 50);
  const skip = (Math.max(1, page) - 1) * take;

  const q = s(opts.q || "");
  const where: any = {
    jewelryId,
    deletedAt: null,
  };

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

  if (q) {
    where.OR = [
      ...(where.OR ?? []),
      { note: { contains: q, mode: "insensitive" } },
      { code: { contains: q, mode: "insensitive" } },
    ];
  }

  const [total, rows] = await prisma.$transaction([
    prisma.inventoryMovement.count({ where }),
    prisma.inventoryMovement.findMany({
      where,
      orderBy: [{ effectiveAt: "desc" }, { createdAt: "desc" }],
      skip,
      take,
      include: {
        createdBy: { select: { id: true, email: true, name: true } },
        warehouse: { select: { id: true, name: true, code: true } },
        fromWarehouse: { select: { id: true, name: true, code: true } },
        toWarehouse: { select: { id: true, name: true, code: true } },
        lines: {
          orderBy: { createdAt: "asc" },
          include: {
            variant: { select: { id: true, name: true, sku: true, metal: { select: { id: true, name: true } } } },
          },
        },
      },
    }),
  ]);

  return {
    rows: rows.map(enrichMetalMovement),
    total,
    page,
    pageSize: take,
  };
}

export async function createMovement(opts: {
  jewelryId: string;
  userId: string;

  warehouseId: string;
  kind: Exclude<Kind, "TRANSFER">;

  effectiveAt: Date;
  note?: string;

  lines: Array<{ variantId: string; grams: any }>;
}) {
  const jewelryId = s(opts.jewelryId);
  const userId = s(opts.userId);
  const warehouseId = s(opts.warehouseId);

  assert(jewelryId, "Tenant inválido.");
  assert(userId, "Usuario inválido.");
  assert(warehouseId, "Almacén requerido.");
  assert(opts.kind === "IN" || opts.kind === "OUT" || opts.kind === "ADJUST", "Tipo inválido.");

  const lines = (opts.lines ?? [])
    .map((l) => ({
      variantId: s(l?.variantId),
      grams: toDec(l?.grams),
    }))
    .filter((l): l is { variantId: string; grams: Prisma.Decimal } =>
      !!(l.variantId && l.grams),
    );

  assert(lines.length > 0, "Agregá al menos una línea.");

  // IN y OUT requieren gramos positivos; ADJUST acepta valores negativos (reduce stock)
  if (opts.kind !== "ADJUST") {
    for (const l of lines) {
      assert(l.grams.gt(0), "Los gramos deben ser mayores a 0 en entradas y salidas.");
    }
  }

  return prisma.$transaction(async (tx) => {
    const wh = await tx.warehouse.findFirst({
      where: { id: warehouseId, jewelryId, deletedAt: null },
      select: { id: true, isActive: true },
    });
    assert(!!wh, "Almacén no encontrado.");
    assert(wh!.isActive, "El almacén está inactivo.");

    const code = await generateMovementCode(tx, jewelryId, opts.kind);

    // Captura snapshot de nombres de variantes para preservar historial
    const variantIds = [...new Set(lines.map((l) => l.variantId))];
    const variantData = await tx.metalVariant.findMany({
      where: { id: { in: variantIds } },
      select: { id: true, name: true, metal: { select: { name: true } } },
    });
    const variantNameMap = new Map(variantData.map((v) => [v.id, v]));

    const created = await tx.inventoryMovement.create({
      data: {
        jewelryId,
        kind: opts.kind,
        code,
        note: s(opts.note || ""),
        effectiveAt: opts.effectiveAt ?? new Date(),
        warehouseId,
        createdById: userId,
        lines: {
          create: lines.map((l) => {
            const vd = variantNameMap.get(l.variantId);
            return {
              jewelryId,
              variantId: l.variantId,
              grams: l.grams,
              snapshot: vd
                ? { metalVariantName: vd.name, metalName: vd.metal?.name ?? vd.name }
                : null,
            } as any;
          }),
        },
      },
      include: {
        createdBy: { select: { id: true, email: true, name: true } },
        warehouse: { select: { id: true, name: true, code: true } },
        lines: {
          include: {
            variant: { select: { id: true, name: true, sku: true, metal: { select: { id: true, name: true } } } },
          },
        },
      },
    });

    // Actualizar stock materializado (WarehouseStock)
    for (const line of lines) {
      let delta: Prisma.Decimal;
      if (opts.kind === "IN") {
        delta = line.grams;
      } else if (opts.kind === "OUT") {
        delta = line.grams.neg();
      } else {
        // ADJUST: gramos con signo (positivo suma, negativo resta)
        delta = line.grams;
      }
      await applyMetalStockDelta(tx, { jewelryId, warehouseId, variantId: line.variantId, delta });
    }

    return enrichMetalMovement(created);
  });
}

export async function transferMovement(opts: {
  jewelryId: string;
  userId: string;

  fromWarehouseId: string;
  toWarehouseId: string;

  effectiveAt: Date;
  note?: string;

  lines: Array<{ variantId: string; grams: any }>;
}) {
  const jewelryId = s(opts.jewelryId);
  const userId = s(opts.userId);

  const fromWarehouseId = s(opts.fromWarehouseId);
  const toWarehouseId = s(opts.toWarehouseId);

  assert(fromWarehouseId, "Almacén origen requerido.");
  assert(toWarehouseId, "Almacén destino requerido.");
  assert(fromWarehouseId !== toWarehouseId, "Origen y destino no pueden ser el mismo.");

  const lines = (opts.lines ?? [])
    .map((l) => ({
      variantId: s(l?.variantId),
      grams: toDec(l?.grams),
    }))
    .filter((l): l is { variantId: string; grams: Prisma.Decimal } =>
      !!(l.variantId && l.grams),
    );

  assert(lines.length > 0, "Agregá al menos una línea.");

  // TRANSFER siempre requiere gramos positivos
  for (const l of lines) {
    assert(l.grams.gt(0), "Los gramos deben ser mayores a 0 en una transferencia.");
  }

  return prisma.$transaction(async (tx) => {
    const [fromWh, toWh] = await Promise.all([
      tx.warehouse.findFirst({ where: { id: fromWarehouseId, jewelryId, deletedAt: null }, select: { id: true, isActive: true } }),
      tx.warehouse.findFirst({ where: { id: toWarehouseId, jewelryId, deletedAt: null }, select: { id: true, isActive: true } }),
    ]);

    assert(!!fromWh, "Almacén origen no encontrado.");
    assert(!!toWh, "Almacén destino no encontrado.");
    assert(fromWh!.isActive, "El almacén origen está inactivo.");
    assert(toWh!.isActive, "El almacén destino está inactivo.");

    const transferCode = await generateMovementCode(tx, jewelryId, "TRANSFER");

    const tvIds = [...new Set(lines.map((l) => l.variantId))];
    const tvData = await tx.metalVariant.findMany({
      where: { id: { in: tvIds } },
      select: { id: true, name: true, metal: { select: { name: true } } },
    });
    const tvNameMap = new Map(tvData.map((v) => [v.id, v]));

    const created = await tx.inventoryMovement.create({
      data: {
        jewelryId,
        kind: "TRANSFER",
        code: transferCode,
        note: s(opts.note || ""),
        effectiveAt: opts.effectiveAt ?? new Date(),
        fromWarehouseId,
        toWarehouseId,
        createdById: userId,
        lines: {
          create: lines.map((l) => {
            const vd = tvNameMap.get(l.variantId);
            return {
              jewelryId,
              variantId: l.variantId,
              grams: l.grams,
              snapshot: vd
                ? { metalVariantName: vd.name, metalName: vd.metal?.name ?? vd.name }
                : null,
            } as any;
          }),
        },
      },
      include: {
        createdBy: { select: { id: true, email: true, name: true } },
        fromWarehouse: { select: { id: true, name: true, code: true } },
        toWarehouse: { select: { id: true, name: true, code: true } },
        lines: {
          include: {
            variant: { select: { id: true, name: true, sku: true, metal: { select: { id: true, name: true } } } },
          },
        },
      },
    });

    // Actualizar stock materializado: FROM pierde gramos, TO los gana
    for (const line of lines) {
      await applyMetalStockDelta(tx, { jewelryId, warehouseId: fromWarehouseId, variantId: line.variantId, delta: line.grams.neg() });
      await applyMetalStockDelta(tx, { jewelryId, warehouseId: toWarehouseId,   variantId: line.variantId, delta: line.grams });
    }

    return enrichMetalMovement(created);
  });
}

export async function voidMovement(opts: { id: string; jewelryId: string; userId: string; note?: string }) {
  const id = s(opts.id);
  const jewelryId = s(opts.jewelryId);
  const userId = s(opts.userId);

  assert(id, "Movimiento inválido.");

  return prisma.$transaction(async (tx) => {
    const row = await tx.inventoryMovement.findFirst({
      where: { id, jewelryId, deletedAt: null },
      select: {
        id: true,
        kind: true,
        warehouseId: true,
        fromWarehouseId: true,
        toWarehouseId: true,
        lines: {
          select: { variantId: true, grams: true },
        },
      },
    });
    assert(!!row, "Movimiento no encontrado.");

    // Revertir el efecto sobre WarehouseStock (inverso al que se aplicó al crear)
    for (const line of row!.lines) {
      const grams = new Prisma.Decimal(line.grams.toString());
      if (row!.kind === "IN") {
        // IN sumo → void resta
        await applyMetalStockDelta(tx, { jewelryId, warehouseId: row!.warehouseId!, variantId: line.variantId, delta: grams.neg() });
      } else if (row!.kind === "OUT") {
        // OUT restó → void suma
        await applyMetalStockDelta(tx, { jewelryId, warehouseId: row!.warehouseId!, variantId: line.variantId, delta: grams });
      } else if (row!.kind === "ADJUST") {
        // ADJUST aplicó grams con signo → void aplica el signo opuesto
        await applyMetalStockDelta(tx, { jewelryId, warehouseId: row!.warehouseId!, variantId: line.variantId, delta: grams.neg() });
      } else if (row!.kind === "TRANSFER") {
        // TRANSFER restó de FROM y sumó a TO → void invierte
        await applyMetalStockDelta(tx, { jewelryId, warehouseId: row!.fromWarehouseId!, variantId: line.variantId, delta: grams });
        await applyMetalStockDelta(tx, { jewelryId, warehouseId: row!.toWarehouseId!,   variantId: line.variantId, delta: grams.neg() });
      }
    }

    const updated = await tx.inventoryMovement.update({
      where: { id },
      data: {
        deletedAt: new Date(),
        voidedById: userId,
        voidedNote: s(opts.note || ""),
        voidedAt: new Date(),
      },
      include: {
        createdBy: { select: { id: true, email: true, name: true } },
        warehouse: { select: { id: true, name: true, code: true } },
        fromWarehouse: { select: { id: true, name: true, code: true } },
        toWarehouse: { select: { id: true, name: true, code: true } },
        lines: {
          include: {
            variant: { select: { id: true, name: true, sku: true, metal: { select: { id: true, name: true } } } },
          },
        },
      },
    });

    return enrichMetalMovement(updated);
  });
}

export async function listMovementsForWarehouse(opts: {
  jewelryId: string
  warehouseId: string
  take?: number
}) {
  const jewelryId = s(opts.jewelryId)
  const warehouseId = s(opts.warehouseId)

  assert(jewelryId, "Tenant inválido.")
  assert(warehouseId, "Almacén inválido.")

  const take = clampTake(opts.take ?? 5, 5)

  const rows = await prisma.inventoryMovement.findMany({
    where: {
      jewelryId,
      deletedAt: null,
      OR: [
        { warehouseId },
        { fromWarehouseId: warehouseId },
        { toWarehouseId: warehouseId }
      ]
    },
    orderBy: [
      { effectiveAt: "desc" },
      { createdAt: "desc" }
    ],
    take,
    include: {
      createdBy: {
        select: { id: true, name: true, email: true }
      },
      lines: {
        include: {
          variant: {
            select: {
              id: true,
              name: true
            }
          }
        }
      }
    }
  })

  return rows.map(enrichMetalMovement)
}
