// tptech-backend/src/modules/movimientos/movimientos.service.ts
import { Prisma } from "@prisma/client";
import { prisma } from "../../lib/prisma.js";

/**
 * Movimiento pensado para joyería:
 * - cantidad = gramos (Decimal compatible)
 * - por ahora: líneas por MetalVariant (variantId)
 *
 * NOTA: este service asume que vas a agregar al schema:
 * - InventoryMovement
 * - InventoryMovementLine
 * - (opcional) WarehouseStock (si querés materializar stock)
 *
 * Si todavía no los agregaste, el código compila pero Prisma no.
 */

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

  // filtro por almacén (cubre warehouseId o from/to)
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

  // búsqueda simple
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
    rows,
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
    .filter((l) => l.variantId && l.grams);

  assert(lines.length > 0, "Agregá al menos una línea.");

  // validación almacén (activo/no borrado)
  const wh = await prisma.warehouse.findFirst({
    where: { id: warehouseId, jewelryId, deletedAt: null },
    select: { id: true, isActive: true },
  });
  assert(!!wh, "Almacén no encontrado.");
  assert(wh!.isActive, "El almacén está inactivo.");

  // crea movimiento + líneas
  const created = await prisma.inventoryMovement.create({
    data: {
      jewelryId,
      kind: opts.kind,
      code: "", // si querés, luego lo generamos con un correlativo
      note: s(opts.note || ""),
      effectiveAt: opts.effectiveAt ?? new Date(),

      warehouseId, // IN/OUT/ADJUST usan warehouseId

      createdById: userId,
      lines: {
        create: lines.map((l) => ({
          jewelryId,
          variantId: l.variantId,
          grams: l.grams!,
        })),
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

  return created;
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
    .filter((l) => l.variantId && l.grams);

  assert(lines.length > 0, "Agregá al menos una línea.");

  const [fromWh, toWh] = await prisma.$transaction([
    prisma.warehouse.findFirst({ where: { id: fromWarehouseId, jewelryId, deletedAt: null }, select: { id: true, isActive: true } }),
    prisma.warehouse.findFirst({ where: { id: toWarehouseId, jewelryId, deletedAt: null }, select: { id: true, isActive: true } }),
  ]);

  assert(!!fromWh, "Almacén origen no encontrado.");
  assert(!!toWh, "Almacén destino no encontrado.");
  assert(fromWh!.isActive, "El almacén origen está inactivo.");
  assert(toWh!.isActive, "El almacén destino está inactivo.");

  const created = await prisma.inventoryMovement.create({
    data: {
      jewelryId,
      kind: "TRANSFER",
      code: "",
      note: s(opts.note || ""),
      effectiveAt: opts.effectiveAt ?? new Date(),

      fromWarehouseId,
      toWarehouseId,

      createdById: userId,
      lines: {
        create: lines.map((l) => ({
          jewelryId,
          variantId: l.variantId,
          grams: l.grams!,
        })),
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

  return created;
}

export async function voidMovement(opts: { id: string; jewelryId: string; userId: string; note?: string }) {
  const id = s(opts.id);
  const jewelryId = s(opts.jewelryId);
  const userId = s(opts.userId);

  assert(id, "Movimiento inválido.");

  const row = await prisma.inventoryMovement.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true, kind: true },
  });
  assert(!!row, "Movimiento no encontrado.");

  // ✅ anulación = soft delete (no borramos líneas)
  const updated = await prisma.inventoryMovement.update({
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

  return updated;
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

  return rows
}
