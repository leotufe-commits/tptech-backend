// tptech-backend/src/modules/warehouses/warehouses.service.ts
import { prisma } from "../../lib/prisma.js";
import {
  getSalesDefaultWarehouseId,
  setSalesDefaultWarehouseId,
  reassignSalesDefaultWarehouse,
} from "../user-preferences/user-preferences.service.js";

function s(v: any) {
  return String(v ?? "").trim();
}

function assert(cond: any, msg: string): asserts cond {
  if (!cond) {
    const err: any = new Error(msg);
    err.status = 400;
    throw err;
  }
}

/* =========================
   CÓDIGO AUTO DE ALMACÉN
   Formato: ALM01, BOD02, CEN03, etc.
   - 3 letras del nombre (sin tildes) + número de orden (2 dígitos)
   - Solo se usa si el usuario deja el campo code vacío.
   - Cuenta TODOS los almacenes del tenant (incluso borrados)
     para que el número nunca se reutilice.
========================= */
async function generateWarehouseCode(jewelryId: string, name: string): Promise<string> {
  const prefix = name
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "") // quitar tildes
    .replace(/[^a-zA-Z]/g, "")       // solo letras
    .toUpperCase()
    .substring(0, 3)
    .padEnd(3, "X");

  const count = await prisma.warehouse.count({ where: { jewelryId } });
  return `${prefix}${String(count + 1).padStart(2, "0")}`;
}

/* =========================
   INTERNAL: LIST BASE
========================= */
async function listWarehousesBase(jewelryId: string) {
  assert(jewelryId, "Tenant inválido.");

  return prisma.warehouse.findMany({
    where: { jewelryId, deletedAt: null },
    orderBy: [{ isActive: "desc" }, { createdAt: "asc" }],
  });
}

/* =========================
   INTERNAL: EFFECTIVE FAVORITE
   - devuelve favoriteWarehouseId válido (activo + existente)
   - si no hay, auto-asigna el primero activo (si existe)
========================= */
async function getOrAssignEffectiveFavoriteWarehouseId(opts: {
  jewelryId: string;
  userId: string;
  warehouses: Array<{ id: string; isActive: boolean }>;
}) {
  const jewelryId = opts.jewelryId;
  const userId = opts.userId;
  const warehouses = opts.warehouses;

  // Fuente de verdad: UserPreference (con fallback legacy SOLO LECTURA).
  const currentFavId = await getSalesDefaultWarehouseId(jewelryId, userId);

  const currentFavOk =
    !!currentFavId && warehouses.some((w) => w.id === currentFavId && w.isActive === true);

  let effectiveFavId: string | null = currentFavOk ? currentFavId : null;

  if (!effectiveFavId) {
    const firstActive = warehouses.find((w) => w.isActive === true) || null;

    if (firstActive) {
      effectiveFavId = firstActive.id;

      // Persistir el auto-asignado en la NUEVA fuente de verdad.
      await setSalesDefaultWarehouseId(jewelryId, userId, effectiveFavId);
    }
  }

  return effectiveFavId;
}

/* =========================
   LIST (for user)
   - devuelve isFavorite, stockGrams, stockPieces
   - auto-assign SOLO si hace falta
========================= */
export async function listWarehousesForUser(jewelryId: string, userId: string) {
  assert(jewelryId, "Tenant inválido.");
  assert(userId, "Usuario inválido.");

  const [rows, metalStocks, articleStocks] = await Promise.all([
    listWarehousesBase(jewelryId),
    prisma.warehouseStock.groupBy({
      by: ["warehouseId"],
      where: { jewelryId },
      _sum: { grams: true },
    }),
    prisma.articleStock.groupBy({
      by: ["warehouseId"],
      where: { jewelryId, quantity: { gt: 0 } },
      _sum: { quantity: true },
    }),
  ]);

  const effectiveFavId = await getOrAssignEffectiveFavoriteWarehouseId({
    jewelryId,
    userId,
    warehouses: rows.map((w) => ({ id: w.id, isActive: w.isActive })),
  });

  const gramsMap = new Map<string, number>();
  for (const s of metalStocks) {
    gramsMap.set(s.warehouseId, Number(s._sum.grams ?? 0));
  }

  const piecesMap = new Map<string, number>();
  for (const s of articleStocks) {
    piecesMap.set(s.warehouseId, Number(s._sum.quantity ?? 0));
  }

  return rows.map((w) => ({
    ...w,
    isFavorite: !!effectiveFavId && effectiveFavId === w.id,
    stockGrams: gramsMap.get(w.id) ?? 0,
    stockPieces: piecesMap.get(w.id) ?? 0,
  }));
}

/* =========================
   LIST (legacy / admin)
========================= */
export async function listWarehouses(jewelryId: string) {
  return listWarehousesBase(jewelryId);
}

/* =========================
   CREATE
   - si el user no tiene favorito, setea este como favorito
========================= */
export async function createWarehouse(jewelryId: string, userId: string, data: any) {
  assert(jewelryId, "Tenant inválido.");
  assert(userId, "Usuario inválido.");

  const name = s(data?.name);
  assert(name, "Nombre requerido.");

  const codeRaw = s(data?.code ?? "");
  const code = codeRaw || (await generateWarehouseCode(jewelryId, name));

  const created = await prisma.warehouse.create({
    data: {
      jewelryId,
      name,
      code,

      email: s(data?.email ?? ""),
      phoneCountry: s(data?.phoneCountry ?? ""),
      phoneNumber: s(data?.phoneNumber ?? ""),

      attn: s(data?.attn ?? ""),
      street: s(data?.street ?? ""),
      number: s(data?.number ?? ""),
      floor: s(data?.floor ?? ""),
      apartment: s(data?.apartment ?? ""),
      city: s(data?.city ?? ""),
      province: s(data?.province ?? ""),
      postalCode: s(data?.postalCode ?? ""),
      country: s(data?.country ?? ""),

      location: s(data?.location ?? ""),
      notes: s(data?.notes ?? ""),

      isActive: true,
    },
  });

  // si el user todavía no tiene almacén por defecto -> asignar este
  // (fuente de verdad: UserPreference; legacy solo lectura).
  const currentFav = await getSalesDefaultWarehouseId(jewelryId, userId);
  if (!currentFav) {
    await setSalesDefaultWarehouseId(jewelryId, userId, created.id);
  }

  return created;
}

/* =========================
   UPDATE
========================= */
export async function updateWarehouse(id: string, jewelryId: string, data: any) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const name = s(data?.name);
  assert(name, "Nombre requerido.");

  const existing = await prisma.warehouse.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true, isActive: true },
  });

  assert(existing, "Almacén no encontrado.");

  const nextIsActive = data?.isActive === false ? false : true;

  const updated = await prisma.warehouse.update({
    where: { id },
    data: {
      name,
      code: s(data?.code ?? ""),

      email: s(data?.email ?? ""),
      phoneCountry: s(data?.phoneCountry ?? ""),
      phoneNumber: s(data?.phoneNumber ?? ""),

      attn: s(data?.attn ?? ""),
      street: s(data?.street ?? ""),
      number: s(data?.number ?? ""),
      floor: s(data?.floor ?? ""),
      apartment: s(data?.apartment ?? ""),
      city: s(data?.city ?? ""),
      province: s(data?.province ?? ""),
      postalCode: s(data?.postalCode ?? ""),
      country: s(data?.country ?? ""),

      location: s(data?.location ?? ""),
      notes: s(data?.notes ?? ""),

      isActive: nextIsActive,
    },
  });

  // si lo desactivaste y era activo -> reasignar favoritos de usuarios que lo tengan
  if (existing.isActive && !updated.isActive) {
    await reassignFavoriteIfNeeded(jewelryId, id);
  }

  return updated;
}

/* =========================
   TOGGLE ACTIVE
========================= */
export async function toggleWarehouseActive(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const w = await prisma.warehouse.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true, isActive: true, jewelryId: true },
  });

  assert(w, "Almacén no encontrado.");

  // si lo vas a desactivar, validar que quede al menos 1 activo
  if (w.isActive) {
    const activeCount = await prisma.warehouse.count({
      where: { jewelryId: w.jewelryId, deletedAt: null, isActive: true },
    });
    assert(activeCount > 1, "Debe existir al menos un almacén activo.");
  }

  const updated = await prisma.warehouse.update({
    where: { id },
    data: { isActive: !w.isActive },
  });

  if (w.isActive && !updated.isActive) {
    await reassignFavoriteIfNeeded(w.jewelryId, id);
  }

  return updated;
}

/* =========================
   DELETE (SOFT)
   Reglas PRO:
   - no eliminar último activo
   - no eliminar con movimientos
   - no eliminar con stock neto != 0 (gramos)
========================= */
export async function deleteWarehouse(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const w = await prisma.warehouse.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true, isActive: true, jewelryId: true, name: true },
  });

  assert(w, "Almacén no encontrado.");

  // 1) No eliminar último activo
  if (w.isActive) {
    const activeCount = await prisma.warehouse.count({
      where: { jewelryId: w.jewelryId, deletedAt: null, isActive: true },
    });
    assert(activeCount > 1, "No se puede eliminar el último almacén activo.");
  }

  // 2) No eliminar si tiene movimientos de metales (no anulados)
  const movementsCount = await prisma.inventoryMovement.count({
    where: {
      jewelryId,
      deletedAt: null,
      OR: [{ warehouseId: id }, { fromWarehouseId: id }, { toWarehouseId: id }],
    },
  });

  assert(movementsCount === 0, "No se puede eliminar: el almacén tiene movimientos de metales registrados.");

  // 2b) No eliminar si tiene movimientos de artículos (no anulados)
  const articleMovementsCount = await prisma.articleMovement.count({
    where: {
      jewelryId,
      voidedAt: null,
      OR: [{ warehouseId: id }, { fromWarehouseId: id }, { toWarehouseId: id }],
    },
  });

  assert(articleMovementsCount === 0, "No se puede eliminar: el almacén tiene movimientos de artículos registrados.");

  // 3) No eliminar si stock neto != 0 (gramos) según movimientos
  const netGrams = await getWarehouseNetGrams({ jewelryId, warehouseId: id });

  // tolerancia mínima para decimales
  const abs = Math.abs(netGrams);
  assert(abs < 0.000001, "No se puede eliminar: el almacén tiene stock de metales distinto de 0.");

  // 4) No eliminar si tiene stock de artículos terminados
  const articleStockCount = await prisma.articleStock.count({
    where: {
      jewelryId,
      warehouseId: id,
      quantity: { gt: 0 },
    },
  });
  assert(articleStockCount === 0, "No se puede eliminar: el almacén tiene stock de artículos registrado.");

  const deleted = await prisma.warehouse.update({
    where: { id },
    data: { deletedAt: new Date(), isActive: false },
  });

  await reassignFavoriteIfNeeded(w.jewelryId, id);

  return deleted;
}

/* =========================
   STOCK NETO (GRAMOS)
   - IN/ADJUST suman a warehouseId
   - OUT resta a warehouseId
   - TRANSFER resta a fromWarehouseId y suma a toWarehouseId
   - Solo movimientos no anulados (deletedAt null)
========================= */
async function getWarehouseNetGrams(opts: { jewelryId: string; warehouseId: string }) {
  const jewelryId = opts.jewelryId;
  const warehouseId = opts.warehouseId;

  const rows: Array<{ grams: any }> = await prisma.$queryRaw`
    SELECT COALESCE(SUM(x.grams), 0) AS grams
    FROM (
      -- IN + ADJUST -> +grams
      SELECT l."grams"::numeric AS grams
      FROM "InventoryMovementLine" l
      JOIN "InventoryMovement" m ON m."id" = l."movementId"
      WHERE m."jewelryId" = ${jewelryId}
        AND m."deletedAt" IS NULL
        AND m."kind" IN ('IN','ADJUST')
        AND m."warehouseId" = ${warehouseId}

      UNION ALL

      -- OUT -> -grams
      SELECT -l."grams"::numeric AS grams
      FROM "InventoryMovementLine" l
      JOIN "InventoryMovement" m ON m."id" = l."movementId"
      WHERE m."jewelryId" = ${jewelryId}
        AND m."deletedAt" IS NULL
        AND m."kind" = 'OUT'
        AND m."warehouseId" = ${warehouseId}

      UNION ALL

      -- TRANSFER from -> -grams
      SELECT -l."grams"::numeric AS grams
      FROM "InventoryMovementLine" l
      JOIN "InventoryMovement" m ON m."id" = l."movementId"
      WHERE m."jewelryId" = ${jewelryId}
        AND m."deletedAt" IS NULL
        AND m."kind" = 'TRANSFER'
        AND m."fromWarehouseId" = ${warehouseId}

      UNION ALL

      -- TRANSFER to -> +grams
      SELECT l."grams"::numeric AS grams
      FROM "InventoryMovementLine" l
      JOIN "InventoryMovement" m ON m."id" = l."movementId"
      WHERE m."jewelryId" = ${jewelryId}
        AND m."deletedAt" IS NULL
        AND m."kind" = 'TRANSFER'
        AND m."toWarehouseId" = ${warehouseId}
    ) x
  `;

  const v = rows?.[0]?.grams ?? 0;
  const n = typeof v === "string" ? Number(v) : Number(v);
  return Number.isFinite(n) ? n : 0;
}

/* =========================
   FAVORITE AUTO REASSIGN
   - no toca users borrados
========================= */
async function reassignFavoriteIfNeeded(jewelryId: string, removedWarehouseId: string) {
  const newFavorite = await prisma.warehouse.findFirst({
    where: { jewelryId, deletedAt: null, isActive: true },
    orderBy: { createdAt: "asc" },
    select: { id: true },
  });

  // Solo opera sobre UserPreference (fuente de verdad). Los usuarios que
  // todavía dependen del legacy se autocuran lazy en listWarehousesForUser
  // vía getOrAssignEffectiveFavoriteWarehouseId.
  await reassignSalesDefaultWarehouse(
    jewelryId,
    removedWarehouseId,
    newFavorite?.id ?? null
  );
}

/* =========================
   SET FAVORITE
   - valida user dentro del tenant
========================= */
export async function setFavoriteWarehouse(opts: {
  userId: string;
  jewelryId: string;
  warehouseId: string;
}) {
  const userId = s(opts.userId);
  const jewelryId = s(opts.jewelryId);
  const warehouseId = s(opts.warehouseId);

  assert(userId, "Usuario inválido.");
  assert(jewelryId, "Tenant inválido.");
  assert(warehouseId, "Almacén inválido.");

  const user = await prisma.user.findFirst({
    where: { id: userId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(user, "Usuario no encontrado.");

  const warehouse = await prisma.warehouse.findFirst({
    where: { id: warehouseId, jewelryId, deletedAt: null, isActive: true },
    select: { id: true },
  });
  assert(warehouse, "No se puede marcar como favorito.");

  // Preferencia PERSONAL del usuario → UserPreference (fuente de verdad).
  // NO se escribe el legacy User.favoriteWarehouseId.
  await setSalesDefaultWarehouseId(jewelryId, userId, warehouseId);

  return { ok: true, favoriteWarehouseId: warehouseId };
}

/* =========================
   ARTICLE STOCK POR ALMACÉN
   Devuelve ArticleStock con datos de artículo y variante
   para mostrar el inventario de piezas terminadas.
========================= */
export async function getWarehouseArticleStock(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const w = await prisma.warehouse.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(w, "Almacén no encontrado.");

  return prisma.articleStock.findMany({
    where: { warehouseId: id, jewelryId },
    orderBy: [
      { article: { name: "asc" as const } },
      { variant: { name: "asc" as const } },
    ],
    select: {
      id: true,
      quantity: true,
      reservedQty: true,
      updatedAt: true,
      article: {
        select: {
          id: true,
          name: true,
          code: true,
          sku: true,
          weight: true,
          reorderPoint: true,
          isActive: true,
        },
      },
      variant: {
        select: {
          id: true,
          name: true,
          code: true,
          sku: true,
          weightOverride: true,
          reorderPoint: true,
          isActive: true,
        },
      },
    },
  });
}

/* =========================
   METAL STOCK POR ALMACÉN
   Agrega gramos por variante a partir de los movimientos activos.
   Cubre IN / OUT / ADJUST / TRANSFER (desde y hacia el almacén).
========================= */
export async function getWarehouseMetalStock(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const w = await prisma.warehouse.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(w, "Almacén no encontrado.");

  const movements = await prisma.inventoryMovement.findMany({
    where: {
      jewelryId,
      deletedAt: null,
      OR: [
        { warehouseId: id },
        { fromWarehouseId: id },
        { toWarehouseId: id },
      ],
    },
    select: {
      kind: true,
      warehouseId: true,
      fromWarehouseId: true,
      toWarehouseId: true,
      lines: {
        select: {
          variantId: true,
          grams: true,
          variant: {
            select: {
              id: true,
              name: true,
              sku: true,
              metal: { select: { id: true, name: true } },
            },
          },
        },
      },
    },
  });

  const stockMap = new Map<string, { variantId: string; grams: number; variant: any }>();

  for (const m of movements) {
    for (const line of m.lines) {
      const raw = Number(line.grams);
      let delta = 0;

      if      (m.kind === "IN"       && m.warehouseId     === id) delta =  raw;
      else if (m.kind === "OUT"      && m.warehouseId     === id) delta = -raw;
      else if (m.kind === "ADJUST"   && m.warehouseId     === id) delta =  raw; // signed
      else if (m.kind === "TRANSFER" && m.fromWarehouseId === id) delta = -raw;
      else if (m.kind === "TRANSFER" && m.toWarehouseId   === id) delta =  raw;

      if (delta === 0) continue;

      const key   = line.variantId;
      const entry = stockMap.get(key);
      if (entry) {
        entry.grams = Math.round((entry.grams + delta) * 1_000_000) / 1_000_000;
      } else {
        stockMap.set(key, { variantId: line.variantId, grams: delta, variant: line.variant });
      }
    }
  }

  return Array.from(stockMap.values());
}

/* =========================
   ATTACHMENTS
========================= */
export async function getWarehouseAttachments(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  return prisma.warehouseAttachment.findMany({
    where: { warehouseId: id, jewelryId, deletedAt: null },
    select: { id: true, filename: true, url: true, mimeType: true, size: true, createdAt: true },
    orderBy: { createdAt: "asc" },
  });
}

export async function addWarehouseAttachment(
  id: string,
  jewelryId: string,
  data: { filename: string; url: string; mimeType: string; size: number }
) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const warehouse = await prisma.warehouse.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(warehouse, "Almacén no encontrado.");

  return prisma.warehouseAttachment.create({
    data: {
      warehouseId: id,
      jewelryId,
      filename: data.filename,
      url: data.url,
      mimeType: data.mimeType,
      size: data.size,
    },
    select: { id: true, filename: true, url: true, mimeType: true, size: true, createdAt: true },
  });
}

export async function deleteWarehouseAttachment(
  warehouseId: string,
  attachmentId: string,
  jewelryId: string
) {
  assert(warehouseId, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const att = await prisma.warehouseAttachment.findFirst({
    where: { id: attachmentId, warehouseId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(att, "Adjunto no encontrado.");

  return prisma.warehouseAttachment.update({
    where: { id: attachmentId },
    data: { deletedAt: new Date() },
    select: { id: true },
  });
}
