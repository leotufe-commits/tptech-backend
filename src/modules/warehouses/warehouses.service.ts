// tptech-backend/src/modules/warehouses/warehouses.service.ts
import { prisma } from "../../lib/prisma.js";

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

  const user = await prisma.user.findFirst({
    where: { id: userId, jewelryId, deletedAt: null },
    select: { id: true, favoriteWarehouseId: true },
  });

  assert(user, "Usuario no encontrado.");

  const currentFavId = user.favoriteWarehouseId || null;

  const currentFavOk =
    !!currentFavId && warehouses.some((w) => w.id === currentFavId && w.isActive === true);

  let effectiveFavId: string | null = currentFavOk ? currentFavId : null;

  if (!effectiveFavId) {
    const firstActive = warehouses.find((w) => w.isActive === true) || null;

    if (firstActive) {
      effectiveFavId = firstActive.id;

      await prisma.user.updateMany({
        where: { id: userId, jewelryId, deletedAt: null },
        data: { favoriteWarehouseId: effectiveFavId },
      });
    }
  }

  return effectiveFavId;
}

/* =========================
   LIST (for user)
   - devuelve isFavorite
   - auto-assign SOLO si hace falta
========================= */
export async function listWarehousesForUser(jewelryId: string, userId: string) {
  assert(jewelryId, "Tenant inválido.");
  assert(userId, "Usuario inválido.");

  const rows = await listWarehousesBase(jewelryId);

  const effectiveFavId = await getOrAssignEffectiveFavoriteWarehouseId({
    jewelryId,
    userId,
    warehouses: rows.map((w) => ({ id: w.id, isActive: w.isActive })),
  });

  return rows.map((w) => ({
    ...w,
    isFavorite: !!effectiveFavId && effectiveFavId === w.id,
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

      phoneCountry: s(data?.phoneCountry ?? ""),
      phoneNumber: s(data?.phoneNumber ?? ""),

      attn: s(data?.attn ?? ""),
      street: s(data?.street ?? ""),
      number: s(data?.number ?? ""),
      city: s(data?.city ?? ""),
      province: s(data?.province ?? ""),
      postalCode: s(data?.postalCode ?? ""),
      country: s(data?.country ?? ""),

      location: s(data?.location ?? ""),
      notes: s(data?.notes ?? ""),

      isActive: true,
    },
  });

  // si el user todavía no tiene favorito -> asignar
  const user = await prisma.user.findFirst({
    where: { id: userId, jewelryId, deletedAt: null },
    select: { id: true, favoriteWarehouseId: true },
  });

  if (user && !user.favoriteWarehouseId) {
    await prisma.user.updateMany({
      where: { id: userId, jewelryId, deletedAt: null },
      data: { favoriteWarehouseId: created.id },
    });
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

      phoneCountry: s(data?.phoneCountry ?? ""),
      phoneNumber: s(data?.phoneNumber ?? ""),

      attn: s(data?.attn ?? ""),
      street: s(data?.street ?? ""),
      number: s(data?.number ?? ""),
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

  // 2) No eliminar si tiene movimientos (no anulados)
  const movementsCount = await prisma.inventoryMovement.count({
    where: {
      jewelryId,
      deletedAt: null,
      OR: [{ warehouseId: id }, { fromWarehouseId: id }, { toWarehouseId: id }],
    },
  });

  assert(movementsCount === 0, "No se puede eliminar: el almacén tiene movimientos registrados.");

  // 3) No eliminar si stock neto != 0 (gramos) según movimientos
  const netGrams = await getWarehouseNetGrams({ jewelryId, warehouseId: id });

  // tolerancia mínima para decimales
  const abs = Math.abs(netGrams);
  assert(abs < 0.000001, "No se puede eliminar: el almacén tiene stock distinto de 0.");

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
  const users = await prisma.user.findMany({
    where: {
      jewelryId,
      deletedAt: null,
      favoriteWarehouseId: removedWarehouseId,
    },
    select: { id: true },
  });

  if (!users.length) return;

  const newFavorite = await prisma.warehouse.findFirst({
    where: { jewelryId, deletedAt: null, isActive: true },
    orderBy: { createdAt: "asc" },
    select: { id: true },
  });

  if (!newFavorite) {
    await prisma.user.updateMany({
      where: {
        jewelryId,
        deletedAt: null,
        favoriteWarehouseId: removedWarehouseId,
      },
      data: { favoriteWarehouseId: null },
    });
    return;
  }

  await prisma.user.updateMany({
    where: {
      jewelryId,
      deletedAt: null,
      favoriteWarehouseId: removedWarehouseId,
    },
    data: { favoriteWarehouseId: newFavorite.id },
  });
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

  await prisma.user.updateMany({
    where: { id: userId, jewelryId, deletedAt: null },
    data: { favoriteWarehouseId: warehouseId },
  });

  return { ok: true, favoriteWarehouseId: warehouseId };
}