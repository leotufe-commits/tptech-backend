// tptech-backend/src/modules/catalogs/catalogs.controller.ts
import type { Request, Response } from "express";
import type { CatalogType } from "@prisma/client";
import { prisma } from "../../lib/prisma.js";
import { auditLog } from "../../lib/auditLogger.js";

/* =========================
   HELPERS
========================= */
function requireTenantId(req: Request, res: Response): string | null {
  const tenantId = (req as any).tenantId as string | undefined;
  if (!tenantId) {
    res.status(400).json({ message: "Tenant no definido en el request." });
    return null;
  }
  return String(tenantId);
}

function normLabel(v: any) {
  const s = String(v ?? "").trim();
  return s.replace(/\s+/g, " ");
}

function requireCatalogDelegate(res: Response) {
  const anyPrisma = prisma as any;
  if (!anyPrisma?.catalogItem) {
    res.status(500).json({
      ok: false,
      message:
        "PrismaClient no incluye el modelo CatalogItem (prisma.catalogItem undefined). " +
        "Corré 'npx prisma generate' y verificá que estás usando el schema correcto (prisma/schema.prisma).",
    });
    return null;
  }
  return anyPrisma.catalogItem as typeof anyPrisma.catalogItem;
}

const ALLOWED_TYPES = new Set<CatalogType>([
  "IVA_CONDITION",
  "DOCUMENT_TYPE",
  "PHONE_PREFIX",
  "CITY",
  "PROVINCE",
  "COUNTRY",
  "PAYMENT_TERM",
  "ARTICLE_BRAND",
  "ARTICLE_MANUFACTURER",
  "UNIT_OF_MEASURE",
  "MULTIPLIER_BASE",
  "WEIGHT_UNIT",
]);

function parseType(raw: any): CatalogType | null {
  const t = String(raw ?? "").trim().toUpperCase() as CatalogType;
  return ALLOWED_TYPES.has(t) ? t : null;
}

function isPrismaUniqueViolation(e: any) {
  return e?.code === "P2002";
}

function parseBool(v: any): boolean | null {
  if (typeof v === "boolean") return v;
  const s = String(v ?? "").trim().toLowerCase();
  if (!s) return null;
  if (s === "1" || s === "true" || s === "yes" || s === "y" || s === "on") return true;
  if (s === "0" || s === "false" || s === "no" || s === "n" || s === "off") return false;
  return null;
}

async function clearOtherFavorites(catalog: any, tenantId: string, type: CatalogType, keepId: string) {
  await catalog.updateMany({
    where: {
      jewelryId: tenantId,
      type,
      isFavorite: true,
      NOT: { id: keepId },
    },
    data: { isFavorite: false },
  });
}

/* =========================
   GET /company/catalogs/:type
========================= */
export async function listCatalog(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const catalog = requireCatalogDelegate(res);
  if (!catalog) return;

  const type = parseType((req.params as any).type);
  if (!type) return res.status(400).json({ message: "Tipo de catálogo inválido." });

  const includeInactive =
    String(req.query.includeInactive ?? "").trim() === "1" ||
    String(req.query.includeInactive ?? "").trim().toLowerCase() === "true";

  try {
    const items = await catalog.findMany({
      where: {
        jewelryId: tenantId,
        type,
        deletedAt: null,
        ...(includeInactive ? {} : { isActive: true }),
      },
      orderBy: [{ sortOrder: "asc" }, { label: "asc" }],
      select: {
        id: true,
        type: true,
        label: true,
        isActive: true,
        isSystem: true,
        sortOrder: true,
        isFavorite: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    auditLog(req, {
      action: "company.catalogs.list",
      success: true,
      userId: (req as any).userId as string | undefined,
      tenantId,
      meta: { type, includeInactive },
    });

    return res.json({ items });
  } catch (e: any) {
    auditLog(req, {
      action: "company.catalogs.list",
      success: false,
      userId: (req as any).userId as string | undefined,
      tenantId,
      meta: { type, error: String(e?.message ?? e) },
    });

    return res.status(500).json({ message: "Error listando catálogo." });
  }
}

/* =========================
   POST /company/catalogs/:type
========================= */
export async function createCatalogItem(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const catalog = requireCatalogDelegate(res);
  if (!catalog) return;

  const actorId = (req as any).userId as string | undefined;

  const type = parseType((req.params as any).type);
  if (!type) return res.status(400).json({ message: "Tipo de catálogo inválido." });

  const body = (req.body ?? {}) as Partial<{ label: string; sortOrder: number }>;
  const label = normLabel(body.label);

  if (!label) return res.status(400).json({ message: "label es requerido." });
  if (label.length > 80) return res.status(400).json({ message: "label es demasiado largo (máx 80)." });

  const sortOrder = Number.isFinite(Number(body.sortOrder)) ? Math.trunc(Number(body.sortOrder)) : 0;

  const ITEM_SELECT = {
    id: true,
    type: true,
    label: true,
    isActive: true,
    isSystem: true,
    sortOrder: true,
    isFavorite: true,
    createdAt: true,
    updatedAt: true,
  };

  // 1. Duplicado activo (case-insensitive) → rechazar con 409
  const existingActive = await catalog.findFirst({
    where: {
      jewelryId: tenantId,
      type,
      label: { equals: label, mode: "insensitive" },
      deletedAt: null,
    },
    select: { id: true },
  });

  if (existingActive) {
    auditLog(req, {
      action: "company.catalogs.create",
      success: false,
      userId: actorId,
      tenantId,
      meta: { type, label, reason: "duplicate_active" },
    });
    return res.status(409).json({ message: "Ya existe un ítem con ese nombre en este catálogo." });
  }

  // 2. Soft-deleted (case-insensitive) → restaurar automáticamente
  const softDeleted = await catalog.findFirst({
    where: {
      jewelryId: tenantId,
      type,
      label: { equals: label, mode: "insensitive" },
      deletedAt: { not: null },
    },
    select: { id: true },
  });

  if (softDeleted) {
    try {
      const restored = await catalog.update({
        where: { id: softDeleted.id },
        data: { deletedAt: null, isActive: true, sortOrder, label },
        select: ITEM_SELECT,
      });

      auditLog(req, {
        action: "company.catalogs.create",
        success: true,
        userId: actorId,
        tenantId,
        meta: { type, label, sortOrder, created: true, restored: true },
      });

      return res.status(200).json({ item: restored, created: true, restored: true });
    } catch (e: any) {
      auditLog(req, {
        action: "company.catalogs.create",
        success: false,
        userId: actorId,
        tenantId,
        meta: { type, label, error: String(e?.message ?? e) },
      });
      return res.status(500).json({ message: "No se pudo restaurar el ítem." });
    }
  }

  // 3. Crear nuevo
  try {
    const created = await catalog.create({
      data: {
        jewelryId: tenantId,
        type,
        label,
        sortOrder,
        isActive: true,
      },
      select: ITEM_SELECT,
    });

    auditLog(req, {
      action: "company.catalogs.create",
      success: true,
      userId: actorId,
      tenantId,
      meta: { type, label, sortOrder, created: true },
    });

    return res.status(201).json({ item: created, created: true });
  } catch (e: any) {
    auditLog(req, {
      action: "company.catalogs.create",
      success: false,
      userId: actorId,
      tenantId,
      meta: { type, label, error: String(e?.message ?? e) },
    });

    return res.status(500).json({ message: "No se pudo crear el ítem." });
  }
}

/* =========================
   POST /company/catalogs/:type/bulk
========================= */
export async function bulkCreateCatalogItems(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const catalog = requireCatalogDelegate(res);
  if (!catalog) return;

  const actorId = (req as any).userId as string | undefined;

  const type = parseType((req.params as any).type);
  if (!type) return res.status(400).json({ message: "Tipo de catálogo inválido." });

  const body = (req.body ?? {}) as Partial<{ labels: any[]; sortOrderStart: number }>;
  const labelsRaw = Array.isArray(body.labels) ? body.labels : [];
  const labels = Array.from(new Set(labelsRaw.map(normLabel).filter(Boolean)));

  if (!labels.length) return res.status(400).json({ message: "labels es requerido (array con al menos 1 item)." });
  if (labels.some((x) => x.length > 80)) return res.status(400).json({ message: "Hay labels demasiado largos (máx 80)." });
  if (labels.length > 500) return res.status(400).json({ message: "Demasiados items (máx 500 por carga)." });

  const sortOrderStart = Number.isFinite(Number(body.sortOrderStart)) ? Math.trunc(Number(body.sortOrderStart)) : 0;

  try {
    const data = labels.map((label, idx) => ({
      jewelryId: tenantId,
      type,
      label,
      isActive: true,
      sortOrder: sortOrderStart + idx,
    }));

    const result = await catalog.createMany({ data, skipDuplicates: true });

    auditLog(req, {
      action: "company.catalogs.bulkCreate",
      success: true,
      userId: actorId,
      tenantId,
      meta: { type, requested: labels.length, created: result.count },
    });

    return res.status(201).json({
      ok: true,
      requested: labels.length,
      created: result.count,
      skipped: labels.length - result.count,
    });
  } catch (e: any) {
    auditLog(req, {
      action: "company.catalogs.bulkCreate",
      success: false,
      userId: actorId,
      tenantId,
      meta: { type, error: String(e?.message ?? e) },
    });
    return res.status(500).json({ message: "Error creando items en bulk." });
  }
}

/* =========================
   PATCH /company/catalogs/item/:id
========================= */
export async function updateCatalogItem(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const catalog = requireCatalogDelegate(res);
  if (!catalog) return;

  const actorId = (req as any).userId as string | undefined;

  const id = String((req.params as any).id ?? "").trim();
  if (!id) return res.status(400).json({ message: "id inválido." });

  const body = (req.body ?? {}) as Partial<{
    label: string;
    isActive: boolean;
    sortOrder: number;
    isFavorite: boolean;
  }>;

  const data: any = {};

  if ("label" in body) {
    const label = normLabel(body.label);
    if (!label) return res.status(400).json({ message: "label no puede ser vacío." });
    if (label.length > 80) return res.status(400).json({ message: "label es demasiado largo (máx 80)." });
    data.label = label;
  }

  if ("isActive" in body) {
    if (typeof body.isActive !== "boolean") return res.status(400).json({ message: "isActive debe ser boolean." });
    data.isActive = body.isActive;
  }

  if ("sortOrder" in body) {
    if (!Number.isFinite(Number(body.sortOrder))) return res.status(400).json({ message: "sortOrder debe ser number." });
    data.sortOrder = Math.trunc(Number(body.sortOrder));
  }

  if ("isFavorite" in body) {
    if (typeof body.isFavorite !== "boolean") return res.status(400).json({ message: "isFavorite debe ser boolean." });
    data.isFavorite = body.isFavorite;
  }

  if (!Object.keys(data).length) return res.status(400).json({ message: "No hay campos para actualizar." });

  const existing = await catalog.findFirst({
    where: { id, jewelryId: tenantId },
    select: { id: true, type: true, label: true },
  });

  if (!existing) return res.status(404).json({ message: "Item no encontrado." });

  try {
    if (data.isFavorite === true) {
      await clearOtherFavorites(catalog, tenantId, existing.type, id);
    }

    const updated = await catalog.update({
      where: { id },
      data,
      select: {
        id: true,
        type: true,
        label: true,
        isActive: true,
        sortOrder: true,
        isFavorite: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    auditLog(req, {
      action: "company.catalogs.update",
      success: true,
      userId: actorId,
      tenantId,
      meta: { id, type: existing.type, fields: Object.keys(data) },
    });

    return res.json({ item: updated });
  } catch (e: any) {
    auditLog(req, {
      action: "company.catalogs.update",
      success: false,
      userId: actorId,
      tenantId,
      meta: { id, type: existing.type, error: String(e?.message ?? e) },
    });

    return res.status(400).json({ message: "No se pudo actualizar. Verificá que no exista otro item con el mismo nombre." });
  }
}

/* =========================
   PATCH /company/catalogs/item/:id/favorite
========================= */
export async function setCatalogItemFavorite(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const catalog = requireCatalogDelegate(res);
  if (!catalog) return;

  const actorId = (req as any).userId as string | undefined;

  const id = String((req.params as any).id ?? "").trim();
  if (!id) return res.status(400).json({ message: "id inválido." });

  const want = parseBool((req.body ?? {})?.isFavorite);
  if (want === null) return res.status(400).json({ message: "isFavorite debe ser boolean." });

  const existing = await catalog.findFirst({
    where: { id, jewelryId: tenantId },
    select: { id: true, type: true, label: true, isFavorite: true },
  });

  if (!existing) return res.status(404).json({ message: "Item no encontrado." });

  try {
    if (want) await clearOtherFavorites(catalog, tenantId, existing.type, id);

    const updated = await catalog.update({
      where: { id },
      data: { isFavorite: want },
      select: {
        id: true,
        type: true,
        label: true,
        isActive: true,
        sortOrder: true,
        isFavorite: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    auditLog(req, {
      action: "company.catalogs.favorite",
      success: true,
      userId: actorId,
      tenantId,
      meta: { id, type: existing.type, isFavorite: want },
    });

    return res.json({ item: updated });
  } catch (e: any) {
    auditLog(req, {
      action: "company.catalogs.favorite",
      success: false,
      userId: actorId,
      tenantId,
      meta: { id, type: existing.type, error: String(e?.message ?? e) },
    });

    return res.status(500).json({ message: "Error actualizando favorito." });
  }
}

/* =========================
   HELPER — ¿Está el label en uso en otras entidades del tenant?
   Devuelve un mensaje de error si está en uso, null si está libre.
   La búsqueda es por coincidencia exacta de string (el label se guarda denormalizado).
========================= */
async function checkCatalogItemInUse(
  tenantId: string,
  type: CatalogType,
  label: string
): Promise<string | null> {
  const db = prisma as any;

  try {
    switch (type) {
      case "IVA_CONDITION": {
        const [jewelry, entities] = await Promise.all([
          db.jewelry.findFirst({ where: { id: tenantId, ivaCondition: label }, select: { id: true } }),
          db.commercialEntity?.count({ where: { jewelryId: tenantId, ivaCondition: label, deletedAt: null } }) ?? 0,
        ]);
        if (jewelry || entities > 0)
          return "No se puede eliminar porque está siendo usado en datos fiscales.";
        return null;
      }

      case "PHONE_PREFIX": {
        const [jewelry, users, warehouses] = await Promise.all([
          db.jewelry.findFirst({ where: { id: tenantId, phoneCountry: label }, select: { id: true } }),
          db.user.count({ where: { jewelryId: tenantId, phoneCountry: label, deletedAt: null } }),
          db.warehouse.count({ where: { jewelryId: tenantId, phoneCountry: label, deletedAt: null } }),
        ]);
        if (jewelry || users > 0 || warehouses > 0)
          return "No se puede eliminar porque está siendo usado en prefijos telefónicos.";
        return null;
      }

      case "DOCUMENT_TYPE": {
        const [users, sellers, entities] = await Promise.all([
          db.user.count({ where: { jewelryId: tenantId, documentType: label, deletedAt: null } }),
          db.seller.count({ where: { jewelryId: tenantId, documentType: label, deletedAt: null } }),
          db.commercialEntity?.count({ where: { jewelryId: tenantId, documentType: label, deletedAt: null } }) ?? 0,
        ]);
        if (users > 0 || sellers > 0 || entities > 0)
          return "No se puede eliminar porque está siendo usado en tipos de documento.";
        return null;
      }

      case "COUNTRY": {
        const [jewelry, users, warehouses, carriers, sellers, addresses] = await Promise.all([
          db.jewelry.findFirst({ where: { id: tenantId, country: label }, select: { id: true } }),
          db.user.count({ where: { jewelryId: tenantId, country: label, deletedAt: null } }),
          db.warehouse.count({ where: { jewelryId: tenantId, country: label, deletedAt: null } }),
          db.shippingCarrier.count({ where: { jewelryId: tenantId, country: label, deletedAt: null } }),
          db.seller.count({ where: { jewelryId: tenantId, country: label, deletedAt: null } }),
          db.entityAddress?.count({ where: { jewelryId: tenantId, country: label, deletedAt: null } }) ?? 0,
        ]);
        if (jewelry || users > 0 || warehouses > 0 || carriers > 0 || sellers > 0 || addresses > 0)
          return "No se puede eliminar porque está siendo usado en direcciones.";
        return null;
      }

      case "PROVINCE": {
        const [jewelry, users, warehouses, carriers, sellers, addresses, rates] = await Promise.all([
          db.jewelry.findFirst({ where: { id: tenantId, province: label }, select: { id: true } }),
          db.user.count({ where: { jewelryId: tenantId, province: label, deletedAt: null } }),
          db.warehouse.count({ where: { jewelryId: tenantId, province: label, deletedAt: null } }),
          db.shippingCarrier.count({ where: { jewelryId: tenantId, province: label, deletedAt: null } }),
          db.seller.count({ where: { jewelryId: tenantId, province: label, deletedAt: null } }),
          db.entityAddress?.count({ where: { jewelryId: tenantId, province: label, deletedAt: null } }) ?? 0,
          db.shippingRate?.count({ where: { jewelryId: tenantId, province: label } }) ?? 0,
        ]);
        if (jewelry || users > 0 || warehouses > 0 || carriers > 0 || sellers > 0 || addresses > 0 || rates > 0)
          return "No se puede eliminar porque está siendo usado en provincias/estados.";
        return null;
      }

      case "CITY": {
        const [jewelry, users, warehouses, carriers, sellers, addresses] = await Promise.all([
          db.jewelry.findFirst({ where: { id: tenantId, city: label }, select: { id: true } }),
          db.user.count({ where: { jewelryId: tenantId, city: label, deletedAt: null } }),
          db.warehouse.count({ where: { jewelryId: tenantId, city: label, deletedAt: null } }),
          db.shippingCarrier.count({ where: { jewelryId: tenantId, city: label, deletedAt: null } }),
          db.seller.count({ where: { jewelryId: tenantId, city: label, deletedAt: null } }),
          db.entityAddress?.count({ where: { jewelryId: tenantId, city: label, deletedAt: null } }) ?? 0,
        ]);
        if (jewelry || users > 0 || warehouses > 0 || carriers > 0 || sellers > 0 || addresses > 0)
          return "No se puede eliminar porque está siendo usado en ciudades.";
        return null;
      }

      default:
        return null;
    }
  } catch {
    // Si algún modelo no está disponible aún en el cliente Prisma, no bloquear
    return null;
  }
}

/* =========================
   DELETE /company/catalogs/item/:id
========================= */
export async function deleteCatalogItem(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const catalog = requireCatalogDelegate(res);
  if (!catalog) return;

  const actorId = (req as any).userId as string | undefined;

  const id = String((req.params as any).id ?? "").trim();
  if (!id) return res.status(400).json({ message: "id inválido." });

  const existing = await catalog.findFirst({
    where: { id, jewelryId: tenantId, deletedAt: null },
    select: { id: true, type: true, label: true },
  });

  if (!existing) return res.status(404).json({ message: "Ítem no encontrado." });

  const inUseMessage = await checkCatalogItemInUse(tenantId, existing.type, existing.label);
  if (inUseMessage) {
    auditLog(req, {
      action: "company.catalogs.delete",
      success: false,
      userId: actorId,
      tenantId,
      meta: { id, type: existing.type, label: existing.label, reason: "in_use" },
    });
    return res.status(409).json({ message: inUseMessage });
  }

  try {
    await catalog.update({
      where: { id },
      data: { deletedAt: new Date(), isActive: false },
    });

    auditLog(req, {
      action: "company.catalogs.delete",
      success: true,
      userId: actorId,
      tenantId,
      meta: { id, type: existing.type, label: existing.label },
    });

    return res.json({ ok: true });
  } catch (e: any) {
    auditLog(req, {
      action: "company.catalogs.delete",
      success: false,
      userId: actorId,
      tenantId,
      meta: { id, error: String(e?.message ?? e) },
    });
    return res.status(500).json({ message: "No se pudo eliminar el ítem." });
  }
}