// tptech-backend/src/controllers/catalogs.controller.ts
import type { Request, Response } from "express";
import type { CatalogType } from "@prisma/client";
import { prisma } from "../lib/prisma.js";
import { auditLog } from "../lib/auditLogger.js";

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

/**
 * Normaliza etiqueta:
 * - trim
 * - colapsa espacios internos
 */
function normLabel(v: any) {
  const s = String(v ?? "").trim();
  return s.replace(/\s+/g, " ");
}

/**
 * Prisma runtime guard:
 * Si el PrismaClient generado NO incluye CatalogItem,
 * prisma.catalogItem será undefined y explota con findMany.
 */
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
]);

function parseType(raw: any): CatalogType | null {
  const t = String(raw ?? "").trim().toUpperCase() as CatalogType;
  return ALLOWED_TYPES.has(t) ? t : null;
}

function isPrismaUniqueViolation(e: any) {
  // Prisma: P2002 Unique constraint failed
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

/* =========================
   INTERNAL: 1 favorito por type
========================= */
async function clearOtherFavorites(catalog: any, tenantId: string, type: CatalogType, keepId: string) {
  // Desmarca otros favoritos del mismo tipo (misma joyería)
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
   Query:
     - includeInactive=1 (opcional)
========================= */
export async function listCatalog(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const catalog = requireCatalogDelegate(res);
  if (!catalog) return;

  const type = parseType((req.params as any).type);
  if (!type) {
    return res.status(400).json({ message: "Tipo de catálogo inválido." });
  }

  const includeInactive =
    String(req.query.includeInactive ?? "").trim() === "1" ||
    String(req.query.includeInactive ?? "").trim().toLowerCase() === "true";

  try {
    const items = await catalog.findMany({
      where: {
        jewelryId: tenantId,
        type,
        ...(includeInactive ? {} : { isActive: true }),
      },
      // ✅ Favoritos primero (si existe el campo en DB)
      orderBy: [{ isFavorite: "desc" }, { sortOrder: "asc" }, { label: "asc" }],
      select: {
        id: true,
        type: true,
        label: true,
        isActive: true,
        sortOrder: true,
        isFavorite: true, // ✅ NUEVO
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
   Body: { label: string, sortOrder?: number }
   ✅ upsert-friendly:
     - si ya existe por unique(jewelryId,type,label) => devuelve el existente con created:false
========================= */
export async function createCatalogItem(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const catalog = requireCatalogDelegate(res);
  if (!catalog) return;

  const actorId = (req as any).userId as string | undefined;

  const type = parseType((req.params as any).type);
  if (!type) {
    return res.status(400).json({ message: "Tipo de catálogo inválido." });
  }

  const body = (req.body ?? {}) as Partial<{ label: string; sortOrder: number }>;
  const label = normLabel(body.label);

  if (!label) {
    return res.status(400).json({ message: "label es requerido." });
  }
  if (label.length > 80) {
    return res.status(400).json({ message: "label es demasiado largo (máx 80)." });
  }

  const sortOrder = Number.isFinite(Number(body.sortOrder)) ? Math.trunc(Number(body.sortOrder)) : 0;

  try {
    const created = await catalog.create({
      data: {
        jewelryId: tenantId,
        type,
        label,
        sortOrder,
        isActive: true,
        // isFavorite queda false por default en DB
      },
      select: {
        id: true,
        type: true,
        label: true,
        isActive: true,
        sortOrder: true,
        isFavorite: true, // ✅ NUEVO
        createdAt: true,
        updatedAt: true,
      },
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
    // ✅ si ya existe, devolvemos el existente (para UX fluida)
    if (isPrismaUniqueViolation(e)) {
      try {
        const existing = await catalog.findFirst({
          where: { jewelryId: tenantId, type, label },
          select: {
            id: true,
            type: true,
            label: true,
            isActive: true,
            sortOrder: true,
            isFavorite: true, // ✅ NUEVO
            createdAt: true,
            updatedAt: true,
          },
        });

        auditLog(req, {
          action: "company.catalogs.create",
          success: true,
          userId: actorId,
          tenantId,
          meta: { type, label, sortOrder, created: false, reason: "already_exists" },
        });

        if (existing) return res.status(200).json({ item: existing, created: false });
      } catch {
        // noop
      }
    }

    auditLog(req, {
      action: "company.catalogs.create",
      success: false,
      userId: actorId,
      tenantId,
      meta: { type, label, error: String(e?.message ?? e) },
    });

    return res.status(400).json({
      message: "No se pudo crear. Verificá que no exista un item con el mismo nombre.",
    });
  }
}

/* =========================
   POST /company/catalogs/:type/bulk
   Body: { labels: string[], sortOrderStart?: number }
   ✅ crea en bloque, ignora duplicados (unique)
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

  if (!labels.length) {
    return res.status(400).json({ message: "labels es requerido (array con al menos 1 item)." });
  }
  if (labels.some((x) => x.length > 80)) {
    return res.status(400).json({ message: "Hay labels demasiado largos (máx 80)." });
  }
  if (labels.length > 500) {
    return res.status(400).json({ message: "Demasiados items (máx 500 por carga)." });
  }

  const sortOrderStart = Number.isFinite(Number(body.sortOrderStart)) ? Math.trunc(Number(body.sortOrderStart)) : 0;

  try {
    const data = labels.map((label, idx) => ({
      jewelryId: tenantId,
      type,
      label,
      isActive: true,
      sortOrder: sortOrderStart + idx,
      // isFavorite false default
    }));

    const result = await catalog.createMany({
      data,
      skipDuplicates: true,
    });

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
   PATCH /company/catalogs/item/:id/favorite
   Body: { isFavorite: boolean }
   ✅ 1 favorito por (jewelryId + type)
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
  if (want === null) {
    return res.status(400).json({ message: "isFavorite debe ser boolean." });
  }

  const existing = await catalog.findFirst({
    where: { id, jewelryId: tenantId },
    select: { id: true, type: true, label: true, isFavorite: true },
  });

  if (!existing) return res.status(404).json({ message: "Item no encontrado." });

  try {
    // Si queremos marcar favorito, primero desmarcamos los otros del mismo tipo
    if (want) {
      await clearOtherFavorites(catalog, tenantId, existing.type, id);
    }

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
   PATCH /company/catalogs/item/:id
   Body: { label?: string, isActive?: boolean, sortOrder?: number, isFavorite?: boolean }
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
    if (typeof body.isActive !== "boolean") {
      return res.status(400).json({ message: "isActive debe ser boolean." });
    }
    data.isActive = body.isActive;
  }

  if ("sortOrder" in body) {
    if (!Number.isFinite(Number(body.sortOrder))) {
      return res.status(400).json({ message: "sortOrder debe ser number." });
    }
    data.sortOrder = Math.trunc(Number(body.sortOrder));
  }

  if ("isFavorite" in body) {
    if (typeof body.isFavorite !== "boolean") {
      return res.status(400).json({ message: "isFavorite debe ser boolean." });
    }
    data.isFavorite = body.isFavorite;
  }

  if (!Object.keys(data).length) {
    return res.status(400).json({ message: "No hay campos para actualizar." });
  }

  const existing = await catalog.findFirst({
    where: { id, jewelryId: tenantId },
    select: { id: true, type: true, label: true },
  });

  if (!existing) {
    return res.status(404).json({ message: "Item no encontrado." });
  }

  try {
    // ✅ si se marca favorito, desmarcar otros del mismo type
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

    return res.status(400).json({
      message: "No se pudo actualizar. Verificá que no exista otro item con el mismo nombre.",
    });
  }
}
