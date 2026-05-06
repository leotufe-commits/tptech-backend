// commercial-entities-ext.service.ts
// Extended service functions: merma overrides, entity relations, merge, bulk import
import { prisma } from "../../lib/prisma.js";
import type { EntityRole, EntityRelationType } from "@prisma/client";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string): asserts cond {
  if (!cond) { const err: any = new Error(msg); err.status = 400; throw err; }
}

const db = prisma as any;

/* ============================================================
   MERMA OVERRIDES
============================================================ */

export async function listMermaOverrides(entityId: string, tenantId: string) {
  const overrides = await db.entityMermaOverride.findMany({
    where: { entityId, jewelryId: tenantId, deletedAt: null },
    select: {
      id: true,
      variantId: true,
      role: true,
      mermaPercent: true,
      notes: true,
      isActive: true,
      createdAt: true,
      updatedAt: true,
      variant: {
        select: {
          id: true,
          name: true,
          sku: true,
          purity: true,
          isFavorite: true,
          isActive: true,
          metal: { select: { id: true, name: true, symbol: true } },
        },
      },
    },
    orderBy: [{ role: "asc" }, { createdAt: "asc" }],
  });
  return overrides;
}

export async function upsertMermaOverride(
  entityId: string,
  tenantId: string,
  data: {
    variantId: string;
    role: EntityRole;
    mermaPercent: number;
    notes?: string;
    isActive?: boolean;
  }
) {
  const { variantId, role, mermaPercent, notes = "", isActive = true } = data;
  assert(variantId, "variantId es requerido.");
  assert(role === "CLIENT" || role === "SUPPLIER", "role debe ser CLIENT o SUPPLIER.");
  assert(mermaPercent >= 0 && mermaPercent <= 100, "mermaPercent debe estar entre 0 y 100.");

  // Verificar que la entidad pertenece al tenant
  const entity = await prisma.commercialEntity.findFirst({
    where: { id: entityId, jewelryId: tenantId, deletedAt: null },
    select: { id: true },
  });
  assert(entity, "Entidad no encontrada.");

  // Verificar que la variante existe
  const variant = await prisma.metalVariant.findFirst({
    where: { id: variantId, deletedAt: null },
    select: { id: true },
  });
  assert(variant, "Variante no encontrada.");

  const existing = await db.entityMermaOverride.findFirst({
    where: { entityId, variantId, role, deletedAt: null },
    select: { id: true },
  });

  if (existing) {
    return db.entityMermaOverride.update({
      where: { id: existing.id },
      data: { mermaPercent: String(mermaPercent), notes, isActive },
    });
  }

  return db.entityMermaOverride.create({
    data: {
      entityId,
      jewelryId: tenantId,
      variantId,
      role,
      mermaPercent: String(mermaPercent),
      notes,
      isActive,
    },
  });
}

export async function removeMermaOverride(
  entityId: string,
  overrideId: string,
  tenantId: string
) {
  const existing = await db.entityMermaOverride.findFirst({
    where: { id: overrideId, entityId, jewelryId: tenantId },
    select: { id: true },
  });
  assert(existing, "Override no encontrado.");
  await db.entityMermaOverride.update({
    where: { id: overrideId },
    data: { deletedAt: new Date(), isActive: false },
  });
  return { id: overrideId, deleted: true };
}

/* ============================================================
   ENTITY RELATIONS
============================================================ */

const RELATION_SELECT = {
  id: true,
  fromEntityId: true,
  toEntityId: true,
  relationType: true,
  notes: true,
  isActive: true,
  createdAt: true,
  fromEntity: { select: { id: true, displayName: true, code: true, avatarUrl: true, isClient: true, isSupplier: true } },
  toEntity:   { select: { id: true, displayName: true, code: true, avatarUrl: true, isClient: true, isSupplier: true } },
};

export async function listRelations(entityId: string, tenantId: string) {
  const relations = await db.entityRelation.findMany({
    where: {
      jewelryId: tenantId,
      deletedAt: null,
      OR: [{ fromEntityId: entityId }, { toEntityId: entityId }],
    },
    select: RELATION_SELECT,
    orderBy: { createdAt: "asc" },
  });
  return relations;
}

export async function addRelation(
  entityId: string,
  tenantId: string,
  data: {
    targetEntityId: string;
    relationType?: EntityRelationType;
    notes?: string;
  }
) {
  const { targetEntityId, relationType = "OTHER", notes = "" } = data;
  assert(targetEntityId, "targetEntityId es requerido.");
  assert(targetEntityId !== entityId, "No se puede relacionar una entidad consigo misma.");

  // Verificar que ambas entidades existen en el tenant
  const [src, tgt] = await Promise.all([
    prisma.commercialEntity.findFirst({ where: { id: entityId, jewelryId: tenantId, deletedAt: null }, select: { id: true } }),
    prisma.commercialEntity.findFirst({ where: { id: targetEntityId, jewelryId: tenantId, deletedAt: null }, select: { id: true } }),
  ]);
  assert(src, "Entidad origen no encontrada.");
  assert(tgt, "Entidad destino no encontrada.");

  // Check duplicate en cualquier dirección (activo o soft-deleted)
  const existing = await db.entityRelation.findFirst({
    where: {
      jewelryId: tenantId,
      OR: [
        { fromEntityId: entityId,       toEntityId: targetEntityId },
        { fromEntityId: targetEntityId, toEntityId: entityId },
      ],
    },
    select: { id: true, deletedAt: true },
  });

  if (existing && !existing.deletedAt) {
    const err: any = new Error("Ya existe una relación entre estas entidades.");
    err.status = 409;
    throw err;
  }

  if (existing && existing.deletedAt) {
    // Reactivar la relación soft-deleted en lugar de crear una nueva
    return db.entityRelation.update({
      where: { id: existing.id },
      data: { deletedAt: null, isActive: true, relationType, notes },
      select: RELATION_SELECT,
    });
  }

  return db.entityRelation.create({
    data: { jewelryId: tenantId, fromEntityId: entityId, toEntityId: targetEntityId, relationType, notes },
    select: RELATION_SELECT,
  });
}

export async function removeRelation(
  entityId: string,
  relationId: string,
  tenantId: string
) {
  const rel = await db.entityRelation.findFirst({
    where: {
      id: relationId,
      jewelryId: tenantId,
      deletedAt: null,
      OR: [{ fromEntityId: entityId }, { toEntityId: entityId }],
    },
    select: { id: true },
  });
  assert(rel, "Relación no encontrada.");
  await db.entityRelation.update({
    where: { id: relationId },
    data: { deletedAt: new Date(), isActive: false },
  });
  return { id: relationId, deleted: true };
}

/* ============================================================
   MERGE ENTITIES
============================================================ */

export async function getMergePreview(
  sourceId: string,
  targetId: string,
  tenantId: string
) {
  assert(sourceId !== targetId, "Origen y destino no pueden ser la misma entidad.");

  const [source, target] = await Promise.all([
    prisma.commercialEntity.findFirst({
      where: { id: sourceId, jewelryId: tenantId, deletedAt: null },
      select: {
        id: true, displayName: true, code: true, entityType: true,
        isClient: true, isSupplier: true, avatarUrl: true,
        mergedIntoEntityId: true,
      },
    }),
    prisma.commercialEntity.findFirst({
      where: { id: targetId, jewelryId: tenantId, deletedAt: null },
      select: {
        id: true, displayName: true, code: true, entityType: true,
        isClient: true, isSupplier: true, avatarUrl: true,
        mergedIntoEntityId: true,
      },
    }),
  ]);

  assert(source, "Entidad origen no encontrada.");
  assert(target, "Entidad destino no encontrada.");
  assert(!source.mergedIntoEntityId, "La entidad origen ya fue fusionada anteriormente.");
  assert(!target.mergedIntoEntityId, "La entidad destino ya fue fusionada anteriormente.");

  const db2 = prisma as any;
  const [addresses, contacts, attachments, rules, balanceEntries] = await Promise.all([
    prisma.entityAddress.count({ where: { entityId: sourceId, deletedAt: null } }),
    prisma.entityContact.count({ where: { entityId: sourceId, deletedAt: null } }),
    db2.entityAttachment.count({ where: { entityId: sourceId, deletedAt: null } }),
    prisma.entityCommercialRule.count({ where: { entityId: sourceId, deletedAt: null } }),
    prisma.entityBalanceEntry.count({ where: { entityId: sourceId } }),
  ]);

  return {
    source: { id: source.id, displayName: source.displayName, code: source.code, avatarUrl: source.avatarUrl },
    target: { id: target.id, displayName: target.displayName, code: target.code, avatarUrl: target.avatarUrl },
    impact: {
      addresses,
      contacts,
      attachments,
      rules,
      balanceEntries,
    },
  };
}

export async function mergeEntities(
  sourceId: string,
  targetId: string,
  tenantId: string,
  actorId?: string
) {
  assert(sourceId !== targetId, "Origen y destino no pueden ser la misma entidad.");

  const [source, target] = await Promise.all([
    prisma.commercialEntity.findFirst({
      where: { id: sourceId, jewelryId: tenantId, deletedAt: null },
      select: { id: true, displayName: true, mergedIntoEntityId: true },
    }),
    prisma.commercialEntity.findFirst({
      where: { id: targetId, jewelryId: tenantId, deletedAt: null },
      select: { id: true, displayName: true, mergedIntoEntityId: true },
    }),
  ]);

  assert(source, "Entidad origen no encontrada.");
  assert(target, "Entidad destino no encontrada.");
  assert(!source.mergedIntoEntityId, "La entidad origen ya fue fusionada.");
  assert(!target.mergedIntoEntityId, "La entidad destino ya fue fusionada.");

  const db2 = prisma as any;

  await prisma.$transaction(async (tx: any) => {
    const txDb = tx as any;

    // 1. Mover direcciones (solo las que no existen ya en destino — evitar duplicados exactos)
    const srcAddresses = await tx.entityAddress.findMany({
      where: { entityId: sourceId, deletedAt: null },
      select: { id: true, type: true, street: true, streetNumber: true, city: true, province: true, country: true, postalCode: true, label: true, floor: true, apartment: true, isDefault: true },
    });
    for (const addr of srcAddresses) {
      const dup = await tx.entityAddress.findFirst({
        where: { entityId: targetId, deletedAt: null, street: addr.street, streetNumber: addr.streetNumber, city: addr.city },
        select: { id: true },
      });
      if (!dup) {
        await tx.entityAddress.create({
          data: {
            entityId: targetId,
            jewelryId: tenantId,
            type: addr.type,
            label: addr.label,
            street: addr.street,
            streetNumber: addr.streetNumber,
            floor: addr.floor,
            apartment: addr.apartment,
            city: addr.city,
            province: addr.province,
            country: addr.country,
            postalCode: addr.postalCode,
            isDefault: false, // nunca sobreescribir el default del destino
          },
        });
      }
    }

    // 2. Mover contactos (evitar duplicados por email)
    const srcContacts = await tx.entityContact.findMany({
      where: { entityId: sourceId, deletedAt: null },
    });
    for (const c of srcContacts) {
      const dup = c.email
        ? await tx.entityContact.findFirst({ where: { entityId: targetId, deletedAt: null, email: c.email }, select: { id: true } })
        : null;
      if (!dup) {
        await tx.entityContact.create({
          data: {
            entityId: targetId,
            jewelryId: tenantId,
            firstName: c.firstName,
            lastName: c.lastName,
            position: c.position,
            email: c.email,
            phone: c.phone,
            whatsapp: c.whatsapp,
            isPrimary: false, // no tocar el primario del destino
            receivesDocuments: c.receivesDocuments,
            receivesPaymentsOrCollections: c.receivesPaymentsOrCollections,
            notes: c.notes,
          },
        });
      }
    }

    // 3. Mover adjuntos (todos — raramente hay duplicados en archivos)
    await txDb.entityAttachment.updateMany({
      where: { entityId: sourceId, deletedAt: null },
      data: { entityId: targetId },
    });

    // 4. Mover reglas comerciales
    await tx.entityCommercialRule.updateMany({
      where: { entityId: sourceId, deletedAt: null },
      data: { entityId: targetId, jewelryId: tenantId },
    });

    // 5. Mover entradas de saldo (historial — nunca se borra)
    await tx.entityBalanceEntry.updateMany({
      where: { entityId: sourceId },
      data: { entityId: targetId },
    });

    // 6. Mover merma overrides (si no existen ya en destino para la misma variante+role)
    const srcMermas = await txDb.entityMermaOverride.findMany({
      where: { entityId: sourceId, deletedAt: null },
    });
    for (const m of srcMermas) {
      const dup = await txDb.entityMermaOverride.findFirst({
        where: { entityId: targetId, variantId: m.variantId, role: m.role, deletedAt: null },
        select: { id: true },
      });
      if (!dup) {
        await txDb.entityMermaOverride.create({
          data: {
            entityId: targetId,
            jewelryId: tenantId,
            variantId: m.variantId,
            role: m.role,
            mermaPercent: m.mermaPercent,
            notes: m.notes,
            isActive: m.isActive,
          },
        });
      }
    }

    // 7. Redirigir relaciones que apuntan al origen
    await txDb.entityRelation.updateMany({
      where: { fromEntityId: sourceId, deletedAt: null },
      data: { fromEntityId: targetId },
    });
    await txDb.entityRelation.updateMany({
      where: { toEntityId: sourceId, deletedAt: null },
      data: { toEntityId: targetId },
    });

    // 8. Marcar origen como fusionado (soft — nunca se borra físicamente)
    await tx.commercialEntity.update({
      where: { id: sourceId },
      data: {
        mergedIntoEntityId: targetId,
        isActive: false,
        notes: `[FUSIONADO → ${target.displayName} (${targetId})]`,
      },
    });
  });

  return { ok: true, sourceId, targetId, mergedAt: new Date().toISOString() };
}

/* ============================================================
   BULK IMPORT
============================================================ */

export type BulkImportRow = {
  entityType?: string;
  isClient?: string;
  isSupplier?: string;
  firstName?: string;
  lastName?: string;
  companyName?: string;
  tradeName?: string;
  email?: string;
  phone?: string;
  documentType?: string;
  documentNumber?: string;
  ivaCondition?: string;
  paymentTerm?: string;
  notes?: string;
  [key: string]: any;
};

export type BulkImportResult = {
  row: number;
  displayName: string;
  status: "created" | "updated" | "skipped" | "error" | "conflict";
  message?: string;
  id?: string;
  conflictCount?: number;
};

// ─── Normalización para matching por nombre ───────────────────────────────────
function normalizeLegacy(v: string): string {
  return v.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/\s+/g, " ").trim();
}

type LegacyMatchResult =
  | { found: true;  conflict: false; id: string }
  | { found: false; conflict: true;  count: number }
  | { found: false; conflict: false };

async function findExistingLegacy(
  tenantId: string,
  raw: BulkImportRow,
  entityType: "COMPANY" | "PERSON",
  role: "client" | "supplier" | "both",
): Promise<LegacyMatchResult> {
  // 1. code
  const code = s(raw.code ?? "");
  if (code) {
    const found = await prisma.commercialEntity.findFirst({
      where: { jewelryId: tenantId, code, deletedAt: null },
      select: { id: true },
    });
    if (found) return { found: true, conflict: false, id: found.id };
  }

  // 2. documentNumber (con o sin documentType)
  const docNumber = s(raw.documentNumber ?? "");
  const docType   = s(raw.documentType ?? "");
  if (docNumber) {
    const where = docType
      ? { jewelryId: tenantId, documentNumber: docNumber, documentType: docType, deletedAt: null as null }
      : { jewelryId: tenantId, documentNumber: docNumber, deletedAt: null as null };
    const found = await prisma.commercialEntity.findFirst({ where, select: { id: true } });
    if (found) return { found: true, conflict: false, id: found.id };
  }

  // 3. email
  const email = s(raw.email ?? "").toLowerCase();
  if (email) {
    const found = await prisma.commercialEntity.findFirst({
      where: { jewelryId: tenantId, email, deletedAt: null },
      select: { id: true },
    });
    if (found) return { found: true, conflict: false, id: found.id };
  }

  // 4. nombre — fallback, solo si hay match único
  const nameCandidates: string[] = [];
  if (entityType === "COMPANY") {
    const tn = normalizeLegacy(s(raw.tradeName ?? ""));
    const cn = normalizeLegacy(s(raw.companyName ?? ""));
    if (tn) nameCandidates.push(tn);
    if (cn && cn !== tn) nameCandidates.push(cn);
  } else {
    const fn = s(raw.firstName ?? "").trim();
    const ln = s(raw.lastName ?? "").trim();
    const full = [ln, fn].filter(Boolean).join(", ");
    if (full) nameCandidates.push(normalizeLegacy(full));
  }

  if (nameCandidates.length > 0) {
    const broadCandidates = await prisma.commercialEntity.findMany({
      where: {
        jewelryId: tenantId,
        deletedAt: null,
        OR: nameCandidates.map((c) => ({
          displayName: { contains: c.split(",")[0].trim(), mode: "insensitive" as const },
        })),
      },
      select: { id: true, displayName: true },
    });

    const matches = broadCandidates.filter((e) =>
      nameCandidates.some((c) => normalizeLegacy(e.displayName) === c)
    );

    if (matches.length === 1) return { found: true, conflict: false, id: matches[0].id };
    if (matches.length > 1)   return { found: false, conflict: true, count: matches.length };
  }

  return { found: false, conflict: false };
}

export async function bulkImportEntities(
  tenantId: string,
  rows: BulkImportRow[],
  opts: {
    dryRun: boolean;
    mode: "create" | "update" | "upsert";
    role: "client" | "supplier" | "both";
    matchBy?: string; // ignorado — prioridad fija: code > document > email > name
  }
): Promise<{ results: BulkImportResult[]; summary: { created: number; updated: number; skipped: number; errors: number; conflicts: number } }> {
  const results: BulkImportResult[] = [];
  let created = 0, updated = 0, skipped = 0, errors = 0, conflicts = 0;

  function isTruthyLocal(v: string): boolean {
    const n = v.toLowerCase().trim();
    return n === "true" || n === "1" || n === "si" || n === "sí" || n === "yes";
  }

  for (let i = 0; i < rows.length; i++) {
    const raw    = rows[i];
    const rowNum = i + 1;

    try {
      const allValues = Object.values(raw).map((v) => s(v));
      if (allValues.every((v) => !v)) continue;

      const rawType    = s(raw.entityType ?? "").toUpperCase();
      const entityType = (rawType === "COMPANY" || rawType === "EMPRESA") ? "COMPANY" : "PERSON";

      const isClient   = opts.role === "client"   || opts.role === "both" ? true : isTruthyLocal(s(raw.isClient   ?? ""));
      const isSupplier = opts.role === "supplier"  || opts.role === "both" ? true : isTruthyLocal(s(raw.isSupplier ?? ""));

      if (!isClient && !isSupplier) {
        results.push({ row: rowNum, displayName: "?", status: "error", message: "Debe ser cliente o proveedor." });
        errors++;
        continue;
      }

      const firstName      = s(raw.firstName      ?? "");
      const lastName       = s(raw.lastName       ?? "");
      const companyName    = s(raw.companyName    ?? "");
      const tradeName      = s(raw.tradeName      ?? "");
      const email          = s(raw.email          ?? "").toLowerCase();
      const phone          = s(raw.phone          ?? "");
      const documentNumber = s(raw.documentNumber ?? "");
      const documentType   = s(raw.documentType   ?? "");
      const ivaCondition   = s(raw.ivaCondition   ?? "");
      const paymentTerm    = s(raw.paymentTerm    ?? "");
      const notes          = s(raw.notes          ?? "");

      const displayName = entityType === "COMPANY"
        ? tradeName || companyName || "Sin nombre"
        : [lastName, firstName].filter(Boolean).join(", ") || email || documentNumber || "Sin nombre";

      if (!email && !documentNumber && !firstName && !lastName && !companyName && !tradeName) {
        results.push({ row: rowNum, displayName: "—", status: "error", message: "Fila vacía o sin datos identificables." });
        errors++;
        continue;
      }

      // Búsqueda por prioridad
      const match = await findExistingLegacy(tenantId, raw, entityType, opts.role);

      if (match.conflict) {
        results.push({
          row: rowNum, displayName, status: "conflict",
          message: `${match.count} registros coinciden por nombre. Usá código, documento o email.`,
          conflictCount: match.count,
        });
        conflicts++;
        continue;
      }

      const existingId = match.found ? match.id : null;

      if (existingId && opts.mode === "create") {
        results.push({ row: rowNum, displayName, status: "skipped", message: "Ya existe (modo crear)." });
        skipped++;
        continue;
      }
      if (!existingId && opts.mode === "update") {
        results.push({ row: rowNum, displayName, status: "skipped", message: "No encontrado (modo actualizar)." });
        skipped++;
        continue;
      }

      if (opts.dryRun) {
        const action = existingId ? "updated" : "created";
        results.push({ row: rowNum, displayName, status: action });
        if (action === "created") created++; else updated++;
        continue;
      }

      const dn = entityType === "COMPANY"
        ? tradeName || companyName || "Sin nombre"
        : [lastName, firstName].filter(Boolean).join(", ") || email || "Sin nombre";

      const payload: any = {
        entityType, isClient, isSupplier,
        firstName, lastName,
        companyName: companyName || (entityType === "COMPANY" ? tradeName : ""),
        tradeName, email, phone,
        documentType, documentNumber, ivaCondition, paymentTerm, notes,
        displayName: dn,
        sourceType: "IMPORT_CSV",
      };

      if (existingId) {
        await prisma.commercialEntity.update({ where: { id: existingId }, data: payload });
        results.push({ row: rowNum, displayName: dn, status: "updated", id: existingId });
        updated++;
      } else {
        const total = await prisma.commercialEntity.count({ where: { jewelryId: tenantId } });
        let seq = total + 1;
        let code = `CE-${String(seq).padStart(4, "0")}`;
        while (await prisma.commercialEntity.findFirst({ where: { jewelryId: tenantId, code }, select: { id: true } })) {
          seq++;
          code = `CE-${String(seq).padStart(4, "0")}`;
        }
        const created2 = await prisma.commercialEntity.create({
          data: { ...payload, jewelryId: tenantId, code },
          select: { id: true },
        });
        results.push({ row: rowNum, displayName: dn, status: "created", id: created2.id });
        created++;
      }
    } catch (err: any) {
      results.push({ row: rowNum, displayName: String(raw.firstName || raw.companyName || "?"), status: "error", message: err?.message || "Error desconocido." });
      errors++;
    }
  }

  return { results, summary: { created, updated, skipped, errors, conflicts } };
}

// ensureDemoEntities está definido y exportado desde src/lib/initTenantDefaults.ts
// No duplicar aquí.
