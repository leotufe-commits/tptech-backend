// commercial-entities.import.service.ts
// Servicio de importación masiva v2: soporta dirección, contacto, validaciones completas,
// resolución de catálogos por nombre/código y detección de duplicados por prioridad.
import { prisma } from "../../lib/prisma.js";
import type { EntityType } from "@prisma/client";

function s(v: any): string { return String(v ?? "").trim(); }
function isTruthy(v: string): boolean {
  const n = v.toLowerCase().trim();
  return n === "true" || n === "1" || n === "si" || n === "sí" || n === "yes";
}

// ─── Normalización de strings ─────────────────────────────────────────────────
// Convierte a minúsculas, elimina acentos, normaliza espacios.
// Se usa para comparar nombres de manera flexible pero segura.
function normalizeStr(v: string): string {
  return v
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim();
}

// ─── Tipos públicos ──────────────────────────────────────────────────────────

export type ImportRow = Record<string, string>;

export type ImportPreviewRow = {
  index:          number;
  displayName:    string;
  status:         "valid" | "existing" | "error" | "conflict";
  errors:         string[];
  existingId?:    string;
  conflictCount?: number;
  matchedBy?:     "code" | "document" | "email" | "name";
};

export type ImportPreviewResult = {
  total:     number;
  valid:     number;
  errors:    number;
  conflicts: number;
  new:       number;
  existing:  number;
  rows:      ImportPreviewRow[];
};

export type ImportCommitRow = {
  row:            number;
  displayName:    string;
  status:         "created" | "updated" | "skipped" | "error" | "conflict";
  errors?:        string[];
  message?:       string;
  id?:            string;
  conflictCount?: number;
};

export type ImportCommitResult = {
  results: ImportCommitRow[];
  summary: { created: number; updated: number; skipped: number; errors: number; conflicts: number };
};

// ─── Resultado de búsqueda ───────────────────────────────────────────────────

type MatchResult =
  | { found: true;  conflict: false; id: string; matchedBy: "code" | "document" | "email" | "name" }
  | { found: false; conflict: true;  count: number }
  | { found: false; conflict: false };

// ─── Validación ──────────────────────────────────────────────────────────────

function validateRow(row: ImportRow, role: "client" | "supplier" | "both" = "both"): string[] {
  const errs: string[] = [];
  const rawType = s(row.entityType).toUpperCase();
  const entityType = (rawType === "COMPANY" || rawType === "EMPRESA") ? "COMPANY" : "PERSON";

  if (role === "supplier") {
    if (!s(row.tradeName)) {
      errs.push("Se requiere Nombre de fantasía.");
    }
  } else if (role === "client") {
    if (entityType === "COMPANY") {
      if (!s(row.companyName) && !s(row.tradeName)) {
        errs.push("EMPRESA requiere Razón social o Nombre de fantasía.");
      }
    } else {
      if (!s(row.firstName) && !s(row.lastName)) {
        errs.push("PERSONA requiere Nombre y Apellido.");
      }
    }
  } else {
    if (entityType === "COMPANY") {
      if (!s(row.companyName) && !s(row.tradeName)) {
        errs.push("EMPRESA requiere Razón social o Nombre de fantasía.");
      }
    } else {
      if (!s(row.firstName) && !s(row.lastName) && !s(row.tradeName)) {
        errs.push("Se requiere al menos Nombre, Apellido o Nombre de fantasía.");
      }
    }
  }

  const email = s(row.email);
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    errs.push(`Email inválido: "${email}".`);
  }

  const contactEmail = s(row.contactEmail);
  if (contactEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contactEmail)) {
    errs.push(`Email de contacto inválido: "${contactEmail}".`);
  }

  const credit = s(row.creditLimitSupplier).replace(",", ".");
  if (credit && isNaN(Number(credit))) {
    errs.push(`Límite de crédito inválido: "${credit}".`);
  }

  return errs;
}

// ─── Display name ─────────────────────────────────────────────────────────────

function buildDisplayName(row: ImportRow): string {
  const rawType = s(row.entityType).toUpperCase();
  const isCompany = rawType === "COMPANY" || rawType === "EMPRESA";
  if (isCompany) {
    return s(row.tradeName) || s(row.companyName) || s(row.email) || "Sin nombre";
  }
  const parts = [s(row.lastName), s(row.firstName)].filter(Boolean);
  return parts.join(", ") || s(row.email) || s(row.documentNumber) || "Sin nombre";
}

// ─── Código automático ────────────────────────────────────────────────────────

async function generateEntityCode(jewelryId: string): Promise<string> {
  const total = await prisma.commercialEntity.count({ where: { jewelryId } });
  let seq = total + 1;
  let code = `CE-${String(seq).padStart(4, "0")}`;
  while (await prisma.commercialEntity.findFirst({ where: { jewelryId, code }, select: { id: true } })) {
    seq++;
    code = `CE-${String(seq).padStart(4, "0")}`;
  }
  return code;
}

// ─── Resolución de catálogos ──────────────────────────────────────────────────

async function resolveCurrency(value: string, jewelryId: string): Promise<string | null> {
  if (!value) return null;
  const found = await prisma.currency.findFirst({
    where: {
      jewelryId, deletedAt: null, isActive: true,
      OR: [
        { code: { equals: value, mode: "insensitive" } },
        { name: { contains: value, mode: "insensitive" } },
      ],
    },
    select: { id: true },
  });
  return found?.id ?? null;
}

async function resolvePriceList(value: string, jewelryId: string): Promise<string | null> {
  if (!value) return null;
  const found = await prisma.priceList.findFirst({
    where: {
      jewelryId, deletedAt: null, isActive: true,
      name: { contains: value, mode: "insensitive" },
    },
    select: { id: true },
  });
  return found?.id ?? null;
}

// ─── Detección de duplicados por prioridad ────────────────────────────────────
//
// Prioridad:
//   1. code           — identificador único, exacto
//   2. documentNumber — con o sin documentType (ambos exactos)
//   3. email          — exacto (normalizado a lowercase)
//   4. nombre         — fallback: SOLO si hay exactamente 1 coincidencia
//                       Proveedor: tradeName o companyName
//                       Cliente:   firstName + lastName (→ displayName "Apellido, Nombre")
//                       Múltiples coincidencias → conflicto (no actualizar)
//
// Nunca se usa nombre como clave principal.
// El nombre solo resuelve si el match es único e inequívoco.

async function findExisting(row: ImportRow, jewelryId: string): Promise<MatchResult> {
  // 1. Código
  const code = s(row.code);
  if (code) {
    const found = await prisma.commercialEntity.findFirst({
      where: { jewelryId, code, deletedAt: null },
      select: { id: true },
    });
    if (found) return { found: true, conflict: false, id: found.id, matchedBy: "code" };
  }

  // 2. Documento (con tipo o sin tipo)
  const docNumber = s(row.documentNumber);
  const docType   = s(row.documentType);
  if (docNumber) {
    const whereDoc = docType
      ? { jewelryId, documentNumber: docNumber, documentType: docType, deletedAt: null as null }
      : { jewelryId, documentNumber: docNumber, deletedAt: null as null };
    const found = await prisma.commercialEntity.findFirst({
      where: whereDoc,
      select: { id: true },
    });
    if (found) return { found: true, conflict: false, id: found.id, matchedBy: "document" };
  }

  // 3. Email
  const email = s(row.email).toLowerCase();
  if (email) {
    const found = await prisma.commercialEntity.findFirst({
      where: { jewelryId, email, deletedAt: null },
      select: { id: true },
    });
    if (found) return { found: true, conflict: false, id: found.id, matchedBy: "email" };
  }

  // 4. Nombre — fallback, solo si hay match único
  const rawType   = s(row.entityType).toUpperCase();
  const isCompany = rawType === "COMPANY" || rawType === "EMPRESA";

  // Construir candidatos normalizados según tipo de entidad
  const nameCandidates: string[] = [];
  if (isCompany) {
    const tn = normalizeStr(s(row.tradeName));
    const cn = normalizeStr(s(row.companyName));
    if (tn) nameCandidates.push(tn);
    if (cn && cn !== tn) nameCandidates.push(cn);
  } else {
    const fn = s(row.firstName).trim();
    const ln = s(row.lastName).trim();
    if (fn || ln) {
      // displayName se construye como "Apellido, Nombre" (igual que calcDisplayName)
      const full = [ln, fn].filter(Boolean).join(", ");
      if (full) nameCandidates.push(normalizeStr(full));
    }
  }

  if (nameCandidates.length > 0) {
    // Búsqueda amplia por displayName insensitive para reducir candidatos
    const broadCandidates = await prisma.commercialEntity.findMany({
      where: {
        jewelryId,
        deletedAt: null,
        OR: nameCandidates.map((c) => ({
          displayName: { contains: c.split(",")[0].trim(), mode: "insensitive" as const },
        })),
      },
      select: { id: true, displayName: true },
    });

    // Filtro estricto: normalizar displayName de DB y comparar exacto
    const matches = broadCandidates.filter((e) =>
      nameCandidates.some((c) => normalizeStr(e.displayName) === c)
    );

    if (matches.length === 1) {
      return { found: true, conflict: false, id: matches[0].id, matchedBy: "name" };
    }
    if (matches.length > 1) {
      return { found: false, conflict: true, count: matches.length };
    }
  }

  return { found: false, conflict: false };
}

// ─── Helpers de datos relacionados ───────────────────────────────────────────

function hasAddressData(row: ImportRow): boolean {
  return !!(s(row.street) || s(row.city) || s(row.province) || s(row.postalCode));
}

function hasContactData(row: ImportRow): boolean {
  return !!(s(row.contactFirstName) || s(row.contactLastName) || s(row.contactEmail) || s(row.contactPhone));
}

// ─── Payload entidad ─────────────────────────────────────────────────────────

function buildEntityPayload(
  row: ImportRow,
  currencyId: string | null,
  priceListId: string | null,
  role: "client" | "supplier" | "both",
) {
  const rawType   = s(row.entityType).toUpperCase();
  const entityType: EntityType = (rawType === "COMPANY" || rawType === "EMPRESA") ? "COMPANY" : "PERSON";
  const isActiveStr = s(row.isActive);
  const isActive  = isActiveStr === "" ? true : isTruthy(isActiveStr);
  const creditStr = s(row.creditLimitSupplier).replace(",", ".");
  const creditLimitSupplier = creditStr && !isNaN(Number(creditStr)) ? Number(creditStr) : undefined;

  const isClient   = role === "client"   || role === "both";
  const isSupplier = role === "supplier" || role === "both";

  const companyName = s(row.companyName) || (entityType === "COMPANY" ? s(row.tradeName) : "");

  return {
    entityType,
    isClient,
    isSupplier,
    firstName:      s(row.firstName),
    lastName:       s(row.lastName),
    companyName,
    tradeName:      s(row.tradeName),
    email:          s(row.email).toLowerCase(),
    phone:          s(row.phone),
    documentType:   s(row.documentType),
    documentNumber: s(row.documentNumber),
    ivaCondition:   s(row.ivaCondition),
    paymentTerm:    s(row.paymentTerm),
    notes:          s(row.notes),
    isActive,
    sourceType:     "IMPORT_CSV" as const,
    ...(creditLimitSupplier !== undefined ? { creditLimitSupplier } : {}),
    ...(currencyId  ? { currencyId }  : {}),
    ...(priceListId ? { priceListId } : {}),
  } as any; // eslint-disable-line @typescript-eslint/no-explicit-any
}

// ─── PREVIEW ─────────────────────────────────────────────────────────────────

export async function previewImport(
  tenantId: string,
  rows: ImportRow[],
  opts: { role: "client" | "supplier" | "both" },
): Promise<ImportPreviewResult> {
  const results: ImportPreviewRow[] = [];
  let validCount = 0, errorCount = 0, newCount = 0, existingCount = 0, conflictCount = 0;

  for (let i = 0; i < rows.length; i++) {
    const raw = rows[i];
    if (Object.values(raw).every((v) => !s(v))) continue;

    const displayName = buildDisplayName(raw);
    const errs = validateRow(raw, opts.role);

    if (errs.length > 0) {
      errorCount++;
      results.push({ index: i + 1, displayName, status: "error", errors: errs });
      continue;
    }

    const match = await findExisting(raw, tenantId);

    if (match.found) {
      existingCount++;
      results.push({
        index:      i + 1,
        displayName,
        status:     "existing",
        errors:     [],
        existingId: match.id,
        matchedBy:  match.matchedBy,
      });
    } else if (match.conflict) {
      conflictCount++;
      results.push({
        index:         i + 1,
        displayName,
        status:        "conflict",
        errors:        [`${match.count} registros con ese nombre. Usá código, documento o email para identificar.`],
        conflictCount: match.count,
      });
    } else {
      newCount++;
      validCount++;
      results.push({ index: i + 1, displayName, status: "valid", errors: [] });
    }
  }

  return {
    total:     results.length,
    valid:     validCount + existingCount,
    errors:    errorCount,
    conflicts: conflictCount,
    new:       newCount,
    existing:  existingCount,
    rows:      results,
  };
}

// ─── COMMIT ──────────────────────────────────────────────────────────────────

export async function commitImport(
  tenantId: string,
  rows: ImportRow[],
  opts: {
    mode:    "create" | "update" | "upsert";
    role:    "client" | "supplier" | "both";
    matchBy?: string; // ignorado — la prioridad es fija: code > document > email > name
  },
): Promise<ImportCommitResult> {
  const results: ImportCommitRow[] = [];
  let created = 0, updated = 0, skipped = 0, errors = 0, conflicts = 0;

  for (let i = 0; i < rows.length; i++) {
    const raw    = rows[i];
    const rowNum = i + 1;
    if (Object.values(raw).every((v) => !s(v))) continue;

    const displayName = buildDisplayName(raw);

    try {
      const errs = validateRow(raw, opts.role);
      if (errs.length > 0) {
        results.push({ row: rowNum, displayName, status: "error", errors: errs, message: errs[0] });
        errors++;
        continue;
      }

      const match = await findExisting(raw, tenantId);

      // Conflicto: múltiples coincidencias por nombre → no procesar
      if (match.conflict) {
        results.push({
          row:          rowNum,
          displayName,
          status:       "conflict",
          message:      `${match.count} registros coinciden por nombre. Usá código, documento o email.`,
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

      const currencyId  = await resolveCurrency(s(raw.currencyCode), tenantId);
      const priceListId = await resolvePriceList(s(raw.priceListName), tenantId);
      const payload     = buildEntityPayload(raw, currencyId, priceListId, opts.role);
      const dn          = buildDisplayName(raw);

      if (existingId) {
        await prisma.commercialEntity.update({
          where: { id: existingId },
          data:  { ...payload, displayName: dn },
        });

        if (hasAddressData(raw)) {
          const existingAddr = await prisma.entityAddress.findFirst({
            where:  { entityId: existingId, deletedAt: null, isDefault: true },
            select: { id: true },
          });
          const addrData = {
            label:        s(raw.addressLabel) || "Principal",
            street:       s(raw.street),
            streetNumber: s(raw.streetNumber),
            floor:        s(raw.floor),
            apartment:    s(raw.apartment),
            city:         s(raw.city),
            province:     s(raw.province),
            country:      s(raw.country) || "Argentina",
            postalCode:   s(raw.postalCode),
            isDefault:    true,
          };
          if (existingAddr) {
            await prisma.entityAddress.update({ where: { id: existingAddr.id }, data: addrData });
          } else {
            await prisma.entityAddress.create({ data: { ...addrData, entityId: existingId, jewelryId: tenantId } });
          }
        }

        results.push({ row: rowNum, displayName: dn, status: "updated", id: existingId });
        updated++;
      } else {
        const code      = await generateEntityCode(tenantId);
        const newEntity = await prisma.commercialEntity.create({
          data:   { ...payload, displayName: dn, jewelryId: tenantId, code },
          select: { id: true },
        });

        if (hasAddressData(raw)) {
          await prisma.entityAddress.create({
            data: {
              entityId:     newEntity.id,
              jewelryId:    tenantId,
              label:        s(raw.addressLabel) || "Principal",
              street:       s(raw.street),
              streetNumber: s(raw.streetNumber),
              floor:        s(raw.floor),
              apartment:    s(raw.apartment),
              city:         s(raw.city),
              province:     s(raw.province),
              country:      s(raw.country) || "Argentina",
              postalCode:   s(raw.postalCode),
              isDefault:    true,
            },
          });
        }

        if (hasContactData(raw)) {
          await prisma.entityContact.create({
            data: {
              entityId:  newEntity.id,
              jewelryId: tenantId,
              firstName: s(raw.contactFirstName),
              lastName:  s(raw.contactLastName),
              position:  s(raw.contactPosition),
              email:     s(raw.contactEmail).toLowerCase(),
              phone:     s(raw.contactPhone),
              whatsapp:  s(raw.contactWhatsapp),
              notes:     s(raw.contactNotes),
              isPrimary: true,
            },
          });
        }

        results.push({ row: rowNum, displayName: dn, status: "created", id: newEntity.id });
        created++;
      }
    } catch (err: any) {
      results.push({ row: rowNum, displayName, status: "error", message: err?.message ?? "Error desconocido." });
      errors++;
    }
  }

  return { results, summary: { created, updated, skipped, errors, conflicts } };
}
