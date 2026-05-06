// src/modules/import-batches/import-batches.service.ts
// Consulta y exportación de historial de importaciones masivas.
// Multi-tenant: todas las queries filtran por jewelryId.
import { prisma } from "../../lib/prisma.js";
import { executeImport, executeImportV2, type V2ParsedData } from "../articles/articles.import.service.js";
import { commitImport } from "../commercial-entities/commercial-entities.import.service.js";

function clamp(v: any, def: number, max: number): number {
  const n = Number(v);
  return Number.isFinite(n) ? Math.max(1, Math.min(max, Math.floor(n))) : def;
}

// ─── listBatches ─────────────────────────────────────────────────────────────

export async function listBatches(opts: {
  jewelryId:   string;
  entityType?: string | null;
  status?:     string | null;
  from?:       Date | null;
  to?:         Date | null;
  page?:       number;
  pageSize?:   number;
}) {
  const take = clamp(opts.pageSize, 20, 100);
  const skip = (Math.max(1, opts.page ?? 1) - 1) * take;

  const where: any = { jewelryId: opts.jewelryId };
  if (opts.entityType) where.entityType = opts.entityType;
  if (opts.status)     where.status = opts.status;
  if (opts.from || opts.to) {
    where.importedAt = {};
    if (opts.from) where.importedAt.gte = opts.from;
    if (opts.to)   where.importedAt.lte = opts.to;
  }

  const [total, rows] = await prisma.$transaction([
    prisma.importBatch.count({ where }),
    prisma.importBatch.findMany({
      where,
      orderBy: { importedAt: "desc" },
      skip,
      take,
      select: {
        id:         true,
        importedAt: true,
        entityType: true,
        fileName:   true,
        onConflict: true,
        status:     true,
        totalRows:  true,
        created:    true,
        updated:    true,
        skipped:    true,
        errors:     true,
        createdBy:  { select: { id: true, name: true, email: true } },
      },
    }),
  ]);

  return { rows, total, page: opts.page ?? 1, pageSize: take };
}

// ─── getBatch ────────────────────────────────────────────────────────────────

export async function getBatch(id: string, jewelryId: string) {
  const batch = await prisma.importBatch.findFirst({
    where: { id, jewelryId },
    select: {
      id:         true,
      importedAt: true,
      entityType: true,
      fileName:   true,
      onConflict: true,
      status:     true,
      totalRows:  true,
      created:    true,
      updated:    true,
      skipped:    true,
      errors:     true,
      createdBy:  { select: { id: true, name: true, email: true } },
    },
  });
  if (!batch) {
    const err: any = new Error("Importación no encontrada.");
    err.status = 404;
    throw err;
  }
  return batch;
}

// ─── listBatchRows ────────────────────────────────────────────────────────────

export async function listBatchRows(opts: {
  batchId:      string;
  jewelryId:    string;
  actionResult?: string | null;  // CREATED | UPDATED | SKIPPED | FAILED | CONFLICT
  page?:        number;
  pageSize?:    number;
}) {
  // Verificar que el batch pertenece al tenant
  const batch = await prisma.importBatch.findFirst({
    where:  { id: opts.batchId, jewelryId: opts.jewelryId },
    select: { id: true },
  });
  if (!batch) {
    const err: any = new Error("Importación no encontrada.");
    err.status = 404;
    throw err;
  }

  const take = clamp(opts.pageSize, 50, 500);
  const skip = (Math.max(1, opts.page ?? 1) - 1) * take;

  const where: any = { batchId: opts.batchId };
  if (opts.actionResult) where.actionResult = opts.actionResult;

  const [total, rows] = await prisma.$transaction([
    prisma.importBatchRow.count({ where }),
    prisma.importBatchRow.findMany({
      where,
      orderBy: { rowIndex: "asc" },
      skip,
      take,
      select: {
        id:           true,
        rowIndex:     true,
        displayName:  true,
        actionResult: true,
        identifier:   true,
        message:      true,
        errors:       true,
        rawData:      true,
        createdAt:    true,
      },
    }),
  ]);

  return { rows, total, page: opts.page ?? 1, pageSize: take };
}

// ─── exportBatchErrorsCsv ─────────────────────────────────────────────────────
// Devuelve un CSV descargable con las filas fallidas de un batch.

export async function exportBatchErrorsCsv(batchId: string, jewelryId: string): Promise<string> {
  // Verificar ownership
  const batch = await prisma.importBatch.findFirst({
    where:  { id: batchId, jewelryId },
    select: { id: true, fileName: true },
  });
  if (!batch) {
    const err: any = new Error("Importación no encontrada.");
    err.status = 404;
    throw err;
  }

  const rows = await prisma.importBatchRow.findMany({
    where:   { batchId, actionResult: "FAILED" },
    orderBy: { rowIndex: "asc" },
    select: {
      rowIndex:    true,
      displayName: true,
      identifier:  true,
      message:     true,
      errors:      true,
    },
  });

  if (rows.length === 0) return "rowIndex,displayName,identifier,errores\n";

  const escape = (v: string) => `"${v.replace(/"/g, '""')}"`;

  const header = "rowIndex,displayName,identifier,errores";
  const lines  = rows.map((r) => {
    const errs = Array.isArray(r.errors) ? (r.errors as string[]).join("; ") : (r.message ?? "");
    return [
      r.rowIndex,
      escape(r.displayName),
      escape(r.identifier ?? ""),
      escape(errs),
    ].join(",");
  });

  return [header, ...lines].join("\n");
}

// ─── retryErrors ──────────────────────────────────────────────────────────────
// Reintenta SOLO las filas FAILED de un batch que tengan rawData guardado.
// Ejecuta el mismo tipo de importación original y crea un NUEVO ImportBatch.
// No modifica el batch original.

export type RetryResult = {
  batchId:   string;
  status:    string;
  created:   number;
  updated:   number;
  skipped:   number;
  errors:    number;
  totalRows: number;
};

export async function retryErrors(opts: {
  batchId:   string;
  jewelryId: string;
  userId?:   string;
}): Promise<RetryResult> {
  // 1. Cargar batch original (verifica ownership)
  const batch = await prisma.importBatch.findFirst({
    where:  { id: opts.batchId, jewelryId: opts.jewelryId },
    select: { id: true, entityType: true, onConflict: true, fileName: true, errors: true },
  });
  if (!batch) {
    const err: any = new Error("Importación no encontrada.");
    err.status = 404;
    throw err;
  }

  if (batch.errors === 0) {
    const err: any = new Error("Esta importación no tiene errores para reintentar.");
    err.status = 422;
    throw err;
  }

  // 2. Obtener todas las filas FAILED con sus datos para reintento
  const failedRows = await prisma.importBatchRow.findMany({
    where:   { batchId: opts.batchId, actionResult: "FAILED" },
    orderBy: { rowIndex: "asc" },
    select:  { rowIndex: true, rawData: true, retryPayload: true },
  });

  // Separar por tipo:
  // V2 articles/variants → tienen retryPayload
  // V1 articles/entities → tienen rawData con contenido
  const v2Rows = failedRows.filter((r) => r.retryPayload != null);
  const v1Rows = failedRows.filter((r) => {
    if (r.retryPayload != null) return false; // ya contado en v2Rows
    if (!r.rawData) return false;
    return Object.keys(r.rawData as object).length > 0;
  });

  if (v2Rows.length === 0 && v1Rows.length === 0) {
    const err: any = new Error(
      batch.entityType === "ARTICLE"
        ? "Las filas fallidas no tienen datos de reintento disponibles."
        : "Las filas fallidas no tienen datos suficientes para reintentarse.",
    );
    err.status = 422;
    throw err;
  }

  const retryFileName = `Reintento - ${batch.fileName}`.slice(0, 255);
  const artConflict   = (batch.onConflict === "update" ? "update" : "skip") as "skip" | "update";

  let newBatchId: string | null = null;

  // ── 3a. Reintento V2 (artículos con retryPayload) ──────────────────────
  if (v2Rows.length > 0) {
    const v2Articles: Record<string, string>[] = [];
    const v2Variants: Record<string, string>[] = [];

    for (const row of v2Rows) {
      const rp = row.retryPayload as any;
      if (!rp?.type || !rp?.payload) continue;
      if (rp.type === "article") v2Articles.push(rp.payload as Record<string, string>);
      else if (rp.type === "variant") v2Variants.push(rp.payload as Record<string, string>);
    }

    if (v2Articles.length > 0 || v2Variants.length > 0) {
      const v2Data: V2ParsedData = {
        articles:   v2Articles,
        variants:   v2Variants,
        metals:     [],
        stock:      [],
        attributes: [],
      };
      const result = await executeImportV2(v2Data, opts.jewelryId, {
        onConflict: artConflict,
        userId:     opts.userId,
        fileName:   retryFileName,
      });
      newBatchId = result.batchId ?? null;
    }
  }

  // ── 3b. Reintento V1 artículos (rawData plano) ────────────────────────
  if (!newBatchId && v1Rows.length > 0 && batch.entityType === "ARTICLE") {
    const retryRows = v1Rows.map((r) => r.rawData as Record<string, string>);
    const result = await executeImport(retryRows, opts.jewelryId, {
      onConflict: artConflict,
      userId:     opts.userId,
      fileName:   retryFileName,
    });
    newBatchId = result.batchId ?? null;
  }

  // ── 3c. Reintento entidades comerciales ───────────────────────────────
  if (!newBatchId && v1Rows.length > 0 && batch.entityType === "COMMERCIAL_ENTITY") {
    const retryRows = v1Rows.map((r) => r.rawData as Record<string, string>);
    // Usar "upsert" para dar la mayor probabilidad de éxito en el reintento
    const entMode = (["create", "update", "upsert"].includes(batch.onConflict)
      ? batch.onConflict
      : "upsert") as "create" | "update" | "upsert";
    const result = await commitImport(opts.jewelryId, retryRows, {
      mode:     entMode,
      role:     "both",
      userId:   opts.userId,
      fileName: retryFileName,
    });
    newBatchId = result.batchId ?? null;
  }

  if (!newBatchId) {
    const err: any = new Error("El reintento se ejecutó pero no se pudo registrar la nueva importación.");
    err.status = 500;
    throw err;
  }

  // 4. Devolver resumen del nuevo batch
  const newBatch = await prisma.importBatch.findFirst({
    where:  { id: newBatchId },
    select: { id: true, status: true, created: true, updated: true, skipped: true, errors: true, totalRows: true },
  });

  if (!newBatch) {
    const err: any = new Error("No se pudo recuperar la nueva importación.");
    err.status = 500;
    throw err;
  }

  return {
    batchId:   newBatch.id,
    status:    newBatch.status,
    created:   newBatch.created,
    updated:   newBatch.updated,
    skipped:   newBatch.skipped,
    errors:    newBatch.errors,
    totalRows: newBatch.totalRows,
  };
}
