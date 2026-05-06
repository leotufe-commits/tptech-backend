// src/lib/importBatch.helper.ts
// Helper compartido para registrar ImportBatch + ImportBatchRow al finalizar
// una importación masiva (artículos v1, v2 y entidades comerciales).
//
// El registro es BEST-EFFORT: si falla la escritura en DB el proceso de
// importación NO se interrumpe. Los errores se loguean en consola.

import { prisma } from "./prisma.js";

// ─── Tipos públicos ──────────────────────────────────────────────────────────

/**
 * Payload estructurado para reintento de filas FAILED en importaciones V2 de artículos.
 * Permite reconstruir el input exacto para executeImportV2 sin necesidad del archivo original.
 */
export type V2RetryPayload = {
  type:    "article" | "variant";
  payload: Record<string, string>;
};

/** Resultado de una fila individual para guardar en ImportBatchRow */
export type BatchRowInput = {
  rowIndex:      number;
  displayName:   string;
  /** CREATED | UPDATED | SKIPPED | FAILED | CONFLICT */
  actionResult:  "CREATED" | "UPDATED" | "SKIPPED" | "FAILED" | "CONFLICT";
  /** Código, email, documento — el identificador más específico de la fila */
  identifier?:   string;
  /** Primer mensaje legible (primer error o mensaje de skip) */
  message?:      string;
  /** Lista completa de errores de validación */
  errors?:       string[];
  /** Datos originales de la fila en texto plano (FAILED v1 artículos y entidades) */
  rawData?:      Record<string, unknown>;
  /** Payload estructurado para reintento (FAILED v2 artículos y variantes) */
  retryPayload?: V2RetryPayload;
};

/** Opciones para registrar un batch completo */
export type SaveBatchOpts = {
  jewelryId:  string;
  entityType: string;        // "ARTICLE" | "COMMERCIAL_ENTITY"
  fileName:   string;
  onConflict: string;        // "skip" | "update" | "upsert" | "create"
  userId?:    string;
  summary: {
    created:    number;
    updated:    number;
    skipped:    number;
    errors:     number;
    conflicts?: number;
  };
  rows: BatchRowInput[];
};

// ─── Helper de estado del batch ──────────────────────────────────────────────

function computeBatchStatus(
  created: number,
  updated: number,
  errors: number,
): "SUCCESS" | "PARTIAL" | "FAILED" {
  if (errors === 0)          return "SUCCESS";
  if (created + updated > 0) return "PARTIAL";
  return "FAILED";
}

// ─── Conversor de status de servicio → actionResult ─────────────────────────

/**
 * Convierte el `status` que devuelven los servicios de importación
 * al `actionResult` que guarda ImportBatchRow.
 *
 * Articles:  "created" | "updated" | "skipped" | "error"
 * Entities:  "created" | "updated" | "skipped" | "error" | "conflict"
 */
export function toActionResult(
  status: string,
): "CREATED" | "UPDATED" | "SKIPPED" | "FAILED" | "CONFLICT" {
  switch (status) {
    case "created":  return "CREATED";
    case "updated":  return "UPDATED";
    case "skipped":  return "SKIPPED";
    case "conflict": return "CONFLICT";
    default:         return "FAILED"; // "error" y cualquier desconocido
  }
}

// ─── saveBatch ───────────────────────────────────────────────────────────────

/**
 * Guarda el ImportBatch y todas sus filas en una sola escritura.
 * Usa best-effort: si falla, loguea en consola pero no lanza excepción.
 * Devuelve el id del batch creado, o null si falló / no había filas.
 */
export async function saveBatch(opts: SaveBatchOpts): Promise<string | null> {
  const { created, updated, skipped, errors } = opts.summary;
  const totalRows = opts.rows.length;

  if (totalRows === 0) return null; // nada que guardar

  const status = computeBatchStatus(created, updated, errors);

  try {
    const { id } = await prisma.importBatch.create({
      data: {
        jewelryId:  opts.jewelryId,
        entityType: opts.entityType,
        fileName:   opts.fileName,
        onConflict: opts.onConflict,
        totalRows,
        created,
        updated,
        skipped,
        errors,
        status,
        ...(opts.userId ? { createdById: opts.userId } : {}),
        rows: {
          create: opts.rows.map((r) => ({
            jewelryId:    opts.jewelryId,
            rowIndex:     r.rowIndex,
            displayName:  r.displayName,
            actionResult: r.actionResult,
            identifier:   r.identifier ?? "",
            message:      r.message ?? "",
            // Solo guardar el array de errors si hay al menos uno
            ...(r.errors && r.errors.length > 0 ? { errors: r.errors } : {}),
            // rawData: para filas FAILED v1 (para diagnóstico y descarga CSV)
            ...(r.actionResult === "FAILED" && r.rawData
              ? { rawData: r.rawData as any }
              : {}),
            // retryPayload: para filas FAILED v2 (para reintento estructurado)
            ...(r.actionResult === "FAILED" && r.retryPayload
              ? { retryPayload: r.retryPayload as any }
              : {}),
          })),
        },
      },
      select: { id: true },
    });
    return id;
  } catch (err) {
    // No interrumpir la importación si falla el registro de auditoría
    console.error("[ImportBatch] Error al guardar batch:", (err as any)?.message ?? err);
    return null;
  }
}

// ─── buildBatchRowsFromArticleResults ────────────────────────────────────────

/**
 * Convierte los results de executeImport (v1 y v2) de artículos en BatchRowInput[].
 *
 * V1: usa el mapa rawRows (index → fila original) para rawData e identifier.
 * V2: usa _retryPayload incluido en cada result para retryPayload e identifier.
 *
 * Los results de V2 incluyen _retryPayload (campo interno, solo para FAILED).
 * Los results de V1 no tienen _retryPayload → usa rawRows como antes.
 */
export function buildBatchRowsFromArticleResults(
  results: Array<{
    index:          number;
    displayName:    string;
    status:         string;
    errors?:        string[];
    id?:            string;
    /** Campo interno — solo V2 agrega esto en filas FAILED */
    _retryPayload?: V2RetryPayload;
  }>,
  rawRows: Map<number, Record<string, string>>,
): BatchRowInput[] {
  return results.map((r, pos) => {
    const raw          = rawRows.get(r.index) ?? {};
    const actionResult = toActionResult(r.status);
    const firstError   = r.errors?.[0] ?? "";

    // ── Identificador ──────────────────────────────────────────────────────
    let identifier: string;
    if (r._retryPayload) {
      // V2: extraer desde el payload según tipo
      const p = r._retryPayload.payload;
      if (r._retryPayload.type === "article") {
        identifier =
          String(p["Codigo"]  ?? "").trim() ||
          String(p["Nombre"]  ?? "").trim() ||
          r.displayName;
      } else {
        identifier =
          String(p["SKU"]             ?? "").trim() ||
          String(p["Barcode"]         ?? "").trim() ||
          String(p["Articulo_Codigo"] ?? "").trim() ||
          String(p["Nombre"]          ?? "").trim() ||
          r.displayName;
      }
    } else {
      // V1: Codigo > SKU > Nombre > displayName
      identifier =
        String(raw["Codigo"] ?? raw["Articulo_Codigo"] ?? "").trim() ||
        String(raw["SKU"]  ?? "").trim() ||
        String(raw["Nombre"] ?? "").trim() ||
        r.displayName;
    }

    // ── rawData / retryPayload (solo FAILED) ───────────────────────────────
    const rawData: Record<string, unknown> | undefined =
      !r._retryPayload && actionResult === "FAILED" && Object.keys(raw).length > 0
        ? (raw as Record<string, unknown>)
        : undefined;

    const retryPayload: V2RetryPayload | undefined =
      r._retryPayload && actionResult === "FAILED"
        ? r._retryPayload
        : undefined;

    return {
      rowIndex:    pos + 1,   // posición secuencial en resultados
      displayName: r.displayName,
      actionResult,
      identifier,
      message:     firstError,
      errors:      r.errors && r.errors.length > 0 ? r.errors : undefined,
      rawData,
      retryPayload,
    };
  });
}

// ─── buildBatchRowsFromEntityResults ─────────────────────────────────────────

/**
 * Convierte los results de commitImport de entidades en BatchRowInput[].
 * Entities usan `row` (no `index`) como número de fila.
 */
export function buildBatchRowsFromEntityResults(
  results: Array<{
    row:           number;
    displayName:   string;
    status:        string;
    errors?:       string[];
    message?:      string;
    id?:           string;
    conflictCount?: number;
  }>,
  rawRows: Map<number, Record<string, string>>,
): BatchRowInput[] {
  return results.map((r, pos) => {
    const raw          = rawRows.get(r.row) ?? {};
    const actionResult = toActionResult(r.status);

    // Identificador: código > documento > email > nombre
    const identifier =
      String(raw["code"]           ?? "").trim() ||
      String(raw["documentNumber"] ?? "").trim() ||
      String(raw["email"]          ?? "").trim() ||
      r.displayName;

    const firstError = r.errors?.[0] ?? r.message ?? "";

    return {
      rowIndex:    pos + 1,
      displayName: r.displayName,
      actionResult,
      identifier,
      message:     firstError,
      errors:      r.errors && r.errors.length > 0 ? r.errors : undefined,
      rawData:     actionResult === "FAILED" ? (raw as Record<string, unknown>) : undefined,
    };
  });
}
