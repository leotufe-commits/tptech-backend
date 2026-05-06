// src/lib/__tests__/importBatch.helper.test.ts
// Tests para el helper de trazabilidad de importaciones masivas.
// Todos los tests son aislados — mockean Prisma sin tocar la DB real.

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock Prisma ──────────────────────────────────────────────────────────────
const mockCreate = vi.fn();
const mockPrisma = vi.hoisted(() => ({
  importBatch: { create: vi.fn() },
}));
vi.mock("../prisma.js", () => ({ prisma: mockPrisma }));

// Import DESPUÉS del mock
import {
  toActionResult,
  buildBatchRowsFromArticleResults,
  buildBatchRowsFromEntityResults,
  saveBatch,
  type BatchRowInput,
} from "../importBatch.helper.js";

// ─── Helpers de test ─────────────────────────────────────────────────────────

function makeArticleResult(
  index: number,
  status: string,
  displayName = "Artículo X",
  errors?: string[],
) {
  return { index, displayName, status, errors, id: undefined };
}

function makeEntityResult(
  row: number,
  status: string,
  displayName = "Entidad X",
  errors?: string[],
  message?: string,
) {
  return { row, displayName, status, errors, message, id: undefined };
}

// ─── toActionResult ──────────────────────────────────────────────────────────

describe("toActionResult", () => {
  it("mapea 'created' → CREATED", () => {
    expect(toActionResult("created")).toBe("CREATED");
  });
  it("mapea 'updated' → UPDATED", () => {
    expect(toActionResult("updated")).toBe("UPDATED");
  });
  it("mapea 'skipped' → SKIPPED", () => {
    expect(toActionResult("skipped")).toBe("SKIPPED");
  });
  it("mapea 'error' → FAILED", () => {
    expect(toActionResult("error")).toBe("FAILED");
  });
  it("mapea 'conflict' → CONFLICT", () => {
    expect(toActionResult("conflict")).toBe("CONFLICT");
  });
  it("mapea string desconocido → FAILED (fallback seguro)", () => {
    expect(toActionResult("unexpected")).toBe("FAILED");
  });
});

// ─── buildBatchRowsFromArticleResults ────────────────────────────────────────

describe("buildBatchRowsFromArticleResults", () => {
  it("genera rowIndex secuencial (pos+1) independiente del index de resultado", () => {
    const results = [
      makeArticleResult(5, "created", "Artículo A"),
      makeArticleResult(3, "skipped", "Artículo B"),
    ];
    const rawRows = new Map<number, Record<string, string>>();
    const batchRows = buildBatchRowsFromArticleResults(results, rawRows);

    expect(batchRows[0].rowIndex).toBe(1);
    expect(batchRows[1].rowIndex).toBe(2);
  });

  it("extrae identifier del campo Codigo del raw cuando está disponible", () => {
    const results = [makeArticleResult(1, "created", "Anillo de Oro")];
    const rawRows = new Map([[1, { Codigo: "ART-001", Nombre: "Anillo de Oro", SKU: "" }]]);

    const batchRows = buildBatchRowsFromArticleResults(results, rawRows);
    expect(batchRows[0].identifier).toBe("ART-001");
  });

  it("cae en SKU si Codigo está vacío", () => {
    const results = [makeArticleResult(1, "created", "Anillo de Oro")];
    const rawRows = new Map([[1, { Codigo: "", Nombre: "Anillo de Oro", SKU: "SKU-001" }]]);

    const batchRows = buildBatchRowsFromArticleResults(results, rawRows);
    expect(batchRows[0].identifier).toBe("SKU-001");
  });

  it("cae en displayName si raw no tiene Codigo ni SKU", () => {
    const results = [makeArticleResult(1, "created", "Mi Artículo")];
    const rawRows = new Map([[1, { Codigo: "", SKU: "", Nombre: "" }]]);

    const batchRows = buildBatchRowsFromArticleResults(results, rawRows);
    expect(batchRows[0].identifier).toBe("Mi Artículo");
  });

  it("incluye rawData solo para filas FAILED", () => {
    const results = [
      makeArticleResult(1, "error",   "Falla",   ["SKU duplicado"]),
      makeArticleResult(2, "created", "Éxito"),
    ];
    const raw1 = { Codigo: "X", SKU: "SKU-BAD" };
    const raw2 = { Codigo: "Y", SKU: "" };
    const rawRows = new Map<number, Record<string, string>>([[1, raw1], [2, raw2]]);

    const batchRows = buildBatchRowsFromArticleResults(results, rawRows);

    expect(batchRows[0].actionResult).toBe("FAILED");
    expect(batchRows[0].rawData).toEqual(raw1);

    expect(batchRows[1].actionResult).toBe("CREATED");
    expect(batchRows[1].rawData).toBeUndefined();
  });

  it("copia el primer error como message", () => {
    const results = [makeArticleResult(1, "error", "Art", ["Error 1", "Error 2"])];
    const rawRows = new Map<number, Record<string, string>>();

    const [row] = buildBatchRowsFromArticleResults(results, rawRows);
    expect(row.message).toBe("Error 1");
    expect(row.errors).toEqual(["Error 1", "Error 2"]);
  });

  it("no incluye errors cuando no hay errores", () => {
    const results = [makeArticleResult(1, "created", "Art")];
    const rawRows = new Map<number, Record<string, string>>();

    const [row] = buildBatchRowsFromArticleResults(results, rawRows);
    expect(row.errors).toBeUndefined();
    expect(row.message).toBe("");
  });

  it("funciona con rawRows vacío (caso v2 donde índices se solapan)", () => {
    const results = [
      makeArticleResult(1, "created", "Artículo 1"),
      makeArticleResult(1, "error",   "[Variante] Var 1", ["Falta padre"]),
    ];
    const rawRows = new Map<number, Record<string, string>>();

    const batchRows = buildBatchRowsFromArticleResults(results, rawRows);
    expect(batchRows).toHaveLength(2);
    expect(batchRows[0].identifier).toBe("Artículo 1");
    expect(batchRows[1].identifier).toBe("[Variante] Var 1");
  });
});

// ─── buildBatchRowsFromEntityResults ─────────────────────────────────────────

describe("buildBatchRowsFromEntityResults", () => {
  it("genera rowIndex secuencial", () => {
    const results = [
      makeEntityResult(1, "created"),
      makeEntityResult(2, "skipped"),
    ];
    const batchRows = buildBatchRowsFromEntityResults(results, new Map());
    expect(batchRows[0].rowIndex).toBe(1);
    expect(batchRows[1].rowIndex).toBe(2);
  });

  it("extrae identifier por prioridad: code > documentNumber > email > displayName", () => {
    const rawRows = new Map([[2, {
      code:           "",
      documentNumber: "20-12345678-9",
      email:          "test@test.com",
    }]]);
    const results = [makeEntityResult(2, "updated", "García, Juan")];

    const [row] = buildBatchRowsFromEntityResults(results, rawRows);
    expect(row.identifier).toBe("20-12345678-9");
  });

  it("mapea status conflict → CONFLICT", () => {
    const results = [makeEntityResult(1, "conflict", "García", undefined, "3 registros coinciden")];
    const [row] = buildBatchRowsFromEntityResults(results, new Map());
    expect(row.actionResult).toBe("CONFLICT");
    expect(row.message).toBe("3 registros coinciden");
  });

  it("incluye rawData solo para FAILED", () => {
    const raw = { code: "", documentNumber: "123", email: "" };
    const rawRows = new Map([[1, raw]]);
    const results = [makeEntityResult(1, "error", "Entidad", ["Email inválido"])];

    const [row] = buildBatchRowsFromEntityResults(results, rawRows);
    expect(row.actionResult).toBe("FAILED");
    expect(row.rawData).toEqual(raw);
  });
});

// ─── saveBatch ───────────────────────────────────────────────────────────────

describe("saveBatch", () => {
  beforeEach(() => {
    mockPrisma.importBatch.create.mockReset();
    mockPrisma.importBatch.create.mockResolvedValue({ id: "batch-1" });
  });

  it("no llama a prisma si rows está vacío", async () => {
    await saveBatch({
      jewelryId:  "j1",
      entityType: "ARTICLE",
      fileName:   "test.xlsx",
      onConflict: "skip",
      summary:    { created: 0, updated: 0, skipped: 0, errors: 0 },
      rows:       [],
    });
    expect(mockPrisma.importBatch.create).not.toHaveBeenCalled();
  });

  it("calcula status SUCCESS cuando errors=0", async () => {
    const rows: BatchRowInput[] = [
      { rowIndex: 1, displayName: "A", actionResult: "CREATED" },
    ];
    await saveBatch({
      jewelryId:  "j1",
      entityType: "ARTICLE",
      fileName:   "test.xlsx",
      onConflict: "skip",
      summary:    { created: 1, updated: 0, skipped: 0, errors: 0 },
      rows,
    });
    const call = mockPrisma.importBatch.create.mock.calls[0][0];
    expect(call.data.status).toBe("SUCCESS");
  });

  it("calcula status PARTIAL cuando hay errores y al menos un éxito", async () => {
    const rows: BatchRowInput[] = [
      { rowIndex: 1, displayName: "A", actionResult: "CREATED" },
      { rowIndex: 2, displayName: "B", actionResult: "FAILED" },
    ];
    await saveBatch({
      jewelryId:  "j1",
      entityType: "ARTICLE",
      fileName:   "test.xlsx",
      onConflict: "skip",
      summary:    { created: 1, updated: 0, skipped: 0, errors: 1 },
      rows,
    });
    const call = mockPrisma.importBatch.create.mock.calls[0][0];
    expect(call.data.status).toBe("PARTIAL");
  });

  it("calcula status FAILED cuando solo hay errores sin éxitos", async () => {
    const rows: BatchRowInput[] = [
      { rowIndex: 1, displayName: "A", actionResult: "FAILED" },
    ];
    await saveBatch({
      jewelryId:  "j1",
      entityType: "ARTICLE",
      fileName:   "test.xlsx",
      onConflict: "skip",
      summary:    { created: 0, updated: 0, skipped: 0, errors: 1 },
      rows,
    });
    const call = mockPrisma.importBatch.create.mock.calls[0][0];
    expect(call.data.status).toBe("FAILED");
  });

  it("incluye todos los totales en el data del batch", async () => {
    const rows: BatchRowInput[] = [
      { rowIndex: 1, displayName: "A", actionResult: "CREATED" },
      { rowIndex: 2, displayName: "B", actionResult: "UPDATED" },
      { rowIndex: 3, displayName: "C", actionResult: "SKIPPED" },
    ];
    await saveBatch({
      jewelryId:  "j1",
      entityType: "COMMERCIAL_ENTITY",
      fileName:   "clientes.csv",
      onConflict: "upsert",
      userId:     "user-1",
      summary:    { created: 1, updated: 1, skipped: 1, errors: 0 },
      rows,
    });
    const call = mockPrisma.importBatch.create.mock.calls[0][0];
    expect(call.data.entityType).toBe("COMMERCIAL_ENTITY");
    expect(call.data.fileName).toBe("clientes.csv");
    expect(call.data.onConflict).toBe("upsert");
    expect(call.data.created).toBe(1);
    expect(call.data.updated).toBe(1);
    expect(call.data.skipped).toBe(1);
    expect(call.data.errors).toBe(0);
    expect(call.data.totalRows).toBe(3);
    expect(call.data.createdById).toBe("user-1");
  });

  it("crea las filas anidadas dentro del batch (nested create)", async () => {
    const rows: BatchRowInput[] = [
      { rowIndex: 1, displayName: "Art A", actionResult: "CREATED", identifier: "ART-001" },
      { rowIndex: 2, displayName: "Art B", actionResult: "FAILED",  identifier: "ART-002", errors: ["SKU dup"], rawData: { Codigo: "ART-002" } },
    ];
    await saveBatch({
      jewelryId:  "j1",
      entityType: "ARTICLE",
      fileName:   "f.xlsx",
      onConflict: "skip",
      summary:    { created: 1, updated: 0, skipped: 0, errors: 1 },
      rows,
    });
    const call = mockPrisma.importBatch.create.mock.calls[0][0];
    const created = call.data.rows.create;

    expect(created).toHaveLength(2);
    expect(created[0].actionResult).toBe("CREATED");
    expect(created[0].identifier).toBe("ART-001");
    expect(created[0].rawData).toBeUndefined(); // no FAILED → sin rawData

    expect(created[1].actionResult).toBe("FAILED");
    expect(created[1].errors).toEqual(["SKU dup"]);
    expect(created[1].rawData).toEqual({ Codigo: "ART-002" }); // FAILED → con rawData
  });

  it("no falla si prisma.create lanza (best-effort)", async () => {
    mockPrisma.importBatch.create.mockRejectedValueOnce(new Error("DB error"));
    const rows: BatchRowInput[] = [
      { rowIndex: 1, displayName: "A", actionResult: "CREATED" },
    ];
    await expect(
      saveBatch({
        jewelryId:  "j1",
        entityType: "ARTICLE",
        fileName:   "f.xlsx",
        onConflict: "skip",
        summary:    { created: 1, updated: 0, skipped: 0, errors: 0 },
        rows,
      })
    ).resolves.not.toThrow();
  });
});

// ─── Integración: batch con mezcla de resultados ─────────────────────────────

describe("batch con mezcla de resultados", () => {
  beforeEach(() => {
    mockPrisma.importBatch.create.mockReset();
    mockPrisma.importBatch.create.mockResolvedValue({ id: "batch-x" });
  });

  it("PARTIAL: 3 created + 2 failed guarda rows correctamente", async () => {
    const articleResults = [
      makeArticleResult(1, "created", "Art A"),
      makeArticleResult(2, "created", "Art B"),
      makeArticleResult(3, "created", "Art C"),
      makeArticleResult(4, "error",   "Art D", ["Nombre obligatorio"]),
      makeArticleResult(5, "error",   "Art E", ["SKU duplicado"]),
    ];
    const rawRows = new Map<number, Record<string, string>>([
      [1, { Codigo: "A001", SKU: "", Nombre: "Art A" }],
      [2, { Codigo: "A002", SKU: "", Nombre: "Art B" }],
      [3, { Codigo: "A003", SKU: "", Nombre: "Art C" }],
      [4, { Codigo: "",     SKU: "", Nombre: "Art D" }],
      [5, { Codigo: "A005", SKU: "SKU-005", Nombre: "Art E" }],
    ]);
    const batchRows = buildBatchRowsFromArticleResults(articleResults, rawRows);

    await saveBatch({
      jewelryId:  "j1",
      entityType: "ARTICLE",
      fileName:   "articulos.xlsx",
      onConflict: "skip",
      summary:    { created: 3, updated: 0, skipped: 0, errors: 2 },
      rows:       batchRows,
    });

    const call = mockPrisma.importBatch.create.mock.calls[0][0];
    expect(call.data.status).toBe("PARTIAL");
    expect(call.data.totalRows).toBe(5);

    const failedRows = call.data.rows.create.filter((r: any) => r.actionResult === "FAILED");
    expect(failedRows).toHaveLength(2);
    // FAILED rows deben tener rawData
    expect(failedRows[0].rawData).toBeDefined();
    expect(failedRows[1].rawData).toBeDefined();
    // CREATED rows NO deben tener rawData
    const createdRows = call.data.rows.create.filter((r: any) => r.actionResult === "CREATED");
    createdRows.forEach((r: any) => expect(r.rawData).toBeUndefined());
  });
});
