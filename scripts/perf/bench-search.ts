// scripts/perf/bench-search.ts
// ============================================================================
// Etapa 2 (perf) — BENCH READ-ONLY de las búsquedas de Factura de Ventas.
//
// Mide, con datos REALES de la DB apuntada por DATABASE_URL:
//   1. Escala actual (conteo de filas por tabla relevante).
//   2. Plan de ejecución + tiempo real (EXPLAIN ANALYZE) de:
//        · búsqueda de clientes (combo de cliente, ILIKE multi-campo)
//        · búsqueda de artículos (combo de línea, ILIKE multi-campo)
//
// 100% solo-lectura: no inserta, no borra, no toca pricing ni snapshots.
// Para medir el escenario "50k" hay que correr `perf-seed.ts` primero
// (idealmente contra una DB descartable). Ver README-perf.md.
//
// Uso:
//   npx tsx scripts/perf/bench-search.ts            # término por defecto "a"
//   npx tsx scripts/perf/bench-search.ts ros        # término "ros"
// ============================================================================

import "dotenv/config";
import { PrismaClient } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL! });
const prisma = new PrismaClient({ adapter });

const term = process.argv[2] ?? "a";
const like = `%${term}%`;

function planText(rows: Array<Record<string, unknown>>): string {
  // EXPLAIN devuelve filas con la clave "QUERY PLAN".
  return rows.map((r) => String(r["QUERY PLAN"] ?? Object.values(r)[0])).join("\n");
}

async function main() {
  console.log("════════════════════════════════════════════════════════════");
  console.log(" BENCH READ-ONLY — búsquedas de Factura de Ventas");
  console.log(` término de búsqueda: "${term}"  (ILIKE '${like}')`);
  console.log("════════════════════════════════════════════════════════════\n");

  // ── 1. Escala actual ──────────────────────────────────────────────────────
  const [jewelries, clients, articles, variants, priceLists, warehouses, metalVariants] =
    await Promise.all([
      prisma.jewelry.count(),
      prisma.commercialEntity.count({ where: { isClient: true, deletedAt: null } }),
      prisma.article.count({ where: { deletedAt: null } }),
      prisma.articleVariant.count({ where: { deletedAt: null } }),
      prisma.priceList.count({ where: { deletedAt: null } }),
      prisma.warehouse.count({ where: { deletedAt: null } }),
      prisma.metalVariant.count(),
    ]);

  console.log("ESCALA ACTUAL (filas):");
  console.table({
    Jewelry: jewelries,
    "CommercialEntity (clientes)": clients,
    Article: articles,
    ArticleVariant: variants,
    PriceList: priceLists,
    Warehouse: warehouses,
    MetalVariant: metalVariants,
  });

  // Tenant con más clientes (el caso más representativo para la búsqueda).
  const firstEntity = await prisma.commercialEntity.findFirst({
    where: { isClient: true, deletedAt: null },
    select: { jewelryId: true },
  });
  const jewelryId = firstEntity?.jewelryId;

  if (!jewelryId) {
    console.log("\n⚠️  No hay clientes en la DB — sembrá con perf-seed.ts para medir a escala.");
    return;
  }
  console.log(`\nTenant medido: ${jewelryId}\n`);

  // ── 2. EXPLAIN ANALYZE — búsqueda de clientes ─────────────────────────────
  const clientSql = `
    SELECT "id","displayName","code","documentNumber","email","phone"
    FROM "CommercialEntity"
    WHERE "jewelryId" = $1 AND "deletedAt" IS NULL AND "isClient" = true
      AND ("displayName" ILIKE $2 OR "code" ILIKE $2 OR "documentNumber" ILIKE $2
           OR "email" ILIKE $2 OR "phone" ILIKE $2)
    ORDER BY "displayName" ASC
    LIMIT 50`;
  const clientPlan = await prisma.$queryRawUnsafe<Array<Record<string, unknown>>>(
    `EXPLAIN (ANALYZE, BUFFERS) ${clientSql}`,
    jewelryId,
    like,
  );
  console.log("── BÚSQUEDA DE CLIENTES (combo cliente) ─────────────────────");
  console.log(planText(clientPlan), "\n");

  // ── 3. EXPLAIN ANALYZE — búsqueda de artículos ────────────────────────────
  const articleSql = `
    SELECT "id","code","name","sku","barcode"
    FROM "Article"
    WHERE "jewelryId" = $1 AND "deletedAt" IS NULL
      AND ("name" ILIKE $2 OR "code" ILIKE $2 OR "sku" ILIKE $2 OR "barcode" ILIKE $2)
    ORDER BY "name" ASC
    LIMIT 30`;
  const articlePlan = await prisma.$queryRawUnsafe<Array<Record<string, unknown>>>(
    `EXPLAIN (ANALYZE, BUFFERS) ${articleSql}`,
    jewelryId,
    like,
  );
  console.log("── BÚSQUEDA DE ARTÍCULOS (combo de línea) ───────────────────");
  console.log(planText(articlePlan), "\n");

  console.log("Cómo leerlo:");
  console.log(" · 'Seq Scan' + Rows altos = escaneo completo (no escala con 50k).");
  console.log(" · 'Index Scan'/'Bitmap' = usa índice (escala).");
  console.log(" · ILIKE '%x%' (substring) NO usa índice btree → la mejora real es");
  console.log("   pg_trgm (GIN) o búsqueda por prefijo. Ver README-perf.md.");
}

main()
  .catch((e) => { console.error("bench-search falló:", e); process.exitCode = 1; })
  .finally(() => prisma.$disconnect());
