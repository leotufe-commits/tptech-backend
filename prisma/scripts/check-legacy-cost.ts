/**
 * prisma/scripts/check-legacy-cost.ts
 *
 * Verificación de condición de seguridad antes de ejecutar la migración
 * destructiva de limpieza de campos legacy de costo.
 *
 * Checks:
 *   1. Artículos sin ArticleCostLine (aún en modo legacy)
 *   2. Artículos que dependen de campos legacy activos
 *   3. Filas en ArticleMetalComposition
 *   4. ArticleCostLine con variantId != null
 *   5. Variantes con costPrice o hechuraPriceOverride cargados
 *
 * Uso:
 *   tsx prisma/scripts/check-legacy-cost.ts
 *
 * Si algún check reporta valores > 0, ejecutar el script de migración primero:
 *   tsx prisma/scripts/migrate-cost-to-lines.ts --apply
 */

import "dotenv/config";
import { PrismaClient } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL! });
const prisma  = new PrismaClient({ adapter });

// ---------------------------------------------------------------------------

type CheckResult = {
  name:    string;
  count:   number;
  blocker: boolean;   // si true → NO se puede ejecutar la migración destructiva
  detail?: string;
};

// ---------------------------------------------------------------------------

async function main() {
  console.log("=".repeat(60));
  console.log("  check-legacy-cost — Verificación de seguridad");
  console.log("=".repeat(60));
  console.log();

  const results: CheckResult[] = [];

  // ── CHECK 1: artículos sin ninguna ArticleCostLine ────────────────────────
  const artsSinLineas = await prisma.article.count({
    where: {
      deletedAt: null,
      costComposition: { none: {} },
    },
  });
  results.push({
    name:    "Artículos sin ArticleCostLine",
    count:   artsSinLineas,
    blocker: artsSinLineas > 0,
    detail:  artsSinLineas > 0
      ? "→ Ejecutar: tsx prisma/scripts/migrate-cost-to-lines.ts --apply"
      : undefined,
  });

  // ── CHECK 2a: artículos con costPrice != null ─────────────────────────────
  const artsCostPrice = await prisma.article.count({
    where: {
      deletedAt: null,
      costPrice: { not: null },
    },
  });
  results.push({
    name:    "Article.costPrice con valor",
    count:   artsCostPrice,
    blocker: false,   // informativo: hay datos pero pueden ignorarse tras migración
    detail:  "Columna a eliminar — datos serán borrados por la migración",
  });

  // ── CHECK 2b: artículos con hechuraPrice != null ──────────────────────────
  const artsHechura = await prisma.article.count({
    where: {
      deletedAt: null,
      hechuraPrice: { not: null },
    },
  });
  results.push({
    name:    "Article.hechuraPrice con valor",
    count:   artsHechura,
    blocker: false,
    detail:  "Columna a eliminar — datos serán borrados por la migración",
  });

  // ── CHECK 2c: artículos con costCalculationMode != MANUAL ─────────────────
  const artsNonManual = await prisma.article.count({
    where: {
      deletedAt: null,
      costCalculationMode: { not: "MANUAL" as any },
    },
  });
  results.push({
    name:    "Article.costCalculationMode != MANUAL",
    count:   artsNonManual,
    blocker: false,
    detail:  "Enumerado a eliminar — incluye MULTIPLIER y METAL_MERMA_HECHURA",
  });

  // ── CHECK 2d: artículos con multiplierValue != null ───────────────────────
  const artsMultiplier = await prisma.article.count({
    where: {
      deletedAt: null,
      multiplierValue: { not: null },
    },
  });
  results.push({
    name:    "Article.multiplierValue con valor",
    count:   artsMultiplier,
    blocker: false,
    detail:  "Columnas multiplier* a eliminar",
  });

  // ── CHECK 2e: artículos con manualBaseCost != null ────────────────────────
  const artsManualBase = await prisma.article.count({
    where: {
      deletedAt: null,
      manualBaseCost: { not: null },
    },
  });
  results.push({
    name:    "Article.manualBaseCost con valor",
    count:   artsManualBase,
    blocker: false,
    detail:  "Columnas manual* a eliminar (manualBaseCost, manualCurrencyId)",
  });

  // ── CHECK 3: filas en ArticleMetalComposition ─────────────────────────────
  const compRows = await prisma.articleMetalComposition.count();
  results.push({
    name:    "Filas en ArticleMetalComposition",
    count:   compRows,
    blocker: false,
    detail:  "Tabla a eliminar — datos ya migrados a ArticleCostLine (type=METAL)",
  });

  // ── CHECK 4: ArticleCostLine con variantId != null ────────────────────────
  // No es un blocker: la migración destructiva los elimina con DELETE + DROP COLUMN.
  // Solo informativo para conocer el volumen de datos que se perderán.
  const lineVariant = await prisma.articleCostLine.count({
    where: { variantId: { not: null } },
  });
  results.push({
    name:    "ArticleCostLine con variantId != null",
    count:   lineVariant,
    blocker: false,
    detail:  lineVariant > 0
      ? "Serán ELIMINADAS por la migración (variantes sin costo propio)"
      : "Campo variantId puede eliminarse de ArticleCostLine",
  });

  // ── CHECK 5a: variantes con costPrice != null ─────────────────────────────
  const varsCostPrice = await prisma.articleVariant.count({
    where: {
      deletedAt: null,
      costPrice: { not: null },
    },
  });
  results.push({
    name:    "ArticleVariant.costPrice con valor",
    count:   varsCostPrice,
    blocker: false,
    detail:  "Columna a eliminar de ArticleVariant",
  });

  // ── CHECK 5b: variantes con hechuraPriceOverride != null ─────────────────
  const varsHechura = await prisma.articleVariant.count({
    where: {
      deletedAt: null,
      hechuraPriceOverride: { not: null },
    },
  });
  results.push({
    name:    "ArticleVariant.hechuraPriceOverride con valor",
    count:   varsHechura,
    blocker: false,
    detail:  "Columna a eliminar de ArticleVariant",
  });

  // ── Mostrar resultados ────────────────────────────────────────────────────
  let hasBlockers = false;
  let total = 0;

  for (const r of results) {
    const icon   = r.count === 0 ? "✅" : (r.blocker ? "🔴" : "🟡");
    const status = r.count === 0 ? "OK" : (r.blocker ? "BLOQUEADOR" : "PENDIENTE");
    console.log(`${icon} ${status.padEnd(10)} ${String(r.count).padStart(6)}  ${r.name}`);
    if (r.detail) console.log(`             ${r.detail}`);
    if (r.blocker && r.count > 0) hasBlockers = true;
    total += r.count;
  }

  console.log();
  console.log("=".repeat(60));

  if (hasBlockers) {
    console.log("  ❌ MIGRACIÓN BLOQUEADA — resolver los items BLOQUEADOR primero.");
    console.log();
    console.log("  Pasos:");
    console.log("  1. tsx prisma/scripts/migrate-cost-to-lines.ts");
    console.log("     (dry-run para verificar el plan)");
    console.log("  2. tsx prisma/scripts/migrate-cost-to-lines.ts --apply");
    console.log("     (aplicar migración)");
    console.log("  3. tsx prisma/scripts/check-legacy-cost.ts");
    console.log("     (re-verificar que no queden blockers)");
    console.log("  4. Aplicar migración Prisma destructiva");
  } else {
    console.log("  ✅ SIN BLOCKERS — se puede ejecutar la migración destructiva.");
    console.log();
    console.log("  Comando sugerido:");
    console.log("  npm run prisma:migrate:dev -- --name remove_legacy_cost_fields");
    if (total > 0) {
      console.log();
      console.log("  NOTA: Hay datos PENDIENTE que serán eliminados por la migración.");
      console.log("  Asegurarse de que ya estén migrados a ArticleCostLine antes de continuar.");
    }
  }
  console.log("=".repeat(60));
}

main()
  .catch((e) => { console.error(e); process.exit(1); })
  .finally(() => prisma.$disconnect());
