/**
 * prisma/scripts/migrate-cost-to-lines.ts
 *
 * Migra artículos legacy (sin ArticleCostLine) al nuevo modelo COST_LINES.
 *
 * Modos legacy soportados:
 *   MANUAL              → 1 línea MANUAL (manualBaseCost o costPrice)
 *   MULTIPLIER          → 1 línea MANUAL (quantity=multiplierQty, unitValue=multiplierValue)
 *   METAL_MERMA_HECHURA → N líneas METAL + 1 línea HECHURA (si aplica)
 *
 * Uso:
 *   # Simulación (sin escribir nada):
 *   tsx prisma/scripts/migrate-cost-to-lines.ts
 *
 *   # Aplicar migración real:
 *   tsx prisma/scripts/migrate-cost-to-lines.ts --apply
 *
 *   # Solo un tenant específico:
 *   tsx prisma/scripts/migrate-cost-to-lines.ts --apply --jewelry <jewelryId>
 *
 * Idempotente: artículos que ya tienen costComposition no son modificados.
 */

import "dotenv/config";
import { Prisma, PrismaClient } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL! });
const prisma  = new PrismaClient({ adapter });

const DRY_RUN = !process.argv.includes("--apply");
const TARGET_JEWELRY = (() => {
  const idx = process.argv.indexOf("--jewelry");
  return idx !== -1 ? process.argv[idx + 1] : undefined;
})();

// ---------------------------------------------------------------------------
// Tipos internos
// ---------------------------------------------------------------------------

type ArticleWithLegacy = {
  id: string;
  jewelryId: string;
  costCalculationMode: string;
  // MANUAL
  costPrice: Prisma.Decimal | null;
  manualBaseCost: Prisma.Decimal | null;
  manualCurrencyId: string | null;
  // MULTIPLIER
  multiplierBase: string;
  multiplierValue: Prisma.Decimal | null;
  multiplierQuantity: Prisma.Decimal | null;
  multiplierCurrencyId: string | null;
  // METAL_MERMA_HECHURA
  hechuraPrice: Prisma.Decimal | null;
  hechuraPriceMode: string;
  mermaPercent: Prisma.Decimal | null;
  category: { mermaPercent: Prisma.Decimal | null } | null;
  compositions: Array<{
    variantId: string;
    grams: Prisma.Decimal;
  }>;
};

type MigrationStats = {
  total: number;
  manual: number;
  multiplier: number;
  metalMermaHechura: number;
  skippedNoData: number;
  errors: number;
};

// ---------------------------------------------------------------------------
// buildLinesForArticle — construye las líneas a crear para un artículo
// ---------------------------------------------------------------------------

function buildLinesForArticle(
  art: ArticleWithLegacy
): Omit<Prisma.ArticleCostLineCreateManyInput, "id" | "createdAt" | "updatedAt">[] {
  const mode = art.costCalculationMode ?? "MANUAL";

  // ── MANUAL ────────────────────────────────────────────────────────────────
  if (mode === "MANUAL") {
    const unitValue = art.manualBaseCost ?? art.costPrice;
    if (unitValue == null) return [];
    return [
      {
        articleId:     art.id,
        jewelryId:     art.jewelryId,
        type:          "MANUAL",
        label:         "Costo manual",
        quantity:      new Prisma.Decimal(1),
        unitValue:     new Prisma.Decimal(unitValue.toString()),
        currencyId:    art.manualCurrencyId ?? null,
        sortOrder:     0,
      },
    ];
  }

  // ── MULTIPLIER ────────────────────────────────────────────────────────────
  if (mode === "MULTIPLIER") {
    if (art.multiplierValue == null || art.multiplierQuantity == null) return [];
    const label =
      art.multiplierBase === "GRAMS"   ? "Multiplicador (gramos)"  :
      art.multiplierBase === "KILATES" ? "Multiplicador (kilates)" :
      art.multiplierBase === "UNITS"   ? "Multiplicador (unidades)" :
      "Multiplicador";
    return [
      {
        articleId:  art.id,
        jewelryId:  art.jewelryId,
        type:       "MANUAL",
        label,
        quantity:   new Prisma.Decimal(art.multiplierQuantity.toString()),
        unitValue:  new Prisma.Decimal(art.multiplierValue.toString()),
        currencyId: art.multiplierCurrencyId ?? null,
        sortOrder:  0,
      },
    ];
  }

  // ── METAL_MERMA_HECHURA ───────────────────────────────────────────────────
  if (mode === "METAL_MERMA_HECHURA") {
    if (art.compositions.length === 0) return [];

    const mermaPercent =
      art.mermaPercent ??
      art.category?.mermaPercent ??
      null;

    const lines: Omit<Prisma.ArticleCostLineCreateManyInput, "id" | "createdAt" | "updatedAt">[] = [];

    // Líneas de metal
    let sortOrder = 0;
    let totalBaseGrams = new Prisma.Decimal(0);
    for (const comp of art.compositions) {
      totalBaseGrams = totalBaseGrams.add(new Prisma.Decimal(comp.grams.toString()));
      lines.push({
        articleId:      art.id,
        jewelryId:      art.jewelryId,
        type:           "METAL",
        label:          "",
        quantity:       new Prisma.Decimal(comp.grams.toString()),
        unitValue:      new Prisma.Decimal(0),  // cotizado dinámicamente por el motor
        metalVariantId: comp.variantId,
        mermaPercent:   mermaPercent,
        currencyId:     null,
        sortOrder:      sortOrder++,
      });
    }

    // Línea de hechura (si existe)
    if (art.hechuraPrice != null) {
      const hp = new Prisma.Decimal(art.hechuraPrice.toString());

      if (art.hechuraPriceMode === "PER_GRAM") {
        // PER_GRAM: la hechura legacy = hechuraPrice × sum(grams × mermaFactor).
        // En el nuevo modelo no hay modo PER_GRAM, por lo que calculamos el total
        // usando los gramos base y la merma del artículo como una aproximación.
        // El resultado se almacena como HECHURA FIXED con la nota de origen.
        //
        // NOTA: el valor queda fijo al momento de la migración. Si el usuario
        // modifica las composiciones metálicas más adelante, deberá actualizar
        // esta línea manualmente.
        const mermaFactor = mermaPercent != null
          ? new Prisma.Decimal(1).add(new Prisma.Decimal(mermaPercent.toString()).div(100))
          : new Prisma.Decimal(1);
        const gramsWithMerma = totalBaseGrams.mul(mermaFactor);
        const computedHechura = hp.mul(gramsWithMerma);

        lines.push({
          articleId:  art.id,
          jewelryId:  art.jewelryId,
          type:       "HECHURA",
          label:      "Hechura (migrada de PER_GRAM — verificar)",
          quantity:   new Prisma.Decimal(1),
          unitValue:  computedHechura,
          currencyId: null,
          sortOrder:  sortOrder++,
        });
      } else {
        // FIXED: mano de obra fija
        lines.push({
          articleId:  art.id,
          jewelryId:  art.jewelryId,
          type:       "HECHURA",
          label:      "Hechura",
          quantity:   new Prisma.Decimal(1),
          unitValue:  hp,
          currencyId: null,
          sortOrder:  sortOrder++,
        });
      }
    }

    return lines;
  }

  return [];
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

async function main() {
  console.log("=".repeat(60));
  console.log("  migrate-cost-to-lines");
  console.log(DRY_RUN ? "  MODO: DRY RUN (sin cambios)" : "  MODO: APLICAR CAMBIOS");
  if (TARGET_JEWELRY) console.log(`  Tenant: ${TARGET_JEWELRY}`);
  console.log("=".repeat(60));

  const stats: MigrationStats = {
    total: 0,
    manual: 0,
    multiplier: 0,
    metalMermaHechura: 0,
    skippedNoData: 0,
    errors: 0,
  };

  // Cargar artículos sin costComposition (en lotes de 200)
  const PAGE = 200;
  let cursor: string | undefined;
  let hasMore = true;

  const jewelryFilter = TARGET_JEWELRY
    ? { jewelryId: TARGET_JEWELRY }
    : {};

  while (hasMore) {
    const batch = await prisma.article.findMany({
      where: {
        ...jewelryFilter,
        deletedAt: null,
        costComposition: { none: {} },
      },
      select: {
        id: true,
        jewelryId: true,
        costCalculationMode: true,
        costPrice: true,
        manualBaseCost: true,
        manualCurrencyId: true,
        multiplierBase: true,
        multiplierValue: true,
        multiplierQuantity: true,
        multiplierCurrencyId: true,
        hechuraPrice: true,
        hechuraPriceMode: true,
        mermaPercent: true,
        category: { select: { mermaPercent: true } },
        compositions: { select: { variantId: true, grams: true } },
      },
      take: PAGE,
      ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
      orderBy: { id: "asc" },
    });

    hasMore = batch.length === PAGE;
    if (batch.length > 0) cursor = batch[batch.length - 1].id;

    stats.total += batch.length;

    for (const art of batch) {
      try {
        const lines = buildLinesForArticle(art as ArticleWithLegacy);
        const mode  = (art.costCalculationMode ?? "MANUAL") as string;

        if (lines.length === 0) {
          stats.skippedNoData++;
          console.log(`  SKIP   [${art.id}] mode=${mode} — sin datos suficientes para migrar`);
          continue;
        }

        if (mode === "MANUAL")              stats.manual++;
        else if (mode === "MULTIPLIER")     stats.multiplier++;
        else if (mode === "METAL_MERMA_HECHURA") stats.metalMermaHechura++;

        const modeTag = mode.padEnd(20);
        console.log(`  ${DRY_RUN ? "PLAN " : "MIGR "} [${art.id}] mode=${modeTag} lines=${lines.length}`);

        if (!DRY_RUN) {
          await prisma.articleCostLine.createMany({
            data: lines as Prisma.ArticleCostLineCreateManyInput[],
          });
        }
      } catch (err) {
        stats.errors++;
        console.error(`  ERROR  [${art.id}]`, err);
      }
    }
  }

  console.log();
  console.log("=".repeat(60));
  console.log("  RESUMEN");
  console.log("=".repeat(60));
  console.log(`  Artículos procesados : ${stats.total}`);
  console.log(`  MANUAL               : ${stats.manual}`);
  console.log(`  MULTIPLIER           : ${stats.multiplier}`);
  console.log(`  METAL_MERMA_HECHURA  : ${stats.metalMermaHechura}`);
  console.log(`  Sin datos (saltados) : ${stats.skippedNoData}`);
  console.log(`  Errores              : ${stats.errors}`);
  if (DRY_RUN) {
    console.log();
    console.log("  Para aplicar cambios ejecutar:");
    console.log("  tsx prisma/scripts/migrate-cost-to-lines.ts --apply");
  } else {
    console.log();
    console.log("  Migración completada.");
    console.log("  Verificar con: tsx prisma/scripts/migrate-cost-to-lines.ts");
  }
  console.log("=".repeat(60));
}

main()
  .catch((e) => { console.error(e); process.exit(1); })
  .finally(() => prisma.$disconnect());
