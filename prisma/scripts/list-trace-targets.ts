/**
 * prisma/scripts/list-trace-targets.ts
 *
 * Helper de descubrimiento — lista los IDs necesarios para correr
 * `trace-commercial-document-rounding.ts`:
 *
 *   1. Clientes activos (CommercialEntity con isClient=true)
 *   2. Listas METAL_HECHURA activas con rounding de hechura configurado
 *   3. Artículos activos con composición METAL + HECHURA en ArticleCostLine
 *
 * Solo lectura. Filtra por jewelryId si se provee `--jewelry=<id>` o
 * env `JEWELRY_ID`. Sin filtro, muestra de todas las joyerías.
 *
 * Uso:
 *   npx tsx prisma/scripts/list-trace-targets.ts
 *   npx tsx prisma/scripts/list-trace-targets.ts --jewelry=<id>
 *   JEWELRY_ID=<id> npx tsx prisma/scripts/list-trace-targets.ts
 */

import "dotenv/config";
import { prisma } from "../../src/lib/prisma.js";

const log = (...x: unknown[]) => console.log(...x);  // eslint-disable-line no-console

function jewelryFilter(): string | null {
  const arg = process.argv.slice(2).find((a) => a.startsWith("--jewelry="));
  if (arg) return arg.slice("--jewelry=".length);
  return process.env.JEWELRY_ID ?? null;
}

async function main(): Promise<void> {
  const jewelryId = jewelryFilter();
  const where = jewelryId ? { jewelryId } : {};

  log("");
  log(`Scope: ${jewelryId ? `jewelryId=${jewelryId}` : "(todas las joyerías)"}`);
  log("");

  // 1. CLIENTES
  const clients = await prisma.commercialEntity.findMany({
    where: { ...where, isClient: true, deletedAt: null },
    select: { id: true, code: true, displayName: true, jewelryId: true },
    orderBy: { displayName: "asc" },
    take: 50,
  });
  log("━━━━━━━━━━━━ 1) Clientes activos ━━━━━━━━━━━━");
  if (clients.length === 0) {
    log("  (ninguno)");
  } else {
    for (const c of clients) {
      log(`  ${c.id}  ${c.code.padEnd(10)}  ${c.displayName}${jewelryId ? "" : `  [jwl: ${c.jewelryId}]`}`);
    }
    log(`  Total: ${clients.length}${clients.length === 50 ? " (truncado a 50)" : ""}`);
  }
  log("");

  // 2. LISTAS METAL_HECHURA activas con rounding de hechura
  const lists = await prisma.priceList.findMany({
    where: {
      ...where,
      mode:     "METAL_HECHURA",
      isActive: true,
      deletedAt: null,
    },
    select: {
      id: true, code: true, name: true, jewelryId: true,
      roundingTarget: true, roundingMode: true, roundingDirection: true,
      roundingModeHechura: true, roundingDirectionHechura: true,
      commercialRoundingMetalDomain: true,
    },
    orderBy: { name: "asc" },
  });
  log("━━━━ 2) Listas METAL_HECHURA activas ━━━━");
  if (lists.length === 0) {
    log("  (ninguna)");
  } else {
    for (const l of lists) {
      const heActive = l.roundingModeHechura && l.roundingModeHechura !== "NONE";
      const metalActive = l.roundingMode && l.roundingMode !== "NONE";
      const flag = (heActive || metalActive)
        ? "  ✓ apta para PER_DOCUMENT (con rounding)"
        : "  ⚠ sin rounding configurado — la capa no actuará";
      log(`  ${l.id}  ${(l.code || "(sin code)").padEnd(10)}  ${l.name}${flag}`);
      log(`      target=${l.roundingTarget}  metal=${l.roundingMode} ${l.roundingDirection}  hechura=${l.roundingModeHechura ?? "—"} ${l.roundingDirectionHechura ?? "—"}  metalDomain=${l.commercialRoundingMetalDomain ?? "—"}`);
    }
    log(`  Total: ${lists.length}`);
  }
  log("");

  // 3. Artículos con composición METAL + HECHURA
  // Estrategia: buscar ArticleCostLine con type=METAL agrupado por articleId,
  // y luego intersectar con los que tienen type=HECHURA. Hacemos dos queries
  // y cruzamos en JS — más simple que un raw SQL y trabaja con MongoDB-like
  // chunking si el dataset crece.
  const articleWhere = jewelryId ? { jewelryId } : {};
  const metalArticleIds = new Set(
    (await prisma.articleCostLine.findMany({
      where: { type: "METAL", article: { ...articleWhere, deletedAt: null } },
      select: { articleId: true },
      distinct: ["articleId"],
    })).map((r) => r.articleId),
  );
  const hechuraArticleIds = new Set(
    (await prisma.articleCostLine.findMany({
      where: { type: "HECHURA", article: { ...articleWhere, deletedAt: null } },
      select: { articleId: true },
      distinct: ["articleId"],
    })).map((r) => r.articleId),
  );
  const bothIds = [...metalArticleIds].filter((id) => hechuraArticleIds.has(id));

  const articles = bothIds.length > 0
    ? await prisma.article.findMany({
        where: { id: { in: bothIds }, status: "ACTIVE", deletedAt: null },
        select: { id: true, code: true, name: true, jewelryId: true, sku: true },
        orderBy: { name: "asc" },
        take: 50,
      })
    : [];

  log("━━━ 3) Artículos activos con METAL + HECHURA ━━━");
  if (articles.length === 0) {
    log("  (ninguno)");
  } else {
    for (const a of articles) {
      log(`  ${a.id}  ${a.code.padEnd(10)}  ${a.name}${a.sku ? `  [sku: ${a.sku}]` : ""}${jewelryId ? "" : `  [jwl: ${a.jewelryId}]`}`);
    }
    log(`  Total: ${articles.length}${articles.length === 50 ? " (truncado a 50)" : ""}`);
  }
  log("");

  // Hint final
  if (clients[0] && lists.some((l) => l.roundingModeHechura !== "NONE") && articles[0]) {
    const lh = lists.find((l) => l.roundingModeHechura !== "NONE")!;
    log("──────────────────────────────────────────────────");
    log("Ejemplo listo para copiar/pegar:");
    log("");
    log(`npx tsx prisma/scripts/trace-commercial-document-rounding.ts \\`);
    log(`  --client=${clients[0].id} \\`);
    log(`  --price-list=${lh.id} \\`);
    log(`  --article=${articles[0].id} \\`);
    log(`  --qty=1`);
    log("");
  }

  await prisma.$disconnect();
}

main().catch(async (err) => {
  // eslint-disable-next-line no-console
  console.error("\n❌ Error:", err);
  try { await prisma.$disconnect(); } catch {}
  process.exit(1);
});
