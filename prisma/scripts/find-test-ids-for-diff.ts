/**
 * prisma/scripts/find-test-ids-for-diff.ts
 *
 * Devuelve IDs reales (priceList PER_DOCUMENT + article con METAL + cliente)
 * para alimentar diff-commercial-rounding-by-quantity.ts.
 *
 * Solo lectura.
 */

import "dotenv/config";
import { prisma } from "../../src/lib/prisma.js";

async function main(): Promise<void> {
  // 1) Lista de precios con commercialRoundingScope=PER_DOCUMENT y BREAKDOWN
  const lists = await prisma.priceList.findMany({
    where: {
      isActive: true,
      deletedAt: null,
      commercialRoundingScope: "PER_DOCUMENT",
    },
    select: {
      id: true,
      name: true,
      jewelryId: true,
      commercialRoundingScope: true,
    },
    take: 5,
  });

  // eslint-disable-next-line no-console
  console.log("\n━━━ PriceLists con PER_DOCUMENT ━━━");
  for (const l of lists) {
    console.log(`  id=${l.id}  name="${l.name}"  jewelryId=${l.jewelryId}`);
    console.log(`     scope=${l.commercialRoundingScope}`);
  }

  if (lists.length === 0) {
    console.log("  (ninguna — el bug solo se reproduce con PER_DOCUMENT)");
    await prisma.$disconnect();
    process.exit(1);
  }

  const tenant = lists[0].jewelryId;

  // 2) Artículos con composición METAL para ese tenant
  const articles = await prisma.article.findMany({
    where: {
      jewelryId: tenant,
      deletedAt: null,
      isActive: true,
      costComposition: { some: { type: "METAL" } },
    },
    select: {
      id: true,
      name: true,
      costComposition: {
        where: { type: "METAL" },
        select: { id: true, label: true, quantity: true },
        take: 3,
      },
    },
    take: 5,
  });

  console.log("\n━━━ Articles con METAL en composición ━━━");
  for (const a of articles) {
    console.log(`  id=${a.id}  name="${a.name}"`);
    for (const c of a.costComposition) {
      console.log(`     costLine METAL id=${c.id}  label="${c.label}"  qty=${c.quantity}`);
    }
  }

  // 3) Un cliente del tenant
  const clients = await prisma.commercialEntity.findMany({
    where: { jewelryId: tenant, deletedAt: null, isActive: true },
    select: { id: true },
    take: 3,
  });
  console.log("\n━━━ Clients ━━━");
  for (const c of clients) console.log(`  id=${c.id}`);

  // 4) Comando armado listo para copy-paste (modo SIMPLE y OVERRIDE)
  if (lists.length > 0 && articles.length > 0) {
    const l = lists[0];
    const a = articles[0];
    const c = clients[0];
    const cl = a.costComposition[0];
    console.log("\n━━━ Comandos sugeridos ━━━\n");
    console.log("Modo SIMPLE (varía quantity de la línea):");
    console.log(`  npx tsx prisma/scripts/diff-commercial-rounding-by-quantity.ts \\`);
    console.log(`    --client=${c?.id ?? "<falta>"} \\`);
    console.log(`    --price-list=${l.id} \\`);
    console.log(`    --article=${a.id} \\`);
    console.log(`    --qty-a=1.50 --qty-b=2.25`);
    console.log("");
    console.log("Modo OVERRIDE (edita gramos del metal — reproduce edición de la grilla):");
    console.log(`  npx tsx prisma/scripts/diff-commercial-rounding-by-quantity.ts \\`);
    console.log(`    --client=${c?.id ?? "<falta>"} \\`);
    console.log(`    --price-list=${l.id} \\`);
    console.log(`    --article=${a.id} \\`);
    console.log(`    --qty=1 \\`);
    console.log(`    --metal-cost-line=${cl?.id ?? "<falta>"} \\`);
    console.log(`    --metal-grams-a=1.50 --metal-grams-b=2.25`);
  }

  await prisma.$disconnect();
  process.exit(0);
}

main().catch(async (err) => {
  // eslint-disable-next-line no-console
  console.error("❌", err);
  try { await prisma.$disconnect(); } catch {}
  process.exit(1);
});
