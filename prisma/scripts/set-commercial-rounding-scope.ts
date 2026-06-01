/**
 * prisma/scripts/set-commercial-rounding-scope.ts
 *
 * Inspecciona y/o actualiza `PriceList.commercialRoundingScope` desde la DB
 * configurada en .env. Solo afecta UNA fila (la del id pasado).
 *
 * Usos:
 *   1) Solo consultar el valor actual:
 *      npx tsx prisma/scripts/set-commercial-rounding-scope.ts --id=<priceListId>
 *
 *   2) Cambiar a PER_DOCUMENT (incluye SELECT antes/después):
 *      npx tsx prisma/scripts/set-commercial-rounding-scope.ts \
 *        --id=<priceListId> --set=PER_DOCUMENT
 *
 *   3) Volver al default legacy:
 *      npx tsx prisma/scripts/set-commercial-rounding-scope.ts \
 *        --id=<priceListId> --set=PER_LINE_LEGACY
 */

import "dotenv/config";
import { prisma } from "../../src/lib/prisma.js";

const log = (...x: unknown[]) => console.log(...x); // eslint-disable-line no-console

function flag(name: string): string | null {
  for (const a of process.argv.slice(2)) {
    if (a.startsWith(`--${name}=`)) return a.slice(name.length + 3);
  }
  return null;
}

async function main(): Promise<void> {
  const id  = flag("id");
  const set = flag("set");

  if (!id) {
    console.error("\n❌ Falta --id=<priceListId>\n");
    process.exit(1);
  }

  // ── 1) Mostrar valor actual ─────────────────────────────────────────────
  const before = await prisma.priceList.findFirst({
    where: { id },
    select: {
      id: true, name: true, code: true, mode: true,
      commercialRoundingScope: true,
      roundingTarget: true, roundingMode: true, roundingDirection: true,
      roundingModeHechura: true, roundingDirectionHechura: true,
      commercialRoundingMetalDomain: true,
    },
  });
  if (!before) {
    console.error(`\n❌ PriceList ${id} no encontrada\n`);
    process.exit(1);
  }

  log("");
  log("━━━━━━━━━━━━ Estado actual ━━━━━━━━━━━━");
  log(`  id:                            ${before.id}`);
  log(`  code:                          ${before.code || "(sin code)"}`);
  log(`  name:                          ${before.name}`);
  log(`  mode:                          ${before.mode}`);
  log(`  commercialRoundingScope:       ${before.commercialRoundingScope}   ← clave Etapa D'`);
  log(`  roundingTarget:                ${before.roundingTarget}`);
  log(`  roundingMode:                  ${before.roundingMode} ${before.roundingDirection}`);
  log(`  roundingModeHechura:           ${before.roundingModeHechura ?? "—"} ${before.roundingDirectionHechura ?? ""}`);
  log(`  commercialRoundingMetalDomain: ${before.commercialRoundingMetalDomain}`);
  log("");

  // ── 2) Sin --set → solo SELECT, salir ───────────────────────────────────
  if (!set) {
    log("(SELECT-only — pasá --set=PER_DOCUMENT o --set=PER_LINE_LEGACY para actualizar)");
    log("");
    await prisma.$disconnect();
    return;
  }

  // ── 3) Validar el nuevo valor ───────────────────────────────────────────
  if (set !== "PER_DOCUMENT" && set !== "PER_LINE_LEGACY") {
    console.error(`\n❌ --set debe ser PER_DOCUMENT o PER_LINE_LEGACY (recibido: "${set}")\n`);
    process.exit(1);
  }
  if (before.commercialRoundingScope === set) {
    log(`(El valor ya era "${set}" — no hay nada que cambiar)`);
    log("");
    await prisma.$disconnect();
    return;
  }

  // ── 4) UPDATE acotado por id ────────────────────────────────────────────
  const after = await prisma.priceList.update({
    where: { id },
    data:  { commercialRoundingScope: set as any },
    select: { id: true, name: true, commercialRoundingScope: true },
  });
  log("━━━━━━━━━━━━ UPDATE aplicado ━━━━━━━━━━━━");
  log(`  ${before.commercialRoundingScope}  →  ${after.commercialRoundingScope}`);
  log(`  lista:  ${after.name} (${after.id})`);
  log("");
  log("✓ Listo. Re-correr el trace para validar:");
  log("");
  log(`  npx tsx prisma/scripts/trace-commercial-document-rounding.ts \\`);
  log(`    --client=<CLIENT_ID> \\`);
  log(`    --price-list=${after.id} \\`);
  log(`    --article=<ARTICLE_ID> \\`);
  log(`    --qty=1`);
  log("");

  await prisma.$disconnect();
}

main().catch(async (err) => {
  console.error("\n❌ Error:", err);
  try { await prisma.$disconnect(); } catch {}
  process.exit(1);
});
