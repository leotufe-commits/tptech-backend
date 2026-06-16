// scripts/perf/perf-seed.ts
// ============================================================================
// Etapa 2 (perf) — GENERADOR DE DATASET GRANDE para medir Factura a escala.
//
// ⚠️  ESCRIBE filas en la DB apuntada por DATABASE_URL. NO correr contra una DB
//     con datos reales que te importen. Ideal: una DB descartable / staging.
//     Por seguridad exige la variable PERF_SEED_CONFIRM=yes.
//
// Todas las filas llevan marcador `PERF-` en `code` → limpieza trivial con
// `--clean`. No toca pricing, snapshots ni ventas; solo catálogo de búsqueda
// (CommercialEntity + Article) que es lo que estresa los combos.
//
// Uso (PowerShell):
//   $env:PERF_SEED_CONFIRM="yes"; npx tsx scripts/perf/perf-seed.ts
//   $env:PERF_SEED_CONFIRM="yes"; $env:CLIENTS="10000"; $env:ARTICLES="50000"; npx tsx scripts/perf/perf-seed.ts
//   $env:PERF_SEED_CONFIRM="yes"; npx tsx scripts/perf/perf-seed.ts --clean
// ============================================================================

import "dotenv/config";
import { PrismaClient } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL! });
const prisma = new PrismaClient({ adapter });

const CLIENTS = Number(process.env.CLIENTS ?? 10_000);
const ARTICLES = Number(process.env.ARTICLES ?? 50_000);
const CHUNK = 1_000;
const CLEAN = process.argv.includes("--clean");

// Palabras para nombres variados (que la búsqueda por substring tenga selectividad).
const WORDS = ["Anillo", "Cadena", "Dije", "Pulsera", "Aro", "Argolla", "Colgante",
  "Rosario", "Esclava", "Medalla", "Solitario", "Alianza", "Brillante", "Perla"];
const SURN = ["Gómez", "Rossi", "Pérez", "López", "Díaz", "Romero", "Sosa", "Ruiz",
  "Acuña", "Vega", "Molina", "Castro", "Herrera", "Núñez", "Ramos", "Silva"];

function pad(n: number) { return String(n).padStart(6, "0"); }

async function clean() {
  const a = await prisma.article.deleteMany({ where: { code: { startsWith: "PERF-ART-" } } });
  const c = await prisma.commercialEntity.deleteMany({ where: { code: { startsWith: "PERF-CLI-" } } });
  console.log(`🧹 Limpieza: ${c.count} clientes + ${a.count} artículos PERF-* borrados.`);
}

async function seed() {
  const jewelry = await prisma.jewelry.findFirst({ select: { id: true, name: true } });
  if (!jewelry) { console.error("No hay Jewelry en la DB."); return; }
  console.log(`Sembrando en tenant: ${jewelry.name} (${jewelry.id})`);
  console.log(`Objetivo: ${CLIENTS} clientes + ${ARTICLES} artículos\n`);

  // ── Clientes ──────────────────────────────────────────────────────────────
  for (let i = 0; i < CLIENTS; i += CHUNK) {
    const batch = [];
    for (let j = i; j < Math.min(i + CHUNK, CLIENTS); j++) {
      const apellido = SURN[j % SURN.length];
      const display = `${apellido}, Cliente ${pad(j)}`;
      batch.push({
        jewelryId: jewelry.id,
        code: `PERF-CLI-${pad(j)}`,
        displayName: display,
        entityType: "PERSON" as const,
        isClient: true,
        lastName: apellido,
        firstName: `Cliente ${pad(j)}`,
        email: `cli${pad(j)}@perf.test`,
        phone: `11${pad(j)}${j % 100}`,
        documentNumber: `30${pad(j)}${j % 10}`,
      });
    }
    await prisma.commercialEntity.createMany({ data: batch, skipDuplicates: true });
    if ((i / CHUNK) % 10 === 0) console.log(`  clientes: ${Math.min(i + CHUNK, CLIENTS)}/${CLIENTS}`);
  }

  // ── Artículos ─────────────────────────────────────────────────────────────
  for (let i = 0; i < ARTICLES; i += CHUNK) {
    const batch = [];
    for (let j = i; j < Math.min(i + CHUNK, ARTICLES); j++) {
      const w = WORDS[j % WORDS.length];
      batch.push({
        jewelryId: jewelry.id,
        code: `PERF-ART-${pad(j)}`,
        name: `${w} modelo ${pad(j)}`,
        sku: `SKU-${pad(j)}`,
        barcode: `779${pad(j)}${j % 10}`,
      });
    }
    try {
      await prisma.article.createMany({ data: batch as any, skipDuplicates: true });
    } catch (e) {
      console.error("\n⚠️  createMany de Article falló — tu schema exige más campos.",
        "Ajustá el objeto `batch` de artículos con los requeridos.\n", e);
      return;
    }
    if ((i / CHUNK) % 10 === 0) console.log(`  artículos: ${Math.min(i + CHUNK, ARTICLES)}/${ARTICLES}`);
  }

  console.log("\n✅ Seed completo. Ahora corré: npx tsx scripts/perf/bench-search.ts");
}

async function main() {
  if (process.env.PERF_SEED_CONFIRM !== "yes") {
    console.error("Abortado: seteá PERF_SEED_CONFIRM=yes para confirmar que esta DB es descartable.");
    process.exitCode = 1;
    return;
  }
  if (CLEAN) await clean();
  else await seed();
}

main()
  .catch((e) => { console.error("perf-seed falló:", e); process.exitCode = 1; })
  .finally(() => prisma.$disconnect());
