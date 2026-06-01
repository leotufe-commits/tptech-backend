// FIXTURE de desarrollo — artículo multimetal Oro + Plata para validar la
// consistencia de gramos (Opción PURE) en Simulador y Factura.
//
// SEGURO: guard NODE_ENV !== production. NO modifica artículos reales — crea
// uno nuevo marcado (notes = __FIXTURE_MULTIMETAL__) y borrable.
//
// Uso:
//   npx tsx scripts/fixture-multimetal.ts          → crea (idempotente)
//   npx tsx scripts/fixture-multimetal.ts delete    → borra el/los fixture(s)
import "dotenv/config";
import { prisma } from "../src/lib/prisma.js";

if (process.env.NODE_ENV === "production") {
  // eslint-disable-next-line no-console
  console.error("ABORTADO: NODE_ENV=production. Este fixture es SOLO para desarrollo.");
  process.exit(1);
}

const JEWELRY     = "cmprg38kp00000scabmdsuj20";
const ORO_ARTICLE = "cmprgvq03007k0scal9pnhz9k";       // clon base (campos válidos)
const ORO_18K     = "cmprg38xo00690scak2pizk4t";       // purity 0,75 · margen → delta≠0
const PLATA_950   = "cmprg38y7006k0scadt5u0q1y";       // purity 1 · grams a delta=0
const MARKER      = "__FIXTURE_MULTIMETAL__";

async function del() {
  const arts = await (prisma as any).article.findMany({
    where: { jewelryId: JEWELRY, notes: MARKER },
    select: { id: true, name: true },
  });
  for (const a of arts) {
    await (prisma as any).articleCostLine.deleteMany({ where: { articleId: a.id } });
    await (prisma as any).article.delete({ where: { id: a.id } });
    // eslint-disable-next-line no-console
    console.log("Borrado:", a.name, a.id);
  }
  if (arts.length === 0) console.log("No hay fixtures para borrar.");
}

async function create() {
  await del(); // idempotente
  const oro = await (prisma as any).article.findFirst({ where: { id: ORO_ARTICLE } });
  if (!oro) { console.error("No se encontró el artículo base."); return; }
  const { id, code, sku, barcode, name, notes, mainImageUrl, createdAt, updatedAt, ...rest } = oro;
  const art = await (prisma as any).article.create({
    data: {
      ...rest,
      code:    "FIXTURE-MM-001",
      name:    "[FIXTURE] MULTIMETAL ORO+PLATA",
      sku:     "FIXTURE-MM-001",
      barcode: "FIXTURE-MM-001",
      mainImageUrl: "",
      notes:   MARKER,
    },
  });
  await (prisma as any).articleCostLine.createMany({
    data: [
      // ORO 18k — 1,5 g × 0,75 × merma 10% = 1,2375 g puros → DECIMAL_1 → 1,20 (delta≠0)
      { articleId: art.id, jewelryId: JEWELRY, type: "METAL", label: "", quantity: "1.5", quantityUnit: "g", unitValue: "206250", mermaPercent: "10", metalVariantId: ORO_18K, sortOrder: 0, affectsStock: false },
      // PLATA 950 — 2,0 g × 1 × merma 0% = 2,0 g puros → DECIMAL_1 → 2,00 (delta=0)
      { articleId: art.id, jewelryId: JEWELRY, type: "METAL", label: "", quantity: "2", quantityUnit: "g", unitValue: "1800", mermaPercent: "0", metalVariantId: PLATA_950, sortOrder: 1, affectsStock: false },
      // HECHURA simple
      { articleId: art.id, jewelryId: JEWELRY, type: "HECHURA", label: "Precio / Hechura", quantity: "1", quantityUnit: "g", unitValue: "50003", sortOrder: 2, affectsStock: false },
    ],
  });
  // eslint-disable-next-line no-console
  console.log("\n✅ FIXTURE creado:");
  console.log("   id:", art.id);
  console.log("   code/sku:", art.code);
  console.log("   name:", art.name);
}

const cmd = process.argv[2];
(cmd === "delete" ? del() : create())
  .catch((e) => { console.error("ERR:", e?.message ?? e, e?.stack); process.exitCode = 1; })
  .finally(async () => { try { await (prisma as any).$disconnect?.(); } catch {} });
