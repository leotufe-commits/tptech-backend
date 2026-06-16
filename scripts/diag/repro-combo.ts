// scripts/diag/repro-combo.ts
// ============================================================================
// REPRODUCCIÓN del caso del combo + caracterización runtime. Siembra un combo
// CONTROLADO (componente que vende 558.850,66 + ajuste DISCOUNT_PERCENT 10%),
// corre el motor REAL y vuelca los valores que deciden E1 vs E2. Limpia todo
// al terminar (finally).
//
// Observación pura: corre el motor existente, no lo modifica. La data sembrada
// lleva prefijo DIAG- y se borra al final.
//
//   npx tsx scripts/diag/repro-combo.ts            # new-pipeline (unitValue>0)
//   npx tsx scripts/diag/repro-combo.ts legacy     # legacy (unitValue=0)
// ============================================================================

import "dotenv/config";
import { prisma } from "../../src/lib/prisma.js";
import { resolveFinalSalePrice } from "../../src/lib/pricing-engine/pricing-engine.js";

const LEGACY = process.argv[2] === "legacy";
const COMP_COST = 400_000;
const COMP_SALE = 558_850.66;
const ADJ_PCT = 10;

function num(v: unknown): number | null {
  if (v == null) return null;
  const n = typeof v === "object" && v !== null && "toString" in v ? Number((v as any).toString()) : Number(v);
  return Number.isFinite(n) ? n : null;
}

async function cleanup() {
  await prisma.articleCostLine.deleteMany({ where: { article: { code: { startsWith: "DIAG-" } } } });
  await prisma.article.deleteMany({ where: { code: { startsWith: "DIAG-" } } });
}

async function main() {
  const jewelry = await prisma.jewelry.findFirst({ select: { id: true } });
  if (!jewelry) { console.log("No hay Jewelry."); return; }
  const jewelryId = jewelry.id;

  await cleanup(); // por si una corrida anterior quedó a medias

  // ── Componente: vende COMP_SALE (manual) y cuesta COMP_COST (hechura) ──────
  const comp = await prisma.article.create({
    data: {
      jewelryId, code: "DIAG-COMP", name: "DIAG Componente",
      articleType: "PRODUCT", stockMode: "NO_STOCK",
      salePrice: COMP_SALE as any, useManualSalePrice: true,
      costComposition: { create: [{ jewelryId, type: "HECHURA", quantity: 1 as any, unitValue: COMP_COST as any }] },
    },
    select: { id: true },
  });

  // ── Combo: ajuste global DISCOUNT_PERCENT 10% ─────────────────────────────
  const combo = await prisma.article.create({
    data: {
      jewelryId, code: "DIAG-COMBO", name: "DIAG Combo",
      articleType: "PRODUCT", stockMode: "NO_STOCK", sellWithoutVariants: true,
      commercialMode: "COMBO_COMMERCIAL",
      comboAdjustmentKind: "DISCOUNT_PERCENT", comboAdjustmentValue: ADJ_PCT as any,
      costComposition: {
        create: [{
          jewelryId, type: "PRODUCT", quantity: 1 as any,
          unitValue: (LEGACY ? 0 : COMP_COST) as any, // legacy=0 ⇒ comboPriceUsedCostLines=false
          catalogItemId: comp.id,
        }],
      },
    },
    select: { id: true },
  });

  console.log("════════════════════════════════════════════════════════════");
  console.log(` REPRO COMBO — pipeline: ${LEGACY ? "LEGACY (unitValue=0)" : "NEW (unitValue>0)"}`);
  console.log(`   componente vende ${COMP_SALE} · ajuste ${ADJ_PCT}% · esperado post = ${COMP_SALE * 0.9}`);
  console.log("════════════════════════════════════════════════════════════");

  const r: any = await resolveFinalSalePrice(jewelryId, { articleId: combo.id, quantity: 1 });
  const steps: any[] = r.steps ?? [];
  const cps = steps.find((s) => s?.key === "COMBO_PRICE");
  const meta = cps?.meta ?? {};
  const subtotal = num(meta.subtotal);
  const finalPrice = num(meta.finalPrice);
  const adjAmount = num(meta.adjustmentAmount);
  const basePrice = num(r.basePrice);
  const priceSource = r.priceSource;
  const comboPriceWins = priceSource === "COMBO_COMPONENTS";

  console.table({
    "comboAdjustmentKind":  meta.adjustmentKind,
    "comboAdjustmentValue": num(meta.adjustmentValue),
    "subtotal (PRE)":       subtotal,
    "adjustmentAmount":     adjAmount,
    "finalPrice/comboDerivedPrice (POST)": finalPrice,
    "basePrice (canónico)": basePrice,
    "unitPrice":            num(r.unitPrice),
    "priceSource":          String(priceSource),
    "comboPriceWins":       comboPriceWins,
  });

  console.log("\n── VEREDICTO ────────────────────────────────────────────────");
  const eps = 0.05;
  if (basePrice != null && finalPrice != null && Math.abs(basePrice - finalPrice) <= eps) {
    console.log(`E2 — basePrice (${basePrice}) == comboDerivedPrice POST (${finalPrice}). El ajuste SÍ llega al canónico. Sin bypass.`);
  } else if (basePrice != null && subtotal != null && Math.abs(basePrice - subtotal) <= eps && adjAmount != null && Math.abs(adjAmount) > eps) {
    console.log(`E1 — BYPASS: basePrice (${basePrice}) == subtotal PRE (${subtotal}); comboDerivedPrice POST=${finalPrice} se DESCARTÓ. Punto: comboPriceWins (sale.ts:1987-1995).`);
  } else {
    console.log(`INDETERMINADO: basePrice=${basePrice}, finalPrice=${finalPrice}, subtotal=${subtotal}, priceSource=${priceSource}.`);
  }
}

main()
  .catch((e) => { console.error("repro-combo falló:", e); process.exitCode = 1; })
  .finally(async () => { await cleanup(); await prisma.$disconnect(); });
