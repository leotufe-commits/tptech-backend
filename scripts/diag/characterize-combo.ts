// scripts/diag/characterize-combo.ts
// ============================================================================
// CARACTERIZACIÓN RUNTIME del precio de un COMBO COMERCIAL.
//
// Corre el motor REAL (`resolveFinalSalePrice`) sobre un combo de la DB y vuelca
// los valores que deciden E1 vs E2:
//   comboAdjustmentKind/Value · COMBO_PRICE.meta (subtotal/adjustment/finalPrice)
//   · priceSource · basePrice · unitPrice · ¿comboPriceWins?
//
// 100% solo-lectura / observación: NO escribe, NO toca cálculos, NO modifica el
// motor. Solo ejecuta y reporta.
//
// Uso:
//   npx tsx scripts/diag/characterize-combo.ts            # primer COMBO_COMMERCIAL de la DB
//   npx tsx scripts/diag/characterize-combo.ts <articleId> # un combo específico
// ============================================================================

import "dotenv/config";
import { prisma } from "../../src/lib/prisma.js";
import { resolveFinalSalePrice } from "../../src/lib/pricing-engine/pricing-engine.js";

const ARTICLE_ID = process.argv[2] ?? null;

function num(v: unknown): number | null {
  if (v == null) return null;
  const n = typeof v === "object" && v !== null && "toString" in v ? Number((v as any).toString()) : Number(v);
  return Number.isFinite(n) ? n : null;
}

async function main() {
  const sel = {
    id: true, jewelryId: true, name: true, code: true,
    commercialMode: true, comboAdjustmentKind: true, comboAdjustmentValue: true,
  } as const;

  const combo = ARTICLE_ID
    ? await prisma.article.findUnique({ where: { id: ARTICLE_ID }, select: sel })
    : await prisma.article.findFirst({ where: { commercialMode: "COMBO_COMMERCIAL", deletedAt: null }, select: sel });

  if (!combo) {
    console.log("⚠️  No hay COMBO_COMMERCIAL en esta DB (o el id no existe).");
    console.log("   Pasá el articleId del combo real: npx tsx scripts/diag/characterize-combo.ts <id>");
    return;
  }

  // Componentes (para inferir new-pipeline: unitValue > 0 ⇒ comboPriceUsedCostLines)
  const costLines = await prisma.articleCostLine.findMany({
    where: { articleId: combo.id },
    select: { type: true, unitValue: true, quantity: true, catalogItemId: true, affectsStock: true },
  });
  const anyUnitValuePositive = costLines.some((c) => num(c.unitValue) != null && (num(c.unitValue) as number) > 0);

  console.log("════════════════════════════════════════════════════════════");
  console.log(" CARACTERIZACIÓN — COMBO COMERCIAL");
  console.log("════════════════════════════════════════════════════════════");
  console.log(`Combo: ${combo.name} (${combo.code ?? "-"})  id=${combo.id}`);
  console.log(`commercialMode:      ${combo.commercialMode}`);
  console.log(`comboAdjustmentKind: ${combo.comboAdjustmentKind}`);
  console.log(`comboAdjustmentValue:${num(combo.comboAdjustmentValue)}`);
  console.log(`componentes (costLines): ${costLines.length}  · algún unitValue>0: ${anyUnitValuePositive}`);
  console.log("");

  // ── Correr el motor REAL ──────────────────────────────────────────────────
  const r: any = await resolveFinalSalePrice(combo.jewelryId, { articleId: combo.id, quantity: 1 });

  const steps: any[] = r.steps ?? [];
  const comboPriceStep = steps.find((s) => s?.key === "COMBO_PRICE");
  const comboCostStep  = steps.find((s) => s?.key === "COMBO_COST");
  const manualStep     = steps.find((s) => s?.key === "MANUAL_PRICE_OVERRIDE");

  const meta = comboPriceStep?.meta ?? {};
  const subtotal        = num(meta.subtotal);         // PRE ajuste
  const adjustmentKind  = meta.adjustmentKind;
  const adjustmentValue = num(meta.adjustmentValue);
  const adjustmentAmount= num(meta.adjustmentAmount);
  const finalPrice      = num(meta.finalPrice);       // POST ajuste (comboDerivedPrice)
  const basePrice       = num(r.basePrice);
  const unitPrice       = num(r.unitPrice);
  const priceSource     = r.priceSource;

  console.log("── VALORES DEL MOTOR ────────────────────────────────────────");
  console.table({
    "comboAdjustmentKind":  String(adjustmentKind ?? combo.comboAdjustmentKind),
    "comboAdjustmentValue": adjustmentValue ?? num(combo.comboAdjustmentValue),
    "subtotal (PRE ajuste)":  subtotal,
    "adjustmentAmount":       adjustmentAmount,
    "finalPrice (comboDerivedPrice, POST)": finalPrice,
    "basePrice (canónico final)": basePrice,
    "unitPrice":              unitPrice,
    "priceSource":            String(priceSource),
    "COMBO_COST.totalCost":   num(comboCostStep?.meta?.totalCost),
    "MANUAL_PRICE_OVERRIDE?": manualStep ? "SÍ" : "no",
  });

  // ── Inferencias clave ─────────────────────────────────────────────────────
  // comboPriceWins fired ⟺ priceSource === "COMBO_COMPONENTS" (sale.ts:2004).
  const comboPriceWins = priceSource === "COMBO_COMPONENTS";
  const eps = 0.02;
  const baseEqFinal    = subtotalCmp(basePrice, finalPrice, eps);
  const baseEqSubtotal = subtotalCmp(basePrice, subtotal, eps);

  console.log("\n── INFERENCIAS ──────────────────────────────────────────────");
  console.log(`comboPriceUsedCostLines (inferido por unitValue>0): ${anyUnitValuePositive}`);
  console.log(`comboPriceWins (priceSource===COMBO_COMPONENTS):    ${comboPriceWins}`);
  console.log(`basePrice == finalPrice (ajuste aplicado al canónico)? ${baseEqFinal}`);
  console.log(`basePrice == subtotal  (ajuste PERDIDO antes del canónico)? ${baseEqSubtotal}`);

  console.log("\n── VEREDICTO ────────────────────────────────────────────────");
  if (baseEqFinal && !baseEqSubtotal) {
    console.log("E2 — El ajuste YA está en el precio canónico (basePrice == finalPrice POST-ajuste).");
    console.log("     No hay bypass. La diferencia con la composición pertenece a OTRO mecanismo.");
  } else if (baseEqSubtotal && !baseEqFinal && adjustmentAmount != null && Math.abs(adjustmentAmount) > eps) {
    console.log("E1 — BYPASS: el ajuste se calculó (adjustmentAmount != 0, finalPrice POST) pero");
    console.log("     basePrice == subtotal (PRE-ajuste). El ajuste se PIERDE antes del canónico.");
    console.log("     Punto: el precio ajustado (comboDerivedPrice) NO ganó → ver gate");
    console.log("     `comboPriceWins` en pricing-engine.sale.ts:1987-1995.");
  } else {
    console.log("INDETERMINADO con estos valores. basePrice no coincide ni con finalPrice ni con");
    console.log("subtotal — el precio pudo venir de otra fuente (lista/manual). Revisar priceSource");
    console.log(`y los valores de arriba. (basePrice=${basePrice}, finalPrice=${finalPrice}, subtotal=${subtotal}, priceSource=${priceSource})`);
  }
}

function subtotalCmp(a: number | null, b: number | null, eps: number): boolean {
  if (a == null || b == null) return false;
  return Math.abs(a - b) <= eps;
}

main()
  .catch((e) => { console.error("characterize-combo falló:", e); process.exitCode = 1; })
  .finally(() => prisma.$disconnect());
