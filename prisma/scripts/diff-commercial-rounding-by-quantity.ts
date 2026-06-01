/**
 * prisma/scripts/diff-commercial-rounding-by-quantity.ts
 *
 * Diagnóstico: ejecuta DOS `previewSale` consecutivos variando la cantidad
 * (o el `quantityOverride` del METAL del operador en la grilla) y compara
 * `documentTotals.commercialDocumentRoundingApplied.breakdown.metals[]`.
 *
 * Veredicto:
 *   · `preGrams` IDÉNTICO entre A y B  → BUG BACKEND CONFIRMADO
 *     (el agregado del Redondeo Comercial NO refleja la edición).
 *   · `preGrams` CAMBIA entre A y B    → BACKEND OK. El bug vive en
 *     frontend (pipeline FE no propaga el response al draft).
 *
 * Solo lectura. NO crea ni modifica datos.
 *
 * USO — Modo SIMPLE (varía `quantity` de la línea):
 *   npx tsx prisma/scripts/diff-commercial-rounding-by-quantity.ts \
 *     --client=<id> --price-list=<id> --article=<id> \
 *     --qty-a=1.50 --qty-b=2.25
 *
 * USO — Modo OVERRIDE (reproduce edición de gramos del metal en la grilla):
 *   npx tsx prisma/scripts/diff-commercial-rounding-by-quantity.ts \
 *     --client=<id> --price-list=<id> --article=<id> --qty=1 \
 *     --metal-cost-line=<costLineId> --metal-grams-a=1.50 --metal-grams-b=2.25
 *
 * Si no se especifica --metal-cost-line, el modo OVERRIDE detecta el
 * primer cost line de tipo METAL del artículo automáticamente.
 */

import "dotenv/config";

// PRICING_TRACE off — este script no necesita el trace por consola.
process.env.PRICING_TRACE = "off";

import { prisma } from "../../src/lib/prisma.js";
import { previewSale, type SalePreviewInput } from "../../src/modules/sales/sales.service.js";

// ─────────────────────────────────────────────────────────────────────────────
// Args
// ─────────────────────────────────────────────────────────────────────────────

function flag(name: string): string | null {
  for (const a of process.argv.slice(2)) {
    const prefix = `--${name}=`;
    if (a.startsWith(prefix)) return a.slice(prefix.length);
  }
  return null;
}

const ARGS = {
  clientId:       flag("client")       ?? process.env.CLIENT_ID      ?? null,
  priceListId:    flag("price-list")   ?? process.env.PRICE_LIST_ID  ?? null,
  articleId:      flag("article")      ?? process.env.ARTICLE_ID     ?? null,
  variantId:      flag("variant")      ?? process.env.VARIANT_ID     ?? null,
  qty:            flag("qty"),
  qtyA:           flag("qty-a"),
  qtyB:           flag("qty-b"),
  metalCostLine:  flag("metal-cost-line"),
  metalGramsA:    flag("metal-grams-a"),
  metalGramsB:    flag("metal-grams-b"),
};

function bailUsage(msg: string): never {
  // eslint-disable-next-line no-console
  console.error(`\n❌ ${msg}\n
Uso (modo SIMPLE — varía quantity de la línea):
  npx tsx prisma/scripts/diff-commercial-rounding-by-quantity.ts \\
    --client=<id> --price-list=<id> --article=<id> \\
    --qty-a=1.50 --qty-b=2.25

Uso (modo OVERRIDE — reproduce edición de gramos del metal en la grilla):
  npx tsx prisma/scripts/diff-commercial-rounding-by-quantity.ts \\
    --client=<id> --price-list=<id> --article=<id> --qty=1 \\
    [--metal-cost-line=<costLineId>] --metal-grams-a=1.50 --metal-grams-b=2.25
`);
  process.exit(1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Detección automática del primer METAL cost line del artículo
// ─────────────────────────────────────────────────────────────────────────────

async function detectFirstMetalCostLineId(articleId: string): Promise<string | null> {
  const composition = await prisma.articleCostLine.findMany({
    where:  { articleId, type: "METAL" },
    select: { id: true, label: true },
    orderBy:{ id: "asc" },
    take:   1,
  });
  return composition[0]?.id ?? null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Construcción de inputs (A y B)
// ─────────────────────────────────────────────────────────────────────────────

async function buildInputs(): Promise<{
  jewelryId: string;
  mode: "SIMPLE" | "OVERRIDE";
  inputA: SalePreviewInput;
  inputB: SalePreviewInput;
  descA: string;
  descB: string;
}> {
  if (!ARGS.articleId)   bailUsage("Falta --article=<id>.");
  if (!ARGS.priceListId) bailUsage("Falta --price-list=<id>.");

  const article = await prisma.article.findFirst({
    where: { id: ARGS.articleId },
    select: { id: true, jewelryId: true },
  });
  if (!article) bailUsage(`Article ${ARGS.articleId} no encontrado.`);

  // Modo OVERRIDE — el operador edita gramos del METAL en la grilla.
  if (ARGS.metalGramsA != null || ARGS.metalGramsB != null) {
    if (ARGS.metalGramsA == null || ARGS.metalGramsB == null) {
      bailUsage("Modo OVERRIDE requiere AMBOS --metal-grams-a y --metal-grams-b.");
    }
    const metalCostLineId =
      ARGS.metalCostLine ?? (await detectFirstMetalCostLineId(ARGS.articleId));
    if (!metalCostLineId) {
      bailUsage(`No se encontró ningún cost line METAL para article=${ARGS.articleId}.`);
    }
    const baseQty = Number(ARGS.qty ?? "1");
    const gramsA  = Number(ARGS.metalGramsA);
    const gramsB  = Number(ARGS.metalGramsB);
    const lineCommon = {
      articleId:           ARGS.articleId,
      variantId:           ARGS.variantId,
      quantity:            baseQty,
      priceListIdOverride: ARGS.priceListId,
    };
    return {
      jewelryId: article.jewelryId,
      mode:      "OVERRIDE",
      inputA: {
        lines: [{
          ...lineCommon,
          costLineOverrides: [{
            costLineId:        metalCostLineId,
            type:              "METAL",
            quantityOverride:  gramsA,
          }],
        }],
        clientId:    ARGS.clientId,
        priceListId: ARGS.priceListId,
      },
      inputB: {
        lines: [{
          ...lineCommon,
          costLineOverrides: [{
            costLineId:        metalCostLineId,
            type:              "METAL",
            quantityOverride:  gramsB,
          }],
        }],
        clientId:    ARGS.clientId,
        priceListId: ARGS.priceListId,
      },
      descA: `costLineOverrides[METAL ${metalCostLineId}].quantityOverride = ${gramsA} g`,
      descB: `costLineOverrides[METAL ${metalCostLineId}].quantityOverride = ${gramsB} g`,
    };
  }

  // Modo SIMPLE — varía la quantity de la línea.
  const qtyA = Number(ARGS.qtyA ?? "1.50");
  const qtyB = Number(ARGS.qtyB ?? "2.25");
  const lineCommon = {
    articleId:           ARGS.articleId,
    variantId:           ARGS.variantId,
    priceListIdOverride: ARGS.priceListId,
  };
  return {
    jewelryId: article.jewelryId,
    mode:      "SIMPLE",
    inputA: {
      lines:       [{ ...lineCommon, quantity: qtyA }],
      clientId:    ARGS.clientId,
      priceListId: ARGS.priceListId,
    },
    inputB: {
      lines:       [{ ...lineCommon, quantity: qtyB }],
      clientId:    ARGS.clientId,
      priceListId: ARGS.priceListId,
    },
    descA: `line.quantity = ${qtyA}`,
    descB: `line.quantity = ${qtyB}`,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers de presentación
// ─────────────────────────────────────────────────────────────────────────────

const LINE = "━".repeat(78);
const log  = (...x: unknown[]) => console.log(...x);  // eslint-disable-line no-console

type MetalEntry = {
  metalParentId?:      string | null;
  metalParentName?:    string | null;
  preGrams?:           number | null;
  postGrams?:          number | null;
  deltaGrams?:         number | null;
  monetaryEquivalent?: number | null;
};

function indexByName(metals: MetalEntry[]): Map<string, MetalEntry> {
  const out = new Map<string, MetalEntry>();
  for (const m of metals) {
    const key = String(m?.metalParentName ?? m?.metalParentId ?? "");
    if (key.length === 0) continue;
    out.set(key, m);
  }
  return out;
}

function printMetalsBlock(label: string, metals: MetalEntry[]): void {
  log(LINE);
  log(label);
  log(LINE);
  if (metals.length === 0) {
    log("  (vacío — snapshot ausente o sin metales)");
    return;
  }
  for (const m of metals) {
    log(`  metalParentName:    "${m.metalParentName}"`);
    log(`    preGrams:         ${m.preGrams}`);
    log(`    postGrams:        ${m.postGrams}`);
    log(`    deltaGrams:       ${m.deltaGrams}`);
    log(`    monetaryEquivalent:${m.monetaryEquivalent}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const { jewelryId, mode, inputA, inputB, descA, descB } = await buildInputs();

  log("");
  log(LINE);
  log("DIFF — commercialDocumentRoundingApplied.breakdown.metals[]  (A vs B)");
  log(LINE);
  log(`jewelryId: ${jewelryId}`);
  log(`mode:      ${mode}`);
  log(`Preview A: ${descA}`);
  log(`Preview B: ${descB}`);
  log("");

  // ── Ejecutar los dos previews ─────────────────────────────────────────────
  const resA: any = await previewSale(jewelryId, inputA);
  const resB: any = await previewSale(jewelryId, inputB);

  const snapA = resA?.documentTotals?.commercialDocumentRoundingApplied ?? null;
  const snapB = resB?.documentTotals?.commercialDocumentRoundingApplied ?? null;

  log(`scope A: ${snapA?.scope ?? "(no snapshot)"}`);
  log(`scope B: ${snapB?.scope ?? "(no snapshot)"}`);
  log("");

  // ── Opción δ — Validación per línea del invariante ──────────────────────
  // Metal Visible + Hechura = Total línea c/ imp.
  // Σ metalRoundingMonetaryImpact = metalMonetaryEquivalent agregado del snapshot.
  for (const [label, res, snap] of [["A", resA, snapA], ["B", resB, snapB]] as const) {
    log(LINE);
    log(`OPCIÓN δ — Preview ${label}: Metal Visible / Hechura / Conservación`);
    log(LINE);
    const lines = (res as any)?.lines ?? [];
    let sumImpacts = 0;
    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i] as any;
      const totalLine    = Number(ln.lineTotalWithTax ?? 0);
      const metalSaleSum = (() => {
        const comp = ln.composition?.metals ?? [];
        if (!Array.isArray(comp) || comp.length === 0) return 0;
        let s = 0;
        for (const m of comp) {
          const ls = Number(m?.lineSale ?? 0);
          if (Number.isFinite(ls)) s += ls;
        }
        return s * (ln.quantity || 1);
      })();
      const impact       = Number(ln.metalRoundingMonetaryImpact ?? 0);
      const metalVisible = Math.round((metalSaleSum + impact) * 100) / 100;
      const hechura      = Math.round((totalLine - metalVisible) * 100) / 100;
      const sum          = Math.round((metalVisible + hechura) * 100) / 100;
      const cierra       = Math.abs(sum - totalLine) < 0.005 ? "✓" : "✗";
      sumImpacts += impact;
      log(`  Línea ${i}: qty=${ln.quantity}`);
      log(`    metalSale × qty            = ${metalSaleSum}`);
      log(`    metalRoundingMonetaryImpact = ${impact}`);
      log(`    Metal Visible              = ${metalVisible}`);
      log(`    Hechura                    = ${hechura}`);
      log(`    Total línea c/ imp.        = ${totalLine}`);
      log(`    Metal + Hechura            = ${sum}    ${cierra}`);
    }
    // Conservación: Σ impacts = metalMonetaryEquivalent agregado
    const aggImpact = Number(snap?.breakdown?.metalMonetaryEquivalent ?? 0);
    const sumImpactsR = Math.round(sumImpacts * 100) / 100;
    const ok = Math.abs(sumImpactsR - aggImpact) < 0.005 ? "✓" : "✗";
    log("");
    log(`  Σ metalRoundingMonetaryImpact (líneas) = ${sumImpactsR}`);
    log(`  metalMonetaryEquivalent (snapshot doc) = ${aggImpact}`);
    log(`  Conservación                            ${ok}`);
    log("");
  }

  if (!snapA || !snapB) {
    log("⚠️  Algún preview no emitió `commercialDocumentRoundingApplied`.");
    log("   Eso indica que la lista de precios NO está en commercialRoundingScope=PER_DOCUMENT,");
    log("   o que el helper devolvió null (sin redondeo neto). Diagnosticar el setup primero.");
    await prisma.$disconnect();
    process.exit(1);
  }

  if (snapA.scope !== "BREAKDOWN" || snapB.scope !== "BREAKDOWN") {
    log("⚠️  Snapshot NO en BREAKDOWN — esta auditoría aplica solo a BREAKDOWN.");
    log(`   A.scope=${snapA.scope}  B.scope=${snapB.scope}`);
    await prisma.$disconnect();
    process.exit(1);
  }

  const metalsA: MetalEntry[] = Array.isArray(snapA?.breakdown?.metals) ? snapA.breakdown.metals : [];
  const metalsB: MetalEntry[] = Array.isArray(snapB?.breakdown?.metals) ? snapB.breakdown.metals : [];

  printMetalsBlock("PREVIEW A — breakdown.metals[]", metalsA);
  log("");
  printMetalsBlock("PREVIEW B — breakdown.metals[]", metalsB);
  log("");

  // ── Tabla de diff por metal padre ─────────────────────────────────────────
  log(LINE);
  log("DIFF por metal padre");
  log(LINE);
  const idxA = indexByName(metalsA);
  const idxB = indexByName(metalsB);
  const allNames = new Set<string>([...idxA.keys(), ...idxB.keys()]);

  type DiffRow = {
    name:        string;
    preA?:       number | null;
    preB?:       number | null;
    preDelta:    number | null;
    postA?:      number | null;
    postB?:      number | null;
    postDelta:   number | null;
    preChanged:  boolean;
    postChanged: boolean;
  };

  const rows: DiffRow[] = [];
  for (const name of allNames) {
    const a = idxA.get(name);
    const b = idxB.get(name);
    const preA  = a?.preGrams  ?? null;
    const preB  = b?.preGrams  ?? null;
    const postA = a?.postGrams ?? null;
    const postB = b?.postGrams ?? null;
    const preDelta  = (preA  != null && preB  != null) ? Number((preB  - preA ).toFixed(6)) : null;
    const postDelta = (postA != null && postB != null) ? Number((postB - postA).toFixed(6)) : null;
    rows.push({
      name,
      preA, preB, preDelta,
      postA, postB, postDelta,
      preChanged:  preDelta  != null && Math.abs(preDelta)  > 1e-9,
      postChanged: postDelta != null && Math.abs(postDelta) > 1e-9,
    });
  }

  log("");
  log("  Metal padre          | preGrams A   | preGrams B   | ΔpreGrams  | postA  | postB  | ΔpostGrams");
  log("  ---------------------|--------------|--------------|------------|--------|--------|-----------");
  for (const r of rows) {
    const f = (v: number | null | undefined, w: number): string =>
      v == null ? "—".padEnd(w) : String(v).padEnd(w);
    log(
      "  " + r.name.padEnd(20) + " | " +
      f(r.preA, 12)  + " | " + f(r.preB, 12)  + " | " + f(r.preDelta, 10) + " | " +
      f(r.postA, 6) + " | " + f(r.postB, 6) + " | " + f(r.postDelta, 10),
    );
  }
  log("");

  // ── Veredicto ─────────────────────────────────────────────────────────────
  log(LINE);
  log("VEREDICTO");
  log(LINE);

  const anyPreChanged  = rows.some(r => r.preChanged);
  const anyPostChanged = rows.some(r => r.postChanged);

  if (!anyPreChanged) {
    log("");
    log("  🛑 BUG BACKEND CONFIRMADO");
    log("");
    log("     `preGrams` es IDÉNTICO entre Preview A y Preview B.");
    log("     El agregado del Redondeo Comercial NO refleja la edición de cantidad/gramos.");
    log("");
    log("     Esto significa que `aggregateMetalsForCommercialDocRounding`");
    log("     (en `sales.service.ts:5180-5197`) está construyendo `metalValuationSum` y");
    log("     `metalsByParent` a partir de datos que NO incorporan el override.");
    log("");
    log("     Punto de inspección probable: `extractMetalItemsFromSteps(steps)`");
    log("     (`balance-mode-runtime.ts`) — los `step.meta.gramsOriginal` que devuelve");
    log("     pueden venir del shape crudo del artículo antes de aplicar");
    log("     `costLineOverrides[].quantityOverride`.");
    log("");
    log("     Fix mínimo: asegurar que los `steps` que se pasan al agregado provengan");
    log("     del pipeline POST-overrides (calculateCostFromLines aplicado).");
  } else if (!anyPostChanged) {
    log("");
    log("  ⚠️  BACKEND CASI OK — `preGrams` cambia pero `postGrams` quedó igual");
    log("");
    log("     Esto NO es bug: la edición es chica y no cruzó el umbral del step de redondeo.");
    log("     Probar con un cambio más grande para confirmar.");
    log("");
    log("     Si con cambio grande `postGrams` SÍ se mueve, el backend es correcto.");
    log("     El operador ve el mismo postGrams entre dos previews porque ambos cantos");
    log("     redondean al mismo step (comportamiento esperado del redondeo físico).");
  } else {
    log("");
    log("  ✅ BACKEND OK — `preGrams` Y `postGrams` cambian entre A y B");
    log("");
    log("     El motor sí está re-calculando el Redondeo Comercial con cada edición.");
    log("     El bug vive en frontend — el response actualizado llega pero el draft");
    log("     conserva el snapshot anterior por algún motivo.");
    log("");
    log("     Próximo paso: auditar la propagación FE con devtools de red:");
    log("       1. Inspeccionar response del preview → confirmar que el snapshot llegó.");
    log("       2. Inspeccionar `draft.lines[i].pricingMeta.commercialRoundingContext`");
    log("          tras el preview → confirmar si se pisó o no.");
    log("       3. Si no se pisó → bug en `applySalePreviewToDraft` o en algún wrapper.");
    log("       4. Si se pisó pero la UI no actualiza → memoización en algún componente");
    log("          padre (no en `CommercialRoundingFooter`, que es passthrough puro).");
  }
  log("");

  await prisma.$disconnect();
  process.exit(0);
}

main().catch(async (err) => {
  // eslint-disable-next-line no-console
  console.error("\n❌ Error:", err);
  try { await prisma.$disconnect(); } catch {}
  process.exit(1);
});
