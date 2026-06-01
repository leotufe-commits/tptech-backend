/**
 * prisma/scripts/verify-commercial-metal-matching.ts
 *
 * Diagnóstico de matching de nombres entre:
 *   · `balanceBreakdown.metals[].metalParentName`              (FE consume con `name`)
 *   · `commercialDocumentRoundingApplied.breakdown.metals[].metalParentName`
 *
 * Simula la prioridad #0 de `resolveCardMetals` (helper FE
 * `aggregateCommercialDocPostGramsByName`) y reporta:
 *   · valores exactos por línea
 *   · keys del Map agregado
 *   · MATCH / MISMATCH por nombre
 *
 * Solo lectura. NO crea ni modifica datos.
 *
 * Uso (mismos args que trace-commercial-document-rounding.ts):
 *   npx tsx prisma/scripts/verify-commercial-metal-matching.ts \
 *     --client=<id> --price-list=<id> --article=<id> --qty=1
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
  saleId:      flag("sale")        ?? process.env.SALE_ID        ?? null,
  clientId:    flag("client")      ?? process.env.CLIENT_ID      ?? null,
  priceListId: flag("price-list")  ?? process.env.PRICE_LIST_ID  ?? null,
  articleId:   flag("article")     ?? process.env.ARTICLE_ID     ?? null,
  variantId:   flag("variant")     ?? process.env.VARIANT_ID     ?? null,
  quantity:    Number(flag("qty") ?? process.env.QUANTITY ?? "1"),
};

function bailUsage(msg: string): never {
  // eslint-disable-next-line no-console
  console.error(`\n❌ ${msg}\n
Uso:
  npx tsx prisma/scripts/verify-commercial-metal-matching.ts \\
    --client=<id> --price-list=<id> --article=<id> --qty=1
  (alt: --sale=<id> reproduce el input desde un DRAFT existente)
`);
  process.exit(1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Resolución de input (reusa la misma lógica de trace-commercial-document-rounding)
// ─────────────────────────────────────────────────────────────────────────────

async function resolveInput(): Promise<{ jewelryId: string; input: SalePreviewInput }> {
  if (ARGS.saleId) {
    const sale = await prisma.sale.findFirst({
      where: { id: ARGS.saleId },
      select: {
        jewelryId: true, clientId: true,
        lines: { select: { articleId: true, variantId: true, quantity: true, priceListIdOverride: true } },
      },
    });
    if (!sale) bailUsage(`Sale ${ARGS.saleId} no encontrada.`);
    if (!sale.lines.length) bailUsage(`Sale ${ARGS.saleId} sin líneas.`);
    return {
      jewelryId: sale.jewelryId,
      input: {
        lines: sale.lines.map((l) => ({
          articleId:           l.articleId!,
          variantId:           l.variantId,
          quantity:            Number(l.quantity),
          priceListIdOverride: l.priceListIdOverride ?? ARGS.priceListId ?? null,
        })),
        clientId:    sale.clientId,
        priceListId: ARGS.priceListId,
      },
    };
  }

  if (!ARGS.articleId)   bailUsage("Falta --article=<id>.");
  if (!ARGS.priceListId) bailUsage("Falta --price-list=<id>.");

  const article = await prisma.article.findFirst({
    where: { id: ARGS.articleId },
    select: { id: true, jewelryId: true },
  });
  if (!article) bailUsage(`Article ${ARGS.articleId} no encontrado.`);

  return {
    jewelryId: article.jewelryId,
    input: {
      lines: [{
        articleId:           ARGS.articleId,
        variantId:           ARGS.variantId,
        quantity:            ARGS.quantity,
        priceListIdOverride: ARGS.priceListId,
      }],
      clientId:    ARGS.clientId,
      priceListId: ARGS.priceListId,
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers de presentación
// ─────────────────────────────────────────────────────────────────────────────

const LINE = "━".repeat(72);
const log  = (...x: unknown[]) => console.log(...x);  // eslint-disable-line no-console

// Espejo EXACTO del helper FE `aggregateCommercialDocPostGramsByName`
// (`tptech-frontend/src/components/sales/TotalDelComprobanteCard/helpers.ts`).
// Lo reproduzco acá para verificar qué Map produciría sobre el snapshot real.
function aggregateCommercialDocPostGramsByName(snapshot: any): Map<string, number> {
  const out = new Map<string, number>();
  if (!snapshot || snapshot.scope !== "BREAKDOWN") return out;
  const metals = snapshot?.breakdown?.metals;
  if (!Array.isArray(metals)) return out;
  for (const m of metals) {
    if (!m) continue;
    const name = typeof m.metalParentName === "string" && m.metalParentName.length > 0
      ? m.metalParentName
      : null;
    const post = typeof m.postGrams === "number" && Number.isFinite(m.postGrams) ? m.postGrams : null;
    if (name == null || post == null) continue;
    out.set(name, (out.get(name) ?? 0) + post);
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const { jewelryId, input } = await resolveInput();
  const result: any = await previewSale(jewelryId, input);

  const balance = result.balanceBreakdown;
  const snapshot = result.documentTotals?.commercialDocumentRoundingApplied ?? null;

  log("");
  log(LINE);
  log("VERIFY — Matching de metalParentName entre BALANCE y SNAPSHOT D'");
  log(LINE);
  log(`jewelryId:       ${jewelryId}`);
  log(`lines:           ${result.lines.length}`);
  log(`balanceMode:     ${result.balanceMode}`);
  log(`scope snapshot:  ${snapshot?.scope ?? "(no snapshot)"}`);
  log(`appliedAt:       ${snapshot?.appliedAt ?? "—"}`);
  log(`appliedToLineCount (replicado por línea): ${
    result.lines[0]?.commercialRoundingContext?.appliedToLineCount ?? "—"
  }`);
  log("");

  // ── BLOQUE 1 — balanceBreakdown.metals[] ────────────────────────────────
  log(LINE);
  log("1) balanceBreakdown.metals[]   (lo que `metalsFromBreakdown` consume — FE arma `name` desde esto)");
  log(LINE);
  const balMetals = Array.isArray(balance?.metals) ? balance.metals : [];
  if (balMetals.length === 0) {
    log("  (vacío)");
  } else {
    for (const m of balMetals) {
      log(`  metalParentId:    ${m.metalParentId}`);
      log(`  metalParentName:  "${m.metalParentName}"`);
      log(`  gramsPure:        ${m.gramsPure}`);
      log(`  valuationMonetary:${m.valuationMonetary ?? "—"}`);
      log("");
    }
  }

  // ── BLOQUE 2 — snapshot D' breakdown.metals[] ───────────────────────────
  log(LINE);
  log("2) commercialDocumentRoundingApplied.breakdown.metals[]   (Etapa D' — debería ser fuente única)");
  log(LINE);
  const snapMetals = Array.isArray(snapshot?.breakdown?.metals) ? snapshot.breakdown.metals : [];
  if (snapMetals.length === 0) {
    log("  (vacío)");
    if (snapshot?.fallback) log(`  fallback: ${snapshot.fallback}`);
  } else {
    for (const m of snapMetals) {
      log(`  metalParentId:    ${m.metalParentId}`);
      log(`  metalParentName:  "${m.metalParentName}"`);
      log(`  preGrams:         ${m.preGrams}`);
      log(`  postGrams:        ${m.postGrams}`);
      log(`  deltaGrams:       ${m.deltaGrams}`);
      log(`  monetaryEquivalent:${m.monetaryEquivalent}`);
      log("");
    }
  }

  // ── BLOQUE 3 — Snapshot completo de hechura ─────────────────────────────
  log(LINE);
  log("3) commercialDocumentRoundingApplied.breakdown.hechura");
  log(LINE);
  const hech = snapshot?.breakdown?.hechura ?? null;
  if (!hech) {
    log("  (sin hechura)");
  } else {
    log(`  preRoundingSaldoMonetario:  ${hech.preRoundingSaldoMonetario}`);
    log(`  postRoundingSaldoMonetario: ${hech.postRoundingSaldoMonetario}`);
    log(`  deltaSaldoMonetario:        ${hech.deltaSaldoMonetario}`);
    log("");
  }

  // ── BLOQUE 4 — Resultado de `aggregateCommercialDocPostGramsByName` ────
  log(LINE);
  log("4) aggregateCommercialDocPostGramsByName(snapshot)   (espejo del helper FE)");
  log(LINE);
  const aggMap = aggregateCommercialDocPostGramsByName(snapshot);
  if (aggMap.size === 0) {
    log("  Map<string, number> vacío");
    log("  → resolveCardMetals NO va a usar la prioridad #0.");
  } else {
    log(`  Map<string, number> con ${aggMap.size} entries:`);
    for (const [name, grams] of aggMap) {
      log(`    "${name}" → ${grams}`);
    }
  }
  log("");

  // ── BLOQUE 5 — Matching balance vs snapshot ─────────────────────────────
  log(LINE);
  log("5) Matching balance.name ↔ aggregateMap.key   (¿matchea para override de grams?)");
  log(LINE);
  const balNames = new Set<string>(balMetals.map((m: any) => String(m.metalParentName ?? "")));
  const snapNames = new Set<string>(Array.from(aggMap.keys()));
  log(`  balance names:  ${JSON.stringify(Array.from(balNames))}`);
  log(`  snapshot names: ${JSON.stringify(Array.from(snapNames))}`);
  log("");
  const matched   = Array.from(balNames).filter((n) => snapNames.has(n));
  const balOnly   = Array.from(balNames).filter((n) => !snapNames.has(n));
  const snapOnly  = Array.from(snapNames).filter((n) => !balNames.has(n));
  log(`  ✓ MATCH (en ambos):      ${JSON.stringify(matched)}`);
  log(`  ⚠ Solo en balance:       ${JSON.stringify(balOnly)}`);
  log(`  ⚠ Solo en snapshot:      ${JSON.stringify(snapOnly)}`);
  log("");

  // ── BLOQUE 6 — Simulación del resolvedMetals que el FE produciría ──────
  log(LINE);
  log("6) Simulación: ¿qué retornaría `resolveCardMetals` con prioridad #0?");
  log(LINE);
  if (aggMap.size === 0) {
    log("  Prioridad #0 NO aplica (Map vacío). Cae a prioridades 1-4 (legacy):");
    log("  → MetalsSummary mostraría `gramsPure` del balance:");
    for (const m of balMetals) {
      log(`     "${m.metalParentName}" → ${m.gramsPure} gr   ← valor LEGACY (NO post-redondeo)`);
    }
  } else {
    log("  Prioridad #0 SÍ aplica. Recorriendo balance.metals[] y matching por name:");
    for (const m of balMetals) {
      const override = aggMap.get(String(m.metalParentName ?? ""));
      if (override != null) {
        log(`     "${m.metalParentName}" → ${override} gr   ← OVERRIDE del snapshot (post-redondeo)  ✓`);
      } else {
        log(`     "${m.metalParentName}" → ${m.gramsPure} gr   ← legacy (no matcheó en snapshot)  ✗`);
      }
    }
    // Items que están en el snapshot pero no en el balance → se agregan al output.
    if (snapOnly.length > 0) {
      log("");
      log("  + Items del snapshot que NO están en balance (se agregarían como nuevos):");
      for (const name of snapOnly) {
        log(`     "${name}" → ${aggMap.get(name)} gr   ← NEW desde snapshot`);
      }
    }
  }
  log("");

  // ── BLOQUE 7 — Snapshot crudo (JSON) ───────────────────────────────────
  log(LINE);
  log("7) JSON crudo (referencia)");
  log(LINE);
  log("  commercialDocumentRoundingApplied:");
  log(JSON.stringify(snapshot, null, 2));
  log("");
  log("  balanceBreakdown.metals[]:");
  log(JSON.stringify(balance?.metals ?? [], null, 2));
  log("");

  log(LINE);
  log("FIN");
  log(LINE);

  await prisma.$disconnect();
  process.exit(0);
}

main().catch(async (err) => {
  // eslint-disable-next-line no-console
  console.error("\n❌ Error:", err);
  try { await prisma.$disconnect(); } catch {}
  process.exit(1);
});
