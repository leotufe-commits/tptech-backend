/**
 * prisma/scripts/trace-commercial-document-rounding.ts
 *
 * Validación end-to-end del pipeline PER_DOCUMENT (Etapa D') contra la DB
 * REAL — sin frontend, sin servidor HTTP, sin escrituras.
 *
 * Activa los modos temporales:
 *   · PRICING_COMMERCIAL_DOC_ROUNDING_ENABLED=1 (capa nueva activa)
 *   · PRICING_TRACE=console (traza por capa en stdout)
 *
 * Ejecuta `previewSale` DOS VECES con el mismo input (simula preview vs.
 * confirm — confirm modifica la DB, así que usamos preview×2 como proxy
 * de paridad byte-equivalente). Valida:
 *   1. preview = confirm (snapshots idénticos)
 *   2. no doble redondeo (línea sin redondeo absorbido + capa nueva activa)
 *   3. commercial delta aplicado UNA sola vez
 *
 * Solo lectura. NO crea ventas, NO modifica DB, NO guarda borradores.
 *
 * Uso:
 *   npx tsx prisma/scripts/trace-commercial-document-rounding.ts \
 *     --client=<id> \
 *     --price-list=<id> \
 *     --article=<id> \
 *     --qty=1
 *
 *   Opcionales: --variant=<id> --shipping=<n> --no-trace
 *   Alternativa env: CLIENT_ID=… PRICE_LIST_ID=… ARTICLE_ID=… QUANTITY=…
 *                    [VARIANT_ID=… SHIPPING=… SALE_ID=…]
 *
 * El SALE_ID es opcional: cuando se pasa, el script lee el `clientId` y la
 * `priceListId` del DRAFT persistido para reproducir el mismo input (útil
 * para diagnosticar un sale específico).
 */

import "dotenv/config";

// Etapa D' cerrada — el modo PER_DOCUMENT ahora se lee del campo persistido
// `PriceList.commercialRoundingScope`. El env var
// `PRICING_COMMERCIAL_DOC_ROUNDING_ENABLED` quedó retirado; este script ya
// NO lo setea. Para activar PER_DOCUMENT en una lista, usar:
//   npx tsx prisma/scripts/set-commercial-rounding-scope.ts \
//     --id=<priceListId> --set=PER_DOCUMENT
if (process.env.PRICING_TRACE == null) {
  process.env.PRICING_TRACE = "console";
}

import { prisma } from "../../src/lib/prisma.js";
import { previewSale, type SalePreviewInput } from "../../src/modules/sales/sales.service.js";

// ─────────────────────────────────────────────────────────────────────────────
// Args
// ─────────────────────────────────────────────────────────────────────────────

interface Args {
  saleId:      string | null;
  clientId:    string | null;
  priceListId: string | null;
  articleId:   string | null;
  variantId:   string | null;
  quantity:    number;
  shipping:    number;
  noTrace:     boolean;
}

function parseArgs(): Args {
  const argv = process.argv.slice(2);
  const flag = (name: string): string | null => {
    for (const a of argv) {
      const prefix = `--${name}=`;
      if (a.startsWith(prefix)) return a.slice(prefix.length);
    }
    return null;
  };
  const hasFlag = (name: string): boolean => argv.includes(`--${name}`);

  const args: Args = {
    saleId:      flag("sale")        ?? process.env.SALE_ID        ?? null,
    clientId:    flag("client")      ?? process.env.CLIENT_ID      ?? null,
    priceListId: flag("price-list")  ?? process.env.PRICE_LIST_ID  ?? null,
    articleId:   flag("article")     ?? process.env.ARTICLE_ID     ?? null,
    variantId:   flag("variant")     ?? process.env.VARIANT_ID     ?? null,
    quantity:    Number(flag("qty") ?? process.env.QUANTITY ?? "1"),
    shipping:    Number(flag("shipping") ?? process.env.SHIPPING ?? "0"),
    noTrace:     hasFlag("no-trace"),
  };
  if (args.noTrace) process.env.PRICING_TRACE = "off";
  return args;
}

function exitWithUsage(reason: string): never {
  // eslint-disable-next-line no-console
  console.error(`\n❌ ${reason}\n`);
  // eslint-disable-next-line no-console
  console.error(`Uso:
  npx tsx prisma/scripts/trace-commercial-document-rounding.ts \\
    --client=<id> \\
    --price-list=<id> \\
    --article=<id> \\
    --qty=1
  [opciones: --variant=<id>  --shipping=<n>  --no-trace  --sale=<id>]
`);
  process.exit(1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Resolución de input
// ─────────────────────────────────────────────────────────────────────────────

async function resolveInput(args: Args): Promise<{
  jewelryId: string;
  input:     SalePreviewInput;
}> {
  // Si pasaron SALE_ID: cargar el sale y reusar sus campos. Solo lectura.
  if (args.saleId) {
    const sale = await prisma.sale.findFirst({
      where: { id: args.saleId },
      select: {
        jewelryId: true, clientId: true,
        lines: {
          select: {
            articleId: true, variantId: true, quantity: true,
            priceListIdOverride: true,
          },
        },
      },
    });
    if (!sale) exitWithUsage(`Sale ${args.saleId} no encontrada.`);
    if (!sale.lines.length) exitWithUsage(`Sale ${args.saleId} sin líneas.`);
    const inputLines = sale.lines.map((l) => ({
      articleId:           l.articleId!,
      variantId:           l.variantId,
      quantity:            Number(l.quantity),
      priceListIdOverride: l.priceListIdOverride ?? args.priceListId ?? null,
    }));
    return {
      jewelryId: sale.jewelryId,
      input: {
        lines:     inputLines,
        clientId:  sale.clientId,
        priceListId: args.priceListId,
      },
    };
  }

  // Si no pasaron SALE_ID, validar args mínimos.
  if (!args.articleId)   exitWithUsage("Falta --article=<id> o ARTICLE_ID env.");
  if (!args.priceListId) exitWithUsage("Falta --price-list=<id> o PRICE_LIST_ID env.");

  const article = await prisma.article.findFirst({
    where: { id: args.articleId },
    select: { id: true, jewelryId: true },
  });
  if (!article) exitWithUsage(`Article ${args.articleId} no encontrado.`);

  return {
    jewelryId: article.jewelryId,
    input: {
      lines: [{
        articleId:           args.articleId,
        variantId:           args.variantId,
        quantity:            args.quantity,
        // Override por línea: garantiza que el helper de wiring detecte una
        // "lista compartida" (PER_DOCUMENT). Sin este override la wiring
        // mínima cae a MIXED_LIST_FALLBACK.
        priceListIdOverride: args.priceListId,
      }],
      clientId:    args.clientId,
      priceListId: args.priceListId,   // refuerzo doc-level
      shippingAmount: args.shipping > 0 ? args.shipping : undefined,
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Formato de output
// ─────────────────────────────────────────────────────────────────────────────

const LINE  = "━".repeat(60);
const BLANK = "";
const log = (...x: unknown[]) => console.log(...x);  // eslint-disable-line no-console

function fmt(n: number | null | undefined, decimals = 2): string {
  if (n == null || !Number.isFinite(n)) return "—";
  return n.toFixed(decimals);
}

function printTrace(jewelryId: string, result: any): void {
  // BUG FIX — `previewSale` devuelve `SalePreviewResult` con `documentTotals`
  // (no `totals`). `commercialDocumentRoundingApplied` y `documentRoundingApplied`
  // viven DENTRO de `documentTotals`. El alias `documentRoundingSnapshot`
  // top-level apunta al mismo objeto que `documentTotals.documentRoundingApplied`.
  const totals = result.documentTotals ?? {};
  const com    = totals.commercialDocumentRoundingApplied ?? null;
  const fin    = totals.documentRoundingApplied ?? result.documentRoundingSnapshot ?? null;
  const bal    = result.balanceBreakdown ?? {};
  const mono   = bal.monetaryBalance ?? {};

  // Heurística para reportar el contexto comercial (el script no lo expone
  // top-level, pero podemos derivarlo del snapshot).
  const commercialActive = com != null;
  const scope            = com?.scope ?? null;
  const fallback         = com?.fallback ?? null;

  log(BLANK);
  log(LINE);
  log("DOCUMENT COMMERCIAL ROUNDING TRACE");
  log(LINE);
  log(`jewelryId:            ${jewelryId}`);
  log(`previewSale:          ejecutado dos veces (paridad preview = confirm)`);
  log(BLANK);

  log("── Contexto comercial ─────────────────────────────────────────");
  log(`Lista activa:         ${result._documentActivePriceList ?? "(no expuesto)"}`);
  log(`Modo comercial:       ${commercialActive ? "PER_DOCUMENT (capa activa)" : "PER_LINE_LEGACY o sin lista compartida"}`);
  log(`Scope:                ${scope ?? "—"}`);
  log(`Fallback:             ${fallback ?? "—"}`);
  log(`Flags PER_LINE:       suprimidos = ${commercialActive ? "true (gate anti-doble)" : "false (comportamiento legacy)"}`);
  log(`Flags PER_DOCUMENT:   capa actuó = ${commercialActive}`);
  log(BLANK);

  log("── L05B_COMMERCIAL_DOC_ROUNDING ───────────────────────────────");
  if (!com) {
    log("  (capa no activada o sin movimiento — verificar L00 en el trace de consola)");
  } else {
    log(`  scope:              ${com.scope}`);
    log(`  totalAdjustment:    ${fmt(com.totalAdjustment)}`);
    if (com.unified) {
      log(`  unified.pre:        ${fmt(com.unified.pre)}`);
      log(`  unified.post:       ${fmt(com.unified.post)}`);
      log(`  unified.adjustment: ${fmt(com.unified.adjustment)}`);
      log(`  unified.mode:       ${com.unified.mode} ${com.unified.direction}`);
    }
    if (com.breakdown) {
      const h = com.breakdown.hechura;
      log(`  hechura.preRoundingSaldoMonetario:  ${fmt(h?.preRoundingSaldoMonetario)}`);
      log(`  hechura.postRoundingSaldoMonetario: ${fmt(h?.postRoundingSaldoMonetario)}`);
      log(`  hechura.deltaSaldoMonetario:        ${fmt(h?.deltaSaldoMonetario)}`);
      log(`  hechura.mode/direction:             ${h?.mode} ${h?.direction}`);
      log(`  hechura.source:                     ${h?.source}`);
      log(BLANK);
      log("  Metal (PER_DOCUMENT):");
      if ((com.breakdown.metals?.length ?? 0) === 0) {
        log("    (sin redondeo de metal en esta config)");
      } else {
        for (const m of com.breakdown.metals) {
          log(`    ${m.metalParentName}: preGrams=${fmt(m.preGrams, 4)} postGrams=${fmt(m.postGrams, 4)} deltaGrams=${fmt(m.deltaGrams, 4)} → $${fmt(m.monetaryEquivalent)}`);
        }
      }
      log(`  metalMonetaryEquivalent:  ${fmt(com.breakdown.metalMonetaryEquivalent)}`);
      log(`  combinedAdjustment:       ${fmt(com.breakdown.combinedAdjustment)}`);
    }
  }
  log(BLANK);

  log("── Pipeline (post-capa nueva) ─────────────────────────────────");
  log(`Commercial Delta:     ${fmt(com?.totalAdjustment ?? 0)}`);
  log(`Shipping:             ${fmt(totals.shippingAmount)}`);
  log(`Payment:              ${fmt(totals.paymentAdjustmentAmount)}`);
  log(`Financial Rounding:   ${fin ? `${fin.scope} delta=${fmt(fin.totalAdjustment)}` : "(no activo)"}`);
  log(`Engine Total:         ${fmt(totals.total)}`);
  log(BLANK);

  log("── Balance Breakdown ──────────────────────────────────────────");
  log(`Modo:                       ${bal.metals?.length ? "BREAKDOWN" : "UNIFIED"}`);
  log(`Σ valorización metal:       ${fmt((bal.metals ?? []).reduce((s: number, m: any) => s + (m.valuationMonetary ?? 0), 0))}`);
  log(`Monetary Balance amount:    ${fmt(mono.amount)}`);
  log(`Monetary Balance currency:  ${mono.currencyCode ?? "—"}`);
  log(LINE);
  log(BLANK);

  log("── Snapshot completo: commercialDocumentRoundingApplied ──");
  log(JSON.stringify(com, null, 2));
  log(BLANK);

  log("── Snapshot completo: monetaryBalance ──");
  log(JSON.stringify(mono, null, 2));
  log(BLANK);
}

// ─────────────────────────────────────────────────────────────────────────────
// Validaciones automáticas
// ─────────────────────────────────────────────────────────────────────────────

interface Check {
  name: string;
  ok:   boolean;
  detail?: string;
}

function validate(previewA: any, previewB: any): Check[] {
  const checks: Check[] = [];

  // BUG FIX — leer desde `documentTotals` (no `totals`). Ver comentario en
  // `printTrace`.
  const totalsA = previewA.documentTotals ?? {};
  const totalsB = previewB.documentTotals ?? {};

  // 1) preview = confirm (proxy: dos previews idénticos).
  const a = JSON.stringify(totalsA.commercialDocumentRoundingApplied ?? null);
  const b = JSON.stringify(totalsB.commercialDocumentRoundingApplied ?? null);
  checks.push({
    name:   "preview = confirm (snapshots idénticos)",
    ok:     a === b,
    detail: a === b ? undefined : `A: ${a.slice(0, 80)}…  B: ${b.slice(0, 80)}…`,
  });
  checks.push({
    name:   "engineTotal preview×2 idéntico",
    ok:     totalsA.total === totalsB.total,
    detail: totalsA.total === totalsB.total ? undefined : `A=${totalsA.total} B=${totalsB.total}`,
  });

  const balA = JSON.stringify(previewA.balanceBreakdown?.monetaryBalance ?? null);
  const balB = JSON.stringify(previewB.balanceBreakdown?.monetaryBalance ?? null);
  checks.push({
    name:   "monetaryBalance idéntico entre las dos corridas",
    ok:     balA === balB,
  });

  // 2) No doble redondeo — si la capa nueva actuó, las líneas NO deben traer
  // `metalHechuraBreakdown.hechuraSalePreRounding` ni `physical` poblado.
  const com = totalsA.commercialDocumentRoundingApplied ?? null;
  if (com) {
    let perLineHechuraActed = false;
    let perLinePhysicalActed = false;
    for (const l of (previewA.lines ?? [])) {
      const mh = l.metalHechuraBreakdown ?? null;
      if (mh?.hechuraSalePreRounding != null) perLineHechuraActed = true;
      if (mh?.physical != null)                perLinePhysicalActed = true;
    }
    checks.push({
      name:   "no doble redondeo HECHURA (per-line suprimido)",
      ok:     !perLineHechuraActed,
      detail: perLineHechuraActed ? "Una línea reporta hechuraSalePreRounding != null → PER_LINE actuó pese a la capa doc" : undefined,
    });
    checks.push({
      name:   "no doble redondeo METAL físico (per-line suprimido)",
      ok:     !perLinePhysicalActed,
      detail: perLinePhysicalActed ? "Una línea reporta metalHechuraBreakdown.physical != null → path PHYSICAL actuó pese a la capa doc" : undefined,
    });
  } else {
    checks.push({
      name:   "capa comercial PER_DOCUMENT activa",
      ok:     false,
      detail: "documentTotals.commercialDocumentRoundingApplied === null. Verificar:\n" +
              "   · que la lista tenga mode=METAL_HECHURA + roundingTarget=METAL + roundingModeHechura activo\n" +
              "   · que todas las líneas compartan el mismo priceListId (--price-list aplica)\n" +
              "   · que PriceList.commercialRoundingScope = 'PER_DOCUMENT' (ver set-commercial-rounding-scope.ts)",
    });
  }

  // 3) commercial delta aplicado UNA sola vez:
  // engineTotal == totalComercialPostCommercialRounding + shipping + payment + (financialDelta).
  if (totalsA.totalComercialPostCommercialRounding != null) {
    const expected =
      totalsA.totalComercialPostCommercialRounding
      + (totalsA.shippingAmount ?? 0)
      + (totalsA.paymentAdjustmentAmount ?? 0)
      + (totalsA.documentRoundingApplied?.totalAdjustment ?? 0);
    const expectedRound = Math.round(expected * 100) / 100;
    const actual        = Math.round((totalsA.total ?? 0) * 100) / 100;
    checks.push({
      name:   "commercial delta aplicado una sola vez (consistencia algebraica)",
      ok:     Math.abs(actual - expectedRound) < 0.01,
      detail: Math.abs(actual - expectedRound) < 0.01
        ? undefined
        : `actual=${actual} expected=${expectedRound} (diff=${(actual - expectedRound).toFixed(4)})`,
    });
  }

  return checks;
}

function printChecks(checks: Check[]): boolean {
  log("── Validaciones automáticas ───────────────────────────────────");
  let allOk = true;
  for (const c of checks) {
    const icon = c.ok ? "✓" : "✗";
    log(`  ${icon} ${c.name}`);
    if (c.detail) log(`      ${c.detail}`);
    if (!c.ok) allOk = false;
  }
  log(LINE);
  log(allOk ? "✅ Todas las validaciones OK." : "❌ Falló al menos una validación.");
  return allOk;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = parseArgs();
  const { jewelryId, input } = await resolveInput(args);

  // Pasada A — emite el trace de consola (PRICING_TRACE=console).
  const previewA = await previewSale(jewelryId, input) as any;
  // Pasada B — para comparar paridad. Silenciamos el trace de la 2da
  // corrida para no duplicar output.
  const prevMode = process.env.PRICING_TRACE;
  process.env.PRICING_TRACE = "off";
  // Importante: hace falta limpiar el cache del modo del trace si quisiéramos
  // que esto surta efecto runtime, pero como el helper cachea en el primer
  // call, la 2da corrida ya no emite. Restauramos al terminar.
  const previewB = await previewSale(jewelryId, input) as any;
  process.env.PRICING_TRACE = prevMode;

  printTrace(jewelryId, previewA);

  const checks = validate(previewA, previewB);
  const allOk  = printChecks(checks);

  await prisma.$disconnect();
  process.exit(allOk ? 0 : 1);
}

main().catch(async (err) => {
  // eslint-disable-next-line no-console
  console.error("\n❌ Error fatal:", err);
  try { await prisma.$disconnect(); } catch {}
  process.exit(1);
});
