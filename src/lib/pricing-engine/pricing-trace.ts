// src/lib/pricing-engine/pricing-trace.ts
// =============================================================================
// Pricing Trace — diagnostic dev-only.
//
// Captura la traza por línea y por documento de las 15 capas canónicas del
// pipeline de pricing tal como están hoy. Apagado por default. No altera
// comportamiento productivo.
//
// Activación:
//   PRICING_TRACE=off       → desactivado (default — sin overhead).
//   PRICING_TRACE=console   → solo log a stdout.
//   PRICING_TRACE=response  → adjunta `_diagnostics` al response de previewSale.
//   PRICING_TRACE=both      → console + response.
//
// Capas (orden canónico — el mismo que pidió el contrato nuevo):
//   L01_PRICE_LIST_BASE                    — precio base / precio lista
//   L02_LINE_DISCOUNT                      — descuento de línea
//   L03_LINE_TAX                           — impuestos de línea
//   L04_LINE_TOTAL_BEFORE_COMM_ROUND       — total línea antes de redondeo comercial
//   L05_COMMERCIAL_ROUNDING                — redondeo comercial: pre/post/delta/scope/mode/direction/source
//   L06_CHANNEL                            — canal de venta
//   L07_COUPON                             — cupón
//   L08_GLOBAL_DISCOUNT                    — bonificación global
//   L09_SHIPPING                           — envío
//   L10_PAYMENT                            — forma de pago
//   L11_TOTAL_BEFORE_FIN_ROUND             — total antes de redondeo financiero
//   L12_FINANCIAL_ROUNDING                 — redondeo financiero: pre/post/delta/scope/mode/direction
//   L13_ENGINE_TOTAL                       — total del motor (pre ajuste manual)
//   L14_MANUAL_ADJUSTMENT                  — ajuste manual (UNIFIED/BREAKDOWN)
//   L15_FINAL_TOTAL                        — total final (= engineTotal + manualAdjustment)
//
// Modelo de uso:
//   await runWithTrace("previewSale", async () => { ... });
//   traceLine("L01_PRICE_LIST_BASE", lineKey, { ... });
//   traceDocument("L06_CHANNEL", { ... });
//
// Cuando `runWithTrace` corre con flag=off, todos los `traceLine`/`traceDocument`
// son no-op (el AsyncLocalStorage no tiene ctx). Costo en producción: una
// lectura de variable de entorno cacheada + un acceso a ALS por capa.
// =============================================================================

import { AsyncLocalStorage } from "node:async_hooks";

export type PricingTraceMode = "off" | "console" | "response" | "both";

let _cachedMode: PricingTraceMode | null = null;

export function resolvePricingTraceMode(): PricingTraceMode {
  if (_cachedMode != null) return _cachedMode;
  const raw = String(process.env.PRICING_TRACE ?? "").trim().toLowerCase();
  if (raw === "1" || raw === "console")       _cachedMode = "console";
  else if (raw === "response")                _cachedMode = "response";
  else if (raw === "both")                    _cachedMode = "both";
  else                                        _cachedMode = "off";
  return _cachedMode;
}

/** Test-only: limpia el cache para que el siguiente llamado relea la env var. */
export function __resetPricingTraceModeCache(): void {
  _cachedMode = null;
}

export interface PricingTraceLineEvent {
  layer:   string;
  lineKey: string;
  seq:     number;
  data:    Record<string, unknown>;
}

export interface PricingTraceDocumentEvent {
  layer: string;
  seq:   number;
  data:  Record<string, unknown>;
}

export interface PricingTraceSnapshot {
  label:     string;
  mode:      PricingTraceMode;
  startedAt: string;
  lines:     PricingTraceLineEvent[];
  document:  PricingTraceDocumentEvent[];
}

interface TraceCtx {
  snapshot: PricingTraceSnapshot;
  seq:      { value: number };
}

const storage = new AsyncLocalStorage<TraceCtx>();

/** Orden canónico de capas para ordenar la salida (legible). */
const LAYER_ORDER: readonly string[] = [
  "L01_PRICE_LIST_BASE",
  "L02_LINE_DISCOUNT",
  "L03_LINE_TAX",
  "L04_LINE_TOTAL_BEFORE_COMM_ROUND",
  "L05_COMMERCIAL_ROUNDING",
  "L05B_COMMERCIAL_DOC_ROUNDING",
  "L06_CHANNEL",
  "L07_COUPON",
  "L08_GLOBAL_DISCOUNT",
  "L09_SHIPPING",
  "L10_PAYMENT",
  "L11_TOTAL_BEFORE_FIN_ROUND",
  "L12_FINANCIAL_ROUNDING",
  "L13_ENGINE_TOTAL",
  "L14_MANUAL_ADJUSTMENT",
  "L15_FINAL_TOTAL",
];

/**
 * Corre `fn` dentro de un contexto de trace. Si `PRICING_TRACE=off`, el ctx
 * no se crea y todos los `traceLine`/`traceDocument` son no-op puros.
 *
 * Devuelve `{ result, trace }`. `trace` es null si está apagado.
 */
export async function runWithTrace<T>(
  label: string,
  fn: () => Promise<T>,
): Promise<{ result: T; trace: PricingTraceSnapshot | null }> {
  const mode = resolvePricingTraceMode();
  if (mode === "off") {
    const result = await fn();
    return { result, trace: null };
  }
  const snapshot: PricingTraceSnapshot = {
    label,
    mode,
    startedAt: new Date().toISOString(),
    lines:     [],
    document:  [],
  };
  const ctx: TraceCtx = { snapshot, seq: { value: 0 } };
  const result = await storage.run(ctx, fn);
  if (mode === "console" || mode === "both") flushToConsole(snapshot);
  return { result, trace: snapshot };
}

export function isTraceActive(): boolean {
  return storage.getStore() != null;
}

export function traceLine(
  layer:   string,
  lineKey: string,
  data:    Record<string, unknown>,
): void {
  const ctx = storage.getStore();
  if (!ctx) return;
  ctx.snapshot.lines.push({ layer, lineKey, seq: ctx.seq.value++, data });
}

export function traceDocument(
  layer: string,
  data:  Record<string, unknown>,
): void {
  const ctx = storage.getStore();
  if (!ctx) return;
  ctx.snapshot.document.push({ layer, seq: ctx.seq.value++, data });
}

// ─────────────────────────────────────────────────────────────────────────────
// Console formatter
// ─────────────────────────────────────────────────────────────────────────────

function layerIdx(layer: string): number {
  const i = LAYER_ORDER.indexOf(layer);
  return i < 0 ? 999 : i;
}

function flushToConsole(snap: PricingTraceSnapshot): void {
  const out: string[] = [];
  out.push("");
  out.push("================================ PRICING_TRACE ================================");
  out.push(`label:     ${snap.label}`);
  out.push(`startedAt: ${snap.startedAt}`);

  if (snap.lines.length > 0) {
    const byLine = new Map<string, PricingTraceLineEvent[]>();
    for (const ev of snap.lines) {
      if (!byLine.has(ev.lineKey)) byLine.set(ev.lineKey, []);
      byLine.get(ev.lineKey)!.push(ev);
    }
    for (const [lineKey, events] of byLine) {
      out.push("");
      out.push(`── Línea: ${lineKey}`);
      const ordered = [...events].sort(
        (a, b) => layerIdx(a.layer) - layerIdx(b.layer) || a.seq - b.seq,
      );
      for (const ev of ordered) {
        out.push(`  [${ev.layer}] ${safeJson(ev.data)}`);
      }
    }
  }

  if (snap.document.length > 0) {
    out.push("");
    out.push("── Documento");
    const ordered = [...snap.document].sort(
      (a, b) => layerIdx(a.layer) - layerIdx(b.layer) || a.seq - b.seq,
    );
    for (const ev of ordered) {
      out.push(`  [${ev.layer}] ${safeJson(ev.data)}`);
    }
  }

  out.push("================================================================================");
  // eslint-disable-next-line no-console
  console.log(out.join("\n"));
}

function safeJson(o: unknown): string {
  try {
    return JSON.stringify(o);
  } catch {
    return "[unserializable]";
  }
}
