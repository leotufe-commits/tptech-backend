// src/lib/document-physical-rounding-apply.ts
// =============================================================================
// Etapa D3 — Orquestador de capa 16: aplica el redondeo automático físico de
// gramos por metal padre al `documentTotals` y al `balanceBreakdown` ya
// construidos por el motor.
//
// Estrategia (POLICY §R-Rounding-13):
//   1. `loadDocumentRoundingConfig` (D2) suprime el redondeo metal monetario
//      (capa 15.metal) cuando `metalDomain=PHYSICAL`. El motor produce un
//      `documentRoundingApplied.breakdown.metal` con delta=0.
//   2. Sales.service construye `balanceBreakdown` (existente).
//   3. ESTE HELPER corre la capa 16:
//        · Llama `roundDocumentMetalGrams` (D1) con los metales del
//          balance + la config resuelta (D2).
//        · Muta `documentTotals.total` sumando el `metalMonetaryEquivalent`.
//        · Muta `documentTotals.documentRoundingApplied`:
//            - Agrega `metalDomain = "PHYSICAL"`.
//            - Reemplaza `breakdown.metal` por `null` (anti doble redondeo).
//            - Agrega `breakdown.metalPhysical = { metals[], metalMonetaryEquivalent, fallback }`.
//            - Agrega bloque universal `totals = { monetaryRoundingAdjustment,
//              metalMonetaryEquivalent, totalRoundingAdjustment }`.
//        · Muta `balanceBreakdown.metals[i].gramsPure / gramsOriginal /
//          valuationMonetary` para que el ajuste manual posterior lea
//          `preGrams = postGrams del redondeo automático`.
//
// Si `metalDomain=MONETARY`: el helper igual agrega el contrato `totals`
// universal con `metalMonetaryEquivalent=0`. No toca el resto.
//
// Determinístico, sin DB, sin async. Mantiene la regla "no se mezclan
// dominios": el delta del metal físico viaja en `metalMonetaryEquivalent`
// y NO entra al bucket monetario (`breakdown.monetary.amount` / hechura).
// =============================================================================

import type { DocumentRoundingPolicy } from "./document-rounding.js";
import {
  roundDocumentMetalGrams,
  type RoundDocumentMetalGramsResult,
} from "./document-physical-rounding.js";
import {
  applyRoundingLayer,
  type DocumentRoundingInput,
  type DocumentRoundingScope,
  type DocumentRoundingLayerResult,
  type DocumentRoundingPartConfig,
} from "./pricing-engine/pricing-engine.js";

/** Subset mínimo de `documentTotals` que la capa 16 muta. Tipado al ras
 *  para no acoplar a `SaleDocumentTotals` (cuyo shape vive en el motor). */
export interface PhysicalRoundingDocumentTotalsLike {
  total:                  number;
  documentRoundingApplied?: any | null;
  metalSaleSubtotal?:     number;
  /** Snapshot del Redondeo Comercial PER_DOCUMENT (`CommercialDocRoundingApplied`).
   *  Tipado al ras para no acoplar al motor. La capa 16 lo lee SOLO para el
   *  anti-doble SECUENCIAL: si el comercial ya redondeó el gramo de VENTA de un
   *  metal padre, el financiero opera sobre ESE postGrams (no sobre el pre). */
  commercialDocumentRoundingApplied?: any | null;
}

/** Subset mínimo de `balanceBreakdown.metals[i]` que la capa 16 actualiza. */
export interface PhysicalRoundingBalanceMetalLike {
  metalParentId:      string | null;
  metalParentName:    string;
  gramsPure:          number;
  gramsOriginal?:     number;
  purity?:            number | null;
  quotePriceSnapshot?: number | null;
  valuationMonetary?: number | null;
}

/** Subset mínimo del balance que mutamos. */
export interface PhysicalRoundingBalanceLike {
  metals: PhysicalRoundingBalanceMetalLike[];
}

/** Metal padre agregado a nivel documento, lado VENTA — input opcional que
 *  el caller comercial (sales.service) provee para que la capa 16 redondee el
 *  gramo de VENTA (`gramsPure × marginFactor`) con el precio de VENTA
 *  (`metalReferenceValue ?? metalPricePerGram`), EXACTAMENTE como el Redondeo
 *  Comercial. Misma fuente que `aggregateMetalsForCommercialDocRounding`. */
export interface PhysicalRoundingCommercialMetalLike {
  metalParentId:       string;
  metalParentName:     string;
  /** Gramos puros agregados (Σ gramsFineEquivalent × qty) por metal padre. */
  gramsPure:           number;
  /** Precio por gramo de COSTO (cotización snapshot) — fallback de refValue. */
  metalPricePerGram:   number;
  /** Precio por gramo de VENTA (referenceValue). Prioritario sobre el costo. */
  metalReferenceValue?: number;
}

/** Input comercial opcional para que la capa 16 opere sobre el gramo de VENTA. */
export interface PhysicalRoundingCommercialInput {
  metalsByParent: PhysicalRoundingCommercialMetalLike[];
  /** Factor de margen documental = metalSaleSubtotal / metalCostSubtotal. */
  marginFactor:   number;
}

/**
 * Input opcional del Redondeo Financiero MONETARIO (saldo BREAKDOWN + total
 * UNIFIED) cuando éste corre EN la capa 16 — es decir, cuando el caller
 * (sales.service) detectó `financialPhysicalActive` y, para que TODO el
 * redondeo financiero ocurra como ÚLTIMO paso automático (post metal sale-gram),
 * NO le pasó `documentRounding` a `computeSaleDocumentTotals`.
 *
 * Cuando viene poblado, la capa 16 aplica, en este orden, DESPUÉS del metal:
 *   2. Saldo (BREAKDOWN / BOTH): `saldoPre = total(post-metal) − metalSaleSubtotal(post-metal)`;
 *      redondea con `breakdown.hechura`; ajusta total. MISMA base que el comercial.
 *   3. Total (UNIFIED / BOTH): redondea el total ya post-metal+post-saldo con
 *      `mode`/`direction`; ajusta total.
 * Y CONSTRUYE el `documentRoundingApplied` completo (mismo shape que el motor).
 *
 * Si NO viene → la capa 16 solo hace el metal sale-gram (el monetario lo hizo
 * la capa 15 dentro del motor; comportamiento histórico intacto).
 */
export interface PhysicalRoundingFinancialMonetaryInput {
  config: DocumentRoundingInput;
}

const round2 = (n: number): number => Math.round(n * 100) / 100;
const round4 = (n: number): number => Math.round(n * 10000) / 10000;

/**
 * Aplica capa 16 al documentTotals y balanceBreakdown. Llamado por
 * sales.service después de `buildSaleBalanceBreakdown`, antes de emitir
 * `engineTotal`. Tras la mutación, `documentTotals.total` ya refleja el
 * delta físico y el snapshot lo audita.
 *
 * @returns el resultado del helper D1 (útil para tests y trazas).
 */
export function applyDocumentPhysicalRounding(args: {
  documentTotals:   PhysicalRoundingDocumentTotalsLike;
  balanceBreakdown: PhysicalRoundingBalanceLike;
  policy:           DocumentRoundingPolicy;
  /** Etapa "venta" — cuando viene con metales, la capa 16 redondea el gramo de
   *  VENTA (`gramsPure × marginFactor`) con el precio de VENTA
   *  (`metalReferenceValue ?? metalPricePerGram`), igual que el Redondeo
   *  Comercial. Sin este arg → back-compat (gramsPure del balance + costo). */
  commercial?:      PhysicalRoundingCommercialInput | null;
  /** Redondeo Financiero MONETARIO (saldo + total) ejecutado EN la capa 16
   *  (post metal sale-gram) cuando `financialPhysicalActive`. Sin este arg el
   *  monetario lo hizo la capa 15 dentro del motor (comportamiento histórico). */
  financialMonetary?: PhysicalRoundingFinancialMonetaryInput | null;
}): RoundDocumentMetalGramsResult | null {
  const { documentTotals, balanceBreakdown, policy, commercial, financialMonetary } = args;

  // ── Bloque universal `totals` — back-compat.
  // `monetaryRoundingAdjustment` = delta $ de capa 15 (hechura + unified +
  // metal $ en MONETARY). Debe capturarse ANTES de mutar `totalAdjustment`
  // con el delta de capa 16, sino contaríamos doble.
  const ensureTotalsBlock = (monetaryAdj: number, metalEq: number): void => {
    const dra = documentTotals.documentRoundingApplied;
    if (!dra) return;
    dra.totals = {
      monetaryRoundingAdjustment: round2(monetaryAdj),
      metalMonetaryEquivalent:    round2(metalEq),
      totalRoundingAdjustment:    round2(monetaryAdj + metalEq),
    };
  };

  // ── Path MONETARY (back-compat) ─────────────────────────────────────────
  // Cuando el dominio es monetario, no corremos D1. Igual sembramos el
  // contrato `totals` universal con metalMonetaryEquivalent=0 si hay snapshot.
  if (policy.metalDomain !== "PHYSICAL" || !policy.physical.enabled) {
    const monetaryAdj = round2(Number(documentTotals.documentRoundingApplied?.totalAdjustment ?? 0));
    ensureTotalsBlock(monetaryAdj, 0);
    return null;
  }

  // ── Path PHYSICAL ───────────────────────────────────────────────────────
  // 1. Tomar metales + config + correr D1.
  //
  // CONTRATO DE VENTA (paridad con el Redondeo Comercial): cuando el caller
  // comercial provee `commercial.metalsByParent`, la capa 16 redondea el gramo
  // de VENTA (`gramsPure × marginFactor`) con el precio de VENTA
  // (`metalReferenceValue ?? metalPricePerGram`). Idéntica matemática que
  // `commercial-document-rounding.ts:399-409`.
  //
  // BACK-COMPAT: sin `commercial`, redondea el gramo PURO físico del balance
  // (`gramsPure`) con el precio de COSTO (`quotePriceSnapshot`).
  // ── GATE POR SCOPE EFECTIVO (metal sale-gram solo si BREAKDOWN) ───────────
  // El redondeo del METAL de VENTA (path `commercial`) pertenece al dominio
  // DESGLOSADO del Redondeo Financiero: solo aplica cuando el scope efectivo
  // INCLUYE BREAKDOWN. En UNIFIED el financiero redondea ÚNICAMENTE el TOTAL
  // crudo (no descompone metal/saldo), así que el metal NO debe redondearse por
  // separado — si corriera, su `metalMonetaryEquivalent` CONTAMINARÍA el total
  // que entra al paso `unified` (ej. 715.986,32 → 718.636,32 → 718.600 en vez
  // de 715.986,32 → 716.000).
  //
  // Gate SOLO cuando el caller comercial pasó `financialMonetary` (lado venta
  // con `financialPhysicalActive`): ahí el scope efectivo es la autoridad.
  //   · scope === "UNIFIED" → suprimir el metal sale-gram (no redondear, no
  //     emitir metalPhysical, no mover el total). El paso `unified` de
  //     `financialMonetary` redondea el total crudo (pre-metal).
  //   · scope incluye BREAKDOWN ("BREAKDOWN"/"BOTH") → metal corre como hoy.
  //
  // BACK-COMPAT: sin `financialMonetary` (callers legacy / no-sales) el metal
  // corre según `metalDomain` (comportamiento histórico intacto).
  const suppressCommercialMetalByScope =
    !!financialMonetary && (financialMonetary.config.scope ?? "UNIFIED") === "UNIFIED";

  const useCommercial =
    !!commercial && commercial.metalsByParent.length > 0 && !suppressCommercialMetalByScope;
  const marginFactor =
    useCommercial && Number.isFinite(commercial!.marginFactor) && commercial!.marginFactor > 0
      ? commercial!.marginFactor
      : 1;

  // ── ANTI-DOBLE SECUENCIAL (comercial → financiero) ────────────────────────
  // Si el comprobante ya aplicó Redondeo Comercial PHYSICAL sobre un metal padre
  // (la LISTA redondeó el gramo de VENTA, ej. 2,2894 → 2,30), el Redondeo
  // Financiero (capa 16) NO debe re-redondear DESDE el gramo pre-comercial:
  // debe encadenar sobre el gramo POST-comercial. Sin este gate, con misma config
  // (lista 0,1 + financiero 0,1) el financiero replicaría el delta de la lista y
  // contaríamos +monetaryEquivalent dos veces.
  //
  // Leemos los postGrams comerciales del snapshot del documento
  // (`commercialDocumentRoundingApplied.breakdown`). Preferimos `metalsPostGrams`
  // (incluye TODOS los metales padre, incluso delta=0) y caemos a `metals`
  // (solo los que movieron). Match por `metalParentId`.
  const commercialPostGramsByParentId = new Map<string, number>();
  {
    const crb = documentTotals.commercialDocumentRoundingApplied?.breakdown;
    const sources: Array<{ metalParentId?: string | null; postGrams?: number }> = [
      ...(Array.isArray(crb?.metalsPostGrams) ? crb!.metalsPostGrams : []),
      ...(Array.isArray(crb?.metals) ? crb!.metals : []),
    ];
    for (const e of sources) {
      const id = e?.metalParentId;
      if (id == null) continue;
      if (commercialPostGramsByParentId.has(id)) continue; // metalsPostGrams gana
      if (typeof e.postGrams === "number" && Number.isFinite(e.postGrams)) {
        commercialPostGramsByParentId.set(id, e.postGrams);
      }
    }
  }

  const helperInput = useCommercial
    ? {
        metals: commercial!.metalsByParent.map((m) => ({
          metalParentId:   m.metalParentId,
          metalParentName: m.metalParentName,
          // Gramo de entrada del financiero: si la LISTA ya redondeó el gramo de
          // VENTA de ESTE metal padre, encadenamos sobre ESE postGrams comercial.
          // Si NO hay redondeo comercial de ese metal → gramsSale pre-comercial
          // (`gramsPure × marginFactor`), comportamiento histórico.
          grams:
            commercialPostGramsByParentId.has(m.metalParentId)
              ? round4(commercialPostGramsByParentId.get(m.metalParentId)!)
              : round4(m.gramsPure * marginFactor),
          // Precio de VENTA (referenceValue) con fallback al costo.
          metalPricePerGram:
            typeof m.metalReferenceValue === "number"
              && Number.isFinite(m.metalReferenceValue)
              && m.metalReferenceValue > 0
              ? m.metalReferenceValue
              : (typeof m.metalPricePerGram === "number" && Number.isFinite(m.metalPricePerGram)
                  ? m.metalPricePerGram
                  : null),
        })),
        configByMetalParentId: policy.physical.configByMetalParentId,
        fallbackConfig:        policy.physical.fallbackConfig,
      }
    : {
        metals: balanceBreakdown.metals.map((m) => ({
          metalParentId:    m.metalParentId,
          metalParentName:  m.metalParentName,
          grams:            m.gramsPure,
          metalPricePerGram:
            typeof m.quotePriceSnapshot === "number" && Number.isFinite(m.quotePriceSnapshot)
              ? m.quotePriceSnapshot
              : null,
        })),
        configByMetalParentId: policy.physical.configByMetalParentId,
        fallbackConfig:        policy.physical.fallbackConfig,
      };
  // Cuando el scope efectivo del financiero es UNIFIED (gate de arriba), el
  // metal NO se redondea por separado: cortocircuitamos el helper a un resultado
  // vacío (metalEq=0, metals=[]). NO caemos al path back-compat del balance —
  // si lo hiciéramos, el metal se redondearía igual y volvería a contaminar el
  // total. El paso `unified` de `financialMonetary` redondeará el total crudo.
  const result: RoundDocumentMetalGramsResult = suppressCommercialMetalByScope
    ? { metals: [], metalMonetaryEquivalent: 0, fallback: "NO_METALS_TO_ROUND" }
    : roundDocumentMetalGrams(helperInput);

  // 2. Mutar balanceBreakdown.metals[i] con los gramos post-redondeo.
  //    SOLO en el path back-compat: ahí el `postGrams` ES gramo puro físico, y
  //    el ajuste manual BREAKDOWN posterior (Etapa C) leerá `gramsPure` del
  //    balance ⇒ verá el postGrams como preGrams del ajuste.
  //    En el path comercial el `postGrams` es gramo de VENTA (con margen) →
  //    mutar `gramsPure` corrompería el gramo puro físico (cuenta corriente),
  //    así que NO se muta el balance: el impacto viaja solo por el equivalente
  //    monetario sobre `documentTotals.total` + el snapshot.
  if (!useCommercial) {
    for (const entry of result.metals) {
      const target = balanceBreakdown.metals.find((m) =>
        (m.metalParentId != null && entry.metalParentId != null && m.metalParentId === entry.metalParentId) ||
        (m.metalParentId == null && entry.metalParentId == null && m.metalParentName === entry.metalParentName)
      );
      if (!target) continue;
      if (entry.fallback != null) continue; // fallback → no mutamos (preserva originales)
      target.gramsPure = entry.postGrams;
      if (typeof target.purity === "number" && target.purity > 0 && target.gramsOriginal != null) {
        target.gramsOriginal = round4(entry.postGrams / target.purity);
      }
      if (typeof target.quotePriceSnapshot === "number" && Number.isFinite(target.quotePriceSnapshot)) {
        target.valuationMonetary = round2(entry.postGrams * target.quotePriceSnapshot);
      }
    }
  }

  // 3. Mutar documentTotals.total (+ metalSaleSubtotal si existía).
  const metalEq = result.metalMonetaryEquivalent;
  documentTotals.total = round2(Math.max(0, documentTotals.total + metalEq));
  if (typeof documentTotals.metalSaleSubtotal === "number") {
    documentTotals.metalSaleSubtotal = round2(documentTotals.metalSaleSubtotal + metalEq);
  }

  // 3.bis — REDONDEO FINANCIERO MONETARIO EN LA CAPA 16 (saldo + total).
  //
  // Solo cuando el caller pasó `financialMonetary` — es decir, cuando detectó
  // `financialPhysicalActive` y por eso NO le pasó `documentRounding` al motor
  // (capa 15). En ese caso TODO el redondeo financiero corre acá, como último
  // paso automático antes del ajuste manual, en este orden:
  //   2. SALDO (BREAKDOWN / BOTH): saldoPre = total(post-metal) − metalSale(post-metal)
  //      → redondeo con `breakdown.hechura` → ajusta total. MISMA base que el
  //      comercial (`commercial-document-rounding.ts`: total − metalSaleBase).
  //   3. TOTAL (UNIFIED / BOTH): redondea el total ya post-metal+post-saldo con
  //      `mode`/`direction` → ajusta total.
  //
  // El snapshot `documentRoundingApplied` se CONSTRUYE acá completo (mismo shape
  // que emite el motor: scope, unified, breakdown.metal/hechura, metalPhysical,
  // metalDomain, combinedAdjustment, totalAdjustment, totals).
  if (financialMonetary) {
    const cfg = financialMonetary.config;
    const scope: DocumentRoundingScope = cfg.scope ?? "UNIFIED";
    const wantsBreakdown = scope === "BREAKDOWN" || scope === "BOTH";
    const wantsUnified   = scope === "UNIFIED"   || scope === "BOTH";

    let saldoLayer:   DocumentRoundingLayerResult | undefined;
    let unifiedLayer: DocumentRoundingLayerResult | undefined;
    let monetaryDelta = 0;

    // — Paso 2: SALDO (BREAKDOWN / BOTH).
    //
    // ANTI-DOBLE SECUENCIAL DEL SALDO (comercial → financiero), espejo del
    // anti-doble del metal: si la LISTA (Redondeo Comercial PER_DOCUMENT) ya
    // redondeó el saldo monetario (`hechura.postRoundingSaldoMonetario`), el
    // financiero NO debe partir de `total − metalSale` (que reintroduce el
    // metal comercial en el saldo y lo infla → re-redondeo de más). Debe
    // ENCADENAR sobre el saldo POST-comercial.
    //
    // Identidad `saldo + metal = total`: el `postRoundingSaldoMonetario`
    // comercial = `totalComercial − metalSaleComercial`. Tanto `documentTotals.total`
    // como `documentTotals.metalSaleSubtotal` ya fueron incrementados por el
    // `metalEq` del metal financiero de ESTE paso (líneas 285-288), así que
    // `total_post − metalSale_post = totalComercial − metalSaleComercial =
    // postRoundingSaldoMonetario`. ⇒ el saldoPre POST-comercial ES directo el
    // `postRoundingSaldoMonetario` (el delta de metal financiero se cancela: si
    // el metal sube X, total sube X y la porción metal sube X → saldo invariante).
    //
    // Sin redondeo comercial del saldo (lista sin redondear o sin hechura):
    // fallback al comportamiento histórico `total − metalSale`.
    if (wantsBreakdown && cfg.breakdown) {
      const commercialPostSaldo =
        documentTotals.commercialDocumentRoundingApplied?.breakdown?.hechura
          ?.postRoundingSaldoMonetario;
      const hasCommercialSaldoRounding =
        typeof commercialPostSaldo === "number" && Number.isFinite(commercialPostSaldo);

      let saldoPre: number;
      if (hasCommercialSaldoRounding) {
        // Saldo POST-comercial. El metalEq del metal financiero ya está reflejado
        // por igual en `total` y en `metalSaleSubtotal`, por lo que el saldo
        // (= total − metalSale) es invariante respecto de ese delta ⇒ usamos el
        // post-comercial directo, preservando `saldo + metal = total`.
        saldoPre = round2(commercialPostSaldo as number);
      } else {
        const metalSalePostMetal = round2(Number(documentTotals.metalSaleSubtotal ?? 0));
        saldoPre = round2(documentTotals.total - metalSalePostMetal);
      }
      const layer = applyRoundingLayer(saldoPre, cfg.breakdown.hechura, "DOC_HECHURA");
      if (layer.adjustment !== 0) {
        monetaryDelta += layer.adjustment;
        documentTotals.total = round2(Math.max(0, documentTotals.total + layer.adjustment));
      }
      // Reportamos la capa hechura SIEMPRE (delta 0 incluido) para que el
      // snapshot refleje pre/post del SALDO mostrado (total − metal), no del
      // subtotal de hechura. Espejo del contrato comercial.
      saldoLayer = layer;
    }

    // — Paso 3: TOTAL (UNIFIED / BOTH). Sobre el total ya post-metal+post-saldo.
    if (wantsUnified) {
      const unifiedCfg: DocumentRoundingPartConfig = { mode: cfg.mode, direction: cfg.direction };
      const layer = applyRoundingLayer(documentTotals.total, unifiedCfg, "DOC_TOTAL");
      if (layer.adjustment !== 0) {
        monetaryDelta += layer.adjustment;
        documentTotals.total = round2(Math.max(0, layer.postRounding));
        unifiedLayer = layer;
      }
    }

    monetaryDelta = round2(monetaryDelta);

    // Construcción del snapshot completo (mismo shape que el motor + capa 16).
    const metalLayerNull: null = null;
    documentTotals.documentRoundingApplied = {
      source:  "TENANT_POLICY",
      scope,
      applyOn: "DOC_TOTAL",
      totalAdjustment: round2(monetaryDelta + metalEq),
      ...(unifiedLayer ? { unified: unifiedLayer } : {}),
      breakdown: {
        metal:         metalLayerNull,
        ...(saldoLayer ? { hechura: saldoLayer } : { hechura: null }),
        metalDomain:   "PHYSICAL",
        metalPhysical: {
          metals: result.metals,
          metalMonetaryEquivalent: result.metalMonetaryEquivalent,
          ...(result.fallback ? { fallback: result.fallback } : { fallback: null }),
        },
        combinedAdjustment: round2(monetaryDelta + metalEq),
      },
      totals: {
        monetaryRoundingAdjustment: round2(monetaryDelta),
        metalMonetaryEquivalent:    round2(metalEq),
        totalRoundingAdjustment:    round2(monetaryDelta + metalEq),
      },
    } as any;

    return result;
  }

  // 4. Mutar documentRoundingApplied:
  //      · breakdown.metal (monetario) → null  (anti doble redondeo).
  //      · breakdown.metalPhysical → snapshot de capa 16.
  //      · metalDomain → "PHYSICAL".
  //      · totalAdjustment → suma con metalEq.
  //      · totals → bloque universal con desglose por dominio.
  const dra = documentTotals.documentRoundingApplied;
  if (dra) {
    // Capturar monetary $ ANTES de mutar totalAdjustment con capa 16.
    const monetaryAdj = round2(Number(dra.totalAdjustment ?? 0));
    if (dra.breakdown) {
      // Limpieza metal $ — el motor lo emitió en NONE (forzado por loader),
      // pero igual lo borramos para que el snapshot sea quirúrgicamente claro.
      dra.breakdown.metal = null;
      dra.breakdown.metalDomain = "PHYSICAL";
      dra.breakdown.metalPhysical = {
        metals: result.metals,
        metalMonetaryEquivalent: result.metalMonetaryEquivalent,
        ...(result.fallback ? { fallback: result.fallback } : { fallback: null }),
      };
      dra.breakdown.combinedAdjustment = round2(
        Number(dra.breakdown.combinedAdjustment ?? 0) + metalEq,
      );
    }
    dra.totalAdjustment = round2(monetaryAdj + metalEq);
    ensureTotalsBlock(monetaryAdj, metalEq);
  } else if (Math.abs(metalEq) > 0.005 || result.metals.length > 0) {
    // Sin snapshot previo (motor pasó por NO_BREAKDOWN_DATA, etc.) pero
    // capa 16 produjo algo: armamos un snapshot mínimo.
    documentTotals.documentRoundingApplied = {
      source:        "TENANT_POLICY",
      scope:         "BREAKDOWN",
      applyOn:       "DOC_TOTAL",
      totalAdjustment: round2(metalEq),
      breakdown: {
        metal:         null,
        hechura:       null,
        metalDomain:   "PHYSICAL",
        metalPhysical: {
          metals: result.metals,
          metalMonetaryEquivalent: result.metalMonetaryEquivalent,
          ...(result.fallback ? { fallback: result.fallback } : { fallback: null }),
        },
        combinedAdjustment: round2(metalEq),
      },
      totals: {
        monetaryRoundingAdjustment: 0,
        metalMonetaryEquivalent: round2(metalEq),
        totalRoundingAdjustment: round2(metalEq),
      },
    };
  }

  return result;
}
