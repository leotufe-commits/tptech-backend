import type { Request, Response } from "express";

import { prisma } from "../../lib/prisma.js";
import { requireTenantId } from "../users/users.helpers.js";
import { auditLog } from "../../lib/auditLogger.js";

import {
  listCurrencies,
  createCurrency,
  updateCurrency,
  setBaseCurrencyAndRecalc,
  toggleCurrencyActive,
  addCurrencyRate,
  listCurrencyRates,

  createMetal,
  listMetals,
  toggleMetalActive,
  updateMetal,
  deleteMetal as deleteMetalSvc,

  moveMetal,
  listMetalRefHistory,

  createMetalVariant,
  listMetalVariants,
  updateMetalVariantPricing,
  setFavoriteVariant,
  toggleVariantActive,

  deleteVariant as deleteVariantSvc,

  addMetalQuote,
  listMetalQuotes,

  deleteCurrency as deleteCurrencySvc,

  // ✅ NUEVO
  updateMetalVariant,
  clearFavoriteVariant,
} from "./valuation.service.js";

import {
  createCurrencySchema,
  updateCurrencySchema,
  createCurrencyRateSchema,

  createMetalSchema,
  updateMetalSchema,

  createMetalVariantSchema,
  updateMetalVariantPricingSchema,
  updateMetalVariantSchema, // ✅ NUEVO
  createMetalQuoteSchema,
} from "./valuation.schemas.js";

/* =========================================================
   Helpers
========================================================= */

function getTake(req: Request, fallback = 50) {
  const v = Number(req.query.take);
  if (!Number.isFinite(v)) return fallback;
  return Math.max(1, Math.min(200, Math.trunc(v)));
}

function boolQ(v: any) {
  if (v === "true") return true;
  if (v === "false") return false;
  return undefined;
}

function numQ(v: any) {
  if (v === undefined || v === null || v === "") return undefined;
  const n = Number(v);
  if (!Number.isFinite(n)) return undefined;
  return n;
}

/* =========================================================
   MONEDAS (FX)
========================================================= */

export async function getCurrencies(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const rows = await listCurrencies(jewelryId);
  res.json({ ok: true, rows });
}

export async function postCurrency(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const userId = (req as any).user?.id ?? null;

  const parsed = createCurrencySchema.parse(req.body);
  const row = await createCurrency(jewelryId, parsed);

  await auditLog(req, {
    action: "valuation.currency.create",
    success: true,
    userId,
    jewelryId,
    meta: { id: row.id, code: row.code },
  });

  res.json({ ok: true, row });
}

export async function patchCurrency(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const userId = (req as any).user?.id ?? null;

  const currencyId = String(req.params.currencyId || "").trim();
  if (!currencyId) return res.status(400).json({ ok: false, error: "currencyId requerido." });

  const parsed = updateCurrencySchema.parse(req.body);

  try {
    const row = await updateCurrency(jewelryId, currencyId, parsed);

    await auditLog(req, {
      action: "valuation.currency.update",
      success: true,
      userId,
      jewelryId,
      meta: { id: row.id, code: row.code },
    });

    res.json({ ok: true, row });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error actualizando moneda.") });
  }
}

export async function deleteCurrencyCtrl(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const userId = (req as any).user?.id ?? null;

  const currencyId = String(req.params.currencyId || "").trim();
  if (!currencyId) return res.status(400).json({ ok: false, error: "currencyId requerido." });

  try {
    await deleteCurrencySvc(jewelryId, currencyId);

    await auditLog(req, {
      action: "valuation.currency.delete",
      success: true,
      userId,
      jewelryId,
      meta: { currencyId },
    });

    res.json({ ok: true });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error eliminando moneda.") });
  }
}

export async function postSetBaseCurrency(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const userId = (req as any).user?.id ?? null;

  const currencyId = String(req.params.currencyId || "").trim();
  if (!currencyId) return res.status(400).json({ ok: false, error: "currencyId requerido." });

  try {
    const result = await setBaseCurrencyAndRecalc({
      jewelryId,
      newBaseCurrencyId: currencyId,
      actorUserId: userId,
      effectiveAt: new Date(),
    });

    await auditLog(req, {
      action: "valuation.currency.set_base",
      success: true,
      userId,
      jewelryId,
      meta: {
        newBaseCurrencyId: currencyId,
        changed: (result as any)?.changed ?? true,
        oldBaseId: (result as any)?.oldBaseId ?? null,
        newBaseId: (result as any)?.newBaseId ?? currencyId,
        k: (result as any)?.k ?? null,
      },
    });

    const row = await prisma.currency.findFirst({
      where: { id: currencyId, jewelryId },
      select: { id: true, code: true, name: true, symbol: true, isBase: true, isActive: true },
    });

    if (!row) return res.status(404).json({ ok: false, error: "Moneda no encontrada." });

    res.json({ ok: true, row });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error cambiando moneda base.") });
  }
}

export async function patchCurrencyActive(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const userId = (req as any).user?.id ?? null;

  const currencyId = String(req.params.currencyId || "").trim();
  const isActive = !!req.body?.isActive;

  try {
    const row = await toggleCurrencyActive(jewelryId, currencyId, isActive);

    await auditLog(req, {
      action: "valuation.currency.toggle_active",
      success: true,
      userId,
      jewelryId,
      meta: { id: row.id, isActive },
    });

    res.json({ ok: true, row });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error actualizando estado de moneda.") });
  }
}

export async function postCurrencyRate(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const userId = (req as any).user?.id ?? null;

  const currencyId = String(req.params.currencyId || "").trim();
  if (!currencyId) return res.status(400).json({ ok: false, error: "currencyId requerido." });

  const parsed = createCurrencyRateSchema.parse(req.body);

  try {
    const row = await addCurrencyRate(jewelryId, currencyId, parsed, userId);

    await auditLog(req, {
      action: "valuation.currency.rate.create",
      success: true,
      userId,
      jewelryId,
      meta: { currencyId, currencyRateId: row.id, rate: parsed.rate, effectiveAt: parsed.effectiveAt },
    });

    res.json({ ok: true, row });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error creando tipo de cambio.") });
  }
}

export async function getCurrencyRates(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const currencyId = String(req.params.currencyId || "").trim();
  if (!currencyId) return res.status(400).json({ ok: false, error: "currencyId requerido." });

  const take = getTake(req, 50);

  try {
    const rows = await listCurrencyRates(jewelryId, currencyId, take);
    res.json({ ok: true, rows });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error obteniendo rates.") });
  }
}

export async function getCurrencyRateHistory(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const currencyId = String(req.params.currencyId || "").trim();
  if (!currencyId) return res.status(400).json({ ok: false, error: "currencyId requerido." });

  const take = getTake(req, 80);

  const currency = await prisma.currency.findFirst({
    where: { id: currencyId, jewelryId },
    select: { id: true, code: true, name: true, symbol: true, isBase: true, isActive: true },
  });
  if (!currency) return res.status(404).json({ ok: false, error: "Moneda no encontrada." });

  const rates = await prisma.currencyRate.findMany({
    where: { currencyId },
    orderBy: [{ effectiveAt: "desc" }, { createdAt: "desc" }],
    take,
    select: {
      id: true,
      rate: true,
      effectiveAt: true,
      createdAt: true,
      createdBy: { select: { id: true, name: true, email: true } },
    },
  });

  const history = rates.map((r) => ({
    id: r.id,
    rate: Number(r.rate),
    effectiveAt: r.effectiveAt,
    createdAt: r.createdAt,
    user: r.createdBy ? { id: r.createdBy.id, name: r.createdBy.name, email: r.createdBy.email } : null,
  }));

  res.json({ ok: true, currency, current: history[0] ?? null, history });
}

/* =========================================================
   METALES PADRES
========================================================= */

export async function getMetals(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const rows = await listMetals(jewelryId);
  res.json({ ok: true, rows });
}

export async function postMetal(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const userId = (req as any).user?.id ?? null;

  const parsed = createMetalSchema.parse(req.body);

  try {
    const row = await createMetal(jewelryId, parsed, userId);

    await auditLog(req, {
      action: "valuation.metal.create",
      success: true,
      userId,
      jewelryId,
      meta: { id: row.id, name: row.name, symbol: (row as any).symbol ?? "" },
    });

    res.json({ ok: true, row });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error creando metal.") });
  }
}

export async function patchMetal(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const userId = (req as any).user?.id ?? null;

  const metalId = String(req.params.metalId || "").trim();
  if (!metalId) return res.status(400).json({ ok: false, error: "metalId requerido." });

  const parsed = updateMetalSchema.parse(req.body);

  try {
    const row = await updateMetal(jewelryId, metalId, parsed, userId);

    await auditLog(req, {
      action: "valuation.metal.update",
      success: true,
      userId,
      jewelryId,
      meta: { id: row.id, name: row.name, symbol: (row as any).symbol ?? "" },
    });

    res.json({ ok: true, row });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error actualizando metal.") });
  }
}

export async function deleteMetalCtrl(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const userId = (req as any).user?.id ?? null;

  const metalId = String(req.params.metalId || "").trim();
  if (!metalId) return res.status(400).json({ ok: false, error: "metalId requerido." });

  try {
    await deleteMetalSvc(jewelryId, metalId);

    await auditLog(req, {
      action: "valuation.metal.delete",
      success: true,
      userId,
      jewelryId,
      meta: { metalId },
    });

    res.json({ ok: true });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error eliminando metal.") });
  }
}

export async function patchMetalActive(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const userId = (req as any).user?.id ?? null;

  const metalId = String(req.params.metalId || "").trim();
  const isActive = !!req.body?.isActive;

  try {
    const row = await toggleMetalActive(jewelryId, metalId, isActive);

    await auditLog(req, {
      action: "valuation.metal.toggle_active",
      success: true,
      userId,
      jewelryId,
      meta: { id: row.id, isActive },
    });

    res.json({ ok: true, row });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error actualizando estado del metal.") });
  }
}

/* =========================================================
   ORDEN METALES
========================================================= */

export async function postMoveMetal(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const userId = (req as any).user?.id ?? null;

  const metalId = String(req.params.metalId || "").trim();
  if (!metalId) return res.status(400).json({ ok: false, error: "metalId requerido." });

  const dir = String(req.body?.dir || "").trim().toUpperCase();
  if (dir !== "UP" && dir !== "DOWN") {
    return res.status(400).json({ ok: false, error: 'dir inválido. Usá "UP" o "DOWN".' });
  }

  try {
    const out = await moveMetal(jewelryId, metalId, dir as "UP" | "DOWN");

    await auditLog(req, {
      action: "valuation.metal.move",
      success: true,
      userId,
      jewelryId,
      meta: { metalId, dir, changed: out.changed },
    });

    res.json({ ok: true, ...out });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error moviendo metal.") });
  }
}

/* =========================================================
   HISTORIAL valor de referencia
========================================================= */

export async function getMetalRefHistory(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);

  const metalId = String(req.params.metalId || "").trim();
  if (!metalId) return res.status(400).json({ ok: false, error: "metalId requerido." });

  const take = getTake(req, 120);

  try {
    const metal = await prisma.metal.findFirst({
      where: { id: metalId, jewelryId },
      select: { id: true, name: true, symbol: true, referenceValue: true, isActive: true, sortOrder: true },
    });

    if (!metal) return res.status(404).json({ ok: false, error: "Metal no encontrado." });

    const history = await listMetalRefHistory(jewelryId, metalId, take);

    res.json({ ok: true, metal, current: history[0] ?? null, history });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error obteniendo historial.") });
  }
}

/* =========================================================
   VARIANTES
========================================================= */

export async function postMetalVariant(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const userId = (req as any).user?.id ?? null;

  const parsed = createMetalVariantSchema.parse(req.body);

  try {
    const row = await createMetalVariant(jewelryId, parsed);

    await auditLog(req, {
      action: "valuation.variant.create",
      success: true,
      userId,
      jewelryId,
      meta: { id: row.id, metalId: row.metalId, sku: row.sku },
    });

    res.json({ ok: true, row });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error creando variante.") });
  }
}

export async function getMetalVariants(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const metalId = String(req.params.metalId || "").trim();
  if (!metalId) return res.status(400).json({ ok: false, error: "metalId requerido." });

  const rows = await listMetalVariants(jewelryId, metalId, {
    q: String(req.query.q || "").trim() || undefined,
    isActive: boolQ(req.query.isActive),
    onlyFavorites: req.query.onlyFavorites === "true",
    minPurchase: numQ(req.query.minPurchase),
    maxPurchase: numQ(req.query.maxPurchase),
    minSale: numQ(req.query.minSale),
    maxSale: numQ(req.query.maxSale),
    currencyId: String(req.query.currencyId || "").trim() || undefined,
  });

  res.json({ ok: true, rows });
}

// ✅ NUEVO: editar variante (PATCH /variants/:variantId)
export async function patchVariant(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const userId = (req as any).user?.id ?? null;

  const variantId = String(req.params.variantId || "").trim();
  if (!variantId) return res.status(400).json({ ok: false, error: "variantId requerido." });

  const parsed = updateMetalVariantSchema.parse(req.body);

  try {
    const row = await updateMetalVariant(jewelryId, variantId, parsed as any);

    await auditLog(req, {
      action: "valuation.variant.update",
      success: true,
      userId,
      jewelryId,
      meta: { variantId, ...parsed },
    });

    res.json({ ok: true, row });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error actualizando variante.") });
  }
}

export async function patchVariantPricing(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const userId = (req as any).user?.id ?? null;

  const variantId = String(req.params.variantId || "").trim();
  if (!variantId) return res.status(400).json({ ok: false, error: "variantId requerido." });

  const parsed = updateMetalVariantPricingSchema.parse(req.body);

  try {
    // ✅ NOTA: si tu service NO recibe actorUserId, sacá el 4to parámetro.
    const row = await (updateMetalVariantPricing as any)(jewelryId, variantId, parsed, userId);

    await auditLog(req, {
      action: "valuation.variant.pricing.update",
      success: true,
      userId,
      jewelryId,
      meta: { variantId, ...parsed },
    });

    res.json({ ok: true, row });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error actualizando pricing de variante.") });
  }
}

export async function patchVariantActive(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const userId = (req as any).user?.id ?? null;

  const variantId = String(req.params.variantId || "").trim();
  const isActive = !!req.body?.isActive;

  try {
    const row = await toggleVariantActive(jewelryId, variantId, isActive);

    await auditLog(req, {
      action: "valuation.variant.toggle_active",
      success: true,
      userId,
      jewelryId,
      meta: { id: row.id, isActive },
    });

    res.json({ ok: true, row });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error actualizando estado de variante.") });
  }
}

export async function postSetFavoriteVariant(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const userId = (req as any).user?.id ?? null;

  const variantId = String(req.params.variantId || "").trim();
  if (!variantId) return res.status(400).json({ ok: false, error: "variantId requerido." });

  try {
    const row = await setFavoriteVariant(jewelryId, variantId);

    await auditLog(req, {
      action: "valuation.variant.set_favorite",
      success: true,
      userId,
      jewelryId,
      meta: { id: row.id },
    });

    res.json({ ok: true, row });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error seteando favorito.") });
  }
}

// ✅ NUEVO: limpiar favorito del metal (dejar sin favorito)
export async function postClearFavoriteVariant(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const userId = (req as any).user?.id ?? null;

  const metalId = String(req.params.metalId || "").trim();
  if (!metalId) return res.status(400).json({ ok: false, error: "metalId requerido." });

  try {
    await clearFavoriteVariant(jewelryId, metalId);

    await auditLog(req, {
      action: "valuation.metal.clear_favorite",
      success: true,
      userId,
      jewelryId,
      meta: { metalId },
    });

    res.json({ ok: true });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error limpiando favorito.") });
  }
}

export async function deleteVariantCtrl(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const userId = (req as any).user?.id ?? null;

  const variantId = String(req.params.variantId || "").trim();
  if (!variantId) return res.status(400).json({ ok: false, error: "variantId requerido." });

  try {
    await deleteVariantSvc(jewelryId, variantId);

    await auditLog(req, {
      action: "valuation.variant.delete",
      success: true,
      userId,
      jewelryId,
      meta: { variantId },
    });

    res.json({ ok: true });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error eliminando variante.") });
  }
}

/* =========================================================
   COTIZACIONES METALES
========================================================= */

export async function postMetalQuote(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const userId = (req as any).user?.id ?? null;

  const parsed = createMetalQuoteSchema.parse(req.body);

  try {
    const row = await addMetalQuote(jewelryId, parsed);

    await auditLog(req, {
      action: "valuation.quote.create",
      success: true,
      userId,
      jewelryId,
      meta: parsed,
    });

    res.json({ ok: true, row });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error creando quote.") });
  }
}

export async function getMetalQuotes(req: Request, res: Response) {
  const jewelryId = requireTenantId(req);
  const variantId = String(req.params.variantId || "").trim();
  if (!variantId) return res.status(400).json({ ok: false, error: "variantId requerido." });

  const take = getTake(req, 50);

  try {
    const rows = await listMetalQuotes(jewelryId, variantId, take);
    res.json({ ok: true, rows });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    res.status(status).json({ ok: false, error: String(e?.message || "Error obteniendo quotes.") });
  }
}

/* =========================================================
   ✅ Aliases para routes con import * as c
========================================================= */
export const deleteCurrency = deleteCurrencyCtrl;
export const deleteMetal = deleteMetalCtrl;
export const deleteVariant = deleteVariantCtrl;

/* =========================================================
   Default export (opcional)
========================================================= */
export default {
  getCurrencies,
  postCurrency,
  patchCurrency,
  deleteCurrency: deleteCurrencyCtrl,
  postSetBaseCurrency,
  patchCurrencyActive,
  postCurrencyRate,
  getCurrencyRates,
  getCurrencyRateHistory,

  getMetals,
  postMetal,
  patchMetal,
  deleteMetal: deleteMetalCtrl,
  patchMetalActive,

  postMoveMetal,
  getMetalRefHistory,

  postMetalVariant,
  getMetalVariants,
  patchVariant, // ✅ NUEVO
  patchVariantPricing,
  patchVariantActive,
  postSetFavoriteVariant,
  postClearFavoriteVariant, // ✅ NUEVO
  deleteVariant: deleteVariantCtrl,

  postMetalQuote,
  getMetalQuotes,
};