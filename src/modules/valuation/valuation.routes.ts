// tptech-backend/src/modules/valuation/valuation.routes.ts
import { Router } from "express";

import { requireAuth } from "../../middlewares/requireAuth.js";
import { requirePermission } from "../../middlewares/requirePermission.js";

import * as c from "./valuation.controller.js";

const router = Router();

/* =========================
   AUTH
========================= */
router.use(requireAuth);

/* =========================
   PERMISSIONS (simple)
========================= */
const canView = requirePermission("CURRENCIES", "VIEW");
const canEdit = requirePermission("CURRENCIES", "EDIT");

/* =========================================================
   MONEDAS (FX)
========================================================= */
router.get("/currencies", canView, c.getCurrencies);
router.post("/currencies", canEdit, c.postCurrency);
router.patch("/currencies/:currencyId", canEdit, c.patchCurrency);
router.delete("/currencies/:currencyId", canEdit, c.deleteCurrency);

router.post("/currencies/:currencyId/set-base", canEdit, c.postSetBaseCurrency);
router.patch("/currencies/:currencyId/active", canEdit, c.patchCurrencyActive);

router.post("/currencies/:currencyId/rates", canEdit, c.postCurrencyRate);
router.get("/currencies/:currencyId/rates", canView, c.getCurrencyRates);
router.get("/currencies/:currencyId/rate-history", canView, c.getCurrencyRateHistory);

/* =========================================================
   METALES PADRES
========================================================= */
router.get("/metals", canView, c.getMetals);
router.post("/metals", canEdit, c.postMetal);
router.patch("/metals/:metalId", canEdit, c.patchMetal);
router.delete("/metals/:metalId", canEdit, c.deleteMetal);

router.patch("/metals/:metalId/active", canEdit, c.patchMetalActive);

/* =========================================================
   ORDEN / HISTORIAL METALES
========================================================= */
router.post("/metals/:metalId/move", canEdit, c.postMoveMetal);
router.get("/metals/:metalId/ref-history", canView, c.getMetalRefHistory);

/* =========================================================
   VARIANTES
========================================================= */
router.post("/variants", canEdit, c.postMetalVariant);
router.get("/metals/:metalId/variants", canView, c.getMetalVariants);

router.patch("/variants/:variantId", canEdit, c.patchVariant);
router.patch("/variants/:variantId/pricing", canEdit, c.patchVariantPricing);
router.patch("/variants/:variantId/active", canEdit, c.patchVariantActive);

router.post("/variants/:variantId/set-favorite", canEdit, c.postSetFavoriteVariant);
router.post("/metals/:metalId/clear-favorite", canEdit, c.postClearFavoriteVariant);

router.delete("/variants/:variantId", canEdit, c.deleteVariant);

/* ✅ HISTORIAL PARA MODAL (OPCIÓN B) */
router.get("/variants/:variantId/value-history", canView, c.getVariantValueHistory);

/* =========================================================
   COTIZACIONES (QUOTES)
========================================================= */
router.post("/quotes", canEdit, c.postMetalQuote);
router.get("/variants/:variantId/quotes", canView, c.getMetalQuotes);

export default router;