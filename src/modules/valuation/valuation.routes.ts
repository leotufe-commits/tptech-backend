// tptech-backend/src/modules/valuation/valuation.routes.ts
import { Router } from "express";

import { requireAuth } from "../../middlewares/requireAuth.js";
import { requirePermission } from "../../middlewares/requirePermission.js";

// ✅ IMPORT ROBUSTO: named exports
import * as c from "./valuation.controller.js";

const r = Router();

r.use(requireAuth);

/* =========================
   Monedas (FX)
========================= */

r.get("/currencies", requirePermission("CURRENCIES", "VIEW"), c.getCurrencies);

r.post("/currencies", requirePermission("CURRENCIES", "CREATE"), c.postCurrency);

r.patch("/currencies/:currencyId", requirePermission("CURRENCIES", "EDIT"), c.patchCurrency);

r.delete("/currencies/:currencyId", requirePermission("CURRENCIES", "DELETE"), c.deleteCurrency);

r.post("/currencies/:currencyId/set-base", requirePermission("CURRENCIES", "ADMIN"), c.postSetBaseCurrency);

r.patch("/currencies/:currencyId/active", requirePermission("CURRENCIES", "EDIT"), c.patchCurrencyActive);

r.post("/currencies/:currencyId/rates", requirePermission("CURRENCIES", "CREATE"), c.postCurrencyRate);

r.get("/currencies/:currencyId/rates", requirePermission("CURRENCIES", "VIEW"), c.getCurrencyRates);

r.get("/currencies/:currencyId/history", requirePermission("CURRENCIES", "VIEW"), c.getCurrencyRateHistory);

/* =========================
   Metales / Divisas
========================= */

r.get("/metals", requirePermission("CURRENCIES", "VIEW"), c.getMetals);

r.post("/metals", requirePermission("CURRENCIES", "CREATE"), c.postMetal);

r.patch("/metals/:metalId", requirePermission("CURRENCIES", "EDIT"), c.patchMetal);

r.delete("/metals/:metalId", requirePermission("CURRENCIES", "DELETE"), c.deleteMetal);

r.patch("/metals/:metalId/active", requirePermission("CURRENCIES", "EDIT"), c.patchMetalActive);

r.post("/metals/:metalId/move", requirePermission("CURRENCIES", "EDIT"), c.postMoveMetal);

r.get("/metals/:metalId/ref-history", requirePermission("CURRENCIES", "VIEW"), c.getMetalRefHistory);

/* =========================
   Variantes
========================= */

r.post("/variants", requirePermission("CURRENCIES", "CREATE"), c.postMetalVariant);

r.get("/metals/:metalId/variants", requirePermission("CURRENCIES", "VIEW"), c.getMetalVariants);

r.patch("/variants/:variantId/active", requirePermission("CURRENCIES", "EDIT"), c.patchVariantActive);

r.post("/variants/:variantId/set-favorite", requirePermission("CURRENCIES", "ADMIN"), c.postSetFavoriteVariant);

// ✅ Pricing (factor + override)
r.patch("/variants/:variantId/pricing", requirePermission("CURRENCIES", "EDIT"), c.patchVariantPricing);

// ✅ eliminar variante
r.delete("/variants/:variantId", requirePermission("CURRENCIES", "DELETE"), c.deleteVariant);

/* =========================
   Cotizaciones Metales
========================= */

r.post("/quotes", requirePermission("CURRENCIES", "CREATE"), c.postMetalQuote);

r.get("/variants/:variantId/quotes", requirePermission("CURRENCIES", "VIEW"), c.getMetalQuotes);

export default r;