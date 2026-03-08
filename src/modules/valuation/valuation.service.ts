// tptech-backend/src/modules/valuation/valuation.service.ts

/* =========================================================
   BARREL (exports centralizados)
   El controller NO debe importar services directos.
   Todo pasa por acá.
========================================================= */

/* -------- CURRENCIES -------- */
export {
  listCurrencies,
  createCurrency,
  updateCurrency,
  setBaseCurrencyAndRecalc,
  toggleCurrencyActive,
  addCurrencyRate,
  listCurrencyRates,
  deleteCurrency,
} from "./valuation.currencies.service.js";

/* -------- METALS -------- */
export {
  createMetal,
  listMetals,
  updateMetal,
  deleteMetal,
  toggleMetalActive,
  moveMetal,
  listMetalRefHistory,
} from "./valuation.metals.service.js";

/* -------- VARIANTS -------- */
export {
  createMetalVariant,
  listMetalVariants,
  updateMetalVariant,
  setFavoriteVariant,
  clearFavoriteVariant,
  toggleVariantActive,
  deleteMetalVariant,
} from "./valuation.variants.service.js";

/* -------- QUOTES -------- */
export {
  addMetalQuote,
  listMetalQuotes,
} from "./valuation.quotes.service.js";