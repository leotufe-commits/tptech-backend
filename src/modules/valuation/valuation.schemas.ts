// tptech-backend/src/modules/valuation/valuation.schemas.ts
import { z } from "zod";

/* =========================
   Helpers Zod
========================= */

const zSku = z
  .string()
  .trim()
  .min(1, "SKU requerido.")
  .max(60, "SKU muy largo.")
  .transform((s) => String(s).trim().toUpperCase());

const zPurity = z.coerce
  .number()
  .gt(0, "Pureza/Ley inválida. Debe ser mayor a 0.")
  .lte(1, "Pureza/Ley inválida. Debe ser hasta 1 (ej: 0.750).");

const zFactorPos = z.coerce.number().gt(0, "Factor inválido. Debe ser mayor a 0.");

/* =========================
   Monedas
========================= */

export const createCurrencySchema = z.object({
  code: z
    .string()
    .trim()
    .min(2, "Código inválido.")
    .max(6, "Código muy largo.")
    .transform((s) => s.toUpperCase().replace(/[^A-Z]/g, "")),
  name: z.string().trim().min(1, "Nombre requerido.").max(60, "Nombre muy largo."),
  symbol: z.string().trim().min(1, "Símbolo requerido.").max(10, "Símbolo muy largo."),
});

export const updateCurrencySchema = createCurrencySchema;

export const createCurrencyRateSchema = z.object({
  rate: z.coerce.number().positive("Tipo de cambio inválido."),
  effectiveAt: z.coerce.date(),
});

/* =========================
   Metales / Variantes / Quotes
========================= */

// ✅ CREATE metal padre (name + symbol + referenceValue)
export const createMetalSchema = z.object({
  name: z.string().trim().min(1, "Nombre requerido.").max(60, "Nombre muy largo."),
  symbol: z
    .string()
    .trim()
    .max(10, "Símbolo muy largo.")
    .optional()
    .transform((s) => String(s ?? "").trim()),

  // ✅ valor referencia (en moneda base)
  referenceValue: z.coerce.number().min(0, "El valor de referencia no puede ser negativo.").optional(),
});

// ✅ EDIT metal padre
export const updateMetalSchema = z.object({
  name: z.string().trim().min(1, "Nombre requerido.").max(60, "Nombre muy largo."),
  symbol: z
    .string()
    .trim()
    .max(10, "Símbolo muy largo.")
    .transform((s) => String(s ?? "").trim()),

  // ✅ valor referencia (en moneda base)
  referenceValue: z.coerce.number().min(0, "El valor de referencia no puede ser negativo.").optional(),
});

/**
 * ✅ CREATE variante
 * - purity: (0, 1]
 * - factors: opcionales, pero si vienen deben ser > 0
 * - overrides: number >= 0 o null
 */
export const createMetalVariantSchema = z.object({
  metalId: z.string().trim().min(1),
  name: z.string().trim().min(1, "Nombre requerido.").max(60, "Nombre muy largo."),
  sku: zSku,
  purity: zPurity,
  saleFactor: zFactorPos.optional(),
});

export const updateMetalVariantSchema = z.object({
  name: z.string().trim().min(1, "Nombre requerido.").max(60, "Nombre muy largo."),
  sku: zSku,
  purity: zPurity,
  saleFactor: zFactorPos.optional(),
});

export const createMetalQuoteSchema = z.object({
  variantId: z.string().trim().min(1),
  currencyId: z.string().trim().min(1),
  price: z.coerce.number().min(0),
  effectiveAt: z.coerce.date().optional(),
});