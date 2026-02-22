import { z } from "zod";

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
  referenceValue: z.coerce
    .number()
    .min(0, "El valor de referencia no puede ser negativo.")
    .optional(),
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
  referenceValue: z.coerce
    .number()
    .min(0, "El valor de referencia no puede ser negativo.")
    .optional(),
});

export const createMetalVariantSchema = z.object({
  metalId: z.string().trim().min(1),
  name: z.string().trim().min(1).max(60),
  sku: z.string().trim().min(1).max(60),

  // 0..1
  purity: z.coerce.number().min(0).max(1),

  // ✅ NUEVO: factor comercial (opcionales, default 1.0 en DB)
  buyFactor: z.coerce.number().min(0).optional(),
  saleFactor: z.coerce.number().min(0).optional(),

  // ✅ NUEVO: override manual (si viene, se guarda)
  purchasePriceOverride: z.coerce.number().min(0).optional().nullable(),
  salePriceOverride: z.coerce.number().min(0).optional().nullable(),
});

// ✅ NUEVO: actualizar pricing de variante
export const updateMetalVariantPricingSchema = z.object({
  buyFactor: z.coerce.number().min(0).optional(),
  saleFactor: z.coerce.number().min(0).optional(),
  purchasePriceOverride: z.coerce.number().min(0).optional().nullable(),
  salePriceOverride: z.coerce.number().min(0).optional().nullable(),

  // helpers
  clearPurchaseOverride: z.coerce.boolean().optional(),
  clearSaleOverride: z.coerce.boolean().optional(),
});

export const createMetalQuoteSchema = z.object({
  variantId: z.string().trim().min(1),
  currencyId: z.string().trim().min(1),
  purchasePrice: z.coerce.number().min(0),
  salePrice: z.coerce.number().min(0),
  effectiveAt: z.coerce.date().optional(),
});
// ✅ NUEVO: editar variante (PATCH /valuation/variants/:variantId)
export const updateMetalVariantSchema = z
  .object({
    name: z.string().trim().min(1).max(60).optional(),
    sku: z.string().trim().min(1).max(60).optional(),

    // 0..1 (pero para negocio conviene > 0)
    purity: z.coerce.number().min(0).max(1).optional(),

    saleFactor: z.coerce.number().min(0).optional(),

    // null = limpiar override; number >= 0 = setear; undefined = no tocar
    salePriceOverride: z
      .union([z.coerce.number().min(0), z.null()])
      .optional(),
  })
  .superRefine((v, ctx) => {
    if (v.purity !== undefined && v.purity <= 0) {
      ctx.addIssue({
        code: "custom",
        path: ["purity"],
        message: "Pureza/Ley inválida. Debe ser mayor a 0 y hasta 1.",
      });
    }
    if (v.saleFactor !== undefined && v.saleFactor <= 0) {
      ctx.addIssue({
        code: "custom",
        path: ["saleFactor"],
        message: "Ajuste venta (factor) inválido. Debe ser mayor a 0.",
      });
    }
  });