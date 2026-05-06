// src/modules/taxes/taxes.schemas.ts
import { z } from "zod";

const numericString = z.union([z.string(), z.number()])
  .transform((v) => String(v))
  .pipe(z.string().regex(/^\d+(\.\d+)?$/, "Debe ser un número válido >= 0"));

export const createTaxSchema = z.object({
  name:             z.string().min(1, "El nombre es obligatorio."),
  code:             z.string().optional(),
  taxType:          z.enum(["IVA", "INTERNAL", "PERCEPTION", "RETENTION", "OTHER"]).optional(),
  calculationType:  z.enum(["PERCENTAGE", "FIXED_AMOUNT", "PERCENTAGE_PLUS_FIXED"]).optional(),
  applyOn:          z.enum(["TOTAL", "METAL", "HECHURA", "METAL_Y_HECHURA", "SUBTOTAL_AFTER_DISCOUNT", "SUBTOTAL_BEFORE_DISCOUNT"]).optional(),
  rate:             numericString.optional().nullable(),
  fixedAmount:      numericString.optional().nullable(),
  includedInPrice:  z.boolean().optional(),
  appliesOnSale:    z.boolean().optional(),
  appliesOnPurchase: z.boolean().optional(),
  isRecoverable:    z.boolean().optional(),
  validFrom:        z.string().datetime({ offset: true }).optional().nullable(),
  validTo:          z.string().datetime({ offset: true }).optional().nullable(),
  sortOrder:        z.number().int().optional(),
  notes:            z.string().optional(),
}).passthrough();

export const updateTaxSchema = createTaxSchema.extend({
  isActive: z.boolean().optional(),
});
