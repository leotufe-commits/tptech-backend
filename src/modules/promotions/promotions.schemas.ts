// src/modules/promotions/promotions.schemas.ts
import { z } from "zod";

export const createPromotionSchema = z.object({
  name:            z.string().min(1, "El nombre es obligatorio."),
  type:            z.enum(["FIXED", "PERCENTAGE"]),
  value:           z.union([z.string(), z.number()]).refine(
    (v) => Number(v) >= 0,
    { message: "El valor debe ser >= 0." }
  ),
  scope:           z.enum(["ALL", "ARTICLE", "VARIANT", "CATEGORY", "BRAND", "GROUP", "METALS"]).optional(),
  applyOn:         z.enum(["TOTAL", "LINE"]).optional(),
  validFrom:       z.string().optional().nullable(),
  validTo:         z.string().optional().nullable(),
  untilStockEnd:   z.boolean().optional(),
  priority:        z.number().int().optional(),
  isStackable:     z.boolean().optional(),
  isActive:        z.boolean().optional(),
  notes:           z.string().optional(),
  articleIds:      z.array(z.string()).optional(),
  variantIds:      z.array(z.string()).optional(),
  categoryIds:     z.array(z.string()).optional(),
  brands:          z.array(z.string()).optional(),
  groupIds:        z.array(z.string()).optional(),
  metalVariantIds: z.array(z.string()).optional(),
}).passthrough();

// El PUT acepta updates parciales (PATCH-like): cualquier subset de campos.
// El service ya hace `data.X !== undefined ? ...` por cada propiedad.
//
// Por eso TODOS los campos son opcionales acá. Heredar `name` (required) del
// createPromotionSchema rompía updates parciales como el toggle isActive,
// generando 400 "Invalid input: expected string, received undefined".
export const updatePromotionSchema = z.object({
  name:            z.string().min(1, "El nombre es obligatorio.").optional(),
  type:            z.enum(["FIXED", "PERCENTAGE"]).optional(),
  value:           z.union([z.string(), z.number()]).optional().refine(
    (v) => v === undefined || Number(v) >= 0,
    { message: "El valor debe ser >= 0." }
  ),
  scope:           z.enum(["ALL", "ARTICLE", "VARIANT", "CATEGORY", "BRAND", "GROUP", "METALS"]).optional(),
  applyOn:         z.enum(["TOTAL", "LINE"]).optional(),
  validFrom:       z.string().optional().nullable(),
  validTo:         z.string().optional().nullable(),
  untilStockEnd:   z.boolean().optional(),
  priority:        z.number().int().optional(),
  isStackable:     z.boolean().optional(),
  isActive:        z.boolean().optional(),
  notes:           z.string().optional(),
  articleIds:      z.array(z.string()).optional(),
  variantIds:      z.array(z.string()).optional(),
  categoryIds:     z.array(z.string()).optional(),
  brands:          z.array(z.string()).optional(),
  groupIds:        z.array(z.string()).optional(),
  metalVariantIds: z.array(z.string()).optional(),
}).passthrough();
