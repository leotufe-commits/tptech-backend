// src/modules/price-lists/price-lists.schemas.ts
import { z } from "zod";

const numericStringOrNull = z.union([z.string(), z.number()])
  .transform((v) => String(v))
  .optional()
  .nullable();

export const createPriceListSchema = z.object({
  name:                 z.string().min(1, "El nombre es obligatorio."),
  code:                 z.string().optional(),
  description:          z.string().optional(),
  scope:                z.enum(["GENERAL", "CHANNEL", "CATEGORY", "CLIENT"]).optional(),
  mode:                 z.enum(["MARGIN_TOTAL", "METAL_HECHURA", "COST_PER_GRAM"]).optional(),
  marginTotal:          numericStringOrNull,
  marginMetal:          numericStringOrNull,
  marginHechura:        numericStringOrNull,
  costPerGram:          numericStringOrNull,
  surcharge:            numericStringOrNull,
  minimumPrice:         numericStringOrNull,
  roundingTarget:       z.enum(["NONE", "METAL", "FINAL_PRICE"]).optional(),
  roundingMode:         z.enum(["NONE", "INTEGER", "DECIMAL_1", "DECIMAL_2", "TEN", "HUNDRED"]).optional(),
  roundingDirection:    z.enum(["NEAREST", "UP", "DOWN"]).optional(),
  roundingApplyOn:      z.enum(["PRICE", "NET", "TOTAL"]).optional(),
  roundingValueMetal:   numericStringOrNull,
  roundingValueHechura: numericStringOrNull,
  // Etapa C-comercial (POLICY §R-Rounding-14). Default MONETARY = compat
  // hacia atrás. PHYSICAL habilita redondeo en gramos por metal padre,
  // consumido por el motor de lista (capa C3 — pendiente).
  commercialRoundingMetalDomain:    z.enum(["MONETARY", "PHYSICAL"]).optional(),
  // Shape canónico — paralelo a `documentPhysicalRoundingConfig`:
  //   { byMetalParentId: { [metalId]: { mode, direction } },
  //     fallback: { mode, direction } }
  // Validación estructural mínima (degradación segura — el parser runtime
  // de C2 descarta entries inválidas sin romper el guardado).
  commercialPhysicalRoundingConfig: z.unknown().optional().nullable(),
  validFrom:            z.string().optional().nullable(),
  validTo:              z.string().optional().nullable(),
  isActive:             z.boolean().optional(),
  sortOrder:            z.number().int().optional(),
  notes:                z.string().optional(),
  categoryId:           z.string().optional().nullable(),
  channelId:            z.string().optional().nullable(),
  clientId:             z.string().optional().nullable(),
}).passthrough();

export const updatePriceListSchema = createPriceListSchema;
