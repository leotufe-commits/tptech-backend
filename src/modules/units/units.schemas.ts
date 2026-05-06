// src/modules/units/units.schemas.ts
import { z } from "zod";

export const unitTypeEnum = z.enum(["QUANTITY", "WEIGHT", "LENGTH", "VOLUME", "OTHER"]);

const baseFields = {
  name: z.string().trim().min(1, "El nombre es obligatorio.").max(80),
  code: z.string().trim().min(1, "El código es obligatorio.").max(40),
  type: unitTypeEnum,
  isActive: z.boolean().optional(),
  isFavorite: z.boolean().optional(),
  sortOrder: z.number().int().optional(),
};

export const createUnitSchema = z.object(baseFields);

export const updateUnitSchema = z.object({
  name: baseFields.name.optional(),
  code: baseFields.code.optional(),
  type: unitTypeEnum.optional(),
  isActive: z.boolean().optional(),
  sortOrder: z.number().int().optional(),
});

export const favoriteUnitSchema = z.object({
  isFavorite: z.boolean(),
});

export type CreateUnitInput = z.infer<typeof createUnitSchema>;
export type UpdateUnitInput = z.infer<typeof updateUnitSchema>;
export type FavoriteUnitInput = z.infer<typeof favoriteUnitSchema>;
