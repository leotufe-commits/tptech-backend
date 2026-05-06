// src/modules/articles/articles.schemas.ts
//
// Schema mínimo pero útil para POST / PUT de artículos.
// Valida los campos críticos y deja pasar el resto con .passthrough(),
// ya que el service tiene validación interna propia para todos los campos.
import { z } from "zod";

export const createArticleSchema = z.object({
  name:        z.string().min(1, "El nombre es obligatorio."),
  code:        z.string().optional(),
  sku:         z.string().optional().nullable(),
  articleType: z.enum(["PRODUCT", "SERVICE", "MATERIAL"]).optional(),
  stockMode:   z.enum(["NO_STOCK", "BY_ARTICLE", "BY_MATERIAL"]).optional(),
  salePrice:   z.union([z.string(), z.number()]).optional().nullable(),
  categoryId:  z.string().optional().nullable(),
}).passthrough();

export const updateArticleSchema = createArticleSchema.extend({
  name: z.string().min(1, "El nombre es obligatorio.").optional(),
});
