// src/modules/receipt-series/receipt-series.schemas.ts
// ============================================================================
// Zod schemas — Etapa A admin de numeración (2026-05-29).
//
// Validan formato comercial estricto de prefix / pointOfSale / nextNumber:
//   · prefix       → 0-3 letras mayúsculas (A, B, FA, FC, "", ...).
//   · pointOfSale  → 4 dígitos exactos (0001..9999).
//   · nextNumber   → entero ≥ 1.
//
// La unicidad del compuesto (jewelryId, type, direction, prefix, pointOfSale)
// y la regla "nextNumber ≥ último emitido + 1" viven en el SERVICE — no en
// el schema — porque requieren acceso a la DB.
// ============================================================================

import { z } from "zod";

// ─── Constantes del dominio ────────────────────────────────────────────────
//
// `ReceiptType` y `ReceiptDirection` son enums Prisma. Los replicamos como
// arrays de string para validar con z.enum() sin importar el cliente Prisma
// (que en tests se mockea).

export const RECEIPT_TYPES = [
  "QUOTE",
  "INVOICE",
  "DELIVERY_NOTE",
  "CREDIT_NOTE",
  "DEBIT_NOTE",
] as const;

export const RECEIPT_DIRECTIONS = [
  "OUTBOUND",
  "INBOUND",
] as const;

export const PREFIX_REGEX        = /^[A-Z]{0,3}$/;
export const POINT_OF_SALE_REGEX = /^\d{4}$/;

// ─── Schemas ───────────────────────────────────────────────────────────────

export const createReceiptSeriesSchema = z.object({
  name: z.string().trim().min(1, "El nombre es obligatorio.").max(120, "Nombre demasiado largo (máx 120)."),
  type:      z.enum(RECEIPT_TYPES),
  direction: z.enum(RECEIPT_DIRECTIONS),
  prefix: z
    .string()
    .regex(PREFIX_REGEX, "Prefijo inválido: usar 0-3 letras mayúsculas (ej. A, B, FA).")
    .optional()
    .default(""),
  pointOfSale: z
    .string()
    .regex(POINT_OF_SALE_REGEX, "Punto de venta inválido: usar 4 dígitos (ej. 0001).")
    .optional()
    .default("0001"),
  nextNumber: z
    .number()
    .int("El próximo número debe ser entero.")
    .min(1, "El próximo número debe ser ≥ 1.")
    .optional()
    .default(1),
  isActive: z.boolean().optional().default(true),
}).strict();

export type CreateReceiptSeriesInput = z.infer<typeof createReceiptSeriesSchema>;

/**
 * PATCH no permite cambiar `type` ni `direction` — esos campos son inmutables
 * porque definen la naturaleza fiscal de la serie. Si el operador necesita
 * un tipo distinto, debe crear OTRA serie y soft-deletear la actual.
 */
export const updateReceiptSeriesSchema = z.object({
  name: z.string().trim().min(1).max(120).optional(),
  prefix: z
    .string()
    .regex(PREFIX_REGEX, "Prefijo inválido: usar 0-3 letras mayúsculas.")
    .optional(),
  pointOfSale: z
    .string()
    .regex(POINT_OF_SALE_REGEX, "Punto de venta inválido: usar 4 dígitos.")
    .optional(),
  nextNumber: z.number().int().min(1).optional(),
  isActive: z.boolean().optional(),
}).strict();

export type UpdateReceiptSeriesInput = z.infer<typeof updateReceiptSeriesSchema>;
