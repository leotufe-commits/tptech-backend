// src/modules/receipts/receipts.schemas.ts
// ============================================================================
// Validación de payloads de Receipt (FASE 3 — borrador).
// ============================================================================

import { z } from "zod";

const num = (msg: string) =>
  z.union([z.number(), z.string()])
   .transform((v) => Number(v))
   .refine((n) => Number.isFinite(n), msg);

const numOpt = z.union([z.number(), z.string(), z.null()])
  .optional()
  .transform((v) => {
    if (v == null || v === "") return undefined;
    const n = Number(v);
    return Number.isFinite(n) ? n : undefined;
  });

/** Línea para POST /receipts. */
export const receiptLineDraftSchema = z.object({
  articleId:  z.string().optional(),
  variantId:  z.string().optional(),
  itemKind:   z.enum(["ARTICLE_SIMPLE", "ARTICLE_VARIANT", "SERVICE", "COMBO"]).default("ARTICLE_SIMPLE"),
  name:       z.string().default(""),
  code:       z.string().default(""),
  sku:        z.string().default(""),
  barcode:    z.string().default(""),

  quantity:        num("quantity inválida"),
  unitPrice:       num("unitPrice inválido"),
  subtotal:        num("subtotal inválido"),
  discountAmount:  num("discountAmount inválido"),
  lineTotal:       num("lineTotal inválido"),
  taxAmount:       num("taxAmount inválido"),
  totalWithTax:    num("totalWithTax inválido"),

  totalCost:   numOpt,
  totalMargin: numOpt,

  sortOrder: z.number().int().nonnegative().default(0),

  /** Snapshot inmutable del cálculo de pricing de la línea. */
  pricingSnapshot: z.unknown().optional(),
});

export const createReceiptDraftSchema = z.object({
  // Identificación del documento
  type:      z.enum(["QUOTE", "INVOICE", "DELIVERY_NOTE", "CREDIT_NOTE", "DEBIT_NOTE"]).default("INVOICE"),
  direction: z.enum(["OUTBOUND", "INBOUND"]).default("OUTBOUND"),

  // Cliente / proveedor (counterparty)
  counterpartyId: z.string().optional(),

  // Moneda
  currencyCode: z.string().default(""),
  currencyRate: num("currencyRate inválido").default(1),

  // Totales (planos — copia del snapshot)
  subtotal:       num("subtotal inválido").default(0),
  discountAmount: num("discountAmount inválido").default(0),
  taxAmount:      num("taxAmount inválido").default(0),
  total:          num("total inválido").default(0),
  totalBase:      num("totalBase inválido").default(0),

  // Fechas
  issueDate: z.string().optional(), // ISO; default = now() en el service
  dueDate:   z.string().optional(),

  // Texto libre
  notes: z.string().default(""),
  terms: z.string().default(""),

  // Snapshots (Json) — el frontend manda el shape que ya armó.
  pricingSnapshot:  z.unknown(),
  currencySnapshot: z.unknown(),

  // Líneas
  lines: z.array(receiptLineDraftSchema).default([]),
});

export type CreateReceiptDraftInput = z.infer<typeof createReceiptDraftSchema>;
export type ReceiptLineDraftInput   = z.infer<typeof receiptLineDraftSchema>;
