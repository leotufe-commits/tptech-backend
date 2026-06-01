// src/modules/user-preferences/user-preferences.schemas.ts
import { z } from "zod";

// Cada campo es opcional; `null` (o "") limpia esa preferencia.
const optId = z.string().trim().min(1).nullable().optional();

// Tipo del Descuento global predeterminado del usuario: "PERCENT" | "AMOUNT".
// `null` limpia la preferencia → frontend cae al fallback "PERCENT".
const optGlobalDiscountType = z
  .enum(["PERCENT", "AMOUNT"])
  .nullable()
  .optional();

// Layout del modal de Factura — JSON opaco para el backend (validación
// mínima de shape; `reconcileLayout` del frontend valida ids/widths).
const optInvoiceLayoutConfig = z
  .object({
    version: z.number(),
    cards: z.array(z.unknown()),
  })
  .passthrough()
  .nullable()
  .optional();

// Plantilla de vista preferida del usuario para la Factura de ventas.
// Enum cerrado. El service también sanitiza defensivamente y mapea
// legacy ("BALANCED", "FINANCIAL") → "COMPACT".
// `null` limpia la preferencia → frontend cae al default "COMPACT".
//
// Valores oficiales (frontend `InvoiceViewPreset`):
//   - COMPACT
//   - CLASSIC
//   - ONE_LINE  (agregado tras el rename — antes faltaba aquí y los
//                clientes que enviaban "ONE_LINE" recibian 400 con
//                "Error al guardar" en la toolbar de Personalizar layout)
//
// Valores legacy aceptados por back-compat (mapeados a COMPACT en el
// sanitizador del service):
//   - SINGLE_COLUMN, CUSTOM, BALANCED, FINANCIAL
//
// Los clientes viejos que envíen un nombre legacy no son rechazados;
// el sanitizador del service hace el mapping al enum nuevo antes de
// persistir.
const optInvoiceViewPreset = z
  .enum([
    "COMPACT",
    "CLASSIC",
    "ONE_LINE",
    // Legacy (aceptados, mapeados al nuevo enum por el service):
    "SINGLE_COLUMN",
    "CUSTOM",
    "BALANCED",
    "FINANCIAL",
  ])
  .nullable()
  .optional();

// Configuraciones finas de UI del modal de Factura — objeto opaco para
// el backend. El frontend lo valida via `resolveInvoiceUiPreferences`.
// Aceptamos cualquier objeto plano + null + ausente.
const optInvoiceUiPreferences = z
  .object({}).passthrough()
  .nullable()
  .optional();

export const updatePreferenceSchema = z.object({
  defaultWarehouseId: optId,
  defaultSellerId:    optId,
  defaultPriceListId: optId,
  defaultChannelId:   optId,
  defaultCurrencyId:  optId,
  defaultGlobalDiscountType: optGlobalDiscountType,
  invoiceLayoutConfig: optInvoiceLayoutConfig,
  preferredInvoiceViewPreset: optInvoiceViewPreset,
  invoiceUiPreferences: optInvoiceUiPreferences,
}).passthrough();
