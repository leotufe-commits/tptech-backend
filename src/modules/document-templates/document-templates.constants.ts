// src/modules/document-templates/document-templates.constants.ts

import { DocumentKind } from "@prisma/client";

// ─────────────────────────────────────────────────────────────────────────────
// Columnas
// ─────────────────────────────────────────────────────────────────────────────

export type ColumnConfig = {
  key:       string;
  label:     string;
  visible:   boolean;
  width:     number;   // en puntos (px en preview, pt en PDF)
  align:     "left" | "center" | "right";
  sortOrder: number;
};

// Columnas disponibles para documentos con líneas de venta / compra
const SALE_COLUMNS: ColumnConfig[] = [
  { key: "position",    label: "#",            visible: false, width: 28,  align: "center", sortOrder: 0  },
  { key: "code",        label: "Código",        visible: false, width: 60,  align: "left",   sortOrder: 1  },
  { key: "sku",         label: "SKU",           visible: false, width: 60,  align: "left",   sortOrder: 2  },
  { key: "description", label: "Descripción",   visible: true,  width: 180, align: "left",   sortOrder: 3  },
  { key: "variant",     label: "Variante",      visible: true,  width: 80,  align: "left",   sortOrder: 4  },
  { key: "quantity",    label: "Cant.",         visible: true,  width: 46,  align: "right",  sortOrder: 5  },
  { key: "unit",        label: "Unidad",        visible: false, width: 48,  align: "center", sortOrder: 6  },
  { key: "weight",      label: "Gramos",        visible: false, width: 56,  align: "right",  sortOrder: 7  },
  { key: "unitPrice",   label: "Precio unit.",  visible: true,  width: 80,  align: "right",  sortOrder: 8  },
  { key: "discount",    label: "Desc.",         visible: false, width: 54,  align: "right",  sortOrder: 9  },
  { key: "tax",         label: "IVA",           visible: false, width: 54,  align: "right",  sortOrder: 10 },
  { key: "subtotal",    label: "Subtotal",      visible: true,  width: 80,  align: "right",  sortOrder: 11 },
];

// Columnas para movimientos de stock (sin precios)
const MOVEMENT_COLUMNS: ColumnConfig[] = [
  { key: "position",    label: "#",            visible: false, width: 28,  align: "center", sortOrder: 0 },
  { key: "code",        label: "Código",        visible: false, width: 60,  align: "left",   sortOrder: 1 },
  { key: "sku",         label: "SKU",           visible: true,  width: 60,  align: "left",   sortOrder: 2 },
  { key: "description", label: "Descripción",   visible: true,  width: 200, align: "left",   sortOrder: 3 },
  { key: "variant",     label: "Variante",      visible: true,  width: 80,  align: "left",   sortOrder: 4 },
  { key: "quantity",    label: "Cant.",         visible: true,  width: 46,  align: "right",  sortOrder: 5 },
  { key: "unit",        label: "Unidad",        visible: false, width: 48,  align: "center", sortOrder: 6 },
  { key: "weight",      label: "Gramos",        visible: true,  width: 56,  align: "right",  sortOrder: 7 },
];

export const COLUMNS_AVAILABLE: Record<DocumentKind, ColumnConfig[]> = {
  PRESUPUESTO:     SALE_COLUMNS,
  FACTURA:         SALE_COLUMNS,
  REMITO:          SALE_COLUMNS,
  ORDEN_COMPRA:    SALE_COLUMNS,
  MOVIMIENTO_STOCK: MOVEMENT_COLUMNS,
};

// ─────────────────────────────────────────────────────────────────────────────
// Secciones
// ─────────────────────────────────────────────────────────────────────────────

export type SectionMeta = { label: string; description: string };

export const SECTIONS_META: Record<string, SectionMeta> = {
  seller:             { label: "Vendedor",             description: "Nombre del vendedor asignado al documento." },
  warehouse:          { label: "Almacén",              description: "Almacén de origen o destino." },
  paymentTerms:       { label: "Condición de pago",    description: "Forma de pago pactada (contado, crédito, etc.)." },
  currency:           { label: "Moneda",               description: "Moneda utilizada en el documento." },
  exchangeRate:       { label: "Cotización",           description: "Tipo de cambio vigente al momento del documento." },
  discount:           { label: "Descuentos",           description: "Línea de descuento global del documento." },
  taxes:              { label: "Impuestos",            description: "Detalle del IVA u otros impuestos aplicados." },
  subtotal:           { label: "Subtotal",             description: "Subtotal antes de impuestos." },
  total:              { label: "Total",                description: "Monto total del documento." },
  observations:       { label: "Observaciones",        description: "Campo de texto libre para notas del documento." },
  signature:          { label: "Firma",                description: "Espacio para firma del receptor o emisor." },
  qrCode:             { label: "Código QR",            description: "QR con datos del documento (fiscal o de seguimiento)." },
  termsAndConditions: { label: "Términos y cond.",     description: "Texto de condiciones generales de venta." },
  validityDate:       { label: "Válido hasta",         description: "Fecha de vencimiento del presupuesto." },
  fiscalData:         { label: "Datos fiscales",       description: "Punto de venta, número de comprobante, CAE." },
  deliveryAddress:    { label: "Dirección de entrega", description: "Dirección de envío diferente a la de facturación." },
};

// Secciones disponibles por tipo de documento
export const SECTIONS_AVAILABLE: Record<DocumentKind, string[]> = {
  PRESUPUESTO: [
    "seller", "warehouse", "paymentTerms", "currency", "exchangeRate",
    "discount", "taxes", "subtotal", "total",
    "observations", "signature", "termsAndConditions", "validityDate",
  ],
  FACTURA: [
    "seller", "warehouse", "paymentTerms", "currency", "exchangeRate",
    "discount", "taxes", "subtotal", "total",
    "observations", "signature", "qrCode", "termsAndConditions", "fiscalData",
  ],
  REMITO: [
    "seller", "warehouse", "currency",
    "subtotal", "total",
    "observations", "signature", "deliveryAddress",
  ],
  ORDEN_COMPRA: [
    "seller", "warehouse", "paymentTerms", "currency", "exchangeRate",
    "discount", "taxes", "subtotal", "total",
    "observations", "termsAndConditions",
  ],
  MOVIMIENTO_STOCK: [
    "warehouse", "observations", "signature",
  ],
};

// Valores por defecto de secciones por tipo de documento
export const SECTIONS_DEFAULTS: Record<DocumentKind, Record<string, boolean>> = {
  PRESUPUESTO: {
    seller: true,  warehouse: false, paymentTerms: true,
    currency: true,  exchangeRate: false,
    discount: true,  taxes: true,  subtotal: true, total: true,
    observations: true,  signature: false, termsAndConditions: false, validityDate: true,
  },
  FACTURA: {
    seller: true,  warehouse: false, paymentTerms: true,
    currency: true,  exchangeRate: false,
    discount: true,  taxes: true,  subtotal: true, total: true,
    observations: true,  signature: false, qrCode: false, termsAndConditions: false, fiscalData: true,
  },
  REMITO: {
    seller: true,  warehouse: true, currency: false,
    subtotal: false, total: false,
    observations: true,  signature: true, deliveryAddress: false,
  },
  ORDEN_COMPRA: {
    seller: true,  warehouse: true, paymentTerms: true,
    currency: true,  exchangeRate: false,
    discount: false, taxes: true,  subtotal: true, total: true,
    observations: true,  termsAndConditions: false,
  },
  MOVIMIENTO_STOCK: {
    warehouse: true,  observations: true, signature: false,
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// Labels de documentos
// ─────────────────────────────────────────────────────────────────────────────

export const DOC_KIND_LABELS: Record<DocumentKind, string> = {
  PRESUPUESTO:     "Presupuesto",
  FACTURA:         "Factura",
  REMITO:          "Remito",
  ORDEN_COMPRA:    "Orden de compra",
  MOVIMIENTO_STOCK: "Movimiento de stock",
};

export const VALID_KINDS = Object.keys(DOC_KIND_LABELS) as DocumentKind[];

// ─────────────────────────────────────────────────────────────────────────────
// Fallback: template por defecto cuando la DB no está disponible
// ─────────────────────────────────────────────────────────────────────────────

export function buildDefaultTemplateResponse(kind: DocumentKind, layoutType = "A4") {
  return {
    id:           `default-${kind}-${layoutType}`,
    kind,
    layoutType,
    name:         "",
    isDefault:    true,
    isActive:     true,

    headerLogoEnabled:      true,
    headerLogoSize:         "md",
    headerShowProductImage: false,
    headerShowName:         true,
    headerShowLegalName:    false,
    headerShowCuit:      true,
    headerShowAddress:   true,
    headerShowPhone:     true,
    headerShowEmail:     false,
    headerShowWebsite:   false,
    headerCustomText:    "",

    pageSizePreset: "A4",
    isCustomSize:   false,
    pageWidthMm:    210,
    pageHeightMm:   297,
    orientation:    "portrait",
    marginTop:      15,
    marginRight:    15,
    marginBottom:   20,
    marginLeft:     15,

    fontFamily:   "inter",
    fontSizeBase: 10,
    accentColor:  "#1a1a1a",
    tableStyle:   "bordered",

    currencyShowSymbol: true,
    currencyShowRate:   false,
    currencyDecimals:   2,
    pricesIncludeTax:   false,

    footerText:            "",
    footerLegalText:       "",
    footerBankData:        "",
    footerTerms:           "",
    footerShowPageNumbers: true,
    footerPageFormat:      "page_of_total",
    footerPagePosition:    "bottom_right",

    sections:       SECTIONS_DEFAULTS[kind] ?? {},
    columns:        COLUMNS_AVAILABLE[kind] ?? [],
    columnsVersion: 1,

    // Plantilla de mail vacia → el modal `SendInvoiceEmailModal` usa los
    // defaults state-aware (BORRADOR / FACTURA ANULADA / Factura).
    emailSubjectTemplate: "",
    emailMessageTemplate: "",

    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers de merge
// ─────────────────────────────────────────────────────────────────────────────

export function mergeColumns(savedJson: string, kind: DocumentKind): ColumnConfig[] {
  const available = COLUMNS_AVAILABLE[kind];
  let saved: ColumnConfig[] = [];
  try { saved = JSON.parse(savedJson); } catch { /* sin guardado previo */ }

  const savedMap = new Map(saved.map((c) => [c.key, c]));

  const merged = available.map((def) => {
    const user = savedMap.get(def.key);
    return user
      ? { ...def, visible: user.visible, width: user.width, align: user.align, sortOrder: user.sortOrder }
      : def;
  });

  return merged.sort((a, b) => a.sortOrder - b.sortOrder);
}

export function mergeSections(savedJson: string, kind: DocumentKind): Record<string, boolean> {
  const defaults = SECTIONS_DEFAULTS[kind] ?? {};
  let saved: Record<string, boolean> = {};
  try { saved = JSON.parse(savedJson); } catch { /* sin guardado previo */ }
  return { ...defaults, ...saved };
}
