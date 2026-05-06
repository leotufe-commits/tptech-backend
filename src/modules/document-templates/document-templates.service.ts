// src/modules/document-templates/document-templates.service.ts

import { DocumentKind } from "@prisma/client";
import { prisma } from "../../lib/prisma.js";
import {
  mergeColumns,
  mergeSections,
  SECTIONS_DEFAULTS,
  COLUMNS_AVAILABLE,
} from "./document-templates.constants.js";

// ─────────────────────────────────────────────────────────────────────────────
// Select completo
// ─────────────────────────────────────────────────────────────────────────────

const TEMPLATE_SELECT = {
  id: true, kind: true, layoutType: true, name: true, isDefault: true, isActive: true,
  headerLogoEnabled: true, headerLogoSize: true, headerLogoPosition: true, headerLogoBorderRadius: true, headerShowProductImage: true,
  headerShowName: true, headerShowLegalName: true,
  headerShowCuit: true, headerShowAddress: true, headerShowPhone: true,
  headerShowEmail: true, headerShowWebsite: true, headerCustomText: true,
  pageSizePreset: true, isCustomSize: true, pageWidthMm: true, pageHeightMm: true,
  orientation: true,
  marginTop: true, marginRight: true, marginBottom: true, marginLeft: true,
  fontFamily: true, fontSizeBase: true, accentColor: true, tableStyle: true,
  currencyShowSymbol: true, currencyShowRate: true,
  currencyDecimals: true, pricesIncludeTax: true,
  footerText: true, footerLegalText: true, footerBankData: true,
  footerTerms: true, footerShowPageNumbers: true,
  footerPageFormat: true, footerPagePosition: true,
  sections: true, columns: true, columnsVersion: true,
  createdAt: true, updatedAt: true,
} as const;

// ─────────────────────────────────────────────────────────────────────────────
// Serialización: convierte el registro raw en la respuesta enriquecida
// ─────────────────────────────────────────────────────────────────────────────

function toNum(v: any): number {
  if (v == null) return 0;
  if (typeof v === "number") return v;
  if (typeof v === "object" && typeof v.toNumber === "function") return v.toNumber();
  return parseFloat(String(v));
}

function serialize(t: any) {
  const kind = t.kind as DocumentKind;
  return {
    ...t,
    marginTop:    toNum(t.marginTop),
    marginRight:  toNum(t.marginRight),
    marginBottom: toNum(t.marginBottom),
    marginLeft:   toNum(t.marginLeft),
    pageWidthMm:  toNum(t.pageWidthMm),
    pageHeightMm: toNum(t.pageHeightMm),
    sections: mergeSections(t.sections, kind),
    columns:  mergeColumns(t.columns,   kind),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// GET — obtener o crear (upsert atómico con defaults)
// ─────────────────────────────────────────────────────────────────────────────

export async function getOrCreateTemplate(jewelryId: string, kind: DocumentKind, layoutType = "A4") {
  // upsert es atómico: nunca genera race condition ni registros duplicados
  const record = await prisma.documentTemplate.upsert({
    where: { jewelryId_kind_layoutType: { jewelryId, kind, layoutType } },
    create: {
      jewelryId,
      kind,
      layoutType,
      sections: JSON.stringify(SECTIONS_DEFAULTS[kind] ?? {}),
      columns:  JSON.stringify(COLUMNS_AVAILABLE[kind] ?? []),
    },
    update: {},   // si ya existe, no modificar nada
    select: TEMPLATE_SELECT,
  });

  return serialize(record);
}

// ─────────────────────────────────────────────────────────────────────────────
// PUT / PATCH — guardar configuración
// ─────────────────────────────────────────────────────────────────────────────

export async function saveTemplate(jewelryId: string, kind: DocumentKind, data: any, layoutType = "A4") {
  // getOrCreateTemplate devuelve { id, ... } — usamos el id para actualizar
  const existing = await getOrCreateTemplate(jewelryId, kind, layoutType);

  const updated = await prisma.documentTemplate.update({
    where: { id: existing.id },
    data: {
      name: data.name ?? undefined,

      // Encabezado
      headerLogoEnabled:      typeof data.headerLogoEnabled      === "boolean" ? data.headerLogoEnabled      : undefined,
      headerLogoSize:             data.headerLogoSize             ?? undefined,
      headerLogoPosition:         data.headerLogoPosition         ?? undefined,
      headerLogoBorderRadius:     data.headerLogoBorderRadius     != null ? Math.round(Number(data.headerLogoBorderRadius)) : undefined,
      headerShowProductImage: typeof data.headerShowProductImage === "boolean" ? data.headerShowProductImage : undefined,
      headerShowName:         typeof data.headerShowName         === "boolean" ? data.headerShowName         : undefined,
      headerShowLegalName: typeof data.headerShowLegalName === "boolean" ? data.headerShowLegalName : undefined,
      headerShowCuit:      typeof data.headerShowCuit      === "boolean" ? data.headerShowCuit      : undefined,
      headerShowAddress:   typeof data.headerShowAddress   === "boolean" ? data.headerShowAddress   : undefined,
      headerShowPhone:     typeof data.headerShowPhone     === "boolean" ? data.headerShowPhone     : undefined,
      headerShowEmail:     typeof data.headerShowEmail     === "boolean" ? data.headerShowEmail     : undefined,
      headerShowWebsite:   typeof data.headerShowWebsite   === "boolean" ? data.headerShowWebsite   : undefined,
      headerCustomText:    data.headerCustomText           ?? undefined,

      // Página
      pageSizePreset: data.pageSizePreset ?? undefined,
      isCustomSize:   typeof data.isCustomSize === "boolean" ? data.isCustomSize : undefined,
      pageWidthMm:    data.pageWidthMm  != null ? data.pageWidthMm  : undefined,
      pageHeightMm:   data.pageHeightMm != null ? data.pageHeightMm : undefined,
      orientation:    data.orientation  ?? undefined,
      marginTop:     data.marginTop    != null ? data.marginTop    : undefined,
      marginRight:   data.marginRight  != null ? data.marginRight  : undefined,
      marginBottom:  data.marginBottom != null ? data.marginBottom : undefined,
      marginLeft:    data.marginLeft   != null ? data.marginLeft   : undefined,

      // Estilo
      fontFamily:   data.fontFamily   ?? undefined,
      fontSizeBase: data.fontSizeBase  != null ? data.fontSizeBase  : undefined,
      accentColor:  data.accentColor   ?? undefined,
      tableStyle:   data.tableStyle    ?? undefined,

      // Moneda
      currencyShowSymbol: typeof data.currencyShowSymbol === "boolean" ? data.currencyShowSymbol : undefined,
      currencyShowRate:   typeof data.currencyShowRate   === "boolean" ? data.currencyShowRate   : undefined,
      currencyDecimals:   data.currencyDecimals != null ? data.currencyDecimals : undefined,
      pricesIncludeTax:   typeof data.pricesIncludeTax   === "boolean" ? data.pricesIncludeTax   : undefined,

      // Pie
      footerText:            data.footerText           ?? undefined,
      footerLegalText:       data.footerLegalText      ?? undefined,
      footerBankData:        data.footerBankData       ?? undefined,
      footerTerms:           data.footerTerms          ?? undefined,
      footerShowPageNumbers: typeof data.footerShowPageNumbers === "boolean" ? data.footerShowPageNumbers : undefined,
      footerPageFormat:      data.footerPageFormat     ?? undefined,
      footerPagePosition:    data.footerPagePosition   ?? undefined,

      // JSON
      sections: data.sections != null ? JSON.stringify(data.sections) : undefined,
      columns:  data.columns  != null ? JSON.stringify(data.columns)  : undefined,
    },
    select: TEMPLATE_SELECT,
  });

  return serialize(updated);
}

// ─────────────────────────────────────────────────────────────────────────────
// RESET — restaurar defaults para un tipo de documento
// ─────────────────────────────────────────────────────────────────────────────

export async function resetTemplate(jewelryId: string, kind: DocumentKind, layoutType = "A4") {
  const existing = await getOrCreateTemplate(jewelryId, kind, layoutType);

  const reset = await prisma.documentTemplate.update({
    where: { id: existing.id },
    data: {
      name:                   "",
      headerLogoEnabled:      true,
      headerLogoSize:           "18",
      headerLogoPosition:       "left",
      headerLogoBorderRadius:   20,
      headerShowProductImage:   false,
      headerShowName:         true,
      headerShowLegalName: false,
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
      marginTop:     15,
      marginRight:   15,
      marginBottom:  20,
      marginLeft:    15,
      fontFamily:    "inter",
      fontSizeBase:  10,
      accentColor:   "#1a1a1a",
      tableStyle:    "bordered",
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
      sections:       JSON.stringify(SECTIONS_DEFAULTS[kind] ?? {}),
      columns:        JSON.stringify(COLUMNS_AVAILABLE[kind] ?? []),
      columnsVersion: 1,
    },
    select: TEMPLATE_SELECT,
  });

  return serialize(reset);
}
