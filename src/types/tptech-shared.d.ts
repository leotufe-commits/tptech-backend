// src/types/tptech-shared.d.ts
// =============================================================================
//  Declaración ambient del módulo `@tptech/shared/document-printables/...`
//  para que TypeScript pueda type-checkear el renderer HTML (C4) sin
//  necesidad de incluir el submódulo `tptech-shared/` dentro del
//  `rootDir` del backend.
//
//  Source of truth real: `tptech-shared/src/document-printables/
//  SaleInvoicePrintable.tsx`. Este archivo es un MIRROR de tipos:
//  si el shared cambia su shape público, hay que actualizar acá.
//
//  Runtime:
//    · tsx (dev) y vitest resuelven `@tptech/shared/...` via `paths`
//      del `tsconfig.json` y leen el .tsx real del submódulo.
//    · En producción (C5+) habrá que cablear `tsc-alias` o cambiar el
//      runtime de `node dist/...` a `tsx`. Hoy el renderer HTML no se
//      ejecuta en prod (el motor activo sigue siendo pdfkit).
// =============================================================================

declare module "@tptech/shared/document-printables/SaleInvoicePrintable.js" {
  import type { ReactElement } from "react";

  export type SaleInvoicePrintableConfig = Record<string, unknown>;

  export interface SaleInvoicePrintableCompany {
    name?:         string;
    legalName?:    string;
    logoUrl?:      string;
    cuit?:         string;
    ivaCondition?: string;
    addressLine?:  string;
    phone?:        string;
    email?:        string;
    website?:      string;
  }

  export interface SaleInvoicePrintableLine {
    id:                 string;
    type?:              "ARTICLE" | "HEADER";
    title?:             string;
    articleId?:         string;
    isManual?:          boolean;
    manualDescription?: string;
    article?:           string;
    variant?:           string;
    sku?:               string;
    quantity?:          number;
    unitPrice?:         number;
    subtotal?:          number;
    lineTotal?:         number;
  }

  export interface SaleInvoicePrintableTotals {
    subtotal:       number;
    discountAmount: number;
    taxAmount:      number;
    total:          number;
  }

  export interface SaleInvoicePrintableProps {
    config:          SaleInvoicePrintableConfig;
    company:         SaleInvoicePrintableCompany;
    documentNumber:  string;
    documentDate:    string;
    clientName:      string;
    clientTaxId?:    string;
    clientAddress?:  string;
    lines:           SaleInvoicePrintableLine[];
    totals:          SaleInvoicePrintableTotals;
    currencyCode:    string;
    fxRate:          number;
    notes?:          string;
    terms?:          string;
    sellerName?:     string;
    warehouseName?:  string;
    paymentTermName?: string;
    status?:         "DRAFT" | "PENDING" | "PARTIAL" | "PAID" | "CANCELLED";
  }

  const SaleInvoicePrintable: (props: SaleInvoicePrintableProps) => ReactElement;
  export default SaleInvoicePrintable;
}
