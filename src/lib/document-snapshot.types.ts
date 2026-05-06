// Interfaces inmutables para los snapshots que se congelan al confirmar
// Sale/Purchase. Estos tipos son el contrato entre la capa de confirmación
// y cualquier futuro módulo de comprobantes (factura, remito, presupuesto).
//
// REGLA: una vez escrito un snapshot, NUNCA se recalcula.
// Si una entidad cambia (nombre, CUIT, dirección), los snapshots históricos
// deben conservar los datos que había AL MOMENTO DE LA CONFIRMACIÓN.

// ─── Entidad comercial (cliente o proveedor) ─────────────────────────────────
export interface EntitySnapshot {
  id:                 string;
  displayName:        string;
  code:               string;
  documentType:       string;
  documentNumber:     string;
  ivaCondition:       string;
  email:              string;
  phone:              string;
  taxExempt:          boolean;
  taxApplyOnOverride: string | null;
  taxOverrides: Array<{
    taxId:        string;
    overrideMode: string;
    applyOn:      string | null;
    isActive:     boolean;
  }>;
  billingAddress: {
    street:       string;
    streetNumber: string;
    floor:        string;
    apartment:    string;
    city:         string;
    province:     string;
    country:      string;
    postalCode:   string;
  } | null;
  snapshotAt: string; // ISO-8601
}

// ─── Vendedor ────────────────────────────────────────────────────────────────
export interface SellerSnapshot {
  id:               string;
  firstName:        string;
  lastName:         string;
  displayName:      string;
  documentType:     string;
  documentNumber:   string;
  email:            string;
  commissionType:   string;   // NONE | PERCENTAGE | FIXED_AMOUNT
  commissionValue:  number | null;
  commissionBase:   string;   // TOTAL | METAL | HECHURA | METAL_Y_HECHURA
  commissionTotal:  number | null; // total calculado al confirmar
  snapshotAt:       string; // ISO-8601
}

// ─── Emisor (joyería / tenant) ───────────────────────────────────────────────
// Se congela en cada comprobante para que cambios futuros en la razón social,
// CUIT o dirección del local no alteren documentos históricos.
export interface IssuerSnapshot {
  id:           string;
  name:         string;        // nombre comercial
  legalName:    string;        // razón social legal
  cuit:         string;
  ivaCondition: string;
  email:        string;
  street:       string;
  number:       string;
  floor:        string;
  apartment:    string;
  city:         string;
  province:     string;
  country:      string;
  postalCode:   string;
  logoUrl:      string;
  snapshotAt:   string; // ISO-8601
}

// ─── Moneda ──────────────────────────────────────────────────────────────────
// Captura la moneda y la cotización vigente al momento de la confirmación.
// exchangeRate = cuántas unidades de moneda base equivalen a 1 unidad de
// esta moneda (null cuando esta moneda ES la base).
export interface CurrencySnapshot {
  id:           string;
  code:         string;   // "ARS" | "USD" | ...
  name:         string;
  symbol:       string;
  isBase:       boolean;
  exchangeRate: number | null;
  snapshotAt:   string;   // ISO-8601
}
